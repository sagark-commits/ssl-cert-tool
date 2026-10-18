"""Cross-platform SSL deployment orchestrator (paramiko-based).

Safety properties (see tests/):
  * Host keys are verified (strict by default); a changed key is always fatal.
  * Every remote path/argument is shell-quoted; paths must be absolute.
  * Files are uploaded to a 0600 temp file, size/hash verified, then atomically
    renamed into place, preserving the owner of the file being replaced.
  * Existing files are backed up first (into an owner-checked 0700 directory);
    if any step of a service fails, that service's files are restored.
  * A failing hook aborts the restarts for that host (and restores its files).
  * Nothing is deployed unless the cert/key pair verifies locally.
"""
from __future__ import annotations

import errno
import hashlib
import logging
import os
import posixpath
import re
import stat as stat_mod
import threading
import uuid
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
from pathlib import Path
from typing import Any, Callable, Dict, List, Optional, Tuple

from ssl_cert_tool.core import KEY_PATTERNS
from ssl_cert_tool.platform import Terminal, expand_user
from ssl_deploy.ameyo_catalogue import expand_ameyo_profile
from ssl_deploy.ssh import (
    DEFAULT_COMMAND_IDLE_TIMEOUT,
    HAS_PARAMIKO,
    POLICY_ACCEPT_NEW,
    POLICY_STRICT,
    VALID_HOST_KEY_POLICIES,
    HostKeyVerificationError,
    RemoteHost,
    connect_chain,
    default_known_hosts_path,
    describe_route,
    load_ssh_config,
    resolve_hops,
    shell_quote as q,
    validate_remote_path,
)
from ssl_deploy.verify import (
    LEVEL_ERROR,
    LEVEL_WARN,
    has_errors,
    leaf_fingerprint_sha256,
    verify_cert_bundle,
    verify_copy_sources,
    wait_for_certificate,
)

try:
    import yaml

    HAS_YAML = True
except ImportError:
    HAS_YAML = False

try:
    import paramiko
except ImportError:  # pragma: no cover
    paramiko = None  # type: ignore[assignment]

DEFAULT_BACKUP_DIR = "/tmp/ssl-deploy-backups"
SNAPSHOT_RE = re.compile(r"^\d{8}_\d{6}$")
_ENV_REF = re.compile(r"\$\{env:([A-Za-z_][A-Za-z0-9_]*)\}")
_SAFE_COMPONENT = re.compile(r"[^A-Za-z0-9._-]")


class ServiceType(Enum):
    JKS = "jks"
    APACHE = "apache"
    ASTERISK = "asterisk"
    NGINX = "nginx"
    CUSTOM = "custom"


class DeploymentStatus(Enum):
    PENDING = "pending"
    SUCCESS = "success"
    FAILED = "failed"
    SKIPPED = "skipped"
    ROLLED_BACK = "rolled_back"


@dataclass
class DeploymentResult:
    server: str
    service: str
    status: DeploymentStatus
    message: str = ""
    details: Dict = field(default_factory=dict)


@dataclass
class CopyItem:
    """One file for `copy`: local source, absolute remote destination, optional octal mode."""

    src: Path
    dest: str
    mode: Optional[int] = None


@dataclass
class _Change:
    """One remote file we replaced (or created) during this run."""

    server: str
    path: str
    backup: Optional[str]
    requested: str = ""  # the path as configured (may be a symlink to `path`)


class ConfigError(ValueError):
    """The deploy config is malformed or references something that is missing."""


class DeployError(Exception):
    """A remote step failed; the current service will be reverted."""


# ---------------------------------------------------------------------------
# Config loading
# ---------------------------------------------------------------------------

def _resolve_env_refs(value: Any, where: str) -> Any:
    """Expand `${env:NAME}` so secrets never have to live in the YAML file."""
    if not isinstance(value, str):
        return value

    def _sub(match: "re.Match[str]") -> str:
        name = match.group(1)
        if name not in os.environ:
            raise ConfigError(f"{where}: environment variable {name} is not set")
        return os.environ[name]

    return _ENV_REF.sub(_sub, value)


def resolve_secret_refs(config: Dict[str, Any]) -> Dict[str, Any]:
    """Resolve `${env:NAME}` in the fields that hold secrets (only those)."""
    cfg = dict(config)

    def _fix(section: Any, name: str, keys: Tuple[str, ...]) -> Any:
        if not isinstance(section, dict):
            return section
        out = dict(section)
        for key in keys:
            if key in out:
                out[key] = _resolve_env_refs(out[key], f"{name}.{key}")
        return out

    # Only touch sections that exist: adding `keystore: None` would break configs that
    # legitimately have no keystore block (deploy-only configs).
    if "keystore" in cfg:
        cfg["keystore"] = _fix(cfg["keystore"], "keystore", ("password", "keystore_pass"))
    if "ssh" in cfg:
        cfg["ssh"] = _fix(cfg["ssh"], "ssh", ("password", "key_passphrase"))
    servers = cfg.get("servers")
    if isinstance(servers, dict):
        cfg["servers"] = {
            name: _fix(srv, f"servers.{name}", ("password", "ssh_password", "key_passphrase"))
            for name, srv in servers.items()
        }
    return cfg


def normalize_deploy_config(config: Dict[str, Any]) -> Dict[str, Any]:
    """Merge top-level keystore/ssh defaults; normalize field aliases."""
    if not isinstance(config, dict):
        raise ConfigError("config must be a YAML mapping")
    cfg = dict(config)
    keystore = cfg.get("keystore") or {}
    if not isinstance(keystore, dict):
        raise ConfigError("'keystore' must be a mapping")
    store_pass = keystore.get("password") or keystore.get("keystore_pass")
    alias = keystore.get("alias")

    services = cfg.get("services") or {}
    if not isinstance(services, dict):
        raise ConfigError("'services' must be a mapping")
    normalized_services: Dict[str, Any] = {}
    for name, svc in services.items():
        if not isinstance(svc, dict):
            raise ConfigError(f"service '{name}' must be a mapping")
        entry = dict(svc)
        if entry.get("type") == "jks":
            entry.setdefault("keystore_path", entry.pop("remote_path", None))
            if store_pass and "keystore_pass" not in entry:
                entry["keystore_pass"] = store_pass
            if alias and "alias" not in entry:
                entry["alias"] = alias
        entry.setdefault("restart_cmd", entry.pop("restart", None))
        normalized_services[name] = entry
    cfg["services"] = normalized_services

    ssh_defaults = cfg.get("ssh") or {}
    if not isinstance(ssh_defaults, dict):
        raise ConfigError("'ssh' must be a mapping")
    servers = cfg.get("servers") or {}
    if not isinstance(servers, dict):
        raise ConfigError("'servers' must be a mapping")
    normalized_servers: Dict[str, Any] = {}
    for name, srv in servers.items():
        if not isinstance(srv, dict):
            raise ConfigError(f"server '{name}' must be a mapping")
        entry = dict(srv)
        legacy_key = entry.pop("ssh_key", None)
        # A server that borrows its settings from ~/.ssh/config (ssh_alias) keeps those; the
        # `ssh:` defaults are applied later, only for what the alias does not define.
        has_alias = bool(entry.get("ssh_alias"))
        if not entry.get("key_file"):
            entry["key_file"] = legacy_key or (
                None if has_alias else (ssh_defaults.get("key") or ssh_defaults.get("key_file"))
            )
        if not has_alias:
            entry.setdefault("user", ssh_defaults.get("user", "root"))
            entry.setdefault("port", ssh_defaults.get("port", 22))
        password = entry.pop("ssh_password", None) or entry.get("password") or ssh_defaults.get("password")
        if password:
            entry["password"] = password
        if "host_key_sha256" not in entry and ssh_defaults.get("host_key_sha256"):
            entry["host_key_sha256"] = ssh_defaults["host_key_sha256"]
        normalized_servers[name] = entry
    cfg["servers"] = normalized_servers
    return cfg


def load_deploy_config(config_path: Path, catalogue_path: Path | None = None) -> Dict[str, Any]:
    if not HAS_YAML:
        raise RuntimeError("PyYAML not installed. Run: pip install pyyaml")
    text = config_path.read_text(encoding="utf-8-sig")
    config = yaml.safe_load(text) or {}
    if not isinstance(config, dict):
        raise ConfigError(f"{config_path.name}: top level must be a mapping")
    config = resolve_secret_refs(config)
    config = expand_ameyo_profile(config, catalogue_path)
    return normalize_deploy_config(config)


def _safe_component(name: str) -> str:
    return _SAFE_COMPONENT.sub("_", str(name)) or "_"


def _contains_private_key(path: Path) -> bool:
    try:
        with open(path, "rb") as fh:
            head = fh.read(65536)
    except OSError:
        return False
    return any(marker in head for marker in KEY_PATTERNS)


# ---------------------------------------------------------------------------
# Deployer
# ---------------------------------------------------------------------------

class SSLDeployer:
    BACKUP_DIR = DEFAULT_BACKUP_DIR

    def __init__(
        self,
        config_path: str | Path,
        cert_path: str | Path | None = None,
        *,
        dry_run: bool = False,
        verbose: bool = False,
        no_restart: bool = False,
        parallel: bool = False,
        terminal: Terminal | None = None,
        host_key_policy: str | None = None,
        known_hosts_path: str | Path | None = None,
        skip_verify: bool = False,
        auto_rollback: bool = True,
        key_password: str | None = None,
        password_prompt: Callable[[Dict[str, Any]], Optional[str]] | None = None,
        ssh_config_path: str | Path | None = None,
        config: Dict[str, Any] | None = None,
    ) -> None:
        self.config_path = Path(config_path)
        self.cert_path = Path(cert_path) if cert_path else None
        self.dry_run = dry_run
        self.verbose = verbose
        self.no_restart = no_restart
        self.parallel = parallel
        self.term = terminal or Terminal()
        self.skip_verify = skip_verify
        self.auto_rollback = auto_rollback
        self.key_password = key_password
        self.password_prompt = password_prompt
        self._ssh_config_path = Path(ssh_config_path) if ssh_config_path else None
        self._ssh_config: Any = None
        self._ssh_config_loaded = False
        self._typed_passwords: Dict[Tuple[Any, Any, Any], str] = {}
        self._preloaded_config = config  # ad-hoc runs (copy --host) pass the config directly
        self._cli_host_key_policy = host_key_policy
        self.known_hosts_path = Path(known_hosts_path) if known_hosts_path else default_known_hosts_path()
        self.config: Dict[str, Any] = {}
        self.results: List[DeploymentResult] = []
        self.ssh_connections: Dict[str, RemoteHost] = {}
        self.aborted_reason: Optional[str] = None
        self.timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        self._deployed_paths: set = set()
        self._backup_ready: set = set()
        self._failed_hosts: Dict[str, str] = {}
        self._lock = threading.RLock()
        self._secrets: List[str] = []
        logging.basicConfig(
            level=logging.DEBUG if verbose else logging.WARNING,
            format="%(levelname)s: %(message)s",
        )
        self.logger = logging.getLogger(__name__)

    # -- config ---------------------------------------------------------

    @property
    def backup_dir(self) -> str:
        configured = self.config.get("backup_dir") if self.config else None
        return validate_remote_path(configured or self.BACKUP_DIR, "backup_dir").rstrip("/")

    @property
    def host_key_policy(self) -> str:
        policy = self._cli_host_key_policy or (self.config.get("ssh") or {}).get(
            "host_key_policy", POLICY_STRICT
        )
        if policy not in VALID_HOST_KEY_POLICIES:
            raise ConfigError(
                f"ssh.host_key_policy must be one of {', '.join(VALID_HOST_KEY_POLICIES)} (got {policy!r})"
            )
        return policy

    def load_config(self) -> bool:
        try:
            if self._preloaded_config is not None:
                self.config = normalize_deploy_config(resolve_secret_refs(self._preloaded_config))
            else:
                self.config = load_deploy_config(self.config_path)
            self._collect_secrets()
            self.host_key_policy  # validate early
            return True
        except Exception as exc:
            self.term.error(f"Failed to load config: {self._mask(str(exc))}")
            return False

    def _collect_secrets(self) -> None:
        secrets: List[str] = []
        keystore = self.config.get("keystore") or {}
        for key in ("password", "keystore_pass"):
            if keystore.get(key):
                secrets.append(str(keystore[key]))
        for srv in (self.config.get("servers") or {}).values():
            for key in ("password", "key_passphrase"):
                if isinstance(srv, dict) and srv.get(key):
                    secrets.append(str(srv[key]))
        for svc in (self.config.get("services") or {}).values():
            if isinstance(svc, dict) and svc.get("keystore_pass"):
                secrets.append(str(svc["keystore_pass"]))
        env_pw = os.environ.get("SSH_PASSWORD")
        if env_pw:
            secrets.append(env_pw)
        # Longest first so a password containing another is fully masked.
        self._secrets = sorted({s for s in secrets if len(s) >= 4}, key=len, reverse=True)

    def _mask(self, text: str) -> str:
        """Never print known passwords (config, env) in logs or error output."""
        for secret in self._secrets:
            text = text.replace(secret, "****")
        return text

    def validate_config(self) -> bool:
        """Validate configuration with graceful handling of missing sections."""
        servers = self.config.get("servers")
        services = self.config.get("services")

        if not servers:
            self.term.warn("No servers defined in config - deploy will be skipped")
            return True

        if not services:
            self.term.warn("No services defined in config - deploy will have no effect")
            return True

        ok = True
        for server_name, server_cfg in servers.items():
            if not isinstance(server_cfg, dict):
                self.term.warn(f"Server '{server_name}' has invalid config, skipping")
                continue
            if not (server_cfg.get("host") or server_cfg.get("ssh_alias")):
                self.term.error(f"Server '{server_name}' has no 'host' (or 'ssh_alias')")
                ok = False
            for svc_name in server_cfg.get("services", []):
                if svc_name not in services:
                    self.term.warn(f"Server '{server_name}' references undefined service '{svc_name}'")
        return ok

    # -- local certificate discovery & verification ----------------------

    _SECRET_FREE_TYPES = ("certificate", "chain", "fullchain", "ca_crt")

    def validate_cert_files(self) -> Dict[str, Path]:
        if not self.cert_path or not self.cert_path.exists():
            self.term.error(f"Certificate path not found: {self.cert_path}")
            return {}

        cert_files: Dict[str, Path] = {}
        domain = self.config.get("domain", "")
        patterns = {
            "private_key": [f"{domain}.key", "private.key", "*.key"],
            "certificate": [f"main_{domain}.crt", f"{domain}.crt", "certificate.crt", "*.crt"],
            "chain": [f"intermediate_{domain}.crt", "chain.crt", "crm-ca.crt", f"{domain}.ca-bundle", "ca-bundle.crt"],
            "fullchain": [f"{domain}.pem", "fullchain.pem", "*.pem"],
            "jks": [f"{domain}.jks", "keystore.jks", "*.jks"],
            "p12": ["keystore.p12", f"{domain}.p12", "*.p12"],
            "asterisk_key": ["asterisk.key", f"asterisk_{domain}.key"],
            "asterisk_crt": [f"asterisk_{domain}.crt", "asterisk.crt"],
            "asterisk_pem": [f"asterisk_{domain}.pem", "asterisk.pem"],
            "ca_crt": ["crm-ca.crt", "ca.crt", "root*.crt"],
        }

        for cert_type, file_patterns in patterns.items():
            for pattern in file_patterns:
                if "*" in pattern:
                    candidates = sorted(p for p in self.cert_path.glob(pattern) if p.is_file())
                else:
                    candidate = self.cert_path / pattern
                    candidates = [candidate] if candidate.is_file() else []
                # A file holding a private key must never be picked up as a
                # public cert/chain: it would be deployed world-readable.
                if cert_type in self._SECRET_FREE_TYPES:
                    candidates = [c for c in candidates if not _contains_private_key(c)]
                if candidates:
                    cert_files[cert_type] = candidates[0]
                    break
        return cert_files

    def _report_findings(self, findings: List[Any]) -> None:
        for finding in findings:
            if finding.level == LEVEL_ERROR:
                self.term.error(f"  [FAIL] {finding.message}")
            elif finding.level == LEVEL_WARN:
                self.term.warn(f"  [WARN] {finding.message}")
            else:
                self.term.detail(f"[ok] {finding.message}")

    def _abort(self, message: str) -> List[DeploymentResult]:
        """Stop the whole deploy and make sure the exit code reflects it."""
        self.aborted_reason = message
        self.term.error(message)
        self.results.append(DeploymentResult("*", "*", DeploymentStatus.FAILED, message))
        return self.results

    # -- SSH ------------------------------------------------------------

    def _ssh_password(self, server_config: Dict[str, Any]) -> str | None:
        return server_config.get("password") or os.environ.get("SSH_PASSWORD")

    def _get_ssh_config(self) -> Any:
        """~/.ssh/config, parsed once and only when a server needs it."""
        if not self._ssh_config_loaded:
            configured = (self.config.get("ssh") or {}).get("config_file")
            path = self._ssh_config_path or (Path(os.path.expanduser(str(configured))) if configured else None)
            self._ssh_config = load_ssh_config(path)
            self._ssh_config_loaded = True
        return self._ssh_config

    def _route(self, server_name: str) -> Tuple[Dict[str, Any], List[Dict[str, Any]]]:
        """(effective target settings, jump hops) for `server_name`; ValueError if unusable."""
        servers = self.config.get("servers") or {}
        cfg = servers.get(server_name)
        if cfg is None:
            raise ValueError(f"Server '{server_name}' not found in config")
        return resolve_hops(
            server_name, cfg, servers, self._get_ssh_config(), self.config.get("ssh") or {}
        )

    def _prompt_password(self, hop: Dict[str, Any]) -> Optional[str]:
        """Ask once per user@host:port (and mask it from then on). Only called after keys
        and the agent were refused by that host."""
        if self.password_prompt is None:
            return None
        key = (hop.get("user"), hop.get("host"), hop.get("port"))
        with self._lock:
            if key in self._typed_passwords:
                return self._typed_passwords[key]
        typed = self.password_prompt(hop)
        if typed:
            with self._lock:
                self._typed_passwords[key] = typed
                if len(typed) >= 4 and typed not in self._secrets:
                    self._secrets = sorted(self._secrets + [typed], key=len, reverse=True)
        return typed

    def _drop_missing_keys(self, hops: List[Dict[str, Any]], target: Dict[str, Any]) -> None:
        for hop in list(hops) + [target]:
            key_file = hop.get("key_file")
            if key_file and not expand_user(key_file).is_file():
                self.term.warn(
                    f"SSH key {key_file} not found for {hop.get('name', hop.get('host'))}; "
                    "falling back to agent/default keys"
                )
                hop["key_file"] = None

    def connect_server(self, server_name: str, *, force: bool = False) -> RemoteHost | None:
        """Connect (cached), through any jump hosts. `force` connects even in dry-run."""
        if self.dry_run and not force:
            try:
                target, hops = self._route(server_name)
            except ValueError as exc:
                self.term.error(f"Cannot plan the connection to '{server_name}': {exc}")
                return None
            self.term.detail(f"[DRY-RUN] Would connect to {describe_route(hops, target)}")
            return None
        if not HAS_PARAMIKO:
            self.term.error("paramiko not installed. Run: pip install paramiko")
            return None

        with self._lock:
            if server_name in self.ssh_connections:
                return self.ssh_connections[server_name]
            if server_name in self._failed_hosts:
                return None

            try:
                target, hops = self._route(server_name)
            except ValueError as exc:
                self._failed_hosts[server_name] = str(exc)
                self.term.error(f"Cannot connect to '{server_name}': {exc}")
                return None
            self._drop_missing_keys(hops, target)
            if hops:
                self.term.detail(f"route: {describe_route(hops, target)}")
            try:
                client = connect_chain(
                    hops,
                    target,
                    policy=self.host_key_policy,
                    known_hosts_path=self.known_hosts_path,
                    target_password=self._ssh_password(target),
                    password_for=self._prompt_password,
                    key_passphrase=target.get("key_passphrase") or os.environ.get("SSH_KEY_PASSPHRASE"),
                    notice=self.term.warn,
                )
            except HostKeyVerificationError as exc:
                message = str(exc)
            except Exception as exc:
                if paramiko is not None and isinstance(exc, paramiko.BadHostKeyException):
                    message = (
                        f"HOST KEY CHANGED: {exc}. This can mean a man-in-the-middle "
                        f"attack, or that the server was rebuilt. Verify out-of-band, then remove the "
                        f"old entry from ~/.ssh/known_hosts / {self.known_hosts_path}."
                    )
                else:
                    message = str(exc)
            else:
                remote = RemoteHost(client, server_name)
                self.ssh_connections[server_name] = remote
                return remote

            message = self._mask(message)
            self._failed_hosts[server_name] = message
            via = f" (route: {describe_route(hops, target)})" if hops else ""
            self.term.error(f"Failed to connect to {target.get('host')}{via}: {message}")
            return None

    def execute_remote(
        self,
        ssh: RemoteHost | None,
        command: str,
        *,
        check_error: bool = True,
        stdin_data: str | None = None,
    ) -> Tuple[int, str, str]:
        if self.dry_run or ssh is None:
            self.term.detail(f"[DRY-RUN] Would execute: {self._mask(command)}")
            return 0, "", ""
        try:
            exit_code, stdout_str, stderr_str = ssh.run(
                command, timeout=DEFAULT_COMMAND_IDLE_TIMEOUT, stdin_data=stdin_data
            )
        except Exception as exc:
            self.logger.error("Command execution failed: %s", self._mask(str(exc)))
            return -1, "", self._mask(str(exc))
        if check_error and exit_code != 0:
            self.logger.warning("Command failed (%s): %s", exit_code, self._mask(stderr_str))
        return exit_code, stdout_str, stderr_str

    # -- remote file primitives -------------------------------------------

    @staticmethod
    def _stat_or_none(sftp: Any, path: str) -> Any:
        try:
            return sftp.stat(path)
        except FileNotFoundError:
            return None
        except IOError as exc:
            if getattr(exc, "errno", None) == errno.ENOENT:
                return None
            raise

    def _resolve_target(self, sftp: Any, remote_path: str) -> str:
        """If the destination is a symlink, write to what it points at (the old
        in-place behaviour) instead of replacing the link with a regular file."""
        try:
            lst = sftp.lstat(remote_path)
        except FileNotFoundError:
            return remote_path
        except IOError as exc:
            if getattr(exc, "errno", None) == errno.ENOENT:
                return remote_path
            raise
        if stat_mod.S_ISLNK(lst.st_mode):
            return sftp.normalize(remote_path)
        return remote_path

    def _mkdir_p(self, sftp: Any, directory: str) -> None:
        missing: List[str] = []
        current = directory
        while current not in ("", "/"):
            if self._stat_or_none(sftp, current) is not None:
                break
            missing.append(current)
            current = posixpath.dirname(current)
        for path in reversed(missing):
            sftp.mkdir(path, 0o755)

    def _ensure_backup_root(self, ssh: RemoteHost | None, server_name: str) -> None:
        """The backup tree holds copies of private keys and is what rollback
        trusts, so it must be a real directory owned by us and closed to others."""
        if self.dry_run or ssh is None:
            return
        with self._lock:
            if server_name in self._backup_ready:
                return
        base = self.backup_dir
        command = (
            f"umask 077; mkdir -p -- {q(base)} && [ -d {q(base)} ] && [ ! -L {q(base)} ] "
            f"&& [ -O {q(base)} ] && chmod 700 {q(base)}"
        )
        code, _out, err = self.execute_remote(ssh, command, check_error=False)
        if code != 0:
            raise DeployError(
                f"backup directory {base} is not a private directory owned by the SSH user "
                f"({err.strip() or 'check failed'}); refusing to deploy without safe backups. "
                f"Set 'backup_dir' in the config to a directory you own."
            )
        with self._lock:
            self._backup_ready.add(server_name)

    def backup_remote_file(
        self, ssh: RemoteHost | None, remote_path: str, server_name: str
    ) -> Optional[str]:
        """Back up `remote_path`. Returns the backup path, or None if the file
        did not exist. Raises DeployError if an existing file cannot be saved."""
        validate_remote_path(remote_path, "destination")
        # Preserve the full original path under the snapshot dir so two files with
        # the same name in different directories never collide and rollback can
        # restore to the exact original path.
        if self.dry_run or ssh is None:
            planned = f"{self.backup_dir}/{_safe_component(server_name)}/{self.timestamp}{remote_path}"
            self.term.detail(f"[DRY-RUN] Would backup {remote_path} -> {planned}")
            return planned
        sftp = ssh.sftp()
        real = self._resolve_target(sftp, remote_path)
        attrs = self._stat_or_none(sftp, real)
        if attrs is None:
            return None
        if stat_mod.S_ISDIR(attrs.st_mode):
            raise DeployError(f"destination {real} is a directory")
        self._ensure_backup_root(ssh, server_name)
        backup_path = f"{self.backup_dir}/{_safe_component(server_name)}/{self.timestamp}{real}"
        # `A && B || C`: copy only if no backup of this path exists yet in this snapshot.
        # Two deploys in the same second share a snapshot folder; the *first* backup is the
        # true original, so a later one must never overwrite it.
        command = (
            f"umask 077; mkdir -p -- {q(posixpath.dirname(backup_path))} "
            f"&& [ -e {q(backup_path)} ] || cp -p -- {q(real)} {q(backup_path)}"
        )
        code, _out, err = self.execute_remote(ssh, command, check_error=False)
        if code != 0:
            raise DeployError(
                f"could not back up {real} ({err.strip() or f'exit {code}'}); refusing to overwrite it"
            )
        return backup_path

    def _upload_atomic(
        self, ssh: RemoteHost, local_path: Path, remote_path: str, mode: int
    ) -> Tuple[str, str]:
        """Upload via a 0600 temp file in the same directory, then rename into place.

        Returns (real_path, local_sha256). The owner/group of an existing file
        is preserved; the final mode is applied before the rename, so the file
        is never visible with the wrong permissions or half written.
        """
        sftp = ssh.sftp()
        data = Path(local_path).read_bytes()
        want_sha = hashlib.sha256(data).hexdigest()
        if _contains_private_key(Path(local_path)) and mode & 0o007:
            mode = 0o600  # never ship key material world-accessible (group access only if asked for)

        real = self._resolve_target(sftp, remote_path)
        directory = posixpath.dirname(real)
        self._mkdir_p(sftp, directory)
        existing = self._stat_or_none(sftp, real)
        if existing is not None and stat_mod.S_ISDIR(existing.st_mode):
            raise DeployError(f"destination {real} is a directory")

        tmp = f"{directory}/.{posixpath.basename(real)}.ssl-auto-{uuid.uuid4().hex[:8]}.tmp"
        try:
            with sftp.open(tmp, "wb") as handle:
                sftp.chmod(tmp, 0o600)  # before any data is written
                handle.write(data)
            in_place = False
            if existing is not None:
                tmp_attrs = sftp.stat(tmp)
                if (tmp_attrs.st_uid, tmp_attrs.st_gid) != (existing.st_uid, existing.st_gid):
                    try:
                        sftp.chown(tmp, existing.st_uid, existing.st_gid)
                    except (IOError, OSError):
                        in_place = True  # cannot keep the owner via rename
            sftp.chmod(tmp, mode)
            if sftp.stat(tmp).st_size != len(data):
                raise DeployError(f"upload of {real} was truncated")
            if in_place:
                with sftp.open(real, "wb") as handle:
                    handle.write(data)
                sftp.chmod(real, mode)
                self._remove_quietly(sftp, tmp)
            else:
                try:
                    sftp.posix_rename(tmp, real)
                except (IOError, OSError):
                    code, _o, err = self.execute_remote(
                        ssh, f"mv -f -- {q(tmp)} {q(real)}", check_error=False
                    )
                    if code != 0:
                        raise DeployError(f"could not move {tmp} into place: {err.strip()}")
        except BaseException:
            self._remove_quietly(sftp, tmp)
            raise
        return real, want_sha

    @staticmethod
    def _remove_quietly(sftp: Any, path: str) -> None:
        try:
            sftp.remove(path)
        except (IOError, OSError):
            pass

    def _verify_remote_hash(self, ssh: RemoteHost, real: str, want_sha: str) -> None:
        code, out, _err = self.execute_remote(ssh, f"sha256sum -- {q(real)}", check_error=False)
        if code != 0 or not out.strip():
            return  # no sha256sum on the host: the size check already ran
        got = out.split()[0].lower()
        if got != want_sha:
            raise DeployError(f"checksum mismatch after uploading {real}")

    def upload_file(
        self, ssh: RemoteHost | None, local_path: Path, remote_path: str, mode: int = 0o644
    ) -> bool:
        """Compatibility wrapper: upload one file, True on success."""
        if self.dry_run or ssh is None:
            self.term.detail(f"[DRY-RUN] Would upload {Path(local_path).name} -> {remote_path}")
            return True
        try:
            validate_remote_path(remote_path, "destination")
            real, want = self._upload_atomic(ssh, Path(local_path), remote_path, mode)
            self._verify_remote_hash(ssh, real, want)
            return True
        except (DeployError, ValueError, IOError, OSError) as exc:
            self.logger.error("Upload failed: %s", self._mask(str(exc)))
            return False

    def _sync_file(
        self,
        ssh: RemoteHost | None,
        server_name: str,
        local_path: Path,
        remote_path: str,
        mode: int = 0o644,
        changes: Optional[List[_Change]] = None,
    ) -> None:
        """Backup + upload one remote file, deduped per (server, path) for this
        run so services sharing a destination (e.g. one JKS read by several
        Tomcat services) are backed up/uploaded once. Raises DeployError."""
        try:
            validate_remote_path(remote_path, "destination")
        except ValueError as exc:
            raise DeployError(str(exc)) from exc
        if remote_path.endswith("/"):
            raise DeployError(
                f"destination {remote_path!r} is a directory path, not a file "
                "(is a name in the config - e.g. ca_bundle_legacy - empty?)"
            )
        key = (server_name, remote_path)
        with self._lock:
            if key in self._deployed_paths:
                self.term.detail(f"  (already deployed this run: {remote_path})")
                return
        if self.dry_run or ssh is None:
            self.backup_remote_file(ssh, remote_path, server_name)
            self.term.detail(f"[DRY-RUN] Would upload {Path(local_path).name} -> {remote_path}")
            with self._lock:
                self._deployed_paths.add(key)
            return
        try:
            real = self._resolve_target(ssh.sftp(), remote_path)
            backup = self.backup_remote_file(ssh, real, server_name)
            # Record the change *before* touching the file: whatever fails from
            # here on (upload, rename, checksum), the service-level revert can
            # put the original back. Restoring an untouched file is harmless.
            if changes is not None:
                changes.append(_Change(server_name, real, backup, remote_path))
            real, want_sha = self._upload_atomic(ssh, Path(local_path), real, mode)
            with self._lock:
                self._deployed_paths.add(key)
            self._verify_remote_hash(ssh, real, want_sha)
        except DeployError:
            raise
        except (IOError, OSError, ValueError) as exc:
            raise DeployError(f"upload to {remote_path} failed: {exc}") from exc

    def _restore_command(self, backup: Optional[str], path: str) -> str:
        if backup:
            tmp = f"{path}.ssl-auto-restore"
            return f"cp -p -- {q(backup)} {q(tmp)} && mv -f -- {q(tmp)} {q(path)}"
        return f"rm -f -- {q(path)}"  # the file did not exist before this run

    def _revert_changes(self, ssh: RemoteHost | None, changes: List[_Change], reason: str) -> bool:
        """Undo this run's changes (newest first). Returns True if all restored."""
        if not changes or ssh is None or self.dry_run:
            return True
        self.term.warn(f"  reverting {len(changes)} file(s) on {changes[0].server}: {reason}")
        ok = True
        for change in reversed(changes):
            code, _o, err = self.execute_remote(
                ssh, self._restore_command(change.backup, change.path), check_error=False
            )
            with self._lock:
                self._deployed_paths.discard((change.server, change.requested or change.path))
            if code != 0:
                ok = False
                self.term.error(f"  FAILED to restore {change.path}: {self._mask(err.strip())}")
        return ok

    # -- per-service deployers ------------------------------------------

    def _failed(self, server: str, service: str, message: str) -> DeploymentResult:
        return DeploymentResult(server, service, DeploymentStatus.FAILED, message)

    def deploy_jks(
        self,
        ssh: Any,
        server_name: str,
        service_name: str,
        service_config: Dict,
        cert_files: Dict[str, Path],
        changes: Optional[List[_Change]] = None,
    ) -> DeploymentResult:
        keystore_path = service_config.get("keystore_path")
        keystore_pass = service_config.get("keystore_pass", "changeit")
        alias = service_config.get("alias", "server")
        if "jks" not in cert_files:
            return self._failed(server_name, service_name, "JKS file not found")
        if not keystore_path:
            return self._failed(server_name, service_name, "no remote_path configured")
        self._sync_file(ssh, server_name, cert_files["jks"], keystore_path, mode=0o600, changes=changes)
        if not self.dry_run and ssh and service_config.get("verify_keystore", True):
            self._verify_remote_keystore(ssh, keystore_path, keystore_pass, alias, service_config)
        return DeploymentResult(
            server_name, service_name, DeploymentStatus.SUCCESS, f"JKS -> {keystore_path}"
        )

    def _verify_remote_keystore(
        self, ssh: RemoteHost, keystore_path: str, password: str, alias: str, service_config: Dict
    ) -> None:
        """Open the uploaded keystore with the configured password/alias *before*
        anything is restarted. The password goes over stdin, not the command line."""
        keytool = service_config.get("keytool", "keytool")
        command = f"{q(keytool)} -list -keystore {q(keystore_path)} -alias {q(alias)}"
        code, out, err = self.execute_remote(
            ssh, command, check_error=False, stdin_data=f"{password}\n"
        )
        if code == 0:
            return
        if code == 127 or "not found" in err.lower():
            self.term.warn(
                f"  keytool not found on the server; skipped keystore check of {keystore_path}"
            )
            return
        detail = self._mask((err or out).strip().splitlines()[-1] if (err or out).strip() else f"exit {code}")
        raise DeployError(
            f"uploaded keystore {keystore_path} does not open with the configured "
            f"password/alias '{alias}': {detail}"
        )

    def _resolve_apache_paths(self, service_config: Dict) -> Tuple[str, str, str]:
        domain = self.config.get("domain", "server")
        ssl_dir = service_config.get("ssl_dir")
        cert_path = service_config.get("cert_path", "/etc/pki/tls/certs/")
        key_path = service_config.get("key_path", "/etc/pki/tls/private/")
        cert_file = service_config.get("cert_file", f"{domain}.crt")
        key_file = service_config.get("key_file", f"{domain}.key")
        chain_file = service_config.get("chain_file", "chain.crt")
        if ssl_dir:
            base = ssl_dir.rstrip("/")
            return f"{base}/{cert_file}", f"{base}/{key_file}", f"{base}/{chain_file}"
        return (
            f"{cert_path.rstrip('/')}/{cert_file}",
            f"{key_path.rstrip('/')}/{key_file}",
            f"{cert_path.rstrip('/')}/{chain_file}",
        )

    def deploy_apache(
        self,
        ssh: Any,
        server_name: str,
        service_name: str,
        service_config: Dict,
        cert_files: Dict[str, Path],
        changes: Optional[List[_Change]] = None,
    ) -> DeploymentResult:
        cert_remote, key_remote, chain_remote = self._resolve_apache_paths(service_config)
        for req in ("certificate", "private_key"):
            if req not in cert_files:
                return self._failed(server_name, service_name, f"Missing {req}")
        # Key first: if only the cert were replaced, a failure here would leave a
        # mismatched pair on disk (the service-level revert covers that too).
        self._sync_file(ssh, server_name, cert_files["private_key"], key_remote, mode=0o600, changes=changes)
        self._sync_file(ssh, server_name, cert_files["certificate"], cert_remote, changes=changes)
        chain_file = cert_files.get("chain") or cert_files.get("ca_crt")
        if chain_file:
            self._sync_file(ssh, server_name, chain_file, chain_remote, changes=changes)
        deploy_dir = posixpath.dirname(cert_remote)
        return DeploymentResult(
            server_name, service_name, DeploymentStatus.SUCCESS, f"Apache -> {deploy_dir}/"
        )

    def deploy_asterisk(
        self,
        ssh: Any,
        server_name: str,
        service_name: str,
        service_config: Dict,
        cert_files: Dict[str, Path],
        changes: Optional[List[_Change]] = None,
    ) -> DeploymentResult:
        cert_dir = service_config.get("cert_dir", "/etc/asterisk/keys/")
        mappings = {
            "asterisk_key": ("asterisk.key", 0o600),
            "asterisk_crt": ("asterisk.crt", 0o644),
            "asterisk_pem": ("asterisk.pem", 0o600),
        }
        # No fallback for the combined PEM: Ameyo/Asterisk needs the private key
        # FIRST in asterisk.pem, and a chain-only file would break WSS silently.
        fallbacks = {"asterisk_key": "private_key", "asterisk_crt": "certificate"}
        uploaded: list[str] = []
        for file_type, (filename, mode) in mappings.items():
            source = cert_files.get(file_type)
            if source is None and file_type in fallbacks:
                source = cert_files.get(fallbacks[file_type])
            if not source:
                continue
            if file_type == "asterisk_pem" and not self._pem_is_key_first(source):
                return self._failed(
                    server_name, service_name,
                    f"{Path(source).name} must have the private key before the certificates",
                )
            remote_path = f"{cert_dir.rstrip('/')}/{filename}"
            self._sync_file(ssh, server_name, source, remote_path, mode=mode, changes=changes)
            uploaded.append(filename)
        if not uploaded:
            return self._failed(server_name, service_name, "No Asterisk files found")
        return DeploymentResult(
            server_name, service_name, DeploymentStatus.SUCCESS, f"Asterisk: {', '.join(uploaded)}"
        )

    @staticmethod
    def _pem_is_key_first(path: Path) -> bool:
        try:
            text = Path(path).read_bytes().decode("utf-8", errors="replace")
        except OSError:
            return False
        key_pos = min((text.find(m.decode()) for m in KEY_PATTERNS if m.decode() in text), default=-1)
        cert_pos = text.find("-----BEGIN CERTIFICATE-----")
        return key_pos >= 0 and (cert_pos < 0 or key_pos < cert_pos)

    def deploy_nginx(
        self,
        ssh: Any,
        server_name: str,
        service_name: str,
        service_config: Dict,
        cert_files: Dict[str, Path],
        changes: Optional[List[_Change]] = None,
    ) -> DeploymentResult:
        cert_path = service_config.get("cert_path", "/etc/nginx/ssl/")
        domain = self.config.get("domain", "server")
        cert_name = service_config.get("cert_file", f"{domain}.crt")
        key_name = service_config.get("key_file", f"{domain}.key")
        use_fullchain = bool(service_config.get("use_fullchain")) or "fullchain" in str(cert_name).lower()
        cert_source = (cert_files.get("fullchain") if use_fullchain else None) or cert_files.get("certificate")
        if not cert_source or "private_key" not in cert_files:
            return self._failed(server_name, service_name, "Missing cert/key")
        cert_remote = f"{cert_path.rstrip('/')}/{cert_name}"
        key_remote = f"{cert_path.rstrip('/')}/{key_name}"
        self._sync_file(ssh, server_name, cert_files["private_key"], key_remote, mode=0o600, changes=changes)
        self._sync_file(ssh, server_name, cert_source, cert_remote, changes=changes)
        return DeploymentResult(
            server_name, service_name, DeploymentStatus.SUCCESS, f"Nginx -> {cert_path}"
        )

    def deploy_custom(
        self,
        ssh: Any,
        server_name: str,
        service_name: str,
        service_config: Dict,
        cert_files: Dict[str, Path],
        changes: Optional[List[_Change]] = None,
    ) -> DeploymentResult:
        file_mappings = service_config.get("file_mappings", {})
        if not file_mappings:
            return self._failed(server_name, service_name, "No file_mappings for custom service")
        uploaded: list[str] = []
        for source_type, destinations in file_mappings.items():
            if source_type not in cert_files:
                continue
            mode = 0o600 if "key" in source_type.lower() else 0o644
            # A destination may be a single path or a list, so one source file
            # (e.g. a CA bundle) can be written under more than one filename.
            dest_list = destinations if isinstance(destinations, list) else [destinations]
            for remote_path in dest_list:
                self._sync_file(
                    ssh, server_name, cert_files[source_type], remote_path, mode=mode, changes=changes
                )
                uploaded.append(remote_path)
        if not uploaded:
            return self._failed(server_name, service_name, "No files deployed")
        return DeploymentResult(
            server_name, service_name, DeploymentStatus.SUCCESS, f"Deployed {len(uploaded)} file(s)"
        )

    def copy_files(
        self,
        server_name: str,
        items: List[CopyItem],
        *,
        check_cmd: str | None = None,
        reload_cmd: str | None = None,
        skip_verify: bool = False,
    ) -> List[DeploymentResult]:
        """scp-style copy with this tool's safety: verified, atomic, backed up, reversible.

        Nothing is touched unless the sources look sane; every replaced file is backed up;
        if any file or the optional `check_cmd` fails, everything copied so far is restored.
        `reload_cmd` runs only after a successful copy (its failure is reported, not undone)."""
        self._deployed_paths.clear()
        self.aborted_reason = None
        if not items:
            return self._abort("Nothing to copy")
        for item in items:
            if not Path(item.src).is_file():
                return self._abort(f"Source file not found: {item.src}")
            try:
                validate_remote_path(item.dest, "destination")
            except ValueError as exc:
                return self._abort(str(exc))
            if item.dest.endswith("/"):
                return self._abort(
                    f"Destination {item.dest!r} is a directory; give the full file path "
                    f"(for example {item.dest}{Path(item.src).name})"
                )

        if not (skip_verify or self.skip_verify):
            findings = verify_copy_sources([Path(i.src) for i in items], key_password=self.key_password)
            self._report_findings(findings)
            if has_errors(findings):
                return self._abort(
                    "Pre-copy verification FAILED - nothing was copied (--skip-verify overrides)"
                )

        try:
            target, _hops = self._route(server_name)
        except ValueError as exc:
            return self._abort(str(exc))
        if not self.config.get("backup_dir"):
            # One shared /tmp folder breaks as soon as two different users deploy to a host.
            self.config["backup_dir"] = f"/tmp/ssl-auto-backups-{_safe_component(target.get('user', 'root'))}"

        ssh = self.connect_server(server_name)
        if not ssh and not self.dry_run:
            reason = self._failed_hosts.get(server_name, "unknown error")
            return self._abort(f"SSH connection failed: {reason}")

        changes: List[_Change] = []
        copied: List[CopyItem] = []
        try:
            self._ensure_backup_root(ssh, server_name)
            for item in items:
                mode = item.mode
                if mode is None:
                    mode = 0o600 if _contains_private_key(Path(item.src)) else 0o644
                self._sync_file(ssh, server_name, Path(item.src), item.dest, mode=mode, changes=changes)
                copied.append(item)
            if check_cmd:
                code, _out, err = self.execute_remote(ssh, check_cmd, check_error=False)
                if code != 0:
                    detail = self._mask(err.strip()[:300]) or "no error output"
                    raise DeployError(f"check command failed (exit {code}): {detail}")
        except DeployError as exc:
            restored = self._revert_changes(ssh, changes, str(exc))
            note = "files restored" if restored else "RESTORE FAILED - run rollback"
            self.results.append(
                DeploymentResult(server_name, "copy", DeploymentStatus.FAILED, f"{self._mask(str(exc))} ({note})")
            )
            self.close_connections()
            return self.results

        for item in copied:
            self.results.append(
                DeploymentResult(server_name, item.dest, DeploymentStatus.SUCCESS, f"{Path(item.src).name} -> {item.dest}")
            )
        if reload_cmd:
            code, _out, err = self.execute_remote(ssh, reload_cmd, check_error=False)
            if code != 0:
                detail = self._mask(err.strip()[:300]) or "no error output"
                self.results.append(DeploymentResult(
                    server_name, "reload", DeploymentStatus.FAILED,
                    f"reload command failed (exit {code}): {detail} - the files were copied; "
                    f"run 'rollback' to undo",
                ))
        self.close_connections()
        return self.results

    def deploy_service(
        self, server_name: str, service_name: str, cert_files: Dict[str, Path]
    ) -> DeploymentResult:
        service_config = (self.config.get("services") or {}).get(service_name)
        if not service_config:
            return self._failed(server_name, service_name, f"Service '{service_name}' not in config")
        try:
            service_type = ServiceType(service_config.get("type", "custom"))
        except ValueError:
            self.term.warn(
                f"Service '{service_name}': unknown type {service_config.get('type')!r}, using 'custom'"
            )
            service_type = ServiceType.CUSTOM
        ssh = self.connect_server(server_name)
        if not ssh and not self.dry_run:
            reason = self._failed_hosts.get(server_name, "SSH connection failed")
            return self._failed(server_name, service_name, f"SSH connection failed: {reason}")
        handlers = {
            ServiceType.JKS: self.deploy_jks,
            ServiceType.APACHE: self.deploy_apache,
            ServiceType.ASTERISK: self.deploy_asterisk,
            ServiceType.NGINX: self.deploy_nginx,
            ServiceType.CUSTOM: self.deploy_custom,
        }
        changes: List[_Change] = []
        try:
            self._ensure_backup_root(ssh, server_name)
            result = handlers[service_type](
                ssh, server_name, service_name, service_config, cert_files, changes
            )
        except DeployError as exc:
            result = self._failed(server_name, service_name, self._mask(str(exc)))
        except Exception as exc:  # never let one service take the whole run down
            self.logger.exception("Unexpected error deploying %s/%s", server_name, service_name)
            result = self._failed(server_name, service_name, f"unexpected error: {self._mask(str(exc))}")
        if result.status == DeploymentStatus.FAILED and changes:
            restored = self._revert_changes(ssh, changes, result.message)
            result.message += " (files restored)" if restored else " (RESTORE FAILED - run rollback)"
            changes = []
        result.details["changes"] = changes
        return result

    # -- hooks, restarts, live verification -------------------------------

    def _run_hooks(self, server_name: str, ssh: RemoteHost | None, service_names: List[str]) -> bool:
        """Run each distinct post-upload hook once per host, in the order its
        service first appears, so e.g. a cacerts import shared by five
        services on one host runs exactly once (mirrors ROLE_POST_* union).

        Returns False if any hook failed: hooks are the safety checks
        (keystore opens, key pair matches, asterisk.pem key-first), so a
        failure must stop the restarts."""
        if ssh is None and not self.dry_run:
            return True
        services = self.config.get("services") or {}
        seen: set = set()
        for service_name in service_names:
            for hook in services.get(service_name, {}).get("hooks") or []:
                if hook in seen:
                    continue
                seen.add(hook)
                label = hook.strip().splitlines()[0][:60] if hook.strip() else ""
                if self.dry_run:
                    self.term.detail(f"[DRY-RUN] Would run hook: {self._mask(label)}")
                    continue
                self.term.detail(f"  hook: {self._mask(label)}")
                exit_code, _out, stderr = self.execute_remote(ssh, hook, check_error=False)
                if exit_code != 0:
                    detail = self._mask(stderr.strip()[:300]) or f"exit code {exit_code}"
                    self.term.error(f"  hook failed ({exit_code}): {detail}")
                    self.results.append(DeploymentResult(
                        server_name, f"hook: {self._mask(label)}", DeploymentStatus.FAILED,
                        f"hook failed ({exit_code}): {detail}",
                    ))
                    return False
        return True

    def _run_restarts(self, server_name: str, ssh: RemoteHost | None, service_names: List[str]) -> List[str]:
        """Restart each distinct command once per host, ordered by ascending
        `priority` (default 50), so e.g. an appserver restart can run before
        a dependent service's (mirrors ROLE_PRIO_*/ROLE_RESTART_* union).
        Returns the names of services whose restart failed."""
        if self.no_restart:
            return []
        if ssh is None and not self.dry_run:
            return []
        services = self.config.get("services") or {}
        ordered = sorted(
            (name for name in service_names if services.get(name, {}).get("restart_cmd")),
            key=lambda name: services.get(name, {}).get("priority", 50),
        )
        seen: set = set()
        failed: List[str] = []
        for service_name in ordered:
            cmd = services[service_name]["restart_cmd"]
            if cmd in seen:
                continue
            seen.add(cmd)
            if self.dry_run:
                self.term.detail(f"[DRY-RUN] Would restart ({service_name}): {self._mask(cmd)}")
                continue
            exit_code, _out, stderr = self.execute_remote(ssh, cmd)
            if exit_code != 0:
                detail = self._mask(stderr.strip()[:200])
                if detail or exit_code in (-1, 126, 127):
                    self.term.error(f"  restart '{service_name}' FAILED ({exit_code}): {detail}")
                    failed.append(service_name)
                else:
                    self.term.warn(f"  restart '{service_name}' exited {exit_code} (no error output)")
        return failed

    def _verify_live(
        self, server_name: str, service_names: List[str], cert_files: Dict[str, Path]
    ) -> List[str]:
        """Handshake with each service's TLS port and confirm it now serves the
        certificate we deployed. Configure with `verify_tls: {port: N}` per service."""
        services = self.config.get("services") or {}
        server_cfg = (self.config.get("servers") or {}).get(server_name) or {}
        expected = leaf_fingerprint_sha256(cert_files)
        problems: List[str] = []
        for service_name in service_names:
            spec = services.get(service_name, {}).get("verify_tls")
            if not spec:
                continue
            specs = spec if isinstance(spec, list) else [spec]
            for item in specs:
                port = item.get("port") if isinstance(item, dict) else item
                host = (item.get("host") if isinstance(item, dict) else None) or server_cfg.get("host")
                if self.dry_run:
                    self.term.detail(f"[DRY-RUN] Would verify TLS on {host}:{port}")
                    continue
                if self.no_restart:
                    self.term.detail(f"  skipped TLS check of {host}:{port} (--no-restart)")
                    continue
                if not expected:
                    self.term.warn(f"  cannot TLS-check {host}:{port}: no local certificate to compare")
                    continue
                opts = item if isinstance(item, dict) else {}
                ok, detail = wait_for_certificate(
                    host, int(port), expected,
                    servername=opts.get("servername"),
                    attempts=int(opts.get("attempts", 6)),
                    delay=float(opts.get("delay", 5)),
                )
                if ok:
                    self.term.detail(f"[ok] {detail}")
                else:
                    self.term.error(f"  TLS verification failed for {service_name}: {detail}")
                    problems.append(f"{service_name}: {detail}")
        return problems

    def deploy_server(
        self,
        server_name: str,
        cert_files: Dict[str, Path],
        service_filter: str | None = None,
    ) -> List[DeploymentResult]:
        server_config = (self.config.get("servers") or {}).get(server_name)
        if not server_config:
            return []
        results: list[DeploymentResult] = []
        deployed_services: list[str] = []
        for service_name in server_config.get("services", []):
            if service_filter and service_name != service_filter:
                continue
            result = self.deploy_service(server_name, service_name, cert_files)
            results.append(result)
            with self._lock:
                self.results.append(result)
            if result.status == DeploymentStatus.SUCCESS:
                deployed_services.append(service_name)

        if not deployed_services:
            return results

        ssh = self.connect_server(server_name)
        server_changes = [c for r in results for c in r.details.get("changes", [])]

        if not self._run_hooks(server_name, ssh, deployed_services):
            if self.auto_rollback:
                restored = self._revert_changes(ssh, server_changes, "a post-upload hook failed")
                for r in results:
                    if r.status == DeploymentStatus.SUCCESS:
                        r.status = DeploymentStatus.ROLLED_BACK
                        r.message += " (reverted: hook failed)"
                self.term.error(
                    f"  {server_name}: hook failed - services were NOT restarted and files were "
                    f"{'restored' if restored else 'only partially restored (run rollback)'}"
                )
            else:
                self.term.error(
                    f"  {server_name}: hook failed - services were NOT restarted; files are left in "
                    f"place (run: rollback --server {server_name})"
                )
            return results

        restart_failures = self._run_restarts(server_name, ssh, deployed_services)
        for name in restart_failures:
            self.results.append(DeploymentResult(
                server_name, f"restart: {name}", DeploymentStatus.FAILED,
                f"restart failed - check the service; run 'rollback --server {server_name} --restart' to undo",
            ))
        for problem in self._verify_live(server_name, deployed_services, cert_files):
            self.results.append(DeploymentResult(
                server_name, "tls-verify", DeploymentStatus.FAILED,
                f"{problem} - run 'rollback --server {server_name} --restart' to undo",
            ))
        return results

    def _deploy_server_guarded(
        self, server_name: str, cert_files: Dict[str, Path], service_filter: str | None
    ) -> None:
        try:
            self.deploy_server(server_name, cert_files, service_filter)
        except Exception as exc:
            self.logger.exception("Unexpected error on %s", server_name)
            with self._lock:
                self.results.append(self._failed(server_name, "*", f"unexpected error: {self._mask(str(exc))}"))

    def deploy_all(
        self,
        server_filter: str | None = None,
        service_filter: str | None = None,
    ) -> List[DeploymentResult]:
        self._deployed_paths.clear()
        self.aborted_reason = None
        cert_files = self.validate_cert_files()
        if not cert_files and not self.dry_run:
            return self._abort("No certificate files found - nothing was deployed")

        if cert_files and not self.skip_verify:
            self.term.detail("Verifying certificate files before deploy...")
            findings = verify_cert_bundle(
                cert_files, self.config.get("domain") or None, key_password=self.key_password
            )
            self._report_findings(findings)
            if has_errors(findings):
                return self._abort(
                    "Pre-deploy verification FAILED - nothing was deployed "
                    "(fix the files, or pass --skip-verify to override)"
                )

        servers = self.config.get("servers") or {}
        if not servers:
            self.term.warn("No servers defined - nothing to deploy")
            return []

        server_names = [name for name in servers if not server_filter or name == server_filter]
        if not server_names:
            return self._abort(f"No server named '{server_filter}' in the config")

        try:
            if self.parallel and len(server_names) > 1:
                with ThreadPoolExecutor(max_workers=len(server_names)) as pool:
                    futures = [
                        pool.submit(self._deploy_server_guarded, name, cert_files, service_filter)
                        for name in server_names
                    ]
                    for future in futures:
                        future.result()
            else:
                for server_name in server_names:
                    self._deploy_server_guarded(server_name, cert_files, service_filter)
        finally:
            self.close_connections()
        return self.results

    def close_connections(self) -> None:
        with self._lock:
            for ssh in self.ssh_connections.values():
                try:
                    ssh.close()
                except Exception:
                    pass
            self.ssh_connections.clear()

    def format_server_summary(self, server_name: str) -> str:
        server_results = [r for r in self.results if r.server == server_name]
        if not server_results:
            return ""
        host = (self.config.get("servers") or {}).get(server_name, {}).get("host", server_name)
        marks = {
            DeploymentStatus.SUCCESS: "OK",
            DeploymentStatus.ROLLED_BACK: "REVERTED",
            DeploymentStatus.SKIPPED: "SKIPPED",
        }
        parts = [f"{r.service} {marks.get(r.status, 'FAIL')}" for r in server_results]
        return f"      {host}: {', '.join(parts)}"

    @property
    def failed_count(self) -> int:
        return sum(1 for r in self.results if r.status == DeploymentStatus.FAILED)

    # -------------------------------------------------------------------
    # Pre-flight
    # -------------------------------------------------------------------
    # Reads each server's *live* state before a deploy, independent of
    # self.dry_run (it's read-only, so it should always reflect reality).

    _AMEYOCTL_RESTART_RE = re.compile(r"ameyoctl service (\S+)")
    _AMEYOCTL_STATUS_RE = re.compile(r"^(\S+)\s+is\s+(RUNNING|NOT_RUNNING)")

    def _extract_ameyoctl_service(self, restart_cmd: str) -> Optional[str]:
        """Pull the ameyoctl service name out of a restart command, whether
        it came from the Ameyo catalogue's guarded one-liner or a
        hand-written restart string (e.g. "ameyoctl service X faststop && ...")."""
        if not restart_cmd:
            return None
        match = self._AMEYOCTL_RESTART_RE.search(restart_cmd)
        return match.group(1) if match else None

    def preflight_server(self, server_name: str) -> Dict[str, Any]:
        server_config = (self.config.get("servers") or {}).get(server_name)
        if not server_config:
            return {"server": server_name, "error": "not found in config"}
        host = server_config.get("host", server_name)

        ssh = self.connect_server(server_name, force=True)
        if not ssh:
            reason = self._failed_hosts.get(server_name, "SSH connection failed")
            return {"server": server_name, "host": host, "error": f"SSH connection failed: {reason}"}

        warning = None
        try:
            _code, raw, _err = ssh.run("ameyoctl status 2>/dev/null", timeout=30)
        except TimeoutError:
            # Reachable, but the status probe is slow/stuck. That is worth a warning, not a
            # reason to refuse the whole deploy (a dropped connection still is an error).
            raw = ""
            warning = "'ameyoctl status' gave no answer within 30s; service states are unknown"
        except Exception as exc:
            return {"server": server_name, "host": host, "error": self._mask(str(exc))}

        running = set()
        for line in raw.splitlines():
            match = self._AMEYOCTL_STATUS_RE.match(line.strip())
            if match and match.group(2) == "RUNNING":
                running.add(match.group(1))

        services = self.config.get("services") or {}
        rows = []
        for service_name in server_config.get("services", []):
            restart_cmd = services.get(service_name, {}).get("restart_cmd") or ""
            ameyoctl_name = self._extract_ameyoctl_service(restart_cmd)
            rows.append({
                "service": service_name,
                "ameyoctl": ameyoctl_name,
                "running": None if (warning or not ameyoctl_name) else (ameyoctl_name in running),
            })
        report = {"server": server_name, "host": host, "rows": rows, "ameyoctl_ok": bool(raw.strip())}
        if warning:
            report["warning"] = warning
        return report

    def preflight_all(self, server_filter: str | None = None) -> List[Dict[str, Any]]:
        servers = self.config.get("servers") or {}
        try:
            return [
                self.preflight_server(name)
                for name in servers
                if not server_filter or name == server_filter
            ]
        finally:
            self.close_connections()

    # -------------------------------------------------------------------
    # Rollback
    # -------------------------------------------------------------------
    # Restores files backed up by backup_remote_file()/_sync_file() during a
    # prior deploy. Snapshots live under backup_dir/<server>/<timestamp>/,
    # with each file's full original absolute path preserved underneath, so
    # restoring is "copy every file in the snapshot back to /<its path>".
    # Done over SFTP + quoted `cp`/`mv`, so no timestamp or path is ever
    # interpolated into a shell script.

    def _list_snapshot_files(self, sftp: Any, snapshot: str) -> List[str]:
        files: List[str] = []
        stack = [snapshot]
        while stack:
            current = stack.pop()
            for entry in sftp.listdir_attr(current):
                path = f"{current}/{entry.filename}"
                if stat_mod.S_ISLNK(entry.st_mode):
                    continue  # never follow links out of the snapshot
                if stat_mod.S_ISDIR(entry.st_mode):
                    stack.append(path)
                elif stat_mod.S_ISREG(entry.st_mode):
                    files.append(path)
        return sorted(files)

    def rollback_server(
        self, server_name: str, timestamp: Optional[str] = None, *, restart: bool = False
    ) -> DeploymentResult:
        base = f"{self.backup_dir}/{_safe_component(server_name)}"
        if timestamp is not None and not SNAPSHOT_RE.match(timestamp):
            return self._failed(
                server_name, "*", f"invalid snapshot name {timestamp!r} (expected YYYYMMDD_HHMMSS)"
            )
        if self.dry_run:
            self.term.detail(
                f"[DRY-RUN] Would restore snapshot {timestamp or '(newest)'} under {base} on {server_name}"
            )
            return DeploymentResult(
                server_name, "*", DeploymentStatus.ROLLED_BACK,
                f"[DRY-RUN] would restore {timestamp or '(newest)'}",
            )

        ssh = self.connect_server(server_name)
        if not ssh:
            return self._failed(
                server_name, "*",
                f"SSH connection failed: {self._failed_hosts.get(server_name, 'unknown error')}",
            )
        try:
            self._ensure_backup_root(ssh, server_name)
            sftp = ssh.sftp()
            try:
                names = sorted(n for n in sftp.listdir(base) if SNAPSHOT_RE.match(n))
            except FileNotFoundError:
                names = []
            if not names:
                return self._failed(server_name, "*", f"no snapshots under {base}")
            chosen = timestamp or names[-1]
            if chosen not in names:
                return self._failed(server_name, "*", f"no snapshot: {base}/{chosen}")
            snapshot = f"{base}/{chosen}"
            files = self._list_snapshot_files(sftp, snapshot)
            if not files:
                return self._failed(server_name, "*", f"snapshot {snapshot} is empty")
            for backup in files:
                target = backup[len(snapshot):]
                validate_remote_path(target, "restore target")
                self._mkdir_p(sftp, posixpath.dirname(target))
                code, _o, err = self.execute_remote(
                    ssh, self._restore_command(backup, target), check_error=False
                )
                if code != 0:
                    return self._failed(
                        server_name, "*", f"could not restore {target}: {self._mask(err.strip())}"
                    )
        except (DeployError, ValueError, IOError, OSError) as exc:
            return self._failed(server_name, "*", self._mask(str(exc)))

        message = f"restored {len(files)} file(s) from {snapshot}"
        if restart:
            services = (self.config.get("servers") or {}).get(server_name, {}).get("services", [])
            failed = self._run_restarts(server_name, ssh, list(services))
            message += "; services restarted" if not failed else f"; restart FAILED for {', '.join(failed)}"
            if failed:
                return DeploymentResult(server_name, "*", DeploymentStatus.FAILED, message)
        else:
            message += "; restart the services to apply (or re-run with --restart)"
        return DeploymentResult(server_name, "*", DeploymentStatus.ROLLED_BACK, message)

    def rollback_all(
        self,
        server_filter: str | None = None,
        timestamp: str | None = None,
        *,
        restart: bool = False,
    ) -> List[DeploymentResult]:
        servers = self.config.get("servers") or {}
        results: list[DeploymentResult] = []
        try:
            for server_name in servers:
                if server_filter and server_name != server_filter:
                    continue
                result = self.rollback_server(server_name, timestamp, restart=restart)
                results.append(result)
                self.results.append(result)
        finally:
            self.close_connections()
        return results


def resolve_default_config(script_dir: Path) -> Path | None:
    """Search for default config in standard locations."""
    search_paths = [
        script_dir / "deploy-config.yaml",
        script_dir / "deploy-config.yml",
        script_dir / "configs" / "default.yaml",
        script_dir / "configs" / "default.yml",
        script_dir / "config.yaml",
        script_dir.parent / "ssl-deploy" / "config.yaml",
    ]
    for candidate in search_paths:
        if candidate.is_file():
            return candidate
    return None
