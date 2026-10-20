# Author: Sagar K | 2026 | MIT licence
"""The Studio's service layer: plain functions over the real core/deployer, returning plain data.

Nothing here touches Tk, so it is unit-tested directly. The UI calls these on a worker thread.
"""
from __future__ import annotations

import os
import platform
import sys
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Callable, Dict, List, Optional, Sequence, Tuple

from ssl_cert_tool import __version__ as TOOL_VERSION
from ssl_cert_tool import core
from ssl_cert_tool.platform import Terminal, find_keytool
from ssl_deploy.deployer import CopyItem, DeploymentStatus, SSLDeployer, load_deploy_config
from ssl_deploy.ssh import (
    default_known_hosts_path,
    describe_route,
    hop_from_ssh_config,
    load_ssh_config,
    parse_hop_spec,
    resolve_hops,
)
from ssl_deploy.verify import cert_names


class UiError(Exception):
    """A problem the user can fix; the message is shown as-is."""


# ---------------------------------------------------------------------------
# Environment
# ---------------------------------------------------------------------------

@dataclass
class EnvView:
    version: str
    python: str
    keytool: Optional[str]
    ssh_config: Optional[str]
    ssh_aliases: List[str]
    trusted_hosts: int
    configs: List[str]


def ssh_aliases(path: Optional[Path] = None) -> List[str]:
    """Concrete host aliases from ~/.ssh/config (wildcard blocks are skipped)."""
    try:
        config = load_ssh_config(path)
    except ValueError:
        return []
    if config is None:
        return []
    return sorted(h for h in config.get_hostnames() if h and "*" not in h and "?" not in h)


def _count_known_hosts(*paths: Path) -> int:
    total = 0
    for path in paths:
        try:
            for line in Path(path).read_text(encoding="utf-8", errors="replace").splitlines():
                if line.strip() and not line.startswith("#"):
                    total += 1
        except OSError:
            continue
    return total


def env_status(configs_dir: Optional[Path] = None, ssh_config: Optional[Path] = None) -> EnvView:
    keytool = find_keytool()
    cfg_path = Path(ssh_config) if ssh_config else Path.home() / ".ssh" / "config"
    configs = []
    if configs_dir and Path(configs_dir).is_dir():
        configs = sorted(p.name for p in Path(configs_dir).glob("*.y*ml") if p.name != "template.yaml")
    return EnvView(
        version=TOOL_VERSION,
        python=platform.python_version(),
        keytool=str(keytool) if keytool else None,
        ssh_config=str(cfg_path) if cfg_path.is_file() else None,
        ssh_aliases=ssh_aliases(cfg_path),
        trusted_hosts=_count_known_hosts(Path.home() / ".ssh" / "known_hosts", default_known_hosts_path()),
        configs=configs,
    )


# ---------------------------------------------------------------------------
# Certificates: inspect & generate
# ---------------------------------------------------------------------------

@dataclass
class CertCard:
    role: str            # LEAF / INTERMEDIATE / ROOT / CERT
    cn: str
    issuer: str
    not_after: str
    days_left: int
    expired: bool
    source: str
    names: List[str] = field(default_factory=list)
    key_info: str = ""


@dataclass
class InspectView:
    files_scanned: int
    certs: List[CertCard]
    keys: List[Tuple[str, Optional[bool]]]   # (file name, matches the leaf?)
    leaf_cn: Optional[str]
    ready: bool
    notes: List[str]
    warnings: List[str]


def _role(label: str) -> str:
    if label.startswith("leaf"):
        return "LEAF"
    if label == "root":
        return "ROOT"
    if "intermediate" in label:
        return "INTERMEDIATE"
    return "CERT"


def inspect_paths(
    paths: Sequence[Path],
    key_path: Optional[Path] = None,
    key_password: Optional[str] = None,
    domain: Optional[str] = None,
) -> InspectView:
    paths = [Path(p) for p in paths]
    if not paths:
        raise UiError("Add at least one certificate file or folder.")
    for path in paths:
        if not path.exists():
            raise UiError(f"Not found: {path}")
    result = core.inspect_inputs(
        paths, key_path=Path(key_path) if key_path else None, domain_hint=domain or None, key_password=key_password or None
    )
    order = {"LEAF": 0, "INTERMEDIATE": 1, "ROOT": 2, "CERT": 3}
    cards: List[CertCard] = []
    for parsed in result.certs:
        cert = parsed.cert
        expired, days = core.check_cert_expiry(cert)
        key_type, key_size = core.get_key_info(cert)
        cards.append(CertCard(
            role=_role(core.cert_role_label(parsed, result.leaf)),
            cn=core.cert_cn(cert) or "(no common name)",
            issuer=core.cert_issuer_cn(cert) or core.cert_issuer(cert),
            not_after=cert.not_valid_after_utc.strftime("%Y-%m-%d"),
            days_left=days,
            expired=expired,
            source=parsed.source.name,
            names=cert_names(cert)[:6],
            key_info=f"{key_type} {key_size}-bit" if key_size else key_type,
        ))
    cards.sort(key=lambda c: (order[c.role], c.cn))
    keys = [
        (key_file.name, core.public_numbers_match(key, result.leaf.cert) if result.leaf else None)
        for key_file, key in result.keys
    ]
    ready = bool(result.leaf) and any(match for _name, match in keys)
    return InspectView(
        files_scanned=len(result.files_scanned),
        certs=cards,
        keys=keys,
        leaf_cn=core.cert_cn(result.leaf.cert) if result.leaf else None,
        ready=ready,
        notes=list(result.notes),
        warnings=list(result.warnings),
    )


@dataclass
class GenerateView:
    output_dir: Path
    domain: str
    files: List[Tuple[str, int]]
    warnings: List[str]
    key_cert_match: bool
    jks: Optional[str]            # "keytool", "built-in" or None (not created)
    expires: str


def generate_artifacts(
    paths: Sequence[Path],
    output_base: Path,
    store_pass: str,
    alias: str,
    *,
    key_path: Optional[Path] = None,
    key_password: Optional[str] = None,
    domain: Optional[str] = None,
    keytool: Optional[Path] = None,
) -> GenerateView:
    paths = [Path(p) for p in paths]
    files = core.collect_input_files(paths)
    if not files:
        raise UiError("No certificate files found in the selected inputs.")
    certs, keys = core.parse_all_inputs(files, None, key_password or None)
    explicit_key = None
    if key_path:
        try:
            explicit_key = core.load_private_key(Path(key_path).read_bytes(), key_password or None)
        except (OSError, ValueError) as exc:
            raise UiError(f"Could not load the private key: {exc}") from exc
    leaf, intermediates, root = core.classify_certs(certs, domain or None)
    if leaf is None:
        raise UiError("Could not identify the server (leaf) certificate in these files.")
    candidates = ([explicit_key] if explicit_key is not None else []) + [k for _p, k in keys]
    if not candidates:
        raise UiError("No private key found. Choose the key file that belongs to this certificate.")
    private_key = next((k for k in candidates if core.public_numbers_match(k, leaf.cert)), None)
    if private_key is None:
        raise UiError("The private key does not match the certificate.")
    name = core.infer_domain(leaf, domain or None)
    if not (store_pass or "").strip():
        raise UiError("Enter a keystore password.")
    tool = Path(keytool) if keytool else (find_keytool() or Path("keytool"))
    result = core.build_outputs(
        domain=name,
        output_dir=Path(output_base) / name,
        leaf=leaf,
        intermediates=intermediates,
        root=root,
        private_key=private_key,
        store_pass=store_pass,
        alias=alias or "server-cert",
        keytool=tool,
    )
    jks_file = result.output_dir / f"{name}.jks"
    jks = None
    if jks_file.is_file():
        jks = "built-in" if any("built-in JKS writer" in w for w in result.warnings) else "keytool"
    return GenerateView(
        output_dir=result.output_dir,
        domain=name,
        files=[(f.name, f.stat().st_size) for f in result.files if f.is_file()],
        warnings=list(result.warnings),
        key_cert_match=bool(result.validation.get("key_cert_match")),
        jks=jks,
        expires=leaf.cert.not_valid_after_utc.strftime("%Y-%m-%d"),
    )


@dataclass
class KeystoreView:
    path: str
    alias: str
    domain: str
    issuer: str
    expires: str
    days_left: Optional[int]       # None when the file does not say
    expired: bool
    key_type: str
    chain: List[Tuple[str, str]]   # (CN, role)


def keystore_info(path: Path, password: str, keytool: Optional[Path] = None) -> KeystoreView:
    path = Path(path)
    if not path.is_file():
        raise UiError(f"File not found: {path}")
    if path.suffix.lower() in (".p12", ".pfx"):
        info = core.read_jks_info_from_p12(path, password)
    else:
        info = core.read_jks_info(path, password, keytool)
    if info.error:
        raise UiError(f"Could not open the keystore: {info.error}")
    return KeystoreView(
        path=str(path),
        alias=info.alias or "(none)",
        domain=info.domain or "(unknown)",
        issuer=info.issuer_cn or info.issuer or "(unknown)",
        expires=info.valid_until.strftime("%Y-%m-%d") if info.valid_until else "(unknown)",
        days_left=info.days_until_expiry if info.valid_until else None,
        expired=info.is_expired,
        key_type=f"{info.key_type or '?'} {info.key_size or ''}-bit".strip(),
        chain=[(c["cn"], c.get("role", "")) for c in info.chain],
    )


# ---------------------------------------------------------------------------
# Routes and deploy plans
# ---------------------------------------------------------------------------

@dataclass
class RouteView:
    hops: List[str]               # "user@host:port" in connect order, target last
    names: List[str]
    error: Optional[str] = None


def preview_route(
    host: str,
    via: str = "",
    user: str = "",
    ssh_config_path: Optional[Path] = None,
    servers: Optional[Dict[str, Any]] = None,
) -> RouteView:
    """What `copy --host ...` would connect through (no network)."""
    host = (host or "").strip()
    if not host:
        return RouteView([], [], "Enter a host or pick an alias.")
    try:
        ssh_config = load_ssh_config(ssh_config_path)
        if servers and host in servers:
            entry: Dict[str, Any] = dict(servers[host])
        else:
            entry = {}
            if hop_from_ssh_config(host, ssh_config) is not None:
                entry["ssh_alias"] = host
            else:
                entry.update({k: v for k, v in parse_hop_spec(host).items() if k != "name"})
        if user.strip():
            entry["user"] = user.strip()
        if via.strip():
            entry["proxy_jump"] = via.strip()
        table = dict(servers or {})
        table["target"] = entry
        target, hops = resolve_hops("target", entry, table, ssh_config, {})
        chain = hops + [target]
        return RouteView([describe_route([], h) for h in chain], [h.get("name", h["host"]) for h in chain])
    except ValueError as exc:
        return RouteView([], [], str(exc))


@dataclass
class ServerView:
    name: str
    route: List[str]
    error: Optional[str]
    services: List[Tuple[str, str, str]]    # (service, type, where)


@dataclass
class PlanView:
    domain: str
    servers: List[ServerView]


def _service_target(svc: Dict[str, Any]) -> str:
    kind = svc.get("type", "custom")
    if kind == "jks":
        return svc.get("keystore_path") or svc.get("remote_path") or "(not set)"
    if kind == "apache":
        return svc.get("ssl_dir") or svc.get("cert_path") or "/etc/pki/tls/certs/"
    if kind == "nginx":
        return svc.get("cert_path", "/etc/nginx/ssl/")
    if kind == "asterisk":
        return svc.get("cert_dir", "/etc/asterisk/keys/")
    maps = svc.get("file_mappings") or {}
    dests = [d for v in maps.values() for d in (v if isinstance(v, list) else [v])] if isinstance(maps, dict) else []
    return ", ".join(dests[:2]) + (" ..." if len(dests) > 2 else "") if dests else "(custom)"


def load_plan(config_path: Path, ssh_config_path: Optional[Path] = None) -> PlanView:
    config_path = Path(config_path)
    if not config_path.is_file():
        raise UiError(f"Config not found: {config_path}")
    try:
        cfg = load_deploy_config(config_path)
    except Exception as exc:
        raise UiError(f"Could not read the config: {exc}") from exc
    servers = cfg.get("servers") or {}
    services = cfg.get("services") or {}
    try:
        ssh_config = load_ssh_config(ssh_config_path)
    except ValueError:
        ssh_config = None
    views = []
    for name, entry in servers.items():
        route, error = [], None
        try:
            target, hops = resolve_hops(name, entry, servers, ssh_config, cfg.get("ssh") or {})
            route = [describe_route([], h) for h in hops + [target]]
        except ValueError as exc:
            error = str(exc)
        rows = []
        for svc_name in entry.get("services", []) or []:
            svc = services.get(svc_name) or {}
            rows.append((svc_name, svc.get("type", "custom"), _service_target(svc)))
        views.append(ServerView(name, route, error, rows))
    return PlanView(cfg.get("domain") or "(auto-detect)", views)


# ---------------------------------------------------------------------------
# Running deploy / copy / rollback
# ---------------------------------------------------------------------------

@dataclass
class ResultRow:
    server: str
    item: str
    status: str       # success / failed / rolled_back / skipped
    message: str


@dataclass
class Outcome:
    ok: bool
    rows: List[ResultRow]
    aborted: Optional[str] = None
    hint: Optional[str] = None


@dataclass
class DeployOptions:
    dry_run: bool = True
    trust_new_hosts: bool = False
    skip_verify: bool = False
    auto_rollback: bool = True
    no_restart: bool = False
    preflight: bool = False
    server: Optional[str] = None
    service: Optional[str] = None


def _outcome(deployer: SSLDeployer, hint_ok: Optional[str] = None, hint_failed: Optional[str] = None) -> Outcome:
    rows = [ResultRow(r.server, r.service, r.status.value, r.message) for r in deployer.results]
    failed = bool(deployer.aborted_reason) or deployer.failed_count > 0
    return Outcome(ok=not failed and bool(rows), rows=rows, aborted=deployer.aborted_reason,
                   hint=hint_failed if failed else hint_ok)


def run_deploy(
    config_path: Path,
    cert_dir: Path,
    options: DeployOptions,
    *,
    terminal: Terminal,
    password_prompt: Optional[Callable[[Dict[str, Any]], Optional[str]]] = None,
    key_password: Optional[str] = None,
    known_hosts: Optional[Path] = None,
    ssh_config: Optional[Path] = None,
) -> Outcome:
    config_path, cert_dir = Path(config_path), Path(cert_dir)
    if not config_path.is_file():
        raise UiError(f"Config not found: {config_path}")
    if not cert_dir.is_dir():
        raise UiError(f"Certificate folder not found: {cert_dir}")
    deployer = SSLDeployer(
        config_path=config_path,
        cert_path=cert_dir,
        dry_run=options.dry_run,
        no_restart=options.no_restart,
        terminal=terminal,
        host_key_policy="accept-new" if options.trust_new_hosts else None,
        known_hosts_path=known_hosts,
        skip_verify=options.skip_verify,
        auto_rollback=options.auto_rollback,
        key_password=key_password or None,
        password_prompt=password_prompt,
        ssh_config_path=ssh_config,
    )
    if not deployer.load_config() or not deployer.validate_config():
        raise UiError("The deployment config is not valid (see the activity log).")
    if options.preflight:
        reports = deployer.preflight_all(server_filter=options.server)
        broken = [r for r in reports if r.get("error")]
        if broken and not options.dry_run:
            raise UiError("Pre-flight failed for: " + ", ".join(r["server"] for r in broken))
    deployer.deploy_all(server_filter=options.server, service_filter=options.service)
    if options.dry_run:
        return _outcome(deployer)
    return _outcome(
        deployer,
        hint_ok="Need to undo it? The Rollback page restores the previous files from the backups.",
        hint_failed="Files of a failed service were restored automatically. The Rollback page can restore the rest.",
    )


def run_copy(
    items: Sequence[CopyItem],
    *,
    terminal: Terminal,
    host: str = "",
    via: str = "",
    user: str = "",
    config_path: Optional[Path] = None,
    server: Optional[str] = None,
    check_cmd: Optional[str] = None,
    reload_cmd: Optional[str] = None,
    backup_dir: Optional[str] = None,
    dry_run: bool = True,
    skip_verify: bool = False,
    trust_new_hosts: bool = False,
    key_password: Optional[str] = None,
    password_prompt: Optional[Callable[[Dict[str, Any]], Optional[str]]] = None,
    known_hosts: Optional[Path] = None,
    ssh_config: Optional[Path] = None,
) -> Outcome:
    if not items:
        raise UiError("Add at least one file to copy.")
    config_dict = None
    path = Path("<ad-hoc>")
    if server:
        if not config_path or not Path(config_path).is_file():
            raise UiError("Pick the deploy config that defines this server.")
        path, name = Path(config_path), server
    else:
        if not host.strip():
            raise UiError("Choose or type the target host.")
        name = "target"
        try:
            ssh_cfg = load_ssh_config(ssh_config)
            entry: Dict[str, Any] = {}
            if hop_from_ssh_config(host.strip(), ssh_cfg) is not None:
                entry["ssh_alias"] = host.strip()
            else:
                entry.update({k: v for k, v in parse_hop_spec(host.strip()).items() if k != "name"})
        except ValueError as exc:
            raise UiError(str(exc)) from exc
        if user.strip():
            entry["user"] = user.strip()
        if via.strip():
            entry["proxy_jump"] = via.strip()
        config_dict = {"servers": {name: entry}, "services": {}}
    deployer = SSLDeployer(
        config_path=path,
        dry_run=dry_run,
        terminal=terminal,
        host_key_policy="accept-new" if trust_new_hosts else None,
        known_hosts_path=known_hosts,
        skip_verify=skip_verify,
        key_password=key_password or None,
        password_prompt=password_prompt,
        ssh_config_path=ssh_config,
        config=config_dict,
    )
    if not deployer.load_config():
        raise UiError("The configuration could not be loaded (see the activity log).")
    if backup_dir:
        deployer.config["backup_dir"] = backup_dir
    if name not in (deployer.config.get("servers") or {}):
        raise UiError(f"Server '{name}' is not defined in the config.")
    deployer.copy_files(name, list(items), check_cmd=check_cmd or None, reload_cmd=reload_cmd or None)
    return _outcome(deployer, hint_failed=None if dry_run else "Nothing is left half-copied: files that were already replaced have been restored.")


def run_rollback(
    config_path: Path,
    *,
    terminal: Terminal,
    server: Optional[str] = None,
    timestamp: Optional[str] = None,
    restart: bool = False,
    dry_run: bool = True,
    trust_new_hosts: bool = False,
    password_prompt: Optional[Callable[[Dict[str, Any]], Optional[str]]] = None,
    known_hosts: Optional[Path] = None,
    ssh_config: Optional[Path] = None,
) -> Outcome:
    config_path = Path(config_path)
    if not config_path.is_file():
        raise UiError(f"Config not found: {config_path}")
    deployer = SSLDeployer(
        config_path=config_path,
        dry_run=dry_run,
        terminal=terminal,
        host_key_policy="accept-new" if trust_new_hosts else None,
        known_hosts_path=known_hosts,
        password_prompt=password_prompt,
        ssh_config_path=ssh_config,
    )
    if not deployer.load_config():
        raise UiError("The deployment config is not valid (see the activity log).")
    results = deployer.rollback_all(server_filter=server or None, timestamp=timestamp or None, restart=restart)
    if not results:
        raise UiError("No server matched: nothing to roll back.")
    rows = [ResultRow(r.server, r.service, r.status.value, r.message) for r in results]
    ok = all(r.status != DeploymentStatus.FAILED for r in results)
    return Outcome(ok=ok, rows=rows)
