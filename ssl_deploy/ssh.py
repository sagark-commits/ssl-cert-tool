"""SSH helpers: strict host-key verification, safe quoting, robust command runner.

The deployer talks to servers through `RemoteHost`, a thin wrapper over a
paramiko client. Keeping this in one place means host-key policy, timeouts and
quoting are enforced identically for every command the tool runs.
"""
from __future__ import annotations

import base64
import fnmatch
import hashlib
import os
import re
import shlex
import threading
import time
from pathlib import Path
from typing import Any, Callable, Dict, List, Optional, Tuple

try:
    import paramiko

    HAS_PARAMIKO = True
except ImportError:  # pragma: no cover - exercised only without paramiko
    paramiko = None  # type: ignore[assignment]
    HAS_PARAMIKO = False

POLICY_STRICT = "strict"
POLICY_ACCEPT_NEW = "accept-new"
VALID_HOST_KEY_POLICIES = (POLICY_STRICT, POLICY_ACCEPT_NEW)

DEFAULT_COMMAND_IDLE_TIMEOUT = 300
COMMAND_HARD_CAP_SECONDS = 1800
MAX_COMMAND_OUTPUT_BYTES = 4 * 1024 * 1024

_ExcBase = paramiko.SSHException if HAS_PARAMIKO else Exception
_PolicyBase = paramiko.MissingHostKeyPolicy if HAS_PARAMIKO else object

_known_hosts_lock = threading.Lock()


class HostKeyVerificationError(_ExcBase):  # type: ignore[misc,valid-type]
    """The server's host key is unknown or does not match what we pinned."""


# ---------------------------------------------------------------------------
# Quoting / validation
# ---------------------------------------------------------------------------

def shell_quote(value: Any) -> str:
    """Quote one argument for a POSIX shell (all remote commands go through this)."""
    return shlex.quote(str(value))


def validate_remote_path(path: Any, label: str = "remote path") -> str:
    """Remote paths must be absolute, single-line, and NUL-free.

    SFTP does not expand `~`, so relative/home-relative paths never worked
    reliably; rejecting them up front avoids writing to the wrong place.
    """
    if not isinstance(path, str) or not path.strip():
        raise ValueError(f"{label} is empty or not a string")
    if "\x00" in path or "\n" in path or "\r" in path:
        raise ValueError(f"{label} contains control characters: {path!r}")
    if not path.startswith("/"):
        raise ValueError(f"{label} must be an absolute path (got {path!r})")
    if path.rstrip("/") == "":
        raise ValueError(f"{label} must not be the filesystem root")
    return path


# ---------------------------------------------------------------------------
# Host keys
# ---------------------------------------------------------------------------

def fingerprint_sha256(key: Any) -> str:
    """OpenSSH-style fingerprint, e.g. 'SHA256:AbC...' (no base64 padding)."""
    digest = hashlib.sha256(key.asbytes()).digest()
    return "SHA256:" + base64.b64encode(digest).decode("ascii").rstrip("=")


def normalize_fingerprint(value: str) -> str:
    text = value.strip()
    if text.upper().startswith("SHA256:"):
        text = text[7:]
    return "SHA256:" + text.rstrip("=")


def default_known_hosts_path() -> Path:
    return Path.home() / ".ssl-auto" / "known_hosts"


class RejectUnknownPolicy(_PolicyBase):  # type: ignore[misc,valid-type]
    """Refuse hosts that are not already trusted (the safe default)."""

    def __init__(self, known_hosts_path: Path) -> None:
        self.known_hosts_path = known_hosts_path

    def missing_host_key(self, client: Any, hostname: str, key: Any) -> None:
        raise HostKeyVerificationError(
            f"Untrusted host key for {hostname}: {key.get_name()} {fingerprint_sha256(key)}. "
            f"Verify this fingerprint with the server owner, then either re-run with "
            f"--accept-new-hostkeys, pin it with 'host_key_sha256' in the config, "
            f"or add it to {self.known_hosts_path} / ~/.ssh/known_hosts."
        )


class PinnedKeyPolicy(_PolicyBase):  # type: ignore[misc,valid-type]
    """Accept an unknown host only if its key matches an operator-pinned fingerprint."""

    def __init__(self, expected_fingerprint: str) -> None:
        self.expected = normalize_fingerprint(expected_fingerprint)

    def missing_host_key(self, client: Any, hostname: str, key: Any) -> None:
        actual = fingerprint_sha256(key)
        if actual != self.expected:
            raise HostKeyVerificationError(
                f"Host key fingerprint mismatch for {hostname}: "
                f"expected {self.expected}, server presented {actual}. "
                f"Refusing to connect (possible man-in-the-middle)."
            )


class AcceptNewPolicy(_PolicyBase):  # type: ignore[misc,valid-type]
    """Trust-on-first-use: remember unknown hosts, but never override a changed key.

    A *changed* key for a known host is rejected by paramiko itself before this
    policy is consulted, so TOFU cannot be used to silently accept a MITM later.
    """

    def __init__(
        self,
        known_hosts_path: Path,
        notice: Optional[Callable[[str], None]] = None,
    ) -> None:
        self.known_hosts_path = known_hosts_path
        self.notice = notice

    def missing_host_key(self, client: Any, hostname: str, key: Any) -> None:
        fp = fingerprint_sha256(key)
        client.get_host_keys().add(hostname, key.get_name(), key)
        _append_known_host(self.known_hosts_path, hostname, key)
        if self.notice:
            self.notice(
                f"Trusted new host key for {hostname}: {key.get_name()} {fp} "
                f"(saved to {self.known_hosts_path})"
            )


def _append_known_host(path: Path, hostname: str, key: Any) -> None:
    from paramiko.hostkeys import HostKeyEntry

    line = HostKeyEntry([hostname], key).to_line()
    if line is None:
        return
    with _known_hosts_lock:
        path.parent.mkdir(parents=True, exist_ok=True)
        if os.name == "posix":
            try:
                os.chmod(path.parent, 0o700)
            except OSError:
                pass
        needs_newline = False
        if path.exists() and path.stat().st_size:
            with open(path, "rb") as probe:
                probe.seek(-1, os.SEEK_END)
                needs_newline = probe.read(1) != b"\n"
        fd = os.open(str(path), os.O_WRONLY | os.O_CREAT | os.O_APPEND, 0o600)
        with os.fdopen(fd, "a", encoding="utf-8") as fh:
            if needs_newline:
                fh.write("\n")
            fh.write(line)


def build_host_key_policy(
    *,
    policy: str,
    pinned_fingerprint: Optional[str],
    known_hosts_path: Path,
    notice: Optional[Callable[[str], None]] = None,
) -> Any:
    if pinned_fingerprint:
        return PinnedKeyPolicy(pinned_fingerprint)
    if policy == POLICY_ACCEPT_NEW:
        return AcceptNewPolicy(known_hosts_path, notice)
    if policy == POLICY_STRICT:
        return RejectUnknownPolicy(known_hosts_path)
    raise ValueError(
        f"unknown host_key_policy {policy!r}; expected one of {VALID_HOST_KEY_POLICIES}"
    )


# ---------------------------------------------------------------------------
# Connection
# ---------------------------------------------------------------------------

def connect_ssh(
    server_cfg: Dict[str, Any],
    *,
    policy: str = POLICY_STRICT,
    known_hosts_path: Optional[Path] = None,
    password: Optional[str] = None,
    key_passphrase: Optional[str] = None,
    timeout: int = 30,
    notice: Optional[Callable[[str], None]] = None,
    sock: Any = None,
) -> Any:
    """Open a verified SSH connection. Raises on any host-key problem.

    `sock` is an already-open channel (a tunnel through a jump host); when given, the
    connection is made over it instead of a fresh TCP socket."""
    if not HAS_PARAMIKO:
        raise RuntimeError("paramiko not installed. Run: pip install paramiko")

    host = server_cfg.get("host")
    if not host:
        raise ValueError("server has no 'host'")
    port = int(server_cfg.get("port", 22))
    kh_path = known_hosts_path or default_known_hosts_path()

    client = paramiko.SSHClient()
    client.load_system_host_keys()
    if kh_path.is_file():
        client.load_host_keys(str(kh_path))
    client.set_missing_host_key_policy(
        build_host_key_policy(
            policy=policy,
            pinned_fingerprint=server_cfg.get("host_key_sha256"),
            known_hosts_path=kh_path,
            notice=notice,
        )
    )

    kwargs: Dict[str, Any] = {
        "hostname": host,
        "port": port,
        "username": server_cfg.get("user", "root"),
        "timeout": timeout,
        "banner_timeout": timeout,
        "auth_timeout": timeout,
        "allow_agent": True,
        "look_for_keys": True,
    }
    key_file = server_cfg.get("key_file")
    if key_file:
        kwargs["key_filename"] = str(Path(os.path.expandvars(os.path.expanduser(str(key_file)))))
    if password:
        kwargs["password"] = password
    if key_passphrase:
        kwargs["passphrase"] = key_passphrase
    if sock is not None:
        kwargs["sock"] = sock
    try:
        client.connect(**kwargs)
    except BaseException:
        client.close()
        raise
    return client


class RemoteHost:
    """Wraps one paramiko client: command runner + cached SFTP session."""

    def __init__(self, client: Any, name: str = "") -> None:
        self.client = client
        self.name = name
        self._sftp: Any = None

    def sftp(self) -> Any:
        if self._sftp is None:
            self._sftp = self.client.open_sftp()
        return self._sftp

    def run(
        self,
        command: str,
        *,
        timeout: int = DEFAULT_COMMAND_IDLE_TIMEOUT,
        stdin_data: Optional[str] = None,
    ) -> Tuple[int, str, str]:
        return run_command(self.client, command, timeout=timeout, stdin_data=stdin_data)

    def close(self) -> None:
        if self._sftp is not None:
            try:
                self._sftp.close()
            except Exception:
                pass
            self._sftp = None
        try:
            self.client.close()
        except Exception:
            pass
        # Tear down the jump-host connections last (they carry the tunnel).
        for jump in reversed(getattr(self.client, "_ssl_auto_jumps", [])):
            try:
                jump.close()
            except Exception:
                pass


def run_command(
    client: Any,
    command: str,
    *,
    timeout: int = DEFAULT_COMMAND_IDLE_TIMEOUT,
    stdin_data: Optional[str] = None,
) -> Tuple[int, str, str]:
    """Run a command and return (exit_code, stdout, stderr).

    Drains stdout and stderr while the command runs, so a chatty command can
    never deadlock on a full SSH window (the classic `recv_exit_status()` then
    `read()` bug). `timeout` is an *idle* timeout; the hard cap bounds the total.
    """
    transport = client.get_transport()
    if transport is None or not transport.is_active():
        raise ConnectionError("SSH connection is not active")
    chan = transport.open_session(timeout=timeout)
    out = bytearray()
    err = bytearray()
    try:
        chan.exec_command(command)
        if stdin_data is not None:
            chan.sendall(stdin_data.encode("utf-8"))
        chan.shutdown_write()

        started = last_progress = time.monotonic()
        while True:
            progressed = False
            while chan.recv_ready():
                chunk = chan.recv(65536)
                if not chunk:
                    break
                if len(out) < MAX_COMMAND_OUTPUT_BYTES:
                    out += chunk
                progressed = True
            while chan.recv_stderr_ready():
                chunk = chan.recv_stderr(65536)
                if not chunk:
                    break
                if len(err) < MAX_COMMAND_OUTPUT_BYTES:
                    err += chunk
                progressed = True
            if chan.exit_status_ready() and not chan.recv_ready() and not chan.recv_stderr_ready():
                break
            now = time.monotonic()
            if progressed:
                last_progress = now
            elif now - last_progress > timeout:
                raise TimeoutError(f"command produced no output for {timeout}s")
            if now - started > max(COMMAND_HARD_CAP_SECONDS, timeout):
                raise TimeoutError("command exceeded the maximum run time")
            if not progressed:
                time.sleep(0.05)
        code = chan.recv_exit_status()
    finally:
        try:
            chan.close()
        except Exception:
            pass
    return code, out.decode("utf-8", errors="replace"), err.decode("utf-8", errors="replace")


# ---------------------------------------------------------------------------
# Jump hosts (ProxyJump) and ~/.ssh/config aliases
# ---------------------------------------------------------------------------

_HOP_SPEC_RE = re.compile(
    r"^(?:(?P<user>[A-Za-z0-9._\-]+)@)?(?P<host>\[[0-9A-Fa-f:.]+\]|[A-Za-z0-9._\-]+)(?::(?P<port>\d{1,5}))?$"
)


def default_ssh_config_path() -> Path:
    return Path.home() / ".ssh" / "config"


def load_ssh_config(path: Optional[Path] = None) -> Any:
    """Parse an OpenSSH client config; None if there is none."""
    config_path = Path(path) if path else default_ssh_config_path()
    if not HAS_PARAMIKO or not config_path.is_file():
        return None
    try:
        return paramiko.SSHConfig.from_path(str(config_path))
    except Exception as exc:
        raise ValueError(f"could not parse {config_path}: {exc}") from exc


def parse_hop_spec(spec: str) -> Dict[str, Any]:
    """`[user@]host[:port]` -> hop dict."""
    match = _HOP_SPEC_RE.match(spec.strip())
    if not match:
        raise ValueError(f"cannot understand host {spec!r} (expected [user@]host[:port])")
    hop: Dict[str, Any] = {"name": spec.strip(), "host": match.group("host").strip("[]")}
    if match.group("user"):
        hop["user"] = match.group("user")
    if match.group("port"):
        port = int(match.group("port"))
        if not 1 <= port <= 65535:
            raise ValueError(f"port {port} is out of range in {spec!r}")
        hop["port"] = port
    return hop


def hop_from_ssh_config(alias: str, ssh_config: Any) -> Optional[Dict[str, Any]]:
    """Resolve `alias` from ~/.ssh/config (HostName, Port, User, IdentityFile, ProxyJump)."""
    if ssh_config is None:
        return None
    patterns = ssh_config.get_hostnames()
    defined = alias in patterns or any(
        fnmatch.fnmatchcase(alias, p) for p in patterns if p not in ("*", "") and ("*" in p or "?" in p)
    )
    if not defined:
        return None
    entry = ssh_config.lookup(alias)
    if entry.get("proxycommand"):
        raise ValueError(
            f"ssh config host '{alias}' uses ProxyCommand, which is not supported; use ProxyJump instead"
        )
    hop: Dict[str, Any] = {"name": alias, "host": entry.get("hostname", alias), "port": int(entry.get("port", 22))}
    if entry.get("user"):
        hop["user"] = entry["user"]
    identity = entry.get("identityfile") or []
    for candidate in [identity] if isinstance(identity, str) else identity:
        expanded = Path(os.path.expandvars(os.path.expanduser(str(candidate))))
        if expanded.is_file():
            hop["key_file"] = str(expanded)
            break
    if entry.get("proxyjump"):
        hop["proxy_jump"] = entry["proxyjump"]
    return hop


def _proxy_specs(value: Any) -> List[str]:
    if value in (None, "", False):
        return []
    if isinstance(value, str):
        items = [part.strip() for part in value.split(",")]
    elif isinstance(value, (list, tuple)):
        items = [str(part).strip() for part in value]
    else:
        raise ValueError("proxy_jump must be a string or a list of strings")
    items = [item for item in items if item]
    return [] if len(items) == 1 and items[0].lower() == "none" else items


def _effective_hop(
    cfg: Dict[str, Any], name: str, ssh_config: Any, defaults: Optional[Dict[str, Any]]
) -> Dict[str, Any]:
    """Merge: explicit settings > ~/.ssh/config alias > the config's `ssh:` defaults > root/22."""
    out: Dict[str, Any] = {}
    alias = cfg.get("ssh_alias")
    if alias:
        base = hop_from_ssh_config(str(alias), ssh_config)
        if base is None:
            raise ValueError(f"ssh_alias '{alias}' (server '{name}') was not found in ~/.ssh/config")
        out.update(base)
    out.update({k: v for k, v in cfg.items() if v not in (None, "") and k not in ("services", "ssh_alias")})
    d = defaults or {}
    if not out.get("user"):
        out["user"] = d.get("user") or "root"
    if not out.get("port"):
        out["port"] = d.get("port") or 22
    if not out.get("key_file") and (d.get("key") or d.get("key_file")):
        out["key_file"] = d.get("key") or d.get("key_file")
    if not out.get("host"):
        raise ValueError(f"server '{name}' has no host (set 'host' or 'ssh_alias')")
    out["port"] = int(out["port"])
    out.setdefault("name", name)
    return out


def resolve_hops(
    name: str,
    cfg: Dict[str, Any],
    servers: Dict[str, Any],
    ssh_config: Any,
    defaults: Optional[Dict[str, Any]] = None,
    _stack: Tuple[str, ...] = (),
) -> Tuple[Dict[str, Any], List[Dict[str, Any]]]:
    """Return (effective target settings, jump hops in connect order).

    A `proxy_jump` entry may name another server in the config, an alias from
    ~/.ssh/config, or `[user@]host[:port]`. Jump hosts that themselves have a
    ProxyJump are followed (like OpenSSH), and loops are rejected."""
    if name in _stack:
        raise ValueError("proxy_jump loop: " + " -> ".join(_stack + (name,)))
    stack = _stack + (name,)
    target = _effective_hop(cfg, name, ssh_config, defaults)
    hops: List[Dict[str, Any]] = []
    for index, spec in enumerate(_proxy_specs(target.get("proxy_jump"))):
        if spec in servers:
            sub_cfg: Optional[Dict[str, Any]] = servers[spec]
        else:
            sub_cfg = hop_from_ssh_config(spec, ssh_config) or parse_hop_spec(spec)
        if not isinstance(sub_cfg, dict):
            raise ValueError(f"jump host '{spec}' is not a valid server entry")
        sub_target, sub_hops = resolve_hops(spec, sub_cfg, servers, ssh_config, defaults, stack)
        if index == 0:  # later entries are reached *through* the earlier ones
            hops.extend(sub_hops)
        hops.append(sub_target)
    return target, hops


def describe_route(hops: List[Dict[str, Any]], target: Dict[str, Any]) -> str:
    def label(hop: Dict[str, Any]) -> str:
        return f"{hop.get('user', 'root')}@{hop['host']}:{hop.get('port', 22)}"

    return " -> ".join([label(h) for h in hops] + [label(target)])


def _env_suffix(name: str) -> str:
    return re.sub(r"[^A-Za-z0-9]", "_", name or "").upper()


def _is_auth_failure(exc: BaseException) -> bool:
    """Authentication failed (as opposed to a host-key or network problem)."""
    if not HAS_PARAMIKO or isinstance(exc, (HostKeyVerificationError, paramiko.BadHostKeyException)):
        return False
    if isinstance(exc, paramiko.AuthenticationException):
        return True
    return type(exc) is paramiko.SSHException and "authentication methods" in str(exc).lower()


def _connect_hop(
    hop: Dict[str, Any],
    open_sock: Callable[[], Any],
    password: Optional[str],
    *,
    password_for: Optional[Callable[[Dict[str, Any]], Optional[str]]],
    **kwargs: Any,
) -> Any:
    def attempt(pw: Optional[str]) -> Any:
        sock = open_sock()  # a fresh tunnel per attempt (a failed login closes the old one)
        try:
            return connect_ssh(hop, password=pw, sock=sock, **kwargs)
        except BaseException:
            if sock is not None:
                try:
                    sock.close()
                except Exception:
                    pass
            raise

    try:
        return attempt(password)
    except Exception as exc:
        # Keys/agent were tried first; only now ask for a password (if the caller can).
        if password is None and password_for is not None and _is_auth_failure(exc):
            typed = password_for(hop)
            if typed:
                return attempt(typed)
        raise


def connect_chain(
    hops: List[Dict[str, Any]],
    target: Dict[str, Any],
    *,
    policy: str = POLICY_STRICT,
    known_hosts_path: Optional[Path] = None,
    target_password: Optional[str] = None,
    password_for: Optional[Callable[[Dict[str, Any]], Optional[str]]] = None,
    key_passphrase: Optional[str] = None,
    timeout: int = 30,
    notice: Optional[Callable[[str], None]] = None,
) -> Any:
    """Connect to `target` through zero or more jump hosts.

    Every hop is host-key verified with the same policy. Passwords are per hop:
    a hop's own `password`, or SSH_PASSWORD_<NAME>, or `password_for(hop)`. The
    *target's* password is never offered to a jump host."""
    chain = list(hops) + [target]
    clients: List[Any] = []
    try:
        previous: Any = None
        for index, hop in enumerate(chain):
            is_target = index == len(chain) - 1
            if is_target:
                password = target_password or hop.get("password")
            else:
                password = hop.get("password") or os.environ.get("SSH_PASSWORD_" + _env_suffix(hop.get("name", "")))

            def open_sock(prev: Any = previous, hop: Dict[str, Any] = hop) -> Any:
                if prev is None:
                    return None
                transport = prev.get_transport()
                if transport is None or not transport.is_active():
                    raise ConnectionError("jump host connection is no longer active")
                return transport.open_channel(
                    "direct-tcpip", (hop["host"], int(hop.get("port", 22))), ("127.0.0.1", 0), timeout=timeout
                )

            client = _connect_hop(
                hop,
                open_sock,
                password,
                password_for=password_for,
                policy=policy,
                known_hosts_path=known_hosts_path,
                key_passphrase=key_passphrase,
                timeout=timeout,
                notice=notice,
            )
            clients.append(client)
            previous = client
        final = clients[-1]
        final._ssl_auto_jumps = clients[:-1]
        return final
    except BaseException:
        for opened in reversed(clients):
            try:
                opened.close()
            except Exception:
                pass
        raise
