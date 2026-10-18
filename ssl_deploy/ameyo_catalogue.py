"""Reusable Ameyo/CRM service catalogue for YAML deploy configs.

A customer config sets `ameyo_profile:` (SSL dir, JKS name, etc.) and then
references catalogue roles by name (`role: appserver`) instead of writing
out a full service definition + hooks by hand. See catalogues/ameyo.yaml.
"""
from __future__ import annotations

from pathlib import Path
from string import Template
from typing import Any, Dict, Optional

from ssl_cert_tool.paths import bundle_dir

try:
    import yaml

    HAS_YAML = True
except ImportError:
    HAS_YAML = False

# bundle_dir() is the project root from source and sys._MEIPASS inside a PyInstaller exe,
# which is where the build puts catalogues/ (--add-data "catalogues;catalogues").
DEFAULT_CATALOGUE_PATH = bundle_dir() / "catalogues" / "ameyo.yaml"


def _load_catalogue(path: Path) -> Dict[str, Any]:
    if not HAS_YAML:
        raise RuntimeError("PyYAML not installed. Run: pip install pyyaml")
    if not path.is_file():
        raise FileNotFoundError(f"Ameyo catalogue not found: {path}")
    return yaml.safe_load(path.read_text(encoding="utf-8")) or {}


def _ameyoctl_guard(service: str, wait: int = 5, faststop: bool = False) -> str:
    """Reproduce ameyo.roles' _r_if/_r_fast: restart a service only if it is
    currently RUNNING, so a service that's intentionally down doesn't get
    started by a cert deploy."""
    stop_verb = "faststop" if faststop else "stop"
    label = f"{service} (faststop)" if faststop else service
    return (
        f"if ameyoctl status 2>/dev/null | grep -qE '^{service}[[:space:]]+is RUNNING'; then "
        f"echo '>> restarting {label}'; ameyoctl service {service} {stop_verb}; "
        f"sleep {wait}; ameyoctl service {service} start; "
        f"ameyoctl status 2>/dev/null | grep -E '^{service}[[:space:]]'; "
        f"else echo '>> SKIP {service} (not running)'; fi"
    )


def _substitute(value: Any, variables: Dict[str, str]) -> Any:
    if isinstance(value, str):
        return Template(value).safe_substitute(variables)
    if isinstance(value, list):
        return [_substitute(v, variables) for v in value]
    if isinstance(value, dict):
        return {k: _substitute(v, variables) for k, v in value.items()}
    return value


# Characters that could break out of the quoting used in catalogue hooks.
_UNSAFE_VALUE_CHARS = frozenset("'\"`$\\\n\r\x00")


def _reject_unsafe(name: str, value: Any) -> str:
    """Profile values are spliced into shell snippets; refuse anything that could
    end a quoted string or start a substitution."""
    text = str(value)
    bad = sorted(c for c in text if c in _UNSAFE_VALUE_CHARS)
    if bad:
        raise ValueError(
            f"ameyo_profile/config value for '{name}' contains unsafe shell characters "
            f"({' '.join(repr(c) for c in bad)}); remove them"
        )
    return text


def _single_quote_escape(value: Any) -> str:
    """Make `value` safe inside '...' (the catalogue wraps secrets in single quotes)."""
    return str(value).replace("'", "'\\''")


def _build_variables(profile: Dict[str, Any], config: Dict[str, Any]) -> Dict[str, str]:
    java_dir = _reject_unsafe("java_dir", profile.get("java_dir", "/usr/lib/jvm/java-1.8.0-amazon-corretto"))
    ssl_dir = _reject_unsafe("ssl_dir", profile.get("ssl_dir", ""))
    jks_name = _reject_unsafe("jks_name", profile.get("jks_name", "keystore.jks"))
    keystore = config.get("keystore") or {}
    return {
        "domain": _reject_unsafe("domain", config.get("domain", "")),
        "ssl_dir": ssl_dir,
        "jks_name": jks_name,
        "jks_path": f"{ssl_dir.rstrip('/')}/{jks_name}" if ssl_dir else jks_name,
        # Secrets may legitimately contain quotes/$; escape instead of rejecting.
        "jks_pass": _single_quote_escape(keystore.get("password", "changeit")),
        "jks_alias": _single_quote_escape(keystore.get("alias", "ameyo-server")),
        "ca_bundle_legacy": _reject_unsafe("ca_bundle_legacy", profile.get("ca_bundle_legacy", "")),
        "java_dir": java_dir,
        "keytool": _reject_unsafe("keytool", profile.get("keytool", f"{java_dir}/jre/bin/keytool")),
        "cacerts": _reject_unsafe("cacerts", profile.get("cacerts", f"{java_dir}/jre/lib/security/cacerts")),
        "asterisk_keys": _reject_unsafe("asterisk_keys", profile.get("asterisk_keys", "")),
    }


def _render_role(
    role_def: Dict[str, Any], hooks_catalogue: Dict[str, str], variables: Dict[str, str]
) -> Dict[str, Any]:
    rendered = dict(_substitute(role_def, variables))

    restart = rendered.get("restart")
    if isinstance(restart, dict) and "ameyoctl_guard" in restart:
        rendered["restart"] = _ameyoctl_guard(
            restart["ameyoctl_guard"],
            wait=int(restart.get("wait", 5)),
            faststop=bool(restart.get("faststop", False)),
        )

    hook_names = rendered.pop("hooks", None) or []
    rendered["hooks"] = [
        Template(hooks_catalogue[name]).safe_substitute(variables) for name in hook_names
    ]
    return rendered


def expand_ameyo_profile(
    config: Dict[str, Any], catalogue_path: Optional[Path] = None
) -> Dict[str, Any]:
    """If `config` has an `ameyo_profile:` block, expand any service with a
    `role:` key into a full service definition from the Ameyo catalogue,
    substituting ${var} placeholders. No-op otherwise."""
    profile = config.get("ameyo_profile")
    if not profile:
        return config

    catalogue = _load_catalogue(catalogue_path or DEFAULT_CATALOGUE_PATH)
    variables = _build_variables(profile, config)
    roles = catalogue.get("roles", {})
    hooks_catalogue = catalogue.get("hooks", {})

    cfg = dict(config)
    services = dict(cfg.get("services") or {})
    for name, entry in list(services.items()):
        if not isinstance(entry, dict) or "role" not in entry:
            continue
        role_name = entry["role"]
        role_def = roles.get(role_name)
        if role_def is None:
            raise ValueError(f"Service '{name}' references unknown Ameyo role '{role_name}'")
        rendered = _render_role(role_def, hooks_catalogue, variables)
        overrides = {k: v for k, v in entry.items() if k != "role"}
        services[name] = {**rendered, **overrides}
    cfg["services"] = services
    return cfg
