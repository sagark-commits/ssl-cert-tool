#!/usr/bin/env python3
"""
ssl-auto: Universal SSL certificate generation and deployment.

Works on Windows, macOS, and Linux with a single Python entry point.
Supports ANY domain, ANY server configuration via YAML config files.
"""
from __future__ import annotations

import argparse
import os
import posixpath
import re
import subprocess
import sys
from pathlib import Path

# Bootstrap paths for source and PyInstaller frozen builds
if getattr(sys, "frozen", False) and hasattr(sys, "_MEIPASS"):
    _meipass = str(sys._MEIPASS)
    if _meipass not in sys.path:
        sys.path.insert(0, _meipass)
    _SCRIPT_DIR = Path(sys.executable).resolve().parent
else:
    _SCRIPT_DIR = Path(__file__).resolve().parent
if str(_SCRIPT_DIR) not in sys.path:
    sys.path.insert(0, str(_SCRIPT_DIR))

try:
    from ssl_cert_tool.paths import app_dir

    _SCRIPT_DIR = app_dir()
except Exception:
    pass


def check_dependencies() -> None:
    missing: list[str] = []
    try:
        import cryptography  # noqa: F401
    except ImportError:
        missing.append("cryptography")
    if missing:
        print("Missing dependencies:", ", ".join(missing))
        print("Run: python setup.py")
        sys.exit(1)


check_dependencies()

from ssl_cert_tool import __version__  # noqa: E402
from ssl_cert_tool import jks as jks_store  # noqa: E402
from ssl_cert_tool.core import (  # noqa: E402
    BuildResult,
    EncryptedKeyError,
    KEYTOOL_PASS_ENV,
    build_outputs,
    cert_cn,
    classify_certs,
    collect_input_files,
    compare_certs,
    format_cert_comparison,
    format_inspect_report,
    format_jks_info,
    infer_domain,
    inspect_inputs,
    keytool_env,
    load_private_key,
    parse_all_inputs,
    public_numbers_match,
    read_jks_info,
    read_jks_info_from_p12,
    validate_key_cert,
)
from ssl_cert_tool.platform import (  # noqa: E402
    Terminal,
    detect_os,
    find_keytool,
    normalize_path,
)
from ssl_deploy.deployer import CopyItem, SSLDeployer, load_deploy_config  # noqa: E402
from ssl_deploy.ssh import (  # noqa: E402
    POLICY_ACCEPT_NEW,
    RemoteHost,
    connect_ssh,
    hop_from_ssh_config,
    load_ssh_config,
    parse_hop_spec,
    validate_remote_path,
)

SUPPORTED_FORMATS = """
Supported input formats:
  .crt, .cer, .pem  - PEM or DER encoded certificates
  .p7b, .p7c        - PKCS7 certificate chains
  .p12, .pfx        - PKCS12 keystores (use --p12-password if encrypted)
  .ca-bundle        - Multiple PEM certificates concatenated
  .eml              - Email files (e.g., GlobalSign certificate emails)
  .txt, .docx       - Text/Word with PEM blocks
  .zip, .7z         - Archives (7z needs py7zr)
  Folders           - Recursively scans by content
"""

CONFIGS_DIR = _SCRIPT_DIR / "configs"


def infer_domain_from_key_path(key_path: Path | None) -> str | None:
    if key_path is None:
        return None
    match = re.search(r"([a-z0-9][-a-z0-9.]*\.[a-z]{2,})", key_path.stem, re.IGNORECASE)
    return match.group(1).lower() if match else None


def filter_inputs_for_key_domain(files: list[Path], key_path: Path | None) -> list[Path]:
    domain = infer_domain_from_key_path(key_path)
    if not domain:
        return files
    domain_hits = [f for f in files if domain in f.name.lower()]
    if not domain_hits:
        return files
    filtered = list(domain_hits)
    if key_path is not None:
        resolved_key = normalize_path(str(key_path))
        if resolved_key not in filtered and resolved_key in files:
            filtered.append(resolved_key)
    return filtered


def path_arg(value: str) -> Path:
    if not value or not value.strip():
        raise argparse.ArgumentTypeError("Path cannot be empty")
    return normalize_path(value)


def resolve_config_path(config_arg: Path | str | None) -> Path | None:
    """Resolve configuration file path with fallback search."""
    if config_arg is not None:
        # Handle string or Path input
        if isinstance(config_arg, str):
            config_arg = config_arg.strip()
            # Check if it's just a name (no path separators, no extension)
            if "/" not in config_arg and "\\" not in config_arg:
                # Try as config name first
                name = config_arg.replace(".yaml", "").replace(".yml", "")
                for ext in (".yaml", ".yml"):
                    candidate = CONFIGS_DIR / f"{name}{ext}"
                    if candidate.is_file():
                        return candidate
            # Try as a path
            config_arg = normalize_path(config_arg)

        if config_arg.is_file():
            return config_arg

        # Check if it's a name without path (e.g., "asnb" -> configs/asnb.yaml)
        if hasattr(config_arg, 'stem'):
            name = config_arg.stem
            for ext in (".yaml", ".yml"):
                candidate = CONFIGS_DIR / f"{name}{ext}"
                if candidate.is_file():
                    return candidate
        return None

    # No explicit config - search for defaults
    search_order = [
        _SCRIPT_DIR / "deploy-config.yaml",
        _SCRIPT_DIR / "deploy-config.yml",
        CONFIGS_DIR / "default.yaml",
        CONFIGS_DIR / "default.yml",
    ]
    for candidate in search_order:
        if candidate.is_file():
            return candidate
    return None


def read_secret(env_name: str | None = None, file_path: Path | None = None) -> str | None:
    """Read a secret from an environment variable or a file (never from argv)."""
    if env_name:
        value = os.environ.get(env_name)
        if value is None:
            raise SystemExit(f"Error: environment variable {env_name} is not set")
        return value
    if file_path:
        try:
            text = Path(file_path).read_text(encoding="utf-8")
        except OSError as exc:
            raise SystemExit(f"Error: cannot read secret file {file_path}: {exc}")
        value = text.rstrip("\r\n")
        if not value:
            raise SystemExit(f"Error: secret file {file_path} is empty")
        return value
    return None


def explicit_password(args: argparse.Namespace) -> str | None:
    """Keystore password from -p, --password-env or --password-file (in that order)."""
    direct = getattr(args, "store_pass", None)
    if direct is not None:
        return direct
    return read_secret(getattr(args, "password_env", None), getattr(args, "password_file", None))


def get_key_password(args: argparse.Namespace) -> str | None:
    """Passphrase for an encrypted private key: --key-password or SSL_KEY_PASSWORD."""
    return getattr(args, "key_password", None) or os.environ.get("SSL_KEY_PASSWORD") or None


def resolve_store_pass(
    explicit: str | None,
    domain: str,
    config_path: Path | None,
    from_old_pass: str | None = None,
) -> tuple[str, str]:
    if explicit is not None:
        return explicit, "CLI --password"
    if from_old_pass is not None:
        return from_old_pass, "imported from old keystore"
    if config_path and config_path.is_file():
        try:
            cfg = load_deploy_config(config_path)
            keystore = cfg.get("keystore") or {}
            password = keystore.get("password") or keystore.get("keystore_pass")
            if password:
                return password, config_path.name
        except Exception:
            pass
    return "changeit", "default"


def resolve_alias(
    explicit: str,
    config_path: Path | None,
    from_old_alias: str | None = None,
) -> str:
    if explicit != "server-cert":
        return explicit
    if from_old_alias:
        return from_old_alias
    if config_path and config_path.is_file():
        try:
            cfg = load_deploy_config(config_path)
            alias = (cfg.get("keystore") or {}).get("alias")
            if alias:
                return alias
        except Exception:
            pass
    return explicit


def add_input_options(parser: argparse.ArgumentParser) -> None:
    parser.add_argument(
        "--input",
        nargs="+",
        metavar="PATH",
        help="Certificate files, folders, or mixed paths",
    )
    parser.add_argument("--input-dir", metavar="DIR", help="Scan a folder for certificate files")
    parser.add_argument("-k", "--key", type=path_arg, help="Private key file")
    parser.add_argument("-o", "--output", type=path_arg, help="Output directory")
    parser.add_argument("-d", "--domain", help="Domain name (auto-detected from leaf CN)")

    pass_group = parser.add_argument_group("Password/Alias Options")
    pass_group.add_argument(
        "-p", "--password", dest="store_pass", default=None,
        help="Keystore password (default: changeit). Visible in the process list - "
             "prefer --password-env or --password-file"
    )
    pass_group.add_argument(
        "--password-env", metavar="VAR", default=None,
        help="Read the keystore password from this environment variable"
    )
    pass_group.add_argument(
        "--password-file", type=path_arg, metavar="FILE", default=None,
        help="Read the keystore password from this file"
    )
    pass_group.add_argument(
        "--key-password", default=None,
        help="Passphrase for an encrypted private key (or set SSL_KEY_PASSWORD)"
    )
    pass_group.add_argument(
        "--store-pass", dest="store_pass", default=None,
        help=argparse.SUPPRESS  # Hidden alias for --password
    )
    pass_group.add_argument(
        "-a", "--alias", default="server-cert",
        help="Keystore alias (default: server-cert)"
    )

    parser.add_argument("--keytool", type=path_arg, help="Path to keytool executable")
    parser.add_argument("--p12-password", help="Password for encrypted PKCS12 inputs")

    old_cert_group = parser.add_argument_group("Import from Existing Certs")
    old_cert_group.add_argument(
        "--from-old", type=path_arg, metavar="PATH",
        help="Import alias from existing JKS/P12 file"
    )
    old_cert_group.add_argument(
        "--old-password", default=None,
        help="Password for old keystore (prompts if not provided)"
    )
    old_cert_group.add_argument(
        "--match-old", type=path_arg, metavar="PATH",
        help="Match all settings (alias, password) from old JKS"
    )


def add_ssh_trust_options(parser: argparse.ArgumentParser) -> None:
    parser.add_argument(
        "--accept-new-hostkeys", action="store_true",
        help="Trust and remember host keys of servers not yet in known_hosts "
             "(a CHANGED key is always refused). Default: refuse unknown hosts",
    )
    parser.add_argument(
        "--known-hosts", type=path_arg, metavar="FILE", default=None,
        help="known_hosts file this tool reads/writes (default: ~/.ssl-auto/known_hosts; "
             "~/.ssh/known_hosts is always consulted)",
    )
    parser.add_argument(
        "--ask-ssh-password", action="store_true",
        help="Prompt (hidden) for an SSH password when a host refuses your keys/agent. Asked once "
             "per user@host, so each jump host gets its own password",
    )
    parser.add_argument(
        "--ssh-config", type=path_arg, metavar="FILE", default=None,
        help="OpenSSH config used to resolve ssh_alias / proxy_jump names (default: ~/.ssh/config)",
    )


def make_password_prompt(args: argparse.Namespace):
    """--ask-ssh-password: a hidden prompt the deployer calls, per host, only after that
    host refused keys/agent. Returns None when the flag is off."""
    if not getattr(args, "ask_ssh_password", False):
        return None
    if not sys.stdin.isatty():
        raise SystemExit("Error: --ask-ssh-password needs an interactive terminal")
    import getpass

    def prompt(hop: dict) -> str:
        return getpass.getpass(f"Password for {hop.get('user', 'root')}@{hop['host']}:{hop.get('port', 22)}: ")

    return prompt


def deployer_trust_kwargs(args: argparse.Namespace) -> dict:
    return {
        "host_key_policy": POLICY_ACCEPT_NEW if getattr(args, "accept_new_hostkeys", False) else None,
        "known_hosts_path": getattr(args, "known_hosts", None),
        "password_prompt": make_password_prompt(args),
        "ssh_config_path": getattr(args, "ssh_config", None),
    }


def add_deploy_options(parser: argparse.ArgumentParser) -> None:
    parser.add_argument(
        "--config",
        type=path_arg,
        help="Deploy config YAML (searches ./deploy-config.yaml, ./configs/)",
    )
    parser.add_argument("--dry-run", action="store_true", help="Preview without making changes")
    parser.add_argument("--no-deploy", action="store_true", help="Generate only; skip deploy")
    parser.add_argument("--no-restart", action="store_true", help="Deploy without restarting services")
    parser.add_argument("--server", help="Deploy to one server only")
    parser.add_argument("--service", help="Deploy one service only")
    parser.add_argument("--parallel", action="store_true", help="Deploy to servers in parallel")
    parser.add_argument(
        "--skip-preflight", action="store_true",
        help="Skip the live ameyoctl pre-flight check before deploying",
    )
    add_ssh_trust_options(parser)
    parser.add_argument(
        "--skip-verify", action="store_true",
        help="Deploy even if the pre-deploy certificate/key checks fail (not recommended)",
    )
    parser.add_argument(
        "--no-auto-rollback", action="store_true",
        help="Leave files in place if a post-upload hook fails (default: restore them)",
    )
    parser.add_argument("--no-color", action="store_true", help="Disable colored output")


def collect_cli_inputs(args: argparse.Namespace) -> tuple[list[str], list[Path]]:
    raw_inputs: list[str] = []
    if getattr(args, "input", None):
        raw_inputs.extend(str(p) for p in args.input)
    if getattr(args, "input_dir", None):
        raw_inputs.append(str(args.input_dir))
    if not raw_inputs:
        raise SystemExit("Error: provide --input PATH [PATH ...] and/or --input-dir DIR")
    resolved = [normalize_path(raw) for raw in raw_inputs]
    return raw_inputs, resolved


def resolve_config(args: argparse.Namespace) -> Path | None:
    return resolve_config_path(getattr(args, "config", None))


def _load_key_file(path: Path, args: argparse.Namespace) -> object:
    """Load a key file, prompting for the passphrase if it is encrypted and we
    are on a terminal (never echoing it)."""
    password = get_key_password(args)
    data = path.read_bytes()
    try:
        return load_private_key(data, password)
    except EncryptedKeyError:
        if password is None and sys.stdin.isatty():
            import getpass

            return load_private_key(data, getpass.getpass(f"Passphrase for {path.name}: "))
        raise


def resolve_private_key(args: argparse.Namespace, keys: list) -> tuple[Path | None, object]:
    if args.key:
        try:
            return args.key, _load_key_file(args.key, args)
        except (OSError, ValueError) as exc:
            print(f"Error: could not load private key {args.key}: {exc}")
            sys.exit(1)
    if keys:
        return keys[0][0], keys[0][1]
    print("\nPrivate key not found in inputs.")
    while True:
        raw = input("Enter path to private key (.key / .pem): ").strip().strip('"')
        if not raw:
            continue
        path = normalize_path(raw)
        if not path.is_file():
            print(f"  File not found: {path}")
            continue
        try:
            return path, _load_key_file(path, args)
        except (OSError, ValueError) as exc:
            print(f"  Could not load key: {exc}")


def parse_step(term: Terminal, args: argparse.Namespace) -> tuple[list[Path], list, list, object]:
    _, input_paths = collect_cli_inputs(args)
    files = collect_input_files(input_paths)
    key_path = normalize_path(str(args.key)) if getattr(args, "key", None) else None
    files = filter_inputs_for_key_domain(files, key_path)
    if not files:
        print("No input files found.")
        sys.exit(1)

    term.detail(f"Found: scanning {len(files)} file(s)")
    all_certs, keys = parse_all_inputs(
        files, getattr(args, "p12_password", None), get_key_password(args)
    )
    term.detail(f"Found: {len(all_certs)} cert(s), {len(keys)} key(s) from input")
    _key_path, private_key = resolve_private_key(args, keys)
    return files, all_certs, keys, private_key


def run_generate(
    args: argparse.Namespace,
    term: Terminal,
    *,
    step_prefix: str = "",
    quiet: bool = False,
    show_parse: bool = True,
) -> tuple[Path, BuildResult, str, str]:
    # Handle --from-old and --match-old options
    from_old_alias = None
    from_old_pass = None
    if getattr(args, "from_old", None) or getattr(args, "match_old", None):
        from_old_alias, from_old_pass = resolve_from_old_settings(args, term)

    if show_parse:
        files, all_certs, keys, private_key = parse_step(term, args)
    else:
        _, input_paths = collect_cli_inputs(args)
        files = collect_input_files(input_paths)
        key_path = normalize_path(str(args.key)) if getattr(args, "key", None) else None
        files = filter_inputs_for_key_domain(files, key_path)
        if not files:
            print("No input files found.")
            sys.exit(1)
        all_certs, keys = parse_all_inputs(
            files, getattr(args, "p12_password", None), get_key_password(args)
        )
        _key_path, private_key = resolve_private_key(args, keys)

    leaf, intermediates, root = classify_certs(all_certs, args.domain)
    if leaf is None:
        term.error("Could not identify leaf/server certificate.")
        sys.exit(1)

    if not public_numbers_match(private_key, leaf.cert):
        # The inputs may hold several keys (old + new); use the one that fits,
        # unless the operator pointed at a specific key with --key.
        alternative = next(
            (k for _kp, k in keys if public_numbers_match(k, leaf.cert)), None
        )
        if alternative is not None and not getattr(args, "key", None):
            private_key = alternative
        else:
            term.error("Private key does not match leaf certificate!")
            sys.exit(1)

    domain = infer_domain(leaf, args.domain)
    output_dir = args.output or Path("output") / domain
    config_path = resolve_config(args)
    store_pass, pass_source = resolve_store_pass(
        explicit_password(args), domain, config_path, from_old_pass
    )
    if pass_source == "default" and not args.dry_run:
        term.warn(
            "  Using the default keystore password 'changeit'. Set keystore.password in the "
            "config or pass --password-env/--password-file for production."
        )
    alias = resolve_alias(args.alias, config_path, from_old_alias)

    keytool_path = args.keytool if getattr(args, "keytool", None) else find_keytool()
    if keytool_path is None:
        keytool_path = Path("keytool")

    if args.dry_run:
        term.detail(f"Would write to: {output_dir}")
        v = validate_key_cert(private_key, leaf)
        result = BuildResult(domain=domain, output_dir=output_dir, validation=v)
        return output_dir.resolve(), result, store_pass, alias

    if not quiet:
        if step_prefix:
            print(step_prefix, end="")
        term.detail(f"Building artifacts -> {output_dir}")

    result = build_outputs(
        domain=domain,
        output_dir=output_dir,
        leaf=leaf,
        intermediates=intermediates,
        root=root,
        private_key=private_key,
        store_pass=store_pass,
        alias=alias,
        keytool=keytool_path,
    )
    if not quiet:
        term.detail(f"Created {len(result.files)} file(s) in {output_dir}")
    return result.output_dir.resolve(), result, store_pass, alias


def validate_jks_password(jks_path: Path, password: str, alias: str, keytool: Path | None) -> bool:
    if not jks_path.is_file():
        return False
    kt = keytool or find_keytool()
    if kt is None or not Path(kt).exists() or os.environ.get("SSL_AUTO_BUILTIN_JKS"):
        # No JDK on this machine: check the keystore with the built-in reader.
        ok, _detail = jks_store.check_password(jks_path, password, alias)
        return ok
    cmd = [
        str(kt),
        "-list",
        "-keystore",
        str(jks_path),
        "-storepass:env",
        KEYTOOL_PASS_ENV,
        "-alias",
        alias,
    ]
    try:
        completed = subprocess.run(
            cmd, capture_output=True, text=True, env=keytool_env(password), timeout=120
        )
    except subprocess.TimeoutExpired:
        return False
    return completed.returncode == 0


def run_validation(
    term: Terminal,
    result: BuildResult,
    store_pass: str,
    alias: str,
    keytool: Path | None,
) -> bool:
    v = result.validation
    key_ok = v.get("key_cert_match", False)
    term.detail(f"Key/Cert match: {'PASS' if key_ok else 'FAIL'}")
    jks_path = result.output_dir / f"{result.domain}.jks"
    if jks_path.is_file():
        jks_ok = validate_jks_password(jks_path, store_pass, alias, keytool)
        masked = "*" * len(store_pass)
        term.detail(f"JKS password: {'PASS' if jks_ok else 'FAIL'} ({masked})")
    elif result.warnings:
        term.detail(f"JKS: skipped ({result.warnings[0]})")
    return key_ok


def print_preflight_report(term: Terminal, reports: list) -> None:
    print("\nPre-flight (live ameyoctl status):")
    for report in reports:
        host = report.get("host", report["server"])
        if report.get("error"):
            term.warn(f"  {report['server']} ({host}): {report['error']}")
            continue
        print(f"  {report['server']} ({host}):")
        if report.get("warning"):
            term.warn(f"    {report['warning']}")
        for row in report.get("rows", []):
            if row["ameyoctl"] is None:
                print(f"    {row['service']:<14} (no ameyoctl mapping)")
            else:
                state = {True: "RUNNING", False: "NOT_RUNNING", None: "UNKNOWN"}[row["running"]]
                print(f"    {row['service']:<14} -> {row['ameyoctl']:<20} {state}")
    print()


def run_deploy(
    args: argparse.Namespace,
    term: Terminal,
    certs_dir: Path,
    *,
    show_step: bool = True,
) -> int:
    config_path = resolve_config(args)
    if config_path is None:
        term.error("Deploy config not found.")
        term.error("Create a config file or use --config path/to/config.yaml")
        term.error("See configs/template.yaml for an example.")
        return 1

    if show_step:
        term.step(4, 4, "Deploying to servers...")

    deployer = SSLDeployer(
        config_path=config_path,
        cert_path=certs_dir,
        dry_run=args.dry_run,
        no_restart=getattr(args, "no_restart", False),
        parallel=getattr(args, "parallel", False),
        terminal=term,
        skip_verify=getattr(args, "skip_verify", False),
        auto_rollback=not getattr(args, "no_auto_rollback", False),
        key_password=get_key_password(args),
        **deployer_trust_kwargs(args),
    )
    if not deployer.load_config() or not deployer.validate_config():
        return 1

    server_filter = getattr(args, "server", None)
    if not getattr(args, "skip_preflight", False):
        reports = deployer.preflight_all(server_filter=server_filter)
        print_preflight_report(term, reports)
        broken = [r for r in reports if r.get("error")]
        if broken and not args.dry_run:
            term.error(
                "Pre-flight failed for: "
                + ", ".join(r["server"] for r in broken)
                + " - nothing was deployed. Fix the connection (or use --server / --skip-preflight)."
            )
            return 1

    deployer.deploy_all(
        server_filter=server_filter,
        service_filter=getattr(args, "service", None),
    )

    for server_name in deployer.config.get("servers", {}):
        if server_filter and server_name != server_filter:
            continue
        line = deployer.format_server_summary(server_name)
        if line:
            print(line)

    print()
    config_hint = f"--config {config_path}"
    if deployer.aborted_reason or deployer.failed_count:
        term.error("=== Deployment completed with errors ===")
        if not args.dry_run and deployer.failed_count and not deployer.aborted_reason:
            term.warn(f"  To undo: ssl-auto rollback {config_hint} --restart")
        return 1
    if not deployer.results and deployer.config.get("servers") and not args.dry_run:
        term.error("=== Nothing was deployed ===")
        return 1
    term.success("=== Deployment Complete ===")
    return 0


# =============================================================================
# COMMANDS
# =============================================================================

def cmd_inspect(args: argparse.Namespace) -> int:
    term = Terminal()
    if args.no_color:
        term.disable()
    _, input_paths = collect_cli_inputs(args)
    if not collect_input_files(input_paths):
        print("No input files found.")
        return 1
    key_path = normalize_path(str(args.key)) if args.key else None
    result = inspect_inputs(
        input_paths,
        key_path=key_path,
        p12_password=args.p12_password,
        domain_hint=args.domain,
        key_password=get_key_password(args),
    )
    print(format_inspect_report(result, domain_hint=args.domain), end="")
    return 0


def cmd_generate(args: argparse.Namespace) -> int:
    term = Terminal()
    if args.no_color:
        term.disable()
    term.step(1, 2, "Parsing input files...")
    output_dir, result, store_pass, alias = run_generate(args, term)
    term.step(2, 2, "Validating...")
    if not run_validation(term, result, store_pass, alias, find_keytool()):
        return 1
    if result.warnings:
        for warning in result.warnings:
            term.warn(f"  {warning}")
    term.success(f"Generated artifacts in {output_dir}")
    return 0


def cmd_deploy(args: argparse.Namespace) -> int:
    term = Terminal()
    if args.no_color:
        term.disable()
    if not args.certs:
        term.error("--certs is required for deploy")
        return 1
    certs_dir = normalize_path(str(args.certs))
    if not certs_dir.is_dir():
        term.error(f"Certificate directory not found: {certs_dir}")
        return 1
    return run_deploy(args, term, certs_dir)


def cmd_rollback(args: argparse.Namespace) -> int:
    term = Terminal()
    if args.no_color:
        term.disable()

    config_path = resolve_config_path(str(args.config) if args.config else None)
    if config_path is None:
        term.error(f"Config file not found: {args.config}")
        term.error("Try: --config configs/asnb.yaml or --config asnb")
        return 1

    deployer = SSLDeployer(
        config_path=config_path,
        dry_run=args.dry_run,
        terminal=term,
        **deployer_trust_kwargs(args),
    )
    if not deployer.load_config():
        return 1

    results = deployer.rollback_all(
        server_filter=getattr(args, "server", None),
        timestamp=getattr(args, "timestamp", None),
        restart=getattr(args, "restart", False),
    )
    if not results:
        term.warn("No servers matched - nothing to roll back")
        return 1

    failed = 0
    for result in results:
        if result.status.value == "failed":
            failed += 1
            term.error(f"  {result.server}: {result.message}")
        else:
            term.success(f"  {result.server}: {result.message}")

    print()
    if failed:
        term.error("=== Rollback completed with errors ===")
        return 1
    term.success("=== Rollback Complete ===")
    return 0


def cmd_preflight(args: argparse.Namespace) -> int:
    term = Terminal()
    if args.no_color:
        term.disable()

    config_path = resolve_config_path(str(args.config) if args.config else None)
    if config_path is None:
        term.error(f"Config file not found: {args.config}")
        term.error("Try: --config configs/asnb.yaml or --config asnb")
        return 1

    deployer = SSLDeployer(config_path=config_path, terminal=term, **deployer_trust_kwargs(args))
    if not deployer.load_config():
        return 1

    reports = deployer.preflight_all(server_filter=getattr(args, "server", None))
    if not reports:
        term.warn("No servers matched - nothing to check")
        return 1

    print_preflight_report(term, reports)
    if any(r.get("error") for r in reports):
        return 1
    return 0


_COPY_FILE_RE = re.compile(r"^(?P<src>.+?):(?P<dest>/[^:]*)(?::(?P<mode>[0-7]{3,4}))?$")


def parse_copy_file(spec: str) -> CopyItem:
    """SRC:/remote/path[:MODE] - the colon in a Windows drive letter is handled."""
    match = _COPY_FILE_RE.match(spec.strip().strip('"'))
    if not match:
        raise argparse.ArgumentTypeError(
            f"expected SRC:/absolute/remote/path[:MODE] (for example crt.pem:/etc/nginx/ssl/crt.pem:644), got {spec!r}"
        )
    mode = int(match.group("mode"), 8) if match.group("mode") else None
    return CopyItem(normalize_path(match.group("src").strip('"')), match.group("dest"), mode)


def cmd_copy(args: argparse.Namespace) -> int:
    """scp-style copy: verified, atomic, backed up, reversible - through jump hosts if needed."""
    term = Terminal()
    if args.no_color:
        term.disable()
    if bool(args.server) == bool(args.host):
        term.error("Give exactly one of --server NAME (with --config) or --host HOST")
        return 1
    if args.server and (args.user or args.via):
        term.error("--user and --via apply to --host; with --server set them in the config")
        return 1

    config_dict = None
    config_path = Path("<ad-hoc>")
    if args.server:
        config_path = resolve_config_path(getattr(args, "config", None))
        if config_path is None:
            term.error("Deploy config not found. Use --config path/to/config.yaml (or use --host)")
            return 1
        server_name = args.server
    else:
        server_name = "target"
        entry: dict = {}
        try:
            alias = hop_from_ssh_config(args.host, load_ssh_config(getattr(args, "ssh_config", None)))
            if alias is not None:
                entry["ssh_alias"] = args.host
            else:
                entry.update({k: v for k, v in parse_hop_spec(args.host).items() if k != "name"})
        except ValueError as exc:
            term.error(f"Cannot use --host {args.host!r}: {exc}")
            return 1
        if args.user:
            entry["user"] = args.user
        if args.via:
            entry["proxy_jump"] = args.via
        config_dict = {"servers": {server_name: entry}, "services": {}}

    deployer = SSLDeployer(
        config_path=config_path,
        dry_run=args.dry_run,
        terminal=term,
        skip_verify=args.skip_verify,
        key_password=get_key_password(args),
        config=config_dict,
        **deployer_trust_kwargs(args),
    )
    if not deployer.load_config():
        return 1
    if args.backup_dir:
        deployer.config["backup_dir"] = args.backup_dir
    if server_name not in (deployer.config.get("servers") or {}):
        term.error(f"Server '{server_name}' is not defined in {config_path}")
        return 1

    deployer.copy_files(server_name, args.file, check_cmd=args.check_cmd, reload_cmd=args.reload_cmd)
    print()
    for result in deployer.results:
        if result.status.value == "success":
            term.success(f"  {'would copy' if args.dry_run else 'copied'}  {result.message}")
        elif result.status.value == "failed":
            term.error(f"  FAILED  {result.service}: {result.message}")
        else:
            term.warn(f"  {result.status.value}  {result.service}: {result.message}")
    print()
    if deployer.aborted_reason or deployer.failed_count:
        term.error("=== Copy failed ===")
        return 1
    term.success("=== Copy Complete ===" + (" (dry run)" if args.dry_run else ""))
    return 0


def cmd_run(args: argparse.Namespace) -> int:
    term = Terminal()
    if args.no_color:
        term.disable()

    term.step(1, 4, "Parsing input files...")
    parse_step(term, args)

    term.step(2, 4, "Generating deployment artifacts...")
    output_dir, result, store_pass, alias = run_generate(
        args, term, quiet=True, show_parse=False
    )

    term.step(3, 4, "Validating...")
    if not run_validation(term, result, store_pass, alias, find_keytool()):
        return 1

    if args.no_deploy:
        term.success(f"=== Generation Complete === (output: {output_dir})")
        return 0

    term.step(4, 4, "Deploying to servers...")
    return run_deploy(args, term, output_dir, show_step=False)


def cmd_init(args: argparse.Namespace) -> int:
    """Initialize a new configuration file interactively."""
    term = Terminal()

    # Determine output path
    if args.output:
        output_path = normalize_path(str(args.output))
    elif args.name:
        output_path = CONFIGS_DIR / f"{args.name}.yaml"
    else:
        output_path = CONFIGS_DIR / "myconfig.yaml"

    # Check if file exists
    if output_path.exists() and not args.force:
        term.error(f"Config file already exists: {output_path}")
        term.error("Use --force to overwrite")
        return 1

    # Ensure configs directory exists
    output_path.parent.mkdir(parents=True, exist_ok=True)

    # Read template
    template_path = CONFIGS_DIR / "template.yaml"
    if not template_path.is_file():
        term.error(f"Template not found: {template_path}")
        return 1

    content = template_path.read_text(encoding="utf-8-sig")

    # Replace domain if provided (validated: it is written into YAML verbatim)
    if args.domain:
        if not re.fullmatch(r"[A-Za-z0-9*]([A-Za-z0-9*.-]*[A-Za-z0-9])?", args.domain):
            term.error(f"Invalid domain name: {args.domain!r}")
            return 1
        content = content.replace('domain: ""', f'domain: "{args.domain}"')

    # Write new config
    output_path.write_text(content, encoding="utf-8")
    term.success(f"Created config: {output_path}")
    print(f"\nNext steps:")
    print(f"  1. Edit {output_path} to configure your servers and services")
    print(f"  2. Run: python ssl-auto.py run --config {output_path} --input <certs> --key <key>")
    return 0


def cmd_configs(args: argparse.Namespace) -> int:
    """List available configuration files."""
    term = Terminal()

    print("Available configurations:\n")

    # Check deploy-config.yaml in root
    root_config = _SCRIPT_DIR / "deploy-config.yaml"
    if root_config.is_file():
        try:
            cfg = load_deploy_config(root_config)
            domain = cfg.get("domain", "(no domain)")
            servers = list(cfg.get("servers", {}).keys())
            print(f"  deploy-config.yaml (active)")
            print(f"    Domain:  {domain}")
            print(f"    Servers: {', '.join(servers) if servers else '(none)'}")
            print()
        except Exception as e:
            print(f"  deploy-config.yaml (error: {e})")
            print()

    # List configs in configs/
    if CONFIGS_DIR.is_dir():
        for config_file in sorted(CONFIGS_DIR.glob("*.yaml")) + sorted(CONFIGS_DIR.glob("*.yml")):
            if config_file.name == "template.yaml":
                print(f"  configs/{config_file.name} (template)")
                print()
                continue
            try:
                cfg = load_deploy_config(config_file)
                domain = cfg.get("domain", "(no domain)")
                servers = list(cfg.get("servers", {}).keys())
                print(f"  configs/{config_file.name}")
                print(f"    Domain:  {domain or '(auto-detect)'}")
                print(f"    Servers: {', '.join(servers) if servers else '(none defined)'}")
                print()
            except Exception as e:
                print(f"  configs/{config_file.name} (error: {e})")
                print()
    else:
        print("  (no configs/ directory)")

    print("Use --config <name> to select a config (e.g., --config asnb)")
    return 0


def cmd_validate(args: argparse.Namespace) -> int:
    """Validate a configuration file."""
    term = Terminal()
    if args.no_color:
        term.disable()

    config_path = resolve_config_path(str(args.config) if args.config else None)
    if config_path is None:
        term.error(f"Config file not found: {args.config}")
        term.error("Try: --config configs/asnb.yaml or --config asnb")
        return 1

    print(f"Validating: {config_path}\n")

    try:
        cfg = load_deploy_config(config_path)
    except Exception as e:
        term.error(f"Failed to parse YAML: {e}")
        return 1

    errors = []
    warnings = []

    # Check required sections
    if "servers" not in cfg:
        errors.append("Missing 'servers' section")
    elif not cfg["servers"]:
        warnings.append("No servers defined - deploy will be skipped")

    if "services" not in cfg:
        errors.append("Missing 'services' section")
    elif not cfg["services"]:
        warnings.append("No services defined - deploy will have no effect")

    # Validate servers reference valid services
    servers = cfg.get("servers", {})
    services = cfg.get("services", {})

    for server_name, server_cfg in servers.items():
        if not isinstance(server_cfg, dict):
            errors.append(f"Server '{server_name}' has invalid config (expected dict)")
            continue

        if not (server_cfg.get("host") or server_cfg.get("ssh_alias")):
            errors.append(f"Server '{server_name}' missing 'host' (or 'ssh_alias')")

        server_services = server_cfg.get("services", [])
        for svc_name in server_services:
            if svc_name not in services:
                errors.append(f"Server '{server_name}' references undefined service '{svc_name}'")

    # Validate services have required fields
    valid_types = {"jks", "apache", "nginx", "asterisk", "custom"}
    for svc_name, svc_cfg in services.items():
        if not isinstance(svc_cfg, dict):
            errors.append(f"Service '{svc_name}' has invalid config (expected dict)")
            continue

        svc_type = svc_cfg.get("type", "custom")
        if svc_type not in valid_types:
            warnings.append(f"Service '{svc_name}' has unknown type '{svc_type}' (will use 'custom')")

        if svc_type == "jks" and not svc_cfg.get("remote_path") and not svc_cfg.get("keystore_path"):
            errors.append(f"Service '{svc_name}' (jks) missing 'remote_path'")

        for field in ("remote_path", "keystore_path", "ssl_dir", "cert_dir", "cert_path", "key_path"):
            if svc_cfg.get(field):
                try:
                    validate_remote_path(str(svc_cfg[field]), f"Service '{svc_name}' {field}")
                except ValueError as exc:
                    errors.append(str(exc))
        for field in ("remote_path", "keystore_path"):
            if str(svc_cfg.get(field) or "").endswith("/"):
                errors.append(f"Service '{svc_name}' {field} ends with '/': it must be a file, not a directory")
        mappings = svc_cfg.get("file_mappings") or {}
        for src, dests in mappings.items() if isinstance(mappings, dict) else []:
            for dest in dests if isinstance(dests, list) else [dests]:
                try:
                    validate_remote_path(str(dest), f"Service '{svc_name}' file_mappings[{src}]")
                except ValueError as exc:
                    errors.append(str(exc))
                else:
                    if str(dest).endswith("/"):
                        errors.append(
                            f"Service '{svc_name}' file_mappings[{src}] is a directory ({dest}); "
                            "if it comes from a variable such as ca_bundle_legacy, that value is empty"
                        )

    # Security hygiene: plaintext secrets and weak defaults
    raw_text = config_path.read_text(encoding="utf-8-sig")
    for server_name, server_cfg in servers.items():
        if isinstance(server_cfg, dict) and server_cfg.get("password"):
            warnings.append(
                f"Server '{server_name}' stores an SSH password in the file; use ${{env:VAR}} or SSH_PASSWORD"
            )
        if isinstance(server_cfg, dict) and not server_cfg.get("host_key_sha256"):
            pass  # optional pin; host keys are verified via known_hosts by default
    ks_pass = (cfg.get("keystore") or {}).get("password")
    if ks_pass == "changeit":
        warnings.append("keystore.password is the default 'changeit'; change it for production")
    elif ks_pass and "${env:" not in raw_text:
        warnings.append("keystore.password is stored in plaintext; consider ${env:VAR}")
    policy = (cfg.get("ssh") or {}).get("host_key_policy", "strict")
    if policy not in ("strict", "accept-new"):
        errors.append(f"ssh.host_key_policy must be 'strict' or 'accept-new' (got {policy!r})")

    # Print results
    domain = cfg.get("domain", "(auto-detect)")
    keystore = cfg.get("keystore", {})

    print(f"Domain:    {domain}")
    print(f"Keystore:  password={'*' * len(keystore.get('password', 'changeit'))}, alias={keystore.get('alias', 'server-cert')}")
    print(f"Servers:   {len(servers)}")
    print(f"Services:  {len(services)}")
    print()

    if errors:
        for err in errors:
            term.error(f"ERROR: {err}")
        print()

    if warnings:
        for warn in warnings:
            term.warn(f"WARNING: {warn}")
        print()

    if errors:
        term.error("Validation FAILED")
        return 1

    term.success("Validation PASSED")
    return 0


def cmd_plan(args: argparse.Namespace) -> int:
    """Show deployment plan without making changes."""
    term = Terminal()
    if args.no_color:
        term.disable()

    config_path = resolve_config_path(str(args.config) if args.config else None)
    if config_path is None:
        term.error(f"Config file not found: {args.config}")
        term.error("Try: --config configs/asnb.yaml or --config asnb")
        return 1

    certs_dir = normalize_path(str(args.certs)) if args.certs else None

    print(f"Deployment Plan")
    print(f"===============")
    print(f"Config: {config_path}")
    print(f"Certs:  {certs_dir or '(not specified)'}")
    print()

    try:
        cfg = load_deploy_config(config_path)
    except Exception as e:
        term.error(f"Failed to load config: {e}")
        return 1

    domain = cfg.get("domain", "(auto-detect from cert)")
    print(f"Domain: {domain}")
    print()

    # Hook/restart commands can embed the keystore password: never print it.
    secrets = sorted(
        {
            str(v)
            for v in [(cfg.get("keystore") or {}).get("password")]
            + [s.get("password") for s in (cfg.get("servers") or {}).values() if isinstance(s, dict)]
            if v and len(str(v)) >= 4
        },
        key=len,
        reverse=True,
    )

    def mask(text: str) -> str:
        for secret in secrets:
            text = text.replace(secret, "****")
        return text

    servers = cfg.get("servers", {})
    services = cfg.get("services", {})

    if not servers:
        print("No servers defined - nothing to deploy")
        return 0

    for server_name, server_cfg in servers.items():
        host = server_cfg.get("host") or server_cfg.get("ssh_alias") or "(no host)"
        user = server_cfg.get("user") or ("(from ssh config)" if server_cfg.get("ssh_alias") else "root")
        server_services = server_cfg.get("services", [])

        print(f"Server: {server_name}")
        print(f"  Host: {user}@{host}")
        if server_cfg.get("proxy_jump"):
            via = server_cfg["proxy_jump"]
            print(f"  Via:  {', '.join(via) if isinstance(via, list) else via}")
        print(f"  Services:")

        for svc_name in server_services:
            svc_cfg = services.get(svc_name, {})
            svc_type = svc_cfg.get("type", "custom")

            if svc_type == "jks":
                dest = svc_cfg.get("remote_path") or svc_cfg.get("keystore_path", "(not set)")
                print(f"    - {svc_name} (JKS) -> {dest}")
            elif svc_type == "apache":
                ssl_dir = svc_cfg.get("ssl_dir", "/etc/httpd/ssl/")
                print(f"    - {svc_name} (Apache) -> {ssl_dir}")
            elif svc_type == "nginx":
                cert_path = svc_cfg.get("cert_path", "/etc/nginx/ssl/")
                print(f"    - {svc_name} (Nginx) -> {cert_path}")
            elif svc_type == "asterisk":
                cert_dir = svc_cfg.get("cert_dir", "/etc/asterisk/keys/")
                print(f"    - {svc_name} (Asterisk) -> {cert_dir}")
            else:
                print(f"    - {svc_name} ({svc_type})")

            restart = svc_cfg.get("restart_cmd") or svc_cfg.get("restart")
            if restart:
                priority = svc_cfg.get("priority")
                suffix = f"  (priority {priority})" if priority is not None else ""
                print(f"      Restart: {mask(str(restart))}{suffix}")

            hooks = svc_cfg.get("hooks") or []
            if hooks:
                print(f"      Hooks:")
                for hook in hooks:
                    first_line = hook.strip().splitlines()[0] if hook.strip() else ""
                    more = " ..." if "\n" in hook.strip() else ""
                    print(f"        - {mask(first_line)}{more}")

        print()

    # Check cert files if directory provided
    if certs_dir and certs_dir.is_dir():
        print("Certificate files found:")
        for f in sorted(certs_dir.iterdir()):
            if f.is_file():
                print(f"  - {f.name}")

    return 0


def cmd_check_old(args: argparse.Namespace) -> int:
    """Inspect existing JKS/cert file."""
    term = Terminal()
    if getattr(args, "no_color", False):
        term.disable()

    jks_path = getattr(args, "jks", None)
    remote = getattr(args, "remote", None)
    config_name = getattr(args, "config", None)
    password = getattr(args, "password", None)
    keytool_path = getattr(args, "keytool", None) or find_keytool()

    # Handle remote checking via SSH
    if remote:
        return cmd_check_old_remote(args, term)

    if not jks_path:
        term.error("--jks or --remote is required")
        return 1

    jks_path = normalize_path(str(jks_path))
    if not jks_path.is_file():
        term.error(f"File not found: {jks_path}")
        return 1

    # Try to get password from config if not provided
    if password is None and config_name:
        config_path = resolve_config_path(config_name)
        if config_path:
            try:
                cfg = load_deploy_config(config_path)
                keystore = cfg.get("keystore") or {}
                password = keystore.get("password") or keystore.get("keystore_pass")
            except Exception:
                pass

    # Prompt for password if still not provided
    if password is None:
        try:
            import getpass
            password = getpass.getpass("Keystore password: ")
        except (EOFError, KeyboardInterrupt):
            print("\nCancelled.")
            return 1

    # Determine file type and read info
    suffix = jks_path.suffix.lower()
    if suffix in (".p12", ".pfx"):
        info = read_jks_info_from_p12(jks_path, password)
    else:
        info = read_jks_info(jks_path, password, keytool_path)

    if info.error:
        term.error(f"Error: {info.error}")
        return 1

    print()
    print(format_jks_info(info))
    print()

    return 0


def cmd_check_old_remote(args: argparse.Namespace, term: Terminal) -> int:
    """Check old cert on remote server via SSH."""
    remote = args.remote
    config_name = getattr(args, "config", None)
    password = getattr(args, "password", None)

    # Parse remote format: hostname:/path or hostname:path
    if ":" not in remote:
        term.error("Remote format should be: hostname:/path/to/keystore.jks")
        return 1

    parts = remote.split(":", 1)
    hostname = parts[0]
    remote_path = parts[1]

    # Get SSH settings from config (same host-key policy as deploys)
    server_cfg: dict = {"host": hostname, "user": "root", "port": 22}

    if config_name:
        config_path = resolve_config_path(config_name)
        if config_path:
            try:
                cfg = load_deploy_config(config_path)
                servers = cfg.get("servers", {})
                # Find server by hostname or by its name in the config
                for server_name, found_cfg in servers.items():
                    if found_cfg.get("host") == hostname or server_name == hostname:
                        server_cfg = dict(found_cfg)
                        if password is None:
                            keystore = cfg.get("keystore") or {}
                            password = keystore.get("password") or keystore.get("keystore_pass")
                        break
            except Exception as exc:
                term.warn(f"Could not read SSH settings from config: {exc}")

    if password is None:
        try:
            import getpass
            password = getpass.getpass("Keystore password: ")
        except (EOFError, KeyboardInterrupt):
            print("\nCancelled.")
            return 1

    # Create temp directory for downloaded file
    import tempfile
    with tempfile.TemporaryDirectory(prefix="ssl-cert-tool-") as tmpdir:
        local_path = Path(tmpdir) / (posixpath.basename(remote_path) or "keystore")

        print(f"Downloading {remote_path} from {server_cfg.get('host', hostname)}...")
        try:
            validate_remote_path(remote_path, "remote path")
            key_file = server_cfg.get("key_file")
            if key_file and not Path(os.path.expanduser(str(key_file))).is_file():
                term.warn(f"SSH key {key_file} not found; using agent/default keys")
                server_cfg = {**server_cfg, "key_file": None}
            client = connect_ssh(
                server_cfg,
                policy=POLICY_ACCEPT_NEW if getattr(args, "accept_new_hostkeys", False) else "strict",
                known_hosts_path=getattr(args, "known_hosts", None),
                password=server_cfg.get("password") or os.environ.get("SSH_PASSWORD"),
                notice=term.warn,
            )
        except Exception as exc:
            term.error(f"Failed to connect: {exc}")
            return 1
        remote = RemoteHost(client)
        try:
            remote.sftp().get(remote_path, str(local_path))
        except (OSError, EOFError) as exc:
            term.error(f"Failed to download file: {exc}")
            return 1
        finally:
            remote.close()

        if not local_path.is_file():
            term.error("Downloaded file not found")
            return 1

        # Read info from downloaded file
        suffix = local_path.suffix.lower()
        keytool_path = getattr(args, "keytool", None) or find_keytool()

        if suffix in (".p12", ".pfx"):
            info = read_jks_info_from_p12(local_path, password)
        else:
            info = read_jks_info(local_path, password, keytool_path)

        # Update path in info for display
        info.path = Path(f"{hostname}:{remote_path}")

        if info.error:
            term.error(f"Error: {info.error}")
            return 1

        print()
        print(format_jks_info(info))
        print()

    return 0


def cmd_compare(args: argparse.Namespace) -> int:
    """Compare old and new certificates."""
    term = Terminal()
    if getattr(args, "no_color", False):
        term.disable()

    old_path = normalize_path(str(args.old))
    new_path = normalize_path(str(args.new))
    password = getattr(args, "password", None)
    keytool_path = getattr(args, "keytool", None) or find_keytool()

    if not old_path.is_file():
        term.error(f"Old file not found: {old_path}")
        return 1

    if not new_path.is_file():
        term.error(f"New file not found: {new_path}")
        return 1

    # Prompt for password if not provided
    if password is None:
        try:
            import getpass
            password = getpass.getpass("Keystore password (used for both): ")
        except (EOFError, KeyboardInterrupt):
            print("\nCancelled.")
            return 1

    # Read old cert info
    old_suffix = old_path.suffix.lower()
    if old_suffix in (".p12", ".pfx"):
        old_info = read_jks_info_from_p12(old_path, password)
    else:
        old_info = read_jks_info(old_path, password, keytool_path)

    if old_info.error:
        term.error(f"Error reading old cert: {old_info.error}")
        return 1

    # Read new cert info
    new_suffix = new_path.suffix.lower()
    if new_suffix in (".p12", ".pfx"):
        new_info = read_jks_info_from_p12(new_path, password)
    else:
        new_info = read_jks_info(new_path, password, keytool_path)

    if new_info.error:
        term.error(f"Error reading new cert: {new_info.error}")
        return 1

    # Compare
    comparison = compare_certs(old_info, new_info)

    print()
    print(format_cert_comparison(comparison))
    print()

    return 0 if comparison.ready_for_renewal else 1


def resolve_from_old_settings(args: argparse.Namespace, term: Terminal) -> tuple[str | None, str | None]:
    """
    Extract alias and password from old JKS file if --from-old or --match-old is specified.
    Returns (alias, password) tuple.
    """
    from_old = getattr(args, "from_old", None) or getattr(args, "match_old", None)
    if not from_old:
        return None, None

    old_path = normalize_path(str(from_old))
    if not old_path.is_file():
        term.warn(f"Old keystore not found: {old_path}")
        return None, None

    old_password = getattr(args, "old_password", None)
    if old_password is None:
        try:
            import getpass
            old_password = getpass.getpass(f"Password for {old_path.name}: ")
        except (EOFError, KeyboardInterrupt):
            return None, None

    keytool_path = getattr(args, "keytool", None) or find_keytool()

    suffix = old_path.suffix.lower()
    if suffix in (".p12", ".pfx"):
        info = read_jks_info_from_p12(old_path, old_password)
    else:
        info = read_jks_info(old_path, old_password, keytool_path)

    if info.error:
        term.warn(f"Could not read old keystore: {info.error}")
        return None, None

    term.detail(f"Imported from old cert: alias={info.alias}, domain={info.domain}")
    if info.valid_until:
        term.detail(f"Old cert expires: {info.valid_until.strftime('%Y-%m-%d')}")

    # For --match-old, also use the old password for the new keystore
    if getattr(args, "match_old", None):
        return info.alias or None, old_password

    # For --from-old, only import the alias
    return info.alias or None, None


def cmd_wizard(args: argparse.Namespace) -> int:
    """Interactive wizard for guided certificate management."""
    term = Terminal()

    print()
    print("=" * 60)
    print("       SSL CERTIFICATE TOOL - INTERACTIVE WIZARD")
    print("=" * 60)
    print()
    print("  Tip: You can drag and drop files/folders into this window!")
    print()

    # Step 0: Check for existing keystore
    print("-" * 60)
    print("STEP 0: Existing Keystore (Optional)")
    print("-" * 60)
    print()
    print("  Do you have an existing keystore to match settings from?")
    print("    1. Yes, I have the old JKS file locally")
    print("    2. Yes, it's on the remote server")
    print("    3. No, this is a new setup")
    print()

    old_alias = None
    old_password = None

    while True:
        old_choice = input("  Select (1-3): ").strip()
        if old_choice in ("1", "2", "3"):
            break
        print("  Please enter 1, 2, or 3.")

    if old_choice == "1":
        # Local old JKS
        while True:
            raw_old = input("  Enter path to old keystore: ").strip().strip('"').strip("'")
            if not raw_old:
                print("  Skipping old keystore import.")
                break
            old_path = normalize_path(raw_old)
            if old_path.is_file():
                try:
                    import getpass
                    old_pw = getpass.getpass(f"  Password for {old_path.name}: ")
                    keytool_path = find_keytool()
                    suffix = old_path.suffix.lower()
                    if suffix in (".p12", ".pfx"):
                        info = read_jks_info_from_p12(old_path, old_pw)
                    else:
                        info = read_jks_info(old_path, old_pw, keytool_path)

                    if info.error:
                        print(f"  Error: {info.error}")
                        continue

                    old_alias = info.alias
                    old_password = old_pw
                    print(f"  -> Imported: alias={info.alias}, domain={info.domain}")
                    if info.valid_until:
                        exp_str = info.valid_until.strftime("%Y-%m-%d")
                        status = "[EXPIRED]" if info.is_expired else f"[{info.days_until_expiry} days left]"
                        print(f"  -> Old cert expires: {exp_str} {status}")
                    break
                except (EOFError, KeyboardInterrupt):
                    print("\n  Skipping old keystore import.")
                    break
            else:
                print(f"  File not found: {old_path}")

    elif old_choice == "2":
        print("  Remote checking requires --config to know SSH settings.")
        print("  Use: ssl-auto.py check-old --remote host:/path --config <name>")
        print("  Continuing without old keystore import...")

    print()

    # Step 1: Get certificate input
    print("-" * 60)
    print("STEP 1: Certificate Files")
    print("-" * 60)
    print()
    print("  Where are the customer's certificate files?")
    print("  (Can be: folder, .eml file, .zip, .p7b, .crt, etc.)")
    print()

    while True:
        raw_input = input("  Enter path (or drag-drop): ").strip().strip('"').strip("'")
        if not raw_input:
            print("  Please enter a path.")
            continue
        input_path = normalize_path(raw_input)
        if input_path.exists():
            break
        print(f"  Path not found: {input_path}")
        print("  Please try again.")

    print(f"  -> Using: {input_path}")
    print()

    # Step 2: Get private key
    print("-" * 60)
    print("STEP 2: Private Key")
    print("-" * 60)
    print()
    print("  Where is the private key file?")
    print("  (Usually a .key or .pem file)")
    print()

    while True:
        raw_key = input("  Enter path to private key: ").strip().strip('"').strip("'")
        if not raw_key:
            print("  Please enter a path.")
            continue
        key_path = normalize_path(raw_key)
        if key_path.is_file():
            break
        print(f"  File not found: {key_path}")
        print("  Please try again.")

    print(f"  -> Using: {key_path}")
    print()

    # Step 3: Choose action
    print("-" * 60)
    print("STEP 3: What would you like to do?")
    print("-" * 60)
    print()
    print("  1. Generate certificates only (no deployment)")
    print("  2. Generate + Deploy to servers")
    print("  3. Cancel")
    print()

    while True:
        action = input("  Select (1-3): ").strip()
        if action in ("1", "2", "3"):
            break
        print("  Please enter 1, 2, or 3.")

    if action == "3":
        print()
        print("  Cancelled.")
        return 0

    config_path = None
    if action == "2":
        # Step 4: Choose config for deployment
        print()
        print("-" * 60)
        print("STEP 4: Deployment Configuration")
        print("-" * 60)
        print()

        # List available configs
        available_configs = []
        if CONFIGS_DIR.is_dir():
            for cfg_file in sorted(CONFIGS_DIR.glob("*.yaml")) + sorted(CONFIGS_DIR.glob("*.yml")):
                if cfg_file.name != "template.yaml":
                    available_configs.append(cfg_file)

        if available_configs:
            print("  Available configurations:")
            for i, cfg in enumerate(available_configs, 1):
                try:
                    cfg_data = load_deploy_config(cfg)
                    domain = cfg_data.get("domain", "(auto)")
                    servers = list(cfg_data.get("servers", {}).keys())
                    print(f"    {i}. {cfg.stem} - {domain} ({len(servers)} server(s))")
                except Exception:
                    print(f"    {i}. {cfg.stem}")
            print(f"    {len(available_configs) + 1}. Enter custom path")
            print(f"    {len(available_configs) + 2}. Create new config")
            print()

            while True:
                cfg_choice = input(f"  Select (1-{len(available_configs) + 2}): ").strip()
                try:
                    cfg_idx = int(cfg_choice)
                    if 1 <= cfg_idx <= len(available_configs):
                        config_path = available_configs[cfg_idx - 1]
                        break
                    elif cfg_idx == len(available_configs) + 1:
                        raw_cfg = input("  Enter config path: ").strip().strip('"')
                        config_path = resolve_config_path(raw_cfg)
                        if config_path:
                            break
                        print("  Config not found. Please try again.")
                    elif cfg_idx == len(available_configs) + 2:
                        print()
                        print("  Run: ssl-auto init --name <config-name>")
                        print("  Then run the wizard again.")
                        return 0
                except ValueError:
                    pass
                print("  Invalid selection. Please try again.")
        else:
            print("  No configurations found.")
            print()
            print("  Options:")
            print("    1. Enter path to existing config")
            print("    2. Create new config and exit")
            print()

            cfg_action = input("  Select (1-2): ").strip()
            if cfg_action == "1":
                while True:
                    raw_cfg = input("  Enter config path: ").strip().strip('"')
                    config_path = resolve_config_path(raw_cfg)
                    if config_path:
                        break
                    print("  Config not found. Please try again.")
            else:
                print()
                print("  Run: ssl-auto init --name <config-name>")
                print("  Then run the wizard again.")
                return 0

        print(f"  -> Using config: {config_path}")

    # Step 5: Output directory
    print()
    print("-" * 60)
    print(f"STEP {'5' if action == '2' else '4'}: Output Directory")
    print("-" * 60)
    print()

    default_output = "output"
    raw_output = input(f"  Enter output folder (Enter for '{default_output}'): ").strip().strip('"')
    output_path = normalize_path(raw_output) if raw_output else Path(default_output)
    print(f"  -> Output: {output_path}")

    # Summary and confirmation
    print()
    print("=" * 60)
    print("SUMMARY")
    print("=" * 60)
    print()
    print(f"  Certificate input: {input_path}")
    print(f"  Private key:       {key_path}")
    print(f"  Output directory:  {output_path}")
    if config_path:
        print(f"  Deploy config:     {config_path}")
        print(f"  Action:            Generate + Deploy")
    else:
        print(f"  Action:            Generate only")
    print()

    confirm = input("  Proceed? (y/n): ").strip().lower()
    if confirm not in ("y", "yes"):
        print()
        print("  Cancelled.")
        return 0

    print()
    print("=" * 60)
    print("RUNNING...")
    print("=" * 60)
    print()

    # Build the command arguments
    if action == "2" and config_path:
        # Full run with deploy
        class Args:
            pass
        run_args = Args()
        run_args.input = [str(input_path)]
        run_args.input_dir = None
        run_args.key = key_path
        run_args.output = output_path
        run_args.domain = None
        run_args.store_pass = old_password  # Use imported password if available
        run_args.alias = old_alias or "server-cert"  # Use imported alias if available
        run_args.keytool = None
        run_args.p12_password = None
        run_args.config = config_path
        run_args.dry_run = False
        run_args.no_deploy = False
        run_args.no_restart = False
        run_args.server = None
        run_args.service = None
        run_args.parallel = False
        run_args.no_color = False
        run_args.from_old = None
        run_args.old_password = None
        run_args.match_old = None

        return cmd_run(run_args)
    else:
        # Generate only
        class Args:
            pass
        gen_args = Args()
        gen_args.input = [str(input_path)]
        gen_args.input_dir = None
        gen_args.key = key_path
        gen_args.output = output_path
        gen_args.domain = None
        gen_args.store_pass = old_password  # Use imported password if available
        gen_args.alias = old_alias or "server-cert"  # Use imported alias if available
        gen_args.keytool = None
        gen_args.p12_password = None
        gen_args.config = None
        gen_args.dry_run = False
        gen_args.no_color = False
        gen_args.from_old = None
        gen_args.old_password = None
        gen_args.match_old = None

        return cmd_generate(gen_args)


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="ssl-auto",
        description="Universal SSL certificate generation and deployment tool.",
        epilog=SUPPORTED_FORMATS,
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument(
        "--version",
        action="version",
        version=f"ssl-auto {__version__} ({detect_os()})",
    )
    parser.add_argument(
        "--wizard",
        action="store_true",
        help="Start interactive wizard for guided operation",
    )
    sub = parser.add_subparsers(dest="command", required=False)

    # inspect
    inspect_p = sub.add_parser("inspect", help="Inspect certificate inputs")
    add_input_options(inspect_p)
    add_deploy_options(inspect_p)
    inspect_p.set_defaults(func=cmd_inspect)

    # generate
    generate_p = sub.add_parser("generate", help="Generate deployment artifacts")
    add_input_options(generate_p)
    add_deploy_options(generate_p)
    generate_p.set_defaults(func=cmd_generate)

    # deploy
    deploy_p = sub.add_parser("deploy", help="Deploy existing certificate artifacts")
    deploy_p.add_argument("--certs", type=path_arg, required=True, help="Generated certs directory")
    add_deploy_options(deploy_p)
    deploy_p.set_defaults(func=cmd_deploy)

    # run (full pipeline)
    run_p = sub.add_parser("run", help="Full automation: generate + validate + deploy")
    add_input_options(run_p)
    add_deploy_options(run_p)
    run_p.set_defaults(func=cmd_run)

    # init (new config)
    init_p = sub.add_parser("init", help="Create a new configuration file")
    init_p.add_argument("-d", "--domain", help="Pre-fill domain name in config")
    init_p.add_argument("-n", "--name", help="Config name (creates configs/<name>.yaml)")
    init_p.add_argument("-o", "--output", type=path_arg, help="Output path for config file")
    init_p.add_argument("-f", "--force", action="store_true", help="Overwrite existing file")
    init_p.set_defaults(func=cmd_init)

    # configs (list)
    configs_p = sub.add_parser("configs", help="List available configurations")
    configs_p.set_defaults(func=cmd_configs)

    # validate
    validate_p = sub.add_parser("validate", help="Validate a configuration file")
    validate_p.add_argument("--config", required=True, help="Config file or name to validate")
    validate_p.add_argument("--no-color", action="store_true", help="Disable colored output")
    validate_p.set_defaults(func=cmd_validate)

    # plan
    plan_p = sub.add_parser("plan", help="Show deployment plan without making changes")
    plan_p.add_argument("--config", required=True, help="Config file or name to use")
    plan_p.add_argument("--certs", type=path_arg, help="Generated certs directory")
    plan_p.add_argument("--no-color", action="store_true", help="Disable colored output")
    plan_p.set_defaults(func=cmd_plan)

    # rollback (restore pre-deploy backups)
    rollback_p = sub.add_parser(
        "rollback", help="Restore files from the most recent (or a specific) pre-deploy backup"
    )
    rollback_p.add_argument("--config", required=True, help="Config file or name to use")
    rollback_p.add_argument("--server", help="Roll back one server only")
    rollback_p.add_argument("--timestamp", help="Specific backup snapshot to restore (default: newest)")
    rollback_p.add_argument("--dry-run", action="store_true", help="Show what would be restored without making changes")
    rollback_p.add_argument(
        "--restart", action="store_true",
        help="Also restart the configured services so the restored files take effect",
    )
    add_ssh_trust_options(rollback_p)
    rollback_p.add_argument("--no-color", action="store_true", help="Disable colored output")
    rollback_p.set_defaults(func=cmd_rollback)

    # preflight (live ameyoctl status check)
    preflight_p = sub.add_parser(
        "preflight", help="Check each server's live ameyoctl status before deploying"
    )
    preflight_p.add_argument("--config", required=True, help="Config file or name to use")
    preflight_p.add_argument("--server", help="Check one server only")
    add_ssh_trust_options(preflight_p)
    preflight_p.add_argument("--no-color", action="store_true", help="Disable colored output")
    preflight_p.set_defaults(func=cmd_preflight)

    # copy (scp-like push of certs/keys, optionally through jump hosts)
    copy_p = sub.add_parser(
        "copy",
        help="Copy cert/key files to a server over SSH (like scp, but verified, atomic and reversible)",
        description=(
            "Copy files to a server. Each file is checksum-verified, written atomically, keeps the "
            "owner of the file it replaces, and the old version is backed up first. If any file or "
            "--check-cmd fails, everything copied so far is restored. Reaches servers behind jump "
            "hosts via ~/.ssh/config aliases (ProxyJump), --via, or proxy_jump in the config."
        ),
        epilog=(
            "examples:\n"
            "  ssl-auto copy --host app-server-1 --ask-ssh-password \\\n"
            "      --file out/x.com/main_x.com.crt:/etc/nginx/ssl/x.crt \\\n"
            "      --file out/x.com/x.com.key:/etc/nginx/ssl/x.key \\\n"
            "      --check-cmd 'nginx -t' --reload-cmd 'systemctl reload nginx'\n"
            "  ssl-auto copy --host deploy@10.0.0.5:2222 --via ops@bastion.example.com --file a.crt:/tmp/a.crt\n"
            "  ssl-auto copy --config myconfig.yaml --server web --file a.crt:/etc/ssl/a.crt:644"
        ),
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    copy_p.add_argument(
        "-f", "--file", action="append", required=True, type=parse_copy_file, metavar="SRC:/remote/path[:MODE]",
        help="File to copy; repeat for several. MODE is octal (default: 600 for private keys, 644 otherwise)",
    )
    copy_p.add_argument("--server", help="Server name from --config")
    copy_p.add_argument("--config", type=path_arg, help="Deploy config YAML (with --server)")
    copy_p.add_argument(
        "--host", metavar="HOST",
        help="Ad-hoc target: an alias from ~/.ssh/config (its ProxyJump chain is followed) or [user@]host[:port]",
    )
    copy_p.add_argument("--via", metavar="HOP[,HOP...]", help="Jump host(s) for --host: ssh-config aliases or [user@]host[:port]")
    copy_p.add_argument("--user", help="SSH user for --host (overrides the alias)")
    copy_p.add_argument("--backup-dir", metavar="DIR", help="Remote folder for backups (default: /tmp/ssl-auto-backups-<user>)")
    copy_p.add_argument(
        "--check-cmd", metavar="CMD",
        help="Run on the server after copying; if it fails, the files are restored (e.g. 'nginx -t')",
    )
    copy_p.add_argument(
        "--reload-cmd", metavar="CMD",
        help="Run after a successful copy and check (e.g. 'systemctl reload nginx'); failure is reported, not undone",
    )
    copy_p.add_argument("--dry-run", action="store_true", help="Show what would happen without connecting or changing anything")
    copy_p.add_argument("--skip-verify", action="store_true", help="Copy even if the key/cert checks fail")
    copy_p.add_argument("--key-password", default=None, help="Passphrase for an encrypted private key (or SSL_KEY_PASSWORD)")
    add_ssh_trust_options(copy_p)
    copy_p.add_argument("--no-color", action="store_true", help="Disable colored output")
    copy_p.set_defaults(func=cmd_copy)

    # check-old (inspect existing JKS/cert)
    check_old_p = sub.add_parser(
        "check-old",
        help="Inspect existing JKS/cert file",
        description="Inspect an existing JKS keystore or PKCS12 file to view certificate details.",
    )
    check_old_p.add_argument(
        "--jks", type=path_arg,
        help="Path to JKS or P12 keystore file"
    )
    check_old_p.add_argument(
        "-p", "--password",
        help="Keystore password (prompts if not provided)"
    )
    check_old_p.add_argument(
        "--remote", metavar="HOST:PATH",
        help="Check cert on remote server (e.g., hostname:/path/to/keystore.jks)"
    )
    check_old_p.add_argument(
        "--config", type=path_arg,
        help="Config file for SSH settings when using --remote"
    )
    check_old_p.add_argument(
        "--keytool", type=path_arg,
        help="Path to keytool executable"
    )
    add_ssh_trust_options(check_old_p)
    check_old_p.add_argument("--no-color", action="store_true", help="Disable colored output")
    check_old_p.set_defaults(func=cmd_check_old)

    # compare (compare old and new certs)
    compare_p = sub.add_parser(
        "compare",
        help="Compare old and new certificates",
        description="Compare two JKS/P12 keystores to verify renewal compatibility.",
    )
    compare_p.add_argument(
        "--old", type=path_arg, required=True,
        help="Path to old JKS/P12 keystore"
    )
    compare_p.add_argument(
        "--new", type=path_arg, required=True,
        help="Path to new JKS/P12 keystore"
    )
    compare_p.add_argument(
        "-p", "--password",
        help="Keystore password (used for both, prompts if not provided)"
    )
    compare_p.add_argument(
        "--keytool", type=path_arg,
        help="Path to keytool executable"
    )
    compare_p.add_argument("--no-color", action="store_true", help="Disable colored output")
    compare_p.set_defaults(func=cmd_compare)

    return parser


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)

    # Handle --wizard flag
    if getattr(args, "wizard", False):
        return cmd_wizard(args)

    # Handle no command (show help or run wizard)
    if not args.command:
        # If no arguments at all, suggest wizard
        if argv is None or len(argv) == 0 or (len(argv) == 1 and argv[0] in ("--help", "-h")):
            parser.print_help()
        else:
            print("No command specified. Use --wizard for guided mode or --help for usage.")
        return 0

    try:
        return args.func(args)
    except KeyboardInterrupt:
        print("\nCancelled.", file=sys.stderr)
        return 130
    except SystemExit:
        raise
    except Exception as exc:  # last resort: one clear line, traceback only on request
        if os.environ.get("SSL_AUTO_DEBUG"):
            raise
        print(f"Error: {exc}", file=sys.stderr)
        print("(set SSL_AUTO_DEBUG=1 for the full traceback)", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
