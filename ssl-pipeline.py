#!/usr/bin/env python3
# Author: Sagar K | 2026 | MIT licence
"""Unified SSL pipeline CLI: inspect, generate, and deploy."""
from __future__ import annotations

import argparse
import re
import subprocess
import sys
from pathlib import Path


def try_repair_mangled_windows_path(path_str: str) -> str:
    """Repair paths where a Unix shell stripped backslashes (e.g. ..ssl-deployconfig.yaml)."""
    if "/" in path_str or "\\" in path_str:
        return path_str
    if path_str.startswith("..") and "config.yaml" in path_str:
        idx = path_str.find("config.yaml")
        if idx > 2:
            prefix = path_str[2:idx]
            return f"../{prefix}/config.yaml"
    match = re.match(r"^\.\.([a-zA-Z0-9_-]+)([a-zA-Z0-9_.-]+\.(yaml|yml|pem|key|crt|cer|eml))$", path_str)
    if match:
        return f"../{match.group(1)}/{match.group(2)}"
    return path_str


def wsl_drives_to_windows(path_str: str) -> str:
    """Convert WSL/MobaXterm /drives/c/... paths to C:/... on Windows."""
    match = re.match(r"^/drives/([a-zA-Z])(?:/(.+))?$", path_str)
    if match:
        drive = match.group(1).upper()
        rest = match.group(2) or ""
        return f"{drive}:/{rest}" if rest else f"{drive}:/"
    return path_str


def path_variants(path_str: str) -> list[str]:
    """Generate alternate path forms to try when the first does not exist."""
    cleaned = path_str.strip().strip('"').strip("'")
    variants: list[str] = []
    seen: set[str] = set()

    def add(value: str) -> None:
        if value and value not in seen:
            seen.add(value)
            variants.append(value)

    add(cleaned)
    add(cleaned.replace("\\", "/"))
    add(wsl_drives_to_windows(cleaned.replace("\\", "/")))
    add(try_repair_mangled_windows_path(cleaned))
    if cleaned.startswith("//"):
        add(cleaned[1:])
    return variants


def resolve_existing_path(path_str: str) -> Path | None:
    """Return the first path variant that exists on disk."""
    for variant in path_variants(path_str):
        candidate = Path(variant)
        try:
            resolved = candidate.resolve()
        except (OSError, RuntimeError):
            resolved = candidate
        if resolved.exists():
            return resolved
    return None


def normalize_path(path_str: str) -> Path:
    """Normalize Windows/WSL/mixed paths and verify the target exists when possible."""
    existing = resolve_existing_path(path_str)
    if existing is not None:
        return existing

    for variant in path_variants(path_str):
        candidate = Path(variant)
        try:
            return candidate.resolve()
        except (OSError, RuntimeError):
            continue
    return Path(path_str.strip().strip('"').strip("'"))


def _path_similarity(query: str, candidate: str) -> float:
    """Simple token overlap score for fuzzy filename matching."""
    query_tokens = set(re.findall(r"[a-z0-9]+", query.lower()))
    candidate_tokens = set(re.findall(r"[a-z0-9]+", candidate.lower()))
    if not query_tokens:
        return 0.0
    return len(query_tokens & candidate_tokens) / len(query_tokens)


def _extract_search_hints(path_str: str) -> tuple[str | None, str | None]:
    """Extract CEPO order number and domain hints from a path string."""
    cepo = None
    domain = None
    cepo_match = re.search(r"CEP[O0]?\d{6,}", path_str, re.IGNORECASE)
    if cepo_match:
        cepo = cepo_match.group(0).upper().replace("CEP0", "CEPO")
    domain_match = re.search(r"([a-z0-9][-a-z0-9.]*\.[a-z]{2,})", path_str, re.IGNORECASE)
    if domain_match:
        domain = domain_match.group(1).lower()
    return cepo, domain


def _existing_ancestor_dirs(path_str: str) -> list[Path]:
    """Walk up path variants and return existing directories from deepest to shallowest."""
    found: list[Path] = []
    seen: set[Path] = set()
    for variant in path_variants(path_str):
        current = Path(variant)
        while current != current.parent:
            current = current.parent
            existing = resolve_existing_path(str(current))
            if existing is not None and existing.is_dir() and existing not in seen:
                seen.add(existing)
                found.append(existing)
    return found


def find_similar_files(path_str: str, limit: int = 5) -> list[Path]:
    """Search parent directories for files similar to the requested path."""
    requested = Path(path_str)
    search_dirs = _existing_ancestor_dirs(path_str)

    cepo_hint, domain_hint = _extract_search_hints(path_str)
    cert_exts = {".eml", ".crt", ".cer", ".pem", ".p7b", ".p7c", ".p12", ".pfx", ".key", ".ca-bundle", ".bundle"}
    scored: list[tuple[float, Path]] = []

    for directory in search_dirs:
        if not directory.is_dir():
            continue
        try:
            entries = list(directory.iterdir())
        except OSError:
            continue
        for entry in entries:
            if not entry.is_file():
                continue
            if entry.suffix.lower() not in cert_exts:
                continue
            score = _path_similarity(requested.name, entry.name)
            name_lower = entry.name.lower()
            if cepo_hint and cepo_hint.lower().replace("o", "0") in name_lower.replace("o", "0"):
                score += 2.0
            if domain_hint and domain_hint in name_lower:
                score += 2.0
            if score > 0:
                scored.append((score, entry.resolve()))

    scored.sort(key=lambda item: (-item[0], item[1].name.lower()))
    seen: set[Path] = set()
    results: list[Path] = []
    for _, path in scored:
        if path in seen:
            continue
        seen.add(path)
        results.append(path)
        if len(results) >= limit:
            break
    return results


def path_arg(value: str) -> Path:
    if not value or not value.strip():
        raise argparse.ArgumentTypeError("Path cannot be empty")
    return normalize_path(value)


def check_dependencies() -> None:
    missing = []
    try:
        import cryptography  # noqa: F401
    except ImportError:
        missing.append("cryptography")
    if missing:
        print("Missing dependencies:", ", ".join(missing))
        print("Run: pip install -r requirements.txt")
        print("Or run: setup.bat (Windows) / ./setup.sh (Linux)")
        sys.exit(1)


check_dependencies()

_SCRIPT_DIR = Path(__file__).resolve().parent
if str(_SCRIPT_DIR) not in sys.path:
    sys.path.insert(0, str(_SCRIPT_DIR))

from ssl_cert_tool.core import (
    KEYTOOL_DEFAULT,
    BuildResult,
    build_outputs,
    cert_cn,
    classify_certs,
    collect_input_files,
    format_inspect_report,
    infer_domain,
    inspect_inputs,
    load_private_key,
    parse_all_inputs,
    public_numbers_match,
    validate_key_cert,
)

DEFAULT_DEPLOY_DIR = _SCRIPT_DIR.parent / "ssl-deploy"
DEFAULT_DEPLOY_CONFIG = DEFAULT_DEPLOY_DIR / "config.yaml"
DEFAULT_DEPLOY_CONF = DEFAULT_DEPLOY_DIR / "deploy.conf"
ALT_DEPLOY_CONFIG = _SCRIPT_DIR / "ssl-deploy" / "config.yaml"

def resolve_store_pass(explicit: str | None, domain: str) -> str:
    """Use explicit --store-pass when provided; else default to 'changeit'."""
    if explicit is not None:
        return explicit
    return "changeit"


def resolve_deploy_config(explicit: Path | None) -> Path | None:
    if explicit is not None:
        return explicit if explicit.is_file() else None
    for candidate in (DEFAULT_DEPLOY_CONFIG, ALT_DEPLOY_CONFIG):
        if candidate.is_file():
            return candidate
    return None


def to_wsl_path(path: Path) -> str:
    resolved = path.resolve()
    text = str(resolved).replace("\\", "/")
    match = re.match(r"^([A-Za-z]):/(.*)$", text)
    if match:
        return f"/drives/{match.group(1).lower()}/{match.group(2)}"
    return text


def report_config_not_found(requested: Path | None) -> None:
    shown = requested or DEFAULT_DEPLOY_CONFIG
    try:
        resolved = shown.resolve()
    except (OSError, RuntimeError):
        resolved = shown
    print(f"Deploy config not found: {resolved}")
    try:
        expected = DEFAULT_DEPLOY_CONFIG.resolve()
    except (OSError, RuntimeError):
        expected = DEFAULT_DEPLOY_CONFIG
    print(f"Expected at: {expected}")
    print(f"Use: --config {to_wsl_path(expected)}")
    print("     (In WSL/bash use forward slashes; backslashes are stripped by the shell.)")

SUPPORTED_FORMATS = """
Supported input formats:
  .crt, .cer, .pem  - PEM or DER encoded certificates
  .p7b, .p7c        - PKCS7 certificate chains
  .p12, .pfx        - PKCS12 keystores (use --p12-password if encrypted)
  .ca-bundle        - Multiple PEM certificates concatenated
  .eml              - Email files (e.g., GlobalSign certificate emails)
  .txt, .docx       - Text/Word with PEM blocks
  .zip, .7z         - Archives (7z needs py7zr)
  .der              - DER binary certificates
  Base64-only       - Auto-decoded single-line cert/key files
  Combined files    - Key + cert in one file
  MIME email        - .eml or extensionless email with PEM body
  Folders           - Recursively scans by content, not extension only
"""


def prompt_for_key() -> tuple[Path, object]:
    print("\nPrivate key not found in inputs.")
    while True:
        raw = input("Enter path to private key (.key / .pem): ").strip().strip('"')
        if not raw:
            print("  Key is required. Try again or Ctrl+C to abort.")
            continue
        path = normalize_path(raw)
        if not path.is_file():
            print(f"  File not found: {path}")
            continue
        try:
            return path, load_private_key(path.read_bytes())
        except ValueError as exc:
            print(f"  Could not load key: {exc}")


def print_validation(result: BuildResult, store_pass: str, alias: str) -> None:
    v = result.validation
    print("\n" + "=" * 60)
    print("VALIDATION REPORT")
    print("=" * 60)
    print(f"  Domain        : {result.domain}")
    print(f"  Subject       : {v.get('subject', 'N/A')}")
    print(f"  Valid from    : {v.get('not_before', 'N/A')}")
    print(f"  Valid until   : {v.get('not_after', 'N/A')}")
    match = v.get("key_cert_match")
    print(f"  Key/Cert match: [{'PASS' if match else 'FAIL'}]")
    print(f"  Cert MD5      : {v.get('cert_fingerprint_md5', 'N/A')}")
    print(f"  Key MD5       : {v.get('key_md5', 'N/A')}")
    print(f"  Keystore pass : {store_pass}")
    print(f"  Key alias     : {alias}")
    print("\n  Output file MD5 checksums:")
    for name, digest in sorted(v.get("output_md5", {}).items()):
        print(f"    {name:45s} {digest}")
    if result.warnings:
        print("\n  Warnings:")
        for w in result.warnings:
            print(f"    - {w}")
    print("\n  Created files:")
    for f in sorted(result.files):
        print(f"    {f} ({f.stat().st_size} bytes)")
    print("=" * 60)
    if not match:
        print("\nERROR: Private key does NOT match the leaf certificate!")
        sys.exit(1)


def infer_domain_from_key_path(key_path: Path | None) -> str | None:
    if key_path is None:
        return None
    stem = key_path.stem
    match = re.search(r"([a-z0-9][-a-z0-9.]*\.[a-z]{2,})", stem, re.IGNORECASE)
    return match.group(1).lower() if match else None


def filter_inputs_for_key_domain(files: list[Path], key_path: Path | None) -> list[Path]:
    """When a folder contains multiple domains, keep files matching the key's domain."""
    domain = infer_domain_from_key_path(key_path)
    if not domain:
        return files
    domain_hits = [f for f in files if domain in f.name.lower()]
    if not domain_hits:
        return files
    # Always keep the explicitly supplied key file.
    filtered = list(domain_hits)
    if key_path is not None:
        resolved_key = normalize_path(str(key_path))
        if resolved_key not in filtered and resolved_key in files:
            filtered.append(resolved_key)
    return filtered


def report_missing_input(raw_paths: list[str], resolved_paths: list[Path]) -> None:
    print("No input files found.")
    print("\nPaths tried:")
    for raw, resolved in zip(raw_paths, resolved_paths):
        exists = resolved.exists()
        kind = "directory" if resolved.is_dir() else "file" if resolved.is_file() else "missing"
        print(f"  Input : {raw}")
        print(f"  Resolved ({kind}{', exists' if exists else ', NOT FOUND'}): {resolved}")
        if not exists:
            suggestions = find_similar_files(raw)
            if suggestions:
                print("  Did you mean:")
                for suggestion in suggestions:
                    print(f"    {to_wsl_path(suggestion)}")
                    print(f"    ({suggestion})")
    print("\nTips:")
    print("  - Quote paths that contain spaces: --input \"/drives/c/.../ASNB CERT/...\"")
    print("  - Pass a folder to scan all cert files: --input \"/drives/c/.../ASNB CERT\"")
    print("  - Or use --input-dir as a shortcut for folder scanning")


def add_input_options(parser: argparse.ArgumentParser) -> None:
    parser.add_argument(
        "--input",
        nargs="+",
        metavar="PATH",
        help="Certificate files, folders, or mixed paths (quote paths with spaces)",
    )
    parser.add_argument(
        "--input-dir",
        metavar="DIR",
        help="Scan a folder for certificate files (.eml, .crt, .pem, etc.)",
    )
    parser.add_argument("-k", "--key", type=path_arg, help="Private key file")
    parser.add_argument("-o", "--output", type=path_arg, help="Output directory for generated artifacts")
    parser.add_argument("-d", "--domain", help="Domain name (auto-detected from leaf CN if omitted)")
    
    pass_group = parser.add_argument_group("Password/Alias Options")
    pass_group.add_argument(
        "-p", "--password", dest="store_pass", default=None,
        help="Keystore password (default: changeit)"
    )
    pass_group.add_argument(
        "--store-pass", dest="store_pass", default=None,
        help=argparse.SUPPRESS  # Hidden alias for --password
    )
    pass_group.add_argument(
        "-a", "--alias", default="server-cert",
        help="Keystore alias (default: server-cert)"
    )
    
    parser.add_argument("--keytool", type=path_arg, default=normalize_path(str(KEYTOOL_DEFAULT)), help="Path to keytool executable")
    parser.add_argument("--p12-password", help="Password for encrypted PKCS12 input files")


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


def resolve_inputs(args: argparse.Namespace) -> tuple[list[Path], list[Path]]:
    raw_inputs, input_paths = collect_cli_inputs(args)
    files = collect_input_files(input_paths)
    key_path = normalize_path(str(args.key)) if getattr(args, "key", None) else None
    files = filter_inputs_for_key_domain(files, key_path)
    if not files:
        report_missing_input(raw_inputs, input_paths)
        sys.exit(1)
    print(f"Found {len(files)} input file(s):")
    for f in files:
        suffix = f.suffix.lower()
        desc = {
            ".eml": "(email)",
            ".p12": "(PKCS12)",
            ".pfx": "(PKCS12)",
            ".p7b": "(PKCS7)",
            ".p7c": "(PKCS7)",
        }.get(suffix, "")
        print(f"  - {f} {desc}")
    return input_paths, files


def resolve_private_key(args: argparse.Namespace, keys: list) -> tuple[Path | None, object]:
    if args.key:
        return args.key, load_private_key(args.key.read_bytes())
    if keys:
        print(f"  Using key from {keys[0][0]}")
        return keys[0][0], keys[0][1]
    key_path, private_key = prompt_for_key()
    return key_path, private_key


def run_generate(args: argparse.Namespace) -> Path:
    _, files = resolve_inputs(args)
    all_certs, keys = parse_all_inputs(files, args.p12_password)
    print(f"\nParsed {len(all_certs)} certificate(s), {len(keys)} private key(s)")

    _key_path, private_key = resolve_private_key(args, keys)

    leaf, intermediates, root = classify_certs(all_certs, args.domain)
    if leaf is None:
        print("\nERROR: Could not identify leaf/server certificate.")
        sys.exit(1)

    print("\nClassified:")
    print(f"  Leaf CN     : {cert_cn(leaf.cert)}")
    print(f"  Intermediate: {[cert_cn(pc.cert) or pc.source.name for pc in intermediates]}")
    print(f"  Root        : {cert_cn(root.cert) if root else 'not found'}")

    if not public_numbers_match(private_key, leaf.cert):
        v = validate_key_cert(private_key, leaf)
        print("\nERROR: Private key does not match leaf certificate!")
        print(f"  Cert MD5: {v['cert_fingerprint_md5']}")
        print(f"  Key MD5 : {v['key_md5']}")
        sys.exit(1)

    domain = infer_domain(leaf, args.domain)
    output_dir = args.output or Path("output") / domain

    if args.dry_run:
        v = validate_key_cert(private_key, leaf)
        print(f"\n[DRY RUN] Would write to: {output_dir}")
        print(f"  Key/Cert match: PASS | Cert MD5: {v['cert_fingerprint_md5']}")
        return output_dir.resolve()

    store_pass = resolve_store_pass(args.store_pass, domain)

    print(f"\nBuilding outputs -> {output_dir}")
    result = build_outputs(
        domain=domain,
        output_dir=output_dir,
        leaf=leaf,
        intermediates=intermediates,
        root=root,
        private_key=private_key,
        store_pass=store_pass,
        alias=args.alias,
        keytool=args.keytool,
    )
    print_validation(result, store_pass, args.alias)
    return result.output_dir.resolve()


def cmd_inspect(args: argparse.Namespace) -> int:
    raw_inputs, input_paths = collect_cli_inputs(args)
    if not collect_input_files(input_paths):
        report_missing_input(raw_inputs, input_paths)
        return 1
    key_path = normalize_path(str(args.key)) if args.key else None
    result = inspect_inputs(
        input_paths,
        key_path=key_path,
        p12_password=args.p12_password,
        domain_hint=args.domain,
    )
    print(format_inspect_report(result, domain_hint=args.domain), end="")
    return 0


def cmd_generate(args: argparse.Namespace) -> int:
    run_generate(args)
    return 0


def run_deploy(args: argparse.Namespace, certs_dir: Path) -> int:
    requested = normalize_path(str(args.config)) if args.config else None
    config_path = resolve_deploy_config(requested)
    if config_path is None:
        report_config_not_found(requested)
        return 1

    use_py = getattr(args, "deploy_py", True)
    if use_py:
        deploy_script = DEFAULT_DEPLOY_DIR / "deploy.py"
        if not deploy_script.is_file():
            print(f"deploy.py not found: {deploy_script}")
            return 1
        cmd = [sys.executable, str(deploy_script), "--certs", str(certs_dir), "--config", str(config_path)]
    else:
        deploy_script = DEFAULT_DEPLOY_DIR / "deploy.sh"
        if not deploy_script.is_file():
            print(f"deploy.sh not found: {deploy_script}")
            return 1
        cmd = ["bash", str(deploy_script), "--certs", str(certs_dir), "--config", str(config_path)]

    if args.dry_run:
        cmd.append("--dry-run")

    print("\nRunning deploy:")
    print("  " + " ".join(cmd))
    completed = subprocess.run(cmd, cwd=str(DEFAULT_DEPLOY_DIR))
    return completed.returncode


def cmd_all(args: argparse.Namespace) -> int:
    output_dir = run_generate(args)
    if args.dry_run and args.no_deploy:
        print("\n[DRY RUN] Skipping deploy (--no-deploy).")
        return 0
    if args.no_deploy:
        print("\nSkipping deploy (--no-deploy).")
        return 0
    return run_deploy(args, output_dir)


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="ssl-pipeline",
        description="Unified SSL pipeline: inspect customer inputs, generate deployment artifacts, deploy to servers.",
        epilog=SUPPORTED_FORMATS,
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    sub = parser.add_subparsers(dest="command", required=True)

    inspect_p = sub.add_parser("inspect", help="Inspect and classify certificate inputs without generating files")
    add_input_options(inspect_p)
    inspect_p.set_defaults(func=cmd_inspect)

    generate_p = sub.add_parser("generate", help="Generate deployment certificate artifacts")
    add_input_options(generate_p)
    generate_p.add_argument("--dry-run", action="store_true", help="Validate and show output path only")
    generate_p.set_defaults(func=cmd_generate)

    all_p = sub.add_parser("all", help="Generate artifacts then run ssl-deploy")
    add_input_options(all_p)
    all_p.add_argument(
        "--config",
        type=path_arg,
        help=f"Deploy config (default: auto-find at {DEFAULT_DEPLOY_CONFIG})",
    )
    all_p.add_argument("--dry-run", action="store_true", help="Dry-run generation and deploy")
    all_p.add_argument("--no-deploy", action="store_true", help="Generate only; do not run deploy")
    all_p.add_argument(
        "--deploy-py",
        action=argparse.BooleanOptionalAction,
        default=True,
        help="Use deploy.py (default). Use --no-deploy-py to run deploy.sh instead.",
    )
    all_p.set_defaults(func=cmd_all)

    return parser


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    return args.func(args)


if __name__ == "__main__":
    raise SystemExit(main())