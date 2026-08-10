"""CLI for SSL certificate deployment automation."""
from __future__ import annotations
import argparse
import sys
from pathlib import Path

from .core import (
    KEYTOOL_DEFAULT,
    BuildResult,
    build_outputs,
    cert_cn,
    classify_certs,
    collect_input_files,
    infer_domain,
    load_certs_from_bytes,
    load_private_key,
    parse_all_inputs,
    public_numbers_match,
    validate_key_cert,
)


def prompt_for_key():
    print("\nPrivate key not found in inputs.")
    while True:
        raw = input("Enter path to private key (.key / .pem): ").strip().strip('"')
        if not raw:
            print("  Key is required. Try again or Ctrl+C to abort.")
            continue
        path = Path(raw)
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


def run_validate_only(key_path: Path, cert_path: Path) -> None:
    key = load_private_key(key_path.read_bytes())
    certs = load_certs_from_bytes(cert_path.read_bytes(), cert_path)
    if not certs:
        print(f"No certificate found in {cert_path}")
        sys.exit(1)
    leaf_parsed, _, _ = classify_certs(certs)
    leaf = leaf_parsed or certs[0]
    v = validate_key_cert(key, leaf)
    print("\n--- Validate Only ---")
    print(f"  Cert file : {cert_path}")
    print(f"  Key file  : {key_path}")
    print(f"  CN        : {cert_cn(leaf.cert)}")
    print(f"  Subject   : {v['subject']}")
    print(f"  Valid     : {v['not_before']} -> {v['not_after']}")
    print(f"  Cert MD5  : {v['cert_fingerprint_md5']}")
    print(f"  Key MD5   : {v['key_md5']}")
    print(f"  Match     : {'PASS' if v['key_cert_match'] else 'FAIL'}")
    sys.exit(0 if v["key_cert_match"] else 1)


def main(argv=None):
    parser = argparse.ArgumentParser(
        prog="ssl-cert-tool",
        description="Build Ameyo/CRM SSL deployment files from arbitrary customer cert inputs.",
        epilog="""
Supported input formats:
  .crt, .cer, .pem  - PEM or DER encoded certificates
  .p7b, .p7c        - PKCS7 certificate chains
  .p12, .pfx        - PKCS12 keystores (use --p12-password if encrypted)
  .ca-bundle        - Multiple PEM certificates concatenated
  .eml              - Email files (e.g., GlobalSign certificate emails)
  .txt              - Text files containing PEM certificates
  Folders           - Recursively scans for certificate files
"""
    )
    parser.add_argument("inputs", nargs="*", help="Cert files, EML files, or directories")
    parser.add_argument("-o", "--output", type=Path, help="Output directory")
    parser.add_argument("-d", "--domain", help="Domain name (auto-detected from cert CN if not specified)")
    parser.add_argument("-k", "--key", type=Path, help="Private key file")
    parser.add_argument("--store-pass", default="changeit", help="Keystore password (default: changeit)")
    parser.add_argument("--alias", default="ameyo-server", help="Key alias (default: ameyo-server)")
    parser.add_argument("--keytool", type=Path, default=KEYTOOL_DEFAULT, help="Path to keytool executable")
    parser.add_argument("--p12-password", help="Password for encrypted PKCS12 input files")
    parser.add_argument("--validate-only", action="store_true", help="Only validate key/cert match")
    parser.add_argument("--dry-run", action="store_true", help="Show what would be done without creating files")
    args = parser.parse_args(argv)
    
    if args.validate_only:
        if not args.key or len(args.inputs) != 1:
            parser.error("--validate-only requires --key and exactly one cert file")
        run_validate_only(args.key, Path(args.inputs[0]))
        return 0
    
    if not args.inputs:
        parser.print_help()
        print("\nExamples:")
        print("  # Process GlobalSign email with key file")
        print("  python -m ssl_cert_tool certificate.eml -k domain.key")
        print("")
        print("  # Process folder of cert files")
        print("  python -m ssl_cert_tool C:\\certs\\ -k domain.key")
        print("")
        print("  # Process multiple files with explicit domain")
        print("  python -m ssl_cert_tool server.crt ca-bundle.crt -k server.key -d example.com")
        print("")
        print("  # Validate key matches cert")
        print("  python -m ssl_cert_tool --validate-only -k domain.key main.crt")
        return 0
    
    files = collect_input_files([Path(p) for p in args.inputs])
    if not files:
        print("No input files found.")
        return 1
    
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
    
    all_certs, keys = parse_all_inputs(files, args.p12_password)
    print(f"\nParsed {len(all_certs)} certificate(s), {len(keys)} private key(s)")
    
    private_key = load_private_key(args.key.read_bytes()) if args.key else (keys[0][1] if keys else None)
    if keys and not args.key:
        print(f"  Using key from {keys[0][0]}")
    
    leaf, intermediates, root = classify_certs(all_certs, args.domain)
    if leaf is None:
        print("\nERROR: Could not identify leaf/server certificate.")
        return 1
    
    print("\nClassified:")
    print(f"  Leaf CN     : {cert_cn(leaf.cert)}")
    print(f"  Intermediate: {[cert_cn(pc.cert) or pc.source.name for pc in intermediates]}")
    print(f"  Root        : {cert_cn(root.cert) if root else 'not found'}")
    
    if private_key is None:
        _, private_key = prompt_for_key()
    
    if not public_numbers_match(private_key, leaf.cert):
        v = validate_key_cert(private_key, leaf)
        print("\nERROR: Private key does not match leaf certificate!")
        print(f"  Cert MD5: {v['cert_fingerprint_md5']}")
        print(f"  Key MD5 : {v['key_md5']}")
        return 1
    
    domain = infer_domain(leaf, args.domain)
    output_dir = args.output or Path("output") / domain
    
    if args.dry_run:
        v = validate_key_cert(private_key, leaf)
        print(f"\n[DRY RUN] Would write to: {output_dir}")
        print(f"  Key/Cert match: PASS | Cert MD5: {v['cert_fingerprint_md5']}")
        return 0
    
    print(f"\nBuilding outputs -> {output_dir}")
    result = build_outputs(
        domain=domain,
        output_dir=output_dir,
        leaf=leaf,
        intermediates=intermediates,
        root=root,
        private_key=private_key,
        store_pass=args.store_pass,
        alias=args.alias,
        keytool=args.keytool,
    )
    print_validation(result, args.store_pass, args.alias)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())