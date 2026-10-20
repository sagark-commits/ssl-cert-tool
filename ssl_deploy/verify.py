# Author: Sagar K | 2026 | MIT licence
"""Pre-deploy sanity checks (local files) and post-deploy TLS verification (live)."""
from __future__ import annotations

import hashlib
import socket
import ssl
import time
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Callable, Dict, List, Optional, Tuple

from cryptography import x509
from cryptography.x509.oid import NameOID

from ssl_cert_tool.core import (
    KEY_PATTERNS,
    EncryptedKeyError,
    cert_fingerprint_sha256,
    load_certs_from_bytes,
    load_private_key,
    public_numbers_match,
)

EXPIRY_WARN_DAYS = 14

LEVEL_ERROR = "error"
LEVEL_WARN = "warn"
LEVEL_INFO = "info"


@dataclass
class Finding:
    level: str
    message: str


def has_errors(findings: List[Finding]) -> bool:
    return any(f.level == LEVEL_ERROR for f in findings)


# ---------------------------------------------------------------------------
# Names
# ---------------------------------------------------------------------------

def name_matches(pattern: str, hostname: str) -> bool:
    """RFC 6125-style match: a leading `*.` covers exactly one label."""
    pattern = pattern.lower().rstrip(".")
    hostname = hostname.lower().rstrip(".")
    if pattern.startswith("*."):
        suffix = pattern[1:]
        if not hostname.endswith(suffix):
            return False
        label = hostname[: -len(suffix)]
        return bool(label) and "." not in label
    return pattern == hostname


def cert_names(cert: x509.Certificate) -> List[str]:
    try:
        san = cert.extensions.get_extension_for_class(x509.SubjectAlternativeName).value
        names = list(san.get_values_for_type(x509.DNSName))
    except x509.ExtensionNotFound:
        names = []
    if not names:
        try:
            names = [cert.subject.get_attributes_for_oid(NameOID.COMMON_NAME)[0].value]
        except IndexError:
            names = []
    return names


def covers_domain(cert: x509.Certificate, domain: str) -> bool:
    """True if the cert covers `domain` (a `*.example.com` cert also counts for the
    base name `example.com`, which is how this tool derives domains from wildcards)."""
    domain = domain.lower().strip().lstrip("*.").rstrip(".")
    for name in cert_names(cert):
        lowered = name.lower()
        if name_matches(lowered, domain) or lowered.lstrip("*.") == domain:
            return True
    return False


# ---------------------------------------------------------------------------
# Local pre-deploy checks
# ---------------------------------------------------------------------------

def _leaf_from(cert_files: Dict[str, Path]) -> Tuple[Optional[x509.Certificate], Optional[Path]]:
    for kind in ("certificate", "fullchain", "asterisk_crt"):
        path = cert_files.get(kind)
        if not path:
            continue
        try:
            parsed = load_certs_from_bytes(Path(path).read_bytes(), Path(path))
        except OSError:
            continue
        if parsed:
            return parsed[0].cert, Path(path)
    return None, None


def leaf_fingerprint_sha256(cert_files: Dict[str, Path]) -> Optional[str]:
    leaf, _ = _leaf_from(cert_files)
    return cert_fingerprint_sha256(leaf) if leaf else None


def verify_cert_bundle(
    cert_files: Dict[str, Path],
    domain: Optional[str] = None,
    *,
    key_password: Optional[str] = None,
    now: Optional[datetime] = None,
    warn_days: int = EXPIRY_WARN_DAYS,
) -> List[Finding]:
    """Check the files we are about to push. Errors must block the deploy."""
    findings: List[Finding] = []
    now = now or datetime.now(timezone.utc)
    leaf, leaf_path = _leaf_from(cert_files)

    if leaf is None:
        if cert_files.get("jks") or cert_files.get("p12"):
            findings.append(Finding(
                LEVEL_INFO,
                "No PEM certificate found next to the keystore; its contents can only be "
                "verified on the server (the JKS post-upload check does that).",
            ))
        else:
            findings.append(Finding(LEVEL_ERROR, "No certificate found among the files to deploy."))
        return findings

    # Validity window
    not_after = leaf.not_valid_after_utc
    not_before = leaf.not_valid_before_utc
    if now < not_before:
        findings.append(Finding(LEVEL_ERROR, f"Certificate is not valid until {not_before:%Y-%m-%d %H:%M} UTC."))
    if now > not_after:
        findings.append(Finding(LEVEL_ERROR, f"Certificate EXPIRED on {not_after:%Y-%m-%d} UTC."))
    else:
        days = (not_after - now).days
        if days < warn_days:
            findings.append(Finding(LEVEL_WARN, f"Certificate expires in {days} day(s) ({not_after:%Y-%m-%d})."))

    # Private key must belong to this certificate
    key_path = cert_files.get("private_key")
    if key_path:
        try:
            key = load_private_key(Path(key_path).read_bytes(), key_password)
        except EncryptedKeyError as exc:
            findings.append(Finding(LEVEL_ERROR, f"Private key {Path(key_path).name}: {exc}"))
        except (OSError, ValueError) as exc:
            findings.append(Finding(LEVEL_ERROR, f"Private key {Path(key_path).name} could not be read: {exc}"))
        else:
            if public_numbers_match(key, leaf):
                findings.append(Finding(LEVEL_INFO, f"Private key matches certificate ({leaf_path.name if leaf_path else 'leaf'})."))
            else:
                findings.append(Finding(
                    LEVEL_ERROR,
                    f"Private key {Path(key_path).name} does NOT match certificate "
                    f"{leaf_path.name if leaf_path else ''} - deploying would break TLS.",
                ))

    # Domain coverage
    if domain:
        if covers_domain(leaf, domain):
            findings.append(Finding(LEVEL_INFO, f"Certificate covers {domain}."))
        else:
            findings.append(Finding(
                LEVEL_WARN,
                f"Certificate names {', '.join(cert_names(leaf)) or '(none)'} do not cover configured domain {domain}.",
            ))

    # Chain linkage: the supplied chain should contain the leaf's issuer
    chain_path = cert_files.get("chain") or cert_files.get("ca_crt")
    if chain_path:
        try:
            chain = load_certs_from_bytes(Path(chain_path).read_bytes(), Path(chain_path))
        except OSError:
            chain = []
        if chain and not any(pc.cert.subject == leaf.issuer for pc in chain):
            findings.append(Finding(
                LEVEL_WARN,
                f"{Path(chain_path).name} does not contain the issuer of the leaf certificate; "
                "clients may fail to build the chain.",
            ))
    return findings


def verify_copy_sources(
    paths: List[Path],
    *,
    key_password: Optional[str] = None,
    now: Optional[datetime] = None,
    warn_days: int = EXPIRY_WARN_DAYS,
) -> List[Finding]:
    """Sanity-check arbitrary files about to be copied: certificates must be in date, and a
    private key among them must belong to one of the certificates. Plain files pass through."""
    findings: List[Finding] = []
    now = now or datetime.now(timezone.utc)
    leaves: List[Tuple[Path, x509.Certificate]] = []
    keys: List[Tuple[Path, object]] = []

    for path in paths:
        path = Path(path)
        try:
            data = path.read_bytes()
        except OSError as exc:
            findings.append(Finding(LEVEL_ERROR, f"{path.name}: {exc}"))
            continue
        if any(marker in data for marker in KEY_PATTERNS):
            try:
                keys.append((path, load_private_key(data, key_password)))
            except EncryptedKeyError as exc:
                findings.append(Finding(LEVEL_ERROR, f"{path.name}: {exc}"))
            except ValueError:
                findings.append(Finding(LEVEL_WARN, f"{path.name} looks like a private key but could not be read"))
        certs = load_certs_from_bytes(data, path) if b"CERTIFICATE" in data else []
        if certs:
            first = certs[0].cert
            try:
                is_ca = first.extensions.get_extension_for_class(x509.BasicConstraints).value.ca
            except x509.ExtensionNotFound:
                is_ca = False
            if not is_ca:
                leaves.append((path, first))

    for path, cert in leaves:
        if now < cert.not_valid_before_utc:
            findings.append(Finding(LEVEL_ERROR, f"{path.name}: not valid until {cert.not_valid_before_utc:%Y-%m-%d} UTC."))
        elif now > cert.not_valid_after_utc:
            findings.append(Finding(LEVEL_ERROR, f"{path.name}: certificate EXPIRED on {cert.not_valid_after_utc:%Y-%m-%d} UTC."))
        else:
            days = (cert.not_valid_after_utc - now).days
            if days < warn_days:
                findings.append(Finding(LEVEL_WARN, f"{path.name}: certificate expires in {days} day(s)."))

    for key_path, key in keys:
        match = next((p for p, c in leaves if public_numbers_match(key, c)), None)
        if match is not None:
            findings.append(Finding(LEVEL_INFO, f"Private key {key_path.name} matches certificate {match.name}."))
        elif leaves:
            findings.append(Finding(
                LEVEL_ERROR,
                f"Private key {key_path.name} does NOT match any certificate being copied "
                f"({', '.join(p.name for p, _ in leaves)}).",
            ))
    if not leaves and not keys:
        findings.append(Finding(LEVEL_INFO, "No certificates or keys recognised; files are copied as they are."))
    return findings


# ---------------------------------------------------------------------------
# Live TLS verification (after restart)
# ---------------------------------------------------------------------------

def fetch_peer_cert_sha256(
    host: str,
    port: int,
    *,
    servername: Optional[str] = None,
    timeout: float = 10.0,
) -> str:
    """Handshake with host:port and return the SHA-256 of the served leaf (DER).

    Certificate verification is off on purpose: we only want to know *which*
    certificate is being served, and we compare it with the one we deployed.
    """
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    try:  # old appliances may only speak TLS 1.0/1.1 or weak ciphers
        ctx.minimum_version = ssl.TLSVersion.MINIMUM_SUPPORTED
        ctx.set_ciphers("DEFAULT:@SECLEVEL=0")
    except (ssl.SSLError, ValueError, AttributeError):
        pass
    with socket.create_connection((host, port), timeout=timeout) as sock:
        with ctx.wrap_socket(sock, server_hostname=servername or host) as tls:
            der = tls.getpeercert(binary_form=True)
    if not der:
        raise ssl.SSLError("server presented no certificate")
    return hashlib.sha256(der).hexdigest()


def wait_for_certificate(
    host: str,
    port: int,
    expected_sha256: str,
    *,
    servername: Optional[str] = None,
    attempts: int = 6,
    delay: float = 5.0,
    sleep: Callable[[float], None] = time.sleep,
    fetch: Callable[..., str] = fetch_peer_cert_sha256,
) -> Tuple[bool, str]:
    """Poll until the endpoint serves the expected certificate (services need a
    few seconds to restart). Returns (ok, human-readable detail)."""
    last = "no attempt made"
    for attempt in range(1, max(1, attempts) + 1):
        try:
            actual = fetch(host, port, servername=servername)
        except (OSError, ssl.SSLError) as exc:
            last = f"{type(exc).__name__}: {exc}"
        else:
            if actual == expected_sha256:
                return True, f"{host}:{port} serves the deployed certificate"
            last = f"{host}:{port} still serves a different certificate ({actual[:16]}...)"
        if attempt < attempts:
            sleep(delay)
    return False, last
