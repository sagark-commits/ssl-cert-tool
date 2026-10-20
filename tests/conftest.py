# Author: Sagar K | 2026 | MIT licence
"""Shared fixtures: a tiny PKI and helpers to lay out certificate directories."""
from __future__ import annotations

import datetime
import sys
from dataclasses import dataclass
from pathlib import Path

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID

ROOT = Path(__file__).resolve().parent.parent
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

posix_only = pytest.mark.skipif(
    sys.platform == "win32", reason="needs POSIX permission/symlink semantics"
)

DOMAIN = "app.example.com"


def now() -> datetime.datetime:
    return datetime.datetime.now(datetime.timezone.utc)


def _name(cn: str) -> x509.Name:
    return x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, cn)])


def issue_cert(
    subject_cn: str,
    public_key,
    issuer_key,
    issuer_cn: str,
    *,
    sans=(),
    ca: bool = False,
    not_before=None,
    not_after=None,
) -> x509.Certificate:
    builder = (
        x509.CertificateBuilder()
        .subject_name(_name(subject_cn))
        .issuer_name(_name(issuer_cn))
        .public_key(public_key)
        .serial_number(x509.random_serial_number())
        .not_valid_before(not_before or now() - datetime.timedelta(days=1))
        .not_valid_after(not_after or now() + datetime.timedelta(days=90))
        .add_extension(x509.BasicConstraints(ca=ca, path_length=None), critical=True)
    )
    if sans:
        builder = builder.add_extension(
            x509.SubjectAlternativeName([x509.DNSName(s) for s in sans]), critical=False
        )
    if not ca:
        builder = builder.add_extension(
            x509.ExtendedKeyUsage([ExtendedKeyUsageOID.SERVER_AUTH]), critical=False
        )
    return builder.sign(issuer_key, hashes.SHA256())


def cert_pem(cert: x509.Certificate) -> bytes:
    return cert.public_bytes(serialization.Encoding.PEM)


def key_pem(key, password: bytes | None = None) -> bytes:
    enc = (
        serialization.BestAvailableEncryption(password)
        if password
        else serialization.NoEncryption()
    )
    return key.private_bytes(
        serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, enc
    )


@dataclass
class PKI:
    ca_key: object
    ca_cert: x509.Certificate

    def leaf(self, cn: str = DOMAIN, sans=None, **kwargs):
        key = ec.generate_private_key(ec.SECP256R1())
        cert = issue_cert(
            cn, key.public_key(), self.ca_key, "Test Root CA",
            sans=sans if sans is not None else (cn,), **kwargs,
        )
        return key, cert


@pytest.fixture(scope="session")
def pki() -> PKI:
    key = ec.generate_private_key(ec.SECP256R1())
    cert = issue_cert("Test Root CA", key.public_key(), key, "Test Root CA", ca=True)
    return PKI(key, cert)


@pytest.fixture
def leaf(pki):
    return pki.leaf()


@pytest.fixture
def cert_dir(tmp_path, pki, leaf) -> Path:
    """A directory shaped like the tool's own output, with a matching key/cert."""
    key, cert = leaf
    d = tmp_path / "certs"
    d.mkdir()
    (d / f"main_{DOMAIN}.crt").write_bytes(cert_pem(cert))
    (d / f"{DOMAIN}.key").write_bytes(key_pem(key))
    (d / "chain.crt").write_bytes(cert_pem(pki.ca_cert))
    (d / f"{DOMAIN}.jks").write_bytes(b"FAKE-JKS-BYTES")
    pem = key_pem(key) + cert_pem(cert) + cert_pem(pki.ca_cert)
    (d / f"asterisk_{DOMAIN}.pem").write_bytes(pem)
    (d / f"asterisk_{DOMAIN}.crt").write_bytes(cert_pem(cert) + cert_pem(pki.ca_cert))
    return d
