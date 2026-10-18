"""Pre-deploy checks and live TLS verification."""
from __future__ import annotations

import datetime as dt
import ssl
import threading
from pathlib import Path

import pytest

from conftest import DOMAIN, cert_pem, key_pem, now
from ssl_cert_tool.core import cert_fingerprint_sha256
from ssl_deploy.verify import (
    LEVEL_ERROR,
    LEVEL_INFO,
    LEVEL_WARN,
    covers_domain,
    fetch_peer_cert_sha256,
    has_errors,
    leaf_fingerprint_sha256,
    name_matches,
    verify_cert_bundle,
    wait_for_certificate,
)


def files(cert_dir: Path) -> dict:
    return {
        "certificate": cert_dir / f"main_{DOMAIN}.crt",
        "private_key": cert_dir / f"{DOMAIN}.key",
        "chain": cert_dir / "chain.crt",
    }


def levels(findings):
    return [f.level for f in findings]


def messages(findings, level):
    return [f.message for f in findings if f.level == level]


def test_good_bundle_has_no_errors_or_warnings(cert_dir):
    found = verify_cert_bundle(files(cert_dir), DOMAIN)
    assert LEVEL_ERROR not in levels(found) and LEVEL_WARN not in levels(found)
    assert any("matches certificate" in m for m in messages(found, LEVEL_INFO))


def test_wrong_private_key_is_an_error(cert_dir, pki):
    other, _ = pki.leaf()
    (cert_dir / f"{DOMAIN}.key").write_bytes(key_pem(other))
    found = verify_cert_bundle(files(cert_dir), DOMAIN)
    assert has_errors(found)
    assert any("does NOT match" in m for m in messages(found, LEVEL_ERROR))


def test_expired_and_not_yet_valid_are_errors(cert_dir, pki):
    key, cert = pki.leaf(not_before=now() - dt.timedelta(days=60), not_after=now() - dt.timedelta(days=1))
    (cert_dir / f"main_{DOMAIN}.crt").write_bytes(cert_pem(cert))
    (cert_dir / f"{DOMAIN}.key").write_bytes(key_pem(key))
    assert any("EXPIRED" in m for m in messages(verify_cert_bundle(files(cert_dir), DOMAIN), LEVEL_ERROR))

    key, cert = pki.leaf(not_before=now() + dt.timedelta(days=2), not_after=now() + dt.timedelta(days=90))
    (cert_dir / f"main_{DOMAIN}.crt").write_bytes(cert_pem(cert))
    (cert_dir / f"{DOMAIN}.key").write_bytes(key_pem(key))
    assert any("not valid until" in m for m in messages(verify_cert_bundle(files(cert_dir), DOMAIN), LEVEL_ERROR))


def test_certificate_expiring_soon_is_a_warning_not_an_error(cert_dir, pki):
    key, cert = pki.leaf(not_after=now() + dt.timedelta(days=5))
    (cert_dir / f"main_{DOMAIN}.crt").write_bytes(cert_pem(cert))
    (cert_dir / f"{DOMAIN}.key").write_bytes(key_pem(key))
    found = verify_cert_bundle(files(cert_dir), DOMAIN)
    assert not has_errors(found)
    assert any("expires in" in m for m in messages(found, LEVEL_WARN))


def test_encrypted_key_is_reported(cert_dir, leaf):
    key, _ = leaf
    (cert_dir / f"{DOMAIN}.key").write_bytes(key_pem(key, b"pw123456"))
    assert has_errors(verify_cert_bundle(files(cert_dir), DOMAIN))
    assert not has_errors(verify_cert_bundle(files(cert_dir), DOMAIN, key_password="pw123456"))


def test_domain_not_covered_is_only_a_warning(cert_dir):
    found = verify_cert_bundle(files(cert_dir), "other.example.org")
    assert not has_errors(found)
    assert any("do not cover" in m for m in messages(found, LEVEL_WARN))


def test_chain_without_the_issuer_warns(cert_dir, pki):
    from conftest import issue_cert
    from cryptography.hazmat.primitives.asymmetric import ec

    stranger_key = ec.generate_private_key(ec.SECP256R1())
    stranger = issue_cert("Stranger CA", stranger_key.public_key(), stranger_key, "Stranger CA", ca=True)
    (cert_dir / "chain.crt").write_bytes(cert_pem(stranger))
    found = verify_cert_bundle(files(cert_dir), DOMAIN)
    assert any("issuer" in m for m in messages(found, LEVEL_WARN))


def test_keystore_only_bundle_is_not_an_error(cert_dir):
    found = verify_cert_bundle({"jks": cert_dir / f"{DOMAIN}.jks"}, DOMAIN)
    assert not has_errors(found)


def test_nothing_to_deploy_is_an_error():
    assert has_errors(verify_cert_bundle({}, DOMAIN))


@pytest.mark.parametrize(
    "pattern, host, expected",
    [
        ("example.com", "example.com", True),
        ("EXAMPLE.com", "example.COM.", True),
        ("*.example.com", "app.example.com", True),
        ("*.example.com", "a.b.example.com", False),
        ("*.example.com", "example.com", False),
        ("*.example.com", "evilexample.com", False),
        ("app.example.com", "example.com", False),
    ],
)
def test_name_matching_follows_wildcard_rules(pattern, host, expected):
    assert name_matches(pattern, host) is expected


def test_wildcard_certificate_covers_its_base_domain(pki):
    _key, cert = pki.leaf("*.example.com", sans=("*.example.com",))
    assert covers_domain(cert, "example.com")  # how this tool names wildcard deployments
    assert covers_domain(cert, "app.example.com")
    assert not covers_domain(cert, "a.b.example.com")


def test_leaf_fingerprint_is_sha256_of_the_certificate(cert_dir, leaf):
    _key, cert = leaf
    assert leaf_fingerprint_sha256(files(cert_dir)) == cert_fingerprint_sha256(cert)
    assert leaf_fingerprint_sha256({}) is None


# ---------------------------------------------------------------------------
# Live TLS check
# ---------------------------------------------------------------------------

def test_wait_for_certificate_retries_until_it_matches():
    served = iter(["old", "old", "new"])
    sleeps = []
    ok, detail = wait_for_certificate(
        "h", 443, "new", attempts=5, delay=2, sleep=sleeps.append,
        fetch=lambda host, port, servername=None: next(served),
    )
    assert ok and sleeps == [2, 2]


def test_wait_for_certificate_gives_up_and_reports(monkeypatch):
    def boom(host, port, servername=None):
        raise ConnectionRefusedError("refused")

    sleeps = []
    ok, detail = wait_for_certificate("h", 443, "x", attempts=3, delay=1, sleep=sleeps.append, fetch=boom)
    assert not ok and "refused" in detail and len(sleeps) == 2


def test_wait_for_certificate_reports_a_stale_certificate():
    ok, detail = wait_for_certificate(
        "h", 443, "new", attempts=1, sleep=lambda s: None,
        fetch=lambda host, port, servername=None: "o" * 64,
    )
    assert not ok and "different certificate" in detail


def test_fetch_peer_cert_returns_the_fingerprint_of_what_is_served(tmp_path, cert_dir, leaf):
    import socket

    key, cert = leaf
    cert_file, key_file = tmp_path / "srv.crt", tmp_path / "srv.key"
    cert_file.write_bytes(cert_pem(cert))
    key_file.write_bytes(key_pem(key))
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    ctx.load_cert_chain(str(cert_file), str(key_file))
    listener = socket.socket()
    listener.bind(("127.0.0.1", 0))
    listener.listen(1)
    port = listener.getsockname()[1]

    def serve():
        try:
            conn, _ = listener.accept()
            with ctx.wrap_socket(conn, server_side=True):
                pass
        except OSError:
            pass

    threading.Thread(target=serve, daemon=True).start()
    try:
        assert fetch_peer_cert_sha256("127.0.0.1", port) == cert_fingerprint_sha256(cert)
    finally:
        listener.close()
