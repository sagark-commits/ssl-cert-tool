# Author: Sagar K | 2026 | MIT licence
"""The built-in JKS reader/writer: round-trips, hostile input, and an independent oracle."""
from __future__ import annotations

import hashlib
import struct

import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec, ed25519, rsa

from conftest import DOMAIN, issue_cert
from ssl_cert_tool import jks

PW = "storepass1"


def der(cert) -> bytes:
    return cert.public_bytes(serialization.Encoding.DER)


def pkcs8(key) -> bytes:
    return key.private_bytes(
        serialization.Encoding.DER, serialization.PrivateFormat.PKCS8, serialization.NoEncryption()
    )


@pytest.fixture(params=["ec", "rsa"])
def key_and_chain(request, pki):
    key = (
        ec.generate_private_key(ec.SECP256R1())
        if request.param == "ec"
        else rsa.generate_private_key(65537, 2048)
    )
    cert = issue_cert(DOMAIN, key.public_key(), pki.ca_key, "Test Root CA", sans=(DOMAIN,))
    return key, [cert, pki.ca_cert]


def sealed(key, chain, alias="Server-Key", password=PW) -> bytes:
    return jks.dumps([jks.key_entry(alias, key, chain)], password)


# ---------------------------------------------------------------------------
# Round trips
# ---------------------------------------------------------------------------

def test_key_entry_round_trips_with_key_and_chain(key_and_chain):
    key, chain = key_and_chain
    [entry] = jks.loads(sealed(key, chain), PW)
    assert entry.is_key_entry
    assert entry.alias == "server-key"  # JKS aliases are stored lowercase
    assert entry.key_pkcs8 == pkcs8(key)
    assert [der(c) for c in entry.chain] == [der(c) for c in chain]


def test_trusted_cert_entries_and_multiple_entries(key_and_chain, pki):
    key, chain = key_and_chain
    data = jks.dumps(
        [jks.key_entry("k", key, chain), jks.JKSEntry("root", [pki.ca_cert])], PW
    )
    entries = jks.loads(data, PW)
    assert [(e.alias, e.is_key_entry) for e in entries] == [("k", True), ("root", False)]
    assert der(entries[1].leaf) == der(pki.ca_cert)


def test_non_ascii_and_astral_aliases_survive(key_and_chain):
    key, chain = key_and_chain
    for alias in ["ключ", "密钥", "key-\U0001F511"]:
        [entry] = jks.loads(sealed(key, chain, alias=alias), PW)
        assert entry.alias == alias.lower()


def test_passwords_with_unicode_work(key_and_chain):
    key, chain = key_and_chain
    password = "pässwörd-é\U0001F512"
    [entry] = jks.loads(sealed(key, chain, password=password), password)
    assert entry.key_pkcs8 == pkcs8(key)


def test_output_is_not_deterministic_but_always_valid(key_and_chain):
    key, chain = key_and_chain
    a, b = sealed(key, chain), sealed(key, chain)
    assert a != b  # random salt
    assert len(a) == len(b)


def test_write_jks_replaces_atomically_and_privately(tmp_path, key_and_chain):
    key, chain = key_and_chain
    path = tmp_path / "ks.jks"
    path.write_bytes(b"old")
    jks.write_jks(path, [jks.key_entry("k", key, chain)], PW)
    assert jks.load_file(path, PW)[0].alias == "k"
    assert not list(tmp_path.glob(".ks.jks.*"))


def test_duplicate_aliases_and_bad_entries_are_refused(key_and_chain, pki):
    key, chain = key_and_chain
    with pytest.raises(jks.JKSError, match="duplicate"):
        jks.dumps([jks.key_entry("A", key, chain), jks.key_entry("a", key, chain)], PW)
    with pytest.raises(jks.JKSError, match="exactly one"):
        jks.dumps([jks.JKSEntry("x", chain)], PW)
    with pytest.raises(jks.JKSError, match="RSA and EC"):
        jks.key_entry("k", ed25519.Ed25519PrivateKey.generate(), chain)
    with pytest.raises(jks.JKSError, match="chain"):
        jks.key_entry("k", key, [])


def test_order_chain_puts_the_leaf_first(pki):
    inter_key = ec.generate_private_key(ec.SECP256R1())
    inter = issue_cert("Test Intermediate", inter_key.public_key(), pki.ca_key, "Test Root CA", ca=True)
    leaf_key = ec.generate_private_key(ec.SECP256R1())
    leaf = issue_cert(DOMAIN, leaf_key.public_key(), inter_key, "Test Intermediate", sans=(DOMAIN,))
    for shuffled in ([pki.ca_cert, leaf, inter], [inter, pki.ca_cert, leaf], [leaf, pki.ca_cert, inter]):
        ordered = jks.order_chain(shuffled)
        assert [der(c) for c in ordered] == [der(leaf), der(inter), der(pki.ca_cert)]
    assert jks.order_chain([]) == []
    assert jks.order_chain([pki.ca_cert]) == [pki.ca_cert]


# ---------------------------------------------------------------------------
# Wrong password / tampering / hostile files
# ---------------------------------------------------------------------------

def test_wrong_password_is_reported_as_such(key_and_chain):
    key, chain = key_and_chain
    with pytest.raises(jks.JKSError, match="password was incorrect"):
        jks.loads(sealed(key, chain), "not-the-password")


def test_any_flipped_byte_breaks_the_integrity_check(key_and_chain):
    key, chain = key_and_chain
    data = bytearray(sealed(key, chain))
    for position in (20, len(data) // 2, len(data) - 25, len(data) - 1):
        tampered = bytearray(data)
        tampered[position] ^= 0x01
        with pytest.raises(jks.JKSError):
            jks.loads(bytes(tampered), PW)


def test_private_key_password_is_checked_separately():
    # protect/unprotect with different passwords must fail, not return garbage
    blob = jks.protect_key(b"\x30\x03\x02\x01\x00" * 7, "right-password")
    assert jks.unprotect_key(blob, "right-password") == b"\x30\x03\x02\x01\x00" * 7
    with pytest.raises(jks.JKSError, match="private key password"):
        jks.unprotect_key(blob, "wrong-password")


@pytest.mark.parametrize(
    "data, message",
    [
        (b"", "too short"),
        (b"\x00" * 64, "bad magic"),
        (struct.pack(">III", jks.JCEKS_MAGIC, 2, 0) + b"\x00" * 20, "JCEKS"),
        (struct.pack(">III", jks.MAGIC, 1, 0) + b"\x00" * 20, "version"),
        (struct.pack(">III", jks.MAGIC, 2, 10**9) + b"\x00" * 20, "too many"),
    ],
)
def test_garbage_headers_are_rejected_cleanly(data, message):
    with pytest.raises(jks.JKSError, match=message):
        jks.loads(data, PW)


def seal_raw(body: bytes, password=PW) -> bytes:
    """Hand-built file with a *valid* digest, so only the structure checks can reject it."""
    digest = hashlib.sha1(jks._password_bytes(password) + jks.WHITENER + body).digest()
    return body + digest


def test_oversized_element_claims_cannot_cause_huge_allocations():
    body = struct.pack(">III", jks.MAGIC, 2, 1)
    body += struct.pack(">I", jks.TAG_PRIVATE_KEY) + jks._encode_mutf8("k") + struct.pack(">q", 0)
    body += struct.pack(">I", 0x7FFFFFFF)  # "protected key is 2 GB long"
    with pytest.raises(jks.JKSError, match="oversized"):
        jks.loads(seal_raw(body), PW)


def test_truncated_structure_and_trailing_junk_are_rejected():
    body = struct.pack(">III", jks.MAGIC, 2, 1) + struct.pack(">I", jks.TAG_TRUSTED_CERT)
    with pytest.raises(jks.JKSError, match="truncated"):
        jks.loads(seal_raw(body), PW)
    empty_with_junk = struct.pack(">III", jks.MAGIC, 2, 0) + b"junk"
    with pytest.raises(jks.JKSError, match="unexpected data"):
        jks.loads(seal_raw(empty_with_junk), PW)


def test_unknown_entry_type_and_bad_chain_length_are_rejected(key_and_chain):
    body = struct.pack(">III", jks.MAGIC, 2, 1) + struct.pack(">I", 99) + jks._encode_mutf8("k") + struct.pack(">q", 0)
    with pytest.raises(jks.JKSError, match="unknown entry"):
        jks.loads(seal_raw(body), PW)
    body = struct.pack(">III", jks.MAGIC, 2, 1) + struct.pack(">I", jks.TAG_PRIVATE_KEY)
    body += jks._encode_mutf8("k") + struct.pack(">q", 0) + struct.pack(">I", 3) + b"abc" + struct.pack(">I", 0)
    with pytest.raises(jks.JKSError, match="chain length"):
        jks.loads(seal_raw(body), PW)


def test_check_password_reports_missing_alias(tmp_path, key_and_chain):
    key, chain = key_and_chain
    path = tmp_path / "ks.jks"
    jks.write_jks(path, [jks.key_entry("present", key, chain)], PW)
    assert jks.check_password(path, PW, "PRESENT") == (True, "ok")
    ok, detail = jks.check_password(path, PW, "absent")
    assert not ok and "not found" in detail
    ok, detail = jks.check_password(path, "nope", None)
    assert not ok and "password" in detail
    assert jks.check_password(tmp_path / "missing.jks", PW)[0] is False


# ---------------------------------------------------------------------------
# Independent oracle: pyjks (skipped when it is not installed)
# ---------------------------------------------------------------------------

@pytest.fixture
def pyjks():
    return pytest.importorskip("jks", reason="pyjks provides an independent JKS implementation")


def test_our_file_opens_in_pyjks(pyjks, key_and_chain):
    key, chain = key_and_chain
    store = pyjks.KeyStore.loads(sealed(key, chain, alias="Srv"), PW)
    entry = store.private_keys["srv"]
    assert entry.pkey_pkcs8 == pkcs8(key)
    assert [cert for _type, cert in entry.cert_chain] == [der(c) for c in chain]


def test_pyjks_file_opens_in_ours(pyjks, key_and_chain, pki):
    key, chain = key_and_chain
    store = pyjks.KeyStore.new(
        "jks",
        [
            pyjks.PrivateKeyEntry.new("theirs", [der(c) for c in chain], pkcs8(key), "pkcs8"),
            pyjks.TrustedCertEntry.new("ca", der(pki.ca_cert)),
        ],
    )
    entries = jks.loads(store.saves(PW), PW)
    by_alias = {e.alias: e for e in entries}
    assert by_alias["theirs"].key_pkcs8 == pkcs8(key)
    assert [der(c) for c in by_alias["theirs"].chain] == [der(c) for c in chain]
    assert der(by_alias["ca"].leaf) == der(pki.ca_cert)
