"""Certificate/key parsing, key matching, archive safety, keytool handling."""
from __future__ import annotations

import os
import stat
import subprocess
import zipfile
from pathlib import Path

import pytest
from cryptography.hazmat.primitives.asymmetric import ec, ed25519, rsa

from conftest import DOMAIN, cert_pem, issue_cert, key_pem, posix_only
from ssl_cert_tool import core
from ssl_cert_tool import jks as jks_store
from ssl_cert_tool.core import (
    EncryptedKeyError,
    ParsedCert,
    UnsafeArchiveError,
    build_outputs,
    create_jks,
    extract_archive,
    inspect_inputs,
    load_private_key,
    parse_all_inputs,
    public_numbers_match,
)


# ---------------------------------------------------------------------------
# Key <-> certificate matching
# ---------------------------------------------------------------------------

@pytest.mark.parametrize(
    "make_key",
    [
        lambda: ec.generate_private_key(ec.SECP256R1()),
        lambda: rsa.generate_private_key(65537, 2048),
        lambda: ed25519.Ed25519PrivateKey.generate(),
    ],
    ids=["ec", "rsa", "ed25519"],
)
def test_key_matches_its_own_cert_for_every_key_type(pki, make_key):
    key = make_key()
    cert = issue_cert(DOMAIN, key.public_key(), pki.ca_key, "Test Root CA", sans=(DOMAIN,))
    assert public_numbers_match(key, cert)
    other = make_key()
    assert not public_numbers_match(other, cert)


def test_mismatch_across_key_types_is_false_not_an_error(pki, leaf):
    _key, cert = leaf
    assert not public_numbers_match(rsa.generate_private_key(65537, 2048), cert)
    assert not public_numbers_match(ed25519.Ed25519PrivateKey.generate(), cert)


# ---------------------------------------------------------------------------
# Private key loading
# ---------------------------------------------------------------------------

def test_encrypted_key_without_passphrase_gives_actionable_error(leaf):
    key, _ = leaf
    data = key_pem(key, b"hunter2")
    with pytest.raises(EncryptedKeyError, match="--key-password"):
        load_private_key(data)
    assert isinstance(EncryptedKeyError("x"), ValueError)  # old `except ValueError` still works


def test_encrypted_key_with_right_and_wrong_passphrase(leaf):
    key, cert = leaf
    data = key_pem(key, b"hunter2")
    assert public_numbers_match(load_private_key(data, "hunter2"), cert)
    with pytest.raises(EncryptedKeyError, match="incorrect"):
        load_private_key(data, "wrong")


def test_a_passphrase_given_for_an_unencrypted_key_is_ignored(leaf):
    key, cert = leaf
    assert public_numbers_match(load_private_key(key_pem(key), "not-needed"), cert)
    assert public_numbers_match(load_private_key(key_pem(key), b"not-needed"), cert)


def test_a_wrong_passphrase_is_always_reported_as_wrong_even_when_the_library_says_parse_error(leaf, monkeypatch):
    """Roughly 1 wrong passphrase in 256 decrypts to valid-looking padding, and the library then
    reports a deserialisation failure instead of 'bad decrypt'. That must not turn into the
    misleading 'supply --key-password'."""
    key, _ = leaf
    data = key_pem(key, b"right-pass")
    real = core.serialization.load_pem_private_key

    def flaky(payload, password=None, **kw):
        if password == b"wrong-pass":
            raise ValueError("Could not deserialize key data. The data may be in an incorrect format")
        return real(payload, password=password, **kw)

    monkeypatch.setattr(core.serialization, "load_pem_private_key", flaky)
    with pytest.raises(EncryptedKeyError, match="incorrect"):
        load_private_key(data, "wrong-pass")
    assert load_private_key(data, "right-pass") is not None


def test_encrypted_key_without_a_passphrase_still_asks_for_one(leaf):
    key, _ = leaf
    with pytest.raises(EncryptedKeyError, match="supply --key-password"):
        load_private_key(key_pem(key, b"right-pass"))


def test_traditional_openssl_encrypted_keys_are_recognised(leaf):
    from cryptography.hazmat.primitives import serialization as ser

    key, cert = leaf
    legacy = key.private_bytes(ser.Encoding.PEM, ser.PrivateFormat.TraditionalOpenSSL, ser.BestAvailableEncryption(b"legacy-pw"))
    with pytest.raises(EncryptedKeyError, match="supply"):
        load_private_key(legacy)
    assert public_numbers_match(load_private_key(legacy, "legacy-pw"), cert)
    with pytest.raises(EncryptedKeyError, match="incorrect"):
        load_private_key(legacy, "nope")


def test_garbage_is_a_plain_value_error():
    with pytest.raises(ValueError) as exc:
        load_private_key(b"not a key at all")
    assert not isinstance(exc.value, EncryptedKeyError)


def test_inspect_reports_encrypted_key_instead_of_crashing(cert_dir, leaf):
    key, _ = leaf
    enc = cert_dir.parent / "enc.key"
    enc.write_bytes(key_pem(key, b"pw123456"))
    result = inspect_inputs([cert_dir], key_path=enc)
    assert any("passphrase" in w for w in result.warnings)
    ok = inspect_inputs([cert_dir], key_path=enc, key_password="pw123456")
    assert any("ready to generate" in n.lower() or "matching key" in n.lower() for n in ok.notes)


# ---------------------------------------------------------------------------
# Output files: private material is owner-only
# ---------------------------------------------------------------------------

def _build(tmp_path, pki, leaf, **kw):
    key, cert = leaf
    return build_outputs(
        domain=DOMAIN,
        output_dir=tmp_path / "out",
        leaf=ParsedCert(cert, Path("leaf.crt"), cert_pem(cert)),
        intermediates=[],
        root=ParsedCert(pki.ca_cert, Path("ca.crt"), cert_pem(pki.ca_cert)),
        private_key=key,
        store_pass="storepass1",
        keytool=Path("definitely-not-a-real-keytool"),
        **kw,
    )


@posix_only
def test_generated_private_files_are_0600_and_dir_is_0700(tmp_path, pki, leaf):
    result = _build(tmp_path, pki, leaf)
    out = tmp_path / "out"
    for name in (f"{DOMAIN}.key", "keystore.p12", f"{DOMAIN}.jks", "asterisk.pem", f"asterisk_{DOMAIN}.pem"):
        assert stat.S_IMODE((out / name).stat().st_mode) == 0o600, name
    assert stat.S_IMODE(out.stat().st_mode) == 0o700
    # keytool is deliberately missing, so the built-in writer made the keystore and said so
    assert any("built-in JKS writer" in w for w in result.warnings)
    assert not any("JKS not created" in w for w in result.warnings)


def test_ed25519_keys_can_be_generated(tmp_path, pki):
    key = ed25519.Ed25519PrivateKey.generate()
    cert = issue_cert(DOMAIN, key.public_key(), pki.ca_key, "Test Root CA", sans=(DOMAIN,))
    result = build_outputs(
        domain=DOMAIN,
        output_dir=tmp_path / "out",
        leaf=ParsedCert(cert, Path("l.crt"), cert_pem(cert)),
        intermediates=[],
        root=None,
        private_key=key,
        keytool=Path("none"),
    )
    assert result.validation["key_cert_match"] is True
    assert b"BEGIN PRIVATE KEY" in (tmp_path / "out" / f"{DOMAIN}.key").read_bytes()


def test_generated_key_matches_leaf_and_pem_is_key_first(tmp_path, pki, leaf):
    result = _build(tmp_path, pki, leaf)
    assert result.validation["key_cert_match"]
    assert result.validation["asterisk_pem_key_first"]


# ---------------------------------------------------------------------------
# keytool: password never in argv, existing keystore never destroyed
# ---------------------------------------------------------------------------

class _FakeKeytool:
    def __init__(self, returncode=0):
        self.returncode = returncode
        self.calls = []

    def __call__(self, cmd, **kwargs):
        self.calls.append((list(cmd), kwargs))
        if self.returncode == 0:
            Path(cmd[cmd.index("-destkeystore") + 1]).write_bytes(b"NEW-JKS")
        return subprocess.CompletedProcess(cmd, self.returncode, b"", b"keytool: boom")


def test_create_jks_passes_password_via_environment_only(tmp_path, monkeypatch):
    kt = tmp_path / "keytool"
    kt.write_bytes(b"")
    p12 = tmp_path / "k.p12"
    p12.write_bytes(b"x")
    fake = _FakeKeytool()
    monkeypatch.setattr(subprocess, "run", fake)
    create_jks(p12, tmp_path / "out.jks", kt, "sup3rsecret")
    cmd, kwargs = fake.calls[0]
    assert all("sup3rsecret" not in part for part in cmd)
    assert "-srcstorepass:env" in cmd and "-deststorepass:env" in cmd
    assert kwargs["env"][core.KEYTOOL_PASS_ENV] == "sup3rsecret"
    assert (tmp_path / "out.jks").read_bytes() == b"NEW-JKS"
    assert not list(tmp_path.glob(".out.jks.*.tmp"))


def test_failed_keytool_keeps_the_existing_keystore(tmp_path, monkeypatch):
    kt = tmp_path / "keytool"
    kt.write_bytes(b"")
    p12 = tmp_path / "k.p12"
    p12.write_bytes(b"x")
    jks = tmp_path / "out.jks"
    jks.write_bytes(b"PRECIOUS-OLD-JKS")
    monkeypatch.setattr(subprocess, "run", _FakeKeytool(returncode=1))
    with pytest.raises(RuntimeError, match="boom"):
        create_jks(p12, jks, kt, "sup3rsecret")
    assert jks.read_bytes() == b"PRECIOUS-OLD-JKS"
    assert not list(tmp_path.glob(".out.jks.*.tmp"))


def test_short_keystore_password_is_rejected_up_front(tmp_path):
    kt = tmp_path / "keytool"
    kt.write_bytes(b"")
    with pytest.raises(ValueError, match="at least 6"):
        create_jks(tmp_path / "a", tmp_path / "b", kt, "abc")


def test_missing_keytool_falls_back_to_the_builtin_writer(tmp_path, pki, leaf):
    result = _build(tmp_path, pki, leaf)  # keytool=Path("definitely-not-a-real-keytool")
    jks_path = tmp_path / "out" / f"{DOMAIN}.jks"
    assert jks_path in result.files
    assert any("built-in JKS writer" in w for w in result.warnings)
    entries = jks_store.load_file(jks_path, "storepass1")
    assert [e.alias for e in entries] == ["ameyo-server"]
    assert len(entries[0].chain) == 2  # leaf + root, leaf first
    assert entries[0].leaf.subject == leaf[1].subject


def test_builtin_jks_is_not_left_half_written_on_a_bad_p12(tmp_path):
    bad = tmp_path / "bad.p12"
    bad.write_bytes(b"not a pkcs12 file")
    target = tmp_path / "out.jks"
    target.write_bytes(b"PRECIOUS-OLD-JKS")
    with pytest.raises(ValueError):
        create_jks(bad, target, Path("no-such-keytool-xyz"), "password1")
    assert target.read_bytes() == b"PRECIOUS-OLD-JKS"


def test_force_builtin_env_skips_an_installed_keytool(tmp_path, pki, leaf, monkeypatch):
    kt = tmp_path / "keytool"
    kt.write_bytes(b"")
    monkeypatch.setenv(core.FORCE_BUILTIN_JKS_ENV, "1")
    called = []
    monkeypatch.setattr(subprocess, "run", lambda *a, **k: called.append(a))
    key, cert = leaf
    out = tmp_path / "out"
    build_outputs(
        domain=DOMAIN, output_dir=out,
        leaf=ParsedCert(cert, Path("l.crt"), cert_pem(cert)), intermediates=[], root=None,
        private_key=key, store_pass="storepass1", keytool=kt,
    )
    assert called == [] and (out / f"{DOMAIN}.jks").is_file()


def test_read_jks_info_without_keytool_uses_the_builtin_reader(tmp_path, pki, leaf, monkeypatch):
    monkeypatch.setenv(core.FORCE_BUILTIN_JKS_ENV, "1")
    _build(tmp_path, pki, leaf)
    jks_path = tmp_path / "out" / f"{DOMAIN}.jks"
    info = core.read_jks_info(jks_path, "storepass1")
    assert info.error is None and info.password_valid
    assert info.alias == "ameyo-server" and info.domain == DOMAIN
    assert [c["role"] for c in info.chain] == ["leaf", "root"]
    assert info.key_type == "EC" and not info.is_expired
    wrong = core.read_jks_info(jks_path, "wrong-password")
    assert wrong.error == "Invalid password" and not wrong.password_valid


def test_read_jks_info_keeps_password_out_of_argv(tmp_path, monkeypatch):
    kt = tmp_path / "keytool"
    kt.write_bytes(b"")
    jks = tmp_path / "x.jks"
    jks.write_bytes(b"x")
    seen = {}

    def fake_run(cmd, **kwargs):
        seen["cmd"], seen["env"] = list(cmd), kwargs["env"]
        return subprocess.CompletedProcess(cmd, 1, "", "password was incorrect")

    monkeypatch.setattr(subprocess, "run", fake_run)
    info = core.read_jks_info(jks, "topsecret1", kt)
    assert info.error == "Invalid password"
    assert "topsecret1" not in " ".join(seen["cmd"])
    assert seen["env"][core.KEYTOOL_PASS_ENV] == "topsecret1"


# ---------------------------------------------------------------------------
# Archives from customers are untrusted
# ---------------------------------------------------------------------------

def make_zip(path: Path, members: dict, symlink: str | None = None) -> Path:
    with zipfile.ZipFile(path, "w") as zf:
        for name, data in members.items():
            zf.writestr(name, data)
        if symlink:
            info = zipfile.ZipInfo(symlink)
            info.external_attr = (0o120777 << 16)
            zf.writestr(info, "/etc/passwd")
    return path


def test_zip_slip_is_rejected_and_nothing_escapes(tmp_path):
    archive = make_zip(tmp_path / "evil.zip", {"../evil.txt": "pwned"})
    with pytest.raises(UnsafeArchiveError, match="unsafe path"):
        extract_archive(archive, tmp_path / "out")
    assert not (tmp_path / "evil.txt").exists()


@pytest.mark.parametrize("name", ["/abs/evil.txt", "C:/evil.txt", "a/../../evil.txt", "..\\evil.txt"])
def test_other_hostile_member_names_are_rejected(tmp_path, name):
    archive = make_zip(tmp_path / "evil.zip", {name: "x"})
    with pytest.raises(UnsafeArchiveError):
        extract_archive(archive, tmp_path / "out")


def test_symlink_entries_are_rejected(tmp_path):
    archive = make_zip(tmp_path / "link.zip", {"ok.txt": "fine"}, symlink="link")
    with pytest.raises(UnsafeArchiveError, match="symlink"):
        extract_archive(archive, tmp_path / "out")


def test_zip_bomb_limits(tmp_path, monkeypatch):
    archive = make_zip(tmp_path / "many.zip", {f"f{i}.txt": "x" for i in range(10)})
    monkeypatch.setattr(core, "MAX_ARCHIVE_MEMBERS", 5)
    with pytest.raises(UnsafeArchiveError, match="too many"):
        extract_archive(archive, tmp_path / "o1")
    monkeypatch.setattr(core, "MAX_ARCHIVE_MEMBERS", 100)
    monkeypatch.setattr(core, "MAX_ARCHIVE_TOTAL_BYTES", 5)
    with pytest.raises(UnsafeArchiveError, match="total size"):
        extract_archive(archive, tmp_path / "o2")
    monkeypatch.setattr(core, "MAX_ARCHIVE_TOTAL_BYTES", 10**9)
    monkeypatch.setattr(core, "MAX_ARCHIVE_MEMBER_BYTES", 0)
    with pytest.raises(UnsafeArchiveError, match="oversized"):
        extract_archive(archive, tmp_path / "o3")


def test_normal_zip_still_extracts(tmp_path):
    archive = make_zip(tmp_path / "ok.zip", {"a.txt": "1", "sub/b.txt": "2"})
    names = sorted(p.name for p in extract_archive(archive, tmp_path / "out"))
    assert names == ["a.txt", "b.txt"]


def test_normal_7z_extracts_and_traversal_is_rejected(tmp_path):
    py7zr = pytest.importorskip("py7zr")
    (tmp_path / "a.txt").write_text("hello")
    archive = tmp_path / "t.7z"
    with py7zr.SevenZipFile(archive, "w") as z:
        z.write(tmp_path / "a.txt", "a.txt")
    assert [p.name for p in extract_archive(archive, tmp_path / "out")] == ["a.txt"]

    bad = tmp_path / "bad.7z"
    with py7zr.SevenZipFile(bad, "w") as z:
        z.write(tmp_path / "a.txt", "../escape.txt")
    with pytest.raises(UnsafeArchiveError):
        extract_archive(bad, tmp_path / "out2")
    assert not (tmp_path / "escape.txt").exists()


def test_one_hostile_archive_does_not_abort_the_rest_of_a_folder_scan(tmp_path, pki, leaf, capsys):
    _key, cert = leaf
    folder = tmp_path / "customer"
    folder.mkdir()
    make_zip(folder / "evil.zip", {"../evil.txt": "x"})
    (folder / "good.crt").write_bytes(cert_pem(cert))
    files = core.collect_input_files([folder])
    certs, _keys = parse_all_inputs(files)
    assert len(certs) == 1
    assert "Skipped" in capsys.readouterr().out
    assert not (tmp_path / "evil.txt").exists()


def test_certs_found_inside_a_zip_are_deduplicated_by_sha256(tmp_path, leaf):
    _key, cert = leaf
    make_zip(tmp_path / "bundle.zip", {"one.crt": cert_pem(cert).decode(), "two.pem": cert_pem(cert).decode()})
    certs, _ = parse_all_inputs([tmp_path / "bundle.zip"])
    assert len(certs) == 1


def test_sniffing_does_not_read_whole_files(tmp_path, monkeypatch):
    big = tmp_path / "huge.bin"
    big.write_bytes(b"\x00" * 1_000_000)
    reads = []
    real_open = open

    def tracking_open(path, mode="r", *a, **k):
        f = real_open(path, mode, *a, **k)
        if str(path) == str(big):
            orig = f.read
            f.read = lambda n=-1: (reads.append(n), orig(n))[1]
        return f

    monkeypatch.setattr("builtins.open", tracking_open)
    core.should_scan_file(big)
    assert reads and all(n != -1 for n in reads)
