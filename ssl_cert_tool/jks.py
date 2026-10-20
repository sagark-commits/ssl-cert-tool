# Author: Sagar K | 2026 | MIT licence
"""Pure-Python reader/writer for Java KeyStore (JKS) files - no JDK required.

Used when `keytool` is not installed (and for reading old keystores). Java's own
`keytool` is still preferred when present.

Format (java.security.KeyStore type "JKS", version 2), big-endian:

    0xFEEDFEED  version(2)  entry_count
    entry*:   tag(1=private key, 2=trusted cert)  alias(UTF)  timestamp_ms(int64)
              tag 1: protected_key(int32 len + EncryptedPrivateKeyInfo DER)
                     chain_count(int32)  [cert_type(UTF "X.509")  int32 len + DER]*
              tag 2: cert_type(UTF)  int32 len + DER
    SHA-1( password_utf16be + "Mighty Aphrodite" + everything above )   (20 bytes)

Be aware JKS is a legacy format: the integrity digest is SHA-1 and private keys are
"protected" with Sun's proprietary SHA-1 stream scheme (OID 1.3.6.1.4.1.42.2.17.1.1).
That is what Java expects here; use PKCS#12 where the application allows it.
Only RSA and EC private keys are written (what every Java version can read).
"""
from __future__ import annotations

import hashlib
import hmac
import os
import struct
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import List, Optional, Sequence, Tuple

from cryptography import x509
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec, rsa

from ssl_cert_tool.fsutil import atomic_write_private

MAGIC = 0xFEEDFEED
JCEKS_MAGIC = 0xCECECECE
VERSION_2 = 2
TAG_PRIVATE_KEY = 1
TAG_TRUSTED_CERT = 2
CERT_TYPE = "X.509"
KEY_PROTECTOR_OID = bytes.fromhex("2b060104012a02110101")  # 1.3.6.1.4.1.42.2.17.1.1
WHITENER = b"Mighty Aphrodite"
SALT_LEN = 20
DIGEST_LEN = 20

# Keystores can come from customers: bound what we are willing to parse.
MAX_FILE_BYTES = 64 * 1024 * 1024
MAX_ENTRIES = 10_000
MAX_CHAIN = 100
MAX_BLOB = 16 * 1024 * 1024


class JKSError(ValueError):
    """Malformed keystore, wrong password, or unsupported content."""


@dataclass
class JKSEntry:
    alias: str
    chain: List[x509.Certificate]
    timestamp_ms: int = 0
    key_pkcs8: Optional[bytes] = None  # plaintext PKCS#8 for private-key entries

    @property
    def is_key_entry(self) -> bool:
        return self.key_pkcs8 is not None

    @property
    def leaf(self) -> x509.Certificate:
        return self.chain[0]


# ---------------------------------------------------------------------------
# Small helpers
# ---------------------------------------------------------------------------

def _password_bytes(password: str) -> bytes:
    """Java hashes the password as UTF-16BE chars."""
    return password.encode("utf-16-be", "surrogatepass")


def _encode_mutf8(text: str) -> bytes:
    """java.io.DataOutputStream.writeUTF: 2-byte length + modified UTF-8."""
    units = text.encode("utf-16-be", "surrogatepass")
    out = bytearray()
    for i in range(0, len(units), 2):
        u = (units[i] << 8) | units[i + 1]
        if 0 < u <= 0x7F:
            out.append(u)
        elif u <= 0x7FF:
            out += bytes((0xC0 | (u >> 6), 0x80 | (u & 0x3F)))
        else:
            out += bytes((0xE0 | (u >> 12), 0x80 | ((u >> 6) & 0x3F), 0x80 | (u & 0x3F)))
    if len(out) > 0xFFFF:
        raise JKSError("string too long for JKS")
    return struct.pack(">H", len(out)) + bytes(out)


def _decode_mutf8(raw: bytes) -> str:
    raw = raw.replace(b"\xc0\x80", b"\x00")
    text = raw.decode("utf-8", "surrogatepass")
    try:  # re-join surrogate pairs into real characters
        return text.encode("utf-16-le", "surrogatepass").decode("utf-16-le")
    except UnicodeError:
        return text


def _der_len(n: int) -> bytes:
    if n < 0x80:
        return bytes([n])
    body = n.to_bytes((n.bit_length() + 7) // 8, "big")
    return bytes([0x80 | len(body)]) + body


def _der(tag: int, content: bytes) -> bytes:
    return bytes([tag]) + _der_len(len(content)) + content


def _read_tlv(data: bytes, pos: int) -> Tuple[int, int, int]:
    """Return (tag, content_start, content_end) of the DER element at `pos`."""
    if pos + 2 > len(data):
        raise JKSError("truncated DER data")
    tag = data[pos]
    first = data[pos + 1]
    pos += 2
    if first < 0x80:
        length = first
    else:
        n = first & 0x7F
        if n == 0 or n > 4 or pos + n > len(data):
            raise JKSError("bad DER length")
        length = int.from_bytes(data[pos : pos + n], "big")
        pos += n
    end = pos + length
    if end > len(data):
        raise JKSError("DER element runs past end of data")
    return tag, pos, end


# ---------------------------------------------------------------------------
# Sun's key protection ("KeyProtector")
# ---------------------------------------------------------------------------

def _xor_keystream(data: bytes, pw: bytes, salt: bytes) -> bytes:
    out = bytearray(len(data))
    digest = salt
    offset = 0
    while offset < len(data):
        digest = hashlib.sha1(pw + digest).digest()
        chunk = digest[: len(data) - offset]
        for i, byte in enumerate(chunk):
            out[offset + i] = data[offset + i] ^ byte
        offset += DIGEST_LEN
    return bytes(out)


def protect_key(pkcs8: bytes, password: str) -> bytes:
    """PKCS#8 -> EncryptedPrivateKeyInfo DER using Sun's JKS key protector."""
    pw = _password_bytes(password)
    salt = os.urandom(SALT_LEN)
    encrypted = salt + _xor_keystream(pkcs8, pw, salt) + hashlib.sha1(pw + pkcs8).digest()
    algorithm = _der(0x30, _der(0x06, KEY_PROTECTOR_OID) + b"\x05\x00")
    return _der(0x30, algorithm + _der(0x04, encrypted))


def unprotect_key(blob: bytes, password: str) -> bytes:
    tag, start, end = _read_tlv(blob, 0)
    if tag != 0x30 or end != len(blob):
        raise JKSError("malformed protected key")
    tag, a_start, a_end = _read_tlv(blob, start)  # AlgorithmIdentifier
    if tag != 0x30:
        raise JKSError("malformed protected key")
    otag, o_start, o_end = _read_tlv(blob, a_start)
    if otag != 0x06 or blob[o_start:o_end] != KEY_PROTECTOR_OID:
        raise JKSError("unsupported key protection algorithm (not Sun's JKS protector)")
    tag, d_start, d_end = _read_tlv(blob, a_end)
    if tag != 0x04:
        raise JKSError("malformed protected key")
    encrypted = blob[d_start:d_end]
    if len(encrypted) < SALT_LEN + DIGEST_LEN + 1:
        raise JKSError("protected key is too short")
    pw = _password_bytes(password)
    salt, body, check = encrypted[:SALT_LEN], encrypted[SALT_LEN:-DIGEST_LEN], encrypted[-DIGEST_LEN:]
    plain = _xor_keystream(body, pw, salt)
    if not hmac.compare_digest(hashlib.sha1(pw + plain).digest(), check):
        raise JKSError("private key password is incorrect")
    return plain


# ---------------------------------------------------------------------------
# Writing
# ---------------------------------------------------------------------------

def order_chain(certs: Sequence[x509.Certificate]) -> List[x509.Certificate]:
    """Order leaf -> issuer -> ... (what keytool stores); unlinked certs go last."""
    remaining = list(certs)
    if not remaining:
        return []

    def issues_another(cert: x509.Certificate) -> bool:
        return any(o is not cert and o.issuer == cert.subject and o.subject != o.issuer for o in remaining)

    # The leaf is the certificate that issued none of the others.
    leaf = next((c for c in remaining if not issues_another(c)), remaining[0])
    ordered = [leaf]
    remaining.remove(leaf)
    while remaining:
        nxt = next((c for c in remaining if c.subject == ordered[-1].issuer and c is not ordered[-1]), None)
        if nxt is None:
            break
        ordered.append(nxt)
        remaining.remove(nxt)
    return ordered + remaining


def key_entry(alias: str, private_key, chain: Sequence[x509.Certificate]) -> JKSEntry:
    if not isinstance(private_key, (rsa.RSAPrivateKey, ec.EllipticCurvePrivateKey)):
        raise JKSError(
            "the built-in JKS writer supports RSA and EC keys only; use keytool or a PKCS#12 keystore"
        )
    if not chain:
        raise JKSError("a private-key entry needs a certificate chain")
    pkcs8 = private_key.private_bytes(
        serialization.Encoding.DER, serialization.PrivateFormat.PKCS8, serialization.NoEncryption()
    )
    return JKSEntry(alias=alias, chain=list(chain), key_pkcs8=pkcs8)


def dumps(entries: Sequence[JKSEntry], password: str) -> bytes:
    """Serialize entries into a JKS file (key password == store password)."""
    seen = set()
    body = bytearray(struct.pack(">III", MAGIC, VERSION_2, len(entries)))
    for entry in entries:
        alias = entry.alias.lower()  # JKS aliases are case-insensitive, stored lowercase
        if alias in seen:
            raise JKSError(f"duplicate alias {alias!r}")
        seen.add(alias)
        stamp = entry.timestamp_ms or int(time.time() * 1000)
        if entry.is_key_entry:
            body += struct.pack(">I", TAG_PRIVATE_KEY) + _encode_mutf8(alias) + struct.pack(">q", stamp)
            protected = protect_key(entry.key_pkcs8, password)  # type: ignore[arg-type]
            body += struct.pack(">I", len(protected)) + protected
            body += struct.pack(">I", len(entry.chain))
            for cert in entry.chain:
                der = cert.public_bytes(serialization.Encoding.DER)
                body += _encode_mutf8(CERT_TYPE) + struct.pack(">I", len(der)) + der
        else:
            if len(entry.chain) != 1:
                raise JKSError("a trusted-certificate entry holds exactly one certificate")
            der = entry.chain[0].public_bytes(serialization.Encoding.DER)
            body += struct.pack(">I", TAG_TRUSTED_CERT) + _encode_mutf8(alias) + struct.pack(">q", stamp)
            body += _encode_mutf8(CERT_TYPE) + struct.pack(">I", len(der)) + der
    digest = hashlib.sha1(_password_bytes(password) + WHITENER + bytes(body)).digest()
    return bytes(body) + digest


def write_jks(path: Path, entries: Sequence[JKSEntry], password: str) -> None:
    """Write a keystore atomically (an existing file is only replaced on success)."""
    atomic_write_private(Path(path), dumps(entries, password))


# ---------------------------------------------------------------------------
# Reading
# ---------------------------------------------------------------------------

class _Reader:
    def __init__(self, data: bytes, end: int) -> None:
        self.data, self.pos, self.end = data, 0, end

    def take(self, n: int) -> bytes:
        if n < 0 or self.pos + n > self.end:
            raise JKSError("truncated keystore")
        chunk = self.data[self.pos : self.pos + n]
        self.pos += n
        return chunk

    def u32(self) -> int:
        return struct.unpack(">I", self.take(4))[0]

    def i64(self) -> int:
        return struct.unpack(">q", self.take(8))[0]

    def utf(self) -> str:
        (length,) = struct.unpack(">H", self.take(2))
        return _decode_mutf8(self.take(length))

    def blob(self) -> bytes:
        length = self.u32()
        if length > MAX_BLOB:
            raise JKSError("oversized element in keystore")
        return self.take(length)


def _load_cert(reader: _Reader) -> x509.Certificate:
    cert_type = reader.utf()
    if cert_type != CERT_TYPE:
        raise JKSError(f"unsupported certificate type {cert_type!r}")
    try:
        return x509.load_der_x509_certificate(reader.blob())
    except ValueError as exc:
        raise JKSError(f"unreadable certificate in keystore: {exc}") from exc


def loads(data: bytes, password: str, *, decrypt_keys: bool = True) -> List[JKSEntry]:
    """Parse a JKS file. Verifies the integrity digest (wrong password or a
    tampered file raises JKSError) and, by default, that each private key
    decrypts with the same password."""
    if len(data) > MAX_FILE_BYTES:
        raise JKSError("keystore file is too large")
    if len(data) < 12 + DIGEST_LEN:
        raise JKSError("not a JKS keystore (file too short)")
    magic, version, count = struct.unpack(">III", data[:12])
    if magic == JCEKS_MAGIC:
        raise JKSError("this is a JCEKS keystore, not JKS (use keytool)")
    if magic != MAGIC:
        raise JKSError("not a JKS keystore (bad magic number); PKCS#12 files are read separately")
    if version != VERSION_2:
        raise JKSError(f"unsupported JKS version {version}")
    if count > MAX_ENTRIES:
        raise JKSError("keystore claims too many entries")

    expected = hashlib.sha1(_password_bytes(password) + WHITENER + data[:-DIGEST_LEN]).digest()
    if not hmac.compare_digest(expected, data[-DIGEST_LEN:]):
        raise JKSError("keystore was tampered with, or password was incorrect")

    reader = _Reader(data, len(data) - DIGEST_LEN)
    reader.pos = 12
    entries: List[JKSEntry] = []
    for _ in range(count):
        tag = reader.u32()
        alias = reader.utf()
        stamp = reader.i64()
        if tag == TAG_PRIVATE_KEY:
            protected = reader.blob()
            chain_len = reader.u32()
            if chain_len == 0 or chain_len > MAX_CHAIN:
                raise JKSError("bad certificate chain length")
            chain = [_load_cert(reader) for _ in range(chain_len)]
            pkcs8 = unprotect_key(protected, password) if decrypt_keys else b""
            entries.append(JKSEntry(alias, chain, stamp, pkcs8))
        elif tag == TAG_TRUSTED_CERT:
            entries.append(JKSEntry(alias, [_load_cert(reader)], stamp, None))
        else:
            raise JKSError(f"unknown entry type {tag}")
    if reader.pos != reader.end:
        raise JKSError("unexpected data after the last entry")
    return entries


def load_file(path: Path, password: str, *, decrypt_keys: bool = True) -> List[JKSEntry]:
    path = Path(path)
    if path.stat().st_size > MAX_FILE_BYTES:
        raise JKSError("keystore file is too large")
    return loads(path.read_bytes(), password, decrypt_keys=decrypt_keys)


def check_password(path: Path, password: str, alias: Optional[str] = None) -> Tuple[bool, str]:
    """Does the keystore open with `password` (and contain `alias`)? -> (ok, detail)."""
    try:
        entries = load_file(path, password)
    except (JKSError, OSError) as exc:
        return False, str(exc)
    if alias and alias.lower() not in {e.alias for e in entries}:
        return False, f"alias {alias!r} not found (have: {', '.join(e.alias for e in entries) or 'none'})"
    return True, "ok"
