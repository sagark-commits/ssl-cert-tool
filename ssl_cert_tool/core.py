# Author: Sagar K | 2026 | MIT licence
"""Core SSL cert processing."""
from __future__ import annotations

import base64
import email
import hashlib
import os
import re
import shutil
import subprocess
import tempfile
import zipfile
import xml.etree.ElementTree as ET
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Iterable

from cryptography import x509
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec, rsa
from cryptography.hazmat.primitives.serialization import BestAvailableEncryption, Encoding, PrivateFormat, pkcs12
from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID

from ssl_cert_tool import jks as jks_store
from ssl_cert_tool.fsutil import atomic_write_private, is_within, restrict_to_owner, write_private

def _default_keytool() -> Path:
    from ssl_cert_tool.platform import find_keytool

    found = find_keytool()
    if found:
        return found
    return Path("keytool")


KEYTOOL_DEFAULT = _default_keytool()
CERT_BEGIN = b"-----BEGIN CERTIFICATE-----"
KEY_PATTERNS = (
    b"-----BEGIN PRIVATE KEY-----",
    b"-----BEGIN RSA PRIVATE KEY-----",
    b"-----BEGIN EC PRIVATE KEY-----",
    b"-----BEGIN ENCRYPTED PRIVATE KEY-----",
)

CERT_FILE_EXTENSIONS = (
    ".crt",
    ".cer",
    ".pem",
    ".p7b",
    ".p7c",
    ".p12",
    ".pfx",
    ".der",
    ".ca-bundle",
    ".bundle",
    ".eml",
    ".txt",
    ".docx",
    ".zip",
    ".7z",
)

ARCHIVE_EXTENSIONS = (".zip", ".7z")

EMAIL_HEADER_MARKERS = (
    b"From:",
    b"MIME-Version:",
    b"Content-Type:",
    b"Received:",
    b"Subject:",
)

VENDOR_LEAF_NAME_HINTS = (
    "certificate",
    "cert",
    "server",
    "domain",
    "ssl",
    "wildcard",
    "leaf",
    "main",
)

VENDOR_CHAIN_NAME_HINTS = (
    "chain",
    "bundle",
    "intermediate",
    "ca-bundle",
    "fullchain",
    "ca",
    "root",
    "crm-ca",
)

SKIP_FILE_NAMES = frozenset(
    {
        ".DS_Store",
        "Thumbs.db",
        "desktop.ini",
    }
)

DOCX_W_NS = "{http://schemas.openxmlformats.org/wordprocessingml/2006/main}"

_PARSE_MAX_DEPTH = 12

# Customer-supplied archives are untrusted: cap what we are willing to unpack.
MAX_ARCHIVE_MEMBERS = 2000
MAX_ARCHIVE_TOTAL_BYTES = 256 * 1024 * 1024
MAX_ARCHIVE_MEMBER_BYTES = 64 * 1024 * 1024
MAX_DOCX_XML_BYTES = 32 * 1024 * 1024
MAX_PARSE_FILE_BYTES = 64 * 1024 * 1024


class UnsafeArchiveError(ValueError):
    """Archive contains path traversal, links, or exceeds size limits."""


class EncryptedKeyError(ValueError):
    """Private key is passphrase-protected and no (or the wrong) passphrase was given."""


def _read_head(path: Path, size: int = 8192) -> bytes:
    """Read at most `size` bytes (never loads a whole large file just to sniff it)."""
    with open(path, "rb") as fh:
        return fh.read(size)


@dataclass
class ParsedCert:
    cert: x509.Certificate
    source: Path
    pem: bytes


@dataclass
class BuildResult:
    domain: str
    output_dir: Path
    files: list[Path] = field(default_factory=list)
    warnings: list[str] = field(default_factory=list)
    validation: dict = field(default_factory=dict)


@dataclass
class InspectResult:
    inputs: list[Path]
    files_scanned: list[Path] = field(default_factory=list)
    certs: list[ParsedCert] = field(default_factory=list)
    keys: list[tuple[Path, Any]] = field(default_factory=list)
    leaf: ParsedCert | None = None
    intermediates: list[ParsedCert] = field(default_factory=list)
    root: ParsedCert | None = None
    warnings: list[str] = field(default_factory=list)
    notes: list[str] = field(default_factory=list)
    skipped: list[tuple[Path, str]] = field(default_factory=list)


def md5_file(path: Path) -> str:
    h = hashlib.md5()
    h.update(path.read_bytes())
    return h.hexdigest()


def md5_bytes(data: bytes) -> str:
    return hashlib.md5(data).hexdigest()


def cert_fingerprint_md5(cert: x509.Certificate) -> str:
    return hashlib.md5(cert.public_bytes(Encoding.DER)).hexdigest()


def cert_fingerprint_sha256(cert: x509.Certificate) -> str:
    return hashlib.sha256(cert.public_bytes(Encoding.DER)).hexdigest()


def cert_cn(cert: x509.Certificate) -> str | None:
    try:
        return cert.subject.get_attributes_for_oid(NameOID.COMMON_NAME)[0].value
    except IndexError:
        return None


def cert_subject(cert: x509.Certificate) -> str:
    return cert.subject.rfc4514_string()


def cert_issuer(cert: x509.Certificate) -> str:
    return cert.issuer.rfc4514_string()


def cert_issuer_cn(cert: x509.Certificate) -> str | None:
    try:
        return cert.issuer.get_attributes_for_oid(NameOID.COMMON_NAME)[0].value
    except IndexError:
        return None


def is_self_signed(cert: x509.Certificate) -> bool:
    return cert.issuer == cert.subject


def is_ca(cert: x509.Certificate) -> bool:
    try:
        return cert.extensions.get_extension_for_class(x509.BasicConstraints).value.ca
    except x509.ExtensionNotFound:
        return False


def has_server_auth(cert: x509.Certificate) -> bool:
    try:
        return ExtendedKeyUsageOID.SERVER_AUTH in cert.extensions.get_extension_for_class(
            x509.ExtendedKeyUsage
        ).value
    except x509.ExtensionNotFound:
        return False


def _spki_der(public_key) -> bytes:
    return public_key.public_bytes(Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo)


def public_numbers_match(key, cert: x509.Certificate) -> bool:
    """True if `key` is the private key for `cert`.

    Compares the DER SubjectPublicKeyInfo, so it works for every key type the
    cryptography library supports (RSA, EC, Ed25519, Ed448, DSA), not just RSA/EC.
    """
    try:
        return _spki_der(key.public_key()) == _spki_der(cert.public_key())
    except (AttributeError, ValueError, TypeError):
        return False


def write_pem_cert(cert: x509.Certificate, path: Path) -> None:
    path.write_bytes(cert.public_bytes(Encoding.PEM))


def write_pem_certs(certs: Iterable[x509.Certificate], path: Path) -> None:
    path.write_bytes(b"".join(c.public_bytes(Encoding.PEM) for c in certs))


def extract_pem_blocks(data: bytes, marker: bytes) -> list[bytes]:
    begin, end = marker, marker.replace(b"BEGIN", b"END")
    blocks: list[bytes] = []
    try:
        text = data.decode(errors="replace")
    except Exception:
        return blocks
    for match in re.finditer(
        re.escape(begin.decode()) + r"(.*?)" + re.escape(end.decode()), text, re.DOTALL
    ):
        body = re.sub(r"\s+", "", re.sub(r"[^A-Za-z0-9+/=\n]", "", match.group(1)))
        if len(body) < 100:
            continue
        wrapped = "\n".join(body[i : i + 64] for i in range(0, len(body), 64))
        blocks.append(begin + b"\n" + wrapped.encode() + b"\n" + end + b"\n")
    return blocks


def extract_pem_key_blocks(data: bytes) -> list[bytes]:
    blocks: list[bytes] = []
    seen: set[str] = set()
    for marker in KEY_PATTERNS:
        for block in extract_pem_blocks(data, marker):
            digest = hashlib.md5(block).hexdigest()
            if digest in seen:
                continue
            seen.add(digest)
            blocks.append(block)
    return blocks


def extract_pem_blocks_from_text(text: str) -> list[bytes]:
    blocks: list[bytes] = []
    begin = "-----BEGIN CERTIFICATE-----"
    end = "-----END CERTIFICATE-----"
    for match in re.finditer(re.escape(begin) + r"(.*?)" + re.escape(end), text, re.DOTALL):
        body = re.sub(r"\s+", "", re.sub(r"[^A-Za-z0-9+/=\n]", "", match.group(1)))
        if len(body) < 100:
            continue
        wrapped = "\n".join(body[i : i + 64] for i in range(0, len(body), 64))
        blocks.append((begin + "\n" + wrapped + "\n" + end + "\n").encode())
    return blocks


def looks_like_base64_only(data: bytes) -> bool:
    if not data or len(data) < 80:
        return False
    if CERT_BEGIN in data or b"-----BEGIN" in data:
        return False
    try:
        text = data.decode("ascii", errors="strict").strip()
    except UnicodeDecodeError:
        text = re.sub(r"\s+", "", data.decode("utf-8", errors="ignore"))
    else:
        text = re.sub(r"\s+", "", text)
    if len(text) < 80:
        return False
    return bool(re.fullmatch(r"[A-Za-z0-9+/=]+", text))


def decode_base64_payload(data: bytes) -> bytes:
    text = re.sub(r"\s+", "", data.decode("utf-8", errors="ignore"))
    return base64.b64decode(text, validate=False)


def looks_like_email_bytes(data: bytes) -> bool:
    if not data:
        return False
    head = data[:8192]
    if b"\n" not in head and b"\r" not in head:
        return False
    hits = sum(1 for marker in EMAIL_HEADER_MARKERS if marker in head)
    return hits >= 2


def looks_like_docx(path: Path) -> bool:
    if path.suffix.lower() == ".docx":
        return True
    try:
        sample = _read_head(path, 4)
    except OSError:
        return False
    if sample[:2] != b"PK":
        return False
    try:
        with zipfile.ZipFile(path, "r") as zf:
            return "word/document.xml" in zf.namelist()
    except zipfile.BadZipFile:
        return False


def looks_like_zip(path: Path) -> bool:
    if path.suffix.lower() == ".zip":
        return True
    try:
        sample = _read_head(path, 4)
    except OSError:
        return False
    if sample[:2] != b"PK":
        return False
    try:
        with zipfile.ZipFile(path, "r") as zf:
            zf.namelist()
        return True
    except zipfile.BadZipFile:
        return False


def looks_like_7z(path: Path) -> bool:
    if path.suffix.lower() == ".7z":
        return True
    try:
        return _read_head(path, 6) == b"7z\xbc\xaf\x27\x1c"
    except OSError:
        return False


def load_text_from_docx(path: Path) -> str:
    parts: list[str] = []
    try:
        with zipfile.ZipFile(path, "r") as zf:
            if "word/document.xml" not in zf.namelist():
                return ""
            if zf.getinfo("word/document.xml").file_size > MAX_DOCX_XML_BYTES:
                return ""
            root = ET.fromstring(zf.read("word/document.xml"))
    except (OSError, zipfile.BadZipFile, ET.ParseError, KeyError):
        return ""
    for node in root.iter(f"{DOCX_W_NS}t"):
        if node.text:
            parts.append(node.text)
        if node.tail:
            parts.append(node.tail)
    return "\n".join(parts)


def load_certs_from_docx(path: Path) -> list[ParsedCert]:
    text = load_text_from_docx(path)
    if not text.strip():
        return []
    return load_certs_from_text(text, str(path))


def _check_member_name(name: str, dest: Path) -> None:
    """Reject absolute paths, drive letters, NULs and `..` escapes."""
    normalized = name.replace("\\", "/")
    if (
        not normalized
        or "\x00" in normalized
        or normalized.startswith("/")
        or re.match(r"^[A-Za-z]:", normalized)
        or ".." in normalized.split("/")
    ):
        raise UnsafeArchiveError(f"unsafe path in archive: {name!r}")
    if not is_within(dest, dest / normalized):
        raise UnsafeArchiveError(f"archive member escapes target folder: {name!r}")


def _check_archive_budget(count: int, sizes: Iterable[int]) -> None:
    total = 0
    if count > MAX_ARCHIVE_MEMBERS:
        raise UnsafeArchiveError(f"archive has too many entries ({count} > {MAX_ARCHIVE_MEMBERS})")
    for size in sizes:
        if size > MAX_ARCHIVE_MEMBER_BYTES:
            raise UnsafeArchiveError("archive contains an oversized file")
        total += size
        if total > MAX_ARCHIVE_TOTAL_BYTES:
            raise UnsafeArchiveError("archive expands beyond the allowed total size")


def _extract_zip_safely(path: Path, dest: Path) -> None:
    with zipfile.ZipFile(path, "r") as zf:
        infos = zf.infolist()
        _check_archive_budget(len(infos), (i.file_size for i in infos))
        for info in infos:
            _check_member_name(info.filename, dest)
            # Unix symlink entries (mode 0o120000) must never be materialised.
            if (info.external_attr >> 16) & 0o170000 == 0o120000:
                raise UnsafeArchiveError(f"symlink entry in archive: {info.filename!r}")
        zf.extractall(dest)


def _extract_7z_safely(path: Path, dest: Path) -> None:
    import py7zr

    def _size(entry) -> int:
        value = getattr(entry, "uncompressed", 0) or 0
        if isinstance(value, (list, tuple)):
            value = sum(value)
        return int(value)

    with py7zr.SevenZipFile(path, mode="r") as archive:
        # `files` (ArchiveFile) knows about links; `list()` (FileInfo) does not.
        entries = list(getattr(archive, "files", None) or archive.list())
        _check_archive_budget(len(entries), (_size(e) for e in entries))
        for entry in entries:
            _check_member_name(entry.filename, dest)
            if (
                getattr(entry, "is_symlink", False)
                or getattr(entry, "is_junction", False)
                or getattr(entry, "is_socket", False)
            ):
                raise UnsafeArchiveError(f"link entry in archive: {entry.filename!r}")
    # py7zr consumes the stream on list()/read, so reopen to extract.
    with py7zr.SevenZipFile(path, mode="r") as archive:
        archive.extractall(path=dest)


def extract_archive(path: Path, dest: Path) -> list[Path]:
    """Extract a customer-supplied .zip/.7z, refusing traversal, links and zip bombs."""
    dest.mkdir(parents=True, exist_ok=True)
    extracted: list[Path] = []
    is_zip = path.suffix.lower() == ".zip" or looks_like_zip(path)
    is_7z = path.suffix.lower() == ".7z" or looks_like_7z(path)
    if is_zip and not is_7z:
        _extract_zip_safely(path, dest)
        extracted = [p for p in dest.rglob("*") if p.is_file() and not p.is_symlink()]
    elif is_7z:
        try:
            import py7zr  # noqa: F401
        except ImportError:
            print("  [warn] py7zr not installed; cannot extract .7z archives")
            return extracted
        _extract_7z_safely(path, dest)
        extracted = [p for p in dest.rglob("*") if p.is_file() and not p.is_symlink()]
    return extracted


def vendor_leaf_score(path: Path, cert: x509.Certificate) -> int:
    score = 0
    name = path.name.lower()
    for hint in VENDOR_LEAF_NAME_HINTS:
        if hint in name:
            score += 2
    for hint in VENDOR_CHAIN_NAME_HINTS:
        if hint in name:
            score -= 3
    if has_server_auth(cert):
        score += 5
    if not is_ca(cert):
        score += 3
    if is_self_signed(cert):
        score -= 10
    cn = (cert_cn(cert) or "").lower()
    if cn and not is_ca(cert):
        score += 2
    return score


def is_probably_cert_content(data: bytes) -> bool:
    if not data:
        return False
    if CERT_BEGIN in data or b"-----BEGIN CERTIFICATE-----" in data:
        return True
    if len(data) > 200:
        try:
            x509.load_der_x509_certificate(data)
            return True
        except ValueError:
            pass
    if looks_like_base64_only(data):
        try:
            decoded = decode_base64_payload(data)
        except Exception:
            return False
        if CERT_BEGIN in decoded:
            return True
        if len(decoded) > 200:
            try:
                x509.load_der_x509_certificate(decoded)
                return True
            except ValueError:
                pass
    return False


def should_scan_file(path: Path) -> bool:
    if path.name in SKIP_FILE_NAMES or path.name.startswith("."):
        return False
    if any(part == "__MACOSX" for part in path.parts):
        return False
    ext = path.suffix.lower()
    if ext in CERT_FILE_EXTENSIONS or ext in ARCHIVE_EXTENSIONS or ext == ".key":
        return True
    try:
        sample = _read_head(path)
    except OSError:
        return False
    if any(pattern in sample for pattern in KEY_PATTERNS):
        return True
    if looks_like_email_bytes(sample):
        return True
    if is_probably_cert_content(sample):
        return True
    if sample[:2] == b"PK":
        return True
    if sample[:6] == b"7z\xbc\xaf\x27\x1c":
        return True
    return False


def load_certs_from_bytes(data: bytes, source: Path, *, _allow_b64_retry: bool = True) -> list[ParsedCert]:
    results: list[ParsedCert] = []
    for block in extract_pem_blocks(data, CERT_BEGIN):
        try:
            cert = x509.load_pem_x509_certificate(block)
            results.append(ParsedCert(cert=cert, source=source, pem=block))
        except ValueError:
            pass
    if not results:
        try:
            text = data.decode("utf-8", errors="replace")
        except Exception:
            text = ""
        for block in extract_pem_blocks_from_text(text):
            try:
                cert = x509.load_pem_x509_certificate(block)
                results.append(ParsedCert(cert=cert, source=source, pem=block))
            except ValueError:
                pass
    if not results and _allow_b64_retry and looks_like_base64_only(data):
        try:
            decoded = decode_base64_payload(data)
            if decoded != data:
                results.extend(load_certs_from_bytes(decoded, source, _allow_b64_retry=False))
        except Exception:
            pass
    if not results and len(data) > 200:
        try:
            cert = x509.load_der_x509_certificate(data)
            results.append(
                ParsedCert(cert=cert, source=source, pem=cert.public_bytes(Encoding.PEM))
            )
        except ValueError:
            pass
    return results


def load_certs_from_text(text: str, source_name: str = "pasted") -> list[ParsedCert]:
    results: list[ParsedCert] = []
    source = Path(source_name)
    for block in extract_pem_blocks_from_text(text):
        try:
            cert = x509.load_pem_x509_certificate(block)
            results.append(ParsedCert(cert=cert, source=source, pem=block))
        except ValueError:
            pass
    return results


def load_certs_from_eml(eml_path: Path) -> list[ParsedCert]:
    results: list[ParsedCert] = []
    try:
        raw = eml_path.read_bytes()
        msg = email.message_from_bytes(raw)
        body_text = ""
        if msg.is_multipart():
            for part in msg.walk():
                content_type = part.get_content_type()
                if content_type == "text/plain":
                    payload = part.get_payload(decode=True)
                    if payload:
                        try:
                            body_text = payload.decode("utf-8", errors="replace")
                        except Exception:
                            body_text = payload.decode("latin-1", errors="replace")
                        break
                elif content_type == "text/html" and not body_text:
                    payload = part.get_payload(decode=True)
                    if payload:
                        try:
                            body_text = payload.decode("utf-8", errors="replace")
                        except Exception:
                            body_text = payload.decode("latin-1", errors="replace")
        else:
            payload = msg.get_payload(decode=True)
            if payload:
                try:
                    body_text = payload.decode("utf-8", errors="replace")
                except Exception:
                    body_text = payload.decode("latin-1", errors="replace")
        for block in extract_pem_blocks_from_text(body_text):
            try:
                cert = x509.load_pem_x509_certificate(block)
                results.append(ParsedCert(cert=cert, source=eml_path, pem=block))
            except ValueError:
                pass
    except Exception:
        pass
    return results


def load_certs_from_p7b(data: bytes, source: Path) -> list[ParsedCert]:
    results: list[ParsedCert] = []
    try:
        from cryptography.hazmat.primitives.serialization import pkcs7

        certs = pkcs7.load_pem_pkcs7_certificates(data)
        for cert in certs:
            results.append(ParsedCert(cert=cert, source=source, pem=cert.public_bytes(Encoding.PEM)))
    except Exception:
        try:
            from cryptography.hazmat.primitives.serialization import pkcs7

            certs = pkcs7.load_der_pkcs7_certificates(data)
            for cert in certs:
                results.append(
                    ParsedCert(cert=cert, source=source, pem=cert.public_bytes(Encoding.PEM))
                )
        except Exception:
            pass
    return results


def _to_password_bytes(password: bytes | str | None) -> bytes | None:
    if password is None or password == "" or password == b"":
        return None
    return password.encode("utf-8") if isinstance(password, str) else password


def load_private_key(data: bytes, password: bytes | str | None = None):
    """Load a PEM/DER private key. Raises ValueError (EncryptedKeyError for
    passphrase-protected keys) instead of leaking library-specific exceptions.

    * A passphrase given for a key that is not encrypted is simply ignored.
    * An encrypted key that fails to load *with* a passphrase is reported as a wrong
      passphrase whatever the library said: decrypting with a wrong passphrase
      occasionally yields valid-looking padding, and the error then surfaces as a parse
      failure rather than "bad decrypt" (roughly 1 attempt in 256).
    """
    pwd = _to_password_bytes(password)
    looks_encrypted = b"ENCRYPTED" in data[:8192]  # PKCS#8 header or "Proc-Type: 4,ENCRYPTED"
    wants_password = False

    def attempt(loader, payload):
        nonlocal wants_password
        try:
            return loader(payload, password=pwd)
        except TypeError:
            if pwd is None:
                wants_password = True  # "Password was not given but private key is encrypted"
                return None
            # "Password was given but private key is not encrypted": it needs no password.
            try:
                return loader(payload, password=None)
            except TypeError:
                wants_password = True
            except ValueError:
                pass
        except ValueError:
            pass
        return None

    for loader in (serialization.load_pem_private_key, serialization.load_der_private_key):
        key = attempt(loader, data)
        if key is not None:
            return key
    for block in extract_pem_key_blocks(data):
        key = attempt(serialization.load_pem_private_key, block)
        if key is not None:
            return key
    if looks_encrypted or wants_password:
        if pwd is None:
            raise EncryptedKeyError(
                "Private key is passphrase-protected; supply --key-password "
                "(or set SSL_KEY_PASSWORD)"
            )
        raise EncryptedKeyError("Private key passphrase is incorrect")
    raise ValueError("Could not load private key")


def looks_like_key(path: Path) -> bool:
    if path.suffix.lower() in {".key", ".pem"} and any(
        x in path.name.lower() for x in ("key", "private")
    ):
        return True
    try:
        data = _read_head(path)
    except OSError:
        return False
    if any(pattern in data for pattern in KEY_PATTERNS):
        return True
    return bool(extract_pem_key_blocks(data))


def looks_like_pkcs12(path: Path) -> bool:
    return path.suffix.lower() in {".p12", ".pfx"}


def looks_like_p7b(path: Path) -> bool:
    return path.suffix.lower() in {".p7b", ".p7c"}


def looks_like_eml(path: Path) -> bool:
    if path.suffix.lower() == ".eml":
        return True
    try:
        return looks_like_email_bytes(_read_head(path))
    except OSError:
        return False


def looks_like_text(path: Path) -> bool:
    return path.suffix.lower() == ".txt"


def collect_input_files(inputs: list[Path]) -> list[Path]:
    files: list[Path] = []
    for inp in inputs:
        if inp.is_dir():
            files.extend(
                sorted(p for p in inp.rglob("*") if p.is_file() and should_scan_file(p))
            )
        elif inp.is_file() and should_scan_file(inp):
            files.append(inp)
    return files


def _merge_parsed(
    target_certs: list[ParsedCert],
    target_keys: list[tuple[Path, Any]],
    seen: set[str],
    new_certs: list[ParsedCert],
    new_keys: list[tuple[Path, Any]],
) -> None:
    for key_path, key in new_keys:
        target_keys.append((key_path, key))
    for pc in new_certs:
        fp = cert_fingerprint_sha256(pc.cert)
        if fp in seen:
            continue
        seen.add(fp)
        target_certs.append(pc)


def _parse_file_content(
    path: Path,
    data: bytes,
    p12_password: str | None,
    key_password: str | None = None,
) -> tuple[list[ParsedCert], list[tuple[Path, Any]]]:
    certs: list[ParsedCert] = []
    keys: list[tuple[Path, Any]] = []

    if looks_like_eml(path) or looks_like_email_bytes(data[:8192]):
        certs.extend(load_certs_from_eml(path))
        return certs, keys

    if looks_like_docx(path):
        certs.extend(load_certs_from_docx(path))
        return certs, keys

    if looks_like_pkcs12(path):
        pwd = (p12_password or "").encode() or None
        key, cert, extras = pkcs12.load_key_and_certificates(data, pwd)
        if key:
            keys.append((path, key))
        for c in filter(None, [cert, *(extras or [])]):
            certs.append(ParsedCert(cert=c, source=path, pem=c.public_bytes(Encoding.PEM)))
        return certs, keys

    if looks_like_p7b(path):
        certs.extend(load_certs_from_p7b(data, path))
        return certs, keys

    if looks_like_key(path) or any(p in data for p in KEY_PATTERNS):
        try:
            keys.append((path, load_private_key(data, key_password)))
        except EncryptedKeyError as exc:
            print(f"  [warn] {path.name}: {exc}")
        except ValueError:
            pass

    certs.extend(load_certs_from_bytes(data, path))
    return certs, keys


def parse_any_input(
    path: Path,
    p12_password: str | None = None,
    seen: set[str] | None = None,
    temp_dirs: list[Path] | None = None,
    _depth: int = 0,
    key_password: str | None = None,
) -> tuple[list[ParsedCert], list[tuple[Path, Any]]]:
    if seen is None:
        seen = set()
    if temp_dirs is None:
        temp_dirs = []

    all_certs: list[ParsedCert] = []
    all_keys: list[tuple[Path, Any]] = []

    if _depth > _PARSE_MAX_DEPTH:
        return all_certs, all_keys

    if not path.exists():
        return all_certs, all_keys

    if path.is_dir():
        for child in sorted(path.rglob("*")):
            if child.is_file() and not child.is_symlink() and should_scan_file(child):
                # One unreadable/hostile file must not abort the whole folder scan.
                try:
                    sub_certs, sub_keys = parse_any_input(
                        child, p12_password, seen, temp_dirs, _depth + 1, key_password
                    )
                except Exception as exc:
                    print(f"  [warn] Skipped {child.name}: {exc}")
                    continue
                # The nested call already deduplicated through the shared `seen`
                # set; merging again would drop every cert it just found.
                all_certs.extend(sub_certs)
                all_keys.extend(sub_keys)
        return all_certs, all_keys

    if not should_scan_file(path):
        return all_certs, all_keys

    if (
        path.suffix.lower() in ARCHIVE_EXTENSIONS
        or looks_like_zip(path)
        or looks_like_7z(path)
    ):
        tmp = Path(tempfile.mkdtemp(prefix="ssl-cert-tool-"))
        temp_dirs.append(tmp)
        for member in extract_archive(path, tmp):
            if member.is_file() and should_scan_file(member):
                try:
                    sub_certs, sub_keys = parse_any_input(
                        member, p12_password, seen, temp_dirs, _depth + 1, key_password
                    )
                except Exception as exc:
                    print(f"  [warn] Skipped {path.name}:{member.name}: {exc}")
                    continue
                all_certs.extend(sub_certs)
                all_keys.extend(sub_keys)
        return all_certs, all_keys

    try:
        size = path.stat().st_size
        if size > MAX_PARSE_FILE_BYTES:
            print(f"  [warn] Skipped {path.name}: file too large ({size} bytes)")
            return all_certs, all_keys
        data = path.read_bytes()
    except OSError as exc:
        print(f"  [warn] Skipped {path.name}: {exc}")
        return all_certs, all_keys

    sub_certs, sub_keys = _parse_file_content(path, data, p12_password, key_password)
    _merge_parsed(all_certs, all_keys, seen, sub_certs, sub_keys)
    return all_certs, all_keys


def parse_all_inputs(
    files: list[Path],
    p12_password: str | None = None,
    key_password: str | None = None,
):
    all_certs: list[ParsedCert] = []
    keys: list[tuple[Path, Any]] = []
    seen: set[str] = set()
    temp_dirs: list[Path] = []
    try:
        for path in files:
            try:
                sub_certs, sub_keys = parse_any_input(
                    path, p12_password, seen, temp_dirs, key_password=key_password
                )
                all_certs.extend(sub_certs)
                keys.extend(sub_keys)
            except Exception as exc:
                print(f"  [warn] Skipped {path.name}: {exc}")
    finally:
        for tmp in temp_dirs:
            shutil.rmtree(tmp, ignore_errors=True)
    return all_certs, keys


def build_chain(leaf: x509.Certificate, pool: list[x509.Certificate]) -> list[x509.Certificate]:
    chain, current = [leaf], leaf
    for _ in range(10):
        if current.issuer == current.subject:
            break
        nxt = next((c for c in pool if c.subject == current.issuer), None)
        if nxt is None or nxt in chain:
            break
        chain.append(nxt)
        current = nxt
    return chain


def classify_certs(certs: list[ParsedCert], domain_hint: str | None = None):
    if not certs:
        return None, [], None
    leaf_candidates = [pc for pc in certs if not is_self_signed(pc.cert) and not is_ca(pc.cert)]
    ca_candidates = [pc for pc in certs if is_ca(pc.cert) and not is_self_signed(pc.cert)]
    leaf = None
    if domain_hint:
        hint = domain_hint.lower().lstrip("*.")
        leaf = next(
            (pc for pc in leaf_candidates if hint in (cert_cn(pc.cert) or "").lower()),
            None,
        )
    if leaf is None and leaf_candidates:
        leaf_candidates = sorted(
            leaf_candidates,
            key=lambda pc: vendor_leaf_score(pc.source, pc.cert),
            reverse=True,
        )
        leaf = leaf_candidates[0]
    intermediates, root = [], None
    if leaf:
        chain = build_chain(leaf.cert, [c.cert for c in certs])
        for c in chain[1:]:
            for pc in certs:
                if cert_fingerprint_sha256(pc.cert) != cert_fingerprint_sha256(c):
                    continue
                if is_self_signed(pc.cert):
                    root = pc
                elif is_ca(pc.cert):
                    intermediates.append(pc)
    if not intermediates:
        intermediates = ca_candidates
    if root is None:
        roots = [pc for pc in certs if is_self_signed(pc.cert)]
        root = roots[0] if roots else None
    return leaf, intermediates, root


def cert_role_label(pc: ParsedCert, leaf: ParsedCert | None) -> str:
    if leaf and cert_fingerprint_sha256(pc.cert) == cert_fingerprint_sha256(leaf.cert):
        return "leaf/server"
    if is_self_signed(pc.cert):
        return "root"
    if is_ca(pc.cert):
        return "intermediate/CA"
    return "certificate"


def infer_domain(leaf: ParsedCert | None, hint: str | None) -> str:
    if hint:
        return hint.strip()
    if leaf and cert_cn(leaf.cert):
        return cert_cn(leaf.cert).lstrip("*.")
    raise ValueError("Could not determine domain. Pass --domain explicitly.")


def validate_key_cert(private_key, leaf: ParsedCert) -> dict:
    key_pem = private_key.private_bytes(
        Encoding.PEM, PrivateFormat.PKCS8, serialization.NoEncryption()
    )
    cert_der = leaf.cert.public_bytes(Encoding.DER)
    return {
        "key_cert_match": public_numbers_match(private_key, leaf.cert),
        "key_md5": md5_bytes(key_pem),
        "cert_md5": md5_bytes(cert_der),
        "cert_fingerprint_md5": cert_fingerprint_md5(leaf.cert),
        "subject": cert_subject(leaf.cert),
        "not_before": str(leaf.cert.not_valid_before_utc),
        "not_after": str(leaf.cert.not_valid_after_utc),
    }


def unencrypted_key_pem(private_key) -> bytes:
    """PEM for deployment. RSA/EC keep the traditional ("BEGIN RSA/EC PRIVATE KEY")
    layout legacy Ameyo/Asterisk builds expect; other key types (Ed25519, ...)
    cannot be written that way and use PKCS#8."""
    fmt = (
        PrivateFormat.TraditionalOpenSSL
        if isinstance(private_key, (rsa.RSAPrivateKey, ec.EllipticCurvePrivateKey))
        else PrivateFormat.PKCS8
    )
    return private_key.private_bytes(Encoding.PEM, fmt, serialization.NoEncryption())


def build_ameyo_asterisk_pem_bytes(
    private_key,
    leaf: x509.Certificate,
    intermediates: Iterable[x509.Certificate],
    root: x509.Certificate | None = None,
) -> bytes:
    """Build Ameyo/Asterisk combined PEM: private key first, then full cert chain.

    Order matches production Asterisk http.conf when tlscertfile points at asterisk.pem:
      1. PRIVATE KEY
      2. leaf/server certificate
      3. intermediate CA certificate(s)
      4. root CA certificate (when available)
    """
    key_pem = unencrypted_key_pem(private_key)
    chain = [leaf, *intermediates]
    if root is not None:
        chain.append(root)
    cert_pem = b"".join(cert.public_bytes(Encoding.PEM) for cert in chain)
    return key_pem + cert_pem


try:
    from ssl_cert_tool.paths import bundled_roots_dir

    BUNDLED_ROOTS_DIR = bundled_roots_dir()
except Exception:
    BUNDLED_ROOTS_DIR = Path(__file__).resolve().parent / "bundled_roots"


def load_bundled_root_certs() -> list[x509.Certificate]:
    roots: list[x509.Certificate] = []
    if not BUNDLED_ROOTS_DIR.is_dir():
        return roots
    for pattern in ("*.pem", "*.crt"):
        for path in sorted(BUNDLED_ROOTS_DIR.glob(pattern)):
            try:
                roots.append(x509.load_pem_x509_certificate(path.read_bytes()))
            except ValueError:
                continue
    return roots


def resolve_ca_root_cert(
    intermediates: list[ParsedCert],
    root: ParsedCert | None,
) -> x509.Certificate | None:
    """Return root CA for legacy ca-bundle (intermediate + root)."""
    if root is not None:
        return root.cert
    if not intermediates:
        return None
    pool = load_bundled_root_certs()
    current = intermediates[-1].cert
    for _ in range(5):
        if current.issuer == current.subject:
            return current
        nxt = next((c for c in pool if c.subject == current.issuer), None)
        if nxt is None:
            break
        if nxt.issuer == nxt.subject:
            return nxt
        current = nxt
    return None


def build_ca_bundle_certs(
    intermediates: list[ParsedCert],
    root: ParsedCert | None,
) -> list[x509.Certificate]:
    """Legacy Ameyo ca-bundle: intermediate CA(s) + root (no leaf)."""
    chain = [pc.cert for pc in intermediates]
    resolved_root = resolve_ca_root_cert(intermediates, root)
    if resolved_root is not None:
        root_fp = cert_fingerprint_sha256(resolved_root)
        if not any(cert_fingerprint_sha256(c) == root_fp for c in chain):
            chain.append(resolved_root)
    return chain


def validate_asterisk_pem_format(pem_data: bytes, private_key, leaf: x509.Certificate) -> dict:
    """Validate Ameyo Asterisk combined PEM structure and content."""
    text = pem_data.decode(errors="replace")
    key_markers = ("BEGIN PRIVATE KEY", "BEGIN RSA PRIVATE KEY", "BEGIN EC PRIVATE KEY")
    has_key = any(marker in text for marker in key_markers)
    cert_count = text.count("BEGIN CERTIFICATE")
    key_pos = min((text.find(marker) for marker in key_markers if marker in text), default=-1)
    cert_pos = text.find("BEGIN CERTIFICATE")
    key_first = has_key and cert_pos >= 0 and key_pos >= 0 and key_pos < cert_pos
    return {
        "asterisk_pem_has_key": has_key,
        "asterisk_pem_key_first": key_first,
        "asterisk_pem_cert_count": cert_count,
        "asterisk_pem_key_matches_leaf": has_key and public_numbers_match(private_key, leaf),
    }


KEYTOOL_PASS_ENV = "SSL_AUTO_KEYTOOL_PASS"
KEYTOOL_TIMEOUT_SECONDS = 120


def keytool_env(password: str) -> dict[str, str]:
    """Environment for a keytool child process that carries the keystore password.

    Passing `-storepass <pw>` on the command line exposes the password to every
    local user via the process list; `-storepass:env VAR` keeps it out of argv.
    """
    env = dict(os.environ)
    env[KEYTOOL_PASS_ENV] = password
    return env


def _resolve_keytool(keytool: Path | str) -> str | None:
    candidate = Path(str(keytool))
    if candidate.is_file():
        return str(candidate)
    return shutil.which(str(keytool))


FORCE_BUILTIN_JKS_ENV = "SSL_AUTO_BUILTIN_JKS"


def _create_jks_builtin(p12_path: Path, jks_path: Path, store_pass: str) -> None:
    """Build the JKS from the PKCS#12 with the pure-Python writer (no JDK needed)."""
    p12 = pkcs12.load_pkcs12(Path(p12_path).read_bytes(), store_pass.encode("utf-8"))
    if p12.key is None or p12.cert is None:
        raise RuntimeError("the PKCS#12 keystore has no private key and certificate")
    alias = (p12.cert.friendly_name or b"server").decode("utf-8", errors="replace")
    chain = jks_store.order_chain(
        [p12.cert.certificate] + [c.certificate for c in p12.additional_certs]
    )
    entry = jks_store.key_entry(alias, p12.key, chain)
    jks_store.write_jks(jks_path, [entry], store_pass)
    # Read it straight back: the file must open with the password and hold the same key.
    back = jks_store.load_file(jks_path, store_pass)
    if len(back) != 1 or back[0].key_pkcs8 != entry.key_pkcs8:
        jks_path.unlink(missing_ok=True)
        raise RuntimeError("built-in JKS writer failed its read-back check")


def create_jks(p12_path: Path, jks_path: Path, keytool: Path, store_pass: str) -> str:
    """Create `jks_path` from a PKCS#12 file. Returns "keytool" or "builtin".

    Java's keytool is used when found; otherwise (or with SSL_AUTO_BUILTIN_JKS=1) the
    built-in pure-Python writer produces an equivalent keystore. A keytool that exists
    but fails is reported as an error, not silently replaced.
    """
    # Java keytool rejects store passwords shorter than 6 characters.
    if len(store_pass) < 6:
        raise ValueError(
            f"keystore password must be at least 6 characters "
            f"(got {len(store_pass)}; Java keytool requirement for JKS)"
        )
    resolved = None if os.environ.get(FORCE_BUILTIN_JKS_ENV) else _resolve_keytool(keytool)
    if resolved is None:
        _create_jks_builtin(p12_path, jks_path, store_pass)
        return "builtin"
    # Build next to the target and swap in only on success, so a failed run
    # never destroys the keystore that is already there.
    tmp_jks = jks_path.with_name(f".{jks_path.name}.{os.getpid()}.tmp")
    if tmp_jks.exists():
        tmp_jks.unlink()
    cmd = [
        resolved,
        "-importkeystore",
        "-srckeystore",
        str(p12_path),
        "-srcstoretype",
        "PKCS12",
        "-srcstorepass:env",
        KEYTOOL_PASS_ENV,
        "-destkeystore",
        str(tmp_jks),
        "-deststoretype",
        "JKS",
        "-deststorepass:env",
        KEYTOOL_PASS_ENV,
        "-noprompt",
    ]
    try:
        result = subprocess.run(
            cmd,
            capture_output=True,
            env=keytool_env(store_pass),
            timeout=KEYTOOL_TIMEOUT_SECONDS,
        )
    except subprocess.TimeoutExpired as exc:
        tmp_jks.unlink(missing_ok=True)
        raise RuntimeError(f"keytool timed out after {KEYTOOL_TIMEOUT_SECONDS}s") from exc
    if result.returncode != 0:
        tmp_jks.unlink(missing_ok=True)
        err = (result.stderr or b"").decode("utf-8", errors="replace").strip()
        out = (result.stdout or b"").decode("utf-8", errors="replace").strip()
        detail = err or out or f"keytool exited with code {result.returncode}"
        raise RuntimeError(detail)
    if not tmp_jks.is_file():
        raise RuntimeError("keytool reported success but produced no keystore")
    os.replace(tmp_jks, jks_path)
    return "keytool"


def build_outputs(
    domain,
    output_dir,
    leaf,
    intermediates,
    root,
    private_key,
    store_pass="changeit",
    alias="ameyo-server",
    keytool=KEYTOOL_DEFAULT,
):
    output_dir.mkdir(parents=True, exist_ok=True, mode=0o700)
    result = BuildResult(domain=domain, output_dir=output_dir)
    main_crt = output_dir / f"main_{domain}.crt"
    write_pem_cert(leaf.cert, main_crt)
    result.files.append(main_crt)
    if intermediates:
        p = output_dir / f"intermediate_{domain}.crt"
        write_pem_certs([pc.cert for pc in intermediates], p)
        result.files.append(p)
    if root:
        p = output_dir / f"root_{domain}.crt"
        write_pem_cert(root.cert, p)
        result.files.append(p)
    chain = [leaf.cert] + [pc.cert for pc in intermediates] + ([root.cert] if root else [])
    pem_path = output_dir / f"{domain}.pem"
    write_pem_certs(chain, pem_path)
    result.files.append(pem_path)
    ca_chain = [pc.cert for pc in intermediates] + ([root.cert] if root else [])
    if ca_chain:
        p = output_dir / "crm-ca.crt"
        write_pem_certs(ca_chain, p)
        result.files.append(p)
        chain_copy = output_dir / "chain.crt"
        shutil.copy2(p, chain_copy)
        result.files.append(chain_copy)
    ca_bundle_certs = build_ca_bundle_certs(intermediates, root)
    if ca_bundle_certs:
        ca_bundle_path = output_dir / f"{domain}.ca-bundle"
        write_pem_certs(ca_bundle_certs, ca_bundle_path)
        result.files.append(ca_bundle_path)
        if len(ca_bundle_certs) < 2:
            result.warnings.append(
                f"{domain}.ca-bundle has only {len(ca_bundle_certs)} certificate(s); "
                "legacy Ameyo format expects intermediate + root."
            )
    key_path = output_dir / f"{domain}.key"
    key_pem = unencrypted_key_pem(private_key)
    write_private(key_path, key_pem)
    result.files.append(key_path)
    p12_path = output_dir / "keystore.p12"
    cas = [pc.cert for pc in intermediates] + ([root.cert] if root else [])
    write_private(
        p12_path,
        pkcs12.serialize_key_and_certificates(
            name=alias.encode(),
            key=private_key,
            cert=leaf.cert,
            cas=cas or None,
            encryption_algorithm=BestAvailableEncryption(store_pass.encode()),
        ),
    )
    result.files.append(p12_path)
    jks_path = output_dir / f"{domain}.jks"
    try:
        method = create_jks(p12_path, jks_path, keytool, store_pass)
        restrict_to_owner(jks_path)
        result.files.append(jks_path)
        if method == "builtin":
            result.warnings.append(
                f"{jks_path.name} was built with the built-in JKS writer (keytool not found). "
                "It is a standard JKS; confirm it opens on the target with: "
                f"keytool -list -keystore {jks_path.name}"
            )
    except (FileNotFoundError, RuntimeError, ValueError) as exc:
        result.warnings.append(f"JKS not created: {exc}")
    p = output_dir / f"asterisk_{domain}.crt"
    write_pem_certs(chain, p)
    result.files.append(p)
    asterisk_pem_bytes = build_ameyo_asterisk_pem_bytes(
        private_key,
        leaf.cert,
        [pc.cert for pc in intermediates],
        resolve_ca_root_cert(intermediates, root),
    )
    for name in (f"asterisk_{domain}.pem", "asterisk.pem"):
        p = output_dir / name
        write_private(p, asterisk_pem_bytes)  # contains the private key
        result.files.append(p)
    result.validation = validate_key_cert(private_key, leaf)
    result.validation.update(
        validate_asterisk_pem_format(asterisk_pem_bytes, private_key, leaf.cert)
    )
    if not result.validation.get("asterisk_pem_key_first"):
        result.warnings.append(
            "asterisk.pem must contain the private key before certificates (Ameyo/Asterisk format)."
        )
    if result.validation.get("asterisk_pem_cert_count", 0) < 2:
        result.warnings.append(
            "asterisk.pem has fewer than 2 certificates; include intermediate (and root if available)."
        )
    result.validation["output_md5"] = {f.name: md5_file(f) for f in result.files}
    return result


def get_cert_summary(cert: x509.Certificate) -> dict:
    return {
        "cn": cert_cn(cert) or "(no CN)",
        "subject": cert_subject(cert),
        "issuer": cert_issuer(cert),
        "issuer_cn": cert_issuer_cn(cert) or "(no issuer CN)",
        "not_before": str(cert.not_valid_before_utc),
        "not_after": str(cert.not_valid_after_utc),
        "is_ca": is_ca(cert),
        "is_self_signed": is_self_signed(cert),
        "fingerprint_md5": cert_fingerprint_md5(cert),
    }


def inspect_inputs(
    inputs: list[Path],
    key_path: Path | None = None,
    p12_password: str | None = None,
    domain_hint: str | None = None,
    key_password: str | None = None,
) -> InspectResult:
    result = InspectResult(inputs=list(inputs))
    files = collect_input_files(inputs)
    result.files_scanned = files
    certs, keys = parse_all_inputs(files, p12_password=p12_password, key_password=key_password)
    result.certs = certs
    result.keys = keys
    if key_path:
        if key_path.is_file():
            try:
                key_data = key_path.read_bytes()
                keys.append((key_path, load_private_key(key_data, key_password)))
                result.keys = keys
            except ValueError as exc:
                result.warnings.append(f"Could not load key from {key_path}: {exc}")
                result.notes.append(f"Could not load private key from {key_path.name}; check format and encryption.")
        else:
            result.warnings.append(f"Key file not found: {key_path}")
            result.notes.append("Private key path not found - please provide a valid file with --key.")

    leaf, intermediates, root = classify_certs(certs, domain_hint=domain_hint)
    result.leaf = leaf
    result.intermediates = intermediates
    result.root = root

    if not certs:
        result.warnings.append("No certificates found in inputs.")
        result.notes.append("No certificates found in the supplied inputs; verify archive contents and supported formats.")
    if not result.keys:
        result.warnings.append("No private keys found in inputs.")
        result.notes.append("Private key not found - please provide with --key.")
    if leaf is None and certs:
        result.warnings.append("Could not identify a leaf/server certificate.")
        result.notes.append("Could not identify a leaf/server certificate; try --domain with the target hostname.")

    if result.leaf and result.keys:
        matching = [
            kp for kp, key in result.keys if public_numbers_match(key, result.leaf.cert)
        ]
        if matching:
            domain = (domain_hint or cert_cn(result.leaf.cert) or "").lstrip("*.")
            if domain:
                result.notes.append(
                    f"Ready to generate Ameyo SSL artifacts for {domain} (matching key: {matching[0].name})."
                )
            else:
                result.notes.append(
                    f"Leaf and matching private key found ({matching[0].name}); ready to generate (use --domain if needed)."
                )
        elif not any(
            n.startswith("Private key not found") or n.startswith("Could not load private key")
            for n in result.notes
        ):
            result.notes.append("Private key(s) found but none match the selected leaf certificate.")

    # De-duplicate notes while preserving order
    seen: set[str] = set()
    deduped: list[str] = []
    for note in result.notes:
        if note in seen:
            continue
        seen.add(note)
        deduped.append(note)
    result.notes = deduped

    return result


def _inspect_cert_role_tag(pc: ParsedCert, leaf: ParsedCert | None) -> str:
    role = cert_role_label(pc, leaf)
    if role.startswith("leaf"):
        return "LEAF "
    if role == "root":
        return "ROOT "
    if "intermediate" in role:
        return "INTER"
    return "CERT "


def format_inspect_report(result: InspectResult, domain_hint: str | None = None) -> str:
    lines: list[str] = []
    lines.append("=== SSL Input Inspector ===")
    input_names = ", ".join(p.name for p in result.inputs)
    lines.append(f"Input: {input_names} (scanned {len(result.files_scanned)} files)")
    lines.append("Certificates found:")
    if not result.certs:
        lines.append("  (none)")
    else:
        for pc in result.certs:
            cn = cert_cn(pc.cert) or "(no CN)"
            expires = pc.cert.not_valid_after_utc.strftime("%Y-%m-%d")
            tag = _inspect_cert_role_tag(pc, result.leaf)
            lines.append(
                f"  [{tag}]  CN={cn}  Expires: {expires}  Source: {pc.source.name}"
            )
    lines.append("Private key:")
    if not result.keys:
        lines.append("  NOT FOUND - please provide with --key")
    else:
        for key_path, key in result.keys:
            if result.leaf:
                match = public_numbers_match(key, result.leaf.cert)
                suffix = "matches leaf" if match else "does NOT match leaf"
                lines.append(f"  {key_path.name} ({suffix})")
            else:
                lines.append(f"  {key_path.name}")
    lines.append("Recommendation:")
    if result.notes:
        for note in result.notes:
            lines.append(f"  {note}")
    else:
        lines.append("  Inspection complete; review certificates above.")
    return "\n".join(lines) + "\n"


# =============================================================================
# JKS INSPECTION AND COMPARISON FUNCTIONS
# =============================================================================

@dataclass
class JKSInfo:
    """Information extracted from a JKS keystore."""
    path: Path
    alias: str
    domain: str | None
    issuer: str | None
    issuer_cn: str | None
    subject: str | None
    valid_from: datetime | None
    valid_until: datetime | None
    is_expired: bool
    days_until_expiry: int
    key_type: str | None
    key_size: int | None
    chain: list[dict[str, str]]
    password_valid: bool
    error: str | None = None


@dataclass
class CertComparison:
    """Comparison between two certificates."""
    old_domain: str | None
    new_domain: str | None
    domain_match: bool
    old_alias: str | None
    new_alias: str | None
    alias_match: bool
    old_issuer: str | None
    new_issuer: str | None
    issuer_match: bool
    old_expires: datetime | None
    new_expires: datetime | None
    days_extended: int
    old_key_type: str | None
    new_key_type: str | None
    key_type_match: bool
    old_password_valid: bool
    new_password_valid: bool
    ready_for_renewal: bool


def check_cert_expiry(cert: x509.Certificate) -> tuple[bool, int]:
    """Return (is_expired, days_until_expiry). Negative days means already expired."""
    now = datetime.now(timezone.utc)
    expires = cert.not_valid_after_utc
    delta = expires - now
    days = delta.days
    is_expired = days < 0
    return is_expired, days


def get_key_info(cert: x509.Certificate) -> tuple[str, int]:
    """Extract key type and size from certificate."""
    pub = cert.public_key()
    if isinstance(pub, rsa.RSAPublicKey):
        return "RSA", pub.key_size
    if isinstance(pub, ec.EllipticCurvePublicKey):
        return f"EC ({pub.curve.name})", pub.key_size
    return "Unknown", 0


def _error_info(path: Path, message: str, password_valid: bool = False) -> JKSInfo:
    return JKSInfo(
        path=path, alias="", domain=None, issuer=None, issuer_cn=None,
        subject=None, valid_from=None, valid_until=None, is_expired=False,
        days_until_expiry=0, key_type=None, key_size=None, chain=[],
        password_valid=password_valid, error=message,
    )


def read_jks_info_builtin(jks_path: Path, password: str) -> JKSInfo:
    """Same result as read_jks_info, using the pure-Python reader (no keytool)."""
    try:
        entries = jks_store.load_file(jks_path, password)
    except jks_store.JKSError as exc:
        text = str(exc)
        if "password" in text or "tampered" in text:
            return _error_info(jks_path, "Invalid password")
        return _error_info(jks_path, text)
    except OSError as exc:
        return _error_info(jks_path, str(exc))
    if not entries:
        return _error_info(jks_path, "Keystore is empty", password_valid=True)
    entry = next((e for e in entries if e.is_key_entry), entries[0])
    leaf = entry.leaf
    key_type, key_size = get_key_info(leaf)
    is_expired, days = check_cert_expiry(leaf)
    domain = cert_cn(leaf)
    chain = []
    for i, cert in enumerate(entry.chain):
        role = "leaf" if i == 0 else "root" if is_self_signed(cert) else "intermediate"
        chain.append({"cn": cert_cn(cert) or f"Certificate {i + 1}", "role": role})
    return JKSInfo(
        path=jks_path,
        alias=entry.alias,
        domain=domain.lstrip("*.") if domain else None,
        issuer=cert_issuer(leaf),
        issuer_cn=cert_issuer_cn(leaf),
        subject=cert_subject(leaf),
        valid_from=leaf.not_valid_before_utc,
        valid_until=leaf.not_valid_after_utc,
        is_expired=is_expired,
        days_until_expiry=days,
        key_type=key_type.split(" ")[0],
        key_size=key_size,
        chain=chain,
        password_valid=True,
        error=None,
    )


def read_jks_info(jks_path: Path, password: str, keytool: Path | None = None) -> JKSInfo:
    """Extract alias, cert info from an existing JKS keystore.

    Uses keytool when available, otherwise the built-in pure-Python reader."""
    from ssl_cert_tool.platform import find_keytool

    if not jks_path.is_file():
        return _error_info(jks_path, f"File not found: {jks_path}")

    # The built-in reader is exact (dates, chain, key type) and independent of keytool's
    # locale-specific text. keytool is only needed for formats it cannot read (e.g. JCEKS).
    builtin = read_jks_info_builtin(jks_path, password)
    if builtin.error is None or builtin.error == "Invalid password":
        return builtin

    resolved = _resolve_keytool(keytool) if keytool is not None else None
    if resolved is None and keytool is None:
        found = find_keytool()
        resolved = str(found) if found else None
    if resolved is None or os.environ.get(FORCE_BUILTIN_JKS_ENV):
        return read_jks_info_builtin(jks_path, password)
    keytool = Path(resolved)

    cmd_list = [
        str(keytool), "-list", "-keystore", str(jks_path),
        "-storepass:env", KEYTOOL_PASS_ENV, "-v"
    ]
    try:
        result = subprocess.run(
            cmd_list,
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
            env=keytool_env(password),
            timeout=KEYTOOL_TIMEOUT_SECONDS,
        )
    except subprocess.TimeoutExpired:
        return JKSInfo(
            path=jks_path, alias="", domain=None, issuer=None, issuer_cn=None,
            subject=None, valid_from=None, valid_until=None, is_expired=False,
            days_until_expiry=0, key_type=None, key_size=None, chain=[],
            password_valid=False, error="keytool timed out"
        )

    if result.returncode != 0:
        if "password was incorrect" in result.stderr.lower() or "keystore was tampered" in result.stderr.lower():
            return JKSInfo(
                path=jks_path, alias="", domain=None, issuer=None, issuer_cn=None,
                subject=None, valid_from=None, valid_until=None, is_expired=False,
                days_until_expiry=0, key_type=None, key_size=None, chain=[],
                password_valid=False, error="Invalid password"
            )
        return JKSInfo(
            path=jks_path, alias="", domain=None, issuer=None, issuer_cn=None,
            subject=None, valid_from=None, valid_until=None, is_expired=False,
            days_until_expiry=0, key_type=None, key_size=None, chain=[],
            password_valid=False, error=result.stderr or "keytool error"
        )

    output = result.stdout
    alias = ""
    domain = None
    issuer = None
    issuer_cn = None
    subject = None
    valid_from = None
    valid_until = None
    key_type = None
    key_size = None
    chain: list[dict[str, str]] = []

    alias_match = re.search(r"Alias name:\s*(.+)", output)
    if alias_match:
        alias = alias_match.group(1).strip()

    owner_match = re.search(r"Owner:\s*(.+)", output)
    if owner_match:
        subject = owner_match.group(1).strip()
        cn_match = re.search(r"CN=([^,]+)", subject)
        if cn_match:
            domain = cn_match.group(1).strip().lstrip("*.")

    issuer_match = re.search(r"Issuer:\s*(.+)", output)
    if issuer_match:
        issuer = issuer_match.group(1).strip()
        cn_match = re.search(r"CN=([^,]+)", issuer)
        if cn_match:
            issuer_cn = cn_match.group(1).strip()

    valid_match = re.search(r"Valid from:\s*(.+?)\s+until:\s*(.+?)(?:\n|$)", output)
    if valid_match:
        try:
            from_str = valid_match.group(1).strip()
            until_str = valid_match.group(2).strip()
            for fmt in ["%a %b %d %H:%M:%S %Z %Y", "%Y-%m-%d %H:%M:%S"]:
                try:
                    valid_from = datetime.strptime(from_str, fmt)
                    if valid_from.tzinfo is None:
                        valid_from = valid_from.replace(tzinfo=timezone.utc)
                    break
                except ValueError:
                    continue
            for fmt in ["%a %b %d %H:%M:%S %Z %Y", "%Y-%m-%d %H:%M:%S"]:
                try:
                    valid_until = datetime.strptime(until_str, fmt)
                    if valid_until.tzinfo is None:
                        valid_until = valid_until.replace(tzinfo=timezone.utc)
                    break
                except ValueError:
                    continue
        except Exception:
            pass

    key_match = re.search(r"(\d+)[- ]?bit\s+(RSA|EC|DSA)", output, re.IGNORECASE)
    if key_match:
        key_size = int(key_match.group(1))
        key_type = key_match.group(2).upper()

    cert_blocks = re.findall(r"Certificate\[\d+\]:(.*?)(?=Certificate\[\d+\]:|$)", output, re.DOTALL)
    for i, block in enumerate(cert_blocks):
        cn_match = re.search(r"Owner:\s*.*?CN=([^,\n]+)", block)
        cn = cn_match.group(1).strip() if cn_match else f"Certificate {i+1}"
        role = "leaf" if i == 0 else "intermediate" if i < len(cert_blocks) - 1 else "root"
        chain.append({"cn": cn, "role": role})

    if not chain and subject:
        cn_match = re.search(r"CN=([^,]+)", subject)
        cn = cn_match.group(1).strip() if cn_match else "Certificate"
        chain.append({"cn": cn, "role": "leaf"})

    is_expired = False
    days_until_expiry = 0
    if valid_until:
        now = datetime.now(timezone.utc)
        if valid_until.tzinfo is None:
            valid_until = valid_until.replace(tzinfo=timezone.utc)
        delta = valid_until - now
        days_until_expiry = delta.days
        is_expired = days_until_expiry < 0

    return JKSInfo(
        path=jks_path,
        alias=alias,
        domain=domain,
        issuer=issuer,
        issuer_cn=issuer_cn,
        subject=subject,
        valid_from=valid_from,
        valid_until=valid_until,
        is_expired=is_expired,
        days_until_expiry=days_until_expiry,
        key_type=key_type,
        key_size=key_size,
        chain=chain,
        password_valid=True,
        error=None,
    )


def read_jks_info_from_p12(p12_path: Path, password: str) -> JKSInfo:
    """Extract cert info from PKCS12 file directly."""
    if not p12_path.is_file():
        return JKSInfo(
            path=p12_path, alias="", domain=None, issuer=None, issuer_cn=None,
            subject=None, valid_from=None, valid_until=None, is_expired=False,
            days_until_expiry=0, key_type=None, key_size=None, chain=[],
            password_valid=False, error=f"File not found: {p12_path}"
        )

    try:
        data = p12_path.read_bytes()
        pwd = password.encode() if password else None
        key, cert, extras = pkcs12.load_key_and_certificates(data, pwd)
    except Exception as e:
        return JKSInfo(
            path=p12_path, alias="", domain=None, issuer=None, issuer_cn=None,
            subject=None, valid_from=None, valid_until=None, is_expired=False,
            days_until_expiry=0, key_type=None, key_size=None, chain=[],
            password_valid=False, error=str(e)
        )

    if cert is None:
        return JKSInfo(
            path=p12_path, alias="", domain=None, issuer=None, issuer_cn=None,
            subject=None, valid_from=None, valid_until=None, is_expired=False,
            days_until_expiry=0, key_type=None, key_size=None, chain=[],
            password_valid=True, error="No certificate in PKCS12"
        )

    domain = cert_cn(cert)
    if domain:
        domain = domain.lstrip("*.")

    key_type_str, key_size_val = get_key_info(cert)
    is_expired, days = check_cert_expiry(cert)

    chain: list[dict[str, str]] = []
    chain.append({"cn": cert_cn(cert) or "leaf", "role": "leaf"})
    for i, extra in enumerate(extras or []):
        cn = cert_cn(extra) or f"Certificate {i+2}"
        role = "root" if is_self_signed(extra) else "intermediate"
        chain.append({"cn": cn, "role": role})

    return JKSInfo(
        path=p12_path,
        alias="",
        domain=domain,
        issuer=cert_issuer(cert),
        issuer_cn=cert_issuer_cn(cert),
        subject=cert_subject(cert),
        valid_from=cert.not_valid_before_utc,
        valid_until=cert.not_valid_after_utc,
        is_expired=is_expired,
        days_until_expiry=days,
        key_type=key_type_str,
        key_size=key_size_val,
        chain=chain,
        password_valid=True,
        error=None,
    )


def compare_certs(old_info: JKSInfo, new_info: JKSInfo) -> CertComparison:
    """Compare two JKS/cert infos and return differences."""
    days_extended = 0
    if old_info.valid_until and new_info.valid_until:
        delta = new_info.valid_until - old_info.valid_until
        days_extended = delta.days

    domain_match = (old_info.domain or "").lower() == (new_info.domain or "").lower()
    alias_match = (old_info.alias or "").lower() == (new_info.alias or "").lower()
    issuer_match = (old_info.issuer_cn or "").lower() == (new_info.issuer_cn or "").lower()
    key_type_match = (
        (old_info.key_type or "").upper() == (new_info.key_type or "").upper()
        and old_info.key_size == new_info.key_size
    )

    ready = (
        domain_match
        and old_info.password_valid
        and new_info.password_valid
        and not new_info.is_expired
    )

    return CertComparison(
        old_domain=old_info.domain,
        new_domain=new_info.domain,
        domain_match=domain_match,
        old_alias=old_info.alias,
        new_alias=new_info.alias,
        alias_match=alias_match,
        old_issuer=old_info.issuer_cn,
        new_issuer=new_info.issuer_cn,
        issuer_match=issuer_match,
        old_expires=old_info.valid_until,
        new_expires=new_info.valid_until,
        days_extended=days_extended,
        old_key_type=f"{old_info.key_type or 'Unknown'} {old_info.key_size or ''}-bit".strip(),
        new_key_type=f"{new_info.key_type or 'Unknown'} {new_info.key_size or ''}-bit".strip(),
        key_type_match=key_type_match,
        old_password_valid=old_info.password_valid,
        new_password_valid=new_info.password_valid,
        ready_for_renewal=ready,
    )


def format_jks_info(info: JKSInfo) -> str:
    """Format JKS info for display."""
    lines: list[str] = []
    lines.append("=== Current Certificate Details ===")
    lines.append(f"Keystore: {info.path}")
    lines.append(f"Alias: {info.alias or '(not found)'}")
    lines.append(f"Domain: {info.domain or '(not found)'}")
    lines.append(f"Issuer: {info.issuer_cn or info.issuer or '(not found)'}")

    if info.valid_from:
        lines.append(f"Valid from: {info.valid_from.strftime('%Y-%m-%d')}")

    if info.valid_until:
        expiry_str = info.valid_until.strftime("%Y-%m-%d")
        if info.is_expired:
            lines.append(f"Expires: {expiry_str}  [EXPIRED!]")
        elif info.days_until_expiry <= 30:
            lines.append(f"Expires: {expiry_str}  [Expires in {info.days_until_expiry} days]")
        else:
            lines.append(f"Expires: {expiry_str}  [{info.days_until_expiry} days remaining]")

    if info.key_type and info.key_size:
        lines.append(f"Key type: {info.key_type} {info.key_size}-bit")

    if info.chain:
        lines.append("")
        lines.append("Chain:")
        for i, cert_info in enumerate(info.chain, 1):
            role = f"({cert_info['role']})" if cert_info.get('role') else ""
            lines.append(f"  {i}. CN={cert_info['cn']} {role}")

    if info.error:
        lines.append("")
        lines.append(f"Error: {info.error}")

    return "\n".join(lines)


def format_cert_comparison(comp: CertComparison) -> str:
    """Format certificate comparison for display."""
    lines: list[str] = []
    lines.append("=== Certificate Comparison ===")
    lines.append(f"{'':20s} {'OLD':25s} {'NEW':25s}")

    def match_tag(matches: bool) -> str:
        return "[SAME]" if matches else "[DIFFERENT]"

    lines.append(f"{'Domain:':<20s} {comp.old_domain or '(unknown)':<25s} {comp.new_domain or '(unknown)':<25s} {match_tag(comp.domain_match)}")
    lines.append(f"{'Alias:':<20s} {comp.old_alias or '(unknown)':<25s} {comp.new_alias or '(unknown)':<25s} {match_tag(comp.alias_match)}")

    old_issuer = (comp.old_issuer or "(unknown)")[:22] + "..." if len(comp.old_issuer or "") > 25 else (comp.old_issuer or "(unknown)")
    new_issuer = (comp.new_issuer or "(unknown)")[:22] + "..." if len(comp.new_issuer or "") > 25 else (comp.new_issuer or "(unknown)")
    lines.append(f"{'Issuer:':<20s} {old_issuer:<25s} {new_issuer:<25s} {match_tag(comp.issuer_match)}")

    old_exp = comp.old_expires.strftime("%Y-%m-%d") if comp.old_expires else "(unknown)"
    new_exp = comp.new_expires.strftime("%Y-%m-%d") if comp.new_expires else "(unknown)"
    days_tag = f"[+{comp.days_extended} days]" if comp.days_extended > 0 else f"[{comp.days_extended} days]"
    lines.append(f"{'Expires:':<20s} {old_exp:<25s} {new_exp:<25s} {days_tag}")

    lines.append(f"{'Key type:':<20s} {comp.old_key_type or '(unknown)':<25s} {comp.new_key_type or '(unknown)':<25s} {match_tag(comp.key_type_match)}")

    old_pw = "YES" if comp.old_password_valid else "NO"
    new_pw = "YES" if comp.new_password_valid else "NO"
    lines.append(f"{'Password works:':<20s} {old_pw:<25s} {new_pw:<25s}")

    lines.append("")
    ready_str = "YES" if comp.ready_for_renewal else "NO"
    lines.append(f"Ready for renewal: {ready_str}")

    return "\n".join(lines)
