"""Filesystem helpers: private-file writes, atomic replace, safe archive limits."""
from __future__ import annotations

import os
import tempfile
from pathlib import Path

PRIVATE_FILE_MODE = 0o600


def _fsync_dir(directory: Path) -> None:
    """Best-effort fsync of a directory so a rename survives a crash (POSIX only)."""
    if os.name != "posix":
        return
    try:
        fd = os.open(str(directory), os.O_RDONLY)
    except OSError:
        return
    try:
        os.fsync(fd)
    except OSError:
        pass
    finally:
        os.close(fd)


def write_private(path: Path, data: bytes) -> None:
    """Write `data` to `path` so it is never readable by group/other.

    The file is created 0600 from the start (not chmod-ed after the write), so
    there is no window where a private key is world-readable. An existing file
    with looser permissions is tightened. On Windows the mode bits are mostly
    advisory; the file inherits the ACL of its folder.
    """
    path = Path(path)
    flags = os.O_WRONLY | os.O_CREAT | os.O_TRUNC | getattr(os, "O_BINARY", 0)
    fd = os.open(str(path), flags, PRIVATE_FILE_MODE)
    try:
        with os.fdopen(fd, "wb") as fh:
            fd = -1
            if os.name == "posix":
                os.fchmod(fh.fileno(), PRIVATE_FILE_MODE)
            fh.write(data)
            fh.flush()
            os.fsync(fh.fileno())
    finally:
        if fd != -1:
            os.close(fd)
    if os.name != "posix":
        try:
            os.chmod(path, PRIVATE_FILE_MODE)
        except OSError:
            pass


def atomic_write_private(path: Path, data: bytes) -> None:
    """Like write_private, but replaces `path` atomically (never half-written)."""
    path = Path(path)
    fd, tmp_name = tempfile.mkstemp(prefix=f".{path.name}.", suffix=".tmp", dir=str(path.parent))
    tmp = Path(tmp_name)
    try:
        with os.fdopen(fd, "wb") as fh:
            if os.name == "posix":
                os.fchmod(fh.fileno(), PRIVATE_FILE_MODE)
            fh.write(data)
            fh.flush()
            os.fsync(fh.fileno())
        os.replace(tmp, path)
        _fsync_dir(path.parent)
    except BaseException:
        try:
            tmp.unlink()
        except OSError:
            pass
        raise


def restrict_to_owner(path: Path) -> None:
    """chmod 0600 an existing file (no-op/best effort on Windows)."""
    try:
        os.chmod(path, PRIVATE_FILE_MODE)
    except OSError:
        pass


def is_within(base: Path, candidate: Path) -> bool:
    """True if `candidate` resolves to a location inside `base`."""
    try:
        base_resolved = Path(base).resolve()
        cand_resolved = Path(candidate).resolve()
    except (OSError, RuntimeError):
        return False
    return cand_resolved == base_resolved or base_resolved in cand_resolved.parents
