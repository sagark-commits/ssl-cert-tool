# Author: Sagar K | 2026 | MIT licence
"""An in-memory-ish stand-in for ssl_deploy.ssh.RemoteHost.

Remote absolute paths are mapped into a sandbox directory, and the handful of
shell commands the deployer issues are interpreted in Python (via shlex, so a
badly quoted path would visibly break). This makes the deployer testable on any OS.
"""
from __future__ import annotations

import hashlib
import os
import shlex
import shutil
from pathlib import Path
from types import SimpleNamespace
from typing import Dict, List, Optional, Tuple

Result = Tuple[int, str, str]


class FakeSFTP:
    def __init__(self, remote: "FakeRemote") -> None:
        self.r = remote

    def _attrs(self, p: Path, st: os.stat_result, name: str = "") -> SimpleNamespace:
        uid, gid = self.r.owners.get(str(p), (1000, 1000))
        return SimpleNamespace(
            filename=name or p.name, st_mode=st.st_mode, st_size=st.st_size, st_uid=uid, st_gid=gid
        )

    def stat(self, path: str):
        p = self.r.map(path)
        return self._attrs(p, os.stat(p))

    def lstat(self, path: str):
        p = self.r.map(path)
        return self._attrs(p, os.lstat(p))

    def normalize(self, path: str) -> str:
        return self.r.unmap(Path(os.path.realpath(self.r.map(path))))

    def mkdir(self, path: str, mode: int = 0o755) -> None:
        os.mkdir(self.r.map(path))

    def open(self, path: str, mode: str = "r"):
        p = self.r.map(path)
        if self.r.fail_write_substr and self.r.fail_write_substr in path:
            raise IOError("simulated: no space left on device")
        return open(p, mode)

    def chmod(self, path: str, mode: int) -> None:
        os.chmod(self.r.map(path), mode)

    def chown(self, path: str, uid: int, gid: int) -> None:
        if self.r.chown_fails:
            raise PermissionError("simulated: operation not permitted")
        self.r.owners[str(self.r.map(path))] = (uid, gid)

    def posix_rename(self, old: str, new: str) -> None:
        po, pn = self.r.map(old), self.r.map(new)
        os.replace(po, pn)
        if str(po) in self.r.owners:
            self.r.owners[str(pn)] = self.r.owners.pop(str(po))

    def remove(self, path: str) -> None:
        os.remove(self.r.map(path))

    def listdir(self, path: str) -> List[str]:
        return os.listdir(self.r.map(path))

    def listdir_attr(self, path: str):
        base = self.r.map(path)
        return [self._attrs(base / n, os.lstat(base / n), n) for n in os.listdir(base)]

    def get(self, remote: str, local: str) -> None:
        shutil.copyfile(self.r.map(remote), local)

    def close(self) -> None:
        pass


class FakeRemote:
    """Drop-in for RemoteHost. `commands` records every shell command issued."""

    def __init__(self, root: Path, *, owned: bool = True) -> None:
        self.root = Path(root)
        self.owned = owned  # result of `[ -O dir ]` (backup-dir ownership check)
        self.chown_fails = False
        self.fail_write_substr: Optional[str] = None
        self.sha256sum_available = True
        self.timeout_on: List[str] = []  # commands containing these raise TimeoutError (idle timeout)
        self.sha256_override: Optional[str] = None  # simulate a corrupted upload
        self.keytool_result: Result = (0, "", "")
        self.script_results: Dict[str, Result] = {}  # substring of command -> result
        self.owners: Dict[str, Tuple[int, int]] = {}
        self.commands: List[str] = []
        self.stdin_sent: List[Optional[str]] = []
        self._sftp = FakeSFTP(self)

    # -- path mapping ---------------------------------------------------
    def map(self, path: str) -> Path:
        assert path.startswith("/"), f"remote path must be absolute: {path!r}"
        return self.root / os.path.normpath(path.lstrip("/"))

    def unmap(self, p: Path) -> str:
        return "/" + Path(os.path.relpath(p, self.root)).as_posix()

    # -- test helpers ---------------------------------------------------
    def write(self, path: str, data: bytes, mode: int = 0o644) -> None:
        p = self.map(path)
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_bytes(data)
        os.chmod(p, mode)

    def read(self, path: str) -> bytes:
        return self.map(path).read_bytes()

    def exists(self, path: str) -> bool:
        return self.map(path).exists()

    def files(self) -> List[str]:
        return sorted(self.unmap(p) for p in self.root.rglob("*") if p.is_file())

    def ran(self, needle: str) -> bool:
        return any(needle in c for c in self.commands)

    # -- RemoteHost interface ---------------------------------------------
    def sftp(self) -> FakeSFTP:
        return self._sftp

    def close(self) -> None:
        pass

    def run(self, command: str, *, timeout: int = 300, stdin_data: Optional[str] = None) -> Result:
        self.commands.append(command)
        self.stdin_sent.append(stdin_data)
        for needle in self.timeout_on:
            if needle in command:
                raise TimeoutError(f"command produced no output for {timeout}s")
        for needle, result in self.script_results.items():
            if needle in command:
                return result
        lex = shlex.shlex(command, posix=True, punctuation_chars=True)
        lex.whitespace_split = True
        groups: List[Tuple[Optional[str], List[str]]] = []
        op: Optional[str] = None
        current: List[str] = []
        for token in lex:
            if token in (";", "&&", "||"):
                groups.append((op, current))
                op, current = token, []
            else:
                current.append(token)
        groups.append((op, current))

        code, out, err = 0, "", ""
        for gop, argv in groups:
            if gop == "&&" and code != 0:
                continue
            if gop == "||" and code == 0:
                continue
            code, o, e = self._exec(argv)
            out += o
            err += e
        return code, out, err

    # -- tiny shell ---------------------------------------------------------
    def _exec(self, argv: List[str]) -> Result:
        if not argv:
            return 0, "", ""
        cmd, args = argv[0], argv[1:]
        if cmd == "umask":
            return 0, "", ""
        if cmd == "true":
            return 0, "", ""
        if cmd == "false":
            return 1, "", ""
        if cmd == "exit":
            return int(args[0]) if args else 0, "", ""
        if cmd == "mkdir":
            self.map(args[-1]).mkdir(parents=True, exist_ok=True)
            return 0, "", ""
        if cmd == "[":
            return self._test(args[:-1] if args and args[-1] == "]" else args)
        if cmd == "chmod":
            os.chmod(self.map(args[1]), int(args[0], 8))
            return 0, "", ""
        if cmd == "cp":
            src, dst = (self.map(a) for a in args[-2:])
            if not src.exists():
                return 1, "", f"cp: cannot stat '{args[-2]}'"
            shutil.copy2(src, dst)
            if str(src) in self.owners:
                self.owners[str(dst)] = self.owners[str(src)]
            return 0, "", ""
        if cmd == "mv":
            src, dst = (self.map(a) for a in args[-2:])
            os.replace(src, dst)
            return 0, "", ""
        if cmd == "rm":
            try:
                os.remove(self.map(args[-1]))
            except FileNotFoundError:
                pass
            return 0, "", ""
        if cmd == "sha256sum":
            if not self.sha256sum_available:
                return 127, "", "sha256sum: command not found"
            data = self.map(args[-1]).read_bytes()
            digest = self.sha256_override or hashlib.sha256(data).hexdigest()
            return 0, f"{digest}  {args[-1]}\n", ""
        if cmd.endswith("keytool"):
            return self.keytool_result
        return 127, "", f"{cmd}: command not found"

    def _test(self, args: List[str]) -> Result:
        negate = False
        if args and args[0] == "!":
            negate, args = True, args[1:]
        flag, path = args[0], args[1]
        p = self.map(path)
        if flag == "-d":
            ok = p.is_dir()
        elif flag == "-L":
            ok = p.is_symlink()
        elif flag == "-O":
            ok = self.owned and p.exists()
        elif flag in ("-f", "-e"):
            ok = p.exists()
        else:
            raise AssertionError(f"unsupported test flag {flag}")
        return (0 if ok != negate else 1), "", ""
