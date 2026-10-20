# Author: Sagar K | 2026 | MIT licence
"""Every tracked Python source file carries the author line, so files added later are signed too."""
import subprocess
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
SKIP = {".git", ".venv", "venv", "build", "dist", "output", "offline", "legacy", "__pycache__", "node_modules", ".pytest_cache"}


def python_files():
    """The files Git tracks (so ignored local scratch scripts are left alone); a plain walk if this is not a Git checkout."""
    try:
        out = subprocess.run(["git", "ls-files", "-z", "*.py"], cwd=ROOT, capture_output=True, check=True).stdout
        names = [n for n in out.decode("utf-8").split("\0") if n]
        if names:
            return [ROOT / n for n in names]
    except (OSError, subprocess.CalledProcessError):
        pass
    return [p for p in ROOT.rglob("*.py")
            if not any(part in SKIP or part.startswith(("test-", "test_output", "test_pipeline", "_compare_")) for part in p.relative_to(ROOT).parts)
            and not p.name.startswith("_compare_")]


def test_every_python_file_is_signed():
    unsigned = []
    for path in python_files():
        head = path.read_bytes()[:400].decode("utf-8-sig", "replace")
        if "Author: Sagar K" not in head:
            unsigned.append(path.relative_to(ROOT).as_posix())
    assert not unsigned, "add the '# Author: Sagar K | 2026 | MIT licence' line to: " + ", ".join(sorted(unsigned))


def test_licence_file_names_the_author():
    text = (ROOT / "LICENSE").read_text(encoding="utf-8")
    assert text.startswith("MIT License") and "Copyright (c) 2026 Sagar K" in text
