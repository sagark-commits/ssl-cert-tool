# Author: Sagar K | 2026 | MIT licence
"""Cross-platform utilities: paths, keytool discovery, terminal colors, OS detection."""
from __future__ import annotations

import os
import platform
import re
import shutil
import subprocess
import sys
from pathlib import Path


def detect_os() -> str:
    """Return 'windows', 'macos', 'linux', or 'unknown'."""
    system = platform.system().lower()
    if system == "darwin":
        return "macos"
    if system == "windows":
        return "windows"
    if system == "linux":
        return "linux"
    return "unknown"


def is_wsl() -> bool:
    if detect_os() != "linux":
        return False
    try:
        with open("/proc/version", encoding="utf-8", errors="ignore") as fh:
            return "microsoft" in fh.read().lower()
    except OSError:
        return False


def expand_user(path: str | Path) -> Path:
    """Expand ~ and environment variables on all platforms."""
    text = os.path.expandvars(os.path.expanduser(str(path)))
    return Path(text)


def wsl_drives_to_windows(path_str: str) -> str:
    """Convert WSL/MobaXterm /drives/c/... paths to C:/... on Windows."""
    match = re.match(r"^/drives/([a-zA-Z])(?:/(.+))?$", path_str.replace("\\", "/"))
    if match:
        drive = match.group(1).upper()
        rest = match.group(2) or ""
        return f"{drive}:/{rest}" if rest else f"{drive}:/"
    return path_str


def windows_to_wsl(path: Path) -> str:
    """Convert Windows path to WSL /mnt/c/... style."""
    text = str(path.resolve()).replace("\\", "/")
    match = re.match(r"^([A-Za-z]):/(.*)$", text)
    if match:
        return f"/mnt/{match.group(1).lower()}/{match.group(2)}"
    return text


def try_repair_mangled_windows_path(path_str: str) -> str:
    """Repair paths where a Unix shell stripped backslashes."""
    if "/" in path_str or "\\" in path_str:
        return path_str
    if path_str.startswith("..") and "config.yaml" in path_str:
        idx = path_str.find("config.yaml")
        if idx > 2:
            prefix = path_str[2:idx]
            return f"../{prefix}/config.yaml"
    match = re.match(
        r"^\.\.([a-zA-Z0-9_-]+)([a-zA-Z0-9_.-]+\.(yaml|yml|pem|key|crt|cer|eml))$",
        path_str,
    )
    if match:
        return f"../{match.group(1)}/{match.group(2)}"
    return path_str


def path_variants(path_str: str) -> list[str]:
    """Generate alternate path forms to try when the first does not exist."""
    cleaned = path_str.strip().strip('"').strip("'")
    variants: list[str] = []
    seen: set[str] = set()

    def add(value: str) -> None:
        if value and value not in seen:
            seen.add(value)
            variants.append(value)

    add(cleaned)
    add(cleaned.replace("\\", "/"))
    add(wsl_drives_to_windows(cleaned.replace("\\", "/")))
    add(try_repair_mangled_windows_path(cleaned))
    expanded = os.path.expandvars(os.path.expanduser(cleaned))
    add(expanded)
    add(expanded.replace("\\", "/"))
    if cleaned.startswith("//"):
        add(cleaned[1:])
    return variants


def resolve_existing_path(path_str: str) -> Path | None:
    """Return the first path variant that exists on disk."""
    for variant in path_variants(path_str):
        candidate = Path(variant)
        try:
            resolved = candidate.resolve()
        except (OSError, RuntimeError):
            resolved = candidate
        if resolved.exists():
            return resolved
    return None


def normalize_path(path_str: str) -> Path:
    """Normalize Windows/WSL/mixed paths; resolve when possible."""
    existing = resolve_existing_path(path_str)
    if existing is not None:
        return existing
    for variant in path_variants(path_str):
        candidate = Path(variant)
        try:
            return candidate.resolve()
        except (OSError, RuntimeError):
            continue
    return Path(path_str.strip().strip('"').strip("'"))


def find_keytool(explicit: Path | str | None = None) -> Path | None:
    """Locate keytool on Windows, macOS, or Linux."""
    candidates: list[Path] = []

    if explicit:
        p = Path(str(explicit))
        candidates.append(p)
        if detect_os() == "windows" and p.suffix.lower() != ".exe":
            candidates.append(p.with_suffix(".exe"))

    env_keytool = os.environ.get("KEYTOOL")
    if env_keytool:
        candidates.append(Path(env_keytool))

    which = shutil.which("keytool")
    if which:
        candidates.append(Path(which))

    java_home = os.environ.get("JAVA_HOME", "")
    if java_home:
        candidates.append(Path(java_home) / "bin" / "keytool")
        if detect_os() == "windows":
            candidates.append(Path(java_home) / "bin" / "keytool.exe")

    if detect_os() == "windows":
        program_files = [
            os.environ.get("ProgramFiles(x86)", r"C:\Program Files (x86)"),
            os.environ.get("ProgramFiles", r"C:\Program Files"),
        ]
        for base in program_files:
            java_root = Path(base) / "Java"
            if java_root.is_dir():
                for jre in sorted(java_root.glob("*/bin/keytool.exe"), reverse=True):
                    candidates.append(jre)
    elif detect_os() == "macos":
        try:
            result = subprocess.run(
                ["/usr/libexec/java_home"],
                capture_output=True,
                text=True,
                timeout=5,
            )
            if result.returncode == 0:
                home = result.stdout.strip()
                candidates.append(Path(home) / "bin" / "keytool")
        except (OSError, subprocess.TimeoutExpired):
            pass
        candidates.extend(
            Path(p) / "bin" / "keytool"
            for p in (
                "/Library/Java/JavaVirtualMachines",
                "/System/Library/Java/JavaVirtualMachines",
            )
            if Path(p).is_dir()
            for jvm in Path(p).glob("*/Contents/Home/bin/keytool")
        )

    common_unix = (
        "/usr/bin/keytool",
        "/usr/local/bin/keytool",
        "/opt/java/openjdk/bin/keytool",
    )
    for p in common_unix:
        candidates.append(Path(p))

    seen: set[str] = set()
    for candidate in candidates:
        key = str(candidate)
        if key in seen:
            continue
        seen.add(key)
        if candidate.is_file():
            return candidate
    return None


class Terminal:
    """Colored terminal output with colorama fallback on Windows."""

    def __init__(self) -> None:
        self.enabled = sys.stdout.isatty()
        self._init_colors()

    def _init_colors(self) -> None:
        self.RED = "\033[91m"
        self.GREEN = "\033[92m"
        self.YELLOW = "\033[93m"
        self.BLUE = "\033[94m"
        self.CYAN = "\033[96m"
        self.BOLD = "\033[1m"
        self.RESET = "\033[0m"
        if detect_os() == "windows" and self.enabled:
            try:
                import colorama

                colorama.init()
            except ImportError:
                pass

    def disable(self) -> None:
        self.enabled = False
        self.RED = self.GREEN = self.YELLOW = self.BLUE = ""
        self.CYAN = self.BOLD = self.RESET = ""

    def step(self, current: int, total: int, message: str) -> None:
        print(f"{self.BOLD}{self.CYAN}[{current}/{total}]{self.RESET} {message}")

    def success(self, message: str) -> None:
        print(f"{self.GREEN}{message}{self.RESET}")

    def warn(self, message: str) -> None:
        print(f"{self.YELLOW}{message}{self.RESET}")

    def error(self, message: str) -> None:
        print(f"{self.RED}{message}{self.RESET}")

    def info(self, message: str) -> None:
        print(f"{self.CYAN}{message}{self.RESET}")

    def detail(self, message: str, indent: int = 6) -> None:
        print(f"{' ' * indent}{message}")
