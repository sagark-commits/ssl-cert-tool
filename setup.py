#!/usr/bin/env python3
"""Cross-platform setup: install deps and verify Java/keytool/SSH."""
from __future__ import annotations

import shutil
import subprocess
import sys
from pathlib import Path

SCRIPT_DIR = Path(__file__).resolve().parent
REQUIREMENTS = SCRIPT_DIR / "requirements.txt"


def detect_os() -> str:
    import platform

    system = platform.system().lower()
    if system == "darwin":
        return "macos"
    if system == "windows":
        return "windows"
    if system == "linux":
        return "linux"
    return system


def run_pip_install() -> bool:
    print("\nInstalling Python dependencies...")
    cmd = [sys.executable, "-m", "pip", "install", "-r", str(REQUIREMENTS)]
    result = subprocess.run(cmd)
    return result.returncode == 0


def check_keytool() -> bool:
    sys.path.insert(0, str(SCRIPT_DIR))
    from ssl_cert_tool.platform import find_keytool

    kt = find_keytool()
    if kt:
        print(f"[OK] keytool: {kt}")
        return True
    print("[WARN] keytool not found — JKS generation requires Java JDK")
    print("       Set JAVA_HOME or install JDK and add keytool to PATH")
    return False


def check_ssh() -> bool:
    ssh = shutil.which("ssh")
    if ssh:
        print(f"[OK] ssh client: {ssh}")
        return True
    print("[WARN] ssh not found on PATH (needed for deployment)")
    return False


def check_python() -> bool:
    version = sys.version_info
    if version.major < 3 or (version.major == 3 and version.minor < 8):
        print(f"[ERROR] Python 3.8+ required (found {version.major}.{version.minor})")
        return False
    print(f"[OK] Python {version.major}.{version.minor}.{version.micro}")
    return True


def main() -> int:
    os_name = detect_os()
    print(f"=== ssl-auto setup ({os_name}) ===\n")

    if not check_python():
        return 1
    if not run_pip_install():
        print("[ERROR] pip install failed")
        return 1
    print("[OK] Dependencies installed")

    print("\nChecking tools...")
    check_keytool()
    check_ssh()

    print("\nSetup complete. Quick start:")
    if os_name == "windows":
        print("  ssl-auto.bat run --input customer.eml --key domain.key")
    else:
        print("  ./ssl-auto run --input customer.eml --key domain.key")
    print("  python ssl-auto.py --help")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
