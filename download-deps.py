#!/usr/bin/env python3
"""
Download Python dependencies for offline installation.

Run this on a machine with internet access to download all wheels
for Linux, Windows, and macOS. Then copy the offline/ folder to
the target servers.

Usage:
    python download-deps.py

Output:
    offline/
        wheels/           # All .whl files
        requirements.txt  # Copy of requirements
        install-offline.sh  # Linux offline installer
        install-offline.bat # Windows offline installer
"""

import os
import subprocess
import sys
import shutil
from pathlib import Path

SCRIPT_DIR = Path(__file__).resolve().parent
OFFLINE_DIR = SCRIPT_DIR / "offline"
WHEELS_DIR = OFFLINE_DIR / "wheels"

# Platforms and Python versions to download for
PLATFORMS = [
    # Linux (manylinux for broad compatibility)
    ("manylinux2014_x86_64", "3.8"),
    ("manylinux2014_x86_64", "3.9"),
    ("manylinux2014_x86_64", "3.10"),
    ("manylinux2014_x86_64", "3.11"),
    ("manylinux2014_x86_64", "3.12"),
    # Windows
    ("win_amd64", "3.8"),
    ("win_amd64", "3.9"),
    ("win_amd64", "3.10"),
    ("win_amd64", "3.11"),
    ("win_amd64", "3.12"),
    # macOS (Intel)
    ("macosx_10_9_x86_64", "3.8"),
    ("macosx_10_9_x86_64", "3.9"),
    ("macosx_10_9_x86_64", "3.10"),
    ("macosx_10_9_x86_64", "3.11"),
    ("macosx_10_9_x86_64", "3.12"),
    # macOS (Apple Silicon)
    ("macosx_11_0_arm64", "3.9"),
    ("macosx_11_0_arm64", "3.10"),
    ("macosx_11_0_arm64", "3.11"),
    ("macosx_11_0_arm64", "3.12"),
]

# Core packages (required)
CORE_PACKAGES = [
    "cryptography",
    "paramiko",
    "PyYAML",
    "colorama",
    "bcrypt",
    "pynacl",
    "cffi",
    "pycparser",
]

# Optional packages
OPTIONAL_PACKAGES = [
    "python-docx",
    "py7zr",
]


def run_pip_download(packages, platform, python_version):
    """Download packages for a specific platform."""
    cmd = [
        sys.executable, "-m", "pip", "download",
        "--dest", str(WHEELS_DIR),
        "--platform", platform,
        "--python-version", python_version,
        "--only-binary=:all:",
        "--no-deps",
    ]
    cmd.extend(packages)
    
    print(f"  Downloading for {platform} (Python {python_version})...")
    result = subprocess.run(cmd, capture_output=True, text=True)
    
    if result.returncode != 0:
        print(f"    Warning: Some packages may not be available for this platform")
        return False
    return True


def download_source_packages():
    """Download source distributions as fallback."""
    cmd = [
        sys.executable, "-m", "pip", "download",
        "--dest", str(WHEELS_DIR),
        "--no-binary=:all:",
    ]
    cmd.extend(["PyYAML", "colorama"])
    
    print("  Downloading source distributions as fallback...")
    subprocess.run(cmd, capture_output=True)


def download_universal_wheels():
    """Download universal (pure Python) wheels."""
    cmd = [
        sys.executable, "-m", "pip", "download",
        "--dest", str(WHEELS_DIR),
        "--only-binary=:all:",
    ]
    cmd.extend(["colorama", "pycparser"])
    
    print("  Downloading universal wheels...")
    subprocess.run(cmd, capture_output=True)


def main():
    print("=" * 60)
    print("SSL Certificate Tool - Offline Dependencies Downloader")
    print("=" * 60)
    print()
    
    # Create directories
    WHEELS_DIR.mkdir(parents=True, exist_ok=True)
    print(f"Output directory: {OFFLINE_DIR}")
    print()
    
    # Copy requirements.txt
    req_src = SCRIPT_DIR / "requirements.txt"
    req_dst = OFFLINE_DIR / "requirements.txt"
    if req_src.exists():
        shutil.copy(req_src, req_dst)
        print(f"Copied: requirements.txt")
    
    print()
    print("Downloading packages for multiple platforms...")
    print("(This may take several minutes)")
    print()
    
    # Download for each platform
    all_packages = CORE_PACKAGES + OPTIONAL_PACKAGES
    
    for platform, py_version in PLATFORMS:
        run_pip_download(all_packages, platform, py_version)
    
    # Download universal/source packages
    download_universal_wheels()
    download_source_packages()
    
    print()
    print("=" * 60)
    print("Download complete!")
    print("=" * 60)
    print()
    
    # Count downloaded files
    wheel_count = len(list(WHEELS_DIR.glob("*.whl")))
    tar_count = len(list(WHEELS_DIR.glob("*.tar.gz")))
    
    print(f"  Wheels downloaded: {wheel_count}")
    print(f"  Source packages:   {tar_count}")
    
    total_size = sum(f.stat().st_size for f in WHEELS_DIR.iterdir() if f.is_file())
    print(f"  Total size:        {total_size / 1024 / 1024:.1f} MB")
    print()
    print("To use on offline servers:")
    print("  1. Copy the entire 'offline/' folder to the target server")
    print("  2. Run: cd offline && ./install-offline.sh")
    print("  3. Then: cd .. && python3 ssl-auto.py --wizard")
    print()


if __name__ == "__main__":
    main()