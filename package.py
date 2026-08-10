#!/usr/bin/env python3
"""
Create portable distribution packages for SSL Certificate Tool.

This script creates ready-to-use packages for each platform:
- ssl-auto-portable-windows.zip
- ssl-auto-portable-linux.tar.gz
- ssl-auto-portable-mac.tar.gz

Usage:
    python package.py [--all | --windows | --linux | --mac]

Prerequisites:
    - Run build-windows.bat/build-linux.sh/build-mac.sh first to create executables
    - Or run on each platform to build natively
"""

import argparse
import os
import shutil
import sys
import tarfile
import zipfile
from datetime import datetime
from pathlib import Path

SCRIPT_DIR = Path(__file__).resolve().parent
DIST_DIR = SCRIPT_DIR / "dist"
PACKAGE_DIR = SCRIPT_DIR / "packages"

# Files to include in all packages
COMMON_FILES = [
    "ssl-auto.py",
    "requirements.txt",
    "run.bat",
    "run.sh",
    "README-PORTABLE.txt",
]

COMMON_DIRS = [
    "configs",
    "ssl_cert_tool",
    "ssl_deploy",
    "offline",
]


def create_readme_portable():
    """Create the portable README file."""
    readme_path = SCRIPT_DIR / "README-PORTABLE.txt"
    readme_content = """SSL Certificate Tool - Portable Package
=======================================

QUICK START
-----------

WINDOWS:
  Double-click run.bat for interactive menu
  OR: ssl-auto.exe --wizard

MAC/LINUX:
  chmod +x run.sh ssl-auto
  ./run.sh for interactive menu
  OR: ./ssl-auto --wizard


USAGE EXAMPLES
--------------

Generate certificates from customer files:
  ssl-auto generate --input "customer_folder" --key "private.key"

Deploy certificates to servers:
  ssl-auto deploy --certs output/ --config myconfig

Full automation (generate + deploy):
  ssl-auto run --input "customer.eml" --key "domain.key" --config myconfig

Interactive wizard (recommended for first time):
  ssl-auto --wizard


OFFLINE INSTALLATION (Linux servers without internet)
-----------------------------------------------------

1. Copy this entire folder to the target server
2. If using Python (no executable):
   cd offline/
   chmod +x install-offline.sh
   ./install-offline.sh
3. Run: ./ssl-auto --wizard  (or python3 ssl-auto.py --wizard)


CONFIGURATION
-------------

Configs are in the configs/ folder. To create a new config:
  ssl-auto init --name myconfig

To list available configs:
  ssl-auto configs

To validate a config:
  ssl-auto validate --config myconfig


SUPPORTED INPUT FORMATS
-----------------------

- .crt, .cer, .pem  - Certificate files
- .p7b, .p7c        - PKCS7 certificate chains
- .p12, .pfx        - PKCS12 keystores
- .ca-bundle        - Multiple PEM certificates
- .eml              - Email files (e.g., from GlobalSign)
- .zip, .7z         - Archives containing certificates
- Folders           - Recursively scans for certificates


HELP
----

For full help: ssl-auto --help
For command help: ssl-auto <command> --help

Examples:
  ssl-auto generate --help
  ssl-auto deploy --help
  ssl-auto run --help


TROUBLESHOOTING
---------------

1. "Python not found"
   - Use the standalone executable (ssl-auto.exe or ssl-auto)
   - Or install Python 3.8+ from python.org

2. "Dependencies not installed"
   - Run: cd offline && ./install-offline.sh (Linux/Mac)
   - Run: cd offline && install-offline.bat (Windows)

3. "Config not found"
   - Check configs/ folder
   - Use full path or config name without .yaml

4. "Permission denied" (Linux/Mac)
   - Run: chmod +x ssl-auto run.sh

"""
    readme_path.write_text(readme_content, encoding="utf-8")
    return readme_path


def create_windows_package():
    """Create Windows portable package."""
    print("Creating Windows package...")
    
    package_name = "ssl-auto-portable-windows"
    temp_dir = PACKAGE_DIR / package_name
    
    if temp_dir.exists():
        shutil.rmtree(temp_dir)
    temp_dir.mkdir(parents=True)
    
    exe_path = DIST_DIR / "windows" / "ssl-auto.exe"
    if exe_path.exists():
        shutil.copy(exe_path, temp_dir / "ssl-auto.exe")
        print(f"  Copied: ssl-auto.exe")
    else:
        print(f"  WARNING: {exe_path} not found - package will need Python")
    
    for filename in COMMON_FILES:
        src = SCRIPT_DIR / filename
        if src.exists():
            shutil.copy(src, temp_dir / filename)
            print(f"  Copied: {filename}")
    
    for dirname in COMMON_DIRS:
        src = SCRIPT_DIR / dirname
        if src.exists():
            shutil.copytree(src, temp_dir / dirname)
            print(f"  Copied: {dirname}/")
    
    (temp_dir / "output").mkdir(exist_ok=True)
    
    zip_path = PACKAGE_DIR / f"{package_name}.zip"
    with zipfile.ZipFile(zip_path, 'w', zipfile.ZIP_DEFLATED) as zf:
        for root, dirs, files in os.walk(temp_dir):
            for file in files:
                file_path = Path(root) / file
                arcname = file_path.relative_to(PACKAGE_DIR)
                zf.write(file_path, arcname)
    
    shutil.rmtree(temp_dir)
    
    size_mb = zip_path.stat().st_size / 1024 / 1024
    print(f"  Created: {zip_path} ({size_mb:.1f} MB)")
    return zip_path


def create_linux_package():
    """Create Linux portable package."""
    print("Creating Linux package...")
    
    package_name = "ssl-auto-portable-linux"
    temp_dir = PACKAGE_DIR / package_name
    
    if temp_dir.exists():
        shutil.rmtree(temp_dir)
    temp_dir.mkdir(parents=True)
    
    exe_path = DIST_DIR / "linux" / "ssl-auto"
    if exe_path.exists():
        shutil.copy(exe_path, temp_dir / "ssl-auto")
        print(f"  Copied: ssl-auto")
    else:
        print(f"  WARNING: {exe_path} not found - package will need Python")
    
    for filename in COMMON_FILES:
        src = SCRIPT_DIR / filename
        if src.exists():
            shutil.copy(src, temp_dir / filename)
            print(f"  Copied: {filename}")
    
    for dirname in COMMON_DIRS:
        src = SCRIPT_DIR / dirname
        if src.exists():
            shutil.copytree(src, temp_dir / dirname)
            print(f"  Copied: {dirname}/")
    
    (temp_dir / "output").mkdir(exist_ok=True)
    
    tar_path = PACKAGE_DIR / f"{package_name}.tar.gz"
    with tarfile.open(tar_path, 'w:gz') as tf:
        tf.add(temp_dir, arcname=package_name)
    
    shutil.rmtree(temp_dir)
    
    size_mb = tar_path.stat().st_size / 1024 / 1024
    print(f"  Created: {tar_path} ({size_mb:.1f} MB)")
    return tar_path


def create_mac_package():
    """Create macOS portable package."""
    print("Creating macOS package...")
    
    package_name = "ssl-auto-portable-mac"
    temp_dir = PACKAGE_DIR / package_name
    
    if temp_dir.exists():
        shutil.rmtree(temp_dir)
    temp_dir.mkdir(parents=True)
    
    exe_path = DIST_DIR / "mac" / "ssl-auto"
    if exe_path.exists():
        shutil.copy(exe_path, temp_dir / "ssl-auto")
        print(f"  Copied: ssl-auto")
    else:
        print(f"  WARNING: {exe_path} not found - package will need Python")
    
    for filename in COMMON_FILES:
        src = SCRIPT_DIR / filename
        if src.exists():
            shutil.copy(src, temp_dir / filename)
            print(f"  Copied: {filename}")
    
    for dirname in COMMON_DIRS:
        src = SCRIPT_DIR / dirname
        if src.exists():
            shutil.copytree(src, temp_dir / dirname)
            print(f"  Copied: {dirname}/")
    
    (temp_dir / "output").mkdir(exist_ok=True)
    
    tar_path = PACKAGE_DIR / f"{package_name}.tar.gz"
    with tarfile.open(tar_path, 'w:gz') as tf:
        tf.add(temp_dir, arcname=package_name)
    
    shutil.rmtree(temp_dir)
    
    size_mb = tar_path.stat().st_size / 1024 / 1024
    print(f"  Created: {tar_path} ({size_mb:.1f} MB)")
    return tar_path


def main():
    parser = argparse.ArgumentParser(
        description="Create portable distribution packages for SSL Certificate Tool"
    )
    parser.add_argument("--all", action="store_true", help="Build all platforms")
    parser.add_argument("--windows", action="store_true", help="Build Windows package")
    parser.add_argument("--linux", action="store_true", help="Build Linux package")
    parser.add_argument("--mac", action="store_true", help="Build macOS package")
    
    args = parser.parse_args()
    
    if not any([args.all, args.windows, args.linux, args.mac]):
        args.all = True
    
    print("=" * 60)
    print("SSL Certificate Tool - Package Builder")
    print("=" * 60)
    print()
    
    PACKAGE_DIR.mkdir(exist_ok=True)
    
    print("Creating README-PORTABLE.txt...")
    create_readme_portable()
    print()
    
    packages = []
    
    if args.all or args.windows:
        packages.append(create_windows_package())
        print()
    
    if args.all or args.linux:
        packages.append(create_linux_package())
        print()
    
    if args.all or args.mac:
        packages.append(create_mac_package())
        print()
    
    print("=" * 60)
    print("Package Build Complete!")
    print("=" * 60)
    print()
    print("Created packages:")
    for pkg in packages:
        if pkg and pkg.exists():
            size = pkg.stat().st_size / 1024 / 1024
            print(f"  {pkg.name} ({size:.1f} MB)")
    print()
    print(f"Packages directory: {PACKAGE_DIR}")
    print()
    print("Note: To include executables, first run the build scripts:")
    print("  Windows: build-windows.bat")
    print("  Linux:   ./build-linux.sh (run on Linux)")
    print("  macOS:   ./build-mac.sh (run on Mac)")


if __name__ == "__main__":
    main()