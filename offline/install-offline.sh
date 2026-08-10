#!/bin/bash
# =============================================================================
# SSL Certificate Tool - Offline Installer for Linux Servers
# =============================================================================
#
# INSTRUCTIONS:
# 1. Copy the entire ssl-cert-tool folder to your offline Linux server
# 2. cd into the offline/ directory
# 3. Run: chmod +x install-offline.sh && ./install-offline.sh
#
# =============================================================================

set -e
cd "$(dirname "$0")"
TOOL_DIR="$(dirname "$(pwd)")"

echo ""
echo "=============================================="
echo "  SSL Certificate Tool - Offline Installer"
echo "=============================================="
echo ""

if [ -f "$TOOL_DIR/ssl-auto" ] && [ -x "$TOOL_DIR/ssl-auto" ]; then
    echo "Found standalone binary!"
    echo ""
    echo "No installation needed - the binary is self-contained."
    echo ""
    echo "Run the tool with:"
    echo "  cd $TOOL_DIR"
    echo "  ./ssl-auto --wizard"
    echo ""
    echo "Or use the menu:"
    echo "  ./run.sh"
    echo ""
    exit 0
fi

if [ -f "$TOOL_DIR/dist/linux/ssl-auto" ]; then
    echo "Found Linux binary in dist/linux/"
    cp "$TOOL_DIR/dist/linux/ssl-auto" "$TOOL_DIR/ssl-auto"
    chmod +x "$TOOL_DIR/ssl-auto"
    echo ""
    echo "Copied binary to: $TOOL_DIR/ssl-auto"
    echo ""
    echo "Run the tool with:"
    echo "  cd $TOOL_DIR"
    echo "  ./ssl-auto --wizard"
    echo ""
    exit 0
fi

if command -v python3 &>/dev/null; then
    PYTHON=python3
    PIP="python3 -m pip"
elif command -v python &>/dev/null; then
    PYTHON=python
    PIP="python -m pip"
else
    echo "ERROR: Python not found!"
    echo ""
    echo "Options:"
    echo "  1. Install Python 3.8+: sudo apt install python3 python3-pip"
    echo "  2. Use a pre-built binary (copy from dist/linux/ssl-auto)"
    echo ""
    exit 1
fi

echo "Python: $($PYTHON --version)"
echo ""

if [ ! -d "wheels" ] || [ -z "$(ls -A wheels/ 2>/dev/null)" ]; then
    echo "WARNING: No wheels found in offline/wheels/"
    echo ""
    echo "To prepare offline dependencies:"
    echo "  1. On a machine WITH internet, run: python download-deps.py"
    echo "  2. Copy the offline/ folder to this server"
    echo ""
    
    echo "Attempting online installation..."
    if $PIP install -r "$TOOL_DIR/requirements.txt"; then
        echo ""
        echo "Online installation successful!"
    else
        echo ""
        echo "ERROR: Cannot install dependencies."
        echo "Please prepare offline wheels using download-deps.py"
        exit 1
    fi
else
    echo "Installing dependencies from offline wheels..."
    echo ""
    
    $PIP install --no-index --find-links=wheels/ -r requirements.txt 2>&1 || {
        echo ""
        echo "Some packages failed to install from wheels."
        echo "Trying with source packages..."
        $PIP install --no-index --find-links=wheels/ cryptography paramiko PyYAML colorama
    }
fi

echo ""
echo "=============================================="
echo "  Installation Complete!"
echo "=============================================="
echo ""
echo "Run the tool with:"
echo "  cd $TOOL_DIR"
echo "  $PYTHON ssl-auto.py --wizard"
echo ""
echo "Or use the interactive menu:"
echo "  ./run.sh"
echo ""
echo "Quick commands:"
echo "  $PYTHON ssl-auto.py generate --input <certs> --key <key>"
echo "  $PYTHON ssl-auto.py deploy --certs <output/> --config <name>"
echo "  $PYTHON ssl-auto.py run --input <certs> --key <key> --config <name>"
echo ""