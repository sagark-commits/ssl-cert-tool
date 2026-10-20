#!/bin/bash
# Author: Sagar K | 2026 | MIT licence
set -e

echo "============================================"
echo " SSL Certificate Tool - macOS All-in-One"
echo " Builds GUI + CLI with NO Python required"
echo "============================================"
echo

cd "$(dirname "$0")"

if ! command -v python3 &>/dev/null; then
    echo "ERROR: Python3 is required ON THE BUILD MAC only."
    echo "Install with: brew install python@3.11"
    echo "End users of the package do NOT need Python."
    exit 1
fi

echo "Installing build dependencies..."
python3 -m pip install --upgrade pip >/dev/null
python3 -m pip install -r requirements.txt "pyinstaller>=6.3" "setuptools>=71" >/dev/null

OUT="dist/SSLCertTool-Mac"
rm -rf "$OUT"
mkdir -p "$OUT/configs" "$OUT/output"

# Only the template and examples are shipped: customer configs (hostnames,
# passwords) must never be bundled into the binary or the package.
STAGE="build/package-configs"
rm -rf "$STAGE"; mkdir -p "$STAGE"
cp configs/template.yaml "$STAGE/"
cp configs/example-*.yaml "$STAGE/" 2>/dev/null || true
cp configs/*.example.yaml "$STAGE/" 2>/dev/null || true

echo
echo "[1/2] Building GUI app: SSLCertTool ..."
python3 -m PyInstaller --noconfirm --clean --windowed --onefile \
    --name SSLCertTool \
    --distpath "$OUT" \
    --workpath build/mac-gui \
    --specpath . \
    --paths . \
    --add-data "ssl_cert_tool:ssl_cert_tool" \
    --add-data "ssl_deploy:ssl_deploy" \
    --add-data "$STAGE:configs" \
    --add-data "catalogues:catalogues" \
    --hidden-import=paramiko \
    --hidden-import=cryptography \
    --hidden-import=yaml \
    --hidden-import=colorama \
    --hidden-import=bcrypt \
    --hidden-import=nacl \
    --hidden-import=docx \
    --hidden-import=py7zr \
    --exclude-module setuptools \
    --collect-submodules cryptography \
    --collect-binaries cryptography \
    ssl-gui.py

echo
echo "[2/2] Building CLI: ssl-auto ..."
python3 -m PyInstaller --noconfirm --clean --console --onefile \
    --name ssl-auto \
    --distpath "$OUT" \
    --workpath build/mac-cli \
    --specpath . \
    --paths . \
    --add-data "ssl_cert_tool:ssl_cert_tool" \
    --add-data "ssl_deploy:ssl_deploy" \
    --add-data "$STAGE:configs" \
    --add-data "catalogues:catalogues" \
    --hidden-import=paramiko \
    --hidden-import=cryptography \
    --hidden-import=yaml \
    --hidden-import=colorama \
    --hidden-import=bcrypt \
    --hidden-import=nacl \
    --hidden-import=docx \
    --hidden-import=py7zr \
    --exclude-module setuptools \
    --collect-submodules cryptography \
    --collect-binaries cryptography \
    ssl-auto.py

chmod +x "$OUT/ssl-auto" 2>/dev/null || true
chmod +x "$OUT/SSLCertTool" 2>/dev/null || true
if [ -d "$OUT/SSLCertTool.app" ]; then
    chmod -R u+x "$OUT/SSLCertTool.app"
fi

echo
echo "Copying configs and docs..."
cp -R "$STAGE"/* "$OUT/configs/"
cp README-PORTABLE.txt "$OUT/README.txt"
[ -f INSTALL-MAC.txt ] && cp INSTALL-MAC.txt "$OUT/INSTALL.txt"

cat > "$OUT/Start SSL Certificate Tool.command" << 'EOF'
#!/bin/bash
cd "$(dirname "$0")"
if [ -d "SSLCertTool.app" ]; then
  open "SSLCertTool.app"
elif [ -x "./SSLCertTool" ]; then
  ./SSLCertTool
else
  echo "SSLCertTool not found"
  read -r
fi
EOF
chmod +x "$OUT/Start SSL Certificate Tool.command"

cat > "$OUT/Start CLI Wizard.command" << 'EOF'
#!/bin/bash
cd "$(dirname "$0")"
./ssl-auto --wizard
echo
read -n 1 -s -r -p "Press any key to close..."
EOF
chmod +x "$OUT/Start CLI Wizard.command"

echo
echo "Creating ZIP..."
(
  cd dist
  rm -f SSLCertTool-Mac.zip
  zip -r SSLCertTool-Mac.zip SSLCertTool-Mac
)

echo
echo "============================================"
echo " BUILD COMPLETE"
echo "============================================"
echo
echo " Folder: dist/SSLCertTool-Mac/"
echo " Zip:    dist/SSLCertTool-Mac.zip"
echo
echo " Give users the ZIP. They unzip and double-click:"
echo "   Start SSL Certificate Tool.command"
echo " No Python install needed."
echo
echo " First open on Mac: right-click > Open (Gatekeeper)."
echo
echo " NOTE: JKS generation needs Java keytool on PATH"
echo "       if you use .jks (P12 works without Java)."
echo
