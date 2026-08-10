#!/bin/bash
set -e

echo "============================================"
echo " SSL Certificate Tool - Linux All-in-One"
echo " Build on a Linux machine, then share the ZIP"
echo "============================================"
echo

cd "$(dirname "$0")"

if ! command -v python3 &>/dev/null; then
    echo "ERROR: Python3 required on BUILD machine only"
    echo "  RHEL/CentOS: yum install -y python3 python3-pip"
    echo "  Ubuntu/Debian: apt install -y python3 python3-pip python3-venv"
    exit 1
fi

echo "Installing build dependencies..."
python3 -m pip install --upgrade pip >/dev/null 2>&1 || true
python3 -m pip install -r requirements.txt "pyinstaller>=6.3" "setuptools>=71" >/dev/null

OUT="dist/SSLCertTool-Linux"
rm -rf "$OUT"
mkdir -p "$OUT/configs" "$OUT/output"

echo
echo "[1/1] Building CLI: ssl-auto ..."
python3 -m PyInstaller --noconfirm --clean --console --onefile \
    --name ssl-auto \
    --distpath "$OUT" \
    --workpath build/linux-cli \
    --specpath . \
    --paths . \
    --add-data "ssl_cert_tool:ssl_cert_tool" \
    --add-data "ssl_deploy:ssl_deploy" \
    --add-data "configs:configs" \
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

chmod +x "$OUT/ssl-auto"
cp -R configs/* "$OUT/configs/" 2>/dev/null || true
cp README-PORTABLE.txt "$OUT/README.txt" 2>/dev/null || true
cp INSTALL-LINUX.txt "$OUT/INSTALL.txt" 2>/dev/null || true
cp LINUX_GENERATE_GUIDE.txt "$OUT/LINUX_GENERATE_GUIDE.txt" 2>/dev/null || true
cp generate-on-linux.sh "$OUT/generate-on-linux.sh" 2>/dev/null || true
chmod +x "$OUT/generate-on-linux.sh" 2>/dev/null || true

cat > "$OUT/generate.sh" << 'EOF'
#!/bin/bash
cd "$(dirname "$0")"
./ssl-auto --wizard
EOF
chmod +x "$OUT/generate.sh"

echo
echo "Creating ZIP..."
(
  cd dist
  rm -f SSLCertTool-Linux.zip
  zip -r SSLCertTool-Linux.zip SSLCertTool-Linux
)

echo
echo "============================================"
echo " BUILD COMPLETE"
echo "============================================"
echo " Folder: dist/SSLCertTool-Linux/"
echo " Zip:    dist/SSLCertTool-Linux.zip"
echo
echo " On target server:"
echo "   unzip SSLCertTool-Linux.zip"
echo "   cd SSLCertTool-Linux"
echo "   ./ssl-auto --wizard"
echo "   OR: ./generate-on-linux.sh"
echo
