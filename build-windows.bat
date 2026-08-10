@echo off
setlocal enabledelayedexpansion

echo ============================================
echo  SSL Certificate Tool - Windows All-in-One
echo  Builds GUI + CLI with NO Python required
echo ============================================
echo.

cd /d "%~dp0"

python --version >nul 2>&1
if errorlevel 1 (
    echo ERROR: Python is required ON THE BUILD MACHINE only.
    echo Install Python 3.10+ from https://python.org
    echo End users of the package do NOT need Python.
    pause
    exit /b 1
)

echo Installing build dependencies...
python -m pip install --upgrade pip >nul
python -m pip install -r requirements.txt "pyinstaller>=6.3" "setuptools>=71" >nul
if errorlevel 1 (
    echo ERROR: pip install failed
    pause
    exit /b 1
)

set OUT=dist\SSLCertTool-Windows
if exist "%OUT%" rmdir /s /q "%OUT%"
mkdir "%OUT%"
mkdir "%OUT%\configs"
mkdir "%OUT%\output"

echo.
echo [1/2] Building GUI app: SSLCertTool.exe ...
python -m PyInstaller --noconfirm --clean --windowed --onefile ^
    --name SSLCertTool ^
    --distpath "%OUT%" ^
    --workpath build\windows-gui ^
    --specpath . ^
    --paths . ^
    --add-data "ssl_cert_tool;ssl_cert_tool" ^
    --add-data "ssl_deploy;ssl_deploy" ^
    --add-data "configs;configs" ^
    --hidden-import=paramiko ^
    --hidden-import=cryptography ^
    --hidden-import=yaml ^
    --hidden-import=colorama ^
    --hidden-import=bcrypt ^
    --hidden-import=nacl ^
    --hidden-import=docx ^
    --hidden-import=py7zr ^
    --exclude-module setuptools ^
    --collect-submodules cryptography ^
    --collect-binaries cryptography ^
    ssl-gui.py

if errorlevel 1 (
    echo ERROR: GUI build failed
    pause
    exit /b 1
)

echo.
echo [2/2] Building CLI: ssl-auto.exe ...
python -m PyInstaller --noconfirm --clean --console --onefile ^
    --name ssl-auto ^
    --distpath "%OUT%" ^
    --workpath build\windows-cli ^
    --specpath . ^
    --paths . ^
    --add-data "ssl_cert_tool;ssl_cert_tool" ^
    --add-data "ssl_deploy;ssl_deploy" ^
    --add-data "configs;configs" ^
    --hidden-import=paramiko ^
    --hidden-import=cryptography ^
    --hidden-import=yaml ^
    --hidden-import=colorama ^
    --hidden-import=bcrypt ^
    --hidden-import=nacl ^
    --hidden-import=docx ^
    --hidden-import=py7zr ^
    --exclude-module setuptools ^
    --collect-submodules cryptography ^
    --collect-binaries cryptography ^
    ssl-auto.py

if errorlevel 1 (
    echo ERROR: CLI build failed
    pause
    exit /b 1
)

echo.
echo Copying configs and docs into package...
xcopy /E /I /Y configs "%OUT%\configs\" >nul
copy /Y README-PORTABLE.txt "%OUT%\README.txt" >nul
copy /Y INSTALL-WINDOWS.txt "%OUT%\INSTALL.txt" >nul 2>nul

(
echo @echo off
echo cd /d "%%~dp0"
echo start "" "SSLCertTool.exe"
) > "%OUT%\Start SSL Certificate Tool.bat"

(
echo @echo off
echo cd /d "%%~dp0"
echo ssl-auto.exe --wizard
echo pause
) > "%OUT%\Start CLI Wizard.bat"

echo.
echo Creating ZIP...
powershell -NoProfile -Command "Compress-Archive -Path '%OUT%\*' -DestinationPath 'dist\SSLCertTool-Windows.zip' -Force"

echo.
echo ============================================
echo  BUILD COMPLETE
echo ============================================
echo.
echo  Folder: dist\SSLCertTool-Windows\
echo  Zip:    dist\SSLCertTool-Windows.zip
echo.
echo  Give users the ZIP. They unzip and double-click:
echo    "Start SSL Certificate Tool.bat"
echo  No Python install needed on their PC.
echo.
echo  NOTE: JKS generation still needs Java keytool on PATH
echo        if you use .jks files ^(P12 works without Java^).
echo.
pause
