@REM Author: Sagar K | 2026 | MIT licence
@echo off
setlocal enabledelayedexpansion

echo ============================================
echo  SSL Certificate Tool - Windows All-in-One
echo  Builds GUI + CLI with NO Python required
echo ============================================
echo.

cd /d "%~dp0"

for /f %%v in ('python -c "from ssl_cert_tool import __version__ as v; print(v)"') do set VERSION=%%v

python --version >nul 2>&1
if errorlevel 1 (
    echo ERROR: Python is required ON THE BUILD MACHINE only.
    echo Install Python 3.10+ from https://python.org
    echo End users of the package do NOT need Python.
    if not defined NO_PAUSE pause
    exit /b 1
)

echo Installing build dependencies...
python -m pip install --upgrade pip >nul
python -m pip install -r requirements.txt "pyinstaller>=6.3" "setuptools>=71" >nul
if errorlevel 1 (
    echo ERROR: pip install failed
    if not defined NO_PAUSE pause
    exit /b 1
)

REM Only the template and examples are shipped: customer configs (which can hold
REM hostnames and passwords) must never be bundled into the exe or the package.
set STAGE=build\package-configs
if exist "%STAGE%" rmdir /s /q "%STAGE%"
mkdir "%STAGE%"
copy /Y configs\template.yaml "%STAGE%\" >nul
copy /Y configs\example-*.yaml "%STAGE%\" >nul 2>nul
copy /Y configs\*.example.yaml "%STAGE%\" >nul 2>nul

REM Versioned output folder: building never deletes an earlier release.
set OUT=dist\SSLCertTool-Windows-v%VERSION%
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
    --add-data "%STAGE%;configs" ^
    --add-data "catalogues;catalogues" ^
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
    if not defined NO_PAUSE pause
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
    --add-data "%STAGE%;configs" ^
    --add-data "catalogues;catalogues" ^
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
    if not defined NO_PAUSE pause
    exit /b 1
)

echo.
echo Copying configs and docs into package...
xcopy /E /I /Y "%STAGE%" "%OUT%\configs\" >nul
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
echo Smoke-testing the built executables...
"%OUT%\ssl-auto.exe" --version
if errorlevel 1 (
    echo ERROR: the built ssl-auto.exe failed its smoke test
    if not defined NO_PAUSE pause
    exit /b 1
)

echo Writing SHA-256 checksums...
REM LF line endings, so `sha256sum -c SHA256SUMS.txt` works on Linux/macOS/Git Bash too.
powershell -NoProfile -Command "$l = Get-FileHash -Algorithm SHA256 '%OUT%\*.exe' | ForEach-Object { '{0}  {1}' -f $_.Hash.ToLower(), (Split-Path $_.Path -Leaf) }; [IO.File]::WriteAllText((Join-Path (Get-Location) '%OUT%\SHA256SUMS.txt'), (($l -join [char]10) + [char]10))"

echo.
echo Creating ZIP...
powershell -NoProfile -Command "Compress-Archive -Path '%OUT%\*' -DestinationPath 'dist\SSLCertTool-Windows-v%VERSION%.zip' -Force"

echo.
echo ============================================
echo  BUILD COMPLETE
echo ============================================
echo.
echo  Folder: %OUT%\
echo  Zip:    dist\SSLCertTool-Windows-v%VERSION%.zip
echo.
echo  Give users the ZIP. They unzip and double-click:
echo    "Start SSL Certificate Tool.bat"
echo  No Python install needed on their PC.
echo.
echo  NOTE: no Java needed. .jks files are made with Java's keytool when it is
echo        installed, otherwise with the built-in JKS writer.
echo.
if not defined NO_PAUSE pause