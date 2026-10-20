@REM Author: Sagar K | 2026 | MIT licence
@echo off
REM =============================================================================
REM SSL Certificate Tool - Offline Installer for Windows
REM =============================================================================
REM
REM INSTRUCTIONS:
REM 1. Copy the entire ssl-cert-tool folder to your Windows machine
REM 2. Open Command Prompt in the offline\ directory
REM 3. Run: install-offline.bat
REM
REM =============================================================================

setlocal enabledelayedexpansion
cd /d "%~dp0"
set "TOOL_DIR=%~dp0.."

echo.
echo ==============================================
echo   SSL Certificate Tool - Offline Installer
echo ==============================================
echo.

if exist "%TOOL_DIR%\ssl-auto.exe" (
    echo Found standalone executable!
    echo.
    echo No installation needed - the exe is self-contained.
    echo.
    echo Run the tool with:
    echo   cd %TOOL_DIR%
    echo   ssl-auto.exe --wizard
    echo.
    echo Or use the menu:
    echo   run.bat
    echo.
    pause
    exit /b 0
)

if exist "%TOOL_DIR%\dist\windows\ssl-auto.exe" (
    echo Found Windows binary in dist\windows\
    copy "%TOOL_DIR%\dist\windows\ssl-auto.exe" "%TOOL_DIR%\ssl-auto.exe"
    echo.
    echo Copied executable to: %TOOL_DIR%\ssl-auto.exe
    echo.
    echo Run the tool with:
    echo   cd %TOOL_DIR%
    echo   ssl-auto.exe --wizard
    echo.
    pause
    exit /b 0
)

python --version >nul 2>&1
if errorlevel 1 (
    echo ERROR: Python not found!
    echo.
    echo Options:
    echo   1. Install Python 3.8+ from https://python.org
    echo   2. Use a pre-built binary (copy dist\windows\ssl-auto.exe)
    echo.
    pause
    exit /b 1
)

echo Python found.
echo.

if not exist "wheels\*.whl" (
    echo WARNING: No wheels found in offline\wheels\
    echo.
    echo To prepare offline dependencies:
    echo   1. On a machine WITH internet, run: python download-deps.py
    echo   2. Copy the offline\ folder to this machine
    echo.
    
    echo Attempting online installation...
    pip install -r "%TOOL_DIR%\requirements.txt"
    if errorlevel 1 (
        echo.
        echo ERROR: Cannot install dependencies.
        echo Please prepare offline wheels using download-deps.py
        pause
        exit /b 1
    )
    echo.
    echo Online installation successful!
) else (
    echo Installing dependencies from offline wheels...
    echo.
    
    pip install --no-index --find-links=wheels\ -r requirements.txt
    if errorlevel 1 (
        echo.
        echo Some packages failed. Trying core packages only...
        pip install --no-index --find-links=wheels\ cryptography paramiko PyYAML colorama
    )
)

echo.
echo ==============================================
echo   Installation Complete!
echo ==============================================
echo.
echo Run the tool with:
echo   cd %TOOL_DIR%
echo   python ssl-auto.py --wizard
echo.
echo Or use the interactive menu:
echo   run.bat
echo.
echo Quick commands:
echo   python ssl-auto.py generate --input ^<certs^> --key ^<key^>
echo   python ssl-auto.py deploy --certs ^<output\^> --config ^<name^>
echo   python ssl-auto.py run --input ^<certs^> --key ^<key^> --config ^<name^>
echo.
pause