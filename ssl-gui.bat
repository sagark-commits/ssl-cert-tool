@echo off
REM SSL Certificate Tool - GUI Launcher
REM Double-click this file to launch the GUI

setlocal enabledelayedexpansion

REM Change to script directory
cd /d "%~dp0"

REM Try to find Python
where python >nul 2>&1
if %errorlevel% equ 0 (
    set PYTHON=python
    goto :launch
)

where python3 >nul 2>&1
if %errorlevel% equ 0 (
    set PYTHON=python3
    goto :launch
)

where py >nul 2>&1
if %errorlevel% equ 0 (
    set PYTHON=py
    goto :launch
)

REM Check common install locations
if exist "C:\Python312\python.exe" (
    set PYTHON=C:\Python312\python.exe
    goto :launch
)
if exist "C:\Python311\python.exe" (
    set PYTHON=C:\Python311\python.exe
    goto :launch
)
if exist "C:\Python310\python.exe" (
    set PYTHON=C:\Python310\python.exe
    goto :launch
)

REM Check if running in venv
if exist ".venv\Scripts\python.exe" (
    set PYTHON=.venv\Scripts\python.exe
    goto :launch
)
if exist "venv\Scripts\python.exe" (
    set PYTHON=venv\Scripts\python.exe
    goto :launch
)

echo Python not found!
echo Please install Python 3.10 or later from https://python.org
pause
exit /b 1

:launch
echo Starting SSL Certificate Tool GUI...
"%PYTHON%" ssl-gui.py %*
if %errorlevel% neq 0 (
    echo.
    echo ERROR: GUI failed to start (exit code: %errorlevel%)
    echo.
    echo Make sure dependencies are installed:
    echo   pip install cryptography pyyaml paramiko
    echo.
    pause
)