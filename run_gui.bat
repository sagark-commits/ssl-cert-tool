@REM Author: Sagar K | 2026 | MIT licence
@echo off
cd /d "%~dp0"
python -m ssl_cert_tool.gui
if errorlevel 1 pause
