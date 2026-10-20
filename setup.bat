@REM Author: Sagar K | 2026 | MIT licence
@echo off
setlocal
cd /d "%~dp0"
python setup.py
exit /b %ERRORLEVEL%
