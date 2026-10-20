@REM Author: Sagar K | 2026 | MIT licence
@echo off
cd /d "%~dp0"
echo.
echo WARNING: This will update certificates on ASNB servers.
echo.
set /p OK=Type YES to continue: 
if /i not "%OK%"=="YES" exit /b 1
python ssl-auto.py run --config asnb --input "C:\Users\sagar.k\Downloads\ASNB CERT" --key "C:\Users\sagar.k\Downloads\ASNB CERT\asnbcc.tmone.com.my.key"
pause