@REM Author: Sagar K | 2026 | MIT licence
@echo off
cd /d "%~dp0"
echo TEST ONLY - No server changes
python ssl-auto.py inspect --input "C:\Users\sagar.k\Downloads\ASNB CERT" --key "C:\Users\sagar.k\Downloads\ASNB CERT\asnbcc.tmone.com.my.key"
pause