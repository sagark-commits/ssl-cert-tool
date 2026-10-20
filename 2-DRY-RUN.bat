@REM Author: Sagar K | 2026 | MIT licence
@echo off
cd /d "%~dp0"
echo DRY RUN - Shows what would happen. Servers NOT changed.
python ssl-auto.py run --config asnb --input "C:\Users\sagar.k\Downloads\ASNB CERT" --key "C:\Users\sagar.k\Downloads\ASNB CERT\asnbcc.tmone.com.my.key" --dry-run
pause