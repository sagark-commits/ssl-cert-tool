@REM Author: Sagar K | 2026 | MIT licence
@echo off
setlocal
cd /d "%~dp0"

REM Auto-install dependencies if missing
python -c "import cryptography" 2>nul || (
  echo Installing dependencies...
  pip install -r requirements.txt
)

if "%~1"=="" (
  echo Usage: renew.bat INPUT_PATH KEY_PATH
  echo Example: renew.bat C:\certs C:\certs\domain.key
  exit /b 1
)
if "%~2"=="" (
  echo Usage: renew.bat INPUT_PATH KEY_PATH
  exit /b 1
)
python ssl-pipeline.py all --input %1 --key %2
exit /b %ERRORLEVEL%