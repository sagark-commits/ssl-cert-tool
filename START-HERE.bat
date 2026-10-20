@REM Author: Sagar K | 2026 | MIT licence
@echo off
cd /d "%~dp0"
title SSL Deploy - ASNB
color 0A

:menu
cls
echo.
echo   ============================================================
echo        SSL CERTIFICATE DEPLOY - ASNB (EASY MODE)
echo   ============================================================
echo.
echo   No scripts to edit. Just pick a number and press Enter.
echo.
echo   1. TEST FIRST  (check certs - safe, nothing changes)
echo   2. GENERATE ONLY  (create cert files on this PC)
echo   3. DEPLOY ONLY  (upload certs already in output folder)
echo   4. DO EVERYTHING  (generate + deploy to servers)
echo   5. OPEN GUIDE  (simple instructions)
echo   6. EXIT
echo.
set /p CH=   Your choice (1-6): 

if "%CH%"=="1" goto test
if "%CH%"=="2" goto gen
if "%CH%"=="3" goto dep
if "%CH%"=="4" goto all
if "%CH%"=="5" goto guide
if "%CH%"=="6" exit /b 0
goto menu

:test
cls
echo.
echo   Checking customer certificate and key...
echo.
python ssl-auto.py inspect --input "C:\Users\sagar.k\Downloads\ASNB CERT" --key "C:\Users\sagar.k\Downloads\ASNB CERT\asnbcc.tmone.com.my.key"
echo.
echo   If you see PASS above, you can proceed to option 4.
echo.
pause
goto menu

:gen
cls
echo.
echo   Generating certificate files...
echo.
python ssl-auto.py generate --input "C:\Users\sagar.k\Downloads\ASNB CERT" --key "C:\Users\sagar.k\Downloads\ASNB CERT\asnbcc.tmone.com.my.key" --config asnb --output output\asnbcc.tmone.com.my
echo.
echo   Done. Files are in: output\asnbcc.tmone.com.my
echo.
pause
goto menu

:dep
cls
echo.
echo   STEP 1 - Test deploy (no changes on servers)...
echo.
python ssl-auto.py deploy --config asnb --certs output\asnbcc.tmone.com.my --dry-run
echo.
set /p OK=   Looks OK? Type YES to deploy for real: 
if /i not "%OK%"=="YES" goto menu
echo.
echo   Deploying to servers...
python ssl-auto.py deploy --config asnb --certs output\asnbcc.tmone.com.my
echo.
pause
goto menu

:all
cls
echo.
echo   STEP 1 - Test run (safe - nothing changes on servers)...
echo.
python ssl-auto.py run --config asnb --input "C:\Users\sagar.k\Downloads\ASNB CERT" --key "C:\Users\sagar.k\Downloads\ASNB CERT\asnbcc.tmone.com.my.key" --dry-run
echo.
set /p OK=   Looks OK? Type YES to deploy for real: 
if /i not "%OK%"=="YES" goto menu
echo.
echo   Running full generate + deploy...
python ssl-auto.py run --config asnb --input "C:\Users\sagar.k\Downloads\ASNB CERT" --key "C:\Users\sagar.k\Downloads\ASNB CERT\asnbcc.tmone.com.my.key"
echo.
pause
goto menu

:guide
start "" notepad "%~dp0EASY_DEPLOY.txt"
goto menu