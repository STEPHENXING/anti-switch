@echo off
setlocal
chcp 65001 >nul
title Antigravity - Save Account
set "PYTHONIOENCODING=utf-8"
set "SCRIPT=%USERPROFILE%\.gemini\scripts\agy-account.py"

call :findpy
if errorlevel 1 goto nopy
if not exist "%SCRIPT%" goto noscript

"%PY%" "%SCRIPT%" save
if errorlevel 1 (
  echo.
  pause
  exit /b 1
)
timeout /t 10 >nul
exit /b 0

:findpy
set "PY="
for /d %%D in ("%USERPROFILE%\.workbuddy\binaries\python\versions\*") do (
  if exist "%%~D\python.exe" set "PY=%%~D\python.exe"
)
if defined PY if exist "%PY%" exit /b 0
for /d %%D in ("%LOCALAPPDATA%\Programs\Python\*") do (
  if exist "%%~D\python.exe" set "PY=%%~D\python.exe"
)
if defined PY if exist "%PY%" exit /b 0
for /d %%D in ("C:\Python3*") do (
  if exist "%%~D\python.exe" set "PY=%%~D\python.exe"
)
if defined PY if exist "%PY%" exit /b 0
python -c "import sys" >nul 2>nul
if not errorlevel 1 (
  set "PY=python"
  exit /b 0
)
set "PY="
exit /b 1

:nopy
echo [ERROR] Python not found.
echo Tried: %USERPROFILE%\.workbuddy\binaries\python\versions\*
echo        %LOCALAPPDATA%\Programs\Python\*
echo        C:\Python3*
echo Install Python 3 and rerun.
echo.
pause
exit /b 1

:noscript
echo [ERROR] Script missing: %SCRIPT%
echo.
pause
exit /b 1
