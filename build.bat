@echo off
setlocal
title Security Scanner — Build

echo =============================================
echo  Windows 11 Security Scanner — EXE Builder
echo =============================================
echo.

:: Check Python
python --version >nul 2>&1
if errorlevel 1 (
    echo ERROR: Python not found. Install Python 3.10+ from https://python.org
    pause & exit /b 1
)

:: Install / upgrade PyInstaller
echo [1/3] Installing PyInstaller...
pip install --quiet --upgrade pyinstaller
if errorlevel 1 (
    echo ERROR: pip install failed.
    pause & exit /b 1
)

:: Clean previous build artefacts
echo [2/3] Cleaning previous build...
if exist build  rmdir /s /q build
if exist dist   rmdir /s /q dist

:: Build
echo [3/3] Building SecurityScanner.exe ...
pyinstaller security_scanner.spec
if errorlevel 1 (
    echo.
    echo ERROR: Build failed. See output above.
    pause & exit /b 1
)

echo.
echo =============================================
echo  SUCCESS!
echo  Executable: dist\SecurityScanner.exe
echo  Double-click it to launch (UAC will prompt
echo  for Administrator rights automatically).
echo =============================================
echo.
pause
