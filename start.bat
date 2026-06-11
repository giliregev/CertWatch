@echo off
title CertWatch - Starting...
echo.
echo  ==========================================
echo   CertWatch - SSL/TLS Certificate Scanner
echo  ==========================================
echo.

:: Check if Node.js is installed
where node >nul 2>&1
if %errorlevel% neq 0 (
    echo  ERROR: Node.js is not installed.
    echo.
    echo  Please download and install Node.js from:
    echo  https://nodejs.org  (choose the LTS version)
    echo.
    pause
    exit /b 1
)

:: Install dependencies if needed
if not exist "node_modules" (
    echo  Installing dependencies for the first time...
    echo  (This only happens once)
    echo.
    call npm install
    echo.
)

echo  Starting CertWatch...
echo  Browser will open automatically.
echo.
echo  To stop: close this window or press Ctrl+C
echo.

node server.js
pause
