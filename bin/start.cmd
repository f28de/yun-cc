@echo off
setlocal EnableExtensions DisableDelayedExpansion
title FreeCloud Console

set "ROOT=%~dp0.."
cd /d "%ROOT%" || goto :fail

where node >nul 2>nul
if errorlevel 1 goto :nonode

for /f "usebackq tokens=* delims=" %%V in (`node -v 2^>nul`) do set "NODE_VER=%%V"
if not defined NODE_VER goto :nonode
set "NODE_VER=%NODE_VER:v=%"
for /f "tokens=1 delims=." %%M in ("%NODE_VER%") do set "NODE_MAJOR=%%M"
set /a "NODE_MAJOR_NUM=NODE_MAJOR+0" >nul 2>nul
if errorlevel 1 goto :badver
if %NODE_MAJOR_NUM% LSS 22 goto :badver

echo [FreeCloudConsole] Node %NODE_VER% - starting watchdog...
node "%ROOT%\src\main.js" %*
set "RC=%ERRORLEVEL%"
if not "%RC%"=="0" (
  echo.
  echo [FreeCloudConsole] watchdog exited with code %RC%.
  echo   - Session expired / window closed : run "start.cmd --restart" to re-authenticate.
  echo   - Dependency or environment issue  : run "node src\main.js --selftest".
  pause
)
exit /b %RC%

:nonode
echo [FreeCloudConsole] Node.js not found. Install Node.js 22 LTS or newer: https://nodejs.org/
pause
exit /b 1

:badver
echo [FreeCloudConsole] Node.js 22 or newer is required, found: %NODE_VER%
pause
exit /b 1

:fail
echo [FreeCloudConsole] Cannot enter project directory: %ROOT%
pause
exit /b 1
