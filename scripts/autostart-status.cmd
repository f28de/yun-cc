@echo off
setlocal
set "ROOT=%~dp0.."
where node >nul 2>nul
if errorlevel 1 (
  echo [FreeCloudConsole] Node.js not found. Install Node.js 22 LTS or newer.
  exit /b 1
)
node "%ROOT%\src\autostart.js" status
exit /b %ERRORLEVEL%
