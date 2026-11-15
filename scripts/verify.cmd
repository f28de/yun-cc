@echo off
setlocal EnableExtensions
set "ROOT=%~dp0.."
cd /d "%ROOT%" || exit /b 1
where node >nul 2>nul
if errorlevel 1 (
  echo [FreeCloudConsole] Node.js not found. Install Node.js 22 LTS or newer.
  exit /b 1
)

echo === 1/2 environment self-test ===
node "src\main.js" --selftest
if errorlevel 1 (
  echo [FreeCloudConsole] SELFTEST FAILED - do not deploy.
  exit /b 1
)

echo.
echo === 2/2 automated regression ===
node --test tests\smoke.test.js
if errorlevel 1 (
  echo [FreeCloudConsole] TESTS FAILED - do not deploy.
  exit /b 1
)
echo [FreeCloudConsole] local verification passed. Human acceptance gates are still required.
exit /b 0
