@echo off
setlocal
REM Restore the Balanced-plan defaults captured on 2026-11-15:
REM   AC standby 18000s (5h) / DC standby 600s (10min), hybrid sleep ON,
REM   hibernate already disabled.
echo [FreeCloudConsole] Restoring the previous power settings...

powercfg /setacvalueindex SCHEME_CURRENT SUB_SLEEP STANDBYIDLE 18000
powercfg /setdcvalueindex SCHEME_CURRENT SUB_SLEEP STANDBYIDLE 600
powercfg /setacvalueindex SCHEME_CURRENT SUB_SLEEP HYBRIDSLEEP 1
powercfg /setdcvalueindex SCHEME_CURRENT SUB_SLEEP HYBRIDSLEEP 1
powercfg /setactive SCHEME_CURRENT

echo [FreeCloudConsole] Done. Sleep is back to 5h on AC / 10min on DC.
endlocal & exit /b 0
