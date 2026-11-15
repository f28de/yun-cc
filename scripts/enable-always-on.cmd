@echo off
setlocal
REM ---------------------------------------------------------------
REM Keep this machine alive while you are away.
REM Disables: sleep (standby), hibernate, hybrid sleep - AC and DC.
REM The DISPLAY timeout is intentionally left untouched.
REM Revert with: scripts\restore-power-plan.cmd
REM ---------------------------------------------------------------
echo [FreeCloudConsole] Applying "always on" power settings...

powercfg /change standby-timeout-ac 0
powercfg /change standby-timeout-dc 0
powercfg /change hibernate-timeout-ac 0
powercfg /change hibernate-timeout-dc 0
powercfg /setacvalueindex SCHEME_CURRENT SUB_SLEEP HYBRIDSLEEP 0
powercfg /setdcvalueindex SCHEME_CURRENT SUB_SLEEP HYBRIDSLEEP 0
powercfg /setactive SCHEME_CURRENT

echo [FreeCloudConsole] Done. Sleep / hibernate / hybrid sleep are now disabled.
endlocal & exit /b 0
