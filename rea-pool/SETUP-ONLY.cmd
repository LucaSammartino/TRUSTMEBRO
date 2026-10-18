@echo off
rem For the leader: checks and installs what is needed, but does not join anything.
powershell -NoProfile -ExecutionPolicy Bypass -File "%~dp0setup.ps1" -Mode setup-only %*
echo.
pause
