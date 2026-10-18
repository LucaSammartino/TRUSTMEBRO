@echo off
rem Double-click this file. It checks your setup, installs what is missing (asking first), joins the project and starts working.
powershell -NoProfile -ExecutionPolicy Bypass -File "%~dp0setup.ps1" -Mode friend %*
echo.
pause
