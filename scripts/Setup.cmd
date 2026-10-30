@echo off
cd /d "%~dp0.."
call "%~dp0..\Start.cmd" --setup-only %*
exit /b %errorlevel%
