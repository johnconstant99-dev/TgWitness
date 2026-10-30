@echo off
cd /d "%~dp0.."
call "%~dp0..\Start.cmd" --demo %*
exit /b %errorlevel%
