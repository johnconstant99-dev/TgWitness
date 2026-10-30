@echo off
setlocal EnableExtensions
cd /d "%~dp0"
title TgWitness

rem Use an existing Python 3.11+ or offer to install Python 3.12 for this Windows user.
call :find_python
if defined PYCMD goto run
echo.
echo TgWitness needs Python 3.11 or newer. It was not found on this computer.
echo.
choice /C YN /N /M "Install Python 3.12 for your Windows user now? [Y/N] "
if errorlevel 2 goto manual
call :install_python
call :find_python
if defined PYCMD goto run

:manual
echo.
echo Install Python 3.11 or newer from https://www.python.org/downloads/
echo Enable "Add python.exe to PATH" during setup, then run Start.cmd again.
echo Alternatively, install Docker Desktop and run scripts\Docker.cmd,
echo or download the Windows portable build, which includes Python.
pause
exit /b 1

:run
%PYCMD% start.py %*
set "TGWITNESS_EXIT=%errorlevel%"
if not "%TGWITNESS_EXIT%"=="0" pause
exit /b %TGWITNESS_EXIT%

:find_python
set "PYCMD="
py -3 -c "import sys; sys.exit(sys.version_info < (3, 11))" >nul 2>&1
if not errorlevel 1 (set "PYCMD=py -3" & exit /b 0)
python -c "import sys; sys.exit(sys.version_info < (3, 11))" >nul 2>&1
if not errorlevel 1 (set "PYCMD=python" & exit /b 0)
rem A fresh installation is not on PATH until a new console is opened.
for %%D in ("%LOCALAPPDATA%\Programs\Python" "%ProgramFiles%") do (
  for %%V in (313 312 311) do (
    if exist "%%~D\Python%%V\python.exe" (
      "%%~D\Python%%V\python.exe" -c "import sys" >nul 2>&1
      if not errorlevel 1 (set PYCMD="%%~D\Python%%V\python.exe"& exit /b 0)
    )
  )
)
exit /b 0

:install_python
where winget >nul 2>&1
if not errorlevel 1 (
  echo Installing Python 3.12 with winget...
  winget install --exact --id Python.Python.3.12 --scope user --silent --accept-package-agreements --accept-source-agreements
  call :find_python
  if defined PYCMD exit /b 0
  echo winget did not complete the installation. Trying the python.org installer.
)
set "PYARCH="
if /i "%PROCESSOR_ARCHITECTURE%"=="AMD64" set "PYARCH=amd64"
if /i "%PROCESSOR_ARCHITEW6432%"=="AMD64" set "PYARCH=amd64"
if /i "%PROCESSOR_ARCHITECTURE%"=="ARM64" set "PYARCH=arm64"
if not defined PYARCH (
  echo Automatic installation supports 64-bit Windows only.
  exit /b 1
)
set "PYSETUP=%TEMP%\tgwitness-python-3.12.10-%PYARCH%.exe"
echo Downloading the official Python 3.12.10 installer from python.org...
powershell -NoProfile -ExecutionPolicy Bypass -Command ^
  "$ErrorActionPreference='Stop'; $ProgressPreference='SilentlyContinue';" ^
  "[Net.ServicePointManager]::SecurityProtocol=[Net.SecurityProtocolType]::Tls12;" ^
  "Invoke-WebRequest -UseBasicParsing -Uri 'https://www.python.org/ftp/python/3.12.10/python-3.12.10-%PYARCH%.exe' -OutFile $env:PYSETUP;" ^
  "$s=Get-AuthenticodeSignature $env:PYSETUP;" ^
  "if ($s.Status -ne 'Valid' -or $s.SignerCertificate.Subject -notmatch 'Python Software Foundation') { Remove-Item $env:PYSETUP; throw 'Installer signature check failed.' }"
if errorlevel 1 (
  echo Download or signature check failed.
  exit /b 1
)
echo Installing Python 3.12.10 for this user. This takes a minute...
"%PYSETUP%" /quiet InstallAllUsers=0 PrependPath=1 Include_launcher=1 Include_test=0
set "PYSETUP_EXIT=%errorlevel%"
del "%PYSETUP%" >nul 2>&1
if not "%PYSETUP_EXIT%"=="0" (
  echo The Python installer exited with code %PYSETUP_EXIT%.
  exit /b 1
)
exit /b 0
