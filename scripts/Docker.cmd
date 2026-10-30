@echo off
setlocal EnableExtensions
rem Compose files and .env live in the project root, one level up.
cd /d "%~dp0.."
title TgWitness (Docker)
docker info >nul 2>&1
if errorlevel 1 (
    echo Install and start Docker Desktop using Linux containers, then run scripts\Docker.cmd again.
    echo Download: https://www.docker.com/products/docker-desktop/
    pause
    exit /b 1
)
docker compose version >nul 2>&1
if errorlevel 1 (
    echo Docker Compose v2.20 or newer is required. Update Docker Desktop.
    pause
    exit /b 1
)
echo Building and starting TgWitness. The first build takes a few minutes...
docker compose -f compose.yaml up -d --build --wait --wait-timeout 180
if errorlevel 1 (
    echo Startup failed. Check: docker compose logs --tail 100
    pause
    exit /b 1
)
set "PANEL="
for /f "delims=" %%A in ('docker compose -f compose.yaml port tgwitness 8787') do set "PANEL=%%A"
set "TOKEN="
for /f "delims=" %%T in ('docker compose -f compose.yaml exec -T tgwitness cat /data/panel-token.txt 2^>nul') do set "TOKEN=%%T"
echo.
echo   Panel:        http://%PANEL%
if defined TOKEN (
    echo   Panel token:  %TOKEN%
) else (
    echo   Panel token:  docker compose exec tgwitness cat /data/panel-token.txt
)
echo.
echo The collector keeps running in the background, also after this window closes.
echo Stop it with: docker compose stop     Logs: docker compose logs -f
rem Opens the panel in the default browser; the token stays in this window.
if not defined TGWITNESS_NO_BROWSER if defined PANEL start "" "http://%PANEL%"
pause
exit /b 0
