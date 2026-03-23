@echo off
chcp 65001 >nul 2>&1
title MCP-CMD Server

:: ─── MCP-CMD Server Launcher ───────────────────────────────────────────────
:: Starts the MCP-CMD server in background (minimized window).
:: ─────────────────────────────────────────────────────────────────────────────

cd /d "%~dp0"

:: Check node
where node >nul 2>&1
if errorlevel 1 (
    echo [MCP-CMD] ERROR: Node.js not found in PATH.
    pause
    exit /b 1
)

:: Check node_modules
if not exist "node_modules\" (
    echo [MCP-CMD] Installing dependencies...
    call npm install --silent
    if errorlevel 1 (
        echo [MCP-CMD] ERROR: npm install failed.
        pause
        exit /b 1
    )
)

echo ============================================
echo   MCP-CMD Server v1.1.0
echo ============================================
echo [MCP-CMD] Directory : %~dp0

:: Start node in background with a known window title
start "MCP-CMD-Server" /min node "%~dp0index.js"

:: Wait for process to spawn
ping -n 3 127.0.0.1 >nul

:: Find the node.exe PID running our index.js via wmic
for /f "skip=1" %%p in ('wmic process where "commandline like '%%index.js%%' and name='node.exe'" get processid 2^>nul') do (
    for /f %%i in ("%%p") do (
        echo %%i>"%~dp0.mcp.pid"
        echo [MCP-CMD] Server started ^(PID: %%i^)
    )
)

if not exist "%~dp0.mcp.pid" (
    echo [MCP-CMD] Server started but PID not captured. 
)

echo [MCP-CMD] To stop : run stop.bat
echo.
timeout /t 2 >nul
