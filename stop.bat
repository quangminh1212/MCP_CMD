@echo off
chcp 65001 >nul 2>&1
title MCP-CMD Stop

:: ─── MCP-CMD Server Stopper ────────────────────────────────────────────────
:: Stops the MCP-CMD server by killing the process tree.
:: Uses 3 methods: PID file, window title, and WMIC process search.
:: ─────────────────────────────────────────────────────────────────────────────

cd /d "%~dp0"
set "KILLED=0"

:: Method 1: Kill by PID from .mcp.pid file
if exist ".mcp.pid" (
    set /p PID=<".mcp.pid"
    if defined PID (
        echo [MCP-CMD] Stopping server ^(PID: %PID%^)...
        taskkill /T /F /PID %PID% >nul 2>&1
        if not errorlevel 1 (
            set "KILLED=1"
            echo [MCP-CMD] Process %PID% terminated.
        ) else (
            echo [MCP-CMD] PID %PID% not found ^(may have already exited^).
        )
    )
    del /f /q ".mcp.pid" >nul 2>&1
)

:: Method 2: Kill by window title (backup)
for /f "tokens=2" %%a in ('tasklist /fi "windowtitle eq MCP-CMD-Server" /fo list 2^>nul ^| findstr /i "PID:"') do (
    echo [MCP-CMD] Found running instance ^(PID: %%a^), stopping...
    taskkill /T /F /PID %%a >nul 2>&1
    set "KILLED=1"
)

:: Method 3: Kill any node.exe running index.js in this directory
for /f "skip=1 tokens=1" %%p in ('wmic process where "commandline like '%%MCP_CMD\\index.js%%' and name='node.exe'" get processid 2^>nul') do (
    set "val=%%p"
    if defined val (
        for /f "tokens=*" %%i in ("%%p") do (
            if not "%%i"=="" (
                echo [MCP-CMD] Found node process ^(PID: %%i^), stopping...
                taskkill /T /F /PID %%i >nul 2>&1
                set "KILLED=1"
            )
        )
    )
)

if "%KILLED%"=="0" (
    echo [MCP-CMD] No running server found.
) else (
    echo [MCP-CMD] All MCP-CMD processes stopped.
)

:: Cleanup PID file
if exist ".mcp.pid" del /f /q ".mcp.pid" >nul 2>&1

echo.
timeout /t 2 >nul
exit /b 0
