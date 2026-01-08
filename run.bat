@echo off
echo Server Auto-Restart Script
echo Will restart every 1 hour for listening to new contracts
:loop
echo Starting server at %time%
:: Start server in background
start /b cmd /c "node server.js"
:: Wait a couple seconds to make sure server2.pid exists
timeout /t 2 /nobreak
:: Read the PID from server2.pid
set /p SERVER_PID=<server.pid
if not defined SERVER_PID (
    echo ERROR: Could not read PID from server.pid - exiting.
    exit /b
)
echo Server started with PID %SERVER_PID%, will restart in 1 hour...
:: Wait for 1 hour (3600 seconds)
timeout /t 3600 /nobreak
:: Kill only the process from the PID file
taskkill /f /pid %SERVER_PID%
if %errorlevel% neq 0 (
    echo WARNING: Failed to kill process %SERVER_PID%. It may have already exited.
)
:: Optional - wait a bit to ensure clean shutdown
echo Waiting 30 seconds before restart...
timeout /t 30 /nobreak
echo Restarting server...
goto loop