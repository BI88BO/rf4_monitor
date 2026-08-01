@echo off
setlocal

pushd "%~dp0" || (
    echo [rf4] ERROR: failed to enter script directory.
    pause
    exit /b 1
)

rem --- Self-elevate to Administrator (needed for hosts file and port 443) ---
net session >nul 2>&1
if errorlevel 1 (
    echo [rf4] Requesting administrator privileges...
    powershell -NoProfile -Command "Start-Process cmd -ArgumentList '/c','%~f0' -Verb RunAs -WindowStyle Hidden"
    popd
    exit /b 0
)

echo [rf4] ==============================================
echo [rf4]  RF4 Monitor tray launcher
echo [rf4] ==============================================

rem --- Start the tray program in the background (no console window) ---
if exist ".venv\Scripts\pythonw.exe" (
    start "" ".venv\Scripts\pythonw.exe" "rf4_tray.py"
) else (
    start "" pyw -3 "rf4_tray.py"
)

echo [rf4] Tray icon launched. Use the tray menu to start/stop monitoring.
echo [rf4] To stop everything, right-click the tray icon and choose "Exit".
popd
exit /b 0
