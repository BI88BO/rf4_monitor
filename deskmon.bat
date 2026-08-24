@echo off
setlocal

pushd "%~dp0" || (
    echo [deskmon] ERROR: failed to enter script directory.
    pause
    exit /b 1
)

rem --- Self-elevate to Administrator (needed for hosts file and port 443) ---
net session >nul 2>&1
if errorlevel 1 (
    echo [deskmon] Requesting administrator privileges...
    powershell -NoProfile -Command "Start-Process cmd -ArgumentList '/c','%~f0' -Verb RunAs -WindowStyle Hidden"
    popd
    exit /b 0
)

echo [deskmon] ==============================================
echo [deskmon]  DeskMon tray launcher
echo [deskmon] ==============================================

rem --- Start the tray program in the background (no console window) ---
if exist ".venv\Scripts\pythonw.exe" (
    start "" ".venv\Scripts\pythonw.exe" "deskmon_tray.py"
) else (
    start "" pyw -3 "deskmon_tray.py"
)

echo [deskmon] Tray icon launched. Use the tray menu to start/stop monitoring.
echo [deskmon] To stop everything, right-click the tray icon and choose "Exit".
popd
exit /b 0
