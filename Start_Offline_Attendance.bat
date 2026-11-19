@echo off
title CS Attendance - Offline Classroom Wi-Fi Desktop Launcher
cd /d "%~dp0"

if exist "%~dp0Attendance_Offline.exe" (
    start "" "%~dp0Attendance_Offline.exe"
    exit /b 0
)

python --version >nul 2>&1
if errorlevel 1 (
    echo.
    echo [ERROR] Python was not found on this computer.
    echo Install Python 3.10+ from https://www.python.org/downloads/
    echo ^(tick "Add Python to PATH" during installation^) - or run Attendance_Offline.exe instead.
    echo.
    pause
    exit /b 1
)

python -c "import flask, segno, waitress, tzdata, webview" >nul 2>&1
if errorlevel 1 (
    echo Installing desktop app packages once ^(requires internet this first time^)...
    python -m pip install --upgrade "flask>=3.0" "segno>=1.6" "waitress>=3.0" tzdata pywebview
    if errorlevel 1 (
        echo.
        echo [ERROR] Could not install packages. Connect to the internet once and run this again.
        pause
        exit /b 1
    )
)

where pythonw >nul 2>&1
if not errorlevel 1 (
    start "" pythonw desktop_app.py
    exit /b 0
)

python desktop_app.py
