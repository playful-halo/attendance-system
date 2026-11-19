@echo off
title Build Windows App ^& One-Click Setup Installer - CS Attendance
cd /d "%~dp0"

python --version >nul 2>&1
if errorlevel 1 (
    echo [ERROR] Python was not found on this computer.
    echo Install Python 3.10+ from https://www.python.org/downloads/ ^(tick "Add Python to PATH"^).
    pause
    exit /b 1
)

echo [1/3] Installing desktop app build tools ^(requires internet once^)...
python -m pip install --upgrade pyinstaller pywebview "flask>=3.0" "segno>=1.6" "waitress>=3.0" tzdata
if errorlevel 1 (
    echo.
    echo [ERROR] Failed to install packages. Make sure you are connected to the internet and try again.
    pause
    exit /b 1
)

echo.
echo [2/3] Closing any running Attendance_Offline.exe and building desktop app...
echo       This usually takes 1 to 2 minutes...
taskkill /IM Attendance_Offline.exe /F >nul 2>&1
timeout /t 1 /nobreak >nul
python -m PyInstaller --noconfirm --clean --onefile --windowed ^
    --name Attendance_Offline ^
    --icon "static\app_icon.ico" ^
    --add-data "templates;templates" ^
    --add-data "static;static" ^
    --collect-submodules segno ^
    --collect-all webview ^
    --collect-all pythonnet ^
    --collect-all clr_loader ^
    --collect-data tzdata ^
    --hidden-import waitress ^
    --hidden-import app ^
    desktop_app.py

if errorlevel 1 (
    echo.
    echo [ERROR] Desktop app build failed. Scroll up to see the error details.
    pause
    exit /b 1
)

copy /Y "dist\Attendance_Offline.exe" "%~dp0Attendance_Offline.exe" >nul
if errorlevel 1 (
    echo [WARN] Could not overwrite Attendance_Offline.exe in this folder ^(close it if open^). Using dist\Attendance_Offline.exe for installer.
)

echo.
echo [3/3] Packaging one-click lecturer installer ^(CS_Attendance_Setup.exe^)...
python -m PyInstaller --noconfirm --clean --onefile --windowed --uac-admin ^
    --name CS_Attendance_Setup ^
    --icon "static\app_icon.ico" ^
    --add-data "dist\Attendance_Offline.exe;payload" ^
    --add-data "static\app_icon.ico;payload" ^
    installer_app.py

if errorlevel 1 (
    echo.
    echo [ERROR] Setup installer build failed. Scroll up to see the error details.
    pause
    exit /b 1
)

copy /Y "dist\CS_Attendance_Setup.exe" "%~dp0CS_Attendance_Setup.exe" >nul

echo.
echo ======================================================================
echo   [DONE] Both files are now ready right inside this folder!
echo.
echo   * CS_Attendance_Setup.exe   ^(ONE-CLICK INSTALLER FOR LECTURERS^)
echo       Put ONLY this 1 file on a flash drive or send it to lecturers!
echo       Double-clicking it installs the app, sets Windows Firewall,
echo       adds Desktop/Start Menu shortcuts, and opens CS Attendance.
echo.
echo   * Attendance_Offline.exe    ^(Portable app - ready to run directly^)
echo ======================================================================
echo.
pause
