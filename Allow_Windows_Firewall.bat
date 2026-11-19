@echo off
title Allow Classroom Wi-Fi Attendance through Windows Firewall
net session >nul 2>&1
if errorlevel 1 (
    echo.
    echo Please right-click "Allow_Windows_Firewall.bat" and choose "Run as administrator".
    echo ^(Needed once on a Windows laptop so student phones on classroom Wi-Fi can reach port 5000.^)
    echo.
    pause
    exit /b 1
)

netsh advfirewall firewall delete rule name="CS Attendance Classroom Wi-Fi" >nul 2>&1
netsh advfirewall firewall delete rule name="CS Attendance Classroom Wi-Fi (Ping)" >nul 2>&1
netsh advfirewall firewall add rule name="CS Attendance Classroom Wi-Fi" dir=in action=allow protocol=TCP localport=5000,5050,5055,5080,5100 profile=any
netsh advfirewall firewall add rule name="CS Attendance Classroom Wi-Fi (Ping)" dir=in action=allow protocol=icmpv4:8,any remoteip=localsubnet profile=any
if exist "%~dp0Attendance_Offline.exe" (
    netsh advfirewall firewall delete rule name="CS Attendance Portable App" >nul 2>&1
    netsh advfirewall firewall add rule name="CS Attendance Portable App" dir=in action=allow program="%~dp0Attendance_Offline.exe" enable=yes profile=any >nul 2>&1
)
powershell -NoProfile -ExecutionPolicy Bypass -Command "Get-NetFirewallApplicationFilter -ErrorAction SilentlyContinue | Where-Object { $_.Program -match '(Attendance_Offline|pythonw?)\.exe$' } | Get-NetFirewallRule -ErrorAction SilentlyContinue | Where-Object { $_.Direction -eq 'Inbound' -and $_.Action -eq 'Block' } | Remove-NetFirewallRule -ErrorAction SilentlyContinue" >nul 2>&1

echo.
echo [OK] Windows Firewall is now configured for CS Attendance ^(ports 5000, 5050, 5055, 5080, 5100^).
echo Students connected to the same classroom Wi-Fi or Hotspot can now reach this laptop.
echo.
pause
