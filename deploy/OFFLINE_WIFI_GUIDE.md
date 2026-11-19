# Offline Classroom Wi-Fi + Cloud Sync Guide

Copyright (c) 2026 Mitchell-Fatunji Joshua. All rights reserved.

This edition lets lecturers take attendance **100% offline inside a lecture hall** over a local Wi-Fi router (zero mobile data for students, zero GPS popups, room-level Wi-Fi geofence) and **sync completed sessions back to the online HOD dashboard** (`https://cscattendance.pythonanywhere.com`) whenever the laptop has internet.

---

## 1. One-Time Setup on the Online Server (PythonAnywhere)
Upload the updated `attendance_update.zip` to PythonAnywhere, unzip (`unzip -o attendance_update.zip`), and click **Reload** on the Web tab.
- The online site continues working normally for online classes, and now also accepts sync connections from offline lecturer laptops.

---

## 2. One-Time Setup on a Lecturer's Windows Laptop

### Easiest method — One-Click Installer (`CS_Attendance_Setup.exe`)
1. Copy **only the single file `CS_Attendance_Setup.exe`** (built once on your developer PC via `Build_Windows_EXE.bat`) onto a flash drive or send it to the lecturer. Lecturers do **not** need Python or any code folder.
2. Double-click **`CS_Attendance_Setup.exe`** → click **Yes** on the Windows prompt → click **Install**.
   - Automatically installs CS Attendance to `Program Files`, configures Windows Firewall for classroom Wi-Fi, creates Desktop & Start Menu shortcuts, and opens the app.
3. While the app is open, **right-click its blue icon on the Windows taskbar → Pin to taskbar**.
4. **Link the laptop once (with internet):**
   Confirm the online server address (`https://cscattendance.pythonanywhere.com`) and sign in with your normal **Staff ID and password** — your courses and enrolled students download automatically in ~2 seconds.

*(Manual alternative without the installer: right-click `Allow_Windows_Firewall.bat` → Run as administrator once, then run `Attendance_Offline.exe` or `Start_Offline_Attendance.bat`.)*

---

## 3. Taking Attendance in the Lecture Hall (100% Offline)

1. Plug in the classroom Wi-Fi router (no SIM card or internet cable needed) and connect the **lecturer's laptop** to that Wi-Fi.
2. Double-click `Start_Offline_Attendance.bat` (or `Attendance_Offline.exe`).
3. Click **Start attendance** on your course and project the QR screen:
   - Students connect their phones to the same classroom Wi-Fi.
   - *(Tip shown on projector: if a phone asks "Wi-Fi has no internet — stay connected?", tap **Stay connected / Keep Wi-Fi**, or switch off Mobile Data for 10 seconds while scanning.)*
   - Students scan the rotating QR, log in with their normal matric number & password, and tap **Confirm** (instant — no GPS prompt).
4. Run **Spot check** if desired, then click **End session** when finished.

---

## 4. Syncing Back to the Online HOD Dashboard

Whenever the lecturer's laptop next has internet (office Wi-Fi or phone hotspot for 5 seconds):
1. Open the laptop app and click **↻ Sync now (upload sessions & refresh roster)** on the home page.
2. All completed offline sessions, newly enrolled students, password updates, and spot-check results upload to the online HOD dashboard without duplicates, and any new online enrolments download to the laptop at the same time.

*(For a permanent hall PC that never connects to the internet, open "Server settings & offline USB file sync" to transfer `.json` files via flash drive.)*
