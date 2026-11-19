"""
CS Attendance — One-Click Windows Installer (CS_Attendance_Setup.exe)
---------------------------------------------------------------------
Copyright (c) 2026 Mitchell-Fatunji Joshua. All rights reserved.

Installs Attendance_Offline.exe into C:\\Program Files\\CS Attendance,
configures Windows Defender Firewall for classroom Wi-Fi (ports 5000 & 5050),
creates Start Menu & Desktop shortcuts, registers in Windows Installed Apps,
and optionally launches the app immediately.
"""
import ctypes
import io
import os
import shutil
import subprocess
import sys
import threading
import time

APP_NAME = "CS Attendance"
APP_DISPLAY_NAME = "CS Attendance (Offline Classroom Wi-Fi)"
APP_VERSION = "1.0"
APP_PUBLISHER = "Mitchell-Fatunji Joshua"
UNINSTALL_KEY = r"Software\Microsoft\Windows\CurrentVersion\Uninstall\CSAttendanceOffline"
FW_RULE_PORT = "CS Attendance Classroom Wi-Fi"
FW_RULE_APP = "CS Attendance Classroom Wi-Fi (App)"

_FROZEN = getattr(sys, "frozen", False)
BASE_DIR = os.path.dirname(os.path.abspath(sys.executable if _FROZEN else __file__))
RESOURCE_DIR = getattr(sys, "_MEIPASS", BASE_DIR)
CREATE_NO_WINDOW = getattr(subprocess, "CREATE_NO_WINDOW", 0)


def _setup_stdio():
    if sys.stdout is None:
        sys.stdout = io.StringIO()
    if sys.stderr is None:
        sys.stderr = io.StringIO()


def _is_admin():
    if os.name != "nt":
        return True
    try:
        return bool(ctypes.windll.shell32.IsUserAnAdmin())
    except Exception:
        return False


def _relaunch_as_admin():
    if os.name != "nt":
        return False
    params = " ".join(f'"{a}"' for a in sys.argv[1:]) if not _FROZEN else ""
    target = sys.executable
    args = f'"{os.path.abspath(__file__)}" {params}'.strip() if not _FROZEN else params
    rc = ctypes.windll.shell32.ShellExecuteW(None, "runas", target, args, BASE_DIR, 1)
    return int(rc) > 32


def _find_payload_file(filename):
    candidates = [
        os.path.join(RESOURCE_DIR, "payload", filename),
        os.path.join(RESOURCE_DIR, filename),
        os.path.join(BASE_DIR, "dist", filename),
        os.path.join(BASE_DIR, filename),
        os.path.join(BASE_DIR, "static", filename),
    ]
    for path in candidates:
        if os.path.exists(path):
            return path
    return None


def _install_dir():
    pf = os.environ.get("ProgramFiles") or r"C:\Program Files"
    return os.path.join(pf, "CS Attendance")


def _run_quiet(cmd):
    return subprocess.run(cmd, capture_output=True, text=True, errors="ignore", creationflags=CREATE_NO_WINDOW)


def _write_uninstaller(install_dir):
    bat_path = os.path.join(install_dir, "Uninstall_CS_Attendance.bat")
    content = (
        "@echo off\r\n"
        "title Uninstall CS Attendance\r\n"
        "net session >nul 2>&1\r\n"
        "if errorlevel 1 (\r\n"
        '    powershell -NoProfile -Command "Start-Process -FilePath \'%~f0\' -Verb RunAs"\r\n'
        "    exit /b\r\n"
        ")\r\n"
        "echo Removing CS Attendance...\r\n"
        "taskkill /IM Attendance_Offline.exe /F >nul 2>&1\r\n"
        f'netsh advfirewall firewall delete rule name="{FW_RULE_PORT}" >nul 2>&1\r\n'
        f'netsh advfirewall firewall delete rule name="{FW_RULE_APP}" >nul 2>&1\r\n'
        'netsh advfirewall firewall delete rule name="CS Attendance Classroom Wi-Fi (Ping)" >nul 2>&1\r\n'
        'del /F /Q "%PUBLIC%\\Desktop\\CS Attendance.lnk" >nul 2>&1\r\n'
        'del /F /Q "%PUBLIC%\\Desktop\\CS Attendance (Offline).lnk" >nul 2>&1\r\n'
        'del /F /Q "%USERPROFILE%\\Desktop\\CS Attendance.lnk" >nul 2>&1\r\n'
        'del /F /Q "%USERPROFILE%\\Desktop\\CS Attendance (Offline).lnk" >nul 2>&1\r\n'
        'del /F /Q "%ProgramData%\\Microsoft\\Windows\\Start Menu\\Programs\\CS Attendance.lnk" >nul 2>&1\r\n'
        f'reg delete "HKLM\\{UNINSTALL_KEY}" /f >nul 2>&1\r\n'
        'echo CS Attendance has been uninstalled. ^(Your saved attendance records in AppData\\Local\\CSAttendance were kept safe.^)\r\n'
        "timeout /t 2 >nul\r\n"
        f'start "" /b cmd /c "ping 127.0.0.1 -n 2 >nul & rmdir /S /Q ""{install_dir}"""\r\n'
        "exit /b 0\r\n"
    )
    with open(bat_path, "w", encoding="ascii", errors="ignore") as f:
        f.write(content)
    return bat_path


def perform_install(create_desktop_shortcut=True, status_cb=None):
    def step(pct, text):
        if status_cb:
            status_cb(pct, text)

    src_exe = _find_payload_file("Attendance_Offline.exe")
    if not src_exe:
        raise FileNotFoundError("Embedded Attendance_Offline.exe payload was not found inside this installer.")
    src_ico = _find_payload_file("app_icon.ico")

    install_dir = _install_dir()
    dst_exe = os.path.join(install_dir, "Attendance_Offline.exe")
    dst_ico = os.path.join(install_dir, "app_icon.ico")

    step(15, "Closing any running CS Attendance window...")
    _run_quiet(["taskkill", "/IM", "Attendance_Offline.exe", "/F"])
    time.sleep(0.35)

    step(35, f"Installing application to {install_dir}...")
    os.makedirs(install_dir, exist_ok=True)
    shutil.copy2(src_exe, dst_exe)
    if src_ico:
        shutil.copy2(src_ico, dst_ico)
    with open(os.path.join(install_dir, "installed.flag"), "w", encoding="utf-8") as f:
        f.write(f"Installed {APP_VERSION}\n")
    uninstall_bat = _write_uninstaller(install_dir)

    step(60, "Configuring Windows Firewall for Classroom Wi-Fi...")
    _run_quiet(["netsh", "advfirewall", "firewall", "delete", "rule", f"name={FW_RULE_PORT}"])
    _run_quiet(["netsh", "advfirewall", "firewall", "delete", "rule", f"name={FW_RULE_APP}"])
    _run_quiet(["netsh", "advfirewall", "firewall", "delete", "rule", "name=CS Attendance Classroom Wi-Fi (Ping)"])
    _run_quiet([
        "netsh", "advfirewall", "firewall", "add", "rule",
        f"name={FW_RULE_APP}", "dir=in", "action=allow",
        f"program={dst_exe}", "enable=yes", "profile=any",
    ])
    _run_quiet([
        "netsh", "advfirewall", "firewall", "add", "rule",
        f"name={FW_RULE_PORT}", "dir=in", "action=allow",
        "protocol=TCP", "localport=5000,5050,5055,5080,5100", "profile=any",
    ])
    _run_quiet([
        "netsh", "advfirewall", "firewall", "add", "rule",
        "name=CS Attendance Classroom Wi-Fi (Ping)", "dir=in", "action=allow",
        "protocol=icmpv4:8,any", "remoteip=localsubnet", "profile=any",
    ])
    _run_quiet([
        "powershell", "-NoProfile", "-ExecutionPolicy", "Bypass", "-Command",
        "Get-NetFirewallApplicationFilter -ErrorAction SilentlyContinue | "
        "Where-Object { $_.Program -match '(Attendance_Offline|pythonw?)\\.exe$' } | "
        "Get-NetFirewallRule -ErrorAction SilentlyContinue | "
        "Where-Object { $_.Direction -eq 'Inbound' -and $_.Action -eq 'Block' } | "
        "Remove-NetFirewallRule -ErrorAction SilentlyContinue",
    ])

    step(80, "Creating Start Menu and Desktop shortcuts...")
    # Remove any older user-level duplicate shortcuts so Windows never displays two icons
    for old_dir in [
        os.path.join(os.environ.get("USERPROFILE", ""), "Desktop"),
        os.path.join(os.environ.get("PUBLIC", r"C:\Users\Public"), "Desktop"),
    ]:
        for old_name in ("CS Attendance (Offline).lnk", "CS Attendance.lnk"):
            p = os.path.join(old_dir, old_name)
            if os.path.exists(p):
                try:
                    os.remove(p)
                except OSError:
                    pass

    ps_targets = ["[Environment]::GetFolderPath('CommonPrograms')"]
    if create_desktop_shortcut:
        ps_targets.append("[Environment]::GetFolderPath('CommonDesktopDirectory')")
    ps_cmd = (
        "$ws = New-Object -ComObject WScript.Shell; "
        f"$exe = '{dst_exe.replace(chr(39), chr(39)*2)}'; "
        f"$wd = '{install_dir.replace(chr(39), chr(39)*2)}'; "
        f"foreach ($d in @({', '.join(ps_targets)})) {{ "
        "  if ($d -and (Test-Path $d)) { "
        "    $s = $ws.CreateShortcut((Join-Path $d 'CS Attendance.lnk')); "
        "    $s.TargetPath = $exe; $s.WorkingDirectory = $wd; $s.IconLocation = $exe + ',0'; "
        "    $s.Description = 'CS Attendance - Offline Classroom Wi-Fi'; $s.Save() "
        "  } "
        "}"
    )
    _run_quiet(["powershell", "-NoProfile", "-ExecutionPolicy", "Bypass", "-Command", ps_cmd])

    step(92, "Registering in Windows Installed Apps...")
    if os.name == "nt":
        try:
            import winreg
            with winreg.CreateKeyEx(winreg.HKEY_LOCAL_MACHINE, UNINSTALL_KEY, 0, winreg.KEY_WRITE) as k:
                winreg.SetValueEx(k, "DisplayName", 0, winreg.REG_SZ, APP_DISPLAY_NAME)
                winreg.SetValueEx(k, "DisplayVersion", 0, winreg.REG_SZ, APP_VERSION)
                winreg.SetValueEx(k, "Publisher", 0, winreg.REG_SZ, APP_PUBLISHER)
                winreg.SetValueEx(k, "DisplayIcon", 0, winreg.REG_SZ, f"{dst_exe},0")
                winreg.SetValueEx(k, "InstallLocation", 0, winreg.REG_SZ, install_dir)
                winreg.SetValueEx(k, "UninstallString", 0, winreg.REG_SZ, f'cmd.exe /c "{uninstall_bat}"')
                winreg.SetValueEx(k, "NoModify", 0, winreg.REG_DWORD, 1)
                winreg.SetValueEx(k, "NoRepair", 0, winreg.REG_DWORD, 1)
        except Exception:
            pass

    step(100, "Installation complete!")
    return dst_exe


def _launch_app_de_elevated(exe_path):
    """Use explorer.exe so the app launches as the normal desktop user rather than elevated."""
    if os.name == "nt":
        try:
            subprocess.Popen(["explorer.exe", exe_path], creationflags=CREATE_NO_WINDOW)
            return
        except Exception:
            pass
    subprocess.Popen([exe_path], creationflags=CREATE_NO_WINDOW)


def _run_tk_wizard():
    import tkinter as tk
    from tkinter import ttk, messagebox

    root = tk.Tk()
    root.title(f"{APP_NAME} Setup")
    w, h = 520, 395
    sw, sh = root.winfo_screenwidth(), root.winfo_screenheight()
    root.geometry(f"{w}x{h}+{max(20, (sw - w)//2)}+{max(20, (sh - h)//2)}")
    root.resizable(False, False)
    root.configure(bg="#f8fafc")

    ico = _find_payload_file("app_icon.ico")
    if ico and os.name == "nt":
        try:
            root.iconbitmap(ico)
        except Exception:
            pass

    # Top header banner
    hdr = tk.Frame(root, bg="#1d4ed8", height=84)
    hdr.pack(fill="x")
    hdr.pack_propagate(False)
    tk.Label(
        hdr, text="CS Attendance — Setup", font=("Segoe UI", 15, "bold"),
        fg="#ffffff", bg="#1d4ed8", anchor="w",
    ).pack(fill="x", padx=22, pady=(16, 2))
    tk.Label(
        hdr, text=f"Offline Classroom Wi-Fi Edition  ·  Built by {APP_PUBLISHER}",
        font=("Segoe UI", 9), fg="#dbeafe", bg="#1d4ed8", anchor="w",
    ).pack(fill="x", padx=22)

    body = tk.Frame(root, bg="#f8fafc", padx=24, pady=18)
    body.pack(fill="both", expand=True)

    intro = tk.Label(
        body,
        text=(
            "This wizard will install CS Attendance on this computer and configure\n"
            "everything needed for offline classroom Wi-Fi attendance:"
        ),
        font=("Segoe UI", 9), fg="#1e293b", bg="#f8fafc", justify="left", anchor="w",
    )
    intro.pack(fill="x", pady=(0, 8))

    bullets = (
        "  •  Install CS Attendance to Program Files (no Python required)\n"
        "  •  Allow student phones through Windows Firewall (ports 5000 & 5050)\n"
        "  •  Add shortcuts so the lecturer can pin it straight to the Taskbar"
    )
    tk.Label(
        body, text=bullets, font=("Segoe UI", 9), fg="#334155", bg="#f8fafc",
        justify="left", anchor="w",
    ).pack(fill="x", pady=(0, 12))

    var_desktop = tk.BooleanVar(value=True)
    var_launch = tk.BooleanVar(value=True)

    cb1 = tk.Checkbutton(
        body, text="Create a CS Attendance icon on the Desktop", variable=var_desktop,
        font=("Segoe UI", 9), bg="#f8fafc", fg="#0f172a", activebackground="#f8fafc", anchor="w",
    )
    cb1.pack(fill="x")
    cb2 = tk.Checkbutton(
        body, text="Launch CS Attendance when installation finishes", variable=var_launch,
        font=("Segoe UI", 9), bg="#f8fafc", fg="#0f172a", activebackground="#f8fafc", anchor="w",
    )
    cb2.pack(fill="x", pady=(2, 12))

    status_var = tk.StringVar(value="Ready to install.")
    status_lbl = tk.Label(body, textvariable=status_var, font=("Segoe UI", 9), fg="#475569", bg="#f8fafc", anchor="w")
    status_lbl.pack(fill="x", pady=(0, 4))

    prog = ttk.Progressbar(body, orient="horizontal", mode="determinate", maximum=100)
    prog.pack(fill="x")

    # Footer buttons
    foot = tk.Frame(root, bg="#f1f5f9", height=54, padx=22)
    foot.pack(fill="x", side="bottom")
    foot.pack_propagate(False)

    state = {"installed_exe": None, "busy": False}

    def on_cancel():
        if state["busy"]:
            return
        root.destroy()

    cancel_btn = tk.Button(
        foot, text="Cancel", font=("Segoe UI", 9), width=11,
        bg="#ffffff", fg="#334155", relief="solid", bd=1, command=on_cancel,
    )
    cancel_btn.pack(side="right", pady=11)

    action_btn = tk.Button(
        foot, text="Install", font=("Segoe UI", 9, "bold"), width=18,
        bg="#1d4ed8", fg="#ffffff", activebackground="#1e40af", activeforeground="#ffffff",
        relief="flat", cursor="hand2",
    )
    action_btn.pack(side="right", padx=(0, 10), pady=11)

    def finish_and_close():
        if state["installed_exe"] and var_launch.get():
            _launch_app_de_elevated(state["installed_exe"])
        root.destroy()

    def start_install():
        if state["installed_exe"]:
            finish_and_close()
            return
        if state["busy"]:
            return
        state["busy"] = True
        action_btn.configure(state="disabled", text="Installing...")
        cancel_btn.configure(state="disabled")
        cb1.configure(state="disabled")

        def ui_step(pct, msg):
            root.after(0, lambda: (prog.configure(value=pct), status_var.set(msg)))

        def worker():
            try:
                exe_out = perform_install(create_desktop_shortcut=var_desktop.get(), status_cb=ui_step)
                def done_ok():
                    state["busy"] = False
                    state["installed_exe"] = exe_out
                    status_lbl.configure(fg="#047857", font=("Segoe UI", 9, "bold"))
                    status_var.set("Installed! Tip: Right-click its blue icon on your taskbar -> Pin to taskbar.")
                    action_btn.configure(state="normal", text="Finish", bg="#059669", activebackground="#047857")
                root.after(0, done_ok)
            except Exception as exc:
                def done_err():
                    state["busy"] = False
                    action_btn.configure(state="normal", text="Retry Install")
                    cancel_btn.configure(state="normal")
                    status_lbl.configure(fg="#b91c1c")
                    status_var.set(f"Error: {exc}")
                    messagebox.showerror(f"{APP_NAME} Setup", f"Installation failed:\n\n{exc}")
                root.after(0, done_err)

        threading.Thread(target=worker, daemon=True).start()

    action_btn.configure(command=start_install)
    root.mainloop()


def _run_messagebox_fallback():
    MB_YESNO = 0x0004
    MB_ICONQUESTION = 0x0020
    MB_ICONINFORMATION = 0x0040
    IDYES = 6
    ans = ctypes.windll.user32.MessageBoxW(
        0,
        "Install CS Attendance (Offline Classroom Wi-Fi) on this computer?\n\n"
        "This will:\n"
        "  • Copy CS Attendance to Program Files\n"
        "  • Configure Windows Firewall for Classroom Wi-Fi\n"
        "  • Create Desktop & Start Menu shortcuts",
        f"{APP_NAME} Setup",
        MB_YESNO | MB_ICONQUESTION,
    )
    if ans != IDYES:
        return
    try:
        exe_out = perform_install(create_desktop_shortcut=True)
        ctypes.windll.user32.MessageBoxW(
            0,
            "CS Attendance has been installed!\n\n"
            "The app will now open — right-click its blue icon on your taskbar "
            "and choose 'Pin to taskbar'.",
            f"{APP_NAME} Setup",
            MB_ICONINFORMATION,
        )
        _launch_app_de_elevated(exe_out)
    except Exception as exc:
        ctypes.windll.user32.MessageBoxW(0, f"Installation failed:\n\n{exc}", f"{APP_NAME} Setup", 0x0010)


def main():
    _setup_stdio()
    if os.name == "nt" and not _is_admin():
        if _relaunch_as_admin():
            return
    try:
        _run_tk_wizard()
    except Exception:
        if os.name == "nt":
            _run_messagebox_fallback()
        else:
            raise


if __name__ == "__main__":
    main()
