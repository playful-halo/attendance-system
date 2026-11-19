"""
CS Attendance — Standalone Windows Desktop Application
------------------------------------------------------
Copyright (c) 2026 Mitchell-Fatunji Joshua. All rights reserved.

Runs the Offline Classroom Wi-Fi Attendance server in the background (so student
phones on the lecture hall Wi-Fi can scan & check in) while giving the lecturer
a clean, native Windows desktop window that can be pinned to the Windows taskbar
with its own icon and zero black console window.
"""
import ctypes
import io
import json
import os
import socket
import subprocess
import sys
import threading
import time
import urllib.parse
import urllib.request

APP_USER_MODEL_ID = "MitchellFatunjiJoshua.CSAttendance.Offline.1"
WINDOW_TITLE = "Attendance - Offline Classroom Wi-Fi"
DEFAULT_PORT = int(os.environ.get("PORT", "5000"))

_FROZEN = getattr(sys, "frozen", False)
if _FROZEN:
    EXE_DIR = os.path.dirname(os.path.abspath(sys.executable))
    RESOURCE_DIR = getattr(sys, "_MEIPASS", EXE_DIR)
else:
    EXE_DIR = os.path.dirname(os.path.abspath(__file__))
    RESOURCE_DIR = EXE_DIR


def _user_data_dir():
    base = os.environ.get("LOCALAPPDATA") or os.path.expanduser("~")
    path = os.path.join(base, "CSAttendance")
    os.makedirs(path, exist_ok=True)
    return path


def _setup_windowed_stdio():
    """In PyInstaller --windowed / pythonw.exe, sys.stdout & sys.stderr are None."""
    log_file = None
    if sys.stdout is None or sys.stderr is None:
        try:
            log_path = os.path.join(_user_data_dir(), "attendance_desktop.log")
            log_file = open(log_path, "a", encoding="utf-8", buffering=1)
        except Exception:
            log_file = io.StringIO()
        if sys.stdout is None:
            sys.stdout = log_file
        if sys.stderr is None:
            sys.stderr = log_file


def _set_windows_app_id():
    if os.name != "nt":
        return
    try:
        ctypes.windll.shell32.SetCurrentProcessExplicitAppUserModelID(APP_USER_MODEL_ID)
    except Exception:
        pass


def _initial_window_geometry():
    """Pick a comfortable centered window size that always leaves the title bar & taskbar visible."""
    if os.name == "nt":
        try:
            class RECT(ctypes.Structure):
                _fields_ = [("left", ctypes.c_long), ("top", ctypes.c_long),
                            ("right", ctypes.c_long), ("bottom", ctypes.c_long)]
            rc = RECT()
            SPI_GETWORKAREA = 0x0030
            if ctypes.windll.user32.SystemParametersInfoW(SPI_GETWORKAREA, 0, ctypes.byref(rc), 0):
                work_w = max(800, rc.right - rc.left)
                work_h = max(560, rc.bottom - rc.top)
                w = min(1100, int(work_w * 0.84))
                h = min(690, int(work_h * 0.84))
                x = rc.left + max(16, (work_w - w) // 2)
                y = rc.top + max(16, (work_h - h) // 2)
                return w, h, x, y
        except Exception:
            pass
    return 1080, 680, None, None


def _resolve_db_path():
    explicit = os.environ.get("ATTENDANCE_DB", "").strip()
    if explicit:
        return explicit
    if os.path.exists(os.path.join(EXE_DIR, "installed.flag")) or "program files" in EXE_DIR.lower():
        return os.path.join(_user_data_dir(), "attendance_offline.db")
    # If running from the folder (or next to Attendance_Offline.exe in a writable folder),
    # keep attendance_offline.db right beside it so existing data is preserved automatically.
    portable_db = os.path.join(EXE_DIR, "attendance_offline.db")
    if os.path.exists(portable_db):
        return portable_db
    probe = os.path.join(EXE_DIR, ".write_test_tmp")
    try:
        with open(probe, "w", encoding="utf-8") as f:
            f.write("ok")
        os.remove(probe)
        return portable_db
    except OSError:
        return os.path.join(_user_data_dir(), "attendance_offline.db")


def _ping_existing_instance(port):
    try:
        url = f"http://127.0.0.1:{port}/api/desktop/ping"
        with urllib.request.urlopen(url, timeout=0.4) as resp:
            data = json.loads(resp.read().decode("utf-8"))
            if data.get("app") == "cs-attendance-offline":
                return data
    except Exception:
        pass
    return None


def _focus_existing_window():
    if os.name != "nt":
        return False
    try:
        user32 = ctypes.windll.user32
        hwnd = user32.FindWindowW(None, WINDOW_TITLE)
        if hwnd:
            SW_RESTORE = 9
            if user32.IsIconic(hwnd):
                user32.ShowWindow(hwnd, SW_RESTORE)
            user32.SetForegroundWindow(hwnd)
            return True
    except Exception:
        pass
    return False


def _port_is_free(port):
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.settimeout(0.2)
        return s.connect_ex(("127.0.0.1", port)) != 0


def _choose_port():
    if _port_is_free(DEFAULT_PORT):
        return DEFAULT_PORT
    for candidate in (5050, 5055, 5080, 5100):
        if _port_is_free(candidate):
            return candidate
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


def _wait_until_listening(port, timeout=10.0):
    deadline = time.time() + timeout
    while time.time() < deadline:
        if not _port_is_free(port):
            return True
        time.sleep(0.04)
    return False


def _apply_win32_window_icon(ico_path):
    if os.name != "nt" or not os.path.exists(ico_path):
        return
    try:
        user32 = ctypes.windll.user32
        hwnd = user32.FindWindowW(None, WINDOW_TITLE)
        if not hwnd:
            return
        IMAGE_ICON = 1
        LR_LOADFROMFILE = 0x0010
        WM_SETICON = 0x0080
        hicon_big = user32.LoadImageW(0, ico_path, IMAGE_ICON, 48, 48, LR_LOADFROMFILE)
        hicon_small = user32.LoadImageW(0, ico_path, IMAGE_ICON, 16, 16, LR_LOADFROMFILE)
        if hicon_big:
            user32.SendMessageW(hwnd, WM_SETICON, 1, hicon_big)
        if hicon_small:
            user32.SendMessageW(hwnd, WM_SETICON, 0, hicon_small)
    except Exception:
        pass


def _confirm_close_if_live(port):
    """Return True if safe to close, False if lecturer cancelled close during a live session."""
    info = _ping_existing_instance(port)
    live_n = int((info or {}).get("live_sessions") or 0)
    if live_n <= 0:
        return True
    if os.name == "nt":
        MB_YESNO = 0x0004
        MB_ICONWARNING = 0x0030
        MB_DEFBUTTON2 = 0x0100
        IDYES = 6
        msg = (
            "A live attendance session is currently running!\n\n"
            "Closing this app will stop the classroom Wi-Fi server and "
            "prevent students from scanning the QR code.\n\n"
            "Do you still want to close Attendance?"
        )
        ans = ctypes.windll.user32.MessageBoxW(
            0, msg, WINDOW_TITLE, MB_YESNO | MB_ICONWARNING | MB_DEFBUTTON2
        )
        return ans == IDYES
    return True


def _show_error_box(message):
    if os.name == "nt":
        try:
            ctypes.windll.user32.MessageBoxW(0, str(message), WINDOW_TITLE, 0x0010)
            return
        except Exception:
            pass
    print(f"[ERROR] {message}", file=sys.stderr)


def _page_url(filename, title, message, spinner=False):
    """Build a small local HTML page (loading / error) as an embedded data: URI.

    A data: URI is used instead of a file:// URL so the page renders reliably
    in the window with no file path or disk dependency. (filename is kept for
    signature compatibility and is unused.)
    """
    spin_html = '<div class="spinner"></div>' if spinner else ""
    html = (
        "<!doctype html><html><head><meta charset=\"utf-8\">"
        "<meta name=\"viewport\" content=\"width=device-width, initial-scale=1\">"
        "<style>"
        "body{margin:0;min-height:100vh;display:flex;flex-direction:column;align-items:center;"
        "justify-content:center;font-family:'Segoe UI',Arial,sans-serif;background:#f4f6fb;color:#1f3864;"
        "text-align:center;padding:24px;box-sizing:border-box}"
        ".spinner{width:44px;height:44px;border:5px solid #d9e2f3;border-top-color:#2e74b5;"
        "border-radius:50%;animation:spin .9s linear infinite;margin-bottom:18px}"
        "@keyframes spin{to{transform:rotate(360deg)}}"
        "h1{font-size:20px;margin:0 0 8px}"
        "p{font-size:13px;color:#595659;margin:0;max-width:420px;line-height:1.5}"
        "</style></head><body>"
        + spin_html
        + "<h1>" + title + "</h1><p>" + message + "</p>"
        + "</body></html>"
    )
    return "data:text/html," + urllib.parse.quote(html)


def _show_splash():
    """Show a tiny native 'Starting…' window so the lecturer sees immediate feedback.

    The window is created with the Win32 API on its own thread (with a message
    loop), so it appears within a fraction of a second — before the Flask app,
    firewall check, server or webview engine have loaded. Call
    _close_splash(hwnd) when the real app window is ready.
    Returns (hwnd, thread), or (None, None) on non-Windows / on failure.
    """
    if os.name != "nt":
        return None, None
    result = {}
    done = threading.Event()

    def _run():
        try:
            user32 = ctypes.windll.user32
            kernel32 = ctypes.windll.kernel32
            h_instance = kernel32.GetModuleHandleW(None)

            wndproc_type = getattr(ctypes, "WINFUNCTYPE", ctypes.CFUNCTYPE)

            def wnd_proc(hwnd, msg, wparam, lparam):
                if msg == 0x0002:  # WM_DESTROY
                    user32.PostQuitMessage(0)
                    return 0
                return user32.DefWindowProcW(hwnd, msg, wparam, lparam)

            wnd_proc_cb = wndproc_type(
                ctypes.c_long, ctypes.c_void_p, ctypes.c_uint, ctypes.c_void_p, ctypes.c_void_p
            )(wnd_proc)

            class WNDCLASSW(ctypes.Structure):
                _fields_ = [
                    ("style", ctypes.c_uint),
                    ("lpfnWndProc", ctypes.c_void_p),
                    ("cbClsExtra", ctypes.c_int),
                    ("cbWndExtra", ctypes.c_int),
                    ("hInstance", ctypes.c_void_p),
                    ("hIcon", ctypes.c_void_p),
                    ("hCursor", ctypes.c_void_p),
                    ("hbrBackground", ctypes.c_void_p),
                    ("lpszMenuName", ctypes.c_void_p),
                    ("lpszClassName", ctypes.c_wchar_p),
                ]

            wc = WNDCLASSW(
                0, ctypes.cast(wnd_proc_cb, ctypes.c_void_p), 0, 0,
                h_instance, None, None, None, None, "CSAttendanceSplash",
            )
            user32.RegisterClassW(ctypes.byref(wc))

            WS_CAPTION = 0x00C00000
            WS_SYSMENU = 0x00080000
            WS_VISIBLE = 0x10000000
            WS_CHILD = 0x40000000

            width, height = 440, 150
            x = max(0, (user32.GetSystemMetrics(0) - width) // 2)
            y = max(0, (user32.GetSystemMetrics(1) - height) // 2)

            hwnd = user32.CreateWindowExW(
                0, "CSAttendanceSplash", "Starting Attendance",
                WS_CAPTION | WS_SYSMENU | WS_VISIBLE,
                x, y, width, height, None, None, h_instance, None,
            )
            if not hwnd:
                result["hwnd"] = None
                return
            user32.CreateWindowExW(
                0, "STATIC",
                "Starting Attendance...\r\nPlease wait a moment while the classroom Wi-Fi server starts.\r\nDo not open Attendance again.",
                WS_CHILD | WS_VISIBLE,
                16, 16, width - 32, height - 60, hwnd, None, h_instance, None,
            )
            user32.UpdateWindow(hwnd)
            result["hwnd"] = hwnd

            class MSG(ctypes.Structure):
                _fields_ = [
                    ("hwnd", ctypes.c_void_p),
                    ("message", ctypes.c_uint),
                    ("wParam", ctypes.c_void_p),
                    ("lParam", ctypes.c_long),
                    ("time", ctypes.c_ulong),
                    ("pt_x", ctypes.c_long),
                    ("pt_y", ctypes.c_long),
                ]

            msg = MSG()
            while user32.GetMessageW(ctypes.byref(msg), None, 0, 0) > 0:
                user32.TranslateMessage(ctypes.byref(msg))
                user32.DispatchMessageW(ctypes.byref(msg))
        except Exception:
            result["hwnd"] = None
        finally:
            done.set()

    thread = threading.Thread(target=_run, name="AttendanceSplash", daemon=True)
    thread.start()
    done.wait(timeout=2.0)
    return result.get("hwnd"), thread


def _close_splash(hwnd):
    if hwnd:
        try:
            ctypes.windll.user32.PostMessageW(hwnd, 0x0010, 0, 0)  # WM_CLOSE
        except Exception:
            pass


def _find_chromium_exe():
    if os.name != "nt":
        return None
    candidates = [
        os.path.join(os.environ.get("ProgramFiles(x86)", ""), "Microsoft", "Edge", "Application", "msedge.exe"),
        os.path.join(os.environ.get("ProgramFiles", ""), "Microsoft", "Edge", "Application", "msedge.exe"),
        os.path.join(os.environ.get("ProgramFiles", ""), "Google", "Chrome", "Application", "chrome.exe"),
        os.path.join(os.environ.get("LOCALAPPDATA", ""), "Google", "Chrome", "Application", "chrome.exe"),
    ]
    for p in candidates:
        if p and os.path.exists(p):
            return p
    return None


def _run_fallback_app_window(url):
    """Fallback chromeless app window using built-in Microsoft Edge/Chrome with isolated profile."""
    browser_exe = _find_chromium_exe()
    if browser_exe:
        profile_dir = os.path.join(_user_data_dir(), "edge_app_profile")
        os.makedirs(profile_dir, exist_ok=True)
        proc = subprocess.Popen(
            [
                browser_exe,
                f"--app={url}",
                f"--user-data-dir={profile_dir}",
                "--window-size=1080,680",
                "--no-first-run",
                "--no-default-browser-check",
            ],
            creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0),
        )
        proc.wait()
        return
    import webbrowser
    webbrowser.open(url)
    while True:
        time.sleep(1.0)


class DesktopBridge:
    def __init__(self, port=DEFAULT_PORT):
        self._window = None
        self._port = port
        self._is_fullscreen = False

    def attach(self, window):
        self._window = window

    def toggle_fullscreen(self):
        if self._window is not None:
            self._window.toggle_fullscreen()
            self._is_fullscreen = not self._is_fullscreen
            return self._is_fullscreen
        return False

    def exit_fullscreen(self):
        if self._window is not None and self._is_fullscreen:
            self._window.toggle_fullscreen()
            self._is_fullscreen = False
            return True
        return False

    def is_fullscreen(self):
        return bool(self._is_fullscreen)

    def close_app(self):
        if self._window is not None and _confirm_close_if_live(self._port):
            self._window.destroy()
            return True
        return False


def main():
    _setup_windowed_stdio()
    _set_windows_app_id()

    # If CS Attendance is already running locally, focus its window instead of starting a second server.
    for existing_port in (DEFAULT_PORT, 5050, 5055, 5080):
        if _ping_existing_instance(existing_port):
            if not _focus_existing_window():
                import webbrowser
                webbrowser.open(f"http://127.0.0.1:{existing_port}")
            return

    # Show a native "Starting…" splash immediately so the lecturer sees feedback
    # while the (slow) server startup happens. Closed when the real window is ready.
    splash_hwnd, _splash_thread = _show_splash()

    os.environ["OFFLINE_WIFI"] = "1"
    os.environ.setdefault("CLOUD_SYNC_URL", "https://cscattendance.pythonanywhere.com")
    os.environ["ATTENDANCE_DB"] = _resolve_db_path()

    port = _choose_port()
    os.environ["PORT"] = str(port)
    local_url = f"http://127.0.0.1:{port}"
    ico_path = os.path.join(RESOURCE_DIR, "static", "app_icon.ico")
    storage_dir = os.path.join(_user_data_dir(), "webview_profile")
    os.makedirs(storage_dir, exist_ok=True)

    def _start_server():
        """Import the Flask app, check the firewall, start Waitress and wait until it is listening."""
        try:
            from app import app as flask_app, windows_firewall_ok, apply_windows_firewall_uac
        except Exception as exc:
            _show_error_box(f"Could not start Attendance:\n\n{exc}")
            return False
        if os.name == "nt" and not windows_firewall_ok():
            threading.Thread(target=apply_windows_firewall_uac, name="AttendanceFirewallSetup", daemon=True).start()

        def _serve():
            try:
                from waitress import serve
                serve(
                    flask_app,
                    host="0.0.0.0",
                    port=port,
                    threads=32,
                    connection_limit=1000,
                    channel_timeout=4,
                    cleanup_interval=2,
                    backlog=2048,
                    _quiet=True,
                )
            except Exception:
                flask_app.run(host="0.0.0.0", port=port, debug=False, threaded=True, use_reloader=False)

        threading.Thread(target=_serve, name="AttendanceWiFiServer", daemon=True).start()
        if not _wait_until_listening(port, timeout=12.0):
            _show_error_box("The local classroom Wi-Fi server took too long to start.")
            return False
        return True

    try:
        import inspect
        import webview
        try:
            webview.settings["ALLOW_DOWNLOADS"] = True
        except Exception:
            pass

        bridge = DesktopBridge(port=port)
        win_w, win_h, win_x, win_y = _initial_window_geometry()
        win_kwargs = dict(
            # Show a "Starting…" page immediately so the lecturer can see the app is
            # loading and does not open it again (which would start a second server).
            url=_page_url(
                "loading.html",
                "Starting Attendance…",
                "Please wait a moment while the classroom Wi-Fi server starts. "
                "Do not open Attendance again.",
                spinner=True,
            ),
            js_api=bridge,
            width=win_w,
            height=win_h,
            min_size=(720, 480),
            resizable=True,
            fullscreen=False,
            frameless=False,
            text_select=True,
        )
        if win_x is not None and win_y is not None:
            win_kwargs["x"] = win_x
            win_kwargs["y"] = win_y
        win = webview.create_window(WINDOW_TITLE, **win_kwargs)
        bridge.attach(win)

        def _on_shown():
            _apply_win32_window_icon(ico_path)
            _close_splash(splash_hwnd)

        def _on_closing():
            return _confirm_close_if_live(port)

        win.events.shown += _on_shown
        win.events.closing += _on_closing

        def _startup_and_load():
            if _start_server():
                try:
                    win.load_url(local_url)
                except Exception:
                    time.sleep(0.5)
                    try:
                        win.load_url(local_url)
                    except Exception:
                        pass
            else:
                try:
                    win.load_url(_page_url(
                        "error.html",
                        "Attendance could not start",
                        "Please close this window and try again. "
                        "If the problem continues, restart your computer.",
                        spinner=False,
                    ))
                except Exception:
                    pass

        threading.Thread(target=_startup_and_load, name="AttendanceStartup", daemon=True).start()

        start_kwargs = {}
        sig_params = inspect.signature(webview.start).parameters
        if "private_mode" in sig_params:
            start_kwargs["private_mode"] = False
        if "storage_path" in sig_params:
            start_kwargs["storage_path"] = storage_dir
        if "icon" in sig_params and os.path.exists(ico_path):
            start_kwargs["icon"] = ico_path
        webview.start(**start_kwargs)
    except Exception as exc:
        print(f"[Desktop] pywebview unavailable ({exc}); using Edge/Chrome app window fallback.", file=sys.stderr)
        if _start_server():
            _close_splash(splash_hwnd)
            _run_fallback_app_window(local_url)
        else:
            _close_splash(splash_hwnd)

    os._exit(0)


if __name__ == "__main__":
    main()
