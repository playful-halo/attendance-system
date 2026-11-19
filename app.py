"""
CS Department Attendance System
--------------------------------
Copyright (c) 2026 Mitchell-Fatunji Joshua. All rights reserved.
See LICENSE for terms. Unauthorised copying or redistribution is prohibited.

Solves three problems with paper attendance sheets:
  1. Slow distribution      -> everyone checks in at the same time from their own phone.
  2. Students missed         -> the QR code is projected; anyone in the room can reach it.
  3. Signing for others      -> rotating QR tokens (expire every 15s), one check-in per
                                student per session, and device-reuse flagging.

Run:  python app.py      (then open http://localhost:5000)
"""
import base64
import csv
import hashlib
import hmac
import io
import json
import os
import re
import secrets
import socket
import sqlite3
import struct
import subprocess
import sys
import threading
import time
import urllib.error
import urllib.request
import uuid
import webbrowser
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timedelta, timezone
from functools import wraps

import segno
from flask import (Flask, abort, g, jsonify, redirect, render_template,
                   request, send_file, session, url_for)
from flask import flash as _flask_flash
from urllib.parse import urlencode, urlsplit
from werkzeug.security import check_password_hash, generate_password_hash

_FROZEN = getattr(sys, "frozen", False)
if _FROZEN:
    BASE_DIR = os.path.dirname(os.path.abspath(sys.executable))
    RESOURCE_DIR = getattr(sys, "_MEIPASS", BASE_DIR)
else:
    BASE_DIR = os.path.dirname(os.path.abspath(__file__))
    RESOURCE_DIR = BASE_DIR
DB_PATH = os.environ.get("ATTENDANCE_DB", os.path.join(BASE_DIR, "attendance.db"))

# Offline Classroom Wi-Fi Edition: when OFFLINE_WIFI=1 (or running as a compiled Windows .exe),
# the classroom Wi-Fi router itself acts as the hall geofence (no GPS prompt, zero external
# network calls) and completed sessions sync back to the online HOD server when online.
OFFLINE_WIFI = os.environ.get("OFFLINE_WIFI", "1" if _FROZEN else "0").strip() == "1"
DEFAULT_CLOUD_URL = os.environ.get("CLOUD_SYNC_URL", "https://cscattendance.pythonanywhere.com").strip().rstrip("/")

# Token settings -------------------------------------------------------------
ROTATE_SECONDS = 10          # QR / code changes every 10 seconds
SCAN_TICKET_SECONDS = 300    # after a valid scan the phone has this long to log in, fix location settings and confirm
# Public address students' phones can reach. If unset, the QR uses whatever host
# the lecturer's browser used (fine when everyone is on the same network/domain).
PUBLIC_BASE_URL = os.environ.get("PUBLIC_BASE_URL", "").strip().rstrip("/")
# Show the demo-account hint on the login page only when explicitly enabled (local/sandbox demos).
SHOW_DEMO_LOGINS = os.environ.get("SHOW_DEMO_LOGINS", "0").strip() == "1"
# ---- Product identity / watermark (change in ONE place) ----
APP_NAME = os.environ.get("APP_NAME", "Attendance").strip() or "Attendance"
APP_VERSION = "1.0"
# Stylesheet cache-buster: SHA-256 content hash of style.css so every CSS change gets a fresh URL
# immediately (even inside PyInstaller --onefile or extracted zips where timestamps stay fixed).
try:
    with open(os.path.join(RESOURCE_DIR, "static", "style.css"), "rb") as _css_f:
        STATIC_VERSION = hashlib.sha256(_css_f.read()).hexdigest()[:10]
except OSError:
    STATIC_VERSION = APP_VERSION
APP_AUTHOR = "Mitchell-Fatunji Joshua"
APP_YEAR = "2026"
COPYRIGHT = f"\u00a9 {APP_YEAR} {APP_AUTHOR}. All rights reserved."
# All times are stored as UTC timestamps and *displayed* in this timezone, whatever the server's clock is set to.
from zoneinfo import ZoneInfo
try:
    APP_TZ = ZoneInfo(os.environ.get("APP_TIMEZONE", "Africa/Lagos").strip() or "Africa/Lagos")
except Exception:
    try:
        APP_TZ = ZoneInfo("Africa/Lagos")
    except Exception:
        # Windows lacks an OS IANA timezone database unless 'tzdata' is installed;
        # Africa/Lagos (West Africa Time) is permanently UTC+1 with no daylight saving.
        APP_TZ = timezone(timedelta(hours=1), name="WAT")


def local_dt(ts=None):
    """datetime in the app's display timezone (from a UTC timestamp, or now)."""
    return datetime.fromtimestamp(ts if ts is not None else time.time(), tz=APP_TZ)
DEFAULT_DEMO_PASSWORDS = {"admin123", "lecturer123"}
GRACE_SLOTS = 1              # previous slot is still accepted (scan + network delay)
# A screenshot/forwarded link must be *opened* within ~20 s. Opening it issues a
# scan ticket bound to that phone, so the student can take their time logging in
# and confirming - but the ticket cannot be handed to another phone.

def _resolve_secret_key():
    env_key = os.environ.get("SECRET_KEY", "").strip()
    if env_key:
        return env_key
    try:
        os.makedirs(os.path.dirname(os.path.abspath(DB_PATH)), exist_ok=True)
        con = sqlite3.connect(DB_PATH, timeout=15.0)
        con.execute("CREATE TABLE IF NOT EXISTS settings (key TEXT PRIMARY KEY, value TEXT NOT NULL)")
        row = con.execute("SELECT value FROM settings WHERE key='_secret_key'").fetchone()
        if row and row[0]:
            con.close()
            return row[0]
        key = secrets.token_hex(32)
        con.execute("INSERT OR REPLACE INTO settings (key, value) VALUES ('_secret_key', ?)", (key,))
        con.commit()
        con.close()
        return key
    except Exception:
        return secrets.token_hex(32)


app = Flask(__name__,
            template_folder=os.path.join(RESOURCE_DIR, "templates"),
            static_folder=os.path.join(RESOURCE_DIR, "static"))
app.config["SECRET_KEY"] = _resolve_secret_key()
app.config["PERMANENT_SESSION_LIFETIME"] = timedelta(days=90)
app.config["SEND_FILE_MAX_AGE_DEFAULT"] = 86400

# Behind a reverse proxy / preview host: trust X-Forwarded-* so request.is_secure
# and url_for(_external=True) (used inside the QR) reflect the public https URL.
from werkzeug.middleware.proxy_fix import ProxyFix
from flask.sessions import SecureCookieSessionInterface
app.wsgi_app = ProxyFix(app.wsgi_app, x_for=1, x_proto=1, x_host=1, x_port=1)


def _is_local():
    """Plain-http connection (localhost / classroom Wi-Fi / LAN IP without TLS)."""
    if request.is_secure or "https" in request.headers.get("X-Forwarded-Proto", "").lower():
        return False
    if request.host.split(":")[0].endswith(".e2b.app"):
        return False
    return True


def _is_https():
    return not _is_local()


import inspect as _inspect
from flask import Response as _Response
# Werkzeug < 3.1 has no `partitioned` cookie flag; only pass it when supported.
_SUPPORTS_PARTITIONED = "partitioned" in _inspect.signature(_Response.set_cookie).parameters


def cookie_attrs():
    """Public HTTPS hosts (incl. when the app is embedded in an iframe) need
    SameSite=None; Secure; Partitioned so browsers that block third-party cookies
    still accept it. Plain local http rejects that combination, so use Lax there."""
    if _is_https():
        attrs = dict(samesite="None", secure=True, partitioned=True)
    else:
        attrs = dict(samesite="Lax", secure=False, partitioned=False)
    if not _SUPPORTS_PARTITIONED:
        attrs.pop("partitioned")
    return attrs


class AdaptiveSessionInterface(SecureCookieSessionInterface):
    def get_cookie_secure(self, app):
        return cookie_attrs()["secure"]

    def get_cookie_samesite(self, app):
        return cookie_attrs()["samesite"]

    def get_cookie_partitioned(self, app):
        return cookie_attrs().get("partitioned", False)


app.session_interface = AdaptiveSessionInterface()


# ---------------------------------------------------------------------------
# Database
# ---------------------------------------------------------------------------
SCHEMA = """
CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    matric TEXT UNIQUE NOT NULL,          -- matric no. for students, staff id for lecturers
    name TEXT NOT NULL,
    password_hash TEXT NOT NULL,
    role TEXT NOT NULL CHECK(role IN ('student','lecturer','admin')),
    created_at TEXT NOT NULL,
    must_change_pw INTEGER NOT NULL DEFAULT 0   -- 1 = temporary password, force change at next login
);
CREATE TABLE IF NOT EXISTS courses (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    code TEXT UNIQUE NOT NULL,            -- e.g. CSC301
    title TEXT NOT NULL,
    lecturer_id INTEGER NOT NULL REFERENCES users(id),
    join_code TEXT UNIQUE NOT NULL,       -- students use this to enrol
    created_at TEXT NOT NULL,
    geo_lat REAL, geo_lng REAL,           -- lecture hall location (NULL = no geofence)
    geo_radius_m INTEGER NOT NULL DEFAULT 100,
    network_mode TEXT NOT NULL DEFAULT 'off',  -- 'off' | 'flag' | 'block'
    archived INTEGER NOT NULL DEFAULT 0
);
CREATE TABLE IF NOT EXISTS enrolments (
    course_id INTEGER NOT NULL REFERENCES courses(id),
    student_id INTEGER NOT NULL REFERENCES users(id),
    PRIMARY KEY (course_id, student_id)
);
CREATE TABLE IF NOT EXISTS sessions (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    course_id INTEGER NOT NULL REFERENCES courses(id),
    title TEXT NOT NULL,
    secret TEXT NOT NULL,                 -- per-session HMAC key
    started_at REAL NOT NULL,             -- unix time
    ended_at REAL,
    late_after_min INTEGER NOT NULL DEFAULT 15,
    geo_lat REAL, geo_lng REAL,           -- rules copied from the course at start time
    geo_radius_m INTEGER NOT NULL DEFAULT 100,
    network_mode TEXT NOT NULL DEFAULT 'off'
);
CREATE TABLE IF NOT EXISTS checkins (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    session_id INTEGER NOT NULL REFERENCES sessions(id),
    student_id INTEGER NOT NULL REFERENCES users(id),
    checked_at REAL NOT NULL,
    status TEXT NOT NULL CHECK(status IN ('present','late')),
    method TEXT NOT NULL,                 -- 'qr' | 'code' | 'manual'
    device_id TEXT,                       -- persistent browser cookie
    ip TEXT,
    user_agent TEXT,
    flagged INTEGER NOT NULL DEFAULT 0,   -- 1 = needs lecturer verification (see flag_reason)
    flag_reason TEXT,
    flag_cleared INTEGER NOT NULL DEFAULT 0,
    hw_sig TEXT,                          -- origin-independent phone screen/OS profile hash
    distance_m REAL,                      -- distance from hall at check-in (geofenced sessions)
    accuracy_m REAL,                      -- GPS accuracy reported by the phone
    UNIQUE (session_id, student_id)       -- one check-in per student per session
);
CREATE TABLE IF NOT EXISTS rejections (   -- failed attempts, shown to the lecturer
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    session_id INTEGER NOT NULL REFERENCES sessions(id),
    student_id INTEGER NOT NULL REFERENCES users(id),
    at REAL NOT NULL,
    reason TEXT NOT NULL,
    detail TEXT,
    ip TEXT
);
CREATE TABLE IF NOT EXISTS spot_checks (  -- who was called out, why, and what happened
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    session_id INTEGER NOT NULL REFERENCES sessions(id),
    student_id INTEGER NOT NULL REFERENCES users(id),
    picked_at REAL NOT NULL,
    score INTEGER NOT NULL DEFAULT 0,
    reasons TEXT,                         -- why picked ('' = random)
    outcome TEXT CHECK(outcome IN ('present','absent')),
    decided_at REAL
);
CREATE TABLE IF NOT EXISTS password_resets (  -- audit trail
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id INTEGER NOT NULL REFERENCES users(id),
    by_user_id INTEGER NOT NULL REFERENCES users(id),
    at REAL NOT NULL
);
CREATE TABLE IF NOT EXISTS enrolment_events (  -- who joined / left / was removed, and when
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    course_id INTEGER NOT NULL REFERENCES courses(id) ON DELETE CASCADE,
    student_id INTEGER NOT NULL REFERENCES users(id),
    action TEXT NOT NULL CHECK(action IN ('joined','left','removed','bulk','qr')),
    by_user_id INTEGER REFERENCES users(id),
    at REAL NOT NULL
);
CREATE TABLE IF NOT EXISTS admin_events (  -- account administration audit trail
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    at REAL NOT NULL,
    by_user_id INTEGER,
    by_name TEXT,
    action TEXT NOT NULL,
    target TEXT NOT NULL,
    detail TEXT
);
CREATE TABLE IF NOT EXISTS settings (
    key TEXT PRIMARY KEY,
    value TEXT NOT NULL
);
"""


def log_enrolment(db, course_id, student_id, action, by_user_id=None):
    db.execute("INSERT INTO enrolment_events (course_id, student_id, action, by_user_id, at) VALUES (?,?,?,?,?)",
               (course_id, student_id, action, by_user_id, time.time()))

# Columns added after the first release; applied to existing databases on start-up.
MIGRATIONS = {
    "courses":  [("geo_lat", "REAL"), ("geo_lng", "REAL"), ("geo_radius_m", "INTEGER NOT NULL DEFAULT 100"),
                 ("network_mode", "TEXT NOT NULL DEFAULT 'off'")],
    "sessions": [("geo_lat", "REAL"), ("geo_lng", "REAL"), ("geo_radius_m", "INTEGER NOT NULL DEFAULT 100"),
                 ("network_mode", "TEXT NOT NULL DEFAULT 'off'")],
    "checkins": [("flag_reason", "TEXT"), ("distance_m", "REAL"), ("accuracy_m", "REAL")],
    "users":    [("must_change_pw", "INTEGER NOT NULL DEFAULT 0"), ("active", "INTEGER NOT NULL DEFAULT 1")],
}
MIGRATIONS["courses"].append(("archived", "INTEGER NOT NULL DEFAULT 0"))
MIGRATIONS["courses"].append(("geo_acc_m", "REAL NOT NULL DEFAULT 0"))   # GPS error of the saved hall point (0 = map pin)
MIGRATIONS["courses"].append(("qr_enrol", "INTEGER NOT NULL DEFAULT 1"))  # students may enrol by scanning the session QR
MIGRATIONS["courses"].append(("geo_mode", "TEXT NOT NULL DEFAULT 'flag'"))  # outside geofence -> 'flag' (default) or 'block'
MIGRATIONS["sessions"].append(("geo_mode", "TEXT NOT NULL DEFAULT 'flag'"))
MIGRATIONS["sessions"].append(("geo_acc_m", "REAL NOT NULL DEFAULT 0"))
MIGRATIONS["sessions"].append(("sync_uuid", "TEXT"))
MIGRATIONS["sessions"].append(("synced_at", "REAL"))
MIGRATIONS["sessions"].append(("offline_wifi", "INTEGER NOT NULL DEFAULT 0"))
MIGRATIONS["users"].append(("pw_updated_at", "REAL NOT NULL DEFAULT 0"))
MIGRATIONS["checkins"].append(("hw_sig", "TEXT"))
MIGRATIONS["checkins"].append(("flag_cleared", "INTEGER NOT NULL DEFAULT 0"))


def get_db():
    if "db" not in g:
        g.db = sqlite3.connect(DB_PATH, timeout=15.0)
        g.db.row_factory = sqlite3.Row
        g.db.execute("PRAGMA foreign_keys = ON")
        g.db.execute("PRAGMA busy_timeout = 10000")
    return g.db


@app.teardown_appcontext
def close_db(_exc):
    db = g.pop("db", None)
    if db is not None:
        db.close()


def now_iso():
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def init_db():
    db = sqlite3.connect(DB_PATH, timeout=15.0)
    try:
        db.execute("PRAGMA journal_mode = WAL")
        db.execute("PRAGMA synchronous = NORMAL")
    except sqlite3.OperationalError:
        pass
    db.executescript(SCHEMA)
    for table, cols in MIGRATIONS.items():
        existing = {r[1] for r in db.execute(f"PRAGMA table_info({table})")}
        for name, decl in cols:
            if name not in existing:
                db.execute(f"ALTER TABLE {table} ADD COLUMN {name} {decl}")
    # Older databases have a CHECK constraint on enrolment_events.action without 'qr'
    # (enrol-by-scan). SQLite cannot alter a CHECK, so rebuild that small table once.
    ddl = db.execute("SELECT sql FROM sqlite_master WHERE type='table' AND name='enrolment_events'").fetchone()
    if ddl and "'qr'" not in ddl[0]:
        db.executescript("""
            CREATE TABLE enrolment_events_new (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                course_id INTEGER NOT NULL REFERENCES courses(id) ON DELETE CASCADE,
                student_id INTEGER NOT NULL REFERENCES users(id),
                action TEXT NOT NULL CHECK(action IN ('joined','left','removed','bulk','qr')),
                by_user_id INTEGER REFERENCES users(id),
                at REAL NOT NULL);
            INSERT INTO enrolment_events_new (id,course_id,student_id,action,by_user_id,at)
                SELECT id,course_id,student_id,action,by_user_id,at FROM enrolment_events;
            DROP TABLE enrolment_events;
            ALTER TABLE enrolment_events_new RENAME TO enrolment_events;""")
    for (sid,) in db.execute("SELECT id FROM sessions WHERE sync_uuid IS NULL OR sync_uuid=''").fetchall():
        db.execute("UPDATE sessions SET sync_uuid=? WHERE id=?", (uuid.uuid4().hex, sid))
    db.execute("CREATE UNIQUE INDEX IF NOT EXISTS idx_sessions_sync_uuid ON sessions(sync_uuid)")
    db.execute("CREATE TABLE IF NOT EXISTS deleted_sessions (sync_uuid TEXT PRIMARY KEY, deleted_at REAL NOT NULL)")
    db.commit()
    # Seed demo accounts on first run (skip fake demo students on a real offline lecturer laptop unless SHOW_DEMO_LOGINS=1).
    if (not OFFLINE_WIFI or SHOW_DEMO_LOGINS) and db.execute("SELECT COUNT(*) FROM users").fetchone()[0] == 0:
        ts = now_iso()
        users = [
            ("admin", "Department Admin", "admin123", "admin"),
            ("STAFF001", "Dr. Adaeze Okonkwo", "lecturer123", "lecturer"),
            ("CSC/2022/001", "Tunde Bakare", "student123", "student"),
            ("CSC/2022/002", "Chiamaka Eze", "student123", "student"),
            ("CSC/2022/003", "Ibrahim Musa", "student123", "student"),
            ("CSC/2022/004", "Ngozi Adeyemi", "student123", "student"),
        ]
        for matric, name, pw, role in users:
            db.execute(
                "INSERT INTO users (matric,name,password_hash,role,created_at) VALUES (?,?,?,?,?)",
                (matric, name, generate_password_hash(pw), role, ts),
            )
        lecturer_id = db.execute("SELECT id FROM users WHERE matric='STAFF001'").fetchone()[0]
        db.execute(
            "INSERT INTO courses (code,title,lecturer_id,join_code,created_at) VALUES (?,?,?,?,?)",
            ("CSC301", "Data Structures & Algorithms", lecturer_id, "DSA301", ts),
        )
        course_id = db.execute("SELECT id FROM courses WHERE code='CSC301'").fetchone()[0]
        for (sid,) in db.execute("SELECT id FROM users WHERE role='student'").fetchall():
            db.execute("INSERT INTO enrolments VALUES (?,?)", (course_id, sid))
        db.commit()
    db.close()


# ---------------------------------------------------------------------------
# Auth helpers
# ---------------------------------------------------------------------------
# --- Cookie-less fallback -----------------------------------------------------
# Some environments (sandboxed iframes, embedded previews, very strict browsers)
# do not allow cookies at all.  In that case a signed, time-limited token is
# carried in the URL (?s=...) and automatically appended to every url_for().
# When cookies work normally the token is never used and URLs stay clean.
from itsdangerous import URLSafeTimedSerializer, BadSignature
URL_TOKEN_MAX_AGE = 12 * 60 * 60  # seconds
_url_ser = URLSafeTimedSerializer(app.config["SECRET_KEY"], salt="url-session")


def make_url_token(uid):
    return _url_ser.dumps({"uid": uid})


def read_url_token(tok):
    try:
        return _url_ser.loads(tok, max_age=URL_TOKEN_MAX_AGE)["uid"]
    except (BadSignature, KeyError, TypeError):
        return None


def current_user():
    uid = session.get("uid")
    g.url_token = None
    if not uid:
        tok = request.args.get("s") or request.form.get("s")
        if tok:
            uid = read_url_token(tok)
            if uid:
                g.url_token = tok  # cookie-less mode: propagate token in URLs
    if not uid:
        return None
    u = get_db().execute("SELECT * FROM users WHERE id=?", (uid,)).fetchone()
    if u and not u["active"]:
        session.clear()
        return None
    return u


@app.url_defaults
def add_url_token(endpoint, values):
    if g.get("url_token") and "s" not in values:
        values["s"] = g.url_token


def with_token(url):
    """Append the URL token to a raw path when in cookie-less mode."""
    if g.get("url_token") and "s=" not in url:
        return url + ("&" if "?" in url else "?") + "s=" + g.url_token
    return url


def flash(message, category="message"):
    """flash() that also survives redirects when cookies are unavailable."""
    _flask_flash(message, category)
    g.pending_flash = getattr(g, "pending_flash", []) + [(category, message)]


@app.after_request
def carry_flash_in_url(resp):
    if g.get("url_token") and g.get("pending_flash") and 300 <= resp.status_code < 400:
        loc = resp.headers.get("Location", "")
        q = urlencode([("fm", f"{c}|{m}") for c, m in g.pending_flash])
        resp.headers["Location"] = loc + ("&" if "?" in loc else "?") + q
    return resp


@app.context_processor
def url_flashes():
    return {"url_flashes": [tuple(x.split("|", 1)) for x in request.args.getlist("fm") if "|" in x],
            "SHOW_DEMO_LOGINS": SHOW_DEMO_LOGINS, "APP_NAME": APP_NAME, "APP_VERSION": APP_VERSION, "STATIC_VERSION": STATIC_VERSION,
            "APP_AUTHOR": APP_AUTHOR, "COPYRIGHT": COPYRIGHT, "CURRENT_DEVICE_ID": get_device_id()}


@app.before_request
def load_user():
    g.user = current_user()


@app.context_processor
def inject():
    u = g.get("user")
    need_wifi = (u is not None and u["role"] in ("lecturer", "admin")
                 and not PUBLIC_BASE_URL and (OFFLINE_WIFI or _req_is_loopback()))
    return {"user": u, "ROTATE_SECONDS": ROTATE_SECONDS,
            "public_checkin_url": public_checkin_url, "public_base": PUBLIC_BASE_URL,
            "OFFLINE_WIFI": OFFLINE_WIFI, "wifi": wifi_status(include_candidates=True) if need_wifi else None}


def password_problem(pw, matric):
    """Return an error message if the password is not acceptable, else None."""
    if len(pw) < 6:
        return "Password must be at least 6 characters."
    if pw.strip().lower() == matric.strip().lower():
        return "Your password cannot be your matric/staff number - classmates know it and could sign in as you."
    return None


def password_matches(u, pw):
    """Check a typed password against a user row.

    Tolerates accidental leading/trailing spaces, and when the account is still on its
    temporary password (= matric number) accepts it in any letter case, because students
    type 'csc/2022/045' as readily as 'CSC/2022/045'."""
    pw = pw or ""
    candidates = [pw]
    if pw.strip() != pw:
        candidates.append(pw.strip())
    if u["must_change_pw"] and pw.strip().lower() == (u["matric"] or "").lower():
        candidates.append(u["matric"])
    return any(check_password_hash(u["password_hash"], c) for c in candidates)


def reset_password_to_matric(user_id, by_user_id):
    """Temporary password = matric number; the user must change it at next login."""
    db = get_db()
    u = db.execute("SELECT matric FROM users WHERE id=?", (user_id,)).fetchone()
    db.execute("UPDATE users SET password_hash=?, must_change_pw=1, pw_updated_at=? WHERE id=?",
               (generate_password_hash(u["matric"]), time.time(), user_id))
    db.execute("INSERT INTO password_resets (user_id,by_user_id,at) VALUES (?,?,?)", (user_id, by_user_id, time.time()))
    db.commit()
    return u["matric"]


@app.before_request
def force_password_change():
    if g.get("user") and g.user["must_change_pw"] and request.endpoint not in (
            "change_password", "logout", "static"):
        flash("You are using a temporary password. Please choose a new one to continue.", "error")
        return redirect(url_for("change_password"))


def login_required(*roles):
    def deco(fn):
        @wraps(fn)
        def wrapper(*a, **kw):
            if g.user is None:
                return redirect(url_for("login", next=request.full_path, s=None))
            if roles and g.user["role"] not in roles:
                abort(403)
            return fn(*a, **kw)
        return wrapper
    return deco


def get_device_id():
    """Persistent per-browser id. Assigned on the very first request (so a scan
    ticket can be bound to the phone immediately) and stored in a cookie.
    Used to bind scan tickets and to *flag* one phone checking in several students."""
    dev = request.cookies.get("device_id")
    if not dev:
        if not g.get("new_device_id"):
            g.new_device_id = uuid.uuid4().hex
        dev = g.new_device_id
    return dev


@app.after_request
def ensure_device_cookie(resp):
    if g.get("heal_device_id"):
        resp.set_cookie("device_id", g.heal_device_id, max_age=60 * 60 * 24 * 365 * 3,
                        httponly=True, **cookie_attrs())
    elif not request.cookies.get("device_id"):
        resp.set_cookie("device_id", get_device_id(), max_age=60 * 60 * 24 * 365 * 3,
                        httponly=True, **cookie_attrs())
    return resp


# ---------------------------------------------------------------------------
# Settings (admin-editable, stored in the database)
# ---------------------------------------------------------------------------
def get_setting(key, default=""):
    row = get_db().execute("SELECT value FROM settings WHERE key=?", (key,)).fetchone()
    return row["value"] if row else default


def set_setting(key, value):
    db = get_db()
    db.execute("INSERT INTO settings (key,value) VALUES (?,?) ON CONFLICT(key) DO UPDATE SET value=excluded.value",
               (key, value))
    db.commit()


# ---------------------------------------------------------------------------
# Location (geofence) and network checks
# ---------------------------------------------------------------------------
import ipaddress
import math

GPS_ALLOWANCE_M = 75   # part of the phone's reported GPS error we forgive (indoor GPS is noisy)
LOW_ACCURACY_M = 150   # worse than this -> accepted but flagged for the lecturer
UNUSABLE_ACCURACY_M = 1000  # worse than this the phone is only guessing (e.g. iPhone 'Precise Location' off)
MIN_RADIUS_M = 50
REF_ALLOWANCE_M = 50   # part of the *reference point's* GPS error we forgive


def haversine_m(lat1, lng1, lat2, lng2):
    r = 6371000.0
    p1, p2 = math.radians(lat1), math.radians(lat2)
    dp, dl = math.radians(lat2 - lat1), math.radians(lng2 - lng1)
    a = math.sin(dp / 2) ** 2 + math.cos(p1) * math.cos(p2) * math.sin(dl / 2) ** 2
    return 2 * r * math.asin(math.sqrt(a))


def client_ip():
    return (request.headers.get("CF-Connecting-IP") or request.remote_addr or "").strip()


def allowed_networks():
    nets = []
    for line in get_setting("allowed_networks").replace(",", "\n").splitlines():
        line = line.split("#")[0].strip()
        if not line:
            continue
        try:
            nets.append(ipaddress.ip_network(line, strict=False))
        except ValueError:
            pass
    return nets


def ip_allowed(ip):
    """True if ip is inside any allowed network. Returns None when no networks are configured."""
    nets = allowed_networks()
    if not nets:
        return None
    try:
        addr = ipaddress.ip_address(ip)
    except ValueError:
        return False
    return any(addr in n for n in nets)


def _is_offline_session(sess):
    if OFFLINE_WIFI:
        return True
    try:
        return bool(sess["offline_wifi"]) if sess and "offline_wifi" in sess.keys() else False
    except Exception:
        return False


def session_rules(sess):
    """Human-readable summary of the rules active for a session/course row."""
    if _is_offline_session(sess):
        return "classroom Wi-Fi geofence (must be connected to hall Wi-Fi)"
    parts = []
    if sess["geo_lat"] is not None:
        strict = (sess["geo_mode"] if "geo_mode" in sess.keys() else "flag") == "block"
        parts.append(f"must be within {sess['geo_radius_m']} m of the hall" if strict
                     else f"flagged if more than {sess['geo_radius_m']} m from the hall")
    if sess["network_mode"] == "block":
        parts.append("campus network required")
    elif sess["network_mode"] == "flag":
        parts.append("off-campus network flagged")
    return " · ".join(parts) if parts else "no location or network rules"


# ---------------------------------------------------------------------------
# Rotating token logic
# ---------------------------------------------------------------------------
def current_slot(ts=None):
    return int((ts or time.time()) // ROTATE_SECONDS)


def _sig(secret, session_id, slot):
    msg = f"{session_id}:{slot}".encode()
    return hmac.new(secret.encode(), msg, hashlib.sha256).digest()


def make_token(sess, slot=None):
    slot = slot if slot is not None else current_slot()
    sig = base64.urlsafe_b64encode(_sig(sess["secret"], sess["id"], slot)[:12]).decode().rstrip("=")
    return f"{sess['id']}.{slot}.{sig}"


def make_short_code(sess, slot=None):
    """6-digit code for students who cannot scan (derived from the same HMAC)."""
    slot = slot if slot is not None else current_slot()
    n = int.from_bytes(_sig(sess["secret"], sess["id"], slot)[:4], "big")
    return f"{n % 1_000_000:06d}"


_VIRTUAL_IFACE_RE = re.compile(
    r"(wi-?fi direct|npcap|vethernet|wsl|hyper-v|virtualbox|vbox|vmware|vmnet|docker|podman|minikube|multipass|"
    r"br-|veth|loopback|teredo|isatap|bluetooth|tailscale|zerotier|zt-|wireguard|wintun|utun|nordlynx|proton|"
    r"cloudflare|warp|openvpn|tap-windows|cisco|anyconnect|fortinet|fortissl|pangp|globalprotect|"
    r"surfshark|expressvpn|mullvad|windscribe|cyberghost|softether|radmin|hamachi|\btun[0-9]*\b|\btap[0-9]*\b)",
    re.I,
)
_LAPTOP_HOTSPOT_RE = re.compile(r"local area connection\*", re.I)
_WIFI_IFACE_RE = re.compile(r"(wi-?fi|wireless|wlan|wlp|airport)", re.I)
_lan_cache = {"at": 0.0, "items": [], "meta": {}}
_LAN_LOCK = threading.Lock()
_fw_cache = {"at": 0.0, "ok": True}
_FW_PORTS = "5000,5050,5055,5080,5100"


def _is_usable_lan_ip(ip_str):
    try:
        ip = ipaddress.ip_address(ip_str)
    except ValueError:
        return False
    if ip.version != 4 or ip.is_loopback or ip.is_link_local or ip.is_multicast or ip.is_unspecified:
        return False
    if ip_str == "192.168.56.1":  # VirtualBox Host-Only default bridge
        return False
    return (ip in ipaddress.ip_network("10.0.0.0/8")
            or ip in ipaddress.ip_network("172.16.0.0/12")
            or ip in ipaddress.ip_network("192.168.0.0/16"))


def _hotspot_has_clients(ip_str):
    """True when Windows ARP table shows at least one dynamic client lease on this hotspot adapter."""
    if os.name != "nt" or not ip_str:
        return False
    try:
        out = subprocess.check_output(
            ["arp", "-a", "-N", ip_str], text=True, errors="ignore", timeout=1.2,
            creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0),
        )
        for line in out.splitlines():
            m = re.match(r"^\s*([0-9]+\.[0-9]+\.[0-9]+\.[0-9]+)\s+[0-9a-f-]{11,}\s+dynamic\b", line, re.I)
            if not m:
                continue
            peer = m.group(1)
            if peer == ip_str or peer.endswith(".255"):
                continue
            try:
                p_ip = ipaddress.ip_address(peer)
                if not p_ip.is_multicast and not p_ip.is_unspecified:
                    return True
            except ValueError:
                pass
    except Exception:
        pass
    return False


def detect_lan_ips():
    """Return ranked [{'ip': '192.168.0.104', 'label': 'Wi-Fi'}] for active classroom Wi-Fi / Hotspot interfaces."""
    env_ip = os.environ.get("OFFLINE_LAN_IP", "").strip()
    if env_ip.upper() == "NONE":
        return []
    if env_ip and _is_usable_lan_ip(env_ip):
        return [{"ip": env_ip, "label": "Configured Wi-Fi IP"}]
    now = time.time()
    if now - _lan_cache["at"] < 8.0:
        return list(_lan_cache["items"])
    if not _LAN_LOCK.acquire(blocking=not bool(_lan_cache["items"])):
        return list(_lan_cache["items"])
    try:
        now = time.time()
        if now - _lan_cache["at"] < 8.0:
            return list(_lan_cache["items"])
        found = {}          # ip -> (adj_priority, label)
        meta = {}           # ip -> {"gw": str|None, "bcast": str|None}
        excluded_ips = set()

        def add(ip_str, prio, label, gw=None, mask=None, exact_adj=None):
            if ip_str in excluded_ips or not _is_usable_lan_ip(ip_str):
                return
            adj = exact_adj if exact_adj is not None else (prio + (2 if ip_str.endswith(".1") else 0))
            if ip_str not in found or adj < found[ip_str][0]:
                found[ip_str] = (adj, label)
            bcast = None
            if mask:
                try:
                    bcast = str(ipaddress.IPv4Interface(f"{ip_str}/{mask}").network.broadcast_address)
                except ValueError:
                    pass
            if not bcast:
                parts = ip_str.split(".")
                if len(parts) == 4:
                    bcast = f"{parts[0]}.{parts[1]}.{parts[2]}.255"
            if ip_str not in meta or gw:
                meta[ip_str] = {"gw": gw, "bcast": bcast, "mask": mask}

        if os.name == "nt":
            try:
                out = subprocess.check_output(
                    ["ipconfig"], text=True, errors="ignore", timeout=2,
                    creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0),
                )
                header, lines, sections = "", [], []
                for raw in out.splitlines():
                    if raw and not raw[0].isspace() and raw.rstrip().endswith(":"):
                        if header:
                            sections.append((header, lines))
                        header, lines = raw.rstrip(": ").strip(), []
                    else:
                        lines.append(raw)
                if header:
                    sections.append((header, lines))
                for hdr, body in sections:
                    txt = "\n".join(body)
                    ips = re.findall(r"IPv4[^:]*:\s*([0-9]+\.[0-9]+\.[0-9]+\.[0-9]+)", txt, re.I)
                    if _VIRTUAL_IFACE_RE.search(hdr):
                        excluded_ips.update(ips)
                        continue
                    if "media disconnected" in txt.lower():
                        continue
                    masks = re.findall(r"Subnet Mask[^:]*:\s*([0-9]+\.[0-9]+\.[0-9]+\.[0-9]+)", txt, re.I)
                    gws = re.findall(r"Default Gateway[^:]*:\s*([0-9]+\.[0-9]+\.[0-9]+\.[0-9]+)", txt, re.I)
                    gw_ip = gws[0] if gws else None
                    mask_ip = masks[0] if masks else None
                    if _LAPTOP_HOTSPOT_RE.search(hdr):
                        for ip_s in ips:
                            if _hotspot_has_clients(ip_s):
                                add(ip_s, 0, "Laptop Hotspot (active)", gw=gw_ip, mask=mask_ip, exact_adj=-1)
                            elif ip_s.startswith("192.168.137."):
                                add(ip_s, 3, "Laptop Hotspot", gw=gw_ip, mask=mask_ip, exact_adj=4)
                            else:
                                add(ip_s, 5, "Wi-Fi Direct / Hotspot", gw=gw_ip, mask=mask_ip, exact_adj=7)
                        continue
                    is_wifi = bool(_WIFI_IFACE_RE.search(hdr))
                    prio = (0 if gw_ip else 1) if is_wifi else (2 if gw_ip else 3)
                    lbl = "Wi-Fi" if is_wifi else hdr[:28]
                    for ip_s in ips:
                        add(ip_s, prio, lbl, gw=gw_ip, mask=mask_ip)
            except Exception:
                pass
        else:
            try:
                out = subprocess.check_output(["ip", "-4", "-o", "addr", "show"], text=True, errors="ignore", timeout=2)
                for line in out.splitlines():
                    m = re.match(r"^\d+:\s+(\S+)\s+inet\s+([0-9.]+)/(\d+)", line.strip())
                    if not m:
                        continue
                    ifname, ip_s, pfx = m.group(1), m.group(2), m.group(3)
                    if _VIRTUAL_IFACE_RE.search(ifname):
                        excluded_ips.add(ip_s)
                        continue
                    is_wifi = bool(_WIFI_IFACE_RE.search(ifname))
                    add(ip_s, 1 if is_wifi else 2, "Wi-Fi" if is_wifi else ifname, mask=pfx)
            except Exception:
                pass

        for probe in (("192.168.1.1", "10.0.0.1") if found else ("192.168.1.1", "10.0.0.1", "8.8.8.8")):
            try:
                s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
                s.connect((probe, 80))
                ip_s = s.getsockname()[0]
                s.close()
                add(ip_s, 2, "Active network")
            except OSError:
                pass

        if not found:
            try:
                for info in socket.getaddrinfo(socket.gethostname(), None, socket.AF_INET):
                    add(info[4][0], 4, "Local network")
            except OSError:
                pass

        ranked = [{"ip": k, "label": v[1]} for k, v in sorted(found.items(), key=lambda kv: (kv[1][0], kv[0]))]
        _lan_cache["at"] = time.time()
        _lan_cache["items"] = ranked
        _lan_cache["meta"] = meta
        return list(ranked)
    finally:
        _LAN_LOCK.release()


def windows_firewall_ok(force=False):
    """Check whether Windows Defender Firewall has our inbound classroom port rule enabled."""
    if os.name != "nt" or PUBLIC_BASE_URL:
        return True
    now = time.time()
    if not force and now - _fw_cache["at"] < 15.0:
        return _fw_cache["ok"]
    ok = True
    try:
        res = subprocess.run(
            ["netsh", "advfirewall", "firewall", "show", "rule", "name=CS Attendance Classroom Wi-Fi"],
            capture_output=True, text=True, errors="ignore", timeout=2,
            creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0),
        )
        txt = (res.stdout or "").lower()
        cur_port = str(os.environ.get("PORT", "5000")).strip()
        ok = (
            res.returncode == 0
            and "enabled:" in txt and "yes" in txt
            and "action:" in txt and "allow" in txt
            and (cur_port in txt or "any" in txt)
        )
    except Exception:
        ok = True
    _fw_cache["at"] = now
    _fw_cache["ok"] = ok
    return ok


def apply_windows_firewall_uac():
    """Prompt Windows UAC once to open classroom ports + current runtime & clear accidental Block rules."""
    if os.name != "nt":
        return True
    import tempfile
    exe_path = os.path.abspath(sys.executable)
    bat_path = os.path.join(tempfile.gettempdir(), "cs_attendance_fw_setup.bat")
    ps_unblock = (
        "Get-NetFirewallApplicationFilter -ErrorAction SilentlyContinue | "
        "Where-Object { $_.Program -match '(Attendance_Offline|pythonw?)\\.exe$' } | "
        "Get-NetFirewallRule -ErrorAction SilentlyContinue | "
        "Where-Object { $_.Direction -eq 'Inbound' -and $_.Action -eq 'Block' } | "
        "Remove-NetFirewallRule -ErrorAction SilentlyContinue"
    )
    bat_lines = [
        "@echo off",
        'netsh advfirewall firewall delete rule name="CS Attendance Classroom Wi-Fi" >nul 2>&1',
        'netsh advfirewall firewall delete rule name="CS Attendance Classroom Wi-Fi (Ping)" >nul 2>&1',
        'netsh advfirewall firewall delete rule name="CS Attendance Active Runtime" >nul 2>&1',
        f'netsh advfirewall firewall add rule name="CS Attendance Classroom Wi-Fi" dir=in action=allow protocol=TCP localport={_FW_PORTS} profile=any >nul 2>&1',
        'netsh advfirewall firewall add rule name="CS Attendance Classroom Wi-Fi (Ping)" dir=in action=allow protocol=icmpv4:8,any remoteip=localsubnet profile=any >nul 2>&1',
        f'netsh advfirewall firewall add rule name="CS Attendance Active Runtime" dir=in action=allow program="{exe_path}" enable=yes profile=any >nul 2>&1',
        f'powershell -NoProfile -ExecutionPolicy Bypass -Command "{ps_unblock}" >nul 2>&1',
        "exit /b 0",
    ]
    try:
        with open(bat_path, "w", encoding="ascii", errors="ignore") as f:
            f.write("\r\n".join(bat_lines) + "\r\n")
        ps_run = (
            f"Start-Process -FilePath '{bat_path.replace(chr(39), chr(39)*2)}' "
            "-Verb RunAs -WindowStyle Hidden -Wait"
        )
        subprocess.run(
            ["powershell", "-NoProfile", "-ExecutionPolicy", "Bypass", "-Command", ps_run],
            capture_output=True, timeout=30,
            creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0),
        )
    except Exception:
        pass
    return windows_firewall_ok(force=True)


def _req_host_parts():
    try:
        raw_host = request.host
    except RuntimeError:
        raw_host = f"localhost:{os.environ.get('PORT', 5000)}"
    if ":" in raw_host and not raw_host.endswith("]"):
        req_host, req_port = raw_host.rsplit(":", 1)
    else:
        req_host, req_port = raw_host, ""
    port_suffix = f":{req_port}" if req_port and req_port not in ("80", "443") else ""
    is_loopback = req_host.lower() in ("localhost", "127.0.0.1", "::1", "[::1]")
    return raw_host, req_host, port_suffix, is_loopback


def _req_is_loopback():
    return _req_host_parts()[3]


def wifi_status(include_candidates=False):
    """Current classroom Wi-Fi / Hotspot reachability & base URL for student phones."""
    if PUBLIC_BASE_URL:
        return {"ready": True, "ip": None, "base_url": PUBLIC_BASE_URL,
                "candidates": [], "override": "", "local_mode": False, "firewall_ok": True}
    raw_host, req_host, port_suffix, is_loopback_host = _req_host_parts()
    env_none = os.environ.get("OFFLINE_LAN_IP", "").strip().upper() == "NONE"

    if not is_loopback_host and not env_none and not include_candidates:
        scheme = "https" if _is_https() else "http"
        return {"ready": True, "ip": req_host, "base_url": f"{scheme}://{raw_host}",
                "candidates": [], "override": "", "local_mode": bool(OFFLINE_WIFI), "firewall_ok": True}

    candidates = detect_lan_ips()
    override = ""
    try:
        override = get_setting("lan_ip_override", "").strip()
    except Exception:
        pass
    chosen_ip = None
    if override and any(c["ip"] == override for c in candidates):
        chosen_ip = override
    elif candidates:
        chosen_ip = candidates[0]["ip"]

    fw_ok = windows_firewall_ok() if (OFFLINE_WIFI or is_loopback_host) else True
    if not is_loopback_host and not env_none:
        scheme = "https" if _is_https() else "http"
        return {"ready": True, "ip": chosen_ip or req_host, "base_url": f"{scheme}://{raw_host}",
                "candidates": candidates, "override": override,
                "local_mode": bool(OFFLINE_WIFI), "firewall_ok": fw_ok}
    if chosen_ip:
        return {"ready": True, "ip": chosen_ip, "base_url": f"http://{chosen_ip}{port_suffix}",
                "candidates": candidates, "override": override,
                "local_mode": True, "firewall_ok": fw_ok}
    return {"ready": False, "ip": None, "base_url": f"http://{raw_host}",
            "candidates": candidates, "override": override,
            "local_mode": True, "firewall_ok": fw_ok}


def public_url(endpoint, **values):
    """Absolute URL reachable from students' phones (never carries a login token or 'localhost' when on Wi-Fi)."""
    values["s"] = None
    if PUBLIC_BASE_URL:
        return PUBLIC_BASE_URL + url_for(endpoint, **values)
    if OFFLINE_WIFI or _req_is_loopback():
        ws = wifi_status()
        if ws["base_url"]:
            return ws["base_url"] + url_for(endpoint, **values)
    return url_for(endpoint, _external=True, **values)


def public_checkin_url(token=None):
    return public_url("checkin", t=token)


def verify_token(token):
    """Return session row if token is valid for the current (or grace) slot."""
    try:
        sid_s, slot_s, sig = token.split(".")
        sid, slot = int(sid_s), int(slot_s)
    except ValueError:
        return None, "Malformed code."
    sess = get_db().execute("SELECT * FROM sessions WHERE id=?", (sid,)).fetchone()
    if not sess:
        return None, "Session not found."
    if sess["ended_at"]:
        return None, "This session has already ended."
    cur = current_slot()
    if not (cur - GRACE_SLOTS <= slot <= cur):
        return None, "That QR code has expired. Scan the one on the screen now."
    if not hmac.compare_digest(make_token(sess, slot), token):
        return None, "Invalid code."
    return sess, None


def verify_short_code(code, student_id):
    """Match a 6-digit code against the student's active sessions (strict current slot only — expires the instant the screen rotates)."""
    clean = "".join((code or "").split())
    db = get_db()
    active = db.execute(
        """SELECT s.* FROM sessions s JOIN enrolments e ON e.course_id = s.course_id
           WHERE e.student_id=? AND s.ended_at IS NULL""", (student_id,)).fetchall()
    cur = current_slot()
    for sess in active:
        if hmac.compare_digest(make_short_code(sess, cur), clean):
            return sess, None
    if not active:
        return None, "None of your courses has an active session right now."
    return None, "Code is wrong or has expired. Read the new code on the screen."


def _reject(sess, student_id, reason, detail=None):
    db = get_db()
    db.execute("INSERT INTO rejections (session_id,student_id,at,reason,detail,ip) VALUES (?,?,?,?,?,?)",
               (sess["id"], student_id, time.time(), reason, detail, client_ip()))
    db.commit()


_HW_RAW_RE = re.compile(r"^[a-z0-9|x@._-]{5,80}$", re.I)
_HEX32_RE = re.compile(r"^[0-9a-f]{32}$")
_ANDROID_MODEL_RE = re.compile(r"\(\s*Linux;\s*Android[^;)]*;\s*([^)]+)\)", re.I)


def _normalize_hw_sig(raw):
    raw = (raw or "").strip().lower()
    if not raw:
        return None
    if raw.startswith("hw:") and len(raw) == 19:
        return raw
    if "0x0" in raw or not _HW_RAW_RE.match(raw):
        return None
    return "hw:" + hashlib.sha256(raw.encode("utf-8")).hexdigest()[:16]


def _ua_hw_sig(ua):
    """Fallback hardware family/model signature derived from User-Agent (for legacy rows & non-JS clients)."""
    ua = (ua or "").strip()
    if not ua:
        return None
    low = ua.lower()
    if "iphone" in low:
        key = "ios|iphone"
    elif "ipad" in low:
        key = "ios|ipad"
    elif "android" in low:
        m = _ANDROID_MODEL_RE.search(ua)
        model = "generic"
        if m:
            parts = [p.strip() for p in m.group(1).split(";") if p.strip() and p.strip().lower() != "wv"]
            if parts:
                model = re.sub(r"\s+build/.*$", "", parts[-1], flags=re.I).strip().lower() or "generic"
        key = f"android|{model}"
    elif "windows" in low:
        key = "win|pc"
    elif "macintosh" in low or "mac os x" in low:
        key = "mac|mac"
    elif "linux" in low:
        key = "linux|pc"
    else:
        return None
    return "ua:" + hashlib.sha256(key.encode("utf-8")).hexdigest()[:16]


def _clean_alt_dev(raw):
    val = (raw or "").strip().lower()
    return val if _HEX32_RE.match(val) else None


def _is_lan_phone_ip(ip_str):
    """True for non-loopback private LAN/Hotspot IPs where each phone has its own DHCP lease."""
    if not ip_str or ip_str in ("127.0.0.1", "::1"):
        return False
    return _is_usable_lan_ip(ip_str)


def _rows_share_same_phone(r_a, r_b, offline_sess):
    """True when two check-ins in the same session came from the same physical phone."""
    dev_a, dev_b = (r_a["device_id"] or "").strip(), (r_b["device_id"] or "").strip()
    if dev_a and dev_b and dev_a == dev_b:
        return True
    if offline_sess:
        ip_a, ip_b = (r_a["ip"] or "").strip(), (r_b["ip"] or "").strip()
        if ip_a and ip_a == ip_b and _is_lan_phone_ip(ip_a):
            hw_a = r_a["hw_sig"] if "hw_sig" in r_a.keys() else None
            hw_b = r_b["hw_sig"] if "hw_sig" in r_b.keys() else None
            if not hw_a or not hw_b or hw_a == hw_b:
                return True
    return False


def _is_same_sess_shared_part(part_str):
    low = (part_str or "").strip().lower()
    return low == "shared device" or low.startswith("shared device:") or low.startswith("shared device with ")


def _friendly_phone_label(ua_str):
    ua = (ua_str or "").strip()
    low = ua.lower()
    if "iphone" in low:
        plat = "iPhone"
    elif "ipad" in low:
        plat = "iPad"
    elif "android" in low:
        plat = "Android"
        m = _ANDROID_MODEL_RE.search(ua)
        if m:
            parts = [p.strip() for p in m.group(1).split(";") if p.strip() and p.strip().lower() != "wv"]
            if parts:
                mdl = re.sub(r"\s+build/.*$", "", parts[-1], flags=re.I).strip()
                if mdl and len(mdl) <= 24 and mdl.lower() not in ("k", "generic"):
                    plat = f"Android ({mdl})"
    elif "windows" in low:
        plat = "Windows PC"
    elif "macintosh" in low or "mac os x" in low:
        plat = "Mac"
    elif "linux" in low:
        plat = "Linux"
    else:
        plat = "Phone"

    if "edg/" in low or "edga/" in low or "edgios/" in low:
        brw = "Edge"
    elif "samsungbrowser/" in low:
        brw = "Samsung Internet"
    elif "opr/" in low or "opera" in low:
        brw = "Opera"
    elif "firefox/" in low or "fxios/" in low:
        brw = "Firefox"
    elif "crios/" in low or "chrome/" in low:
        brw = "Chrome"
    elif "safari/" in low:
        brw = "Safari"
    else:
        brw = ""
    return f"{plat} \u00b7 {brw}" if brw else plat


def _format_gap_label(gap_sec):
    gap_sec = max(0, int(round(gap_sec)))
    if gap_sec < 60:
        return f"{gap_sec}s"
    if gap_sec < 600 and gap_sec % 60:
        return f"{gap_sec // 60}m {gap_sec % 60}s"
    return f"{max(1, round(gap_sec / 60))} min"


def _compute_shared_components(rows, offline_sess):
    """Group non-manual check-in rows that came from the same physical phone into chronologically ordered clusters."""
    non_manual = [r for r in rows if r["method"] != "manual"]
    n = len(non_manual)
    parent = list(range(n))

    def find(x):
        while parent[x] != x:
            parent[x] = parent[parent[x]]
            x = parent[x]
        return x

    for i in range(n):
        for j in range(i + 1, n):
            if non_manual[i]["student_id"] != non_manual[j]["student_id"] and _rows_share_same_phone(non_manual[i], non_manual[j], offline_sess):
                ri, rj = find(i), find(j)
                if ri != rj:
                    parent[rj] = ri

    buckets = {}
    for idx, r in enumerate(non_manual):
        buckets.setdefault(find(idx), []).append(r)

    clusters = []
    for comp in buckets.values():
        distinct_students = {r["student_id"] for r in comp}
        if len(distinct_students) >= 2:
            comp.sort(key=lambda r: (float(r["checked_at"] or 0), r["id"]))
            clusters.append(comp)
    clusters.sort(key=lambda c: (float(c[0]["checked_at"] or 0), c[0]["id"]))
    return clusters


def _build_session_phone_groups(db, sess):
    """Build detailed shared-phone groups for a session (who shared with whom, check-in order, and usual phone owner)."""
    offline_sess = _is_offline_session(sess)
    rows = db.execute(
        """SELECT k.id, k.student_id, k.checked_at, k.status, k.method, k.device_id, k.ip,
                  k.user_agent, k.flagged, k.flag_reason, k.flag_cleared, k.hw_sig,
                  u.name, u.matric
             FROM checkins k JOIN users u ON u.id = k.student_id
            WHERE k.session_id=? AND k.method<>'manual'
            ORDER BY k.checked_at ASC, k.id ASC""",
        (sess["id"],),
    ).fetchall()
    clusters = _compute_shared_components(rows, offline_sess)
    if not clusters:
        return []

    # Check chronological earlier sessions in this course to identify the phone's usual owner
    hist_rows = db.execute(
        """SELECT k.student_id, k.device_id, u.name
             FROM checkins k
             JOIN sessions s ON s.id = k.session_id
             JOIN users u ON u.id = k.student_id
            WHERE s.course_id=? AND s.id<>?
              AND (s.started_at < ? OR (s.started_at = ? AND s.id < ?))
              AND k.method<>'manual' AND k.device_id IS NOT NULL AND k.device_id<>''""",
        (sess["course_id"], sess["id"], sess["started_at"], sess["started_at"], sess["id"]),
    ).fetchall()
    dev_hist_counts = {}   # device_id -> {student_id: (count, name)}
    for hr in hist_rows:
        dmap = dev_hist_counts.setdefault(hr["device_id"], {})
        prev_cnt, _ = dmap.get(hr["student_id"], (0, hr["name"]))
        dmap[hr["student_id"]] = (prev_cnt + 1, hr["name"])

    groups = []
    for idx, comp in enumerate(clusters, 1):
        first = comp[0]
        comp_devs = {r["device_id"] for r in comp if r["device_id"]}
        best_owner_sid, best_owner_name, best_owner_cnt = None, None, 0
        cand_counts = {}
        for d_id in comp_devs:
            for sid, (cnt, nm) in dev_hist_counts.get(d_id, {}).items():
                prev_c, _ = cand_counts.get(sid, (0, nm))
                cand_counts[sid] = (prev_c + cnt, nm)
        for sid, (cnt, nm) in cand_counts.items():
            if cnt > best_owner_cnt:
                best_owner_sid, best_owner_name, best_owner_cnt = sid, nm, cnt

        if best_owner_cnt > 0:
            owner_sid = best_owner_sid
            owner_label = f"{best_owner_name} (used in {best_owner_cnt} earlier lecture{'s' if best_owner_cnt != 1 else ''})"
        else:
            owner_sid = first["student_id"]
            owner_label = f"{first['name']} (1st check-in)"

        members = []
        for step_i, m in enumerate(comp):
            gap_s = max(0.0, float(m["checked_at"] or 0) - float(first["checked_at"] or 0))
            others = [o for o in comp if o["student_id"] != m["student_id"]]
            partner_str = ", ".join(f"{o['name']} ({o['matric']})" for o in others[:3])
            if len(others) > 3:
                partner_str += f" +{len(others) - 3} more"
            if step_i == 0:
                order_detail = f"checked in 1st at {fmt_tm(m['checked_at'])}"
                gap_badge = "1st check-in"
            else:
                g_txt = _format_gap_label(gap_s)
                order_detail = f"signed in {g_txt} after {first['name'].split()[0]} on same phone"
                gap_badge = f"+{g_txt} later"
            members.append({
                "checkin_id": m["id"],
                "student_id": m["student_id"],
                "name": m["name"],
                "matric": m["matric"],
                "status": m["status"],
                "method": m["method"],
                "checked_at": m["checked_at"],
                "flagged": bool(m["flagged"]),
                "flag_cleared": bool(m["flag_cleared"] or 0),
                "step": step_i + 1,
                "gap_badge": gap_badge,
                "partner_str": partner_str,
                "order_detail": order_detail,
                "is_owner": m["student_id"] == owner_sid,
            })

        later_names = [m["name"] for m in members[1:]]
        if len(later_names) == 1:
            g_txt = _format_gap_label(float(comp[1]["checked_at"] or 0) - float(first["checked_at"] or 0))
            tip = (f"{later_names[0]} signed in {g_txt} after {first['name']} on the same phone. "
                   f"Call out {later_names[0].split()[0]} in class to verify.")
        else:
            joined = ", ".join(n.split()[0] for n in later_names[:-1]) + " & " + later_names[-1].split()[0]
            tip = (f"{joined} signed in after {first['name']} on the same phone. "
                   f"Call them out in class to verify.")

        groups.append({
            "phone_num": idx,
            "phone_label": _friendly_phone_label(first["user_agent"]),
            "owner_label": owner_label,
            "any_flagged": any(m["flagged"] and not m["flag_cleared"] for m in members),
            "members": members,
            "tip": tip,
        })
    return groups


def _reconcile_shared_device_flags(db, sess, reset_cleared_ids=None):
    """Synchronize 'shared device: Name (MATRIC)' flags for every check-in in this session.
    Names exact sharing partners when >=2 students share a phone, and clears the flag when alone."""
    offline_sess = _is_offline_session(sess)
    rem = db.execute(
        """SELECT k.id, k.student_id, k.checked_at, k.method, k.device_id, k.ip, k.hw_sig,
                  k.flagged, k.flag_reason, k.flag_cleared, u.name, u.matric
             FROM checkins k JOIN users u ON u.id = k.student_id
            WHERE k.session_id=?
            ORDER BY k.checked_at ASC, k.id ASC""",
        (sess["id"],),
    ).fetchall()
    clusters = _compute_shared_components(rem, offline_sess)
    comp_by_row_id = {}
    for comp in clusters:
        for m in comp:
            comp_by_row_id[m["id"]] = comp

    for r in rem:
        fr = r["flag_reason"] or ""
        other_parts = [p.strip() for p in fr.split(";") if p.strip() and not _is_same_sess_shared_part(p)]
        comp = comp_by_row_id.get(r["id"])
        if comp:
            if bool(r["flag_cleared"] or 0) and (not reset_cleared_ids or r["id"] not in reset_cleared_ids):
                continue
            others = [m for m in comp if m["student_id"] != r["student_id"]]
            p_str = ", ".join(f"{m['name']} ({m['matric']})" for m in others[:3])
            if len(others) > 3:
                p_str += f" +{len(others) - 3} more"
            shared_part = f"shared device: {p_str}"
            new_fr = "; ".join([shared_part] + other_parts)
            db.execute(
                "UPDATE checkins SET flagged=1, flag_reason=?, flag_cleared=0 WHERE id=?",
                (new_fr, r["id"]),
            )
        else:
            if any(_is_same_sess_shared_part(p) for p in fr.split(";") if p.strip()):
                new_fr = "; ".join(other_parts) or None
                db.execute(
                    "UPDATE checkins SET flagged=?, flag_reason=? WHERE id=?",
                    (1 if new_fr else 0, new_fr, r["id"]),
                )


def _short_live_flag(flag_reason):
    """Concise badge text for the Live QR screen's Recent activity feed."""
    fr = (flag_reason or "").strip()
    if not fr:
        return "flagged"
    for p in [x.strip() for x in fr.split(";") if x.strip()]:
        low = p.lower()
        if low.startswith("shared device:"):
            rhs = p.split(":", 1)[1].strip()
            first_names = []
            for item in rhs.split(","):
                nm = item.strip().split(" (")[0].strip()
                if nm:
                    first_names.append(nm.split()[0])
            if first_names:
                return "shared phone w/ " + ", ".join(first_names[:2])
            return "shared phone"
        if low == "shared device":
            return "shared phone"
    first_p = fr.split(";")[0].strip().lower()
    if first_p.startswith("previous shared device"):
        return "prev. shared phone"
    if first_p.startswith("new device"):
        return "new phone"
    if first_p.startswith("outside geofence"):
        return "outside hall"
    return "flagged"


def record_checkin(sess, student_id, method, lat=None, lng=None, accuracy=None, hw_sig=None, alt_dev=None):
    """Apply every rule and record the check-in. Returns (ok, status_or_error)."""
    db = get_db()
    enrolled = db.execute("SELECT 1 FROM enrolments WHERE course_id=? AND student_id=?",
                          (sess["course_id"], student_id)).fetchone()
    if not enrolled:
        return False, "You are not enrolled in this course. Join it first with the course join code."
    existing = db.execute("SELECT * FROM checkins WHERE session_id=? AND student_id=?",
                          (sess["id"], student_id)).fetchone()
    if existing:
        return False, "You have already been marked for this session."

    flags = []
    distance = None
    geo_mode = sess["geo_mode"] if "geo_mode" in sess.keys() else "flag"

    offline_sess = _is_offline_session(sess)

    # --- Rule 1: geofence -------------------------------------------------------
    # Produces geo_ok: None (no rule) / True / False, plus the failure (reason, detail, student message).
    # In Offline Classroom Wi-Fi mode, being connected to the hall's Wi-Fi router IS the geofence.
    geo_ok, geo_fail = None, None
    if not offline_sess and sess["geo_lat"] is not None:
        if lat is None or lng is None:
            # No position at all is never accepted, in either mode: location is the whole point.
            _reject(sess, student_id, "no location", "phone did not provide a position")
            return False, ("This course requires your location. Allow location access for this site "
                           "and try again (or ask the lecturer to mark you manually).")
        else:
            distance = haversine_m(lat, lng, sess["geo_lat"], sess["geo_lng"])
            acc = float(accuracy or 0)
            ref_acc = float(sess["geo_acc_m"] or 0)   # the hall point itself was a GPS reading with its own error
            effective = max(0.0, distance - min(acc, GPS_ALLOWANCE_M) - min(ref_acc, REF_ALLOWANCE_M))
            if acc > UNUSABLE_ACCURACY_M and distance > sess["geo_radius_m"]:
                geo_ok = False
                geo_fail = ("imprecise location", f"{distance:.0f} m away (±{acc:.0f} m)",
                            f"Your phone only shared a rough position (±{acc/1000:.1f} km), so the hall cannot be "
                            "confirmed. Turn on Precise Location for this site (iPhone: tap AA in the address bar → "
                            "Website Settings → Precise Location; or Settings → Privacy & Security → Location Services → "
                            "Safari Websites → Precise Location) and scan again.")
            elif effective > sess["geo_radius_m"]:
                geo_ok = False
                geo_fail = ("outside geofence", f"{distance:.0f} m away (±{acc:.0f} m)",
                            f"You appear to be about {distance:.0f} m from the lecture hall "
                            f"(allowed: {sess['geo_radius_m']} m). Attendance can only be taken inside the hall.")
            else:
                geo_ok = True
                if acc > LOW_ACCURACY_M:
                    flags.append(f"low GPS accuracy (±{acc:.0f} m)")

    # --- Rule 2: network --------------------------------------------------------
    ip = client_ip()
    net_ok, net_fail = None, None
    if not offline_sess and sess["network_mode"] in ("flag", "block"):
        ok = ip_allowed(ip)
        if ok is False:
            net_ok = False
            net_fail = ("off-campus network", ip,
                        f"You must be connected to the campus Wi-Fi to take attendance (your network: {ip}).")
        elif ok:
            net_ok = True

    # --- Combine: any-of ----------------------------------------------------------
    # When both rules are active, passing EITHER clears the student (the two signals fail
    # for unrelated reasons - a confused GPS vs. a phone on mobile data). Only when every
    # active rule fails do we act, and then the course decides: block (reject) or flag.
    if geo_ok is False or net_ok is False:
        fails = [f for f in (geo_fail, net_fail) if f]
        any_pass = geo_ok is True or net_ok is True
        if not any_pass:
            block = (geo_fail and geo_mode == "block") or (net_fail and sess["network_mode"] == "block")
            if block:
                reason, detail, msg = next(f for f in fails if (f is geo_fail and geo_mode == "block")
                                           or (f is net_fail and sess["network_mode"] == "block"))
                _reject(sess, student_id, reason, detail)
                return False, msg
            for reason, detail, _msg in fails:
                flags.append(f"{reason}: {detail}")

    # --- Rule 3: device checks (same-session shared, earlier shared, new device) ---
    now = time.time()
    status = "late" if now - sess["started_at"] > sess["late_after_min"] * 60 else "present"
    device_id = get_device_id()
    norm_hw = _normalize_hw_sig(hw_sig)
    clean_alt = _clean_alt_dev(alt_dev)
    ua_str = (request.user_agent.string or "")[:200]
    cur_ua_sig = _ua_hw_sig(ua_str)
    if clean_alt and clean_alt != device_id:
        # Browser cookie was cleared/rotated on the same origin while localStorage persisted:
        # restore and use the original browser device_id so history & shared-device stay intact.
        g.heal_device_id = clean_alt
        cur_devs = {device_id, clean_alt} if device_id else {clean_alt}
        effective_dev = clean_alt
    else:
        cur_devs = {device_id} if device_id else set()
        effective_dev = device_id

    # 3a. Same-session shared device (cookie/localStorage match OR same LAN phone IP in Offline Wi-Fi/Hotspot)
    same_sess_others = db.execute(
        """SELECT id, student_id, method, device_id, ip, hw_sig, flag_reason
             FROM checkins WHERE session_id=? AND student_id<>? AND method<>'manual'""",
        (sess["id"], student_id),
    ).fetchall()
    matched_same_sess = []
    for r in same_sess_others:
        r_dev = (r["device_id"] or "").strip()
        by_dev = bool(r_dev and r_dev in cur_devs)
        by_lan = (offline_sess and _is_lan_phone_ip(ip) and (r["ip"] or "").strip() == ip
                  and (not norm_hw or not r["hw_sig"] or r["hw_sig"] == norm_hw))
        if by_dev or by_lan:
            matched_same_sess.append(r)

    if matched_same_sess:
        flags.append("shared device")

    # 3b. Cross-session shared device (strictly chronological earlier sessions in this course)
    if cur_devs and not matched_same_sess:
        qmarks = ",".join("?" * len(cur_devs))
        earlier_other_rows = db.execute(
            f"""SELECT DISTINCT u.id, u.name
                  FROM checkins k
                  JOIN sessions s ON s.id = k.session_id
                  JOIN users u ON u.id = k.student_id
                 WHERE s.course_id=? AND s.id<>?
                   AND (s.started_at < ? OR (s.started_at = ? AND s.id < ?))
                   AND k.method<>'manual' AND k.student_id<>?
                   AND k.device_id IN ({qmarks})""",
            (sess["course_id"], sess["id"], sess["started_at"], sess["started_at"], sess["id"], student_id, *cur_devs),
        ).fetchall()
        if earlier_other_rows:
            onames = ", ".join(r["name"] for r in earlier_other_rows[:2])
            flags.append(f"previous shared device: used by {onames} in earlier session")

    # 3c. Chronological & origin-independent new device check (no false positive when IP/host changes)
    past_self = db.execute(
        """SELECT k.device_id, k.hw_sig, k.user_agent
             FROM checkins k JOIN sessions s ON s.id = k.session_id
            WHERE s.course_id=? AND s.id<>?
              AND (s.started_at < ? OR (s.started_at = ? AND s.id < ?))
              AND k.student_id=? AND k.method<>'manual'""",
        (sess["course_id"], sess["id"], sess["started_at"], sess["started_at"], sess["id"], student_id),
    ).fetchall()
    if past_self:
        past_devs = {r["device_id"] for r in past_self if r["device_id"]}
        past_hws = {r["hw_sig"] for r in past_self if r["hw_sig"]}
        past_uas = {_ua_hw_sig(r["user_agent"]) for r in past_self if _ua_hw_sig(r["user_agent"])}
        same_phone = bool(cur_devs & past_devs)
        if not same_phone and norm_hw and past_hws:
            same_phone = norm_hw in past_hws
        elif not same_phone and (not norm_hw or not past_hws) and cur_ua_sig and past_uas:
            same_phone = cur_ua_sig in past_uas
        if not same_phone:
            flags.append("new device: different phone from earlier sessions")

    cur_ins = db.execute(
        """INSERT INTO checkins (session_id,student_id,checked_at,status,method,device_id,ip,user_agent,
                                 flagged,flag_reason,flag_cleared,hw_sig,distance_m,accuracy_m)
           VALUES (?,?,?,?,?,?,?,?,?,?,0,?,?,?)""",
        (sess["id"], student_id, now, status, method, effective_dev, ip, ua_str,
         1 if flags else 0, "; ".join(flags) or None, norm_hw, distance, accuracy))
    if matched_same_sess:
        touch_ids = {cur_ins.lastrowid, *(r["id"] for r in matched_same_sess)}
        _reconcile_shared_device_flags(db, sess, reset_cleared_ids=touch_ids)
        upd = db.execute("SELECT flag_reason FROM checkins WHERE id=?", (cur_ins.lastrowid,)).fetchone()
        if upd and upd["flag_reason"]:
            flags = [p.strip() for p in upd["flag_reason"].split(";") if p.strip()]
    db.commit()
    # Structured copy of the flags for the student's result page (what, why, in plain words).
    g.checkin_flags = [{"reason": f.split(":")[0].split(" (")[0].strip(), "text": f} for f in flags]
    g.checkin_distance = distance
    g.checkin_radius = sess["geo_radius_m"] if sess["geo_lat"] is not None else None
    return True, status


# --- Scan tickets ------------------------------------------------------------
# Opening a valid QR link (or entering a valid 6-digit code) issues a short-lived
# ticket bound to this phone's device cookie. The ticket (not the raw QR token)
# is what the Confirm button submits, so slow logins don't hit "expired" and a
# copied link cannot be confirmed from a different phone.
_ticket_ser = URLSafeTimedSerializer(app.config["SECRET_KEY"], salt="scan-ticket")


def make_ticket(sess, method):
    return _ticket_ser.dumps({"sid": sess["id"], "dev": get_device_id() or "", "m": method})


def read_ticket(tok):
    try:
        d = _ticket_ser.loads(tok, max_age=SCAN_TICKET_SECONDS)
    except (BadSignature, TypeError):
        return None, None, "Your scan has expired. Please scan the QR code on the screen again."
    dev = get_device_id() or ""
    if d.get("dev") and dev and d["dev"] != dev:
        return None, None, "This link was opened on a different phone. Scan the QR code yourself."
    sess = get_db().execute("SELECT * FROM sessions WHERE id=?", (d["sid"],)).fetchone()
    if not sess or sess["ended_at"]:
        return None, None, "This session has already ended."
    return sess, d.get("m", "qr"), None


# ---------------------------------------------------------------------------
# Suspicion analysis for spot checks
# ---------------------------------------------------------------------------
from collections import defaultdict
import random

CO_WINDOW_S = 10   # two accounts checking in within this many seconds = "together"


def suspicion_scores(sess):
    """Return {student_id: (score, [reasons])} for everyone marked present in this session.
    Strictly chronological (never looks forward at future sessions) and avoids double-counting flags."""
    db = get_db()
    cid, sid_now = sess["course_id"], sess["id"]
    s_start = sess["started_at"]
    now_rows = db.execute(
        """SELECT k.*, u.name, u.matric FROM checkins k JOIN users u ON u.id=k.student_id
           WHERE k.session_id=?""", (sid_now,)).fetchall()
    now = {r["student_id"]: r for r in now_rows}
    prev = db.execute(
        """SELECT k.session_id, k.student_id, k.device_id, k.hw_sig, k.user_agent, k.checked_at
             FROM checkins k JOIN sessions s ON s.id=k.session_id
            WHERE s.course_id=? AND s.id<>?
              AND (s.started_at < ? OR (s.started_at = ? AND s.id < ?))
              AND k.method<>'manual'""",
        (cid, sid_now, s_start, s_start, sid_now)).fetchall()
    hist_dev = defaultdict(set)          # student -> device_ids used in earlier sessions
    hist_hw = defaultdict(set)           # student -> hw_sigs used in earlier sessions
    hist_ua = defaultdict(set)           # student -> ua_sigs used in earlier sessions
    hist_any = defaultdict(bool)         # student -> attended at least one earlier session
    dev_students = defaultdict(set)      # device  -> students who used it in earlier sessions
    per_sess = defaultdict(dict)         # session -> {student: time}
    for r in prev:
        st_id = r["student_id"]
        hist_any[st_id] = True
        if r["device_id"]:
            hist_dev[st_id].add(r["device_id"])
            dev_students[r["device_id"]].add(st_id)
        if r["hw_sig"]:
            hist_hw[st_id].add(r["hw_sig"])
        ua_s = _ua_hw_sig(r["user_agent"])
        if ua_s:
            hist_ua[st_id].add(ua_s)
        per_sess[r["session_id"]][st_id] = r["checked_at"]
    rejected = {r["student_id"] for r in db.execute(
        "SELECT DISTINCT student_id FROM rejections WHERE session_id=?", (sid_now,))}
    caught = {}
    for r in db.execute(
        """SELECT sc.student_id, MAX(sc.decided_at) AS d FROM spot_checks sc JOIN sessions s ON s.id=sc.session_id
            WHERE s.course_id=? AND s.id<>?
              AND (s.started_at < ? OR (s.started_at = ? AND s.id < ?))
              AND sc.outcome='absent'
            GROUP BY sc.student_id""", (cid, sid_now, s_start, s_start, sid_now)):
        caught[r["student_id"]] = r["d"]
    names = {r["student_id"]: r["name"] for r in now_rows}

    shared_groups = _build_session_phone_groups(db, sess)
    shared_member_info = {}
    for g_item in shared_groups:
        for m in g_item["members"]:
            shared_member_info[m["student_id"]] = m

    out = {}
    for sid, k in now.items():
        reasons = []
        flag_cleared = bool(k["flag_cleared"]) if "flag_cleared" in k.keys() else False
        has_new_dev_flag = False
        has_prev_shared_flag = False
        has_same_shared_flag = False
        if k["flagged"]:
            raw_parts = [p.strip() for p in (k["flag_reason"] or "check").split(";") if p.strip()]
            core_parts = []
            for p in raw_parts:
                low_p = p.lower()
                if low_p.startswith("new device"):
                    has_new_dev_flag = True
                    reasons.append((2, "flagged: " + p))
                elif low_p.startswith("previous shared device"):
                    has_prev_shared_flag = True
                    reasons.append((2, "flagged: " + p))
                else:
                    if _is_same_sess_shared_part(p):
                        has_same_shared_flag = True
                        sm = shared_member_info.get(sid)
                        if sm:
                            p = f"shared device: {sm['partner_str']} ({sm['order_detail']})"
                    core_parts.append(p)
            if core_parts:
                reasons.append((3, "flagged: " + "; ".join(core_parts)))
        if sid in rejected:
            reasons.append((3, "was rejected earlier this session, then succeeded"))
        # Legacy fallback for older sessions recorded before new-device / earlier-shared were stored in flag_reason
        if not flag_cleared and k["method"] != "manual":
            k_dev = k["device_id"]
            k_hw = k["hw_sig"] if "hw_sig" in k.keys() else None
            k_ua = _ua_hw_sig(k["user_agent"])
            if not has_new_dev_flag and hist_any[sid]:
                same_phone = bool(k_dev and k_dev in hist_dev[sid])
                if not same_phone and k_hw and hist_hw[sid]:
                    same_phone = k_hw in hist_hw[sid]
                elif not same_phone and (not k_hw or not hist_hw[sid]) and k_ua and hist_ua[sid]:
                    same_phone = k_ua in hist_ua[sid]
                if not same_phone:
                    reasons.append((2, "new device - different phone from earlier sessions"))
            if k_dev and not has_prev_shared_flag and not has_same_shared_flag:
                others = dev_students[k_dev] - {sid}
                if others:
                    onames = ", ".join(db.execute("SELECT name FROM users WHERE id=?", (o,)).fetchone()["name"] for o in list(others)[:2])
                    reasons.append((2, f"this phone was used by {onames} in earlier sessions"))
        if sid in caught:
            reasons.append((4, "marked ABSENT in a spot check on " + local_dt(caught[sid]).strftime("%d %b")))
        if k["method"] != "manual":
            for oid, ko in now.items():
                if oid == sid or ko["method"] == "manual" or abs(k["checked_at"] - ko["checked_at"]) > CO_WINDOW_S:
                    continue
                shared = together = 0
                for times in per_sess.values():
                    if sid in times and oid in times:
                        shared += 1
                        if abs(times[sid] - times[oid]) <= CO_WINDOW_S:
                            together += 1
                if shared >= 2 and together >= 2 and together / shared >= 0.6:
                    reasons.append((3, f"checked in within {CO_WINDOW_S}s of {names[oid]} in {together + 1} of {shared + 1} sessions"))
        out[sid] = (sum(w for w, _ in reasons), [t for _, t in reasons])
    return out


def pick_spot_check(sess, n):
    """Weighted pick: ~60% from the most suspicious, the rest uniformly random.
    Students already picked in this session are skipped."""
    db = get_db()
    scores = suspicion_scores(sess)
    already = {r["student_id"] for r in db.execute("SELECT student_id FROM spot_checks WHERE session_id=?", (sess["id"],))}
    pool = [sid for sid in scores if sid not in already]
    if not pool:
        return []
    n = min(n, len(pool))
    n_susp = math.ceil(n * 0.6)
    suspicious = sorted([sid for sid in pool if scores[sid][0] > 0], key=lambda x: (-scores[x][0], random.random()))
    chosen = suspicious[:n_susp]
    rest = [sid for sid in pool if sid not in chosen]
    chosen += random.sample(rest, min(n - len(chosen), len(rest)))
    random.shuffle(chosen)   # don't reveal which names were "the suspicious ones" by order
    ts = time.time()
    for sid in chosen:
        sc, reasons = scores[sid]
        db.execute("INSERT INTO spot_checks (session_id,student_id,picked_at,score,reasons) VALUES (?,?,?,?,?)",
                   (sess["id"], sid, ts, sc, "; ".join(reasons)))
    db.commit()
    return chosen


# ---------------------------------------------------------------------------
# Public / auth routes
# ---------------------------------------------------------------------------
@app.route("/")
def index():
    if g.user is None:
        # ?li=1 means we were just redirected here from a successful login; if the
        # session is still missing, the browser rejected the cookie.
        if request.args.get("li"):
            return redirect(url_for("login", cookie_fail=1))
        return redirect(url_for("login"))
    # Cookie worked -> the URL token is unnecessary; url_defaults won't add it
    # because g.url_token is only set when the cookie session was missing.
    if g.user["role"] == "student":
        return redirect(url_for("student_home"))
    if g.user["role"] == "admin":
        return redirect(url_for("admin_home"))
    return redirect(url_for("lecturer_home"))


@app.errorhandler(403)
def forbidden(_e):
    """Explain *why* instead of a bare 'Forbidden': almost always the wrong kind of account."""
    role = g.user["role"] if g.user else None
    path = request.path
    if path.startswith("/checkin"):
        needed = "a student account"
    elif path.startswith(("/lecturer", "/admin")):
        needed = "a lecturer or admin account" if path.startswith("/lecturer") else "an admin account"
    elif path.startswith("/student"):
        needed = "a student account"
    else:
        needed = "a different account"
    # Lecturer opening a colleague's course is the one case that isn't about role
    other_owner = role in ("lecturer",) and path.startswith("/lecturer/")
    return render_template("forbidden.html", role=role, needed=needed, other_owner=other_owner, path=path), 403


def _is_loopback_client():
    return (request.remote_addr or "") in ("127.0.0.1", "::1")


def _laptop_needs_setup():
    if not OFFLINE_WIFI:
        return False
    return get_db().execute("SELECT COUNT(*) FROM users WHERE role IN ('lecturer','admin')").fetchone()[0] == 0


@app.route("/login", methods=["GET", "POST"])
def login():
    is_localhost = _is_loopback_client()
    needs_setup = _laptop_needs_setup()
    cloud_url = get_setting("cloud_url", DEFAULT_CLOUD_URL) or DEFAULT_CLOUD_URL
    if request.method == "POST":
        matric = request.form["matric"].strip()
        pw = request.form["password"]
        db = get_db()
        u = db.execute("SELECT * FROM users WHERE matric=? COLLATE NOCASE", (matric,)).fetchone()
        # First-time (or unlinked / updated-password) lecturer login on an offline laptop:
        # connect to the online server automatically when reachable to pull roster & sync_token.
        raw_url = request.form.get("cloud_url") or cloud_url
        if OFFLINE_WIFI and is_localhost and request.form.get("cloud_bootstrap") == "1":
            if u is None:
                ok_boot, boot_msg, u = _bootstrap_lecturer_from_cloud(db, raw_url, matric, pw)
                if not ok_boot and u is None:
                    flash(boot_msg, "error")
                    return render_template("login.html", next=request.args.get("next", ""), cookie_fail=False,
                                           is_localhost=is_localhost, needs_setup=_laptop_needs_setup(),
                                           cloud_url=_normalize_cloud_url(raw_url) or cloud_url)
                if ok_boot and u is not None:
                    session.clear()
                    session.permanent = True
                    session["uid"] = u["id"]
                    tok = make_url_token(u["id"])
                    flash(boot_msg, "ok")
                    return redirect(url_for("lecturer_home", s=tok))
            elif u["role"] in ("lecturer", "admin"):
                norm_url = _normalize_cloud_url(raw_url) or cloud_url
                has_tok = bool(get_setting(_sync_token_key(u["matric"]), ""))
                if (not password_matches(u, pw) or not has_tok) and _cloud_is_reachable(norm_url, timeout=2.0):
                    ok_boot, _, u_new = _bootstrap_lecturer_from_cloud(db, norm_url, matric, pw)
                    if ok_boot and u_new is not None:
                        u = u_new
        if u and not u["active"] and password_matches(u, pw):
            flash("This account has been deactivated. Contact the department admin.", "error")
            return render_template("login.html", next=request.args.get("next", ""), cookie_fail=False,
                                   is_localhost=is_localhost, needs_setup=needs_setup, cloud_url=cloud_url)
        if u and password_matches(u, pw):
            if (not SHOW_DEMO_LOGINS and not OFFLINE_WIFI and u["role"] in ("admin", "lecturer")
                    and pw in DEFAULT_DEMO_PASSWORDS and not u["must_change_pw"]):
                # Public deployment still using a well-known demo password: force a change now.
                db.execute("UPDATE users SET must_change_pw=1 WHERE id=?", (u["id"],))
                db.commit()
                flash("This account is still using the default demo password. Choose a new one before continuing.", "error")
            session.clear()
            session.permanent = True
            session["uid"] = u["id"]
            tok = make_url_token(u["id"])
            nxt = request.args.get("next") or request.form.get("next")
            if nxt and nxt.startswith("/"):
                return redirect(nxt + ("&" if "?" in nxt else "?") + "s=" + tok)
            return redirect(url_for("index", li=1, s=tok))
        flash("Incorrect matric number or password.", "error")
    return render_template("login.html", next=request.args.get("next", ""),
                           cookie_fail=bool(request.args.get("cookie_fail")),
                           is_localhost=is_localhost, needs_setup=needs_setup, cloud_url=cloud_url)


@app.route("/register", methods=["GET", "POST"])
def register():
    if request.method == "POST":
        matric = request.form["matric"].strip().upper()
        name = request.form["name"].strip()
        pw = request.form["password"]
        if not matric or not name:
            flash("All fields are required.", "error")
        elif password_problem(pw, matric):
            flash(password_problem(pw, matric), "error")
        else:
            db = get_db()
            try:
                db.execute("INSERT INTO users (matric,name,password_hash,role,created_at,pw_updated_at) VALUES (?,?,?,?,?,?)",
                           (matric, name, generate_password_hash(pw), "student", now_iso(), time.time()))
                db.commit()
                mark_sync_dirty()
                flash("Account created. You can log in now.", "ok")
                nxt = request.form.get("next") or ""
                return redirect(url_for("login", next=nxt) if nxt.startswith("/") else url_for("login"))
            except sqlite3.IntegrityError:
                flash("That matric number is already registered.", "error")
    return render_template("register.html", next=request.args.get("next", ""))


@app.route("/logout")
def logout():
    session.clear()
    g.url_token = None
    return redirect(url_for("login"))


# ---------------------------------------------------------------------------
# Student routes
# ---------------------------------------------------------------------------
@app.route("/student")
@login_required("student")
def student_home():
    db = get_db()
    courses = db.execute(
        """SELECT c.*, u.name AS lecturer,
              (SELECT COUNT(*) FROM sessions s WHERE s.course_id=c.id AND s.ended_at IS NOT NULL) AS total_sessions,
              (SELECT COUNT(*) FROM checkins k JOIN sessions s ON s.id=k.session_id
                 WHERE s.course_id=c.id AND s.ended_at IS NOT NULL AND k.student_id=?) AS attended,
              (SELECT s.id FROM sessions s WHERE s.course_id=c.id AND s.ended_at IS NULL LIMIT 1) AS live_session,
              (SELECT s.title FROM sessions s WHERE s.course_id=c.id AND s.ended_at IS NULL LIMIT 1) AS live_title,
              (SELECT k.checked_at FROM checkins k JOIN sessions s ON s.id=k.session_id
                 WHERE s.course_id=c.id AND s.ended_at IS NULL AND k.student_id=? LIMIT 1) AS live_checked_at
           FROM courses c JOIN enrolments e ON e.course_id=c.id JOIN users u ON u.id=c.lecturer_id
           WHERE e.student_id=? AND c.archived=0 ORDER BY c.code""", (g.user["id"], g.user["id"], g.user["id"])).fetchall()
    history = db.execute(
        """SELECT k.*, s.title AS session_title, c.code AS course_code FROM checkins k
           JOIN sessions s ON s.id=k.session_id JOIN courses c ON c.id=s.course_id
           WHERE k.student_id=? ORDER BY k.checked_at DESC LIMIT 20""", (g.user["id"],)).fetchall()
    return render_template("student_home.html", courses=courses, history=history)


@app.route("/student/join", methods=["POST"])
@login_required("student")
def join_course():
    """Step 1: student types a join code -> we show the course and ask for confirmation.
    Step 2 (confirm=1): enrol. Prevents the common 'typed the wrong code' mistake."""
    code = request.form["join_code"].strip().upper()
    db = get_db()
    c = db.execute(
        """SELECT c.*, u.name AS lecturer,
                  (SELECT COUNT(*) FROM enrolments e WHERE e.course_id=c.id) AS n_students
           FROM courses c JOIN users u ON u.id=c.lecturer_id
           WHERE c.join_code=? COLLATE NOCASE AND c.archived=0""", (code,)).fetchone()
    if not c:
        flash("No course with that join code. Check it with your lecturer.", "error")
        return redirect(url_for("student_home"))
    already = db.execute("SELECT 1 FROM enrolments WHERE course_id=? AND student_id=?",
                         (c["id"], g.user["id"])).fetchone()
    if already:
        flash(f"You are already enrolled in {c['code']}.", "ok")
        return redirect(url_for("student_home"))
    if request.form.get("confirm") != "1":
        return render_template("join_confirm.html", course=c, join_code=code)
    db.execute("INSERT OR IGNORE INTO enrolments VALUES (?,?)", (c["id"], g.user["id"]))
    log_enrolment(db, c["id"], g.user["id"], "joined", g.user["id"])
    db.commit()
    mark_sync_dirty()
    flash(f"Enrolled in {c['code']} – {c['title']}.", "ok")
    return redirect(url_for("student_home"))


@app.route("/join/<code>")
def join_link(code):
    """Shareable enrolment link: /join/DSA301. Lecturers paste it in the class group chat.
    Not logged in -> landing page with the course name and Log in / Create account buttons that
    return here afterwards. Student -> the usual 'Yes, enrol me' confirmation. Staff -> 403."""
    code = code.strip().upper()
    db = get_db()
    c = db.execute(
        """SELECT c.*, u.name AS lecturer,
                  (SELECT COUNT(*) FROM enrolments e WHERE e.course_id=c.id) AS n_students
           FROM courses c JOIN users u ON u.id=c.lecturer_id
           WHERE c.join_code=? COLLATE NOCASE AND c.archived=0""", (code,)).fetchone()
    if not g.get("user"):
        return render_template("join_landing.html", course=c, join_code=code,
                               next_url=url_for("join_link", code=code))
    if g.user["role"] != "student":
        abort(403)
    if not c:
        flash("That join link is no longer valid. Ask your lecturer for a new one.", "error")
        return redirect(url_for("student_home"))
    if db.execute("SELECT 1 FROM enrolments WHERE course_id=? AND student_id=?", (c["id"], g.user["id"])).fetchone():
        flash(f"You are already enrolled in {c['code']}.", "ok")
        return redirect(url_for("student_home"))
    return render_template("join_confirm.html", course=c, join_code=code)


@app.route("/student/course/<int:course_id>/leave", methods=["POST"])
@login_required("student")
def leave_course(course_id):
    """Student leaves a course. Past check-ins are kept; the lecturer sees the change."""
    db = get_db()
    c = db.execute("SELECT * FROM courses WHERE id=?", (course_id,)).fetchone()
    enrolled = db.execute("SELECT 1 FROM enrolments WHERE course_id=? AND student_id=?",
                          (course_id, g.user["id"])).fetchone()
    if not c or not enrolled:
        flash("You are not enrolled in that course.", "error")
        return redirect(url_for("student_home"))
    live = db.execute("SELECT 1 FROM sessions WHERE course_id=? AND ended_at IS NULL", (course_id,)).fetchone()
    if live:
        flash(f"{c['code']} is taking attendance right now - you can leave once the session has ended.", "error")
        return redirect(url_for("student_home"))
    if request.form.get("confirm", "").strip().upper() != c["code"].upper():
        flash(f"To leave {c['code']}, type the course code exactly to confirm.", "error")
        return redirect(url_for("student_home"))
    db.execute("DELETE FROM enrolments WHERE course_id=? AND student_id=?", (course_id, g.user["id"]))
    log_enrolment(db, course_id, g.user["id"], "left", g.user["id"])
    db.commit()
    flash(f"You have left {c['code']}. Your past check-ins are kept; you can rejoin any time with the join code.", "ok")
    return redirect(url_for("student_home"))


@app.route("/checkin", methods=["GET", "POST"])
def checkin():
    """
    GET  ?t=QRTOKEN   -> validate the rotating token, issue a scan ticket (?k=)
    GET  ?k=TICKET    -> confirmation page (collects location if the session needs it)
    POST code=123456  -> validate 6-digit code, issue ticket, show confirmation page
    POST k=TICKET     -> apply rules, record the check-in
    """
    db = get_db()

    # 1. A QR scan arrives. Validate quickly (20 s window) and convert to a ticket.
    qr = request.args.get("t", "").strip()
    if qr:
        sess, err = verify_token(qr)
        if err:
            flash(err, "error")
            return redirect(url_for("checkin"))
        return redirect(url_for("checkin", k=make_ticket(sess, "qr")))

    # Everything below requires a logged-in student.
    if g.user is None:
        return redirect(url_for("login", next=request.full_path, s=None))
    if g.user["role"] != "student":
        abort(403)

    def course_of(sess):
        return db.execute("SELECT c.*, u.name AS lecturer FROM courses c JOIN users u ON u.id=c.lecturer_id WHERE c.id=?",
                          (sess["course_id"],)).fetchone()

    def is_enrolled(sess):
        return db.execute("SELECT 1 FROM enrolments WHERE course_id=? AND student_id=?",
                          (sess["course_id"], g.user["id"])).fetchone() is not None

    def confirm_page(sess, ticket):
        course = course_of(sess)
        need_geo = (not _is_offline_session(sess)) and (sess["geo_lat"] is not None)
        return render_template("checkin.html", ticket=ticket, sess=sess, course=course,
                               need_geo=need_geo, rules=session_rules(sess),
                               need_enrol=not is_enrolled(sess), can_enrol=bool(course["qr_enrol"]))

    if request.method == "POST":
        ticket = request.form.get("k", "").strip()
        code = request.form.get("code", "").strip()
        if ticket:
            sess, method, err = read_ticket(ticket)
            if err:
                flash(err, "error")
                return redirect(url_for("checkin"))

            def num(name):
                try:
                    return float(request.form[name])
                except (KeyError, ValueError):
                    return None
            course = course_of(sess)
            just_enrolled = False
            if not is_enrolled(sess):
                # Option A: the rotating QR on the lecturer's screen is the proof the student is in the room,
                # so a course that allows it lets them enrol and check in with one tap (logged as "qr").
                if not course["qr_enrol"]:
                    flash("You are not enrolled in this course and it does not allow enrolment by scanning. "
                          "Ask the lecturer for the join code.", "error")
                    return redirect(url_for("checkin"))
                if request.form.get("enrol") != "1":
                    flash("Tick 'Enrol me in this course' to continue.", "error")
                    return redirect(url_for("checkin", k=ticket))
                db.execute("INSERT OR IGNORE INTO enrolments VALUES (?,?)", (course["id"], g.user["id"]))
                log_enrolment(db, course["id"], g.user["id"], "qr", g.user["id"])
                db.commit()
                just_enrolled = True
            ok, result = record_checkin(
                sess, g.user["id"], method, num("lat"), num("lng"), num("acc"),
                hw_sig=request.form.get("hw_sig"), alt_dev=request.form.get("alt_dev"),
            )
            if not ok:
                if just_enrolled:
                    flash(f"You are now enrolled in {course['code']}, but attendance was not recorded: {result}", "error")
                else:
                    flash(result, "error")
                return redirect(url_for("checkin"))
            if just_enrolled:
                flash(f"You are now enrolled in {course['code']} – {course['title']}.", "ok")
            return render_template("checkin_done.html", sess=sess, course=course, status=result,
                                   flags=getattr(g, "checkin_flags", []), distance=getattr(g, "checkin_distance", None),
                                   radius=getattr(g, "checkin_radius", None))
        if code:
            sess, err = verify_short_code(code, g.user["id"])
            if err:
                flash(err, "error")
                return redirect(url_for("checkin"))
            return confirm_page(sess, make_ticket(sess, "code"))
        flash("Enter the code shown on the screen.", "error")
        return redirect(url_for("checkin"))

    ticket = request.args.get("k", "").strip()
    if ticket:
        sess, _method, err = read_ticket(ticket)
        if err:
            flash(err, "error")
            return redirect(url_for("checkin"))
        return confirm_page(sess, ticket)
    return render_template("checkin.html", ticket=None, sess=None, course=None, need_geo=False)


# ---------------------------------------------------------------------------
# Lecturer routes
# ---------------------------------------------------------------------------
def owned_course(course_id):
    c = get_db().execute("SELECT * FROM courses WHERE id=?", (course_id,)).fetchone()
    if not c:
        abort(404)
    if g.user["role"] != "admin" and c["lecturer_id"] != g.user["id"]:
        abort(403)
    return c


def owned_session(session_id):
    s = get_db().execute("SELECT * FROM sessions WHERE id=?", (session_id,)).fetchone()
    if not s:
        abort(404)
    owned_course(s["course_id"])
    return s


@app.route("/lecturer")
@login_required("lecturer", "admin")
def lecturer_home():
    db = get_db()
    q = """SELECT c.*, u.name AS lecturer,
              (SELECT COUNT(*) FROM enrolments e WHERE e.course_id=c.id) AS n_students,
              (SELECT COUNT(*) FROM sessions s WHERE s.course_id=c.id) AS n_sessions,
              (SELECT s.id FROM sessions s WHERE s.course_id=c.id AND s.ended_at IS NULL LIMIT 1) AS live_session
           FROM courses c JOIN users u ON u.id=c.lecturer_id"""
    show_archived = request.args.get("archived") == "1"
    where = " WHERE c.archived=?" + ("" if g.user["role"] == "admin" else " AND c.lecturer_id=?")
    args = (1 if show_archived else 0,) + (() if g.user["role"] == "admin" else (g.user["id"],))
    courses = db.execute(q + where + " ORDER BY c.code", args).fetchall()
    n_archived = db.execute("SELECT COUNT(*) FROM courses WHERE archived=1" +
                            ("" if g.user["role"] == "admin" else " AND lecturer_id=?"),
                            () if g.user["role"] == "admin" else (g.user["id"],)).fetchone()[0]
    lecturers = db.execute("SELECT id, name, matric FROM users WHERE role='lecturer' AND active=1 ORDER BY name").fetchall() \
        if g.user["role"] == "admin" else []
    return render_template("lecturer_home.html", courses=courses, show_archived=show_archived, n_archived=n_archived,
                           lecturers=lecturers, sync_info=_lecturer_sync_info(db, g.user) if OFFLINE_WIFI else None)


@app.route("/lecturer/course/new", methods=["POST"])
@login_required("lecturer", "admin")
def new_course():
    code = request.form["code"].strip().upper()
    title = request.form["title"].strip()
    join_code = (request.form.get("join_code") or secrets.token_hex(3)).strip().upper()
    db = get_db()
    owner = g.user["id"]
    back = url_for("lecturer_home")
    if g.user["role"] == "admin" and not request.form.get("lecturer_id"):
        flash("Choose which lecturer the course belongs to.", "error")
        return redirect(url_for("lecturer_home"))
    if g.user["role"] == "admin":
        # Admin creating a course on a lecturer's behalf (from the lecturer's admin page).
        lec = db.execute("SELECT id FROM users WHERE id=? AND role='lecturer' AND active=1",
                         (request.form["lecturer_id"],)).fetchone()
        if not lec:
            flash("That lecturer account was not found.", "error")
            return redirect(url_for("admin_home"))
        owner = lec["id"]
        back = url_for("admin_lecturer", user_id=owner)
    try:
        db.execute("INSERT INTO courses (code,title,lecturer_id,join_code,created_at) VALUES (?,?,?,?,?)",
                   (code, title, owner, join_code, now_iso()))
        db.commit()
        mark_sync_dirty()
        flash(f"Course {code} created. Join code: {join_code}", "ok")
    except sqlite3.IntegrityError:
        flash("Course code or join code already exists.", "error")
    return redirect(back)


@app.route("/lecturer/course/<int:course_id>")
@login_required("lecturer", "admin")
def course_page(course_id):
    c = owned_course(course_id)
    db = get_db()
    sessions = db.execute(
        """SELECT s.*, (SELECT COUNT(*) FROM checkins k WHERE k.session_id=s.id) AS n_present,
                  (SELECT COUNT(*) FROM checkins k WHERE k.session_id=s.id AND k.flagged=1) AS n_flagged
           FROM sessions s WHERE s.course_id=? ORDER BY s.started_at DESC""", (course_id,)).fetchall()
    n_ended = sum(1 for s in sessions if s["ended_at"])
    live = next((s for s in sessions if not s["ended_at"]), None)
    # Students already checked in to the session running right now (shown in a separate "Now"
    # column so the lecturer sees who is in the hall without the % moving mid-class).
    live_now = {r["student_id"]: r["checked_at"] for r in db.execute(
        "SELECT student_id, checked_at FROM checkins WHERE session_id=?", (live["id"],)).fetchall()} if live else {}
    students = db.execute(
        """SELECT u.id, u.matric, u.name,
              (SELECT COUNT(*) FROM checkins k JOIN sessions s ON s.id=k.session_id
                 WHERE s.course_id=? AND s.ended_at IS NOT NULL AND k.student_id=u.id) AS attended,
              (SELECT COUNT(*) FROM spot_checks sc JOIN sessions s ON s.id=sc.session_id
                 WHERE s.course_id=? AND sc.student_id=u.id AND sc.outcome='absent') AS caught
           FROM users u JOIN enrolments e ON e.student_id=u.id
           WHERE e.course_id=? ORDER BY u.matric""", (course_id, course_id, course_id)).fetchall()
    lecturers = db.execute("SELECT id, name, matric FROM users WHERE role IN ('lecturer','admin') ORDER BY name").fetchall() \
        if g.user["role"] == "admin" else []
    changes = db.execute(
        """SELECT ev.action, ev.at, u.matric, u.name, b.name AS by_name
           FROM enrolment_events ev JOIN users u ON u.id=ev.student_id LEFT JOIN users b ON b.id=ev.by_user_id
           WHERE ev.course_id=? ORDER BY ev.at DESC LIMIT 15""", (course_id,)).fetchall()
    unsynced_course = sum(1 for s in sessions if s["ended_at"] and not s["synced_at"]) if OFFLINE_WIFI else 0
    return render_template("course.html", course=c, sessions=sessions, students=students, lecturers=lecturers,
                           n_ended=n_ended, n_total=len(sessions), rules=session_rules(c), changes=changes,
                           live=live, live_now=live_now,
                           unsynced_course=unsynced_course,
                           sync_info=_lecturer_sync_info(db, g.user) if OFFLINE_WIFI else None,
                           join_url=public_url("join_link", code=c["join_code"]))


@app.route("/lecturer/course/<int:course_id>/enrol", methods=["POST"])
@login_required("lecturer", "admin")
def bulk_enrol(course_id):
    """Paste a list of matric numbers (one per line, optionally 'MATRIC, Name')."""
    owned_course(course_id)
    db = get_db()
    added = created = 0
    for line in request.form["matrics"].splitlines():
        parts = [p.strip() for p in line.replace("\t", ",").split(",") if p.strip()]
        if not parts:
            continue
        matric = parts[0].upper()
        u = db.execute("SELECT id FROM users WHERE matric=? COLLATE NOCASE", (matric,)).fetchone()
        if not u:
            # Pre-create the account; default password = matric number (student should change it)
            name = parts[1] if len(parts) > 1 else matric
            db.execute("INSERT INTO users (matric,name,password_hash,role,created_at,must_change_pw) VALUES (?,?,?,?,?,1)",
                       (matric, name, generate_password_hash(matric), "student", now_iso()))
            u = db.execute("SELECT id FROM users WHERE matric=?", (matric,)).fetchone()
            created += 1
        cur = db.execute("INSERT OR IGNORE INTO enrolments VALUES (?,?)", (course_id, u["id"]))
        if cur.rowcount:
            log_enrolment(db, course_id, u["id"], "bulk", g.user["id"])
        added += cur.rowcount
    db.commit()
    if added or created:
        mark_sync_dirty()
    flash(f"Enrolled {added} student(s); {created} new account(s) created (temporary password = matric number, must be changed at first login).", "ok")
    return redirect(url_for("course_page", course_id=course_id))


def apply_rules_to_live_sessions(db, course_id):
    """Sessions snapshot the course rules when they start; keep a running session in step
    when the lecturer corrects the hall location / radius mid-lecture. Returns rows touched."""
    c = db.execute("SELECT geo_lat, geo_lng, geo_radius_m, geo_acc_m, geo_mode, network_mode FROM courses WHERE id=?", (course_id,)).fetchone()
    cur = db.execute("""UPDATE sessions SET geo_lat=?, geo_lng=?, geo_radius_m=?, geo_acc_m=?, geo_mode=?, network_mode=?
                        WHERE course_id=? AND ended_at IS NULL""",
                     (c["geo_lat"], c["geo_lng"], c["geo_radius_m"], c["geo_acc_m"], c["geo_mode"], c["network_mode"], course_id))
    return cur.rowcount


@app.route("/lecturer/course/<int:course_id>/rules", methods=["POST"])
@login_required("lecturer", "admin")
def course_rules(course_id):
    owned_course(course_id)
    db = get_db()
    if request.form.get("action") == "clear_geo":
        db.execute("UPDATE courses SET geo_lat=NULL, geo_lng=NULL WHERE id=?", (course_id,))
        live = apply_rules_to_live_sessions(db, course_id)
        db.commit()
        flash("Geofence removed." + (" Applied to the session running now as well." if live else ""), "ok")
        return redirect(url_for("course_page", course_id=course_id))
    try:
        lat = float(request.form["lat"]) if request.form.get("lat") else None
        lng = float(request.form["lng"]) if request.form.get("lng") else None
        radius = max(MIN_RADIUS_M, min(2000, int(request.form.get("radius") or 100)))
    except ValueError:
        flash("Latitude/longitude must be numbers.", "error")
        return redirect(url_for("course_page", course_id=course_id))
    mode = request.form.get("network_mode", "off")
    if mode not in ("off", "flag", "block"):
        mode = "off"
    geo_mode = request.form.get("geo_mode", "flag")
    if geo_mode not in ("flag", "block"):
        geo_mode = "flag"
    if (lat is None) != (lng is None):
        flash("Provide both latitude and longitude, or leave both empty.", "error")
        return redirect(url_for("course_page", course_id=course_id))
    cur = db.execute("SELECT geo_lat, geo_lng, geo_acc_m FROM courses WHERE id=?", (course_id,)).fetchone()
    if lat is None or cur["geo_lat"] is None:
        moved = (lat is None) != (cur["geo_lat"] is None)
    else:   # opening the map rewrites the boxes to 6 decimals (centimetres) - that is not a move
        moved = haversine_m(lat, lng, cur["geo_lat"], cur["geo_lng"]) > 1.0
    acc = 0.0 if moved else float(cur["geo_acc_m"] or 0)   # a new map pin / typed point is exact
    db.execute("UPDATE courses SET geo_lat=?, geo_lng=?, geo_radius_m=?, geo_acc_m=?, geo_mode=?, network_mode=? WHERE id=?",
               (lat, lng, radius, acc, geo_mode, mode, course_id))
    live = apply_rules_to_live_sessions(db, course_id)
    db.commit()
    if live:
        flash("Rules also applied to the session running now - students who were rejected can scan again.", "ok")
    if mode != "off" and not allowed_networks():
        flash("Network rule saved, but no campus networks are configured yet - ask the admin to add them "
              "under Settings. Until then the rule has no effect.", "error")
    else:
        flash("Attendance rules saved.", "ok")
    return redirect(url_for("course_page", course_id=course_id))


# --- Course management: edit / archive / delete / remove student / reset pw ----
@app.route("/lecturer/course/<int:course_id>/edit", methods=["POST"])
@login_required("lecturer", "admin")
def edit_course(course_id):
    c = owned_course(course_id)
    db = get_db()
    if request.form.get("action") == "qr_enrol":
        on = 1 if request.form.get("qr_enrol") == "1" else 0
        db.execute("UPDATE courses SET qr_enrol=? WHERE id=?", (on, course_id))
        db.commit()
        mark_sync_dirty()
        flash("Students can now enrol by scanning the session QR." if on else
              "Enrol-by-scan turned off. Only students on the list (join code / upload) can check in.", "ok")
        return redirect(url_for("course_page", course_id=course_id))
    if request.form.get("action") == "regen_join":
        db.execute("UPDATE courses SET join_code=? WHERE id=?", (secrets.token_hex(3).upper(), course_id))
        db.commit()
        mark_sync_dirty()
        flash("New join code generated. Students already enrolled are unaffected.", "ok")
        return redirect(url_for("course_page", course_id=course_id))
    code = request.form["code"].strip().upper()
    title = request.form["title"].strip()
    join_code = request.form["join_code"].strip().upper()
    if not code or not title or not join_code:
        flash("Code, title and join code are required.", "error")
        return redirect(url_for("course_page", course_id=course_id))
    try:
        db.execute("UPDATE courses SET code=?, title=?, join_code=? WHERE id=?", (code, title, join_code, course_id))
        if g.user["role"] == "admin" and request.form.get("lecturer_id"):
            db.execute("UPDATE courses SET lecturer_id=? WHERE id=?", (int(request.form["lecturer_id"]), course_id))
        db.commit()
        mark_sync_dirty()
        flash("Course details updated.", "ok")
    except sqlite3.IntegrityError:
        flash("Another course already uses that code or join code.", "error")
    return redirect(url_for("course_page", course_id=course_id))


@app.route("/lecturer/course/<int:course_id>/archive", methods=["POST"])
@login_required("lecturer", "admin")
def archive_course(course_id):
    c = owned_course(course_id)
    db = get_db()
    if db.execute("SELECT 1 FROM sessions WHERE course_id=? AND ended_at IS NULL", (course_id,)).fetchone():
        flash("End the live session before archiving.", "error")
        return redirect(url_for("course_page", course_id=course_id))
    new = 0 if c["archived"] else 1
    db.execute("UPDATE courses SET archived=? WHERE id=?", (new, course_id))
    db.commit()
    mark_sync_dirty()
    flash("Course archived. All records are kept; it no longer appears in active lists." if new else "Course restored.", "ok")
    return redirect(url_for("course_page", course_id=course_id) if not new else url_for("lecturer_home"))


@app.route("/lecturer/course/<int:course_id>/delete", methods=["POST"])
@login_required("lecturer", "admin")
def delete_course(course_id):
    c = owned_course(course_id)
    db = get_db()
    n_sessions = db.execute("SELECT COUNT(*) FROM sessions WHERE course_id=?", (course_id,)).fetchone()[0]
    if n_sessions and g.user["role"] != "admin":
        flash("This course has attendance records. Archive it instead (admins can delete).", "error")
        return redirect(url_for("course_page", course_id=course_id))
    if request.form.get("confirm", "").strip().upper() != c["code"]:
        flash(f"Type the course code ({c['code']}) to confirm deletion.", "error")
        return redirect(url_for("course_page", course_id=course_id))
    sess_ids = "(SELECT id FROM sessions WHERE course_id=?)"
    for t in ("spot_checks", "rejections", "checkins"):
        db.execute(f"DELETE FROM {t} WHERE session_id IN {sess_ids}", (course_id,))
    db.execute("DELETE FROM sessions WHERE course_id=?", (course_id,))
    db.execute("DELETE FROM enrolments WHERE course_id=?", (course_id,))
    db.execute("DELETE FROM courses WHERE id=?", (course_id,))
    db.commit()
    flash(f"Course {c['code']} deleted.", "ok")
    return redirect(url_for("lecturer_home"))


@app.route("/lecturer/course/<int:course_id>/unenrol", methods=["POST"])
@login_required("lecturer", "admin")
def unenrol_student(course_id):
    owned_course(course_id)
    db = get_db()
    sid = int(request.form["student_id"])
    db.execute("DELETE FROM enrolments WHERE course_id=? AND student_id=?", (course_id, sid))
    log_enrolment(db, course_id, sid, "removed", g.user["id"])
    db.commit()
    flash("Student removed from the course. Their past check-ins are kept in the records.", "ok")
    return redirect(url_for("course_page", course_id=course_id))


@app.route("/lecturer/course/<int:course_id>/reset_password", methods=["POST"])
@login_required("lecturer", "admin")
def lecturer_reset_password(course_id):
    """A lecturer may reset the password of a student enrolled in their course."""
    owned_course(course_id)
    db = get_db()
    sid = int(request.form["student_id"])
    row = db.execute("""SELECT u.name FROM users u JOIN enrolments e ON e.student_id=u.id
                        WHERE e.course_id=? AND u.id=? AND u.role='student'""", (course_id, sid)).fetchone()
    if not row:
        abort(404)
    matric = reset_password_to_matric(sid, g.user["id"])
    mark_sync_dirty()
    flash(f"Password for {row['name']} reset. Temporary password: {matric} (their matric number). "
          "They must choose a new password at next login.", "ok")
    return redirect(url_for("course_page", course_id=course_id))


@app.route("/lecturer/session/<int:session_id>/edit", methods=["POST"])
@login_required("lecturer", "admin")
def edit_session(session_id):
    owned_session(session_id)
    title = request.form.get("title", "").strip()
    if title:
        db = get_db()
        if OFFLINE_WIFI:
            db.execute("UPDATE sessions SET title=?, synced_at=NULL WHERE id=?", (title, session_id))
        else:
            db.execute("UPDATE sessions SET title=? WHERE id=?", (title, session_id))
        db.commit()
        if OFFLINE_WIFI:
            trigger_auto_sync()
        flash("Session renamed.", "ok")
    return redirect(url_for("session_report", session_id=session_id))


@app.route("/lecturer/session/<int:session_id>/delete", methods=["POST"])
@login_required("lecturer", "admin")
def delete_session(session_id):
    sess = owned_session(session_id)
    db = get_db()
    if OFFLINE_WIFI and sess["sync_uuid"]:
        db.execute("INSERT OR REPLACE INTO deleted_sessions (sync_uuid, deleted_at) VALUES (?, ?)",
                   (sess["sync_uuid"], time.time()))
    for t in ("spot_checks", "rejections", "checkins"):
        db.execute(f"DELETE FROM {t} WHERE session_id=?", (session_id,))
    db.execute("DELETE FROM sessions WHERE id=?", (session_id,))
    db.commit()
    mark_sync_dirty()
    flash(f"Session '{sess['title']}' and its records deleted.", "ok")
    return redirect(url_for("course_page", course_id=sess["course_id"]))


# --- Set the hall location from the lecturer's phone -------------------------
# Laptops have no GPS. The course page shows a QR; the lecturer scans it with a
# phone while standing in the hall, taps "Use this location", and the phone's
# GPS fix is written to the course. A signed 10-minute token authorises it.
_locate_ser = URLSafeTimedSerializer(app.config["SECRET_KEY"], salt="locate")
LOCATE_TOKEN_SECONDS = 10 * 60


@app.route("/lecturer/course/<int:course_id>/locate.svg")
@login_required("lecturer", "admin")
def locate_qr(course_id):
    owned_course(course_id)
    tok = _locate_ser.dumps({"cid": course_id, "by": g.user["id"]})
    qr = segno.make(public_url("locate_phone", tok=tok), error="m")
    buf = io.BytesIO()
    qr.save(buf, kind="svg", scale=8, border=1, dark="#0f172a", light=None)
    buf.seek(0)
    resp = send_file(buf, mimetype="image/svg+xml")
    resp.headers["Cache-Control"] = "no-store"
    return resp


@app.route("/locate/<tok>", methods=["GET", "POST"])
def locate_phone(tok):
    try:
        d = _locate_ser.loads(tok, max_age=LOCATE_TOKEN_SECONDS)
    except BadSignature:
        return render_template("locate.html", course=None, error="This link has expired. Click 'Set from my phone' on the laptop again."), 400
    db = get_db()
    course = db.execute("SELECT * FROM courses WHERE id=?", (d["cid"],)).fetchone()
    if not course:
        abort(404)
    if request.method == "POST":
        try:
            lat, lng, acc = float(request.form["lat"]), float(request.form["lng"]), float(request.form.get("acc") or 0)
        except (KeyError, ValueError):
            return render_template("locate.html", course=course, error="No position received."), 400
        if acc > 150:
            return render_template("locate.html", course=course,
                                   error=f"That fix was only accurate to about {acc:.0f} m - too rough to use as the hall "
                                         "position. Turn on precise location, stand near a window and try again."), 400
        db.execute("UPDATE courses SET geo_lat=?, geo_lng=?, geo_acc_m=? WHERE id=?", (lat, lng, acc, course["id"]))
        apply_rules_to_live_sessions(db, course["id"])
        db.commit()
        course = db.execute("SELECT * FROM courses WHERE id=?", (course["id"],)).fetchone()
        return render_template("locate.html", course=course, done=True, acc=acc,
                               allow_student=GPS_ALLOWANCE_M, allow_ref=REF_ALLOWANCE_M)
    return render_template("locate.html", course=course)


@app.route("/api/course/<int:course_id>/geo")
@login_required("lecturer", "admin")
def course_geo(course_id):
    c = owned_course(course_id)
    return jsonify({"lat": c["geo_lat"], "lng": c["geo_lng"], "radius": c["geo_radius_m"], "acc": c["geo_acc_m"]})


@app.route("/lecturer/course/<int:course_id>/start", methods=["POST"])
@login_required("lecturer", "admin")
def start_session(course_id):
    c = owned_course(course_id)
    db = get_db()
    if c["archived"]:
        flash("This course is archived. Restore it first to take attendance.", "error")
        return redirect(url_for("course_page", course_id=course_id))
    live = db.execute("SELECT id FROM sessions WHERE course_id=? AND ended_at IS NULL", (course_id,)).fetchone()
    if live:
        return redirect(url_for("live_session", session_id=live["id"]))
    title = request.form.get("title", "").strip() or local_dt().strftime("Lecture %d %b %Y, %H:%M")
    late = int(request.form.get("late_after_min") or 15)
    if OFFLINE_WIFI:
        cur = db.execute(
            """INSERT INTO sessions (course_id,title,secret,started_at,late_after_min,
                                     geo_lat,geo_lng,geo_radius_m,geo_acc_m,geo_mode,network_mode,
                                     sync_uuid,offline_wifi) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,1)""",
            (c["id"], title, secrets.token_hex(32), time.time(), late,
             None, None, c["geo_radius_m"], 0, "flag", "off", uuid.uuid4().hex))
    else:
        cur = db.execute(
            """INSERT INTO sessions (course_id,title,secret,started_at,late_after_min,
                                     geo_lat,geo_lng,geo_radius_m,geo_acc_m,geo_mode,network_mode,
                                     sync_uuid,offline_wifi) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,0)""",
            (c["id"], title, secrets.token_hex(32), time.time(), late,
             c["geo_lat"], c["geo_lng"], c["geo_radius_m"], c["geo_acc_m"], c["geo_mode"], c["network_mode"], uuid.uuid4().hex))
    db.commit()
    wake_wifi_now()
    return redirect(url_for("live_session", session_id=cur.lastrowid))


@app.route("/lecturer/session/<int:session_id>/live")
@login_required("lecturer", "admin")
def live_session(session_id):
    s = owned_session(session_id)
    if s["ended_at"]:
        return redirect(url_for("session_report", session_id=session_id))
    wake_wifi_now()
    c = owned_course(s["course_id"])
    lec_row = get_db().execute("SELECT name FROM users WHERE id=?", (c["lecturer_id"],)).fetchone()
    return render_template("live.html", sess=s, course=c,
                           lecturer_name=lec_row["name"] if lec_row else "",
                           rules=session_rules(s),
                           join_url=public_url("join_link", code=c["join_code"]))


@app.route("/api/session/<int:session_id>/qr.svg")
@login_required("lecturer", "admin")
def session_qr(session_id):
    s = owned_session(session_id)
    cur = current_slot()
    try:                                   # honour the slot the page asked for, within reason
        want = int(request.args.get("v") or cur)
    except ValueError:
        want = cur
    slot = want if cur - GRACE_SLOTS <= want <= cur + 1 else cur
    url = public_checkin_url(make_token(s, slot))
    qr = segno.make(url, error="m")
    buf = io.BytesIO()
    qr.save(buf, kind="svg", scale=10, border=1, dark="#0f172a", light=None)
    buf.seek(0)
    resp = send_file(buf, mimetype="image/svg+xml")
    resp.headers["Cache-Control"] = "no-store"
    return resp


TOKEN_BATCH_SLOTS = 36   # projector pre-fetches this many upcoming QR codes (36 x 10 s = 6 min)


@app.route("/api/session/<int:session_id>/tokens")
@login_required("lecturer", "admin")
def session_tokens(session_id):
    """Everything the projector needs to draw the next few minutes of QR codes by itself:
    server time (so the page follows the server clock, not the laptop's) plus one
    pre-rendered QR + short code per upcoming slot. The page swaps images locally at the
    exact slot boundary, so there is no fetch - and no lag - when the code changes."""
    s = owned_session(session_id)
    now = time.time()
    cur = current_slot(now)
    slots = []
    if not s["ended_at"]:
        for slot in range(cur, cur + TOKEN_BATCH_SLOTS):
            qr = segno.make(public_checkin_url(make_token(s, slot)), error="m")
            slots.append({"slot": slot,
                          "qr": qr.svg_data_uri(scale=10, border=1, dark="#0f172a", light=None),
                          "code": make_short_code(s, slot)})
    resp = jsonify({"now": now, "rot": ROTATE_SECONDS, "ended": bool(s["ended_at"]), "slots": slots})
    resp.headers["Cache-Control"] = "no-store"
    return resp


@app.route("/api/session/<int:session_id>/status")
@login_required("lecturer", "admin")
def session_status(session_id):
    s = owned_session(session_id)
    db = get_db()
    n_enrolled = db.execute("SELECT COUNT(*) FROM enrolments WHERE course_id=?", (s["course_id"],)).fetchone()[0]
    rows = db.execute(
        """SELECT u.id AS student_id, u.name, u.matric, k.status, k.checked_at, k.flagged, k.flag_reason FROM checkins k
           JOIN users u ON u.id=k.student_id WHERE k.session_id=? ORDER BY k.checked_at DESC""",
        (session_id,)).fetchall()
    legacy_partners = {}
    if any(r["flagged"] and "shared device" in (r["flag_reason"] or "").lower() and "shared device:" not in (r["flag_reason"] or "").lower() for r in rows):
        legacy_partners = {m["student_id"]: m["partner_str"] for g_item in _build_session_phone_groups(db, s) for m in g_item["members"]}
    now = time.time()
    rej = db.execute(
        """SELECT u.name, u.matric, r.reason, r.detail, r.at FROM rejections r JOIN users u ON u.id=r.student_id
           WHERE r.session_id=? ORDER BY r.at DESC""", (session_id,)).fetchall()
    c_row = db.execute("SELECT join_code FROM courses WHERE id=?", (s["course_id"],)).fetchone()
    local_active = (not PUBLIC_BASE_URL) and (OFFLINE_WIFI or _req_is_loopback())
    ws = wifi_status(include_candidates=True) if local_active else None
    return jsonify({
        "ended": bool(s["ended_at"]),
        "checkin_url": public_checkin_url(),
        "join_url": public_url("join_link", code=c_row["join_code"]) if c_row else "",
        "wifi_ready": ws["ready"] if ws else True,
        "firewall_ok": ws["firewall_ok"] if ws else True,
        "wifi_candidates": ws["candidates"] if ws else [],
        "wifi_override": ws["override"] if ws else "",
        "n_enrolled": n_enrolled,
        "n_checked": len(rows),
        "n_flagged": sum(r["flagged"] for r in rows),
        "n_rejected": len(rej),
        "rejected": [{"name": r["name"], "matric": r["matric"], "reason": r["reason"], "ago": int(now - r["at"])}
                     for r in rej[:5]],
        "code": make_short_code(s),
        "slot_remaining": ROTATE_SECONDS - (now % ROTATE_SECONDS),
        "elapsed_min": int((now - s["started_at"]) // 60),
        "recent": [{"name": r["name"], "matric": r["matric"], "status": r["status"], "flagged": r["flagged"],
                    "flag_short": _short_live_flag(_enrich_flag_reason_text(r["flag_reason"] or "", legacy_partners.get(r["student_id"], ""))) if r["flagged"] else "",
                    "ago": int(now - r["checked_at"])} for r in rows[:8]],
    })


@app.route("/api/lecturer/set-ip", methods=["POST"])
@login_required("lecturer", "admin")
def api_lecturer_set_ip():
    data = request.get_json(silent=True) or {}
    ip_val = (data.get("lan_ip") if "lan_ip" in data else request.form.get("lan_ip", "")).strip()
    set_setting("lan_ip_override", ip_val if ip_val and _is_usable_lan_ip(ip_val) else "")
    _lan_cache["at"] = 0.0
    wake_wifi_now()
    ws = wifi_status(include_candidates=True)
    return jsonify({"ok": True, "checkin_url": public_checkin_url(), "wifi": ws})


@app.route("/api/lecturer/firewall-fix", methods=["POST"])
@login_required("lecturer", "admin")
def api_lecturer_firewall_fix():
    if not _is_loopback_client():
        abort(403)
    ok = apply_windows_firewall_uac()
    if request.accept_mimetypes.best == "application/json" or request.is_json or request.headers.get("X-Requested-With") == "fetch":
        return jsonify({"ok": ok, "firewall_ok": ok})
    if ok:
        flash("Windows Firewall updated — student phones on classroom Wi-Fi / Hotspot can now open the QR link.", "ok")
    else:
        flash("Windows Firewall rule was not added (click Yes on the Windows administrator prompt, or right-click Allow_Windows_Firewall.bat -> Run as administrator).", "error")
    return redirect(request.referrer or url_for("lecturer_home"))


@app.route("/lecturer/session/<int:session_id>/end", methods=["POST"])
@login_required("lecturer", "admin")
def end_session(session_id):
    owned_session(session_id)
    db = get_db()
    db.execute("UPDATE sessions SET ended_at=? WHERE id=? AND ended_at IS NULL", (time.time(), session_id))
    db.commit()
    if OFFLINE_WIFI:
        trigger_auto_sync()
    return redirect(url_for("session_report", session_id=session_id))


def _enrich_flag_reason_text(fr, partner_str):
    if not fr or not partner_str:
        return fr
    parts = [p.strip() for p in fr.split(";") if p.strip()]
    changed = False
    out = []
    for p in parts:
        if p.lower() == "shared device":
            out.append(f"shared device: {partner_str}")
            changed = True
        else:
            out.append(p)
    return "; ".join(out) if changed else fr


@app.route("/lecturer/session/<int:session_id>")
@login_required("lecturer", "admin")
def session_report(session_id):
    s = owned_session(session_id)
    c = owned_course(s["course_id"])
    db = get_db()
    shared_groups = _build_session_phone_groups(db, s)
    shared_partners = {m["student_id"]: m["partner_str"] for g_item in shared_groups for m in g_item["members"]}
    shared_ids = set(shared_partners.keys())
    unresolved_shared = [g_item for g_item in shared_groups if g_item["any_flagged"]]
    cleared_shared = [g_item for g_item in shared_groups if not g_item["any_flagged"]]
    raw_rows = db.execute(
        """SELECT u.id, u.matric, u.name, k.status, k.checked_at, k.method, k.flagged, k.flag_reason,
                  k.device_id, k.distance_m, k.accuracy_m, k.ip
           FROM users u JOIN enrolments e ON e.student_id=u.id
           LEFT JOIN checkins k ON k.student_id=u.id AND k.session_id=?
           WHERE e.course_id=? ORDER BY u.matric""", (session_id, c["id"])).fetchall()
    rows = []
    for r in raw_rows:
        d = dict(r)
        if d["id"] in shared_partners and d.get("flag_reason"):
            d["flag_reason"] = _enrich_flag_reason_text(d["flag_reason"], shared_partners[d["id"]])
        rows.append(d)
    rejections = db.execute(
        """SELECT r.*, u.name, u.matric FROM rejections r JOIN users u ON u.id=r.student_id
           WHERE r.session_id=? ORDER BY r.at DESC""", (session_id,)).fetchall()
    suspicion = suspicion_scores(s)
    spot = db.execute(
        """SELECT sc.*, u.name, u.matric FROM spot_checks sc JOIN users u ON u.id=sc.student_id
           WHERE sc.session_id=? ORDER BY sc.picked_at DESC, sc.id""", (session_id,)).fetchall()
    n_suspicious = sum(1 for v in suspicion.values() if v[0] > 0)
    return render_template("report.html", sess=s, course=c, rows=rows, rejections=rejections,
                           present_ids={r["id"] for r in rows if r["status"]},
                           spot=spot, suspicion=suspicion, n_suspicious=n_suspicious, rules=session_rules(s),
                           shared_groups=shared_groups, unresolved_shared=unresolved_shared,
                           cleared_shared=cleared_shared, shared_ids=shared_ids,
                           n_present=sum(1 for r in rows if r["status"]),
                           n_flagged=sum(1 for r in rows if r["flagged"]))


@app.route("/lecturer/session/<int:session_id>/manual", methods=["POST"])
@login_required("lecturer", "admin")
def manual_mark(session_id):
    """Lecturer override: mark a student present (e.g. phone died). Recorded as 'manual' for audit."""
    s = owned_session(session_id)
    student_id = int(request.form["student_id"])
    action = request.form["action"]
    db = get_db()
    if action == "mark":
        db.execute("""INSERT OR IGNORE INTO checkins (session_id,student_id,checked_at,status,method)
                      VALUES (?,?,?,?,?)""", (session_id, student_id, time.time(), "present", "manual"))
    elif action == "remove":
        db.execute("DELETE FROM checkins WHERE session_id=? AND student_id=?", (session_id, student_id))
        _reconcile_shared_device_flags(db, s)
    elif action == "clear_flag":
        db.execute("UPDATE checkins SET flagged=0, flag_reason=NULL, flag_cleared=1 WHERE session_id=? AND student_id=?",
                   (session_id, student_id))
    if OFFLINE_WIFI:
        db.execute("UPDATE sessions SET synced_at=NULL WHERE id=?", (session_id,))
    db.commit()
    if OFFLINE_WIFI:
        trigger_auto_sync()
    return redirect(url_for("session_report", session_id=session_id))


@app.route("/lecturer/session/<int:session_id>/spotcheck", methods=["POST"])
@login_required("lecturer", "admin")
def run_spot_check(session_id):
    sess = owned_session(session_id)
    n = max(1, min(20, int(request.form.get("n") or 5)))
    chosen = pick_spot_check(sess, n)
    if not chosen:
        flash("Everyone marked present has already been spot-checked in this session.", "error")
    return redirect(url_for("session_report", session_id=session_id) + "#spot")


@app.route("/lecturer/session/<int:session_id>/spotcheck/<int:spot_id>", methods=["POST"])
@login_required("lecturer", "admin")
def spot_check_outcome(session_id, spot_id):
    s = owned_session(session_id)
    db = get_db()
    sc = db.execute("SELECT * FROM spot_checks WHERE id=? AND session_id=?", (spot_id, session_id)).fetchone()
    if not sc:
        abort(404)
    outcome = request.form.get("outcome")
    if outcome not in ("present", "absent"):
        abort(400)
    db.execute("UPDATE spot_checks SET outcome=?, decided_at=? WHERE id=?", (outcome, time.time(), spot_id))
    if outcome == "absent":
        # Remove the attendance mark; the spot_checks row keeps the evidence, and clean up shared-device peer flag.
        db.execute("DELETE FROM checkins WHERE session_id=? AND student_id=?", (session_id, sc["student_id"]))
        _reconcile_shared_device_flags(db, s)
    if OFFLINE_WIFI:
        db.execute("UPDATE sessions SET synced_at=NULL WHERE id=?", (session_id,))
    db.commit()
    if OFFLINE_WIFI:
        trigger_auto_sync()
    return redirect(url_for("session_report", session_id=session_id) + "#spot")


@app.route("/lecturer/session/<int:session_id>/export.csv")
@login_required("lecturer", "admin")
def export_session(session_id):
    s = owned_session(session_id)
    c = owned_course(s["course_id"])
    db = get_db()
    shared_groups = _build_session_phone_groups(db, s)
    shared_partners = {m["student_id"]: m["partner_str"] for g_item in shared_groups for m in g_item["members"]}
    rows = db.execute(
        """SELECT u.id AS student_id, u.matric, u.name, k.status, k.checked_at, k.method, k.flagged, k.flag_reason, k.distance_m
           FROM users u JOIN enrolments e ON e.student_id=u.id
           LEFT JOIN checkins k ON k.student_id=u.id AND k.session_id=?
           WHERE e.course_id=? ORDER BY u.matric""", (session_id, c["id"])).fetchall()
    out = io.StringIO()
    w = csv.writer(out)
    w.writerow(["Matric", "Name", "Status", "Time", "Method", "Flagged", "Flag reason", "Distance (m)"])
    for r in rows:
        fr_txt = _enrich_flag_reason_text(r["flag_reason"] or "", shared_partners.get(r["student_id"], ""))
        w.writerow([r["matric"], r["name"], r["status"] or "absent",
                    local_dt(r["checked_at"]).strftime("%Y-%m-%d %H:%M:%S") if r["checked_at"] else "",
                    r["method"] or "", "YES" if r["flagged"] else "", fr_txt,
                    f"{r['distance_m']:.0f}" if r["distance_m"] is not None else ""])
    w.writerow([]); w.writerow([f"Generated by {APP_NAME} v{APP_VERSION} on {local_dt().strftime('%d %b %Y, %H:%M')} - {COPYRIGHT}"])
    data = io.BytesIO(out.getvalue().encode())
    fname = f"{c['code']}_{s['title'].replace(' ', '_').replace(',', '')}.csv"
    return send_file(data, mimetype="text/csv", as_attachment=True, download_name=fname)


@app.route("/lecturer/course/<int:course_id>/export.csv")
@login_required("lecturer", "admin")
def export_course(course_id):
    """Full attendance matrix: one row per student, one column per session."""
    c = owned_course(course_id)
    db = get_db()
    sessions = db.execute("SELECT * FROM sessions WHERE course_id=? AND ended_at IS NOT NULL ORDER BY started_at", (course_id,)).fetchall()
    # A session running right now is shown as its own "(in progress)" column but is NOT counted
    # in Attended / Total / Percent until the lecturer ends it.
    live = db.execute("SELECT * FROM sessions WHERE course_id=? AND ended_at IS NULL ORDER BY started_at LIMIT 1", (course_id,)).fetchone()
    students = db.execute("""SELECT u.id, u.matric, u.name FROM users u JOIN enrolments e ON e.student_id=u.id
                             WHERE e.course_id=? ORDER BY u.matric""", (course_id,)).fetchall()
    marks = {(r["session_id"], r["student_id"]): r["status"] for r in db.execute(
        "SELECT session_id, student_id, status FROM checkins WHERE session_id IN "
        "(SELECT id FROM sessions WHERE course_id=?)", (course_id,)).fetchall()}
    out = io.StringIO()
    w = csv.writer(out)
    w.writerow(["Matric", "Name"] + [s["title"] for s in sessions] + ["Attended", "Total", "Percent"]
               + ([f"{live['title']} (in progress - not counted)"] if live else []))
    for st in students:
        cells, n = [], 0
        for s in sessions:
            m = marks.get((s["id"], st["id"]))
            cells.append({"present": "P", "late": "L"}.get(m, "A"))
            n += 1 if m else 0
        pct = f"{100 * n / len(sessions):.0f}%" if sessions else ""
        extra = [("P" if marks.get((live["id"], st["id"])) else "")] if live else []
        w.writerow([st["matric"], st["name"]] + cells + [n, len(sessions), pct] + extra)
    w.writerow([]); w.writerow([f"Generated by {APP_NAME} v{APP_VERSION} on {local_dt().strftime('%d %b %Y, %H:%M')} - {COPYRIGHT}"])
    data = io.BytesIO(out.getvalue().encode())
    return send_file(data, mimetype="text/csv", as_attachment=True, download_name=f"{c['code']}_attendance.csv")


# ---------------------------------------------------------------------------
# Admin: create lecturer accounts
# ---------------------------------------------------------------------------
# --- Admin overview -----------------------------------------------------------
COURSE_STATS_SQL = """
    SELECT c.*, u.name AS lecturer,
           (SELECT COUNT(*) FROM enrolments e WHERE e.course_id=c.id) AS n_students,
           (SELECT COUNT(*) FROM sessions s WHERE s.course_id=c.id) AS n_sessions,
           (SELECT COUNT(*) FROM sessions s WHERE s.course_id=c.id AND s.ended_at IS NOT NULL) AS n_ended,
           (SELECT MAX(s.started_at) FROM sessions s WHERE s.course_id=c.id) AS last_session,
           (SELECT s.id FROM sessions s WHERE s.course_id=c.id AND s.ended_at IS NULL LIMIT 1) AS live_session,
           (SELECT COUNT(*) FROM checkins k JOIN sessions s ON s.id=k.session_id
             WHERE s.course_id=c.id AND s.ended_at IS NOT NULL) AS n_checkins,
           (SELECT COUNT(*) FROM checkins k JOIN sessions s ON s.id=k.session_id
             WHERE s.course_id=c.id AND k.flagged=1) AS n_flagged
      FROM courses c JOIN users u ON u.id=c.lecturer_id"""


def attendance_pct(n_checkins, n_ended, n_students):
    """Average attendance across ended sessions, as a whole percentage (None if no data)."""
    if not n_ended or not n_students:
        return None
    return min(100, round(100 * n_checkins / (n_ended * n_students)))


@app.route("/admin")
@login_required("admin")
def admin_home():
    db = get_db()
    now = time.time()
    week_ago = now - 7 * 86400
    totals = {
        "lecturers": db.execute("SELECT COUNT(*) FROM users WHERE role='lecturer' AND active=1").fetchone()[0],
        "students": db.execute("SELECT COUNT(*) FROM users WHERE role='student' AND active=1").fetchone()[0],
        "courses": db.execute("SELECT COUNT(*) FROM courses WHERE archived=0").fetchone()[0],
        "sessions_week": db.execute("SELECT COUNT(*) FROM sessions WHERE started_at>=?", (week_ago,)).fetchone()[0],
        "checkins_week": db.execute(
            "SELECT COUNT(*) FROM checkins k JOIN sessions s ON s.id=k.session_id WHERE s.started_at>=?",
            (week_ago,)).fetchone()[0],
    }
    live = db.execute(
        """SELECT s.id, s.title, s.started_at, c.code, u.name AS lecturer,
                  (SELECT COUNT(*) FROM checkins k WHERE k.session_id=s.id) AS n_present,
                  (SELECT COUNT(*) FROM enrolments e WHERE e.course_id=c.id) AS n_students
             FROM sessions s JOIN courses c ON c.id=s.course_id JOIN users u ON u.id=c.lecturer_id
            WHERE s.ended_at IS NULL ORDER BY s.started_at DESC""").fetchall()
    lecturers = db.execute(
        """SELECT u.id, u.matric, u.name, u.active, u.must_change_pw,
                  (SELECT COUNT(*) FROM courses c WHERE c.lecturer_id=u.id AND c.archived=0) AS n_courses,
                  (SELECT COUNT(DISTINCT e.student_id) FROM enrolments e JOIN courses c ON c.id=e.course_id
                    WHERE c.lecturer_id=u.id AND c.archived=0) AS n_students,
                  (SELECT COUNT(*) FROM sessions s JOIN courses c ON c.id=s.course_id WHERE c.lecturer_id=u.id) AS n_sessions,
                  (SELECT COUNT(*) FROM sessions s JOIN courses c ON c.id=s.course_id
                    WHERE c.lecturer_id=u.id AND s.started_at>=?) AS n_sessions_week,
                  (SELECT MAX(s.started_at) FROM sessions s JOIN courses c ON c.id=s.course_id WHERE c.lecturer_id=u.id) AS last_session,
                  (SELECT COUNT(*) FROM sessions s JOIN courses c ON c.id=s.course_id
                    WHERE c.lecturer_id=u.id AND s.ended_at IS NULL) AS n_live
             FROM users u WHERE u.role='lecturer' ORDER BY u.active DESC, u.name""", (week_ago,)).fetchall()
    return render_template("admin_home.html", totals=totals, live=live, lecturers=lecturers, now=now)


@app.route("/admin/lecturer/<int:user_id>")
@login_required("admin")
def admin_lecturer(user_id):
    db = get_db()
    lec = db.execute("SELECT * FROM users WHERE id=? AND role='lecturer'", (user_id,)).fetchone()
    if not lec:
        abort(404)
    courses = db.execute(COURSE_STATS_SQL + " WHERE c.lecturer_id=? ORDER BY c.archived, c.code", (user_id,)).fetchall()
    rows = []
    for c in courses:
        rows.append({**dict(c), "pct": attendance_pct(c["n_checkins"], c["n_ended"], c["n_students"])})
    recent = db.execute(
        """SELECT s.id, s.title, s.started_at, s.ended_at, s.offline_wifi, c.code,
                  (SELECT COUNT(*) FROM checkins k WHERE k.session_id=s.id) AS n_present,
                  (SELECT COUNT(*) FROM enrolments e WHERE e.course_id=c.id) AS n_students
             FROM sessions s JOIN courses c ON c.id=s.course_id
            WHERE c.lecturer_id=? ORDER BY s.started_at DESC LIMIT 10""", (user_id,)).fetchall()
    return render_template("admin_lecturer.html", lec=lec, courses=rows, recent=recent, now=time.time())


@app.route("/admin/students")
@login_required("admin")
def admin_students():
    db = get_db()
    q = (request.args.get("q") or "").strip()
    students = []
    if q:
        like = f"%{q}%"
        students = db.execute(
            """SELECT u.id, u.matric, u.name, u.active,
                      (SELECT COUNT(*) FROM enrolments e WHERE e.student_id=u.id) AS n_courses,
                      (SELECT COUNT(*) FROM checkins k WHERE k.student_id=u.id) AS n_checkins,
                      (SELECT MAX(k.checked_at) FROM checkins k WHERE k.student_id=u.id) AS last_seen
                 FROM users u WHERE u.role='student' AND (u.matric LIKE ? OR u.name LIKE ?)
                ORDER BY u.matric LIMIT 100""", (like, like)).fetchall()
    return render_template("admin_students.html", q=q, students=students)


@app.route("/admin/student/<int:user_id>")
@login_required("admin")
def admin_student(user_id):
    db = get_db()
    stu = db.execute("SELECT * FROM users WHERE id=? AND role='student'", (user_id,)).fetchone()
    if not stu:
        abort(404)
    courses = db.execute(
        """SELECT c.id, c.code, c.title, c.archived, u.name AS lecturer,
                  (SELECT COUNT(*) FROM sessions s WHERE s.course_id=c.id AND s.ended_at IS NOT NULL) AS n_ended,
                  (SELECT COUNT(*) FROM checkins k JOIN sessions s ON s.id=k.session_id
                    WHERE s.course_id=c.id AND s.ended_at IS NOT NULL AND k.student_id=?) AS attended,
                  (SELECT COUNT(*) FROM checkins k JOIN sessions s ON s.id=k.session_id
                    WHERE s.course_id=c.id AND k.student_id=? AND k.flagged=1) AS flagged,
                  (SELECT COUNT(*) FROM spot_checks sc JOIN sessions s ON s.id=sc.session_id
                    WHERE s.course_id=c.id AND sc.student_id=? AND sc.outcome='absent') AS spot_absent
             FROM courses c JOIN enrolments e ON e.course_id=c.id JOIN users u ON u.id=c.lecturer_id
            WHERE e.student_id=? ORDER BY c.archived, c.code""", (user_id, user_id, user_id, user_id)).fetchall()
    recent = db.execute(
        """SELECT k.checked_at, k.status, k.flagged, k.flag_reason, s.title, c.code
             FROM checkins k JOIN sessions s ON s.id=k.session_id JOIN courses c ON c.id=s.course_id
            WHERE k.student_id=? ORDER BY k.checked_at DESC LIMIT 15""", (user_id,)).fetchall()
    return render_template("admin_student.html", stu=stu, courses=courses, recent=recent)


@app.route("/admin/users", methods=["GET", "POST"])
@login_required("admin")
def admin_users():
    db = get_db()
    if request.method == "POST":
        matric = request.form["matric"].strip().upper()
        name = request.form["name"].strip()
        pw = request.form["password"].strip()
        role = request.form["role"]
        if not matric or not name or role not in ("student", "lecturer", "admin"):
            flash("ID, name and role are required.", "error")
        elif len(pw) < 6:
            flash("Password must be at least 6 characters.", "error")
        else:
            try:
                db.execute("INSERT INTO users (matric,name,password_hash,role,created_at,pw_updated_at) VALUES (?,?,?,?,?,?)",
                           (matric, name, generate_password_hash(pw), role, now_iso(), time.time()))
                db.commit()
                flash(f"User created. They log in with ID {matric} and password \u201c{pw}\u201d "
                      f"(exactly as shown, capital letters matter).", "ok")
            except sqlite3.IntegrityError:
                flash("That ID already exists.", "error")
        return redirect(url_for("admin_users"))
    users = db.execute(
        """SELECT u.*,
                  (SELECT COUNT(*) FROM courses c WHERE c.lecturer_id=u.id) AS n_courses,
                  (SELECT COUNT(*) FROM enrolments e WHERE e.student_id=u.id) AS n_enrol,
                  (SELECT COUNT(*) FROM checkins k WHERE k.student_id=u.id) AS n_checkins
           FROM users u ORDER BY u.role, u.matric""").fetchall()
    n_admins = sum(1 for u in users if u["role"] == "admin" and u["active"])
    events = db.execute("SELECT * FROM admin_events ORDER BY at DESC LIMIT 20").fetchall()
    return render_template("admin_users.html", users=users, n_admins=n_admins, events=events)


@app.route("/admin/users/<int:user_id>/reset_password", methods=["POST"])
@login_required("admin")
def admin_reset_password(user_id):
    u = get_db().execute("SELECT * FROM users WHERE id=?", (user_id,)).fetchone()
    if not u:
        abort(404)
    matric = reset_password_to_matric(user_id, g.user["id"])
    flash(f"Password for {u['name']} reset. Temporary password: {matric}. They must change it at next login.", "ok")
    return redirect(url_for("admin_users"))


def log_admin(db, action, target, detail=""):
    db.execute("INSERT INTO admin_events (at, by_user_id, by_name, action, target, detail) VALUES (?,?,?,?,?,?)",
               (time.time(), g.user["id"], g.user["name"], action, target, detail))


def user_impact(db, uid):
    """What would disappear if this account were deleted."""
    q = lambda sql: db.execute(sql, (uid,)).fetchone()[0]
    return {"courses": q("SELECT COUNT(*) FROM courses WHERE lecturer_id=?"),
            "enrolments": q("SELECT COUNT(*) FROM enrolments WHERE student_id=?"),
            "checkins": q("SELECT COUNT(*) FROM checkins WHERE student_id=?"),
            "spot_checks": q("SELECT COUNT(*) FROM spot_checks WHERE student_id=?")}


def account_block_reason(db, u):
    """Why this account may NOT be deleted / deactivated right now (None = allowed)."""
    if u["id"] == g.user["id"]:
        return "you cannot remove your own account"
    if u["role"] == "admin" and db.execute("SELECT COUNT(*) FROM users WHERE role='admin' AND active=1").fetchone()[0] <= 1:
        return "it is the last active admin"
    return None


def delete_account(db, u):
    """Hard delete: the account and every row that points at it. Lecturers must own no courses."""
    uid = u["id"]
    if db.execute("SELECT COUNT(*) FROM courses WHERE lecturer_id=?", (uid,)).fetchone()[0]:
        return "still owns courses - transfer or delete those courses first"
    for sql in ("DELETE FROM checkins WHERE student_id=?", "DELETE FROM rejections WHERE student_id=?",
                "DELETE FROM spot_checks WHERE student_id=?", "DELETE FROM enrolment_events WHERE student_id=?",
                "UPDATE enrolment_events SET by_user_id=NULL WHERE by_user_id=?",
                "DELETE FROM password_resets WHERE user_id=? OR by_user_id=?", "DELETE FROM enrolments WHERE student_id=?",
                "DELETE FROM users WHERE id=?"):
        db.execute(sql, (uid, uid) if sql.count("?") == 2 else (uid,))
    return None


def apply_account_action(db, u, action):
    """Returns an error string or None. Does not commit."""
    if action in ("delete", "deactivate"):
        why = account_block_reason(db, u)
        if why:
            return why
    if action == "deactivate":
        db.execute("UPDATE users SET active=0 WHERE id=?", (u["id"],))
    elif action == "reactivate":
        db.execute("UPDATE users SET active=1 WHERE id=?", (u["id"],))
    elif action == "delete":
        imp = user_impact(db, u["id"])
        why = delete_account(db, u)
        if why:
            return why
        log_admin(db, "delete", f"{u['matric']} ({u['name']}, {u['role']})",
                  f"removed {imp['enrolments']} enrolment(s), {imp['checkins']} check-in(s), {imp['spot_checks']} spot check(s)")
        return None
    else:
        return "unknown action"
    log_admin(db, action, f"{u['matric']} ({u['name']}, {u['role']})")
    return None


@app.route("/admin/users/<int:user_id>/<action>", methods=["POST"])
@login_required("admin")
def admin_user_action(user_id, action):
    if action not in ("deactivate", "reactivate", "delete"):
        abort(404)
    db = get_db()
    u = db.execute("SELECT * FROM users WHERE id=?", (user_id,)).fetchone()
    if not u:
        abort(404)
    err = apply_account_action(db, u, action)
    if err:
        db.rollback()
        flash(f"Could not {action} {u['name']}: {err}.", "error")
    else:
        db.commit()
        verb = {"delete": "deleted permanently", "deactivate": "deactivated (cannot log in; records kept)",
                "reactivate": "reactivated"}[action]
        flash(f"{u['name']} ({u['matric']}) {verb}.", "ok")
    return redirect(url_for("admin_users"))


@app.route("/admin/users/bulk", methods=["POST"])
@login_required("admin")
def admin_users_bulk():
    action = request.form.get("action", "")
    ids = [int(i) for i in request.form.getlist("ids") if i.isdigit()]
    if action not in ("deactivate", "reactivate", "delete") or not ids:
        flash("Select at least one account and an action.", "error")
        return redirect(url_for("admin_users"))
    db = get_db()
    done, skipped = 0, []
    for uid in ids:
        u = db.execute("SELECT * FROM users WHERE id=?", (uid,)).fetchone()
        if not u:
            continue
        db.execute("SAVEPOINT one")
        err = apply_account_action(db, u, action)
        if err:
            db.execute("ROLLBACK TO one")
            skipped.append(f"{u['matric']} ({err})")
        else:
            done += 1
        db.execute("RELEASE one")
    db.commit()
    verb = {"delete": "deleted", "deactivate": "deactivated", "reactivate": "reactivated"}[action]
    flash(f"{done} account(s) {verb}." + (f" Skipped {len(skipped)}: " + "; ".join(skipped[:6]) + ("…" if len(skipped) > 6 else "") if skipped else ""),
          "ok" if done else "error")
    return redirect(url_for("admin_users"))


@app.route("/admin/settings", methods=["GET", "POST"])
@login_required("admin")
def admin_settings():
    if request.method == "POST":
        set_setting("allowed_networks", request.form.get("allowed_networks", "").strip())
        flash(f"Saved. {len(allowed_networks())} network range(s) recognised.", "ok")
        return redirect(url_for("admin_settings"))
    return render_template("admin_settings.html", allowed_networks=get_setting("allowed_networks"),
                           parsed=allowed_networks(), my_ip=client_ip())


@app.route("/account/password", methods=["GET", "POST"])
@login_required()
def change_password():
    if request.method == "POST":
        if not password_matches(g.user, request.form["current"]):
            flash("Current password is wrong.", "error")
        elif password_problem(request.form["new"], g.user["matric"]):
            flash(password_problem(request.form["new"], g.user["matric"]), "error")
        else:
            db = get_db()
            db.execute("UPDATE users SET password_hash=?, must_change_pw=0, pw_updated_at=? WHERE id=?",
                       (generate_password_hash(request.form["new"]), time.time(), g.user["id"]))
            db.commit()
            mark_sync_dirty()
            flash("Password updated.", "ok")
            return redirect(url_for("index"))
    return render_template("password.html", forced=bool(g.user["must_change_pw"]))


@app.template_filter("dt")
def fmt_dt(ts):
    return local_dt(ts).strftime("%d %b %Y, %H:%M") if ts else "—"


@app.template_filter("tm")
def fmt_tm(ts):
    return local_dt(ts).strftime("%H:%M:%S") if ts else "—"


# ---------------------------------------------------------------------------
# Offline Classroom Wi-Fi <-> Online HOD Cloud Sync Engine
# ---------------------------------------------------------------------------
from itsdangerous import URLSafeSerializer
_sync_ser = URLSafeSerializer(app.config["SECRET_KEY"], salt="cloud-sync-v1")


def make_sync_token(user_row):
    pwh = hashlib.sha256(user_row["password_hash"].encode()).hexdigest()[:16]
    return _sync_ser.dumps({"uid": user_row["id"], "pwh": pwh})


def verify_sync_token(tok):
    try:
        d = _sync_ser.loads(tok)
    except (BadSignature, TypeError):
        return None
    u = get_db().execute("SELECT * FROM users WHERE id=?", (d.get("uid"),)).fetchone()
    if not u or not u["active"] or u["role"] not in ("lecturer", "admin"):
        return None
    pwh = hashlib.sha256(u["password_hash"].encode()).hexdigest()[:16]
    return u if hmac.compare_digest(pwh, d.get("pwh", "")) else None


def _normalize_cloud_url(raw):
    raw = (raw or "").strip()
    if not raw:
        return ""
    if "://" not in raw:
        is_priv = raw.startswith(("localhost", "127.", "192.168.", "10.")) or re.match(r"^172\.(1[6-9]|2\d|3[01])\.", raw)
        raw = ("http://" if is_priv else "https://") + raw
    parts = urlsplit(raw)
    if not parts.netloc:
        return ""
    return f"{parts.scheme}://{parts.netloc}".rstrip("/")


def _sync_token_key(matric):
    return f"sync_token:{(matric or '').strip().upper()}"


def _last_sync_key(matric):
    return f"last_sync:{(matric or '').strip().upper()}"


def _lecturer_sync_info(db, user_row):
    cloud_url = get_setting("cloud_url", DEFAULT_CLOUD_URL) or DEFAULT_CLOUD_URL
    tok = get_setting(_sync_token_key(user_row["matric"]), "")
    last_raw = get_setting(_last_sync_key(user_row["matric"]), "")
    last_sync = float(last_raw) if last_raw else None
    where_owner = "" if user_row["role"] == "admin" else " AND c.lecturer_id=?"
    args = () if user_row["role"] == "admin" else (user_row["id"],)
    unsynced_ended = db.execute(
        f"""SELECT COUNT(*) FROM sessions s JOIN courses c ON c.id=s.course_id
            WHERE s.ended_at IS NOT NULL AND s.synced_at IS NULL{where_owner}""", args
    ).fetchone()[0]
    max_synced = db.execute(
        f"""SELECT MAX(s.synced_at) FROM sessions s JOIN courses c ON c.id=s.course_id
            WHERE s.synced_at IS NOT NULL{where_owner}""", args
    ).fetchone()[0]
    if max_synced and (not last_sync or float(max_synced) > last_sync):
        last_sync = float(max_synced)
    live_count = db.execute(
        f"""SELECT COUNT(*) FROM sessions s JOIN courses c ON c.id=s.course_id
            WHERE s.ended_at IS NULL{where_owner}""", args
    ).fetchone()[0]
    return {
        "cloud_url": cloud_url,
        "has_token": bool(tok),
        "last_sync": last_sync,
        "unsynced_ended": unsynced_ended,
        "live_count": live_count,
    }


def _safe_join_code(db, desired, for_course_id=None):
    code = (desired or "").strip().upper() or secrets.token_hex(3).upper()
    row = db.execute("SELECT id FROM courses WHERE join_code=? COLLATE NOCASE", (code,)).fetchone()
    if not row or (for_course_id is not None and row["id"] == for_course_id):
        return code
    for _ in range(20):
        cand = secrets.token_hex(3).upper()
        if not db.execute("SELECT 1 FROM courses WHERE join_code=? COLLATE NOCASE", (cand,)).fetchone():
            return cand
    return secrets.token_hex(4).upper()


def _sync_auth_from_payload(db, data):
    tok = (data.get("token") or "").strip()
    if tok:
        u = verify_sync_token(tok)
        if u:
            return u, None, 200
        if not data.get("password"):
            return None, "Sync connection expired (password may have changed). Enter your online password to reconnect.", 401
    matric = (data.get("matric") or "").strip()
    pw = data.get("password") or ""
    if not matric or not pw:
        return None, "Staff ID and password are required to link this laptop.", 401
    u = db.execute("SELECT * FROM users WHERE matric=? COLLATE NOCASE", (matric,)).fetchone()
    if not u or not password_matches(u, pw):
        return None, f"Incorrect password for {matric} on this online server (check the server URL and password).", 401
    if not u["active"]:
        return None, "This account is deactivated on the online server.", 403
    if u["role"] not in ("lecturer", "admin"):
        return None, "Only lecturer or admin accounts can sync courses.", 403
    if u["must_change_pw"] or (not SHOW_DEMO_LOGINS and pw in DEFAULT_DEMO_PASSWORDS):
        return None, ("Your online account is still using a temporary/default password. "
                      "Open the online site once in your browser to choose a personal password, then sync again."), 403
    return u, None, 200


def _build_pull_bundle(db, lec, issue_token=True):
    """Build the course + student + past-session bundle sent from Cloud -> Offline Laptop."""
    if lec["role"] == "admin":
        courses = db.execute(
            """SELECT c.*, u.matric AS lec_matric, u.name AS lec_name, u.password_hash AS lec_pwh,
                      u.pw_updated_at AS lec_pw_at
                 FROM courses c JOIN users u ON u.id=c.lecturer_id ORDER BY c.code"""
        ).fetchall()
    else:
        courses = db.execute(
            """SELECT c.*, u.matric AS lec_matric, u.name AS lec_name, u.password_hash AS lec_pwh,
                      u.pw_updated_at AS lec_pw_at
                 FROM courses c JOIN users u ON u.id=c.lecturer_id
                WHERE c.lecturer_id=? ORDER BY c.code""", (lec["id"],)
        ).fetchall()

    out_courses = []
    for c in courses:
        cid = c["id"]
        stus = db.execute(
            """SELECT u.matric, u.name, u.password_hash, u.must_change_pw, u.pw_updated_at, u.active, u.created_at
                 FROM users u JOIN enrolments e ON e.student_id=u.id
                WHERE e.course_id=? AND u.role='student' ORDER BY u.matric""", (cid,)
        ).fetchall()
        ended_sessions = db.execute(
            """SELECT * FROM sessions WHERE course_id=? AND ended_at IS NOT NULL ORDER BY started_at""", (cid,)
        ).fetchall()
        sess_list = []
        extra_users = {}
        for s in ended_sessions:
            suuid = s["sync_uuid"] or uuid.uuid4().hex
            if not s["sync_uuid"]:
                db.execute("UPDATE sessions SET sync_uuid=? WHERE id=?", (suuid, s["id"]))
            cks = db.execute(
                """SELECT u.matric, u.name, u.password_hash, u.must_change_pw, u.pw_updated_at, u.active, u.created_at,
                          k.checked_at, k.status, k.method, k.device_id, k.ip, k.user_agent,
                          k.flagged, k.flag_reason, k.flag_cleared, k.hw_sig, k.distance_m, k.accuracy_m
                     FROM checkins k JOIN users u ON u.id=k.student_id
                    WHERE k.session_id=?""", (s["id"],)
            ).fetchall()
            scs = db.execute(
                """SELECT u.matric, sc.picked_at, sc.score, sc.reasons, sc.outcome, sc.decided_at
                     FROM spot_checks sc JOIN users u ON u.id=sc.student_id
                    WHERE sc.session_id=?""", (s["id"],)
            ).fetchall()
            for k in cks:
                extra_users[k["matric"].upper()] = {
                    "matric": k["matric"], "name": k["name"], "password_hash": k["password_hash"],
                    "must_change_pw": k["must_change_pw"], "pw_updated_at": k["pw_updated_at"] or 0,
                    "active": k["active"], "created_at": k["created_at"],
                }
            sess_list.append({
                "sync_uuid": suuid,
                "title": s["title"],
                "secret": s["secret"],
                "started_at": s["started_at"],
                "ended_at": s["ended_at"],
                "late_after_min": s["late_after_min"],
                "offline_wifi": int(s["offline_wifi"] or 0),
                "checkins": [{
                    "matric": k["matric"], "checked_at": k["checked_at"], "status": k["status"],
                    "method": k["method"], "device_id": k["device_id"], "ip": k["ip"],
                    "user_agent": k["user_agent"], "flagged": k["flagged"], "flag_reason": k["flag_reason"],
                    "flag_cleared": int(k["flag_cleared"] or 0), "hw_sig": k["hw_sig"],
                    "distance_m": k["distance_m"], "accuracy_m": k["accuracy_m"],
                } for k in cks],
                "spot_checks": [dict(x) for x in scs],
            })
        enrolled_set = {st["matric"].upper() for st in stus}
        past_only_users = [u for m, u in extra_users.items() if m not in enrolled_set]
        out_courses.append({
            "code": c["code"],
            "title": c["title"],
            "join_code": c["join_code"],
            "archived": int(c["archived"] or 0),
            "qr_enrol": int(c["qr_enrol"] if "qr_enrol" in c.keys() else 1),
            "created_at": c["created_at"],
            "lecturer": {
                "matric": c["lec_matric"], "name": c["lec_name"],
                "password_hash": c["lec_pwh"], "pw_updated_at": c["lec_pw_at"] or 0,
            },
            "students": [dict(st) for st in stus],
            "past_users": past_only_users,
            "sessions": sess_list,
        })
    db.commit()
    res = {
        "ok": True,
        "kind": "attendance_roster_v1",
        "server_time": time.time(),
        "lecturer": {
            "matric": lec["matric"],
            "name": lec["name"],
            "role": lec["role"],
            "password_hash": lec["password_hash"],
            "must_change_pw": int(lec["must_change_pw"] or 0),
            "pw_updated_at": float(lec["pw_updated_at"] or 0),
        },
        "courses": out_courses,
    }
    if issue_token:
        res["sync_token"] = make_sync_token(lec)
    return res


def _upsert_student_account(db, stu_dict):
    """Ensure a student user row exists and merge password_hash safely by pw_updated_at."""
    raw_matric = (stu_dict.get("matric") or "").strip()
    if not raw_matric:
        return None, False
    matric = raw_matric.upper()
    name = (stu_dict.get("name") or matric).strip() or matric
    pwh = stu_dict.get("password_hash") or generate_password_hash(matric)
    must_chg = int(stu_dict.get("must_change_pw") if stu_dict.get("must_change_pw") is not None else 0)
    inc_pw_at = float(stu_dict.get("pw_updated_at") or 0)
    active = int(stu_dict.get("active") if stu_dict.get("active") is not None else 1)
    created_at = stu_dict.get("created_at") or now_iso()

    u = db.execute("SELECT * FROM users WHERE matric=? COLLATE NOCASE", (matric,)).fetchone()
    if not u:
        cur = db.execute(
            """INSERT INTO users (matric,name,password_hash,role,created_at,must_change_pw,active,pw_updated_at)
               VALUES (?,?,?,?,?,?,?,?)""",
            (matric, name, pwh, "student", created_at, must_chg, active, inc_pw_at),
        )
        return cur.lastrowid, True
    if u["role"] != "student":
        return None, False
    cur_pw_at = float(u["pw_updated_at"] or 0)
    new_name = name if (u["name"].upper() == u["matric"].upper() and name.upper() != matric) else u["name"]
    if inc_pw_at > cur_pw_at:
        db.execute("UPDATE users SET name=?, password_hash=?, must_change_pw=?, pw_updated_at=? WHERE id=?",
                   (new_name, pwh, must_chg, inc_pw_at, u["id"]))
    elif new_name != u["name"]:
        db.execute("UPDATE users SET name=? WHERE id=?", (new_name, u["id"]))
    return u["id"], False


def _apply_push_bundle(db, lec, payload):
    """Merge offline laptop courses, enrolments & completed sessions onto the Cloud DB."""
    now = time.time()
    synced_uuids = []
    deleted_ack = []
    sessions_added = sessions_updated = checkins_synced = students_created = enrolments_added = 0
    touched_codes = []
    warnings = []

    for duuid in (payload.get("deleted_uuids") or []):
        duuid = (duuid or "").strip()
        if not duuid:
            continue
        ex_del = db.execute(
            "SELECT s.id, c.lecturer_id FROM sessions s JOIN courses c ON c.id=s.course_id WHERE s.sync_uuid=?",
            (duuid,),
        ).fetchone()
        if ex_del:
            if lec["role"] == "admin" or ex_del["lecturer_id"] == lec["id"]:
                for t in ("spot_checks", "rejections", "checkins"):
                    db.execute(f"DELETE FROM {t} WHERE session_id=?", (ex_del["id"],))
                db.execute("DELETE FROM sessions WHERE id=?", (ex_del["id"],))
                deleted_ack.append(duuid)
        else:
            deleted_ack.append(duuid)

    for c_data in (payload.get("courses") or []):
        code = (c_data.get("code") or "").strip().upper()
        if not code:
            continue
        title = (c_data.get("title") or code).strip()
        cloud_c = db.execute("SELECT * FROM courses WHERE code=? COLLATE NOCASE", (code,)).fetchone()
        if cloud_c:
            if lec["role"] != "admin" and cloud_c["lecturer_id"] != lec["id"]:
                warnings.append(f"{code} belongs to another lecturer on the online server — skipped.")
                continue
            cid = cloud_c["id"]
            db.execute("UPDATE courses SET title=?, archived=?, qr_enrol=? WHERE id=?",
                       (title or cloud_c["title"], int(c_data.get("archived", cloud_c["archived"])),
                        int(c_data.get("qr_enrol", cloud_c["qr_enrol"])), cid))
        else:
            jcode = _safe_join_code(db, c_data.get("join_code"))
            cur = db.execute(
                """INSERT INTO courses (code,title,lecturer_id,join_code,created_at,archived,qr_enrol)
                   VALUES (?,?,?,?,?,?,?)""",
                (code, title, lec["id"], jcode, c_data.get("created_at") or now_iso(),
                 int(c_data.get("archived") or 0), int(c_data.get("qr_enrol", 1))),
            )
            cid = cur.lastrowid
            touched_codes.append(code)

        uid_map = {}
        for stu in (c_data.get("past_users") or []):
            uid, created = _upsert_student_account(db, stu)
            if uid:
                uid_map[stu["matric"].strip().upper()] = uid
                students_created += int(created)
        for stu in (c_data.get("students") or []):
            uid, created = _upsert_student_account(db, stu)
            if uid:
                uid_map[stu["matric"].strip().upper()] = uid
                students_created += int(created)
                cur = db.execute("INSERT OR IGNORE INTO enrolments VALUES (?,?)", (cid, uid))
                if cur.rowcount:
                    enrolments_added += 1
                    log_enrolment(db, cid, uid, "qr", lec["id"])

        for s_data in (c_data.get("sessions") or []):
            suuid = (s_data.get("sync_uuid") or "").strip()
            ended_at = s_data.get("ended_at")
            if not suuid or not ended_at:
                continue
            ex = db.execute("SELECT * FROM sessions WHERE sync_uuid=?", (suuid,)).fetchone()
            if ex:
                if ex["course_id"] != cid:
                    warnings.append(f"Session '{s_data.get('title')}' UUID conflict across courses — skipped.")
                    continue
                sid = ex["id"]
                db.execute("UPDATE sessions SET title=?, ended_at=?, synced_at=? WHERE id=?",
                           ((s_data.get("title") or ex["title"]).strip(), float(ended_at), now, sid))
                sessions_updated += 1
            else:
                cur = db.execute(
                    """INSERT INTO sessions (course_id,title,secret,started_at,ended_at,late_after_min,
                                             geo_lat,geo_lng,geo_radius_m,geo_acc_m,geo_mode,network_mode,
                                             sync_uuid,synced_at,offline_wifi)
                       VALUES (?,?,?,?,?,?,NULL,NULL,100,0,'flag','off',?,?,?)""",
                    (cid, (s_data.get("title") or "Lecture").strip(),
                     s_data.get("secret") or secrets.token_hex(32),
                     float(s_data.get("started_at") or ended_at), float(ended_at),
                     int(s_data.get("late_after_min") or 15), suuid, now,
                     int(s_data.get("offline_wifi", 1))),
                )
                sid = cur.lastrowid
                sessions_added += 1
            if code not in touched_codes:
                touched_codes.append(code)

            pushed_uids = set()
            for k in (s_data.get("checkins") or []):
                m_up = (k.get("matric") or "").strip().upper()
                uid = uid_map.get(m_up)
                if not uid:
                    uid, created = _upsert_student_account(db, {"matric": m_up, "name": k.get("name") or m_up})
                    if uid:
                        uid_map[m_up] = uid
                        students_created += int(created)
                        db.execute("INSERT OR IGNORE INTO enrolments VALUES (?,?)", (cid, uid))
                if not uid:
                    continue
                pushed_uids.add(uid)
                status = k.get("status") if k.get("status") in ("present", "late") else "present"
                ex_k = db.execute("SELECT id FROM checkins WHERE session_id=? AND student_id=?", (sid, uid)).fetchone()
                if ex_k:
                    db.execute("UPDATE checkins SET status=?, flagged=?, flag_reason=?, flag_cleared=?, hw_sig=COALESCE(?, hw_sig) WHERE id=?",
                               (status, int(k.get("flagged") or 0), k.get("flag_reason"),
                                int(k.get("flag_cleared") or 0), _normalize_hw_sig(k.get("hw_sig")), ex_k["id"]))
                else:
                    db.execute(
                        """INSERT INTO checkins (session_id,student_id,checked_at,status,method,device_id,ip,
                                                 user_agent,flagged,flag_reason,flag_cleared,hw_sig,distance_m,accuracy_m)
                           VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?)""",
                        (sid, uid, float(k.get("checked_at") or ended_at), status,
                         k.get("method") or "qr", k.get("device_id"), k.get("ip"),
                         (k.get("user_agent") or "")[:200], int(k.get("flagged") or 0),
                         k.get("flag_reason"), int(k.get("flag_cleared") or 0),
                         _normalize_hw_sig(k.get("hw_sig")), k.get("distance_m"), k.get("accuracy_m")),
                    )
                    checkins_synced += 1

            for sc in (s_data.get("spot_checks") or []):
                m_up = (sc.get("matric") or "").strip().upper()
                uid = uid_map.get(m_up)
                if not uid:
                    continue
                outcome = sc.get("outcome") if sc.get("outcome") in ("present", "absent") else None
                ex_sc = db.execute("SELECT id FROM spot_checks WHERE session_id=? AND student_id=?", (sid, uid)).fetchone()
                if ex_sc:
                    db.execute("UPDATE spot_checks SET outcome=?, decided_at=? WHERE id=?",
                               (outcome, sc.get("decided_at"), ex_sc["id"]))
                else:
                    db.execute(
                        """INSERT INTO spot_checks (session_id,student_id,picked_at,score,reasons,outcome,decided_at)
                           VALUES (?,?,?,?,?,?,?)""",
                        (sid, uid, float(sc.get("picked_at") or ended_at), int(sc.get("score") or 0),
                         sc.get("reasons") or "", outcome, sc.get("decided_at")),
                    )
                if outcome == "absent" and uid not in pushed_uids:
                    db.execute("DELETE FROM checkins WHERE session_id=? AND student_id=?", (sid, uid))

            if ex and int(s_data.get("offline_wifi", 1)) == 1:
                if pushed_uids:
                    qmarks = ",".join("?" * len(pushed_uids))
                    db.execute(f"DELETE FROM checkins WHERE session_id=? AND student_id NOT IN ({qmarks})",
                               (sid, *pushed_uids))
                else:
                    db.execute("DELETE FROM checkins WHERE session_id=?", (sid,))

            for rj in (s_data.get("rejections") or []):
                m_up = (rj.get("matric") or "").strip().upper()
                uid = uid_map.get(m_up)
                if not uid:
                    continue
                at_ts = float(rj.get("at") or ended_at)
                dup = db.execute(
                    "SELECT 1 FROM rejections WHERE session_id=? AND student_id=? AND ABS(at - ?) < 1.0",
                    (sid, uid, at_ts),
                ).fetchone()
                if not dup:
                    db.execute("INSERT INTO rejections (session_id,student_id,at,reason,detail,ip) VALUES (?,?,?,?,?,?)",
                               (sid, uid, at_ts, rj.get("reason") or "rejected", rj.get("detail"), rj.get("ip")))

            synced_uuids.append(suuid)

    if sessions_added or checkins_synced or enrolments_added:
        db.execute(
            "INSERT INTO admin_events (at, by_user_id, by_name, action, target, detail) VALUES (?,?,?,?,?,?)",
            (now, lec["id"], lec["name"], "offline_sync", f"{lec['matric']} ({lec['name']})",
             f"Synced {sessions_added} new session(s), {checkins_synced} check-in(s), "
             f"{enrolments_added} new enrolment(s) ({', '.join(touched_codes) or 'courses'})"),
        )
    db.commit()
    return {
        "ok": True,
        "synced_uuids": synced_uuids,
        "deleted_ack": deleted_ack,
        "sessions_added": sessions_added,
        "sessions_updated": sessions_updated,
        "checkins_synced": checkins_synced,
        "students_created": students_created,
        "enrolments_added": enrolments_added,
        "warnings": warnings,
    }


def _build_laptop_push_payload(db, user_row):
    """Collect unsynced ended sessions + local courses & student list from Offline Laptop -> Cloud."""
    where_owner = "" if user_row["role"] == "admin" else " WHERE c.lecturer_id=?"
    args = () if user_row["role"] == "admin" else (user_row["id"],)
    courses = db.execute(f"SELECT c.* FROM courses c{where_owner} ORDER BY c.code", args).fetchall()
    out_courses = []
    for c in courses:
        cid = c["id"]
        stus = db.execute(
            """SELECT u.matric, u.name, u.password_hash, u.must_change_pw, u.pw_updated_at, u.active, u.created_at
                 FROM users u JOIN enrolments e ON e.student_id=u.id
                WHERE e.course_id=? AND u.role='student' ORDER BY u.matric""", (cid,)
        ).fetchall()
        unsynced = db.execute(
            """SELECT * FROM sessions WHERE course_id=? AND ended_at IS NOT NULL AND synced_at IS NULL
                ORDER BY started_at""", (cid,)
        ).fetchall()
        sess_list = []
        extra_users = {}
        for s in unsynced:
            suuid = s["sync_uuid"] or uuid.uuid4().hex
            if not s["sync_uuid"]:
                db.execute("UPDATE sessions SET sync_uuid=? WHERE id=?", (suuid, s["id"]))
            cks = db.execute(
                """SELECT u.matric, u.name, u.password_hash, u.must_change_pw, u.pw_updated_at, u.active, u.created_at,
                          k.checked_at, k.status, k.method, k.device_id, k.ip, k.user_agent,
                          k.flagged, k.flag_reason, k.flag_cleared, k.hw_sig, k.distance_m, k.accuracy_m
                     FROM checkins k JOIN users u ON u.id=k.student_id
                    WHERE k.session_id=?""", (s["id"],)
            ).fetchall()
            scs = db.execute(
                """SELECT u.matric, sc.picked_at, sc.score, sc.reasons, sc.outcome, sc.decided_at
                     FROM spot_checks sc JOIN users u ON u.id=sc.student_id
                    WHERE sc.session_id=?""", (s["id"],)
            ).fetchall()
            rejs = db.execute(
                """SELECT u.matric, r.at, r.reason, r.detail, r.ip
                     FROM rejections r JOIN users u ON u.id=r.student_id
                    WHERE r.session_id=?""", (s["id"],)
            ).fetchall()
            for k in cks:
                extra_users[k["matric"].upper()] = {
                    "matric": k["matric"], "name": k["name"], "password_hash": k["password_hash"],
                    "must_change_pw": k["must_change_pw"], "pw_updated_at": k["pw_updated_at"] or 0,
                    "active": k["active"], "created_at": k["created_at"],
                }
            sess_list.append({
                "sync_uuid": suuid,
                "title": s["title"],
                "secret": s["secret"],
                "started_at": s["started_at"],
                "ended_at": s["ended_at"],
                "late_after_min": s["late_after_min"],
                "offline_wifi": int(s["offline_wifi"] if "offline_wifi" in s.keys() else 1),
                "checkins": [{
                    "matric": k["matric"], "name": k["name"], "checked_at": k["checked_at"],
                    "status": k["status"], "method": k["method"], "device_id": k["device_id"],
                    "ip": k["ip"], "user_agent": k["user_agent"], "flagged": k["flagged"],
                    "flag_reason": k["flag_reason"], "flag_cleared": int(k["flag_cleared"] or 0),
                    "hw_sig": k["hw_sig"], "distance_m": k["distance_m"], "accuracy_m": k["accuracy_m"],
                } for k in cks],
                "spot_checks": [dict(x) for x in scs],
                "rejections": [dict(x) for x in rejs],
            })
        enrolled_set = {st["matric"].upper() for st in stus}
        out_courses.append({
            "code": c["code"],
            "title": c["title"],
            "join_code": c["join_code"],
            "archived": int(c["archived"] or 0),
            "qr_enrol": int(c["qr_enrol"] if "qr_enrol" in c.keys() else 1),
            "created_at": c["created_at"],
            "students": [dict(st) for st in stus],
            "past_users": [u for m, u in extra_users.items() if m not in enrolled_set],
            "sessions": sess_list,
        })
    del_uuids = [r[0] for r in db.execute("SELECT sync_uuid FROM deleted_sessions").fetchall()]
    db.commit()
    return {
        "kind": "attendance_sessions_v1",
        "exported_at": time.time(),
        "courses": out_courses,
        "deleted_uuids": del_uuids,
    }


def _apply_pull_bundle_to_laptop(db, bundle):
    """Apply a Cloud pull bundle onto the Offline Laptop DB safely."""
    now = time.time()
    lec_info = bundle.get("lecturer") or {}
    lec_matric = (lec_info.get("matric") or "").strip()
    if not lec_matric:
        raise ValueError("Invalid roster data (missing lecturer profile).")
    local_lec = db.execute("SELECT * FROM users WHERE matric=? COLLATE NOCASE", (lec_matric,)).fetchone()
    role = lec_info.get("role") if lec_info.get("role") in ("lecturer", "admin") else "lecturer"
    inc_pw_at = float(lec_info.get("pw_updated_at") or 0)
    if not local_lec:
        cur = db.execute(
            """INSERT INTO users (matric,name,password_hash,role,created_at,must_change_pw,active,pw_updated_at)
               VALUES (?,?,?,?,?,?,1,?)""",
            (lec_matric, lec_info.get("name") or lec_matric, lec_info["password_hash"],
             role, now_iso(), int(lec_info.get("must_change_pw") or 0), inc_pw_at),
        )
        lec_id = cur.lastrowid
    else:
        lec_id = local_lec["id"]
        if inc_pw_at >= float(local_lec["pw_updated_at"] or 0):
            db.execute("UPDATE users SET name=?, password_hash=?, must_change_pw=?, active=1, pw_updated_at=? WHERE id=?",
                       (lec_info.get("name") or local_lec["name"], lec_info["password_hash"],
                        int(lec_info.get("must_change_pw") or 0), inc_pw_at, lec_id))

    n_courses = 0
    stu_seen = set()
    for c_data in (bundle.get("courses") or []):
        code = (c_data.get("code") or "").strip().upper()
        if not code:
            continue
        owner_id = lec_id
        c_lec = c_data.get("lecturer") or {}
        if c_lec.get("matric") and c_lec["matric"].strip().upper() != lec_matric.upper():
            other = db.execute("SELECT id FROM users WHERE matric=? COLLATE NOCASE", (c_lec["matric"].strip(),)).fetchone()
            if not other:
                cur_o = db.execute(
                    "INSERT INTO users (matric,name,password_hash,role,created_at,pw_updated_at) VALUES (?,?,?,?,?,?)",
                    (c_lec["matric"].strip(), c_lec.get("name") or c_lec["matric"],
                     c_lec.get("password_hash") or generate_password_hash(secrets.token_hex(8)),
                     "lecturer", now_iso(), float(c_lec.get("pw_updated_at") or 0)),
                )
                owner_id = cur_o.lastrowid
            else:
                owner_id = other["id"]

        loc_c = db.execute("SELECT * FROM courses WHERE code=? COLLATE NOCASE", (code,)).fetchone()
        if not loc_c:
            jcode = _safe_join_code(db, c_data.get("join_code"))
            cur_c = db.execute(
                """INSERT INTO courses (code,title,lecturer_id,join_code,created_at,archived,qr_enrol)
                   VALUES (?,?,?,?,?,?,?)""",
                (code, c_data.get("title") or code, owner_id, jcode,
                 c_data.get("created_at") or now_iso(), int(c_data.get("archived") or 0),
                 int(c_data.get("qr_enrol", 1))),
            )
            cid = cur_c.lastrowid
        else:
            cid = loc_c["id"]
            jcode = _safe_join_code(db, c_data.get("join_code"), for_course_id=cid)
            db.execute("UPDATE courses SET title=?, lecturer_id=?, join_code=?, archived=?, qr_enrol=? WHERE id=?",
                       (c_data.get("title") or loc_c["title"], owner_id, jcode,
                        int(c_data.get("archived") or 0), int(c_data.get("qr_enrol", 1)), cid))
        n_courses += 1

        uid_map = {}
        for stu in (c_data.get("past_users") or []):
            uid, _ = _upsert_student_account(db, stu)
            if uid:
                uid_map[stu["matric"].strip().upper()] = uid
        for stu in (c_data.get("students") or []):
            uid, _ = _upsert_student_account(db, stu)
            if uid:
                m_up = stu["matric"].strip().upper()
                uid_map[m_up] = uid
                stu_seen.add(m_up)
                db.execute("INSERT OR IGNORE INTO enrolments VALUES (?,?)", (cid, uid))

        deleted_set = {r[0] for r in db.execute("SELECT sync_uuid FROM deleted_sessions").fetchall()}
        for s_data in (c_data.get("sessions") or []):
            suuid = (s_data.get("sync_uuid") or "").strip()
            ended_at = s_data.get("ended_at")
            if not suuid or not ended_at or suuid in deleted_set:
                continue
            loc_s = db.execute("SELECT * FROM sessions WHERE sync_uuid=?", (suuid,)).fetchone()
            if not loc_s:
                cur_s = db.execute(
                    """INSERT INTO sessions (course_id,title,secret,started_at,ended_at,late_after_min,
                                             geo_lat,geo_lng,geo_radius_m,geo_acc_m,geo_mode,network_mode,
                                             sync_uuid,synced_at,offline_wifi)
                       VALUES (?,?,?,?,?,?,NULL,NULL,100,0,'flag','off',?,?,?)""",
                    (cid, s_data.get("title") or "Lecture", s_data.get("secret") or secrets.token_hex(32),
                     float(s_data.get("started_at") or ended_at), float(ended_at),
                     int(s_data.get("late_after_min") or 15), suuid, now,
                     int(s_data.get("offline_wifi") or 0)),
                )
                sid = cur_s.lastrowid
            else:
                if loc_s["synced_at"] is None:
                    continue
                sid = loc_s["id"]
            for k in (s_data.get("checkins") or []):
                m_up = (k.get("matric") or "").strip().upper()
                uid = uid_map.get(m_up)
                if not uid:
                    continue
                ex_loc_k = db.execute("SELECT id FROM checkins WHERE session_id=? AND student_id=?", (sid, uid)).fetchone()
                if ex_loc_k:
                    db.execute(
                        "UPDATE checkins SET status=?, flagged=?, flag_reason=?, flag_cleared=?, hw_sig=COALESCE(?, hw_sig) WHERE id=?",
                        (k.get("status") if k.get("status") in ("present", "late") else "present",
                         int(k.get("flagged") or 0), k.get("flag_reason"), int(k.get("flag_cleared") or 0),
                         _normalize_hw_sig(k.get("hw_sig")), ex_loc_k["id"]),
                    )
                else:
                    db.execute(
                        """INSERT INTO checkins (session_id,student_id,checked_at,status,method,device_id,ip,
                                                 user_agent,flagged,flag_reason,flag_cleared,hw_sig,distance_m,accuracy_m)
                           VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?)""",
                        (sid, uid, float(k.get("checked_at") or ended_at),
                         k.get("status") if k.get("status") in ("present", "late") else "present",
                         k.get("method") or "qr", k.get("device_id"), k.get("ip"),
                         (k.get("user_agent") or "")[:200], int(k.get("flagged") or 0),
                         k.get("flag_reason"), int(k.get("flag_cleared") or 0),
                         _normalize_hw_sig(k.get("hw_sig")), k.get("distance_m"), k.get("accuracy_m")),
                    )
            for sc in (s_data.get("spot_checks") or []):
                m_up = (sc.get("matric") or "").strip().upper()
                uid = uid_map.get(m_up)
                if not uid:
                    continue
                if not db.execute("SELECT 1 FROM spot_checks WHERE session_id=? AND student_id=?", (sid, uid)).fetchone():
                    db.execute(
                        """INSERT INTO spot_checks (session_id,student_id,picked_at,score,reasons,outcome,decided_at)
                           VALUES (?,?,?,?,?,?,?)""",
                        (sid, uid, float(sc.get("picked_at") or ended_at), int(sc.get("score") or 0),
                         sc.get("reasons") or "", sc.get("outcome"), sc.get("decided_at")),
                    )

    db.commit()
    lec_row = db.execute("SELECT * FROM users WHERE id=?", (lec_id,)).fetchone()
    return lec_row, n_courses, len(stu_seen)


def _cloud_post_json(cloud_url, path, payload, timeout=12):
    url = cloud_url.rstrip("/") + path
    body = json.dumps(payload).encode("utf-8")
    req = urllib.request.Request(
        url, data=body, method="POST",
        headers={"Content-Type": "application/json", "Accept": "application/json",
                 "User-Agent": f"{APP_NAME}-OfflineSync/{APP_VERSION}"},
    )
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            return resp.status, json.loads(resp.read().decode("utf-8"))
    except urllib.error.HTTPError as e:
        if e.code == 404:
            return 404, {"ok": False, "error": (
                f"{cloud_url} does not have the sync endpoint yet (HTTP 404). "
                "Upload the new attendance_update.zip to that server and click Reload first."
            )}
        try:
            data = json.loads(e.read().decode("utf-8"))
            return e.code, data
        except Exception:
            return e.code, {"ok": False, "error": f"Online server ({cloud_url}) returned HTTP {e.code}."}
    except urllib.error.URLError as e:
        reason = getattr(e, "reason", e)
        return 0, {"ok": False, "error": (
            f"Could not reach {cloud_url} ({reason}). Connect this laptop to the internet "
            "(e.g. phone hotspot or office Wi-Fi) and try again — your offline attendance records are safely saved here."
        )}
    except Exception as e:
        return 0, {"ok": False, "error": f"Sync connection failed: {e}"}


def _bootstrap_lecturer_from_cloud(db, raw_url, matric, pw):
    """Used on first-time localhost login on an offline laptop to pull the lecturer's account & courses."""
    cloud_url = _normalize_cloud_url(raw_url)
    if not cloud_url:
        return False, "Enter a valid online server URL (for example https://cscattendance.pythonanywhere.com).", None
    code, resp = _cloud_post_json(cloud_url, "/api/sync/pull", {"matric": matric, "password": pw}, timeout=10)
    if code != 200 or not resp.get("ok"):
        return False, resp.get("error") or "Could not sign in to the online server.", None
    lec_row, n_courses, n_students = _apply_pull_bundle_to_laptop(db, resp)
    set_setting("cloud_url", cloud_url)
    if resp.get("sync_token"):
        set_setting(_sync_token_key(lec_row["matric"]), resp["sync_token"])
    set_setting(_last_sync_key(lec_row["matric"]), str(time.time()))
    return True, (f"Laptop linked to {cloud_url}! Downloaded {n_courses} course(s) and {n_students} student(s). "
                  "You can now disconnect from the internet and take attendance over classroom Wi-Fi."), lec_row


@app.route("/offline/setup", methods=["POST"])
def offline_initial_setup():
    """Localhost-only fallback on a brand-new offline laptop with no internet (import roster JSON or create local lecturer)."""
    if not OFFLINE_WIFI or not _is_loopback_client():
        abort(403)
    db = get_db()
    mode = request.form.get("mode", "")
    if mode == "import_roster":
        f = request.files.get("roster_file")
        if not f or not f.filename:
            flash("Choose the roster .json file downloaded from the online server.", "error")
            return redirect(url_for("login"))
        try:
            bundle = json.loads(f.read().decode("utf-8"))
            if bundle.get("kind") != "attendance_roster_v1":
                raise ValueError("This file is not an Attendance course roster file.")
            lec_row, n_courses, n_students = _apply_pull_bundle_to_laptop(db, bundle)
            flash(f"Imported {n_courses} course(s) and {n_students} student(s) for {lec_row['name']}. Log in with your Staff ID and password.", "ok")
        except Exception as e:
            flash(f"Could not import roster file: {e}", "error")
        return redirect(url_for("login"))
    if mode == "local_account" and _laptop_needs_setup():
        matric = (request.form.get("matric") or "").strip().upper()
        name = (request.form.get("name") or "").strip()
        pw = request.form.get("password") or ""
        if not matric or not name:
            flash("Staff ID and full name are required.", "error")
        elif password_problem(pw, matric):
            flash(password_problem(pw, matric), "error")
        else:
            cur = db.execute(
                "INSERT INTO users (matric,name,password_hash,role,created_at,pw_updated_at) VALUES (?,?,?,?,?,?)",
                (matric, name, generate_password_hash(pw), "lecturer", now_iso(), time.time()),
            )
            db.commit()
            session.clear()
            session.permanent = True
            session["uid"] = cur.lastrowid
            tok = make_url_token(cur.lastrowid)
            flash("Offline lecturer account created. Create your course below to start taking classroom Wi-Fi attendance.", "ok")
            return redirect(url_for("lecturer_home", s=tok))
    return redirect(url_for("login"))


@app.route("/api/sync/pull", methods=["POST"])
def api_sync_pull():
    db = get_db()
    data = request.get_json(silent=True) or {}
    lec, err, status = _sync_auth_from_payload(db, data)
    if err:
        return jsonify({"ok": False, "error": err}), status
    return jsonify(_build_pull_bundle(db, lec, issue_token=True))


@app.route("/api/sync/push", methods=["POST"])
def api_sync_push():
    db = get_db()
    data = request.get_json(silent=True) or {}
    lec, err, status = _sync_auth_from_payload(db, data)
    if err:
        return jsonify({"ok": False, "error": err}), status
    res = _apply_push_bundle(db, lec, data)
    res["sync_token"] = make_sync_token(lec)
    res["pull"] = _build_pull_bundle(db, lec, issue_token=False)
    return jsonify(res)


@app.route("/lecturer/sync", methods=["POST"])
@login_required("lecturer", "admin")
def lecturer_sync():
    db = get_db()
    action = request.form.get("action", "sync")
    back_course = request.form.get("course_id", "").strip()
    back_url = url_for("course_page", course_id=int(back_course)) if back_course.isdigit() else url_for("lecturer_home")

    if action == "set_ip":
        ip_val = request.form.get("lan_ip", "").strip()
        set_setting("lan_ip_override", ip_val if ip_val and _is_usable_lan_ip(ip_val) else "")
        _lan_cache["at"] = 0.0
        flash("Classroom Wi-Fi address updated." if ip_val else "Using automatic classroom Wi-Fi IP detection.", "ok")
        return redirect(back_url)

    if action == "disconnect":
        set_setting(_sync_token_key(g.user["matric"]), "")
        flash("Laptop unlinked from online server. Enter your online password whenever you want to reconnect.", "ok")
        return redirect(back_url)

    raw_url = request.form.get("cloud_url") or get_setting("cloud_url", DEFAULT_CLOUD_URL) or DEFAULT_CLOUD_URL
    cloud_url = _normalize_cloud_url(raw_url)
    if not cloud_url:
        flash("Enter a valid online server URL (for example https://cscattendance.pythonanywhere.com).", "error")
        return redirect(back_url)
    set_setting("cloud_url", cloud_url)

    tok = get_setting(_sync_token_key(g.user["matric"]), "")
    pw = request.form.get("cloud_password", "")
    if not tok and not pw:
        flash("Enter your online server password once to link this laptop.", "error")
        return redirect(back_url)

    with _SYNC_LOCK:
        push_data = _build_laptop_push_payload(db, g.user)
        push_data["matric"] = g.user["matric"]
        if tok:
            push_data["token"] = tok
        if pw:
            push_data["password"] = pw

        code, resp = _cloud_post_json(cloud_url, "/api/sync/push", push_data)
        if code == 401 and tok and not pw:
            set_setting(_sync_token_key(g.user["matric"]), "")
            flash("Your online password changed since this laptop was linked. Enter your online password in the sync box to reconnect.", "error")
            return redirect(back_url)
        if code != 200 or not resp.get("ok"):
            flash(resp.get("error") or "Sync failed.", "error")
            return redirect(back_url)

        now = time.time()
        for suuid in (resp.get("synced_uuids") or []):
            db.execute("UPDATE sessions SET synced_at=? WHERE sync_uuid=?", (now, suuid))
        for duuid in (resp.get("deleted_ack") or []):
            db.execute("DELETE FROM deleted_sessions WHERE sync_uuid=?", (duuid,))
        db.execute("INSERT OR REPLACE INTO settings (key, value) VALUES ('dirty_sync', '0')")
        db.commit()

        n_courses = n_students = 0
        if resp.get("pull"):
            _lec_row, n_courses, n_students = _apply_pull_bundle_to_laptop(db, resp["pull"])
        if resp.get("sync_token"):
            set_setting(_sync_token_key(g.user["matric"]), resp["sync_token"])
        set_setting(_last_sync_key(g.user["matric"]), str(now))

    added = resp.get("sessions_added", 0)
    updated = resp.get("sessions_updated", 0)
    cks = resp.get("checkins_synced", 0)
    parts = []
    if added or updated:
        parts.append(f"uploaded {added + updated} session(s) ({cks} new check-in(s))")
    else:
        parts.append("no pending sessions to upload")
    parts.append(f"refreshed {n_courses} course(s) ({n_students} student(s))")
    msg = f"Synced with {cloud_url}: " + ", ".join(parts) + "."
    if resp.get("warnings"):
        msg += " Note: " + " ".join(resp["warnings"])
    flash(msg, "ok")
    return redirect(back_url)


@app.route("/lecturer/sync/export-roster.json")
@login_required("lecturer", "admin")
def export_roster_json():
    """Online server -> download a .json roster file for a zero-internet classroom PC."""
    bundle = _build_pull_bundle(get_db(), g.user, issue_token=False)
    buf = io.BytesIO(json.dumps(bundle, indent=2).encode("utf-8"))
    fname = f"Attendance_roster_{g.user['matric'].replace('/', '_')}.json"
    return send_file(buf, mimetype="application/json", as_attachment=True, download_name=fname)


@app.route("/lecturer/sync/import-roster", methods=["POST"])
@login_required("lecturer", "admin")
def import_roster_json():
    """Offline laptop -> import a .json roster file downloaded from the online server."""
    f = request.files.get("roster_file")
    if not f or not f.filename:
        flash("Choose a roster .json file first.", "error")
        return redirect(url_for("lecturer_home"))
    try:
        bundle = json.loads(f.read().decode("utf-8"))
        if bundle.get("kind") != "attendance_roster_v1":
            raise ValueError("Not a valid Attendance roster file.")
        _lec, n_courses, n_students = _apply_pull_bundle_to_laptop(get_db(), bundle)
        set_setting(_last_sync_key(g.user["matric"]), str(time.time()))
        flash(f"Roster imported: {n_courses} course(s), {n_students} student(s) ready for offline Wi-Fi attendance.", "ok")
    except Exception as e:
        flash(f"Could not import roster file: {e}", "error")
    return redirect(url_for("lecturer_home"))


@app.route("/lecturer/sync/export-sessions.json")
@login_required("lecturer", "admin")
def export_sessions_json():
    """Offline laptop -> export completed unsynced sessions as a .json file for USB/phone upload."""
    payload = _build_laptop_push_payload(get_db(), g.user)
    buf = io.BytesIO(json.dumps(payload, indent=2).encode("utf-8"))
    fname = f"Attendance_sessions_{g.user['matric'].replace('/', '_')}_{local_dt().strftime('%Y%m%d_%H%M')}.json"
    return send_file(buf, mimetype="application/json", as_attachment=True, download_name=fname)


@app.route("/lecturer/sync/import-sessions", methods=["POST"])
@login_required("lecturer", "admin")
def import_sessions_json():
    """Online server -> import a .json session file exported from an offline classroom PC."""
    f = request.files.get("sessions_file")
    if not f or not f.filename:
        flash("Choose a sessions .json file first.", "error")
        return redirect(url_for("lecturer_home"))
    try:
        payload = json.loads(f.read().decode("utf-8"))
        if payload.get("kind") != "attendance_sessions_v1":
            raise ValueError("Not a valid Attendance sessions file.")
        res = _apply_push_bundle(get_db(), g.user, payload)
        msg = (f"Imported offline file: {res['sessions_added']} new session(s), "
               f"{res['sessions_updated']} updated, {res['checkins_synced']} check-in(s) recorded.")
        if res.get("warnings"):
            msg += " " + " ".join(res["warnings"])
        flash(msg, "ok")
    except Exception as e:
        flash(f"Could not import sessions file: {e}", "error")
    return redirect(url_for("lecturer_home"))


# ---------------------------------------------------------------------------
# Automatic Background Sync (Offline Wi-Fi Laptop -> Cloud Server)
# ---------------------------------------------------------------------------
_SYNC_LOCK = threading.Lock()
_AUTO_SYNC_WAKE = threading.Event()
_AUTO_SYNC_THREAD_LOCK = threading.Lock()
_AUTO_SYNC_STARTED = False
_AUTO_SYNC_INTERVAL = max(3.0, float(os.environ.get("AUTO_SYNC_INTERVAL", "20")))


def _open_bg_db():
    con = sqlite3.connect(DB_PATH, timeout=15.0)
    con.row_factory = sqlite3.Row
    con.execute("PRAGMA foreign_keys = ON")
    con.execute("PRAGMA busy_timeout = 10000")
    return con


def _cloud_is_reachable(cloud_url, timeout=2.5):
    try:
        parsed = urlsplit(cloud_url)
        host = parsed.hostname
        if not host:
            return False
        port = parsed.port or (443 if parsed.scheme == "https" else 80)
        with socket.create_connection((host, port), timeout=timeout):
            return True
    except OSError:
        return False


def _run_auto_sync_once():
    """Upload any pending completed sessions or roster/course edits automatically when internet is available."""
    if not OFFLINE_WIFI:
        return 0
    if not _SYNC_LOCK.acquire(blocking=False):
        return 0
    synced_total = 0
    try:
        db = _open_bg_db()
        try:
            pending_total = db.execute(
                "SELECT COUNT(*) FROM sessions WHERE ended_at IS NOT NULL AND synced_at IS NULL"
            ).fetchone()[0]
            del_total = db.execute("SELECT COUNT(*) FROM deleted_sessions").fetchone()[0]
            dirty_row = db.execute("SELECT value FROM settings WHERE key='dirty_sync'").fetchone()
            is_dirty = bool(dirty_row and dirty_row["value"] == "1")
            if not pending_total and not del_total and not is_dirty:
                return 0
            row_url = db.execute("SELECT value FROM settings WHERE key='cloud_url'").fetchone()
            raw_url = (row_url["value"] if row_url and row_url["value"] else DEFAULT_CLOUD_URL)
            cloud_url = _normalize_cloud_url(raw_url)
            if not cloud_url:
                return 0
            tok_rows = db.execute(
                "SELECT key, value FROM settings WHERE key LIKE 'sync_token:%' AND value != ''"
            ).fetchall()
            linked_accounts = []
            for r in tok_rows:
                matric = r["key"].split(":", 1)[1].strip()
                u = db.execute(
                    "SELECT * FROM users WHERE matric=? COLLATE NOCASE AND active=1 AND role IN ('lecturer','admin')",
                    (matric,),
                ).fetchone()
                if u:
                    linked_accounts.append((dict(u), r["value"]))
            linked_accounts.sort(key=lambda item: 0 if item[0]["role"] == "lecturer" else 1)
        finally:
            db.close()

        if not linked_accounts or not _cloud_is_reachable(cloud_url, timeout=2.5):
            return 0

        for u_dict, tok in linked_accounts:
            db = _open_bg_db()
            try:
                where_owner = "" if u_dict["role"] == "admin" else " AND c.lecturer_id=?"
                args = () if u_dict["role"] == "admin" else (u_dict["id"],)
                rem = db.execute(
                    f"""SELECT COUNT(*) FROM sessions s JOIN courses c ON c.id=s.course_id
                        WHERE s.ended_at IS NOT NULL AND s.synced_at IS NULL{where_owner}""",
                    args,
                ).fetchone()[0]
                del_rem = db.execute("SELECT COUNT(*) FROM deleted_sessions").fetchone()[0]
                dirty_rem_row = db.execute("SELECT value FROM settings WHERE key='dirty_sync'").fetchone()
                dirty_rem = bool(dirty_rem_row and dirty_rem_row["value"] == "1")
                if not rem and not del_rem and not dirty_rem:
                    continue
                push_data = _build_laptop_push_payload(db, u_dict)
                push_data["matric"] = u_dict["matric"]
                push_data["token"] = tok
            finally:
                db.close()

            code, resp = _cloud_post_json(cloud_url, "/api/sync/push", push_data, timeout=15)

            db = _open_bg_db()
            try:
                if code == 200 and resp.get("ok"):
                    now = time.time()
                    uuids = resp.get("synced_uuids") or []
                    for suuid in uuids:
                        db.execute("UPDATE sessions SET synced_at=? WHERE sync_uuid=?", (now, suuid))
                    for duuid in (resp.get("deleted_ack") or []):
                        db.execute("DELETE FROM deleted_sessions WHERE sync_uuid=?", (duuid,))
                    db.execute("INSERT OR REPLACE INTO settings (key, value) VALUES ('dirty_sync', '0')")
                    db.commit()
                    synced_total += len(uuids)
                    if resp.get("pull"):
                        _apply_pull_bundle_to_laptop(db, resp["pull"])
                    if resp.get("sync_token"):
                        db.execute(
                            "INSERT OR REPLACE INTO settings (key, value) VALUES (?, ?)",
                            (_sync_token_key(u_dict["matric"]), resp["sync_token"]),
                        )
                    db.execute(
                        "INSERT OR REPLACE INTO settings (key, value) VALUES (?, ?)",
                        (_last_sync_key(u_dict["matric"]), str(now)),
                    )
                    db.commit()
                elif code == 401:
                    db.execute(
                        "INSERT OR REPLACE INTO settings (key, value) VALUES (?, '')",
                        (_sync_token_key(u_dict["matric"]),),
                    )
                    db.commit()
            finally:
                db.close()
        return synced_total
    except Exception:
        return synced_total
    finally:
        _SYNC_LOCK.release()


def _auto_sync_worker():
    time.sleep(1.5)
    while True:
        _AUTO_SYNC_WAKE.clear()
        _run_auto_sync_once()
        _AUTO_SYNC_WAKE.wait(timeout=_AUTO_SYNC_INTERVAL)


_WIFI_WAKE = threading.Event()
_WIFI_STARTED = False
_ARP_SWEEP_LOCK = threading.Lock()
_arp_last_sweep = {}
_gw_fail_streak = {}
_last_dhcp_renew = 0.0
_SEND_ARP_FN = None


def _get_win_send_arp():
    global _SEND_ARP_FN
    if _SEND_ARP_FN is not None:
        return _SEND_ARP_FN
    if os.name != "nt":
        _SEND_ARP_FN = False
        return False
    try:
        import ctypes
        fn = ctypes.windll.iphlpapi.SendARP
        fn.argtypes = [ctypes.c_uint32, ctypes.c_uint32, ctypes.c_void_p, ctypes.POINTER(ctypes.c_ulong)]
        fn.restype = ctypes.c_uint32
        _SEND_ARP_FN = fn
        return fn
    except Exception:
        _SEND_ARP_FN = False
        return False


def _win_send_arp(dest_ip, src_ip="0.0.0.0"):
    """Send a real Layer-2 802.11 ARP frame via Windows iphlpapi.SendARP.
    Forces AP bridge learning AND populates target phones' ARP tables (RFC 826) before they scan."""
    fn = _get_win_send_arp()
    if not fn:
        return False
    try:
        import ctypes
        dst = struct.unpack("=I", socket.inet_aton(dest_ip))[0]
        src = struct.unpack("=I", socket.inet_aton(src_ip))[0] if src_ip else 0
        mac_buf = (ctypes.c_ubyte * 6)()
        mac_len = ctypes.c_ulong(6)
        return fn(ctypes.c_uint32(dst), ctypes.c_uint32(src), ctypes.byref(mac_buf), ctypes.byref(mac_len)) == 0
    except Exception:
        return False


def _gateway_tcp_heartbeat(lan_ip, gw_ip):
    """Bidirectional unicast TX+RX exchange with the Wi-Fi gateway (SYN -> SYN-ACK or TCP RST).
    Receiving an inbound unicast packet back pulls Intel/Realtek/MediaTek Wi-Fi cards out of
    802.11 Power-Save sleep even on an already-connected Wi-Fi with zero internet."""
    if not gw_ip or gw_ip == lan_ip or gw_ip == "0.0.0.0":
        return False
    for port in (53, 80):
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                s.settimeout(0.22)
                s.bind((lan_ip, 0))
                rc = s.connect_ex((gw_ip, port))
                if rc in (0, 111, 10061):
                    return True
        except OSError as e:
            if getattr(e, "winerror", None) == 10061 or getattr(e, "errno", None) in (111, 10061):
                return True
    return False


def _subnet_hosts_for_ip(lan_ip, mask_str=None):
    """Return peer host IPs in the active classroom subnet (clamped to at most /24 = 253 hosts)."""
    try:
        iface = ipaddress.IPv4Interface(f"{lan_ip}/{mask_str or '24'}")
        net = iface.network
        if net.prefixlen < 24:
            net = ipaddress.IPv4Network(f"{lan_ip}/24", strict=False)
        return [str(h) for h in net.hosts() if str(h) != lan_ip]
    except ValueError:
        return []


def _trigger_arp_subnet_prewarm(targets):
    """Background Layer-2 ARP sweep across active classroom subnet(s) so phones already on the Wi-Fi
    cache the laptop's MAC immediately without needing the lecturer to disconnect/reconnect Wi-Fi."""
    if os.name != "nt" or not targets:
        return
    if not _ARP_SWEEP_LOCK.acquire(blocking=False):
        return

    def _run():
        try:
            for lan_ip, mask_str in targets:
                hosts = _subnet_hosts_for_ip(lan_ip, mask_str)
                if not hosts:
                    continue
                with ThreadPoolExecutor(max_workers=16) as pool:
                    list(pool.map(lambda h: _win_send_arp(h, lan_ip), hosts))
                _arp_last_sweep[lan_ip] = time.time()
        except Exception:
            pass
        finally:
            _ARP_SWEEP_LOCK.release()

    threading.Thread(target=_run, name="AttendanceARPPrewarm", daemon=True).start()


def _renew_stale_wifi_lease_bg():
    global _last_dhcp_renew
    if os.name != "nt":
        return
    now = time.time()
    if now - _last_dhcp_renew < 120.0:
        return
    _last_dhcp_renew = now

    def _renew():
        try:
            subprocess.run(
                ["ipconfig", "/renew", "*Wi-Fi*"],
                capture_output=True, timeout=10,
                creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0),
            )
            _lan_cache["at"] = 0.0
        except Exception:
            pass

    threading.Thread(target=_renew, name="AttendanceDHCPRenew", daemon=True).start()


def _wifi_keepalive_worker():
    """Keep an ALREADY-connected laptop Wi-Fi adapter out of 802.11 Power-Save sleep, refresh the
    router/hotspot's Layer-2 ARP/bridge table via real SendARP + bidirectional TCP heartbeats, and
    pre-warm student phones' ARP caches so the very first QR scan opens without reconnecting Wi-Fi."""
    first_boot = True
    while True:
        woken = _WIFI_WAKE.is_set() or first_boot
        _WIFI_WAKE.clear()
        first_boot = False
        has_live = False
        try:
            if woken:
                _lan_cache["at"] = 0.0
            db = _open_bg_db()
            try:
                has_live = db.execute("SELECT 1 FROM sessions WHERE ended_at IS NULL LIMIT 1").fetchone() is not None
            finally:
                db.close()

            cands = detect_lan_ips()
            now = time.time()
            sweep_targets = []

            for cand in cands[:3]:
                lan_ip = cand["ip"]
                info = (_lan_cache.get("meta") or {}).get(lan_ip) or {}
                parts = lan_ip.split(".")
                real_gw = info.get("gw")
                if real_gw == "0.0.0.0":
                    real_gw = None
                gw_ip = real_gw or (f"{parts[0]}.{parts[1]}.{parts[2]}.1" if len(parts) == 4 else None)
                bcast_ip = info.get("bcast") or (f"{parts[0]}.{parts[1]}.{parts[2]}.255" if len(parts) == 4 else None)
                mask_str = info.get("mask")

                # 1. Real Layer-2 ARP + Two-way TCP heartbeat with gateway (pulls Wi-Fi NIC out of sleep!)
                gw_alive = False
                if os.name == "nt":
                    if woken:
                        # Burst 2 ARP announcements on startup / session start (mimics fresh Wi-Fi connect)
                        _win_send_arp(lan_ip, lan_ip)
                        if gw_ip and gw_ip != lan_ip:
                            gw_alive = _win_send_arp(gw_ip, lan_ip) or gw_alive
                    elif gw_ip and gw_ip != lan_ip:
                        gw_alive = _win_send_arp(gw_ip, lan_ip) or gw_alive

                if gw_ip and gw_ip != lan_ip:
                    gw_alive = _gateway_tcp_heartbeat(lan_ip, gw_ip) or gw_alive
                    try:
                        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
                            s.bind((lan_ip, 0))
                            s.settimeout(0.15)
                            s.sendto(b"\x00", (gw_ip, 9))
                    except OSError:
                        pass

                # Auto-recover stale sleep lease if a real DHCP gateway failed 4 checks in a row
                if os.name == "nt" and real_gw and real_gw != lan_ip:
                    if gw_alive:
                        _gw_fail_streak[lan_ip] = 0
                    else:
                        _gw_fail_streak[lan_ip] = _gw_fail_streak.get(lan_ip, 0) + 1
                        if _gw_fail_streak[lan_ip] >= 4:
                            _gw_fail_streak[lan_ip] = 0
                            _renew_stale_wifi_lease_bg()

                # 2. Subnet broadcast + link-local multicast announcement
                if bcast_ip:
                    try:
                        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
                            s.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
                            s.bind((lan_ip, 0))
                            s.settimeout(0.15)
                            s.sendto(b"CSATT", (bcast_ip, 9))
                    except OSError:
                        pass
                try:
                    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_UDP) as s:
                        s.setsockopt(socket.IPPROTO_IP, socket.IP_MULTICAST_TTL, 1)
                        s.bind((lan_ip, 0))
                        s.settimeout(0.15)
                        s.sendto(b"CSATT", ("224.0.0.251", 9))
                except OSError:
                    pass

                # 3. Queue Layer-2 ARP pre-warm across the classroom subnet on launch, wake, or every 8s live
                sweep_due = woken or (has_live and (now - _arp_last_sweep.get(lan_ip, 0.0) >= 8.0))
                if sweep_due:
                    sweep_targets.append((lan_ip, mask_str))

            if sweep_targets:
                _trigger_arp_subnet_prewarm(sweep_targets)
        except Exception:
            pass
        _WIFI_WAKE.wait(timeout=1.0 if has_live else 2.5)


def _ensure_wifi_keepalive_thread():
    global _WIFI_STARTED
    if PUBLIC_BASE_URL or os.environ.get("DISABLE_WIFI_KEEPALIVE", "0").strip() == "1":
        return
    if not (OFFLINE_WIFI or os.name == "nt"):
        return
    with _AUTO_SYNC_THREAD_LOCK:
        if not _WIFI_STARTED:
            _WIFI_STARTED = True
            threading.Thread(target=_wifi_keepalive_worker, name="AttendanceWiFiKeepAlive", daemon=True).start()


def wake_wifi_now():
    """Immediately wake Wi-Fi adapter, refresh router ARP, and pre-warm connected phones' ARP tables."""
    _ensure_wifi_keepalive_thread()
    _WIFI_WAKE.set()


def _ensure_auto_sync_thread():
    global _AUTO_SYNC_STARTED
    _ensure_wifi_keepalive_thread()
    if not OFFLINE_WIFI or os.environ.get("DISABLE_AUTO_SYNC", "0").strip() == "1":
        return
    with _AUTO_SYNC_THREAD_LOCK:
        if _AUTO_SYNC_STARTED:
            return
        _AUTO_SYNC_STARTED = True
        threading.Thread(target=_auto_sync_worker, name="AttendanceAutoSync", daemon=True).start()


def trigger_auto_sync():
    """Wake the background auto-sync worker immediately after a session ends or is edited."""
    if not OFFLINE_WIFI:
        return
    _ensure_auto_sync_thread()
    _AUTO_SYNC_WAKE.set()


def mark_sync_dirty():
    """Mark local roster/course/session-delete changes as needing background sync."""
    if not OFFLINE_WIFI:
        return
    try:
        set_setting("dirty_sync", "1")
    except Exception:
        pass
    trigger_auto_sync()


@app.route("/api/sync/status")
@login_required("lecturer", "admin")
def api_sync_status():
    """Lightweight poll endpoint so open offline pages flip 'pending sync' -> 'synced' live."""
    _ensure_auto_sync_thread()
    info = _lecturer_sync_info(get_db(), g.user)
    return jsonify({
        "ok": True,
        "pending": int(info["unsynced_ended"]),
        "has_token": bool(info["has_token"]),
        "last_sync": info["last_sync"],
    })


@app.route("/api/desktop/ping")
def api_desktop_ping():
    """Local health & live-session check used by the Windows desktop wrapper."""
    if request.remote_addr not in ("127.0.0.1", "::1"):
        abort(403)
    live_n = get_db().execute("SELECT COUNT(*) FROM sessions WHERE ended_at IS NULL").fetchone()[0]
    return jsonify({"ok": True, "app": "cs-attendance-offline", "live_sessions": int(live_n)})


init_db()
_ensure_auto_sync_thread()

if __name__ == "__main__":
    try:
        sys.stdout.reconfigure(errors="replace")
    except Exception:
        pass
    _port = int(os.environ.get("PORT", 5000))
    if os.name == "nt" and not PUBLIC_BASE_URL:
        wake_wifi_now()
        if not windows_firewall_ok():
            print("  Configuring Windows Firewall for student phone QR scans (one-time prompt)...")
            apply_windows_firewall_uac()
    if OFFLINE_WIFI or (os.name == "nt" and not PUBLIC_BASE_URL):
        _cands = detect_lan_ips()
        _lan = _cands[0]["ip"] if _cands else None
        print("=" * 64)
        print(f"  {APP_NAME} - {'OFFLINE CLASSROOM WI-FI EDITION' if OFFLINE_WIFI else 'LOCAL NETWORK MODE'}")
        print(f"  Lecturer dashboard (this laptop): http://localhost:{_port}")
        if _lan:
            print(f"  Students on Wi-Fi / Hotspot:      http://{_lan}:{_port}")
        else:
            print("  Wi-Fi status: Not connected to Wi-Fi / Hotspot yet.")
            print("  Turn on Laptop Hotspot or join hall Wi-Fi - QR updates automatically.")
        print("  Keep this window open during class. Close it when finished.")
        print("=" * 64, flush=True)
    if os.environ.get("OPEN_BROWSER", "1" if _FROZEN else "0").strip() == "1":
        threading.Timer(0.9, lambda: webbrowser.open(f"http://localhost:{_port}")).start()
    if os.environ.get("USE_WAITRESS", "1" if (OFFLINE_WIFI or os.name == "nt") else "0").strip() == "1":
        try:
            from waitress import serve as _waitress_serve
            _waitress_serve(app, host="0.0.0.0", port=_port, threads=32,
                            connection_limit=1000, channel_timeout=4, cleanup_interval=2, backlog=2048)
        except ImportError:
            app.run(host="0.0.0.0", port=_port, debug=False, threaded=True)
    else:
        app.run(host="0.0.0.0", port=_port, debug=False, threaded=True)
