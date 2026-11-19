# Publishing the Attendance System for your department

You need three things: a **fixed public HTTPS address**, a server that **stays on**, and
a **database that persists**. Pick one of the routes below (A is easiest, C is best).

---

## Route A — PythonAnywhere (fastest, free tier available, no card)

Good for a pilot with one department. Gives you `https://yourname.pythonanywhere.com`.

1. Create an account at https://www.pythonanywhere.com (free "Beginner" is enough to pilot;
   the $5/month "Hacker" plan is recommended once the whole department uses it).
2. **Files** tab → upload the `attendance` folder (zip it, upload, then in a Bash console:
   `unzip attendance.zip`). You should now have `/home/yourname/attendance/app.py`.
3. **Consoles** tab → Bash:
   ```bash
   cd ~/attendance
   pip3 install --user -r requirements.txt
   python3 deploy/reset_for_production.py     # removes demo data, creates your admin
   ```
4. **Web** tab → *Add a new web app* → *Manual configuration* → Python 3.10 (or newer).
5. In the Web tab set **Source code** and **Working directory** to `/home/yourname/attendance`.
6. Click the **WSGI configuration file** link and replace its contents with:
   ```python
   import os, sys
   sys.path.insert(0, '/home/yourname/attendance')
   os.environ['SECRET_KEY'] = 'PASTE-A-LONG-RANDOM-STRING-HERE'
   os.environ['PUBLIC_BASE_URL'] = 'https://yourname.pythonanywhere.com'
   os.environ['ATTENDANCE_DB'] = '/home/yourname/attendance/attendance.db'
   from app import app as application
   ```
   (Generate the random string with `python3 -c "import secrets;print(secrets.token_hex(32))"`.)
7. **Reload** the web app. Open `https://yourname.pythonanywhere.com` — done. HTTPS is
   automatic, so the geofence works on phones.

Free-tier notes: the app must be "reloaded" from the Web tab every 3 months, and CPU is
limited — fine for a few hundred check-ins per lecture.

---

## Route B — Render / Railway (free trial, needs a card for persistent disk)

These deploy straight from GitHub. Important: on their **free** plans the disk is wiped on
every deploy/restart, which would erase `attendance.db`. You must add a **persistent disk**
(paid, ~$1–7/month) and set `ATTENDANCE_DB` to a path on it. Build command
`pip install -r requirements.txt`, start command `gunicorn -w 2 -b 0.0.0.0:$PORT wsgi:application`,
environment variables `SECRET_KEY`, `PUBLIC_BASE_URL`, `ATTENDANCE_DB`.

---

## Route C — University server or a small VPS (recommended for long-term use)

Ask your IT unit for a small Linux VM and a subdomain (e.g. `attendance.cs.university.edu.ng`),
or rent a VPS (~$4–6/month: Hetzner, DigitalOcean, Contabo). Ubuntu 22.04/24.04 assumed.

```bash
# 1. system packages
sudo apt update && sudo apt install -y python3-venv python3-pip sqlite3 caddy
sudo useradd -r -m -d /opt/attendance attendance

# 2. app
sudo -u attendance bash -c '
  cd /opt/attendance && git clone <your-repo> . || true   # or scp the folder here
  python3 -m venv venv && venv/bin/pip install -r requirements.txt
  mkdir -p data && ATTENDANCE_DB=/opt/attendance/data/attendance.db venv/bin/python deploy/reset_for_production.py
'

# 3. service (edit SECRET_KEY and PUBLIC_BASE_URL in the file first)
sudo cp /opt/attendance/deploy/attendance.service /etc/systemd/system/
sudo systemctl enable --now attendance

# 4. HTTPS reverse proxy (edit the domain in the Caddyfile first; DNS must point here)
sudo cp /opt/attendance/deploy/Caddyfile /etc/caddy/Caddyfile
sudo systemctl reload caddy

# 5. nightly backups
(crontab -l 2>/dev/null; echo "0 2 * * * /opt/attendance/deploy/backup.sh") | crontab -
```

Caddy obtains and renews the HTTPS certificate automatically. Updates later:
`cd /opt/attendance && git pull && sudo systemctl restart attendance`.

Bonus of hosting on campus: the server can sit on the campus network and the
**network rule** becomes trivially reliable.

---

## Go-live checklist (all routes)

- [ ] `SECRET_KEY` set to a fixed random value (otherwise everyone is logged out on restart)
- [ ] `PUBLIC_BASE_URL` set to the real https address (this is what the QR encodes)
- [ ] Demo data removed with `deploy/reset_for_production.py`; real admin created
- [ ] Lecturer accounts created under **Users**; lecturers change their password on first login
- [ ] Courses created; students bulk-enrolled (paste `MATRIC, Name` lines) or given the join code
- [ ] **Attendance rules** set per course from inside the hall (geofence 100–150 m)
- [ ] Campus IP ranges added under **Settings** if you use the network rule
- [ ] Backups of `attendance.db` scheduled (Route C script, or PythonAnywhere's file download)
- [ ] Short briefing to students: log in once, allow location, scan from the projector

## Capacity

SQLite + 2 gunicorn workers comfortably handles a 300-student lecture hall checking in
within a minute. For a whole faculty on one server, move to PostgreSQL later (the SQL is
standard; only the connection code in `get_db()` changes).

## Optional polish before launch

- Put the department logo/name in `templates/base.html`.
- Disable public self-registration (remove the `/register` route) if you prefer to
  bulk-enrol everyone.
- Set `ROTATE_SECONDS` to 15 if scanning in large halls proves too tight at 10.
