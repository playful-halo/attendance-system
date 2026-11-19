# CS Department Attendance System

A lightweight web app that replaces the paper attendance sheet. The lecturer projects a
QR code; every student checks in at the same time from their own phone.

---

## 1. The problems it solves

| Problem with the paper sheet | How this system fixes it |
|---|---|
| **Slow** – one sheet passed around; some students hold on to it | No sheet. Everyone checks in *simultaneously* from their own phone. A 200-student class is done in about a minute. |
| **Some students never receive it** | The QR code **and** a 6-digit code are projected on the screen for everyone. No camera? Type the 6 digits. Phone dead? The lecturer can mark the student manually (recorded as `manual` for audit). |
| **Students sign for their friends** | 1. QR / code **rotates every 10 seconds** – a forwarded link must be *opened* within ~20 s.<br>2. Opening it issues a **scan ticket bound to that phone**; the ticket cannot be confirmed from a different phone.<br>3. **Geofence** – the student's phone must be within N metres of the lecture hall (per course).<br>4. **Network rule** – flag or block check-ins not made from the campus Wi-Fi.<br>5. **One check-in per student per session**, enforced by a database constraint, using the student's **own login**.<br>6. **Shared-device flagging** – one phone checking in two students flags both.<br>7. **Rejected attempts are logged** and shown to the lecturer live ("blocked" counter).<br>8. **Spot check** – pick N random present students to call out; the deterrent that makes cheating not worth it.<br>9. Late arrivals are marked **late** automatically. |

---

## 2. Quick start

```bash
cd attendance
pip install -r requirements.txt
python app.py                 # → http://localhost:5000
```

To let phones on *other* networks reach it (e.g. for testing from home), start it with
a free public Cloudflare tunnel instead:

```bash
bash run_public.sh            # prints "PUBLIC URL: https://xxxx.trycloudflare.com"
```

The QR code will then point at that public address automatically.

### Demo accounts (created automatically on first run)

| Role | ID | Password |
|---|---|---|
| Lecturer | `STAFF001` | `lecturer123` |
| Admin | `admin` | `admin123` |
| Students | `CSC/2022/001` … `CSC/2022/004` | `student123` |

Demo course: **CSC301 – Data Structures & Algorithms**, join code `DSA301`.

---

## 3. How a lecture works

1. **Lecturer** logs in → **Start attendance** on the course → the projector screen opens
   (click *Full screen*). It shows a large QR code, a 6-digit code, a countdown, a live
   count and the most recent names.
2. **Students** scan the QR with their normal camera app (it opens `/checkin?t=…`), log in
   once, and tap **Confirm — I am <name>**. Or they open the site, tap **Enter attendance
   code** and type the 6 digits.
3. Late arrivals (after the threshold, default 15 min) are automatically marked **late**.
4. Lecturer clicks **End session** → register showing present / late / absent, any flags,
   and a **CSV export**.
5. On the course page, **Export full register** produces a student × session matrix with
   percentages (P = present, L = late, A = absent).

---

## 4. Roles & features

### Student
* Self-register with matric number, or be pre-enrolled by the lecturer.
* Join a course with its **join code**.
* Dashboard with attendance percentage per course and check-in history.
* Live banner when one of their courses is taking attendance right now.

### Lecturer
* Create courses; each gets a join code.
* **Bulk enrol** – paste `MATRIC` or `MATRIC, Full Name` lines. Unknown matric numbers get an
  account automatically (initial password = matric number; students should change it).
* Start / end sessions, set the late threshold, open the projector screen.
* Per-session register with actions: **Mark present**, **Remove**, **Clear flag**.
* CSV export per session and for the whole course.

### Admin
* `/admin/users` – create lecturer (or other) accounts.
* Can view and manage every course.

---

## 5. Security design

### The "forwarded link" problem and how it is closed
A QR code proves *someone is looking at the projector now* – not *who* or *where*. Any
phone-based system is therefore vulnerable to a student forwarding the link to a friend at
home. Layers that close it (configure per course under **Attendance rules**):

| Layer | Effect on the friend at home |
|---|---|
| 10 s rotation, 20 s validity | Must open the link almost instantly. |
| Scan ticket bound to the phone | The link *after* opening cannot be reused on another phone; only the raw QR link within 20 s can. |
| **Geofence** (recommended: 100–150 m) | Rejected: "You appear to be 6,800 m from the lecture hall". Logged as a rejected attempt. |
| **Network rule** (flag or block) | On mobile data / home Wi-Fi → flagged ⚠ or rejected. |
| Rejected-attempt log | The lecturer *sees* that someone tried. |
| Spot check | Random present students are called out; being caught once is the real deterrent. |

Setting up: on the course page, stand in the hall and click **Use my current location**,
set the radius, choose a network rule, **Save rules**. The admin adds the campus IP ranges
under **Settings** (open that page from the campus Wi-Fi to see your IP). Rules are copied
into each session when it starts.

GPS notes: indoor GPS is noisy, so up to 75 m of the phone's reported error is forgiven and
readings worse than ±150 m are accepted but flagged. Location requires HTTPS. Coordinates
are not stored – only the distance from the hall.


| Mechanism | Detail |
|---|---|
| Rotating token | `token = session_id.slot.HMAC(secret, session_id:slot)`, slot = `floor(now / 10 s)`. The current and previous slot are accepted (20 s window) to allow for scan delay. |
| Scan ticket | Opening a valid QR/code issues a signed 120 s ticket containing the session and the phone's device id. The Confirm button submits the ticket, so slow logins never "expire" and a copied link fails on another phone. |
| Geofence / network | See above. Rejections stored in `rejections` with reason, detail and IP. |
| 6-digit code | Derived from the same HMAC; checked only against sessions of courses the student is enrolled in. |
| Uniqueness | `UNIQUE (session_id, student_id)` in the database – a second check-in is impossible. |
| Enrolment check | Only enrolled students can check in to a session. |
| Device flag | A persistent `device_id` cookie; two different students from the same device in one session are both flagged (not blocked – the lecturer decides). |
| Audit trail | Time, method (`qr` / `code` / `manual`), IP and user-agent are stored per check-in. |
| Passwords | Hashed with Werkzeug (`pbkdf2/scrypt`). |
| QR contents | The QR only ever contains the public check-in URL + rotating token – never a login token. |

### Cookie-less operation
Some environments (embedded preview frames, very strict browsers) block cookies entirely.
The app detects this: after login it issues a signed, 12-hour token that is carried in the URL
(`?s=…`) and automatically added to every link, form and API call. When cookies work normally
this token is never used and URLs stay clean. In cookie-less mode the shared-device flag is
inactive (it depends on a cookie); everything else works identically.

---

## 6. Configuration

All via environment variables (or edit the constants at the top of `app.py`):

| Variable | Purpose | Default |
|---|---|---|
| `SECRET_KEY` | Signs sessions and URL tokens. **Set a fixed random value in production** so logins survive restarts. | random per start |
| `ATTENDANCE_DB` | Path to the SQLite database file. | `attendance.db` next to `app.py` |
| `PUBLIC_BASE_URL` | Address students' phones can reach, used in the QR and on the projector screen. Leave empty if everyone uses the same host name. | *(empty)* |
| `PORT` | Listening port. | `5000` |
| `ROTATE_SECONDS` (in `app.py`) | How often the QR / code changes. | `10` |
| `SCAN_TICKET_SECONDS` (in `app.py`) | Time allowed between scanning and confirming. | `120` |
| `GPS_ALLOWANCE_M` / `LOW_ACCURACY_M` (in `app.py`) | GPS error forgiven / flagged above. | `75` / `150` |
| `GRACE_SLOTS` (in `app.py`) | How many previous slots remain valid. | `1` |

---

## 7. Deploying for real use

1. **Host it where phones can reach it** – a campus server or a small cloud VM
   (Render, Railway, PythonAnywhere, a €5 VPS…). Use **HTTPS**; phone cameras open http
   links less readily and cookies need it.
2. Run behind a production WSGI server:
   ```bash
   pip install gunicorn
   SECRET_KEY=$(python -c 'import secrets;print(secrets.token_hex(32))') \
   PUBLIC_BASE_URL=https://attendance.cs.youruni.edu \
   gunicorn -w 2 -b 0.0.0.0:8000 app:app
   ```
   (A single worker is also fine – SQLite handles a lecture-sized load easily.)
3. Put Nginx / Caddy in front for TLS, or use the host's built-in HTTPS.
4. Back up `attendance.db` regularly (it's a single file).
5. Create lecturer accounts via `/admin/users`, change the demo passwords, and delete the
   demo student accounts.
6. Tune `ROTATE_SECONDS` / `GRACE_SLOTS` if your halls have a noticeable projector-to-phone
   delay.

---

## 8. Project layout

```
attendance/
├── app.py              # Flask backend – routes, token logic, database schema
├── run_public.sh       # Start app + Cloudflare quick tunnel (public URL for phones)
├── requirements.txt    # flask, segno
├── attendance.db       # SQLite database (created on first run)
├── static/style.css
└── templates/
    ├── base.html           # layout + flash messages
    ├── login.html / register.html / password.html
    ├── student_home.html   # student dashboard
    ├── checkin.html        # QR landing page & 6-digit code entry
    ├── checkin_done.html   # confirmation
    ├── lecturer_home.html  # course list
    ├── course.html         # sessions, students, bulk enrol, exports
    ├── live.html           # projector screen (rotating QR, live counter)
    ├── report.html         # session register with actions
    └── admin_users.html    # create users
```

---

## 9. Optional hardening (not enabled – straightforward to add)

* **Device binding** – lock each student account to the first device that logs in.
* **University SSO / email magic links** instead of local passwords.
* **Photo verification** – the student must take a selfie during random spot-checks.
* **Browser fingerprinting** – harder-to-clear device identity than a cookie.

---

## 10. Troubleshooting

| Symptom | Cause / fix |
|---|---|
| "Your password was correct, but your browser refused to keep you signed in" | The page is embedded in a frame that blocks cookies. The app falls back to URL tokens automatically; if it still fails, open it in a new tab. |
| Phone shows "missing traffic access token" or can't load the QR link | The QR points at a private/preview host. Set `PUBLIC_BASE_URL` to a public address (or use `run_public.sh`). |
| "That QR code has expired" | The student scanned a screenshot or took more than ~30 s. Scan the live code. |
| "You are not enrolled in this course" | Student must join with the course join code (or be bulk-enrolled) first. |
| "This course requires your location" | Student denied location permission; enable it for the site in browser settings. Lecturer can mark manually. |
| Genuine students rejected as "outside geofence" | Increase the radius (large halls / poor GPS), or re-capture the hall location from inside the room. |
| "You must be connected to the campus Wi-Fi" | Network rule is *block* and the phone is on mobile data. Switch to Wi-Fi, or set the rule to *flag*. |
| Network rule has no effect | Admin hasn't added campus IP ranges under Settings. |
| "This link was opened on a different phone" | A scan link was forwarded; the recipient must scan the projector themselves. |
| Logins lost after restart | Set a fixed `SECRET_KEY`. |


### Timezone
All times are stored in UTC and displayed in `APP_TIMEZONE` (default `Africa/Lagos`), regardless of the server's clock.
