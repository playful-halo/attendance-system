"""
Seed realistic demo data so the suspicion engine has something to show:
  python demo_seed.py
25 students, 6 past lectures, then a LIVE 7th lecture with everyone checked in.
Patterns planted:
  * Tunde (001) & Chiamaka (002): the "two-phone" pair - always within seconds of each other
  * Ibrahim (003): checks in from a different phone today than in every previous lecture
  * Ngozi (004): was caught absent in a spot check 2 weeks ago
  * Student 010: shares a phone with 011 today (shared-device flag) and was rejected from outside first
"""
import random, sqlite3, time, uuid
from datetime import datetime, timezone
from werkzeug.security import generate_password_hash
from app import DB_PATH

random.seed(7)
db = sqlite3.connect(DB_PATH)
db.row_factory = sqlite3.Row
ts = datetime.now(timezone.utc).isoformat(timespec="seconds")
course = db.execute("SELECT * FROM courses WHERE code='CSC301'").fetchone()
cid = course["id"]

# wipe previous activity for a clean demo
for t in ("spot_checks", "rejections", "checkins", "sessions"):
    db.execute(f"DELETE FROM {t} WHERE {'session_id' if t!='sessions' else 'course_id'} IN "
               f"({'SELECT id FROM sessions WHERE course_id=?' if t!='sessions' else '?'})", (cid,))

names = ["Tunde Bakare","Chiamaka Eze","Ibrahim Musa","Ngozi Adeyemi","Emeka Obi","Aisha Bello","Seun Adebayo",
         "Fatima Sani","Kelechi Nwosu","Yusuf Lawal","Blessing Okafor","Samuel Ojo","Halima Abdullahi","Chidi Okeke",
         "Zainab Umar","Femi Alade","Amaka Ude","Musa Garba","Tobi Olawale","Precious Eke","Kunle Ajayi",
         "Nneka Igwe","Bashir Yakubu","Ada Nwachukwu","Segun Bello"]
students = []
for i, n in enumerate(names, 1):
    m = f"CSC/2022/{i:03d}"
    u = db.execute("SELECT id FROM users WHERE matric=?", (m,)).fetchone()
    if not u:
        db.execute("INSERT INTO users (matric,name,password_hash,role,created_at) VALUES (?,?,?,?,?)",
                   (m, n, generate_password_hash("student123"), "student", ts))
        u = db.execute("SELECT id FROM users WHERE matric=?", (m,)).fetchone()
    db.execute("INSERT OR IGNORE INTO enrolments VALUES (?,?)", (cid, u["id"]))
    students.append(u["id"])
S = {i + 1: sid for i, sid in enumerate(students)}          # 1..25 -> user id
device = {sid: uuid.uuid4().hex for sid in students}        # each student's usual phone

def add_session(title, start, live=False):
    cur = db.execute("INSERT INTO sessions (course_id,title,secret,started_at,ended_at,late_after_min) VALUES (?,?,?,?,?,15)",
                     (cid, title, uuid.uuid4().hex, start, None if live else start + 100 * 60))
    return cur.lastrowid

def checkin(sess, sid, t, dev=None, flagged=0, reason=None, ip="10.20.4.15"):
    db.execute("""INSERT OR IGNORE INTO checkins (session_id,student_id,checked_at,status,method,device_id,ip,user_agent,flagged,flag_reason)
                  VALUES (?,?,?,?,?,?,?,?,?,?)""",
               (sess, sid, t, "present" if t - START[sess] < 900 else "late", random.choice(["qr","qr","qr","code"]),
                dev or device[sid], ip, "Mozilla/5.0 (Linux; Android 13) Chrome/128", flagged, reason))

START = {}
now = time.time()
DAY = 86400
# 6 past lectures, weekly, at 10:00
for w in range(6, 0, -1):
    start = now - w * 7 * DAY
    sess = add_session(f"Lecture {7 - w}", start)
    START[sess] = start
    absent = set(random.sample(students, random.randint(2, 5)))
    for sid in students:
        if sid in absent:
            continue
        checkin(sess, sid, start + random.uniform(20, 600))
    # the pair: always within a few seconds
    t = start + random.uniform(40, 300)
    for k in (1, 2):
        db.execute("DELETE FROM checkins WHERE session_id=? AND student_id=?", (sess, S[k]))
        checkin(sess, S[k], t + random.uniform(0, 4))
    # Ngozi caught absent in lecture 4
    if 7 - w == 4:
        db.execute("INSERT INTO spot_checks (session_id,student_id,picked_at,score,reasons,outcome,decided_at) VALUES (?,?,?,?,?,?,?)",
                   (sess, S[4], start + 1800, 0, "", "absent", start + 1900))
        db.execute("DELETE FROM checkins WHERE session_id=? AND student_id=?", (sess, S[4]))
        # Also two random 'present' outcomes for realism
        for sid in random.sample([s for s in students if s not in absent and s != S[4]], 2):
            db.execute("INSERT INTO spot_checks (session_id,student_id,picked_at,score,reasons,outcome,decided_at) VALUES (?,?,?,?,?,?,?)",
                       (sess, sid, start + 1800, 0, "", "present", start + 1900))

# today's LIVE lecture, started 12 minutes ago
start = now - 12 * 60
live = add_session("Lecture 7", start, live=True)
START[live] = start
for sid in students:
    if sid in (S[1], S[2], S[3], S[4], S[10], S[11], S[20]):
        continue
    checkin(live, sid, start + random.uniform(15, 500))
t = start + 95
checkin(live, S[1], t); checkin(live, S[2], t + 3)                       # pair again
checkin(live, S[3], start + 130, dev=uuid.uuid4().hex)                   # Ibrahim: new phone
checkin(live, S[4], start + 200)                                         # Ngozi: previously caught
shared = uuid.uuid4().hex                                                # 010 & 011 share a phone
checkin(live, S[11], start + 240, dev=shared, flagged=1, reason="shared device")
db.execute("INSERT INTO rejections (session_id,student_id,at,reason,detail,ip) VALUES (?,?,?,?,?,?)",
           (live, S[10], start + 60, "outside geofence", "742 m away (±18 m)", "41.58.100.7"))
checkin(live, S[10], start + 250, dev=shared, flagged=1, reason="shared device", ip="41.58.100.7")
# student 20 simply absent
db.commit()
print(f"Seeded: 25 students, 6 past lectures, live session id={live}")
