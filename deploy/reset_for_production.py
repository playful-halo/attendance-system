"""
Run ONCE before going live:  python deploy/reset_for_production.py
Removes all demo accounts/courses/sessions and creates your real admin account.
"""
import getpass, os, sqlite3, sys
from datetime import datetime, timezone
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from werkzeug.security import generate_password_hash
from app import DB_PATH

db = sqlite3.connect(DB_PATH)
print("This will delete ALL users, courses, sessions and check-ins in", DB_PATH)
if input("Type YES to continue: ") != "YES":
    sys.exit("Cancelled.")
for t in ("checkins", "rejections", "sessions", "enrolments", "courses", "users"):
    db.execute(f"DELETE FROM {t}")
staff_id = input("Admin staff ID (used to log in): ").strip()
name = input("Admin full name: ").strip()
pw = getpass.getpass("Admin password (min 8 chars): ")
if len(pw) < 8:
    sys.exit("Password too short.")
db.execute("INSERT INTO users (matric,name,password_hash,role,created_at) VALUES (?,?,?,?,?)",
           (staff_id, name, generate_password_hash(pw), "admin", datetime.now(timezone.utc).isoformat()))
db.commit()
print("Done. Log in as", staff_id, "and create lecturer accounts under Users.")
