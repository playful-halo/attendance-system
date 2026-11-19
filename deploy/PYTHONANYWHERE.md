# Put the attendance app online with PythonAnywhere (free)

Result: a permanent address like **https://YOURNAME.pythonanywhere.com** that works on any
phone, any time, without your laptop. Takes about 20 minutes. Everything is done in the browser.

Wherever you see **YOURNAME** below, use the username you pick in step 1 (lowercase letters/numbers only).

---

## 1. Create the account (3 min)
1. Go to https://www.pythonanywhere.com and click **Pricing & signup** → **Create a Beginner account** (free, no card).
2. Choose a username — it becomes your web address, e.g. `csc-attendance` → `https://csc-attendance.pythonanywhere.com`.
3. Confirm your e-mail. You land on the **Dashboard**.

## 2. Upload the app (3 min)
1. Top menu → **Files**.
2. On the right, **Upload a file** → choose `attendance_update.zip` (the zip I gave you).
3. Top menu → **Consoles** → **Bash** (starts a black terminal in the browser). Type, pressing Enter after each line:
   ```
   unzip -o attendance_update.zip
   pip install --user --upgrade "flask>=3.1" segno
   ```
   Wait until it finishes (about a minute). You now have a folder `/home/YOURNAME/attendance`.

## 3. Create the web app (5 min)
1. Top menu → **Web** → **Add a new web app** → **Next**.
2. Choose **Manual configuration** (NOT the Flask option) → **Next**.
3. Choose **Python 3.11** (or the newest 3.x offered) → **Next** → you're back on the Web tab.
4. Scroll to the **Code** section and set:
   - **Source code:** `/home/YOURNAME/attendance`
   - **Working directory:** `/home/YOURNAME/attendance`
5. In the same section click the link next to **WSGI configuration file** (it looks like `/var/www/YOURNAME_pythonanywhere_com_wsgi.py`). An editor opens.
6. **Delete everything** in that file and paste exactly this (change YOURNAME in three places, and the secret key to any long random text):
   ```python
   import os, sys

   APP_DIR = '/home/YOURNAME/attendance'
   sys.path.insert(0, APP_DIR)
   os.chdir(APP_DIR)

   os.environ['SECRET_KEY'] = 'PASTE-A-LONG-RANDOM-STRING-HERE'   # keep this private; never change it later or everyone is logged out
   os.environ['PUBLIC_BASE_URL'] = 'https://YOURNAME.pythonanywhere.com'
   os.environ['APP_TIMEZONE'] = 'Africa/Lagos'   # times are shown in this timezone (default if omitted)

   from app import app as application
   ```
   Click **Save** (top right).
7. Back on the **Web** tab, scroll to **Static files** and click **Enter URL** / **Enter path** to add one row:
   - URL: `/static/`
   - Directory: `/home/YOURNAME/attendance/static`
8. Scroll to **Security** → switch **Force HTTPS** to **Enabled** (phones only share location over https).
9. Scroll back to the top and press the big green **Reload YOURNAME.pythonanywhere.com** button.

## 4. Open it
Go to **https://YOURNAME.pythonanywhere.com** on your phone or laptop.
Demo logins: `admin` / `admin123`, `STAFF001` / `lecturer123`, students `CSC/2022/001`–`025` / `student123`.

The QR code on the live screen now points at your public address, so scanning it with any phone works.

---

## Keeping your existing data (optional)
If you already have real students/courses in the copy on your laptop, upload your laptop's
`attendance.db` (Files → open the `attendance` folder → Upload) **before** step 3.9, then Reload.
Otherwise the site starts with the demo data.

## Demo account hint
The login page does **not** list the demo accounts on a public site. If you want it shown for a
closed demo, add this line to the WSGI file above `from app import app`: `os.environ['SHOW_DEMO_LOGINS'] = '1'`
When the hint is hidden, anyone logging in as admin/lecturer with a default demo password is forced to choose a new one.

## Before real use (not for the demo)
In a Bash console:
```
cd ~/attendance
python deploy/reset_for_production.py
```
This wipes the demo accounts and creates your real admin account. Then Reload on the Web tab.

## Updating later
When I give you a new zip: Files → Upload it → Bash console → `unzip -o attendance_update.zip` → Web tab → **Reload**. Your database is never inside the zip, so nothing is lost.

## Things to know about the free plan
- The site stays up, but you must click **"Run until 3 months from today"** on the Web tab once every 3 months, or it is switched off. PythonAnywhere e-mails you a reminder.
- Free accounts get one web app and modest CPU — plenty for a department's check-ins.
- Your data is one file: `/home/YOURNAME/attendance/attendance.db`. Download it from the Files tab now and then as a backup.

## If something goes wrong
On the **Web** tab, open the **Error log** link — the last lines say what failed. Most common:
- `No module named flask/segno` → run `pip install --user --upgrade "flask>=3.1" segno` again in a Bash console, then Reload.
- Page shows but no styling → check the Static files row (step 3.7) has the exact path.
- "Bad gateway"/"Something went wrong" → a typo in the WSGI file; re-check YOURNAME in all three places.
