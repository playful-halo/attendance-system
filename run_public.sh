#!/usr/bin/env bash
# Starts the app + a public Cloudflare quick tunnel so phones outside the network can scan the QR.
cd "$(dirname "$0")"
pip list 2>/dev/null | grep -qi segno || pip install -q flask segno
CF=${CLOUDFLARED:-$HOME/.local/bin/cloudflared}
LOG=/tmp/cloudflared.log; : > $LOG
$CF tunnel --url http://127.0.0.1:5000 --no-autoupdate >$LOG 2>&1 &
for i in $(seq 1 30); do
  URL=$(grep -o 'https://[a-z0-9-]*\.trycloudflare\.com' $LOG | head -1); [ -n "$URL" ] && break; sleep 1
done
echo "PUBLIC URL: ${URL:-<tunnel failed, see $LOG>}"
export PUBLIC_BASE_URL="$URL"
export SHOW_DEMO_LOGINS=${SHOW_DEMO_LOGINS:-1}
exec python app.py
