#!/usr/bin/env bash
# Nightly backup of the database. Add to cron:  0 2 * * * /opt/attendance/deploy/backup.sh
DB=${ATTENDANCE_DB:-/opt/attendance/data/attendance.db}
DEST=/opt/attendance/backups; mkdir -p "$DEST"
sqlite3 "$DB" ".backup '$DEST/attendance-$(date +%F).db'"
find "$DEST" -name 'attendance-*.db' -mtime +30 -delete
