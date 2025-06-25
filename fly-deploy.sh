#!/usr/bin/env bash
#
# Custom Fly deploy for poetrist
# --------------------------------------------
# 0. ensure poetrist/.secret_key exists locally
# 1. pull the current blog.sqlite3 from the live VM (if any)
# 2. fly deploy  (build + release)
# 3. ssh in, rotate the one-time token, print it

set -euo pipefail
APP="poetrist"                  # your Fly app name
REMOTE_DB="/app/poetrist/blog.sqlite3"
LOCAL_DB="poetrist/blog.sqlite3"
TMP_DB="${LOCAL_DB}.remote"
SECRET_FILE="poetrist/.secret_key"

# ─────────────────────────────────────────────────────────────────── 0
if [[ ! -f "$SECRET_FILE" ]]; then
  echo "➕  Creating missing .secret_key"
  mkdir -p "$(dirname "$SECRET_FILE")"
  openssl rand -hex 32 > "$SECRET_FILE"
fi

# ─────────────────────────────────────────────────────────────────── 1
echo "⬇️   Updating local database copy…"
# 1. download to a temp file
if fly ssh sftp get "$REMOTE_DB" "$TMP_DB" -a "$APP" 2>/dev/null; then
  # 2. move it into place atomically
  mv -f "$TMP_DB" "$LOCAL_DB"
  echo "    pulled → $LOCAL_DB"
else
  echo "    no remote DB found – continuing"
  rm -f "$TMP_DB"
fi

# ─────────────────────────────────────────────────────────────────── 2
echo "🚀  fly deploy"
fly deploy -a "$APP"

# ─────────────────────────────────────────────────────────────────── 3
echo "🔑  Rotating one-time login token…"
TOKEN=$(
  fly ssh console -a "$APP" -C \
    '/app/.venv/bin/flask --app poetrist/blog.py token' |
  grep -Eo '^[A-Za-z0-9_-]{20,}$' | head -n1
)

echo
echo "One-time token → $TOKEN"
echo "Login URL      → https://$APP.fly.dev/login?token=$TOKEN"
