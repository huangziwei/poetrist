#!/usr/bin/env bash
#
# fly-tool ─ modular helper for the “poetrist” Fly app
# --------------------------------------------
# USAGE:
#   ./fly-tool all         # run every step
#   ./fly-tool check-secret
#   ./fly-tool pull-db
#   ./fly-tool deploy
#   ./fly-tool token
#   ./fly-tool help

set -euo pipefail

# ───── constants ────────────────────────────────────────────────────────────────
APP="poetrist"
REMOTE_DB="/app/poetrist/blog.sqlite3"
LOCAL_DB="poetrist/blog.sqlite3"
TMP_DB="${LOCAL_DB}.remote"
SECRET_FILE="poetrist/.secret_key"

# ───── functions ───────────────────────────────────────────────────────────────
usage() { cat <<EOF
fly-tool – modular Fly helper for “${APP}”

Sub-commands:
  check-secret   Ensure .secret_key exists locally
  pull-db        Download blog.sqlite3 from production
  deploy         fly deploy (build + release)
  token          Rotate one-time login token & print login URL
  all            Perform every step (check-secret → pull-db → deploy → token)
  help           Show this message
EOF
}

check_secret() {
  if [[ -f "$SECRET_FILE" ]]; then return 0; fi
  echo "➕  Creating missing .secret_key"
  mkdir -p "$(dirname "$SECRET_FILE")"
  openssl rand -hex 32 > "$SECRET_FILE"
}

pull_db() {
  echo "⬇️   Updating local database copy…"
  if fly ssh sftp get "$REMOTE_DB" "$TMP_DB" -a "$APP" 2>/dev/null; then
    mv -f "$TMP_DB" "$LOCAL_DB"
    echo "    pulled → $LOCAL_DB"
  else
    echo "    no remote DB found – continuing"
    rm -f "$TMP_DB" || true
  fi
}

deploy_app() {
  echo "🚀  fly deploy"
  fly deploy -a "$APP"
}

rotate_token() {
  echo "🔑  Rotating one-time login token…"
  local token
  token=$(
    fly ssh console -a "$APP" -C \
      '/app/.venv/bin/flask --app poetrist/blog.py token' |
    grep -Eo '^[A-Za-z0-9._-]{20,}$' | head -n1
  )
  echo
  echo "One-time token (1 minute) → \n$token"
}

# ───── dispatcher ──────────────────────────────────────────────────────────────
cmd="${1:-help}"
case "$cmd" in
  check-secret)  check_secret ;;
  pull-db)       pull_db ;;
  deploy)        deploy_app ;;
  token)         rotate_token ;;
  all)           check_secret && pull_db && deploy_app && rotate_token ;;
  help|-h|--help) usage ;;
  *) echo "Unknown sub-command: $cmd"; echo; usage; exit 1 ;;
esac
