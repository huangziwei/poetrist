#!/usr/bin/env bash
set -euo pipefail

BASE_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$BASE_DIR"

DB_SRC="poetrist/blog.sqlite3"
STAMP=$(date +%F_%H%M)             # e.g. 2025-07-08_0335
REMOTE="/Root/${STAMP}.sqlite3"    # MEGA destination

megaput --path "$REMOTE" "$DB_SRC"

KEEP=30                                    
megals /Root/ | grep '\.sqlite3$' | sort -r |      # newest → oldest
awk -v keep="$KEEP" 'NR>keep' | while read -r old; do
    megarm "$old"
done