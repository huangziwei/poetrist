#!/usr/bin/env python3
"""
migrate_db.py – copy everything from blog.sqlite3.old to blog.sqlite2,
respecting foreign-key order so constraints remain enabled.
"""

import sqlite3
import sys
from contextlib import closing
from pathlib import Path

ROOT = Path(__file__).resolve().parent
PKG  = ROOT / "poetrist"

OLD_DB = Path(sys.argv[1]) if len(sys.argv) > 1 else PKG / "blog.sqlite3.old"
NEW_DB = Path(sys.argv[2]) if len(sys.argv) > 2 else PKG / "blog.sqlite2"

if not OLD_DB.exists():
    sys.exit(f"❌  source DB not found: {OLD_DB}")
if NEW_DB.exists():
    sys.exit(f"❌  {NEW_DB} already exists – remove it first")

print("• old →", OLD_DB)
print("• new →", NEW_DB)

# ----------------------------------------------------- 1. build empty target
sys.path.insert(0, str(ROOT))
from poetrist import blog  # pulls in init_db()

blog.app.config["DATABASE"] = str(NEW_DB)
with blog.app.app_context():
    blog.init_db()
print("  schema created")

# ----------------------------------------------------- 2. open both DBs
new_db = sqlite3.connect(NEW_DB)
new_db.row_factory = sqlite3.Row
new_db.execute("PRAGMA foreign_keys = ON")

old_db = sqlite3.connect(OLD_DB)
old_db.row_factory = sqlite3.Row

# ----------------------------------------------------- 3. copy in FK-order
TABLES_IN_ORDER = [
    "user",
    "settings",
    "tag",
    "item",
    "item_meta",
    "entry",
    "entry_item",
    "entry_tag",
    "object",          # optional / harmless
]

for tbl in TABLES_IN_ORDER:
    try:
        cols = [c["name"] for c in old_db.execute(f"PRAGMA table_info({tbl})")]
    except sqlite3.OperationalError:
        continue                        # table absent in old DB – skip

    if not cols:                        # empty table definition
        continue

    if tbl == "settings":
        new_db.execute("DELETE FROM settings")  # drop the seeded defaults


    col_list = ", ".join(cols)
    q_marks  = ", ".join("?" * len(cols))
    rows     = old_db.execute(f"SELECT {col_list} FROM {tbl}").fetchall()

    if rows:
        new_db.executemany(
            f"INSERT INTO {tbl} ({col_list}) VALUES ({q_marks})",
            [tuple(r[c] for c in cols) for r in rows]
        )
    print(f"  {tbl:<10} {len(rows):>6} rows")

new_db.commit()

# ----------------------------------------------------- 4. rebuild FTS mirror
new_db.execute("INSERT INTO entry_fts(entry_fts) VALUES('rebuild')")
new_db.commit()
print("  FTS mirror rebuilt ✔")

print("\n✅  migration finished – new DB at", NEW_DB)
