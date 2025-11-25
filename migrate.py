#!/usr/bin/env python3
"""
migrate.py  –  generic “from-backup” data migrator.

• Expects:
      blog.sqlite3.backup   ← the *old* DB (ro)
      blog.sqlite3          ← **must not exist** (will be created)

• Reads the live schema that poetrist now ships with and copies
  only columns that still exist.  Extra columns / tables in the
  backup are ignored.

Run once, then start the server as usual.
"""

import sqlite3
import sys
from pathlib import Path

import poetrist.blog as blog

# ----------------------------------------------------------------------
# 0.  locations + sanity checks
# ----------------------------------------------------------------------
ROOT = Path(__file__).parent
BACKUP = ROOT / "poetrist/blog.sqlite3.backup"
TARGET = ROOT / "poetrist/blog.sqlite3"


if not BACKUP.exists():
    sys.exit(f"❌  blog.sqlite3.backup not found in {ROOT} – aborting.")
if TARGET.exists():
    sys.exit(f"❌  blog.sqlite3 already exists in {ROOT} – move it away first.")

# ----------------------------------------------------------------------
# 1.  create an empty brand-new DB by importing poetrist and calling init_db()
# ----------------------------------------------------------------------
with blog.app.app_context():
    blog.init_db()  # writes TARGET to disk

# ----------------------------------------------------------------------
# 2.  open connections
# ----------------------------------------------------------------------
src = sqlite3.connect(f"file:{BACKUP}?mode=ro", uri=True)
src.row_factory = sqlite3.Row

with blog.app.app_context():
    dst = blog.get_db()  # strip_caret() is already registered
    dst.execute("PRAGMA foreign_keys=OFF;")  # easier while bulk-copying

    def dst_cols(table: str) -> list[str]:
        """Column list in the *destination* table (correct order)."""
        return [c["name"] for c in dst.execute(f"PRAGMA table_info({table})")]

    def src_cols(table: str) -> set[str]:
        """Set of column names that exist in the *source* DB."""
        return {c["name"] for c in src.execute(f"PRAGMA table_info({table})")}

    def copy_table(table: str):
        if not src_cols(table):
            print(f"  • {table:12}  (absent in backup – skipped)")
            return  # whole table vanished in new schema

        common = [c for c in dst_cols(table) if c in src_cols(table)]
        if not common:
            print(f"  • {table:12}  (no common columns – skipped)")
            return

        if table == "settings":
            # throw away the two bootstrap rows so we can re-insert the real ones
            dst.execute("DELETE FROM settings")

        col_list = ",".join(common)
        qms = ",".join("?" * len(common))
        rows = src.execute(f"SELECT {col_list} FROM {table}")
        dst.executemany(
            f"INSERT INTO {table} ({col_list}) VALUES ({qms})",
            (tuple(r[c] for c in common) for r in rows),
        )
        cnt = dst.execute(f"SELECT COUNT(*) FROM {table}").fetchone()[0]
        print(f"  • {table:12}  ({cnt} rows)")

    print("→ copying compatible tables/columns")
    # Any sensible order that keeps FK parents before children
    for tbl in (
        "user",
        "settings",
        "object",
        "item",
        "item_meta",
        "entry",
        "project",
        "project_entry",
        "tag",
        "entry_tag",
        "entry_item",
        "passkey",
    ):
        copy_table(tbl)

    # ------------------------------------------------------------------
    # 3.  rebuild the FTS5 index (faster than copying)
    # ------------------------------------------------------------------
    print("→ rebuilding entry_fts")
    dst.execute("INSERT INTO entry_fts(entry_fts) VALUES('rebuild');")

    dst.execute("PRAGMA foreign_keys=ON;")
    dst.commit()

print("\n✔  Migration finished – start the app with the new database.")
