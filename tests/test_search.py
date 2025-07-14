"""
tests/test_search.py
"""
from __future__ import annotations

import re

import poetrist.blog as blog
from poetrist.blog import extract_tags, get_db, sync_tags


# ────────────────────────── helpers ──────────────────────────
def _add_entry(*, kind: str = "say", title: str | None = None, body: str = "") -> None:
    """
    Insert an entry directly into the DB **and** keep tag tables in sync.
    Uses the session-wide utc_now() monkey-patch → collision-free slugs.
    """
    db = get_db()
    now_dt  = blog.utc_now()
    slug    = now_dt.strftime("%Y%m%d%H%M%S")
    now_iso = now_dt.isoformat(timespec="seconds")

    db.execute(
        """
        INSERT INTO entry (title, body, created_at, slug, kind)
             VALUES (?,?,?,?,?)
        """,
        (title, body, now_iso, slug, kind),
    )
    entry_id = db.execute("SELECT last_insert_rowid()").fetchone()[0]
    sync_tags(entry_id, extract_tags(body), db=db)
    db.commit()
    return slug, now_dt           # return both for later assertions


def _hit_slugs(html: str) -> list[str]:
    """Extract *all* slugs that appear as entry links in the search results."""
    return re.findall(r'href="/[^/]+/([0-9]{14})"', html)


# ─────────────────────────────────────────────────────────────
def test_fts_search_basic(client):
    """
    A 3-char term should hit the FTS index and find our entry.
    """
    kw   = "FtsMagic"
    slug, _ = _add_entry(body=f"Hello **{kw}** world")

    rv = client.get(f"/search?q={kw}")
    assert rv.status_code == 200
    html = rv.data.decode()
    # the snippet should highlight the token with <mark>
    assert "<mark" in html and kw.lower() in html.lower()
    assert slug in _hit_slugs(html)


def test_like_fallback_for_short_queries(client):
    """
    Two-character searches fall back to a LIKE query.
    """
    slug, _ = _add_entry(body="Hi XY!")

    rv = client.get("/search?q=Hi")
    assert rv.status_code == 200
    assert slug in _hit_slugs(rv.data.decode())


def test_sort_new_vs_old(client):
    """
    Ensure ?sort=new (default) and ?sort=old flip the order.
    """
    kw = "Chrono"
    slug_old, dt_old = _add_entry(body=f"First {kw}")        # older timestamp
    slug_new, dt_new = _add_entry(body=f"Second {kw}")       # newer timestamp

    assert dt_new > dt_old          # sanity check

    res_new = client.get(f"/search?q={kw}&sort=new").data.decode()
    res_old = client.get(f"/search?q={kw}&sort=old").data.decode()

    hits_new = _hit_slugs(res_new)
    hits_old = _hit_slugs(res_old)

    # newest first
    assert hits_new[0] == slug_new
    # oldest first
    assert hits_old[0] == slug_old
