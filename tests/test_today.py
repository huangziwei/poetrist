"""
tests/test_today.py
"""
from __future__ import annotations

import datetime as _dt
from zoneinfo import ZoneInfo

from poetrist.blog import get_db


# ───────────────────────── helpers ────────────────────────────────────
def _md_today() -> tuple[int, int]:
    """Return (MM, DD) for ‘today’ in Europe/Berlin – same logic as blog._today_md()."""
    now = _dt.datetime.now(ZoneInfo("Europe/Berlin"))
    return now.month, now.day

# ── helper used by both tests ─────────────────────────────────────────
def _insert_entry(*, year: int, title: str, kind: str = "say") -> None:
    """
    Insert one entry with a specific YYYY-MM-DD (today's month & day)
    but **guarantee a unique slug** by adding a running second-offset.
    """
    db = get_db()

    # static month-day = “today” in Europe/Berlin
    mm, dd = _md_today()

    # bump the seconds each call so slugs differ
    counter = getattr(_insert_entry, "_counter", 0)
    setattr(_insert_entry, "_counter", counter + 1)

    ts = _dt.datetime(year, mm, dd, 12, 34, 56 + counter,
                      tzinfo=_dt.timezone.utc)

    db.execute(
        """
        INSERT INTO entry (title, body, created_at, slug, kind)
        VALUES (?,?,?,?,?)
        """,
        (
            title,
            f"Body for {title}",
            ts.isoformat(timespec="seconds"),
            ts.strftime("%Y%m%d%H%M%S"),   # ← now unique
            kind,
        ),
    )
    db.commit()

# ───────────────────────── tests ──────────────────────────────────────
def test_today_view_lists_all_years(client, monkeypatch):
    """
    • /today shows pills for **each** year it has data for  
    • list contains entries from multiple years, newest first
    """
    # fabricate two different years that share today's MM-DD
    _insert_entry(year=2099, title="Entry-2099")
    _insert_entry(year=2100, title="Entry-2100")

    resp = client.get("/today")
    assert resp.status_code == 200
    html = resp.data.decode()

    # pills: “2099” and “2100” must appear
    assert "2099" in html and "2100" in html

    # both entries visible
    assert "Entry-2099" in html and "Entry-2100" in html

    # newest (2100) should appear *before* 2099
    assert html.find("Entry-2100") < html.find("Entry-2099")


def test_today_year_filter_isolated(client):
    """
    /today/<year> only shows entries from that specific year
    """
    target_year = 2099
    other_year  = 2098

    _insert_entry(year=target_year, title="Solo-Target")
    _insert_entry(year=other_year,  title="Should-Not-Show")

    resp = client.get(f"/today/{target_year}")
    assert resp.status_code == 200
    html = resp.data.decode()

    # only the target entry is present
    assert "Solo-Target" in html
    assert "Should-Not-Show" not in html

    # year-pill “All” plus the two specific years should still be rendered
    assert str(target_year) in html and str(other_year) in html
