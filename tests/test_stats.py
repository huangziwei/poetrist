"""
tests/test_stats.py
"""
from __future__ import annotations

import datetime as _dt
import re
import uuid

from poetrist.blog import get_db


# ───────────────────────── helpers ────────────────────────────────────
def _add_entry(
    *,
    year: int,
    month: int,
    day: int,
    kind: str,
    body: str,
    tags: tuple[str, ...] = (),
) -> int:
    """
    Insert one entry with a specific timestamp and optional tags.
    """
    db = get_db()
    counter = getattr(_add_entry, "_counter", 0)
    setattr(_add_entry, "_counter", counter + 1)

    ts = _dt.datetime(year, month, day, 12, 0, counter, tzinfo=_dt.timezone.utc)
    slug = f"stats-{year}{month:02d}{day:02d}-{kind}-{counter}"

    db.execute(
        "INSERT INTO entry (title, body, created_at, slug, kind) VALUES (?,?,?,?,?)",
        (f"{kind.title()} {counter}", body, ts.isoformat(timespec="seconds"), slug, kind),
    )
    entry_id = db.execute("SELECT last_insert_rowid()").fetchone()[0]

    for tag in tags:
        db.execute("INSERT OR IGNORE INTO tag (name) VALUES (?)", (tag,))
        tag_id = db.execute("SELECT id FROM tag WHERE name=?", (tag,)).fetchone()[0]
        db.execute(
            "INSERT OR IGNORE INTO entry_tag (entry_id, tag_id) VALUES (?,?)",
            (entry_id, tag_id),
        )

    db.commit()
    return entry_id


def _attach_item(
    entry_id: int,
    *,
    verb: str,
    action: str,
    progress: str | None = None,
    item_type: str = "book",
    title: str = "Stats Item",
) -> None:
    """Create an item row and link it to the given entry_id."""
    db = get_db()
    uid = uuid.uuid4()
    db.execute(
        "INSERT INTO item (uuid, slug, item_type, title) VALUES (?,?,?,?)",
        (str(uid), f"item-{uid}", item_type, title),
    )
    item_id = db.execute("SELECT last_insert_rowid()").fetchone()[0]

    db.execute(
        "INSERT INTO entry_item (entry_id, item_id, verb, action, progress) VALUES (?,?,?,?,?)",
        (entry_id, item_id, verb, action, progress),
    )
    db.commit()


# ───────────────────────── tests ──────────────────────────────────────
def test_stats_json_includes_breakdowns(client):
    """
    /stats?format=json should return yearly + monthly breakdowns and item stats.
    """
    _ = _add_entry(
        year=2301,
        month=5,
        day=1,
        kind="say",
        body="alpha body content",
        tags=("stats-alpha",),
    )
    _ = _add_entry(
        year=2301,
        month=5,
        day=2,
        kind="post",
        body="post body more words",
        tags=("stats-beta",),
    )
    finished_entry = _add_entry(
        year=2301,
        month=5,
        day=3,
        kind="read",
        body="read entry finished",
        tags=("stats-read",),
    )
    reading_entry = _add_entry(
        year=2302,
        month=1,
        day=10,
        kind="read",
        body="reading update body",
        tags=("stats-next",),
    )

    _attach_item(
        finished_entry,
        verb="read",
        action="finished",
        progress="100%",
        title="Alpha Book",
    )
    _attach_item(
        reading_entry,
        verb="read",
        action="reading",
        progress="40%",
        title="Next Book",
    )

    resp = client.get("/stats?format=json&months=24")
    assert resp.status_code == 200
    data = resp.get_json()
    assert data and data["yearly"]

    year_2301 = next(y for y in data["yearly"] if y["year"] == "2301")
    assert year_2301["total"] == 3
    assert year_2301["kinds"]["say"] == 1
    assert year_2301["kinds"]["post"] == 1
    assert year_2301["kinds"]["read"] == 1
    assert year_2301["tags"] >= 3

    month_2301 = next(m for m in data["monthly"] if m["month"] == "2301-05")
    assert month_2301["total"] == 3
    month_2302 = next(m for m in data["monthly"] if m["month"] == "2302-01")
    assert month_2302["total"] == 1

    assert data["items"]["checkins"] >= 2
    assert data["items"]["completed"] >= 1
    assert any(a["action"] == "finished" for a in data["items"]["by_action"])
    assert data["overview"]["total_entries"] >= 4


def test_stats_page_renders_sections(client):
    """
    /stats HTML should render the major sections and tag list.
    """
    # boost one tag so it appears in the “Top tags” section
    for day in (20, 21, 22):
        _add_entry(
            year=2303,
            month=2,
            day=day,
            kind="say",
            body="html stats body",
            tags=("stats-html",),
        )

    resp = client.get("/stats")
    assert resp.status_code == 200
    html = resp.data.decode()

    assert "Yearly cadence" in html
    assert "Last" in html           # monthly trend header
    assert "#stats-html" in html    # tag pill
    assert "On this day" in html
    assert "Download as JSON" in html


def test_stats_counts_entries_without_entry_item(client):
    """
    Entries with verb kinds but no entry_item rows still count as check-ins.
    """
    resp_before = client.get("/stats?format=json")
    before = resp_before.get_json()["items"]["checkins"]

    _add_entry(
        year=2304,
        month=3,
        day=15,
        kind="read",
        body="no item link here",
    )

    resp_after = client.get("/stats?format=json")
    after = resp_after.get_json()["items"]["checkins"]

    assert after >= before + 1


def test_stats_normalizes_case_and_typos(client):
    """
    Uppercase verb kinds should still count toward check-ins.
    """
    resp_before = client.get("/stats?format=json")
    before = resp_before.get_json()["items"]["checkins"]

    _add_entry(
        year=2304,
        month=3,
        day=16,
        kind="Read",  # uppercase variant
        body="capitalized verb",
    )

    resp_after = client.get("/stats?format=json")
    data = resp_after.get_json()

    assert data["items"]["checkins"] >= before + 1
    actions = {a["action"] for a in data["items"]["by_action"]}
    assert "read" in actions


def test_stats_items_section_shows_when_checkins_exist(client):
    """Items & check-ins section should not display the empty state."""
    entry_id = _add_entry(
        year=2305,
        month=4,
        day=1,
        kind="read",
        body="render items section",
    )
    _attach_item(
        entry_id,
        verb="read",
        action="reading",
        progress="10%",
        title="HTML Check",
    )

    resp = client.get("/stats")
    html = resp.data.decode()

    assert "No check-ins yet." not in html
    assert "Items & check-ins" in html
    assert re.search(
        r"Check-ins</div>\s*<div[^>]*>\s*\d+",
        html,
        re.MULTILINE,
    )
    assert re.search(
        r"unique item[s]?",
        html,
        re.IGNORECASE,
    )
