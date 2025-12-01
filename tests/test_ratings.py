"""
tests/test_ratings.py
"""
from uuid import uuid4

from poetrist.blog import get_db, utc_now

CSRF = "test-token"


def _login(client) -> None:
    with client.session_transaction() as sess:
        sess["logged_in"] = True
        sess["csrf"] = CSRF


def _seed_item(action: str, verb: str = "read", item_type: str = "book") -> tuple[str, int]:
    """Create one item + entry_item row for tests."""
    db = get_db()
    now = utc_now().isoformat(timespec="seconds")
    item_slug = f"itm-{uuid4().hex[:8]}"
    entry_slug = f"entry-{uuid4().hex[:8]}"

    db.execute(
        "INSERT INTO item (uuid, slug, item_type, title) VALUES (?,?,?,?)",
        (str(uuid4()), item_slug, item_type, "Item Title"),
    )
    item_id = db.execute("SELECT last_insert_rowid()").fetchone()[0]

    db.execute(
        "INSERT INTO entry (body, created_at, slug, kind) VALUES (?,?,?,?)",
        ("body", now, entry_slug, verb),
    )
    entry_id = db.execute("SELECT last_insert_rowid()").fetchone()[0]

    db.execute(
        "INSERT INTO entry_item (entry_id, item_id, verb, action, progress) "
        "VALUES (?,?,?,?,?)",
        (entry_id, item_id, verb, action, None),
    )
    db.commit()
    return item_slug, item_id


def test_rating_hidden_until_finished(client):
    slug, item_id = _seed_item("reading")
    _login(client)

    resp = client.get(f"/read/book/{slug}")
    assert b'class="score-stars"' not in resp.data

    rv = client.post(
        f"/read/book/{slug}", data={"rating": "4", "csrf": CSRF}, follow_redirects=True
    )
    assert rv.status_code == 200
    rating = (
        get_db()
        .execute("SELECT rating FROM item WHERE id=?", (item_id,))
        .fetchone()["rating"]
    )
    assert rating is None


def test_rating_set_and_clear(client):
    slug, item_id = _seed_item("finished")
    _login(client)

    resp = client.get(f"/read/book/{slug}")
    assert b'class="score-stars"' in resp.data
    assert b'data-score="0"' in resp.data

    rated = client.post(
        f"/read/book/{slug}", data={"rating": "4", "csrf": CSRF}, follow_redirects=True
    )
    assert rated.status_code == 200
    assert (
        get_db()
        .execute("SELECT rating FROM item WHERE id=?", (item_id,))
        .fetchone()["rating"]
        == 4
    )
    assert b'data-score="4"' in rated.data

    cleared = client.post(
        f"/read/book/{slug}", data={"rating": "0", "csrf": CSRF}, follow_redirects=True
    )
    assert cleared.status_code == 200
    assert (
        get_db()
        .execute("SELECT rating FROM item WHERE id=?", (item_id,))
        .fetchone()["rating"]
        is None
    )
    assert b'data-score="0"' in cleared.data
