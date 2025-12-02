"""
tests/test_posting.py
"""
from __future__ import annotations

import re
from typing import Any

from poetrist.blog import get_db

CSRF = "test-token"          # shared constant so the token matches the session


def _login(client) -> None:
    with client.session_transaction() as sess:
        sess["logged_in"] = True
        sess["csrf"] = CSRF

def _submit(
    client,
    path: str,               # "/", "/posts", "/pins"
    payload: dict[str, Any],
    href_regex: str,         # e.g. r'href="/posts/([^"]+)"'
) -> str:
    """POST helper – returns the new <slug> extracted from response HTML."""
    _login(client)
    rv = client.post(path, data={**payload, "csrf": CSRF}, follow_redirects=True)
    assert rv.status_code == 200, rv.data.decode()

    match = re.search(href_regex, rv.data.decode())
    assert match, "detail link not found"
    return match.group(1)              # slug


def _detail_ok(client, url: str, *expect: bytes) -> None:
    resp = client.get(url)
    assert resp.status_code == 200
    for token in expect:
        assert token in resp.data, url


# ───────────────────────── parametric tests ────────────────────────────
def test_quick_add_say(client):
    slug = _submit(
        client,
        "/",                                   # index form
        payload={"body": "hello **say**"},
        href_regex=r'href="/says/([^"]+)"',
    )
    _detail_ok(client, f"/says/{slug}", b"<strong>say</strong>")


def test_quick_add_post(client):
    slug = _submit(
        client,
        "/posts",
        payload={"title": "My *Post*", "body": "post **body**"},
        href_regex=r'href="/posts/([^"]+)"',
    )
    # title is rendered as <h2> on detail page
    _detail_ok(client, f"/posts/{slug}", b"My *Post*", b"<strong>body</strong>")


def test_quick_add_pin(client):
    slug = _submit(
        client,
        "/pins",
        payload={
            "title": "PyPI",
            "link": "https://pypi.org",
            "body": "the **cheese** shop",
        },
        href_regex=r'href="/pins/([^"]+)"',
    )
    # Pin shows external link + markdown render
    _detail_ok(
        client,
        f"/pins/{slug}",
        b'href="https://pypi.org"',
        b"<strong>cheese</strong>",
    )

def test_caret_checkin_creates_item(client):
    _login(client)
    body = '^reading:book:"The Hobbit":42%'

    # POST quick-add
    rv = client.post("/", data={"body": body, "csrf": CSRF}, follow_redirects=True)
    assert rv.status_code == 200

    html = rv.data.decode()

    # ➊ Entry link   e.g.  href="/read/20250714125900"
    m = re.search(r'href="/read/([^"]+)"', html)
    assert m, "read entry link missing"
    entry_slug = m.group(1)

    # ➋ Item link    e.g.  href="/read/book/<item-slug>"
    n = re.search(r'href="/read/book/([^"]+)"', html)
    assert n, "item link missing"
    item_slug = n.group(1)

    # —— entry detail page ——
    detail = client.get(f"/read/{entry_slug}")
    assert b"The Hobbit" in detail.data
    assert b"42%" in detail.data             # progress pill
    assert b"reading" in detail.data         # action pill

    # —— item detail page ——
    item = client.get(f"/read/book/{item_slug}")
    assert b"The Hobbit" in item.data
    assert b"book" in item.data

    # —— database sanity: exactly one item row exists with that slug ——
    db = get_db()
    rows = db.execute("SELECT COUNT(*) AS c FROM item WHERE slug=?", (item_slug,)).fetchone()
    assert rows["c"] == 1


def test_invalid_caret_is_ignored_no_item_or_link(client):
    """
    Posting an invalid caret snippet like '^watched:"The Matrix"' should not
    crash, and must not create items or entry_item links.
    """
    _login(client)

    db = get_db()
    items_before = db.execute("SELECT COUNT(*) AS c FROM item").fetchone()["c"]
    links_before = db.execute("SELECT COUNT(*) AS c FROM entry_item").fetchone()["c"]
    entries_before = db.execute("SELECT COUNT(*) AS c FROM entry").fetchone()["c"]

    rv = client.post("/", data={"body": '^watched:"The Matrix"', "csrf": CSRF}, follow_redirects=True)
    assert rv.status_code == 200, rv.data.decode()

    items_after = db.execute("SELECT COUNT(*) AS c FROM item").fetchone()["c"]
    links_after = db.execute("SELECT COUNT(*) AS c FROM entry_item").fetchone()["c"]
    entries_after = db.execute("SELECT COUNT(*) AS c FROM entry").fetchone()["c"]

    # no items or links created by invalid caret
    assert items_after == items_before
    assert links_after == links_before

    # ensure the last entry (if a new one was created) has a non-empty kind
    if entries_after > entries_before:
        last = db.execute("SELECT kind FROM entry ORDER BY id DESC LIMIT 1").fetchone()
        assert last["kind"]


def test_item_detail_allows_custom_action_for_existing_item(client):
    """
    Existing items should accept free-form actions on check-in (not limited to VERB_MAP).
    """
    _login(client)
    db = get_db()
    db.execute(
        "INSERT INTO item (uuid, slug, item_type, title) VALUES (?,?,?,?)",
        ("123e4567-e89b-12d3-a456-426614174000", "custom-item", "book", "Custom Book"),
    )
    db.commit()

    rv = client.post(
        "/read/book/custom-item",
        data={"meta": "^action:afterparty\n^progress:10%", "csrf": CSRF},
        follow_redirects=True,
    )
    assert rv.status_code == 200

    row = db.execute(
        "SELECT action FROM entry_item ORDER BY rowid DESC LIMIT 1"
    ).fetchone()
    assert row and row["action"] == "afterparty"
