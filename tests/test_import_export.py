"""
tests/test_item_import_export.py
"""
from __future__ import annotations

import uuid
from types import SimpleNamespace
from typing import Any

import pytest

import poetrist.blog as blog
from poetrist.blog import app, get_db, import_item_json


# ───────────────────────── helpers ────────────────────────────────
def _create_item(
    *,
    item_type: str = "book",
    title: str = "The Hobbit",
    slug: str = "the-hobbit",
    meta: dict[str, str] | None = None,
) -> tuple[str, str]:
    """
    Insert an item (+meta) directly; return (verb, slug) so callers
    can build /<verb>/<item_type>/<slug>/json URLs easily.
    """
    db = get_db()
    uuid_ = str(uuid.uuid4())
    db.execute(
        "INSERT INTO item (uuid, slug, item_type, title) VALUES (?,?,?,?)",
        (uuid_, slug, item_type, title),
    )
    item_id = db.execute("SELECT last_insert_rowid()").fetchone()[0]

    meta = meta or {"author": "J. R. R. Tolkien", "date": "1937"}
    for ord_, (k, v) in enumerate(meta.items(), 1):
        db.execute(
            "INSERT INTO item_meta (item_id, k, v, ord) VALUES (?,?,?,?)",
            (item_id, k, v, ord_),
        )
    db.commit()
    return "read", slug        # we’ll expose it under the “read” verb


# ───────────────────────── tests ──────────────────────────────────
def test_export_json_endpoint(client):
    verb, slug = _create_item()

    rv = client.get(f"/{verb}/book/{slug}/json")
    assert rv.status_code == 200
    data = rv.get_json()

    assert data["title"] == "The Hobbit"
    assert data["item_type"] == "book"
    assert data["slug"] == slug
    assert any(m["k"] == "author" and "Tolkien" in m["v"] for m in data["meta"])


def _fake_resp(payload: dict[str, Any]):
    """Return a plain object that mimics requests.Response just enough."""
    return SimpleNamespace(
        status_code=200,
        ok=True,
        json=lambda: payload,
        raise_for_status=lambda: None,
    )


def test_import_item_json_happy(monkeypatch):
    # fake remote JSON
    remote = {
        "title": "Kafka on the Shore",
        "item_type": "book",
        "slug": "kafka-on-the-shore",
        "uuid": str(uuid.uuid4()),
        "meta": [{"k": "author", "v": "Haruki Murakami", "ord": 1}],
    }
    monkeypatch.setattr(blog.requests, "get", lambda *a, **kw: _fake_resp(remote))

    blk = import_item_json(
        "https://example.com/read/book/kafka-on-the-shore", action="reading"
    )
    assert blk["verb"] == "read"
    assert blk["item_type"] == "book"
    assert blk["title"] == "Kafka on the Shore"
    assert blk["slug"] == "kafka-on-the-shore"
    assert blk["meta"]["author"] == "Haruki Murakami"


def test_import_item_json_verb_mismatch(monkeypatch):
    """reading vs. URL /watch/… → should raise ValueError."""
    monkeypatch.setattr(blog.requests, "get", lambda *a, **kw: _fake_resp({
        "title": "My Video",
        "item_type": "video",
        "slug": "my-video",
        "uuid": str(uuid.uuid4()),
        "meta": [],
    }))
    with pytest.raises(ValueError, match="Verb/action mismatch"):
        import_item_json("https://x.com/watch/video/my-video", action="reading")


def test_import_item_json_appends_suffix(monkeypatch):
    """
    Caller passes …/json?  fine.  
    Caller passes plain item URL?  helper must add '/json' automatically.
    """
    dummy = {
        "title": "Dummy",
        "item_type": "book",
        "slug": "dummy",
        "uuid": str(uuid.uuid4()),
        "meta": [],
    }
    captured = {}

    def _mock_get(url, *a, **kw):
        captured["url"] = url      # so we can assert on it
        return _fake_resp(dummy)

    monkeypatch.setattr(blog.requests, "get", _mock_get)

    import_item_json("https://foo.com/read/book/dummy", action="reading")
    assert captured["url"].endswith("/json")          # suffixed automatically
