"""
tests/test_import_export.py
"""
from __future__ import annotations

import json
import uuid
from typing import Any

import pytest

import poetrist.blog as blog
from poetrist.blog import get_db, import_item_json

# ───────────────────────── Flask client ────────────────────────────
# The pytest-flask plugin supplies a `client` fixture automatically
# (declared in conftest.py of poetrist’s test suite).

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
    can build  /<verb>/<item_type>/<slug>/json  URLs easily.
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
    return "read", slug            # we expose it under the “read” verb


class _FakeResp:
    """
    Minimal Response stub that supports the context-manager protocol
    and the handful of attributes / methods accessed by import_item_json().
    """

    def __init__(self, payload: dict[str, Any], *, ctype: str = "application/json"):
        self._body = json.dumps(payload).encode()
        self.headers = {"Content-Type": ctype}
        self.encoding = "utf-8"

    # --- context-manager --------------------------------------------------
    def __enter__(self):          # with requests.get(...) as resp:
        return self

    def __exit__(self, exc_type, exc, tb):
        return False              # don’t swallow exceptions

    # --- tiny requests.Response API surface ------------------------------
    def raise_for_status(self):   # import_item_json() calls this
        pass

    def iter_content(self, chunk_size: int = 8192):
        for i in range(0, len(self._body), chunk_size):
            yield self._body[i : i + chunk_size]


# ───────────────────────── tests ───────────────────────────────────
def test_export_json_endpoint(client):
    verb, slug = _create_item()

    rv = client.get(f"/{verb}/book/{slug}/json")
    assert rv.status_code == 200
    data = rv.get_json(force=True)

    assert data["title"] == "The Hobbit"
    assert data["item_type"] == "book"
    assert data["slug"] == slug
    assert any(m["k"] == "author" and "Tolkien" in m["v"] for m in data["meta"])


def test_import_item_json_happy(monkeypatch):
    remote = {
        "title": "Kafka on the Shore",
        "item_type": "book",
        "slug": "kafka-on-the-shore",
        "uuid": str(uuid.uuid4()),
        "meta": [{"k": "author", "v": "Haruki Murakami", "ord": 1}],
    }

    # patch requests.get to return our stub response
    monkeypatch.setattr(
        blog.requests,
        "get",
        lambda *a, **kw: _FakeResp(remote),
    )

    blk = import_item_json(
        "https://example.com/read/book/kafka-on-the-shore", action="reading"
    )
    assert blk["verb"] == "read"
    assert blk["item_type"] == "book"
    assert blk["title"] == "Kafka on the Shore"
    assert blk["slug"] == "kafka-on-the-shore"
    assert blk["meta"]["author"] == "Haruki Murakami"


def test_import_item_json_verb_mismatch(monkeypatch):
    monkeypatch.setattr(
        blog.requests,
        "get",
        lambda *a, **kw: _FakeResp(
            {
                "title": "My Video",
                "item_type": "video",
                "slug": "my-video",
                "uuid": str(uuid.uuid4()),
                "meta": [],
            }
        ),
    )
    with pytest.raises(ValueError, match="Verb/action mismatch"):
        import_item_json("https://x.com/watch/video/my-video", action="reading")


def test_import_item_json_appends_suffix(monkeypatch):
    dummy = {
        "title": "Dummy",
        "item_type": "book",
        "slug": "dummy",
        "uuid": str(uuid.uuid4()),
        "meta": [],
    }
    captured: dict[str, str] = {}

    def _mock_get(url, *a, **kw):
        captured["url"] = url
        return _FakeResp(dummy)

    monkeypatch.setattr(blog.requests, "get", _mock_get)

    import_item_json("https://foo.com/read/book/dummy", action="reading")
    assert captured["url"].endswith("/json")   # helper auto-appended suffix
