"""
tests/test_genre_filters.py
"""
from __future__ import annotations

import uuid

import poetrist.blog as blog
from poetrist.blog import get_db


def _add_item(
    *,
    item_type: str = "book",
    title: str,
    meta: dict[str, str] | None = None,
    verb: str = "read",
) -> str:
    """
    Create one item + metadata + a single linked entry so it shows up.
    Returns:
        slug of the created item (lower-cased, dash-separated title).
    """
    db = get_db()
    slug = title.lower().replace(" ", "-")
    uuid_ = str(uuid.uuid4())

    db.execute(
        "INSERT INTO item (uuid, slug, item_type, title) VALUES (?,?,?,?)",
        (uuid_, slug, item_type, title),
    )
    item_id = db.execute("SELECT last_insert_rowid()").fetchone()[0]

    if meta:
        for ord_, (k, v) in enumerate(meta.items(), 1):
            db.execute(
                "INSERT INTO item_meta (item_id,k,v,ord) VALUES (?,?,?,?)",
                (item_id, k, v, ord_),
            )

    now_dt = blog.utc_now()
    ent_slug = now_dt.strftime("%Y%m%d%H%M%S")
    db.execute(
        "INSERT INTO entry (body, created_at, slug, kind) VALUES (?,?,?,?)",
        (f"{verb.title()}ing *{title}*", now_dt.isoformat(timespec="seconds"), ent_slug, verb),
    )
    entry_id = db.execute("SELECT last_insert_rowid()").fetchone()[0]
    db.execute(
        "INSERT INTO entry_item (entry_id,item_id,verb,action,progress) VALUES (?,?,?,?,?)",
        (entry_id, item_id, verb, f"{verb}ing", None),
    )
    db.commit()
    return slug


def test_genre_pills_include_available_tags(client):
    slug_one = _add_item(title=f"Genre One {uuid.uuid4().hex[:6]}", meta={"genre": "Fantasy"})
    slug_two = _add_item(
        title=f"Genre Two {uuid.uuid4().hex[:6]}", meta={"genres": "Mystery / Thriller"}
    )
    slug_plain = _add_item(title=f"Genre Plain {uuid.uuid4().hex[:6]}", meta={})

    html = client.get("/read").data.decode().lower()

    # all three items render in the base list
    for slug in (slug_one, slug_two, slug_plain):
        assert slug in html

    # genre pills include both distinct genres we set
    assert "genre=fantasy" in html
    assert "genre=thriller" in html


def test_filter_items_by_genre_token(client):
    slug_skip = _add_item(title=f"Genre Skip {uuid.uuid4().hex[:6]}", meta={"genre": "Fantasy"})
    slug_thriller = _add_item(
        title=f"Genre Hit {uuid.uuid4().hex[:6]}",
        meta={"genres": "Mystery / Thriller"},
    )
    slug_nogenre = _add_item(title=f"No Genre {uuid.uuid4().hex[:6]}", meta={})

    html = client.get("/read?genre=thriller").data.decode().lower()

    assert slug_thriller in html
    assert slug_skip not in html
    assert slug_nogenre not in html
