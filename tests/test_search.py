"""
tests/test_search.py
"""
from __future__ import annotations

import re
import uuid

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

def _add_item(
    *,
    item_type: str = "book",
    title: str,
    meta: dict[str, str] | None = None,
    verb: str = "read",
) -> str:
    """
    • create one `item` + some `item_meta`
    • add a single “check-in” entry so the item actually shows up
      in the ranked list (the query orders by #check-ins).
    Returns the item’s slug so tests can look for it in the HTML.
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

    # one tiny entry that links to the item
    now_dt = blog.utc_now()
    ent_slug = now_dt.strftime("%Y%m%d%H%M%S")
    db.execute(
        "INSERT INTO entry (body, created_at, slug, kind) VALUES (?,?,?,?)",
        (f"{verb.title()}ing *{title}*", now_dt.isoformat(timespec='seconds'), ent_slug, verb),
    )
    entry_id = db.execute("SELECT last_insert_rowid()").fetchone()[0]
    db.execute(
        "INSERT INTO entry_item (entry_id,item_id,verb,action,progress) "
        "VALUES (?,?,?,?,?)",
        (entry_id, item_id, verb, f"{verb}ing", None),
    )
    db.commit()
    return slug


def _item_slugs(html: str) -> list[str]:
    """
    Extract every `/verb/<type>/<slug>` occurrence from the item-search page.
    """
    return re.findall(r'/[a-z]+/[^/]+/([a-z0-9_-]+)"', html, flags=re.I)


# ───────────────────────── actual tests ────────────────────────────────
def test_item_search_by_title(client):
    """
    `book:"Trial"` should match the item whose *title* contains “Trial”.
    """
    slug = _add_item(item_type="book", title="The Trial", meta={"author": "Franz Kafka"})

    rv = client.get('/search?q=book:"Trial"')
    assert rv.status_code == 200
    html = rv.data.decode()

    assert slug in _item_slugs(html)
    assert "The Trial" in html


def test_item_search_by_specific_field(client):
    """
    `book:author:kafka` should hit items where meta.author LIKE "%kafka%".
    """
    slug_ok = _add_item(
        item_type="book",
        title="Metamorphosis",
        meta={"author": "Franz Kafka"},
    )
    _add_item(item_type="book", title="The Iliad", meta={"author": "Homer"})  # distractor

    html = client.get("/search?q=book:author:kafka").data.decode()

    assert slug_ok in _item_slugs(html)
    assert "Metamorphosis" in html
    # ensure the Iliad is NOT in the result set
    assert "iliad" not in html.lower()


def test_item_search_all_types(client):
    slug_book = _add_item(
        item_type="book",
        title="Shared Story",
        meta={"author": "Shared Author"},
    )
    slug_anime = _add_item(
        item_type="anime",
        title="Shared Saga",
        meta={"author": "Shared Author"},
    )
    slug_other = _add_item(
        item_type="book",
        title="Other Story",
        meta={"author": "Other Author"},
    )

    html = client.get("/search", query_string={"q": 'all:author:"Shared Author"'}).data.decode()
    slugs = _item_slugs(html)

    assert slug_book in slugs
    assert slug_anime in slugs
    assert slug_other not in slugs


def test_item_search_allows_multiword_type(client):
    slug = _add_item(
        item_type="short story",
        title="Mystery Tale",
        meta={"author": "Anthony Abbot"},
    )

    html = client.get("/search", query_string={"q": 'short story:author:"Anthony Abbot"'}).data.decode()

    assert slug in _item_slugs(html)
    assert "Mystery Tale" in html
