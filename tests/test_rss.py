"""
tests/test_rss.py
"""
from __future__ import annotations

import xml.etree.ElementTree as ET

import poetrist.blog as blog
from poetrist.blog import extract_tags, get_db, kind_to_slug, sync_tags


# ───────────────────────── helpers ────────────────────────────────────
def _add_entry(
    *,
    kind: str,
    title: str | None = None,
    body: str = "",
    link: str | None = None,
) -> None:
    """
    Insert one entry directly into the test database **and**
    keep the tag tables in sync (needed for /tags/…/rss).
    """
    db = get_db()
    now_dt = blog.utc_now()
    now_iso = now_dt.isoformat(timespec="seconds")
    slug = now_dt.strftime("%Y%m%d%H%M%S")

    db.execute(
        """
        INSERT INTO entry (title, body, link, created_at, slug, kind)
        VALUES (?,?,?,?,?,?)
        """,
        (title, body, link, now_iso, slug, kind),
    )
    entry_id = db.execute("SELECT last_insert_rowid()").fetchone()[0]
    sync_tags(entry_id, extract_tags(body), db=db)
    db.commit()


def _xml(resp) -> ET.Element:
    """Parse the RSS response body and return the <rss> root element."""
    assert resp.status_code == 200
    assert resp.mimetype == "application/rss+xml"
    return ET.fromstring(resp.get_data(as_text=True))


def _item_titles(root: ET.Element) -> list[str]:
    """Return a list of all <item>/<title> texts in the feed."""
    return [t.text or "" for t in root.findall("./channel/item/title")]


# ───────────────────────── tests ──────────────────────────────────────
def test_global_rss_contains_latest_entries(client):
    title_txt = "Global-RSS-Test"
    _add_entry(kind="say", title=title_txt, body=f"hello #{title_txt.lower()}")

    root = _xml(client.get("/rss"))

    # channel title matches the configured site-name (default is po.etr.ist)
    chan_title = root.findtext("./channel/title")
    assert chan_title and "po.etr.ist" in chan_title

    # our freshly-added entry shows up
    assert any(title_txt in t for t in _item_titles(root))


def test_kind_rss_only_shows_that_kind(client):
    kind_title = "Post-Kind-RSS-Test"
    _add_entry(kind="post", title=kind_title, body="body **md**")

    root = _xml(client.get(f"/{kind_to_slug('post')}/rss"))

    # every <item> in a /posts/rss feed must have either the title we added
    # or originate from another *post* created in earlier tests – never from
    # says or pins
    assert any(kind_title in t for t in _item_titles(root))
    assert all(
        slug_part.startswith(kind_to_slug("post"))
        or "Post" in t  # our own post title
        for t in _item_titles(root)
        for slug_part in [t.lower()]
    )


def test_tags_rss_filters_by_tag(client):
    tag = "rsstag"
    tag_title = "Tag-RSS-Entry"
    _add_entry(kind="say", body=f"This is a #{tag} test titled {tag_title}")

    root = _xml(client.get(f"/tags/{tag}/rss"))

    titles = _item_titles(root)
    assert any(tag_title in t for t in titles), "feed missing tagged entry"

    # ensure that an unrelated entry does **not** creep in
    assert not any("Global-RSS-Test" in t for t in titles)
