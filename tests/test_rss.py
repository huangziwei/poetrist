"""
tests/test_rss.py
"""
from __future__ import annotations

import uuid
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
) -> tuple[str, int]:
    """
    Insert one entry directly into the test database **and**
    keep the tag tables in sync (needed for /tags/…/rss).
    """
    db = get_db()
    now_dt = blog.utc_now()
    now_iso = now_dt.isoformat(timespec="seconds")
    slug = now_dt.strftime("%Y%m%d%H%M%S%f")

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
    return slug, entry_id


def _add_checkin(
    *,
    item_title: str = "Checkin Book",
    item_slug: str | None = None,
    kind: str = "read",
    action: str = "reading",
    progress: str = "42%",
    body: str = "",
) -> tuple[str, int]:
    """Insert an item + one check-in entry linked to it."""
    db = get_db()
    item_slug = item_slug or f"checkin-{uuid.uuid4().hex[:8]}"
    db.execute(
        "INSERT INTO item (uuid, slug, item_type, title) VALUES (?,?,?,?)",
        (str(uuid.uuid4()), item_slug, "book", item_title),
    )
    item_id = db.execute("SELECT last_insert_rowid()").fetchone()[0]

    slug, entry_id = _add_entry(
        kind=kind,
        title=None,
        body=body,
    )

    db.execute(
        "INSERT INTO entry_item (entry_id, item_id, verb, action, progress) "
        "VALUES (?,?,?,?,?)",
        (entry_id, item_id, kind, action, progress),
    )
    db.commit()
    return slug, entry_id


def _xml(resp) -> ET.Element:
    """Parse the RSS response body and return the <rss> root element."""
    assert resp.status_code == 200
    assert resp.mimetype == "application/rss+xml"
    return ET.fromstring(resp.get_data(as_text=True))


def _item_titles(root: ET.Element) -> list[str]:
    """Return a list of all <item>/<title> texts in the feed."""
    return [t.text or "" for t in root.findall("./channel/item/title")]


def _item_by_slug(root: ET.Element, slug: str) -> ET.Element | None:
    """Return the <item> element whose link contains the given slug."""
    for itm in root.findall("./channel/item"):
        link = (itm.findtext("link") or "").strip()
        if slug in link:
            return itm
    return None


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

    # our added post shows up
    assert any(kind_title in t for t in _item_titles(root))

    # every item link should point to the post slug namespace
    links = [lnk.text or "" for lnk in root.findall("./channel/item/link")]
    post_slug = f"/{kind_to_slug('post')}/"
    assert links and all(post_slug in lnk for lnk in links)


def test_tags_rss_filters_by_tag(client):
    tag = "rsstag"
    tag_title = "Tag-RSS-Entry"
    _add_entry(
        kind="say",
        title=tag_title,                              # ← add a proper title
        body=f"This is a #{tag} test titled {tag_title}",
    )
    root = _xml(client.get(f"/tags/{tag}/rss"))

    titles = _item_titles(root)
    assert any(tag_title in t for t in titles), "feed missing tagged entry"

    # ensure that an unrelated entry does **not** creep in
    assert not any("Global-RSS-Test" in t for t in titles)


def test_rss_titles_include_checkin_context(client):
    slug, _ = _add_checkin(body="#logtag progress note")
    root = _xml(client.get(f"/{kind_to_slug('read')}/rss"))

    item = _item_by_slug(root, slug)
    assert item is not None
    title = item.findtext("title") or ""
    assert "Checkin Book" in title
    assert "42%" in title

    cats = [c.text for c in item.findall("category")]
    assert "logtag" in cats


def test_rss_titles_fall_back_to_excerpt_for_says(client):
    slug, _ = _add_entry(kind="say", body="hello rss world without a heading")
    root = _xml(client.get("/rss"))

    item = _item_by_slug(root, slug)
    assert item is not None
    title = item.findtext("title") or ""
    assert title.startswith("Say:")
    assert "hello rss world" in title


def test_rss_image_excerpts_drop_image_urls(client):
    slug, _ = _add_entry(
        kind="say",
        body='![alt text](https://example.com/img.png) some copy',
    )
    root = _xml(client.get("/rss"))

    item = _item_by_slug(root, slug)
    assert item is not None
    title = item.findtext("title") or ""
    assert "img.png" not in title
    assert "alt text" in title


def test_rss_strips_embed_markers_from_titles(client):
    # create the embedded target first
    embed_slug, _ = _add_entry(kind="say", body="embedded target")
    slug, _ = _add_entry(
        kind="say",
        body=f"Lead in sentence @entry:{embed_slug} tail text",
    )
    root = _xml(client.get("/rss"))

    item = _item_by_slug(root, slug)
    assert item is not None
    title = item.findtext("title") or ""
    assert "@entry:" not in title


def test_kind_feed_does_not_prefix_titles(client):
    slug, _ = _add_checkin(kind="read", action="to-read", progress=None)
    root = _xml(client.get(f"/{kind_to_slug('read')}/rss"))

    item = _item_by_slug(root, slug)
    assert item is not None
    title = item.findtext("title") or ""
    assert not title.lower().startswith(f"{kind_to_slug('read')}/")
    assert title.lower().startswith("to-read")
