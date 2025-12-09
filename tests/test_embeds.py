"""
tests/test_embeds.py
"""
from __future__ import annotations

from uuid import uuid4

from poetrist.blog import get_db, kind_to_slug
from poetrist.blog import utc_now

CSRF = "test-token"


def _login(client) -> None:
    with client.session_transaction() as sess:
        sess["logged_in"] = True
        sess["csrf"] = CSRF


def _latest_entry():
    return (
        get_db()
        .execute("SELECT slug, kind FROM entry ORDER BY id DESC LIMIT 1")
        .fetchone()
    )


def _detail_url(kind: str, slug: str) -> str:
    return f"/{kind_to_slug(kind)}/{slug}"


def _seed_item_with_meta() -> str:
    """Create one item with metadata + a linking entry for embeds."""
    db = get_db()
    now = utc_now().isoformat(timespec="seconds")
    item_slug = f"itm-{uuid4().hex[:8]}"
    entry_slug = f"entry-{uuid4().hex[:8]}"

    db.execute(
        "INSERT INTO item (uuid, slug, item_type, title, rating) VALUES (?,?,?,?,?)",
        (str(uuid4()), item_slug, "book", "Embed Item", 4),
    )
    item_id = db.execute("SELECT last_insert_rowid()").fetchone()[0]

    db.execute(
        "INSERT INTO item_meta (item_id, k, v, ord) VALUES (?,?,?,?)",
        (item_id, "date", f"{now[:4]}-01-01", 1),
    )
    db.execute(
        "INSERT INTO item_meta (item_id, k, v, ord) VALUES (?,?,?,?)",
        (item_id, "author", "Embed Author", 2),
    )

    db.execute(
        "INSERT INTO entry (body, created_at, slug, kind) VALUES (?,?,?,?)",
        ("body", now, entry_slug, "read"),
    )
    entry_id = db.execute("SELECT last_insert_rowid()").fetchone()[0]
    db.execute(
        "INSERT INTO entry_item (entry_id, item_id, verb, action, progress) VALUES (?,?,?,?,?)",
        (entry_id, item_id, "read", "finished", None),
    )
    db.commit()
    return item_slug


def test_embed_full_entry(client):
    _login(client)

    # source entry
    client.post(
        "/posts",
        data={"title": "Source", "body": "hello **embed**", "csrf": CSRF},
        follow_redirects=True,
    )
    src = _latest_entry()

    # entry with embed reference
    client.post(
        "/posts",
        data={"title": "Wrapper", "body": f"See below:\n\n@entry:{src['slug']}", "csrf": CSRF},
        follow_redirects=True,
    )
    dest = _latest_entry()

    resp = client.get(_detail_url(dest["kind"], dest["slug"]))
    assert resp.status_code == 200
    html = resp.data.decode()
    assert 'class="entry-embed' in html
    assert "<strong>embed</strong>" in html
    assert f'href="{_detail_url(src["kind"], src["slug"])}"' in html


def test_embed_item_meta_and_rating(client):
    _login(client)
    item_slug = _seed_item_with_meta()

    client.post(
        "/posts",
        data={"title": "Wrapper", "body": f"@item:{item_slug}", "csrf": CSRF},
        follow_redirects=True,
    )
    dest = _latest_entry()

    resp = client.get(_detail_url(dest["kind"], dest["slug"]))
    assert resp.status_code == 200
    html = resp.data.decode()
    assert "entry-embed--item" in html
    assert "Embed Author" in html
    assert "Embed Item" in html
    assert "★★★★" in html
    assert f'href="/{kind_to_slug("read")}/book/{item_slug}"' in html


def test_item_detail_mentions_embed_backlinks(client):
    _login(client)
    item_slug = _seed_item_with_meta()
    db = get_db()
    now = utc_now().isoformat(timespec="seconds")
    mention_slug = now.replace("-", "").replace(":", "")
    mention_body = f"Pin body\n\n@item:{item_slug}"
    db.execute(
        "INSERT INTO entry (title, body, created_at, slug, kind) VALUES (?,?,?,?,?)",
        ("Wrapper", mention_body, now, mention_slug, "pin"),
    )
    db.commit()

    resp = client.get(f"/read/book/{item_slug}")
    html = resp.data.decode()

    assert "mentioned" in html
    assert "Wrapper" in html
    assert "Pin body" in html
    assert f'href="/{kind_to_slug("pin")}/{mention_slug}"' in html
    # ensure the embed card itself isn't rendered in the timeline row
    assert "entry-embed--item" not in html


def test_item_detail_mentions_link_backlinks(client):
    _login(client)
    item_slug = _seed_item_with_meta()
    db = get_db()
    now = utc_now().isoformat(timespec="seconds")
    mention_slug = f"m-{uuid4().hex[:6]}"
    body = f"Linked item [here](/reading/book/{item_slug})."
    db.execute(
        "INSERT INTO entry (title, body, created_at, slug, kind) VALUES (?,?,?,?,?)",
        ("Linker", body, now, mention_slug, "post"),
    )
    db.commit()

    resp = client.get(f"/read/book/{item_slug}")
    html = resp.data.decode()
    assert "mentioned" in html
    assert "Linker" in html
    assert f'href="/{kind_to_slug("post")}/{mention_slug}"' in html


def test_item_detail_ignores_code_block_mentions(client):
    _login(client)
    item_slug = _seed_item_with_meta()
    db = get_db()
    now = utc_now().isoformat(timespec="seconds")
    tutorial_slug = f"tut-{uuid4().hex[:6]}"
    body = (
        "Example usage for docs:\n\n"
        "```\n"
        f"@item:{item_slug}\n"
        "```\n\n"
        f"Inline `@item:{item_slug}` stays code."
    )
    db.execute(
        "INSERT INTO entry (title, body, created_at, slug, kind) VALUES (?,?,?,?,?)",
        ("Tutorial", body, now, tutorial_slug, "post"),
    )
    db.commit()

    resp = client.get(f"/read/book/{item_slug}")
    html = resp.data.decode()
    assert "Tutorial" not in html
    assert tutorial_slug not in html


def test_embed_section_only(client):
    _login(client)

    body = "# Intro\nIntro text\n\n## Details\nMore details here."
    client.post(
        "/posts",
        data={"title": "Sectioned", "body": body, "csrf": CSRF},
        follow_redirects=True,
    )
    src = _latest_entry()

    client.post(
        "/posts",
        data={"title": "Section embed", "body": f"@entry:{src['slug']}#intro", "csrf": CSRF},
        follow_redirects=True,
    )
    dest = _latest_entry()

    resp = client.get(_detail_url(dest["kind"], dest["slug"]))
    assert resp.status_code == 200
    html = resp.data.decode()
    assert "Intro text" in html
    assert "More details here." not in html


def test_embed_section_stops_at_next_heading(client):
    _login(client)

    body = "# Morning\n\n### Side Quest\nCold shower log\n\n## Links\n- later section"
    client.post(
        "/posts",
        data={"title": "Routine", "body": body, "csrf": CSRF},
        follow_redirects=True,
    )
    src = _latest_entry()

    client.post(
        "/posts",
        data={
            "title": "Section embed",
            "body": f"@entry:{src['slug']}#side-quest",
            "csrf": CSRF,
        },
        follow_redirects=True,
    )
    dest = _latest_entry()

    resp = client.get(_detail_url(dest["kind"], dest["slug"]))
    assert resp.status_code == 200
    html = resp.data.decode()
    assert "Cold shower log" in html
    assert "later section" not in html  # stops before the next heading


def test_embed_accepts_full_url(client):
    _login(client)

    client.post(
        "/",
        data={"body": "origin body", "csrf": CSRF},
        follow_redirects=True,
    )
    src = _latest_entry()

    client.post(
        "/",
        data={"body": f"@entry:http://localhost/says/{src['slug']}", "csrf": CSRF},
        follow_redirects=True,
    )
    dest = _latest_entry()

    resp = client.get(_detail_url(dest["kind"], dest["slug"]))
    assert resp.status_code == 200
    html = resp.data.decode()
    assert 'class="entry-embed' in html
    assert "origin body" in html


def test_embed_self_loop_warns(client):
    _login(client)

    client.post("/", data={"body": "self ref placeholder", "csrf": CSRF}, follow_redirects=True)
    row = _latest_entry()
    db = get_db()
    db.execute("UPDATE entry SET body=? WHERE slug=?", (f"@entry:{row['slug']}", row["slug"]))
    db.commit()

    resp = client.get(_detail_url(row["kind"], row["slug"]))
    assert resp.status_code == 200
    html = resp.data.decode()
    assert "Embed error" in html
    assert "circular" in html.lower()


def test_embed_titleless_entry_shows_no_title_block(client):
    _login(client)
    # create source "say" without title
    client.post("/", data={"body": "just a say", "csrf": CSRF}, follow_redirects=True)
    src = _latest_entry()

    # create another entry embedding it
    client.post("/", data={"body": f"@entry:{src['slug']}", "csrf": CSRF}, follow_redirects=True)
    dest = _latest_entry()

    resp = client.get(_detail_url(dest["kind"], dest["slug"]))
    assert resp.status_code == 200
    html = resp.data.decode()
    assert 'entry-embed__title' not in html
    assert "just a say" in html
