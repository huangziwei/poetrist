"""
tests/test_embeds.py
"""
from __future__ import annotations

from poetrist.blog import get_db, kind_to_slug

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
