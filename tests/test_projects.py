"""
tests/test_projects.py
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
        .execute("SELECT slug, kind, title FROM entry ORDER BY id DESC LIMIT 1")
        .fetchone()
    )


def test_project_creation_and_pill(client):
    _login(client)
    body = "~project:alpha|Alpha Project\nBody text"
    client.post(
        "/posts",
        data={"title": "Project Post", "body": body, "csrf": CSRF},
        follow_redirects=True,
    )

    db = get_db()
    proj = db.execute("SELECT slug, title FROM project WHERE slug='alpha'").fetchone()
    assert proj and proj["title"] == "Alpha Project"

    entry = _latest_entry()
    resp = client.get(f"/{kind_to_slug(entry['kind'])}/{entry['slug']}")
    html = resp.data.decode()
    assert "Alpha Project" in html
    assert "~project" not in html


def test_posts_index_filters_by_project(client):
    _login(client)
    client.post(
        "/posts",
        data={"title": "Alpha One", "body": "~project:alpha|Alpha\nbody", "csrf": CSRF},
        follow_redirects=True,
    )
    client.post(
        "/posts",
        data={
            "title": "Alpha Two",
            "body": "~project:alpha|Alpha\n~project:beta|Beta\nbody",
            "csrf": CSRF,
        },
        follow_redirects=True,
    )
    client.post(
        "/posts",
        data={"title": "Beta Only", "body": "~project:beta|Beta\nbody", "csrf": CSRF},
        follow_redirects=True,
    )

    html = client.get("/posts?project=alpha").data.decode()
    assert "Alpha One" in html and "Alpha Two" in html
    assert "Beta Only" not in html
    assert "Alpha" in html and "Beta" in html


def test_project_page_sorting(client):
    _login(client)
    client.post(
        "/posts",
        data={"title": "Old Post", "body": "~project:gamma|Gamma\nold body", "csrf": CSRF},
        follow_redirects=True,
    )
    client.post(
        "/posts",
        data={"title": "New Post", "body": "~project:gamma|Gamma\nnew body", "csrf": CSRF},
        follow_redirects=True,
    )

    html_old = client.get("/projects/gamma").data.decode()
    assert html_old.index("Old Post") < html_old.index("New Post")

    html_new = client.get("/projects/gamma?sort=new").data.decode()
    assert html_new.index("New Post") < html_new.index("Old Post")
