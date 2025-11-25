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


def _latest_project():
    return get_db().execute("SELECT slug, title FROM project ORDER BY id DESC LIMIT 1").fetchone()


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


def test_edit_prefills_project_marker(client):
    _login(client)
    client.post(
        "/posts",
        data={"title": "Edit Me", "body": "~project:delta|Delta\nbody", "csrf": CSRF},
        follow_redirects=True,
    )
    entry = _latest_entry()

    edit_html = client.get(f"/{kind_to_slug(entry['kind'])}/{entry['slug']}/edit").data.decode()
    assert "~project:delta|Delta" in edit_html

    client.post(
        f"/{kind_to_slug(entry['kind'])}/{entry['slug']}/edit",
        data={
            "title": "Edit Me Updated",
            "body": "~project:delta|Delta\nupdated body",
            "slug": entry["slug"],
            "csrf": CSRF,
        },
        follow_redirects=True,
    )
    # still linked
    proj_html = client.get("/projects/delta").data.decode()
    assert "Edit Me Updated" in proj_html


def test_project_edit_updates_slug_and_title(client):
    _login(client)
    client.post(
        "/posts",
        data={"title": "Project Rename", "body": "~project:epsilon|Old Title", "csrf": CSRF},
        follow_redirects=True,
    )
    proj = _latest_project()
    assert proj["slug"] == "epsilon"

    resp = client.post(
        f"/projects/{proj['slug']}/edit",
        data={"title": "New Title", "slug": "epsilon-new", "csrf": CSRF},
        follow_redirects=False,
    )
    assert resp.status_code == 302
    assert resp.headers["Location"].endswith("/projects/epsilon-new")

    page = client.get("/projects/epsilon-new")
    assert page.status_code == 200
    html = page.data.decode()
    assert "New Title" in html
    assert "Old Title" not in html
