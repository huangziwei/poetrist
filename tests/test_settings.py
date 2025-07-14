"""
tests/test_settings.py
"""
import re
import secrets

from flask import session

from poetrist.blog import PAGE_DEFAULT, _create_admin, app, get_db, get_setting


def _ensure_admin():
    with app.app_context():
        db = get_db()
        if not db.execute("SELECT 1 FROM user LIMIT 1").fetchone():
            _create_admin(db, username="tester")        # token is thrown away

CSRF = "test-token"

def _login(client):
    _ensure_admin()
    with client.session_transaction() as s:
        s["logged_in"] = True
        s["csrf"] = CSRF

# ────────────────────────────────────────────────────────────────
def test_settings_requires_login(client):
    rv = client.get("/settings")
    assert rv.status_code == 403          # redirect or hard-forbidden

def test_settings_get_ok(client):
    _login(client)
    rv = client.get("/settings")
    assert rv.status_code == 200
    assert b"name=\"csrf\"" in rv.data    # token present in form

def test_settings_csrf_rejects(client):
    _login(client)
    rv = client.post("/settings", data={}, follow_redirects=False)
    assert rv.status_code == 403          # missing token → blocked

def test_settings_update_site_name(client):
    _login(client)
    new_name = "PyTest Blog"
    rv = client.post(
        "/settings",
        data={
                "site_name": new_name,
                "username":  "tester",       # present row’s user name
                "theme_color": "#aabbcc",    # any 6-digit hex
                "page_size":  "20",          # something numeric
                "slug_say":  "say",
                "slug_post": "post",
                "slug_pin":  "pin",
                "csrf": CSRF
            },
            follow_redirects=True,
    )
    assert rv.status_code == 200

    with client.session_transaction():
        pass                               # session still valid
    # verify the DB update
    assert get_db().execute(
        "SELECT value FROM settings WHERE key='site_name'"
    ).fetchone()["value"] == new_name

def test_rotate_token_flow(client):
    """
    POST /settings  action=rotate_token should…
      • redirect (303) to /settings#new-token
      • stash the *plain* token in session once
      • actually replace the hash in the DB
    """
    _login(client)

    # --- remember the current token-hash in the DB
    old_hash = get_db().execute(
        "SELECT token_hash FROM user WHERE id=1"
    ).fetchone()["token_hash"]

    resp = client.post(
        "/settings",
        data={"action": "rotate_token", "csrf": CSRF},
        follow_redirects=False,
    )
    assert resp.status_code == 303
    assert resp.headers["Location"].endswith("#new-token")

    # session got a one-time copy for display ↓
    with client.session_transaction() as s:
        tmp_tok = s.pop("one_time_token", None)      # must exist exactly once
    assert tmp_tok and len(tmp_tok) > 30             # looks like a JWT-ish blob

    # and the DB hash *did* change
    new_hash = get_db().execute(
        "SELECT token_hash FROM user WHERE id=1"
    ).fetchone()["token_hash"]
    assert new_hash != old_hash


def test_invalid_color_rejected(client):
    """
    A colour that is *not* a 3/6-digit hex should:
      • leave the setting unchanged
      • flash an error (we just grep the response-HTML)
    """
    _login(client)
    bad = "magenta"                 # “#pink” is accepted, plain “pink” isn’t
    prev = get_setting("theme_color")

    html = client.post(
        "/settings",
        data={
            "theme_color": bad,
            "username": "tester",
            "page_size": str(PAGE_DEFAULT),
            "site_name": "PyTest",
            "slug_say": "say",
            "slug_post": "post",
            "slug_pin": "pin",
            "csrf": CSRF,
        },
        follow_redirects=True,
    ).data.decode()

    assert "Invalid color" in html
    assert get_setting("theme_color") == prev         # unchanged


def test_page_size_coercion(client):
    """
    page_size is coerced with `max(1,int(x)) if x.isdigit() else DEFAULT`.
    We feed:
        • a digit   → stored verbatim
        • garbage   → falls back to PAGE_DEFAULT
    """
    _login(client)

    client.post(
        "/settings",
        data={
            "username": "tester",
            "csrf": CSRF,
            "site_name": "PyTest",
            "slug_say": "say",
            "slug_post": "post",
            "slug_pin": "pin",
            "theme_color": "#abcdef",
            "page_size": "42",
        },
        follow_redirects=True,
    )
    assert int(get_setting("page_size")) == 42

    client.post(
        "/settings",
        data={
            "site_name": "PyTest",
            "slug_say": "say",
            "slug_post": "post",
            "slug_pin": "pin",
            "theme_color": "#abcdef",
            "page_size": "not-a-number",
            "username": "tester",
            "csrf": CSRF,
        },
        follow_redirects=True,
    )
    assert int(get_setting("page_size")) == PAGE_DEFAULT