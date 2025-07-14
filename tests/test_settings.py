"""
tests/test_settings.py
"""
from poetrist.blog import _create_admin, app, get_db


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
