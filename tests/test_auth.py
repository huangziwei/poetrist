"""
tests/test_auth.py
"""
from __future__ import annotations

import itertools
import time
from contextlib import contextmanager
from typing import Iterator

from flask.testing import FlaskClient

from poetrist.blog import (
    _create_admin,
    _rotate_token,
    app,
    get_db,
    signer,
    utc_now,
)


# ───────────────────────── helpers ────────────────────────────────────
def _fresh_token() -> str:
    """Return a valid one-time login token, creating the admin row if needed."""
    with app.app_context():
        db = get_db()
        if not db.execute("SELECT 1 FROM user LIMIT 1").fetchone():
            return _create_admin(db, username="tester")
        return _rotate_token(db)

_ip_counter = itertools.count(1)
@contextmanager
def _new_client() -> Iterator[FlaskClient]:
    """
    Yield a brand-new Flask test-client whose REMOTE_ADDR is unique
    for every call, so the rate-limit (keyed by IP) never bleeds
    between tests unless we stay inside the same `with`-block.
    """
    ip = f"127.0.0.{next(_ip_counter)}"
    with app.test_client() as c, app.app_context():
        c.environ_base["REMOTE_ADDR"] = ip
        yield c

def _login(client, token: str, follow=True):
    """POST /login with the given token and return the response."""
    return client.post(
        "/login",
        data={"token": token},
        follow_redirects=follow,
    )


# ───────────────────────── tests ──────────────────────────────────────
def test_successful_login(client):
    token = _fresh_token()
    rv = _login(client, token)
    assert rv.status_code == 200
    with client.session_transaction() as sess:
        assert sess["logged_in"] is True



def test_token_expired(monkeypatch):
    tok = _fresh_token()

    # jump 70 s into the future (signer default max_age = 60 s)
    monkeypatch.setattr(time, "time", lambda: int(utc_now().timestamp()) + 70)

    with _new_client() as c:
        rv = _login(c, tok, follow=False)
        assert rv.status_code == 200
        with c.session_transaction() as sess:
            assert "logged_in" not in sess

def test_token_forged():
    bad = signer.sign("evil-payload").decode()[:-1] + "x"   # break the sig

    with _new_client() as c:
        rv = _login(c, bad, follow=False)
        assert rv.status_code == 200
        with c.session_transaction() as sess:
            assert "logged_in" not in sess

def test_token_is_burned_after_login():
    tok = _fresh_token()

    # first client logs in           → OK
    with _new_client() as c1:
        assert _login(c1, tok).status_code == 200

    # second client re-uses same tok → rejected (back on login page)
    with _new_client() as c2:
        rv2 = _login(c2, tok, follow=False)
        assert rv2.status_code == 200
        with c2.session_transaction() as sess:
            assert "logged_in" not in sess


def test_rotate_token_invalidates_old_one():
    old = _fresh_token()         # implied rotation / creation
    new = _fresh_token()         # explicit rotation

    # old no longer works
    with _new_client() as c:
        rv = _login(c, old, follow=False)
        assert rv.status_code == 200
        with c.session_transaction() as sess:
            assert "logged_in" not in sess

    # new works
    with _new_client() as c:
        rv = _login(c, new)
        with c.session_transaction() as sess:
            assert sess.get("logged_in") is True

def test_login_rate_limit(monkeypatch):
    forged = signer.sign("nope").decode()[:-1] + "x"

    # freeze time so every call lands within the same 60 s window
    now = int(utc_now().timestamp())
    monkeypatch.setattr(time, "time", lambda: now)

    with _new_client() as c:
        # 5 bogus attempts are allowed
        for _ in range(5):
            assert _login(c, forged, follow=False).status_code == 200

        # 6th → 429 Too Many Requests
        resp = _login(c, forged, follow=False)
        assert resp.status_code == 429
        assert b"Too many requests" in resp.data

