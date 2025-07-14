"""
tests/test_passkey.py
"""
from __future__ import annotations

import base64
import json
from types import SimpleNamespace
from typing import Any

import pytest

from poetrist import blog
from poetrist.blog import _create_admin, get_db, utc_now

CSRF = "csrf-test-token"


# ───────────────────────── helpers ────────────────────────────────────
def _login(client) -> None:
    with client.session_transaction() as sess:
        sess["logged_in"] = True
        sess["csrf"] = CSRF


def _fake_cred() -> dict[str, Any]:
    raw = b"\x01\x02\x03"

    def b64(data: bytes) -> str:
        return base64.urlsafe_b64encode(data).decode().rstrip("=")

    return {
        "id": b64(raw),
        "rawId": b64(raw),
        "type": "public-key",
        "response": {
            "attestationObject": b64(b"ao"),
            "clientDataJSON": b64(b"cd"),
            "authenticatorData": b64(b"ad"),
            "signature": b64(b"sig"),
            "userHandle": None,
        },
        "clientExtensionResults": {},
    }


# ───────────────────────── fixtures ───────────────────────────────────
@pytest.fixture(autouse=True, scope="session")
def _admin():
    with blog.app.app_context():
        db = get_db()
        if not db.execute("SELECT 1 FROM user LIMIT 1").fetchone():
            _create_admin(db, username="pytest")


# ───────────────────────── tests ──────────────────────────────────────
def test_register_and_login_flow(client, monkeypatch):
    _login(client)

    cred = _fake_cred()

    # stub-out the heavy WebAuthn crypto calls
    monkeypatch.setattr(
        blog,
        "verify_registration_response",
        lambda *a, **kw: SimpleNamespace(credential_public_key=b"pk", sign_count=1),
    )
    monkeypatch.setattr(
        blog,
        "verify_authentication_response",
        lambda *a, **kw: SimpleNamespace(new_sign_count=2),
    )

    # -- BEGIN register -------------------------------------------------
    reg_resp = client.get("/webauthn/begin_register")
    assert reg_resp.status_code == 200
    reg_opt = json.loads(reg_resp.get_data(as_text=True))
    assert reg_opt["challenge"]  # sanity

    # -- COMPLETE register ---------------------------------------------
    headers = {"Content-Type": "application/json", "X-CSRFToken": CSRF}
    rv = client.post(
        "/webauthn/complete_register", data=json.dumps(cred), headers=headers
    )
    assert rv.status_code == 200 and rv.get_json()["ok"]
    assert get_db().execute("SELECT COUNT(*) AS c FROM passkey").fetchone()["c"] == 1

    client.get("/logout")  # ensure we are logged out

    # -- BEGIN login ----------------------------------------------------
    log_opt = json.loads(
        client.get("/webauthn/begin_login").get_data(as_text=True)
    )
    allowed = {c["id"] for c in log_opt["allowCredentials"]}
    assert cred["id"] in allowed

    # -- COMPLETE login -------------------------------------------------
    rv2 = client.post(
        "/webauthn/complete_login", data=json.dumps(cred), headers=headers
    )
    assert rv2.status_code == 200 and rv2.get_json()["ok"]
    with client.session_transaction() as sess:
        assert sess.get("logged_in") is True


def test_rename_and_delete_passkey(client):
    _login(client)

    db = get_db()
    if not db.execute("SELECT 1 FROM passkey LIMIT 1").fetchone():
        db.execute(
            """
            INSERT INTO passkey
            (user_id, cred_id, pub_key, sign_count, nickname, created_at)
            VALUES (1, ?, ?, 0, 'Key-1', ?)
            """,
            (
                b"\x01\x02\x03",
                b"pk",
                utc_now().isoformat(timespec="seconds"),
            ),
        )
        db.commit()

    pkid = db.execute("SELECT id FROM passkey LIMIT 1").fetchone()["id"]

    headers = {"Content-Type": "application/json", "X-CSRFToken": CSRF}

    # rename ------------------------------------------------------------
    rv = client.post(
        f"/webauthn/rename/{pkid}",
        data=json.dumps({"nickname": "Renamed"}),
        headers=headers,
    )
    assert rv.status_code == 200 and rv.get_json()["ok"]
    assert (
        db.execute("SELECT nickname FROM passkey WHERE id=?", (pkid,)).fetchone()[
            "nickname"
        ]
        == "Renamed"
    )

    # delete ------------------------------------------------------------
    del_resp = client.post(
        f"/webauthn/delete/{pkid}", data={"csrf": CSRF}, follow_redirects=False
    )
    assert del_resp.status_code == 303
    assert not db.execute("SELECT 1 FROM passkey WHERE id=?", (pkid,)).fetchone()
