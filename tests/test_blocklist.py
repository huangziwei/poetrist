"""
tests/test_blocklist.py
"""
from __future__ import annotations

import json
from pathlib import Path

from poetrist import blog
from poetrist.blog import app, block_ip_addr, get_db, traffic_snapshot

CSRF = "block-csrf"


def _login(client) -> None:
    with app.app_context():
        db = get_db()
        if not db.execute("SELECT 1 FROM user LIMIT 1").fetchone():
            db.execute(
                "INSERT INTO user (id, username, token_hash) VALUES (1, 'tester', 'hash')"
            )
            db.commit()
    with client.session_transaction() as s:
        s["logged_in"] = True
        s["csrf"] = CSRF


def test_blocked_ip_gets_403(client):
    with app.app_context():
        block_ip_addr("203.0.113.10", reason="test", expires_at=None, db=get_db())

    client.environ_base["REMOTE_ADDR"] = "203.0.113.10"
    resp = client.get("/")
    assert resp.status_code == 403


def test_logged_in_bypasses_block_for_admin_views(client):
    with app.app_context():
        block_ip_addr("203.0.113.11", reason="test", expires_at=None, db=get_db())

    _login(client)
    client.environ_base["REMOTE_ADDR"] = "203.0.113.11"
    resp = client.get("/stats")
    assert resp.status_code == 200


def test_block_and_unblock_via_endpoint(client):
    _login(client)

    resp = client.post(
        "/ip-blocklist",
        data={"ip": "198.51.100.5", "action": "block", "csrf": CSRF},
        follow_redirects=False,
    )
    assert resp.status_code in (302, 303)

    row = get_db().execute(
        "SELECT reason FROM ip_blocklist WHERE ip=?", ("198.51.100.5",)
    ).fetchone()
    assert row

    resp2 = client.post(
        "/ip-blocklist",
        data={"ip": "198.51.100.5", "action": "unblock", "csrf": CSRF},
        follow_redirects=False,
    )
    assert resp2.status_code in (302, 303)
    row2 = get_db().execute(
        "SELECT reason FROM ip_blocklist WHERE ip=?", ("198.51.100.5",)
    ).fetchone()
    assert row2 is None


def test_stats_flags_suspicious_ips(client, tmp_path: Path):
    _login(client)
    app.config.update(
        TRAFFIC_LOG_DIR=str(tmp_path),
        TRAFFIC_LOG_ENABLED=True,
        TRAFFIC_SUSPICIOUS_MIN_HITS=5,
        TRAFFIC_NOTFOUND_SHARE=0.3,
    )

    log_path = tmp_path / f"traffic-{blog.utc_now():%Y%m%d}.log"
    entries = [
        {
            "ts": blog.utc_now().isoformat(),
            "ip": "1.2.3.4",
            "path": "/does-not-exist",
            "m": "GET",
            "st": 404,
            "flags": ["nonexistent_path"],
        }
        for _ in range(6)
    ] + [
        {
            "ts": blog.utc_now().isoformat(),
            "ip": "1.2.3.4",
            "path": "/",
            "m": "GET",
            "st": 200,
            "flags": [],
        }
    ]
    log_path.write_text("\n".join(json.dumps(e) for e in entries) + "\n", encoding="utf-8")

    resp = client.get("/stats?traffic_hours=24")
    html = resp.data.decode()
    assert "Traffic (last" in html
    snap = traffic_snapshot(db=get_db(), hours=24)
    assert any(s["ip"] == "1.2.3.4" for s in snap["suspicious"])
    resp_json = client.get("/stats?format=traffic-json&traffic_hours=24")
    data = resp_json.get_json()
    assert any(ev["ip"] == "1.2.3.4" for ev in data["events"])


def test_blocked_ips_filtered_from_traffic_json(client, tmp_path: Path):
    _login(client)
    app.config.update(
        TRAFFIC_LOG_DIR=str(tmp_path),
        TRAFFIC_LOG_ENABLED=True,
    )
    with app.app_context():
        block_ip_addr("203.0.113.20", reason="test", expires_at=None, db=get_db())

    log_path = tmp_path / f"traffic-{blog.utc_now():%Y%m%d}.log"
    entries = [
        {
            "ts": blog.utc_now().isoformat(),
            "ip": "203.0.113.20",
            "path": "/",
            "m": "GET",
            "st": 200,
            "flags": [],
        },
        {
            "ts": blog.utc_now().isoformat(),
            "ip": "198.51.100.1",
            "path": "/about",
            "m": "GET",
            "st": 200,
            "flags": [],
        },
    ]
    log_path.write_text("\n".join(json.dumps(e) for e in entries) + "\n", encoding="utf-8")

    snap = traffic_snapshot(db=get_db(), hours=24)
    assert snap["total"] == 1
    assert snap["unique_ips"] == 1
    assert all(ev["ip"] != "203.0.113.20" for ev in snap["events"])
    assert any(ev["ip"] == "198.51.100.1" for ev in snap["events"])

    resp_json = client.get("/stats?format=traffic-json&traffic_hours=24")
    assert resp_json.status_code == 200
    data = resp_json.get_json()
    assert data["total"] == 1
    assert all(ev["ip"] != "203.0.113.20" for ev in data["events"])
    assert any(ev["ip"] == "198.51.100.1" for ev in data["events"])


def test_blocklist_page_shows_entries(client):
    _login(client)
    with app.app_context():
        block_ip_addr("198.51.100.10", reason="test", expires_at=None, db=get_db())

    resp = client.get("/blocklist")
    html = resp.data.decode()
    assert resp.status_code == 200
    assert "198.51.100.10" in html
    assert "Blocked IPs" in html

    stats_html = client.get("/stats").data.decode()
    assert "Blocked IPs" not in stats_html
    assert "Block" in html  # action button rendered
