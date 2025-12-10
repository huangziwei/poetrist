"""
tests/test_blocklist_admin_traffic.py
"""
from __future__ import annotations

import json
from pathlib import Path

from poetrist import blog
from poetrist.blog import app, get_db, traffic_snapshot


def _login(client) -> None:
    with app.app_context():
        db = get_db()
        if not db.execute("SELECT 1 FROM user LIMIT 1").fetchone():
            db.execute("INSERT INTO user (id, username, token_hash) VALUES (1,'tester','hash')")
            db.commit()
    with client.session_transaction() as s:
        s["logged_in"] = True
        s["csrf"] = "csrf"


def test_admin_traffic_not_flagged(client, tmp_path: Path):
    _login(client)
    app.config.update(
        TRAFFIC_LOG_DIR=str(tmp_path),
        TRAFFIC_LOG_ENABLED=True,
        TRAFFIC_SUSPICIOUS_MIN_HITS=5,
        TRAFFIC_HIGH_HITS=10,
    )

    log_path = tmp_path / f"traffic-{blog.utc_now():%Y%m%d}.log"
    entries = [
        {
            "ts": blog.utc_now().isoformat(),
            "ip": "2001:db8::1",
            "path": "/stats",
            "m": "GET",
            "st": 200,
            "flags": ["admin_view"],
        }
        for _ in range(15)
    ]
    log_path.write_text("\n".join(json.dumps(e) for e in entries) + "\n", encoding="utf-8")

    snap = traffic_snapshot(db=get_db(), hours=24)
    assert snap["total"] == 0
    assert snap["unique_ips"] == 0
    assert not snap["events"]
    assert not snap["suspicious"]

    resp = client.get("/stats?format=traffic-json&traffic_hours=24")
    assert resp.status_code == 200
    assert not resp.get_json()["events"]
