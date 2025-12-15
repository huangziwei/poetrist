"""
tests/test_traffic.py
"""
from __future__ import annotations

import json
from pathlib import Path

from poetrist import blog


def test_global_rate_limit(monkeypatch, client):
    client.environ_base["REMOTE_ADDR"] = "127.0.0.2"
    blog._global_hits.clear()
    monkeypatch.setitem(blog.app.config, "TRAFFIC_GLOBAL_LIMIT", 3)
    monkeypatch.setitem(blog.app.config, "TRAFFIC_GLOBAL_WINDOW_SEC", 60)

    for _ in range(3):
        assert client.get("/").status_code == 200

    resp = client.get("/")
    assert resp.status_code == 403


def test_rate_limit_auto_blocks_ip(monkeypatch, client):
    client.environ_base["REMOTE_ADDR"] = "127.0.0.3"
    blog._global_hits.clear()
    monkeypatch.setitem(blog.app.config, "TRAFFIC_GLOBAL_LIMIT", 2)
    monkeypatch.setitem(blog.app.config, "TRAFFIC_GLOBAL_WINDOW_SEC", 60)

    assert client.get("/").status_code == 200
    assert client.get("/").status_code == 200

    resp = client.get("/")
    assert resp.status_code == 403

    db = blog.get_db()
    row = db.execute(
        "SELECT ip FROM ip_blocklist WHERE ip=?", ("127.0.0.3",)
    ).fetchone()
    assert row is not None

    resp_again = client.get("/")
    assert resp_again.status_code == 403


def test_traffic_log_includes_host_and_type(monkeypatch, client, tmp_path: Path):
    monkeypatch.setitem(blog.app.config, "TRAFFIC_LOG_DIR", str(tmp_path))
    monkeypatch.setitem(blog.app.config, "TRAFFIC_LOG_ENABLED", True)

    client.get("/", headers={"Host": "poetrist.fly.dev"})
    client.get("/", headers={"Host": "custom.example.com"})

    files = sorted(tmp_path.glob("traffic-*.log"))
    assert files
    events = [
        json.loads(line) for line in files[-1].read_text().splitlines() if line.strip()
    ]
    by_host = {ev.get("host"): ev for ev in events}

    assert by_host["poetrist.fly.dev"]["host_type"] == "fly_dev"
    assert by_host["custom.example.com"]["host_type"] == "custom"


def test_traffic_log_marks_cloudflare(monkeypatch, client, tmp_path: Path):
    monkeypatch.setitem(blog.app.config, "TRAFFIC_LOG_DIR", str(tmp_path))
    monkeypatch.setitem(blog.app.config, "TRAFFIC_LOG_ENABLED", True)

    cf_edge_ip = "173.245.48.10"  # in default Cloudflare ranges
    client.get(
        "/",
        headers={
            "CF-Ray": "abcd1234-ORD",
            "CF-Connecting-IP": "203.0.113.50",
            "X-Forwarded-For": "203.0.113.50, 173.245.48.10",
        },
        environ_overrides={"REMOTE_ADDR": cf_edge_ip},
    )
    client.get("/", environ_overrides={"REMOTE_ADDR": "198.51.100.1"})

    files = sorted(tmp_path.glob("traffic-*.log"))
    assert files
    events = [
        json.loads(line) for line in files[-1].read_text().splitlines() if line.strip()
    ]

    cf_events = [ev for ev in events if ev.get("cf") is True]
    assert cf_events
    cf_event = cf_events[-1]
    assert cf_event.get("cfray") == "abcd1234-ORD"
    assert cf_event.get("cfip") == "203.0.113.50"
    assert cf_event.get("edge") == cf_edge_ip
    assert cf_event.get("cf_src") == "header+edge"
    assert any(ev.get("cf") is False for ev in events)
