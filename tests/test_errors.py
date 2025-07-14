"""
tests/test_errors.py
"""
from __future__ import annotations

from typing import Iterable

from poetrist.blog import app


# ───────────────────────── helpers ──────────────────────────────────
def _assert_410(client, path: str, *, methods: Iterable[str] = ("GET",)) -> None:
    """
    Helper: request *path* with every verb in *methods* and expect a 410.
    """
    for m in methods:
        resp = client.open(path, method=m)
        assert resp.status_code == 410
        # spec says body MAY be empty – we enforce the implementation detail:
        assert resp.data == b""


# ─────────────────────────■  tests  ■────────────────────────────────

def test_gone_routes(client):
    """
    The “ActivityPub / Mastodon discovery” endpoints are deliberately
    disabled – every variant must return **410 Gone**.
    """
    paths = [
        "/.well-known", "/.well-known/webfinger",
        "/users/alice",
        "/nodeinfo", "/nodeinfo/2.0",
        "/api/nodeinfo", "/api/nodeinfo/2.1",
    ]
    for p in paths:
        _assert_410(client, p)

    # /inbox is registered for both GET & POST
    _assert_410(client, "/inbox", methods=("GET", "POST"))


def test_404_custom_page(client):
    """
    Any unknown URL yields the themed “Page not found” template.
    """
    resp = client.get("/this/route/does/not/exist")
    assert resp.status_code == 404
    # sanity-check that we really rendered *our* template, not Werkzeug’s
    assert b"Page not found" in resp.data
    # site title appears in the heading
    assert b"po.etr.ist" in resp.data


def test_500_handler_renders_friendly_page(client, monkeypatch):
    """
    Temporarily replace ``index`` with a view that crashes, but disable
    exception propagation so the global 500-handler can render the page.
    """
    def _boom():
        raise RuntimeError("kaboom!")

    # ➊ monkey-patch the failing view
    monkeypatch.setitem(app.view_functions, "index", _boom)

    # ➋ turn *off* propagation just for this test
    monkeypatch.setitem(app.config, "PROPAGATE_EXCEPTIONS", False)

    resp = client.get("/")                 # handled by our 500-handler
    assert resp.status_code == 500
    assert b"Internal Server Error" in resp.data
