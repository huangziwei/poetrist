"""tests/test_smoke.py"""

import pytest


@pytest.mark.parametrize(
    "path",
    [
        "/",             # index
        "/login",        # login form
        "/rss",          # global RSS
        "/robots.txt",   # meta routes
    ],
)
def test_public_routes_ok(client, path):
    """Each public endpoint should return a *successful* HTTP status."""
    rv = client.get(path)
    assert rv.status_code in {200, 302, 410}


def test_not_found(client):
    """Completely unknown URL → 404 page."""
    rv = client.get("/does/not/exist")
    assert rv.status_code == 404
    assert b"Page not found" in rv.data
