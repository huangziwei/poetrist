"""
tests/conftest.py
"""
from __future__ import annotations

import datetime as _dt
import itertools
from pathlib import Path
from typing import Generator

import pytest
from flask.testing import FlaskClient
from pytest import MonkeyPatch

# The single-file app lives here:
from poetrist.blog import app, init_db  # noqa: WPS433 (importing from a module)


@pytest.fixture(scope="session")
def _tmp_db_path(tmp_path_factory: pytest.TempPathFactory) -> Path:
    """One temp file for the whole test session (faster than per-test)."""
    db_file = tmp_path_factory.mktemp("data") / "test.sqlite3"
    return db_file


@pytest.fixture(scope="session", autouse=True)
def _configure_app(_tmp_db_path: Path) -> None:
    """
    Configure the Flask app *once* before the first test is collected.
    """
    app.config.update(
        TESTING=True,
        DATABASE=str(_tmp_db_path),
        # Disable CSRF + rate-limit for unit tests – we’ll test them separately
    )
    with app.app_context():
        init_db()


@pytest.fixture
def client() -> Generator[FlaskClient, None, None]:
    """
    Gives each test an isolated application context *and* test client.

    Yields:
        `flask.testing.FlaskClient`
    """
    with app.test_client() as client:
        with app.app_context():
            # Each test starts in a brand-new DB transaction that is rolled back
            yield client


@pytest.fixture(autouse=True, scope="session")
def _fast_slugs():
    """
    Patch poetrist.blog.utc_now for the whole test session so every call
    returns an ever-increasing timestamp.  No need for time.sleep().
    """
    from poetrist import blog  # import here to avoid early import

    counter = itertools.count()         # 0, 1, 2, …

    base = _dt.datetime(2099, 1, 1, tzinfo=_dt.timezone.utc)
    def _fake_now():
        return base + _dt.timedelta(seconds=next(counter))

    mp = MonkeyPatch()
    mp.setattr(blog, "utc_now", _fake_now)

    yield                               # tests run here

    mp.undo()                           # clean up at session end
