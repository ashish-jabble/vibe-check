"""Shared pytest fixtures.

Autouse fixtures reset cross-test state (rate limiter counters, DNS overrides)
so any single test can be run in isolation and produce the same result.
"""
from __future__ import annotations

import pytest
from bs4 import BeautifulSoup
from requests.structures import CaseInsensitiveDict


@pytest.fixture
def client():
    """Flask test client — bypasses the network and rate-limit storage init lag."""
    from app import app
    app.config["TESTING"] = True
    return app.test_client()


@pytest.fixture(autouse=True)
def _reset_limiter():
    """Counters are in-memory; reset before AND after every test so order doesn't matter."""
    from app import limiter
    limiter.reset()
    yield
    limiter.reset()


@pytest.fixture(autouse=True)
def _reset_dns_overrides():
    """The thread-local DNS pin map persists across tests in the same thread; clear it."""
    from analyzer import _dns_overrides
    if hasattr(_dns_overrides, "map"):
        _dns_overrides.map.clear()
    yield
    if hasattr(_dns_overrides, "map"):
        _dns_overrides.map.clear()


@pytest.fixture
def make_page():
    """Build a PageData for detector tests without going through the network."""
    from analyzer import PageData

    def _make(url: str, html: str, headers: dict | None = None):
        soup = BeautifulSoup(html, "lxml")
        return PageData(url, html, CaseInsensitiveDict(headers or {}), soup)

    return _make
