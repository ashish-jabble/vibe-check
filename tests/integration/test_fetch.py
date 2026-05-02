"""Integration tests that exercise _safe_get against the live internet.

Marked @pytest.mark.integration so they can be skipped offline:
    pytest -m "not integration"
"""
from __future__ import annotations

import pytest

from analyzer import REQUEST_HEADERS, UnsafeURLError, _safe_get

pytestmark = pytest.mark.integration


def test_fetches_public_url():
    r = _safe_get("https://example.com", headers=REQUEST_HEADERS, timeout=15)
    assert r.status_code == 200
    body = r.content.lower()
    assert b"<html" in body or b"<!doctype" in body


def test_https_round_trip_with_pinned_dns():
    """Cert verification must succeed even though connect() goes to a pinned IP.
    If SNI/Host/cert handling were broken, requests would raise SSLError here."""
    r = _safe_get("https://www.google.com", headers=REQUEST_HEADERS, timeout=15)
    assert r.status_code == 200


def test_body_truncates_at_max_bytes():
    r = _safe_get("https://example.com", headers=REQUEST_HEADERS, timeout=15, max_bytes=128)
    assert len(r.content) <= 128


def test_brotli_is_decoded_to_real_html():
    """Sites that prefer brotli used to return compressed bytes; the fix dropped
    'br' from Accept-Encoding so requests/urllib3 only sees gzip/deflate."""
    r = _safe_get("https://vercel.com", headers=REQUEST_HEADERS, timeout=15)
    assert r.status_code == 200
    body = r.content.lower()
    # Decoded HTML — should contain a real tag, not compressed garbage
    assert b"<html" in body or b"<!doctype" in body
    # And it should be substantial — vercel.com homepage is ~600 KB decoded
    assert len(r.content) > 50_000, f"only got {len(r.content)} bytes"


def test_unsafe_url_raises_before_any_request():
    with pytest.raises(UnsafeURLError):
        _safe_get("http://127.0.0.1", headers=REQUEST_HEADERS, timeout=5)
