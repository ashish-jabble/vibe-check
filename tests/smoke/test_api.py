"""Smoke tests for the Flask API.

Exercise every endpoint contract via the Flask test client — no outbound HTTP,
no real DNS. Everything here should run in well under a second.
"""
from __future__ import annotations


class TestIndex:
    def test_renders_template(self, client):
        r = client.get("/")
        assert r.status_code == 200
        assert b"VibeCheck" in r.data


class TestAnalyzeBadInputs:
    def test_empty_body(self, client):
        r = client.post("/api/analyze", data="", content_type="application/json")
        assert r.status_code == 400
        assert "Please provide a URL" in r.get_json()["error"]

    def test_invalid_json(self, client):
        r = client.post("/api/analyze", data="not-json", content_type="application/json")
        assert r.status_code == 400

    def test_missing_url_field(self, client):
        r = client.post("/api/analyze", json={})
        assert r.status_code == 400

    def test_null_url_field(self, client):
        # Used to AttributeError before silent JSON parsing was added
        r = client.post("/api/analyze", json={"url": None})
        assert r.status_code == 400

    def test_whitespace_only_url(self, client):
        r = client.post("/api/analyze", json={"url": "   "})
        assert r.status_code == 400

    def test_wrong_content_type(self, client):
        r = client.post("/api/analyze", data="x", content_type="text/plain")
        assert r.status_code == 400


class TestAnalyzeSecurityBoundaries:
    def test_oversized_body_returns_413(self, client):
        big = "x" * (17 * 1024)  # > MAX_CONTENT_LENGTH (16 KB)
        body = '{"url":"' + big + '"}'
        r = client.post("/api/analyze", data=body, content_type="application/json")
        assert r.status_code == 413

    def test_localhost_rejected(self, client):
        r = client.post("/api/analyze", json={"url": "http://localhost"})
        assert r.status_code == 400
        assert "not allowed" in r.get_json()["error"]

    def test_metadata_service_rejected(self, client):
        r = client.post("/api/analyze", json={"url": "http://169.254.169.254/latest/meta-data/"})
        assert r.status_code == 400
        assert "not allowed" in r.get_json()["error"]

    def test_private_ipv4_rejected(self, client):
        r = client.post("/api/analyze", json={"url": "http://10.0.0.1"})
        assert r.status_code == 400

    def test_ipv6_loopback_rejected(self, client):
        r = client.post("/api/analyze", json={"url": "http://[::1]/"})
        assert r.status_code == 400

    def test_non_http_scheme_rejected(self, client):
        r = client.post("/api/analyze", json={"url": "ftp://example.com"})
        assert r.status_code == 400


class TestRateLimit:
    def test_per_minute_limit_fires(self, client):
        # /api/analyze has "10 per minute". The 11th cheap-rejected request must 429.
        codes = [
            client.post("/api/analyze", json={"url": "http://localhost"}).status_code
            for _ in range(13)
        ]
        assert codes.count(400) == 10
        assert codes.count(429) == 3

    def test_429_has_clean_json(self, client):
        for _ in range(11):
            r = client.post("/api/analyze", json={"url": "http://localhost"})
        assert r.status_code == 429
        assert r.is_json
        assert "Rate limit" in r.get_json()["error"]

    def test_index_is_exempt_from_rate_limit(self, client):
        # 30 GETs should all succeed even though /api/analyze would 429 at 11
        for _ in range(30):
            r = client.get("/")
            assert r.status_code == 200
