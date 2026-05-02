"""End-to-end integration tests for /api/analyze.

These run a real fetch against example.com and assert on the full response shape.
"""
from __future__ import annotations

import json

import pytest

pytestmark = pytest.mark.integration


def test_analyze_example_com_happy_path(client):
    r = client.post("/api/analyze", json={"url": "https://example.com"})
    assert r.status_code == 200
    data = r.get_json()

    # Top-level shape contract — frontend depends on every one of these keys
    for key in ("url", "overall_score", "verdict", "verdict_emoji",
                "pages_analyzed", "assets_analyzed", "pages_list",
                "evidence_summary", "categories"):
        assert key in data, f"missing top-level key {key!r}"

    assert isinstance(data["overall_score"], int)
    assert 0 <= data["overall_score"] <= 100

    # All 9 categories must be present. Order is set by the frontend's
    # orderedCategories array, not by this dict — Flask alphabetizes JSON
    # keys, so don't pin a specific order here.
    expected = {"ai_platforms", "ui_libraries", "frameworks", "content",
                "code_quality", "deployment", "design_patterns",
                "accessibility", "seo_quality"}
    assert set(data["categories"].keys()) == expected

    # Evidence summary is JSON-clean (no Infinity values)
    json.dumps(data["evidence_summary"])
    assert data["evidence_summary"]["definitive"]["cap"] is None
    assert data["evidence_summary"]["strong"]["cap"] == 40


def test_analyze_recognises_human_crafted_baseline(client):
    """example.com is the canonical 'plain HTML' page — its score should be low."""
    r = client.post("/api/analyze", json={"url": "https://example.com"})
    data = r.get_json()
    assert data["overall_score"] < 50, f"got score {data['overall_score']}"
    assert data["verdict"] in ("Likely Human-Crafted", "Mixed Signals")


def test_url_without_scheme_is_normalised(client):
    # The analyzer prepends https:// when absent
    r = client.post("/api/analyze", json={"url": "example.com"})
    assert r.status_code == 200
    assert r.get_json()["url"] == "https://example.com"
