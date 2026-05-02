"""Unit tests for the evidence-tier scoring system.

Covers _compute_tiered_score, CategoryResult.add() dedupe, the JSON-safe
evidence summary, and the per-tier caps (definitive uncapped, others bounded).
"""
from __future__ import annotations

import json

import pytest

from analyzer import (
    _UNCAPPED,
    CategoryResult,
    Finding,
    TIER_CAPS,
    Tier,
    VibeCodingAnalyzer,
    _compute_tiered_score,
)


class TestCompute:
    def test_no_findings_returns_zero(self):
        assert _compute_tiered_score([]) == 0

    def test_single_definitive_worth_25(self):
        assert _compute_tiered_score([Finding("v0", "", Tier.DEFINITIVE)]) == 25

    def test_definitive_uncapped_until_overall_ceiling(self):
        # 4 × 25 = 100 → hits the overall 100 ceiling
        findings = [Finding(f"s{i}", "", Tier.DEFINITIVE) for i in range(4)]
        assert _compute_tiered_score(findings) == 100

    def test_overall_score_clamped_to_100(self):
        findings = [Finding(f"s{i}", "", Tier.DEFINITIVE) for i in range(10)]
        assert _compute_tiered_score(findings) == 100

    def test_strong_capped_at_40(self):
        findings = [Finding(f"s{i}", "", Tier.STRONG) for i in range(10)]  # raw 100, capped 40
        assert _compute_tiered_score(findings) == 40

    def test_moderate_capped_at_25(self):
        findings = [Finding(f"s{i}", "", Tier.MODERATE) for i in range(10)]  # raw 40, capped 25
        assert _compute_tiered_score(findings) == 25

    def test_weak_capped_at_10(self):
        findings = [Finding(f"s{i}", "", Tier.WEAK) for i in range(20)]  # raw 40, capped 10
        assert _compute_tiered_score(findings) == 10

    def test_caps_apply_per_tier_independently(self):
        # 1 def (25) + 5 strong (50→40) + 10 moderate (40→25) + 20 weak (40→10) = 100
        findings = (
            [Finding("d", "", Tier.DEFINITIVE)]
            + [Finding(f"s{i}", "", Tier.STRONG) for i in range(5)]
            + [Finding(f"m{i}", "", Tier.MODERATE) for i in range(10)]
            + [Finding(f"w{i}", "", Tier.WEAK) for i in range(20)]
        )
        assert _compute_tiered_score(findings) == 100


class TestTierCaps:
    def test_definitive_is_uncapped_marker(self):
        assert TIER_CAPS[Tier.DEFINITIVE] == _UNCAPPED

    def test_other_tiers_have_finite_caps(self):
        for tier in (Tier.STRONG, Tier.MODERATE, Tier.WEAK):
            assert TIER_CAPS[tier] != _UNCAPPED
            assert TIER_CAPS[tier] > 0


class TestCategoryResult:
    def test_add_dedupes_by_signal_and_tier(self):
        cat = CategoryResult("Test", "🧪")
        assert cat.add(Finding("Replit", "first", Tier.MODERATE)) is True
        assert cat.add(Finding("Replit", "second", Tier.MODERATE)) is False
        assert len(cat.findings) == 1
        assert cat.findings[0].description == "first"

    def test_add_allows_same_signal_different_tier(self):
        cat = CategoryResult("Test", "🧪")
        cat.add(Finding("Replit", "", Tier.MODERATE))
        cat.add(Finding("Replit", "", Tier.DEFINITIVE))
        assert len(cat.findings) == 2

    def test_seen_set_seeded_from_initial_findings(self):
        # Pre-populating findings should also seed the dedup set
        seed = [Finding("X", "", Tier.STRONG)]
        cat = CategoryResult("Test", "🧪", seed)
        assert cat.add(Finding("X", "", Tier.STRONG)) is False

    def test_score_property_uses_tiered_score(self):
        cat = CategoryResult("Test", "🧪")
        cat.add(Finding("X", "", Tier.DEFINITIVE))
        assert cat.score == 25

    def test_to_dict_includes_findings(self):
        cat = CategoryResult("Test", "🧪")
        cat.add(Finding("X", "desc", Tier.STRONG))
        d = cat.to_dict()
        assert d["name"] == "Test"
        assert d["score"] == 10
        assert d["findings"][0]["signal"] == "X"


class TestEvidenceSummary:
    def test_summary_is_json_serializable(self):
        """Definitive cap is float('inf') internally — must surface as JSON null."""
        a = VibeCodingAnalyzer()
        es = a._build_evidence_summary([Finding("x", "", Tier.DEFINITIVE)])
        # Round-trip through JSON to confirm no Infinity sneaks out
        rendered = json.dumps(es)
        parsed = json.loads(rendered)
        assert parsed["definitive"]["cap"] is None
        assert parsed["strong"]["cap"] == 40
        assert parsed["moderate"]["cap"] == 25
        assert parsed["weak"]["cap"] == 10

    def test_capped_points_reflect_cap(self):
        a = VibeCodingAnalyzer()
        # 10 strong findings → raw 100, capped 40
        es = a._build_evidence_summary([Finding(f"s{i}", "", Tier.STRONG) for i in range(10)])
        assert es["strong"]["raw_points"] == 100
        assert es["strong"]["capped_points"] == 40
        assert es["strong"]["count"] == 10
