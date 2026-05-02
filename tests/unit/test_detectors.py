"""Unit tests for the detector category methods.

Each test feeds canned HTML through a single _check_* method and asserts on the
findings emitted. No network — we build PageData directly from strings.
"""
from __future__ import annotations

from analyzer import Tier, VibeCodingAnalyzer


class TestSEO:
    def test_flags_missing_meta_description(self, make_page):
        page = make_page("https://x.com/", "<html><head><title>X</title></head><body></body></html>")
        cat = VibeCodingAnalyzer()._check_seo([page])
        assert any(f.signal == "No Meta Description" for f in cat.findings)

    def test_flags_missing_title(self, make_page):
        page = make_page("https://x.com/", "<html><head></head><body></body></html>")
        cat = VibeCodingAnalyzer()._check_seo([page])
        assert any(f.signal == "No Title Tag" for f in cat.findings)

    def test_flags_generic_title(self, make_page):
        html = "<html><head><title>My App</title></head><body></body></html>"
        page = make_page("https://x.com/", html)
        cat = VibeCodingAnalyzer()._check_seo([page])
        assert any(f.signal == "Generic Title" for f in cat.findings)

    def test_does_not_flag_real_title(self, make_page):
        # The bug we fixed — "My Apparel Co." should NOT trigger Generic Title
        html = "<html><head><title>My Apparel Co.</title></head><body></body></html>"
        page = make_page("https://x.com/", html)
        cat = VibeCodingAnalyzer()._check_seo([page])
        assert not any(f.signal == "Generic Title" for f in cat.findings)

    def test_flags_missing_lang_attribute(self, make_page):
        html = "<html><head><title>OK</title></head><body></body></html>"
        page = make_page("https://x.com/", html)
        cat = VibeCodingAnalyzer()._check_seo([page])
        assert any(f.signal == "No Lang Attribute" for f in cat.findings)

    def test_no_findings_for_well_formed_page(self, make_page):
        html = """
        <html lang="en">
          <head>
            <title>Acme — payment infrastructure for the internet</title>
            <meta name="description" content="Acme processes payments for millions of businesses.">
            <meta property="og:title" content="Acme">
            <link rel="icon" href="/favicon.ico">
          </head><body></body>
        </html>
        """
        page = make_page("https://acme.com/", html)
        cat = VibeCodingAnalyzer()._check_seo([page])
        assert cat.findings == []


class TestAccessibility:
    def test_flags_missing_alt_when_majority_missing(self, make_page):
        html = """
        <html><body>
          <img src="/a.jpg">
          <img src="/b.jpg">
          <img src="/c.jpg">
          <img src="/d.jpg" alt="d">
        </body></html>
        """
        page = make_page("https://x.com/", html)
        cat = VibeCodingAnalyzer()._check_accessibility([page])
        # 3/4 missing → 75% → MODERATE finding
        assert any(f.signal == "Missing Alt Text" and f.tier == Tier.MODERATE
                   for f in cat.findings)

    def test_flags_multiple_h1(self, make_page):
        html = "<html><body><h1>One</h1><h1>Two</h1></body></html>"
        page = make_page("https://x.com/", html)
        cat = VibeCodingAnalyzer()._check_accessibility([page])
        assert any(f.signal == "Multiple H1s" for f in cat.findings)

    def test_flags_no_landmarks(self, make_page):
        html = "<html><body><div>content</div></body></html>"
        page = make_page("https://x.com/", html)
        cat = VibeCodingAnalyzer()._check_accessibility([page])
        assert any(f.signal == "No ARIA/Landmarks" for f in cat.findings)


class TestContent:
    def test_flags_lorem_ipsum(self, make_page):
        html = "<html><body><p>Lorem ipsum dolor sit amet</p></body></html>"
        page = make_page("https://x.com/", html)
        cat = VibeCodingAnalyzer()._check_content([page])
        assert any(f.signal == "Lorem Ipsum" for f in cat.findings)

    def test_flags_placeholder_text(self, make_page):
        html = "<html><body><p>Your Company Name here</p></body></html>"
        page = make_page("https://x.com/", html)
        cat = VibeCodingAnalyzer()._check_content([page])
        assert any(f.signal == "Placeholder" for f in cat.findings)

    def test_detects_lazy_loaded_stock_image(self, make_page):
        # The fix we shipped: stock-image detection now looks at data-srcset/data-original/srcset
        html = '<html><body><img data-srcset="https://images.unsplash.com/foo.jpg"></body></html>'
        page = make_page("https://x.com/", html)
        cat = VibeCodingAnalyzer()._check_content([page])
        assert any(f.signal == "Stock Images" for f in cat.findings)


class TestAIPlatformsDedup:
    def test_meta_generator_does_not_double_count_across_pages(self, make_page):
        # Both pages have the same generator tag — should produce ONE finding, not two.
        html = '<html><head><meta name="generator" content="Bolt 1.0"></head></html>'
        p1 = make_page("https://x.com/a", html)
        p2 = make_page("https://x.com/b", html)
        cat = VibeCodingAnalyzer()._check_ai_platforms([p1, p2], "")
        bolt_findings = [f for f in cat.findings if f.signal == "bolt"]
        assert len(bolt_findings) == 1, f"got {len(bolt_findings)} findings"

    def test_replit_does_not_double_count(self, make_page):
        # Replit netloc + 'replit' in source — the dedup must keep one finding.
        html = '<html><body>built with replit</body></html>'
        page = make_page("https://something.replit.dev/", html)
        cat = VibeCodingAnalyzer()._check_ai_platforms([page], "")
        replit_findings = [f for f in cat.findings if f.signal == "Replit"]
        assert len(replit_findings) == 1
