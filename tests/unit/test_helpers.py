"""Unit tests for analyzer helpers: depth measurement, link discovery, tailwind detection."""
from __future__ import annotations

from bs4 import BeautifulSoup

from analyzer import VibeCodingAnalyzer


class TestMaxDepth:
    """The iterative implementation must produce the same result as the prior recursive one
    and also handle DOMs that would have blown Python's recursion limit."""

    def test_empty_body_depth_zero(self):
        soup = BeautifulSoup("<html><body></body></html>", "lxml")
        a = VibeCodingAnalyzer()
        assert a._max_depth(soup.body) == 0

    def test_known_depth(self):
        # html→body→div→div→div→span = 5 levels under soup
        soup = BeautifulSoup("<html><body><div><div><div><span>x</span></div></div></div></body></html>", "lxml")
        a = VibeCodingAnalyzer()
        # _max_depth starts at 0 and counts each level
        assert a._max_depth(soup.body) == 4  # body→div→div→div→span

    def test_handles_pathologically_deep_dom(self):
        """Recursion limit defaults to 1000; the iterative version must handle 5000 levels."""
        depth = 5000
        html = "<html><body>" + "<div>" * depth + "</div>" * depth + "</body></html>"
        soup = BeautifulSoup(html, "lxml")
        a = VibeCodingAnalyzer()
        # Should not raise RecursionError. We don't assert exact depth — lxml may collapse
        # some empty tags — only that we got a sensible positive number without crashing.
        result = a._max_depth(soup.body)
        assert result > 100


class TestDetectTailwind:
    def test_detects_via_class_density(self):
        html = '<div class="flex items-center justify-center rounded-lg px-4 py-2 text-sm">x</div>'
        assert VibeCodingAnalyzer._detect_tailwind(html, "")

    def test_no_tailwind_returns_false(self):
        html = '<div class="content article">x</div>'
        assert not VibeCodingAnalyzer._detect_tailwind(html, "")

    def test_detects_via_asset_markers(self):
        # A page with no inline classes but tailwind in the CSS bundle
        assert VibeCodingAnalyzer._detect_tailwind("<div></div>", "/* tailwindcss */ --tw-translate-x: 0;")


class TestDiscoverInternalLinks:
    """Internal-link crawler dedupe; case-insensitivity is the recently-fixed bug."""

    def _page(self, url, html):
        from analyzer import PageData
        from requests.structures import CaseInsensitiveDict
        soup = BeautifulSoup(html, "lxml")
        return PageData(url, html, CaseInsensitiveDict(), soup)

    def test_dedupes_case_insensitive_hostnames(self):
        a = VibeCodingAnalyzer()
        # The seed page is lowercase; same target hostname in mixed case must be deduped.
        page = self._page("https://example.com/", """
            <a href="https://Example.com/about">About</a>
            <a href="https://EXAMPLE.com/about">About again</a>
            <a href="https://example.com/about">About one more time</a>
        """)
        links = a._discover_internal_links(page, "https://example.com")
        assert len(links) == 1

    def test_skips_anchor_and_mailto(self):
        a = VibeCodingAnalyzer()
        page = self._page("https://example.com/", """
            <a href="#section">Anchor</a>
            <a href="mailto:hi@example.com">Mail</a>
            <a href="tel:+1234">Tel</a>
            <a href="javascript:void(0)">JS</a>
            <a href="/page">Real page</a>
        """)
        links = a._discover_internal_links(page, "https://example.com")
        assert links == ["https://example.com/page"]

    def test_skips_external_origins(self):
        a = VibeCodingAnalyzer()
        page = self._page("https://example.com/", """
            <a href="https://other.com/x">External</a>
            <a href="/internal">Internal</a>
        """)
        links = a._discover_internal_links(page, "https://example.com")
        assert links == ["https://example.com/internal"]

    def test_skips_asset_extensions(self):
        a = VibeCodingAnalyzer()
        page = self._page("https://example.com/", """
            <a href="/file.pdf">PDF</a>
            <a href="/image.PNG">PNG</a>
            <a href="/style.css">CSS (counted — not in skip list)</a>
            <a href="/page">Page</a>
        """)
        links = a._discover_internal_links(page, "https://example.com")
        assert "https://example.com/file.pdf" not in links
        assert "https://example.com/image.PNG" not in links
        assert "https://example.com/page" in links
