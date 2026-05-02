"""Unit tests for module-level pattern constants and regexes."""
from __future__ import annotations

import pytest

from analyzer import GENERIC_TITLE_RE


class TestGenericTitleRegex:
    @pytest.mark.parametrize("title", [
        "Home",
        "home",
        "HOME",
        "Welcome",
        "Welcome to our site",
        "My App",
        "My App - Login",
        "My Site",
        "My Website",
        "Untitled",
        "Untitled Document",
        "Create Next App",
        "Vite App",
        "Vite + React",
    ])
    def test_matches_generic_titles(self, title):
        assert GENERIC_TITLE_RE.match(title) is not None

    @pytest.mark.parametrize("title", [
        # The bug we fixed: "My Apparel Co." used to match "my app" via startswith
        "My Apparel Co.",
        "My Application Studio",
        "My Apple Store",
        # "welcoming" / "homestead" share the prefix but extend through the word boundary
        "Welcoming Committee",
        "Homestead Realtors",
        # Real product titles
        "Stripe — Online payment processing",
        "Vercel: Build and deploy",
        "GitHub: Where the world builds software",
        # Empty / weird
        "",
        " ",
    ])
    def test_does_not_match_real_titles(self, title):
        assert GENERIC_TITLE_RE.match(title) is None
