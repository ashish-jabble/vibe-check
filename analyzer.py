"""
VibeCheck Analyzer — Evidence-Based Detection Engine.

Scores are NOT based on assumptions/arbitrary weights.
Every point in the score is backed by a concrete, verifiable finding
classified into evidence tiers with fixed point values and contribution caps.

Evidence Tiers:
  - DEFINITIVE: Irrefutable proof (e.g., v0.dev data attributes, meta generator tag)
  - STRONG:     Very likely signal (e.g., full shadcn stack in bundles, Lovable references)
  - MODERATE:   Circumstantial evidence (e.g., heavy Tailwind, generic copy)
  - WEAK:       Only meaningful with other evidence (e.g., dark mode, Vercel deployment)
"""

import re
import requests
from bs4 import BeautifulSoup
from urllib.parse import urlparse, urljoin
from concurrent.futures import ThreadPoolExecutor, as_completed
from collections import Counter


# ── Request constants ───────────────────────────────────────────────
REQUEST_HEADERS = {
    "User-Agent": (
        "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) "
        "AppleWebKit/537.36 (KHTML, like Gecko) "
        "Chrome/131.0.0.0 Safari/537.36"
    ),
    "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8",
    "Accept-Language": "en-US,en;q=0.9",
    "Accept-Encoding": "gzip, deflate, br",
    "Sec-Fetch-Dest": "document",
    "Sec-Fetch-Mode": "navigate",
    "Sec-Fetch-Site": "none",
    "Sec-Fetch-User": "?1",
    "Upgrade-Insecure-Requests": "1",
    "Connection": "keep-alive",
    "Cache-Control": "max-age=0",
}

ALT_USER_AGENT = (
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
    "AppleWebKit/537.36 (KHTML, like Gecko) "
    "Chrome/130.0.0.0 Safari/537.36"
)

REQUEST_TIMEOUT = 15
MAX_CRAWL_PAGES = 6
MAX_ASSET_FETCH = 10

HTTP_ERROR_MESSAGES = {
    401: "This site requires authentication. VibeCheck can only analyze publicly accessible pages.",
    403: "This site blocked our request (HTTP 403 Forbidden). It may use bot protection (Cloudflare, etc.). Try a different URL from the same site.",
    404: "Page not found (HTTP 404). Check the URL and try again.",
    429: "Too many requests (HTTP 429). The site is rate-limiting us. Try again in a minute.",
    500: "The target site returned a server error (HTTP 500). Try again later.",
    502: "The target site returned a bad gateway error (HTTP 502). Try again later.",
    503: "The target site is temporarily unavailable (HTTP 503). Try again later.",
}


# ── Evidence Tier System ────────────────────────────────────────────

class Tier:
    DEFINITIVE = "definitive"   # Hard proof — each worth 25 pts
    STRONG     = "strong"       # Very likely — each worth 10 pts, capped at 40 total
    MODERATE   = "moderate"     # Circumstantial — each worth 4 pts, capped at 25 total
    WEAK       = "weak"         # Context only — each worth 2 pts, capped at 10 total

TIER_POINTS = {
    Tier.DEFINITIVE: 25,
    Tier.STRONG:     10,
    Tier.MODERATE:    4,
    Tier.WEAK:        2,
}

TIER_CAPS = {
    Tier.DEFINITIVE: 100,  # no cap – definitive proof should dominate
    Tier.STRONG:      40,
    Tier.MODERATE:    25,
    Tier.WEAK:        10,
}

TIER_LABELS = {
    Tier.DEFINITIVE: "Hard Proof",
    Tier.STRONG:     "Strong Signal",
    Tier.MODERATE:   "Indicator",
    Tier.WEAK:       "Context",
}


class Finding:
    """One piece of evidence."""

    def __init__(self, signal: str, description: str, tier: str,
                 evidence: str = "", page: str = "", category: str = ""):
        self.signal = signal
        self.description = description
        self.tier = tier
        self.evidence = evidence
        self.page = page
        self.category = category
        self.points = TIER_POINTS.get(tier, 0)

    def to_dict(self):
        d = {
            "signal": self.signal,
            "description": self.description,
            "tier": self.tier,
            "tier_label": TIER_LABELS.get(self.tier, "Unknown"),
            "points": self.points,
            "evidence": self.evidence,
        }
        if self.page:
            d["page"] = self.page
        return d


class CategoryResult:
    """Result for one analysis category."""

    def __init__(self, name: str, icon: str, findings: list = None):
        self.name = name
        self.icon = icon
        self.findings = findings or []

    @property
    def score(self):
        """Category score = sum of finding points (capped by tier)."""
        return _compute_tiered_score(self.findings)

    def to_dict(self):
        return {
            "name": self.name,
            "icon": self.icon,
            "score": self.score,
            "findings": [f.to_dict() for f in self.findings],
        }


def _compute_tiered_score(findings: list) -> int:
    """Compute a score from findings using tiered point values and caps."""
    tier_totals = {t: 0 for t in (Tier.DEFINITIVE, Tier.STRONG, Tier.MODERATE, Tier.WEAK)}
    for f in findings:
        tier_totals[f.tier] = tier_totals.get(f.tier, 0) + f.points

    total = 0
    for tier, points in tier_totals.items():
        total += min(points, TIER_CAPS.get(tier, 0))
    return min(100, total)


# ── PageData ────────────────────────────────────────────────────────

class PageData:
    def __init__(self, url: str, html: str, headers: dict, soup: BeautifulSoup):
        self.url = url
        self.html = html
        self.headers = headers
        self.soup = soup
        self.parsed = urlparse(url)


# ── NPM packages strongly associated with vibe coding ──────────────
VIBE_PACKAGES = [
    "@radix-ui/", "lucide-react", "class-variance-authority", "clsx",
    "tailwind-merge", "cmdk", "@hookform/resolvers", "react-hook-form",
    "zod", "sonner", "vaul", "embla-carousel", "input-otp", "recharts",
    "next-themes",
]

# shadcn/ui signature class combos
SHADCN_PATTERNS = [
    "inline-flex items-center justify-center",
    "inline-flex items-center rounded-full border",
    "relative w-full rounded-lg border",
    "fixed inset-0 z-50 bg-black/80",
    "flex h-full w-full items-center justify-center rounded-full",
    "relative flex cursor-default select-none items-center rounded-sm",
    "shrink-0 rounded-sm border border-primary",
]

# shadcn CSS custom properties
SHADCN_VARS = [
    "--radius", "--primary", "--ring", "--card", "--popover",
    "--muted", "--accent", "--destructive",
]

TEMPLATE_SECTIONS = ["hero", "features", "testimonials", "pricing", "faq", "cta", "footer"]

GENERIC_PHRASES = [
    r"transform your", r"revolutionize", r"empower your",
    r"take your .+ to the next level", r"unlock the (full )?power",
    r"supercharge your", r"streamline your", r"elevate your",
    r"reimagine", r"cutting[- ]edge", r"next[- ]gen(eration)?",
    r"state[- ]of[- ]the[- ]art", r"game[- ]chang(er|ing)",
    r"seamless(ly)?", r"effortless(ly)?", r"blazing[- ]fast",
    r"lightning[- ]fast", r"world[- ]class", r"enterprise[- ]grade",
    r"built for the future", r"designed for .+ by .+",
]

GENERIC_CTAS = [
    "get started", "learn more", "sign up", "join now", "try it free",
    "start free trial", "book a demo", "request access", "join the waitlist",
    "coming soon", "start building", "get early access", "try for free",
]

STOCK_DOMAINS = [
    "unsplash.com", "images.pexels.com", "placeholder.com", "placehold.co",
    "placekitten.com", "picsum.photos", "via.placeholder.com", "dummyimage.com",
]


# ====================================================================
# Main Analyzer
# ====================================================================

class VibeCodingAnalyzer:

    def analyze(self, url: str) -> dict:
        if not url.startswith(("http://", "https://")):
            url = "https://" + url

        parsed = urlparse(url)
        base_origin = f"{parsed.scheme}://{parsed.netloc}"

        # 1. Fetch primary page
        primary = self._fetch_page(url, is_primary=True)
        if isinstance(primary, str):
            return {"error": primary}
        if primary is None:
            return {"error": f"Failed to fetch {url}. Check the URL and try again."}

        pages = [primary]

        # 2. Crawl internal pages
        internal = self._discover_internal_links(primary, base_origin)
        if internal:
            pages.extend(self._fetch_pages_parallel(internal))

        # 3. Fetch linked assets
        css_texts, js_texts = self._fetch_linked_assets(primary, base_origin)
        asset_text = "\n".join(css_texts + js_texts)

        # 4. Run ALL detection categories
        categories = {
            "ai_platforms":    self._check_ai_platforms(pages, asset_text),
            "ui_libraries":    self._check_ui_libraries(pages, asset_text),
            "frameworks":      self._check_frameworks(pages, asset_text),
            "content":         self._check_content(pages),
            "code_quality":    self._check_code_quality(pages, asset_text),
            "deployment":      self._check_deployment(pages, base_origin),
            "design_patterns": self._check_design_patterns(pages, asset_text),
            "accessibility":   self._check_accessibility(pages),
            "seo_quality":     self._check_seo(pages),
        }

        # 5. Compute EVIDENCE-BASED score
        all_findings = []
        for cat in categories.values():
            all_findings.extend(cat.findings)

        overall = _compute_tiered_score(all_findings)
        verdict, verdict_emoji = self._get_verdict(overall)

        # Evidence breakdown for transparency
        evidence_summary = self._build_evidence_summary(all_findings)

        return {
            "url": url,
            "overall_score": overall,
            "verdict": verdict,
            "verdict_emoji": verdict_emoji,
            "pages_analyzed": len(pages),
            "assets_analyzed": len(css_texts) + len(js_texts),
            "pages_list": [p.url for p in pages],
            "evidence_summary": evidence_summary,
            "categories": {k: v.to_dict() for k, v in categories.items()},
        }

    # ================================================================
    # Evidence summary
    # ================================================================

    def _build_evidence_summary(self, findings: list) -> dict:
        tier_counts = Counter(f.tier for f in findings)
        tier_points = {}
        for tier in (Tier.DEFINITIVE, Tier.STRONG, Tier.MODERATE, Tier.WEAK):
            raw = sum(f.points for f in findings if f.tier == tier)
            capped = min(raw, TIER_CAPS[tier])
            tier_points[tier] = {
                "count": tier_counts.get(tier, 0),
                "raw_points": raw,
                "capped_points": capped,
                "cap": TIER_CAPS[tier],
                "label": TIER_LABELS[tier],
            }
        return tier_points

    # ================================================================
    # Fetching
    # ================================================================

    def _fetch_page(self, url, is_primary=False):
        """Fetch a page. Uses requests first, falls back to headless browser for protected sites."""
        last_error = None
        needs_browser = False

        for attempt in range(2):
            headers = dict(REQUEST_HEADERS)
            if attempt == 1:
                headers["User-Agent"] = ALT_USER_AGENT
            try:
                resp = requests.get(url, headers=headers, timeout=REQUEST_TIMEOUT,
                                    allow_redirects=True)
                resp.raise_for_status()
                return PageData(url, resp.text, dict(resp.headers),
                                BeautifulSoup(resp.text, "lxml"))
            except requests.exceptions.HTTPError as exc:
                status = exc.response.status_code if exc.response is not None else 0
                if status == 403 and attempt == 0:
                    last_error = status
                    continue
                if status in (403, 401):
                    needs_browser = True
                    last_error = status
                    break
                if is_primary:
                    msg = HTTP_ERROR_MESSAGES.get(
                        status,
                        f"The site returned HTTP {status}. Check the URL and try again.",
                    )
                    return msg
                return None
            except requests.exceptions.Timeout:
                if attempt == 1:
                    needs_browser = True
                    last_error = "timeout"
                    break
                last_error = "timeout"
                continue
            except requests.exceptions.ConnectionError as exc:
                err_str = str(exc).lower()
                if "connection reset" in err_str or "connection aborted" in err_str:
                    needs_browser = True
                    last_error = "blocked"
                    break
                if is_primary:
                    return "Could not connect to the site. Check the URL or your network connection."
                return None
            except requests.exceptions.TooManyRedirects:
                if is_primary:
                    return "Too many redirects. The site may be misconfigured."
                return None
            except Exception as exc:
                if is_primary:
                    return f"Failed to fetch: {str(exc)[:200]}"
                return None

        # ── Fallback: headless browser for protected sites ─────────────
        if needs_browser:
            browser_result = self._fetch_with_browser(url)
            if browser_result is not None:
                return browser_result
            # Browser fallback also failed
            if is_primary:
                reason = {
                    "blocked": "Connection blocked by the site's bot protection.",
                    "timeout": "Request timed out.",
                }.get(str(last_error), f"HTTP {last_error}.")
                return (
                    f"{reason} We also tried a headless browser but could not load the page. "
                    "The site may require login or use advanced bot protection."
                )
            return None

        # Both HTTP attempts failed without triggering browser fallback
        if is_primary:
            msg = HTTP_ERROR_MESSAGES.get(last_error, "Failed to fetch the page after retrying.")
            return msg
        return None

    def _fetch_with_browser(self, url):
        """Fallback: use Playwright headless browser for Cloudflare-protected sites."""
        try:
            from playwright.sync_api import sync_playwright
        except ImportError:
            return None

        try:
            with sync_playwright() as pw:
                browser = pw.chromium.launch(headless=True)
                context = browser.new_context(
                    user_agent=(
                        "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) "
                        "AppleWebKit/537.36 (KHTML, like Gecko) "
                        "Chrome/131.0.0.0 Safari/537.36"
                    ),
                    viewport={"width": 1440, "height": 900},
                    locale="en-US",
                )
                page = context.new_page()
                resp = page.goto(url, wait_until="domcontentloaded", timeout=25000)
                # Wait a bit for any Cloudflare challenge JS to complete
                page.wait_for_timeout(3000)
                html = page.content()
                headers = dict(resp.headers) if resp else {}
                browser.close()

                if len(html) < 200:
                    return None  # Page likely didn't load properly

                return PageData(url, html, headers, BeautifulSoup(html, "lxml"))
        except Exception:
            return None

    def _fetch_pages_parallel(self, urls):
        results = []
        with ThreadPoolExecutor(max_workers=4) as pool:
            futs = {pool.submit(self._fetch_page, u): u for u in urls}
            for f in as_completed(futs):
                page = f.result()
                if page:
                    results.append(page)
        return results

    def _discover_internal_links(self, page, base_origin):
        seen = {page.url.rstrip("/")}
        links = []
        for a in page.soup.find_all("a", href=True):
            href = a["href"].strip()
            if href.startswith(("#", "javascript:", "mailto:", "tel:")):
                continue
            full = urljoin(page.url, href).split("#")[0].split("?")[0]
            norm = full.rstrip("/")
            if not full.startswith(base_origin) or norm in seen:
                continue
            if re.search(r"\.(png|jpg|jpeg|gif|svg|webp|pdf|zip|mp4|ico|woff2?|ttf|eot)$",
                         full, re.IGNORECASE):
                continue
            seen.add(norm)
            links.append(full)
            if len(links) >= MAX_CRAWL_PAGES - 1:
                break
        return links

    def _fetch_linked_assets(self, page, base_origin):
        css_urls = [urljoin(page.url, l["href"])
                    for l in page.soup.find_all("link", rel="stylesheet", href=True)]
        js_urls = [urljoin(page.url, s["src"])
                   for s in page.soup.find_all("script", src=True)]

        def fetch(url):
            try:
                r = requests.get(url, headers=REQUEST_HEADERS, timeout=8)
                r.raise_for_status()
                return url, r.text[:500_000]
            except Exception:
                return url, None

        urls = css_urls[:MAX_ASSET_FETCH] + js_urls[:MAX_ASSET_FETCH]
        css_texts, js_texts = [], []
        with ThreadPoolExecutor(max_workers=6) as pool:
            for fut in as_completed({pool.submit(fetch, u): u for u in urls}):
                url, txt = fut.result()
                if txt is None:
                    continue
                (css_texts if url in css_urls else js_texts).append(txt)
        return css_texts, js_texts

    # ================================================================
    # 1. AI PLATFORM SIGNATURES
    # ================================================================

    def _check_ai_platforms(self, pages, asset_text):
        cat = CategoryResult("AI Platform Signatures", "🤖")
        F = cat.findings
        html_all = "\n".join(p.html for p in pages)
        html_lower = html_all.lower()

        # ── v0.dev (DEFINITIVE if data attributes found) ────────────────
        for p in pages:
            if p.soup.find_all(attrs=lambda a: a and any(k.startswith("data-v0") for k in a)):
                F.append(Finding("v0.dev", "data-v0-* attributes found — irrefutable v0.dev marker",
                                 Tier.DEFINITIVE, "data-v0-* attributes"))
                break
        if "v0.dev" in html_lower and not any(f.signal == "v0.dev" for f in F):
            F.append(Finding("v0.dev", "Reference to v0.dev in source", Tier.STRONG))

        # ── Bolt.new / StackBlitz ──────────────────────────────────────
        for marker in ["bolt.new", "stackblitz"]:
            if marker in html_lower:
                F.append(Finding("Bolt.new", f"'{marker}' reference in source", Tier.STRONG))
        for p in pages:
            if p.soup.find_all(attrs={"data-bolt": True}):
                F.append(Finding("Bolt.new", "data-bolt attributes — definitive Bolt marker",
                                 Tier.DEFINITIVE))
                break

        # ── Lovable / GPTEngineer ──────────────────────────────────────
        for marker in ["lovable", "gptengineer", "gpt-engineer"]:
            if marker in html_lower:
                F.append(Finding("Lovable", f"'{marker}' reference in source", Tier.STRONG))

        # ── Meta generator tag (DEFINITIVE) ────────────────────────────
        for p in pages:
            meta = p.soup.find("meta", attrs={"name": "generator"})
            if meta:
                content = (meta.get("content") or "").lower()
                for name in ["v0", "bolt", "lovable", "gptengineer", "cursor", "windsurf", "replit"]:
                    if name in content:
                        F.append(Finding(name,
                                         f"Meta generator tag explicitly names '{name}'",
                                         Tier.DEFINITIVE, content))

        # ── Vercel AI SDK ──────────────────────────────────────────────
        if re.search(r"@vercel/ai|ai/react|useChat|useCompletion", html_all):
            F.append(Finding("Vercel AI SDK", "Vercel AI SDK references", Tier.MODERATE))

        # ── Vibe-stack packages in JS bundles ──────────────────────────
        if asset_text:
            hits = [p for p in VIBE_PACKAGES if p in asset_text]
            if len(hits) >= 6:
                F.append(Finding("Vibe Stack",
                                 f"Found {len(hits)} vibe-coding packages in bundles — classic AI-scaffolded stack",
                                 Tier.STRONG, ", ".join(hits[:6])))
            elif len(hits) >= 3:
                F.append(Finding("Vibe Stack",
                                 f"Found {len(hits)} vibe-coding packages in bundles",
                                 Tier.MODERATE, ", ".join(hits)))

        # ── Replit ─────────────────────────────────────────────────────
        primary = pages[0]
        if ".repl.co" in primary.parsed.netloc or ".replit.dev" in primary.parsed.netloc:
            F.append(Finding("Replit", "Hosted on Replit domain", Tier.MODERATE))
        if "replit" in html_lower:
            F.append(Finding("Replit", "Replit reference in source", Tier.MODERATE))

        return cat

    # ================================================================
    # 2. UI LIBRARY PATTERNS
    # ================================================================

    def _check_ui_libraries(self, pages, asset_text):
        cat = CategoryResult("UI Library Patterns", "🧩")
        F = cat.findings
        html_all = "\n".join(p.html for p in pages)
        all_text = html_all + "\n" + asset_text

        # ── Radix UI ───────────────────────────────────────────────────
        radix_count = sum(
            len(p.soup.find_all(attrs=lambda a: a and any(k.startswith("data-radix") for k in a)))
            for p in pages
        )
        if radix_count >= 10:
            F.append(Finding("Radix UI", f"{radix_count} data-radix-* elements — heavy Radix usage",
                             Tier.STRONG, f"{radix_count} elements"))
        elif radix_count >= 1:
            F.append(Finding("Radix UI", f"{radix_count} data-radix-* elements",
                             Tier.MODERATE, f"{radix_count} elements"))

        if re.search(r"@radix-ui", all_text):
            F.append(Finding("Radix UI", "Radix UI package in source/bundles", Tier.MODERATE))

        # ── shadcn/ui class patterns ───────────────────────────────────
        shadcn_hits = sum(1 for p in SHADCN_PATTERNS if p in html_all)
        if shadcn_hits >= 3:
            F.append(Finding("shadcn/ui", f"{shadcn_hits} shadcn/ui class patterns matched",
                             Tier.STRONG, f"{shadcn_hits}/7 patterns"))
        elif shadcn_hits >= 1:
            F.append(Finding("shadcn/ui", f"{shadcn_hits} possible shadcn/ui class pattern",
                             Tier.MODERATE))

        # ── shadcn CSS variables ───────────────────────────────────────
        var_hits = sum(1 for v in SHADCN_VARS if v in all_text)
        if var_hits >= 6:
            F.append(Finding("shadcn/ui", f"{var_hits}/8 shadcn CSS custom properties — confirms shadcn theming",
                             Tier.STRONG, f"{var_hits}/8 variables"))
        elif var_hits >= 3:
            F.append(Finding("shadcn/ui", f"{var_hits} shadcn-style CSS variables",
                             Tier.MODERATE))

        # ── Full shadcn stack combo (Radix + shadcn vars + Lucide = STRONG) ──
        has_radix = radix_count >= 1
        has_vars = var_hits >= 3
        has_lucide = "lucide" in all_text.lower()
        if has_radix and has_vars and has_lucide:
            F.append(Finding("shadcn Stack",
                             "Full shadcn/ui stack confirmed: Radix + CSS variables + Lucide icons",
                             Tier.STRONG, "Complete stack detected"))

        # ── Lucide Icons ───────────────────────────────────────────────
        lucide_count = sum(len(p.soup.find_all(class_=re.compile(r"lucide"))) for p in pages)
        if lucide_count:
            F.append(Finding("Lucide Icons", f"{lucide_count} Lucide icon elements", Tier.WEAK))
        if "lucide-react" in all_text:
            F.append(Finding("Lucide Icons", "lucide-react package referenced", Tier.WEAK))

        return cat

    # ================================================================
    # 3. FRAMEWORK DETECTION
    # ================================================================

    def _check_frameworks(self, pages, asset_text):
        cat = CategoryResult("Framework Detection", "⚡")
        F = cat.findings
        html_all = "\n".join(p.html for p in pages)
        primary = pages[0]

        # Next.js
        has_next = False
        for p in pages:
            if p.soup.find(id="__next"):
                F.append(Finding("Next.js", "#__next root element", Tier.WEAK))
                has_next = True
                break
        if "/_next/static" in html_all:
            F.append(Finding("Next.js", "Next.js static asset paths", Tier.WEAK))
            has_next = True
        if primary.headers.get("x-powered-by", "").lower() == "next.js":
            F.append(Finding("Next.js", "x-powered-by: Next.js header", Tier.WEAK))
            has_next = True

        # Vite
        if "/@vite" in html_all or "/node_modules/.vite" in html_all:
            F.append(Finding("Vite", "Vite dev server references", Tier.WEAK))

        # React
        if asset_text and re.search(r"react-dom|ReactDOM", asset_text):
            F.append(Finding("React", "React detected in JS bundles", Tier.WEAK))

        # Astro
        if "astro-island" in html_all or "data-astro" in html_all:
            F.append(Finding("Astro", "Astro framework detected", Tier.WEAK))

        # SvelteKit
        if "__sveltekit" in html_all:
            F.append(Finding("SvelteKit", "SvelteKit framework detected", Tier.WEAK))

        # ── TECH STACK COMBO (this IS a real signal) ───────────────────
        # Next.js + Vercel + shadcn + Tailwind = classic vibe-coding stack
        has_vercel = any(k.lower().startswith("x-vercel") for k in primary.headers)
        has_tailwind = self._detect_tailwind(html_all, asset_text)
        has_shadcn = any(v in (html_all + asset_text) for v in SHADCN_VARS[:4])

        combo_count = sum([has_next, has_vercel, has_tailwind, has_shadcn])
        if combo_count == 4:
            F.append(Finding("Vibe Stack Combo",
                             "Next.js + Vercel + TailwindCSS + shadcn/ui — the classic vibe-coding stack",
                             Tier.STRONG, "All 4 components confirmed"))
        elif combo_count == 3:
            F.append(Finding("Likely Vibe Stack",
                             f"{combo_count}/4 components of the classic vibe-coding stack detected",
                             Tier.MODERATE))

        return cat

    # ================================================================
    # 4. CONTENT SIGNALS
    # ================================================================

    def _check_content(self, pages):
        cat = CategoryResult("Content Signals", "📝")
        F = cat.findings
        all_text = " ".join(p.soup.get_text(separator=" ", strip=True).lower() for p in pages)

        # Generic marketing phrases
        phrase_hits = [p for p in GENERIC_PHRASES if re.search(p, all_text, re.IGNORECASE)]
        if len(phrase_hits) >= 7:
            F.append(Finding("Generic AI Copy",
                             f"{len(phrase_hits)} generic marketing phrases — strongly suggests AI-generated copy",
                             Tier.STRONG, ", ".join(phrase_hits[:5])))
        elif len(phrase_hits) >= 4:
            F.append(Finding("Generic Copy",
                             f"{len(phrase_hits)} generic marketing phrases",
                             Tier.MODERATE, ", ".join(phrase_hits[:4])))
        elif len(phrase_hits) >= 2:
            F.append(Finding("Generic Copy",
                             f"{len(phrase_hits)} generic phrases (common in AI and human marketing)",
                             Tier.WEAK, ", ".join(phrase_hits[:3])))

        # Generic CTAs
        cta_hits = []
        for page in pages:
            for el in page.soup.find_all(["a", "button"]):
                el_text = el.get_text(strip=True).lower()
                for cta in GENERIC_CTAS:
                    if cta in el_text:
                        cta_hits.append(cta)
                        break
        if len(cta_hits) >= 8:
            F.append(Finding("Generic CTAs",
                             f"{len(cta_hits)} generic CTAs across {len(pages)} page(s)",
                             Tier.MODERATE, ", ".join(sorted(set(cta_hits))[:5])))
        elif len(cta_hits) >= 3:
            F.append(Finding("Generic CTAs",
                             f"{len(cta_hits)} generic CTAs", Tier.WEAK,
                             ", ".join(sorted(set(cta_hits)))))

        # Stock images
        stock_hits = []
        for page in pages:
            for img in page.soup.find_all("img"):
                src = img.get("src", "") or img.get("data-src", "")
                for domain in STOCK_DOMAINS:
                    if domain in src:
                        stock_hits.append(domain)
                        break
        if stock_hits:
            F.append(Finding("Stock Images",
                             f"{len(stock_hits)} images from stock/placeholder services",
                             Tier.MODERATE, ", ".join(sorted(set(stock_hits)))))

        # Lorem ipsum (STRONG — this is undeniable evidence of template/generated content)
        if "lorem ipsum" in all_text:
            F.append(Finding("Lorem Ipsum", "Lorem ipsum placeholder text found",
                             Tier.STRONG))

        # Placeholder company text
        if re.search(r"your (company|brand|product) (name|here)", all_text, re.IGNORECASE):
            F.append(Finding("Placeholder", "Unfilled placeholder text (company/brand name)",
                             Tier.STRONG))

        return cat

    # ================================================================
    # 5. CODE QUALITY (replaces "Code Style")
    # ================================================================

    def _check_code_quality(self, pages, asset_text):
        cat = CategoryResult("Code Quality", "🔬")
        F = cat.findings
        html_all = "\n".join(p.html for p in pages)

        # DOM nesting depth
        max_depth = max((self._max_depth(p.soup.body) for p in pages if p.soup.body), default=0)
        if max_depth > 18:
            F.append(Finding("Excessive Nesting",
                             f"DOM nesting depth: {max_depth} — usually indicates AI-generated markup",
                             Tier.MODERATE, f"{max_depth} levels"))
        elif max_depth > 12:
            F.append(Finding("Deep Nesting",
                             f"DOM nesting depth: {max_depth}",
                             Tier.WEAK, f"{max_depth} levels"))

        # Tailwind
        if self._detect_tailwind(html_all, asset_text):
            # Count heavy utility elements
            heavy = sum(
                1 for p in pages for el in p.soup.find_all(True)
                if isinstance(el.get("class"), list) and len(el.get("class", [])) > 10
            )
            if heavy > 30:
                F.append(Finding("Utility Class Overload",
                                 f"{heavy} elements with 10+ utility classes — possible AI-generated markup",
                                 Tier.MODERATE, f"{heavy} elements"))
            elif heavy > 10:
                F.append(Finding("Heavy Tailwind",
                                 f"{heavy} elements with 10+ utility classes",
                                 Tier.WEAK, f"{heavy} elements"))

        # TailwindCSS confirmation in CSS bundles
        if asset_text:
            tw_markers = ["tailwindcss", "--tw-", "tw-ring-offset", "tw-translate-x"]
            if sum(1 for m in tw_markers if m in asset_text) >= 2:
                F.append(Finding("TailwindCSS", "Confirmed via CSS bundle markers", Tier.WEAK))

        # AI-style comments
        ai_comments = re.findall(
            r"<!--\s*(This (component|section|div|element)|Main (content|section|layout)|The following)",
            html_all, re.IGNORECASE,
        )
        if len(ai_comments) >= 5:
            F.append(Finding("AI Comments",
                             f"{len(ai_comments)} overly descriptive HTML comments — strong AI generation pattern",
                             Tier.MODERATE))
        elif len(ai_comments) >= 2:
            F.append(Finding("AI Comments",
                             f"{len(ai_comments)} verbose HTML comments",
                             Tier.WEAK))

        # ── Repetitive DOM structure (NEW) ─────────────────────────────
        self._check_repetitive_structures(pages, F)

        return cat

    def _check_repetitive_structures(self, pages, findings):
        """Detect if multiple sections have nearly identical DOM structure — AI generates repetitive patterns."""
        for page in pages:
            sections = page.soup.find_all("section")
            if len(sections) < 3:
                continue

            # Get structural fingerprint for each section (tag sequence)
            fingerprints = []
            for sec in sections:
                children_tags = []
                for child in sec.descendants:
                    if hasattr(child, "name") and child.name:
                        children_tags.append(child.name)
                # Fingerprint = first 20 tags in order
                fp = tuple(children_tags[:20])
                if len(fp) >= 5:
                    fingerprints.append(fp)

            # Check for repeats
            fp_counter = Counter(fingerprints)
            most_common = fp_counter.most_common(1)
            if most_common and most_common[0][1] >= 3:
                count = most_common[0][1]
                findings.append(Finding("Repetitive Sections",
                                        f"{count} sections with identical DOM structure — AI tends to repeat patterns",
                                        Tier.MODERATE, f"{count} matching sections"))
            break  # Only check primary page

    # ================================================================
    # 6. DEPLOYMENT SIGNALS
    # ================================================================

    def _check_deployment(self, pages, base_origin):
        cat = CategoryResult("Deployment Signals", "🚀")
        F = cat.findings
        headers = pages[0].headers
        parsed = pages[0].parsed

        # These are WEAK signals — being on Vercel doesn't mean vibe-coded
        if any(k.lower().startswith("x-vercel") for k in headers) or ".vercel.app" in parsed.netloc:
            F.append(Finding("Vercel", "Deployed on Vercel",
                             Tier.WEAK, "Many legitimate sites use Vercel"))
        if any(k.lower().startswith("x-nf") for k in headers) or ".netlify.app" in parsed.netloc:
            F.append(Finding("Netlify", "Deployed on Netlify", Tier.WEAK))
        if ".pages.dev" in parsed.netloc:
            F.append(Finding("Cloudflare Pages", "Deployed on Cloudflare Pages", Tier.WEAK))
        if ".railway.app" in parsed.netloc:
            F.append(Finding("Railway", "Deployed on Railway", Tier.WEAK))
        if ".onrender.com" in parsed.netloc:
            F.append(Finding("Render", "Deployed on Render", Tier.WEAK))

        # Missing basics
        try:
            r = requests.get(f"{base_origin}/robots.txt", headers=REQUEST_HEADERS, timeout=5)
            if r.status_code == 404:
                F.append(Finding("No robots.txt", "Missing robots.txt", Tier.WEAK))
        except Exception:
            pass
        try:
            r = requests.get(f"{base_origin}/sitemap.xml", headers=REQUEST_HEADERS, timeout=5)
            if r.status_code == 404:
                F.append(Finding("No sitemap", "Missing sitemap.xml", Tier.WEAK))
        except Exception:
            pass

        return cat

    # ================================================================
    # 7. DESIGN PATTERNS
    # ================================================================

    def _check_design_patterns(self, pages, asset_text):
        cat = CategoryResult("Design Patterns", "🎨")
        F = cat.findings
        html_all = "\n".join(p.html for p in pages)
        all_text = html_all + "\n" + asset_text

        # Glassmorphism
        if "backdrop-filter" in all_text or "backdrop-blur" in all_text:
            F.append(Finding("Glassmorphism", "Backdrop blur / glassmorphism effects", Tier.WEAK))

        # Gradients
        g_count = len(re.findall(r"(bg-gradient-to-|linear-gradient|radial-gradient)", all_text))
        if g_count >= 10:
            F.append(Finding("Heavy Gradients", f"{g_count} gradient references", Tier.WEAK))

        # Cookie-cutter layout
        section_names = []
        for p in pages:
            for s in p.soup.find_all(["section", "div"], id=True):
                section_names.append(s.get("id", "").lower())
            for s in p.soup.find_all(["section", "div"], class_=True):
                section_names.extend(c.lower() for c in (s.get("class") or []))

        template_hits = sum(1 for t in TEMPLATE_SECTIONS if t in section_names)
        if template_hits >= 5:
            F.append(Finding("Template Layout",
                             f"{template_hits}/7 cookie-cutter sections (hero → features → testimonials → …)",
                             Tier.MODERATE))
        elif template_hits >= 3:
            F.append(Finding("Template Layout",
                             f"{template_hits} template-style section names",
                             Tier.WEAK))

        # Card grid
        card_count = sum(len(p.soup.find_all(class_=re.compile(r"card", re.IGNORECASE))) for p in pages)
        if card_count >= 9:
            F.append(Finding("Card Grid", f"{card_count} card components", Tier.WEAK))

        return cat

    # ================================================================
    # 8. ACCESSIBILITY AUDIT (NEW)
    # ================================================================

    def _check_accessibility(self, pages):
        cat = CategoryResult("Accessibility", "♿")
        F = cat.findings

        total_imgs = 0
        missing_alt = 0
        empty_alt = 0
        for p in pages:
            imgs = p.soup.find_all("img")
            total_imgs += len(imgs)
            for img in imgs:
                alt = img.get("alt")
                if alt is None:
                    missing_alt += 1
                elif alt.strip() == "":
                    empty_alt += 1

        if total_imgs > 0:
            missing_pct = (missing_alt / total_imgs) * 100
            if missing_pct >= 50 and missing_alt >= 3:
                F.append(Finding("Missing Alt Text",
                                 f"{missing_alt}/{total_imgs} images missing alt attribute "
                                 f"({missing_pct:.0f}%) — AI-generated code often skips accessibility",
                                 Tier.MODERATE, f"{missing_alt} missing"))
            elif missing_alt >= 1:
                F.append(Finding("Missing Alt Text",
                                 f"{missing_alt} image(s) missing alt text",
                                 Tier.WEAK))

        # Heading hierarchy
        for p in pages:
            headings = p.soup.find_all(re.compile(r"h[1-6]"))
            if not headings:
                continue
            levels = [int(h.name[1]) for h in headings]
            # Check for skipped levels (h1 → h3 without h2)
            skips = 0
            for i in range(1, len(levels)):
                if levels[i] > levels[i - 1] + 1:
                    skips += 1
            if skips >= 2:
                F.append(Finding("Heading Hierarchy",
                                 f"{skips} heading level skips — AI often generates inconsistent headings",
                                 Tier.WEAK))
            # Multiple h1s
            h1_count = levels.count(1)
            if h1_count > 1:
                F.append(Finding("Multiple H1s",
                                 f"{h1_count} H1 tags on a single page — suggests auto-generated structure",
                                 Tier.WEAK))
            break  # Check primary page only

        # Missing ARIA landmarks
        landmarks = pages[0].soup.find_all(attrs={"role": True})
        nav_elements = pages[0].soup.find_all("nav")
        main_elements = pages[0].soup.find_all("main")
        if not landmarks and not nav_elements and not main_elements:
            F.append(Finding("No ARIA/Landmarks",
                             "No ARIA roles or semantic landmarks — vibe-coded sites typically skip accessibility",
                             Tier.WEAK))

        # Empty links/buttons
        empty_interactive = 0
        for p in pages:
            for el in p.soup.find_all(["a", "button"]):
                text = el.get_text(strip=True)
                aria = el.get("aria-label", "")
                title = el.get("title", "")
                if not text and not aria and not title:
                    empty_interactive += 1
        if empty_interactive >= 3:
            F.append(Finding("Empty Interactive Elements",
                             f"{empty_interactive} links/buttons with no accessible text",
                             Tier.WEAK))

        return cat

    # ================================================================
    # 9. SEO QUALITY (NEW)
    # ================================================================

    def _check_seo(self, pages):
        cat = CategoryResult("SEO Quality", "🔍")
        F = cat.findings
        primary = pages[0]

        # Meta description
        meta_desc = primary.soup.find("meta", attrs={"name": "description"})
        if not meta_desc or not (meta_desc.get("content") or "").strip():
            F.append(Finding("No Meta Description",
                             "Missing meta description — AI-generated sites often skip SEO basics",
                             Tier.WEAK))

        # Open Graph tags
        og_tags = primary.soup.find_all("meta", attrs={"property": re.compile(r"^og:")})
        if not og_tags:
            F.append(Finding("No Open Graph",
                             "No Open Graph tags — social sharing will show no preview",
                             Tier.WEAK))

        # Title tag
        title = primary.soup.find("title")
        if not title or not title.get_text(strip=True):
            F.append(Finding("No Title Tag",
                             "Missing or empty <title> tag",
                             Tier.WEAK))
        elif title:
            title_text = title.get_text(strip=True).lower()
            generic_titles = ["home", "welcome", "untitled", "my app", "my site", "my website",
                              "create next app", "vite app", "vite + react"]
            if any(t == title_text or title_text.startswith(t) for t in generic_titles):
                F.append(Finding("Generic Title",
                                 f"Page title is generic: '{title.get_text(strip=True)}'",
                                 Tier.MODERATE, title.get_text(strip=True)))

        # Favicon
        favicon = primary.soup.find("link", rel=lambda r: r and "icon" in r)
        if not favicon:
            F.append(Finding("No Favicon",
                             "No favicon defined — common in quickly scaffolded AI projects",
                             Tier.WEAK))

        # Lang attribute
        html_tag = primary.soup.find("html")
        if html_tag and not html_tag.get("lang"):
            F.append(Finding("No Lang Attribute",
                             "HTML tag missing lang attribute",
                             Tier.WEAK))

        return cat

    # ================================================================
    # Helpers
    # ================================================================

    def _max_depth(self, el, d=0):
        if not hasattr(el, "children"):
            return d
        mx = d
        for c in el.children:
            if hasattr(c, "name") and c.name:
                mx = max(mx, self._max_depth(c, d + 1))
        return mx

    @staticmethod
    def _detect_tailwind(html, asset_text):
        """Returns True if TailwindCSS is detected."""
        tw_classes = ["flex", "items-center", "justify-center", "rounded-lg",
                      "px-4", "py-2", "bg-gradient-to-r", "text-sm", "font-medium"]
        hits = sum(1 for c in tw_classes if f" {c}" in html or f'"{c}' in html)
        if hits >= 5:
            return True
        if asset_text:
            return any(m in asset_text for m in ["tailwindcss", "--tw-", "tw-ring-offset"])
        return False

    @staticmethod
    def _get_verdict(score):
        if score >= 76:
            return "Almost Certainly Vibe Coded", "🔴"
        elif score >= 51:
            return "Probably Vibe Coded", "🟠"
        elif score >= 26:
            return "Mixed Signals", "🟡"
        else:
            return "Likely Human-Crafted", "🟢"
