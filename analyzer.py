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

import ipaddress
import logging
import os
import re
import socket
import threading
from collections import Counter
from concurrent.futures import ThreadPoolExecutor, as_completed
from urllib.parse import urlparse, urljoin

import requests
from bs4 import BeautifulSoup
from requests.structures import CaseInsensitiveDict


# ── Request constants ───────────────────────────────────────────────
REQUEST_HEADERS = {
    "User-Agent": (
        "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) "
        "AppleWebKit/537.36 (KHTML, like Gecko) "
        "Chrome/131.0.0.0 Safari/537.36"
    ),
    "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8",
    "Accept-Language": "en-US,en;q=0.9",
    # 'br' deliberately omitted — requests/urllib3 only auto-decodes gzip/deflate;
    # accepting brotli without the optional `brotli` package returns compressed bytes.
    "Accept-Encoding": "gzip, deflate",
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

# Hard ceilings on response body size — prevent memory exhaustion via huge responses.
MAX_PAGE_BYTES = 5_000_000     # 5 MB per HTML page
MAX_ASSET_BYTES = 500_000      # 500 KB per CSS/JS asset (matches prior inline truncation)
MAX_PROBE_BYTES = 200_000      # 200 KB for robots.txt / sitemap.xml probes
MAX_REDIRECTS = 5

# Bound concurrent Playwright launches. Chromium is heavy (~200 MB resident);
# without a cap, every 401/403/timeout fans out into a fresh browser process.
# Override with VIBECHECK_BROWSER_CONCURRENCY env var.
_BROWSER_CONCURRENCY = max(1, int(os.environ.get("VIBECHECK_BROWSER_CONCURRENCY", "2")))
_browser_semaphore = threading.BoundedSemaphore(_BROWSER_CONCURRENCY)

# Hostnames that must never be fetched regardless of DNS resolution.
BLOCKED_HOSTS = frozenset({
    "localhost",
    "ip6-localhost",
    "ip6-loopback",
    "metadata.google.internal",
    "metadata.goog",
})

URL_NOT_ALLOWED_MESSAGE = (
    "This URL is not allowed. VibeCheck only analyzes publicly accessible "
    "websites — private, internal, and loopback addresses are blocked."
)

HTTP_ERROR_MESSAGES = {
    401: "This site requires authentication. VibeCheck can only analyze publicly accessible pages.",
    403: "This site blocked our request (HTTP 403 Forbidden). It may use bot protection (Cloudflare, etc.). Try a different URL from the same site.",
    404: "Page not found (HTTP 404). Check the URL and try again.",
    429: "Too many requests (HTTP 429). The site is rate-limiting us. Try again in a minute.",
    500: "The target site returned a server error (HTTP 500). Try again later.",
    502: "The target site returned a bad gateway error (HTTP 502). Try again later.",
    503: "The target site is temporarily unavailable (HTTP 503). Try again later.",
}


# ── SSRF protection ─────────────────────────────────────────────────
#
# Two-layer defence:
#  1. _resolve_safe() validates the URL and resolves the hostname to a public IP,
#     rejecting any IP that's private/loopback/link-local/multicast/reserved.
#  2. _DNSPin pins that IP into a thread-local DNS override; while pinned,
#     socket.getaddrinfo() returns the validated IP without re-resolving.
#     This closes the DNS-rebinding window between validation and the actual
#     TCP connect (where requests/urllib3 would otherwise call getaddrinfo
#     a second time and could be served a different IP).
#
# TLS, SNI, the Host header, and certificate verification all continue to use
# the original hostname — only the address used for connect() is pinned.

class UnsafeURLError(Exception):
    """Raised when a URL is rejected (scheme, blocked host, private IP, oversized body, redirect loop)."""


_dns_overrides = threading.local()
_real_getaddrinfo = socket.getaddrinfo


def _patched_getaddrinfo(host, port=None, *args, **kwargs):
    """Drop-in replacement for socket.getaddrinfo that honours thread-local pins.

    When a hostname has a pinned IP (set via _DNSPin), return that IP synthetically
    instead of doing real DNS. Falls through to the real getaddrinfo otherwise so
    Flask, logging, and any other non-fetch code is unaffected.
    """
    overrides = getattr(_dns_overrides, "map", None)
    if overrides:
        ip = overrides.get(host)
        if ip is not None:
            try:
                ipaddress.IPv6Address(ip)
                family = socket.AF_INET6
                sockaddr = (ip, port or 0, 0, 0)
            except ValueError:
                family = socket.AF_INET
                sockaddr = (ip, port or 0)
            return [(family, socket.SOCK_STREAM, socket.IPPROTO_TCP, "", sockaddr)]
    return _real_getaddrinfo(host, port, *args, **kwargs)


socket.getaddrinfo = _patched_getaddrinfo


class _DNSPin:
    """Thread-local DNS override context manager.

    Within the with-block, ``socket.getaddrinfo(hostname, ...)`` returns the
    pinned IP instead of consulting DNS. Use this to ensure the actual TCP
    connect uses the IP we already validated, not a freshly-resolved (and
    potentially attacker-controlled) one.
    """

    def __init__(self, hostname: str, ip: str):
        self._hostname = hostname
        self._ip = ip

    def __enter__(self):
        existing = getattr(_dns_overrides, "map", None)
        if existing is None:
            existing = {}
            _dns_overrides.map = existing
        self._was_set = self._hostname in existing
        self._previous = existing.get(self._hostname)
        existing[self._hostname] = self._ip
        return self

    def __exit__(self, *_exc):
        existing = getattr(_dns_overrides, "map", None)
        if existing is None:
            return
        if self._was_set:
            existing[self._hostname] = self._previous
        else:
            existing.pop(self._hostname, None)


def _resolve_safe(url: str) -> tuple[str, str]:
    """Validate the URL and return (hostname, validated_ip).

    Pinning DNS to the returned IP for the actual fetch guarantees the
    connect() goes to the address we just classified as public.

    Raises:
        UnsafeURLError: scheme/host invalid, host blocked, no resolution, or
        any resolved IP is private/loopback/link-local/multicast/reserved.
    """
    try:
        parsed = urlparse(url)
    except (ValueError, TypeError) as exc:
        raise UnsafeURLError("invalid URL") from exc
    if parsed.scheme not in ("http", "https"):
        raise UnsafeURLError("scheme must be http or https")
    host = parsed.hostname
    if not host:
        raise UnsafeURLError("URL must include a hostname")
    if host.lower() in BLOCKED_HOSTS:
        raise UnsafeURLError("host is blocked")

    # Use the REAL getaddrinfo so we never validate against a value we ourselves
    # pinned in a previous iteration of the redirect loop.
    try:
        infos = _real_getaddrinfo(host, parsed.port)
    except socket.gaierror as exc:
        raise UnsafeURLError("could not resolve hostname") from exc

    safe_ip = None
    for info in infos:
        ip_str = info[4][0].split("%", 1)[0]  # strip IPv6 zone id if present
        try:
            ip = ipaddress.ip_address(ip_str)
        except ValueError:
            continue
        if (ip.is_private or ip.is_loopback or ip.is_link_local
                or ip.is_multicast or ip.is_reserved or ip.is_unspecified):
            raise UnsafeURLError("host resolves to a private/internal IP")
        if safe_ip is None:
            safe_ip = ip_str
    if safe_ip is None:
        raise UnsafeURLError("could not resolve hostname")
    return host, safe_ip


def _validate_url_safe(url: str) -> str | None:
    """Return None if the URL is safe to fetch, otherwise a short reason string.

    Thin wrapper around _resolve_safe for callers (e.g. the Playwright fallback)
    that don't need the resolved IP.
    """
    try:
        _resolve_safe(url)
    except UnsafeURLError as exc:
        return str(exc)
    return None


def _safe_get(url, *, headers=None, timeout=REQUEST_TIMEOUT,
              max_bytes=MAX_PAGE_BYTES, allow_redirects=True,
              max_redirects=MAX_REDIRECTS):
    """HTTP GET with SSRF validation, manual redirect handling, DNS-pinning, and bounded body size.

    Raises:
        UnsafeURLError: URL or any redirect target fails validation, or redirect limit exceeded.
        requests.exceptions.RequestException: forwarded from underlying requests.get.

    Returns:
        requests.Response with the body fully read into ``_content`` (truncated at
        ``max_bytes``). ``response.url`` is set to the final URL after redirects.
    """
    current_url = url
    redirects_remaining = max_redirects if allow_redirects else 0
    while True:
        # Validate AND get the IP to pin. Done outside the pin context so the
        # validator's getaddrinfo call always hits the real DNS.
        hostname, pinned_ip = _resolve_safe(current_url)

        # Pin the validated IP for the duration of this single fetch. The TCP
        # connect inside requests.get() will use this IP via _patched_getaddrinfo;
        # SNI/Host/cert verification still use the original hostname because the
        # URL itself is unchanged.
        with _DNSPin(hostname, pinned_ip):
            resp = requests.get(current_url, headers=headers or {}, timeout=timeout,
                                allow_redirects=False, stream=True)
            if resp.is_redirect and allow_redirects:
                location = resp.headers.get("Location")
                resp.close()
                if not location:
                    raise UnsafeURLError("redirect with no Location header")
                if redirects_remaining <= 0:
                    raise UnsafeURLError("too many redirects")
                redirects_remaining -= 1
                current_url = urljoin(current_url, location)
                continue

            # Read up to max_bytes, then stop. Truncation is silent — detectors
            # operate on whatever fits in the cap. Body read happens inside the
            # pinned context to keep the connection's IP consistent if urllib3
            # ever needs to reconnect mid-stream.
            content = bytearray()
            try:
                for chunk in resp.iter_content(chunk_size=8192):
                    if not chunk:
                        continue
                    content.extend(chunk)
                    if len(content) >= max_bytes:
                        content = content[:max_bytes]
                        break
            finally:
                resp.close()
        resp._content = bytes(content)
        resp.url = current_url
        return resp


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

_UNCAPPED = float("inf")

TIER_CAPS = {
    Tier.DEFINITIVE: _UNCAPPED,  # definitive proof should dominate, no per-tier ceiling
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
        # (signal, tier) pairs already added — used by add() to dedupe.
        self._seen = {(f.signal, f.tier) for f in self.findings}

    def add(self, finding: "Finding") -> bool:
        """Append a finding only if (signal, tier) hasn't been recorded yet.

        Returns True if added, False if it was a duplicate. Use this instead of
        ``self.findings.append(...)`` whenever a detection path could fire more
        than once for the same evidence (e.g. iterating multiple pages).
        """
        key = (finding.signal, finding.tier)
        if key in self._seen:
            return False
        self._seen.add(key)
        self.findings.append(finding)
        return True

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

# Generic page titles. The trailing \b prevents matching real titles whose first
# word merely shares a prefix (e.g. "My Apparel Co." starts with "my app" but is
# not a generic title — \b requires a word boundary after the prefix).
GENERIC_TITLE_RE = re.compile(
    r"^(?:home|welcome|untitled|my app|my site|my website|"
    r"create next app|vite app|vite \+ react)\b",
    re.IGNORECASE,
)


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
            cap = TIER_CAPS[tier]
            capped = raw if cap == _UNCAPPED else min(raw, cap)
            tier_points[tier] = {
                "count": tier_counts.get(tier, 0),
                "raw_points": raw,
                "capped_points": capped,
                # Use null in JSON to signal "no cap" (Infinity is not valid JSON).
                "cap": None if cap == _UNCAPPED else cap,
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
                resp = _safe_get(url, headers=headers, timeout=REQUEST_TIMEOUT,
                                 max_bytes=MAX_PAGE_BYTES)
                resp.raise_for_status()
                return PageData(url, resp.text, CaseInsensitiveDict(resp.headers),
                                BeautifulSoup(resp.text, "lxml"))
            except UnsafeURLError as exc:
                # SSRF guard — never retry, never fall back to browser.
                logging.warning("Rejected unsafe URL %s: %s", url, exc)
                if is_primary:
                    return URL_NOT_ALLOWED_MESSAGE
                return None
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
            except Exception:
                # Log full exception details server-side, but return a generic message to the user.
                logging.exception("Unexpected error while fetching URL %s", url)
                if is_primary:
                    return "Failed to fetch the site due to an unexpected error. Please try again later."
                return None

        # ── Fallback: headless browser for protected sites ─────────────
        if needs_browser:
            browser_result = self._fetch_with_browser(url)
            if browser_result is not None:
                return browser_result
            # Browser fallback also failed — build a useful reason.
            if is_primary:
                if last_error == "blocked":
                    reason = "Connection blocked by the site's bot protection."
                elif last_error == "timeout":
                    reason = "Request timed out."
                elif isinstance(last_error, int) and last_error:
                    reason = f"HTTP {last_error}."
                else:
                    reason = "Unable to fetch the page."
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
            from playwright.sync_api import (
                sync_playwright,
                Error as PlaywrightError,
                TimeoutError as PlaywrightTimeoutError,
            )
        except ImportError:
            return None

        # SSRF check before launching the browser. Note: Playwright follows redirects
        # internally, so a public URL that 302s to a private IP is not blocked here.
        # The primary attack surface (user-supplied URL) is covered.
        err = _validate_url_safe(url)
        if err:
            logging.warning("Browser fallback rejected URL %s: %s", url, err)
            return None

        # Bound concurrent chromium launches. If the cap is saturated, skip the
        # fallback rather than queue (callers handle None) — keeps latency bounded
        # under load.
        if not _browser_semaphore.acquire(blocking=False):
            logging.warning("Browser fallback skipped (concurrency cap reached) for %s", url)
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
                headers = CaseInsensitiveDict(resp.headers) if resp else CaseInsensitiveDict()
                browser.close()

                if len(html) < 200:
                    return None  # Page likely didn't load properly

                return PageData(url, html, headers, BeautifulSoup(html, "lxml"))
        except (PlaywrightError, PlaywrightTimeoutError):
            logging.warning("Playwright fallback failed for %s", url, exc_info=True)
            return None
        finally:
            _browser_semaphore.release()

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
        # Hosts are case-insensitive — normalise scheme+host to lowercase before
        # dedupe so "Example.com/" and "example.com/" count as the same URL.
        def _normalise(u):
            parsed = urlparse(u)
            host = (parsed.hostname or "").lower()
            port = f":{parsed.port}" if parsed.port else ""
            path = parsed.path.rstrip("/")
            return f"{parsed.scheme.lower()}://{host}{port}{path}"

        base_origin_lower = base_origin.lower()
        seen = {_normalise(page.url)}
        links = []
        for a in page.soup.find_all("a", href=True):
            href = a["href"].strip()
            if href.startswith(("#", "javascript:", "mailto:", "tel:")):
                continue
            full = urljoin(page.url, href).split("#")[0].split("?")[0]
            norm = _normalise(full)
            if not norm.startswith(base_origin_lower) or norm in seen:
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
                r = _safe_get(url, headers=REQUEST_HEADERS, timeout=8,
                              max_bytes=MAX_ASSET_BYTES)
                r.raise_for_status()
                return url, r.text
            except UnsafeURLError as exc:
                logging.info("Skipping unsafe asset URL %s: %s", url, exc)
                return url, None
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
        html_all = "\n".join(p.html for p in pages)
        html_lower = html_all.lower()

        # ── v0.dev (DEFINITIVE if data attributes found) ────────────────
        v0_definitive = False
        for p in pages:
            if p.soup.find_all(attrs=lambda a: a and any(k.startswith("data-v0") for k in a)):
                cat.add(Finding("v0.dev", "data-v0-* attributes found — irrefutable v0.dev marker",
                                Tier.DEFINITIVE, "data-v0-* attributes"))
                v0_definitive = True
                break
        # Only add the weaker STRONG finding when no DEFINITIVE one fired.
        if not v0_definitive and "v0.dev" in html_lower:
            cat.add(Finding("v0.dev", "Reference to v0.dev in source", Tier.STRONG))

        # ── Bolt.new / StackBlitz ──────────────────────────────────────
        for marker in ["bolt.new", "stackblitz"]:
            if marker in html_lower:
                cat.add(Finding("Bolt.new", f"'{marker}' reference in source", Tier.STRONG))
        for p in pages:
            if p.soup.find_all(attrs={"data-bolt": True}):
                cat.add(Finding("Bolt.new", "data-bolt attributes — definitive Bolt marker",
                                Tier.DEFINITIVE))
                break

        # ── Lovable / GPTEngineer ──────────────────────────────────────
        for marker in ["lovable", "gptengineer", "gpt-engineer"]:
            if marker in html_lower:
                cat.add(Finding("Lovable", f"'{marker}' reference in source", Tier.STRONG))

        # ── Meta generator tag (DEFINITIVE) ────────────────────────────
        for p in pages:
            meta = p.soup.find("meta", attrs={"name": "generator"})
            if not meta:
                continue
            content = (meta.get("content") or "").lower()
            for name in ["v0", "bolt", "lovable", "gptengineer", "cursor", "windsurf", "replit"]:
                if name in content:
                    cat.add(Finding(name,
                                    f"Meta generator tag explicitly names '{name}'",
                                    Tier.DEFINITIVE, content))

        # ── Vercel AI SDK ──────────────────────────────────────────────
        if re.search(r"@vercel/ai|ai/react|useChat|useCompletion", html_all):
            cat.add(Finding("Vercel AI SDK", "Vercel AI SDK references", Tier.MODERATE))

        # ── Vibe-stack packages in JS bundles ──────────────────────────
        if asset_text:
            hits = [p for p in VIBE_PACKAGES if p in asset_text]
            if len(hits) >= 6:
                cat.add(Finding("Vibe Stack",
                                f"Found {len(hits)} vibe-coding packages in bundles — classic AI-scaffolded stack",
                                Tier.STRONG, ", ".join(hits[:6])))
            elif len(hits) >= 3:
                cat.add(Finding("Vibe Stack",
                                f"Found {len(hits)} vibe-coding packages in bundles",
                                Tier.MODERATE, ", ".join(hits)))

        # ── Replit ─────────────────────────────────────────────────────
        primary = pages[0]
        if ".repl.co" in primary.parsed.netloc or ".replit.dev" in primary.parsed.netloc:
            cat.add(Finding("Replit", "Hosted on Replit domain", Tier.MODERATE))
        if "replit" in html_lower:
            cat.add(Finding("Replit", "Replit reference in source", Tier.MODERATE))

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

        # Stock images. Modern lazy-loaders use any of these attributes to defer
        # the real URL until the image scrolls into view, so check them all.
        stock_hits = []
        img_src_attrs = ("src", "data-src", "data-srcset", "data-original",
                         "data-lazy", "data-lazy-src", "srcset")
        for page in pages:
            for img in page.soup.find_all("img"):
                src = " ".join(img.get(a, "") for a in img_src_attrs)
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

            # Get structural fingerprint for each section (first 20 tags in order).
            fingerprints = []
            for sec in sections:
                children_tags = []
                for child in sec.descendants:
                    if hasattr(child, "name") and child.name:
                        children_tags.append(child.name)
                        if len(children_tags) >= 20:
                            break  # avoid walking the whole subtree once we have enough
                fp = tuple(children_tags)
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

        # Missing basics. Treat 404 OR a 200 that obviously isn't the right doc
        # (SPA catch-all serving HTML for /sitemap.xml) as "missing".
        def _missing(url, expected_keywords):
            try:
                r = _safe_get(url, headers=REQUEST_HEADERS,
                              timeout=5, max_bytes=MAX_PROBE_BYTES)
            except (UnsafeURLError, requests.exceptions.RequestException):
                return False  # probe failed — don't claim "missing"
            if r.status_code >= 400:
                return True
            if r.status_code == 200:
                ctype = (r.headers.get("Content-Type") or "").lower()
                # SPA catch-all: served as HTML rather than the expected text/xml
                if "html" in ctype:
                    return True
                # Body sanity check: real robots/sitemap contains its keyword
                body = (r.text or "").lower()
                if body and not any(k in body for k in expected_keywords):
                    return True
            return False

        if _missing(f"{base_origin}/robots.txt", ("user-agent", "disallow", "allow", "sitemap")):
            F.append(Finding("No robots.txt", "Missing robots.txt", Tier.WEAK))
        if _missing(f"{base_origin}/sitemap.xml", ("<urlset", "<sitemapindex", "<url>", "<loc>")):
            F.append(Finding("No sitemap", "Missing sitemap.xml", Tier.WEAK))

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
            title_text = title.get_text(strip=True)
            if GENERIC_TITLE_RE.match(title_text):
                F.append(Finding("Generic Title",
                                 f"Page title is generic: '{title_text}'",
                                 Tier.MODERATE, title_text))

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
        """Maximum tag-nesting depth under ``el``, computed iteratively to avoid
        Python's recursion limit on pathologically deep DOMs."""
        if not hasattr(el, "children"):
            return d
        max_depth = d
        stack = [(el, d)]
        while stack:
            node, depth = stack.pop()
            if depth > max_depth:
                max_depth = depth
            children = getattr(node, "children", None)
            if children is None:
                continue
            for child in children:
                if hasattr(child, "name") and child.name:
                    stack.append((child, depth + 1))
        return max_depth

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
