# Security Policy

## Reporting a Vulnerability

If you find a security issue in VibeCheck, please **do not** open a public
issue. Email the maintainer at **jabble.ashish@gmail.com** with:

- A clear description of the issue and impact
- Steps to reproduce (or proof-of-concept request/response)
- The commit SHA or release version you observed it on
- Any suggested fix, if you have one

Expect an initial acknowledgement within **3 business days**. After triage,
we will share an estimated remediation timeline; critical issues are typically
fixed within 7 days, lower-severity issues within 30 days.

## Supported Versions

VibeCheck is a single-branch project. Security fixes land on `main` and are
deployed from there. There is no LTS branch.

## Scope

In scope:

- The Flask API (`/api/analyze`, `/`)
- The detection engine (`analyzer.py`) and its outbound fetch behavior
- Dependencies pinned in `requirements.txt`

Out of scope:

- Findings produced by analyzing third-party sites (the tool reports evidence;
  it does not vouch for those sites)
- Denial-of-service via heuristic-resistant inputs alone (rate limits and body
  caps are the mitigations; report bypasses, not raw load)
- Issues in the third-party hosting environment (Vercel, etc.)

## Hardening Already in Place

- **SSRF protection**: every outbound URL (primary, internal-link crawl,
  linked CSS/JS, `/robots.txt`, `/sitemap.xml`) is validated with
  `_validate_url_safe` and rejects non-http(s) schemes, blocked hostnames
  (`localhost`, GCP metadata), and any host resolving to a private/loopback/
  link-local/multicast/reserved IP. Redirects are followed manually with the
  same validation applied at every hop.
- **Body-size caps**: 5 MB pages, 500 KB CSS/JS assets, 200 KB probes.
- **Request body cap**: `MAX_CONTENT_LENGTH = 16 KB` on Flask.
- **Rate limiting**: `120/hour` global, `10/minute` and `60/hour` on
  `/api/analyze`. Override storage with `RATELIMIT_STORAGE_URI=redis://...`.
- **Playwright concurrency cap**: at most 2 chromium browsers run concurrently
  (override with `VIBECHECK_BROWSER_CONCURRENCY`).

## Known Limitations

- **Playwright + redirects**: when the requests-based fetch fails and we fall
  back to a headless browser, redirects are followed by chromium without our
  per-hop validation. Validation runs only on the user-supplied URL before the
  browser launches.
- **DNS rebinding**: the SSRF check resolves the hostname once before fetching;
  a determined attacker controlling DNS could in theory return a public IP at
  validation time and a private IP at fetch time. The window is small and the
  response body is not returned to the client (only scoring metadata).
