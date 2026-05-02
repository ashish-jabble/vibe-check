"""Unit tests for the SSRF validator.

These exercise _validate_url_safe and _resolve_safe purely via IP literals and
mocked DNS, so they don't need outbound network access.
"""
from __future__ import annotations

import socket

import pytest

from analyzer import (
    BLOCKED_HOSTS,
    UnsafeURLError,
    _resolve_safe,
    _validate_url_safe,
)


class TestValidateUrlSafe:
    @pytest.mark.parametrize("url", [
        "http://127.0.0.1",
        "http://10.0.0.1",
        "http://192.168.1.1",
        "http://172.16.0.1",
        "http://169.254.169.254",       # AWS metadata
        "http://[::1]/",                # IPv6 loopback
        "http://2130706433/",           # decimal-encoded 127.0.0.1
        "http://0.0.0.0",
    ])
    def test_rejects_private_ip_literals(self, url):
        assert _validate_url_safe(url) is not None

    @pytest.mark.parametrize("scheme", ["ftp", "file", "javascript", "gopher"])
    def test_rejects_non_http_schemes(self, scheme):
        assert _validate_url_safe(f"{scheme}://example.com") == "scheme must be http or https"

    @pytest.mark.parametrize("host", sorted(BLOCKED_HOSTS))
    def test_rejects_blocked_hosts(self, host):
        assert _validate_url_safe(f"http://{host}") == "host is blocked"

    def test_rejects_missing_hostname(self):
        # urlparse("http://") returns hostname=None
        assert "hostname" in (_validate_url_safe("http://") or "")

    def test_rejects_invalid_url(self):
        # urlparse on bytes / non-str raises
        assert _validate_url_safe(None) is not None  # type: ignore[arg-type]


class TestResolveSafe:
    """_resolve_safe is the validator that returns (host, ip). Use monkeypatch
    on _real_getaddrinfo to drive it without real DNS."""

    def _stub(self, ip: str):
        family = socket.AF_INET6 if ":" in ip else socket.AF_INET
        sa = (ip, 0, 0, 0) if family == socket.AF_INET6 else (ip, 0)
        return [(family, socket.SOCK_STREAM, socket.IPPROTO_TCP, "", sa)]

    def test_returns_host_and_ip_for_public_address(self, monkeypatch):
        monkeypatch.setattr("analyzer._real_getaddrinfo",
                            lambda h, p, *a, **k: self._stub("93.184.216.34"))
        host, ip = _resolve_safe("https://example.com/path?q=1")
        assert host == "example.com"
        assert ip == "93.184.216.34"

    def test_strips_ipv6_zone_id(self, monkeypatch):
        # A real edge case: getaddrinfo can return "fe80::1%lo0" — the %lo0 must be stripped
        # before ipaddress.ip_address parses it. Use a public-looking IPv6 to confirm
        # strip happens regardless of classification.
        monkeypatch.setattr("analyzer._real_getaddrinfo",
                            lambda h, p, *a, **k: [(socket.AF_INET6, 1, 6, "",
                                                    ("2606:2800:220::1%eth0", 0, 0, 0))])
        host, ip = _resolve_safe("https://example.com")
        assert ip == "2606:2800:220::1"

    def test_rejects_when_dns_returns_private_ip(self, monkeypatch):
        # Defends against an attacker who points a public hostname at a private IP
        monkeypatch.setattr("analyzer._real_getaddrinfo",
                            lambda h, p, *a, **k: self._stub("10.0.0.1"))
        with pytest.raises(UnsafeURLError, match="private/internal"):
            _resolve_safe("http://attacker.example")

    def test_picks_first_safe_ip_in_mixed_answer_set(self, monkeypatch):
        # Real-world DNS often returns mixed sets (e.g. dual-stack NAT64).
        # The validator must skip the private/reserved IPs and pin the first
        # safe one. _DNSPin then forces the connect to that safe IP, so the
        # private IP in the answer is never contacted.
        monkeypatch.setattr("analyzer._real_getaddrinfo",
                            lambda h, p, *a, **k: self._stub("10.0.0.1") + self._stub("93.184.216.34"))
        host, ip = _resolve_safe("http://example.com")
        assert ip == "93.184.216.34"

    def test_rejects_when_all_resolved_ips_are_unsafe(self, monkeypatch):
        # If EVERY answer is private, fail closed with a distinct message.
        monkeypatch.setattr("analyzer._real_getaddrinfo",
                            lambda h, p, *a, **k: self._stub("10.0.0.1") + self._stub("192.168.1.1"))
        with pytest.raises(UnsafeURLError, match="only to private/internal"):
            _resolve_safe("http://attacker.example")

    def test_raises_on_unresolvable_host(self, monkeypatch):
        def boom(*_a, **_k):
            raise socket.gaierror("no such host")
        monkeypatch.setattr("analyzer._real_getaddrinfo", boom)
        with pytest.raises(UnsafeURLError, match="resolve"):
            _resolve_safe("http://nope.invalid")

    def test_raises_on_blocked_host_without_dns_lookup(self, monkeypatch):
        # Blocked-host check must run BEFORE DNS — otherwise we'd be doing DNS for
        # localhost variants that we'll reject anyway.
        called = []
        def spy(*a, **k):
            called.append(a)
            return self._stub("127.0.0.1")
        monkeypatch.setattr("analyzer._real_getaddrinfo", spy)
        with pytest.raises(UnsafeURLError, match="blocked"):
            _resolve_safe("http://localhost")
        assert called == [], "DNS should not be called for blocked hosts"

    @pytest.mark.parametrize("scheme", ["ftp", "file", "javascript"])
    def test_raises_on_non_http_scheme(self, scheme):
        with pytest.raises(UnsafeURLError, match="http"):
            _resolve_safe(f"{scheme}://example.com")
