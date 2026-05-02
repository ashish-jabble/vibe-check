"""Unit tests for the DNS-pinning context manager.

The pin is what closes the rebinding window between SSRF validation and the
actual TCP connect. These tests verify that pins take effect, fall through for
unrelated hostnames, restore prior state, and don't leak between threads.
"""
from __future__ import annotations

import socket
import threading

import pytest

from analyzer import _DNSPin, _patched_getaddrinfo


def test_socket_getaddrinfo_is_patched_at_import():
    """The patch is installed at module load — every socket consumer goes through it."""
    assert socket.getaddrinfo is _patched_getaddrinfo


class TestDNSPin:
    def test_ipv4_pin_returns_synthetic_answer(self):
        with _DNSPin("example.com", "93.184.216.34"):
            result = socket.getaddrinfo("example.com", 443)
        assert result[0][0] == socket.AF_INET
        assert result[0][4][0] == "93.184.216.34"
        assert result[0][4][1] == 443  # port preserved

    def test_ipv6_pin_returns_synthetic_answer(self):
        with _DNSPin("example.com", "2606:2800:220::1"):
            result = socket.getaddrinfo("example.com", 443)
        assert result[0][0] == socket.AF_INET6
        assert result[0][4][0] == "2606:2800:220::1"

    def test_pin_scoped_to_one_hostname(self, monkeypatch):
        """Pinning example.com must not poison google.com lookups."""
        # Stub _real_getaddrinfo so this test never touches DNS
        sentinel = [(socket.AF_INET, 1, 6, "", ("99.99.99.99", 0))]
        monkeypatch.setattr("analyzer._real_getaddrinfo", lambda *a, **k: sentinel)
        with _DNSPin("example.com", "1.2.3.4"):
            other = socket.getaddrinfo("google.com", 443)
        assert other[0][4][0] == "99.99.99.99"

    def test_pin_cleared_after_with_block(self, monkeypatch):
        sentinel = [(socket.AF_INET, 1, 6, "", ("99.99.99.99", 0))]
        monkeypatch.setattr("analyzer._real_getaddrinfo", lambda *a, **k: sentinel)
        with _DNSPin("example.com", "1.2.3.4"):
            pass
        result = socket.getaddrinfo("example.com", 443)
        assert result[0][4][0] == "99.99.99.99"

    def test_nested_pins_restore_outer_value(self, monkeypatch):
        sentinel = [(socket.AF_INET, 1, 6, "", ("99.99.99.99", 0))]
        monkeypatch.setattr("analyzer._real_getaddrinfo", lambda *a, **k: sentinel)
        with _DNSPin("example.com", "1.1.1.1"):
            with _DNSPin("example.com", "2.2.2.2"):
                inner = socket.getaddrinfo("example.com", 443)[0][4][0]
            outer = socket.getaddrinfo("example.com", 443)[0][4][0]
        cleared = socket.getaddrinfo("example.com", 443)[0][4][0]
        assert (inner, outer, cleared) == ("2.2.2.2", "1.1.1.1", "99.99.99.99")

    def test_thread_local_isolation(self):
        """Two threads pinning the same hostname to different IPs must not collide."""
        results: dict[str, str] = {}
        barrier = threading.Barrier(2)

        def worker(name: str, ip: str):
            with _DNSPin("example.com", ip):
                # Synchronize so both threads have set up their pins simultaneously
                barrier.wait()
                results[name] = socket.getaddrinfo("example.com", 443)[0][4][0]

        t1 = threading.Thread(target=worker, args=("t1", "1.1.1.1"))
        t2 = threading.Thread(target=worker, args=("t2", "2.2.2.2"))
        t1.start(); t2.start()
        t1.join(); t2.join()
        assert results == {"t1": "1.1.1.1", "t2": "2.2.2.2"}

    def test_pin_falls_through_for_unrelated_host(self, monkeypatch):
        called_for: list[str] = []
        def real(host, *_a, **_k):
            called_for.append(host)
            return [(socket.AF_INET, 1, 6, "", ("8.8.8.8", 0))]
        monkeypatch.setattr("analyzer._real_getaddrinfo", real)
        with _DNSPin("a.com", "1.1.1.1"):
            socket.getaddrinfo("b.com", 80)
        assert called_for == ["b.com"]
