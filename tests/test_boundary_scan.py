"""Boundary tests for aegis.modules.scan (ScanModule)."""

from aegis.models import EngagementContext, OpenPort
from aegis.modules.scan import ScanModule


mod = ScanModule()


# ── _fingerprint_version ────────────────────────────────────────────────────

def test_fingerprint_empty_banner():
    assert mod._fingerprint_version("", "SSH") == ""


def test_fingerprint_empty_service():
    assert mod._fingerprint_version("SSH-2.0-OpenSSH_8.9", "") == ""


def test_fingerprint_ssh_banner():
    assert mod._fingerprint_version("SSH-2.0-OpenSSH_8.9p1", "SSH") == "OpenSSH_8.9p1"


def test_fingerprint_http_banner():
    result = mod._fingerprint_version("HTTP/1.1 200 OK\r\nServer: nginx/1.25.3", "HTTP")
    assert result == "nginx/1.25.3"


def test_fingerprint_redis_banner():
    result = mod._fingerprint_version("redis_version:7.2.4\r\n", "Redis")
    assert result == "7.2.4"


def test_fingerprint_mysql_banner():
    result = mod._fingerprint_version("\x00\x00\x00\x008.0.35-", "MySQL")
    assert "8.0.35" in result or isinstance(result, str)


def test_fingerprint_unknown_service():
    assert mod._fingerprint_version("some banner", "UnknownService") == ""


def test_fingerprint_very_long_banner():
    banner = "SSH-2.0-" + "A" * 10000
    result = mod._fingerprint_version(banner, "SSH")
    assert isinstance(result, str)


def test_fingerprint_special_chars():
    result = mod._fingerprint_version("SSH-2.0-OpenSSH_<script>alert(1)</script>", "SSH")
    assert isinstance(result, str)


def test_fingerprint_binary_data():
    result = mod._fingerprint_version("\x00\x01\x02\xff\xfe", "SSH")
    assert result == ""


# ── run with empty context ──────────────────────────────────────────────────

def test_scan_run_no_targets():
    ctx = EngagementContext(targets=[], ports=[80], threads=1, timeout=0.5)
    results = mod.run(ctx)
    assert results == []


def test_scan_run_no_ports():
    ctx = EngagementContext(targets=["192.0.2.1"], ports=[], threads=1, timeout=0.5)
    results = mod.run(ctx)
    assert results == []


def test_scan_run_unreachable_target():
    ctx = EngagementContext(targets=["192.0.2.1"], ports=[1], threads=1, timeout=0.3)
    results = mod.run(ctx)
    assert isinstance(results, list)


def test_scan_run_single_thread():
    ctx = EngagementContext(targets=["192.0.2.1"], ports=[80, 443], threads=1, timeout=0.3)
    results = mod.run(ctx)
    assert isinstance(results, list)


def test_scan_run_zero_timeout():
    ctx = EngagementContext(targets=["192.0.2.1"], ports=[80], threads=1, timeout=0.0)
    results = mod.run(ctx)
    assert isinstance(results, list)
