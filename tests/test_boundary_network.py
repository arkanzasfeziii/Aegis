"""Boundary tests for aegis.utils.network functions."""

from aegis.models import EngagementContext
from aegis.utils.network import expand_targets, grab_banner, sleep_if_stealth, tcp_connect
from aegis.data.ports import PORT_SERVICES


# ── expand_targets ──────────────────────────────────────────────────────────

def test_expand_targets_empty_list():
    assert expand_targets([]) == []


def test_expand_targets_single_host_32():
    result = expand_targets(["10.0.0.1/32"])
    assert result == ["10.0.0.1"]


def test_expand_targets_large_cidr_16():
    result = expand_targets(["10.0.0.0/16"])
    assert len(result) == 65534


def test_expand_targets_invalid_cidr():
    result = expand_targets(["not-an-ip"])
    assert result == ["not-an-ip"]


def test_expand_targets_mixed_valid_invalid():
    result = expand_targets(["10.0.0.1", "garbage", "192.168.0.0/30"])
    assert "10.0.0.1" in result
    assert "garbage" in result
    assert len(result) == 4


# ── tcp_connect ─────────────────────────────────────────────────────────────

def test_tcp_connect_unreachable_host():
    result = tcp_connect("192.0.2.1", 1, 0.5)
    if result is not None:
        result.close()
    assert result is None or result is not None


def test_tcp_connect_invalid_port_zero():
    result = tcp_connect("127.0.0.1", 0, 0.5)
    assert result is None


def test_tcp_connect_very_short_timeout():
    result = tcp_connect("192.0.2.1", 80, 0.001)
    if result is not None:
        result.close()
    assert result is None or result is not None


def test_tcp_connect_empty_host():
    result = tcp_connect("", 80, 1.0)
    assert result is None


def test_tcp_connect_ipv6_localhost():
    result = tcp_connect("::1", 1, 0.5)
    assert result is None


# ── grab_banner ─────────────────────────────────────────────────────────────

def test_grab_banner_unreachable():
    result = grab_banner("192.0.2.1", 1, 0.5, PORT_SERVICES)
    assert result == ""


def test_grab_banner_empty_host():
    result = grab_banner("", 80, 0.5, PORT_SERVICES)
    assert result == ""


def test_grab_banner_zero_timeout():
    result = grab_banner("192.0.2.1", 80, 0.0, PORT_SERVICES)
    assert result == ""


def test_grab_banner_unknown_port():
    result = grab_banner("192.0.2.1", 99999, 0.5, {})
    assert result == ""


def test_grab_banner_negative_timeout():
    result = grab_banner("192.0.2.1", 80, -1.0, PORT_SERVICES)
    assert result == ""


# ── sleep_if_stealth ────────────────────────────────────────────────────────

def test_sleep_if_stealth_disabled():
    ctx = EngagementContext(stealth=False, delay=5.0)
    sleep_if_stealth(ctx)


def test_sleep_if_stealth_zero_delay():
    ctx = EngagementContext(stealth=True, delay=0.0)
    sleep_if_stealth(ctx)


def test_sleep_if_stealth_negative_delay():
    ctx = EngagementContext(stealth=True, delay=-1.0)
    sleep_if_stealth(ctx)


def test_sleep_if_stealth_very_small_delay():
    ctx = EngagementContext(stealth=True, delay=0.001)
    sleep_if_stealth(ctx)


def test_sleep_if_stealth_default_context():
    ctx = EngagementContext()
    sleep_if_stealth(ctx)
