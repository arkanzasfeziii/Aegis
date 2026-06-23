"""Tests for network utilities."""

from aegis.utils.network import expand_targets


def test_expand_single_ip():
    result = expand_targets(["10.0.0.1"])
    assert result == ["10.0.0.1"]


def test_expand_cidr_24():
    result = expand_targets(["10.0.0.0/30"])
    assert len(result) == 2
    assert "10.0.0.1" in result
    assert "10.0.0.2" in result


def test_expand_hostname():
    result = expand_targets(["example.com"])
    assert result == ["example.com"]


def test_expand_mixed():
    result = expand_targets(["10.0.0.1", "192.168.0.0/30", "host.local"])
    assert "10.0.0.1" in result
    assert "host.local" in result
    assert len(result) == 4
