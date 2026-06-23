"""Tests for port data."""

from aegis.data.ports import PORT_SERVICES, TOP_PORTS, DEFAULT_CREDS


def test_top_ports_not_empty():
    assert len(TOP_PORTS) > 40


def test_port_services_mapping():
    assert PORT_SERVICES[22] == "SSH"
    assert PORT_SERVICES[445] == "SMB"
    assert PORT_SERVICES[80] == "HTTP"


def test_default_creds_not_empty():
    assert len(DEFAULT_CREDS) > 10


def test_common_ports_in_top():
    for port in [22, 80, 443, 445, 3389]:
        assert port in TOP_PORTS
