"""Tests for data models."""

from aegis.models import AttackResult, Credential, EngagementContext, OpenPort


def test_open_port():
    p = OpenPort(host="10.0.0.1", port=22, service="SSH", banner="OpenSSH_8.9")
    assert p.host == "10.0.0.1"
    assert p.version == ""


def test_attack_result_defaults():
    r = AttackResult(module="scan", action="open_port", status="SUCCESS")
    assert r.severity == "INFO"
    assert r.host == ""


def test_credential():
    c = Credential(service="SSH", host="10.0.0.1", port=22,
                   username="root", password="toor")
    assert c.hash_val == ""


def test_engagement_context_defaults():
    ctx = EngagementContext()
    assert ctx.threads == 50
    assert ctx.timeout == 2.0
    assert ctx.stealth is False
    assert ctx.open_ports == []
    assert ctx.credentials == []
