"""Boundary tests for aegis.models dataclasses."""

from aegis.models import AttackResult, Credential, EngagementContext, OpenPort


# ── OpenPort ────────────────────────────────────────────────────────────────

def test_openport_empty_strings():
    p = OpenPort(host="", port=0, service="")
    assert p.host == ""
    assert p.port == 0


def test_openport_max_port():
    p = OpenPort(host="10.0.0.1", port=65535, service="unknown")
    assert p.port == 65535


def test_openport_long_banner():
    p = OpenPort(host="10.0.0.1", port=22, service="SSH", banner="X" * 10000)
    assert len(p.banner) == 10000


def test_openport_special_chars_in_service():
    p = OpenPort(host="10.0.0.1", port=80, service="HTTP/1.1 <script>")
    assert "<script>" in p.service


def test_openport_ipv6_host():
    p = OpenPort(host="::1", port=443, service="HTTPS")
    assert p.host == "::1"


# ── AttackResult ────────────────────────────────────────────────────────────

def test_attackresult_empty_fields():
    r = AttackResult(module="", action="", status="")
    assert r.severity == "INFO"


def test_attackresult_all_statuses():
    for status in ("SUCCESS", "FAILED", "PARTIAL", "INFO"):
        r = AttackResult(module="test", action="test", status=status)
        assert r.status == status


def test_attackresult_long_notes():
    r = AttackResult(module="scan", action="test", status="SUCCESS", notes="N" * 50000)
    assert len(r.notes) == 50000


def test_attackresult_unicode_notes():
    r = AttackResult(module="scan", action="test", status="SUCCESS", notes="تست فارسی 日本語")
    assert "فارسی" in r.notes


def test_attackresult_none_data():
    r = AttackResult(module="scan", action="test", status="SUCCESS", data=None)
    assert r.data is None


# ── Credential ──────────────────────────────────────────────────────────────

def test_credential_empty_password():
    c = Credential(service="FTP", host="10.0.0.1", port=21, username="anonymous", password="")
    assert c.password == ""


def test_credential_very_long_password():
    c = Credential(service="SSH", host="10.0.0.1", port=22, username="root", password="P" * 10000)
    assert len(c.password) == 10000


def test_credential_special_chars():
    c = Credential(service="SSH", host="10.0.0.1", port=22, username="admin'--", password='"; DROP TABLE')
    assert "'" in c.username


def test_credential_hash_val():
    c = Credential(service="SMB", host="10.0.0.1", port=445, username="admin", password="",
                   hash_val="aad3b435b51404ee:8846f7eaee8fb117")
    assert ":" in c.hash_val


def test_credential_unicode_username():
    c = Credential(service="HTTP", host="10.0.0.1", port=80, username="用户", password="密码")
    assert c.username == "用户"


# ── EngagementContext ───────────────────────────────────────────────────────

def test_context_empty():
    ctx = EngagementContext()
    assert ctx.targets == []
    assert ctx.open_ports == []


def test_context_many_targets():
    targets = [f"10.0.{i}.{j}" for i in range(256) for j in range(1, 3)]
    ctx = EngagementContext(targets=targets)
    assert len(ctx.targets) == 512


def test_context_zero_threads():
    ctx = EngagementContext(threads=0)
    assert ctx.threads == 0


def test_context_negative_timeout():
    ctx = EngagementContext(timeout=-1.0)
    assert ctx.timeout == -1.0


def test_context_loot_nested():
    ctx = EngagementContext()
    ctx.loot["deep"] = {"level1": {"level2": {"level3": [1, 2, 3]}}}
    assert ctx.loot["deep"]["level1"]["level2"]["level3"] == [1, 2, 3]
