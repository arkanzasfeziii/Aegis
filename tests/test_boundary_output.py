"""Boundary tests for aegis.output, aegis.logger, aegis.exceptions, aegis.cli."""

import os
import tempfile

from aegis.cli import build_parser
from aegis.config import TOOL_NAME
from aegis.exceptions import AegisError, DependencyError, ModuleError
from aegis.logger import log
from aegis.models import AttackResult, Credential, EngagementContext, OpenPort
from aegis.output import dump_results


# ── log ─────────────────────────────────────────────────────────────────────

def test_log_empty_message():
    log("", "INFO")


def test_log_unknown_level():
    log("test message", "NONEXISTENT")


def test_log_very_long_message():
    log("A" * 10000, "INFO")


def test_log_special_chars():
    log("test <>&\"'\\n\\t\\r\\0", "WARN")


def test_log_all_levels():
    for level in ("INFO", "OK", "WARN", "ERR", "CRIT", "SUCCESS"):
        log(f"testing {level}", level)


# ── dump_results ────────────────────────────────────────────────────────────

def test_dump_results_empty_context():
    ctx = EngagementContext()
    dump_results(ctx, None)


def test_dump_results_with_results():
    ctx = EngagementContext()
    ctx.results = [AttackResult("test", "action", "SUCCESS", severity="HIGH", notes="note")]
    dump_results(ctx, None)


def test_dump_results_with_credentials():
    ctx = EngagementContext()
    ctx.credentials = [Credential("SSH", "10.0.0.1", 22, "root", "toor")]
    dump_results(ctx, None)


def test_dump_results_with_open_ports():
    ctx = EngagementContext()
    ctx.open_ports = [OpenPort("10.0.0.1", 22, "SSH", "OpenSSH_8.9", "8.9")]
    dump_results(ctx, None)


def test_dump_results_to_file():
    ctx = EngagementContext()
    ctx.results = [AttackResult("test", "action", "SUCCESS")]
    with tempfile.NamedTemporaryFile(suffix=".json", delete=False) as f:
        path = f.name
    try:
        dump_results(ctx, path)
        assert os.path.exists(path)
        with open(path) as fh:
            content = fh.read()
            assert "test" in content
    finally:
        os.unlink(path)


# ── build_parser ────────────────────────────────────────────────────────────

def test_parser_minimal_args():
    p = build_parser()
    args = p.parse_args(["--targets", "10.0.0.1"])
    assert args.targets == ["10.0.0.1"]


def test_parser_multiple_targets():
    p = build_parser()
    args = p.parse_args(["--targets", "10.0.0.1", "10.0.0.2", "192.168.0.0/24"])
    assert len(args.targets) == 3


def test_parser_all_modules():
    p = build_parser()
    args = p.parse_args(["--targets", "x", "--modules", "all"])
    assert "all" in args.modules


def test_parser_custom_ports():
    p = build_parser()
    args = p.parse_args(["--targets", "x", "--ports", "22", "80", "443"])
    assert args.ports == [22, 80, 443]


def test_parser_stealth_with_delay():
    p = build_parser()
    args = p.parse_args(["--targets", "x", "--stealth", "--delay", "2.5"])
    assert args.stealth is True
    assert args.delay == 2.5


# ── exceptions ──────────────────────────────────────────────────────────────

def test_aegis_error_base():
    e = AegisError("test error")
    assert str(e) == "test error"


def test_module_error():
    e = ModuleError("scan failed")
    assert isinstance(e, AegisError)


def test_dependency_error_message():
    e = DependencyError("impacket")
    assert "impacket" in str(e)
    assert "pip install" in str(e)


def test_dependency_error_package_attr():
    e = DependencyError("ldap3")
    assert e.package == "ldap3"


def test_dependency_error_inherits():
    e = DependencyError("test")
    assert isinstance(e, AegisError)
