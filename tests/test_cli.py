"""Tests for CLI argument parsing."""

from aegis.cli import MODULE_REGISTRY, build_parser


def test_all_modules_registered():
    expected = {"scan", "enum", "cred", "lateral", "tunnel", "iot"}
    assert set(MODULE_REGISTRY.keys()) == expected


def test_default_modules():
    p = build_parser()
    args = p.parse_args(["--targets", "10.0.0.1"])
    assert args.modules == ["scan"]


def test_threads_default():
    p = build_parser()
    args = p.parse_args(["--targets", "10.0.0.1"])
    assert args.threads == 50


def test_stealth_flag():
    p = build_parser()
    args = p.parse_args(["--targets", "10.0.0.1", "--stealth"])
    assert args.stealth is True


def test_domain_flag():
    p = build_parser()
    args = p.parse_args(["--targets", "10.0.0.1", "--modules", "enum", "--domain", "corp.local"])
    assert args.domain == "corp.local"
