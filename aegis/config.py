"""Constants and configuration for Aegis."""

from __future__ import annotations

from aegis import __version__, __author__

TOOL_NAME = "Aegis Framework"
VERSION = __version__
AUTHOR = __author__
COMMAND = "aegis"

LEGAL_WARNING = """
╔══════════════════════════════════════════════════════════════════════════════╗
║         ⚠   AEGIS — AUTHORIZED RED TEAM USE ONLY   ⚠                       ║
╠══════════════════════════════════════════════════════════════════════════════╣
║  This framework executes REAL network attacks: port scanning, SMB credential ║
║  capture, LDAP enumeration, protocol exploitation, lateral movement,         ║
║  password spraying, and C2 tunneling.                                        ║
║                                                                              ║
║  Requirements before use:                                                   ║
║    ✓ Written authorization from the target organization                     ║
║    ✓ Defined IP/subnet scope                                                ║
║    ✓ Rules of engagement signed off                                         ║
║                                                                              ║
║  The author (arkanzasfeziii) accepts NO LIABILITY for misuse.               ║
╚══════════════════════════════════════════════════════════════════════════════╝
"""
