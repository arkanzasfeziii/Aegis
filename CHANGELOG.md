# Changelog

## [2.0.0] - 2026-06-23

### Changed
- Complete rewrite from single-file to modular package architecture
- Each protocol/attack vector is an independent module under aegis/modules/
- Network utilities extracted to aegis/utils/network.py
- Port data and credentials extracted to aegis/data/ports.py

### Added
- aegis/modules/base.py — abstract base module
- aegis/utils/network.py — TCP connect, banner grab, target expansion
- aegis/exceptions.py — typed exception hierarchy
- 17 unit tests (models, network, ports, CLI)
- Dockerfile, CHANGELOG.md
- docs/ARCHITECTURE.md

## [1.0.0] - 2026-06-19

### Added
- Initial release: port scanning, SMB/LDAP/DNS/SNMP enumeration,
  credential attacks, lateral movement, C2 tunneling, IoT/OT attacks
