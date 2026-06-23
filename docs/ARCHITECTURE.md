# Architecture

## Package Structure

```
aegis/
├── cli.py               # Argument parsing, module dispatch
├── config.py            # Tool metadata, legal warning
├── models.py            # OpenPort, AttackResult, Credential, EngagementContext
├── logger.py            # Colored terminal logging
├── output.py            # Banner, results, JSON export
├── exceptions.py        # Typed exceptions
│
├── modules/
│   ├── base.py          # BaseModule ABC
│   ├── scan.py          # TCP port scanner with banner grabbing
│   ├── enum.py          # SMB, LDAP, DNS, SNMP enumeration
│   ├── cred.py          # SSH spray, FTP anon, Redis/ES/Mongo/Memcached unauth
│   ├── lateral.py       # PSExec-style SMB exec, SSH command execution
│   ├── tunnel.py        # DNS exfiltration, HTTP beacon C2
│   └── iot.py           # MQTT, Modbus, BACnet, Telnet, IoT web panels
│
├── utils/
│   └── network.py       # TCP connect, banner grab, CIDR expand, stealth sleep
│
└── data/
    └── ports.py         # Top ports, service map, default creds, SNMP OIDs
```

## Key Design

**EngagementContext as shared state**: Scan results feed enumeration,
credential successes feed lateral movement. Nothing is isolated.

**BaseModule ABC**: All modules implement `run(ctx, **kwargs) -> List[AttackResult]`.
Adding a new protocol means one file + registration in MODULE_REGISTRY.
