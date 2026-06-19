# Aegis — Offensive Network Attack Framework

> **Enumerate, credential-spray, move laterally, and exfiltrate — across every protocol layer an enterprise network exposes.**

---

## Threat Model

An enterprise network is never a flat surface. It is an ecosystem of unpatched legacy services, misconfigured protocols, and overlooked defaults — each one a stepping stone.

Aegis simulates the adversary who starts from a foothold inside the perimeter and methodically converts protocol exposure into access:

| Stage | What Fails | Adversary Action |
|---|---|---|
| **Discovery** | Open ports on internal subnets behind overly permissive firewall rules | TCP sweep with banner grabbing across /24 blocks |
| **Enumeration** | SMB null sessions never disabled after Windows 2003 migration | Enumerate shares, hunt sensitive filenames, detect signing disabled |
| **Enumeration** | LDAP anonymous bind left enabled on AD domain controllers | Dump all users, groups, Domain Admins — including passwords stored in descriptions |
| **Credential Access** | Redis, Elasticsearch, MongoDB, Memcached deployed without authentication | Command execution, data extraction, full keyspace dump |
| **Lateral Movement** | Service accounts with weak passwords, no network segmentation between workloads | PSExec-style SCMR service creation; SSH exec on Linux hosts |
| **Exfiltration** | DNS egress never monitored; HTTP beacons indistinguishable from normal traffic | Data encoded as base32 over DNS subdomain labels; payload in User-Agent header |
| **OT/IoT** | Modbus/TCP, MQTT, and BACnet running on default settings in flat networks | Register read, topic subscription, device discovery |

**Scope:** Authorized red team engagements and adversary simulation against enterprise environments where the goal is to identify attack paths before the actual adversary does.

---

## Why This Exists

Enterprise networks accumulate protocol debt. Every tool in the scanner category identifies open ports. None of them answer the question that matters: *"If an attacker sits here, what happens next?"*

Aegis chains the answer:

- A port scan becomes a target list for protocol-specific enumeration
- An anonymous LDAP bind becomes a full user roster with Domain Admin membership
- An unauthenticated Redis instance becomes lateral movement without touching credential stores
- A successful credential becomes a PSExec shell becomes a C2 channel over DNS

The framework is built around an `EngagementContext` — a shared state object that accumulates discovered open ports, valid credentials, and loot across every module so findings compound rather than sit in disconnected report sections.

---

## Capabilities

### Network Discovery & Fingerprinting
- Concurrent TCP port scanner across top-50 ports with configurable thread pool
- CIDR expansion — scan `/24` blocks as a single target expression
- Banner grabbing with version extraction via regex: SSH, HTTP, FTP, SMTP, Redis, MySQL
- Service fingerprinting that identifies what's running before deciding which module fires next

### Protocol Enumeration
| Protocol | What Aegis Tests |
|---|---|
| **SMB** | Null session authentication · Share enumeration · Sensitive filename hunt (passwords, backup, private) · SMB signing disabled detection |
| **LDAP** | Anonymous bind feasibility · Full user/group dump · `password` in description field detection · Domain Admin group membership |
| **DNS** | Zone transfer (AXFR) against all NS records · Subdomain brute-force across wordlist |
| **SNMP** | Community string brute-force · Full OID walk (sysDescr, ifTable, hrSWInstalled, hrStorageTable) |

### Credential Attacks
- SSH password spray via Paramiko (rate-limited with configurable delay)
- SMB authentication spray via Impacket
- FTP anonymous login detection
- Unauthenticated service access: Redis (`INFO` command), Elasticsearch (`/_cat/indices`), MongoDB (wire protocol), Memcached (`stats` command)
- HTTP panel default credential testing across admin endpoints

### Lateral Movement
- SMB lateral movement via SCMR service creation (PSExec-style) — creates a temporary service, executes command, reads output from `C$`, removes service
- SSH command execution with credential reuse across discovered hosts

### Command & Control — Exfiltration Channels
- **DNS tunnel:** Data encoded as base32, chunked into DNS subdomain labels, exfiltrated via standard DNS queries — bypasses HTTP-layer proxies and DLP appliances
- **HTTP beacon:** Reconnaissance data embedded in `User-Agent` headers — blends into ambient HTTPS traffic patterns

### OT / IoT Coverage
- MQTT: Subscribe to `#` wildcard topic — captures all published messages across the broker
- Modbus/TCP: Holding register read (FC 0x03) — reads PLC process data without authentication
- BACnet: Who-Is broadcast discovery — enumerates building automation devices
- Telnet: Default credential testing on discovered port 23
- Web admin panels: Default credential spray across `/admin`, `/login`, `/management` endpoints

---

## Architecture

```
Targets (IP · CIDR · hostname list)
            │
            ▼
    EngagementContext
  ┌─────────────────────────────────────┐
  │  targets · ports · threads          │
  │  open_ports · credentials · loot    │
  │  stealth mode · delay               │
  └─────────────────────────────────────┘
            │
     ┌──────┼──────┐
     ▼      ▼      ▼
 ScanModule  →  EnumModule  →  CredAttackModule
  TCP sweep     SMB/LDAP/        spray + default
  banner grab   DNS/SNMP         unauthenticated
     │
     ▼
 LateralModule  →  TunnelModule  →  IoTModule
  PSExec/SSH        DNS C2           MQTT/Modbus
  exec chains       HTTP beacon      BACnet/Telnet
            │
            ▼
     JSON Report
  (loot · creds · open_ports · severity)
```

Each module reads from and writes back to `EngagementContext`. The scan results feed enumeration targets; credential successes feed lateral movement targets. Nothing is isolated.

---

## Attack Flow

1. **Target expansion** — CIDR notation expands to individual host list; `--targets` accepts mixed IP, CIDR, and hostname inputs
2. **Concurrent TCP sweep** — ThreadPoolExecutor scans top-50 ports with configurable thread count; open ports stored in context
3. **Banner acquisition** — raw socket banner grab on each open port; version strings extracted via regex patterns
4. **Protocol enumeration** — ScanModule results drive EnumModule: SMB hosts get null session testing; LDAP port triggers anonymous bind; DNS ports get zone transfer attempts; SNMP port 161 gets community string brute-force
5. **Credential attacks** — all identified services tested for default or weak credentials; successes stored in `EngagementContext.credentials`
6. **Lateral chain** — valid SSH/SMB credentials from CredAttackModule passed directly to LateralModule; PSExec service created, command executed, output retrieved, service removed
7. **Data exfiltration** — discovered loot base32-encoded and transmitted as DNS subdomain queries to operator-controlled resolver; HTTP beacon option for environments where DNS is filtered
8. **OT/IoT sweep** — MQTT broker subscription, Modbus register read, BACnet device discovery run against identified OT-range hosts
9. **Report** — `--output report.json` produces structured findings with module, action, status, severity, and notes per finding

---

## Usage

```bash
# Install dependencies
pip install -r requirements.txt

# TCP scan a subnet, identify open services
python aegis.py --targets 192.168.1.0/24 --modules scan

# Full protocol enumeration against a domain controller
python aegis.py --targets 10.0.0.5 --modules enum --domain corp.local

# Credential attacks across discovered hosts
python aegis.py --targets 10.0.0.0/24 --modules cred

# Password spray over SMB with specific credential
python aegis.py --targets 10.0.0.5 --modules cred --spray-user jsmith --spray-pass "Summer2024!"

# Lateral movement using harvested credentials
python aegis.py --targets 10.0.0.8 --modules lateral --username svc-backup --password "found-cred"

# Full engagement chain — scan → enum → cred → lateral
python aegis.py --targets 10.0.0.0/24 --modules all --domain corp.local --output engagement.json

# Non-interactive mode (CI/pipeline use)
python aegis.py --targets 10.0.0.0/24 --modules all --yes --output results.json
```

---

## Output

```
13:41:01 [INFO]  [Scan] Expanding CIDR 10.0.0.0/24 → 254 hosts
13:41:02 [OK]    [Scan] OPEN  10.0.0.5:445    Windows Server 2019 SMB
13:41:02 [OK]    [Scan] OPEN  10.0.0.5:389    Microsoft LDAP
13:41:02 [OK]    [Scan] OPEN  10.0.0.8:6379   Redis 6.2.1
13:41:02 [OK]    [Scan] OPEN  10.0.0.12:22    OpenSSH_8.9

13:41:03 [CRIT]  [Enum/SMB] Null session authenticated on 10.0.0.5:445
13:41:03 [CRIT]  [Enum/SMB] Shares: ADMIN$, C$, Users, Backups, IT-Archive
13:41:03 [CRIT]  [Enum/SMB] Sensitive file: \\10.0.0.5\Backups\db_passwords.txt
13:41:03 [CRIT]  [Enum/SMB] SMB signing DISABLED — relay attacks feasible

13:41:04 [CRIT]  [Enum/LDAP] Anonymous bind accepted on 10.0.0.5:389
13:41:04 [INFO]  [Enum/LDAP] 312 user objects enumerated
13:41:04 [CRIT]  [Enum/LDAP] Domain Admins: Administrator, svc-backup, john.admin
13:41:04 [CRIT]  [Enum/LDAP] Password in description → svc-db: "Temp@1234 reset later"

13:41:05 [CRIT]  [Cred/Redis] Unauthenticated access confirmed — 10.0.0.8:6379
13:41:05 [INFO]  [Cred/Redis] Redis version: 6.2.1 | keyspace: db0 → 1,847 keys

13:41:06 [CRIT]  [Cred/SSH]  Valid credential → 10.0.0.12:22  svc-backup:Temp@1234
13:41:07 [CRIT]  [Lateral/SSH] Command exec success on 10.0.0.12 as svc-backup
13:41:07 [INFO]  [Tunnel/DNS] Exfiltrating 2.1KB via DNS subdomain encoding

[✓] Engagement complete — 4 critical findings | report: engagement.json
```

---

## MITRE ATT&CK Coverage

| Technique | ID | Module |
|---|---|---|
| Network Service Discovery | T1046 | ScanModule |
| Network Share Discovery | T1135 | EnumModule / SMB |
| Account Discovery: Domain Account | T1087.002 | EnumModule / LDAP |
| OS Credential Dumping: LSASS / Credential Stores | T1003 | CredAttackModule |
| Brute Force: Password Spraying | T1110.003 | CredAttackModule |
| Remote Services: SMB/Windows Admin Shares | T1021.002 | LateralModule |
| Remote Services: SSH | T1021.004 | LateralModule |
| Exfiltration Over Alternative Protocol: DNS | T1048.003 | TunnelModule |
| Application Layer Protocol: Web Protocols | T1071.001 | TunnelModule / HTTP |
| Exploit Public-Facing Application | T1190 | CredAttackModule (unauthenticated services) |

**Tactics:** TA0007 Discovery · TA0006 Credential Access · TA0008 Lateral Movement · TA0011 Command and Control · TA0010 Exfiltration

---

## CWE Coverage Exercised

| CWE | Description | Where |
|---|---|---|
| CWE-521 | Weak Password Requirements | SSH/SMB spray targets |
| CWE-306 | Missing Authentication for Critical Function | Redis, Elasticsearch, MongoDB, Memcached |
| CWE-200 | Exposure of Sensitive Information to Unauthorized Actor | LDAP anonymous bind, SMB null session |
| CWE-284 | Improper Access Control | Share enumeration, unauthenticated service access |
| CWE-522 | Insufficiently Protected Credentials | Passwords in LDAP description fields |

---

## Legal Notice

Aegis is designed exclusively for authorized penetration testing, red team engagements, and security assessment activities where explicit written permission has been obtained from the asset owner. Unauthorized use against systems you do not own or have permission to test is illegal in most jurisdictions. The author assumes no liability for misuse.
