"""TCP port scanner with banner grabbing and service fingerprinting."""

from __future__ import annotations

import concurrent.futures
import re
import time
from typing import List, Optional

from aegis.models import AttackResult, EngagementContext, OpenPort
from aegis.logger import log
from aegis.modules.base import BaseModule
from aegis.utils.network import tcp_connect, grab_banner, expand_targets
from aegis.data.ports import PORT_SERVICES


class ScanModule(BaseModule):
    """TCP port scanner with banner grabbing and service fingerprinting."""

    name = "scan"

    def run(self, ctx: EngagementContext, **kwargs: object) -> List[AttackResult]:
        results: List[AttackResult] = []
        all_hosts = expand_targets(ctx.targets)
        log(f"[Scan] Scanning {len(all_hosts)} host(s), {len(ctx.ports)} ports per host", "INFO")

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
                    log(f"[Scan] OPEN  {result.host}:{result.port}/{result.service}"
                        + (f" | {result.banner[:60]}" if result.banner else ""), "OK")
                    results.append(AttackResult(
                        "scan", "open_port", "INFO",
                        host=result.host, port=result.port,
                        data={"service": result.service, "banner": result.banner},
                        notes=f"{result.host}:{result.port} ({result.service}) OPEN"
                    ))
                if ctx.stealth:
                    time.sleep(ctx.delay)

        log(f"[Scan] Done. {total_open} open port(s) found.", "INFO")
        ctx.loot["scan"] = [{"host": p.host, "port": p.port, "service": p.service,
                              "banner": p.banner} for p in ctx.open_ports]
        return results

    def _probe(self, host: str, port: int, ctx: EngagementContext) -> Optional[OpenPort]:
        s = tcp_connect(host, port, ctx.timeout)
        if not s:
            return None
        service = PORT_SERVICES.get(port, f"unknown/{port}")
        s.close()
        banner = grab_banner(host, port, ctx.timeout, PORT_SERVICES)
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
