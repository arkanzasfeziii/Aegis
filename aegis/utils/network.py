"""Network utilities: TCP connect, banner grabbing, target expansion."""

from __future__ import annotations

import ipaddress
import socket
import time
from typing import Dict, List, Optional

from aegis.models import EngagementContext

BANNER_PROBES: Dict[str, bytes] = {
    "HTTP": b"GET / HTTP/1.0\r\nHost: target\r\n\r\n",
    "SMTP": b"EHLO aegis\r\n",
    "FTP": b"",
    "SSH": b"",
    "REDIS": b"*1\r\n$4\r\nINFO\r\n",
    "MYSQL": b"",
}


def tcp_connect(host: str, port: int, timeout: float) -> Optional[socket.socket]:
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(timeout)
        s.connect((host, port))
        return s
    except Exception:
        return None


def grab_banner(host: str, port: int, timeout: float, port_services: Dict[int, str]) -> str:
    try:
        s = tcp_connect(host, port, timeout)
        if not s:
            return ""
        probe = BANNER_PROBES.get(port_services.get(port, ""), b"")
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


def expand_targets(targets: List[str]) -> List[str]:
    hosts: List[str] = []
    for t in targets:
        try:
            net = ipaddress.ip_network(t, strict=False)
            hosts.extend(str(h) for h in net.hosts())
        except ValueError:
            hosts.append(t)
    return hosts


def sleep_if_stealth(ctx: EngagementContext) -> None:
    if ctx.stealth and ctx.delay > 0:
        time.sleep(ctx.delay)
