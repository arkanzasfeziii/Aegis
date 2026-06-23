"""Banner, legal warning, and result formatting."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Optional

from aegis.config import AUTHOR, LEGAL_WARNING, TOOL_NAME, VERSION
from aegis.models import EngagementContext

try:
    import pyfiglet
    HAS_PYFIGLET = True
except ImportError:
    HAS_PYFIGLET = False


def print_banner() -> None:
    if HAS_PYFIGLET:
        print(f"\033[35m{pyfiglet.figlet_format('Aegis', font='slant')}\033[0m")
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
    success = sum(1 for r in ctx.results if r.status == "SUCCESS")
    crits = sum(1 for r in ctx.results if r.severity == "CRITICAL")
    print(f"\n\033[35m{'═' * 60}\n  ENGAGEMENT RESULTS\n{'═' * 60}\033[0m")
    print(f"  Open Ports   : {len(ctx.open_ports)}")
    print(f"  Successes    : \033[32m{success}\033[0m")
    print(f"  Critical     : \033[35m{crits}\033[0m")
    print(f"  Credentials  : \033[33m{len(ctx.credentials)}\033[0m\n")

    icons = {"SUCCESS": "\033[32m[+]", "FAILED": "\033[31m[x]",
             "PARTIAL": "\033[33m[~]", "INFO": "\033[36m[*]"}
    reset = "\033[0m"
    for r in ctx.results:
        c = icons.get(r.status, "   ")
        host_str = f"{r.host}:{r.port}" if r.host else ""
        print(f"  {c}{reset} [{r.module}] {r.action} {host_str}")
        if r.notes:
            print(f"        {r.notes}")

    if ctx.credentials:
        print(f"\n\033[32m[+] CREDENTIALS ({len(ctx.credentials)})\033[0m")
        for c in ctx.credentials:
            print(f"  [{c.service}] {c.host}:{c.port} — {c.username}:{c.password or c.hash_val}")
            if c.notes:
                print(f"         {c.notes}")

    if ctx.open_ports:
        print(f"\n\033[36m[*] OPEN PORTS ({len(ctx.open_ports)})\033[0m")
        for op in ctx.open_ports:
            ver_str = f" [{op.version}]" if op.version else ""
            print(f"  {op.host}:{op.port}\t{op.service}{ver_str}")

    if output:
        payload = {
            "tool": TOOL_NAME, "version": VERSION,
            "open_ports": [{"host": p.host, "port": p.port, "service": p.service}
                           for p in ctx.open_ports],
            "credentials": [{"service": c.service, "host": c.host, "port": c.port,
                             "username": c.username} for c in ctx.credentials],
            "results": [{"module": r.module, "action": r.action, "status": r.status,
                         "severity": r.severity, "notes": r.notes} for r in ctx.results],
            "loot": ctx.loot,
        }
        Path(output).write_text(json.dumps(payload, indent=2, default=str), encoding="utf-8")
        print(f"\n\033[32m[+] Results saved → {output}\033[0m")
