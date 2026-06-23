"""Command-line interface for Aegis."""

from __future__ import annotations

import argparse
import textwrap

from aegis.config import COMMAND, TOOL_NAME, VERSION
from aegis.data.ports import TOP_PORTS
from aegis.logger import log
from aegis.models import EngagementContext
from aegis.modules import (
    CredAttackModule, EnumModule, IoTModule,
    LateralModule, ScanModule, TunnelModule,
)
from aegis.output import dump_results, print_banner, print_legal

MODULE_REGISTRY = {
    "scan": (ScanModule, lambda a: {}),
    "enum": (EnumModule, lambda a: {"domain": a.domain}),
    "cred": (CredAttackModule, lambda a: {"spray_password": a.spray_pass}),
    "lateral": (LateralModule, lambda a: {"command": a.command, "domain": a.domain}),
    "tunnel": (TunnelModule, lambda a: {"c2_domain": a.c2_domain, "data_to_exfil": a.exfil_data}),
    "iot": (IoTModule, lambda a: {}),
}


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog=COMMAND,
        description=f"{TOOL_NAME} v{VERSION}",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=textwrap.dedent(f"""\
            examples:
              {COMMAND} --targets 192.168.1.0/24 --modules scan
              {COMMAND} --targets 10.0.0.5 --modules enum --domain corp.local
              {COMMAND} --targets 10.0.0.0/24 --modules cred
              {COMMAND} --targets 10.0.0.5 --modules lateral --command "whoami"
              {COMMAND} --targets 10.0.0.0/24 --modules all --output loot.json
        """),
    )
    p.add_argument("--targets", nargs="+", required=True)
    p.add_argument("--modules", nargs="+",
                   choices=["scan", "enum", "cred", "lateral", "tunnel", "iot", "all"],
                   default=["scan"])
    p.add_argument("--ports", nargs="+", type=int)
    p.add_argument("--domain", default="")
    p.add_argument("--command", default="whoami")
    p.add_argument("--spray-pass", default="")
    p.add_argument("--c2-domain", default="")
    p.add_argument("--exfil-data", default="")
    p.add_argument("--threads", type=int, default=50)
    p.add_argument("--timeout", type=float, default=2.0)
    p.add_argument("--delay", type=float, default=0.1)
    p.add_argument("--stealth", action="store_true")
    p.add_argument("--output", "-o", help="Save results to JSON")
    p.add_argument("--yes", "-y", action="store_true")
    p.add_argument("--version", action="version", version=f"{TOOL_NAME} v{VERSION}")
    return p


def main() -> int:
    args = build_parser().parse_args()
    print_banner()
    if not print_legal(args.yes):
        print("Aborted.")
        return 1

    ctx = EngagementContext(
        targets=args.targets,
        ports=args.ports or TOP_PORTS,
        threads=args.threads,
        timeout=args.timeout,
        delay=args.delay,
        stealth=args.stealth,
    )

    modules_to_run = list(MODULE_REGISTRY.keys()) if "all" in args.modules else args.modules

    for mod_name in modules_to_run:
        entry = MODULE_REGISTRY.get(mod_name)
        if not entry:
            continue
        mod_cls, kwargs_fn = entry
        log(f"Running module: {mod_name.upper()}", "INFO")
        try:
            mod = mod_cls()
            results = mod.run(ctx, **kwargs_fn(args))
            ctx.results.extend(results)
        except Exception as exc:
            log(f"Module {mod_name} error: {exc}", "ERR")

    dump_results(ctx, args.output)
    return 0
