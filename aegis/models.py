"""Data models used across all Aegis modules."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Dict, List


@dataclass
class OpenPort:
    host: str
    port: int
    service: str
    banner: str = ""
    version: str = ""


@dataclass
class AttackResult:
    module: str
    action: str
    status: str
    host: str = ""
    port: int = 0
    data: Any = None
    severity: str = "INFO"
    notes: str = ""


@dataclass
class Credential:
    service: str
    host: str
    port: int
    username: str
    password: str
    hash_val: str = ""
    notes: str = ""


@dataclass
class EngagementContext:
    targets: List[str] = field(default_factory=list)
    ports: List[int] = field(default_factory=list)
    threads: int = 50
    timeout: float = 2.0
    delay: float = 0.1
    stealth: bool = False
    results: List[AttackResult] = field(default_factory=list)
    open_ports: List[OpenPort] = field(default_factory=list)
    credentials: List[Credential] = field(default_factory=list)
    loot: Dict[str, Any] = field(default_factory=dict)
