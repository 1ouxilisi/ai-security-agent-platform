# -*- coding: utf-8 -*-
"""真实攻击链控制台聚合。"""
from __future__ import annotations

from typing import Any, Dict, List, Optional

from .chain_orchestrator import ChainOrchestrator
from .discovery_phase import DiscoveryPhase
from .exploitation_phase import ExploitationPhase
from .lateral_phase import LateralPhase
from .privesc_phase import PrivescPhase
from .recon_phase import ReconPhase


class _ChainDashboard:
    def __init__(self) -> None:
        self.orch = ChainOrchestrator()
        self.recon = ReconPhase()
        self.discovery = DiscoveryPhase()
        self.exploit = ExploitationPhase()
        self.privesc = PrivescPhase()
        self.lateral = LateralPhase()

    def health(self) -> Dict[str, Any]:
        return {
            "service": "attack-chain-real",
            "status": "ok",
            "phases": ["recon", "discovery", "exploitation", "privesc", "lateral", "cleanup"],
        }

    # ---------- recon ----------
    def subfinder(self, domain: str, timeout: int = 180) -> Dict[str, Any]:
        return self.recon.subfinder(domain, timeout=timeout)

    def crt_sh(self, domain: str, timeout: int = 60) -> Dict[str, Any]:
        return self.recon.crt_sh(domain, timeout=timeout)

    def port_scan(self, target: str, ports: str = "--top-ports 1000", timeout: int = 300) -> Dict[str, Any]:
        return self.recon.port_scan(target, ports, timeout=timeout)

    def service_detect(self, target: str, ports: Optional[str] = None, timeout: int = 300) -> Dict[str, Any]:
        return self.recon.service_detect(target, ports, timeout=timeout)

    def fingerprint(self, url: str, timeout: int = 30) -> Dict[str, Any]:
        return self.recon.http_fingerprint(url, timeout=timeout)

    # ---------- discovery ----------
    def nuclei(self, url: str, severity: str = "critical,high,medium", timeout: int = 300) -> Dict[str, Any]:
        return self.discovery.nuclei(url, severity=severity, timeout=timeout)

    def sqlmap_probe(self, url: str, data: Optional[str] = None, timeout: int = 300) -> Dict[str, Any]:
        return self.discovery.sqlmap_probe(url, data=data, timeout=timeout)

    def nikto(self, host: str, timeout: int = 300) -> Dict[str, Any]:
        return self.discovery.nikto(host, timeout=timeout)

    def dirbust(self, url: str, wordlist: str = "/usr/share/wordlists/dirb/common.txt", timeout: int = 180) -> Dict[str, Any]:
        return self.discovery.dir_bruteforce(url, wordlist, timeout=timeout)

    # ---------- exploitation ----------
    def sqli_dump(self, url: str, data: Optional[str] = None, tables: Optional[List[str]] = None, timeout: int = 300) -> Dict[str, Any]:
        return self.exploit.sqli_dump(url, data=data, tables=tables, timeout=timeout)

    def xss_verify(self, url: str, param: str, payload: str = "<script>alert(1)</script>") -> Dict[str, Any]:
        return self.exploit.xss_verify(url, param, payload)

    def lfi_read(self, url_template: str) -> Dict[str, Any]:
        return self.exploit.lfi_read(url_template)

    def redis_unauth(self, host: str, port: int = 6379) -> Dict[str, Any]:
        return self.exploit.redis_unauth(host, port)

    def es_unauth(self, host: str, port: int = 9200) -> Dict[str, Any]:
        return self.exploit.es_unauth(host, port)

    # ---------- privesc ----------
    def privesc_enum(self) -> Dict[str, Any]:
        return self.privesc.run()

    def privesc_try(self, vector: str) -> Dict[str, Any]:
        return self.privesc.try_exploit(vector)

    # ---------- lateral ----------
    def smb_spray(self, cidr: str, username: str, password: str, timeout: int = 180) -> Dict[str, Any]:
        return self.lateral.smb_spray(cidr, username, password, timeout=timeout)

    def wmiexec(self, target: str, username: str, password: str, command: str = "whoami") -> Dict[str, Any]:
        return self.lateral.wmiexec(target, username, password, command)

    def winrm_exec(self, target: str, username: str, password: str, command: str = "whoami") -> Dict[str, Any]:
        return self.lateral.winrm_exec(target, username, password, command)

    def ldap_enum(self, server: str, base_dn: str, username: str = "", password: str = "") -> Dict[str, Any]:
        return self.lateral.ldap_enum(server, base_dn, username, password)

    def pivot(self, cidr: str, username: str, password: str) -> Dict[str, Any]:
        return self.lateral.pivot(cidr, username, password)

    # ---------- orchestrator ----------
    def create_run(self, target: str, stages: Optional[List[str]] = None) -> Dict[str, Any]:
        return self.orch.create_run(target, stages)

    def get_run(self, run_id: str) -> Dict[str, Any]:
        r = self.orch.get(run_id)
        if not r:
            return {"success": False, "error": "run not found"}
        return {"success": True, "run": r}

    def list_runs(self) -> Dict[str, Any]:
        return {"runs": self.orch.list_runs()}

    def run_stage(self, run_id: str, stage: str, **kw: Any) -> Dict[str, Any]:
        methods = {
            "recon": self.orch.run_recon,
            "discovery": self.orch.run_discovery,
            "exploitation": self.orch.run_exploitation,
            "privesc": self.orch.run_privesc,
            "lateral": self.orch.run_lateral,
        }
        fn = methods.get(stage)
        if not fn:
            return {"success": False, "error": f"unknown stage {stage}"}
        return fn(run_id, **kw) if kw else fn(run_id)

    def run_full_chain(self, target: str) -> Dict[str, Any]:
        return self.orch.run_chain(target)


dashboard = _ChainDashboard()
