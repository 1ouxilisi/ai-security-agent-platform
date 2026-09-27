# -*- coding: utf-8 -*-
"""攻击链编排：按阶段顺序串联，记录每步结果到时间线。"""
from __future__ import annotations

import time
import uuid
from typing import Any, Dict, List, Optional

from .discovery_phase import DiscoveryPhase
from .exploitation_phase import ExploitationPhase
from .lateral_phase import LateralPhase
from .privesc_phase import PrivescPhase
from .recon_phase import ReconPhase


STAGES = ["recon", "discovery", "exploitation", "privesc", "lateral", "cleanup"]


class ChainOrchestrator:
    """真实攻击链编排器。"""

    def __init__(self) -> None:
        self.recon = ReconPhase()
        self.discovery = DiscoveryPhase()
        self.exploit = ExploitationPhase()
        self.privesc = PrivescPhase()
        self.lateral = LateralPhase()
        self.runs: Dict[str, Dict[str, Any]] = {}

    def create_run(self, target: str, stages: Optional[List[str]] = None) -> Dict[str, Any]:
        run_id = uuid.uuid4().hex[:10]
        run = {
            "run_id": run_id,
            "target": target,
            "created_at": time.strftime("%Y-%m-%d %H:%M:%S"),
            "stages": stages or STAGES,
            "status": "pending",
            "timeline": [],
            "results": {},
        }
        self.runs[run_id] = run
        return run

    def get(self, run_id: str) -> Optional[Dict[str, Any]]:
        return self.runs.get(run_id)

    def list_runs(self) -> List[Dict[str, Any]]:
        return list(self.runs.values())

    # ---------- 阶段执行 ----------
    def run_recon(self, run_id: str, timeout: int = 300) -> Dict[str, Any]:
        run = self.runs.get(run_id)
        if not run:
            return {"success": False, "error": "run not found"}
        self._log(run, "recon", "start", "开始信息收集")
        res = self.recon.run_full(run["target"], timeout=timeout)
        run["results"]["recon"] = res
        self._log(run, "recon", "done", "信息收集完成", extra={"summary": self._recon_summary(res)})
        return res

    def run_discovery(self, run_id: str, target_url: Optional[str] = None, timeout: int = 300) -> Dict[str, Any]:
        run = self.runs.get(run_id)
        if not run:
            return {"success": False, "error": "run not found"}
        self._log(run, "discovery", "start", "开始漏洞发现")
        url = target_url or self._guess_web_url(run)
        res = self.discovery.run_full(url, timeout=timeout)
        run["results"]["discovery"] = res
        self._log(run, "discovery", "done", "漏洞发现完成", extra={"url": url})
        return res

    def run_exploitation(self, run_id: str, sqli_url: Optional[str] = None, lfi_template: Optional[str] = None) -> Dict[str, Any]:
        run = self.runs.get(run_id)
        if not run:
            return {"success": False, "error": "run not found"}
        self._log(run, "exploitation", "start", "开始漏洞利用")
        res: Dict[str, Any] = {}
        if sqli_url:
            res["sqli"] = self.exploit.sqli_dump(sqli_url)
        if lfi_template:
            res["lfi"] = self.exploit.lfi_read(lfi_template)
        run["results"]["exploitation"] = res
        self._log(run, "exploitation", "done", "漏洞利用完成")
        return res

    def run_privesc(self, run_id: str) -> Dict[str, Any]:
        run = self.runs.get(run_id)
        if not run:
            return {"success": False, "error": "run not found"}
        self._log(run, "privesc", "start", "开始权限提升枚举")
        res = self.privesc.run()
        run["results"]["privesc"] = res
        self._log(run, "privesc", "done", "权限提升枚举完成")
        return res

    def run_lateral(self, run_id: str, cidr: str, username: str, password: str) -> Dict[str, Any]:
        run = self.runs.get(run_id)
        if not run:
            return {"success": False, "error": "run not found"}
        self._log(run, "lateral", "start", f"开始横向移动 {cidr}")
        res = self.lateral.pivot(cidr, username, password)
        run["results"]["lateral"] = res
        self._log(run, "lateral", "done", "横向移动完成", extra={"hosts": res.get("hosts_controlled")})
        return res

    # ---------- 一站式 ----------
    def run_chain(self, target: str, stages: Optional[List[str]] = None) -> Dict[str, Any]:
        run = self.create_run(target, stages)
        run["status"] = "running"
        try:
            if "recon" in run["stages"]:
                self.run_recon(run["run_id"])
            if "discovery" in run["stages"]:
                self.run_discovery(run["run_id"])
            run["status"] = "partial"  # exploitation 起需要人工输入（注入点/凭证）
            run["finished_at"] = time.strftime("%Y-%m-%d %H:%M:%S")
        except Exception as e:  # noqa: BLE001
            run["status"] = "error"
            run["error"] = str(e)
        return run

    # ---------- 内部 ----------
    @staticmethod
    def _log(run: Dict[str, Any], stage: str, status: str, message: str, extra: Optional[Dict[str, Any]] = None) -> None:
        entry = {
            "ts": time.strftime("%H:%M:%S"),
            "stage": stage,
            "status": status,
            "message": message,
        }
        if extra:
            entry.update(extra)
        run["timeline"].append(entry)

    @staticmethod
    def _recon_summary(res: Dict[str, Any]) -> Dict[str, Any]:
        sub = (res.get("subfinder") or {}).get("count", 0)
        port = (res.get("port_scan") or {}).get("count", 0)
        svc = len((res.get("service_detect") or {}).get("services", []))
        return {"subdomains": sub, "open_ports": port, "services": svc}

    @staticmethod
    def _guess_web_url(run: Dict[str, Any]) -> str:
        fp = (run.get("results", {}).get("recon", {}).get("http_fingerprint") or {})
        if fp.get("success"):
            return run["target"]
        return f"http://{run['target']}"
