# -*- coding: utf-8 -*-
"""
real_orchestrator.py — 真实云安全检查编排器。

按 provider 调用各真实检查器，聚合结果，运行 CIS 映射，生成真实报告。
全部内存字典存储。不 mock。
"""

from __future__ import annotations

import threading
import time
import uuid
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional

from .aws_security_check import get_aws_checker, detect_aws_status
from .azure_security_check import get_azure_checker, detect_azure_status
from .aliyun_security_check import get_aliyun_checker, detect_aliyun_status
from .container_security_check import get_container_checker
from .cis_benchmark import get_cis_benchmark
from .real_report_generator import (
    RealReportData, get_real_report_generator)


STAGES = [
    ("credential_check", "凭证/SDK 检测", 15),
    ("cloud_scan", "真实云 API 扫描", 60),
    ("container_scan", "容器/K8s 扫描", 78),
    ("cis_map", "CIS 基线映射", 90),
    ("report", "真实报告生成", 100),
]


@dataclass
class RealTask:
    task_id: str = ""
    provider: str = "aws"
    status: str = "pending"
    stage: str = "init"
    progress: int = 0
    created_at: str = ""
    finished_at: Optional[str] = None
    result: Dict[str, Any] = field(default_factory=dict)
    report_path: str = ""
    log: List[str] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "task_id": self.task_id, "provider": self.provider,
            "status": self.status, "stage": self.stage,
            "progress": self.progress, "created_at": self.created_at,
            "finished_at": self.finished_at, "result": self.result,
            "report_path": self.report_path, "log": self.log[-100:],
        }


class RealOrchestrator:
    """真实云安全检查编排器。"""

    def __init__(self) -> None:
        self._tasks: Dict[str, RealTask] = {}

    # ------------------------------------------------------------------ #
    def create_task(self, provider: str = "aws") -> RealTask:
        tid = uuid.uuid4().hex[:16]
        t = RealTask(task_id=tid, provider=provider,
                     created_at=time.strftime("%Y-%m-%d %H:%M:%S"))
        self._tasks[tid] = t
        return t

    def get_task(self, task_id: str) -> Optional[RealTask]:
        return self._tasks.get(task_id)

    def list_tasks(self) -> List[Dict[str, Any]]:
        return [t.to_dict() for t in sorted(
            self._tasks.values(), key=lambda x: x.created_at, reverse=True)]

    # ------------------------------------------------------------------ #
    def run(self, provider: str = "aws",
            region: Optional[str] = None,
            task_id: Optional[str] = None) -> RealTask:
        t = self._tasks.get(task_id) if task_id else None
        if t is None:
            t = self.create_task(provider)
        t.status = "running"
        try:
            # 1) 凭证检测
            t.stage = "credential_check"; t.progress = 15
            t.log.append(f"[*] 检测 {provider.upper()} SDK 与凭证...")
            if provider == "aws":
                cred = detect_aws_status()
                cloud = get_aws_checker(region).run()
            elif provider == "azure":
                cred = detect_azure_status()
                cloud = get_azure_checker().run()
            elif provider == "aliyun":
                cred = detect_aliyun_status()
                cloud = get_aliyun_checker(region).run()
            else:
                raise ValueError(f"不支持的 provider: {provider}")
            t.log.append(f"[*] {cred.get('hint','')}")

            # 2) 容器扫描
            t.stage = "container_scan"; t.progress = 78
            t.log.append("[*] 容器/K8s 安全扫描...")
            container = get_container_checker().run()

            # 3) CIS 映射
            t.stage = "cis_map"; t.progress = 90
            cis_findings = cloud.get("findings", [])
            cis = get_cis_benchmark().evaluate_all(
                {provider: cis_findings, "k8s":
                 (container.get("k8s") or {}).get("findings", [])})

            # 4) 报告
            t.stage = "report"; t.progress = 100
            rd = RealReportData(
                task_id=t.task_id, provider=provider,
                started_at=t.created_at,
                finished_at=time.strftime("%Y-%m-%d %H:%M:%S"),
                credential_status=cloud.get("credential_status", {}),
                summary=cloud.get("summary", {}),
                by_service=cloud.get("by_service", {}),
                findings=cloud.get("findings", []),
                cis=cis, container=container)
            path = get_real_report_generator().save(rd, "html")
            t.result = {"cloud": cloud, "container": container,
                        "cis": cis, "report": path}
            t.report_path = path
            t.log.append(f"[+] 报告已落盘: {path}")
            t.status = "done"; t.stage = "done"; t.progress = 100
            t.finished_at = time.strftime("%Y-%m-%d %H:%M:%S")
        except Exception as e:  # noqa: BLE001
            t.status = "error"
            t.log.append(f"[!] 失败: {type(e).__name__}: {e}")
            t.finished_at = time.strftime("%Y-%m-%d %H:%M:%S")
        return t

    def start_async(self, provider: str = "aws",
                   region: Optional[str] = None) -> RealTask:
        t = self.create_task(provider)
        threading.Thread(target=self.run,
                         args=(provider, region, t.task_id),
                         daemon=True).start()
        return t


_default_orch: Optional[RealOrchestrator] = None


def get_real_orchestrator() -> RealOrchestrator:
    global _default_orch
    if _default_orch is None:
        _default_orch = RealOrchestrator()
    return _default_orch
