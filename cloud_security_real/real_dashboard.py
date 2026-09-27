# -*- coding: utf-8 -*-
"""
real_dashboard.py — 真实云安全仪表盘（聚合最近任务统计）。
"""

from __future__ import annotations

from typing import Any, Dict, List, Optional

from .real_orchestrator import get_real_orchestrator
from .cis_benchmark import get_cis_benchmark


class RealDashboard:
    """真实云安全仪表盘聚合。"""

    def overview(self) -> Dict[str, Any]:
        orch = get_real_orchestrator()
        tasks = orch.list_tasks()
        total_findings = 0
        by_sev: Dict[str, int] = {}
        by_provider: Dict[str, int] = {}
        done = 0
        for t in tasks:
            if t.get("status") == "done":
                done += 1
            res = t.get("result") or {}
            cloud = res.get("cloud") or {}
            s = cloud.get("summary") or {}
            total_findings += s.get("total", 0)
            for k, v in (s.get("by_severity") or {}).items():
                by_sev[k] = by_sev.get(k, 0) + v
            by_provider[t.get("provider", "?")] = (
                by_provider.get(t.get("provider", "?"), 0) + 1)
        return {
            "task_count": len(tasks), "done_count": done,
            "total_findings": total_findings,
            "by_severity": by_sev,
            "by_provider": by_provider,
            "frameworks": get_cis_benchmark().frameworks(),
            "recent": tasks[:10],
        }

    def credential_matrix(self) -> Dict[str, Any]:
        from .aws_security_check import detect_aws_status
        from .azure_security_check import detect_azure_status
        from .aliyun_security_check import detect_aliyun_status
        from .container_security_check import (
            detect_k8s_status, detect_docker_status, detect_scanner)
        return {
            "aws": detect_aws_status(),
            "azure": detect_azure_status(),
            "aliyun": detect_aliyun_status(),
            "k8s": detect_k8s_status(),
            "docker": detect_docker_status(),
            "image_scanner": detect_scanner(),
        }


_default_dash: Optional[RealDashboard] = None


def get_real_dashboard() -> RealDashboard:
    global _default_dash
    if _default_dash is None:
        _default_dash = RealDashboard()
    return _default_dash
