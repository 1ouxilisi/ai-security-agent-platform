# -*- coding: utf-8 -*-
"""
data_security_orchestrator.py — 数据安全 Pro 八阶段编排器。

阶段:
    1. discovery    数据发现
    2. classification 数据分类分级
    3. asset        数据资产盘点
    4. dlp          DLP 防泄漏
    5. privacy      隐私合规
    6. encryption   加密与密钥
    7. access       数据访问审计
    8. risk         风险评级
"""

from __future__ import annotations

import os
import time
import uuid
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional

from .data_discovery_phase import get_data_discovery_phase
from .data_classification_phase import get_data_classification_phase
from .data_asset_phase import get_data_asset_phase
from .dlp_phase import get_dlp_phase
from .privacy_compliance_phase import get_privacy_compliance_phase
from .encryption_key_phase import get_encryption_key_phase
from .access_audit_phase import get_access_audit_phase
from .risk_rating_phase import get_risk_rating_phase
from .ai_analysis import get_ai_analysis
from .report_generator import get_report_generator, REPORTS_DIR
from .realtime_push import push_event_sync


STAGES = [
    ("discovery",      "数据发现",   12),
    ("classification", "分类分级",   25),
    ("asset",          "资产盘点",   37),
    ("dlp",            "DLP防泄漏",  50),
    ("privacy",        "隐私合规",   62),
    ("encryption",     "加密密钥",   74),
    ("access",         "访问审计",   87),
    ("risk",           "风险评级",  100),
]


@dataclass
class DSTask:
    task_id: str = ""
    target: str = ""
    status: str = "pending"
    stage: str = "init"
    progress: int = 0
    created_at: str = ""
    finished_at: Optional[str] = None
    error: Optional[str] = None
    discovery: Dict[str, Any] = field(default_factory=dict)
    classification: Dict[str, Any] = field(default_factory=dict)
    asset: Dict[str, Any] = field(default_factory=dict)
    dlp: Dict[str, Any] = field(default_factory=dict)
    privacy: Dict[str, Any] = field(default_factory=dict)
    encryption: Dict[str, Any] = field(default_factory=dict)
    access: Dict[str, Any] = field(default_factory=dict)
    risk: Dict[str, Any] = field(default_factory=dict)
    ai: Dict[str, Any] = field(default_factory=dict)
    report_path: str = ""
    report_markdown: str = ""
    report_html: str = ""
    log: List[str] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "task_id": self.task_id, "target": self.target,
            "status": self.status, "stage": self.stage,
            "progress": self.progress,
            "created_at": self.created_at,
            "finished_at": self.finished_at, "error": self.error,
            "discovery": self.discovery,
            "classification": self.classification,
            "asset": self.asset, "dlp": self.dlp,
            "privacy": self.privacy, "encryption": self.encryption,
            "access": self.access, "risk": self.risk,
            "ai": self.ai, "report_path": self.report_path,
            "log": self.log[-80:],
        }


class DataSecurityOrchestrator:
    """八阶段编排器。"""

    def __init__(self) -> None:
        self.disc = get_data_discovery_phase()
        self.cls = get_data_classification_phase()
        self.asset = get_data_asset_phase()
        self.dlp = get_dlp_phase()
        self.priv = get_privacy_compliance_phase()
        self.enc = get_encryption_key_phase()
        self.acc = get_access_audit_phase()
        self.risk = get_risk_rating_phase()
        self.ai = get_ai_analysis()
        self.report = get_report_generator()
        self._tasks: Dict[str, DSTask] = {}

    # ------------------------------------------------------------------ #
    def create_task(self, target: str = "data-security-audit"
                    ) -> DSTask:
        tid = uuid.uuid4().hex[:16]
        t = DSTask(task_id=tid, target=target,
                   created_at=time.strftime("%Y-%m-%d %H:%M:%S"))
        self._tasks[tid] = t
        return t

    def get_task(self, task_id: str) -> Optional[DSTask]:
        return self._tasks.get(task_id)

    def list_tasks(self) -> List[Dict[str, Any]]:
        return [t.to_dict() for t in sorted(
            self._tasks.values(), key=lambda x: x.created_at,
            reverse=True)]

    # ------------------------------------------------------------------ #
    def _log(self, t: DSTask, msg: str, level: str = "info") -> None:
        t.log.append(msg)
        push_event_sync(t.task_id, "log", {"msg": msg}, level=level)

    def _stage(self, t: DSTask, key: str, label: str) -> None:
        for k, name, prog in STAGES:
            if k == key:
                t.stage = key
                t.progress = prog
                self._log(t, f"[*] 进入阶段: {label}", "step")
                push_event_sync(t.task_id, "progress",
                                {"stage": key, "progress": prog,
                                 "label": label})
                return

    # ------------------------------------------------------------------ #
    def run_full(self, target: str = "data-security-audit",
                 task_id: Optional[str] = None) -> DSTask:
        t = self._tasks.get(task_id) if task_id else None
        if t is None:
            t = self.create_task(target)
        t.status = "running"
        try:
            # 1 数据发现
            self._stage(t, "discovery", "数据发现")
            t.discovery = self.disc.scan(progress_cb=lambda p, m:
                                          push_event_sync(
                                              t.task_id, "progress",
                                              {"progress": p, "msg": m}))
            self._log(t, f"[+] 数据发现: 命中 "
                         f"{t.discovery.get('hit_count', 0)} 条")

            # 2 分类分级
            self._stage(t, "classification", "数据分类分级")
            hits = []
            for s in self.disc.list_sources():
                hits.extend(s.get("sensitive_hits", []))
            t.classification = self.cls.classify_batch(hits)
            self._log(t, f"[+] 分类分级: "
                         f"{t.classification.get('by_level', {})}")

            # 3 资产盘点
            self._stage(t, "asset", "数据资产盘点")
            t.asset = self.asset.summary()
            t.asset["flows"] = self.asset.data_flows()
            self._log(t, f"[+] 资产: "
                         f"{t.asset.get('total_assets', 0)} 项")

            # 4 DLP
            self._stage(t, "dlp", "DLP 防泄漏")
            # 模拟几条 DLP 事件
            self.dlp.simulate_event("email_out", "身份证 110101199003077758")
            self.dlp.simulate_event("web_upload", "phone 13800138000")
            t.dlp = self.dlp.stats()
            self._log(t, f"[+] DLP: {t.dlp.get('alert_total', 0)} 告警")

            # 5 隐私合规
            self._stage(t, "privacy", "隐私合规")
            self.priv.auto_assess()
            t.privacy = self.priv.summary()
            self._log(t, f"[+] 合规分: "
                         f"{t.privacy.get('overall_score', '-')}")

            # 6 加密密钥
            self._stage(t, "encryption", "加密与密钥")
            t.encryption = self.enc.risk_summary()
            self._log(t, f"[+] 加密覆盖率: "
                         f"{t.encryption.get('coverage', {}).get('encryption_coverage_pct', '-')}%")

            # 7 访问审计
            self._stage(t, "access", "数据访问审计")
            self.acc.ingest_log("demo", "export", "crm.users",
                                "203.0.113.9", "境外", False, 200000)
            t.access = self.acc.stats()
            self._log(t, f"[+] 访问异常: "
                         f"{t.access.get('anomaly_total', 0)}")

            # 8 风险评级
            self._stage(t, "risk", "风险评级")
            t.risk = self.risk.compute(
                classification=t.classification,
                dlp=t.dlp, compliance=t.privacy,
                encryption=t.encryption, access=t.access,
            )
            self._log(t, f"[+] 综合风险: "
                         f"{t.risk.get('overall_level')} "
                         f"({t.risk.get('overall_score')})")

            # AI 分析
            t.ai = self.ai.analyze_overall(t.risk, t.privacy, t.encryption)
            self._log(t, "[+] AI 分析完成")

            # 报告
            ctx = {
                "discovery": t.discovery,
                "classification": t.classification,
                "asset_summary": t.asset,
                "dlp": t.dlp, "compliance": t.privacy,
                "encryption": t.encryption, "access": t.access,
                "risk": t.risk, "ai": t.ai,
            }
            t.report_markdown = self.report.generate_markdown(ctx)
            t.report_html = self.report.generate_html(ctx)
            os.makedirs(REPORTS_DIR, exist_ok=True)
            t.report_path = self.report.save(ctx, REPORTS_DIR, "html")
            self._log(t, f"[+] 报告: {t.report_path}")

            t.status = "done"
            t.stage = "done"
            t.progress = 100
            t.finished_at = time.strftime("%Y-%m-%d %H:%M:%S")
            push_event_sync(t.task_id, "done",
                            {"status": "done", "progress": 100})
        except Exception as e:  # noqa: BLE001
            t.status = "error"
            t.error = f"{type(e).__name__}: {e}"
            self._log(t, f"[!] 失败: {t.error}", "error")
            t.finished_at = time.strftime("%Y-%m-%d %H:%M:%S")
        return t


_default_orch: Optional[DataSecurityOrchestrator] = None


def get_orchestrator() -> DataSecurityOrchestrator:
    global _default_orch
    if _default_orch is None:
        _default_orch = DataSecurityOrchestrator()
    return _default_orch


__all__ = ["DataSecurityOrchestrator", "DSTask", "get_orchestrator",
           "STAGES", "REPORTS_DIR"]
