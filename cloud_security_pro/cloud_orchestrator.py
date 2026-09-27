# -*- coding: utf-8 -*-
"""
cloud_orchestrator.py — 云安全 Pro 五阶段编排器。

阶段:
    1. asset_discovery  资产发现（真实云 API）
    2. config_check     配置检查（18 条规则）
    3. risk_rating      风险评级（0-100 / 四级）
    4. vuln_detect      漏洞检测（CVE 匹配）
    5. compliance_audit 合规审计（等保/ISO/CIS）
    + AI 分析 + 报告生成
"""

from __future__ import annotations

import time
import uuid
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional

from .asset_discovery_phase import get_asset_discovery_phase
from .config_check_phase import get_config_check_phase
from .risk_rating_phase import get_risk_rating_phase
from .vuln_detect_phase import get_vuln_detect_phase
from .compliance_audit_phase import get_compliance_audit_phase
from .ai_analysis import get_ai_analysis
from .realtime_push import get_push_manager
from .report_generator import CloudReportData, get_report_generator


STAGES = [
    ("asset_discovery", "资产发现", 20),
    ("config_check", "配置检查", 45),
    ("risk_rating", "风险评级", 60),
    ("vuln_detect", "漏洞检测", 78),
    ("compliance_audit", "合规审计", 92),
    ("ai_report", "AI分析与报告", 100),
]


@dataclass
class CloudTask:
    task_id: str = ""
    provider: str = "aws"
    status: str = "pending"
    stage: str = "init"
    progress: int = 0
    created_at: str = ""
    finished_at: Optional[str] = None
    error: Optional[str] = None
    inventory: Dict[str, Any] = field(default_factory=dict)
    config: Dict[str, Any] = field(default_factory=dict)
    risk: Dict[str, Any] = field(default_factory=dict)
    vuln: Dict[str, Any] = field(default_factory=dict)
    compliance: Dict[str, Any] = field(default_factory=dict)
    ai: Dict[str, Any] = field(default_factory=dict)
    report_path: str = ""
    report_markdown: str = ""
    report_html: str = ""
    log: List[str] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "task_id": self.task_id, "provider": self.provider,
            "status": self.status, "stage": self.stage,
            "progress": self.progress,
            "created_at": self.created_at,
            "finished_at": self.finished_at,
            "error": self.error,
            "inventory": self.inventory,
            "config": self.config, "risk": self.risk,
            "vuln": self.vuln, "compliance": self.compliance,
            "ai": self.ai, "report_path": self.report_path,
            "log": self.log[-80:],
        }


class CloudSecurityOrchestrator:
    """五阶段编排器。"""

    def __init__(self) -> None:
        self.discovery = get_asset_discovery_phase()
        self.config = get_config_check_phase()
        self.risk = get_risk_rating_phase()
        self.vuln = get_vuln_detect_phase()
        self.compliance = get_compliance_audit_phase()
        self.ai = get_ai_analysis()
        self.report = get_report_generator()
        self.push = get_push_manager()
        self._tasks: Dict[str, CloudTask] = {}

    # ------------------------------------------------------------------ #
    def create_task(self, provider: str = "aws") -> CloudTask:
        tid = uuid.uuid4().hex[:16]
        t = CloudTask(task_id=tid, provider=provider,
                      created_at=time.strftime("%Y-%m-%d %H:%M:%S"))
        self._tasks[tid] = t
        return t

    def get_task(self, task_id: str) -> Optional[CloudTask]:
        return self._tasks.get(task_id)

    def list_tasks(self) -> List[Dict[str, Any]]:
        return [t.to_dict() for t in sorted(
            self._tasks.values(), key=lambda x: x.created_at,
            reverse=True)]

    # ------------------------------------------------------------------ #
    def _stage(self, t: CloudTask, key: str, label: str,
               percent: int, eta: int = 0) -> None:
        t.stage = key
        t.progress = percent
        self.push.sync_stage(t.task_id, key, "active", label)
        self.push.sync_progress(t.task_id, percent, key, label, eta)
        self.push.sync_log(t.task_id, "INFO", f"进入阶段: {label}", key)

    # ------------------------------------------------------------------ #
    def run_full(self, provider: str = "aws",
                 region: Optional[str] = None,
                 task_id: Optional[str] = None) -> CloudTask:
        t = self._tasks.get(task_id) if task_id else None
        if t is None:
            t = self.create_task(provider)
        t.status = "running"
        try:
            # 阶段1 资产发现
            self._stage(t, "asset_discovery", "资产发现", 20, 30)
            self.push.sync_thought(
                t.task_id,
                f"调用 {provider.upper()} 云 API 枚举 EC2/RDS/S3/IAM 等资源",
                "asset_discovery")
            inv = self.discovery.discover(provider=provider, region=region)
            t.inventory = inv.to_dict()
            cred = inv.credential_status
            if not cred.get("credentials_configured"):
                self.push.sync_log(
                    t.task_id, "WARNING",
                    f"凭证未配置：{cred.get('hint','')}",
                    "asset_discovery")
            else:
                self.push.sync_log(
                    t.task_id, "SUCCESS",
                    f"发现 {inv.to_dict().get('resource_count',0)} 个资源",
                    "asset_discovery")

            # 阶段2 配置检查
            self._stage(t, "config_check", "配置检查", 45, 20)
            self.push.sync_thought(
                t.task_id, "对 18 条基线规则逐一评估安全组/存储桶/IAM...",
                "config_check")
            cr = self.config.run(t.inventory)
            t.config = cr.to_dict()
            self.push.sync_log(
                t.task_id, "SUCCESS",
                f"配置检查 {cr.to_dict().get('finding_count',0)} 个发现",
                "config_check")

            # 阶段3 风险评级
            self._stage(t, "risk_rating", "风险评级", 60, 10)
            if cr.executed:
                rr = self.risk.rate(t.config.get("findings", []),
                                     resource_count=t.inventory.get("resource_count", 0))
                t.risk = rr.to_dict()
                self.push.sync_log(
                    t.task_id, "NOTICE",
                    f"风险评分 {t.risk.get('score')}/100 等级 "
                    f"{t.risk.get('grade')}", "risk_rating")
            else:
                t.risk = {"score": None, "grade": "N/A", "level": "unknown",
                          "by_severity": {}, "top_risks": [],
                          "note": "未评估：无资源清单（未配置云凭证）"}
                self.push.sync_log(
                    t.task_id, "WARNING",
                    "风险评级跳过：未发现真实资源", "risk_rating")

            # 阶段4 漏洞检测
            self._stage(t, "vuln_detect", "漏洞检测", 78, 15)
            vr = self.vuln.detect(t.inventory)
            t.vuln = vr
            self.push.sync_log(
                t.task_id, "SUCCESS",
                f"CVE 匹配 {vr.get('count',0)} 个", "vuln_detect")

            # 阶段5 合规审计
            self._stage(t, "compliance_audit", "合规审计", 92, 10)
            if cr.executed:
                cp = self.compliance.audit(t.config.get("findings", []))
                t.compliance = cp.to_dict()
                self.push.sync_log(
                    t.task_id, "NOTICE",
                    f"合规通过率 {t.compliance.get('pass_rate')}%",
                    "compliance_audit")
            else:
                t.compliance = {"pass_rate": None, "frameworks": {},
                                "note": "未审计：无资源清单"}
                self.push.sync_log(
                    t.task_id, "WARNING",
                    "合规审计跳过：未发现真实资源", "compliance_audit")

            # AI 分析 + 报告
            self._stage(t, "ai_report", "AI分析与报告", 100, 5)
            t.ai = self.ai.analyze(t.inventory, t.config, t.risk,
                                   t.vuln, t.compliance)
            rd = CloudReportData(
                task_id=t.task_id, provider=provider,
                started_at=t.created_at,
                finished_at=time.strftime("%Y-%m-%d %H:%M:%S"),
                inventory=t.inventory, config=t.config, risk=t.risk,
                vuln=t.vuln, compliance=t.compliance, ai=t.ai)
            t.report_path = self.report.save(rd, "html")
            t.report_markdown = self.report.generate_markdown(rd)
            t.report_html = self.report.generate_html(rd)
            self.push.sync_log(t.task_id, "SUCCESS",
                               f"报告已生成: {t.report_path}", "ai_report")

            t.status = "done"
            t.stage = "done"
            t.progress = 100
            t.finished_at = time.strftime("%Y-%m-%d %H:%M:%S")
            self.push.sync_progress(t.task_id, 100, "done", "完成", 0)
            self.push.sync_stage(t.task_id, "done", "done", "全部完成")
        except Exception as e:  # noqa: BLE001
            t.status = "error"
            t.error = f"{type(e).__name__}: {e}"
            self.push.sync_log(t.task_id, "ERROR", f"失败: {t.error}")
            t.finished_at = time.strftime("%Y-%m-%d %H:%M:%S")
        return t


_default_orch: Optional[CloudSecurityOrchestrator] = None


def get_orchestrator() -> CloudSecurityOrchestrator:
    global _default_orch
    if _default_orch is None:
        _default_orch = CloudSecurityOrchestrator()
    return _default_orch
