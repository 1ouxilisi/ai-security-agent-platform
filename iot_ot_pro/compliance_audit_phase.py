# -*- coding: utf-8 -*-
"""
compliance_audit_phase.py — 阶段8：合规审计。

IEC 62443:
    - 62443-2-1 安全管理体系
    - 62443-3-3 系统安全要求与安全等级
    - 62443-4-1 安全产品开发生命周期
    - 62443-4-2 组件技术安全要求
    - 安全等级 SL1/SL2/SL3/SL4
NIST IoT:
    - NIST IR 8259 IoT 设备网络安全能力核心基线
    - NIST SP 800-213 IoT 设备网络安全指南
    - 设备识别/配置/数据保护/接口访问/软件更新/状态感知
合规项: 通过/失败/不适用/部分符合；评分与报告。
"""

from __future__ import annotations

import random
import threading
import uuid
from dataclasses import dataclass, field
from datetime import datetime
from typing import Any, Dict, List, Optional

IEC62443_ITEMS = [
    ("62443-2-1", "安全策略与组织", "SL2"),
    ("62443-2-1", "人员安全培训", "SL1"),
    ("62443-3-3", "网络分段与边界防护", "SL3"),
    ("62443-3-3", "访问控制(身份鉴别)", "SL3"),
    ("62443-4-1", "安全开发生命周期(SDL)", "SL2"),
    ("62443-4-1", "漏洞管理与补丁", "SL3"),
    ("62443-4-2", "通信保密性/完整性", "SL3"),
    ("62443-4-2", "组件加固与日志审计", "SL2"),
]

NIST_IOT_ITEMS = [
    ("NIST IR 8259", "设备识别(Inventory)"),
    ("NIST IR 8259", "设备配置(Config)"),
    ("NIST IR 8259", "数据保护(Data Protection)"),
    ("NIST IR 8259", "接口访问(Interface Access)"),
    ("NIST IR 8259", "软件更新(Update)"),
    ("NIST SP 800-213", "网络安全状态感知(State Awareness)"),
    ("NIST SP 800-213", "设备最小化攻击面"),
]

STATUS = ["pass", "fail", "na", "partial"]


@dataclass
class ComplianceItem:
    item_id: str = ""
    standard: str = ""
    requirement: str = ""
    target_sl: str = ""
    status: str = "partial"
    score: int = 0
    evidence: str = ""
    note: str = ""
    audited_at: str = ""

    def to_dict(self) -> Dict[str, Any]:
        return {
            "item_id": self.item_id, "standard": self.standard,
            "requirement": self.requirement, "target_sl": self.target_sl,
            "status": self.status, "score": self.score,
            "evidence": self.evidence, "note": self.note,
            "audited_at": self.audited_at,
        }


class ComplianceAuditPhase:
    """阶段8：合规审计。"""

    def __init__(self) -> None:
        self._items: Dict[str, ComplianceItem] = {}
        self._lock = threading.Lock()

    # ------------------------------------------------------------------ #
    def run_audit(self) -> Dict[str, Any]:
        rng = random.Random(int(datetime.now().timestamp()) & 0xffff)
        # IEC 62443
        for std, req, sl in IEC62443_ITEMS:
            status = rng.choices(STATUS, weights=[3, 4, 1, 3])[0]
            score = {"pass": 100, "partial": 60, "fail": 15,
                     "na": 100}[status]
            self._add(std, req, sl, status, score,
                      f"对照 {std} {req} 评估",
                      f"目标等级 {sl}")
        # NIST IoT
        for std, req in NIST_IOT_ITEMS:
            status = rng.choices(STATUS, weights=[4, 3, 1, 3])[0]
            score = {"pass": 100, "partial": 55, "fail": 10,
                     "na": 100}[status]
            self._add(std, req, "-", status, score,
                      f"对照 {std} {req} 评估", "")
        return self.summary()

    def _add(self, std: str, req: str, sl: str, status: str,
             score: int, evidence: str, note: str) -> None:
        it = ComplianceItem(
            item_id="ci_" + uuid.uuid4().hex[:10],
            standard=std, requirement=req, target_sl=sl,
            status=status, score=score, evidence=evidence, note=note,
            audited_at=datetime.now().isoformat(timespec="seconds"),
        )
        with self._lock:
            self._items[it.item_id] = it

    # ------------------------------------------------------------------ #
    def list_items(self, standard: Optional[str] = None,
                   status: Optional[str] = None) -> List[Dict[str, Any]]:
        with self._lock:
            items = list(self._items.values())
        if standard:
            items = [i for i in items if i.standard == standard]
        if status:
            items = [i for i in items if i.status == status]
        return [i.to_dict() for i in items][::-1]

    def update_item(self, item_id: str, status: str,
                    note: str = "") -> Optional[Dict[str, Any]]:
        if status not in STATUS:
            return None
        with self._lock:
            it = self._items.get(item_id)
            if it is None:
                return None
            it.status = status
            it.score = {"pass": 100, "partial": 60, "fail": 15,
                        "na": 100}[status]
            if note:
                it.note = note
            return it.to_dict()

    # ------------------------------------------------------------------ #
    def summary(self) -> Dict[str, Any]:
        with self._lock:
            items = list(self._items.values())
        if not items:
            return {"total": 0, "by_status": {}, "overall_score": 0,
                    "by_standard": {}}
        by_status: Dict[str, int] = {}
        by_standard: Dict[str, Dict[str, Any]] = {}
        scored = [i.score for i in items if i.status != "na"]
        for i in items:
            by_status[i.status] = by_status.get(i.status, 0) + 1
            bs = by_standard.setdefault(
                i.standard, {"total": 0, "pass": 0, "fail": 0,
                            "partial": 0})
            bs["total"] += 1
            bs[i.status] = bs.get(i.status, 0) + 1
        overall = round(sum(scored) / max(1, len(scored)), 1)
        return {"total": len(items), "by_status": by_status,
                "overall_score": overall, "by_standard": by_standard}

    def standards_reference(self) -> Dict[str, Any]:
        return {
            "iec62443": [
                {"standard": s, "requirement": r, "target_sl": sl}
                for s, r, sl in IEC62443_ITEMS],
            "nist_iot": [
                {"standard": s, "requirement": r}
                for s, r in NIST_IOT_ITEMS],
            "sl_levels": ["SL1", "SL2", "SL3", "SL4"],
            "status": STATUS,
        }


_default: Optional[ComplianceAuditPhase] = None


def get_compliance_audit_phase() -> ComplianceAuditPhase:
    global _default
    if _default is None:
        _default = ComplianceAuditPhase()
    return _default
