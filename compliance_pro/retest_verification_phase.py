# -*- coding: utf-8 -*-
"""
retest_verification_phase.py — 阶段6：复测验证。

- 整改后自动复测
- 验证结果（通过/未通过/部分通过）
- 更新合规状态
- 复测记录 / 报告 / 未通过回流整改 / 通过率统计
"""

from __future__ import annotations

import threading
import uuid
from dataclasses import asdict, dataclass, field
from datetime import datetime
from typing import Any, Dict, List, Optional


@dataclass
class RetestRecord:
    retest_id: str = ""
    gap_id: str = ""
    task_id: str = ""
    result: str = "pending"  # pass/fail/partial
    evidence: str = ""
    notes: str = ""
    retested_at: str = ""

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


class RetestVerificationPhase:
    """阶段6：复测验证。"""

    def __init__(self) -> None:
        self._records: Dict[str, RetestRecord] = {}
        self._lock = threading.Lock()

    # ------------------------------------------------------------------ #
    def retest_gap(self, gap_id: str, task_id: str = "",
                   evidence: str = "") -> Dict[str, Any]:
        """对整改后的差距项自动复测。"""
        from .gap_analysis_phase import get_gap_analysis_phase
        from .remediation_tracking_phase import (
            get_remediation_tracking_phase)
        gaps = get_gap_analysis_phase()
        rm = get_remediation_tracking_phase()

        gap = gaps.get_gap(gap_id)
        if gap is None:
            return {"error": "gap not found"}
        # 模拟复测：若整改任务已完成则大概率通过
        task = rm.get_task(task_id) if task_id else None
        if task and task["status"] == "completed":
            result = "pass"
        elif task and task["status"] == "in_progress":
            result = "partial"
        else:
            result = "fail"
        rid = "ret_" + uuid.uuid4().hex[:10]
        rec = RetestRecord(
            retest_id=rid, gap_id=gap_id, task_id=task_id, result=result,
            evidence=evidence or f"自动复测: {result}",
            notes="整改完成后复测通过" if result == "pass"
                  else ("整改未完成，复测未通过，回流整改"
                        if result == "fail" else "部分通过，需补充整改"),
            retested_at=datetime.now().isoformat(timespec="seconds"),
        )
        with self._lock:
            self._records[rid] = rec
        # 更新差距状态
        if result == "pass":
            gaps.update_gap(gap_id, status="verified")
        elif result == "fail":
            gaps.update_gap(gap_id, status="open")
            if task_id:
                rm.update_task(task_id, status="in_progress",
                               progress_note="复测未通过，重新整改")
        return rec.to_dict()

    def retest_batch(self, gap_ids: List[str]) -> Dict[str, Any]:
        results = []
        for gid in gap_ids:
            results.append(self.retest_gap(gid))
        return {"retested": len(results), "results": results,
                "stats": self.stats()}

    # ------------------------------------------------------------------ #
    def list_records(self, result: Optional[str] = None) -> List[Dict[str, Any]]:
        with self._lock:
            items = list(self._records.values())
        out = [r.to_dict() for r in items]
        if result:
            out = [r for r in out if r["result"] == result]
        return out

    def stats(self) -> Dict[str, Any]:
        with self._lock:
            items = list(self._records.values())
        total = len(items)
        passed = sum(1 for r in items if r.result == "pass")
        failed = sum(1 for r in items if r.result == "fail")
        partial = sum(1 for r in items if r.result == "partial")
        return {"total": total, "pass": passed, "fail": failed,
                "partial": partial,
                "pass_rate": round(passed / max(1, total) * 100, 1)}

    def retest_report(self) -> Dict[str, Any]:
        return {"stats": self.stats(),
                "records": [r.to_dict() for r in self._records.values()],
                "generated_at": datetime.now().isoformat(
                    timespec="seconds")}


_default: Optional[RetestVerificationPhase] = None


def get_retest_verification_phase() -> RetestVerificationPhase:
    global _default
    if _default is None:
        _default = RetestVerificationPhase()
    return _default
