# -*- coding: utf-8 -*-
"""
test_dashboard.py — 测试管理与仪表盘。

能力：
  1. 测试用例管理：用例库 / 分类 / 标签 / 优先级 / 状态 / 评审 / 关联需求
  2. 测试执行管理：计划 / 轮次 / 执行记录 / 结果统计 / 缺陷关联
  3. 缺陷管理：创建 / 分类 / 严重程度 / 优先级 / 状态 / 分配 / 复发检测
  4. 测试度量：用例数 / 覆盖率 / 通过率 / 缺陷数 / 修复率 / MTTR / 趋势
  5. 测试仪表盘：实时状态 / 覆盖率趋势 / 缺陷分布 / 质量评分
  6. 报告生成：单元 / 集成 / 性能 / 安全 / 综合报告与导出

仅依赖标准库；全部内存字典模拟。
"""

from __future__ import annotations

import random
import time
import uuid
from typing import Any, Dict, List, Optional


# --------------------------------------------------------------------------- #
# 1. 测试用例管理
# --------------------------------------------------------------------------- #
class TestCaseManager:
    PRIORITIES = ["P0", "P1", "P2", "P3"]
    STATUSES = ["draft", "ready", "approved", "deprecated"]
    TYPES = ["unit", "integration", "e2e", "performance", "security"]

    def __init__(self) -> None:
        self.cases: Dict[str, Dict[str, Any]] = {}
        self._seed_library()

    def _seed_library(self) -> None:
        rng = random.Random(2026)
        for t in self.TYPES:
            for i in range(1, 9):
                cid = f"TC-{t[:2].upper()}-{100 + i}"
                self.cases[cid] = {
                    "case_id": cid, "title": f"[{t}] 场景 {i}",
                    "type": t, "priority": rng.choice(self.PRIORITIES),
                    "status": rng.choice(self.STATUSES),
                    "tags": [t, "regression"] if i % 2 else [t],
                    "requirement": f"REQ-{500 + i}",
                    "reviewer": "qa-lead",
                }

    def create(self, title: str, ctype: str = "unit",
               priority: str = "P2") -> Dict[str, Any]:
        cid = f"TC-{ctype[:2].upper()}-{random.randint(100, 999)}"
        c = {"case_id": cid, "title": title, "type": ctype,
             "priority": priority, "status": "draft",
             "tags": [ctype], "requirement": "", "reviewer": ""}
        self.cases[cid] = c
        return c

    def list(self, ctype: Optional[str] = None,
             priority: Optional[str] = None) -> Dict[str, Any]:
        rows = list(self.cases.values())
        if ctype:
            rows = [r for r in rows if r["type"] == ctype]
        if priority:
            rows = [r for r in rows if r["priority"] == priority]
        by_pri: Dict[str, int] = {}
        by_type: Dict[str, int] = {}
        for r in self.cases.values():
            by_pri[r["priority"]] = by_pri.get(r["priority"], 0) + 1
            by_type[r["type"]] = by_type.get(r["type"], 0) + 1
        return {"total": len(self.cases), "by_priority": by_pri,
                "by_type": by_type, "cases": rows[:200]}


# --------------------------------------------------------------------------- #
# 2. 测试执行管理
# --------------------------------------------------------------------------- #
class ExecutionManager:
    def __init__(self) -> None:
        self.runs: List[Dict[str, Any]] = []

    def start_run(self, name: str, ctype: str = "all") -> Dict[str, Any]:
        run = {
            "run_id": uuid.uuid4().hex[:12], "name": name, "type": ctype,
            "started_at": time.strftime("%Y-%m-%d %H:%M:%S"),
            "finished_at": None, "stats": {}, "status": "running",
        }
        rng = random.Random(time.time_ns() % 100000)
        total = rng.randint(120, 400)
        passed = int(total * rng.uniform(0.88, 0.99))
        failed = total - passed
        run["stats"] = {"total": total, "passed": passed,
                        "failed": failed, "skipped": rng.randint(0, 8)}
        run["status"] = "done"
        run["finished_at"] = time.strftime("%Y-%m-%d %H:%M:%S")
        self.runs.append(run)
        return run

    def history(self) -> Dict[str, Any]:
        return {"count": len(self.runs), "runs": self.runs[-20:]}


# --------------------------------------------------------------------------- #
# 3. 缺陷管理
# --------------------------------------------------------------------------- #
class DefectManager:
    SEVERITIES = ["S1-blocker", "S2-critical", "S3-major", "S4-minor"]
    STATUSES = ["open", "in_progress", "fixed", "verified", "closed", "reopened"]

    def __init__(self) -> None:
        self.bugs: Dict[str, Dict[str, Any]] = {}
        self._seed()

    def _seed(self) -> None:
        rng = random.Random(7)
        for i in range(1, 9):
            bid = f"BUG-{2000 + i}"
            self.bugs[bid] = {
                "bug_id": bid, "title": f"回归缺陷 {i}",
                "severity": rng.choice(self.SEVERITIES),
                "status": rng.choice(self.STATUSES),
                "owner": rng.choice(["alice", "bob", "carol"]),
                "recurrence": False,
                "created_at": time.strftime("%Y-%m-%d"),
            }

    def create(self, title: str, severity: str = "S3-major") -> Dict[str, Any]:
        bid = f"BUG-{random.randint(2000, 9999)}"
        b = {"bug_id": bid, "title": title, "severity": severity,
             "status": "open", "owner": "unassigned", "recurrence": False,
             "created_at": time.strftime("%Y-%m-%d")}
        self.bugs[bid] = b
        return b

    def list(self) -> Dict[str, Any]:
        by_sev: Dict[str, int] = {}
        by_status: Dict[str, int] = {}
        for b in self.bugs.values():
            by_sev[b["severity"]] = by_sev.get(b["severity"], 0) + 1
            by_status[b["status"]] = by_status.get(b["status"], 0) + 1
        return {"total": len(self.bugs), "by_severity": by_sev,
                "by_status": by_status, "bugs": list(self.bugs.values())[:50]}


# --------------------------------------------------------------------------- #
# 4. 测试度量
# --------------------------------------------------------------------------- #
class TestMetrics:
    def __init__(self, cases: TestCaseManager,
                 runs: ExecutionManager, bugs: DefectManager) -> None:
        self.cases = cases
        self.runs = runs
        self.bugs = bugs

    def metrics(self) -> Dict[str, Any]:
        runs = self.runs.runs
        total_exec = sum(r["stats"].get("total", 0) for r in runs)
        total_pass = sum(r["stats"].get("passed", 0) for r in runs)
        closed = sum(1 for b in self.bugs.bugs.values() if b["status"] in ("closed", "verified"))
        total_bugs = max(1, len(self.bugs.bugs))
        trend = [
            {"day": f"D-{i}", "pass_rate": round(88 + i * 0.3 + random.uniform(-1, 1), 2)}
            for i in range(7, 0, -1)
        ]
        return {
            "case_count": len(self.cases.cases),
            "executed_cases": total_exec,
            "pass_rate": round(100 * total_pass / max(1, total_exec), 2),
            "coverage": {"line": 76.4, "branch": 68.1, "function": 82.0},
            "open_bugs": len(self.bugs.bugs) - closed,
            "fix_rate": round(100 * closed / total_bugs, 1),
            "mttr_hours": round(random.uniform(4, 20), 1),
            "trend": trend,
        }


# --------------------------------------------------------------------------- #
# 5. 仪表盘
# --------------------------------------------------------------------------- #
class DashboardBuilder:
    def __init__(self, metrics: TestMetrics, monitor: Any) -> None:
        self.metrics = metrics
        self.monitor = monitor

    def dashboard(self) -> Dict[str, Any]:
        m = self.metrics.metrics()
        mon = self.monitor.dashboard()
        quality_score = round(
            0.3 * m["pass_rate"] + 0.25 * m["coverage"]["line"] +
            0.2 * m["fix_rate"] + 0.25 * mon["success_rate"], 1)
        return {
            "quality_score": quality_score,
            "quality_grade": "A" if quality_score >= 85 else ("B" if quality_score >= 70 else "C"),
            "test_status": {"running_runs": 0, "last_run_status": "done"},
            "coverage": m["coverage"],
            "pass_rate": m["pass_rate"],
            "open_bugs": m["open_bugs"],
            "pipeline": {"success_rate": mon["success_rate"],
                         "avg_duration_s": mon["avg_duration_s"]},
            "gate": {"recent_pass": True},
            "updated_at": time.strftime("%Y-%m-%d %H:%M:%S"),
        }


# --------------------------------------------------------------------------- #
# 6. 报告生成
# --------------------------------------------------------------------------- #
class ReportGenerator:
    def __init__(self, metrics: TestMetrics, dash: DashboardBuilder) -> None:
        self.metrics = metrics
        self.dash = dash

    def report(self, kind: str = "comprehensive") -> Dict[str, Any]:
        m = self.metrics.metrics()
        d = self.dash.dashboard()
        md = (
            f"# 测试报告 ({kind})\n\n"
            f"- 生成时间: {time.strftime('%Y-%m-%d %H:%M:%S')}\n"
            f"- 质量评分: {d['quality_score']} ({d['quality_grade']})\n"
            f"- 通过率: {m['pass_rate']}%\n"
            f"- 行覆盖率: {m['coverage']['line']}%\n"
            f"- 未关闭缺陷: {m['open_bugs']}\n"
            f"- 修复率: {m['fix_rate']}%\n"
            f"- MTTR: {m['mttr_hours']}h\n"
        )
        return {"kind": kind, "markdown": md, "format": ["html", "pdf", "json", "md"]}


# --------------------------------------------------------------------------- #
# 顶层门面
# --------------------------------------------------------------------------- #
class TestDashboardManager:
    def __init__(self) -> None:
        from testing.cicd_pipeline import PipelineMonitor
        self.cases = TestCaseManager()
        self.executions = ExecutionManager()
        self.bugs = DefectManager()
        self.metrics = TestMetrics(self.cases, self.executions, self.bugs)
        self.dashboard = DashboardBuilder(self.metrics, PipelineMonitor())
        self.reports = ReportGenerator(self.metrics, self.dashboard)
        # 预跑一轮执行，让度量有数据
        self.executions.start_run("nightly-regression")
        self.executions.start_run("pr-gate")
