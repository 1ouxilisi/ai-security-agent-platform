# -*- coding: utf-8 -*-
"""report_dashboard.py — 报告管理控制台（第20轮·报告引擎做深）。

六大能力：
1. 报告库：列表/分类/标签/搜索/筛选/排序/收藏/归档/状态
2. 报告生成向导：类型→模板→数据→配置→预览→生成→下载
3. 报告模板管理：列表/创建/编辑/预览/克隆/导入导出/使用统计
4. 指标与统计：数量/类型分布/生成时长/质量分/满意度/及时率/趋势
5. 客户报告门户：登录/列表/在线查看/下载/评论/确认/历史/反馈
6. 报告自动化：定时/触发/模板填充/数据聚合/自动发送/审批/规则

全部内存字典模拟。
"""

from __future__ import annotations

import threading
import time
import uuid
from datetime import datetime
from typing import Any, Dict, List, Optional


class ReportDashboard:
    """报告管理控制台后端数据。"""

    def __init__(self) -> None:
        self._lock = threading.RLock()
        self._reports: Dict[str, Dict[str, Any]] = {}
        self._favorites: set = set()
        self._templates: Dict[str, Dict[str, Any]] = {}
        self._customers: Dict[str, Dict[str, Any]] = {}
        self._portal_sessions: Dict[str, Dict[str, Any]] = {}
        self._automation_rules: Dict[str, Dict[str, Any]] = {}
        self._seed()

    # ---- 演示种子数据 ---- #
    def _seed(self) -> None:
        now = datetime.now().isoformat(timespec="seconds")
        for i in range(1, 9):
            rid = f"RPT-{1000 + i}"
            self._reports[rid] = {
                "report_id": rid,
                "title": f"示例安全评估报告 #{i}",
                "client": "示例客户" if i % 2 else "示例金融客户",
                "report_type": ["penetration_test", "vulnerability_assessment",
                                "security_audit", "compliance_assessment"][i % 4],
                "industry": ["finance", "internet", "healthcare", "government"][i % 4],
                "status": ["draft", "reviewing", "final", "archived"][i % 4],
                "tags": ["年度", "复测", "专项"][i % 3],
                "created_at": now,
                "author": "分析师A",
                "vuln_count": 5 + i * 3,
                "quality_score": 80 + i,
                "archived": False,
            }
        self._templates["TPL-PENTEST-V2"] = {
            "id": "TPL-PENTEST-V2", "name": "标准版渗透测试模板",
            "category": "penetration_test", "version": "2.1", "uses": 42, "approved": True}
        self._templates["TPL-MLPS-3"] = {
            "id": "TPL-MLPS-3", "name": "等保2.0三级测评模板",
            "category": "compliance", "version": "1.4", "uses": 18, "approved": True}
        self._customers["CUST-001"] = {
            "id": "CUST-001", "name": "示例金融客户", "contact": "security@example.com",
            "reports": ["RPT-1001", "RPT-1005"], "feedback": []}

    # ---- 1. 报告库 ---- #
    def list_reports(self, keyword: Optional[str] = None,
                     status: Optional[str] = None,
                     report_type: Optional[str] = None,
                     sort_by: str = "created_at",
                     desc: bool = True) -> Dict[str, Any]:
        rows = list(self._reports.values())
        if keyword:
            kw = keyword.lower()
            rows = [r for r in rows if kw in r["title"].lower() or kw in r["client"].lower()]
        if status:
            rows = [r for r in rows if r["status"] == status]
        if report_type:
            rows = [r for r in rows if r["report_type"] == report_type]
        rows.sort(key=lambda r: r.get(sort_by, ""), reverse=desc)
        return {"total": len(rows), "reports": rows,
                "favorites": list(self._favorites)}

    def get_report(self, rid: str) -> Optional[Dict[str, Any]]:
        return self._reports.get(rid)

    def toggle_favorite(self, rid: str) -> Dict[str, Any]:
        if rid in self._favorites:
            self._favorites.discard(rid)
            return {"report_id": rid, "favorite": False}
        self._favorites.add(rid)
        return {"report_id": rid, "favorite": True}

    def archive_report(self, rid: str, archived: bool = True) -> Dict[str, Any]:
        r = self._reports.get(rid)
        if not r:
            return {"error": "报告不存在"}
        r["archived"] = archived
        r["status"] = "archived" if archived else "draft"
        return {"report_id": rid, "archived": archived}

    def delete_report(self, rid: str) -> bool:
        with self._lock:
            return self._reports.pop(rid, None) is not None

    # ---- 2. 生成向导 ---- #
    def wizard_start(self, report_type: str, industry: str,
                     template_id: str, client: str) -> Dict[str, Any]:
        rid = f"RPT-{uuid.uuid4().hex[:6].upper()}"
        doc = {
            "report_id": rid, "title": f"{report_type}-{client}",
            "client": client, "report_type": report_type,
            "industry": industry, "template_id": template_id,
            "status": "draft", "tags": ["向导生成"], "archived": False,
            "created_at": datetime.now().isoformat(timespec="seconds"),
            "author": "wizard", "vuln_count": 0, "quality_score": 0,
            "wizard_stage": "data", "progress": 10,
        }
        self._reports[rid] = doc
        return {"report_id": rid, "stage": "data", "progress": 10,
                "message": "向导已启动，请选择数据与配置"}

    def wizard_preview(self, rid: str) -> Dict[str, Any]:
        r = self._reports.get(rid)
        if not r:
            return {"error": "报告不存在"}
        r["wizard_stage"] = "preview"
        r["progress"] = 70
        return {"report_id": rid, "stage": "preview", "progress": 70,
                "preview_sections": ["封面", "执行摘要", "漏洞详情", "修复建议"],
                "estimated_pages": max(8, r.get("vuln_count", 10) // 3)}

    def wizard_generate(self, rid: str) -> Dict[str, Any]:
        r = self._reports.get(rid)
        if not r:
            return {"error": "报告不存在"}
        r["status"] = "reviewing"
        r["wizard_stage"] = "done"
        r["progress"] = 100
        r["generated_at"] = datetime.now().isoformat(timespec="seconds")
        r["vuln_count"] = r.get("vuln_count") or 12
        return {"report_id": rid, "status": "reviewing", "progress": 100,
                "message": "报告生成完成，进入审核"}

    # ---- 3. 模板管理 ---- #
    def list_templates(self) -> List[Dict[str, Any]]:
        return list(self._templates.values())

    def create_template(self, name: str, category: str,
                        description: str = "") -> Dict[str, Any]:
        tid = f"TPL-{uuid.uuid4().hex[:6].upper()}"
        doc = {"id": tid, "name": name, "category": category,
               "version": "1.0", "uses": 0, "approved": False,
               "description": description, "created_at": datetime.now().isoformat(timespec="seconds")}
        self._templates[tid] = doc
        return doc

    def update_template(self, tid: str, patch: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        with self._lock:
            if tid in self._templates:
                self._templates[tid].update(patch)
                return self._templates[tid]
        return None

    def clone_template(self, tid: str) -> Optional[Dict[str, Any]]:
        src = self._templates.get(tid)
        if not src:
            return None
        new_id = f"TPL-{uuid.uuid4().hex[:6].upper()}"
        clone = {**src, "id": new_id, "name": src["name"] + "(副本)", "uses": 0}
        self._templates[new_id] = clone
        return clone

    def delete_template(self, tid: str) -> bool:
        with self._lock:
            return self._templates.pop(tid, None) is not None

    def approve_template(self, tid: str) -> Dict[str, Any]:
        t = self._templates.get(tid)
        if not t:
            return {"error": "模板不存在"}
        t["approved"] = True
        return {"id": tid, "approved": True}

    # ---- 4. 指标统计 ---- #
    def metrics(self) -> Dict[str, Any]:
        rows = list(self._reports.values())
        total = len(rows)
        by_type: Dict[str, int] = {}
        by_status: Dict[str, int] = {}
        scores = []
        for r in rows:
            by_type[r["report_type"]] = by_type.get(r["report_type"], 0) + 1
            by_status[r["status"]] = by_status.get(r["status"], 0) + 1
            if r.get("quality_score"):
                scores.append(r["quality_score"])
        avg_score = round(sum(scores) / len(scores), 1) if scores else 0
        return {
            "total_reports": total,
            "by_type": by_type,
            "by_status": by_status,
            "avg_quality_score": avg_score,
            "avg_generation_seconds": 18.5,
            "customer_satisfaction": 4.6,
            "delivery_on_time_rate": 0.94,
            "trend": [
                {"month": "2026-04", "count": 8},
                {"month": "2026-05", "count": 12},
                {"month": "2026-06", "count": 15},
                {"month": "2026-07", "count": 11},
                {"month": "2026-08", "count": 18},
                {"month": "2026-09", "count": total},
            ],
            "template_uses_total": sum(t["uses"] for t in self._templates.values()),
        }

    # ---- 5. 客户门户 ---- #
    def portal_login(self, customer_id: str, token: str = "") -> Dict[str, Any]:
        c = self._customers.get(customer_id)
        if not c:
            return {"error": "客户不存在"}
        sid = uuid.uuid4().hex[:16]
        self._portal_sessions[sid] = {"customer_id": customer_id,
                                      "login_at": datetime.now().isoformat(timespec="seconds")}
        return {"session_id": sid, "customer": c, "message": "登录成功"}

    def portal_reports(self, customer_id: str) -> List[Dict[str, Any]]:
        c = self._customers.get(customer_id)
        if not c:
            return []
        return [self._reports[rid] for rid in c.get("reports", []) if rid in self._reports]

    def portal_feedback(self, customer_id: str, rating: int,
                        comment: str) -> Dict[str, Any]:
        c = self._customers.get(customer_id)
        if not c:
            return {"error": "客户不存在"}
        fb = {"rating": rating, "comment": comment,
              "at": datetime.now().isoformat(timespec="seconds")}
        c.setdefault("feedback", []).append(fb)
        return {"customer_id": customer_id, "feedback": fb}

    # ---- 6. 报告自动化 ---- #
    def list_automation_rules(self) -> List[Dict[str, Any]]:
        return list(self._automation_rules.values())

    def create_automation_rule(self, name: str, trigger: str,
                              template_id: str, schedule: str = "0 8 * * 1",
                              recipients: Optional[List[str]] = None) -> Dict[str, Any]:
        rid = f"AUTO-{uuid.uuid4().hex[:6].upper()}"
        doc = {
            "id": rid, "name": name, "trigger": trigger,
            "template_id": template_id, "schedule": schedule,
            "recipients": recipients or [], "enabled": True,
            "last_run": None, "run_count": 0,
            "created_at": datetime.now().isoformat(timespec="seconds"),
        }
        self._automation_rules[rid] = doc
        return doc

    def run_automation_rule(self, rid: str) -> Dict[str, Any]:
        r = self._automation_rules.get(rid)
        if not r:
            return {"error": "规则不存在"}
        r["run_count"] += 1
        r["last_run"] = datetime.now().isoformat(timespec="seconds")
        return {"id": rid, "run_count": r["run_count"], "last_run": r["last_run"],
                "message": "规则已触发（模拟）"}

    def toggle_automation_rule(self, rid: str, enabled: bool) -> Dict[str, Any]:
        r = self._automation_rules.get(rid)
        if not r:
            return {"error": "规则不存在"}
        r["enabled"] = enabled
        return {"id": rid, "enabled": enabled}


_singleton: Optional[ReportDashboard] = None


def get_dashboard() -> ReportDashboard:
    global _singleton
    if _singleton is None:
        _singleton = ReportDashboard()
    return _singleton
