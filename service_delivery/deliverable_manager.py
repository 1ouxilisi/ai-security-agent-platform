#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
deliverable_manager.py — 交付物管理。

覆盖：
    - 交付物清单 / 模板
    - 版本管理、审核流程、签收确认
    - 归档管理、交付确认书、质量检查
    - 客户验收、交付物统计
"""

from __future__ import annotations

import uuid
from datetime import datetime
from typing import Any, Dict, List, Optional


DELIVERABLE_TEMPLATES: Dict[str, Dict[str, Any]] = {
    "pentest_report": {"name": "渗透测试报告", "format": "PDF",
                        "pages": "30-60", "owner_role": "项目负责人"},
    "compliance_report": {"name": "合规审计报告", "format": "PDF",
                          "pages": "80-150", "owner_role": "合规专家"},
    "ir_report": {"name": "应急响应报告", "format": "PDF",
                  "pages": "20-40", "owner_role": "应急负责人"},
    "training_material": {"name": "安全培训课件", "format": "PPTX",
                          "pages": "40-80", "owner_role": "培训讲师"},
    "hw_daily": {"name": "护网日报", "format": "DOCX",
                 "pages": "5-10", "owner_role": "值守工程师"},
    "risk_report": {"name": "风险评估报告", "format": "PDF",
                     "pages": "50-100", "owner_role": "风险顾问"},
    "code_audit_report": {"name": "代码审计报告", "format": "PDF",
                          "pages": "40-80", "owner_role": "代码审计师"},
    "cloud_baseline": {"name": "云配置基线报告", "format": "PDF",
                       "pages": "30-60", "owner_role": "云安全顾问"},
}

REVIEW_STATUS: List[str] = ["draft", "in_review", "approved", "rejected",
                            "signed_off", "archived"]


def _uid(prefix: str) -> str:
    return f"{prefix}-{uuid.uuid4().hex[:8].upper()}"


def _now() -> str:
    return datetime.now().strftime("%Y-%m-%d %H:%M:%S")


class DeliverableManager:
    """交付物清单 / 版本 / 审核 / 签收 / 归档 / 质量检查。"""

    def __init__(self) -> None:
        self.items: Dict[str, Dict[str, Any]] = {}
        self.versions: Dict[str, List[Dict[str, Any]]] = {}
        self.reviews: Dict[str, List[Dict[str, Any]]] = {}
        self._seed()

    def _seed(self) -> None:
        seeds = [
            ("DEL-001", "PRJ-DEMO-001", "pentest_report", "初版渗透测试报告"),
            ("DEL-002", "PRJ-DEMO-001", "pentest_report", "复测报告"),
            ("DEL-003", "PRJ-DEMO-002", "compliance_report", "等保差距分析"),
            ("DEL-004", "PRJ-DEMO-003", "ir_report", "勒索事件分析报告"),
        ]
        for did, pid, tpl, title in seeds:
            self.items[did] = {
                "deliverable_id": did, "project_id": pid, "template": tpl,
                "title": title, "current_version": "v1.0",
                "status": "in_review", "quality_score": 88,
                "owner": "张工", "created_at": _now(), "signed_at": None,
                "archived": False,
            }
            self.versions[did] = [
                {"version": "v0.9", "author": "李工", "time": _now(),
                 "note": "初稿"},
                {"version": "v1.0", "author": "张工", "time": _now(),
                 "note": "修订版"},
            ]
            self.reviews[did] = [
                {"reviewer": "王专家", "result": "pass",
                 "comment": "结构完整", "time": _now()},
            ]

    # ------------------------- 清单 ------------------------- #
    def list_items(self, project_id: Optional[str] = None,
                   status: Optional[str] = None) -> List[Dict[str, Any]]:
        items = list(self.items.values())
        if project_id:
            items = [x for x in items if x["project_id"] == project_id]
        if status:
            items = [x for x in items if x["status"] == status]
        return items

    def get_item(self, did: str) -> Optional[Dict[str, Any]]:
        return self.items.get(did)

    def create_item(self, project_id: str, template: str,
                    title: str, owner: str) -> Dict[str, Any]:
        did = _uid("DEL")
        item = {"deliverable_id": did, "project_id": project_id,
                "template": template, "title": title,
                "current_version": "v0.1", "status": "draft",
                "quality_score": 0, "owner": owner,
                "created_at": _now(), "signed_at": None, "archived": False}
        self.items[did] = item
        self.versions[did] = [{"version": "v0.1", "author": owner,
                               "time": _now(), "note": "创建"}]
        self.reviews[did] = []
        return item

    # ------------------------- 版本 ------------------------- #
    def add_version(self, did: str, author: str, note: str) -> Optional[Dict[str, Any]]:
        if did not in self.items:
            return None
        arr = self.versions.setdefault(did, [])
        n = len(arr) + 1
        v = f"v1.{n}"
        rec = {"version": v, "author": author, "time": _now(), "note": note}
        arr.append(rec)
        self.items[did]["current_version"] = v
        self.items[did]["status"] = "in_review"
        return rec

    def list_versions(self, did: str) -> List[Dict[str, Any]]:
        return self.versions.get(did, [])

    # ------------------------- 审核 ------------------------- #
    def submit_review(self, did: str, reviewer: str, result: str,
                      comment: str) -> Optional[Dict[str, Any]]:
        if did not in self.items:
            return None
        rec = {"reviewer": reviewer, "result": result,
               "comment": comment, "time": _now()}
        self.reviews.setdefault(did, []).append(rec)
        if result == "pass":
            self.items[did]["status"] = "approved"
        elif result == "fail":
            self.items[did]["status"] = "rejected"
        return rec

    def list_reviews(self, did: str) -> List[Dict[str, Any]]:
        return self.reviews.get(did, [])

    # ------------------------- 质量检查 ------------------------- #
    def quality_check(self, did: str) -> Optional[Dict[str, Any]]:
        item = self.items.get(did)
        if not item:
            return None
        checks = [
            {"item": "目录完整性", "score": 92},
            {"item": "漏洞描述清晰度", "score": 88},
            {"item": "修复建议可操作性", "score": 85},
            {"item": "措辞与保密要求", "score": 95},
            {"item": "排版与格式", "score": 90},
        ]
        avg = round(sum(c["score"] for c in checks) / len(checks), 1)
        item["quality_score"] = avg
        return {"deliverable_id": did, "checks": checks,
                "overall_score": avg, "passed": avg >= 80,
                "time": _now()}

    # ------------------------- 签收 / 归档 ------------------------- #
    def sign_off(self, did: str, customer_name: str) -> Optional[Dict[str, Any]]:
        item = self.items.get(did)
        if not item:
            return None
        item["status"] = "signed_off"
        item["signed_at"] = _now()
        cert = {"cert_id": _uid("DOC"), "deliverable_id": did,
                "title": item["title"], "customer": customer_name,
                "version": item["current_version"],
                "signed_at": item["signed_at"],
                "statement": "客户确认交付物内容完整、质量合格。"}
        return cert

    def archive(self, did: str) -> Optional[Dict[str, Any]]:
        item = self.items.get(did)
        if not item:
            return None
        item["archived"] = True
        item["status"] = "archived"
        return item

    # ------------------------- 统计 ------------------------- #
    def stats(self) -> Dict[str, Any]:
        items = list(self.items.values())
        by_status: Dict[str, int] = {}
        for x in items:
            by_status[x["status"]] = by_status.get(x["status"], 0) + 1
        signed = [x for x in items if x["status"] == "signed_off"]
        archived = [x for x in items if x["archived"]]
        avg_q = round(sum(x["quality_score"] for x in items) / len(items), 1) \
            if items else 0
        return {
            "total": len(items),
            "by_status": by_status,
            "signed_off": len(signed),
            "archived": len(archived),
            "avg_quality_score": avg_q,
            "templates": DELIVERABLE_TEMPLATES,
            "updated_at": _now(),
        }
