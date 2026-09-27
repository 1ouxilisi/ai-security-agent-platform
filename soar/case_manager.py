#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
soar/case_manager.py — 安全案例（事件）管理。

覆盖：
    - 案例创建/分类/分级/分配
    - 时间线（告警、动作、人工记录按时间排序）
    - 证据挂载与引用
    - 协作评论与@指派
    - SLA 计时与自动升级
    - 复盘 (postmortem) 与知识库沉淀
    - 案例报告导出
"""

from __future__ import annotations

import time
import uuid
from typing import Any, Dict, List, Optional


SEVERITIES = ["info", "low", "medium", "high", "critical"]
STATUSES = ["open", "triage", "containment", "eradication", "recovery", "closed"]
CATEGORIES = ["勒索软件", "钓鱼攻击", "入侵", "数据泄露", "内部威胁",
              "恶意软件", "Web 攻击", "云安全", "其他"]

# SLA 阈值（分钟）
SLA_MINUTES = {"critical": 15, "high": 60, "medium": 240, "low": 1440}


class CaseManager:
    """安全案例管理器。"""

    def __init__(self) -> None:
        self.cases: Dict[str, Dict[str, Any]] = {}
        self.knowledge_base: List[Dict[str, Any]] = []
        self.analysts = ["alice", "bob", "carol", "dave"]

    # ---- 创建 ----
    def create(self, title: str, severity: str = "medium",
               category: str = "其他", owner: str = "",
               description: str = "", related_alerts: Optional[List[str]] = None) -> Dict[str, Any]:
        cid = f"CASE-{uuid.uuid4().hex[:8].upper()}"
        now = time.strftime("%Y-%m-%d %H:%M:%S")
        sla_min = SLA_MINUTES.get(severity, 1440)
        case = {
            "case_id": cid, "title": title, "severity": severity, "category": category,
            "owner": owner or self.analysts[0], "description": description,
            "status": "open", "related_alerts": related_alerts or [],
            "evidence": [], "comments": [], "timeline": [],
            "sla": {"threshold_minutes": sla_min, "started_at": now,
                    "due_at": self._due(now, sla_min), "breached": False},
            "created_at": now, "updated_at": now,
        }
        self._log(case, "created", f"案例创建: {title}")
        self.cases[cid] = case
        return case

    @staticmethod
    def _due(started: str, minutes: int) -> str:
        t = time.mktime(time.strptime(started, "%Y-%m-%d %H:%M:%S")) + minutes * 60
        return time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(t))

    @staticmethod
    def _log(case: Dict[str, Any], kind: str, detail: str,
             actor: str = "system") -> None:
        case["timeline"].append({
            "ts": time.strftime("%Y-%m-%d %H:%M:%S"),
            "kind": kind, "detail": detail, "actor": actor,
        })
        case["updated_at"] = time.strftime("%Y-%m-%d %H:%M:%S")

    # ---- 查询 ----
    def list_cases(self, status: Optional[str] = None,
                   severity: Optional[str] = None,
                   owner: Optional[str] = None) -> List[Dict[str, Any]]:
        out = list(self.cases.values())
        if status:
            out = [c for c in out if c["status"] == status]
        if severity:
            out = [c for c in out if c["severity"] == severity]
        if owner:
            out = [c for c in out if c["owner"] == owner]
        out.sort(key=lambda c: c["updated_at"], reverse=True)
        return out

    def get(self, case_id: str) -> Optional[Dict[str, Any]]:
        return self.cases.get(case_id)

    # ---- 状态流转 ----
    def update_status(self, case_id: str, status: str,
                      actor: str = "system", note: str = "") -> Optional[Dict[str, Any]]:
        c = self.cases.get(case_id)
        if not c:
            return None
        if status not in STATUSES:
            return None
        c["status"] = status
        self._log(c, "status_change", f"状态 -> {status} {('：' + note) if note else ''}", actor)
        return c

    def assign(self, case_id: str, new_owner: str,
               actor: str = "system") -> Optional[Dict[str, Any]]:
        c = self.cases.get(case_id)
        if not c:
            return None
        old = c["owner"]
        c["owner"] = new_owner
        self._log(c, "assigned", f"负责人 {old} -> {new_owner}", actor)
        return c

    # ---- 证据 / 评论 ----
    def add_evidence(self, case_id: str, artifact_id: str,
                     source: str = "soar", note: str = "") -> Optional[Dict[str, Any]]:
        c = self.cases.get(case_id)
        if not c:
            return None
        ev = {"artifact_id": artifact_id, "source": source, "note": note,
              "attached_at": time.strftime("%Y-%m-%d %H:%M:%S")}
        c["evidence"].append(ev)
        self._log(c, "evidence", f"挂载证据 {artifact_id}", source)
        return ev

    def add_comment(self, case_id: str, author: str, body: str,
                    mentions: Optional[List[str]] = None) -> Optional[Dict[str, Any]]:
        c = self.cases.get(case_id)
        if not c:
            return None
        cm = {"comment_id": uuid.uuid4().hex[:8], "author": author, "body": body,
              "mentions": mentions or [],
              "at": time.strftime("%Y-%m-%d %H:%M:%S")}
        c["comments"].append(cm)
        self._log(c, "comment", f"{author}: {body[:40]}", author)
        return cm

    # ---- SLA ----
    def sla_check(self, case_id: str) -> Dict[str, Any]:
        c = self.cases.get(case_id)
        if not c:
            return {}
        due = time.mktime(time.strptime(c["sla"]["due_at"], "%Y-%m-%d %H:%M:%S"))
        now = time.time()
        remaining = round((due - now) / 60, 1)
        breached = remaining < 0 and c["status"] != "closed"
        c["sla"]["breached"] = breached
        c["sla"]["remaining_minutes"] = remaining
        if breached:
            self._log(c, "sla_breach", f"SLA 超时 {abs(remaining)} 分钟", "sla-monitor")
        return {"case_id": case_id, "due_at": c["sla"]["due_at"],
                "remaining_minutes": remaining, "breached": breached,
                "status": c["status"]}

    def escalate(self, case_id: str, to_level: str = "L2",
                 reason: str = "") -> Optional[Dict[str, Any]]:
        c = self.cases.get(case_id)
        if not c:
            return None
        c["escalation"] = {"level": to_level, "reason": reason,
                           "at": time.strftime("%Y-%m-%d %H:%M:%S")}
        self._log(c, "escalate", f"升级到 {to_level}: {reason}", "sla-monitor")
        return c

    # ---- 复盘与知识库 ----
    def retro(self, case_id: str, summary: str, root_cause: str,
              lessons: List[str], actions: List[str]) -> Optional[Dict[str, Any]]:
        c = self.cases.get(case_id)
        if not c:
            return None
        record = {
            "case_id": case_id, "title": c["title"], "severity": c["severity"],
            "summary": summary, "root_cause": root_cause,
            "lessons_learned": lessons, "action_items": actions,
            "created_at": time.strftime("%Y-%m-%d %H:%M:%S"),
        }
        c["retrospective"] = record
        self.knowledge_base.append(record)
        self._log(c, "retro", "完成复盘并沉淀知识库", "pm")
        return record

    def knowledge_list(self, keyword: Optional[str] = None) -> List[Dict[str, Any]]:
        if not keyword:
            return self.knowledge_base
        kw = keyword.lower()
        return [k for k in self.knowledge_base
                if kw in k.get("title", "").lower()
                or kw in k.get("summary", "").lower()
                or kw in k.get("root_cause", "").lower()]

    # ---- 报告 ----
    def report(self, case_id: str) -> Optional[Dict[str, Any]]:
        c = self.cases.get(case_id)
        if not c:
            return None
        lines = [
            f"# 安全案例报告 — {c['case_id']}", "",
            f"- 标题: {c['title']}",
            f"- 类别: {c['category']}",
            f"- 严重度: {c['severity']}",
            f"- 负责人: {c['owner']}",
            f"- 当前状态: {c['status']}",
            f"- 创建: {c['created_at']}",
            f"- 更新: {c['updated_at']}", "",
            "## 时间线",
        ]
        for ev in c["timeline"]:
            lines.append(f"- [{ev['ts']}] {ev['kind']}: {ev['detail']} ({ev['actor']})")
        lines += ["", "## 证据", f"- 共 {len(c['evidence'])} 项"]
        for e in c["evidence"]:
            lines.append(f"  - {e['artifact_id']} ({e['source']}): {e['note']}")
        lines += ["", "## 评论", f"- 共 {len(c['comments'])} 条"]
        for cm in c["comments"]:
            lines.append(f"  - [{cm['at']}] {cm['author']}: {cm['body']}")
        if c.get("retrospective"):
            r = c["retrospective"]
            lines += ["", "## 复盘", f"- 根因: {r['root_cause']}",
                      "- 经验教训:"] + [f"  - {l}" for l in r["lessons_learned"]]
        return {"case_id": case_id, "report_markdown": "\n".join(lines), "case": c}

    def stats(self) -> Dict[str, Any]:
        by_status: Dict[str, int] = {}
        by_sev: Dict[str, int] = {}
        open_cases = 0
        for c in self.cases.values():
            by_status[c["status"]] = by_status.get(c["status"], 0) + 1
            by_sev[c["severity"]] = by_sev.get(c["severity"], 0) + 1
            if c["status"] != "closed":
                open_cases += 1
        return {"total_cases": len(self.cases), "open_cases": open_cases,
                "by_status": by_status, "by_severity": by_sev,
                "knowledge_entries": len(self.knowledge_base),
                "analysts": self.analysts}


_SINGLETON: Optional[CaseManager] = None


def get_case_manager() -> CaseManager:
    global _SINGLETON
    if _SINGLETON is None:
        _SINGLETON = CaseManager()
    return _SINGLETON


if __name__ == "__main__":  # pragma: no cover
    cm = get_case_manager()
    c = cm.create("可疑横向移动", "critical", "入侵", "alice")
    cm.add_comment(c["case_id"], "bob", "已隔离主机", ["alice"])
    print(cm.sla_check(c["case_id"]))
