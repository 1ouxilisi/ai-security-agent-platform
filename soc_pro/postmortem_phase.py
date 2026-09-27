# -*- coding: utf-8 -*-
"""
postmortem_phase.py — 阶段7：事件复盘。

功能:
    - 攻击时间线（事件时间线重建/关键节点标记）
    - 根因分析（根本原因/漏洞点/防护失败点）
    - 改进建议（检测规则优化/响应流程优化/防护加固）
    - 经验沉淀（知识库/案例库/最佳实践）
    - 复盘报告生成
    - 改进项跟踪
"""

from __future__ import annotations

import threading
import uuid
from dataclasses import dataclass, field
from datetime import datetime
from typing import Any, Dict, List, Optional


@dataclass
class TimelineNode:
    ts: str = ""
    event: str = ""
    kind: str = "info"     # info/attack/detection/response/containment
    owner: str = ""


@dataclass
class PostmortemReport:
    pm_id: str = ""
    title: str = ""
    incident: str = ""
    summary: str = ""
    root_causes: List[str] = field(default_factory=list)
    failures: List[str] = field(default_factory=list)
    improvements: List[Dict[str, Any]] = field(default_factory=list)
    timeline: List[Dict[str, Any]] = field(default_factory=list)
    lessons: List[str] = field(default_factory=list)
    status: str = "draft"
    created_at: str = ""

    def to_dict(self) -> Dict[str, Any]:
        return {
            "pm_id": self.pm_id, "title": self.title,
            "incident": self.incident, "summary": self.summary,
            "root_causes": self.root_causes, "failures": self.failures,
            "improvements": self.improvements,
            "timeline": self.timeline, "lessons": self.lessons,
            "status": self.status, "created_at": self.created_at,
        }


class PostmortemPhase:
    """阶段7：事件复盘。"""

    def __init__(self) -> None:
        self._reports: Dict[str, PostmortemReport] = {}
        self._kb: List[Dict[str, Any]] = []
        self._lock = threading.Lock()

    # ------------------------------------------------------------------ #
    def build_timeline(self, incident_id: str = ""
                       ) -> List[Dict[str, Any]]:
        from .correlation_phase import get_correlation_phase
        from .alert_generation_phase import get_alert_generation_phase
        from .incident_response_phase import get_incident_response_phase

        nodes: List[Dict[str, Any]] = []
        for h in get_correlation_phase().recent_hits(200):
            nodes.append({
                "ts": h.get("timestamp", ""),
                "event": f"[检测] {h.get('rule_name','')} "
                         f"({h.get('src_ip','')})",
                "kind": "attack",
                "owner": "siem",
            })
        for a in get_alert_generation_phase().list_alerts(limit=50):
            nodes.append({
                "ts": a.get("last_seen", ""),
                "event": f"[告警] {a.get('title','')} "
                         f"→ {a.get('status','')}",
                "kind": "detection",
                "owner": "soc",
            })
        for t in get_incident_response_phase().list_tickets()[-20:]:
            nodes.append({
                "ts": t.get("resolved_at") or t.get("created_at", ""),
                "event": f"[工单] {t.get('title','')} "
                         f"→ {t.get('status','')}",
                "kind": "response",
                "owner": "ir",
            })
        nodes.sort(key=lambda n: n.get("ts") or "")
        return nodes

    # ------------------------------------------------------------------ #
    def generate(self, title: str, incident: str = "") -> Dict[str, Any]:
        tl = self.build_timeline(incident)
        # 简易根因推断
        root_causes: List[str] = []
        failures: List[str] = []
        improvements: List[Dict[str, Any]] = []
        lessons: List[str] = []

        kinds = {n["kind"] for n in tl}
        if "attack" in kinds and "detection" not in kinds:
            root_causes.append("攻击发生但未被实时检测规则覆盖")
            failures.append("检测规则缺失或阈值过宽")
            improvements.append({
                "item": "补充对应 ATT&CK 技术的检测规则",
                "owner": "detect-team", "due": "2 周", "status": "open"})
        if "response" not in kinds:
            root_causes.append("告警后缺乏自动化响应动作")
            failures.append("SOAR 剧本未触发或未覆盖该场景")
            improvements.append({
                "item": "新增对应场景的 SOAR 剧本并演练",
                "owner": "ir-team", "due": "3 周", "status": "open"})
        if not root_causes:
            root_causes.append("攻击链已被检测与响应覆盖，"
                               "主要问题在人工研判耗时")
            failures.append("告警分级与降噪不足，导致值班疲劳")
            improvements.append({
                "item": "上线 AI 告警降噪与自动分级",
                "owner": "soc-lead", "due": "1 月", "status": "open"})

        lessons.append("建立每日威胁狩猎例会，固化 IOC 库")
        lessons.append("每季度进行一次红蓝对抗复盘")

        pm = PostmortemReport(
            pm_id="pm_" + uuid.uuid4().hex[:8],
            title=title, incident=incident,
            summary=f"事件 {incident or title} 共记录 {len(tl)} 个时间线节点，"
                    f"识别根因 {len(root_causes)} 项，改进项 "
                    f"{len(improvements)} 项。",
            root_causes=root_causes, failures=failures,
            improvements=improvements,
            timeline=tl, lessons=lessons,
            created_at=datetime.now().isoformat(timespec="seconds"),
        )
        with self._lock:
            self._reports[pm.pm_id] = pm
        return pm.to_dict()

    # ------------------------------------------------------------------ #
    def list_reports(self) -> List[Dict[str, Any]]:
        with self._lock:
            return [r.to_dict() for r in self._reports.values()]

    def get_report(self, pm_id: str) -> Optional[Dict[str, Any]]:
        with self._lock:
            r = self._reports.get(pm_id)
            return r.to_dict() if r else None

    def close_report(self, pm_id: str) -> bool:
        with self._lock:
            r = self._reports.get(pm_id)
            if r is None:
                return False
            r.status = "closed"
            return True

    # ------------------------------------------------------------------ #
    def add_kb(self, title: str, content: str, tags: List[str]
               ) -> Dict[str, Any]:
        item = {
            "id": "kb_" + uuid.uuid4().hex[:8],
            "title": title, "content": content, "tags": tags,
            "at": datetime.now().isoformat(timespec="seconds"),
        }
        with self._lock:
            self._kb.append(item)
        return item

    def list_kb(self, tag: Optional[str] = None) -> List[Dict[str, Any]]:
        with self._lock:
            items = list(self._kb)
        if tag:
            items = [x for x in items if tag in x.get("tags", [])]
        return items

    def improvement_track(self) -> List[Dict[str, Any]]:
        out = []
        with self._lock:
            for r in self._reports.values():
                for imp in r.improvements:
                    out.append({**imp, "report": r.title})
        return out


_default: Optional[PostmortemPhase] = None


def get_postmortem_phase() -> PostmortemPhase:
    global _default
    if _default is None:
        _default = PostmortemPhase()
    return _default
