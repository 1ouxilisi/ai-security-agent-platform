# -*- coding: utf-8 -*-
"""
phishing_simulation_phase.py — 阶段5：钓鱼演练。

功能:
    - 模板管理（邮件/页面/附件/landing page）
    - 钓鱼邮件发送（批量/定时/个性化/追踪链接）
    - 点击跟踪（打开/点击/输入凭据/下载附件）
    - 数据收集（点击/输入/时间/设备）
    - 风险评估（高/中/低风险用户/部门）
    - 培训建议 / 演练报告 / 演练计划 / 统计
"""

from __future__ import annotations

import threading
import uuid
from dataclasses import dataclass, field
from datetime import datetime
from typing import Any, Dict, List, Optional

RISK_LEVELS = ["高风险", "中风险", "低风险"]


@dataclass
class PhishingTemplate:
    tpl_id: str = ""
    name: str = ""
    ttype: str = "邮件模板"
    subject: str = ""
    body: str = ""
    landing: str = ""

    def to_dict(self) -> Dict[str, Any]:
        return {
            "tpl_id": self.tpl_id, "name": self.name, "ttype": self.ttype,
            "subject": self.subject, "body": self.body, "landing": self.landing,
        }


@dataclass
class Campaign:
    camp_id: str = ""
    name: str = ""
    template_id: str = ""
    targets: List[str] = field(default_factory=list)
    departments: List[str] = field(default_factory=list)
    schedule: str = "now"
    events: List[Dict[str, Any]] = field(default_factory=list)
    status: str = "规划中"
    created_at: str = ""

    def to_dict(self) -> Dict[str, Any]:
        return {
            "camp_id": self.camp_id, "name": self.name,
            "template_id": self.template_id, "targets": self.targets,
            "departments": self.departments, "schedule": self.schedule,
            "events": self.events, "status": self.status,
            "created_at": self.created_at,
        }


class PhishingSimulationPhase:
    """阶段5：钓鱼演练。"""

    def __init__(self) -> None:
        self._templates: Dict[str, PhishingTemplate] = {}
        self._camps: Dict[str, Campaign] = {}
        self._lock = threading.Lock()
        self._seed()

    # ------------------------------------------------------------------ #
    def _seed(self) -> None:
        self._templates["tpl_mail_hr"] = PhishingTemplate(
            tpl_id="tpl_mail_hr", name="HR 工资条邮件", ttype="邮件模板",
            subject="【紧急】您的本月工资条待查收",
            body="点击链接查看工资条，逾期作废。",
            landing="/login-hr")
        self._templates["tpl_page_login"] = PhishingTemplate(
            tpl_id="tpl_page_login", name="伪造 SSO 登录页",
            ttype="页面模板", landing="/fake-sso")
        self._templates["tpl_attach_zip"] = PhishingTemplate(
            tpl_id="tpl_attach_zip", name="发票压缩包附件",
            ttype="附件模板", landing="/invoice.zip")

    # ------------------------------------------------------------------ #
    def list_templates(self) -> List[Dict[str, Any]]:
        with self._lock:
            return [t.to_dict() for t in self._templates.values()]

    def add_template(self, name: str, ttype: str = "邮件模板",
                     subject: str = "", body: str = "",
                     landing: str = "") -> Dict[str, Any]:
        t = PhishingTemplate(
            tpl_id="tpl_" + uuid.uuid4().hex[:8], name=name,
            ttype=ttype, subject=subject, body=body, landing=landing)
        with self._lock:
            self._templates[t.tpl_id] = t
        return t.to_dict()

    # ------------------------------------------------------------------ #
    def create_campaign(self, name: str, template_id: str,
                        targets: Optional[List[str]] = None,
                        departments: Optional[List[str]] = None,
                        schedule: str = "now") -> Optional[Dict[str, Any]]:
        if template_id not in self._templates:
            return None
        c = Campaign(
            camp_id="camp_" + uuid.uuid4().hex[:8], name=name,
            template_id=template_id, targets=targets or [],
            departments=departments or [], schedule=schedule,
            created_at=datetime.now().isoformat(timespec="seconds"))
        with self._lock:
            self._camps[c.camp_id] = c
        return c.to_dict()

    def send_campaign(self, camp_id: str) -> Optional[Dict[str, Any]]:
        c = self._camps.get(camp_id)
        if c is None:
            return None
        with self._lock:
            c.status = "进行中"
            # 模拟发送 + 部分点击
            import random
            rng = random.Random(camp_id)
            for tgt in c.targets:
                c.events.append({
                    "user": tgt, "type": "email_sent",
                    "ts": datetime.now().isoformat(timespec="seconds")})
                if rng.random() < 0.35:
                    c.events.append({
                        "user": tgt, "type": "opened",
                        "ts": datetime.now().isoformat(timespec="seconds")})
                if rng.random() < 0.18:
                    c.events.append({
                        "user": tgt, "type": "clicked",
                        "device": "Windows/Chrome",
                        "ts": datetime.now().isoformat(timespec="seconds")})
                if rng.random() < 0.08:
                    c.events.append({
                        "user": tgt, "type": "credentials_entered",
                        "ts": datetime.now().isoformat(timespec="seconds")})
            c.status = "已结束"
        return c.to_dict()

    # ------------------------------------------------------------------ #
    def track_event(self, camp_id: str, user: str,
                    etype: str, device: str = "") -> Optional[Dict[str, Any]]:
        c = self._camps.get(camp_id)
        if c is None:
            return None
        ev = {"user": user, "type": etype, "device": device,
              "ts": datetime.now().isoformat(timespec="seconds")}
        with self._lock:
            c.events.append(ev)
        return ev

    # ------------------------------------------------------------------ #
    def risk_assessment(self, camp_id: str) -> Dict[str, Any]:
        c = self._camps.get(camp_id)
        if c is None:
            return {}
        user_actions: Dict[str, Dict[str, int]] = {}
        for ev in c.events:
            ua = user_actions.setdefault(
                ev["user"], {"opened": 0, "clicked": 0, "creds": 0})
            if ev["type"] == "opened":
                ua["opened"] += 1
            elif ev["type"] == "clicked":
                ua["clicked"] += 1
            elif ev["type"] == "credentials_entered":
                ua["creds"] += 1
        high, mid, low = [], [], []
        for u, a in user_actions.items():
            if a["creds"] > 0 or a["clicked"] >= 2:
                high.append(u)
            elif a["clicked"] > 0:
                mid.append(u)
            else:
                low.append(u)
        return {"camp_id": camp_id,
                "high_risk": high, "mid_risk": mid, "low_risk": low,
                "high_count": len(high), "mid_count": len(mid),
                "low_count": len(low)}

    def training_suggestions(self, camp_id: str) -> List[Dict[str, str]]:
        ra = self.risk_assessment(camp_id)
        out = []
        for u in ra.get("high_risk", []):
            out.append({"user": u, "suggestion":
                        "针对性强化培训 + 1V1 复盘（已输入凭据）"})
        for u in ra.get("mid_risk", []):
            out.append({"user": u, "suggestion":
                        "定期复习钓鱼识别课程"})
        return out

    # ------------------------------------------------------------------ #
    def campaign_report(self, camp_id: str) -> Dict[str, Any]:
        c = self._camps.get(camp_id)
        if c is None:
            return {}
        total = len(c.targets)
        opened = sum(1 for e in c.events if e["type"] == "opened")
        clicked = sum(1 for e in c.events if e["type"] == "clicked")
        creds = sum(1 for e in c.events
                    if e["type"] == "credentials_entered")
        ra = self.risk_assessment(camp_id)
        return {
            "camp_id": camp_id, "name": c.name,
            "total_targets": total,
            "open_rate": round(opened / max(1, total) * 100, 1),
            "click_rate": round(clicked / max(1, total) * 100, 1),
            "cred_rate": round(creds / max(1, total) * 100, 1),
            "risk": ra,
            "suggestions": self.training_suggestions(camp_id),
            "improvement": "对高风险用户 7 天内完成复测演练",
        }

    def list_campaigns(self) -> List[Dict[str, Any]]:
        with self._lock:
            return [c.to_dict() for c in self._camps.values()]

    def stats(self) -> Dict[str, Any]:
        with self._lock:
            camps = list(self._camps.values())
        all_ev = [e for c in camps for e in c.events]
        return {
            "campaigns": len(camps),
            "templates": len(self._templates),
            "total_events": len(all_ev),
            "clicked": sum(1 for e in all_ev if e["type"] == "clicked"),
            "credentials": sum(
                1 for e in all_ev if e["type"] == "credentials_entered"),
        }


_default: Optional[PhishingSimulationPhase] = None


def get_phishing_simulation_phase() -> PhishingSimulationPhase:
    global _default
    if _default is None:
        _default = PhishingSimulationPhase()
    return _default
