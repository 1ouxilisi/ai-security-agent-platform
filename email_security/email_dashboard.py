# -*- coding: utf-8 -*-
"""email_dashboard.py — 邮件安全运营仪表盘。

覆盖：实时邮件流 / 告警管理 / 威胁趋势 / 安全度量 / 模拟钓鱼演练 / 综合运营视图。
全部内存数据 + 确定性伪随机。
"""

from __future__ import annotations

import hashlib
import time
from typing import Any, Dict, List, Optional


ALERTS: List[Dict[str, Any]] = [
    {"alert_id": "AL-20260914-001", "type": "phishing", "severity": "critical",
     "from": "service@paypa1-support.xyz", "subject": "您的 PayPal 账户已被限制",
     "score": 92, "status": "open", "created_at": "2026-09-14 09:12:11"},
    {"alert_id": "AL-20260914-002", "type": "bec", "severity": "critical",
     "from": "ceo@company-secure.net", "subject": "紧急：请立即安排付款",
     "score": 88, "status": "open", "created_at": "2026-09-14 10:03:45"},
    {"alert_id": "AL-20260914-003", "type": "malware_attachment", "severity": "high",
     "from": "invoice@vendor-dyn.net", "subject": "Invoice #8812 attached",
     "score": 76, "status": "triaged", "created_at": "2026-09-14 11:20:01"},
    {"alert_id": "AL-20260914-004", "type": "auth_failure", "severity": "medium",
     "from": "marketing@unknown.io", "subject": "Newsletter",
     "score": 41, "status": "false_positive", "created_at": "2026-09-14 13:01:20"},
]


SIM_SIMULATIONS: List[Dict[str, Any]] = [
    {"campaign_id": "SIM-001", "name": "Q3 全员钓鱼演练", "template": "伪造HR工资单",
     "target_group": "全体员工(1200人)", "sent_at": "2026-09-01",
     "status": "finished", "sent": 1200, "clicked": 96,
     "credentials_entered": 12, "report_rate": 0.08, "click_rate": 0.08},
    {"campaign_id": "SIM-002", "name": "财务部门BEC专项", "template": "伪造CEO紧急付款",
     "target_group": "财务部(18人)", "sent_at": "2026-09-10",
     "status": "running", "sent": 18, "clicked": 2,
     "credentials_entered": 0, "report_rate": 0.0, "click_rate": 0.11},
]


class EmailDashboard:
    """运营仪表盘数据聚合。"""

    # ------------------------------------------------------------------ #
    # 实时邮件流
    # ------------------------------------------------------------------ #
    def mail_flow(self) -> Dict[str, Any]:
        total = 18420
        phishing_blocked = 214
        bec_blocked = 12
        attachment_blocked = 67
        auth_failed = 486
        return {
            "total_today": total,
            "phishing_blocked": phishing_blocked,
            "bec_blocked": bec_blocked,
            "attachment_blocked": attachment_blocked,
            "auth_failed": auth_failed,
            "phishing_block_rate": round(phishing_blocked / total * 100, 3),
            "bec_block_rate": round(bec_blocked / total * 100, 3),
            "attachment_block_rate": round(attachment_blocked / total * 100, 3),
            "auth_fail_rate": round(auth_failed / total * 100, 3),
            "updated_at": time.strftime("%Y-%m-%d %H:%M:%S"),
        }

    # ------------------------------------------------------------------ #
    # 告警管理
    # ------------------------------------------------------------------ #
    def list_alerts(self, status: Optional[str] = None,
                    atype: Optional[str] = None) -> Dict[str, Any]:
        out = ALERTS
        if status:
            out = [a for a in out if a["status"] == status]
        if atype:
            out = [a for a in out if a["type"] == atype]
        buckets: Dict[str, int] = {}
        for a in ALERTS:
            buckets[a["status"]] = buckets.get(a["status"], 0) + 1
        return {"alerts": out, "total": len(out),
                "status_breakdown": buckets}

    def update_alert(self, alert_id: str, action: str,
                     note: str = "") -> Dict[str, Any]:
        for a in ALERTS:
            if a["alert_id"] == alert_id:
                if action == "confirm":
                    a["status"] = "confirmed"
                elif action == "false_positive":
                    a["status"] = "false_positive"
                elif action == "escalate":
                    a["status"] = "escalated"
                elif action == "resolve":
                    a["status"] = "resolved"
                else:
                    return {"success": False, "error": "未知动作"}
                a["note"] = note
                return {"success": True, "alert": a}
        return {"success": False, "error": "告警不存在"}

    # ------------------------------------------------------------------ #
    # 威胁趋势（7 天）
    # ------------------------------------------------------------------ #
    def trends(self) -> Dict[str, Any]:
        days = []
        for i in range(6, -1, -1):
            t = time.localtime(time.time() - i * 86400)
            day = time.strftime("%m-%d", t)
            seed = int(hashlib.md5(day.encode()).hexdigest()[:8], 16)
            days.append({
                "date": day,
                "phishing": 120 + seed % 80,
                "bec": 4 + seed % 6,
                "malware": 20 + seed % 25,
            })
        top_sources = [
            {"ip": "103.75.190.22", "count": 312, "country": "HK"},
            {"ip": "185.220.101.45", "count": 248, "country": "DE"},
            {"ip": "45.155.205.77", "count": 171, "country": "RU"},
            {"ip": "91.243.92.14", "count": 132, "country": "NL"},
        ]
        top_targets = [
            {"dept": "财务部", "hits": 48},
            {"dept": "采购部", "hits": 35},
            {"dept": "总经理办公室", "hits": 22},
            {"dept": "HR", "hits": 18},
        ]
        return {"daily": days, "top_sources": top_sources,
                "top_targets": top_targets}

    # ------------------------------------------------------------------ #
    # 度量
    # ------------------------------------------------------------------ #
    def metrics(self) -> Dict[str, Any]:
        return {
            "block_rate_7d": 1.52,
            "false_positive_rate": 0.41,
            "mttd_minutes": 6.5,
            "user_report_rate": 2.3,
            "training_completion": 0.86,
            "auth_pass_rate": 97.2,
            "avg_response_minutes": 4.2,
            "phish_click_rate_trend": [8.2, 7.5, 6.9, 6.1, 5.4, 4.9, 4.3],
        }

    # ------------------------------------------------------------------ #
    # 模拟钓鱼演练
    # ------------------------------------------------------------------ #
    def list_simulations(self) -> List[Dict[str, Any]]:
        return SIM_SIMULATIONS

    def create_simulation(self, name: str, template: str,
                          target_group: str) -> Dict[str, Any]:
        camp = {
            "campaign_id": "SIM-" + hashlib.md5(
                (name + str(time.time())).encode()).hexdigest()[:3].upper(),
            "name": name, "template": template, "target_group": target_group,
            "sent_at": time.strftime("%Y-%m-%d"), "status": "planned",
            "sent": 0, "clicked": 0, "credentials_entered": 0,
            "report_rate": 0.0, "click_rate": 0.0,
        }
        SIM_SIMULATIONS.append(camp)
        return camp

    def simulation_report(self, campaign_id: str) -> Dict[str, Any]:
        c = next((x for x in SIM_SIMULATIONS
                  if x["campaign_id"] == campaign_id), None)
        if not c:
            return {"error": "演练不存在"}
        advice = []
        if c["click_rate"] > 0.08:
            advice.append("点击率偏高，建议针对目标组开展专项反钓鱼培训")
        if c["credentials_entered"] > 0:
            advice.append("有用户提交凭据，强制改密并排查是否被横向移动")
        if not advice:
            advice.append("整体表现良好，保持现有培训节奏")
        return {"campaign": c, "recommendations": advice}

    # ------------------------------------------------------------------ #
    # 综合运营视图
    # ------------------------------------------------------------------ #
    def overview(self) -> Dict[str, Any]:
        flow = self.mail_flow()
        trends = self.trends()
        metrics = self.metrics()
        alerts = self.list_alerts()
        return {
            "cards": flow,
            "alerts": alerts,
            "trends": trends,
            "metrics": metrics,
            "compliance": {
                "dmarc_policy": "quarantine",
                "enforced_domains": 12, "total_domains": 14,
                "coverage": round(12 / 14 * 100, 1),
            },
            "generated_at": time.strftime("%Y-%m-%d %H:%M:%S"),
        }
