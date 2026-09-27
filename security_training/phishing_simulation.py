# -*- coding: utf-8 -*-
"""
phishing_simulation.py — 钓鱼演练（第14轮·方向2）。

钓鱼模板库（20+模板，邮件/短信/IM）、目标分组、演练计划、发送模拟、
点击追踪、数据录入追踪、报告、意识评分、再培训触发。

合规红线：本模块仅做"模拟与评估"，绝不真实发送任何钓鱼邮件/短信，
所有"发送"均为在靶场环境内生成演练链接与记录。
"""

from __future__ import annotations

import time
from typing import Any, Dict, List, Optional


def _build_templates() -> List[Dict[str, Any]]:
    rows = []
    # 12 邮件模板
    email_scenes = [
        ("邮箱容量已满", "mailbox", "urgent"),
        ("密码即将过期", "it", "urgent"),
        ("工资条已发放", "hr", "normal"),
        ("发票报销待审批", "finance", "normal"),
        ("VPN异地登录告警", "it", "urgent"),
        ("企业网盘共享文件", "cloud", "normal"),
        ("会议邀请更新", "meeting", "normal"),
        ("客户合同签署", "legal", "urgent"),
        ("快递到件通知", "misc", "normal"),
        ("中奖活动通知", "misc", "lure"),
        ("IT系统升级维护", "it", "normal"),
        ("供应商对账单", "finance", "normal"),
    ]
    for i, (name, category, level) in enumerate(email_scenes, 1):
        rows.append({
            "tpl_id": f"TPL-M{i:02d}", "channel": "email", "name": name,
            "category": category, "risk": level,
            "subject": f"【模拟演练】{name}：请尽快处理",
            "body_mock": f"尊敬的同事，关于「{name}」的通知（演练占位正文，无真实链接）。",
            "lure_type": (" urgency" if level == "urgent" else
                          " prize" if level == "lure" else " normal"),
        })
    # 6 短信模板
    sms_scenes = ["验证码5分钟有效", "快递取件码", "账户异常冻结",
                  "信用卡还款提醒", "政务通知", "医保电子凭证"]
    for i, name in enumerate(sms_scenes, 1):
        rows.append({
            "tpl_id": f"TPL-S{i:02d}", "channel": "sms", "name": name,
            "category": "mobile", "risk": "urgent" if "异常" in name else "normal",
            "subject": f"【模拟演练短信】{name}",
            "body_mock": f"【演练】{name}，回T退订（占位，无真实短链）。",
            "lure_type": " sms",
        })
    # 4 IM模板
    im_scenes = ["同事共享文档", "领导临时安排", "群投票接龙", "朋友圈外链"]
    for i, name in enumerate(im_scenes, 1):
        rows.append({
            "tpl_id": f"TPL-I{i:02d}", "channel": "im", "name": name,
            "category": "social", "risk": "normal",
            "subject": f"【模拟演练IM】{name}",
            "body_mock": f"[演练] {name}：点这里查看（占位，无真实链接）。",
            "lure_type": " im",
        })
    return rows


PHISHING_TEMPLATES: Dict[str, Dict[str, Any]] = {t["tpl_id"]: t for t in _build_templates()}

DEPARTMENTS = ["研发部", "财务部", "人事部", "市场部", "运维部", "客服部", "管理层"]


class PhishingSimulation:
    """钓鱼演练器（纯模拟）。"""

    def __init__(self) -> None:
        self.plans: Dict[str, Dict[str, Any]] = {}
        self.groups: Dict[str, Dict[str, Any]] = {}

    def list_templates(self, channel: Optional[str] = None) -> Dict[str, Any]:
        items = list(PHISHING_TEMPLATES.values())
        if channel:
            items = [t for t in items if t["channel"] == channel]
        return {"templates": items, "total": len(items),
                "channels": sorted({t["channel"] for t in PHISHING_TEMPLATES.values()})}

    def create_group(self, name: str, members: List[str],
                     department: str = "研发部") -> Dict[str, Any]:
        gid = f"G{int(time.time())%1000000:06d}"
        self.groups[gid] = {"group_id": gid, "name": name,
                            "department": department, "members": members,
                            "size": len(members)}
        return {"ok": True, "group": self.groups[gid]}

    def list_groups(self) -> Dict[str, Any]:
        return {"groups": list(self.groups.values()), "total": len(self.groups)}

    # ---- 演练计划与"发送模拟" ----
    def run_drill(self, plan_name: str, tpl_ids: List[str],
                  group_ids: List[str],
                  channel: str = "email") -> Dict[str, Any]:
        """生成演练。仅记录"已投递"，不真实发送。"""
        pid = f"DR{int(time.time())%1000000:06d}"
        members: List[str] = []
        for gid in group_ids:
            g = self.groups.get(gid)
            if g:
                members.extend(g["members"])
        members = members or ["demo_user_" + str(i) for i in range(1, 21)]
        records = []
        for m in members:
            # 模拟行为：是否点击 / 是否录入数据
            clicked = (hash(m) % 100) < 35          # ~35% 点击率
            entered = clicked and (hash(m + "x") % 100) < 55  # 点击后55%录入
            reported = (hash(m + "r") % 100) < 25   # ~25% 主动上报
            records.append({
                "email": m, "clicked": clicked, "entered": entered,
                "reported": reported,
                "safe": (not clicked) or reported,
            })
        clicked_n = sum(1 for r in records if r["clicked"])
        entered_n = sum(1 for r in records if r["entered"])
        reported_n = sum(1 for r in records if r["reported"])
        total = max(1, len(records))
        plan = {
            "drill_id": pid, "plan_name": plan_name, "channel": channel,
            "templates": [PHISHING_TEMPLATES.get(t, {}) for t in tpl_ids],
            "sent": len(records), "clicked": clicked_n, "entered": entered_n,
            "reported": reported_n,
            "click_rate": round(clicked_n / total * 100, 1),
            "data_entry_rate": round(entered_n / total * 100, 1),
            "report_rate": round(reported_n / total * 100, 1),
            "awareness_score": round(100 - clicked_n / total * 100 * 0.6
                                    - entered_n / total * 100 * 0.4, 1),
            "records": records,
            "sent_at": time.strftime("%Y-%m-%d %H:%M:%S"),
            "note": "本演练为纯模拟，未发送任何真实邮件/短信",
        }
        self.plans[pid] = plan
        # 再培训触发：点击率 > 30%
        plan["retraining_triggered"] = plan["click_rate"] > 30
        return plan

    def drill_report(self, drill_id: str) -> Dict[str, Any]:
        p = self.plans.get(drill_id)
        if not p:
            return {"found": False}
        # 按部门（记录邮箱前的演示部门字段）聚合
        by_dept: Dict[str, Dict[str, float]] = {}
        for i, rec in enumerate(p["records"]):
            dept = DEPARTMENTS[i % len(DEPARTMENTS)]
            d = by_dept.setdefault(dept, {"sent": 0, "clicked": 0})
            d["sent"] += 1
            d["clicked"] += int(rec["clicked"])
        dept_stats = []
        for dept, d in by_dept.items():
            dept_stats.append({"department": dept, "sent": d["sent"],
                               "clicked": d["clicked"],
                               "click_rate": round(d["clicked"] / max(1, d["sent"]) * 100, 1)})
        md_lines = [
            f"# 钓鱼演练报告 {p['plan_name']}", "",
            f"- 演练编号: {p['drill_id']}",
            f"- 投递人数: {p['sent']}",
            f"- 点击率: {p['click_rate']}%",
            f"- 数据录入率: {p['data_entry_rate']}%",
            f"- 主动上报率: {p['report_rate']}%",
            f"- 综合意识分: {p['awareness_score']}",
            f"- 再培训触发: {'是' if p['retraining_triggered'] else '否'}", "",
            "## 部门对比",
        ]
        for d in sorted(dept_stats, key=lambda x: x["click_rate"], reverse=True):
            md_lines.append(f"- {d['department']}: 点击 {d['click_rate']}% ({d['clicked']}/{d['sent']})")
        return {"drill_id": drill_id, "summary": {k: p[k] for k in
                ("sent", "clicked", "entered", "reported", "click_rate",
                 "data_entry_rate", "report_rate", "awareness_score",
                 "retraining_triggered")},
                "dept_stats": dept_stats, "report_markdown": "\n".join(md_lines)}

    def list_drills(self) -> Dict[str, Any]:
        rows = [{k: v[k] for k in ("drill_id", "plan_name", "channel", "sent",
                "click_rate", "awareness_score", "retraining_triggered", "sent_at")}
                for v in self.plans.values()]
        avg_awareness = round(sum(r["awareness_score"] for r in rows) / max(1, len(rows)), 1)
        return {"drills": rows, "total": len(rows), "avg_awareness_score": avg_awareness}
