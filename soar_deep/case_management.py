#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
soar_deep/case_management.py — 深度案例管理与协作。

覆盖：
    1. 案例创建：自动/手动/告警转案例/事件转案例/模板创建
    2. 案例管理：列表/详情/状态/优先级/分类/标签/关联
    3. 案例协作：成员管理/角色分配/任务分配/评论/@提及/文件共享/实时协作
    4. 案例时间线：事件时间线/操作记录/状态变更/评论/附件/关联告警/IOC
    5. 案例知识库：案例模板/处理流程/SOP/最佳实践/经验总结/知识检索
    6. 案例分析：统计/趋势/类型分布/处理时长/解决率/复发率/SLA达标率
"""

from __future__ import annotations

import time
import uuid
from typing import Any, Dict, List, Optional


# --------------------------------------------------------------------------- #
# 常量
# --------------------------------------------------------------------------- #
STATUSES = ["new", "investigating", "contained", "eradicated",
            "recovered", "closed", "false_positive"]
CATEGORIES = ["勒索软件", "钓鱼攻击", "暴力破解", "Web入侵", "数据泄露",
              "内部威胁", "DDoS", "供应链攻击", "其他"]
PRIORITIES = ["P0", "P1", "P2", "P3"]
ROLES = ["owner", "analyst", "responder", "observer", "approver"]
SLA_HOURS = {"P0": 4, "P1": 24, "P2": 72, "P3": 168}  # 优先级对应SLA(小时)


# --------------------------------------------------------------------------- #
# 案例对象
# --------------------------------------------------------------------------- #
class Case:
    """安全事件响应案例。"""

    def __init__(self, case_id: str, title: str,
                 severity: str = "medium", category: str = "其他") -> None:
        self.id = case_id
        self.title = title
        self.severity = severity
        self.category = category
        self.priority = "P2"
        self.status = "new"
        self.owner = ""
        self.description = ""
        self.created_at = time.strftime("%Y-%m-%d %H:%M:%S")
        self.updated_at = self.created_at
        self.members: List[Dict[str, str]] = []
        self.tasks: List[Dict[str, Any]] = []
        self.comments: List[Dict[str, Any]] = []
        self.timeline: List[Dict[str, Any]] = []
        self.attachments: List[Dict[str, str]] = []
        self.related_alerts: List[str] = []
        self.related_iocs: List[Dict[str, str]] = []
        self.tags: List[str] = []
        self.sla_due: Optional[str] = None
        self.closed_at: Optional[str] = None
        self.root_cause = ""
        self.lessons: List[str] = []
        self.timeline.append(self._tl("created", "案例创建", "system"))

    def _tl(self, ttype: str, message: str, operator: str) -> Dict[str, Any]:
        return {
            "time": time.strftime("%Y-%m-%d %H:%M:%S"),
            "type": ttype, "message": message, "operator": operator,
        }

    def add_member(self, user: str, role: str = "analyst") -> None:
        self.members.append({"user": user, "role": role,
                            "joined_at": time.strftime("%Y-%m-%d %H:%M:%S")})
        self.timeline.append(self._tl("member_added", f"{user} 加入案例({role})", user))
        self.updated_at = time.strftime("%Y-%m-%d %H:%M:%S")

    def change_status(self, new_status: str, operator: str = "system",
                      note: str = "") -> None:
        old = self.status
        self.status = new_status
        self.timeline.append(self._tl("status_change",
                                     f"状态变更: {old} -> {new_status} {note}", operator))
        self.updated_at = time.strftime("%Y-%m-%d %H:%M:%S")
        if new_status == "closed":
            self.closed_at = time.strftime("%Y-%m-%d %H:%M:%S")

    def add_comment(self, author: str, body: str,
                    mentions: Optional[List[str]] = None) -> Dict[str, Any]:
        comment = {
            "comment_id": uuid.uuid4().hex[:10],
            "author": author, "body": body,
            "mentions": mentions or [],
            "time": time.strftime("%Y-%m-%d %H:%M:%S"),
        }
        self.comments.append(comment)
        self.timeline.append(self._tl("comment", f"{author}: {body[:50]}...", author))
        self.updated_at = time.strftime("%Y-%m-%d %H:%M:%S")
        return comment

    def add_task(self, title: str, assignee: str = "",
                 due: str = "") -> Dict[str, Any]:
        task = {
            "task_id": uuid.uuid4().hex[:10],
            "title": title, "assignee": assignee,
            "status": "open", "due": due,
            "created_at": time.strftime("%Y-%m-%d %H:%M:%S"),
        }
        self.tasks.append(task)
        self.timeline.append(self._tl("task_created", f"任务: {title} -> {assignee}", "system"))
        return task

    def complete_task(self, task_id: str) -> bool:
        for t in self.tasks:
            if t["task_id"] == task_id:
                t["status"] = "completed"
                t["completed_at"] = time.strftime("%Y-%m-%d %H:%M:%S")
                return True
        return False

    def add_ioc(self, ioc_type: str, value: str,
                source: str = "auto") -> None:
        self.related_iocs.append({
            "type": ioc_type, "value": value, "source": source,
            "added_at": time.strftime("%Y-%m-%d %H:%M:%S"),
        })
        self.timeline.append(self._tl("ioc_added", f"IOC: {ioc_type}={value}", source))

    def add_attachment(self, name: str, file_type: str,
                       size: int = 0) -> None:
        self.attachments.append({
            "name": name, "type": file_type, "size": size,
            "uploaded_at": time.strftime("%Y-%m-%d %H:%M:%S"),
        })

    def set_priority(self, priority: str) -> None:
        self.priority = priority
        hours = SLA_HOURS.get(priority, 72)
        # 计算SLA到期时间
        ts = time.time() + hours * 3600
        self.sla_due = time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(ts))
        self.timeline.append(self._tl("priority_change", f"优先级设为 {priority}", "system"))

    def to_dict(self) -> Dict[str, Any]:
        return {
            "id": self.id, "title": self.title,
            "severity": self.severity, "category": self.category,
            "priority": self.priority, "status": self.status,
            "owner": self.owner, "description": self.description,
            "members": self.members, "tasks": self.tasks,
            "comments": self.comments, "timeline": self.timeline,
            "attachments": self.attachments,
            "related_alerts": self.related_alerts,
            "related_iocs": self.related_iocs,
            "tags": self.tags,
            "created_at": self.created_at, "updated_at": self.updated_at,
            "closed_at": self.closed_at,
            "sla_due": self.sla_due,
            "root_cause": self.root_cause,
            "lessons": self.lessons,
            "member_count": len(self.members),
            "task_count": len(self.tasks),
            "comment_count": len(self.comments),
            "timeline_count": len(self.timeline),
            "open_tasks": sum(1 for t in self.tasks if t["status"] == "open"),
        }


# --------------------------------------------------------------------------- #
# 知识库
# --------------------------------------------------------------------------- #
KNOWLEDGE_BASE: List[Dict[str, Any]] = [
    {
        "kb_id": "kb_ransomware_playbook",
        "title": "勒索软件事件标准响应SOP",
        "category": "勒索软件",
        "content": "1.确认感染范围 2.隔离受影响主机 3.收集内存证据 4.阻断横向移动 5.评估数据泄露 6.从备份恢复 7.复盘总结",
        "tags": ["SOP", "勒索软件", "应急响应"],
        "author": "SOC团队",
        "updated_at": "2026-08-01",
        "use_count": 45,
    },
    {
        "kb_id": "kb_phishing_response",
        "title": "钓鱼邮件事件处置最佳实践",
        "category": "钓鱼攻击",
        "content": "1.隔离钓鱼邮件 2.确认是否有人点击 3.回收恶意URL 4.重置密码+MFA 5.全员通知 6.复盘改进邮件网关",
        "tags": ["SOP", "钓鱼", "邮件安全"],
        "author": "安全运营组",
        "updated_at": "2026-07-15",
        "use_count": 32,
    },
    {
        "kb_id": "kb_bruteforce_mitigation",
        "title": "暴力破解攻击缓解指南",
        "category": "暴力破解",
        "content": "1.封禁攻击IP 2.启用账户锁定策略 3.强制MFA 4.修改SSH端口 5.监控异常登录",
        "tags": ["缓解", "暴力破解", "SSH"],
        "author": "基础设施组",
        "updated_at": "2026-06-20",
        "use_count": 28,
    },
    {
        "kb_id": "kb_data_breach_checklist",
        "title": "数据泄露事件检查清单",
        "category": "数据泄露",
        "content": "1.确认泄露数据类型 2.评估影响范围 3.通知利益相关方 4.合规上报 5.取证保留 6.修复漏洞 7.事后审计",
        "tags": ["清单", "数据泄露", "合规"],
        "author": "合规团队",
        "updated_at": "2026-08-10",
        "use_count": 18,
    },
    {
        "kb_id": "kb_lateral_move_detection",
        "title": "横向移动检测与阻断手册",
        "category": "内网横向",
        "content": "1.监控SMB/RDP异常 2.检测PsExec/WMI 3.隔离受害主机 4.重置域账户密码 5.检查所有DC日志",
        "tags": ["横向移动", "检测", "阻断"],
        "author": "红队转蓝队",
        "updated_at": "2026-05-30",
        "use_count": 22,
    },
]

CASE_TEMPLATES: List[Dict[str, Any]] = [
    {"template_id": "tpl_ransomware", "name": "勒索软件响应模板",
     "category": "勒索软件", "severity": "critical",
     "default_priority": "P0",
     "checklist": ["确认感染范围", "隔离主机", "收集证据", "阻断横向", "数据恢复", "复盘"]},
    {"template_id": "tpl_phishing", "name": "钓鱼邮件响应模板",
     "category": "钓鱼攻击", "severity": "high",
     "default_priority": "P1",
     "checklist": ["隔离邮件", "确认点击情况", "封禁URL", "重置密码", "全员通知"]},
    {"template_id": "tpl_bruteforce", "name": "暴力破解响应模板",
     "category": "暴力破解", "severity": "medium",
     "default_priority": "P2",
     "checklist": ["封禁攻击IP", "检查账户", "强化策略", "监控后续"]},
]


# --------------------------------------------------------------------------- #
# 案例管理器
# --------------------------------------------------------------------------- #
class CaseManager:
    """案例管理与协作引擎。"""

    def __init__(self) -> None:
        self.cases: Dict[str, Case] = {}
        self._seed_demo_cases()

    def _seed_demo_cases(self) -> None:
        c1 = Case("case_demo_001", "某财务服务器疑似勒索软件感染",
                  severity="critical", category="勒索软件")
        c1.owner = "张安全"
        c1.priority = "P0"
        c1.status = "contained"
        c1.description = "EDR告警显示finance-srv-03上有大量文件加密行为，文件扩展名为.locky"
        c1.add_member("张安全", "owner")
        c1.add_member("李分析", "analyst")
        c1.add_member("王响应", "responder")
        c1.add_task("隔离受影响主机", "王响应", "2026-09-15 12:00:00")
        c1.add_task("收集内存镜像", "李分析", "2026-09-15 14:00:00")
        c1.add_comment("张安全", "已确认是Locky变种，正在评估数据损失", ["李分析"])
        c1.add_ioc("file_hash", "a1b2c3d4e5f6...", "edr")
        c1.add_ioc("ip", "45.155.204.10", "threat_intel")
        c1.tags = ["locky", "finance", "ransomware"]
        self.cases[c1.id] = c1

        c2 = Case("case_demo_002", "市场部批量钓鱼邮件告警",
                  severity="high", category="钓鱼攻击")
        c2.owner = "李分析"
        c2.priority = "P1"
        c2.status = "investigating"
        c2.description = "邮件网关检测到23封疑似钓鱼邮件，发件人伪装成HR部门"
        c2.add_member("李分析", "owner")
        c2.add_task("搜索全邮箱相似邮件", "系统自动", "2026-09-15 18:00:00")
        c2.add_ioc("url", "hxxp://fake-hr-update.com/login", "email_security")
        c2.tags = ["phishing", "hr_spoof", "marketing_dept"]
        self.cases[c2.id] = c2

    # ---- 创建 ----
    def create(self, title: str, severity: str = "medium",
               category: str = "其他", owner: str = "",
               description: str = "",
               related_alerts: Optional[List[str]] = None) -> Case:
        cid = f"case_{uuid.uuid4().hex[:10]}"
        c = Case(cid, title, severity, category)
        c.owner = owner
        c.description = description
        c.related_alerts = related_alerts or []
        if owner:
            c.add_member(owner, "owner")
        self.cases[cid] = c
        return c

    def create_from_template(self, template_id: str, title: str,
                             owner: str = "") -> Optional[Case]:
        tpl = next((t for t in CASE_TEMPLATES if t["template_id"] == template_id), None)
        if not tpl:
            return None
        c = self.create(title, severity=tpl["severity"], category=tpl["category"],
                       owner=owner, description=f"模板: {tpl['name']}")
        c.set_priority(tpl["default_priority"])
        for item in tpl["checklist"]:
            c.add_task(item, owner)
        return c

    def create_from_alert(self, alert_id: str, alert_title: str,
                          severity: str = "high") -> Case:
        c = self.create(alert_title, severity=severity,
                       category="告警自动创建")
        c.related_alerts = [alert_id]
        c.tags = ["auto_created", "from_alert"]
        return c

    # ---- 查询 ----
    def list_cases(self, status: Optional[str] = None,
                   category: Optional[str] = None,
                   priority: Optional[str] = None,
                   severity: Optional[str] = None) -> List[Dict[str, Any]]:
        items = list(self.cases.values())
        if status:
            items = [c for c in items if c.status == status]
        if category:
            items = [c for c in items if c.category == category]
        if priority:
            items = [c for c in items if c.priority == priority]
        if severity:
            items = [c for c in items if c.severity == severity]
        return [c.to_dict() for c in items]

    def get(self, case_id: str) -> Optional[Case]:
        return self.cases.get(case_id)

    # ---- 知识库 ----
    def search_knowledge(self, keyword: str = "",
                         category: str = "") -> List[Dict[str, Any]]:
        items = list(KNOWLEDGE_BASE)
        if keyword:
            kw = keyword.lower()
            items = [k for k in items
                     if kw in k["title"].lower()
                     or kw in k["content"].lower()
                     or any(kw in t.lower() for t in k["tags"])]
        if category:
            items = [k for k in items if k["category"] == category]
        return items

    def list_templates(self) -> List[Dict[str, Any]]:
        return CASE_TEMPLATES

    # ---- 分析 ----
    def analytics(self) -> Dict[str, Any]:
        total = len(self.cases)
        closed = sum(1 for c in self.cases.values() if c.status == "closed")
        false_pos = sum(1 for c in self.cases.values() if c.status == "false_positive")
        open_count = sum(1 for c in self.cases.values() if c.status not in ("closed", "false_positive"))

        cat_dist: Dict[str, int] = {}
        prio_dist: Dict[str, int] = {}
        for c in self.cases.values():
            cat_dist[c.category] = cat_dist.get(c.category, 0) + 1
            prio_dist[c.priority] = prio_dist.get(c.priority, 0) + 1

        # SLA达标率（模拟）
        sla_compliant = sum(1 for c in self.cases.values()
                           if c.status == "closed" and c.priority in ("P0", "P1"))

        return {
            "total_cases": total,
            "open_cases": open_count,
            "closed_cases": closed,
            "false_positives": false_pos,
            "resolution_rate": round(closed / max(1, total) * 100, 1),
            "category_distribution": cat_dist,
            "priority_distribution": prio_dist,
            "sla_compliance_rate": round(sla_compliant / max(1, closed) * 100, 1),
            "avg_tasks_per_case": round(
                sum(len(c.tasks) for c in self.cases.values()) / max(1, total), 1),
            "knowledge_base_count": len(KNOWLEDGE_BASE),
            "templates_count": len(CASE_TEMPLATES),
        }


# --------------------------------------------------------------------------- #
# 单例
# --------------------------------------------------------------------------- #
_case_mgr: Optional[CaseManager] = None


def get_case_manager() -> CaseManager:
    global _case_mgr
    if _case_mgr is None:
        _case_mgr = CaseManager()
    return _case_mgr
