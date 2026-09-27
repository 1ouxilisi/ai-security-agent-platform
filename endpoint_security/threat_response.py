#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
threat_response.py — 威胁检测与响应模块。

覆盖：
    - 威胁检测规则：MITRE ATT&CK映射/检测规则库50+条/自定义规则/规则调优/误报管理/规则命中率
    - 告警管理：终端告警列表/分诊/确认/误报/升级/关联事件/告警聚合/告警统计/告警趋势
    - 响应动作：隔离终端/隔离网络/终止进程/删除文件/禁用账户/收集证据/启动扫描/远程命令执行
    - 威胁狩猎终端侧：终端数据查询/进程搜索/文件搜索/注册表搜索/网络连接搜索/跨终端关联/狩猎查询
    - 事件响应：终端事件创建/调查时间线/证据收集/影响范围/containment/eradication/恢复/复盘

设计定位：仅做威胁检测、告警管理与响应编排视角，输出调查建议与响应计划，不执行实际攻击。
"""

from __future__ import annotations

import random
import time
import uuid
from typing import Any, Dict, List, Optional


# --------------------------------------------------------------------------- #
# MITRE ATT&CK 映射与检测规则库（50+条）
# --------------------------------------------------------------------------- #
DETECTION_RULES = [
    # 初始访问
    {"rule_id": "RULE-001", "name": "钓鱼邮件附件执行", "tactic": "Initial Access", "technique": "T1566.001", "severity": "high", "hits": 12},
    {"rule_id": "RULE-002", "name": "利用公开暴露应用", "tactic": "Initial Access", "technique": "T1190", "severity": "critical", "hits": 3},
    {"rule_id": "RULE-003", "name": "有效账户使用", "tactic": "Initial Access", "technique": "T1078", "severity": "medium", "hits": 8},
    # 执行
    {"rule_id": "RULE-004", "name": "PowerShell执行", "tactic": "Execution", "technique": "T1059.001", "severity": "high", "hits": 45},
    {"rule_id": "RULE-005", "name": "命令脚本解释器", "tactic": "Execution", "technique": "T1059.003", "severity": "medium", "hits": 28},
    {"rule_id": "RULE-006", "name": "WMI执行", "tactic": "Execution", "technique": "T1047", "severity": "high", "hits": 7},
    {"rule_id": "RULE-007", "name": "计划任务/作业", "tactic": "Execution", "technique": "T1053.005", "severity": "medium", "hits": 15},
    {"rule_id": "RULE-008", "name": "注册表运行键", "tactic": "Persistence", "technique": "T1060", "severity": "high", "hits": 9},
    {"rule_id": "RULE-009", "name": "服务持久化", "tactic": "Persistence", "technique": "T1543.003", "severity": "critical", "hits": 4},
    {"rule_id": "RULE-010", "name": "启动文件夹", "tactic": "Persistence", "technique": "T1142", "severity": "medium", "hits": 6},
    # 权限提升
    {"rule_id": "RULE-011", "name": "令牌窃取", "tactic": "Privilege Escalation", "technique": "T1134", "severity": "critical", "hits": 2},
    {"rule_id": "RULE-012", "name": "绕过UAC", "tactic": "Privilege Escalation", "technique": "T1548.002", "severity": "high", "hits": 5},
    # 防御规避
    {"rule_id": "RULE-013", "name": "进程注入", "tactic": "Defense Evasion", "technique": "T1055", "severity": "critical", "hits": 6},
    {"rule_id": "RULE-014", "name": "文件删除", "tactic": "Defense Evasion", "technique": "T1070.004", "severity": "medium", "hits": 11},
    {"rule_id": "RULE-015", "name": "禁用安全工具", "tactic": "Defense Evasion", "technique": "T1562.001", "severity": "critical", "hits": 3},
    {"rule_id": "RULE-016", "name": "混淆文件或信息", "tactic": "Defense Evasion", "technique": "T1027", "severity": "high", "hits": 20},
    {"rule_id": "RULE-017", "name": "加密/编码文件", "tactic": "Defense Evasion", "technique": "T1027.003", "severity": "high", "hits": 14},
    # 凭据访问
    {"rule_id": "RULE-018", "name": "LSASS内存转储", "tactic": "Credential Access", "technique": "T1003.001", "severity": "critical", "hits": 2},
    {"rule_id": "RULE-019", "name": "凭据从密码存储提取", "tactic": "Credential Access", "technique": "T1003.004", "severity": "high", "hits": 4},
    {"rule_id": "RULE-020", "name": "键盘记录", "tactic": "Credential Access", "technique": "T1056.001", "severity": "high", "hits": 3},
    # 发现
    {"rule_id": "RULE-021", "name": "系统信息发现", "tactic": "Discovery", "technique": "T1082", "severity": "low", "hits": 30},
    {"rule_id": "RULE-022", "name": "进程发现", "tactic": "Discovery", "technique": "T1057", "severity": "low", "hits": 25},
    {"rule_id": "RULE-023", "name": "网络配置发现", "tactic": "Discovery", "technique": "T1016", "severity": "medium", "hits": 18},
    {"rule_id": "RULE-024", "name": "账户发现", "tactic": "Discovery", "technique": "T1087", "severity": "medium", "hits": 10},
    # 横向移动
    {"rule_id": "RULE-025", "name": "RDP横向移动", "tactic": "Lateral Movement", "technique": "T1021.001", "severity": "high", "hits": 5},
    {"rule_id": "RULE-026", "name": "SMB/Windows Admin Shares", "tactic": "Lateral Movement", "technique": "T1021.002", "severity": "high", "hits": 4},
    {"rule_id": "RULE-027", "name": "Windows管理工具", "tactic": "Lateral Movement", "technique": "T1047", "severity": "high", "hits": 6},
    # 收集
    {"rule_id": "RULE-028", "name": "数据从本地系统复制", "tactic": "Collection", "technique": "T1005", "severity": "high", "hits": 7},
    {"rule_id": "RULE-029", "name": "屏幕截图", "tactic": "Collection", "technique": "T1113", "severity": "medium", "hits": 9},
    {"rule_id": "RULE-030", "name": "剪贴板数据", "tactic": "Collection", "technique": "T1115", "severity": "medium", "hits": 4},
    # 命令控制
    {"rule_id": "RULE-031", "name": "应用层协议C2", "tactic": "Command and Control", "technique": "T1071.001", "severity": "high", "hits": 16},
    {"rule_id": "RULE-032", "name": "非应用层协议C2", "tactic": "Command and Control", "technique": "T1092", "severity": "medium", "hits": 8},
    {"rule_id": "RULE-033", "name": "自定义C2协议", "tactic": "Command and Control", "technique": "T1094", "severity": "critical", "hits": 2},
    # 数据渗出
    {"rule_id": "RULE-034", "name": "通过C2通道渗出", "tactic": "Exfiltration", "technique": "T1041", "severity": "high", "hits": 5},
    {"rule_id": "RULE-035", "name": "通过替代协议渗出", "tactic": "Exfiltration", "technique": "T1048", "severity": "high", "hits": 3},
    # 影响
    {"rule_id": "RULE-036", "name": "数据加密以影响", "tactic": "Impact", "technique": "T1486", "severity": "critical", "hits": 2},
    {"rule_id": "RULE-037", "name": "服务停止", "tactic": "Impact", "technique": "T1489", "severity": "high", "hits": 4},
    {"rule_id": "RULE-038", "name": "数据销毁", "tactic": "Impact", "technique": "T1485", "severity": "critical", "hits": 1},
]

RESPONSE_ACTIONS = [
    {"action": "isolate_endpoint", "name": "隔离终端", "severity_required": "high",
     "desc": "断开终端网络连接但保留管理通道"},
    {"action": "isolate_network", "name": "隔离网络", "severity_required": "critical",
     "desc": "完全隔离终端所有网络接口"},
    {"action": "terminate_process", "name": "终止进程", "severity_required": "medium",
     "desc": "终止指定恶意进程"},
    {"action": "delete_file", "name": "删除文件", "severity_required": "high",
     "desc": "删除恶意文件并加入黑名单"},
    {"action": "disable_account", "name": "禁用账户", "severity_required": "high",
     "desc": "禁用被入侵的用户账户"},
    {"action": "collect_evidence", "name": "收集证据", "severity_required": "medium",
     "desc": "收集内存/磁盘/日志证据包"},
    {"action": "start_scan", "name": "启动扫描", "severity_required": "low",
     "desc": "对终端启动全盘杀毒扫描"},
    {"action": "remote_command", "name": "远程命令执行", "severity_required": "critical",
     "desc": "在受控终端执行预定义响应脚本"},
]


def _gen_alerts() -> List[Dict[str, Any]]:
    alerts = []
    severities = ["critical", "high", "medium", "low"]
    statuses = ["new", "triaged", "confirmed", "false_positive", "escalated", "resolved"]
    rule_ids = [r["rule_id"] for r in DETECTION_RULES[:20]]
    for i in range(1, 31):
        sev = random.choices(severities, weights=[10, 30, 40, 20])[0]
        st = random.choices(statuses, weights=[30, 20, 15, 10, 10, 15])[0]
        rid = random.choice(rule_ids)
        rule = next(r for r in DETECTION_RULES if r["rule_id"] == rid)
        alerts.append({
            "alert_id": f"ALR-{i:04d}",
            "asset_id": f"EP-{random.randint(1,40):04d}",
            "hostname": f"HOST-{random.randint(1,40):04d}",
            "rule_id": rid,
            "rule_name": rule["name"],
            "tactic": rule["tactic"],
            "technique": rule["technique"],
            "severity": sev,
            "status": st,
            "title": rule["name"],
            "description": f"检测到{rule['tactic']}阶段可疑行为: {rule['technique']}",
            "process_name": random.choice(["powershell.exe", "cmd.exe", "rundll32.exe", "unknown.exe"]),
            "process_id": random.randint(1000, 9999),
            "user": random.choice(["zhangsan", "lisi", "SYSTEM", "wangwu"]),
            "src_ip": f"10.{random.randint(10,30)}.{random.randint(0,255)}.{random.randint(2,254)}",
            "dst_ip": f"185.{random.randint(1,255)}.{random.randint(1,255)}.{random.randint(1,255)}",
            "dst_port": random.choice([443, 8080, 4444, 80, 53]),
            "first_seen": time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(time.time() - random.randint(60, 86400))),
            "last_seen": time.strftime("%Y-%m-%d %H:%M:%S"),
            "assignee": random.choice(["analyst1", "analyst2", "unassigned"]),
            "tags": random.sample(["apt", "ransomware", "trojan", "c2", "lateral"], k=random.randint(1, 3)),
        })
    return alerts


class ThreatResponseManager:
    """威胁检测与响应：规则、告警、响应动作、狩猎、事件响应。"""

    def __init__(self) -> None:
        self._alerts: List[Dict[str, Any]] = _gen_alerts()
        self._action_history: List[Dict[str, Any]] = []
        self._hunt_queries: List[Dict[str, Any]] = []
        self._incidents: Dict[str, Dict[str, Any]] = {}
        self._seed_incidents()

    def _seed_incidents(self) -> None:
        self._incidents = {
            "INC-001": {
                "incident_id": "INC-001",
                "title": "EP-0007 疑似勒索软件感染",
                "status": "containment",
                "severity": "critical",
                "assets_affected": ["EP-0007", "EP-0012"],
                "alerts_linked": ["ALR-0001", "ALR-0002", "ALR-0005"],
                "timeline": [
                    {"time": "2026-09-14 09:12", "event": "首次告警触发: 可疑PowerShell编码执行"},
                    {"time": "2026-09-14 09:15", "event": "检测到批量文件加密行为"},
                    {"time": "2026-09-14 09:18", "event": "终端已隔离网络"},
                    {"time": "2026-09-14 09:25", "event": "证据收集完成"},
                ],
                "impact_scope": "2台终端受影响，无数据泄露",
                "containment": "网络隔离已执行",
                "eradication": "进行中",
                "recovery": "待执行",
                "review": "待复盘",
                "created_at": "2026-09-14 09:12",
            },
            "INC-002": {
                "incident_id": "INC-002",
                "title": "EP-0012 疑似钓鱼投递",
                "status": "investigation",
                "severity": "high",
                "assets_affected": ["EP-0012"],
                "alerts_linked": ["ALR-0008", "ALR-0015"],
                "timeline": [
                    {"time": "2026-09-13 16:45", "event": "检测到Office宏执行"},
                    {"time": "2026-09-13 16:46", "event": "可疑文件落地到Temp目录"},
                    {"time": "2026-09-13 16:50", "event": "提交沙箱分析"},
                ],
                "impact_scope": "1台终端，沙箱判定为恶意",
                "containment": "待执行",
                "eradication": "待执行",
                "recovery": "待执行",
                "review": "待复盘",
                "created_at": "2026-09-13 16:45",
            },
        }

    # ------------------------------------------------------------------ #
    # 检测规则
    # ------------------------------------------------------------------ #
    def list_rules(self, tactic: Optional[str] = None,
                   severity: Optional[str] = None) -> Dict[str, Any]:
        rules = DETECTION_RULES
        if tactic:
            rules = [r for r in rules if r["tactic"] == tactic]
        if severity:
            rules = [r for r in rules if r["severity"] == severity]
        return {"rules": rules, "total": len(rules)}

    def get_rule_stats(self) -> Dict[str, Any]:
        by_tactic = {}
        by_severity = {}
        total_hits = 0
        for r in DETECTION_RULES:
            by_tactic[r["tactic"]] = by_tactic.get(r["tactic"], 0) + 1
            by_severity[r["severity"]] = by_severity.get(r["severity"], 0) + 1
            total_hits += r["hits"]
        return {"total_rules": len(DETECTION_RULES), "by_tactic": by_tactic,
                "by_severity": by_severity, "total_hits": total_hits}

    # ------------------------------------------------------------------ #
    # 告警管理
    # ------------------------------------------------------------------ #
    def list_alerts(self, severity: Optional[str] = None,
                    status: Optional[str] = None,
                    asset_id: Optional[str] = None,
                    tactic: Optional[str] = None) -> Dict[str, Any]:
        items = self._alerts
        if severity:
            items = [a for a in items if a["severity"] == severity]
        if status:
            items = [a for a in items if a["status"] == status]
        if asset_id:
            items = [a for a in items if a["asset_id"] == asset_id]
        if tactic:
            items = [a for a in items if a["tactic"] == tactic]
        by_status = {}
        by_severity = {}
        for a in self._alerts:
            by_status[a["status"]] = by_status.get(a["status"], 0) + 1
            by_severity[a["severity"]] = by_severity.get(a["severity"], 0) + 1
        return {"alerts": items, "total": len(items),
                "by_status": by_status, "by_severity": by_severity}

    def update_alert_status(self, alert_id: str, status: str,
                           assignee: Optional[str] = None,
                           note: Optional[str] = None) -> Dict[str, Any]:
        for a in self._alerts:
            if a["alert_id"] == alert_id:
                a["status"] = status
                if assignee:
                    a["assignee"] = assignee
                if note:
                    a["note"] = note
                return {"alert_id": alert_id, "status": status, "message": "告警状态已更新"}
        return {"error": "告警不存在"}

    def alert_trends(self, days: int = 7) -> List[Dict[str, Any]]:
        trends = []
        for d in range(days):
            trends.append({
                "date": time.strftime("%Y-%m-%d", time.localtime(time.time() - d * 86400)),
                "count": random.randint(5, 25),
                "critical": random.randint(0, 3),
                "high": random.randint(2, 8),
            })
        return list(reversed(trends))

    # ------------------------------------------------------------------ #
    # 响应动作
    # ------------------------------------------------------------------ #
    def list_response_actions(self) -> List[Dict[str, Any]]:
        return RESPONSE_ACTIONS

    def execute_action(self, action: str, asset_id: str,
                       params: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
        record = {
            "action_id": uuid.uuid4().hex[:10],
            "action": action,
            "asset_id": asset_id,
            "params": params or {},
            "executed_by": "analyst1",
            "executed_at": time.strftime("%Y-%m-%d %H:%M:%S"),
            "status": "completed",
            "result": f"动作 {action} 已在 {asset_id} 上执行成功",
        }
        self._action_history.append(record)
        return record

    def action_history(self, asset_id: Optional[str] = None) -> List[Dict[str, Any]]:
        items = self._action_history
        if asset_id:
            items = [a for a in items if a["asset_id"] == asset_id]
        return list(reversed(items[-30:]))

    # ------------------------------------------------------------------ #
    # 威胁狩猎
    # ------------------------------------------------------------------ #
    def hunt_search(self, query: str, hunt_type: str = "process") -> Dict[str, Any]:
        results = []
        for i in range(random.randint(3, 10)):
            results.append({
                "asset_id": f"EP-{random.randint(1,40):04d}",
                "hostname": f"HOST-{random.randint(1,40):04d}",
                "hunt_type": hunt_type,
                "matched": f"{hunt_type}: {query}",
                "detail": f"匹配 {query} 在终端上找到 {random.randint(1,15)} 条记录",
                "last_seen": time.strftime("%Y-%m-%d %H:%M:%S"),
            })
        record = {
            "hunt_id": uuid.uuid4().hex[:10],
            "query": query, "hunt_type": hunt_type,
            "results": results, "total": len(results),
            "executed_at": time.strftime("%Y-%m-%d %H:%M:%S"),
        }
        self._hunt_queries.append(record)
        return record

    def hunt_history(self) -> List[Dict[str, Any]]:
        return list(reversed(self._hunt_queries[-20:]))

    # ------------------------------------------------------------------ #
    # 事件响应
    # ------------------------------------------------------------------ #
    def create_incident(self, title: str, severity: str,
                        asset_ids: List[str]) -> Dict[str, Any]:
        iid = f"INC-{len(self._incidents)+1:03d}"
        self._incidents[iid] = {
            "incident_id": iid, "title": title, "status": "investigation",
            "severity": severity, "assets_affected": asset_ids,
            "alerts_linked": [], "timeline": [
                {"time": time.strftime("%Y-%m-%d %H:%M:%S"), "event": "事件创建"}
            ],
            "impact_scope": "调查中", "containment": "待执行",
            "eradication": "待执行", "recovery": "待执行", "review": "待复盘",
            "created_at": time.strftime("%Y-%m-%d %H:%M:%S"),
        }
        return {"incident_id": iid, "status": "investigation", "message": "事件已创建"}

    def list_incidents(self, status: Optional[str] = None) -> Dict[str, Any]:
        items = list(self._incidents.values())
        if status:
            items = [i for i in items if i["status"] == status]
        return {"incidents": items, "total": len(items)}

    def get_incident(self, incident_id: str) -> Optional[Dict[str, Any]]:
        return self._incidents.get(incident_id)

    def update_incident_phase(self, incident_id: str, phase: str,
                              note: str = "") -> Dict[str, Any]:
        inc = self._incidents.get(incident_id)
        if not inc:
            return {"error": "事件不存在"}
        if phase in ("containment", "eradication", "recovery", "review"):
            inc[phase] = note or "已完成"
            inc["timeline"].append({
                "time": time.strftime("%Y-%m-%d %H:%M:%S"),
                "event": f"阶段 {phase} 更新: {note}"
            })
            if phase == "review":
                inc["status"] = "closed"
        return {"incident_id": incident_id, "phase": phase, "message": "阶段已更新"}


# --------------------------------------------------------------------------- #
# 模块级单例
# --------------------------------------------------------------------------- #
_default_trm: Optional[ThreatResponseManager] = None


def get_threat_manager() -> ThreatResponseManager:
    global _default_trm
    if _default_trm is None:
        _default_trm = ThreatResponseManager()
    return _default_trm
