# -*- coding: utf-8 -*-
"""
hypothesis_driven_hunt.py — 假设驱动狩猎。

提供狩猎假设管理（MITRE ATT&CK映射）、狩猎项目管理、
狩猎剧本步骤化流程、狩猎发现管理四大子系统。

设计定位：仅用于经过授权的防御性威胁狩猎活动。
"""

from __future__ import annotations

import time
import uuid
from typing import Any, Dict, List, Optional


# --------------------------------------------------------------------------- #
# 假设管理
# --------------------------------------------------------------------------- #
class HypothesisManager:
    """狩猎假设管理器。"""

    STATUS_OPTIONS = ["draft", "active", "validated", "falsified", "expired"]
    PRIORITY_OPTIONS = ["low", "medium", "high", "critical"]

    def __init__(self) -> None:
        self._hypotheses: Dict[str, Dict[str, Any]] = {}
        self._seed_default_hypotheses()

    def _seed_default_hypotheses(self) -> None:
        """预置默认狩猎假设。"""
        defaults = [
            {
                "title": "可能存在利用公开漏洞的初始访问",
                "description": "近期公开的Exchange/Confluence漏洞可能被利用，需排查内网是否存在相关攻击痕迹",
                "mitre_tactics": ["TA0001"],
                "mitre_techniques": ["T1190", "T1133"],
                "verification_method": "搜索Web服务器日志中的漏洞利用特征，检查WAF告警",
                "priority": "high",
            },
            {
                "title": "可能存在钓鱼邮件投递恶意附件",
                "description": "结合最近钓鱼邮件拦截记录，检查是否有用户打开恶意附件并产生后续行为",
                "mitre_tactics": ["TA0001"],
                "mitre_techniques": ["T1566.001", "T1204.002"],
                "verification_method": "追踪被拦截钓鱼邮件发件人，检查对应主机是否有异常进程启动",
                "priority": "critical",
            },
            {
                "title": "可能存在横向移动活动",
                "description": "内网中可能存在攻击者通过SMB/WMI/RDP进行横向移动",
                "mitre_tactics": ["TA0008"],
                "mitre_techniques": ["T1021.002", "T1047", "T1021.001"],
                "verification_method": "分析认证日志，查找异常横向登录模式",
                "priority": "high",
            },
            {
                "title": "可能存在数据外渗行为",
                "description": "可能存在敏感数据通过云存储或加密通道外渗",
                "mitre_tactics": ["TA0010"],
                "mitre_techniques": ["T1048.003", "T1567.002"],
                "verification_method": "监控出站流量到云存储和非常规外部IP",
                "priority": "medium",
            },
            {
                "title": "可能存在持久化机制",
                "description": "攻击者可能已在目标系统上建立持久化机制",
                "mitre_tactics": ["TA0003"],
                "mitre_techniques": ["T1547.001", "T1543.003", "T1053.005"],
                "verification_method": "检查注册表Run键、服务、计划任务中的异常条目",
                "priority": "high",
            },
        ]
        for d in defaults:
            self.create_hypothesis(
                title=d["title"],
                description=d["description"],
                mitre_tactics=d["mitre_tactics"],
                mitre_techniques=d["mitre_techniques"],
                verification_method=d["verification_method"],
                priority=d["priority"],
            )

    def create_hypothesis(self, title: str, description: str = "",
                          mitre_tactics: List[str] = None,
                          mitre_techniques: List[str] = None,
                          verification_method: str = "",
                          priority: str = "medium",
                          analyst: str = "analyst") -> Dict[str, Any]:
        """创建狩猎假设。"""
        hid = uuid.uuid4().hex[:12]
        entry = {
            "hypothesis_id": hid,
            "title": title,
            "description": description,
            "mitre_tactics": mitre_tactics or [],
            "mitre_techniques": mitre_techniques or [],
            "verification_method": verification_method,
            "priority": priority if priority in self.PRIORITY_OPTIONS else "medium",
            "status": "draft",
            "analyst": analyst,
            "created_at": time.strftime("%Y-%m-%d %H:%M:%S"),
            "updated_at": time.strftime("%Y-%m-%d %H:%M:%S"),
            "validated_at": None,
            "findings_count": 0,
        }
        self._hypotheses[hid] = entry
        return entry

    def update_hypothesis(self, hypothesis_id: str, **kwargs) -> Optional[Dict[str, Any]]:
        """更新假设。"""
        h = self._hypotheses.get(hypothesis_id)
        if not h:
            return None
        for k, v in kwargs.items():
            if k in h:
                h[k] = v
        h["updated_at"] = time.strftime("%Y-%m-%d %H:%M:%S")
        if h["status"] == "validated":
            h["validated_at"] = time.strftime("%Y-%m-%d %H:%M:%S")
        return h

    def list_hypotheses(self, status: Optional[str] = None,
                        priority: Optional[str] = None) -> List[Dict[str, Any]]:
        """列出假设，支持按状态/优先级过滤。"""
        items = list(self._hypotheses.values())
        if status:
            items = [h for h in items if h["status"] == status]
        if priority:
            items = [h for h in items if h["priority"] == priority]
        return items

    def get_hypothesis(self, hypothesis_id: str) -> Optional[Dict[str, Any]]:
        return self._hypotheses.get(hypothesis_id)


# --------------------------------------------------------------------------- #
# 狩猎项目管理
# --------------------------------------------------------------------------- #
class HuntProjectManager:
    """狩猎项目管理器。"""

    STATUS_OPTIONS = ["planning", "active", "paused", "completed", "cancelled"]

    def __init__(self) -> None:
        self._projects: Dict[str, Dict[str, Any]] = {}
        self._seed_default_projects()

    def _seed_default_projects(self) -> None:
        """预置默认狩猎项目。"""
        defaults = [
            {
                "name": "Q3季度例行威胁狩猎",
                "goal": "覆盖核心业务系统，验证ATT&CK T1078/T1110/T1021",
                "scope": "全部Windows服务器+域控+Web前端",
                "timeline": "2026-09-01 至 2026-09-30",
                "team": ["analyst_a", "analyst_b"],
            },
            {
                "name": "新漏洞紧急狩猎",
                "goal": "排查公开漏洞CVE-2026-XXXX在内部的利用痕迹",
                "scope": "对外暴露的Web应用和中间件",
                "timeline": "2026-09-10 至 2026-09-20",
                "team": ["analyst_a"],
            },
        ]
        for d in defaults:
            self.create_project(**d)

    def create_project(self, name: str, goal: str = "", scope: str = "",
                       timeline: str = "", team: List[str] = None) -> Dict[str, Any]:
        """创建狩猎项目。"""
        pid = uuid.uuid4().hex[:12]
        entry = {
            "project_id": pid,
            "name": name,
            "goal": goal,
            "scope": scope,
            "timeline": timeline,
            "team": team or [],
            "status": "planning",
            "findings_count": 0,
            "hypotheses_count": 0,
            "playbooks_count": 0,
            "created_at": time.strftime("%Y-%m-%d %H:%M:%S"),
        }
        self._projects[pid] = entry
        return entry

    def update_project(self, project_id: str, **kwargs) -> Optional[Dict[str, Any]]:
        p = self._projects.get(project_id)
        if not p:
            return None
        for k, v in kwargs.items():
            if k in p:
                p[k] = v
        return p

    def list_projects(self, status: Optional[str] = None) -> List[Dict[str, Any]]:
        items = list(self._projects.values())
        if status:
            items = [p for p in items if p["status"] == status]
        return items

    def get_project(self, project_id: str) -> Optional[Dict[str, Any]]:
        return self._projects.get(project_id)


# --------------------------------------------------------------------------- #
# 狩猎剧本管理
# --------------------------------------------------------------------------- #
class HuntPlaybookManager:
    """狩猎剧本管理器。"""

    def __init__(self) -> None:
        self._playbooks: Dict[str, Dict[str, Any]] = {}
        self._seed_default_playbooks()

    def _seed_default_playbooks(self) -> None:
        """预置默认狩猎剧本。"""
        defaults = [
            {
                "name": "钓鱼邮件响应狩猎剧本",
                "description": "从钓鱼邮件投递到初始执行的完整狩猎流程",
                "hypothesis_ref": "可能存在钓鱼邮件投递恶意附件",
                "steps": [
                    {"step": 1, "name": "识别钓鱼邮件", "query": "FROM email WHERE subject MATCHES 'urgent|verify|password' AND attachment_count > 0",
                     "expected_result": "找到可疑邮件", "criteria": "邮件含恶意附件URL", "done_when": "可疑邮件已标记"},
                    {"step": 2, "name": "追踪执行痕迹", "query": "FROM process WHERE parent_process_name IN ('outlook.exe','winword.exe') AND process_name IN ('powershell.exe','cmd.exe','wscript.exe')",
                     "expected_result": "找到由Office启动的子进程", "criteria": "子进程为脚本解释器", "done_when": "异常进程已记录"},
                    {"step": 3, "name": "检查网络连接", "query": "FROM network WHERE direction = 'outbound' AND hostname IN (SELECT hostname FROM process WHERE parent_process_name IN ('outlook.exe','winword.exe'))",
                     "expected_result": "找到可疑C2连接", "criteria": "连接到非业务IP", "done_when": "C2 IOC已提取"},
                    {"step": 4, "name": "持久化排查", "query": "FROM registry WHERE registry_key MATCHES 'Run|RunOnce|Services' AND event_type = 'set'",
                     "expected_result": "找到持久化条目", "criteria": "注册表值指向可疑路径", "done_when": "持久化点已确认"},
                ],
            },
            {
                "name": "横向移动狩猎剧本",
                "description": "检测内网横向移动行为",
                "hypothesis_ref": "可能存在横向移动活动",
                "steps": [
                    {"step": 1, "name": "异常登录检测", "query": "FROM login WHERE result = 'success' AND service IN ('rdp','smb','winrm')",
                     "expected_result": "找到异常登录", "criteria": "非工作时间或非日常IP", "done_when": "异常登录已标记"},
                    {"step": 2, "name": "WMI远程执行", "query": "FROM process WHERE process_name IN ('wmic.exe','wmiprvse.exe') AND command_line MATCHES '/node:|process.*create'",
                     "expected_result": "找到WMI远程执行", "criteria": "远程节点不在基线列表", "done_when": "WMI活动已记录"},
                    {"step": 3, "name": "SMB横向连接", "query": "FROM network WHERE destination_port = 445 GROUP BY source_ip, source_user HAVING COUNT(DISTINCT destination_ip) > 3",
                     "expected_result": "找到SMB横向扩散", "criteria": "单用户连接多主机", "done_when": "横向范围已确认"},
                ],
            },
        ]
        for d in defaults:
            self.create_playbook(**d)

    def create_playbook(self, name: str, description: str = "",
                        hypothesis_ref: str = "",
                        steps: List[Dict[str, Any]] = None) -> Dict[str, Any]:
        """创建狩猎剧本。"""
        pid = uuid.uuid4().hex[:12]
        entry = {
            "playbook_id": pid,
            "name": name,
            "description": description,
            "hypothesis_ref": hypothesis_ref,
            "steps": steps or [],
            "current_step": 0,
            "status": "not_started",
            "created_at": time.strftime("%Y-%m-%d %H:%M:%S"),
        }
        self._playbooks[pid] = entry
        return entry

    def update_playbook_step(self, playbook_id: str, step_index: int,
                             status: str = "completed") -> Optional[Dict[str, Any]]:
        """更新剧本步骤状态。"""
        pb = self._playbooks.get(playbook_id)
        if not pb:
            return None
        if 0 <= step_index < len(pb["steps"]):
            pb["steps"][step_index]["status"] = status
            pb["steps"][step_index]["completed_at"] = time.strftime("%Y-%m-%d %H:%M:%S")
        pb["current_step"] = step_index + 1
        if pb["current_step"] >= len(pb["steps"]):
            pb["status"] = "completed"
        return pb

    def list_playbooks(self) -> List[Dict[str, Any]]:
        return list(self._playbooks.values())

    def get_playbook(self, playbook_id: str) -> Optional[Dict[str, Any]]:
        return self._playbooks.get(playbook_id)


# --------------------------------------------------------------------------- #
# 狩猎发现管理
# --------------------------------------------------------------------------- #
class HuntFindingManager:
    """狩猎发现管理器。"""

    SEVERITY_OPTIONS = ["informational", "low", "medium", "high", "critical"]
    STATUS_OPTIONS = ["new", "triaged", "confirmed", "false_positive", "remediated", "closed"]

    def __init__(self) -> None:
        self._findings: Dict[str, Dict[str, Any]] = {}
        self._seed_default_findings()

    def _seed_default_findings(self) -> None:
        """预置默认发现。"""
        defaults = [
            {
                "title": "WIN-PC-01上检测到可疑PowerShell编码执行",
                "description": "在WIN-PC-01上发现powershell.exe执行Base64编码命令，疑似钓鱼后执行",
                "iocs": ["powershell.exe -enc SQBFAFgA...", "45.132.9.87:443"],
                "ttps": ["T1059.001", "T1140"],
                "affected_systems": ["WIN-PC-01"],
                "evidence": ["进程ID: 10001", "命令行含Base64编码", "出站连接到45.132.9.87"],
                "severity": "high",
                "hypothesis_ref": "可能存在钓鱼邮件投递恶意附件",
            },
            {
                "title": "WEB01上发现WebShell文件",
                "description": "在IIS目录下发现.aspx脚本文件，无签名，创建时间异常",
                "iocs": ["C:\\inetpub\\wwwroot\\shell.aspx", "UNHASH: a1b2c3d4e5f6"],
                "ttps": ["T1505.003", "T1190"],
                "affected_systems": ["WEB01"],
                "evidence": ["文件创建时间: 2026-09-14 10:30:00", "无数字签名", "访问日志POST请求"],
                "severity": "critical",
                "hypothesis_ref": "可能存在利用公开漏洞的初始访问",
            },
            {
                "title": "检测到RDP暴力破解成功",
                "description": "jsmith账号从45.132.9.87多次RDP失败后成功登录",
                "iocs": ["45.132.9.87", "rdp://WIN-PC-01:3389"],
                "ttps": ["T1110.001", "T1021.001"],
                "affected_systems": ["WIN-PC-01"],
                "evidence": ["4次失败后1次成功", "源IP不在管理IP列表", "登录时间07:55非工作时间"],
                "severity": "critical",
                "hypothesis_ref": "大量失败登录后成功登录",
            },
        ]
        for d in defaults:
            self.create_finding(**d)

    def create_finding(self, title: str, description: str = "",
                       iocs: List[str] = None, ttps: List[str] = None,
                       affected_systems: List[str] = None,
                       evidence: List[str] = None,
                       severity: str = "medium",
                       hypothesis_ref: str = "",
                       analyst: str = "analyst",
                       remediation: str = "") -> Dict[str, Any]:
        """创建狩猎发现。"""
        fid = uuid.uuid4().hex[:12]
        entry = {
            "finding_id": fid,
            "title": title,
            "description": description,
            "iocs": iocs or [],
            "ttps": ttps or [],
            "affected_systems": affected_systems or [],
            "evidence": evidence or [],
            "severity": severity if severity in self.SEVERITY_OPTIONS else "medium",
            "status": "new",
            "hypothesis_ref": hypothesis_ref,
            "analyst": analyst,
            "remediation": remediation or "隔离受影响主机，重置凭据，清除持久化",
            "created_at": time.strftime("%Y-%m-%d %H:%M:%S"),
            "updated_at": time.strftime("%Y-%m-%d %H:%M:%S"),
        }
        self._findings[fid] = entry
        return entry

    def update_finding(self, finding_id: str, **kwargs) -> Optional[Dict[str, Any]]:
        f = self._findings.get(finding_id)
        if not f:
            return None
        for k, v in kwargs.items():
            if k in f:
                f[k] = v
        f["updated_at"] = time.strftime("%Y-%m-%d %H:%M:%S")
        return f

    def list_findings(self, severity: Optional[str] = None,
                      status: Optional[str] = None) -> List[Dict[str, Any]]:
        items = list(self._findings.values())
        if severity:
            items = [f for f in items if f["severity"] == severity]
        if status:
            items = [f for f in items if f["status"] == status]
        return items

    def get_finding(self, finding_id: str) -> Optional[Dict[str, Any]]:
        return self._findings.get(finding_id)

    def finding_summary(self) -> Dict[str, Any]:
        """发现统计摘要。"""
        items = list(self._findings.values())
        by_severity: Dict[str, int] = {}
        by_status: Dict[str, int] = {}
        for f in items:
            by_severity[f["severity"]] = by_severity.get(f["severity"], 0) + 1
            by_status[f["status"]] = by_status.get(f["status"], 0) + 1
        return {
            "total": len(items),
            "by_severity": by_severity,
            "by_status": by_status,
            "critical": by_severity.get("critical", 0),
            "high": by_severity.get("high", 0),
        }
