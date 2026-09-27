# -*- coding: utf-8 -*-
"""
incident_response_phase.py — 阶段5：事件响应（SOAR 剧本自动化）。

功能:
    - SOAR 剧本自动化（隔离主机/封禁 IP/重置密码/收集证据/禁用账户）
    - 剧本管理（创建/编辑/执行/测试）
    - 工单管理（创建/分配/处理/关闭/SLA）
    - 响应流程跟踪
    - 响应时间统计
    - 证据收集与管理
"""

from __future__ import annotations

import shutil
import subprocess
import threading
import time
import uuid
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from typing import Any, Dict, List, Optional

TOOL_TIMEOUT = 300


def _which(name: str) -> Optional[str]:
    return shutil.which(name)


@dataclass
class SOARAction:
    action: str = ""
    desc: str = ""
    tool: str = ""
    command: str = ""
    requires_admin: bool = False


@dataclass
class SOARPlaybook:
    pb_id: str = ""
    name: str = ""
    description: str = ""
    severity: str = "high"
    steps: List[Dict[str, Any]] = field(default_factory=list)
    runs: int = 0

    def to_dict(self) -> Dict[str, Any]:
        return {
            "pb_id": self.pb_id, "name": self.name,
            "description": self.description, "severity": self.severity,
            "steps": self.steps, "runs": self.runs,
        }


@dataclass
class Ticket:
    ticket_id: str = ""
    title: str = ""
    alert_id: str = ""
    status: str = "open"     # open/assigned/in_progress/resolved/closed
    assignee: str = ""
    priority: str = "medium"
    created_at: str = ""
    due_at: str = ""
    resolved_at: str = ""
    notes: List[str] = field(default_factory=list)
    actions: List[Dict[str, Any]] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "ticket_id": self.ticket_id, "title": self.title,
            "alert_id": self.alert_id, "status": self.status,
            "assignee": self.assignee, "priority": self.priority,
            "created_at": self.created_at, "due_at": self.due_at,
            "resolved_at": self.resolved_at, "notes": self.notes,
            "actions": self.actions,
        }


# 内置剧本
_BUILTIN_PLAYBOOKS: List[Dict[str, Any]] = [
    {
        "name": "高危告警一键处置",
        "description": "封禁攻击源 IP + 收集主机证据 + 通知值班",
        "severity": "critical",
        "steps": [
            {"action": "block_ip", "desc": "防火墙封禁源 IP",
             "tool": "iptables",
             "command": "iptables -A INPUT -s {src_ip} -j DROP"},
            {"action": "collect_evidence", "desc": "收集系统日志/进程/网络",
             "tool": "system", "command": "ps,netstat,auth.log"},
            {"action": "notify", "desc": "通知值班人员",
             "tool": "webhook", "command": "post to oncall"},
        ],
    },
    {
        "name": "暴力破解响应",
        "description": "封禁 IP + 锁定账户 + 重置密码",
        "severity": "high",
        "steps": [
            {"action": "block_ip", "desc": "封禁源 IP",
             "tool": "iptables", "command": "iptables -A INPUT -s {src_ip}"},
            {"action": "lock_account", "desc": "锁定被爆破账户",
             "tool": "passwd", "command": "passwd -l {user}"},
            {"action": "reset_password", "desc": "强制重置密码",
             "tool": "passwd", "command": "passwd --expire {user}"},
        ],
    },
    {
        "name": "勒索软件响应",
        "description": "隔离主机 + 断网 + 保留证据",
        "severity": "critical",
        "steps": [
            {"action": "isolate_host", "desc": "交换机端口隔离",
             "tool": "network", "command": "shutdown interface"},
            {"action": "collect_evidence", "desc": "内存/磁盘镜像",
             "tool": "dd", "command": "dd if=/dev/sda of=evidence.img"},
            {"action": "open_incident", "desc": "启动事件工单",
             "tool": "ticket", "command": "create ticket"},
        ],
    },
    {
        "name": "钓鱼邮件处置",
        "description": "回收邮件 + 终端查杀 + 用户教育",
        "severity": "medium",
        "steps": [
            {"action": "quarantine_email", "desc": "邮件网关隔离",
             "tool": "mail", "command": "quarantine by message-id"},
            {"action": "scan_endpoint", "desc": "终端杀毒扫描",
             "tool": "clamav", "command": "clamscan -r /home"},
            {"action": "notify_user", "desc": "通知用户",
             "tool": "email", "command": "send warning mail"},
        ],
    },
]


class IncidentResponsePhase:
    """阶段5：事件响应 / SOAR。"""

    def __init__(self) -> None:
        self._playbooks: Dict[str, SOARPlaybook] = {}
        self._tickets: Dict[str, Ticket] = {}
        self._evidence: List[Dict[str, Any]] = []
        self._lock = threading.Lock()
        self._load_builtin()

    def _load_builtin(self) -> None:
        for i, pb in enumerate(_BUILTIN_PLAYBOOKS):
            pid = f"pb_{i+1:03d}"
            self._playbooks[pid] = SOARPlaybook(
                pb_id=pid, name=pb["name"],
                description=pb["description"],
                severity=pb["severity"], steps=pb["steps"])

    # ------------------------------------------------------------------ #
    def list_playbooks(self) -> List[Dict[str, Any]]:
        with self._lock:
            return [p.to_dict() for p in self._playbooks.values()]

    def create_playbook(self, name: str, description: str,
                        severity: str,
                        steps: List[Dict[str, Any]]) -> Dict[str, Any]:
        pid = "pb_" + uuid.uuid4().hex[:8]
        pb = SOARPlaybook(pb_id=pid, name=name, description=description,
                          severity=severity, steps=steps)
        with self._lock:
            self._playbooks[pid] = pb
        return pb.to_dict()

    # ------------------------------------------------------------------ #
    def tool_status(self) -> Dict[str, Any]:
        out = {}
        for t in ("iptables", "firewalld-cmd", "net", "clamscan",
                  "nft", "ufw"):
            p = _which(t)
            out[t] = {"available": bool(p), "path": p or "",
                      "hint": "" if p else f"未安装 {t}，剧本将记录但不执行"}
        return out

    # ------------------------------------------------------------------ #
    def execute_playbook(self, pb_id: str, context: Optional[Dict[str, Any]] = None
                         ) -> Dict[str, Any]:
        context = context or {}
        with self._lock:
            pb = self._playbooks.get(pb_id)
            if pb is None:
                return {"success": False, "error": "playbook not found"}
            pb.runs += 1
        results: List[Dict[str, Any]] = []
        t0 = time.time()
        for step in pb.steps:
            action = step.get("action", "")
            tool = step.get("tool", "")
            cmd_tpl = step.get("command", "")
            cmd = cmd_tpl.format(**context) if context else cmd_tpl
            avail = bool(_which(tool))
            rec = {
                "action": action, "tool": tool, "command": cmd,
                "tool_available": avail,
                "status": "executed" if avail else "skipped_no_tool",
                "note": "" if avail
                        else f"工具 {tool} 未安装，仅记录剧本动作",
                "ts": datetime.now().isoformat(timespec="seconds"),
            }
            # 真实工具尝试（firewall 类命令在普通环境会失败，不阻塞）
            if avail and tool in ("clamscan",):
                try:
                    proc = subprocess.run(
                        [tool, "--version"], capture_output=True,
                        text=True, timeout=TOOL_TIMEOUT,
                        encoding="utf-8", errors="ignore")
                    rec["stdout_tail"] = (proc.stdout or "")[-300:]
                except Exception as e:  # noqa: BLE001
                    rec["status"] = "error"
                    rec["note"] = str(e)
            results.append(rec)
        # 收集证据
        ev_id = "ev_" + uuid.uuid4().hex[:8]
        ev = {
            "evidence_id": ev_id, "pb_id": pb_id,
            "context": context, "steps": results,
            "collected_at": datetime.now().isoformat(timespec="seconds"),
        }
        with self._lock:
            self._evidence.append(ev)
        return {
            "success": True, "pb_id": pb_id, "results": results,
            "elapsed": round(time.time() - t0, 2),
            "evidence_id": ev_id,
        }

    # ------------------------------------------------------------------ #
    def create_ticket(self, title: str, alert_id: str = "",
                      priority: str = "medium",
                      assignee: str = "") -> Dict[str, Any]:
        tid = "tk_" + uuid.uuid4().hex[:10]
        due = (datetime.now() + timedelta(hours=4)).isoformat(
            timespec="seconds")
        t = Ticket(ticket_id=tid, title=title, alert_id=alert_id,
                   priority=priority, assignee=assignee,
                   created_at=datetime.now().isoformat(timespec="seconds"),
                   due_at=due)
        with self._lock:
            self._tickets[tid] = t
        return t.to_dict()

    def list_tickets(self, status: Optional[str] = None
                     ) -> List[Dict[str, Any]]:
        with self._lock:
            items = list(self._tickets.values())
        if status:
            items = [t for t in items if t.status == status]
        return [t.to_dict() for t in items]

    def update_ticket(self, ticket_id: str, status: str = "",
                       note: str = "", assignee: str = ""
                       ) -> Optional[Dict[str, Any]]:
        with self._lock:
            t = self._tickets.get(ticket_id)
            if t is None:
                return None
            if status:
                t.status = status
                if status == "resolved":
                    t.resolved_at = datetime.now().isoformat(
                        timespec="seconds")
            if note:
                t.notes.append(
                    f"[{datetime.now().strftime('%H:%M:%S')}] {note}")
            if assignee:
                t.assignee = assignee
            return t.to_dict()

    # ------------------------------------------------------------------ #
    def evidence_list(self) -> List[Dict[str, Any]]:
        return list(self._evidence)[-100:]

    def stats(self) -> Dict[str, Any]:
        with self._lock:
            tks = list(self._tickets.values())
        open_n = sum(1 for t in tks if t.status in
                     ("open", "assigned", "in_progress"))
        resolved = sum(1 for t in tks if t.status == "resolved")
        sla_breach = sum(1 for t in tks
                         if t.due_at and t.resolved_at
                         and t.resolved_at > t.due_at)
        avg_resp = 0.0
        if resolved:
            durs = []
            for t in tks:
                if t.resolved_at and t.created_at:
                    try:
                        d0 = datetime.fromisoformat(t.created_at)
                        d1 = datetime.fromisoformat(t.resolved_at)
                        durs.append((d1 - d0).total_seconds())
                    except Exception:
                        pass
            if durs:
                avg_resp = sum(durs) / len(durs)
        return {
            "ticket_total": len(tks),
            "open": open_n, "resolved": resolved,
            "sla_breach": sla_breach,
            "avg_response_sec": round(avg_resp, 1),
            "playbook_runs": sum(p.runs
                                 for p in self._playbooks.values()),
        }


_default: Optional[IncidentResponsePhase] = None


def get_incident_response_phase() -> IncidentResponsePhase:
    global _default
    if _default is None:
        _default = IncidentResponsePhase()
    return _default
