# -*- coding: utf-8 -*-
"""
blue_response_phase.py — 蓝队阶段2：响应。

功能:
    - 应急响应流程（准备/识别/遏制/根除/恢复/总结）
    - 隔离（主机隔离/账户禁用/网络隔离）
    - 清除（恶意软件清除/后门清除/账户清理）
    - 恢复（系统恢复/服务恢复/数据恢复）
"""

from __future__ import annotations

import time
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional

IR_LIFECYCLE = [
    {"step": "准备", "goal": "应急预案/工具/联系清单就绪",
     "done": False},
    {"step": "识别", "goal": "确认事件真伪与影响范围",
     "done": False},
    {"step": "遏制", "goal": "隔离受影响主机/账户，防止扩散",
     "done": False},
    {"step": "根除", "goal": "清除恶意软件/后门/异常账户",
     "done": False},
    {"step": "恢复", "goal": "从干净备份恢复系统与数据",
     "done": False},
    {"step": "总结", "goal": "复盘报告与改进项",
     "done": False},
]


@dataclass
class ResponseResult:
    phase: str = ""
    actions: List[Dict[str, Any]] = field(default_factory=list)
    status: str = "pending"
    notes: str = ""

    def to_dict(self) -> Dict[str, Any]:
        return {"phase": self.phase, "action_count": len(self.actions),
                "actions": self.actions, "status": self.status,
                "notes": self.notes}


class BlueResponsePhase:
    """蓝队阶段2：响应。"""

    # ------------------------------------------------------------------ #
    def ir_lifecycle(self) -> List[Dict[str, Any]]:
        return [dict(x) for x in IR_LIFECYCLE]

    # ------------------------------------------------------------------ #
    def isolate_host(self, host: str = "192.168.1.100") -> ResponseResult:
        r = ResponseResult(phase="containment")
        r.actions = [
            {"name": "主机隔离", "cmd": f"iptables -A INPUT -s {host} "
             f"-j DROP  # 或交换机端口 shutdown", "auto": True},
            {"name": "账户禁用", "cmd": f"net user compromised /active:no",
             "auto": True},
            {"name": "网络隔离", "cmd": "在防火墙将该 IP 加入黑名单",
             "auto": False},
        ]
        r.status = "recommended"
        r.notes = f"建议立即隔离 {host}"
        return r

    def isolate_account(self, username: str = "compromised") -> ResponseResult:
        r = ResponseResult(phase="containment")
        r.actions = [
            {"name": "禁用账户",
             "cmd": f"net user {username} /active:no", "auto": True},
            {"name": "重置密码", "cmd": f"net user {username} NewP@ss!",
             "auto": True},
            {"name": "踢出会话", "cmd": f"query user | findstr {username}",
             "auto": False},
        ]
        r.status = "recommended"
        return r

    # ------------------------------------------------------------------ #
    def eradicate_malware(self) -> ResponseResult:
        r = ResponseResult(phase="eradication")
        r.actions = [
            {"name": "查杀恶意软件", "cmd": "杀毒软件全盘扫描",
             "auto": False},
            {"name": "清除后门", "cmd": "删除计划任务/启动项/服务",
             "auto": True},
            {"name": "清理异常账户", "cmd": "net user admin$ /delete",
             "auto": True},
        ]
        r.status = "recommended"
        return r

    # ------------------------------------------------------------------ #
    def recover_system(self) -> ResponseResult:
        r = ResponseResult(phase="recovery")
        r.actions = [
            {"name": "系统恢复", "cmd": "从干净镜像重装", "auto": False},
            {"name": "服务恢复", "cmd": "按基线启动业务服务",
             "auto": False},
            {"name": "数据恢复", "cmd": "从干净备份还原数据",
             "auto": False},
        ]
        r.status = "recommended"
        r.notes = "恢复前确认已根除，避免二次入侵"
        return r

    # ------------------------------------------------------------------ #
    def run_full(self, host: str = "") -> Dict[str, Any]:
        """一键应急响应流程建议。"""
        iso = self.isolate_host(host)
        era = self.eradicate_malware()
        rec = self.recover_system()
        return {
            "lifecycle": self.ir_lifecycle(),
            "isolate": iso.to_dict(),
            "eradicate": era.to_dict(),
            "recovery": rec.to_dict(),
            "ts": time.strftime("%Y-%m-%d %H:%M:%S"),
        }


_default: Optional[BlueResponsePhase] = None


def get_blue_response_phase() -> BlueResponsePhase:
    global _default
    if _default is None:
        _default = BlueResponsePhase()
    return _default
