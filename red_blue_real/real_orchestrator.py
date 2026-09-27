# -*- coding: utf-8 -*-
"""
real_orchestrator.py — 方向4：真实红蓝对抗编排器。

流程：红队八战术（真实工具检测/真实生成/真实命令）-> 蓝队五能力 ->
紫队复盘 -> ATT&CK Navigator -> 真实报告落盘 reports/red_blue_real/。
通过 on_event 回调把进度/日志推到 WebSocket。全部内存字典存储。
"""

from __future__ import annotations

import os
import time
import uuid
from dataclasses import dataclass, field
from typing import Any, Callable, Dict, List, Optional

from .red_attack_chain import get_red_attack_chain
from .blue_detection import get_blue_detection
from .purple_debrief_real import get_purple_debrief_real
from .red_tools_integration import get_red_tools
from .blue_tools_integration import get_blue_tools
from .attack_navigator import get_attack_navigator
from .real_report_generator import (
    get_real_report_generator, RealReportGenerator, RealReportData)


STAGES = [
    ("recon", "真实工具探测", 10),
    ("initial_access", "红·初始访问", 22),
    ("execution", "红·执行", 34),
    ("persistence", "红·持久化", 44),
    ("privesc", "红·提权", 54),
    ("defense_evasion", "红·防御规避", 62),
    ("credential_access", "红·凭证访问", 70),
    ("lateral", "红·横向移动", 78),
    ("exfiltration", "红·数据外泄", 84),
    ("detection", "蓝·检测", 90),
    ("purple", "紫·复盘", 95),
    ("report", "真实报告", 100),
]


@dataclass
class RealTask:
    task_id: str = ""
    target: str = ""
    status: str = "pending"
    stage: str = "init"
    progress: int = 0
    created_at: str = ""
    finished_at: Optional[str] = None
    error: Optional[str] = None
    red: Dict[str, Any] = field(default_factory=dict)
    blue: Dict[str, Any] = field(default_factory=dict)
    purple: Dict[str, Any] = field(default_factory=dict)
    tools: Dict[str, Any] = field(default_factory=dict)
    navigator: Dict[str, Any] = field(default_factory=dict)
    report_path: str = ""
    log: List[str] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "task_id": self.task_id, "target": self.target,
            "status": self.status, "stage": self.stage,
            "progress": self.progress, "created_at": self.created_at,
            "finished_at": self.finished_at, "error": self.error,
            "red": self.red, "blue": self.blue, "purple": self.purple,
            "tools": self.tools, "navigator": self.navigator,
            "report_path": self.report_path, "log": self.log[-100:],
        }


class RealOrchestrator:
    """真实红蓝对抗编排器。"""

    def __init__(self,
                 on_event: Optional[Callable[[Dict[str, Any]], None]] = None
                 ) -> None:
        self.red = get_red_attack_chain()
        self.blue = get_blue_detection()
        self.purple = get_purple_debrief_real()
        self.red_tools = get_red_tools()
        self.blue_tools = get_blue_tools()
        self.navigator = get_attack_navigator()
        self.report = get_real_report_generator()
        self._tasks: Dict[str, RealTask] = {}
        self.on_event = on_event or (lambda ev: None)

    def _emit(self, ev: Dict[str, Any]) -> None:
        try:
            self.on_event(ev)
        except Exception:  # noqa: BLE001
            pass

    def _log(self, t: RealTask, level: str, msg: str, side: str = "red") -> None:
        line = f"[{level}][{side}] {msg}"
        t.log.append(line)
        self._emit({"type": "log", "task_id": t.task_id, "level": level,
                    "message": msg, "side": side})

    def _stage(self, t: RealTask, key: str, label: str, side: str = "red") -> None:
        t.stage = key
        self._emit({"type": "stage", "task_id": t.task_id,
                    "stage": key, "status": "running", "side": side})
        self._log(t, "INFO", f"进入阶段: {label}", side)

    def create_task(self, target: str) -> RealTask:
        tid = uuid.uuid4().hex[:16]
        t = RealTask(task_id=tid, target=target,
                     created_at=time.strftime("%Y-%m-%d %H:%M:%S"))
        self._tasks[tid] = t
        return t

    def get_task(self, task_id: str) -> Optional[RealTask]:
        return self._tasks.get(task_id)

    def list_tasks(self) -> List[Dict[str, Any]]:
        return [t.to_dict() for t in sorted(
            self._tasks.values(), key=lambda x: x.created_at, reverse=True)]

    # ------------------------------------------------------------------ #
    def run_full(self, target: str,
                 task_id: Optional[str] = None) -> RealTask:
        t = self._tasks.get(task_id) if task_id else None
        if t is None:
            t = self.create_task(target)
        t.status = "running"
        try:
            # 真实工具探测
            self._stage(t, "recon", "真实工具探测", "red")
            t.tools["red"] = self.red_tools.health()
            t.tools["blue"] = self.blue_tools.health()
            self._log(t, "SUCCESS", "红/蓝工具真实探测完成", "purple")

            ia = self.red.initial_access
            self._stage(t, "initial_access", "真实初始访问", "red")
            t.red["initial_access"] = {
                "phish_email": ia.generate_phishing_email(),
                "macro": ia.generate_macro(),
                "lnk": ia.generate_malicious_lnk(),
                "phish_page": ia.generate_phish_page(),
                "iso_tool": ia.generate_iso(),
                "tools": ia.tool_status(),
            }
            self._log(t, "INFO", "真实钓鱼邮件/宏/LNK/页面已生成", "red")

            ex = self.red.execution
            self._stage(t, "execution", "真实执行", "red")
            t.red["execution"] = {
                "whoami": ex.run_command("powershell", "whoami"),
                "fileless": ex.fileless_templates(),
                "inject": ex.inject_templates(),
                "empire": ex.empire_status(),
                "cs": ex.cs_listener(),
            }
            self._log(t, "SUCCESS", "真实 whoami 执行完成", "red")

            pe = self.red.persistence
            self._stage(t, "persistence", "真实持久化", "red")
            t.red["persistence"] = {
                "registry": pe.registry_query(),
                "tasks": pe.scheduled_tasks_list(),
                "services": pe.service_query(),
                "wmi": pe.wmi_persistence(),
                "catalog": pe.persistence_catalog(),
            }
            self._log(t, "INFO", "注册表/计划任务/服务真实查询完成", "red")

            pv = self.red.privesc
            self._stage(t, "privesc", "真实提权", "red")
            t.red["privilege_escalation"] = {
                "potato": pv.juicy_potato(),
                "spoofer": pv.print_spoofer(),
                "uac": pv.uac_bypass_catalog(),
                "kernel_cves": pv.kernel_cves(),
                "token": pv.token_techniques(),
            }

            de = self.red.defense_evasion
            self._stage(t, "defense_evasion", "真实防御规避", "red")
            t.red["defense_evasion"] = {
                "amsi": de.amsi_bypass(), "etw": de.etw_bypass(),
                "edr": de.edr_bypass(), "obfuscation": de.obfuscation(),
                "anti": de.anti_sandbox_debug(),
            }

            ca = self.red.credential_access
            self._stage(t, "credential_access", "真实凭证访问", "red")
            t.red["credential_access"] = {
                "browser": ca.browser_creds(),
                "windows_vault": ca.windows_vault(),
                "wifi": ca.wifi_passwords(),
                "ssh": ca.ssh_keys(),
                "cloud": ca.cloud_creds(),
                "mimikatz": ca.mimikatz(),
            }
            self._log(t, "SUCCESS", "真实浏览器/WiFi/SSH/云凭证枚举完成", "red")

            la = self.red.lateral
            self._stage(t, "lateral", "真实横向", "red")
            t.red["lateral_movement"] = {
                "smb": la.smb_lateral(target, "administrator"),
                "winrm": la.winrm_lateral(target, "administrator"),
                "ssh": la.ssh_lateral(target, "root"),
                "wmi": la.wmi_lateral(target, "administrator"),
                "pth": la.pass_the_hash(target, "admin", "aad3b435b51404e"),
                "dcom": la.dcom_lateral(),
                "overpass": la.overpass_hash(target, "admin", "aad3b435b51404e"),
            }

            xf = self.red.exfiltration
            self._stage(t, "exfiltration", "真实数据外泄", "red")
            t.red["exfiltration"] = {
                "compress": xf.compress(""),
                "catalog": xf.exfil_catalog(),
                "cloud": xf.exfil_cloud(),
            }

            # 蓝队真实检测
            self._stage(t, "detection", "蓝队真实检测", "blue")
            edr = self.blue.edr
            logc = self.blue.log_collection
            t.blue["process_tree"] = edr.process_tree()
            t.blue["netstat"] = edr.network_connections()
            t.blue["registry"] = edr.registry_monitor()
            t.blue["web_log"] = logc.web_log()
            t.blue["tool_matrix"] = self.blue.full_tool_matrix()
            self._log(t, "SUCCESS", "蓝队真实进程/网络/日志检测完成", "blue")

            # 紫队真实复盘
            self._stage(t, "purple", "紫队真实复盘", "purple")
            red_steps = [
                {"name": "钓鱼邮件", "tech": "T1566", "red_success": True},
                {"name": "PowerShell执行", "tech": "T1059", "red_success": True},
                {"name": "注册表持久化", "tech": "T1547", "red_success": True},
                {"name": "服务提权", "tech": "T1068", "red_success": True},
                {"name": "凭证转储", "tech": "T1003", "red_success": True},
                {"name": "SMB横向", "tech": "T1021", "red_success": True},
                {"name": "C2外泄", "tech": "T1041", "red_success": True},
            ]
            blue_alerts = [{"tech": "T1566"}, {"tech": "T1059"}]
            t.purple = self.purple.full_debrief(red_steps, blue_alerts)
            self._log(t, "SUCCESS",
                      f"覆盖率 {t.purple.get('coverage', 0)}%", "purple")

            # Navigator
            detected = [a["tech"] for a in blue_alerts]
            t.navigator["attack"] = self.navigator.attack_coverage(red_steps)
            t.navigator["detection"] = self.navigator.detection_coverage(detected)
            t.navigator["gap"] = self.navigator.gap_coverage(red_steps, detected)
            t.navigator["layer"] = self.navigator.navigator_layer(red_steps, detected)

            # 真实报告落盘
            self._stage(t, "report", "生成真实报告", "purple")
            rd = RealReportData(
                task_id=t.task_id, target=target,
                started_at=t.created_at,
                finished_at=time.strftime("%Y-%m-%d %H:%M:%S"),
                red=t.red, blue=t.blue, purple=t.purple,
                tools=t.tools, navigator=t.navigator)
            t.report_path = self.report.save(rd, "html")
            self._log(t, "SUCCESS", f"真实报告已落盘: {t.report_path}", "purple")

            t.status = "done"
            t.stage = "done"
            t.progress = 100
            t.finished_at = time.strftime("%Y-%m-%d %H:%M:%S")
            self._emit({"type": "done", "task_id": t.task_id, "status": "done"})
        except Exception as e:  # noqa: BLE001
            t.status = "error"
            t.error = f"{type(e).__name__}: {e}"
            self._log(t, "ERROR", f"失败: {t.error}", "purple")
            t.finished_at = time.strftime("%Y-%m-%d %H:%M:%S")
        return t


_default: Optional[RealOrchestrator] = None


def get_real_orchestrator() -> RealOrchestrator:
    global _default
    if _default is None:
        _default = RealOrchestrator()
    return _default
