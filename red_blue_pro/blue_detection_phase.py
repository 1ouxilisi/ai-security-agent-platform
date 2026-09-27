# -*- coding: utf-8 -*-
"""
blue_detection_phase.py — 蓝队阶段1：检测。

功能:
    - 入侵检测规则（Suricata/Snort 规则模板）
    - 日志分析（Windows 事件日志 / Linux syslog / 网络流量）
    - 异常行为检测（登录异常 / 进程异常 / 网络异常）
    - 威胁情报匹配（IOC 匹配）
"""

from __future__ import annotations

import time
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional


SURICATA_RULES = [
    {"id": "SID1000001", "msg": "SMB 横向移动 (psexec)",
     "rule": "alert smb any any -> any 445 (msg:\"SMB Exec\"; "
             "flow:established; content:\"|00 00 00|\"; sid:1000001;)",
     "severity": "high"},
    {"id": "SID1000002", "msg": "可疑 WinRM 远程执行",
     "rule": "alert tcp any any -> any 5985 (msg:\"WinRM Remote\"; "
             "sid:1000002;)", "severity": "medium"},
    {"id": "SID1000003", "msg": "Mimikatz 特征",
     "rule": "alert tcp any any -> any any (msg:\"Mimikatz\"; "
             "content:\"sekurlsa\"; sid:1000003;)",
     "severity": "critical"},
    {"id": "SID1000004", "msg": "反向 Shell (bash /dev/tcp)",
     "rule": "alert tcp any any -> any any (msg:\"Reverse Shell\"; "
             "content:\"/dev/tcp/\"; sid:1000004;)",
     "severity": "critical"},
]

IOC_LIST = [
    {"type": "ip", "value": "45.155.205.10", "source": "abuse.ch",
     "note": "Cobalt Strike C2"},
    {"type": "domain", "value": "update-ms[.]xyz", "source": "MISP",
     "note": "钓鱼域名"},
    {"type": "hash", "value": "a1b2c3d4e5f6...", "source": "VT",
     "note": "Emotet 样本"},
]


@dataclass
class DetectionResult:
    module: str = ""
    target: str = ""
    alerts: List[Dict[str, Any]] = field(default_factory=list)
    matched_iocs: List[Dict[str, Any]] = field(default_factory=list)
    summary: Dict[str, Any] = field(default_factory=dict)
    error: str = ""

    def to_dict(self) -> Dict[str, Any]:
        return {
            "module": self.module, "target": self.target,
            "alert_count": len(self.alerts),
            "alerts": self.alerts[:50],
            "matched_iocs": self.matched_iocs,
            "ioc_hit_count": len(self.matched_iocs),
            "summary": self.summary, "error": self.error,
        }


class BlueDetectionPhase:
    """蓝队阶段1：检测。"""

    # ------------------------------------------------------------------ #
    def suricata_rules(self) -> Dict[str, Any]:
        return {"rules": SURICATA_RULES, "count": len(SURICATA_RULES)}

    # ------------------------------------------------------------------ #
    def analyze_windows_log(self, event_id: int = 4688,
                            sample: Optional[List[str]] = None
                            ) -> DetectionResult:
        """Windows 事件日志异常分析（4688 进程创建 / 4624 登录）。"""
        r = DetectionResult(module="windows_log", target=f"EventID={event_id}")
        sample = sample or [
            "powershell -nop -enc ...",
            "cmd.exe /c net user",
            "rundll32.exe javascript:",
        ]
        susp_patterns = ["powershell -nop", "net user", "rundll32",
                         "certutil", "bitsadmin", "mshta"]
        for line in sample:
            for pat in susp_patterns:
                if pat in line.lower():
                    r.alerts.append({
                        "severity": "high",
                        "pattern": pat,
                        "evidence": line,
                        "hint": "可疑进程命令行",
                    })
                    break
        r.summary = {"scanned": len(sample), "alerted": len(r.alerts)}
        return r

    def analyze_syslog(self, lines: Optional[List[str]] = None
                       ) -> DetectionResult:
        r = DetectionResult(module="syslog")
        lines = lines or [
            "sshd[1001]: Failed password for root from 1.2.3.4 port 22",
            "sudo: badpass : 1 failure ; user=root",
        ]
        for line in lines:
            if "Failed password" in line:
                r.alerts.append({"severity": "medium",
                                 "pattern": "brute_force",
                                 "evidence": line,
                                 "hint": "SSH 暴力破解迹象"})
        r.summary = {"scanned": len(lines), "alerted": len(r.alerts)}
        return r

    # ------------------------------------------------------------------ #
    def anomaly_login(self, logins: Optional[List[Dict[str, Any]]] = None
                      ) -> DetectionResult:
        """登录异常：非常用 IP / 非常用时间 / 爆破。"""
        r = DetectionResult(module="anomaly_login")
        logins = logins or [
            {"user": "admin", "ip": "203.0.113.99", "time": "03:14",
             "success": True},
            {"user": "admin", "ip": "192.168.1.10", "time": "10:00",
             "success": True},
        ]
        for lg in logins:
            if lg.get("time", "") < "06:00" and lg.get("success"):
                r.alerts.append({"severity": "medium",
                                 "pattern": "off_hours_login",
                                 "evidence": str(lg),
                                 "hint": "非工作时间登录"})
            if not lg.get("ip", "").startswith("192.168.") and \
                    not lg.get("ip", "").startswith("10."):
                r.alerts.append({"severity": "high",
                                 "pattern": "external_login",
                                 "evidence": str(lg),
                                 "hint": "外部 IP 登录"})
        r.summary = {"scanned": len(logins), "alerted": len(r.alerts)}
        return r

    def anomaly_process(self, procs: Optional[List[str]] = None
                       ) -> DetectionResult:
        r = DetectionResult(module="anomaly_process")
        procs = procs or ["c:\\windows\\temp\\unknown.exe",
                          "powershell -enc"]
        susp = ["temp", "appdata", "-enc", "bitsadmin", "certutil"]
        for p in procs:
            for s in susp:
                if s in p.lower():
                    r.alerts.append({"severity": "high",
                                     "pattern": "suspicious_process",
                                     "evidence": p,
                                     "hint": "可疑进程路径/命令行"})
                    break
        r.summary = {"scanned": len(procs), "alerted": len(r.alerts)}
        return r

    # ------------------------------------------------------------------ #
    def ioc_match(self, observables: Optional[List[str]] = None
                 ) -> DetectionResult:
        r = DetectionResult(module="ioc_match")
        observables = observables or ["45.155.205.10",
                                      "update-ms.xyz", "normal.com"]
        for obs in observables:
            for ioc in IOC_LIST:
                if ioc["type"] in ("ip", "domain") and \
                        ioc["value"].replace("[.]", ".") in obs:
                    r.matched_iocs.append(ioc)
        r.summary = {"scanned": len(observables),
                     "hits": len(r.matched_iocs)}
        return r

    # ------------------------------------------------------------------ #
    def tool_status(self) -> Dict[str, Any]:
        return {
            "suricata_rules": len(SURICATA_RULES),
            "ioc_count": len(IOC_LIST),
            "analyzers": ["windows_log", "syslog", "login", "process",
                          "ioc"],
            "ts": time.strftime("%Y-%m-%d %H:%M:%S"),
        }


_default: Optional[BlueDetectionPhase] = None


def get_blue_detection_phase() -> BlueDetectionPhase:
    global _default
    if _default is None:
        _default = BlueDetectionPhase()
    return _default
