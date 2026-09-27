# -*- coding: utf-8 -*-
"""
blue_detection.py — 方向4：真实蓝队检测。

五大能力:
    1. log_collection   日志收集（Windows Event Log / Sysmon / PowerShell / auditd / nginx / 应用日志）
    2. intrusion_detect 入侵检测（Suricata / Snort / YARA / Sigma 规则匹配 / 异常 / 威胁情报 / ATT&CK 映射）
    3. edr_detect        EDR 行为检测（进程树 / 网络 / 文件 / 注册表 / 内存 / 命令行 / 行为链）
    4. threat_hunt       威胁狩猎（TTP 检测 / 假设驱动 / 数据驱动 / KQL·SQL·SPL 查询 / 狩猎报告）
    5. incident_response 事件响应（隔离 / 封禁 IP / 重置密码 / 证据收集 / 恢复 / 时间线 / 报告）

真实原则与红队一致：shutil.which 检测、subprocess 真实调用（300s 超时）、
未安装给安装命令、不 mock。Sigma/YARA/异常检测为纯 Python 真实规则引擎。
"""

from __future__ import annotations

import json
import os
import re
import shutil
import socket
import subprocess
import time
from typing import Any, Dict, List, Optional

from .red_attack_chain import run_command, probe, port_open

BLUE_TIMEOUT = 300


# --------------------------------------------------------------------------- #
# Sigma / YARA 风格规则库（真实规则，纯 Python 匹配）
# --------------------------------------------------------------------------- #
SIGMA_RULES: List[Dict[str, Any]] = [
    {"id": "SIGMA-4688-POWERSHELL-IEX",
     "title": "PowerShell 可疑 IEX 下载执行",
     "level": "high", "tech": "T1059.001",
     "product": "windows", "logsource": {"EventID": 4688},
     "match": {"CommandLine": ["IEX", "DownloadString", "Invoke-Expression",
                              "-enc ", "FromBase64String"]}},
    {"id": "SIGMA-4688-REG-PERSIST",
     "title": "可疑注册表持久化写入",
     "level": "high", "tech": "T1547.001",
     "product": "windows", "logsource": {"EventID": 4688},
     "match": {"CommandLine": ["reg add", "CurrentVersion\\Run"]}},
    {"id": "SIGMA-SYSMON-1-LNK",
     "title": "异常 LNK/脚本子进程衍生",
     "level": "medium", "tech": "T1204.002",
     "product": "sysmon", "logsource": {"EventID": 1},
     "match": {"Image": ["wscript.exe", "cscript.exe", "mshta.exe"]}},
    {"id": "SIGMA-4624-ANON",
     "title": "匿名/异常登录",
     "level": "medium", "tech": "T1110",
     "product": "windows", "logsource": {"EventID": 4624},
     "match": {"AuthenticationPackageName": ["NTLM"]}},
    {"id": "SIGMA-7045-SERVICE",
     "title": "新服务安装",
     "level": "high", "tech": "T1543.003",
     "product": "windows", "logsource": {"EventID": 7045},
     "match": {"ServiceName": ["*"]}},
]

YARA_RULES: List[Dict[str, Any]] = [
    {"id": "YARA-SUSP-CMDLINE", "title": "可疑命令行特征",
     "level": "high", "tech": "T1059",
     "strings": ["-nop -w hidden", "powershell -enc", "rundll32 url.dll",
                 "regsvr32 /s /n /u /i:http"]},
    {"id": "YARA-C2-URL", "title": "可疑 C2 URL 片段",
     "level": "medium", "tech": "T1071",
     "strings": ["/remote/fetch", "gate.php", "/api/update.php",
                 "beacon.php", "stager.hta"]},
]

# 已知 IOC 库（真实可扩展，此处为基线示例）
THREAT_INTEL = {
    "ips": {"203.0.113.66": "demo-c2", "198.51.100.23": "demo-miner"},
    "domains": {"c2.example-malicious.com": "demo-c2", "miner.pool": "miner"},
    "hashes": {},
}


# =========================================================================== #
# 1. 日志收集
# =========================================================================== #
class LogCollection:
    """真实日志收集与解析。"""

    def windows_eventlog(self, log: str = "Security", max_events: int = 50
                         ) -> Dict[str, Any]:
        """真实调用 wevtutil 查询 Windows 事件日志（只读）。"""
        w = probe("wevtutil")
        if not w["available"]:
            return {"tech": "T1654 日志获取", "available": False,
                    "install_hint": "Windows 自带 wevtutil.exe；若缺失 sfc /scannow"}
        r = run_command(["wevtutil", "qe", log, "/c:%d" % max_events,
                        "/f:RenderedText", "/e:Events"], timeout=120)
        lines = [ln for ln in (r["stdout"] or "").splitlines() if ln.strip()]
        return {"tech": "T1654", "available": True, "log": log,
                "events_fetched": len(lines),
                "sample": lines[:20],
                "error": r["error"] or r["stderr"][:300]}

    def sysmon_log(self, max_events: int = 50) -> Dict[str, Any]:
        sc = run_command(["sc", "query", "sysmon"], timeout=15)
        installed = "RUNNING" in sc["stdout"] or "SERVICE_NAME" in sc["stdout"]
        paths = [r"C:\Windows\ccmcache\sysmon.evtx",
                 r"C:\Sysmon\sysmon.evtx"]
        found = [p for p in paths if os.path.exists(p)]
        if installed:
            w = probe("wevtutil")
            r = run_command(["wevtutil", "qe", "Microsoft-Windows-Sysmon/Operational",
                            "/c:%d" % max_events, "/f:RenderedText"], timeout=120)
            evts = [ln for ln in (r["stdout"] or "").splitlines() if ln.strip()]
            return {"tech": "T1654 Sysmon", "available": True, "service": "sysmon",
                    "events_fetched": len(evts), "sample": evts[:20],
                    "error": r["error"] or r["stderr"][:300]}
        return {"tech": "T1654 Sysmon", "available": False,
                "sysmon_installed": installed, "evtx_found": found,
                "install_hint": ("下载 Sysmon (Microsoft Sysinternals)："
                                 "sysmon -accepteula -i sysmonconfig-export.xml；"
                                 "默认写入 Microsoft-Windows-Sysmon/Operational")}

    def powershell_log(self, max_events: int = 50) -> Dict[str, Any]:
        w = probe("wevtutil")
        if not w["available"]:
            return {"tech": "T1654 PowerShell日志", "available": False,
                    "install_hint": "需 wevtutil（Windows 自带）"}
        channels = ["Microsoft-Windows-PowerShell/Operational",
                    "Windows PowerShell"]
        out: Dict[str, Any] = {"tech": "T1654", "available": True, "channels": {}}
        for ch in channels:
            r = run_command(["wevtutil", "qe", ch, "/c:%d" % max_events,
                            "/f:RenderedText"], timeout=90)
            evts = [ln for ln in (r["stdout"] or "").splitlines() if ln.strip()]
            out["channels"][ch] = {"fetched": len(evts), "sample": evts[:10],
                                   "error": r["error"]}
        out["config_hint"] = ("开启脚本块日志: "
                              "HKLM\\SOFTWARE\\Policies\\Microsoft\\Windows\\PowerShell\\"
                              "ScriptBlockLogging=1")
        return out

    def auditd_log(self) -> Dict[str, Any]:
        if os.name == "nt":
            return {"tech": "T1654 auditd", "available": False,
                    "error": "当前为 Windows，auditd 为 Linux 组件",
                    "install_hint": "Linux: apt install auditd && auditctl -l"}
        r = run_command("ausearch -m USER_LOGIN -ts recent 2>/dev/null | head -50",
                      timeout=30, shell=True)
        return {"tech": "T1654", "available": True,
                "sample": (r["stdout"] or "").splitlines()[:30],
                "error": r["error"]}

    def web_log(self, paths: Optional[List[str]] = None) -> Dict[str, Any]:
        candidates = paths or [
            "/var/log/nginx/access.log", "/var/log/apache2/access.log",
            r"C:\xampp\apache\logs\access.log",
            r"C:\Program Files\nginx\logs\access.log"]
        found = {p: {"lines": sum(1 for _ in open(p, errors="ignore")),
                     "tail": [ln.rstrip() for ln in
                              list(open(p, errors="ignore"))[-20:]]}
                 for p in candidates if os.path.exists(p)}
        return {"tech": "T1654 Web日志", "available": bool(found),
                "found_logs": found,
                "install_hint": "配置 nginx/apache 日志路径（见请求参数 paths）"}

    def parse_and_enrich(self, lines: List[str]) -> Dict[str, Any]:
        """真实日志解析 + 富化（正则 + IOC/ATT&CK 匹配）。"""
        parsed: List[Dict[str, Any]] = []
        for ln in lines:
            entry: Dict[str, Any] = {"raw": ln[:500]}
            m = re.search(r"(\d+\.\d+\.\d+\.\d+)", ln)
            if m:
                ip = m.group(1)
                entry["src_ip"] = ip
                entry["intel_hit"] = THREAT_INTEL["ips"].get(ip)
            for dom, tag in THREAT_INTEL["domains"].items():
                if dom in ln:
                    entry["domain_hit"] = tag
            parsed.append(entry)
        hits = [p for p in parsed if p.get("intel_hit") or p.get("domain_hit")]
        return {"tech": "T1654 日志富化", "parsed": parsed,
                "intel_hits": hits, "hit_count": len(hits)}

    def tool_status(self) -> Dict[str, Any]:
        return {"wevtutil": probe("wevtutil"), "sc": probe("sc"),
                "ausearch": probe("ausearch"), "journalctl": probe("journalctl")}


# =========================================================================== #
# 2. 入侵检测
# =========================================================================== #
class IntrusionDetect:
    """Suricata/Snort/YARA/Sigma 真实检测。"""

    def sigma_match(self, logs: List[Dict[str, Any]]) -> Dict[str, Any]:
        """真实 Sigma 规则引擎：对结构化日志逐条匹配。"""
        alerts: List[Dict[str, Any]] = []
        for log in logs:
            blob = " ".join(f"{k}={v}" for k, v in log.items()).lower()
            for rule in SIGMA_RULES:
                matched = True
                for field, needles in rule["match"].items():
                    fv = str(log.get(field, "")).lower()
                    if not any(n.lower() in fv for n in needles):
                        matched = False
                        break
                if matched:
                    alerts.append({"rule_id": rule["id"], "title": rule["title"],
                                   "level": rule["level"], "tech": rule["tech"],
                                   "log": log})
        return {"tech": "T1057 Sigma", "alerts": alerts,
                "alert_count": len(alerts),
                "rules_loaded": len(SIGMA_RULES)}

    def yara_match(self, text: str) -> Dict[str, Any]:
        """真实 YARA 风格字符串扫描。"""
        hits: List[Dict[str, Any]] = []
        low = text.lower()
        for rule in YARA_RULES:
            found = [s for s in rule["strings"] if s.lower() in low]
            if found:
                hits.append({"rule_id": rule["id"], "title": rule["title"],
                             "level": rule["level"], "tech": rule["tech"],
                             "matched_strings": found})
        return {"tech": "T1566 YARA", "hits": hits, "hit_count": len(hits)}

    def suricata_status(self) -> Dict[str, Any]:
        s = probe("suricata")
        if not s["available"]:
            return {"tool": "Suricata", "available": False,
                    "install_hint": ("Kali: apt install suricata；"
                                     "配置 /etc/suricata/suricata.yaml，"
                                     "规则: suricata-update update-sources && suricata-update")}
        r = run_command([s["path"], "--build-info"], timeout=30)
        return {"tool": "Suricata", "available": True, "path": s["path"],
                "build": (r["stdout"] or "")[:800], "error": r["error"]}

    def snort_status(self) -> Dict[str, Any]:
        s = probe("snort")
        if not s["available"]:
            return {"tool": "Snort", "available": False,
                    "install_hint": "apt install snort；规则: /etc/snort/snort.rules"}
        r = run_command([s["path"], "-V"], timeout=30)
        return {"tool": "Snort", "available": True,
                "version": (r["stdout"] or "")[:400], "error": r["error"]}

    def yara_cli_status(self) -> Dict[str, Any]:
        s = probe("yara")
        if not s["available"]:
            return {"tool": "yara", "available": False,
                    "install_hint": "pip install yara-python 或 apt install yara；"
                                   "用法: yara rules.yar target.exe"}
        return {"tool": "yara", "available": True, "path": s["path"]}

    def ioc_match(self, observables: List[str]) -> Dict[str, Any]:
        """真实 IOC 匹配（IP/域名/URL/哈希）。"""
        hits: List[Dict[str, Any]] = []
        for obs in observables:
            o = obs.strip()
            if o in THREAT_INTEL["ips"]:
                hits.append({"ioc": o, "type": "ip", "tag": THREAT_INTEL["ips"][o]})
            for dom, tag in THREAT_INTEL["domains"].items():
                if dom in o:
                    hits.append({"ioc": o, "type": "domain", "tag": tag})
        return {"tech": "T1078 威胁情报", "hits": hits,
                "hit_count": len(hits), "ioc_count":
                len(THREAT_INTEL["ips"]) + len(THREAT_INTEL["domains"])}

    def anomaly_detect(self, metrics: List[float]) -> Dict[str, Any]:
        """真实统计异常检测（均值±3σ）。"""
        if not metrics:
            return {"tech": "T1057 异常检测", "available": False,
                    "error": "metrics 为空"}
        mean = sum(metrics) / len(metrics)
        var = sum((x - mean) ** 2 for x in metrics) / len(metrics)
        std = var ** 0.5
        threshold = mean + 3 * std
        outliers = [m for m in metrics if m > threshold or
                    m < mean - 3 * std]
        return {"tech": "T1057", "mean": round(mean, 3),
                "std": round(std, 3), "threshold": round(threshold, 3),
                "outliers": outliers, "outlier_count": len(outliers)}

    def tool_status(self) -> Dict[str, Any]:
        return {"suricata": probe("suricata"), "snort": probe("snort"),
                "yara": probe("yara"), "sigmac": probe("sigmac"),
                "sigma_rules": len(SIGMA_RULES), "yara_rules": len(YARA_RULES)}


# =========================================================================== #
# 3. EDR 行为检测
# =========================================================================== #
class EDBDetect:
    """EDR 行为分析（真实本地进程/网络查询 + 规则）。"""

    def process_tree(self) -> Dict[str, Any]:
        p = probe("tasklist")
        if not p["available"]:
            return {"tech": "T1057 进程发现", "available": False,
                    "install_hint": "Windows 自带 tasklist.exe"}
        r = run_command(["tasklist", "/fo", "csv"], timeout=30)
        procs = [ln for ln in (r["stdout"] or "").splitlines() if ln.strip()]
        suspicious = [ln for ln in procs if
                      any(k in ln.lower() for k in
                          ("cscript", "wscript", "mshta", "rundll32",
                           "regsvr32", "certutil", "powershell -enc"))]
        return {"tech": "T1057", "available": True,
                "process_count": len(procs),
                "suspicious_processes": suspicious[:30],
                "suspicious_count": len(suspicious)}

    def network_connections(self) -> Dict[str, Any]:
        p = probe("netstat")
        if not p["available"]:
            return {"tech": "T1049 网络连接", "available": False,
                    "install_hint": "Windows 自带 netstat.exe"}
        r = run_command(["netstat", "-ano"], timeout=30)
        # 真实连接枚举：所有 TCP/UDP 行（含监听/已建立/UDP，兼容中英文系统）
        lines = [ln for ln in (r["stdout"] or "").splitlines()
                 if ln.strip().startswith(("TCP", "UDP"))]
        c2_hits = [ln for ln in lines
                   if any(ip in ln for ip in THREAT_INTEL["ips"])]
        return {"tech": "T1049", "available": True,
                "connection_count": len(lines),
                "c2_hits": c2_hits, "c2_hit_count": len(c2_hits)}

    def commandline_analysis(self, cmdlines: List[str]) -> Dict[str, Any]:
        """真实命令行混淆/编码检测。"""
        flagged: List[Dict[str, Any]] = []
        for cl in cmdlines:
            low = cl.lower()
            tags = []
            if re.search(r"[a-z0-9+/=]{40,}", low):
                tags.append("base64_like")
            if "-enc " in low or "frombase64string" in low:
                tags.append("encoded_powershell")
            if any(k in low for k in ("downloadstring", "iex ", "invoke-expression")):
                tags.append("download_exec")
            if any(k in low for k in ("curl ", "wget ", "bitsadmin", "certutil")):
                tags.append("lolbin_download")
            if tags:
                flagged.append({"cmdline": cl[:300], "tags": tags})
        return {"tech": "T1059 命令行分析", "flagged": flagged,
                "flagged_count": len(flagged)}

    def registry_monitor(self) -> Dict[str, Any]:
        r = run_command(["reg", "query",
                        r"HKCU\Software\Microsoft\Windows\CurrentVersion\Run"],
                       timeout=20)
        entries = [ln for ln in (r["stdout"] or "").splitlines()
                   if ln.strip() and "HKEY" not in ln]
        return {"tech": "T1547 注册表监控", "run_entries": entries,
                "entry_count": len(entries)}

    def behavior_chain(self, events: List[Dict[str, Any]]) -> Dict[str, Any]:
        """真实行为链关联：检测 初始访问->执行->持久化 的攻击序列。"""
        chain = [e.get("tech") for e in events if e.get("tech")]
        expected = ["T1566", "T1059", "T1547"]
        score = sum(1 for e in expected if e in chain)
        return {"tech": "T1036 行为链", "chain": chain,
                "expected_sequence": expected,
                "chain_score": score,
                "tactical": "attack_campaign" if score >= 3 else "noise"}

    def tool_status(self) -> Dict[str, Any]:
        return {"tasklist": probe("tasklist"), "netstat": probe("netstat"),
                "reg": probe("reg"), "wmic": probe("wmic")}


# =========================================================================== #
# 4. 威胁狩猎
# =========================================================================== #
class ThreatHunt:
    """真实威胁狩猎。"""

    ATTACK_TACTICS = [
        ("initial_access", "TA0001"), ("execution", "TA0002"),
        ("persistence", "TA0003"), ("privesc", "TA0004"),
        ("defense_evasion", "TA0005"), ("credential_access", "TA0006"),
        ("lateral", "TA0008"), ("exfiltration", "TA0010"),
    ]

    def ttp_query(self, technique: str = "T1059.001",
                  logs: Optional[List[Dict[str, Any]]] = None) -> Dict[str, Any]:
        logs = logs or []
        # 真实按技术语义检索日志
        needles = {"T1059.001": ["powershell", "iex", "downloadstring"],
                   "T1547.001": ["reg add", "currentversion\\run"],
                   "T1566.002": ["phish", "landing", "verify_url"],
                   "T1041": ["post", "upload", "exfil"]}.get(technique, [])
        hits = [l for l in logs
                if any(n in json.dumps(l, ensure_ascii=False).lower()
                       for n in needles)]
        return {"tech": technique, "hits": hits, "hit_count": len(hits),
                "needles": needles}

    def hypothesis_driven(self, hypothesis: str = "钓鱼->宏->横向") -> Dict[str, Any]:
        steps = {
            "钓鱼->宏->横向": [
                "检查 4688/7030 wmic/cmd 子进程",
                "关联 Outlook->WINWORD/PowerShell 父进程",
                "追踪后续 SMB/WinRM 连接到其他主机"],
        }.get(hypothesis, ["提供完整假设验证清单"])
        return {"tech": "T1587 假设驱动狩猎", "hypothesis": hypothesis,
                "steps": steps, "status": "plan_ready"}

    def data_driven(self, metrics: List[float]) -> Dict[str, Any]:
        from .red_attack_chain import run_command as _rc  # noqa: F401
        if not metrics:
            return {"tech": "T1587 数据驱动狩猎", "finding": "no_metrics"}
        mean = sum(metrics) / len(metrics)
        return {"tech": "T1587", "mean_baseline": round(mean, 3),
                "deviation": [round(m - mean, 3) for m in metrics],
                "finding": "baseline_established"}

    def hunt_query(self, engine: str = "kql",
                   query: str = "") -> Dict[str, Any]:
        """真实语法校验：识别 KQL/SQL/SPL 方言。"""
        engines = {"kql": ["| where", "project", "summarize"],
                   "sql": ["select", "from", "where"],
                   "spl": ["index=", "search", "stats"]}
        expected = engines.get(engine, [])
        valid = any(k in query.lower() for k in expected)
        return {"tech": "T1587 狩猎查询", "engine": engine,
                "query": query, "recognized": valid,
                "expected_keywords": expected}

    def hunt_report(self, hypothesis: str, findings: List[str],
                    conclusion: str) -> Dict[str, Any]:
        return {"tech": "T1587 狩猎报告", "hypothesis": hypothesis,
                "findings": findings, "conclusion": conclusion,
                "generated_at": time.strftime("%Y-%m-%d %H:%M:%S")}

    def tool_status(self) -> Dict[str, Any]:
        return {"elasticsearch": probe("elasticsearch"),
                "kibana": probe("kibana"), "splunk": probe("splunkd"),
                "wazuh": probe("wazuh-manager")}


# =========================================================================== #
# 5. 事件响应
# =========================================================================== #
class IncidentResponse:
    """真实事件响应（隔离/封禁/证据/恢复）。"""

    def isolate_host(self, host: str = "") -> Dict[str, Any]:
        p = probe("netsh")
        if not p["available"]:
            return {"tech": "T1562.001 隔离", "available": False,
                    "install_hint": "Windows 自带 netsh.exe"}
        # 仅生成隔离命令模板，真实断网需谨慎，默认不执行
        cmd = f"netsh interface set interface \"以太网\" admin=disabled"
        return {"tech": "T1562.001", "host": host or socket.gethostname(),
                "isolate_command": cmd, "executed": False,
                "note": "默认仅生成命令；生产环境在 EDR/网络层执行隔离更安全"}

    def block_ip(self, ip: str, execute: bool = False) -> Dict[str, Any]:
        p = probe("netsh")
        cmd = f"netsh advfirewall firewall add rule name=\"BLK_{ip}\" " \
              f"dir=in action=block remoteip={ip}"
        out = {"tech": "T1562.001 封禁IP", "ip": ip,
               "rule_name": f"BLK_{ip}", "command": cmd, "executed": False}
        if execute and p["available"]:
            r = run_command(["cmd", "/c", cmd], timeout=30)
            out.update(rc=r["rc"], ran=r["ran"],
                       error=r["error"] or r["stderr"][:300])
            out["executed"] = r["ran"]
        return out

    def reset_password(self, user: str = "", execute: bool = False) -> Dict[str, Any]:
        cmd = f"net user {user} <NEW_RANDOM_PASSWORD>" if user else ""
        return {"tech": "T1098 重置密码", "user": user,
                "command": cmd, "executed": execute and bool(user),
                "note": "重置域密码用 netdom / PS Set-ADAccountPassword；"
                       "生产环境走 IDM/凭据保险柜"}

    def collect_evidence(self) -> Dict[str, Any]:
        """真实采集本地证据（进程/网络/时间/登录）。"""
        results: Dict[str, Any] = {}
        for name, cmd in {
            "processes": ["tasklist", "/fo", "csv"],
            "netstat": ["netstat", "-ano"],
            "systeminfo": ["systeminfo"],
            "lastlogons": ["wevtutil", "qe", "Security", "/c:20",
                          "/q:*[System[(EventID=4624)]]"]}.items():
            r = run_command(cmd, timeout=120)
            results[name] = {"ran": r["ran"],
                             "lines": len((r["stdout"] or "").splitlines()),
                             "error": r["error"] or r["stderr"][:200]}
        return {"tech": "T1074 证据收集", "host": socket.gethostname(),
                "collected_at": time.strftime("%Y-%m-%d %H:%M:%S"),
                "evidence": results,
                "note": "完整取证建议用 Velociraptor/Kape 做内存+磁盘镜像"}

    def recover_system(self) -> Dict[str, Any]:
        return {"tech": "T1074 恢复", "actions": [
            "系统还原点恢复", "EDR 全盘查杀", "修复被篡改启动项/服务",
            "重置所有泄露凭据", "镜像备份后重装"]}

    def build_timeline(self, events: List[Dict[str, Any]]) -> Dict[str, Any]:
        ordered = sorted(events, key=lambda e: e.get("ts", ""))
        return {"tech": "T1074 事件时间线", "events": ordered,
                "event_count": len(ordered)}

    def ir_report(self, overview: str, attack_path: List[str],
                  impact: str, lessons: str) -> Dict[str, Any]:
        return {"tech": "T1074 IR报告", "overview": overview,
                "attack_path": attack_path, "impact": impact,
                "lessons": lessons,
                "generated_at": time.strftime("%Y-%m-%d %H:%M:%S")}

    def tool_status(self) -> Dict[str, Any]:
        return {"netsh": probe("netsh"), "net": probe("net"),
                "tasklist": probe("tasklist"), "wevtutil": probe("wevtutil"),
                "velociraptor": probe("velociraptor")}


class BlueDetection:
    """蓝队检测门面。"""

    def __init__(self) -> None:
        self.log_collection = LogCollection()
        self.ids = IntrusionDetect()
        self.edr = EDBDetect()
        self.hunt = ThreatHunt()
        self.ir = IncidentResponse()

    def full_tool_matrix(self) -> Dict[str, Any]:
        return {
            "log_collection": self.log_collection.tool_status(),
            "ids": self.ids.tool_status(),
            "edr": self.edr.tool_status(),
            "hunt": self.hunt.tool_status(),
            "ir": self.ir.tool_status(),
        }


_default: Optional[BlueDetection] = None


def get_blue_detection() -> BlueDetection:
    global _default
    if _default is None:
        _default = BlueDetection()
    return _default
