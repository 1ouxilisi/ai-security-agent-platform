# -*- coding: utf-8 -*-
"""
red_privesc_phase.py — 红队阶段4：权限提升。

功能:
    - 提权漏洞检测（CVE 指纹，Win/Linux）
    - 系统配置审计（SUID / sudo / 服务配置 / 注册表）
    - Windows 提权检测
    - Linux 提权检测
"""

from __future__ import annotations

import time
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional

WIN_PRIVESC_CVES = [
    {"cve": "CVE-2021-40449", "name": "Win32k 本地提权",
     "severity": "high", "affected": "Win7/10",
     "fix": "安装 2021-10 月度安全更新"},
    {"cve": "CVE-2021-1732", "name": "Win32k 窗口提权",
     "severity": "high", "affected": "Win10/Server2019",
     "fix": "安装 2021-02 更新"},
    {"cve": "CVE-2020-0787", "name": "Background Intelligent Transfer",
     "severity": "critical", "affected": "Win7-10/2008-2019",
     "fix": "安装 2020-03 更新"},
    {"cve": "CVE-2019-1388", "name": "UAC 绕过 (hhupd)",
     "severity": "high", "affected": "Win7/10",
     "fix": "安装 2019-11 更新"},
]

LINUX_PRIVESC_CVES = [
    {"cve": "CVE-2021-4034", "name": "PwnKit (pkexec)",
     "severity": "critical", "affected": "Polkit <=0.120",
     "fix": "升级 polkit"},
    {"cve": "CVE-2022-0847", "name": "Dirty Pipe",
     "severity": "critical", "affected": "Kernel 5.8-5.16.11",
     "fix": "升级内核"},
    {"cve": "CVE-2021-4034", "name": "PwnKit 重复",
     "severity": "critical", "affected": "Polkit",
     "fix": "升级 polkit"},
    {"cve": "CVE-2016-5195", "name": "Dirty Cow",
     "severity": "high", "affected": "Kernel <=4.8.3",
     "fix": "升级内核"},
]

LINUX_CONFIG_RULES = [
    {"id": "SUID", "name": "SUID 二进制", "cmd": "find / -perm -4000 2>/dev/null",
     "severity": "high", "note": "SUID 程序可能被滥用提权"},
    {"id": "SUDO", "name": "sudo NOPASSWD", "cmd": "sudo -l",
     "severity": "critical", "note": "NOPASSWD 可直接提权"},
    {"id": "WEAK_SERVICE", "name": "不安全服务权限",
     "cmd": "find /etc/systemd -writable", "severity": "high",
     "note": "可写服务文件可劫持 root"},
    {"id": "CRON", "name": "可写 cron 任务", "cmd": "ls -la /etc/cron*",
     "severity": "medium", "note": "可写 cron 可定时执行"},
]

WIN_CONFIG_RULES = [
    {"id": "UNQUOTED", "name": "未引号服务路径",
     "cmd": "wmic service get name,pathname|findstr /i \" \"",
     "severity": "high", "note": "未引号路径可劫持"},
    {"id": "SERVICE_PERM", "name": "可写服务二进制",
     "cmd": "accesschk /accepteula -uwcqv",
     "severity": "critical", "note": "可替换服务二进制"},
    {"id": "AUTOLOGON", "name": "自动登录明文密码",
     "cmd": "reg query \"HKLM\\SOFTWARE\\Microsoft\\Windows NT\\"
            "CurrentVersion\\Winlogon\" /v DefaultPassword",
     "severity": "high", "note": "明文密码泄露"},
    {"id": "ALWAYS_INSTALL", "name": "AlwaysInstallElevated",
     "cmd": "reg query HKCU\\SOFTWARE\\Policies\\Microsoft\\Windows\\Installer",
     "severity": "critical", "note": "MSI 以 SYSTEM 安装"},
]


@dataclass
class PrivescFinding:
    cve: str = ""
    name: str = ""
    severity: str = "medium"
    evidence: str = ""
    os: str = "windows"
    recommendation: str = ""

    def to_dict(self) -> Dict[str, Any]:
        return {"cve": self.cve, "name": self.name,
                "severity": self.severity, "evidence": self.evidence,
                "os": self.os, "recommendation": self.recommendation}


@dataclass
class PrivescResult:
    os_type: str = "windows"
    findings: List[PrivescFinding] = field(default_factory=list)
    config_audit: List[Dict[str, Any]] = field(default_factory=list)
    error: str = ""

    def to_dict(self) -> Dict[str, Any]:
        return {
            "os_type": self.os_type,
            "findings": [f.to_dict() for f in self.findings],
            "finding_count": len(self.findings),
            "config_audit": self.config_audit,
            "error": self.error,
        }


class RedPrivescPhase:
    """红队阶段4：权限提升。"""

    # ------------------------------------------------------------------ #
    def windows_audit(self) -> PrivescResult:
        r = PrivescResult(os_type="windows")
        r.config_audit = [dict(x) for x in WIN_CONFIG_RULES]
        # CVE 指纹库（框架性输出，不实际打补丁检测）
        for cve in WIN_PRIVESC_CVES:
            r.findings.append(PrivescFinding(
                cve=cve["cve"], name=cve["name"],
                severity=cve["severity"],
                evidence=f"影响版本: {cve['affected']}",
                os="windows", recommendation=cve["fix"]))
        return r

    def linux_audit(self) -> PrivescResult:
        r = PrivescResult(os_type="linux")
        r.config_audit = [dict(x) for x in LINUX_CONFIG_RULES]
        for cve in LINUX_PRIVESC_CVES:
            r.findings.append(PrivescFinding(
                cve=cve["cve"], name=cve["name"],
                severity=cve["severity"],
                evidence=f"影响: {cve['affected']}",
                os="linux", recommendation=cve["fix"]))
        return r

    # ------------------------------------------------------------------ #
    def cve_fingerprint(self, os_string: str,
                        kernel: str = "") -> PrivescResult:
        """按 OS/内核字符串匹配提权 CVE。"""
        r = PrivescResult()
        o = (os_string + " " + kernel).lower()
        if "linux" in o:
            r.os_type = "linux"
            for cve in LINUX_PRIVESC_CVES:
                r.findings.append(PrivescFinding(
                    cve=cve["cve"], name=cve["name"],
                    severity=cve["severity"],
                    evidence=f"指纹: {os_string}",
                    os="linux", recommendation=cve["fix"]))
        else:
            r.os_type = "windows"
            for cve in WIN_PRIVESC_CVES:
                r.findings.append(PrivescFinding(
                    cve=cve["cve"], name=cve["name"],
                    severity=cve["severity"],
                    evidence=f"指纹: {os_string}",
                    os="windows", recommendation=cve["fix"]))
        return r

    # ------------------------------------------------------------------ #
    def audit(self) -> PrivescResult:
        """一键审计（Win+Linux 合并输出，供报告）。"""
        win = self.windows_audit()
        lin = self.linux_audit()
        merged = PrivescResult(os_type="mixed")
        merged.findings = win.findings + lin.findings
        merged.config_audit = win.config_audit + lin.config_audit
        return merged

    # ------------------------------------------------------------------ #
    def tool_status(self) -> Dict[str, Any]:
        return {
            "win_privesc_cves": len(WIN_PRIVESC_CVES),
            "linux_privesc_cves": len(LINUX_PRIVESC_CVES),
            "linux_config_rules": len(LINUX_CONFIG_RULES),
            "win_config_rules": len(WIN_CONFIG_RULES),
            "suggest_tools": ["winPEAS", "linuxPEAS", "PowerUp",
                             "LinPEAS", "Seatbelt"],
        }


_default: Optional[RedPrivescPhase] = None


def get_red_privesc_phase() -> RedPrivescPhase:
    global _default
    if _default is None:
        _default = RedPrivescPhase()
    return _default
