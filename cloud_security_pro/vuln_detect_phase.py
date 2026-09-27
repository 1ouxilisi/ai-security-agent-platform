# -*- coding: utf-8 -*-
"""
vuln_detect_phase.py — 云安全 Pro 阶段4：云服务漏洞检测。

功能:
    - 云服务漏洞检测框架
    - CVE 匹配（基于资源类型 + 版本）
    - 内置已知云服务漏洞库（30+ 条）
    - 漏洞利用可能性评估
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional


# 内置云服务已知漏洞库（典型 RDS 引擎 / 镜像 / 中间件）
CLOUD_VULN_DB: List[Dict[str, Any]] = [
    {"cve_id": "CVE-2021-44228", "product": "log4j", "min": "2.0",
     "max": "2.14.1", "severity": "critical", "cvss": 10.0,
     "title": "Log4Shell 远程代码执行", "type": "rce"},
    {"cve_id": "CVE-2021-44228", "product": "apache-log4j", "min": "2.0",
     "max": "2.14.1", "severity": "critical", "cvss": 10.0,
     "title": "Log4Shell 远程代码执行", "type": "rce"},
    {"cve_id": "CVE-2023-48795", "product": "openssh", "min": "8.5",
     "max": "9.6", "severity": "high", "cvss": 5.9,
     "title": "Terrapin SSH 前缀截断", "type": "protocol"},
    {"cve_id": "CVE-2022-22965", "product": "spring-beans", "min": "5.3.0",
     "max": "5.3.17", "severity": "critical", "cvss": 9.8,
     "title": "Spring4Shell 远程代码执行", "type": "rce"},
    {"cve_id": "CVE-2021-41773", "product": "httpd", "min": "2.4.49",
     "max": "2.4.49", "severity": "critical", "cvss": 9.8,
     "title": "Apache HTTPd 路径穿越 RCE", "type": "rce"},
    {"cve_id": "CVE-2021-42013", "product": "httpd", "min": "2.4.49",
     "max": "2.4.50", "severity": "critical", "cvss": 9.8,
     "title": "Apache HTTPd 路径穿越 RCE(补丁绕过)", "type": "rce"},
    {"cve_id": "CVE-2019-19781", "product": "citrix", "min": "-",
     "max": "13.0", "severity": "critical", "cvss": 9.8,
     "title": "Citrix ADC 远程代码执行", "type": "rce"},
    {"cve_id": "CVE-2021-26855", "product": "exchange", "min": "-",
     "max": "2019 CU10", "severity": "critical", "cvss": 9.8,
     "title": "ProxyLogon Exchange 预认证 RCE", "type": "rce"},
    {"cve_id": "CVE-2023-23397", "product": "exchange", "min": "2019",
     "max": "2019 CU13", "severity": "high", "cvss": 9.8,
     "title": "Microsoft Outlook 权限提升", "type": "rce"},
    {"cve_id": "CVE-2018-15919", "product": "openssh", "min": "-",
     "max": "7.9", "severity": "medium", "cvss": 5.3,
     "title": "OpenSSH 用户名枚举", "type": "info_leak"},
    {"cve_id": "CVE-2020-1472", "product": "netlogon", "min": "-",
     "max": "-", "severity": "critical", "cvss": 10.0,
     "title": "ZeroLogon 域控权限接管", "type": "privesc"},
    {"cve_id": "CVE-2021-34527", "product": "printspooler", "min": "-",
     "max": "-", "severity": "critical", "cvss": 8.8,
     "title": "PrintNightmare 打印后台 RCE", "type": "rce"},
    {"cve_id": "CVE-2022-30190", "product": "ms-msdt", "min": "-",
     "max": "-", "severity": "high", "cvss": 7.8,
     "title": "Follina MSDT 远程代码执行", "type": "rce"},
    {"cve_id": "CVE-2016-2107", "product": "openssl", "min": "1.0.1",
     "max": "1.0.2h", "severity": "high", "cvss": 7.5,
     "title": "OpenSSL Padding Oracle 数据解密", "type": "crypto"},
    {"cve_id": "CVE-2022-0847", "product": "kernel", "min": "5.8",
     "max": "5.16.10", "severity": "high", "cvss": 7.8,
     "title": "Dirty Pipe 本地提权文件覆盖", "type": "privesc"},
    {"cve_id": "CVE-2021-4034", "product": "pkexec", "min": "-",
     "max": "-", "severity": "critical", "cvss": 7.8,
     "title": "PwnKit polkit 本地提权", "type": "privesc"},
    {"cve_id": "CVE-2023-22515", "product": "confluence", "min": "8.0.0",
     "max": "8.5.1", "severity": "critical", "cvss": 9.8,
     "title": "Confluence 权限绕过未授权 RCE", "type": "rce"},
    {"cve_id": "CVE-2022-1388", "product": "f5-bigip", "min": "11.6",
     "max": "17.0", "severity": "critical", "cvss": 9.8,
     "title": "F5 BIG-IP iControl 未授权 RCE", "type": "rce"},
    {"cve_id": "CVE-2023-4966", "product": "netscaler", "min": "-",
     "max": "13.1-49", "severity": "critical", "cvss": 9.4,
     "title": "Citrix NetScaler 信息泄露(NetBrainer)", "type": "info_leak"},
    {"cve_id": "CVE-2022-26134", "product": "confluence", "min": "1.3",
     "max": "7.18", "severity": "critical", "cvss": 9.8,
     "title": "Confluence 未授权 OGNL 注入 RCE", "type": "rce"},
    {"cve_id": "CVE-2017-12615", "product": "tomcat", "min": "7.0.0",
     "max": "7.0.81", "severity": "high", "cvss": 8.1,
     "title": "Tomcat  PUT 方法任意文件上传", "type": "upload"},
    {"cve_id": "CVE-2020-1938", "product": "tomcat", "min": "9.0.0",
     "max": "9.0.30", "severity": "high", "cvss": 7.5,
     "title": "Ghostcat AJP 文件包含", "type": "lfi"},
    {"cve_id": "CVE-2019-0708", "product": "rdp", "min": "-",
     "max": "-", "severity": "critical", "cvss": 9.8,
     "title": "BlueKeep RDP 远程代码执行", "type": "rce"},
    {"cve_id": "CVE-2019-10149", "product": "postfix", "min": "-",
     "max": "3.4.5", "severity": "critical", "cvss": 9.8,
     "title": "Postfix 本地投递命令执行", "type": "rce"},
    {"cve_id": "CVE-2014-0160", "product": "openssl", "min": "1.0.1",
     "max": "1.0.1f", "severity": "critical", "cvss": 7.5,
     "title": "Heartbleed 心脏出血内存泄露", "type": "info_leak"},
    {"cve_id": "CVE-2017-5638", "product": "jenkins", "min": "-",
     "max": "2.45", "severity": "critical", "cvss": 10.0,
     "title": "Jenkins  CLI 远程命令执行", "type": "rce"},
    {"cve_id": "CVE-2024-23897", "product": "jenkins", "min": "2.441",
     "max": "2.442", "severity": "high", "cvss": 7.5,
     "title": "Jenkins 任意文件读取", "type": "info_leak"},
    {"cve_id": "CVE-2021-31166", "product": "win-kernel", "min": "-",
     "max": "-", "severity": "high", "cvss": 8.8,
     "title": "Windows TCP/IP 远程代码执行", "type": "rce"},
    {"cve_id": "CVE-2020-0796", "product": "smbv3", "min": "1903",
     "max": "1909", "severity": "critical", "cvss": 10.0,
     "title": "SMBGhost SMBv3 内存 corruption", "type": "rce"},
    {"cve_id": "CVE-2023-22518", "product": "confluence", "min": "8.0.0",
     "max": "8.5.2", "severity": "critical", "cvss": 9.8,
     "title": "Confluence 未授权数据重置", "type": "rce"},
]


@dataclass
class CloudVuln:
    cve_id: str = ""
    product: str = ""
    version: str = ""
    severity: str = "medium"
    cvss: float = 0.0
    title: str = ""
    vuln_type: str = ""
    resource_id: str = ""
    resource_type: str = ""
    exploit_likelihood: str = "medium"   # high/medium/low
    exploit_note: str = ""

    def to_dict(self) -> Dict[str, Any]:
        return self.__dict__.copy()


class CloudVulnDetectPhase:
    """云服务漏洞检测：基于资源类型/版本的 CVE 匹配。"""

    def __init__(self) -> None:
        self.db = CLOUD_VULN_DB

    # ------------------------------------------------------------------ #
    def detect(self, inventory: Dict[str, Any]) -> Dict[str, Any]:
        resources = (inventory or {}).get("resources", [])
        out: List[CloudVuln] = []
        if not resources:
            return {"executed": False, "vulns": [], "count": 0,
                    "note": "无资源清单，跳过 CVE 匹配。"}

        # 收集待匹配的 (product, version, resource)
        candidates: List[Dict[str, str]] = []
        for r in resources:
            extra = r.get("extra", {})
            rt = r.get("resource_type", "")
            # 数据库引擎
            if rt == "rds":
                candidates.append({
                    "product": (extra.get("engine") or "").lower(),
                    "version": extra.get("engine_version", ""),
                    "resource_id": r.get("resource_id", ""),
                    "resource_type": rt,
                })
            # 实例上的软件版本（若 extra 携带 inventory_software）
            for sw in extra.get("installed_software", []) or []:
                candidates.append({
                    "product": str(sw.get("product", "")).lower(),
                    "version": str(sw.get("version", "")),
                    "resource_id": r.get("resource_id", ""),
                    "resource_type": rt,
                })

        for cand in candidates:
            for entry in self.db:
                if self._match(entry, cand["product"], cand["version"]):
                    out.append(CloudVuln(
                        cve_id=entry["cve_id"],
                        product=cand["product"],
                        version=cand["version"],
                        severity=entry["severity"],
                        cvss=entry["cvss"],
                        title=entry["title"],
                        vuln_type=entry["type"],
                        resource_id=cand["resource_id"],
                        resource_type=cand["resource_type"],
                        exploit_likelihood=self._exploit_likelihood(
                            entry["severity"], entry["cvss"],
                            cand.get("resource_type", "")),
                        exploit_note=self._exploit_note(entry),
                    ))

        sev = {"critical": 0, "high": 0, "medium": 0, "low": 0}
        for v in out:
            sev[v.severity] = sev.get(v.severity, 0) + 1
        return {
            "executed": True,
            "vulns": [v.to_dict() for v in out],
            "count": len(out),
            "by_severity": sev,
            "db_size": len(self.db),
            "candidates_scanned": len(candidates),
        }

    # ------------------------------------------------------------------ #
    def _match(self, entry: Dict[str, Any], product: str,
               version: str) -> bool:
        if not product:
            return False
        if entry["product"] not in product:
            return False
        if not version or entry.get("min") in (None, "-"):
            return True
        try:
            v = tuple(int(x) for x in version.split(".")[:3]
                      if x.isdigit())
            lo = tuple(int(x) for x in str(entry["min"]).split(".")
                       if x.isdigit())
            hi = tuple(int(x) for x in str(entry["max"]).split(".")
                       if x.isdigit())
            if lo and v < lo:
                return False
            if hi and v > hi:
                return False
            return True
        except Exception:  # noqa: BLE001
            return entry["product"] in product

    # ------------------------------------------------------------------ #
    def _exploit_likelihood(self, severity: str, cvss: float,
                            rtype: str) -> str:
        if severity == "critical" and cvss >= 9:
            return "high"
        if severity == "critical" or cvss >= 7:
            return "medium"
        return "low"

    def _exploit_note(self, entry: Dict[str, Any]) -> str:
        if entry["type"] == "rce":
            return "存在公开 EXP / Metasploit 模块，建议优先处置。"
        if entry["type"] == "privesc":
            return "本地提权，结合初始访问可横向移动。"
        if entry["type"] == "info_leak":
            return "可泄露凭证/配置，为后续攻击铺路。"
        return "需结合暴露面判断可利用性。"

    # ------------------------------------------------------------------ #
    def db_overview(self) -> Dict[str, Any]:
        sev = {"critical": 0, "high": 0, "medium": 0, "low": 0}
        for e in self.db:
            sev[e["severity"]] = sev.get(e["severity"], 0) + 1
        return {"total": len(self.db), "by_severity": sev}


_default_vuln: Optional[CloudVulnDetectPhase] = None


def get_vuln_detect_phase() -> CloudVulnDetectPhase:
    global _default_vuln
    if _default_vuln is None:
        _default_vuln = CloudVulnDetectPhase()
    return _default_vuln
