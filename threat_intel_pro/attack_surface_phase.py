# -*- coding: utf-8 -*-
"""
attack_surface_phase.py — 方向2 威胁情报 Pro：阶段5 攻击面管理。

外部资产测绘:
    - 子域名枚举  (subfinder / crt.sh / 证书透明度)
    - IP 地址发现
    - 端口扫描    (nmap)
    - 服务识别 / 技术栈识别 (CMS/框架/中间件)
    - 证书信息 / DNS 记录

风险发现:
    - 暴露服务风险 / 已知漏洞匹配 / 配置错误检测 / 影子 IT 发现
资产变更监控 + 攻击面评分。

原则: 真实 API 调用 (crt.sh) 用 requests 超时 30s; nmap 未安装明确提示,
不 mock。
"""

from __future__ import annotations

import re
import shutil
import socket
import subprocess
import time
import uuid
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional

try:
    import requests  # type: ignore
    _REQ = True
except Exception:  # pragma: no cover
    requests = None  # type: ignore
    _REQ = False

HTTP_TIMEOUT = 30


def _which_nmap() -> Optional[str]:
    p = shutil.which("nmap")
    if p:
        return p
    for c in (r"C:\Program Files (x86)\Nmap\nmap.exe",
              r"C:\Program Files\Nmap\nmap.exe",
              "/usr/bin/nmap"):
        try:
            import os
            if os.path.exists(c):
                return c
        except Exception:
            pass
    return None


@dataclass
class SurfaceAsset:
    asset_id: str = ""
    domain: str = ""
    subdomain: str = ""
    ips: List[str] = field(default_factory=list)
    ports: List[Dict[str, Any]] = field(default_factory=list)
    services: List[str] = field(default_factory=list)
    tech_stack: List[str] = field(default_factory=list)
    cert: Dict[str, Any] = field(default_factory=dict)
    dns: Dict[str, Any] = field(default_factory=dict)
    risks: List[Dict[str, Any]] = field(default_factory=list)
    score: int = 0
    first_seen: str = ""
    last_seen: str = ""

    def to_dict(self) -> Dict[str, Any]:
        return {
            "asset_id": self.asset_id, "domain": self.domain,
            "subdomain": self.subdomain, "ips": self.ips,
            "ports": self.ports, "services": self.services,
            "tech_stack": self.tech_stack, "cert": self.cert,
            "dns": self.dns, "risks": self.risks, "score": self.score,
            "first_seen": self.first_seen, "last_seen": self.last_seen,
        }


# 技术栈指纹规则
TECH_RULES = [
    ("wordpress", r"wp-content|wp-includes", "WordPress"),
    ("drupal", r"Drupal", "Drupal"),
    ("joomla", r"Joomla", "Joomla"),
    ("nginx", r"nginx", "Nginx"),
    ("apache", r"Apache", "Apache HTTPD"),
    ("iis", r"Microsoft-IIS", "Microsoft IIS"),
    ("tomcat", r"Tomcat", "Apache Tomcat"),
    ("spring", r"Spring", "Spring"),
    ("django", r"django", "Django"),
    ("react", r"react", "React"),
    ("jquery", r"jquery", "jQuery"),
    ("cloudflare", r"cloudflare", "Cloudflare"),
    ("laravel", r"laravel", "Laravel"),
    ("php", r"PHP/", "PHP"),
    ("aspnet", r"ASP\.NET", "ASP.NET"),
]

# 高风险端口
HIGH_RISK_PORTS = {
    21: "FTP (明文)", 23: "Telnet (明文)", 445: "SMB",
    135: "MSRPC", 1433: "MSSQL", 3306: "MySQL", 3389: "RDP",
    6379: "Redis", 27017: "MongoDB", 9200: "Elasticsearch",
    2375: "Docker API", 5900: "VNC",
}


class AttackSurfacePhase:
    """阶段5: 攻击面管理。"""

    def __init__(self) -> None:
        self._assets: Dict[str, SurfaceAsset] = {}
        self._history: Dict[str, List[Dict[str, Any]]] = {}
        self.nmap_bin = _which_nmap()

    # ------------------------------------------------------------------ #
    # 子域名枚举 (crt.sh 真实 API)
    # ------------------------------------------------------------------ #
    def enum_subdomains(self, domain: str) -> List[Dict[str, Any]]:
        """通过 crt.sh 证书透明度日志枚举子域名（真实 API）。"""
        if not _REQ:
            return [{"subdomain": "", "source": "crt.sh",
                     "note": "requests 未安装，无法查询 crt.sh"}]
        try:
            r = requests.get(
                f"https://crt.sh/?q=%25.{domain}&output=json",
                timeout=HTTP_TIMEOUT)
            r.raise_for_status()
            seen = set()
            out: List[Dict[str, Any]] = []
            for row in r.json():
                name = row.get("name_value", "")
                for nm in name.split("\n"):
                    nm = nm.strip().lower()
                    if nm.endswith(domain) and "*" not in nm and nm not in seen:
                        seen.add(nm)
                        out.append({"subdomain": nm, "source": "crt.sh",
                                    "not_before": row.get("not_before", "")})
            return out
        except Exception as e:  # noqa: BLE001
            return [{"subdomain": "", "source": "crt.sh",
                     "error": f"crt.sh 查询失败: {e}"}]

    # ------------------------------------------------------------------ #
    # DNS 解析
    # ------------------------------------------------------------------ #
    def resolve(self, hostname: str) -> Dict[str, Any]:
        try:
            infos = socket.getaddrinfo(hostname, None)
            ips = sorted({i[4][0] for i in infos})
            return {"host": hostname, "ips": ips,
                    "resolved": True}
        except Exception as e:  # noqa: BLE001
            return {"host": hostname, "ips": [], "resolved": False,
                    "error": str(e)}

    # ------------------------------------------------------------------ #
    # 端口扫描 (nmap)
    # ------------------------------------------------------------------ #
    def port_scan(self, host: str,
                  ports: str = "21,22,80,443,445,1433,3306,3389,6379,8080,8443"
                  ) -> Dict[str, Any]:
        if not self.nmap_bin:
            return {"host": host, "available": False,
                    "note": "nmap 未安装；请安装 Nmap 以启用真实端口扫描",
                    "ports": []}
        try:
            cmd = [self.nmap_bin, "-Pn", "-sV", "-p", ports, host]
            proc = subprocess.run(cmd, capture_output=True, text=True,
                                  timeout=180)
            ports_found: List[Dict[str, Any]] = []
            for line in proc.stdout.splitlines():
                m = re.match(r"^(\d+)/tcp\s+(\w+)\s+(\S+)\s*(.*)$", line)
                if m:
                    ports_found.append({
                        "port": int(m.group(1)), "state": m.group(2),
                        "service": m.group(3), "version": m.group(4).strip()})
            return {"host": host, "available": True,
                    "ports": ports_found}
        except Exception as e:  # noqa: BLE001
            return {"host": host, "available": False,
                    "error": str(e), "ports": []}

    # ------------------------------------------------------------------ #
    # 技术栈识别
    # ------------------------------------------------------------------ #
    def fingerprint_http(self, url: str) -> Dict[str, Any]:
        if not _REQ:
            return {"url": url, "tech": [], "note": "requests 未安装"}
        try:
            r = requests.get(url, timeout=HTTP_TIMEOUT,
                             headers={"User-Agent": "Mozilla/5.0"})
            headers = dict(r.headers)
            body = r.text[:200000]
            tech: List[str] = []
            for key, pattern, label in TECH_RULES:
                if re.search(pattern, body, re.I) \
                        or re.search(pattern, str(headers), re.I):
                    tech.append(label)
            server = headers.get("Server", "")
            if server:
                tech.append(f"Server:{server}")
            return {"url": url, "status": r.status_code, "tech": tech,
                    "server": server,
                    "content_type": headers.get("Content-Type", "")}
        except Exception as e:  # noqa: BLE001
            return {"url": url, "tech": [], "error": str(e)}

    # ------------------------------------------------------------------ #
    # 风险发现
    # ------------------------------------------------------------------ #
    def _detect_risks(self, asset: SurfaceAsset) -> List[Dict[str, Any]]:
        risks: List[Dict[str, Any]] = []
        for p in asset.ports:
            port = p.get("port", 0)
            if port in HIGH_RISK_PORTS and p.get("state") == "open":
                risks.append({
                    "type": "exposed_service",
                    "severity": "high" if port in (3389, 2375, 6379)
                    else "medium",
                    "title": f"暴露 {HIGH_RISK_PORTS[port]} (port {port})",
                    "detail": f"{p.get('service','')} {p.get('version','')}"})
            if port == 443 and "expired" in str(asset.cert).lower():
                risks.append({
                    "type": "cert_expired", "severity": "high",
                    "title": "TLS 证书过期", "detail": str(asset.cert)})
        # 配置错误占位
        for t in asset.tech_stack:
            if t in ("PHP", "Apache HTTPD"):
                risks.append({
                    "type": "config_review", "severity": "low",
                    "title": f"{t} 建议审查默认配置",
                    "detail": "默认页/目录列表/调试模式"})
        return risks

    def _score(self, risks: List[Dict[str, Any]],
               open_ports: int) -> int:
        score = 30
        score += min(open_ports * 2, 30)
        sev_score = {"critical": 25, "high": 15, "medium": 8, "low": 3}
        for r in risks:
            score += sev_score.get(r.get("severity", "low"), 0)
        return min(score, 100)

    # ------------------------------------------------------------------ #
    # 一键测绘
    # ------------------------------------------------------------------ #
    def map_domain(self, domain: str,
                   do_port_scan: bool = True) -> Dict[str, Any]:
        now = time.strftime("%Y-%m-%d %H:%M:%S")
        subs = self.enum_subdomains(domain)
        assets: List[SurfaceAsset] = []
        for s in subs[:30]:
            sd = s.get("subdomain") or ""
            if not sd:
                continue
            asset = SurfaceAsset(
                asset_id=uuid.uuid4().hex[:12],
                domain=domain, subdomain=sd,
                first_seen=now, last_seen=now)
            dns = self.resolve(sd)
            asset.dns = dns
            asset.ips = dns.get("ips", [])
            # HTTP 指纹
            for scheme in ("https", "http"):
                fp = self.fingerprint_http(f"{scheme}://{sd}")
                if "error" not in fp:
                    asset.tech_stack = fp.get("tech", [])
                    asset.services.append(
                        f"{scheme.upper()}/{fp.get('status','?')}")
                    break
            # 端口扫描
            if do_port_scan and asset.ips:
                ps = self.port_scan(asset.ips[0])
                asset.ports = ps.get("ports", [])
            # 风险
            asset.risks = self._detect_risks(asset)
            asset.score = self._score(asset.risks, len(asset.ports))
            assets.append(asset)
            self._assets[asset.asset_id] = asset
        # 历史快照
        self._history[domain] = self._history.get(domain, []) + [
            {"ts": now, "asset_count": len(assets),
             "avg_score": sum(a.score for a in assets) //
             max(len(assets), 1)}]
        return {
            "domain": domain,
            "subdomains_found": len(subs),
            "assets": [a.to_dict() for a in assets],
            "nmap_available": bool(self.nmap_bin),
        }

    # ------------------------------------------------------------------ #
    # 影子 IT 发现（在资产清单里找未登记资产）
    # ------------------------------------------------------------------ #
    def detect_shadow_it(self, registered: List[str],
                         discovered: List[str]) -> List[str]:
        reg = {r.lower() for r in registered}
        return [d for d in discovered
                if d.lower() not in reg and not any(
            d.lower().endswith("." + x) for x in reg)]

    def changes(self, domain: str) -> List[Dict[str, Any]]:
        return self._history.get(domain, [])

    def list_assets(self, domain: str = "") -> List[Dict[str, Any]]:
        out = list(self._assets.values())
        if domain:
            out = [a for a in out if a.domain == domain]
        return [a.to_dict() for a in sorted(
            out, key=lambda x: x.score, reverse=True)]

    def stats(self) -> Dict[str, Any]:
        assets = list(self._assets.values())
        if not assets:
            return {"total_assets": 0}
        high = sum(1 for a in assets if a.score >= 60)
        return {
            "total_assets": len(assets),
            "avg_score": sum(a.score for a in assets) // len(assets),
            "high_risk_assets": high,
            "domains": sorted({a.domain for a in assets}),
            "nmap_available": bool(self.nmap_bin),
        }


_phase: Optional[AttackSurfacePhase] = None


def get_attack_surface_phase() -> AttackSurfacePhase:
    global _phase
    if _phase is None:
        _phase = AttackSurfacePhase()
    return _phase
