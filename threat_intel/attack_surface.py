# -*- coding: utf-8 -*-
"""
attack_surface.py — 攻击面管理（第23轮升级方向3）。

功能：
- 资产发现：主动扫描/被动流量/证书透明日志/子域名枚举/ASN/Whois/搜索引擎（模拟）
- 资产分类：IP/域名/URL/端口/服务/应用/证书/云资源/容器/API/员工/第三方
- 资产画像：技术栈/版本/开放端口/服务/证书/地理位置/ISP/归属/风险标签
- 攻击面分析：暴露面分析/风险评分/优先级排序/攻击路径分析/最弱环节识别
- 攻击面监控：持续监控/变更检测/新增资产告警/风险变更告警/过期证书告警
- 攻击面报告：总览/风险分布/趋势/改进建议/合规映射

全部内存字典模拟，不建数据库表。
"""

from __future__ import annotations

import hashlib
import socket
import uuid
from datetime import datetime, timedelta
from typing import Any, Dict, List, Optional

try:
    import requests  # type: ignore
    _REQUESTS_OK = True
except Exception:  # pragma: no cover
    requests = None  # type: ignore
    _REQUESTS_OK = False


# 常见服务端口映射
COMMON_PORTS: Dict[int, str] = {
    21: "ftp", 22: "ssh", 23: "telnet", 25: "smtp", 53: "dns",
    80: "http", 110: "pop3", 143: "imap", 443: "https", 445: "smb",
    3306: "mysql", 3389: "rdp", 5432: "postgresql", 6379: "redis",
    8080: "http-proxy", 8443: "https-alt", 9200: "elasticsearch", 27017: "mongodb",
}

HIGH_RISK_PORTS = {23, 445, 3389, 6379, 9200, 27017}


class AttackSurfaceManager:
    """攻击面管理：资产发现/画像/风险评分/监控/报告。"""

    def __init__(self) -> None:
        self.assets: Dict[str, Dict[str, Any]] = {}
        self.changes: List[Dict[str, Any]] = []
        self.alerts: List[Dict[str, Any]] = []
        self.scan_history: List[Dict[str, Any]] = []
        self._seed()

    @staticmethod
    def _now(days: int = 0) -> str:
        return (datetime.now() - timedelta(days=days)).isoformat()

    # ---------- 种子资产库 ----------
    def _seed(self) -> None:
        seeds = [
            {"name": "门户主站", "type": "domain", "value": "www.example-corp.com",
             "ip": "203.0.113.10", "ports": [80, 443], "services": ["nginx/1.24", "https"],
             "tech_stack": ["Nginx", "React", "Cloudflare"], "cert_expires_days": 45,
             "geo": "上海", "isp": "中国联通", "owner": "市场部"},
            {"name": "VPN网关", "type": "ip", "value": "203.0.113.20",
             "ip": "203.0.113.20", "ports": [443, 8443],
             "services": ["Fortinet SSL VPN"], "tech_stack": ["FortiOS 7.2.1"],
             "cert_expires_days": 20, "geo": "北京", "isp": "中国电信", "owner": "IT"},
            {"name": "员工OA", "type": "domain", "value": "oa.example-corp.com",
             "ip": "203.0.113.30", "ports": [443], "services": ["Apache Tomcat 9.0.30"],
             "tech_stack": ["Tomcat", "Spring"], "cert_expires_days": 300,
             "geo": "上海", "isp": "中国联通", "owner": "行政部"},
            {"name": "Redis缓存", "type": "ip", "value": "10.0.0.21",
             "ip": "10.0.0.21", "ports": [6379], "services": ["Redis 5.0.7"],
             "tech_stack": ["Redis"], "cert_expires_days": 0,
             "geo": "内网", "isp": "私有", "owner": "运维部"},
            {"name": "测试环境API", "type": "url", "value": "https://test-api.example-corp.com",
             "ip": "203.0.113.40", "ports": [8080, 8443],
             "services": ["Spring Boot 2.6", "swagger"], "tech_stack": ["Java", "Swagger UI"],
             "cert_expires_days": 10, "geo": "上海", "isp": "中国联通", "owner": "研发部"},
        ]
        for s in seeds:
            self._upsert(s)

    def _upsert(self, data: Dict[str, Any]) -> Dict[str, Any]:
        aid = data.get("id") or f"asset-{uuid.uuid4().hex[:8]}"
        rec = {
            "id": aid, "name": data.get("name", aid), "type": data.get("type", "ip"),
            "value": data.get("value", ""), "ip": data.get("ip", ""),
            "ports": data.get("ports", []), "services": data.get("services", []),
            "tech_stack": data.get("tech_stack", []),
            "cert_expires_days": int(data.get("cert_expires_days", 999)),
            "geo": data.get("geo", ""), "isp": data.get("isp", ""),
            "owner": data.get("owner", ""),
            "discovered_via": data.get("discovered_via", "manual"),
            "first_seen": self._now(days=60), "last_seen": self._now(),
            "risk_tags": [], "risk_score": 0, "status": "active",
        }
        rec["risk_score"] = self._compute_risk(rec)
        rec["risk_tags"] = self._risk_tags(rec)
        self.assets[aid] = rec
        return rec

    # ---------- 风险评分（真实规则） ----------
    def _compute_risk(self, a: Dict[str, Any]) -> int:
        score = 10
        # 高危暴露端口
        risky = set(a.get("ports", [])) & HIGH_RISK_PORTS
        score += len(risky) * 15
        # 老旧组件
        svc = " ".join(a.get("services", [])).lower()
        for old in ("tomcat 9.0.3", "fortios 7.2.1", "redis 5", "apache httpd 2.2"):
            if old in svc:
                score += 20
        # 证书即将过期
        ce = int(a.get("cert_expires_days", 999))
        if ce < 15:
            score += 25
        elif ce < 45:
            score += 10
        # Swagger/调试暴露
        if "swagger" in svc or "debug" in svc:
            score += 10
        # 内网资产默认低风险
        if str(a.get("ip", "")).startswith("10.") or str(a.get("ip", "")).startswith("192.168."):
            score = min(score, 45)
        return max(0, min(100, score))

    def _risk_tags(self, a: Dict[str, Any]) -> List[str]:
        tags = []
        if set(a.get("ports", [])) & HIGH_RISK_PORTS:
            tags.append("高危端口暴露")
        if int(a.get("cert_expires_days", 999)) < 15:
            tags.append("证书即将过期")
        svc = " ".join(a.get("services", [])).lower()
        if "fortinet" in svc or "vpn" in svc:
            tags.append("VPN边界")
        if "swagger" in svc:
            tags.append("API文档暴露")
        if not tags:
            tags.append("常规")
        return tags

    # ---------- 资产发现（模拟+真实DNS） ----------
    def discover_subdomains(self, domain: str) -> List[Dict[str, Any]]:
        """子域名枚举：尝试常见前缀，真实DNS解析（失败回退模拟）。"""
        results = []
        prefixes = ["www", "mail", "vpn", "oa", "api", "test", "dev", "admin",
                    "ftp", "git", "jenkins", "crm"]
        for p in prefixes:
            fqdn = f"{p}.{domain}"
            ip = ""
            if _REQUESTS_OK:
                try:
                    ip = socket.gethostbyname(fqdn)
                except Exception:
                    ip = ""
            if ip:
                rec = self._upsert({
                    "name": fqdn, "type": "domain", "value": fqdn, "ip": ip,
                    "ports": [80, 443], "services": ["http"],
                    "discovered_via": "subdomain_enum", "tech_stack": [],
                    "cert_expires_days": 90, "geo": "未知", "isp": "未知", "owner": ""})
                results.append(rec)
                self.changes.append({"time": self._now(), "type": "new_asset",
                                    "asset_id": rec["id"], "value": fqdn})
        return results

    def discover_by_scan(self, target: str) -> Dict[str, Any]:
        """模拟主动扫描发现资产。"""
        self.scan_history.append({"time": self._now(), "target": target,
                                  "status": "running"})
        # 模拟发现2个新资产
        new_assets = []
        for i in range(2):
            a = self._upsert({
                "name": f"scan-{target}-{i}", "type": "ip",
                "value": f"198.51.100.{50+i}", "ip": f"198.51.100.{50+i}",
                "ports": [22, 443], "services": ["ssh", "nginx"],
                "discovered_via": "active_scan", "tech_stack": ["Linux"],
                "cert_expires_days": 60, "geo": "未知", "isp": "未知", "owner": ""})
            new_assets.append(a)
            self.changes.append({"time": self._now(), "type": "new_asset",
                                 "asset_id": a["id"], "value": a["value"]})
        self.scan_history[-1]["status"] = "done"
        self.scan_history[-1]["found"] = len(new_assets)
        return {"target": target, "found": len(new_assets), "assets": new_assets}

    def discover_from_ct(self, domain: str) -> List[Dict[str, Any]]:
        """模拟证书透明日志发现。"""
        found = []
        for sub in [f"*.{domain}", f"api.{domain}", f"dev.{domain}"]:
            rec = self._upsert({
                "name": sub, "type": "domain", "value": sub,
                "ports": [443], "services": ["https"], "discovered_via": "ct_log",
                "tech_stack": [], "cert_expires_days": 30,
                "geo": "未知", "isp": "未知", "owner": ""})
            found.append(rec)
        return found

    # ---------- 资产画像 ----------
    def profile(self, asset_id: str) -> Dict[str, Any]:
        a = self.assets.get(asset_id)
        if not a:
            raise KeyError(f"资产不存在: {asset_id}")
        return {
            **a,
            "exposure_level": self._exposure_level(a),
            "recommended_actions": self._recommendations(a),
        }

    @staticmethod
    def _exposure_level(a: Dict[str, Any]) -> str:
        s = a.get("risk_score", 0)
        if s >= 60:
            return "高暴露"
        if s >= 35:
            return "中暴露"
        return "低暴露"

    @staticmethod
    def _recommendations(a: Dict[str, Any]) -> List[str]:
        recs = []
        if set(a.get("ports", [])) & HIGH_RISK_PORTS:
            recs.append("关闭或限制高危端口访问（防火墙白名单/VPN）")
        if int(a.get("cert_expires_days", 999)) < 15:
            recs.append("立即更新TLS证书")
        if "swagger" in " ".join(a.get("services", [])).lower():
            recs.append("生产环境关闭Swagger/调试端点")
        svc = " ".join(a.get("services", [])).lower()
        if "tomcat 9.0.3" in svc:
            recs.append("升级Tomcat到最新安全版本")
        if not recs:
            recs.append("维持现有防护，纳入持续监控")
        return recs

    # ---------- 攻击面分析 ----------
    def analyze(self) -> Dict[str, Any]:
        assets = list(self.assets.values())
        scored = sorted(assets, key=lambda x: x.get("risk_score", 0), reverse=True)
        weakest = scored[:5]
        by_type: Dict[str, int] = {}
        by_owner: Dict[str, int] = {}
        exposed_high = 0
        for a in assets:
            by_type[a["type"]] = by_type.get(a["type"], 0) + 1
            by_owner[a["owner"] or "未分配"] = by_owner.get(a["owner"] or "未分配", 0) + 1
            if a.get("risk_score", 0) >= 60:
                exposed_high += 1
        # 攻击路径：边界→服务→资产
        attack_paths = [
            {"path": "互联网 → VPN(443/8443) → 内网资产",
             "entrypoint": next((a["name"] for a in assets if "VPN" in a["name"]), "VPN"),
             "risk": "高", "description": "VPN为主要远程入口，需重点防护0day"},
            {"path": "互联网 → OA(443) → 员工数据",
             "entrypoint": "OA", "risk": "中",
             "description": "OA系统公开访问，存在弱口令/漏洞风险"},
        ]
        return {
            "total_assets": len(assets),
            "high_exposed": exposed_high,
            "avg_risk": round(sum(a.get("risk_score", 0) for a in assets) / max(1, len(assets)), 1),
            "top_risky": weakest,
            "weakest_link": weakest[0]["name"] if weakest else None,
            "by_type": by_type, "by_owner": by_owner,
            "attack_paths": attack_paths,
            "recommendations": [
                "优先处置高风险VPN边界与高危端口暴露",
                "清理影子资产/测试环境暴露",
                "建立证书到期自动告警",
            ],
        }

    # ---------- 监控 / 变更检测 ----------
    def monitor_tick(self) -> Dict[str, Any]:
        """模拟一次监控巡检：变更检测+过期证书告警。"""
        new_alerts = []
        for a in self.assets.values():
            if int(a.get("cert_expires_days", 999)) < 15:
                msg = f"证书即将过期: {a['name']} ({a['cert_expires_days']}天)"
                new_alerts.append({"time": self._now(), "level": "high",
                                   "asset_id": a["id"], "type": "cert_expiry",
                                   "message": msg})
            if a.get("risk_score", 0) >= 60:
                new_alerts.append({"time": self._now(), "level": "medium",
                                   "asset_id": a["id"], "type": "high_risk",
                                   "message": f"高风险资产: {a['name']}"})
        self.alerts.extend(new_alerts)
        return {"checked": len(self.assets), "new_alerts": len(new_alerts),
                "alerts": new_alerts}

    def list_alerts(self, level: Optional[str] = None) -> List[Dict[str, Any]]:
        out = self.alerts
        if level:
            out = [a for a in out if a["level"] == level]
        return out

    def list_assets(self, typ: Optional[str] = None, q: str = "") -> List[Dict[str, Any]]:
        out = list(self.assets.values())
        if typ:
            out = [a for a in out if a["type"] == typ]
        if q:
            ql = q.lower()
            out = [a for a in out if ql in a["name"].lower()
                   or ql in a["value"].lower()]
        return out

    def get_asset(self, aid: str) -> Optional[Dict[str, Any]]:
        return self.assets.get(aid)

    # ---------- 报告 ----------
    def report(self) -> Dict[str, Any]:
        analysis = self.analyze()
        trend = [{"day": f"T-{i}", "assets": len(self.assets) - i} for i in range(6, -1, -1)]
        return {
            "overview": analysis,
            "trend": trend,
            "compliance_mapping": {
                "等保2.0 安全区域边界": "VPN/防火墙资产已纳管",
                "ISO27001 A.12.1.2": "变更管理流程覆盖资产变更",
                "PCI-DSS Req11": "定期漏洞扫描与攻击面评审",
            },
            "generated_at": self._now(),
        }

    def stats(self) -> Dict[str, Any]:
        a = self.analyze()
        return {"total_assets": a["total_assets"],
                "high_exposed": a["high_exposed"],
                "avg_risk": a["avg_risk"],
                "alerts": len(self.alerts),
                "changes": len(self.changes)}


_manager: Optional[AttackSurfaceManager] = None


def get_attack_surface_manager() -> AttackSurfaceManager:
    global _manager
    if _manager is None:
        _manager = AttackSurfaceManager()
    return _manager
