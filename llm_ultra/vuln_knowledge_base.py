# -*- coding: utf-8 -*-
"""vuln_knowledge_base.py — 漏洞知识库。

AI分析时自动查CVE、自动查Exploit-DB、自动关联已知漏洞。
内存字典模拟存储，不依赖外部API（真实API调用用subprocess）。
"""
from __future__ import annotations

import time
from typing import Any, Dict, List, Optional


# 内置漏洞知识库（常见CVE摘要）
CVE_KNOWLEDGE_BASE: List[Dict[str, Any]] = [
    {
        "cve_id": "CVE-2021-44228",
        "name": "Log4Shell",
        "description": "Apache Log4j2 远程代码执行漏洞，通过JNDI注入实现RCE",
        "severity": "critical",
        "cvss": 10.0,
        "affected": "Apache Log4j2 2.0-beta9 to 2.14.1",
        "exploit_available": True,
        "exploit_db_id": 50515,
        "references": [
            "https://logging.apache.org/log4j/2.x/security.html",
            "https://nvd.nist.gov/vuln/detail/CVE-2021-44228",
        ],
        "remediation": "升级到Log4j 2.17.0+",
    },
    {
        "cve_id": "CVE-2017-5638",
        "name": "Struts2 S2-045",
        "description": "Apache Struts2 远程代码执行漏洞（Content-Type OGNL注入）",
        "severity": "critical",
        "cvss": 10.0,
        "affected": "Apache Struts 2.3.5-2.3.31, 2.5-2.5.10",
        "exploit_available": True,
        "exploit_db_id": 41570,
        "references": [
            "https://cwiki.apache.org/confluence/display/WW/S2-045",
        ],
        "remediation": "升级到Struts 2.3.32 or 2.5.10.1",
    },
    {
        "cve_id": "CVE-2021-41773",
        "name": "Apache 2.4.49 路径穿越",
        "description": "Apache HTTP Server 2.4.49 路径遍历漏洞，可读取文件甚至RCE",
        "severity": "critical",
        "cvss": 9.8,
        "affected": "Apache HTTP Server 2.4.49",
        "exploit_available": True,
        "exploit_db_id": 50383,
        "references": [
            "https://httpd.apache.org/security/vulnerabilities_24.html",
        ],
        "remediation": "升级到2.4.50+",
    },
    {
        "cve_id": "CVE-2014-0160",
        "name": "Heartbleed",
        "description": "OpenSSL 心跳信息泄露漏洞，可读取服务器内存中的私钥",
        "severity": "critical",
        "cvss": 7.5,
        "affected": "OpenSSL 1.0.1 to 1.0.1f",
        "exploit_available": True,
        "exploit_db_id": 32745,
        "references": [
            "https://heartbleed.com/",
        ],
        "remediation": "升级到OpenSSL 1.0.1g+",
    },
    {
        "cve_id": "CVE-2019-0211",
        "name": "Apache 权限提升",
        "description": "Apache HTTP Server 本地权限提升漏洞",
        "severity": "high",
        "cvss": 7.8,
        "affected": "Apache HTTP Server 2.4.17-2.4.38",
        "exploit_available": True,
        "exploit_db_id": 46676,
        "references": [],
        "remediation": "升级到2.4.39+",
    },
    {
        "cve_id": "CVE-2020-1472",
        "name": "Zerologon",
        "description": "Netlogon 远程协议权限提升漏洞，可接管域控",
        "severity": "critical",
        "cvss": 10.0,
        "affected": "Windows Server 2008-2019",
        "exploit_available": True,
        "exploit_db_id": 49766,
        "references": [
            "https://www.secura.com/blog/zero-logon",
        ],
        "remediation": "安装KB4557222补丁",
    },
    {
        "cve_id": "CVE-2022-22965",
        "name": "Spring4Shell",
        "description": "Spring Framework 远程代码执行漏洞",
        "severity": "critical",
        "cvss": 9.8,
        "affected": "Spring Framework 5.3.0-5.3.17, 5.2.0-5.2.19",
        "exploit_available": True,
        "exploit_db_id": 50868,
        "references": [
            "https://spring.io/security/cve-2022-22965",
        ],
        "remediation": "升级到5.3.18+或5.2.20+",
    },
    {
        "cve_id": "CVE-2018-7600",
        "name": "Drupalgeddon2",
        "description": "Drupal 核心远程代码执行漏洞",
        "severity": "critical",
        "cvss": 9.8,
        "affected": "Drupal 7.x before 7.58, 8.x before 8.3.9",
        "exploit_available": True,
        "exploit_db_id": 44449,
        "references": [
            "https://www.drupal.org/sa-core-2018-002",
        ],
        "remediation": "升级到Drupal 7.58/8.3.9+",
    },
]

# 漏洞类型到CVE的映射
TYPE_CVE_MAP: Dict[str, List[str]] = {
    "rce": ["CVE-2021-44228", "CVE-2017-5638", "CVE-2022-22965", "CVE-2018-7600"],
    "sql_injection": ["CVE-2017-11508", "CVE-2018-12613"],
    "xss": ["CVE-2021-25926", "CVE-2022-24866"],
    "path_traversal": ["CVE-2021-41773"],
    "authentication": ["CVE-2020-1472", "CVE-2019-0211"],
}


class VulnKnowledgeBase:
    """漏洞知识库：自动关联CVE和Exploit-DB。"""

    def __init__(self) -> None:
        self._kb: Dict[str, Dict[str, Any]] = {
            c["cve_id"]: c for c in CVE_KNOWLEDGE_BASE
        }
        self._custom_entries: Dict[str, Dict[str, Any]] = {}
        self._query_log: List[Dict[str, Any]] = []
        self._auto_correlations: List[Dict[str, Any]] = []

    def query_cve(self, cve_id: str) -> Optional[Dict[str, Any]]:
        """查询CVE详情。"""
        result = self._kb.get(cve_id) or self._custom_entries.get(cve_id)
        self._query_log.append({
            "cve_id": cve_id, "found": result is not None,
            "ts": time.strftime("%Y-%m-%d %H:%M:%S"),
        })
        return result

    def search_by_keyword(self, keyword: str) -> List[Dict[str, Any]]:
        """按关键词搜索漏洞。"""
        kw = keyword.lower()
        results = []
        for cve in list(self._kb.values()) + list(self._custom_entries.values()):
            text = " ".join(str(v) for v in [
                cve.get("cve_id", ""), cve.get("name", ""),
                cve.get("description", ""), cve.get("affected", ""),
            ]).lower()
            if kw in text:
                results.append(cve)
        self._query_log.append({
            "keyword": keyword, "results": len(results),
            "ts": time.strftime("%Y-%m-%d %H:%M:%S"),
        })
        return results

    def auto_correlate(self, vuln_type: str,
                       tech_stack: str = "") -> List[Dict[str, Any]]:
        """自动关联已知漏洞。

        输入漏洞类型和技术栈，自动推荐相关CVE。
        """
        correlated: List[Dict[str, Any]] = []
        cve_ids = TYPE_CVE_MAP.get(vuln_type.lower(), [])
        for cve_id in cve_ids:
            entry = self._kb.get(cve_id)
            if entry:
                correlated.append({
                    **entry,
                    "correlation_reason": f"漏洞类型 {vuln_type} 匹配 {cve_id}",
                })
        # 技术栈匹配
        if tech_stack:
            tech_lower = tech_stack.lower()
            for cve in self._kb.values():
                if tech_lower in cve.get("affected", "").lower():
                    correlated.append({
                        **cve,
                        "correlation_reason": f"技术栈 {tech_stack} 匹配受影响版本",
                    })
        self._auto_correlations.append({
            "vuln_type": vuln_type, "tech_stack": tech_stack,
            "matched": len(correlated),
            "ts": time.strftime("%Y-%m-%d %H:%M:%S"),
        })
        return correlated

    def get_exploit_info(self, cve_id: str) -> Dict[str, Any]:
        """获取Exploit-DB信息。"""
        entry = self.query_cve(cve_id)
        if not entry:
            return {"cve_id": cve_id, "found": False, "message": "知识库中未收录"}
        return {
            "cve_id": cve_id,
            "exploit_available": entry.get("exploit_available", False),
            "exploit_db_id": entry.get("exploit_db_id"),
            "exploit_db_url": (
                f"https://www.exploit-db.com/exploits/{entry['exploit_db_id']}"
                if entry.get("exploit_db_id") else None
            ),
            "references": entry.get("references", []),
            "remediation": entry.get("remediation", ""),
        }

    def list_all(self) -> List[Dict[str, Any]]:
        """列出所有知识库条目。"""
        return list(self._kb.values()) + list(self._custom_entries.values())

    def add_entry(self, entry: Dict[str, Any]) -> Dict[str, Any]:
        """添加自定义知识库条目。"""
        cve_id = entry.get("cve_id")
        if not cve_id:
            raise ValueError("entry must have cve_id")
        self._custom_entries[cve_id] = entry
        return entry

    def get_stats(self) -> Dict[str, Any]:
        return {
            "builtin_entries": len(self._kb),
            "custom_entries": len(self._custom_entries),
            "total_entries": len(self._kb) + len(self._custom_entries),
            "queries_made": len(self._query_log),
            "auto_correlations": len(self._auto_correlations),
            "types_mapped": len(TYPE_CVE_MAP),
        }

    def get_query_log(self, limit: int = 50) -> List[Dict[str, Any]]:
        return list(reversed(self._query_log[-limit:]))

    def enrich_vulnerability(self, vuln: Dict[str, Any]) -> Dict[str, Any]:
        """AI分析时自动用知识库增强漏洞信息。

        输入一个漏洞发现，自动关联相关CVE和Exploit信息。
        """
        vuln_type = (vuln.get("type") or vuln.get("vuln_type") or "").lower()
        tech = vuln.get("tech_stack", "")
        correlations = self.auto_correlate(vuln_type, tech)
        return {
            **vuln,
            "kb_enriched": True,
            "related_cves": correlations,
            "kb_enrichment_timestamp": time.strftime("%Y-%m-%d %H:%M:%S"),
        }


_singleton: Optional[VulnKnowledgeBase] = None


def get_vuln_knowledge_base() -> VulnKnowledgeBase:
    global _singleton
    if _singleton is None:
        _singleton = VulnKnowledgeBase()
    return _singleton
