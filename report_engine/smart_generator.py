# -*- coding: utf-8 -*-
"""smart_generator.py — 智能报告生成。

能力：
- 数据自动填充（从扫描结果/漏洞库/资产库提取）
- 漏洞描述智能生成 / 风险评级自动计算 / 修复建议匹配
- 执行摘要生成 / 图表自动生成（风险分布/趋势/Top漏洞）
- 证据链组织 / AI 辅助撰写提示
"""

from __future__ import annotations

import hashlib
import time
import uuid
from typing import Any, Dict, List, Optional


# --------------------------------------------------------------------------- #
# 漏洞库内置样例（用于自动匹配描述与修复建议）
# --------------------------------------------------------------------------- #
VULN_KB: List[Dict[str, Any]] = [
    {
        "cve_id": "CVE-2021-44228", "name": "Log4Shell 远程代码执行",
        "severity": "critical", "cvss": 10.0,
        "description": "Apache Log4j2 存在 JNDI 注入漏洞，攻击者可通过构造恶意日志条目远程加载任意代码。",
        "remediation": "升级 Log4j2 至 2.17.1 及以上；临时移除 JndiLookup 类；开启 jndi 协议限制。",
        "category": "rce",
    },
    {
        "cve_id": "CVE-2017-5638", "name": "Struts2 S2-045 远程代码执行",
        "severity": "critical", "cvss": 10.0,
        "description": "Jakarta Multipart parser 错误处理允许 OGNL 表达式注入，导致 RCE。",
        "remediation": "升级 Struts 至 2.3.32 / 2.5.10.1；禁用未使用的 Struts 插件。",
        "category": "rce",
    },
    {
        "cve_id": "CVE-2014-0160", "name": "Heartbleed 心脏滴血",
        "severity": "high", "cvss": 7.5,
        "description": "OpenSSL 心跳扩展未正确验证扩展长度，泄露内存敏感数据。",
        "remediation": "升级 OpenSSL 至 1.0.1g；轮换受影响证书与密钥。",
        "category": "info_leak",
    },
    {
        "cve_id": "CVE-2019-11043", "name": "PHP-FPM RCE",
        "severity": "high", "cvss": 9.8,
        "description": "特定 Nginx + PHP-FPM 配置下可通过 URL 触发代码执行。",
        "remediation": "升级 PHP 至 7.2.24+；修正 Nginx try_files 配置。",
        "category": "rce",
    },
    {
        "cve_id": "SQLI-GEN-001", "name": "SQL 注入",
        "severity": "high", "cvss": 8.6,
        "description": "用户输入未参数化拼接 SQL，导致未授权数据读取/写入。",
        "remediation": "使用参数化查询/ORM；最小权限数据库账号；WAF 拦截。",
        "category": "sqli",
    },
    {
        "cve_id": "XSS-GEN-001", "name": "反射型 XSS",
        "severity": "medium", "cvss": 6.1,
        "description": "未对用户输入输出做编码，攻击者可注入脚本窃取会话。",
        "remediation": "输出编码 + CSP；HttpOnly Cookie；过滤特殊字符。",
        "category": "xss",
    },
    {
        "cve_id": "MISCONF-001", "name": "目录遍历/未授权访问",
        "severity": "medium", "cvss": 5.3,
        "description": "Web 服务器暴露备份文件、.git、管理后台。",
        "remediation": "关闭目录浏览；删除敏感备份；访问控制。",
        "category": "misconfig",
    },
    {
        "cve_id": "WEAKCRYPT-001", "name": "弱加密/明文传输",
        "severity": "medium", "cvss": 5.9,
        "description": "使用 TLS1.0/1.1 或明文 HTTP 传输敏感数据。",
        "remediation": "强制 TLS1.2+；HSTS；禁用旧套件。",
        "category": "crypto",
    },
]


def _match_kb(scan_vuln: Dict[str, Any]) -> Dict[str, Any]:
    """根据扫描结果匹配知识库。"""
    text = " ".join(str(scan_vuln.get(k, "")) for k in ("name", "cve_id", "title", "desc", "category")).lower()
    for kb in VULN_KB:
        if kb["cve_id"] and kb["cve_id"].lower() in text:
            return kb
        if kb["name"].lower() in text:
            return kb
    # 默认兜底
    return {
        "cve_id": scan_vuln.get("cve_id", "CUSTOM-0000"),
        "name": scan_vuln.get("name", scan_vuln.get("title", "未命名漏洞")),
        "severity": scan_vuln.get("severity", "medium"),
        "cvss": float(scan_vuln.get("cvss", 5.0)),
        "description": scan_vuln.get("desc", "未提供描述，需人工复核"),
        "remediation": "建议人工复核并参照行业最佳实践进行修复。",
        "category": scan_vuln.get("category", "unknown"),
    }


def auto_risk_level(score: float) -> str:
    if score >= 9.0:
        return "critical"
    if score >= 7.0:
        return "high"
    if score >= 4.0:
        return "medium"
    return "low"


class SmartGenerator:
    """智能报告生成器。"""

    def __init__(self) -> None:
        self.reports: Dict[str, Dict[str, Any]] = {}

    # ---------------- 主入口 ---------------- #
    def generate(self, template: Dict[str, Any],
                 scan_results: List[Dict[str, Any]],
                 assets: List[Dict[str, Any]],
                 meta: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
        meta = meta or {}
        rid = f"RPT-{uuid.uuid4().hex[:10].upper()}"

        # 1) 漏洞智能增强
        enriched_vulns: List[Dict[str, Any]] = []
        for v in scan_results:
            kb = _match_kb(v)
            sev = kb["severity"]
            enriched_vulns.append({
                "id": f"V-{len(enriched_vulns)+1:03d}",
                "cve_id": kb["cve_id"],
                "name": kb["name"],
                "severity": sev,
                "cvss": kb["cvss"],
                "description": kb["description"],
                "remediation": kb["remediation"],
                "category": kb["category"],
                "asset": v.get("asset", v.get("host", "未知资产")),
                "evidence": v.get("evidence", []),
            })

        # 2) 风险分布
        severity_counter = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
        for v in enriched_vulns:
            severity_counter[v["severity"]] = severity_counter.get(v["severity"], 0) + 1

        # 3) Top 漏洞
        top_vulns = sorted(enriched_vulns, key=lambda x: (-x["cvss"], x["severity"]))[:10]

        # 4) 执行摘要
        exec_summary = self._exec_summary(meta, assets, severity_counter, top_vulns)

        # 5) 图表数据
        charts = {
            "severity_distribution": severity_counter,
            "top_vulns": [{"name": v["name"], "cvss": v["cvss"], "severity": v["severity"]} for v in top_vulns],
            "asset_coverage": {"total_assets": len(assets), "scanned": len({a.get("ip", a.get("host")) for a in assets})},
        }

        # 6) 证据链
        evidence_chain = [
            {"vuln_id": v["id"], "steps": v["evidence"] or ["未提供证据，需补截图/日志"]}
            for v in enriched_vulns
        ]

        # 7) 章节填充
        sections = []
        for sec in template.get("required_sections", []):
            sections.append({
                "title": sec,
                "content": self._fill_section(sec, enriched_vulns, assets, severity_counter, meta),
            })

        report = {
            "report_id": rid,
            "template_id": template["template_id"],
            "template_name": template["name"],
            "client": meta.get("client", "某客户"),
            "project": meta.get("project", "安全评估项目"),
            "author": meta.get("author", "安全团队"),
            "created_at": time.strftime("%Y-%m-%d %H:%M:%S"),
            "meta": meta,
            "assets": assets,
            "vulnerabilities": enriched_vulns,
            "severity_counter": severity_counter,
            "executive_summary": exec_summary,
            "charts": charts,
            "evidence_chain": evidence_chain,
            "sections": sections,
            "ai_prompts": self._ai_prompts(template, enriched_vulns, meta),
            "overall_risk": auto_risk_level(
                max([v["cvss"] for v in enriched_vulns] or [0.0])
            ),
        }
        self.reports[rid] = report
        return report

    # ---------------- 内部 ---------------- #
    def _exec_summary(self, meta: Dict[str, Any], assets: List[Dict[str, Any]],
                      counter: Dict[str, int], top_vulns: List[Dict[str, Any]]) -> str:
        total = sum(counter.values())
        critical = counter.get("critical", 0)
        high = counter.get("high", 0)
        return (
            f"{meta.get('client', '某客户')} 于 {time.strftime('%Y-%m')} 开展 {meta.get('project', '安全评估')}，"
            f"共覆盖 {len(assets)} 项资产，发现 {total} 项安全问题，"
            f"其中严重 {critical} 项、高危 {high} 项。"
            f"最严重问题为「{top_vulns[0]['name'] if top_vulns else '无'}」，"
            f"建议优先处置 critical/high 级别漏洞并在 30 日内完成复测。"
        )

    def _fill_section(self, section: str, vulns: List[Dict[str, Any]],
                      assets: List[Dict[str, Any]],
                      counter: Dict[str, int], meta: Dict[str, Any]) -> str:
        total = sum(counter.values())
        if "执行摘要" in section:
            return self._exec_summary(meta, assets, counter, vulns)
        if "范围" in section or "资产" in section:
            return f"本次评估覆盖 {len(assets)} 项资产，主要包括：" + \
                   "；".join(f"{a.get('ip', a.get('host', '主机'))}({a.get('os', a.get('type', '未知'))})"
                             for a in assets[:10])
        if "漏洞" in section:
            lines = [f"共发现 {total} 项漏洞："]
            for v in sorted(vulns, key=lambda x: -x["cvss"])[:20]:
                lines.append(f"- [{v['severity'].upper()}] {v['name']} ({v['cve_id']}) — {v['asset']}")
            return "\n".join(lines)
        if "修复" in section:
            seen = set()
            lines = []
            for v in vulns:
                if v["remediation"] not in seen:
                    seen.add(v["remediation"])
                    lines.append(f"- {v['remediation']}")
            return "\n".join(lines) or "暂无修复建议"
        if "附录" in section:
            return f"附录 A：CVE 编号映射表；附录 B：证据截图 {len(vulns)} 项。"
        return f"【{section}】需根据项目实际情况补充。"

    def _ai_prompts(self, template: Dict[str, Any], vulns: List[Dict[str, Any]],
                    meta: Dict[str, Any]) -> List[str]:
        sev = sum(1 for v in vulns if v["severity"] in ("critical", "high"))
        return [
            f"请以资深安全顾问口吻扩写执行摘要：客户 {meta.get('client','某客户')} 共发现 {len(vulns)} 项问题，其中高危及以上 {sev} 项。",
            f"请为模板「{template['name']}」撰写一份 800 字的项目背景介绍。",
            "请将下列漏洞列表改写为面向 CTO 的非技术语言版本，强调业务影响。",
            "请基于合规框架 " + "、".join(template.get("compliance_refs", [])) + " 生成差距分析段落。",
        ]

    # ---------------- 读取 ---------------- #
    def get(self, report_id: str) -> Optional[Dict[str, Any]]:
        return self.reports.get(report_id)

    def list_reports(self) -> List[Dict[str, Any]]:
        return [
            {k: v for k, v in r.items() if k not in ("vulnerabilities", "sections", "evidence_chain")}
            for r in self.reports.values()
        ]


_GEN: Optional[SmartGenerator] = None


def get_smart_generator() -> SmartGenerator:
    global _GEN
    if _GEN is None:
        _GEN = SmartGenerator()
    return _GEN
