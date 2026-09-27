#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
报告数据规范化工具 - 将不同来源的评估数据统一为导出器可用的结构
"""
from typing import Any, Dict, List


# 严重程度映射（统一为 critical/high/medium/low/info）
SEVERITY_ORDER = ["critical", "high", "medium", "low", "info"]

SEVERITY_LABELS_ZH = {
    "critical": "严重",
    "high": "高危",
    "medium": "中危",
    "low": "低危",
    "info": "信息",
}

SEVERITY_LABELS_EN = {
    "critical": "Critical",
    "high": "High",
    "medium": "Medium",
    "low": "Low",
    "info": "Info",
}

# 严重程度颜色（统一 RGB 0-255）
SEVERITY_RGB = {
    "critical": (0xDC, 0x26, 0x26),
    "high": (0xEA, 0x58, 0x0C),
    "medium": (0xCA, 0x8A, 0x04),
    "low": (0x25, 0x63, 0xEB),
    "info": (0x6B, 0x72, 0x80),
}

SEVERITY_HEX = {
    "critical": "#DC2626",
    "high": "#EA580C",
    "medium": "#CA8A04",
    "low": "#2563EB",
    "info": "#6B7280",
}

_SEV_ALIAS = {
    "critical": "critical", "crit": "critical", "严重": "critical", "严重漏洞": "critical",
    "high": "high", "高危": "high", "高": "high",
    "medium": "medium", "med": "medium", "中危": "medium", "中": "medium",
    "low": "low", "低危": "low", "低": "low",
    "info": "info", "informational": "info", "信息": "info", "info级别": "info",
}


def normalize_severity(value: Any) -> str:
    """把任意严重程度取值归一化到 critical/high/medium/low/info"""
    if value is None:
        return "info"
    if isinstance(value, dict):
        value = value.get("value") or value.get("label") or ""
    s = str(value).strip().lower()
    return _SEV_ALIAS.get(s, "info")


def normalize_findings(raw: Any) -> List[Dict[str, Any]]:
    """将漏洞列表归一化为标准结构

    兼容:
    - Finding.to_dict() 的字典
    - 直接传入的 dict 列表
    - 嵌套在 domain_results 中的 findings
    """
    findings: List[Dict[str, Any]] = []

    # 如果传入的是整个评估结果 dict，尝试从中抽取
    if isinstance(raw, dict):
        # 优先 all_findings / findings
        for key in ("all_findings", "findings"):
            if isinstance(raw.get(key), list):
                raw = raw[key]
                break
        else:
            # 从 domain_results 里聚合
            collected: List[Any] = []
            for da in raw.get("domain_results", {}).values():
                if isinstance(da, dict) and isinstance(da.get("findings"), list):
                    collected.extend(da["findings"])
            raw = collected

    if not isinstance(raw, list):
        return findings

    for item in raw:
        if not isinstance(item, dict):
            continue
        sev = normalize_severity(item.get("severity"))
        title = (
            item.get("title")
            or item.get("name")
            or item.get("vuln_name")
            or "未命名漏洞"
        )
        # CVE: 优先 cve 字段，其次从 cwe/extra 里取
        cve = item.get("cve") or item.get("cve_id") or ""
        if not cve:
            extra = item.get("extra") or {}
            if isinstance(extra, dict):
                cve = extra.get("cve") or ""
        rec = (
            item.get("recommendation")
            or item.get("remediation")
            or item.get("fix")
            or ""
        )
        findings.append({
            "id": item.get("id") or "",
            "cve": cve,
            "title": str(title),
            "severity": sev,
            "severity_label": SEVERITY_LABELS_ZH[sev],
            "category": item.get("category") or item.get("type") or "",
            "description": item.get("description") or "",
            "location": item.get("location") or item.get("target") or "",
            "evidence": item.get("evidence") or "",
            "cwe": item.get("cwe") or "",
            "owasp": item.get("owasp") or "",
            "cvss": item.get("cvss") or 0,
            "recommendation": str(rec),
            "status": item.get("status") or "未修复",
            "detected_at": item.get("detected_at") or 0,
            "target": item.get("target") or "",
        })

    # 按严重程度排序
    order = {s: i for i, s in enumerate(SEVERITY_ORDER)}
    findings.sort(key=lambda f: order.get(f["severity"], 99))
    return findings


def normalize_ports(raw: Any) -> List[Dict[str, Any]]:
    """归一化端口列表"""
    ports: List[Dict[str, Any]] = []
    if isinstance(raw, dict):
        for key in ("ports", "open_ports", "port_list"):
            if isinstance(raw.get(key), list):
                raw = raw[key]
                break
        else:
            raw = []

    if not isinstance(raw, list):
        return ports

    for item in raw:
        if isinstance(item, dict):
            ports.append({
                "port": item.get("port") or item.get("port_number") or "",
                "protocol": item.get("protocol") or item.get("proto") or "tcp",
                "service": item.get("service") or item.get("name") or "",
                "version": item.get("version") or item.get("product") or "",
                "status": item.get("status") or "open",
            })
        elif isinstance(item, (int, str)):
            ports.append({
                "port": item, "protocol": "tcp",
                "service": "", "version": "", "status": "open",
            })

    # 按端口号排序
    def _p(p: Dict[str, Any]) -> int:
        try:
            return int(str(p["port"]).split("/")[0])
        except (ValueError, TypeError):
            return 99999
    ports.sort(key=_p)
    return ports


def normalize_assessment(raw: Any) -> Dict[str, Any]:
    """将任意评估数据归一化为统一结构"""
    data: Dict[str, Any] = {}
    if isinstance(raw, dict):
        data = dict(raw)
    else:
        # 可能是 UnifiedAssessmentResult 对象
        to_dict = getattr(raw, "to_dict", None)
        if callable(to_dict):
            try:
                data = to_dict()
            except Exception:
                data = {}

    findings = normalize_findings(data)
    ports = normalize_ports(data.get("ports") or data.get("raw_output") or {})

    return {
        "assessment_id": data.get("assessment_id") or data.get("id") or "",
        "target": data.get("target") or "",
        "assessment_type": data.get("assessment_type") or data.get("task_type") or "pentest",
        "started_at": data.get("started_at") or data.get("created_at") or 0,
        "completed_at": data.get("completed_at") or 0,
        "duration": data.get("duration") or 0,
        "overall_risk_score": data.get("overall_risk_score") or 0,
        "overall_risk_level": data.get("overall_risk_level") or "未评估",
        "executive_summary": data.get("executive_summary") or "",
        "key_findings": data.get("key_findings") or [],
        "recommendations": data.get("recommendations") or [],
        "findings": findings,
        "ports": ports,
        "tools_used": data.get("tools_used") or [],
        "checks_run": data.get("checks_run") or [],
        "metadata": data.get("metadata") or {},
    }


def severity_counts(findings: List[Dict[str, Any]]) -> Dict[str, int]:
    """统计各严重程度数量"""
    counts = {s: 0 for s in SEVERITY_ORDER}
    for f in findings:
        sev = f.get("severity", "info")
        counts[sev] = counts.get(sev, 0) + 1
    return counts
