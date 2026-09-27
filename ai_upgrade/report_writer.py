# -*- coding: utf-8 -*-
"""
ai_upgrade/report_writer.py — 报告自动生成

AI 根据扫描结果生成自然语言渗透测试报告。真实 LLM 可用时由模型撰写叙述段落；
否则用模板引擎拼装专业报告（执行摘要 / 发现明细 / 风险评级 / 修复建议 / 附录）。
"""
from __future__ import annotations

import time
import uuid
from typing import Any, Dict, List, Optional

from .llm_integration import get_enhanced_llm
from .vuln_analyzer import get_vuln_analyzer

# 报告存储（内存字典模拟）
REPORTS: Dict[str, Dict[str, Any]] = {}


_LEVEL_CN = {"critical": "严重", "high": "高危", "medium": "中危",
             "low": "低危", "info": "信息"}
_LEVEL_COLOR = {"critical": "#f85149", "high": "#ff9800", "medium": "#ffd33d",
                "low": "#58a6ff", "info": "#8b949e"}


def _rule_executive_summary(target: str, agg: Dict[str, Any]) -> str:
    sc = agg["severity_count"]
    total = agg["total"]
    parts = [f"本次对目标「{target}」共发现 {total} 个安全问题，其中："]
    for k in ("critical", "high", "medium", "low", "info"):
        if sc.get(k):
            parts.append(f"{_LEVEL_CN[k]} {sc[k]} 个")
    tail = "；".join(parts[1:]) if len(parts) > 1 else "未发现明显安全问题"
    parts[-1] = parts[-1] + "。" if len(parts) > 1 else parts[-1]
    summary = parts[0] + tail + "。"
    if sc.get("critical") or sc.get("high"):
        summary += (" 综合评估：目标存在可被远程利用的高危风险，建议在 72 小时内"
                    "完成高危项修复并复测。")
    elif sc.get("medium"):
        summary += " 综合评估：目标存在中等风险，建议在两周内排期修复。"
    else:
        summary += " 综合评估：整体安全态势良好，保持常规巡检即可。"
    return summary


class ReportWriter:
    """自然语言报告生成器。"""

    def generate(self, target: str, vulns: List[Dict[str, Any]],
                 author: str = "AI 渗透助手",
                 template: str = "standard") -> Dict[str, Any]:
        analyzer = get_vuln_analyzer()
        agg = analyzer.analyze_batch(vulns)
        el = get_enhanced_llm()

        exec_summary = _rule_executive_summary(target, agg)
        engine = "rule"

        # 尝试用 LLM 润色执行摘要
        sys_p = ("你是安全报告撰写专家。根据扫描统计数据，用一段专业、客观、"
                 "150 字以内的中文执行摘要总结本次渗透测试结论。")
        user_p = (f"目标：{target}\n统计：{agg['severity_count']}\n"
                  f"最高风险：{agg['top_risk']}\n请写执行摘要。")
        r = el.chat(sys_p, user_p, rule_fallback="", task="report_writing",
                    max_tokens=300)
        if r["engine"] == "llm" and r["content"]:
            exec_summary = r["content"]
            engine = "llm"

        # 明细表
        findings = []
        for i, it in enumerate(agg["items"], 1):
            findings.append({
                "no": i,
                "name": it["name"],
                "severity": it["severity"],
                "severity_cn": _LEVEL_CN.get(it["severity"], it["severity"]),
                "cvss": it["cvss_score"],
                "cwe": it["cwe"],
                "exploit": it["exploit_advice"],
                "fix": it["fix_advice"],
            })

        rid = uuid.uuid4().hex[:12]
        report = {
            "report_id": rid,
            "target": target,
            "author": author,
            "template": template,
            "generated_at": time.strftime("%Y-%m-%d %H:%M:%S"),
            "engine": engine,
            "overview": {
                "total": agg["total"],
                "severity_count": agg["severity_count"],
                "top_risk": agg["top_risk"],
                "priority_order": agg["priority_order"],
            },
            "executive_summary": exec_summary,
            "findings": findings,
            "appendix": {
                "methodology": "信息收集 -> 漏洞探测 -> 智能分析 -> 优先级排序",
                "disclaimer": "本报告仅用于授权范围内的安全测试。",
            },
        }
        REPORTS[rid] = report
        return report

    def list_reports(self) -> List[Dict[str, Any]]:
        return [{"report_id": r["report_id"], "target": r["target"],
                 "generated_at": r["generated_at"],
                 "total": r["overview"]["total"],
                 "top_risk": r["overview"]["top_risk"],
                 "engine": r["engine"]}
                for r in sorted(REPORTS.values(),
                                key=lambda x: x["generated_at"], reverse=True)]

    def get_report(self, rid: str) -> Optional[Dict[str, Any]]:
        return REPORTS.get(rid)

    def export_markdown(self, rid: str) -> Optional[str]:
        r = REPORTS.get(rid)
        if not r:
            return None
        lines = [f"# 渗透测试报告 — {r['target']}", ""]
        lines.append(f"- 生成时间：{r['generated_at']}")
        lines.append(f"- 报告引擎：{r['engine']}")
        lines.append(f"- 发现总数：{r['overview']['total']}")
        lines.append("")
        lines.append("## 执行摘要")
        lines.append(r["executive_summary"])
        lines.append("")
        lines.append("## 风险统计")
        for k, v in r["overview"]["severity_count"].items():
            lines.append(f"- {_LEVEL_CN.get(k, k)}：{v}")
        lines.append("")
        lines.append("## 漏洞明细")
        for f in r["findings"]:
            lines.append(f"### {f['no']}. {f['name']} "
                         f"[{f['severity_cn']} / CVSS {f['cvss']}]")
            lines.append(f"- 利用建议：{f['exploit']}")
            lines.append(f"- 修复建议：{f['fix']}")
            lines.append("")
        return "\n".join(lines)


_singleton: Optional[ReportWriter] = None


def get_report_writer() -> ReportWriter:
    global _singleton
    if _singleton is None:
        _singleton = ReportWriter()
    return _singleton
