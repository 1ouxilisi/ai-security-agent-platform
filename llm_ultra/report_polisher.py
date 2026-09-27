# -*- coding: utf-8 -*-
"""report_polisher.py — 报告润色。

AI自动润色报告，让报告更专业，语言风格统一。
支持：格式规范化、语言润色、风格统一、质量检查。
"""
from __future__ import annotations

import re
import time
from typing import Any, Dict, List, Optional


# 润色规则
POLISH_RULES: Dict[str, Dict[str, str]] = {
    "professionalize": {
        "name": "专业术语规范化",
        "description": "将口语化表达替换为专业安全术语",
        "replacements": {
            "被黑了": "遭受未授权访问",
            "被脱库了": "数据库信息泄露",
            "网站有漏洞": "应用程序存在安全弱点",
            "可以进后台": "存在未授权管理面板访问",
            "拿到shell了": "获得远程代码执行能力",
            "被搞了": "遭遇安全事件",
        },
    },
    "format_standardize": {
        "name": "格式标准化",
        "description": "统一报告格式：标题层级、表格、列表",
        "rules": [
            "确保所有标题使用Markdown标准格式 (# ## ###)",
            "严重级别统一使用: Critical/High/Medium/Low",
            "漏洞描述先一句话概括，再展开技术细节",
            "修复建议按优先级排序（P0/P1/P2）",
        ],
    },
    "tone_professional": {
        "name": "语气专业化",
        "description": "去除情绪化表达，保持客观中立",
        "patterns": [
            r"(?i)(简直|太可怕|太严重|超级|非常严重)",
            r"(?i)(必须马上|立刻马上|赶紧)",
        ],
        "replacements": [
            "存在较高风险",
            "建议优先处理",
        ],
    },
}

# 报告质量检查项
QUALITY_CHECKS: List[Dict[str, str]] = [
    {"id": "has_exec_summary", "check": "是否包含执行摘要",
     "pattern": r"(?i)(执行摘要|executive summary|概述)?"},
    {"id": "has_scope", "check": "是否包含测试范围",
     "pattern": r"(?i)(测试范围|scope|目标资产)"},
    {"id": "has_severity", "check": "是否有严重级别标注",
     "pattern": r"(?i)(critical|high|medium|low|严重|高危|中危|低危)"},
    {"id": "has_remediation", "check": "是否包含修复建议",
     "pattern": r"(?i)(修复|建议|remediation|patch|fix)"},
    {"id": "has_evidence", "check": "是否包含验证证据",
     "pattern": r"(?i)(证据|验证|evidence|proof|poc)"},
]


class ReportPolisher:
    """报告润色引擎：自动优化报告质量。"""

    def __init__(self) -> None:
        self._rules = {k: dict(v) for k, v in POLISH_RULES.items()}
        self._polish_history: List[Dict[str, Any]] = []
        self._stats: Dict[str, int] = {
            "total_polished": 0,
            "words_replaced": 0,
            "format_issues_fixed": 0,
        }

    def polish(self, report_content: str,
               report_type: str = "generic") -> Dict[str, Any]:
        """润色一份报告。

        流程：
        1. 专业术语替换
        2. 语气规范化
        3. 格式检查与标准化建议
        4. 质量评分
        """
        original = report_content
        polished = report_content
        changes: List[Dict[str, str]] = []

        # 1. 术语替换
        prof_rule = self._rules.get("professionalize", {})
        for old, new in prof_rule.get("replacements", {}).items():
            if old in polished:
                polished = polished.replace(old, new)
                changes.append({
                    "rule": "professionalize",
                    "original": old,
                    "replacement": new,
                })
                self._stats["words_replaced"] += 1

        # 2. 语气规范化
        tone_rule = self._rules.get("tone_professional", {})
        for i, pat in enumerate(tone_rule.get("patterns", [])):
            repl = tone_rule.get("replacements", [""])[min(i, 1)]
            polished = re.sub(pat, repl, polished)

        # 3. 质量检查
        quality = self.quality_check(polished)

        # 4. 格式建议
        format_suggestions = self._suggest_format_improvements(polished)

        result = {
            "original_length": len(original),
            "polished_length": len(polished),
            "changes_made": changes,
            "quality_score": quality["score"],
            "quality_grade": quality["grade"],
            "quality_checks": quality["checks"],
            "format_suggestions": format_suggestions,
            "polished_content": polished,
            "report_type": report_type,
            "polished_at": time.strftime("%Y-%m-%d %H:%M:%S"),
        }
        self._polish_history.append(result)
        self._stats["total_polished"] += 1
        return result

    def quality_check(self, content: str) -> Dict[str, Any]:
        """报告质量检查。"""
        checks = []
        passed = 0
        for chk in QUALITY_CHECKS:
            found = bool(re.search(chk["pattern"], content))
            checks.append({
                "id": chk["id"],
                "name": chk["check"],
                "passed": found,
            })
            if found:
                passed += 1
        score = round(passed / len(QUALITY_CHECKS) * 100, 1)
        return {
            "score": score,
            "checks": checks,
            "passed_count": passed,
            "total_checks": len(QUALITY_CHECKS),
            "grade": "A" if score >= 90 else "B" if score >= 70
                     else "C" if score >= 50 else "D",
        }

    def _suggest_format_improvements(self, content: str) -> List[str]:
        """格式改进建议。"""
        suggestions = []
        if not re.search(r"^# ", content, re.MULTILINE):
            suggestions.append("建议添加一级标题（# 标题）")
        if not re.search(r"\|.*\|", content):
            suggestions.append("建议使用表格汇总漏洞列表")
        if not re.search(r"(?i)(修复|remediation)", content):
            suggestions.append("建议添加修复建议章节")
        if len(content.split("\n")) < 20:
            suggestions.append("报告内容较短，建议补充技术细节")
        return suggestions

    def standardize_vuln_entry(self, entry: Dict[str, Any]) -> Dict[str, Any]:
        """标准化单个漏洞条目的格式。"""
        standardized = {
            "id": entry.get("id", f"VULN-{self._stats['total_polished'] + 1}"),
            "name": entry.get("name", "未命名漏洞"),
            "severity": (entry.get("severity") or "medium").capitalize(),
            "cvss": entry.get("cvss", "N/A"),
            "description": entry.get("description", entry.get("detail", "")),
            "location": entry.get("url", entry.get("location", "")),
            "impact": entry.get("impact", ""),
            "remediation": entry.get("remediation", entry.get("fix", "")),
            "confidence": entry.get("confidence_level", "unknown"),
        }
        return standardized

    def generate_executive_summary(self, vulns: List[Dict[str, Any]],
                                    target: str = "") -> str:
        """自动生成执行摘要。"""
        total = len(vulns)
        critical = sum(1 for v in vulns
                       if (v.get("severity") or "").lower() == "critical")
        high = sum(1 for v in vulns
                   if (v.get("severity") or "").lower() == "high")
        medium = sum(1 for v in vulns
                     if (v.get("severity") or "").lower() == "medium")
        low = sum(1 for v in vulns
                  if (v.get("severity") or "").lower() == "low")

        lines = [
            f"本次安全评估针对 {target or '目标系统'} 共发现 {total} 个安全问题。",
            f"其中：严重(Critical) {critical} 个、高危(High) {high} 个、"
            f"中危(Medium) {medium} 个、低危(Low) {low} 个。",
        ]
        if critical > 0 or high > 0:
            lines.append(
                f"整体风险等级为{'高' if critical > 0 else '中'}，"
                f"建议{'立即' if critical > 0 else '优先'}处理"
                f"{critical + high}个高危及以上漏洞。"
            )
        else:
            lines.append("整体风险可控，建议按计划修复中低危漏洞。")
        return "\n".join(lines)

    def get_polish_rules(self) -> Dict[str, Any]:
        return {
            "rules": self._rules,
            "quality_checks": QUALITY_CHECKS,
        }

    def get_stats(self) -> Dict[str, Any]:
        return {
            **self._stats,
            "history_count": len(self._polish_history),
        }

    def get_history(self, limit: int = 20) -> List[Dict[str, Any]]:
        return list(reversed(self._polish_history[-limit:]))


_singleton: Optional[ReportPolisher] = None


def get_report_polisher() -> ReportPolisher:
    global _singleton
    if _singleton is None:
        _singleton = ReportPolisher()
    return _singleton
