# -*- coding: utf-8 -*-
"""
report_validator.py — 真实报告验证。

用真实扫描结果生成报告，按维度评分：完整性/准确性/可读性/专业性，
每项 1-10 分，总分 100。含人工评审模板与质量趋势。
"""

from __future__ import annotations

import time
from typing import Any, Dict, List, Optional

# 评分维度（每项权重*10 -> 总分100）
DIMENSIONS: List[Dict[str, Any]] = [
    {"id": "completeness", "name": "报告完整性", "weight": 25,
     "checks": ["封面", "执行摘要", "风险发现", "修复建议", "附录"]},
    {"id": "accuracy", "name": "报告准确性", "weight": 25,
     "checks": ["漏洞描述准确", "复现步骤可复现", "修复建议可行"]},
    {"id": "readability", "name": "报告可读性", "weight": 25,
     "checks": ["排版整洁", "图表辅助", "语言表达清晰"]},
    {"id": "professionalism", "name": "报告专业性", "weight": 25,
     "checks": ["术语规范", "结构严谨", "格式统一"]},
]


class ReportValidator:
    """报告质量验证器。"""

    def list_dimensions(self) -> List[Dict[str, Any]]:
        return DIMENSIONS

    def validate_report(self, report_text: str,
                       report_meta: Optional[Dict[str, Any]] = None
                       ) -> Dict[str, Any]:
        """对一份报告文本做质量评分（基于规则启发式）。"""
        text = report_text or ""
        lower = text.lower()
        scores: Dict[str, int] = {}
        detail: Dict[str, Any] = {}

        for dim in DIMENSIONS:
            passed = sum(1 for c in dim["checks"]
                         if self._check(c, text, lower))
            ratio = passed / len(dim["checks"])
            # 1-10 分
            score = max(1, round(ratio * 10))
            scores[dim["id"]] = score
            detail[dim["id"]] = {"name": dim["name"], "score": score,
                                 "passed": passed,
                                 "total_checks": len(dim["checks"])}

        total = sum(round(scores[d["id"]] * d["weight"] / 10) for d in DIMENSIONS)
        return {
            "ok": True, "scores": scores, "total": total,
            "grade": self._grade(total), "detail": detail,
            "meta": report_meta or {},
            "checked_at": time.strftime("%Y-%m-%d %H:%M:%S"),
            "word_count": len(text),
        }

    @staticmethod
    def _check(check: str, text: str, lower: str) -> bool:
        rules = {
            "封面": len(text) > 200,
            "执行摘要": "执行摘要" in text or "executive" in lower,
            "风险发现": "风险" in text or "漏洞" in text or "vuln" in lower,
            "修复建议": "修复" in text or "建议" in text or "remediation" in lower,
            "附录": "附录" in text or "appendix" in lower,
            "漏洞描述准确": "CVE" in text or "CVSS" in text,
            "复现步骤可复现": "步骤" in text or "reproduce" in lower or "1." in text,
            "修复建议可行": any(k in text for k in ["升级", "禁用", "配置", "patch"]),
            "排版整洁": text.count("##") >= 3 or text.count("<h2") >= 3,
            "图表辅助": "图" in text or "chart" in lower or "表" in text,
            "语言表达清晰": len(text.splitlines()) >= 10,
            "术语规范": any(k in text for k in ["CVSS", "ATT&CK", "OWASP", "MITRE"]),
            "结构严谨": text.count("##") >= 4,
            "格式统一": text.count("|") >= 6 or text.count("<td") >= 6,
        }
        return rules.get(check, False)

    @staticmethod
    def _grade(total: int) -> str:
        if total >= 90:
            return "A 优秀"
        if total >= 80:
            return "B 良好"
        if total >= 70:
            return "C 合格"
        if total >= 60:
            return "D 待改进"
        return "E 不合格"

    def human_review_template(self) -> Dict[str, Any]:
        return {
            "title": "报告质量人工评审模板",
            "dimensions": DIMENSIONS,
            "scale": "每项 1-10 分，总分 100",
            "questions": [
                "漏洞描述是否与实际扫描结果一致？",
                "复现步骤是否可独立复现？",
                "修复建议是否可落地？",
                "是否存在误导性或夸大描述？",
            ],
        }

    def trend(self, history: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        return history[-20:]


_validator: Optional[ReportValidator] = None


def get_report_validator() -> ReportValidator:
    global _validator
    if _validator is None:
        _validator = ReportValidator()
    return _validator
