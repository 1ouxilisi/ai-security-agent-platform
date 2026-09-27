# -*- coding: utf-8 -*-
"""quality_checker.py — 报告质量校验。

能力：
- 完整性检查（必填章节/必填字段）
- 数据一致性（漏洞数量前后一致/评级一致）
- 风险评级合理性 / 修复建议匹配度 / 证据充分性
- 格式规范 / 术语统一 / 查重检测 / 质量评分 0-100
"""

from __future__ import annotations

import hashlib
import re
from typing import Any, Dict, List, Tuple


REQUIRED_FIELDS = ["report_id", "client", "created_at", "overall_risk", "vulnerabilities"]
REQUIRED_SECTION_TERMS = ["执行摘要", "漏洞", "修复建议"]
TERM_BLACKLIST = {
    "vuln": "漏洞",
    "pentest": "渗透测试",
    "低危": "低风险",  # 示例：禁止中英混杂
}
SEVERITY_LEVELS = ["critical", "high", "medium", "low", "info"]


class QualityChecker:
    """对一份生成完毕的报告做质量评分。"""

    def check(self, report: Dict[str, Any],
              required_sections: List[str] | None = None) -> Dict[str, Any]:
        findings: List[Dict[str, Any]] = []
        score = 100

        # 1) 必填字段
        for f in REQUIRED_FIELDS:
            if f not in report or report[f] in (None, "", [], {}):
                findings.append({"level": "error", "item": f"缺失必填字段: {f}"})
                score -= 10

        # 2) 必填章节
        sections = report.get("sections", [])
        section_titles = [s.get("title", "") for s in sections]
        if required_sections:
            for req in required_sections:
                if not any(req in t for t in section_titles):
                    findings.append({"level": "warn", "item": f"缺少章节: {req}"})
                    score -= 4

        # 3) 数据一致性：漏洞计数
        vulns = report.get("vulnerabilities", [])
        counter = report.get("severity_counter", {})
        total_vuln = len(vulns)
        total_counter = sum(counter.values())
        if total_vuln != total_counter:
            findings.append({
                "level": "error",
                "item": f"漏洞数量不一致: 列表{total_vuln} vs 统计{total_counter}",
            })
            score -= 12

        # 4) 评级合理性
        for v in vulns:
            sev = v.get("severity", "")
            cvss = float(v.get("cvss", 0))
            expected = self._expected_severity(cvss)
            if sev in SEVERITY_LEVELS and sev != expected and sev != "info":
                findings.append({
                    "level": "warn",
                    "item": f"[{v.get('name')}] 评级 {sev} 与 CVSS {cvss} 预期 {expected} 不符",
                })
                score -= 2

        # 5) 修复建议匹配度
        no_fix = [v for v in vulns if not v.get("remediation") or "人工复核" in v["remediation"]]
        if no_fix:
            findings.append({"level": "warn", "item": f"{len(no_fix)} 个漏洞缺少具体修复建议"})
            score -= 3 * len(no_fix)

        # 6) 证据充分性
        weak_evidence = [v for v in vulns if not v.get("evidence")]
        if weak_evidence:
            findings.append({"level": "warn", "item": f"{len(weak_evidence)} 个漏洞缺少证据链"})
            score -= 2 * len(weak_evidence)

        # 7) 格式规范
        if not report.get("report_id", "").startswith("RPT-"):
            findings.append({"level": "warn", "item": "report_id 命名不符合 RPT- 规范"})
            score -= 2

        # 8) 术语统一（检测中英混杂）
        all_text = " ".join(s.get("content", "") for s in sections)
        for bad, good in TERM_BLACKLIST.items():
            if re.search(rf"\b{bad}\b", all_text, re.IGNORECASE):
                findings.append({"level": "info", "item": f"建议使用规范术语: {good}（检测到 {bad}）"})
                score -= 1

        # 9) 查重
        dup_ratio, dup_pairs = self._duplicate_ratio(vulns)
        if dup_ratio > 0.2:
            findings.append({"level": "warn", "item": f"漏洞重复率 {dup_ratio:.0%}，建议去重"})
            score -= 8

        score = max(0, min(100, score))
        grade = self._grade(score)

        return {
            "report_id": report.get("report_id"),
            "score": score,
            "grade": grade,
            "passed": score >= 70,
            "findings": findings,
            "duplicate_ratio": round(dup_ratio, 3),
            "duplicate_pairs": dup_pairs[:5],
            "summary": {
                "errors": sum(1 for f in findings if f["level"] == "error"),
                "warns": sum(1 for f in findings if f["level"] == "warn"),
                "infos": sum(1 for f in findings if f["level"] == "info"),
            },
            "checked_at": __import__("time").strftime("%Y-%m-%d %H:%M:%S"),
        }

    # ---------------- 内部 ---------------- #
    @staticmethod
    def _expected_severity(cvss: float) -> str:
        if cvss >= 9.0:
            return "critical"
        if cvss >= 7.0:
            return "high"
        if cvss >= 4.0:
            return "medium"
        return "low"

    @staticmethod
    def _grade(score: int) -> str:
        if score >= 90:
            return "A"
        if score >= 80:
            return "B"
        if score >= 70:
            return "C"
        if score >= 60:
            return "D"
        return "F"

    @staticmethod
    def _duplicate_ratio(vulns: List[Dict[str, Any]]) -> Tuple[float, List[Tuple[str, str]]]:
        seen: Dict[str, str] = {}
        pairs: List[Tuple[str, str]] = []
        dup = 0
        for v in vulns:
            h = hashlib.md5(v.get("name", "").encode("utf-8")).hexdigest()
            if h in seen:
                pairs.append((seen[h], v.get("name", "")))
                dup += 1
            else:
                seen[h] = v.get("name", "")
        ratio = dup / len(vulns) if vulns else 0.0
        return ratio, pairs


_CHECKER: QualityChecker | None = None


def get_quality_checker() -> QualityChecker:
    global _CHECKER
    if _CHECKER is None:
        _CHECKER = QualityChecker
    return _CHECKER()
