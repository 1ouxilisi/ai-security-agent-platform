# -*- coding: utf-8 -*-
"""
risk_rater.py — 云配置风险评级与修复建议（方向4）。
"""
from __future__ import annotations

from typing import Any, Dict, List


SEVERITY_WEIGHT = {"critical": 10, "high": 6, "medium": 3, "low": 1}


class RiskRater:
    """风险评级器。"""

    def rate(self, findings: List[Dict[str, Any]]) -> Dict[str, Any]:
        score = 0.0
        sev_counts = {"critical": 0, "high": 0, "medium": 0, "low": 0}
        for f in findings:
            sev = f.get("severity", "low")
            sev_counts[sev] = sev_counts.get(sev, 0) + 1
            score += SEVERITY_WEIGHT.get(sev, 0)
        # 0~100
        normalized = min(100.0, round(score * 2.5, 1))
        if normalized >= 60:
            level = "high"
        elif normalized >= 25:
            level = "medium"
        else:
            level = "low"
        return {
            "risk_score": normalized,
            "risk_level": level,
            "severity_counts": sev_counts,
            "total_findings": len(findings),
            "top_fixes": self._top_fixes(findings),
        }

    @staticmethod
    def _top_fixes(findings: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        seen: Dict[str, str] = {}
        out: List[Dict[str, Any]] = []
        for f in findings:
            rid = f.get("rule_id", "")
            if rid in seen:
                continue
            seen[rid] = rid
            out.append({
                "rule_id": rid,
                "title": f.get("title"),
                "severity": f.get("severity"),
                "fix": f.get("fix"),
            })
            if len(out) >= 10:
                break
        return out

    @staticmethod
    def remediation_template(rule_id: str) -> Dict[str, Any]:
        return {
            "rule_id": rule_id,
            "steps": [
                "1. 在控制台或 Terraform 定位资源",
                "2. 修改配置",
                "3. 用 cloud-deep 重新扫描验证",
            ],
        }
