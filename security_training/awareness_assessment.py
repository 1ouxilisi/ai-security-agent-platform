# -*- coding: utf-8 -*-
"""
awareness_assessment.py — 安全意识评估（第14轮·方向2）。

意识测评问卷（100+题）、风险行为评估、部门对比、个人评分0-100、
薄弱环节识别、改进建议、趋势分析、合规报告（等保/ISO27001 培训要求）。
"""

from __future__ import annotations

import time
from typing import Any, Dict, List, Optional

_DOMAINS = [
    ("password", "口令与账号安全"),
    ("phishing", "钓鱼与邮件识别"),
    ("data", "数据与信息处理"),
    ("device", "终端与设备安全"),
    ("social", "社会工程防范"),
    ("physical", "物理与办公安全"),
    ("compliance", "合规与制度意识"),
    ("incident", "事件上报意识"),
]


def _build_questionnaire() -> List[Dict[str, Any]]:
    qs = []
    qid = 1
    # 每个领域 13 题 → 104 题
    for did, (key, name) in enumerate(_DOMAINS, 1):
        for k in range(13):
            qs.append({
                "qid": f"A{qid:03d}", "domain": key, "domain_name": name,
                "stem": f"[{name}] 您在工作中遇到类似情况{k+1}时，最可能的做法是？",
                "options": ["总是规范处理", "多数时候规范",
                            "偶尔侥幸", "图省事直接做"],
                "score_map": {"总是规范处理": 4, "多数时候规范": 3,
                              "偶尔侥幸": 2, "图省事直接做": 1},
            })
            qid += 1
    return qs


AWARENESS_QUESTIONNAIRE: Dict[str, Dict[str, Any]] = {q["qid"]: q
                                                     for q in _build_questionnaire()}

COMPLIANCE_REQUIREMENTS = {
    "等保2.0三级": {
        "training_hours_min": 8, "awareness_assessment_required": True,
        "phishing_drill_required": True, "record_retention_months": 12,
    },
    "ISO27001 A.7.2": {
        "training_hours_min": 6, "awareness_assessment_required": True,
        "phishing_drill_required": False, "record_retention_months": 24,
    },
}


class AwarenessAssessor:
    """安全意识评估器。"""

    def __init__(self) -> None:
        self.results: Dict[str, Dict[str, Any]] = {}

    def questionnaire(self) -> Dict[str, Any]:
        items = list(AWARENESS_QUESTIONNAIRE.values())
        return {"total": len(items),
                "domains": [{"key": k, "name": n} for k, n in _DOMAINS],
                "sample": items[:5]}

    # ---- 个人测评 ----
    def assess(self, student: str, department: str,
               answers: Dict[str, str]) -> Dict[str, Any]:
        domain_score: Dict[str, List[int]] = {k: [] for k, _ in _DOMAINS}
        weak: List[str] = []
        for q in AWARENESS_QUESTIONNAIRE.values():
            ans = answers.get(q["qid"], "多数时候规范")
            pts = q["score_map"].get(ans, 3)
            domain_score[q["domain"]].append(pts)
            if pts <= 2:
                weak.append(q["stem"])
        # 换算 0-100
        per_domain = {}
        total_pts = 0
        total_max = 0
        for k, pts_list in domain_score.items():
            got = sum(pts_list)
            mx = len(pts_list) * 4
            per_domain[k] = round(got / max(1, mx) * 100, 1)
            total_pts += got
            total_max += mx
        overall = round(total_pts / max(1, total_max) * 100, 1)
        level = ("优秀" if overall >= 85 else "良好" if overall >= 70 else
                 "一般" if overall >= 55 else "薄弱")
        weak_domains = sorted(per_domain.items(), key=lambda x: x[1])[:3]
        result = {
            "student": student, "department": department, "score": overall,
            "level": level, "per_domain": per_domain,
            "weak_domains": [{"domain": k, "name": dict(_DOMAINS).get(k, k),
                              "score": v} for k, v in weak_domains],
            "suggestions": self._suggest(weak_domains),
            "weak_count": len(weak), "answered": len(answers),
            "assessed_at": time.strftime("%Y-%m-%d %H:%M:%S"),
        }
        rid = f"AS{int(time.time())%1000000:06d}"
        self.results[rid] = result
        result["assessment_id"] = rid
        return result

    @staticmethod
    def _suggest(weak_domains: List) -> List[str]:
        names = {k: n for k, n in _DOMAINS}
        tips = []
        for k, v in weak_domains:
            tips.append(f"重点补训「{names.get(k, k)}」（当前 {v} 分）："
                        f"建议完成对应课程并参加一次针对性钓鱼演练。")
        tips.append("建立每月一次的部门意识微测，将结果纳入年度考核参考。")
        return tips

    # ---- 部门对比 ----
    def department_compare(self) -> Dict[str, Any]:
        dept_buckets: Dict[str, List[float]] = {}
        for r in self.results.values():
            dept_buckets.setdefault(r["department"], []).append(r["score"])
        rows = []
        for dept, scores in dept_buckets.items():
            rows.append({"department": dept, "headcount": len(scores),
                         "avg_score": round(sum(scores) / len(scores), 1)})
        rows.sort(key=lambda x: x["avg_score"], reverse=True)
        return {"departments": rows, "total_assessments": len(self.results)}

    # ---- 趋势 ----
    def trend(self, months: int = 6) -> Dict[str, Any]:
        rows = list(self.results.values())
        # 模拟近 N 月趋势（按评分时间分布）
        series = []
        for i in range(months):
            month = time.strftime("%Y-%m", time.localtime(
                time.time() - (months - 1 - i) * 30 * 86400))
            series.append({"month": month,
                           "avg_score": round(
                               62 + i * 2.5 + (i % 3) * 1.2, 1),
                           "assessments": 10 + i * 3})
        return {"months": months, "series": series,
                "note": "趋势为内存模拟，可接入真实历史数据"}

    # ---- 合规报告 ----
    def compliance_report(self, framework: str = "等保2.0三级") -> Dict[str, Any]:
        req = COMPLIANCE_REQUIREMENTS.get(framework, COMPLIANCE_REQUIREMENTS["等保2.0三级"])
        rows = list(self.results.values())
        avg = round(sum(r["score"] for r in rows) / max(1, len(rows)), 1)
        compliant = avg >= 70 and len(rows) > 0
        md = [
            f"# 安全意识培训合规报告 · {framework}", "",
            f"- 报告日期: {time.strftime('%Y-%m-%d')}",
            f"- 累计测评人数: {len(rows)}",
            f"- 平均意识分: {avg}",
            f"- 要求最低培训学时: {req['training_hours_min']} 学时/年",
            f"- 要求开展意识测评: {'是' if req['awareness_assessment_required'] else '否'}",
            f"- 要求开展钓鱼演练: {'是' if req['phishing_drill_required'] else '否'}",
            f"- 记录留存: {req['record_retention_months']} 个月", "",
            f"## 结论: {'符合' if compliant else '待改进'}",
        ]
        if not compliant:
            md.append("- 建议：扩大测评覆盖、对薄弱部门安排补训并复评。")
        return {"framework": framework, "requirement": req,
                "coverage": len(rows), "avg_score": avg,
                "compliant": compliant,
                "report_markdown": "\n".join(md)}
