# -*- coding: utf-8 -*-
"""quality_check.py — 输出质量检查（方向3）。

每个漏洞都要有：详情 / POC / 复现步骤 / 修复建议。
"""
from __future__ import annotations

import logging
from typing import Any, Dict, List

logger = logging.getLogger(__name__)

# 质量评分细则
QUALITY_RUBRIC: List[Dict[str, Any]] = [
    {"id": "has_title", "name": "漏洞标题", "weight": 5,
     "check": lambda f: bool(f.get("name") or f.get("title"))},
    {"id": "has_severity", "name": "危害等级", "weight": 5,
     "check": lambda f: f.get("severity") in
             ("critical", "high", "medium", "low", "info")},
    {"id": "has_detail", "name": "漏洞详情", "weight": 20,
     "check": lambda f: bool(f.get("detail") or f.get("description"))},
    {"id": "has_poc", "name": "POC", "weight": 25,
     "check": lambda f: bool(f.get("poc") or f.get("poc_code"))},
    {"id": "has_repro", "name": "复现步骤", "weight": 20,
     "check": lambda f: bool(f.get("repro_steps") or f.get("steps"))},
    {"id": "has_fix", "name": "修复建议", "weight": 20,
     "check": lambda f: bool(f.get("fix") or f.get("remediation"))},
    {"id": "has_cwe", "name": "CWE 映射", "weight": 5,
     "check": lambda f: bool(f.get("cwe"))},
]

# 漏洞详情模板（用于把低质量条目升级到客户付费级）
VULN_TEMPLATES: Dict[str, Dict[str, Any]] = {
    "sqli": {
        "cwe": "CWE-89",
        "detail": "应用未对用户输入做严格过滤，攻击者可构造恶意 SQL 语句，"
                  "通过报错/布尔/时间盲注提取数据库内容。",
        "poc_template": "GET /page.php?id=1' AND SLEEP(5)-- -",
        "repro_template": "1) 打开含参数的页面\n2) 在参数后加单引号\n"
                          "3) 观察报错或时间差\n4) 用 sqlmap 提权",
        "fix_template": "使用预编译语句（PreparedStatement）；"
                       "最小化数据库账号权限；开启 WAF。",
    },
    "xss": {
        "cwe": "CWE-79",
        "detail": "应用将用户输入直接回显到页面，未做 HTML 编码，"
                  "攻击者可注入任意 JavaScript。",
        "poc_template": "<script>alert(document.domain)</script>",
        "repro_template": "1) 在输入框粘贴 POC\n2) 提交\n"
                          "3) 观察是否弹窗",
        "fix_template": "输出编码（HTML entities）+ CSP + HttpOnly Cookie。",
    },
    "rce": {
        "cwe": "CWE-78",
        "detail": "应用将用户输入拼接到系统命令中，未做过滤，"
                  "攻击者可执行任意命令。",
        "poc_template": "; id",
        "repro_template": "1) 在命令执行点输入 POC\n2) 观察回显",
        "fix_template": "禁用危险函数；使用白名单；禁止 shell=True。",
    },
    "idor": {
        "cwe": "CWE-639",
        "detail": "应用未校验用户对资源的访问权限，攻击者可通过修改 ID "
                  "访问他人数据。",
        "poc_template": "GET /api/user/1001 修改为 /api/user/1002",
        "repro_template": "1) 用 A 账号登录\n2) 记录资源 ID\n"
                          "3) 改 ID 访问 B 的资源",
        "fix_template": "服务端做对象级授权检查（ABAC）。",
    },
}


class QualityChecker:
    """漏洞输出质量检查。"""

    def __init__(self) -> None:
        self.rubric = QUALITY_RUBRIC
        self.templates = VULN_TEMPLATES

    def check_finding(self, finding: Dict[str, Any]) -> Dict[str, Any]:
        score = 0
        passed: List[str] = []
        failed: List[str] = []
        for rule in self.rubric:
            try:
                ok = bool(rule["check"](finding))
            except Exception:
                ok = False
            if ok:
                score += rule["weight"]
                passed.append(rule["id"])
            else:
                failed.append(rule["id"])
        return {
            "score": score,
            "max_score": 100,
            "grade": "A" if score >= 90 else "B" if score >= 75
                     else "C" if score >= 60 else "D",
            "passed": passed,
            "failed": failed,
        }

    def upgrade(self, finding: Dict[str, Any]) -> Dict[str, Any]:
        """用模板把低质量条目升级到客户付费级。"""
        vtype = (finding.get("type") or finding.get("name") or "").lower()
        for key, tpl in self.templates.items():
            if key in vtype or key in (finding.get("cwe") or "").lower():
                out = dict(finding)
                out.setdefault("cwe", tpl["cwe"])
                out.setdefault("detail", tpl["detail"])
                out.setdefault("poc", tpl["poc_template"])
                out.setdefault("repro_steps", tpl["repro_template"])
                out.setdefault("fix", tpl["fix_template"])
                return out
        return finding

    def check_report(self, findings: List[Dict[str, Any]]) -> Dict[str, Any]:
        if not findings:
            return {"total": 0, "avg_score": 0, "grade": "N/A",
                    "upgraded": 0}
        scores = []
        upgraded = 0
        for f in findings:
            upgraded_f = self.upgrade(f)
            if upgraded_f is not f:
                upgraded += 1
            r = self.check_finding(upgraded_f)
            scores.append(r["score"])
        avg = sum(scores) / len(scores)
        return {
            "total": len(findings),
            "avg_score": round(avg, 1),
            "grade": "A" if avg >= 90 else "B" if avg >= 75
                     else "C" if avg >= 60 else "D",
            "upgraded": upgraded,
            "target_grade": "A",
            "pass": avg >= 90,
        }
