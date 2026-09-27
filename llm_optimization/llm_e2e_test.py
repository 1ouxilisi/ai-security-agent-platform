# -*- coding: utf-8 -*-
"""
llm_optimization/llm_e2e_test.py — LLM 端到端测试运行器

跑三个标准用例，验证「配了 Key 后三大 AI 功能真能用」：
    a. 输入 SQL 注入漏洞信息，AI 分析严重程度
    b. 输入 3 个漏洞数据，AI 生成自然语言报告
    c. 输入「这个网站有什么风险」，AI 智能回答

每个用例记录：
    - passed: bool（是否成功返回结构化结果）
    - mode: llm / rule
    - latency_ms
    - 关键产物片段（供前端展示）
    - 失败原因（如有）

结果存内存字典，dashboard 与 /e2e-run 端点共用。
"""
from __future__ import annotations

import time
import traceback
from datetime import datetime
from typing import Any, Dict, List

from .ai_function_tester import get_ai_tester


# 标准测试用例
SAMPLE_VULN_DESCRIPTION = (
    "用户登录接口的 password 参数存在 SQL 注入，"
    "单引号触发 MySQL 报错，存在报错注入与布尔盲注可能性"
)
SAMPLE_TARGET = "http://demo.testfire.net/login"

SAMPLE_VULNS: List[Dict[str, Any]] = [
    {
        "name": "登录接口 SQL 注入",
        "vuln_type": "sql_injection",
        "severity": "critical",
        "target": "/login",
        "impact": "可能导致拖库、管理员账号泄露",
    },
    {
        "name": "反射型 XSS",
        "vuln_type": "xss",
        "severity": "high",
        "target": "/search?q=",
        "impact": "可窃取会话 Cookie、钓鱼",
    },
    {
        "name": "管理后台暴露",
        "vuln_type": "path_traversal",
        "severity": "medium",
        "target": "/admin",
        "impact": "攻击者可直接访问管理后台入口",
    },
]

SAMPLE_QUESTION = "这个网站有什么风险？"
SAMPLE_CONTEXT = (
    "目标：http://demo.testfire.net\n"
    "已发现：登录接口 SQL 注入、反射型 XSS、/admin 后台直接暴露"
)


class LLME2ETestRunner:
    """端到端测试运行器。"""

    def __init__(self) -> None:
        self.tester = get_ai_tester()
        self.last_run: Dict[str, Any] = {}

    # ------------------------------------------------------------------
    # 用例 a：漏洞智能分析
    # ------------------------------------------------------------------
    def _case_vuln_analysis(self) -> Dict[str, Any]:
        t0 = time.time()
        try:
            r = self.tester.analyze_vulnerability(
                vuln_description=SAMPLE_VULN_DESCRIPTION,
                target=SAMPLE_TARGET,
                cve="",
            )
            result = r.get("result", {})
            passed = bool(r.get("success")) and bool(
                result.get("vuln_type") or result.get("raw_text")
            )
            return {
                "case": "a_vuln_analysis",
                "title": "输入 SQL 注入漏洞信息，AI 分析严重程度",
                "passed": passed,
                "mode": r.get("mode"),
                "mode_label": r.get("mode_label"),
                "latency_ms": int((time.time() - t0) * 1000),
                "llm_latency_ms": r.get("latency_ms"),
                "model": r.get("model"),
                "fallback": r.get("fallback", False),
                "key_fields": {
                    "vuln_type": result.get("vuln_type"),
                    "severity": result.get("severity"),
                    "cvss_score": result.get("cvss_score"),
                    "confidence": result.get("confidence"),
                    "root_cause": result.get("root_cause"),
                },
                "remediation": result.get("remediation", []),
                "error": r.get("error"),
            }
        except Exception as e:  # noqa: BLE001
            return {
                "case": "a_vuln_analysis",
                "title": "输入 SQL 注入漏洞信息，AI 分析严重程度",
                "passed": False,
                "mode": "error",
                "mode_label": "异常",
                "latency_ms": int((time.time() - t0) * 1000),
                "error": f"{e}\n{traceback.format_exc()[-300:]}",
            }

    # ------------------------------------------------------------------
    # 用例 b：报告自动生成
    # ------------------------------------------------------------------
    def _case_report_generation(self) -> Dict[str, Any]:
        t0 = time.time()
        try:
            r = self.tester.generate_report(vulns=SAMPLE_VULNS,
                                            target=SAMPLE_TARGET)
            md = (r.get("result") or {}).get("report_markdown", "")
            passed = bool(r.get("success")) and len(md) > 50
            return {
                "case": "b_report_generation",
                "title": "输入 3 个漏洞数据，AI 生成自然语言报告",
                "passed": passed,
                "mode": r.get("mode"),
                "mode_label": r.get("mode_label"),
                "latency_ms": int((time.time() - t0) * 1000),
                "llm_latency_ms": r.get("latency_ms"),
                "model": r.get("model"),
                "fallback": r.get("fallback", False),
                "vuln_count": len(SAMPLE_VULNS),
                "report_preview": md[:600],
                "report_length": len(md),
                "error": r.get("error"),
            }
        except Exception as e:  # noqa: BLE001
            return {
                "case": "b_report_generation",
                "title": "输入 3 个漏洞数据，AI 生成自然语言报告",
                "passed": False,
                "mode": "error",
                "mode_label": "异常",
                "latency_ms": int((time.time() - t0) * 1000),
                "error": f"{e}\n{traceback.format_exc()[-300:]}",
            }

    # ------------------------------------------------------------------
    # 用例 c：智能问答
    # ------------------------------------------------------------------
    def _case_smart_qa(self) -> Dict[str, Any]:
        t0 = time.time()
        try:
            r = self.tester.answer_question(question=SAMPLE_QUESTION,
                                            context=SAMPLE_CONTEXT)
            ans = (r.get("result") or {}).get("answer", "")
            passed = bool(r.get("success")) and len(ans) > 20
            return {
                "case": "c_smart_qa",
                "title": "输入「这个网站有什么风险」，AI 智能回答",
                "passed": passed,
                "mode": r.get("mode"),
                "mode_label": r.get("mode_label"),
                "latency_ms": int((time.time() - t0) * 1000),
                "llm_latency_ms": r.get("latency_ms"),
                "model": r.get("model"),
                "fallback": r.get("fallback", False),
                "question": SAMPLE_QUESTION,
                "answer_preview": ans[:600],
                "answer_length": len(ans),
                "error": r.get("error"),
            }
        except Exception as e:  # noqa: BLE001
            return {
                "case": "c_smart_qa",
                "title": "输入「这个网站有什么风险」，AI 智能回答",
                "passed": False,
                "mode": "error",
                "mode_label": "异常",
                "latency_ms": int((time.time() - t0) * 1000),
                "error": f"{e}\n{traceback.format_exc()[-300:]}",
            }

    # ------------------------------------------------------------------
    # 主入口
    # ------------------------------------------------------------------
    def run_all(self) -> Dict[str, Any]:
        """跑全部三个用例，汇总结果。"""
        started = datetime.now().isoformat(timespec="seconds")
        cases = [
            self._case_vuln_analysis(),
            self._case_report_generation(),
            self._case_smart_qa(),
        ]
        passed = sum(1 for c in cases if c.get("passed"))
        used_llm = [c for c in cases if c.get("mode") == "llm"]
        used_rule = [c for c in cases if c.get("mode") == "rule"]
        summary = {
            "started_at": started,
            "finished_at": datetime.now().isoformat(timespec="seconds"),
            "total": len(cases),
            "passed": passed,
            "failed": len(cases) - passed,
            "llm_cases": len(used_llm),
            "rule_cases": len(used_rule),
            "overall": "passed" if passed == len(cases) else "partial",
        }
        self.last_run = {"summary": summary, "cases": cases}
        return self.last_run

    def get_last_run(self) -> Dict[str, Any]:
        return self.last_run or {"summary": None, "cases": []}


# 模块级单例
_runner: LLME2ETestRunner | None = None


def get_e2e_runner() -> LLME2ETestRunner:
    global _runner
    if _runner is None:
        _runner = LLME2ETestRunner()
    return _runner
