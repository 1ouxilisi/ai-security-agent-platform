# -*- coding: utf-8 -*-
"""
ai_upgrade/smart_qa.py — 智能问答

用户用自然语言提问（如"这个网站有什么风险"），AI 自动结合当前扫描上下文
进行分析回答。真实 LLM 可用时生成自然语言答案；否则走意图识别 + 规则回答。
"""
from __future__ import annotations

import time
import uuid
from typing import Any, Dict, List, Optional

from .llm_integration import get_enhanced_llm

# 会话历史（内存）
QA_HISTORY: List[Dict[str, Any]] = []

# 当前会话上下文（最近一次扫描结果快照）
CONTEXT: Dict[str, Any] = {
    "target": "https://demo.target.com",
    "vulns": [
        {"name": "SQL 注入", "type": "sql_injection", "severity": "critical"},
        {"name": "反射型 XSS", "type": "xss", "severity": "medium"},
        {"name": "SSRF", "type": "ssrf", "severity": "high"},
        {"name": "目录穿越", "type": "path_traversal", "severity": "high"},
    ],
}


def set_context(target: str, vulns: List[Dict[str, Any]]) -> None:
    CONTEXT["target"] = target
    CONTEXT["vulns"] = vulns or []


def _rule_answer(question: str) -> str:
    q = question.lower()
    vulns = CONTEXT.get("vulns", [])
    n_crit = sum(1 for v in vulns if v.get("severity") == "critical")
    n_high = sum(1 for v in vulns if v.get("severity") == "high")
    names = "、".join(v["name"] for v in vulns) or "暂未发现"

    if any(k in question for k in ["风险", "安全吗", "怎么样", "有什么问题", "威胁"]):
        return (f"根据对 {CONTEXT['target']} 的扫描，共发现 {len(vulns)} 个安全问题："
                f"严重 {n_crit} 个、高危 {n_high} 个。具体包括 {names}。"
                f"建议优先处理严重与高危项（如 SQL 注入、SSRF），这些可被远程利用。")
    if any(k in question for k in ["漏洞", "vuln", "明细", "列表"]):
        return f"当前发现的漏洞清单：{names}。可在『漏洞管理』查看详情与修复建议。"
    if any(k in question for k in ["修", "fix", "修复", "整改"]):
        return ("修复建议优先级：1) SQL 注入 -> 参数化查询；2) SSRF -> URL 白名单；"
                "3) 目录穿越 -> 路径规范化校验；4) XSS -> 输出编码 + CSP。"
                "每项都有对应的一键修复方案说明。")
    if any(k in question for k in ["报告", "report", "生成"]):
        return ("可以为你自动生成自然语言渗透测试报告，包含执行摘要、风险统计、"
                "漏洞明细与修复建议，支持导出 Markdown。")
    if any(k in question for k in ["怎么打", "利用", "下一步", "攻击", "渗透"]):
        return ("建议攻击路径：先验证 SQL 注入（sqlmap）确认数据权限，再尝试 SSRF "
                "读取云元数据横向移动，最后通过目录穿越读配置文件完成信息收集。")
    return (f"我已分析 {CONTEXT['target']} 的扫描结果。你可以问我："
            "『有什么风险』『怎么修』『生成报告』『下一步怎么打』。")


class SmartQA:
    """智能问答引擎。"""

    def ask(self, question: str, user_id: str = "default") -> Dict[str, Any]:
        el = get_enhanced_llm()
        vulns_brief = "\n".join(
            f"- {v.get('name')}（{v.get('severity')}）" for v in CONTEXT["vulns"])
        sys_p = ("你是安全助手。基于给定的扫描结果，用简练专业的中文回答用户问题。"
                 "不要编造数据，未知就说不确定。")
        user_p = (f"当前目标：{CONTEXT['target']}\n已发现漏洞：\n{vulns_brief}\n\n"
                  f"用户问题：{question}")
        r = el.chat(sys_p, user_p, rule_fallback="", task="smart_qa",
                    max_tokens=400)
        if r["engine"] == "llm" and r["content"]:
            answer = r["engine"]
            text = r["content"]
        else:
            answer = "rule"
            text = _rule_answer(question)

        entry = {
            "qa_id": uuid.uuid4().hex[:10],
            "ts": time.strftime("%Y-%m-%d %H:%M:%S"),
            "user_id": user_id,
            "question": question,
            "answer": text,
            "engine": answer,
            "latency_ms": r["latency_ms"],
            "target": CONTEXT["target"],
        }
        QA_HISTORY.append(entry)
        if len(QA_HISTORY) > 200:
            del QA_HISTORY[: len(QA_HISTORY) - 200]
        return entry

    def history(self, limit: int = 20) -> List[Dict[str, Any]]:
        return list(reversed(QA_HISTORY[-limit:]))

    def suggestions(self) -> List[str]:
        return ["这个网站有什么风险？", "最严重的漏洞怎么修？",
                "下一步怎么打？", "帮我生成一份报告", "有没有能拿权限的点？"]


_singleton: Optional[SmartQA] = None


def get_smart_qa() -> SmartQA:
    global _singleton
    if _singleton is None:
        _singleton = SmartQA()
    return _singleton
