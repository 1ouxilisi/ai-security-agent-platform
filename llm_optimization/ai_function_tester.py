# -*- coding: utf-8 -*-
"""
llm_optimization/ai_function_tester.py — 三大 AI 功能验证器

统一封装三大 AI 能力，确保「配了 Key 就真能用」：
    1. analyze_vulnerability()  —— 漏洞智能分析
    2. generate_report()        —— 报告自动生成
    3. answer_question()        —— 智能问答

每次调用都返回统一结构：
    {
      success: bool,
      mode: "llm" | "rule",
      mode_label: "LLM 模式" | "规则模式（未配置LLM）",
      result: <结构化结果>,
      latency_ms: int,
      model: str,
      error: str | None,
      fallback: bool,          # 是否走了降级
    }

设计要点：
    - 每次调用前 refresh 一次客户端，确保「保存 Key 后立即生效，无需重启」；
    - LLM 返回失败时自动回退规则引擎，不抛异常；
    - 调用历史存内存字典，供仪表盘与 e2e 测试读取。
"""
from __future__ import annotations

import time
from datetime import datetime
from typing import Any, Dict, List, Optional

from .prompt_optimizer import get_prompt_optimizer


# 内存存储：调用历史
_CALL_HISTORY: List[Dict[str, Any]] = []
_MAX_HISTORY = 200


def _record(entry: Dict[str, Any]) -> None:
    _CALL_HISTORY.append(entry)
    if len(_CALL_HISTORY) > _MAX_HISTORY:
        del _CALL_HISTORY[: len(_CALL_HISTORY) - _MAX_HISTORY]


def get_history(limit: int = 50) -> List[Dict[str, Any]]:
    return _CALL_HISTORY[-limit:] if limit else list(_CALL_HISTORY)


def clear_history() -> None:
    _CALL_HISTORY.clear()


class AIFunctionTester:
    """三大 AI 功能验证器：LLM 可用走 LLM，不可用走规则引擎。"""

    def __init__(self) -> None:
        self.optimizer = get_prompt_optimizer()

    # ------------------------------------------------------------------
    # 内部：拿到「刷新过」的 LLM 客户端
    # ------------------------------------------------------------------
    @staticmethod
    def _fresh_client():
        """每次都刷新配置，保证保存 Key 后立即生效。"""
        try:
            from llm_integration import get_llm_client, reset_llm_client, reload_config
            reload_config()
            reset_llm_client()
            return get_llm_client()
        except Exception:
            return None

    @staticmethod
    def _is_configured() -> bool:
        try:
            from llm_integration import get_config_manager
            return bool(get_config_manager().is_configured())
        except Exception:
            return False

    # ------------------------------------------------------------------
    # 1. 漏洞智能分析
    # ------------------------------------------------------------------
    def analyze_vulnerability(self, vuln_description: str,
                              target: str = "", cve: str = "") -> Dict[str, Any]:
        """输入扫描结果，AI 自动分析漏洞严重程度。"""
        t0 = time.time()
        scene = "vuln_analysis"
        user_content = (
            f"漏洞描述: {vuln_description}\n"
            f"目标: {target or '未提供'}\n"
            f"CVE: {cve or '未提供'}"
        )

        # 先尝试 LLM
        if self._is_configured():
            client = self._fresh_client()
            if client is not None:
                meta = self.optimizer.registry[scene]
                msgs = self.optimizer.build_messages(scene, user_content)
                resp = client.chat(
                    messages=msgs,
                    temperature=meta.get("temperature", 0.1),
                    max_tokens=meta.get("max_tokens", 800),
                )
                if resp.get("success"):
                    content = resp.get("content", "")
                    parsed = self._parse_llm_json(content)
                    parsed.setdefault("mode", "llm")
                    parsed.setdefault("mode_label", "LLM 模式")
                    parsed["raw_llm_content"] = content
                    out = {
                        "success": True,
                        "mode": "llm",
                        "mode_label": "LLM 模式",
                        "result": parsed,
                        "latency_ms": resp.get("latency_ms", 0),
                        "model": resp.get("model", ""),
                        "error": None,
                        "fallback": False,
                    }
                    _record({"scene": scene, **out,
                             "ts": datetime.now().isoformat(timespec="seconds")})
                    return out
                # LLM 失败 -> 降级
                rule_out = self.optimizer.rule_fallback(
                    scene, vuln_description=vuln_description,
                    target=target, cve=cve)
                out = {
                    "success": True,
                    "mode": "rule",
                    "mode_label": "规则模式（未配置LLM）",
                    "result": rule_out,
                    "latency_ms": int((time.time() - t0) * 1000),
                    "model": "",
                    "error": f"LLM 调用失败已降级: {resp.get('error')}",
                    "fallback": True,
                }
                _record({"scene": scene, **out,
                         "ts": datetime.now().isoformat(timespec="seconds")})
                return out

        # 无 Key -> 规则引擎
        rule_out = self.optimizer.rule_fallback(
            scene, vuln_description=vuln_description, target=target, cve=cve)
        out = {
            "success": True,
            "mode": "rule",
            "mode_label": "规则模式（未配置LLM）",
            "result": rule_out,
            "latency_ms": int((time.time() - t0) * 1000),
            "model": "",
            "error": None,
            "fallback": True,
        }
        _record({"scene": scene, **out,
                 "ts": datetime.now().isoformat(timespec="seconds")})
        return out

    # ------------------------------------------------------------------
    # 2. 报告自动生成
    # ------------------------------------------------------------------
    def generate_report(self, vulns: List[Dict[str, Any]],
                        target: str = "") -> Dict[str, Any]:
        """输入扫描数据，AI 自动生成自然语言报告。"""
        t0 = time.time()
        scene = "report_generation"

        # 把漏洞清单压缩成给 LLM 的文本
        vuln_lines: List[str] = []
        for i, v in enumerate(vulns, 1):
            vuln_lines.append(
                f"{i}. 名称={v.get('name', v.get('vuln_type', '未命名'))}; "
                f"类型={v.get('vuln_type', 'unknown')}; "
                f"严重度={v.get('severity', 'medium')}; "
                f"位置={v.get('target', v.get('location', '未知'))}; "
                f"影响={v.get('impact', '待评估')}"
            )
        user_content = (
            f"目标系统: {target or '未提供'}\n"
            f"漏洞清单（共 {len(vulns)} 个）:\n" + "\n".join(vuln_lines)
        )

        if self._is_configured():
            client = self._fresh_client()
            if client is not None:
                meta = self.optimizer.registry[scene]
                msgs = self.optimizer.build_messages(scene, user_content)
                resp = client.chat(
                    messages=msgs,
                    temperature=meta.get("temperature", 0.2),
                    max_tokens=meta.get("max_tokens", 2048),
                )
                if resp.get("success"):
                    out = {
                        "success": True,
                        "mode": "llm",
                        "mode_label": "LLM 模式",
                        "result": {
                            "report_markdown": resp.get("content", ""),
                            "vuln_count": len(vulns),
                        },
                        "latency_ms": resp.get("latency_ms", 0),
                        "model": resp.get("model", ""),
                        "error": None,
                        "fallback": False,
                    }
                    _record({"scene": scene, **out,
                             "ts": datetime.now().isoformat(timespec="seconds")})
                    return out
                # LLM 失败 -> 降级
                md = self.optimizer.rule_fallback(scene, vulns=vulns)
                out = {
                    "success": True,
                    "mode": "rule",
                    "mode_label": "规则模式（未配置LLM）",
                    "result": {"report_markdown": md, "vuln_count": len(vulns)},
                    "latency_ms": int((time.time() - t0) * 1000),
                    "model": "",
                    "error": f"LLM 调用失败已降级: {resp.get('error')}",
                    "fallback": True,
                }
                _record({"scene": scene, **out,
                         "ts": datetime.now().isoformat(timespec="seconds")})
                return out

        # 无 Key -> 规则引擎
        md = self.optimizer.rule_fallback(scene, vulns=vulns)
        out = {
            "success": True,
            "mode": "rule",
            "mode_label": "规则模式（未配置LLM）",
            "result": {"report_markdown": md, "vuln_count": len(vulns)},
            "latency_ms": int((time.time() - t0) * 1000),
            "model": "",
            "error": None,
            "fallback": True,
        }
        _record({"scene": scene, **out,
                 "ts": datetime.now().isoformat(timespec="seconds")})
        return out

    # ------------------------------------------------------------------
    # 3. 智能问答
    # ------------------------------------------------------------------
    def answer_question(self, question: str, context: str = "") -> Dict[str, Any]:
        """用户问「这个网站有什么风险」，AI 自动分析回答。"""
        t0 = time.time()
        scene = "smart_qa"
        user_content = (
            f"已知信息:\n{context or '（无补充信息）'}\n\n"
            f"用户问题: {question}"
        )

        if self._is_configured():
            client = self._fresh_client()
            if client is not None:
                meta = self.optimizer.registry[scene]
                msgs = self.optimizer.build_messages(scene, user_content)
                resp = client.chat(
                    messages=msgs,
                    temperature=meta.get("temperature", 0.3),
                    max_tokens=meta.get("max_tokens", 1024),
                )
                if resp.get("success"):
                    out = {
                        "success": True,
                        "mode": "llm",
                        "mode_label": "LLM 模式",
                        "result": {"answer": resp.get("content", ""),
                                   "question": question},
                        "latency_ms": resp.get("latency_ms", 0),
                        "model": resp.get("model", ""),
                        "error": None,
                        "fallback": False,
                    }
                    _record({"scene": scene, **out,
                             "ts": datetime.now().isoformat(timespec="seconds")})
                    return out
                # 降级
                ans = self.optimizer.rule_fallback(scene, question=question,
                                                   context=context)
                out = {
                    "success": True,
                    "mode": "rule",
                    "mode_label": "规则模式（未配置LLM）",
                    "result": {"answer": ans, "question": question},
                    "latency_ms": int((time.time() - t0) * 1000),
                    "model": "",
                    "error": f"LLM 调用失败已降级: {resp.get('error')}",
                    "fallback": True,
                }
                _record({"scene": scene, **out,
                         "ts": datetime.now().isoformat(timespec="seconds")})
                return out

        # 无 Key -> 规则引擎
        ans = self.optimizer.rule_fallback(scene, question=question,
                                           context=context)
        out = {
            "success": True,
            "mode": "rule",
            "mode_label": "规则模式（未配置LLM）",
            "result": {"answer": ans, "question": question},
            "latency_ms": int((time.time() - t0) * 1000),
            "model": "",
            "error": None,
            "fallback": True,
        }
        _record({"scene": scene, **out,
                 "ts": datetime.now().isoformat(timespec="seconds")})
        return out

    # ------------------------------------------------------------------
    # 内部：解析 LLM 返回的 JSON（容错）
    # ------------------------------------------------------------------
    @staticmethod
    def _parse_llm_json(content: str) -> Dict[str, Any]:
        """LLM 可能返回 ```json ... ``` 包裹或夹杂文字，尽量提取 JSON。"""
        import json
        import re
        if not content:
            return {}
        # 去 markdown 代码块
        cleaned = content.strip()
        cleaned = re.sub(r"^```(?:json)?\s*", "", cleaned)
        cleaned = re.sub(r"\s*```$", "", cleaned)
        # 找第一个 { 到最后一个 }
        m = re.search(r"\{.*\}", cleaned, re.DOTALL)
        if m:
            try:
                return dict(json.loads(m.group(0)))
            except Exception:
                pass
        # 解析失败：把原文塞进去
        return {"raw_text": content}


# 模块级单例
_tester: AIFunctionTester | None = None


def get_ai_tester() -> AIFunctionTester:
    global _tester
    if _tester is None:
        _tester = AIFunctionTester()
    return _tester
