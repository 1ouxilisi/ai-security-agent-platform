#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
AI 智能体安全评估器 (AIAgentAssessor)
=====================================

统一框架领域评估器，domain = DomainType.AI_AGENT。

自动判别 target 类型并调度对应检测器：
  - prompt 文本 / .txt 文件          → PromptInjectionDetector + JailbreakDetector
  - .json 且含 tools/agent 字段      → AgentSecurityAuditor
  - .json 且含 api_key/endpoint 字段 → LLMAPISecurityChecker
  - 对话历史（messages 列表）         → 全部模块综合检测
  - 任意文本                         → 额外做 API 密钥泄露扫描

所有发现统一封装为 unified.models.Finding 对象输出。
纯规则实现，不调用外部 LLM API。
"""
import json
import os
import time
from typing import Any, Dict, List, Optional

from unified.engine import DomainAssessor
from unified.models import DomainAssessment, DomainType

# 领域检测器（独立实现，可单独使用）
from ai_security.prompt_injection_detector import PromptInjectionDetector
from ai_security.jailbreak_detector import JailbreakDetector
from ai_security.agent_security_auditor import AgentSecurityAuditor
from ai_security.llm_api_security import LLMAPISecurityChecker


class AIAgentAssessor(DomainAssessor):
    """AI 智能体安全领域统一评估器"""

    domain = DomainType.AI_AGENT
    name = "ai_agent_assessor"
    description = "AI智能体安全：提示注入/越狱/Agent配置/LLM API密钥与过滤检测"

    def __init__(self):
        super().__init__()
        # 各检测器实例（规则全部在 __init__ 阶段预编译）
        self.prompt_detector = PromptInjectionDetector()
        self.jailbreak_detector = JailbreakDetector()
        self.agent_auditor = AgentSecurityAuditor()
        self.api_checker = LLMAPISecurityChecker()

    # ------------------------------------------------------------------ #
    # 统一入口
    # ------------------------------------------------------------------ #
    def assess(self, target: Any, options: Optional[Dict] = None) -> DomainAssessment:
        """执行 AI 智能体安全评估

        Args:
            target: 评估目标，支持以下形态：
                - str: prompt 文本 / 文件路径(.txt/.json) / JSON 字符串
                - dict: Agent 配置 / API 配置
                - list: 对话历史消息
            options: 评估选项（预留，如 {"scan_endpoint": true}）

        Returns:
            DomainAssessment 统一评估结果
        """
        options = options or {}
        result = DomainAssessment(domain=self.domain, target=str(target)[:200],
                                  started_at=time.time())
        findings: List = []
        errors: List[str] = []

        try:
            # 1) 解析 target → 归一化为 (kind, payload, source_label)
            kind, payload, source = self._resolve_target(target)

            # 2) 按类型调度检测器
            if kind == "conversation":
                findings.extend(self._assess_conversation(payload, source))
            elif kind == "agent_config":
                findings.extend(self._assess_agent_config(payload, source))
            elif kind == "api_config":
                findings.extend(self._assess_api_config(payload, source, options))
            elif kind in ("text", "file_text"):
                findings.extend(self._assess_text(payload, source))
            else:
                errors.append(f"无法识别的目标类型: {type(target).__name__}")

            # 3) 无论哪种类型，都对最终文本做一次 API 密钥泄露扫描
            blob = self._to_text_blob(kind, payload)
            if blob:
                for leak in self.api_checker.detect_api_leaks(blob):
                    findings.append(self._make_finding(
                        title=f"泄露的 {leak['vendor']} API 密钥",
                        severity=leak["severity"],
                        category="密钥泄露",
                        description=leak["description"],
                        target=source,
                        location=f"第 {leak['line']} 行",
                        evidence=f"命中: {leak['evidence']}",
                        cwe="CWE-798",
                        recommendation=leak["recommendation"],
                        extra={"rule": "API_KEY_LEAK", "line": leak["line"]},
                    ))

            result.checks_run = [
                "prompt_injection", "jailbreak", "agent_audit",
                "tool_hijacking", "api_leak", "rate_limit", "filtering",
            ]
            result.checks_total = len(findings)
            result.tools_used = [
                "PromptInjectionDetector", "JailbreakDetector",
                "AgentSecurityAuditor", "LLMAPISecurityChecker",
            ]
        except Exception as e:  # 评估器自身不应抛出
            errors.append(f"{type(e).__name__}: {e}")

        return self._complete_result(result, findings, errors)

    # ------------------------------------------------------------------ #
    # target 类型判别
    # ------------------------------------------------------------------ #
    def _resolve_target(self, target: Any):
        """把任意输入归一化为 (kind, payload, source)

        kind ∈ {text, file_text, agent_config, api_config, conversation, unknown}
        """
        # 列表 → 对话历史
        if isinstance(target, list):
            return "conversation", target, "对话历史"

        # 字典 → 配置
        if isinstance(target, dict):
            return self._classify_config(target), target, "配置对象"

        # 字符串
        if isinstance(target, str):
            # 文件路径
            if os.path.isfile(target):
                ext = os.path.splitext(target)[1].lower()
                with open(target, "r", encoding="utf-8", errors="replace") as f:
                    content = f.read()
                if ext == ".json":
                    try:
                        data = json.loads(content)
                    except json.JSONDecodeError:
                        return "file_text", content, target
                    if isinstance(data, list):
                        return "conversation", data, target
                    return self._classify_config(data), data, target
                return "file_text", content, target

            # JSON 字符串
            stripped = target.strip()
            if stripped.startswith(("{", "[")):
                try:
                    data = json.loads(stripped)
                except json.JSONDecodeError:
                    return "text", target, "prompt文本"
                if isinstance(data, list):
                    return "conversation", data, "对话历史(JSON)"
                return self._classify_config(data), data, "配置(JSON)"

            # 普通 prompt 文本
            return "text", target, "prompt文本"

        return "unknown", target, str(type(target))

    @staticmethod
    def _classify_config(cfg: Dict) -> str:
        """判断配置字典是 Agent 配置还是 API 配置"""
        keys_blob = " ".join(cfg.keys()).lower()
        if any(k in keys_blob for k in ("tools", "tool_list", "agent", "system_prompt",
                                        "persona", "goal", "steps")):
            return "agent_config"
        if any(k in keys_blob for k in ("api_key", "endpoint", "base_url", "model",
                                        "llm_config", "openai", "anthropic")):
            return "api_config"
        # 都不命中时按对话历史/通用配置兜底走 agent_config
        return "agent_config"

    # ------------------------------------------------------------------ #
    # 各类型评估逻辑
    # ------------------------------------------------------------------ #
    def _assess_text(self, text: str, source: str) -> List:
        """文本类：提示注入 + 越狱"""
        out: List = []
        for d in self.prompt_detector.detect(text):
            out.append(self._make_finding(
                title=f"提示注入: {d['rule_name']}",
                severity=d["severity"],
                category="提示注入",
                description=d["description"],
                target=source,
                location=f"位置 {d['position']}",
                evidence=f"模式[{d['rule_id']}] 命中文本: {d['evidence']}",
                cwe=d.get("cwe", ""),
                recommendation=d.get("recommendation", ""),
                extra={"rule_id": d["rule_id"], "pattern": d["pattern"]},
            ))
        for d in self.jailbreak_detector.detect(text):
            out.append(self._make_finding(
                title=f"越狱攻击: {d['rule_name']}",
                severity=d["severity"],
                category="越狱攻击",
                description=d["description"],
                target=source,
                location=f"位置 {d['position']}",
                evidence=f"模式[{d['rule_id']}] 命中文本: {d['evidence']}",
                cwe=d.get("cwe", ""),
                recommendation=d.get("recommendation", ""),
                extra={"rule_id": d["rule_id"], "pattern": d["pattern"]},
            ))
        return out

    def _assess_agent_config(self, cfg: Dict, source: str) -> List:
        """Agent 配置类：静态审计 + 对话劫持检测"""
        out: List = []
        tools = cfg.get("tools") or cfg.get("tool_list") or []
        for a in self.agent_auditor.audit(cfg, tools):
            out.append(self._make_finding(
                title=a["name"],
                severity=a["severity"],
                category="Agent配置审计",
                description=a["description"],
                target=source,
                location=a.get("check_id", ""),
                evidence=a.get("evidence", ""),
                recommendation=a.get("recommendation", ""),
                extra={"check_id": a.get("check_id"), "status": a.get("status")},
            ))
        # 若配置里带对话历史，顺带做工具劫持检测
        history = cfg.get("conversation") or cfg.get("messages") or cfg.get("history")
        if isinstance(history, list):
            out.extend(self._assess_conversation(history, source))
        return out

    def _assess_api_config(self, cfg: Dict, source: str, options: Dict) -> List:
        """API 配置类：限流/过滤/端点检测"""
        out: List = []
        # 限流
        rl = self.api_checker.check_rate_limit(cfg)
        for f in rl["findings"]:
            out.append(self._make_finding(
                title=f"API 配置缺项: {f['item']}",
                severity=f["severity"],
                category="API调用安全",
                description=f["detail"],
                target=source,
                location="rate_limit",
                evidence=f"配置中未检测到 {f['item']} 相关设置",
                recommendation=f["recommendation"],
            ))
        # 输入输出过滤
        for f in self.api_checker.check_input_output_filtering(cfg):
            out.append(self._make_finding(
                title=f"API {f['side']}侧缺项: {f['item']}",
                severity=f["severity"],
                category="API调用安全",
                description=f["detail"],
                target=source,
                location=f"{f['side']}_filter",
                evidence=f"配置中未检测到 {f['item']} 相关设置",
                recommendation=f["recommendation"],
            ))
        # 端点探测（默认开启，可由 options.scan_endpoint 关闭）
        if options.get("scan_endpoint", True):
            url = cfg.get("endpoint") or cfg.get("base_url") or cfg.get("api_base")
            if url:
                for f in self.api_checker.scan_endpoint_security(str(url)):
                    out.append(self._make_finding(
                        title=f"端点安全: {f['item']}",
                        severity=f["severity"],
                        category="API端点安全",
                        description=f["detail"],
                        target=str(url),
                        location="endpoint",
                        evidence=f.get("detail", ""),
                        recommendation=f.get("recommendation", ""),
                    ))
        return out

    def _assess_conversation(self, history: List, source: str) -> List:
        """对话历史类：注入+越狱+工具劫持 综合检测"""
        out: List = []
        for idx, msg in enumerate(history):
            content = str(msg.get("content", "") or "") if isinstance(msg, dict) else str(msg)
            label = f"{source} 第{idx+1}轮"
            out.extend(self._assess_text(content, label))
        # 工具调用劫持
        for h in self.agent_auditor.detect_tool_hijacking(history):
            out.append(self._make_finding(
                title=h["name"],
                severity=h["severity"],
                category="工具调用劫持",
                description=h["description"],
                target=source,
                location=f"对话第 {h.get('line', '?')+1} 轮({h.get('role', '')})",
                evidence=h["evidence"],
                recommendation=h.get("recommendation", ""),
                extra={"check_id": h.get("check_id")},
            ))
        return out

    # ------------------------------------------------------------------ #
    # 内部工具
    # ------------------------------------------------------------------ #
    @staticmethod
    def _to_text_blob(kind: str, payload: Any) -> str:
        """把目标转回纯文本，供密钥泄露扫描"""
        if isinstance(payload, str):
            return payload
        try:
            return json.dumps(payload, ensure_ascii=False)
        except (TypeError, ValueError):
            return str(payload)


# --------------------------------------------------------------------------- #
# 注册入口：供 UnifiedAssessmentEngine 注册
# --------------------------------------------------------------------------- #
def register(engine) -> None:
    """把 AIAgentAssessor 注册到统一评估引擎"""
    engine.register(AIAgentAssessor())
