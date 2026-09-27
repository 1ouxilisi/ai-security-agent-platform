#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
LLM API 安全检测器 (LLM API Security Checker)
==============================================

纯规则实现，四个能力：

1. detect_api_leaks(text)        —— 从文本/源码中识别硬编码的 LLM API 密钥
2. check_rate_limit(config)      —— 检查 API 配置是否设置速率/配额/成本告警
3. check_input_output_filtering(config) —— 检查输入输出过滤与脱敏
4. scan_endpoint_security(url)   —— 对端点做轻量级安全探测（HTTPS/认证/错误信息泄露）

不依赖第三方库（scan 使用标准库 urllib），规则全部真实匹配。
"""
import re
import ssl
import urllib.request
import urllib.error
from typing import Dict, List, Optional


class LLMAPISecurityChecker:
    """LLM API 密钥泄露与调用安全检测"""

    # ------------------------------------------------------------------ #
    # 1. API 密钥泄露检测
    # ------------------------------------------------------------------ #
    # 密钥模式表：(厂商, 正则, 严重度, 描述)
    KEY_PATTERNS: List[Dict] = [
        {
            "vendor": "OpenAI",
            "pattern": r"sk-[A-Za-z0-9]{20,}",
            "severity": "critical",
            "desc": "OpenAI API 密钥 (sk-...)",
        },
        {
            "vendor": "Anthropic",
            "pattern": r"sk-ant-[A-Za-z0-9_-]{20,}",
            "severity": "critical",
            "desc": "Anthropic Claude API 密钥 (sk-ant-...)",
        },
        {
            "vendor": "Google Gemini",
            "pattern": r"AIza[A-Za-z0-9_-]{35}",
            "severity": "critical",
            "desc": "Google AI / Gemini API 密钥 (AIza...)",
        },
        {
            "vendor": "Azure OpenAI",
            "pattern": r"(?i)azure[-_]?openai[^\n]{0,80}?["
                       r"']([A-Za-z0-9]{32})['\"]",
            "severity": "high",
            "desc": "Azure OpenAI API key（资源配置中 32 位 key）",
        },
        {
            "vendor": "通用环境变量/赋值",
            "pattern": r"(?i)(api[_-]?key|apikey|secret|token)\s*[:=]\s*[\""
                       r"'][A-Za-z0-9_\-]{16,}[\"']",
            "severity": "high",
            "desc": "代码中硬编码的 api_key/secret/token 赋值",
        },
        {
            "vendor": "知名环境变量名",
            "pattern": r"(?i)(OPENAI_API_KEY|ANTHROPIC_API_KEY|GOOGLE_API_KEY|"
                       r"AZURE_OPENAI_KEY|HUGGINGFACE_TOKEN|REPLICATE_API_TOKEN)",
            "severity": "info",
            "desc": "出现知名 LLM 环境变量名（需人工确认是否在示例/文档中）",
        },
    ]

    def detect_api_leaks(self, text: str) -> List[Dict]:
        """扫描文本/代码，找出泄露的 LLM API 密钥

        Args:
            text: 待扫描的源码或配置文本

        Returns:
            密钥泄露发现列表，evidence 为脱敏后的命中串（保留首尾各 4 位）
        """
        findings: List[Dict] = []
        if not text:
            return findings

        # 逐行扫描，记录行号
        lines = text.splitlines()
        for lineno, line in enumerate(lines, start=1):
            for entry in self.KEY_PATTERNS:
                for m in re.finditer(entry["pattern"], line):
                    raw = m.group(0)
                    findings.append({
                        "vendor": entry["vendor"],
                        "severity": entry["severity"],
                        "description": entry["desc"],
                        "line": lineno,
                        "evidence": self._mask_secret(raw),
                        "full_match_len": len(raw),
                        "recommendation": "立即吊销该密钥并轮换，改用环境变量/密钥管理服务",
                    })
        return findings

    @staticmethod
    def _mask_secret(s: str) -> str:
        """密钥脱敏：保留前后各 4 字符，中间打码"""
        if len(s) <= 10:
            return s
        return s[:4] + "*" * (len(s) - 8) + s[-4:]

    # ------------------------------------------------------------------ #
    # 2. 速率限制检查
    # ------------------------------------------------------------------ #
    def check_rate_limit(self, config: Dict) -> Dict:
        """检查 API 调用配置中的速率/配额/成本控制

        Args:
            config: 配置字典，例如
                {"requests_per_minute": 60, "daily_budget_usd": 10.0, ...}

        Returns:
            {"has_rate_limit": bool, "has_quota": bool, "has_cost_alert": bool,
             "findings": [...]}
        """
        blob = self._flatten(config).lower()
        result = {"has_rate_limit": False, "has_quota": False,
                  "has_cost_alert": False, "findings": []}

        # 速率限制关键词
        if re.search(r"(requests?_per_(minute|hour|day)|rpm|rph|rpd|"
                     r"rate_?limit|max_calls?_per|throttle|qps|并发|每分钟|每小时|每天)",
                     blob):
            result["has_rate_limit"] = True
        else:
            result["findings"].append({
                "severity": "medium",
                "item": "速率限制",
                "detail": "未配置 requests_per_minute / rate_limit / RPM 等限流",
                "recommendation": "按厂商配额设置 RPM/TPM 限流与退避重试",
            })

        # 配额关键词
        if re.search(r"(daily_budget|monthly_budget|max_tokens|token_quota|"
                     r"max_cost|budget_usd|成本预算|token\s*上限|每日预算)", blob):
            result["has_quota"] = True
        else:
            result["findings"].append({
                "severity": "medium",
                "item": "用量配额",
                "detail": "未配置 max_tokens / daily_budget / token_quota",
                "recommendation": "设置 token 预算与日成本上限，防止失控调用产生巨额账单",
            })

        # 成本告警关键词
        if re.search(r"(cost_?alert|spend_?alert|budget_?alert|alert_threshold|"
                     r"成本告警|超支告警|预算告警)", blob):
            result["has_cost_alert"] = True
        else:
            result["findings"].append({
                "severity": "low",
                "item": "成本告警",
                "detail": "未配置成本/花费告警阈值",
                "recommendation": "设置花费阈值告警，接近预算上限自动熔断",
            })
        return result

    # ------------------------------------------------------------------ #
    # 3. 输入输出过滤检查
    # ------------------------------------------------------------------ #
    def check_input_output_filtering(self, config: Dict) -> List[Dict]:
        """检查输入输出侧是否有过滤/审核/PII 脱敏

        Args:
            config: API 调用/网关配置字典

        Returns:
            缺失项发现列表
        """
        blob = self._flatten(config).lower()
        findings: List[Dict] = []

        # ---- 输入侧 ----
        if not re.search(r"(max_input_length|max_prompt_tokens|input_length_limit|"
                         r"输入长度限制|最大输入)", blob):
            findings.append({
                "side": "input", "severity": "low",
                "item": "输入长度限制",
                "detail": "未设置输入长度上限，易受超长 payload/DoS",
                "recommendation": "设置 max_input_tokens 并对超长输入截断/拒绝",
            })

        if not re.search(r"(input_filter|content_filter|injection_detection|"
                         r"prompt_safety|输入过滤|注入检测|内容过滤)", blob):
            findings.append({
                "side": "input", "severity": "high",
                "item": "输入内容过滤",
                "detail": "未启用输入侧内容过滤/提示注入检测",
                "recommendation": "接入提示注入检测与敏感词过滤后再调用 LLM",
            })

        # ---- 输出侧 ----
        if not re.search(r"(output_filter|moderation|safety_check|response_safety|"
                         r"输出审核|内容审核|moderation_api)", blob):
            findings.append({
                "side": "output", "severity": "high",
                "item": "输出内容审核",
                "detail": "未启用输出侧内容审核（OpenAI Moderation 等）",
                "recommendation": "模型输出经过内容审核 API 后再返回用户",
            })

        if not re.search(r"(pii|redact|desensitize|mask|脱敏|隐私过滤|"
                         r"sensitive_info_filter)", blob):
            findings.append({
                "side": "output", "severity": "medium",
                "item": "PII/敏感信息脱敏",
                "detail": "未配置 PII/敏感信息识别与脱敏",
                "recommendation": "输出前对身份证/手机号/密钥等 PII 做识别与打码",
            })

        return findings

    # ------------------------------------------------------------------ #
    # 4. 端点安全轻量探测（标准库 urllib，短超时）
    # ------------------------------------------------------------------ #
    def scan_endpoint_security(self, url: str) -> List[Dict]:
        """对 LLM API 端点做轻量级安全探测

        检查项：HTTPS、是否要求认证（401/403）、错误信息是否泄露堆栈。
        网络不可达时返回对应说明，不抛异常。

        Args:
            url: 端点 URL

        Returns:
            探测发现列表
        """
        findings: List[Dict] = []
        if not url:
            return [{"severity": "info", "item": "端点",
                     "detail": "未提供 URL，跳过端点探测"}]

        # (a) 必须 HTTPS
        if not url.lower().startswith("https://"):
            findings.append({
                "severity": "high", "item": "传输加密",
                "detail": f"端点未使用 HTTPS: {url}",
                "recommendation": "LLM API 调用必须走 TLS，禁止 http://",
            })
        else:
            findings.append({
                "severity": "info", "item": "传输加密",
                "detail": "端点使用 HTTPS",
            })

        # (b) 发一个不带认证的请求，观察是否要求鉴权 / 是否泄露堆栈
        try:
            req = urllib.request.Request(
                url, headers={"User-Agent": "AIAgentAssessor/1.0"})
            ctx = ssl.create_default_context()
            with urllib.request.urlopen(req, timeout=5, context=ctx) as resp:
                status = getattr(resp, "status", 200)
                body = resp.read(2048).decode("utf-8", errors="replace")
        except urllib.error.HTTPError as e:
            status = e.code
            try:
                body = e.read(2048).decode("utf-8", errors="replace")
            except Exception:
                body = ""
        except Exception as e:
            findings.append({
                "severity": "info", "item": "连通性",
                "detail": f"端点探测失败（网络不可达/超时）: {type(e).__name__}",
            })
            return findings

        # 未认证直接 200 → 未鉴权
        if status == 200:
            findings.append({
                "severity": "critical", "item": "认证",
                "detail": f"不带凭证请求返回 200，端点可能未鉴权: {url}",
                "recommendation": "端点必须要求 API Key / Bearer Token 鉴权",
            })
        elif status in (401, 403):
            findings.append({
                "severity": "info", "item": "认证",
                "detail": f"端点正确要求认证（HTTP {status}）",
            })

        # 错误信息泄露内部细节
        leak_indicators = ("Traceback (most recent call last)", "java.lang.",
                           "SQLException", "stack trace", "at line ",
                           "internal error: ", "debug info", "SQLSTATE")
        if any(ind in body for ind in leak_indicators):
            findings.append({
                "severity": "medium", "item": "错误信息泄露",
                "detail": "错误响应中疑似包含堆栈/SQL/内部调试信息",
                "recommendation": "对外返回通用错误文案，细节仅写入服务端日志",
            })
        return findings

    # ------------------------------------------------------------------ #
    # 内部工具
    # ------------------------------------------------------------------ #
    @staticmethod
    def _flatten(config: Dict, prefix: str = "") -> str:
        parts: List[str] = []
        for k, v in (config or {}).items():
            key = f"{prefix}{k}"
            if isinstance(v, dict):
                parts.append(LLMAPISecurityChecker._flatten(v, key + "."))
            elif isinstance(v, list):
                parts.append(key + " " + " ".join(str(x) for x in v))
            else:
                parts.append(f"{key} {v}")
        return "\n".join(parts)


_default_checker = LLMAPISecurityChecker()

def detect_api_leaks(text: str) -> List[Dict]:
    return _default_checker.detect_api_leaks(text)


def register(engine) -> None:  # pragma: no cover
    """注册占位（统一入口见 unified/ai_assessor.py）"""
    return None
