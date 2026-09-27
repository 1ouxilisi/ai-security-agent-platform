#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
LLM智能决策引擎（LLM Intelligence Engine）

真正接入大模型，让AI参与：
- 漏洞智能分析与优先级排序
- API参数智能补全
- 自然语言任务解析
- 智能报告生成
- 攻击路径推理
- 修复建议生成

支持OpenAI兼容API（硅基流动/OpenAI/本地Ollama）。
"""

import json
import time
import hashlib
from typing import Dict, List, Optional, Any, Tuple
from dataclasses import dataclass, field
from enum import Enum
import urllib.request
import urllib.error


class LLMProvider(Enum):
    """LLM提供商"""
    SILICONFLOW = "siliconflow"  # 硅基流动
    OPENAI = "openai"
    OLLAMA = "ollama"  # 本地
    CUSTOM = "custom"


@dataclass
class LLMConfig:
    """LLM配置"""
    provider: LLMProvider = LLMProvider.SILICONFLOW
    api_key: str = ""
    base_url: str = "https://api.siliconflow.cn/v1"
    model: str = "Qwen/Qwen2.5-7B-Instruct"
    temperature: float = 0.3
    max_tokens: int = 2048
    timeout: int = 60


@dataclass
class ChatMessage:
    """聊天消息"""
    role: str  # system/user/assistant
    content: str
    timestamp: float = 0


@dataclass
class LLMResponse:
    """LLM响应"""
    content: str
    model: str
    usage: Dict = field(default_factory=dict)
    latency_ms: int = 0
    success: bool = True
    error: str = ""


class PromptTemplate:
    """提示词模板库"""

    # 漏洞分析
    VULN_ANALYSIS = """你是一位资深网络安全专家。请分析以下安全扫描发现，给出专业评估：

扫描目标：{target}
发现的漏洞/问题：
{findings}

请按以下格式输出（JSON）：
{{
  "overall_risk": "critical/high/medium/low",
  "risk_score": 0-100,
  "prioritized_vulns": [
    {{"name": "", "severity": "", "cvss": 0, "exploitability": "easy/medium/hard", "business_impact": ""}}
  ],
  "attack_chain": "描述可能的攻击路径",
  "top_remediation": ["修复建议1", "修复建议2"]
}}

只输出JSON，不要其他文字。"""

    # API参数补全
    API_PARAM_INFER = """你是一位API安全测试专家。根据以下API端点信息，推断可能的参数：

端点URL：{url}
HTTP方法：{method}
已提取的参数：{existing_params}
端点路径：{path}

请推断这个端点可能需要的所有参数，包括：
1. 路径参数（URL中的变量）
2. 查询参数（?key=value）
3. 请求体参数（JSON/Form）
4. 请求头参数（Authorization等）

输出格式（JSON）：
{{
  "parameters": [
    {{"name": "", "location": "path/query/body/header", "type": "string/int/bool/object", "required": true/false, "description": "", "example_value": ""}}
  ],
  "auth_required": true/false,
  "auth_type": "none/bearer/basic/api_key/cookie",
  "content_type": "application/json/x-www-form-urlencoded/multipart"
}}

只输出JSON。"""

    # 自然语言任务解析
    TASK_PARSING = """你是一位安全测试任务调度器。将用户的自然语言指令解析为结构化任务：

用户指令：{user_input}

可用的任务类型：
- web_scan: Web漏洞扫描
- port_scan: 端口扫描
- api_pentest: API渗透测试
- recon: 信息收集
- vuln_verify: 漏洞验证
- report: 生成报告
- mobile_audit: 移动安全审计
- cloud_audit: 云安全评估
- ai_security: AI智能体安全测试
- full_pentest: 完整渗透测试

输出格式（JSON）：
{{
  "task_type": "任务类型",
  "target": "目标地址",
  "parameters": {{"key": "value"}},
  "aggressive": true/false,
  "description": "任务描述",
  "estimated_time": "预计耗时"
}}

只输出JSON。"""

    # 报告生成
    REPORT_GENERATION = """你是一位专业的渗透测试报告撰写专家。根据以下测试数据生成专业报告：

目标：{target}
测试时间：{duration}秒
发现的漏洞：
{findings}
工具使用：{tools}

请生成一份结构清晰的渗透测试报告，包含：
1. 执行摘要（风险概览）
2. 测试范围与方法论
3. 漏洞详情（按严重程度排序）
4. 攻击路径分析
5. 修复建议（优先级排序）
6. 附录（工具列表、原始数据）

用中文输出，专业但易懂。"""

    # 攻击路径推理
    ATTACK_CHAIN = """你是一位红队攻击专家。基于以下发现，推理可能的攻击路径：

目标：{target}
已发现：
{findings}
开放端口/服务：{services}

请分析从初始访问到目标达成的完整攻击链，输出：
1. 最可能的攻击路径（步骤化）
2. 每个步骤的成功率评估
3. 关键转折点
4. 需要的额外信息/工具

用中文输出。"""

    # 修复建议
    REMEDIATION = """你是一位安全加固专家。针对以下漏洞，给出具体可执行的修复方案：

漏洞列表：
{vulnerabilities}

对每个漏洞给出：
1. 修复方法（具体代码/配置示例）
2. 修复优先级（P0紧急/P1高/P2中/P3低）
3. 预计修复时间
4. 验证方法

用中文输出，代码示例用对应语言。"""


class LLMClient:
    """
    LLM客户端

    支持OpenAI兼容API（硅基流动/OpenAI/本地Ollama）。
    """

    def __init__(self, config: LLMConfig = None):
        self.config = config or LLMConfig()
        self.conversation_history: List[ChatMessage] = []
        self.total_calls = 0
        self.total_tokens = 0
        self.cache: Dict[str, LLMResponse] = {}

    def configure(self, api_key: str = None, model: str = None,
                  base_url: str = None, provider: LLMProvider = None):
        """配置LLM参数"""
        if api_key:
            self.config.api_key = api_key
        if model:
            self.config.model = model
        if base_url:
            self.config.base_url = base_url
        if provider:
            self.config.provider = provider

    def chat(self, messages: List[Dict], temperature: float = None,
             max_tokens: int = None) -> LLMResponse:
        """
        发送聊天请求

        Args:
            messages: [{"role": "system/user/assistant", "content": "..."}]
            temperature: 温度（覆盖配置）
            max_tokens: 最大token（覆盖配置）
        """
        start_time = time.time()
        self.total_calls += 1

        # 缓存检查（简单hash）
        cache_key = hashlib.md5(
            json.dumps(messages, ensure_ascii=False).encode()
        ).hexdigest()
        if cache_key in self.cache:
            cached = self.cache[cache_key]
            cached.latency_ms = 5  # 缓存命中
            return cached

        try:
            url = f"{self.config.base_url}/chat/completions"
            payload = {
                "model": self.config.model,
                "messages": messages,
                "temperature": temperature or self.config.temperature,
                "max_tokens": max_tokens or self.config.max_tokens,
                "stream": False,
            }

            headers = {
                "Content-Type": "application/json",
                "Authorization": f"Bearer {self.config.api_key}",
            }

            req = urllib.request.Request(
                url,
                data=json.dumps(payload).encode("utf-8"),
                headers=headers,
                method="POST",
            )

            resp = urllib.request.urlopen(req, timeout=self.config.timeout)
            result = json.loads(resp.read().decode("utf-8"))

            content = result["choices"][0]["message"]["content"]
            usage = result.get("usage", {})
            self.total_tokens += usage.get("total_tokens", 0)

            response = LLMResponse(
                content=content,
                model=self.config.model,
                usage=usage,
                latency_ms=int((time.time() - start_time) * 1000),
                success=True,
            )

            # 缓存（最多100条）
            if len(self.cache) < 100:
                self.cache[cache_key] = response

            return response

        except urllib.error.HTTPError as e:
            error_body = ""
            try:
                error_body = e.read().decode("utf-8", errors="ignore")
            except Exception:
                pass
            return LLMResponse(
                content="",
                model=self.config.model,
                latency_ms=int((time.time() - start_time) * 1000),
                success=False,
                error=f"HTTP {e.code}: {error_body[:200]}",
            )
        except Exception as e:
            return LLMResponse(
                content="",
                model=self.config.model,
                latency_ms=int((time.time() - start_time) * 1000),
                success=False,
                error=str(e),
            )

    def chat_with_system(self, system_prompt: str, user_prompt: str,
                         **kwargs) -> LLMResponse:
        """带系统提示词的单次对话"""
        messages = [
            {"role": "system", "content": system_prompt},
            {"role": "user", "content": user_prompt},
        ]
        return self.chat(messages, **kwargs)

    def analyze_vulnerabilities(self, target: str, findings: List[Dict]) -> Dict:
        """
        智能漏洞分析

        Returns:
            结构化分析结果
        """
        findings_text = "\n".join(
            f"- [{f.get('severity', 'unknown')}] {f.get('name', '')}: {f.get('description', '')}"
            for f in findings[:20]
        )
        prompt = PromptTemplate.VULN_ANALYSIS.format(
            target=target, findings=findings_text
        )
        response = self.chat_with_system(
            "你是网络安全专家，只输出JSON。",
            prompt,
            temperature=0.2,
        )
        return self._parse_json_response(response)

    def infer_api_parameters(self, url: str, method: str = "GET",
                             existing_params: List = None, path: str = "") -> Dict:
        """
        API参数智能补全
        """
        existing = existing_params or []
        existing_text = ", ".join(p.get("name", str(p)) for p in existing) if existing else "无"
        prompt = PromptTemplate.API_PARAM_INFER.format(
            url=url, method=method, existing_params=existing_text, path=path or url
        )
        response = self.chat_with_system(
            "你是API安全测试专家，只输出JSON。",
            prompt,
            temperature=0.3,
        )
        return self._parse_json_response(response)

    def parse_task(self, user_input: str) -> Dict:
        """
        自然语言任务解析
        """
        prompt = PromptTemplate.TASK_PARSING.format(user_input=user_input)
        response = self.chat_with_system(
            "你是安全测试任务调度器，只输出JSON。",
            prompt,
            temperature=0.2,
        )
        return self._parse_json_response(response)

    def generate_report(self, target: str, findings: List[Dict],
                        duration: float, tools: List[str]) -> str:
        """
        智能报告生成
        """
        findings_text = "\n".join(
            f"- [{f.get('severity', '?')}] {f.get('name', '')} (CVSS: {f.get('cvss', 'N/A')})"
            for f in findings[:30]
        )
        tools_text = ", ".join(tools) if tools else "无"
        prompt = PromptTemplate.REPORT_GENERATION.format(
            target=target, findings=findings_text,
            duration=f"{duration:.1f}", tools=tools_text
        )
        response = self.chat_with_system(
            "你是专业渗透测试报告撰写专家。",
            prompt,
            temperature=0.4,
            max_tokens=4096,
        )
        return response.content if response.success else f"报告生成失败: {response.error}"

    def reason_attack_chain(self, target: str, findings: List[Dict],
                            services: List[Dict]) -> str:
        """
        攻击路径推理
        """
        findings_text = "\n".join(
            f"- {f.get('name', '')}: {f.get('description', '')}"
            for f in findings[:15]
        )
        services_text = "\n".join(
            f"- {s.get('port', '')}/{s.get('protocol', '')}: {s.get('service', '')}"
            for s in services[:10]
        ) or "无"
        prompt = PromptTemplate.ATTACK_CHAIN.format(
            target=target, findings=findings_text, services=services_text
        )
        response = self.chat_with_system(
            "你是红队攻击专家。",
            prompt,
            temperature=0.5,
        )
        return response.content if response.success else f"攻击链推理失败: {response.error}"

    def get_remediation(self, vulnerabilities: List[Dict]) -> str:
        """
        修复建议生成
        """
        vulns_text = "\n".join(
            f"- [{v.get('severity', '?')}] {v.get('name', '')}: {v.get('description', '')}"
            for v in vulnerabilities[:20]
        )
        prompt = PromptTemplate.REMEDIATION.format(vulnerabilities=vulns_text)
        response = self.chat_with_system(
            "你是安全加固专家。",
            prompt,
            temperature=0.3,
        )
        return response.content if response.success else f"修复建议生成失败: {response.error}"

    def _parse_json_response(self, response: LLMResponse) -> Dict:
        """解析LLM的JSON响应"""
        if not response.success:
            return {"error": response.error, "success": False}
        try:
            # 尝试提取JSON（可能被markdown包裹）
            content = response.content.strip()
            if content.startswith("```"):
                content = content.split("```")[1]
                if content.startswith("json"):
                    content = content[4:]
                content = content.strip()
            # 找到第一个{和最后一个}
            start = content.find("{")
            end = content.rfind("}")
            if start >= 0 and end > start:
                content = content[start:end + 1]
            return json.loads(content)
        except Exception as e:
            return {
                "error": f"JSON解析失败: {e}",
                "raw_content": response.content[:500],
                "success": False,
            }

    def get_stats(self) -> Dict:
        """获取LLM使用统计"""
        return {
            "provider": self.config.provider.value,
            "model": self.config.model,
            "base_url": self.config.base_url,
            "api_key_configured": bool(self.config.api_key),
            "total_calls": self.total_calls,
            "total_tokens": self.total_tokens,
            "cache_size": len(self.cache),
        }


# 单例模式
_llm_instance: Optional[LLMClient] = None

def get_llm_client() -> LLMClient:
    """获取全局LLM客户端实例"""
    global _llm_instance
    if _llm_instance is None:
        _llm_instance = LLMClient()
    return _llm_instance
