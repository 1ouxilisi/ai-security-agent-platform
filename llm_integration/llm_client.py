# -*- coding: utf-8 -*-
"""
llm_integration/llm_client.py — 统一 LLM 客户端

封装 OpenAI 兼容的 Chat Completions 调用，支持多家提供商：
    智谱AI(GLM) / DeepSeek / 硅基流动(SiliconFlow) / 任意 OpenAI 兼容接口。

统一对外只暴露一个 chat() 方法，所有 AI 模块（安全助手 / 漏洞验证 /
修复方案 / 自然语言）都复用它。错误被归一化处理，不向调用方抛原始异常：
    - 未配置（无 API Key）  -> success=False, error_code="not_configured"
    - 认证失败 (401)        -> error_code="auth_error"
    - 超时                   -> error_code="timeout"
    - 网络错误               -> error_code="network_error"
    - 其它                   -> error_code="http_error" / "parse_error"
"""
from __future__ import annotations

import time
from typing import Any, Dict, List, Optional

try:
    import requests
except ImportError:  # pragma: no cover
    requests = None  # type: ignore

try:
    from utils.logger import log
except Exception:  # pragma: no cover
    import logging
    logging.basicConfig(level=logging.INFO)
    log = logging.getLogger("llm_integration.client")

from .llm_config import get_config_manager, reload_config


class LLMClient:
    """统一 OpenAI 兼容 LLM 客户端。"""

    def __init__(self, api_key: Optional[str] = None,
                 base_url: Optional[str] = None,
                 model: Optional[str] = None,
                 temperature: Optional[float] = None,
                 max_tokens: Optional[int] = None,
                 timeout: int = 30):
        # 优先级：显式入参 > 全局配置
        cfg = get_config_manager().get_config()
        self.api_key = (api_key if api_key is not None else cfg["api_key"]) or ""
        self.base_url = ((base_url or cfg["base_url"]) or "").rstrip("/")
        self.model = model or cfg["model"] or "glm-4-flash"
        self.temperature = 0.1 if temperature is None else temperature
        self.max_tokens = max_tokens or cfg["max_tokens"] or 4096
        self.timeout = timeout
        self.llm_available = bool(self.api_key and self.base_url and requests)
        # 兼容旧模块状态字段
        self.provider = get_config_manager()._guess_provider(self.base_url)

    # ------------------------------------------------------------------
    # 状态
    # ------------------------------------------------------------------
    def refresh(self) -> bool:
        """从 .env / 环境变量重新加载配置，返回刷新后是否可用。"""
        reload_config()
        cfg = get_config_manager().get_config()
        self.api_key = cfg["api_key"]
        self.base_url = cfg["base_url"]
        self.model = cfg["model"]
        self.temperature = cfg["temperature"]
        self.max_tokens = cfg["max_tokens"]
        self.provider = get_config_manager()._guess_provider(self.base_url)
        self.llm_available = bool(self.api_key and self.base_url and requests)
        return self.llm_available

    # ------------------------------------------------------------------
    # 核心调用
    # ------------------------------------------------------------------
    def chat(self,
             messages: List[Dict[str, str]],
             temperature: Optional[float] = None,
             max_tokens: Optional[int] = None) -> Dict[str, Any]:
        """
        调用 Chat Completions。返回统一结构：
            {success: bool, content: str, error: str|None,
             error_code: str|None, latency_ms: int, model: str}
        """
        if not self.api_key or not self.base_url:
            return self._fail("未配置 API Key 或 Base URL", "not_configured")
        if requests is None:
            return self._fail("requests 库不可用", "dependency_error")

        url = f"{self.base_url}/chat/completions"
        headers = {
            "Authorization": f"Bearer {self.api_key}",
            "Content-Type": "application/json",
        }
        body = {
            "model": self.model,
            "messages": messages,
            "temperature": self.temperature if temperature is None else temperature,
            "max_tokens": max_tokens or self.max_tokens,
        }
        t0 = time.time()
        try:
            resp = requests.post(url, headers=headers, json=body, timeout=self.timeout)
            latency_ms = int((time.time() - t0) * 1000)
        except requests.exceptions.Timeout:
            return self._fail("请求超时", "timeout", int((time.time() - t0) * 1000))
        except requests.exceptions.ConnectionError as e:
            return self._fail(f"网络连接失败: {e}", "network_error",
                              int((time.time() - t0) * 1000))
        except Exception as e:  # noqa: BLE001
            return self._fail(f"请求异常: {e}", "network_error",
                              int((time.time() - t0) * 1000))

        latency_ms = int((time.time() - t0) * 1000)

        # HTTP 状态处理
        if resp.status_code in (401, 403):
            return self._fail(f"认证失败 HTTP {resp.status_code}（检查 API Key）",
                              "auth_error", latency_ms)
        if resp.status_code == 404:
            return self._fail(f"接口不存在 HTTP 404（检查 Base URL）",
                              "not_found", latency_ms)
        if resp.status_code == 429:
            return self._fail("触发限流 HTTP 429（额度或并发限制）",
                              "rate_limit", latency_ms)
        if resp.status_code >= 500:
            return self._fail(f"服务端错误 HTTP {resp.status_code}",
                              "server_error", latency_ms)
        try:
            resp.raise_for_status()
        except Exception as e:  # noqa: BLE001
            return self._fail(f"HTTP 错误: {e}", "http_error", latency_ms)

        # 解析响应
        try:
            data = resp.json()
            content = data["choices"][0]["message"]["content"]
        except (ValueError, KeyError, IndexError, TypeError) as e:
            return self._fail(f"响应解析失败: {e}", "parse_error", latency_ms)

        return {
            "success": True,
            "content": (content or "").strip(),
            "error": None,
            "error_code": None,
            "latency_ms": latency_ms,
            "model": self.model,
            "usage": data.get("usage", {}),
        }

    def simple_chat(self, system_prompt: str, user_prompt: str,
                    temperature: Optional[float] = None,
                    max_tokens: Optional[int] = None) -> Optional[str]:
        """便捷方法：system+user 两段式，成功返回文本，失败返回 None。"""
        result = self.chat(
            messages=[{"role": "system", "content": system_prompt},
                      {"role": "user", "content": user_prompt}],
            temperature=temperature, max_tokens=max_tokens)
        if result["success"]:
            return result["content"]
        log.warning(f"LLM 调用未成功: [{result['error_code']}] {result['error']}")
        return None

    # ------------------------------------------------------------------
    # 连通性测试
    # ------------------------------------------------------------------
    def test_connection(self) -> Dict[str, Any]:
        """测试连接：发送一个极短请求验证可用性。"""
        cfg = get_config_manager().status()
        if not cfg["configured"]:
            return {"success": False, "error": "未配置 API Key",
                    "error_code": "not_configured", "data": cfg}
        result = self.chat(
            messages=[{"role": "user", "content": "ping，回复一个字：pong"}],
            max_tokens=16)
        return {
            "success": result["success"],
            "error": result["error"],
            "error_code": result["error_code"],
            "data": {
                "base_url": self.base_url,
                "model": self.model,
                "latency_ms": result.get("latency_ms"),
                "reply": result.get("content", ""),
            },
        }

    # ------------------------------------------------------------------
    # 内部
    # ------------------------------------------------------------------
    def _fail(self, error: str, code: str, latency_ms: int = 0) -> Dict[str, Any]:
        return {"success": False, "content": "", "error": error,
                "error_code": code, "latency_ms": latency_ms, "model": self.model}


# 模块级单例
_client: Optional[LLMClient] = None


def get_llm_client() -> LLMClient:
    """获取全局统一 LLM 客户端单例。"""
    global _client
    if _client is None:
        _client = LLMClient()
    return _client


def reset_llm_client() -> None:
    """重置单例（保存新配置后调用，强制下次重建并读取最新 .env）。"""
    global _client
    _client = None


def get_fresh_client() -> LLMClient:
    """丢弃旧单例并重建一个读取最新配置的客户端。"""
    reset_llm_client()
    return get_llm_client()
