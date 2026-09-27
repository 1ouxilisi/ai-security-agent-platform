# -*- coding: utf-8 -*-
"""
llm_config/llm_tester.py — LLM Key 真实测试

通过 requests 发起真实 HTTP 请求：
  - OpenAI 兼容：POST {base_url}/chat/completions
  - Anthropic：POST {base_url}/messages
返回：成功/失败、响应时间、Token 用量、失败原因、修复建议。
"""
from __future__ import annotations

import time
from typing import Any, Dict, Optional

from .llm_providers import get_provider

try:
    import requests  # type: ignore
except Exception:  # noqa: BLE001
    requests = None  # type: ignore


def _build_headers(provider_id: str, api_key: str,
                    base_url: str) -> Dict[str, str]:
    p = get_provider(provider_id) or {}
    scheme = p.get("auth_scheme", "Bearer")
    header = p.get("auth_header", "Authorization")
    if not header:
        return {}
    if scheme == "Bearer":
        return {header: f"Bearer {api_key}",
                "Content-Type": "application/json"}
    return {header: api_key, "Content-Type": "application/json"}


def test_key(provider_id: str, api_key: str,
             base_url: Optional[str] = None,
             model: Optional[str] = None,
             timeout: int = 60,
             proxy: Optional[str] = None,
             prompt: str = "Hello") -> Dict[str, Any]:
    if requests is None:
        return {"success": False, "error": "requests 未安装",
                "suggestion": "执行 pip install requests"}

    p = get_provider(provider_id)
    if not p:
        return {"success": False, "error": f"未知提供商 {provider_id}"}
    base = (base_url or p["default_base_url"]).rstrip("/")
    mdl = model or (p["models"][0] if p["models"] else "gpt-3.5-turbo")

    proxies = {"http": proxy, "https": proxy} if proxy else None
    started = time.time()
    try:
        if provider_id == "anthropic":
            url = f"{base}/messages"
            headers = _build_headers(provider_id, api_key, base)
            headers["anthropic-version"] = "2023-06-01"
            payload = {"model": mdl, "max_tokens": 64,
                       "messages": [{"role": "user", "content": prompt}]}
        else:
            url = f"{base}/chat/completions"
            headers = _build_headers(provider_id, api_key, base)
            payload = {"model": mdl,
                       "messages": [{"role": "user", "content": prompt}],
                       "max_tokens": 64, "temperature": 0.7}
        r = requests.post(url, headers=headers, json=payload,
                          timeout=timeout, proxies=proxies)
        elapsed = round((time.time() - started) * 1000, 1)
        if r.status_code == 200:
            data = r.json()
            content = ""
            if provider_id == "anthropic":
                content = (data.get("content") or [{}])[0].get("text", "")
            else:
                choices = data.get("choices") or []
                content = (choices[0].get("message") or {}).get("content", "")
            usage = data.get("usage", {})
            return {"success": True,
                    "provider": provider_id, "model": mdl,
                    "elapsed_ms": elapsed,
                    "reply": content[:500],
                    "prompt_tokens": usage.get("prompt_tokens"),
                    "completion_tokens": usage.get("completion_tokens"),
                    "total_tokens": usage.get("total_tokens")}
        # 错误分类
        reason, suggestion = _classify_error(r.status_code, r.text)
        return {"success": False, "provider": provider_id, "model": mdl,
                "elapsed_ms": elapsed,
                "status_code": r.status_code,
                "error": reason, "detail": r.text[:500],
                "suggestion": suggestion}
    except requests.exceptions.ConnectTimeout:
        return {"success": False, "error": "连接超时",
                "suggestion": "检查网络 / base_url / 代理设置"}
    except requests.exceptions.SSLError:
        return {"success": False, "error": "SSL 错误",
                "suggestion": "检查证书或代理"}
    except requests.exceptions.ConnectionError:
        return {"success": False, "error": "网络连接失败",
                "suggestion": f"无法连接 {base}，检查网络或 base_url"}
    except Exception as e:  # noqa: BLE001
        return {"success": False, "error": f"请求异常: {e}",
                "suggestion": "检查 API Key / Base URL / 网络"}


def _classify_error(status: int, text: str) -> tuple:
    t = text.lower()
    if status == 401 or "unauthorized" in t or "invalid_api_key" in t:
        return ("认证失败（401）", "API Key 错误或已失效，请重新复制")
    if status == 402 or "insufficient" in t or "quota" in t or "balance" in t:
        return ("余额不足", "账户余额/额度不足，请充值或更换 Key")
    if status == 404 or "model_not_found" in t or "does not exist" in t:
        return ("模型不存在", "该模型名不正确或未开通，请从模型列表选择")
    if status == 429:
        return ("限流", "请求太频繁，稍后再试或降低并发")
    if status == 400:
        return ("请求参数错误", "检查 base_url / model / 消息格式")
    return (f"HTTP {status}", "查看 detail 字段获取原始错误")
