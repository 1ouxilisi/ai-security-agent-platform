# -*- coding: utf-8 -*-
"""
llm_config/llm_providers.py — LLM 提供商注册表

维护所有支持的 LLM 提供商：
  - 默认 API Base URL
  - 模型列表
  - 鉴权方式（Bearer / ApiKey header）
  - 申请地址 / 免费额度说明
纯数据。
"""
from __future__ import annotations

from typing import Any, Dict, List

PROVIDERS: Dict[str, Dict[str, Any]] = {
    "deepseek": {
        "name": "DeepSeek",
        "default_base_url": "https://api.deepseek.com/v1",
        "auth_header": "Authorization",
        "auth_scheme": "Bearer",
        "models": ["deepseek-chat", "deepseek-coder", "deepseek-reasoner"],
        "apply_url": "https://platform.deepseek.com/api_keys",
        "free_quota": "新用户赠送 500 万 Tokens（限时）",
        "docs": "https://platform.deepseek.com/docs",
    },
    "openai": {
        "name": "OpenAI",
        "default_base_url": "https://api.openai.com/v1",
        "auth_header": "Authorization",
        "auth_scheme": "Bearer",
        "models": ["gpt-4o", "gpt-4o-mini", "gpt-4-turbo", "gpt-3.5-turbo"],
        "apply_url": "https://platform.openai.com/api-keys",
        "free_quota": "注册赠 $5（部分账号）",
        "docs": "https://platform.openai.com/docs",
    },
    "anthropic": {
        "name": "Anthropic",
        "default_base_url": "https://api.anthropic.com/v1",
        "auth_header": "x-api-key",
        "auth_scheme": "",
        "models": ["claude-3-opus-latest", "claude-3-sonnet-latest",
                   "claude-3-haiku-latest"],
        "apply_url": "https://console.anthropic.com/",
        "free_quota": "新用户赠 $5",
        "docs": "https://docs.anthropic.com",
    },
    "qwen": {
        "name": "通义千问",
        "default_base_url": "https://dashscope.aliyuncs.com/compatible-mode/v1",
        "auth_header": "Authorization",
        "auth_scheme": "Bearer",
        "models": ["qwen-max", "qwen-plus", "qwen-turbo", "qwen-long"],
        "apply_url": "https://dashscope.console.aliyun.com/apiKey",
        "free_quota": "新用户百万 Tokens 免费额度",
        "docs": "https://help.aliyun.com/zh/dashscope/",
    },
    "ernie": {
        "name": "文心一言",
        "default_base_url": "https://aip.baidubce.com/rpc/2.0/ai_custom/v1",
        "auth_header": "",
        "auth_scheme": "query_access_token",
        "models": ["ernie-4.0-8k", "ernie-3.5-8k", "ernie-speed"],
        "apply_url": "https://console.bce.baidu.com/qianfan/ais/console/applicationConsole/application",
        "free_quota": "新用户有免费额度",
        "docs": "https://cloud.baidu.com/doc/WENXINWORKSHOP/",
    },
    "spark": {
        "name": "讯飞星火",
        "default_base_url": "https://spark-api-open.xf-yun.com/v1",
        "auth_header": "Authorization",
        "auth_scheme": "Bearer",
        "models": ["spark-max", "spark-pro", "spark-lite"],
        "apply_url": "https://console.xfyun.cn/services/cbm",
        "free_quota": "每日赠送额度",
        "docs": "https://www.xfyun.cn/doc/spark/",
    },
    "zhipu": {
        "name": "智谱AI",
        "default_base_url": "https://open.bigmodel.cn/api/paas/v4",
        "auth_header": "Authorization",
        "auth_scheme": "Bearer",
        "models": ["glm-4-plus", "glm-4", "glm-4-flash", "glm-3-turbo"],
        "apply_url": "https://open.bigmodel.cn/usercenter/apikeys",
        "free_quota": "新用户赠 tokens",
        "docs": "https://open.bigmodel.cn/dev/api",
    },
    "moonshot": {
        "name": "月之暗面 Kimi",
        "default_base_url": "https://api.moonshot.cn/v1",
        "auth_header": "Authorization",
        "auth_scheme": "Bearer",
        "models": ["moonshot-v1-8k", "moonshot-v1-32k", "moonshot-v1-128k"],
        "apply_url": "https://platform.moonshot.cn/console/api-keys",
        "free_quota": "新用户赠送额度",
        "docs": "https://platform.moonshot.cn/docs",
    },
    "hunyuan": {
        "name": "腾讯混元",
        "default_base_url": "https://api.hunyuan.cloud.tencent.com/v1",
        "auth_header": "Authorization",
        "auth_scheme": "Bearer",
        "models": ["hunyuan-pro", "hunyuan-standard", "hunyuan-lite"],
        "apply_url": "https://console.cloud.tencent.com/hunyuan/api-key",
        "free_quota": "新用户有免费额度",
        "docs": "https://cloud.tencent.com/document/product/1729",
    },
    "local": {
        "name": "本地模型",
        "default_base_url": "http://127.0.0.1:11434/v1",
        "auth_header": "Authorization",
        "auth_scheme": "Bearer",
        "models": ["llama3", "qwen2", "deepseek-r1", "mistral"],
        "apply_url": "https://ollama.com",
        "free_quota": "完全本地免费",
        "docs": "https://github.com/ollama/ollama",
        "note": "支持 Ollama / LM Studio / vLLM 的 OpenAI 兼容端点",
    },
}


def list_providers() -> List[Dict[str, Any]]:
    out = []
    for k, v in PROVIDERS.items():
        out.append({"id": k, **{kk: vv for kk, vv in v.items()}})
    return out


def get_provider(pid: str) -> Dict[str, Any] | None:
    return PROVIDERS.get(pid)


def get_models(pid: str) -> List[str]:
    p = PROVIDERS.get(pid)
    return list(p["models"]) if p else []
