# -*- coding: utf-8 -*-
"""
llm_integration/llm_config_guide.py — LLM 提供商配置引导数据

集中维护支持的 LLM 提供商清单、默认 Base URL / 模型、获取 API Key 的步骤，
供前端配置页面渲染「快速配置引导」和提供商下拉选择。纯数据，无副作用。
"""
from __future__ import annotations

from typing import Any, Dict, List


# 支持的 LLM 提供商（OpenAI 兼容接口）
PROVIDERS: List[Dict[str, Any]] = [
    {
        "id": "zhipu",
        "name": "智谱AI (GLM)",
        "base_url": "https://open.bigmodel.cn/api/paas/v4",
        "default_model": "glm-4-flash",
        "models": ["glm-4-flash", "glm-4-air", "glm-4-plus", "glm-4-long"],
        "api_key_url": "https://open.bigmodel.cn/usercenter/apikeys",
        "homepage": "https://open.bigmodel.cn/",
        "desc": "国内老牌大模型服务商，GLM-4-Flash 免费、速度快，适合起步。",
        "get_key_steps": [
            "打开智谱AI开放平台 open.bigmodel.cn 注册/登录",
            "进入「API Keys」控制台，点击「创建 API Key」",
            "复制生成的 Key（以一串字母数字组成）粘贴到下方",
            "模型推荐填 glm-4-flash（免费额度充足）",
        ],
    },
    {
        "id": "deepseek",
        "name": "DeepSeek",
        "base_url": "https://api.deepseek.com/v1",
        "default_model": "deepseek-chat",
        "models": ["deepseek-chat", "deepseek-reasoner"],
        "api_key_url": "https://platform.deepseek.com/api_keys",
        "homepage": "https://platform.deepseek.com/",
        "desc": "推理能力强、价格低廉，deepseek-chat 性价比高。",
        "get_key_steps": [
            "打开 DeepSeek 开放平台 platform.deepseek.com 注册",
            "进入「API Keys」页面，点击「创建 API Key」",
            "复制 sk- 开头的密钥粘贴到下方",
            "模型推荐填 deepseek-chat",
        ],
    },
    {
        "id": "siliconflow",
        "name": "硅基流动 (SiliconFlow)",
        "base_url": "https://api.siliconflow.cn/v1",
        "default_model": "Qwen/Qwen2.5-7B-Instruct",
        "models": [
            "Qwen/Qwen2.5-7B-Instruct",
            "Qwen/Qwen2.5-72B-Instruct",
            "deepseek-ai/DeepSeek-V2.5",
            "THUDM/glm-4-9b-chat",
        ],
        "api_key_url": "https://cloud.siliconflow.cn/account/ak",
        "homepage": "https://siliconflow.cn/",
        "desc": "聚合托管众多开源模型，新用户赠送额度，可选模型丰富。",
        "get_key_steps": [
            "打开硅基流动 cloud.siliconflow.cn 注册",
            "进入「账号 -> API 密钥」新建密钥",
            "复制 sk- 开头的密钥粘贴到下方",
            "模型需带发布者前缀，如 Qwen/Qwen2.5-7B-Instruct",
        ],
    },
    {
        "id": "openai",
        "name": "OpenAI 兼容 (自定义)",
        "base_url": "https://api.openai.com/v1",
        "default_model": "gpt-4o-mini",
        "models": ["gpt-4o-mini", "gpt-4o", "gpt-3.5-turbo", "自定义模型名"],
        "api_key_url": "https://platform.openai.com/api-keys",
        "homepage": "https://platform.openai.com/",
        "desc": "任意兼容 OpenAI Chat Completions 协议的网关 / 自建服务。",
        "get_key_steps": [
            "在对应服务商控制台创建 API Key",
            "Base URL 填服务商提供的接口根地址（不要带 /chat/completions）",
            "Model 填该服务支持的模型名",
            "本地代理/自建服务也按此格式填写",
        ],
    },
]


def list_providers() -> List[Dict[str, Any]]:
    """返回提供商列表（供 GET /providers）。"""
    return PROVIDERS


def get_provider(provider_id: str) -> Dict[str, Any]:
    """按 id 取提供商配置，找不到回退到 openai 兼容。"""
    for p in PROVIDERS:
        if p["id"] == provider_id:
            return p
    return PROVIDERS[-1]


def quick_config(provider_id: str) -> Dict[str, Any]:
    """按提供商 id 给出一键预填参数。"""
    p = get_provider(provider_id)
    return {
        "id": p["id"],
        "name": p["name"],
        "base_url": p["base_url"],
        "model": p["default_model"],
        "models": p["models"],
        "api_key_url": p["api_key_url"],
    }
