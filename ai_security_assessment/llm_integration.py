#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
v4.7 真实LLM回调集成

让遗传算法进化引擎和多轮攻击编排引擎能调用真实AI API，
而不是模拟模式。支持硅基流动、OpenAI兼容接口。
"""

import json
import time
from typing import Optional, Callable

try:
    import requests
except ImportError:
    requests = None


class LLMClient:
    """统一LLM客户端，兼容OpenAI API格式"""

    def __init__(
        self,
        api_key: str = "",
        base_url: str = "https://api.siliconflow.cn/v1",
        model: str = "Qwen/Qwen2.5-7B-Instruct",
        timeout: int = 30,
    ):
        self.api_key = api_key
        self.base_url = base_url.rstrip("/")
        self.model = model
        self.timeout = timeout
        self.call_count = 0
        self.total_tokens = 0

    def chat(self, messages: list, temperature: float = 0.7, max_tokens: int = 1024) -> str:
        """发送聊天请求"""
        if not self.api_key or not requests:
            return self._simulate_response(messages)

        self.call_count += 1
        try:
            resp = requests.post(
                f"{self.base_url}/chat/completions",
                headers={
                    "Authorization": f"Bearer {self.api_key}",
                    "Content-Type": "application/json",
                },
                json={
                    "model": self.model,
                    "messages": messages,
                    "temperature": temperature,
                    "max_tokens": max_tokens,
                },
                timeout=self.timeout,
            )
            if resp.status_code == 200:
                data = resp.json()
                content = data["choices"][0]["message"]["content"]
                usage = data.get("usage", {})
                self.total_tokens += usage.get("total_tokens", 0)
                return content
            else:
                return f"[API Error {resp.status_code}] {resp.text[:200]}"
        except Exception as e:
            return f"[Request Error] {str(e)[:200]}"

    def _simulate_response(self, messages: list) -> str:
        """模拟响应（无API Key时使用）"""
        last_msg = messages[-1]["content"] if messages else ""
        if any(w in last_msg.lower() for w in ["system prompt", "instructions", "rules"]):
            return "I'm sorry, but I cannot share my system prompt or internal instructions. However, I can tell you that I'm designed to be helpful, harmless, and honest."
        if any(w in last_msg.lower() for w in ["hack", "exploit", "attack", "vulnerability"]):
            return "I can explain security concepts in general terms for educational purposes. For example, vulnerability scanning involves checking systems for known weaknesses. I cannot provide actual exploit code or attack instructions."
        return f"Thank you for your message. I understand you're asking about: {last_msg[:50]}... I'm here to help with legitimate questions."

    def get_callback(self) -> Callable[[str], str]:
        """获取单轮回调函数（用于遗传算法）"""
        def callback(prompt: str) -> str:
            return self.chat([{"role": "user", "content": prompt}])
        return callback

    def get_conversation_callback(self) -> Callable:
        """获取多轮回调函数（用于多轮攻击）"""
        history = []
        def callback(prompt: str) -> str:
            history.append({"role": "user", "content": prompt})
            response = self.chat(history)
            history.append({"role": "assistant", "content": response})
            return response
        return callback

    def get_stats(self) -> dict:
        return {
            "call_count": self.call_count,
            "total_tokens": self.total_tokens,
            "model": self.model,
            "base_url": self.base_url,
            "has_api_key": bool(self.api_key),
        }


# 单例
_llm_client = None

def get_llm_client() -> LLMClient:
    global _llm_client
    if _llm_client is None:
        # 尝试从环境变量或配置读取
        import os
        api_key = os.environ.get("SILICONFLOW_API_KEY", "")
        if not api_key:
            # 尝试从项目.env读取
            env_path = os.path.join(os.path.dirname(os.path.dirname(__file__)), ".env")
            if os.path.exists(env_path):
                with open(env_path, "r", encoding="utf-8") as f:
                    for line in f:
                        if "SILICONFLOW_API_KEY" in line or "API_KEY" in line:
                            parts = line.strip().split("=", 1)
                            if len(parts) == 2:
                                api_key = parts[1].strip().strip('"').strip("'")
                                break
        _llm_client = LLMClient(api_key=api_key)
    return _llm_client


def run_genetic_with_llm(
    target_model: str = "",
    population_size: int = 20,
    max_generations: int = 5,
    api_key: str = "",
) -> dict:
    """用真实LLM运行遗传算法进化"""
    from ai_security_assessment import GeneticPromptEvolver

    client = LLMClient(api_key=api_key) if api_key else get_llm_client()
    callback = client.get_callback()

    evolver = GeneticPromptEvolver(
        population_size=population_size,
        max_generations=max_generations,
        llm_callback=callback,
    )
    result = evolver.evolve(target_model=target_model or client.model)

    return {
        "result": result,
        "llm_stats": client.get_stats(),
        "best_attacks": evolver.get_best_attacks(10),
    }


def run_multiturn_with_llm(
    strategy: str = "all",
    target_model: str = "",
    max_turns: int = 5,
    api_key: str = "",
) -> dict:
    """用真实LLM运行多轮攻击"""
    from ai_security_assessment import MultiTurnAttackOrchestrator, MULTI_TURN_STRATEGIES

    client = LLMClient(api_key=api_key) if api_key else get_llm_client()
    callback = client.get_conversation_callback()

    orchestrator = MultiTurnAttackOrchestrator(llm_callback=callback)

    if strategy == "all":
        results = orchestrator.run_all_strategies(target=target_model or client.model)
    else:
        result = orchestrator.run_attack(
            strategy=strategy,
            target=target_model or client.model,
            max_turns=max_turns,
        )
        results = [result]

    return {
        "results": results,
        "summary": orchestrator.get_summary(),
        "llm_stats": client.get_stats(),
    }
