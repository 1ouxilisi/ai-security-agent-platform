"""
client模块，提供相关安全测试功能。

模块功能：
    - 提供相关安全测试功能
    - 支持API调用和命令行使用
    - 与其他模块集成协作

注意事项：
    - 本模块仅用于授权的安全测试
    - 请勿用于非法用途
    - 使用前请确保已获得相关授权
"""

import os
import json
import time
from typing import List, Dict, Any, Optional
from loguru import logger

# 自动加载.env文件
try:
    from dotenv import load_dotenv
    load_dotenv()
except ImportError:
    pass

try:
    from openai import OpenAI
    HAS_OPENAI = True
except ImportError:
    HAS_OPENAI = False
    logger.warning("openai库未安装，LLM调用功能不可用。请运行: pip install openai")


class LLMClient:
    """大模型调用客户端"""

    def __init__(
        self,
        api_key: Optional[str] = None,
        base_url: Optional[str] = None,
        model: Optional[str] = None,
        temperature: float = 0.1,
        max_tokens: int = 4096,
        timeout: int = 60,
    ):
        """初始化LLMClient实例。

        Args:
            self: 类实例。
        """
        self.api_key = api_key or os.getenv("LLM_API_KEY", "")
        self.base_url = base_url or os.getenv("LLM_BASE_URL", "https://api.deepseek.com/v1")
        self.model = model or os.getenv("LLM_MODEL", "deepseek-chat")
        self.temperature = temperature or float(os.getenv("LLM_TEMPERATURE", "0.1"))
        self.max_tokens = max_tokens or int(os.getenv("LLM_MAX_TOKENS", "4096"))
        self.timeout = timeout
        self.client = None
        self.call_count = 0
        self.total_tokens = 0
        self.last_error = None

        if HAS_OPENAI and self.api_key and self.api_key != "sk-your-api-key-here":
            try:
                self.client = OpenAI(
                    api_key=self.api_key,
                    base_url=self.base_url,
                    timeout=self.timeout,
                )
                logger.info(f"LLM客户端初始化成功: model={self.model}, base_url={self.base_url}")
            except Exception as e:
                logger.error(f"LLM客户端初始化失败: {e}")
                self.last_error = str(e)
        else:
            if not self.api_key or self.api_key == "sk-your-api-key-here":
                logger.warning("LLM_API_KEY未配置，LLM调用功能不可用")
            if not HAS_OPENAI:
                logger.warning("openai库未安装，请运行: pip install openai")

    @property
    def is_available(self) -> bool:
        """LLM是否可用"""
        return self.client is not None and HAS_OPENAI

    def chat(
        self,
        messages: List[Dict[str, str]],
        temperature: Optional[float] = None,
        max_tokens: Optional[int] = None,
        response_format: Optional[Dict] = None,
    ) -> Optional[str]:
        """
        发送聊天请求

        Args:
            messages: 消息列表，格式 [{"role": "user", "content": "..."}]
            temperature: 温度
            max_tokens: 最大token数
            response_format: 响应格式，如 {"type": "json_object"}

        Returns:
            响应文本，失败返回None
        """
        if not self.is_available:
            self.last_error = "LLM客户端不可用（未配置API密钥或未安装openai库）"
            logger.error(self.last_error)
            return None

        try:
            start_time = time.time()
            kwargs = {
                "model": self.model,
                "messages": messages,
                "temperature": temperature or self.temperature,
                "max_tokens": max_tokens or self.max_tokens,
            }
            if response_format:
                kwargs["response_format"] = response_format

            response = self.client.chat.completions.create(**kwargs)
            elapsed = time.time() - start_time

            content = response.choices[0].message.content
            usage = response.usage

            self.call_count += 1
            if usage:
                self.total_tokens += usage.total_tokens

            logger.info(
                f"LLM调用成功: model={self.model}, "
                f"tokens={usage.total_tokens if usage else 'N/A'}, "
                f"time={elapsed:.2f}s"
            )
            return content

        except Exception as e:
            self.last_error = str(e)
            logger.error(f"LLM调用失败: {e}")
            return None

    def chat_json(
        self,
        messages: List[Dict[str, str]],
        temperature: Optional[float] = None,
    ) -> Optional[Dict]:
        """
        发送聊天请求并解析JSON响应

        Args:
            messages: 消息列表
            temperature: 温度

        Returns:
            解析后的JSON字典，失败返回None
        """
        # 确保系统消息要求JSON输出
        json_messages = []
        has_system = False
        for msg in messages:
            if msg["role"] == "system":
                msg = msg.copy()
                msg["content"] = msg["content"] + "\n\n请严格以JSON格式回复，不要包含任何其他文字。"
                has_system = True
            json_messages.append(msg)

        if not has_system:
            json_messages.insert(0, {
                "role": "system",
                "content": "你是一个专业的安全分析助手。请严格以JSON格式回复，不要包含任何其他文字、解释或markdown标记。"
            })

        content = self.chat(json_messages, temperature=temperature)
        if not content:
            return None

        # 清理可能的markdown标记
        content = content.strip()
        if content.startswith("```json"):
            content = content[7:]
        if content.startswith("```"):
            content = content[3:]
        if content.endswith("```"):
            content = content[:-3]
        content = content.strip()

        try:
            return json.loads(content)
        except json.JSONDecodeError as e:
            logger.error(f"JSON解析失败: {e}, 原始内容: {content[:200]}")
            self.last_error = f"JSON解析失败: {e}"
            return None

    def simple_chat(self, user_message: str, system_message: Optional[str] = None) -> Optional[str]:
        """
        简单的单轮对话

        Args:
            user_message: 用户消息
            system_message: 系统消息

        Returns:
            响应文本
        """
        messages = []
        if system_message:
            messages.append({"role": "system", "content": system_message})
        messages.append({"role": "user", "content": user_message})
        return self.chat(messages)

    def get_stats(self) -> Dict:
        """获取调用统计"""
        return {
            "is_available": self.is_available,
            "model": self.model,
            "base_url": self.base_url,
            "call_count": self.call_count,
            "total_tokens": self.total_tokens,
            "last_error": self.last_error,
        }


# 全局单例
_llm_client: Optional[LLMClient] = None


def get_llm_client() -> LLMClient:
    """获取全局LLM客户端单例"""
    global _llm_client
    if _llm_client is None:
        _llm_client = LLMClient()
    return _llm_client


def test_llm_connection() -> Dict:
    """测试LLM连接"""
    client = get_llm_client()
    result = {
        "is_available": client.is_available,
        "model": client.model,
        "base_url": client.base_url,
    }

    if not client.is_available:
        result["error"] = client.last_error or "LLM不可用"
        result["fix"] = "请在.env文件中配置LLM_API_KEY，并运行 pip install openai"
        return result

    # 发送测试消息
    test_response = client.simple_chat(
        user_message="请回复'连接成功'四个字，不要回复其他内容。",
        system_message="你是一个测试助手。"
    )

    if test_response:
        result["connection"] = "成功"
        result["test_response"] = test_response[:100]
    else:
        result["connection"] = "失败"
        result["error"] = client.last_error

    return result

# 向后兼容：部分旧脚本/测试使用 `from llm.client import llm_client`
llm_client = get_llm_client()
