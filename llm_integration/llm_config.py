# -*- coding: utf-8 -*-
"""
llm_integration/llm_config.py — LLM 配置管理

统一读取 / 写入 .env 中的 LLM_* 配置项，作为全项目 LLM 接入的唯一配置源。
所有 AI 模块（自然语言、漏洞验证、修复方案、安全助手）都从这里取配置，
避免各自读取环境变量导致不一致。

设计要点：
    - 读取优先级：显式传入 > 系统环境变量 > .env 文件
    - 没有 API Key 时不抛异常，仅标记为「未配置」，系统降级到规则化模式
    - save_config() 会原子地回写 .env，并刷新进程内环境变量
"""
from __future__ import annotations

import os
from pathlib import Path
from typing import Any, Dict, Optional

try:
    from dotenv import load_dotenv, set_key
except ImportError:  # pragma: no cover
    load_dotenv = None
    set_key = None  # type: ignore


# 项目根目录（本文件位于 <root>/llm_integration/llm_config.py）
PROJECT_ROOT: Path = Path(__file__).resolve().parent.parent
ENV_PATH: Path = PROJECT_ROOT / ".env"

# .env 中识别的 LLM 配置键
LLM_KEYS = ("LLM_API_KEY", "LLM_BASE_URL", "LLM_MODEL",
            "LLM_TEMPERATURE", "LLM_MAX_TOKENS")

# 默认值
DEFAULTS: Dict[str, str] = {
    "LLM_API_KEY": "",
    "LLM_BASE_URL": "https://open.bigmodel.cn/api/paas/v4",
    "LLM_MODEL": "glm-4-flash",
    "LLM_TEMPERATURE": "0.1",
    "LLM_MAX_TOKENS": "4096",
}


def _ensure_dotenv_loaded() -> None:
    """加载 .env 到进程环境变量（幂等）。"""
    if load_dotenv is not None and ENV_PATH.exists():
        try:
            load_dotenv(dotenv_path=str(ENV_PATH), override=False)
        except Exception:
            pass


class LLMConfigManager:
    """LLM 配置读写与状态管理（线程不安全，按单例使用）。"""

    def __init__(self, env_path: Optional[Path] = None):
        self.env_path = Path(env_path) if env_path else ENV_PATH
        _ensure_dotenv_loaded()

    # ------------------------------------------------------------------
    # 读取
    # ------------------------------------------------------------------
    def get_raw(self, key: str) -> str:
        """读取单个配置项：环境变量优先，否则回退默认值。"""
        val = os.getenv(key)
        if val is None:
            return DEFAULTS.get(key, "")
        return val.strip()

    def get_config(self) -> Dict[str, Any]:
        """返回完整配置快照（API Key 做脱敏）。"""
        api_key = self.get_raw("LLM_API_KEY")
        return {
            "api_key": api_key,
            "api_key_masked": self._mask_key(api_key),
            "base_url": self.get_raw("LLM_BASE_URL").rstrip("/"),
            "model": self.get_raw("LLM_MODEL"),
            "temperature": self._to_float(self.get_raw("LLM_TEMPERATURE"), 0.1),
            "max_tokens": self._to_int(self.get_raw("LLM_MAX_TOKENS"), 4096),
        }

    @staticmethod
    def _mask_key(key: str) -> str:
        """对 API Key 脱敏：只显示前 4 位与后 4 位。"""
        if not key:
            return ""
        if len(key) <= 8:
            return "*" * len(key)
        return f"{key[:4]}{'*' * (len(key) - 8)}{key[-4:]}"

    @staticmethod
    def _to_float(v: str, default: float) -> float:
        try:
            return float(v)
        except (TypeError, ValueError):
            return default

    @staticmethod
    def _to_int(v: str, default: int) -> int:
        try:
            return int(float(v))
        except (TypeError, ValueError):
            return default

    # ------------------------------------------------------------------
    # 状态
    # ------------------------------------------------------------------
    def is_configured(self) -> bool:
        """是否已配置可用的 LLM（API Key + Base URL 均非空）。"""
        cfg = self.get_config()
        return bool(cfg["api_key"] and cfg["base_url"])

    def status(self) -> Dict[str, Any]:
        """返回前端需要的状态摘要。"""
        cfg = self.get_config()
        configured = self.is_configured()
        return {
            "configured": configured,
            "provider_hint": self._guess_provider(cfg["base_url"]),
            "base_url": cfg["base_url"],
            "model": cfg["model"],
            "api_key_masked": cfg["api_key_masked"],
            "temperature": cfg["temperature"],
            "max_tokens": cfg["max_tokens"],
            "env_path": str(self.env_path),
            "message": "已配置 LLM" if configured else "未配置 API Key，AI 功能降级为规则化模式",
        }

    @staticmethod
    def _guess_provider(base_url: str) -> str:
        """根据 base_url 猜测提供商标识。"""
        u = (base_url or "").lower()
        if "bigmodel" in u or "zhipu" in u or "glm" in u:
            return "zhipu"
        if "deepseek" in u:
            return "deepseek"
        if "siliconflow" in u:
            return "siliconflow"
        if "openai" in u or "api.openai" in u:
            return "openai"
        return "openai_compatible"

    # ------------------------------------------------------------------
    # 写入
    # ------------------------------------------------------------------
    def save_config(self, api_key: Optional[str] = None,
                    base_url: Optional[str] = None,
                    model: Optional[str] = None,
                    temperature: Optional[float] = None,
                    max_tokens: Optional[int] = None) -> Dict[str, Any]:
        """保存配置到 .env，并同步进程环境变量。仅更新传入的字段。"""
        updates: Dict[str, str] = {}
        if api_key is not None:
            updates["LLM_API_KEY"] = api_key.strip()
        if base_url is not None:
            updates["LLM_BASE_URL"] = base_url.strip().rstrip("/")
        if model is not None:
            updates["LLM_MODEL"] = model.strip()
        if temperature is not None:
            updates["LLM_TEMPERATURE"] = str(temperature)
        if max_tokens is not None:
            updates["LLM_MAX_TOKENS"] = str(int(max_tokens))

        if not updates:
            return {"success": False, "error": "未提供任何需要保存的配置项", "data": None}

        # 确保 .env 存在
        if not self.env_path.exists():
            try:
                self.env_path.touch()
            except OSError as e:
                return {"success": False, "error": f"无法创建 .env: {e}", "data": None}

        # 写文件（自写行替换，避免 python-dotenv 给值自动加引号）+ 同步环境变量
        for k, v in updates.items():
            try:
                self._write_dotenv(k, v)
            except Exception as e:
                return {"success": False, "error": f"写入 {k} 失败: {e}", "data": None}
            os.environ[k] = v  # 立即生效

        return {"success": True, "error": None,
                "data": {"saved_keys": list(updates.keys()),
                         "status": self.status()}}

    def _write_dotenv(self, key: str, value: str) -> None:
        """替换或追加一行 KEY=VALUE（不额外加引号，保持 .env 干净）。"""
        lines = []
        if self.env_path.exists():
            with open(self.env_path, "r", encoding="utf-8") as f:
                lines = f.read().splitlines()
        out, found = [], False
        for line in lines:
            if line.strip().startswith(f"{key}="):
                out.append(f"{key}={value}")
                found = True
            else:
                out.append(line)
        if not found:
            out.append(f"{key}={value}")
        with open(self.env_path, "w", encoding="utf-8") as f:
            f.write("\n".join(out) + "\n")

    def _append_dotenv(self, key: str, value: str) -> None:
        """无 python-dotenv 时的回退写入（沿用 _write_dotenv）。"""
        self._write_dotenv(key, value)


# 模块级单例
_manager: Optional[LLMConfigManager] = None


def get_config_manager() -> LLMConfigManager:
    """获取全局配置管理器单例。"""
    global _manager
    if _manager is None:
        _manager = LLMConfigManager()
    return _manager


def reload_config() -> None:
    """重新加载 .env（保存配置后调用，使所有客户端即时生效）。"""
    _ensure_dotenv_loaded()
