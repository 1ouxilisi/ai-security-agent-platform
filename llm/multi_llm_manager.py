#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
multi_llm_manager模块，提供相关安全测试功能。

模块功能：
    - 提供相关安全测试功能
    - 支持API调用和命令行使用
    - 与其他模块集成协作

注意事项：
    - 本模块仅用于授权的安全测试
    - 请勿用于非法用途
    - 使用前请确保已获得相关授权
"""

import json
import os
import time
import threading
from typing import Dict, List, Optional, Any, Tuple
from dataclasses import dataclass, field
from enum import Enum
from loguru import logger

try:
    import requests
except ImportError:
    requests = None


class ModelProvider(Enum):
    """模型服务商"""
    ZHIPU = "zhipu"  # 智谱AI
    SILICONFLOW = "siliconflow"  # 硅基流动
    DEEPSEEK = "deepseek"  # DeepSeek
    OPENAI = "openai"  # OpenAI
    MODELVERSE = "modelverse"  # 模型宇宙
    CUSTOM = "custom"  # 自定义


class TaskType(Enum):
    """任务类型（用于选择最优模型）"""
    CODE = "code"  # 代码生成/审查
    ANALYSIS = "analysis"  # 漏洞分析
    REPORT = "report"  # 报告生成
    CHAT = "chat"  # 日常对话
    PLANNING = "planning"  # 任务规划
    TRANSLATION = "translation"  # 翻译


@dataclass
class ModelConfig:
    """模型配置"""
    name: str  # 配置名称
    provider: str  # 服务商
    api_key: str
    base_url: str
    model: str
    max_tokens: int = 4096
    temperature: float = 0.1
    enabled: bool = True
    priority: int = 10  # 优先级，数字越大越优先
    weight: int = 1  # 负载均衡权重
    cost_per_1k_input: float = 0.0  # 每1k输入token成本
    cost_per_1k_output: float = 0.0  # 每1k输出token成本
    rpm_limit: int = 60  # 每分钟请求限制
    tpm_limit: int = 100000  # 每分钟token限制
    supported_tasks: List[str] = field(default_factory=lambda: ["code", "analysis", "report", "chat", "planning", "translation"])
    notes: str = ""


@dataclass
class ModelStats:
    """模型统计"""
    name: str
    total_requests: int = 0
    successful_requests: int = 0
    failed_requests: int = 0
    total_tokens: int = 0
    total_cost: float = 0.0
    avg_response_time: float = 0.0
    last_used: str = ""
    consecutive_failures: int = 0
    is_healthy: bool = True


class MultiLLMManager:
    """多模型管理器"""

    def __init__(self, config_path: Optional[str] = None):
        """初始化MultiLLMManager实例。

        Args:
            self: 类实例。
        """
        self.config_path = config_path or "./config/multi_llm_config.json"
        self.models: Dict[str, ModelConfig] = {}
        self.stats: Dict[str, ModelStats] = {}
        self.current_model: Optional[str] = None
        self._lock = threading.Lock()
        self._request_count = 0

        self._ensure_config_dir()
        self._load_config()
        self._init_stats()

        if self.models:
            self.current_model = self._get_highest_priority_model()
            logger.info(f"多模型管理器初始化完成，共{len(self.models)}个模型，当前使用: {self.current_model}")
        else:
            logger.warning("多模型管理器初始化完成，但没有配置任何模型")

    def _ensure_config_dir(self):
        """确保配置目录存在"""
        os.makedirs(os.path.dirname(self.config_path), exist_ok=True)

    def _load_config(self):
        """加载配置"""
        if os.path.exists(self.config_path):
            try:
                with open(self.config_path, "r", encoding="utf-8") as f:
                    data = json.load(f)
                for name, cfg in data.get("models", {}).items():
                    model = ModelConfig(
                        name=name,
                        provider=cfg.get("provider", "custom"),
                        api_key=cfg.get("api_key", ""),
                        base_url=cfg.get("base_url", ""),
                        model=cfg.get("model", ""),
                        max_tokens=cfg.get("max_tokens", 4096),
                        temperature=cfg.get("temperature", 0.1),
                        enabled=cfg.get("enabled", True),
                        priority=cfg.get("priority", 10),
                        weight=cfg.get("weight", 1),
                        cost_per_1k_input=cfg.get("cost_per_1k_input", 0.0),
                        cost_per_1k_output=cfg.get("cost_per_1k_output", 0.0),
                        rpm_limit=cfg.get("rpm_limit", 60),
                        tpm_limit=cfg.get("tpm_limit", 100000),
                        supported_tasks=cfg.get("supported_tasks", ["code", "analysis", "report", "chat", "planning", "translation"]),
                        notes=cfg.get("notes", ""),
                    )
                    self.models[name] = model
            except Exception as e:
                logger.error(f"加载多模型配置失败: {e}")
        else:
            # 创建默认配置
            self._create_default_config()

    def _create_default_config(self):
        """创建默认配置"""
        default_config = {
            "models": {
                "zhipu_glm4_flash": {
                    "provider": "zhipu",
                    "api_key": os.getenv("LLM_API_KEY", ""),
                    "base_url": os.getenv("LLM_BASE_URL", "https://open.bigmodel.cn/api/paas/v4"),
                    "model": os.getenv("LLM_MODEL", "glm-4-flash"),
                    "max_tokens": 4096,
                    "temperature": 0.1,
                    "enabled": True,
                    "priority": 10,
                    "weight": 1,
                    "cost_per_1k_input": 0.0,
                    "cost_per_1k_output": 0.0,
                    "rpm_limit": 60,
                    "tpm_limit": 100000,
                    "supported_tasks": ["code", "analysis", "report", "chat", "planning", "translation"],
                    "notes": "智谱AI GLM-4-Flash，免费额度大，适合日常使用"
                }
            },
            "settings": {
                "auto_switch": True,
                "max_consecutive_failures": 3,
                "load_balancing": False,
                "default_task_model": {
                    "code": "zhipu_glm4_flash",
                    "analysis": "zhipu_glm4_flash",
                    "report": "zhipu_glm4_flash",
                    "chat": "zhipu_glm4_flash",
                    "planning": "zhipu_glm4_flash",
                    "translation": "zhipu_glm4_flash"
                }
            }
        }

        try:
            with open(self.config_path, "w", encoding="utf-8") as f:
                json.dump(default_config, f, ensure_ascii=False, indent=2)
            logger.info(f"创建默认多模型配置: {self.config_path}")

            # 加载默认配置
            model = ModelConfig(
                name="zhipu_glm4_flash",
                provider="zhipu",
                api_key=os.getenv("LLM_API_KEY", ""),
                base_url=os.getenv("LLM_BASE_URL", "https://open.bigmodel.cn/api/paas/v4"),
                model=os.getenv("LLM_MODEL", "glm-4-flash"),
                max_tokens=4096,
                temperature=0.1,
                enabled=True,
                priority=10,
                weight=1,
                supported_tasks=["code", "analysis", "report", "chat", "planning", "translation"],
                notes="智谱AI GLM-4-Flash，免费额度大，适合日常使用"
            )
            self.models["zhipu_glm4_flash"] = model
        except Exception as e:
            logger.error(f"创建默认配置失败: {e}")

    def _init_stats(self):
        """初始化统计"""
        for name in self.models:
            if name not in self.stats:
                self.stats[name] = ModelStats(name=name)

    def _get_highest_priority_model(self) -> Optional[str]:
        """获取优先级最高的健康模型"""
        enabled_models = [
            (name, m) for name, m in self.models.items()
            if m.enabled and self.stats.get(name, ModelStats(name=name)).is_healthy
        ]
        if not enabled_models:
            # 如果没有健康模型，返回所有启用的模型
            enabled_models = [(name, m) for name, m in self.models.items() if m.enabled]

        if not enabled_models:
            return None

        enabled_models.sort(key=lambda x: x[1].priority, reverse=True)
        return enabled_models[0][0]

    def add_model(self, config: ModelConfig) -> bool:
        """添加模型"""
        with self._lock:
            self.models[config.name] = config
            if config.name not in self.stats:
                self.stats[config.name] = ModelStats(name=config.name)
            self._save_config()
            logger.info(f"添加模型: {config.name} ({config.provider}/{config.model})")
            return True

    def remove_model(self, name: str) -> bool:
        """删除模型"""
        with self._lock:
            if name in self.models:
                del self.models[name]
                if name in self.stats:
                    del self.stats[name]
                if self.current_model == name:
                    self.current_model = self._get_highest_priority_model()
                self._save_config()
                logger.info(f"删除模型: {name}")
                return True
            return False

    def _save_config(self):
        """保存配置"""
        try:
            data = {"models": {}}
            for name, m in self.models.items():
                data["models"][name] = {
                    "provider": m.provider,
                    "api_key": m.api_key,
                    "base_url": m.base_url,
                    "model": m.model,
                    "max_tokens": m.max_tokens,
                    "temperature": m.temperature,
                    "enabled": m.enabled,
                    "priority": m.priority,
                    "weight": m.weight,
                    "cost_per_1k_input": m.cost_per_1k_input,
                    "cost_per_1k_output": m.cost_per_1k_output,
                    "rpm_limit": m.rpm_limit,
                    "tpm_limit": m.tpm_limit,
                    "supported_tasks": m.supported_tasks,
                    "notes": m.notes,
                }
            with open(self.config_path, "w", encoding="utf-8") as f:
                json.dump(data, f, ensure_ascii=False, indent=2)
        except Exception as e:
            logger.error(f"保存配置失败: {e}")

    def list_models(self) -> List[Dict]:
        """列出所有模型"""
        result = []
        for name, m in self.models.items():
            stat = self.stats.get(name, ModelStats(name=name))
            result.append({
                "name": name,
                "provider": m.provider,
                "model": m.model,
                "base_url": m.base_url,
                "enabled": m.enabled,
                "priority": m.priority,
                "weight": m.weight,
                "is_current": self.current_model == name,
                "is_healthy": stat.is_healthy,
                "total_requests": stat.total_requests,
                "successful_requests": stat.successful_requests,
                "failed_requests": stat.failed_requests,
                "success_rate": round(stat.successful_requests / stat.total_requests * 100, 1) if stat.total_requests > 0 else 0,
                "avg_response_time": round(stat.avg_response_time, 2),
                "total_tokens": stat.total_tokens,
                "total_cost": round(stat.total_cost, 4),
                "supported_tasks": m.supported_tasks,
                "notes": m.notes,
            })
        return result

    def chat(self, messages: List[Dict], task_type: str = "chat", model_name: Optional[str] = None,
             max_tokens: Optional[int] = None, temperature: Optional[float] = None,
             timeout: int = 60) -> Tuple[Optional[str], Dict]:
        """
        发送聊天请求
        返回: (回复内容, 元数据)
        """
        if requests is None:
            return None, {"error": "requests库未安装"}

        # 选择模型
        selected_model = model_name or self._select_model(task_type)
        if not selected_model or selected_model not in self.models:
            return None, {"error": "没有可用的模型"}

        model = self.models[selected_model]
        if not model.enabled:
            return None, {"error": f"模型 {selected_model} 已禁用"}

        stat = self.stats.get(selected_model, ModelStats(name=selected_model))

        start_time = time.time()
        try:
            response = requests.post(
                f"{model.base_url}/chat/completions",
                headers={
                    "Authorization": f"Bearer {model.api_key}",
                    "Content-Type": "application/json"
                },
                json={
                    "model": model.model,
                    "messages": messages,
                    "max_tokens": max_tokens or model.max_tokens,
                    "temperature": temperature if temperature is not None else model.temperature,
                },
                timeout=timeout
            )

            elapsed = time.time() - start_time

            # 更新统计
            stat.total_requests += 1
            stat.last_used = time.strftime("%Y-%m-%d %H:%M:%S")

            if response.status_code == 200:
                data = response.json()
                content = data["choices"][0]["message"]["content"]
                usage = data.get("usage", {})
                input_tokens = usage.get("prompt_tokens", 0)
                output_tokens = usage.get("completion_tokens", 0)
                total_tokens = input_tokens + output_tokens

                stat.successful_requests += 1
                stat.consecutive_failures = 0
                stat.is_healthy = True
                stat.total_tokens += total_tokens
                stat.avg_response_time = (stat.avg_response_time * (stat.successful_requests - 1) + elapsed) / stat.successful_requests

                # 计算成本
                cost = (input_tokens / 1000 * model.cost_per_1k_input) + (output_tokens / 1000 * model.cost_per_1k_output)
                stat.total_cost += cost

                metadata = {
                    "model": selected_model,
                    "provider": model.provider,
                    "model_name": model.model,
                    "status_code": 200,
                    "response_time": round(elapsed, 2),
                    "input_tokens": input_tokens,
                    "output_tokens": output_tokens,
                    "total_tokens": total_tokens,
                    "cost": round(cost, 6),
                    "finish_reason": data["choices"][0].get("finish_reason", ""),
                }

                logger.debug(f"模型 {selected_model} 请求成功，耗时 {elapsed:.2f}s，tokens: {total_tokens}")
                return content, metadata
            else:
                stat.failed_requests += 1
                stat.consecutive_failures += 1
                if stat.consecutive_failures >= 3:
                    stat.is_healthy = False
                    logger.warning(f"模型 {selected_model} 连续失败{stat.consecutive_failures}次，标记为不健康")

                error_msg = response.text[:500]
                metadata = {
                    "model": selected_model,
                    "status_code": response.status_code,
                    "response_time": round(elapsed, 2),
                    "error": error_msg,
                }

                # 自动切换
                if stat.consecutive_failures >= 1:
                    self._auto_switch(selected_model, task_type)

                return None, metadata

        except Exception as e:
            elapsed = time.time() - start_time
            stat.failed_requests += 1
            stat.consecutive_failures += 1
            if stat.consecutive_failures >= 3:
                stat.is_healthy = False

            metadata = {
                "model": selected_model,
                "status_code": 0,
                "response_time": round(elapsed, 2),
                "error": str(e),
            }

            # 自动切换
            self._auto_switch(selected_model, task_type)

            logger.error(f"模型 {selected_model} 请求异常: {e}")
            return None, metadata

    def _select_model(self, task_type: str) -> Optional[str]:
        """根据任务类型选择最优模型"""
        # 1. 优先选择支持该任务且健康的模型
        candidates = [
            (name, m) for name, m in self.models.items()
            if m.enabled and self.stats.get(name, ModelStats(name=name)).is_healthy
            and task_type in m.supported_tasks
        ]

        if not candidates:
            # 2. 如果没有支持该任务的模型，选择所有健康模型
            candidates = [
                (name, m) for name, m in self.models.items()
                if m.enabled and self.stats.get(name, ModelStats(name=name)).is_healthy
            ]

        if not candidates:
            # 3. 如果没有健康模型，选择所有启用的模型
            candidates = [(name, m) for name, m in self.models.items() if m.enabled]

        if not candidates:
            return None

        # 按优先级排序
        candidates.sort(key=lambda x: x[1].priority, reverse=True)
        return candidates[0][0]

    def _auto_switch(self, failed_model: str, task_type: str):
        """自动切换模型"""
        if self.current_model == failed_model:
            new_model = self._select_model(task_type)
            if new_model and new_model != failed_model:
                self.current_model = new_model
                logger.info(f"自动切换模型: {failed_model} -> {new_model}")

    def switch_model(self, model_name: str) -> bool:
        """手动切换模型"""
        if model_name in self.models and self.models[model_name].enabled:
            self.current_model = model_name
            logger.info(f"手动切换模型到: {model_name}")
            return True
        return False

    def test_model(self, model_name: str) -> Dict:
        """测试模型连接"""
        if model_name not in self.models:
            return {"success": False, "error": "模型不存在"}

        content, metadata = self.chat(
            messages=[{"role": "user", "content": "请回复：连接成功"}],
            model_name=model_name,
            max_tokens=50,
            timeout=30
        )

        return {
            "success": content is not None,
            "content": content,
            "metadata": metadata,
        }

    def test_all_models(self) -> List[Dict]:
        """测试所有模型"""
        results = []
        for name in self.models:
            result = self.test_model(name)
            result["name"] = name
            results.append(result)
        return results

    def get_current_model(self) -> Optional[Dict]:
        """获取当前模型信息"""
        if not self.current_model or self.current_model not in self.models:
            return None
        m = self.models[self.current_model]
        return {
            "name": self.current_model,
            "provider": m.provider,
            "model": m.model,
            "base_url": m.base_url,
            "priority": m.priority,
        }

    def get_statistics(self) -> Dict:
        """获取总体统计"""
        total_requests = sum(s.total_requests for s in self.stats.values())
        total_success = sum(s.successful_requests for s in self.stats.values())
        total_failed = sum(s.failed_requests for s in self.stats.values())
        total_tokens = sum(s.total_tokens for s in self.stats.values())
        total_cost = sum(s.total_cost for s in self.stats.values())

        return {
            "total_models": len(self.models),
            "enabled_models": len([m for m in self.models.values() if m.enabled]),
            "healthy_models": len([s for s in self.stats.values() if s.is_healthy]),
            "current_model": self.current_model,
            "total_requests": total_requests,
            "successful_requests": total_success,
            "failed_requests": total_failed,
            "success_rate": round(total_success / total_requests * 100, 1) if total_requests > 0 else 0,
            "total_tokens": total_tokens,
            "total_cost": round(total_cost, 4),
            "models": self.list_models(),
        }


# 便捷函数
def create_multi_llm_manager(config_path: Optional[str] = None) -> MultiLLMManager:
    """创建多模型管理器"""
    return MultiLLMManager(config_path)


if __name__ == "__main__":
    print("=== 多模型管理器 ===")
    print()

    manager = MultiLLMManager()

    # 列出模型
    models = manager.list_models()
    print(f"已配置模型: {len(models)}个")
    for m in models:
        print(f"  - {m['name']}: {m['provider']}/{m['model']} (优先级: {m['priority']}, 健康: {m['is_healthy']})")
    print()

    # 当前模型
    current = manager.get_current_model()
    if current:
        print(f"当前使用模型: {current['name']} ({current['provider']}/{current['model']})")
    print()

    # 测试连接
    print("测试模型连接...")
    result = manager.chat(
        messages=[{"role": "user", "content": "你好，请用一句话回复"}],
        task_type="chat"
    )
    if result[0]:
        print(f"✅ 连接成功: {result[0]}")
        print(f"   元数据: {json.dumps(result[1], ensure_ascii=False, indent=2)}")
    else:
        print(f"❌ 连接失败: {result[1]}")
