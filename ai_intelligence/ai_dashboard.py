#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
AI 管理控制台数据层 (AI Dashboard)
=====================================

为 AI 管理控制台提供全部后台数据（内存字典模拟）：

    1. AI 总览：模型状态 / 调用次数 / Token 消耗 / 成功率 / 平均响应时间 / 成本
    2. 模型管理：模型列表 / 配置 / 切换 / 对比 / 评测 / 微调
    3. 提示词管理：系统提示 / 模板 / 版本 / A/B 测试 / 效果分析
    4. 对话管理：会话列表 / 详情 / 搜索 / 导出 / 删除 / 标签
    5. 任务管理：AI 任务列表 / 状态 / 进度 / 结果 / 重试 / 取消
    6. 系统设置：API 密钥 / 代理 / 限流 / 缓存 / 日志 / 审计

所有数据均为模拟运行态，不接外部服务。
"""
from __future__ import annotations

import uuid
from datetime import datetime
from typing import Any, Dict, List, Optional


def _now() -> str:
    return datetime.now().isoformat(timespec="seconds")


_MODELS: List[Dict[str, Any]] = [
    {"model_id": "gpt-4o-mini", "vendor": "OpenAI", "status": "online",
     "context_window": 128000, "input_price_per_1k": 0.00015, "output_price_per_1k": 0.0006,
     "strengths": ["通用对话", "意图识别"], "latency_ms": 800},
    {"model_id": "qwen2.5-72b", "vendor": "Aliyun", "status": "online",
     "context_window": 32768, "input_price_per_1k": 0.0008, "output_price_per_1k": 0.002,
     "strengths": ["中文理解", "代码"], "latency_ms": 1200},
    {"model_id": "deepseek-v3", "vendor": "DeepSeek", "status": "standby",
     "context_window": 64000, "input_price_per_1k": 0.00027, "output_price_per_1k": 0.0011,
     "strengths": ["推理", "长文本"], "latency_ms": 1500},
    {"model_id": "local-mock", "vendor": "Local", "status": "offline-fallback",
     "context_window": 8192, "input_price_per_1k": 0.0, "output_price_per_1k": 0.0,
     "strengths": ["离线可用", "零成本"], "latency_ms": 50},
]


class AIDashboard:
    """AI 管理控制台数据（单例）。"""

    def __init__(self) -> None:
        self.models: List[Dict[str, Any]] = [dict(m) for m in _MODELS]
        self.active_model: str = "gpt-4o-mini"
        self.metrics: Dict[str, Any] = {
            "total_calls": 1284,
            "success_calls": 1251,
            "total_tokens": 482391,
            "input_tokens": 351200,
            "output_tokens": 131191,
            "avg_latency_ms": 920,
            "cost_cny": 12.48,
        }
        self.prompt_versions: List[Dict[str, Any]] = [
            {"version": "v1.0", "name": "基础版", "status": "archived",
             "hit_rate": 0.78, "created_at": "2026-08-01T10:00:00"},
            {"version": "v1.1", "name": "授权约束强化版", "status": "current",
             "hit_rate": 0.91, "created_at": "2026-09-01T10:00:00"},
        ]
        self.ab_tests: List[Dict[str, Any]] = [
            {"test_id": "ab-001", "variant_a": "v1.0", "variant_b": "v1.1",
             "sample": 200, "winner": "B", "b_score": 0.91, "a_score": 0.78},
        ]
        self.ai_tasks: Dict[str, Dict[str, Any]] = {}
        self.conversations: Dict[str, Dict[str, Any]] = {}
        self.settings: Dict[str, Any] = {
            "api_key_masked": "sk-****...****8f21",
            "proxy": "http://127.0.0.1:7890",
            "rate_limit_per_min": 60,
            "cache_enabled": True,
            "cache_ttl_sec": 300,
            "log_level": "INFO",
            "audit_enabled": True,
        }
        # 预置示例任务
        for i in range(5):
            self._new_task(f"示例任务 {i + 1}", ["scan", "report"][i % 2])

    # ------------------------------------------------------------------
    # 1. AI 总览
    # ------------------------------------------------------------------
    def overview(self) -> Dict[str, Any]:
        m = self.metrics
        return {
            **m,
            "success_rate": round(m["success_calls"] / max(1, m["total_calls"]), 3),
            "active_model": self.active_model,
            "online_models": sum(1 for x in self.models if x["status"] == "online"),
            "total_models": len(self.models),
            "open_tasks": sum(1 for t in self.ai_tasks.values() if t["status"] in ("pending", "running")),
            "updated_at": _now(),
        }

    # ------------------------------------------------------------------
    # 2. 模型管理
    # ------------------------------------------------------------------
    def list_models(self) -> List[Dict[str, Any]]:
        return self.models

    def switch_model(self, model_id: str) -> Dict[str, Any]:
        if not any(m["model_id"] == model_id for m in self.models):
            return {"error": "model not found"}
        self.active_model = model_id
        return {"active_model": model_id, "switched_at": _now()}

    def compare_models(self, model_ids: List[str]) -> List[Dict[str, Any]]:
        picked = [m for m in self.models if m["model_id"] in model_ids]
        return sorted(picked, key=lambda x: x["latency_ms"])

    def eval_model(self, model_id: str, samples: int = 50) -> Dict[str, Any]:
        return {
            "model_id": model_id,
            "samples": samples,
            "accuracy": 0.86,
            "avg_rt_ms": 980,
            "cost_per_sample": 0.0021,
            "evaluated_at": _now(),
        }

    def fine_tune(self, model_id: str, epochs: int = 3) -> Dict[str, Any]:
        return {
            "model_id": model_id,
            "job_id": f"ft-{uuid.uuid4().hex[:8]}",
            "epochs": epochs,
            "estimated_time_min": 120,
            "status": "queued",
            "created_at": _now(),
        }

    # ------------------------------------------------------------------
    # 3. 提示词管理
    # ------------------------------------------------------------------
    def list_prompt_versions(self) -> List[Dict[str, Any]]:
        return self.prompt_versions

    def add_prompt_version(self, name: str, prompt: str) -> Dict[str, Any]:
        v = f"v{len(self.prompt_versions) + 1}.0"
        item = {"version": v, "name": name, "status": "candidate",
                "prompt": prompt, "hit_rate": 0.0, "created_at": _now()}
        self.prompt_versions.append(item)
        return item

    def ab_test_result(self, test_id: Optional[str] = None) -> List[Dict[str, Any]]:
        return self.ab_tests

    # ------------------------------------------------------------------
    # 4. 对话管理
    # ------------------------------------------------------------------
    def list_conversations(self, keyword: Optional[str] = None,
                           tag: Optional[str] = None) -> List[Dict[str, Any]]:
        items = list(self.conversations.values())
        if keyword:
            kw = keyword.lower()
            items = [c for c in items if kw in c.get("title", "").lower()]
        if tag:
            items = [c for c in items if tag in c.get("tags", [])]
        return [
            {"conv_id": c["conv_id"], "title": c["title"], "tags": c["tags"],
             "message_count": len(c["messages"]), "updated_at": c["updated_at"]}
            for c in items
        ]

    def get_conversation(self, conv_id: str) -> Optional[Dict[str, Any]]:
        return self.conversations.get(conv_id)

    def create_conversation(self, title: str, messages: Optional[List[Dict[str, Any]]] = None,
                            tags: Optional[List[str]] = None) -> Dict[str, Any]:
        cid = f"conv-{uuid.uuid4().hex[:8]}"
        conv = {
            "conv_id": cid, "title": title, "tags": tags or [],
            "messages": messages or [], "created_at": _now(), "updated_at": _now(),
        }
        self.conversations[cid] = conv
        return conv

    def delete_conversation(self, conv_id: str) -> bool:
        return self.conversations.pop(conv_id, None) is not None

    def tag_conversation(self, conv_id: str, tags: List[str]) -> bool:
        c = self.conversations.get(conv_id)
        if not c:
            return False
        c["tags"] = list(set(c["tags"] + tags))
        return True

    # ------------------------------------------------------------------
    # 5. 任务管理
    # ------------------------------------------------------------------
    def _new_task(self, name: str, kind: str) -> Dict[str, Any]:
        tid = f"ai-task-{uuid.uuid4().hex[:8]}"
        task = {
            "task_id": tid, "name": name, "kind": kind,
            "status": "running", "progress": 30,
            "result": None, "error": None, "created_at": _now(),
        }
        self.ai_tasks[tid] = task
        return task

    def list_tasks(self, status: Optional[str] = None) -> List[Dict[str, Any]]:
        items = list(self.ai_tasks.values())
        if status:
            items = [t for t in items if t["status"] == status]
        return items

    def get_task(self, task_id: str) -> Optional[Dict[str, Any]]:
        t = self.ai_tasks.get(task_id)
        if t and t["status"] == "running":
            # 模拟进度推进
            t["progress"] = min(100, t["progress"] + 25)
            if t["progress"] >= 100:
                t["status"] = "success"
                t["result"] = {"summary": "任务完成（模拟）"}
        return t

    def retry_task(self, task_id: str) -> bool:
        t = self.ai_tasks.get(task_id)
        if not t:
            return False
        t["status"] = "pending"
        t["progress"] = 0
        t["error"] = None
        return True

    def cancel_task(self, task_id: str) -> bool:
        t = self.ai_tasks.get(task_id)
        if not t:
            return False
        if t["status"] == "running":
            t["status"] = "cancelled"
        return True

    # ------------------------------------------------------------------
    # 6. 系统设置
    # ------------------------------------------------------------------
    def get_settings(self) -> Dict[str, Any]:
        return self.settings

    def update_settings(self, updates: Dict[str, Any]) -> Dict[str, Any]:
        for k, v in updates.items():
            if k in self.settings:
                self.settings[k] = v
        return self.settings

    def rotate_api_key(self) -> Dict[str, Any]:
        self.settings["api_key_masked"] = "sk-****...****newkey"
        return {"api_key_masked": self.settings["api_key_masked"], "rotated_at": _now()}

    def stats(self) -> Dict[str, Any]:
        return {
            "models": len(self.models),
            "conversations": len(self.conversations),
            "tasks": len(self.ai_tasks),
            "prompt_versions": len(self.prompt_versions),
        }


ai_dashboard = AIDashboard()
