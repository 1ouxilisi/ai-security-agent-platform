#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
workflow/builder.py — Round 7 新增：工作流构建器。

提供：
    - WorkflowBuilder：以编程方式构建/校验/导入导出/保存自定义 DAG 工作流
    - 校验：DAG 循环依赖、无效依赖引用、参数缺失、步骤ID重复
    - 自定义工作流内存存储（可扩展到文件）

本模块仅用于授权安全评估场景的工作流编排。
"""
import json
import copy
import threading
from typing import Any, Dict, List, Optional


class WorkflowBuilder:
    """工作流构建器：创建、编辑、校验、导入导出、保存自定义工作流。"""

    def __init__(self):
        self._lock = threading.RLock()
        self._custom_workflows: Dict[str, Dict[str, Any]] = {}

    # ---------- 构建 ----------
    def create_workflow(self, name: str, description: str = "") -> Dict[str, Any]:
        """创建一个空的工作流定义字典。"""
        return {
            "name": name,
            "description": description,
            "steps": [],
        }

    def add_step(self, workflow_def: Dict[str, Any], step_id: str, name: str,
                 action_type: str = "tool_call",
                 action_params: Optional[Dict[str, Any]] = None,
                 depends_on: Optional[List[str]] = None,
                 condition: Optional[str] = None,
                 on_failure: str = "continue",
                 retry_count: int = 0) -> Dict[str, Any]:
        """向工作流定义添加一个步骤。"""
        if not step_id:
            raise ValueError("step_id 不能为空")
        steps = workflow_def.setdefault("steps", [])
        if any(s.get("step_id") == step_id for s in steps):
            raise ValueError(f"步骤ID重复: {step_id}")
        steps.append({
            "step_id": step_id,
            "name": name or step_id,
            "description": "",
            "action_type": action_type,
            "action_params": action_params or {},
            "depends_on": depends_on or [],
            "condition": condition,
            "on_failure": on_failure,
            "retry_count": retry_count,
            "retry_delay": 2.0,
            "timeout": 600,
        })
        return workflow_def

    def remove_step(self, workflow_def: Dict[str, Any], step_id: str) -> Dict[str, Any]:
        """移除步骤，并从其他步骤的 depends_on 中清理引用。"""
        steps = workflow_def.get("steps", [])
        workflow_def["steps"] = [s for s in steps if s.get("step_id") != step_id]
        for s in workflow_def["steps"]:
            s["depends_on"] = [d for d in (s.get("depends_on") or []) if d != step_id]
        return workflow_def

    def update_step(self, workflow_def: Dict[str, Any], step_id: str, **kwargs) -> Dict[str, Any]:
        """更新步骤字段（白名单）。"""
        allowed = {"name", "description", "action_type", "action_params",
                   "depends_on", "condition", "on_failure", "retry_count",
                   "retry_delay", "timeout"}
        for s in workflow_def.get("steps", []):
            if s.get("step_id") == step_id:
                for k, v in kwargs.items():
                    if k in allowed:
                        s[k] = v
                return workflow_def
        raise KeyError(f"步骤不存在: {step_id}")

    # ---------- 校验 ----------
    def validate_workflow(self, workflow_def: Dict[str, Any]) -> Dict[str, Any]:
        """校验工作流定义：DAG 循环、无效引用、重复ID、参数缺失。"""
        errors: List[str] = []
        steps = workflow_def.get("steps", []) or []
        if not steps:
            errors.append("工作流至少需要一个步骤")

        ids = [s.get("step_id") for s in steps]
        id_set = set()
        for sid in ids:
            if not sid:
                errors.append("存在空 step_id 的步骤")
            elif sid in id_set:
                errors.append(f"步骤ID重复: {sid}")
            else:
                id_set.add(sid)

        # 依赖引用检查
        for s in steps:
            for dep in (s.get("depends_on") or []):
                if dep not in id_set:
                    errors.append(f"步骤 {s.get('step_id')} 依赖不存在的步骤: {dep}")
                if dep == s.get("step_id"):
                    errors.append(f"步骤 {s.get('step_id')} 不能依赖自身")

        # 循环依赖检测（Kahn 拓扑排序，无递归栈残留问题）
        graph = {sid: [] for sid in id_set}
        indeg = {sid: 0 for sid in id_set}
        for s in steps:
            sid = s.get("step_id")
            for dep in (s.get("depends_on") or []):
                if dep in graph:
                    graph[dep].append(sid)
                    indeg[sid] += 1
        queue = [sid for sid, d in indeg.items() if d == 0]
        visited_count = 0
        while queue:
            n = queue.pop(0)
            visited_count += 1
            for nxt in graph[n]:
                indeg[nxt] -= 1
                if indeg[nxt] == 0:
                    queue.append(nxt)
        if visited_count != len(id_set):
            errors.append("检测到循环依赖（无法完成拓扑排序）")

        # 参数基本检查
        for s in steps:
            if not s.get("action_type"):
                errors.append(f"步骤 {s.get('step_id')} 缺少 action_type")
            if not isinstance(s.get("action_params", {}), dict):
                errors.append(f"步骤 {s.get('step_id')} 的 action_params 必须是字典")

        return {"valid": len(errors) == 0, "errors": errors,
                "steps_count": len(steps)}

    # ---------- 导入导出 ----------
    def export_workflow(self, workflow_def: Dict[str, Any]) -> str:
        """导出为 JSON 字符串（UTF-8，缩进2格）。"""
        return json.dumps(workflow_def, ensure_ascii=False, indent=2)

    def import_workflow(self, json_str: str) -> Dict[str, Any]:
        """从 JSON 字符串导入工作流定义。"""
        if isinstance(json_str, dict):
            return copy.deepcopy(json_str)
        return json.loads(json_str)

    # ---------- 自定义工作流存储 ----------
    def save_custom_workflow(self, name: str, workflow_def: Dict[str, Any]) -> Dict[str, Any]:
        """保存自定义工作流到内存存储。"""
        if not name:
            raise ValueError("工作流名称不能为空")
        v = self.validate_workflow(workflow_def)
        if not v["valid"]:
            raise ValueError("工作流校验失败: " + "; ".join(v["errors"]))
        with self._lock:
            self._custom_workflows[name] = copy.deepcopy(workflow_def)
        return {"name": name, "saved": True, "steps_count": len(workflow_def.get("steps", []))}

    def load_custom_workflow(self, name: str) -> Optional[Dict[str, Any]]:
        """获取自定义工作流。"""
        wf = self._custom_workflows.get(name)
        return copy.deepcopy(wf) if wf else None

    def list_custom_workflows(self) -> List[Dict[str, Any]]:
        """列出所有自定义工作流概要。"""
        with self._lock:
            return [
                {
                    "name": n,
                    "description": wf.get("description", ""),
                    "steps_count": len(wf.get("steps", [])),
                }
                for n, wf in self._custom_workflows.items()
            ]

    def delete_custom_workflow(self, name: str) -> bool:
        """删除自定义工作流。"""
        with self._lock:
            if name in self._custom_workflows:
                del self._custom_workflows[name]
                return True
            return False


# 全局构建器单例
workflow_builder = WorkflowBuilder()


__all__ = ["WorkflowBuilder", "workflow_builder"]
