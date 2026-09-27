# -*- coding: utf-8 -*-
"""
workflow_visualization.py — 工作流 DAG 可视化数据生成（第16轮升级·方向1）。

输出供前端 SVG/Canvas 直接渲染的数据：
    - 节点（步骤）：名称/描述/输入/输出/耗时/日志/错误
    - 边（依赖关系）
    - 节点状态颜色：等待(灰)/执行中(蓝)/已完成(绿)/失败(红)/已跳过(黄)
    - 执行路径高亮
    - 关键路径计算（决定总耗时的最长步骤链）
"""

from __future__ import annotations

from typing import Any, Dict, List, Optional

from workflow_v2.execution_tracker import (
    STATUS_DONE, STATUS_FAILED, STATUS_PENDING,
    STATUS_RUNNING, STATUS_SKIPPED, STATUS_CANCELLED,
)

STATUS_COLOR = {
    STATUS_PENDING: "#9aa0a6",      # 灰
    STATUS_RUNNING: "#4285f4",      # 蓝
    STATUS_DONE: "#34a853",         # 绿
    STATUS_FAILED: "#ea4335",       # 红
    STATUS_SKIPPED: "#fbbc04",      # 黄
    STATUS_CANCELLED: "#fbbc04",    # 黄
}


def _layout(nodes: List[Dict[str, Any]],
            edges: List[Dict[str, Any]]) -> Dict[str, Dict[str, float]]:
    """简单分层布局：按依赖深度分层，层内水平排列。"""
    indeg: Dict[str, int] = {n["id"]: 0 for n in nodes}
    for e in edges:
        indeg[e["to"]] = indeg.get(e["to"], 0) + 1

    layer: Dict[str, int] = {}
    queue = [n["id"] for n in nodes if indeg[n["id"]] == 0]
    while queue:
        nid = queue.pop(0)
        layer[nid] = layer.get(nid, 0)
        for e in edges:
            if e["from"] == nid:
                layer[e["to"]] = max(layer.get(e["to"], 0), layer[nid] + 1)
                indeg[e["to"]] -= 1
                if indeg[e["to"]] == 0:
                    queue.append(e["to"])

    max_layer = max(layer.values()) if layer else 0
    col_count: Dict[int, int] = {}
    pos: Dict[str, Dict[str, float]] = {}
    for n in nodes:
        L = layer.get(n["id"], 0)
        row = col_count.get(L, 0)
        col_count[L] = row + 1
        pos[n["id"]] = {
            "x": 80 + L * 220,
            "y": 70 + row * 110,
        }
    return pos


def build_dag(task: Any) -> Dict[str, Any]:
    """根据 TaskRecord 生成 DAG 可视化数据。"""
    nodes: List[Dict[str, Any]] = []
    edges: List[Dict[str, Any]] = []
    for sid in task.step_order:
        s = task.steps[sid]
        nodes.append({
            "id": sid,
            "label": s.name,
            "description": s.description,
            "status": s.status,
            "color": STATUS_COLOR.get(s.status, "#9aa0a6"),
            "duration_ms": s.duration_ms,
            "input": s.input_summary,
            "output": s.output_summary,
            "error": s.error,
            "logs": s.logs,
        })
        for dep in s.depends_on:
            edges.append({"from": dep, "to": sid})

    pos = _layout(nodes, edges)
    for n in nodes:
        n["x"] = pos.get(n["id"], {}).get("x", 0)
        n["y"] = pos.get(n["id"], {}).get("y", 0)

    key_path = compute_critical_path(task)
    executed_path = [sid for sid in task.step_order
                     if task.steps[sid].status == STATUS_DONE]

    return {
        "task_id": task.task_id,
        "scenario": task.scenario_name,
        "status": task.status,
        "progress": task.progress(),
        "nodes": nodes,
        "edges": edges,
        "executed_path": executed_path,
        "critical_path": key_path,
        "width": 1200,
        "height": max(400, 120 * (len(nodes) + 1)),
    }


def compute_critical_path(task: Any) -> List[str]:
    """关键路径：在依赖 DAG 上求最长耗时链。"""
    # 每个节点的耗时
    dur: Dict[str, float] = {}
    for sid in task.step_order:
        d = task.steps[sid].duration_ms
        dur[sid] = float(d) if d else 0.0

    # dp：到该节点为止的最长路径耗时与前驱
    best: Dict[str, float] = {}
    prev: Dict[str, Optional[str]] = {}
    order = task.step_order
    for sid in order:
        s = task.steps[sid]
        best[sid] = dur[sid]
        prev[sid] = None
        for dep in s.depends_on:
            if dep in best and best.get(dep, 0) + dur[sid] > best[sid]:
                best[sid] = best[dep] + dur[sid]
                prev[sid] = dep

    if not order:
        return []
    # 找终点（出度为0，或取 best 最大者）
    has_out: set = set()
    for sid in order:
        for dep in task.steps[sid].depends_on:
            has_out.add(dep)
    sinks = [sid for sid in order if sid not in has_out]
    if not sinks:
        sinks = order
    end = max(sinks, key=lambda x: best.get(x, 0))

    # 回溯
    path: List[str] = []
    cur: Optional[str] = end
    while cur is not None:
        path.append(cur)
        cur = prev.get(cur)
    path.reverse()
    return path


def node_detail(task: Any, step_id: str) -> Optional[Dict[str, Any]]:
    s = task.steps.get(step_id)
    if s is None:
        return None
    return {
        "step_id": s.step_id,
        "name": s.name,
        "description": s.description,
        "status": s.status,
        "color": STATUS_COLOR.get(s.status, "#9aa0a6"),
        "started_at": s.started_at_str,
        "finished_at": s.finished_at_str,
        "duration_ms": s.duration_ms,
        "input": s.input_summary,
        "output": s.output_summary,
        "error": s.error,
        "traceback": s.traceback,
        "logs": s.logs,
        "depends_on": s.depends_on,
    }


__all__ = ["build_dag", "compute_critical_path", "node_detail", "STATUS_COLOR"]
