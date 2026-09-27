# -*- coding: utf-8 -*-
"""
tools_installer/tools_dashboard.py — 工具仪表盘聚合

汇总：
  - 原生工具 / Python 库 / Docker 镜像的安装统计
  - 包管理器状态
  - 最近安装任务
  - 分类覆盖率
"""
from __future__ import annotations

from typing import Any, Dict

from . import tool_registry as reg
from .package_manager import detect_all
from .tool_detector import detect_all_tools
from .tool_installer import list_tasks


def get_dashboard() -> Dict[str, Any]:
    detected = detect_all_tools()
    pm = detect_all()

    # 按分类统计
    cat_stats: Dict[str, Dict[str, int]] = {}
    for item in detected["native"]["items"]:
        c = item["category"]
        s = cat_stats.setdefault(c, {"total": 0, "installed": 0})
        s["total"] += 1
        if item["installed"]:
            s["installed"] += 1

    pm_ready = [k for k, v in pm.items()
                if isinstance(v, dict) and v.get("available")]
    pm_missing = [{"name": k, "install": v.get("install_cmd"),
                   "url": v.get("install_url")}
                  for k, v in pm.items()
                  if isinstance(v, dict) and not v.get("available")
                  and k != "platform"]

    return {
        "native": detected["native"]["summary"],
        "python_libs": detected["python_libs"]["summary"],
        "docker_images": detected["docker_images"]["summary"],
        "categories": cat_stats,
        "category_labels": reg.get_categories(),
        "package_managers": pm,
        "pm_ready": pm_ready,
        "pm_missing": pm_missing,
        "recent_tasks": list_tasks(limit=10)["data"],
        "notice": "仅限授权环境：所有工具仅用于授权安全测试 / 教学 / 演示。",
    }
