# -*- coding: utf-8 -*-
"""
target_lab_real/labs_dashboard.py — 靶场仪表盘聚合
"""
from __future__ import annotations

from typing import Any, Dict

from . import docker_manager
from .lab_registry import labs_by_category, list_categories
from .lab_deployer import list_instances, NOTICE


def get_dashboard() -> Dict[str, Any]:
    insts = list_instances()
    running = [i for i in insts if i.get("status") == "running"]
    mock_count = sum(1 for i in insts if i.get("mode") == "mock")
    docker_count = sum(1 for i in insts if i.get("mode") == "docker")
    return {
        "docker": docker_manager.docker_available(),
        "categories": list_categories(),
        "labs_by_category": labs_by_category(),
        "instances": insts,
        "stats": {
            "total_instances": len(insts),
            "running": len(running),
            "mock": mock_count,
            "docker": docker_count,
        },
        "notice": NOTICE,
    }
