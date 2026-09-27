# -*- coding: utf-8 -*-
"""
target_lab_real/lab_template.py — 靶场部署模板

预设模板 + 用户自定义模板（内存字典，可导入导出）。
"""
from __future__ import annotations

import time
from typing import Any, Dict, List

from .lab_config import LabDeployConfig

_PRESETS: Dict[str, Dict[str, Any]] = {
    "default_web": {
        "name": "默认 Web 靶场",
        "description": "基础 Web 靶场配置",
        "config": LabDeployConfig(restart="no").to_dict(),
    },
    "persistent_web": {
        "name": "持久化 Web 靶场",
        "description": "数据卷持久化 + 自动重启",
        "config": LabDeployConfig(
            volumes={"./lab_data": "/data"},
            restart="unless-stopped").to_dict(),
    },
    "lightweight": {
        "name": "轻量靶场",
        "description": "限制 CPU 0.5 / 内存 512m",
        "config": LabDeployConfig(
            cpu_limit="0.5", memory_limit="512m").to_dict(),
    },
}

_custom: Dict[str, Dict[str, Any]] = {}


def list_templates() -> List[Dict[str, Any]]:
    out = []
    for k, v in _PRESETS.items():
        out.append({"id": k, "builtin": True, **v})
    for k, v in _custom.items():
        out.append({"id": k, "builtin": False, **v})
    return out


def get_template(tid: str) -> Dict[str, Any] | None:
    if tid in _PRESETS:
        return {"id": tid, "builtin": True, **_PRESETS[tid]}
    if tid in _custom:
        return {"id": tid, "builtin": False, **_custom[tid]}
    return None


def create_template(name: str, description: str,
                    config: Dict[str, Any]) -> Dict[str, Any]:
    tid = f"tpl_{int(time.time())}"
    _custom[tid] = {"name": name, "description": description,
                    "config": config, "created_at": time.time()}
    return {"id": tid, **_custom[tid]}


def update_template(tid: str, name: str | None = None,
                    description: str | None = None,
                    config: Dict[str, Any] | None = None) -> bool:
    if tid not in _custom:
        return False
    if name:
        _custom[tid]["name"] = name
    if description:
        _custom[tid]["description"] = description
    if config:
        _custom[tid]["config"] = config
    return True


def delete_template(tid: str) -> bool:
    if tid in _custom:
        del _custom[tid]
        return True
    return False


def export_templates() -> Dict[str, Any]:
    return {"presets": _PRESETS, "custom": _custom}


def import_templates(data: Dict[str, Any]) -> int:
    added = 0
    for k, v in (data.get("custom") or {}).items():
        if k not in _custom:
            _custom[k] = v
            added += 1
    return added
