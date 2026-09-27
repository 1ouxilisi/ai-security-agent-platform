#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
binary_reverse/binary_dashboard.py — 二进制逆向控制台数据聚合层。

聚合各子模块指标，提供总览 / 任务状态 / 系统设置。
"""

from __future__ import annotations

import time
from typing import Any, Dict, List, Optional

from .disassembler import get_disassembler, SAMPLE_X86_64, SAMPLE_ARM
from .decompiler import get_decompiler, decompile_sample
from .vuln_miner import get_vuln_miner, mine_demo
from .patch_diff import get_patch_differ, diff_demo
from .malware_analysis import get_malware_analyzer, analyze_demo
from .pack_unpack import get_pack_detector, detect_demo


SYSTEM_SETTINGS: Dict[str, Any] = {
    "default_arch": "x86_64",
    "max_file_size_mb": 100,
    "auto_decompile": True,
    "auto_vuln_scan": True,
    "default_fuzz_seeds": 16,
    "sandbox_enabled": True,
    "notify_on_crash": True,
}


class BinaryDashboard:
    """聚合层：总览指标 + 任务流。"""

    def __init__(self) -> None:
        self.tasks: Dict[str, Dict[str, Any]] = {}
        self.history: List[Dict[str, Any]] = []

    def overview(self) -> Dict[str, Any]:
        # 用真实演示数据快速跑一遍
        disasm = get_disassembler("x86_64")
        insns = disasm.disassemble(SAMPLE_X86_64, 0x100000)
        blocks = disasm.basic_blocks(insns)
        funcs = disasm.identify_functions(insns)
        mine = mine_demo()
        unpack = detect_demo()
        return {
            "version": "27.3.0",
            "modules": {
                "disassembler": "已加载",
                "decompiler": "已加载",
                "vuln_miner": "已加载",
                "patch_diff": "已加载",
                "malware_analysis": "已加载",
                "pack_unpack": "已加载",
            },
            "stats": {
                "sample_instructions": len(insns),
                "sample_basic_blocks": len(blocks),
                "sample_functions": len(funcs),
                "vuln_findings": mine.get("risk_score", 0),
                "packed_detected": unpack.get("is_packed", False),
            },
            "recent_tasks": list(self.tasks.values())[-10:],
            "settings": SYSTEM_SETTINGS,
            "generated_at": time.strftime("%Y-%m-%d %H:%M:%S"),
        }

    def submit_task(self, kind: str, payload: Dict[str, Any]) -> str:
        import uuid
        tid = uuid.uuid4().hex[:16]
        self.tasks[tid] = {
            "task_id": tid, "kind": kind, "status": "done",
            "submitted_at": time.strftime("%Y-%m-%d %H:%M:%S"),
            "payload": payload,
        }
        return tid

    def list_tasks(self) -> List[Dict[str, Any]]:
        return list(self.tasks.values())

    def get_task(self, tid: str) -> Optional[Dict[str, Any]]:
        return self.tasks.get(tid)


_DASH: Optional[BinaryDashboard] = None


def get_dashboard() -> BinaryDashboard:
    global _DASH
    if _DASH is None:
        _DASH = BinaryDashboard()
    return _DASH
