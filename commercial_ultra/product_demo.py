# -*- coding: utf-8 -*-
"""
commercial_ultra/product_demo.py — 产品一键演示（商业产品体验极致）。

- 一键 Demo：用户点一下看到完整效果
- 预置演示数据
- 演示流程引导（分步 walkthrough）
"""

from __future__ import annotations

import threading
import time
from typing import Any, Dict, List


class ProductDemo:
    """产品演示引擎（全内存模拟）。"""

    DEMO_SCENES: List[Dict[str, Any]] = [
        {"step": 1, "key": "target", "title": "输入目标",
         "desc": "在演示模式下，预置目标 https://demo.testfire.net",
         "action": "start_scan", "expect": "任务进入队列"},
        {"step": 2, "key": "recon", "title": "AI 侦察",
         "desc": "自动指纹识别 / 端口 / 子域名 / 技术栈",
         "action": "recon", "expect": "识别到 Apache + Spring 栈"},
        {"step": 3, "key": "scan", "title": "自动化扫描",
         "desc": "Web 漏洞库全量匹配，POC 自动验证",
         "action": "scan", "expect": "命中 1 个高危 / 3 个中危"},
        {"step": 4, "key": "chain", "title": "攻击链关联",
         "desc": "把 XSS + 越权串成完整攻击路径",
         "action": "chain", "expect": "生成 1 条完整攻击链"},
        {"step": 5, "key": "report", "title": "一键出报告",
         "desc": "自动撰写可执行修复建议",
         "action": "report", "expect": "在线报告 + PDF 导出"},
    ]

    def __init__(self) -> None:
        self._lock = threading.RLock()
        self._sessions: Dict[str, Dict[str, Any]] = {}
        self._seq = 0

    def _next_id(self, prefix: str) -> str:
        self._seq += 1
        return f"{prefix}-{int(time.time()) % 100000:05d}{self._seq:03d}"

    def scenes(self) -> List[Dict[str, Any]]:
        """演示流程引导脚本。"""
        return [dict(s) for s in self.DEMO_SCENES]

    def start(self) -> Dict[str, Any]:
        """一键启动完整 Demo。"""
        sid = self._next_id("DEMO")
        with self._lock:
            self._sessions[sid] = {
                "demo_id": sid, "current_step": 1, "status": "running",
                "started_at": time.strftime("%Y-%m-%d %H:%M:%S"),
                "target": "https://demo.testfire.net",
                "results": {},
            }
        return {"demo_id": sid, "target": "https://demo.testfire.net",
                "total_steps": len(self.DEMO_SCENES),
                "message": "演示已启动，调用 /next 逐步引导，或 /run-all 一键跑完"}

    def _preset_results(self, scene_key: str) -> Dict[str, Any]:
        return {
            "recon": {"fingerprints": ["Apache 2.4", "Spring Boot", "MySQL"],
                      "ports": [80, 443, 8080], "subdomains": ["www", "api", "admin"]},
            "scan": {"high": 1, "medium": 3, "low": 6,
                     "vulns": [
                         {"id": "VULN-001", "name": "SQL 注入 (登录框)", "level": "high",
                          "verified": True},
                         {"id": "VULN-002", "name": "反射型 XSS", "level": "medium",
                          "verified": True},
                         {"id": "VULN-003", "name": "目录遍历", "level": "medium",
                          "verified": False},
                     ]},
            "chain": {"chains": [{"name": "SQLi → 拖库 → 后台登录",
                                  "nodes": ["SQL注入", "读取管理员哈希", "后台接管"]}]},
            "report": {"report_id": "RPT-DEMO-001", "format": ["online", "pdf"],
                       "executive_summary": "本轮发现 1 个高危 SQL 注入，建议立即修复登录接口。"},
        }.get(scene_key, {})

    def next_step(self, demo_id: str) -> Dict[str, Any]:
        """执行下一步引导。"""
        with self._lock:
            d = self._sessions.get(demo_id)
            if not d:
                raise ValueError("演示会话不存在，请先 /start")
            step_idx = d["current_step"] - 1
            if step_idx >= len(self.DEMO_SCENES):
                d["status"] = "done"
                return {"demo_id": demo_id, "done": True,
                        "message": "演示已全部完成"}
            scene = self.DEMO_SCENES[step_idx]
            d["results"][scene["key"]] = self._preset_results(scene["key"])
            d["current_step"] += 1
            if d["current_step"] > len(self.DEMO_SCENES):
                d["status"] = "done"
            return {"demo_id": demo_id, "step": scene,
                    "result": d["results"][scene["key"]],
                    "next": d["current_step"] if d["status"] != "done" else None,
                    "done": d["status"] == "done"}

    def run_all(self, demo_id: str) -> Dict[str, Any]:
        """一键跑完整个演示流程。"""
        steps_done: List[Dict[str, Any]] = []
        while True:
            r = self.next_step(demo_id)
            steps_done.append(r)
            if r.get("done"):
                break
        return {"demo_id": demo_id, "steps_completed": len(steps_done),
                "report": self._preset_results("report"),
                "message": "一键演示完成，可在报告页查看完整效果"}

    def status(self, demo_id: str) -> Dict[str, Any]:
        with self._lock:
            d = self._sessions.get(demo_id)
            if not d:
                raise ValueError("演示会话不存在")
            return dict(d)


_demo: ProductDemo | None = None


def get_product_demo() -> ProductDemo:
    global _demo
    if _demo is None:
        _demo = ProductDemo()
    return _demo
