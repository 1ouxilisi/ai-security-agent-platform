# -*- coding: utf-8 -*-
"""
realtime_pusher.py — 实时推送器。

把“当前步骤 / 工具调用 / 发现的漏洞 / AI 分析 / 进度 / 日志”打包成统一的
实时事件，并通过 WebSocketManager 推送到对应 channel。

对外提供一个 demo 模拟推进器：它会定时产生新事件，让前端在没有真实工具
接入时也能看到“像安全专家现场操作一样”的实时画面。
"""

from __future__ import annotations

import asyncio
import random
import time
import uuid
from typing import Any, Dict, List, Optional

from .websocket_manager import manager
from .progress_tracker import tracker
from .log_streamer import streamer


# 模拟“现场操作”脚本
_SCRIPT: List[Dict[str, str]] = [
    {"tool": "nmap", "msg": "nmap -sV -p- target", "level": "tool", "stage": "recon"},
    {"tool": "curl", "msg": "curl -I http://target/", "level": "tool", "stage": "recon"},
    {"tool": "gobuster", "msg": "gobuster dir -u target -w wordlist", "level": "tool", "stage": "enum"},
    {"tool": "whatweb", "msg": "whatweb --color=never target", "level": "tool", "stage": "enum"},
    {"tool": "sqlmap", "msg": "sqlmap -u 'target/?id=1' --batch", "level": "vuln", "stage": "vuln"},
    {"tool": "xss-scan", "msg": "xssssan -u target/search?q=", "level": "vuln", "stage": "vuln"},
    {"tool": "dirb", "msg": "dirb target /usr/share/wordlists/common.txt", "level": "vuln", "stage": "vuln"},
    {"tool": "ai", "msg": "AI 正在关联所有发现并过滤误报", "level": "thinking", "stage": "analysis"},
    {"tool": "report", "msg": "生成渗透报告 report.pdf", "level": "ok", "stage": "report"},
]


class RealtimePusher:
    """把各类事件打包并实时推送。"""

    def __init__(self) -> None:
        # task_id -> asyncio.Task（模拟推进协程）
        self._jobs: Dict[str, asyncio.Task] = {}

    # ------------------------------------------------------------------ #
    # 通用推送
    # ------------------------------------------------------------------ #
    async def push_event(self, task_id: str, event_type: str,
                         payload: Dict[str, Any]) -> None:
        msg = {
            "type": event_type,
            "task_id": task_id,
            "ts": time.time(),
            "data": payload,
        }
        await manager.broadcast(f"task:{task_id}", msg)

    async def push_progress(self, task_id: str) -> None:
        snap = tracker.snapshot(task_id)
        await self.push_event(task_id, "progress", snap)

    async def push_log(self, entry: Dict[str, Any]) -> None:
        await manager.broadcast(f"task:{entry['task_id']}", {
            "type": "log", "task_id": entry["task_id"],
            "ts": time.time(), "data": entry,
        })

    async def push_finding(self, task_id: str, finding: Dict[str, Any]) -> None:
        await self.push_event(task_id, "finding", finding)

    async def push_thinking(self, task_id: str, thought: Dict[str, Any]) -> None:
        await self.push_event(task_id, "thinking", thought)

    # ------------------------------------------------------------------ #
    # 启动一个 demo 实时推进任务
    # ------------------------------------------------------------------ #
    async def start_demo(self, target: str) -> Dict[str, Any]:
        # 初始化进度（用 tracker 生成的真实 task_id，保持一致）
        steps = [{"name": s["tool"] + ": " + s["msg"][:40], "stage": s["stage"]}
                 for s in _SCRIPT]
        tp = tracker.create_task(target, steps=steps)
        task_id = tp.task_id
        streamer.info(task_id, f"实时会话建立，目标 {target}", "system")
        await self.push_event(task_id, "connected", {"target": target})

        job = asyncio.create_task(self._run_demo(task_id))
        self._jobs[task_id] = job
        return {"task_id": task_id, "target": target}

    async def _run_demo(self, task_id: str) -> None:
        for i, step in enumerate(_SCRIPT):
            tp = tracker.get(task_id)
            if tp is None:
                break
            sid = tp.steps[i].step_id
            tracker.start_step(task_id, sid)
            streamer.tool(task_id, step["msg"], step["tool"])
            await self.push_event(task_id, "step_started",
                                  {"index": i, **step})
            await self.push_log(streamer.tail(task_id, limit=1)[0])
            await self.push_progress(task_id)

            # 模拟推进 0→100
            for pct in (0.3, 0.6, 1.0):
                await asyncio.sleep(random.uniform(0.15, 0.4))
                tracker.update_step(task_id, sid, pct)
                await self.push_progress(task_id)

            # 偶尔产生漏洞发现 / AI 思考
            if step["level"] == "vuln" and random.random() < 0.7:
                f = {
                    "title": random.choice(["SQL 注入", "反射型 XSS",
                                            "目录遍历", "未授权访问"]),
                    "severity": random.choice(["high", "medium", "high"]),
                    "evidence": step["msg"],
                }
                streamer.vuln(task_id, f"发现：{f['title']} ({f['severity']})",
                              step["tool"])
                await self.push_finding(task_id, f)
                await self.push_log(streamer.tail(task_id, limit=1)[0])
            elif step["level"] == "thinking":
                th = {"observation": "正在关联...",
                      "decision": "优先验证高危",
                      "reasoning": "高危项可直接影响数据"}
                streamer.thinking(task_id, th["decision"], "ai")
                await self.push_thinking(task_id, th)
                await self.push_log(streamer.tail(task_id, limit=1)[0])

            tracker.finish_step(task_id, sid)
            await self.push_progress(task_id)

        streamer.ok(task_id, "实时演示完成", "system")
        await self.push_event(task_id, "completed",
                              {"task_id": task_id})
        await self.push_progress(task_id)

    def stop_demo(self, task_id: str) -> bool:
        job = self._jobs.get(task_id)
        if job and not job.done():
            job.cancel()
            return True
        return False

    # ------------------------------------------------------------------ #
    def stats(self) -> Dict[str, Any]:
        return {
            "active_demos": sum(1 for j in self._jobs.values() if not j.done()),
            "total_demos": len(self._jobs),
        }


pusher = RealtimePusher()
