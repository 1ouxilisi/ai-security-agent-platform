# -*- coding: utf-8 -*-
"""
task_manager_simple.py —— 极简任务管理

内存字典模拟存储。支持：创建任务 / 列表 / 详情 / 日志流 / 进度 / 报告。
任务阶段为模拟流水线：recon -> fingerprint -> dirscan -> vuln -> report。
"""

from __future__ import annotations

import threading
import time
import uuid
from datetime import datetime
from typing import Any, Dict, List, Optional


# 任务阶段定义（极简模式只暴露这条主线）
STAGES: List[Dict[str, Any]] = [
    {"id": "recon",     "name": "信息收集",   "icon": "🔎"},
    {"id": "fingerprint","name": "指纹识别",  "icon": "🖥️"},
    {"id": "dirscan",   "name": "目录扫描",   "icon": "🗂️"},
    {"id": "vuln",      "name": "漏洞扫描",   "icon": "🐞"},
    {"id": "report",    "name": "生成报告",   "icon": "📄"},
]

# 模拟日志模板
_LOG_TEMPLATES: Dict[str, List[str]] = {
    "recon": [
        "[recon] 开始对 {target} 进行信息收集...",
        "[recon] 解析 DNS 记录...",
        "[recon] 抓取首页响应头...",
        "[recon] 信息收集完成，发现 8 个端点",
    ],
    "fingerprint": [
        "[fingerprint] 识别 Web 服务器指纹...",
        "[fingerprint] 检测到 Nginx / PHP 栈",
        "[fingerprint] 指纹识别完成",
    ],
    "dirscan": [
        "[dirscan] 加载字典（500 条）...",
        "[dirscan] 进度 30%...",
        "[dirscan] 发现 /admin /login /robots.txt",
        "[dirscan] 目录扫描完成",
    ],
    "vuln": [
        "[vuln] 启动漏洞检测引擎...",
        "[vuln] 检测 SQL 注入点...",
        "[vuln] 检测 XSS 反射点...",
        "[vuln] 发现 3 个低危 / 1 个中危",
        "[vuln] 漏洞扫描完成",
    ],
    "report": [
        "[report] 汇总检测结果...",
        "[report] 生成 Markdown 报告...",
        "[report] 报告已就绪，可下载",
    ],
}


class SimpleTaskManager:
    """极简任务管理器（内存模拟）。"""

    def __init__(self) -> None:
        self._lock = threading.Lock()
        self._tasks: Dict[str, Dict[str, Any]] = {}
        self._logs: Dict[str, List[Dict[str, Any]]] = {}

    # ------------------------------------------------------------------
    # 创建
    # ------------------------------------------------------------------
    def create_task(self, target: str, name: Optional[str] = None,
                    options: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
        if not target:
            return {"success": False, "error": "target 不能为空"}
        task_id = "simpletask-" + uuid.uuid4().hex[:8]
        now = datetime.now().isoformat(timespec="seconds")
        task = {
            "id": task_id,
            "name": name or f"任务-{task_id[-6:]}",
            "target": target,
            "options": options or {},
            "status": "queued",          # queued / running / done / failed
            "stage_index": 0,
            "stage": STAGES[0]["id"],
            "progress": 0,
            "created_at": now,
            "updated_at": now,
            "vuln_count": {"high": 0, "medium": 0, "low": 0, "info": 0},
        }
        with self._lock:
            self._tasks[task_id] = task
            self._logs[task_id] = []
            self._append_log(task_id, "info", f"任务已创建，目标 {target}，排队等待执行")
            # 立即进入 running，并注入第一条阶段日志
            task["status"] = "running"
            self._advance(task_id)
        return {"success": True, "data": task}

    # ------------------------------------------------------------------
    # 列表 / 详情
    # ------------------------------------------------------------------
    def list_tasks(self, status: Optional[str] = None,
                   limit: int = 50) -> Dict[str, Any]:
        with self._lock:
            items = list(self._tasks.values())
        items.sort(key=lambda t: t["created_at"], reverse=True)
        if status:
            items = [t for t in items if t["status"] == status]
        return {"success": True, "data": {"tasks": items[:limit], "total": len(items)}}

    def get_task(self, task_id: str) -> Dict[str, Any]:
        with self._lock:
            t = self._tasks.get(task_id)
        if not t:
            return {"success": False, "error": f"任务 {task_id} 不存在"}
        return {"success": True, "data": t}

    # ------------------------------------------------------------------
    # 日志流
    # ------------------------------------------------------------------
    def _append_log(self, task_id: str, level: str, message: str) -> None:
        entry = {
            "time": datetime.now().isoformat(timespec="seconds"),
            "level": level,
            "message": message,
        }
        self._logs.setdefault(task_id, []).append(entry)

    def get_logs(self, task_id: str, since: int = 0,
                 limit: int = 200) -> Dict[str, Any]:
        with self._lock:
            logs = list(self._logs.get(task_id, []))
        part = logs[since:]
        return {
            "success": True,
            "data": {"logs": part[-limit:], "count": len(part),
                     "total": len(logs)},
        }

    # ------------------------------------------------------------------
    # 模拟推进（极简版：每次调用推进一步）
    # ------------------------------------------------------------------
    def _advance(self, task_id: str) -> None:
        task = self._tasks.get(task_id)
        if not task or task["status"] not in ("queued", "running"):
            return
        stage = STAGES[task["stage_index"]]["id"]
        for line in _LOG_TEMPLATES.get(stage, []):
            self._append_log(task_id, "info", line.format(target=task["target"]))
        task["stage_index"] += 1
        if task["stage_index"] >= len(STAGES):
            task["status"] = "done"
            task["progress"] = 100
            task["stage"] = "done"
            task["vuln_count"] = {"high": 0, "medium": 1, "low": 3, "info": 6}
            self._append_log(task_id, "success", "任务完成，报告已生成")
        else:
            task["progress"] = int(task["stage_index"] / len(STAGES) * 100)
            task["stage"] = STAGES[task["stage_index"]]["id"]
            self._append_log(task_id, "info",
                             f"进入阶段：{STAGES[task['stage_index']]['name']}")
        task["updated_at"] = datetime.now().isoformat(timespec="seconds")

    def tick(self, task_id: str) -> Dict[str, Any]:
        """手动推进一个阶段（前端轮询调用）。"""
        with self._lock:
            if task_id not in self._tasks:
                return {"success": False, "error": "任务不存在"}
            self._advance(task_id)
            return {"success": True, "data": self._tasks[task_id]}

    def delete_task(self, task_id: str) -> Dict[str, Any]:
        with self._lock:
            t = self._tasks.pop(task_id, None)
            self._logs.pop(task_id, None)
        if not t:
            return {"success": False, "error": "任务不存在"}
        return {"success": True, "data": {"deleted": task_id}}

    def cancel(self, task_id: str) -> Dict[str, Any]:
        with self._lock:
            t = self._tasks.get(task_id)
            if not t:
                return {"success": False, "error": "任务不存在"}
            if t["status"] in ("done", "failed"):
                return {"success": False, "error": "任务已结束，无法取消"}
            t["status"] = "failed"
            t["updated_at"] = datetime.now().isoformat(timespec="seconds")
            self._append_log(task_id, "warn", "任务被用户取消")
            return {"success": True, "data": t}

    # ------------------------------------------------------------------
    # 报告
    # ------------------------------------------------------------------
    def get_report(self, task_id: str) -> Dict[str, Any]:
        with self._lock:
            t = self._tasks.get(task_id)
        if not t:
            return {"success": False, "error": "任务不存在"}
        report = {
            "task_id": task_id,
            "title": f"安全测试报告 - {t['name']}",
            "target": t["target"],
            "status": t["status"],
            "progress": t["progress"],
            "vuln_count": t["vuln_count"],
            "generated_at": datetime.now().isoformat(timespec="seconds"),
            "summary": (
                f"对 {t['target']} 完成信息收集、指纹识别、目录扫描与漏洞检测，"
                f"共发现高危 {t['vuln_count']['high']} / "
                f"中危 {t['vuln_count']['medium']} / "
                f"低危 {t['vuln_count']['low']} 项。"
            ),
            "lines": [e["message"] for e in self._logs.get(task_id, [])],
        }
        return {"success": True, "data": report}

    def stats(self) -> Dict[str, Any]:
        with self._lock:
            items = list(self._tasks.values())
        return {
            "success": True,
            "data": {
                "total": len(items),
                "running": sum(1 for t in items if t["status"] == "running"),
                "done": sum(1 for t in items if t["status"] == "done"),
                "queued": sum(1 for t in items if t["status"] == "queued"),
                "failed": sum(1 for t in items if t["status"] == "failed"),
            },
        }


_singleton: SimpleTaskManager | None = None


def get_task_manager() -> SimpleTaskManager:
    global _singleton
    if _singleton is None:
        _singleton = SimpleTaskManager()
    return _singleton
