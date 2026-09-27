# -*- coding: utf-8 -*-
"""
system_health.py — 统一系统健康检查面板聚合。

汇总：服务状态、数据库连接（SQLite，只读探测）、外部工具、API 健康、
资源使用、最近备份、定时任务。所有数据来自真实采样（工具检测/进程信息），
数据库部分以只读方式探测现有 SQLite 文件，不创建表。
"""

from __future__ import annotations

import logging
import os
import platform
import sqlite3
import time
from typing import Any, Dict, List, Optional

from .performance_monitor import get_monitor
from .tool_detector import get_detector

logger = logging.getLogger(__name__)

_START_TIME = time.time()


def _uptime_seconds() -> int:
    return int(time.time() - _START_TIME)


def _fmt_duration(seconds: int) -> str:
    d, rem = divmod(seconds, 86400)
    h, rem = divmod(rem, 3600)
    m, s = divmod(rem, 60)
    parts = []
    if d:
        parts.append(f"{d}d")
    if h:
        parts.append(f"{h}h")
    if m:
        parts.append(f"{m}m")
    parts.append(f"{s}s")
    return " ".join(parts)


def _find_sqlite_files() -> List[str]:
    """在 api_server/ 与项目根下找常见 SQLite 文件，只读探测。"""
    candidates = []
    here = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    for root in (here, os.path.join(here, "api_server"),
                 os.path.join(here, "data"), os.path.join(here, "db")):
        if not os.path.isdir(root):
            continue
        try:
            for name in os.listdir(root):
                if name.endswith((".db", ".sqlite", ".sqlite3")):
                    candidates.append(os.path.join(root, name))
        except Exception:
            continue
    return candidates[:5]


def service_status() -> Dict[str, Any]:
    return {
        "status": "running",
        "pid": os.getpid(),
        "platform": platform.platform(),
        "python_version": platform.python_version(),
        "start_time": time.strftime("%Y-%m-%d %H:%M:%S",
                                    time.localtime(_START_TIME)),
        "uptime_seconds": _uptime_seconds(),
        "uptime_human": _fmt_duration(_uptime_seconds()),
        "threads": _import_thread_count(),
    }


def _import_thread_count() -> int:
    try:
        import threading
        return threading.active_count()
    except Exception:
        return 0


def database_status() -> Dict[str, Any]:
    """只读探测 SQLite，不创建表。"""
    files = _find_sqlite_files()
    if not files:
        return {
            "connected": False,
            "file": None,
            "message": "未发现 SQLite 数据库文件（本模块不创建表，仅只读探测）",
            "tables": 0, "rows_total": 0, "size_bytes": 0,
        }
    path = files[0]
    try:
        size = os.path.getsize(path)
        conn = sqlite3.connect(f"file:{path}?mode=ro", uri=True, timeout=2)
        cur = conn.cursor()
        cur.execute("SELECT name FROM sqlite_master WHERE type='table'")
        tables = [r[0] for r in cur.fetchall()]
        rows_total = 0
        for t in tables[:20]:
            try:
                cur.execute(f"SELECT COUNT(*) FROM \"{t}\"")
                rows_total += cur.fetchone()[0]
            except Exception:
                continue
        conn.close()
        return {
            "connected": True,
            "file": path,
            "size_bytes": size,
            "tables": len(tables),
            "rows_total": rows_total,
            "recent_query_time": time.strftime("%Y-%m-%d %H:%M:%S"),
        }
    except Exception as e:
        return {
            "connected": False,
            "file": path,
            "error": str(e),
            "tables": 0, "rows_total": 0, "size_bytes": os.path.getsize(path) if os.path.exists(path) else 0,
        }


def tools_status() -> Dict[str, Any]:
    det = get_detector()
    return det.summary()


def api_health(window_minutes: int = 60) -> Dict[str, Any]:
    mon = get_monitor()
    ov = mon.overview()
    return {
        "window_minutes": window_minutes,
        "requests": ov["total_requests"],
        "error_rate": ov["error_rate"],
        "p50_ms": ov["global_p50_ms"],
        "p95_ms": ov["global_p95_ms"],
        "p99_ms": ov["global_p99_ms"],
        "status_codes": ov["status_codes"],
        "slow_endpoints": ov["slow_count"],
    }


def resources_status() -> Dict[str, Any]:
    return get_monitor().resources()


def backup_status() -> Dict[str, Any]:
    """无外部备份调度器时返回空状态（不模拟数据）。"""
    return {
        "last_backup_at": None,
        "size_bytes": 0,
        "status": "unknown",
        "count": 0,
        "note": "未检测到备份调度器接入",
    }


def scheduled_tasks_status() -> Dict[str, Any]:
    return {
        "tasks": [],
        "note": "未检测到定时任务注册",
    }


def anomalies() -> List[Dict[str, Any]]:
    out: List[Dict[str, Any]] = []
    db = database_status()
    if not db.get("connected"):
        out.append({"level": "warn", "source": "database",
                    "message": "数据库未连接或未找到文件"})
    ts = tools_status()
    if ts.get("coverage", 100) < 60:
        out.append({"level": "warn", "source": "tools",
                    "message": f"外部工具覆盖率仅 {ts.get('coverage')}%"})
    ah = api_health()
    if ah.get("error_rate", 0) > 5:
        out.append({"level": "error", "source": "api",
                    "message": f"API 错误率 {ah['error_rate']}% 过高"})
    res = resources_status()
    if res.get("system_memory_percent") and res["system_memory_percent"] > 90:
        out.append({"level": "error", "source": "resource",
                    "message": f"系统内存 {res['system_memory_percent']}%"})
    return out


def full_health() -> Dict[str, Any]:
    return {
        "generated_at": time.strftime("%Y-%m-%d %H:%M:%S"),
        "service": service_status(),
        "database": database_status(),
        "tools": tools_status(),
        "api": api_health(),
        "resources": resources_status(),
        "backup": backup_status(),
        "scheduled_tasks": scheduled_tasks_status(),
        "anomalies": anomalies(),
        "overall": "healthy" if not any(
            a["level"] == "error" for a in anomalies()
        ) else "degraded",
    }
