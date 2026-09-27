# -*- coding: utf-8 -*-
"""
deploy_dashboard.py — 部署管理控制台数据模型。

模块:
  - 部署状态大屏（服务状态/资源/版本/运行时长/健康检查）
  - 部署历史
  - 环境管理
  - 日志中心
  - 监控告警
  - 部署文档
"""

from __future__ import annotations

import time
from typing import Any, Dict, List


# =========================================================================== #
# 1. 部署状态大屏
# =========================================================================== #
def get_overview_dashboard() -> Dict[str, Any]:
    return {
        "version": "20.1.0",
        "build_time": "2026-09-14 10:00:00",
        "uptime_hours": 72,
        "services": [
            {"name": "api_server", "status": "running", "port": 8000, "latency_ms": 23},
            {"name": "redis",      "status": "running", "port": 6379, "latency_ms": 1},
            {"name": "worker",     "status": "running", "port": None,  "latency_ms": None},
        ],
        "resources": {
            "cpu_percent": 35.2,
            "memory_used_mb": 1024,
            "memory_total_mb": 8192,
            "disk_used_gb": 45.6,
            "disk_total_gb": 500,
            "network_in_mbps": 12.5,
            "network_out_mbps": 8.3,
        },
        "health_check": {
            "status": "healthy",
            "checked_at": time.strftime("%Y-%m-%d %H:%M:%S"),
            "checks_passed": 5,
            "checks_failed": 0,
        },
        "recent_deploy": {
            "version": "20.1.0",
            "deployed_at": "2026-09-14 10:30:00",
            "operator": "admin",
            "result": "success",
        },
    }


# =========================================================================== #
# 2. 日志中心
# =========================================================================== #
_LOG_POOL: List[Dict[str, Any]] = [
    {"ts": "2026-09-14 10:30:01", "level": "INFO",  "source": "uvicorn",  "message": "Application startup complete."},
    {"ts": "2026-09-14 10:30:02", "level": "INFO",  "source": "deploy",   "message": "Deploy v20.1.0 successful"},
    {"ts": "2026-09-14 10:31:15", "level": "WARN",  "source": "auth",     "message": "Failed login attempt from 10.0.0.5"},
    {"ts": "2026-09-14 10:35:22", "level": "ERROR", "source": "backup",   "message": "Incremental backup delayed by 3s"},
    {"ts": "2026-09-14 10:40:00", "level": "INFO",  "source": "cron",      "message": "Scheduled health check passed"},
    {"ts": "2026-09-14 11:00:00", "level": "INFO",  "source": "cron",      "message": "Daily backup completed"},
    {"ts": "2026-09-14 11:15:33", "level": "DEBUG", "source": "api",       "message": "GET /api/v1/deploy/env/report 200 in 120ms"},
]


def get_logs(level: str = "", source: str = "", limit: int = 50) -> Dict[str, Any]:
    items = list(_LOG_POOL)
    if level:
        items = [l for l in items if l["level"].lower() == level.lower()]
    if source:
        items = [l for l in items if source.lower() in l["source"].lower()]
    return {
        "total": len(items),
        "returned": len(items[:limit]),
        "logs": items[:limit],
        "levels_available": ["DEBUG", "INFO", "WARN", "ERROR", "FATAL"],
    }


# =========================================================================== #
# 3. 监控告警
# =========================================================================== #
ALERT_RULES: List[Dict[str, Any]] = [
    {"rule_id": "CPU_HIGH",     "metric": "cpu_percent",   "threshold": 80, "duration": "5m", "enabled": True},
    {"rule_id": "MEM_HIGH",     "metric": "memory_percent", "threshold": 85, "duration": "5m", "enabled": True},
    {"rule_id": "DISK_LOW",     "metric": "disk_free_gb",   "threshold": 10, "duration": "1m", "enabled": True},
    {"rule_id": "API_LATENCY",  "metric": "http_latency_ms", "threshold": 500, "duration": "3m", "enabled": True},
    {"rule_id": "ERROR_RATE",   "metric": "http_error_rate", "threshold": 5,  "duration": "5m", "enabled": False},
]

ALERT_HISTORY: List[Dict[str, Any]] = [
    {"alert_id": "ALT-001", "rule": "CPU_HIGH", "level": "warning",
     "triggered_at": "2026-09-13 03:22:00", "resolved_at": "2026-09-13 03:35:00",
     "value": 92.4, "message": "CPU 使用率超过 80%"},
]


def get_monitoring_metrics() -> Dict[str, Any]:
    return {
        "cpu_percent": 35.2,
        "memory_percent": 12.5,
        "disk_percent": 9.1,
        "network_in_mbps": 12.5,
        "network_out_mbps": 8.3,
        "http_latency_ms": 23,
        "http_error_rate": 0.02,
        "active_connections": 42,
        "metrics_at": time.strftime("%Y-%m-%d %H:%M:%S"),
    }


def get_alert_rules() -> List[Dict[str, Any]]:
    return ALERT_RULES


def get_alert_history() -> List[Dict[str, Any]]:
    return ALERT_HISTORY


# =========================================================================== #
# 4. 部署文档
# =========================================================================== #
DEPLOY_DOCS: List[Dict[str, Any]] = [
    {"id": "install-guide",       "title": "安装指南",       "category": "安装",
     "content": "1. 安装 Python 3.10+\\n2. 运行 pip install -r requirements.txt\\n3. 启动 uvicorn api_server.app:app"},
    {"id": "config-guide",        "title": "配置指南",       "category": "配置",
     "content": "编辑 .env 文件，配置端口、数据库、JWT 密钥"},
    {"id": "upgrade-guide",       "title": "升级指南",       "category": "升级",
     "content": "1. 备份\\n2. git pull\\n3. 运行迁移\\n4. 重启"},
    {"id": "backup-recovery",    "title": "备份恢复指南",   "category": "运维",
     "content": "使用备份接口创建全量/增量备份，灾难时选择恢复点"},
    {"id": "troubleshooting",    "title": "故障排查指南",   "category": "运维",
     "content": "查看日志 → 检查端口 → 重启服务 → 回滚版本"},
    {"id": "best-practices",     "title": "最佳实践",       "category": "运维",
     "content": "生产环境必做：HTTPS、防火墙、备份、监控、日志轮转"},
    {"id": "faq",                "title": "常见问题 FAQ",   "category": "帮助",
     "content": "Q: 端口被占用？A: 修改 AI_HACKING_PORT"},
]


def list_docs() -> List[Dict[str, Any]]:
    return DEPLOY_DOCS


def get_doc(doc_id: str) -> Dict[str, Any]:
    for d in DEPLOY_DOCS:
        if d["id"] == doc_id:
            return d
    return {"error": "文档不存在"}
