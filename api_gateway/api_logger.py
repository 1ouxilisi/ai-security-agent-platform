# -*- coding: utf-8 -*-
"""
api_logger.py - API 日志器。

记录请求级日志（请求ID/端点/方法/参数脱敏/响应码/耗时/IP/用户等），
内存环形缓冲区 + JSON 文件按天滚动持久化，支持过滤查询、统计、导出与敏感字段脱敏。
纯 Python 实现。
"""

from __future__ import annotations

import os
import csv
import json
import time
import uuid
import threading
from collections import deque, Counter
from typing import Any, Deque, Dict, List, Optional


_DATA_DIR = os.path.join(
    os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
    "data",
    "api_gateway",
)

# 敏感字段（小写匹配）
_SENSITIVE_KEYS = {
    "password", "passwd", "token", "secret", "key", "apikey", "api_key",
    "authorization", "cookie", "set-cookie", "session", "credential",
    "creditcard", "card", "privatekey",
}

# 日志级别
LEVEL_ALL = "all"          # 记录全部
LEVEL_ERROR = "error"      # 仅错误（>=400）
LEVEL_SLOW = "slow"        # 仅慢请求
LEVEL_OFF = "off"          # 关闭


class APILogger:
    """API 日志器（线程安全，单例）。"""

    def __init__(self, data_dir: Optional[str] = None,
                 buffer_size: int = 10_000) -> None:
        """初始化日志器。

        Args:
            data_dir: 持久化目录。
            buffer_size: 内存环形缓冲区大小。
        """
        self._lock = threading.RLock()
        self._data_dir = data_dir or os.path.join(_DATA_DIR, "logs")
        os.makedirs(self._data_dir, exist_ok=True)
        self._buffer: Deque[Dict[str, Any]] = deque(maxlen=buffer_size)

        # 日志级别：全局 + 按端点覆盖
        self._global_level = LEVEL_ALL
        self._endpoint_levels: Dict[str, str] = {}

        # 慢请求阈值（秒）
        self._slow_threshold = 1.0

    # ------------------------------------------------------------------ #
    # 脱敏
    # ------------------------------------------------------------------ #
    def _mask_value(self, value: Any) -> Any:
        """对单个值做脱敏（保留前2后2，中间打码）。"""
        try:
            s = str(value)
        except Exception:
            return "***"
        if len(s) <= 4:
            return "***"
        return f"{s[:2]}***{s[-2:]}"

    def _sanitize(self, obj: Any, depth: int = 0) -> Any:
        """递归脱敏字典/列表中的敏感字段，并截断超长内容。"""
        if depth > 6:
            return "..."
        if isinstance(obj, dict):
            out: Dict[str, Any] = {}
            for k, v in obj.items():
                kl = str(k).lower()
                if any(sens in kl for sens in _SENSITIVE_KEYS):
                    out[k] = self._mask_value(v)
                else:
                    out[k] = self._sanitize(v, depth + 1)
            return out
        if isinstance(obj, (list, tuple)):
            return [self._sanitize(v, depth + 1) for v in obj[:20]]
        if isinstance(obj, str) and len(obj) > 2000:
            return obj[:2000] + "...[truncated]"
        return obj

    # ------------------------------------------------------------------ #
    # 日志级别
    # ------------------------------------------------------------------ #
    def set_log_level(self, level: str, endpoint: Optional[str] = None) -> None:
        """设置日志级别。

        Args:
            level: all / error / slow / off。
            endpoint: 目标端点，None 表示全局。
        """
        if level not in (LEVEL_ALL, LEVEL_ERROR, LEVEL_SLOW, LEVEL_OFF):
            level = LEVEL_ALL
        with self._lock:
            if endpoint:
                self._endpoint_levels[endpoint] = level
            else:
                self._global_level = level

    def get_log_level(self, endpoint: Optional[str] = None) -> str:
        """获取日志级别。"""
        with self._lock:
            if endpoint and endpoint in self._endpoint_levels:
                return self._endpoint_levels[endpoint]
            return self._global_level

    def _should_log(self, endpoint: str, status_code: int,
                    duration: float) -> bool:
        """根据级别判断是否记录该请求。"""
        level = self.get_log_level(endpoint)
        if level == LEVEL_OFF:
            return False
        if level == LEVEL_ALL:
            return True
        if level == LEVEL_ERROR:
            return status_code >= 400
        if level == LEVEL_SLOW:
            return duration >= self._slow_threshold
        return True

    # ------------------------------------------------------------------ #
    # 记录
    # ------------------------------------------------------------------ #
    def log_request(self, request_data: Dict[str, Any]) -> Optional[str]:
        """记录一条 API 请求日志。

        Args:
            request_data: 请求数据字典，可包含 endpoint/method/params/headers/
                          body/status_code/duration_ms/client_ip/user_agent/
                          api_key/user_id/tenant_id/error 等。

        Returns:
            请求 ID；若按级别未记录返回 None。
        """
        endpoint = request_data.get("endpoint", request_data.get("path", "/"))
        status_code = int(request_data.get("status_code", 200))
        duration_ms = float(request_data.get("duration_ms", 0.0))

        if not self._should_log(endpoint, status_code, duration_ms / 1000.0):
            return None

        req_id = request_data.get("request_id") or uuid.uuid4().hex[:16]
        entry = {
            "request_id": req_id,
            "timestamp": request_data.get("timestamp") or time.strftime(
                "%Y-%m-%d %H:%M:%S", time.localtime()),
            "endpoint": endpoint,
            "method": request_data.get("method", "GET"),
            "params": self._sanitize(request_data.get("params")),
            "headers": self._sanitize(request_data.get("headers")),
            "body": self._sanitize(request_data.get("body")),
            "status_code": status_code,
            "duration_ms": duration_ms,
            "client_ip": request_data.get("client_ip", ""),
            "user_agent": request_data.get("user_agent", ""),
            "api_key": self._mask_value(request_data.get("api_key", ""))
            if request_data.get("api_key") else "",
            "user_id": request_data.get("user_id", ""),
            "tenant_id": request_data.get("tenant_id", ""),
            "error": request_data.get("error", ""),
        }
        with self._lock:
            self._buffer.append(entry)
            self._async_persist(entry)
        return req_id

    def _async_persist(self, entry: Dict[str, Any]) -> None:
        """异步写入按天滚动的 JSON 文件（简化：直接追加，主流程不阻塞）。"""
        try:
            day = time.strftime("%Y-%m-%d", time.localtime())
            path = os.path.join(self._data_dir, f"api_{day}.jsonl")
            with open(path, "a", encoding="utf-8") as f:
                f.write(json.dumps(entry, ensure_ascii=False) + "\n")
        except Exception:
            pass

    # ------------------------------------------------------------------ #
    # 查询
    # ------------------------------------------------------------------ #
    def get_logs(self, filters: Optional[Dict[str, Any]] = None,
                 page: int = 1, page_size: int = 50) -> Dict[str, Any]:
        """分页查询日志。

        Args:
            filters: 过滤条件（endpoint/method/status_code/client_ip/
                     user_id/api_key/request_id/start_time/end_time）。
            page: 页码（从 1 开始）。
            page_size: 每页条数。

        Returns:
            {"total", "page", "page_size", "items"}。
        """
        filters = filters or {}
        with self._lock:
            items = list(self._buffer)
        # 反转：最新在前
        items = items[::-1]

        # 过滤
        def match(it: Dict[str, Any]) -> bool:
            for k, v in filters.items():
                if v is None or v == "":
                    continue
                if k == "start_time":
                    if it["timestamp"] < str(v):
                        return False
                elif k == "end_time":
                    if it["timestamp"] > str(v):
                        return False
                elif k == "status_code":
                    if int(it.get("status_code", 0)) != int(v):
                        return False
                else:
                    if str(it.get(k, "")) != str(v):
                        return False
            return True

        filtered = [it for it in items if match(it)]
        total = len(filtered)
        start = (page - 1) * page_size
        end = start + page_size
        return {
            "total": total,
            "page": page,
            "page_size": page_size,
            "items": filtered[start:end],
        }

    def get_recent_logs(self, limit: int = 100) -> List[Dict[str, Any]]:
        """获取最近 N 条日志。"""
        with self._lock:
            items = list(self._buffer)[::-1]
        return items[:limit]

    # ------------------------------------------------------------------ #
    # 统计
    # ------------------------------------------------------------------ #
    def get_stats(self, time_range: str = "1h") -> Dict[str, Any]:
        """获取日志统计。

        Args:
            time_range: 时间范围（本实现基于内存缓冲，不严格按时间窗）。
        """
        with self._lock:
            items = list(self._buffer)
        if not items:
            return {"total": 0, "by_status": {}, "by_endpoint": {},
                    "slowest": [], "errors": {}}

        by_endpoint = Counter(it["endpoint"] for it in items)
        by_status = Counter(it["status_code"] for it in items)
        by_method = Counter(it["method"] for it in items)

        # Top 10 慢请求
        slowest = sorted(items, key=lambda x: x.get("duration_ms", 0),
                         reverse=True)[:10]
        # Top 10 错误端点
        err_endpoints = Counter(
            it["endpoint"] for it in items if it["status_code"] >= 400)

        return {
            "total": len(items),
            "time_range": time_range,
            "by_status_code": dict(by_status),
            "by_method": dict(by_method),
            "top_endpoints": by_endpoint.most_common(10),
            "top_error_endpoints": err_endpoints.most_common(10),
            "top_slow_requests": [
                {"endpoint": it["endpoint"], "duration_ms": it["duration_ms"],
                 "request_id": it["request_id"]}
                for it in slowest
            ],
        }

    # ------------------------------------------------------------------ #
    # 导出
    # ------------------------------------------------------------------ #
    def export_logs(self, fmt: str = "json",
                     filters: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
        """导出日志为 JSON 或 CSV。

        Args:
            fmt: json / csv。
            filters: 过滤条件。

        Returns:
            {"format", "count", "content" 或 "path"}。
        """
        result = self.get_logs(filters=filters, page=1, page_size=100_000)
        items = result["items"]
        os.makedirs(self._data_dir, exist_ok=True)
        ts = time.strftime("%Y%m%d_%H%M%S", time.localtime())

        if fmt.lower() == "csv":
            path = os.path.join(self._data_dir, f"export_{ts}.csv")
            fields = ["request_id", "timestamp", "endpoint", "method",
                      "status_code", "duration_ms", "client_ip",
                      "user_id", "tenant_id", "error"]
            try:
                with open(path, "w", encoding="utf-8-sig", newline="") as f:
                    writer = csv.DictWriter(f, fieldnames=fields)
                    writer.writeheader()
                    for it in items:
                        writer.writerow({k: it.get(k, "") for k in fields})
            except Exception as e:
                return {"format": "csv", "count": 0, "error": str(e)}
            return {"format": "csv", "count": len(items), "path": path}

        # JSON
        path = os.path.join(self._data_dir, f"export_{ts}.json")
        try:
            with open(path, "w", encoding="utf-8") as f:
                json.dump(items, f, ensure_ascii=False, indent=2)
        except Exception as e:
            return {"format": "json", "count": 0, "error": str(e)}
        return {"format": "json", "count": len(items), "path": path}

    # ------------------------------------------------------------------ #
    # 清空
    # ------------------------------------------------------------------ #
    def clear_logs(self) -> int:
        """清空内存日志缓冲区。"""
        with self._lock:
            n = len(self._buffer)
            self._buffer.clear()
            return n


# 模块级单例
api_logger = APILogger()
