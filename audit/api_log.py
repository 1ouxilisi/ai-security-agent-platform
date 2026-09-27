# -*- coding: utf-8 -*-
"""
api_log.py - API 调用日志模块。

功能：
    - 记录每次 API 调用（端点、方法、参数、状态码、耗时、IP、API Key）
    - 敏感数据自动脱敏（密码/token/密钥/身份证/手机号）
    - 记录级别可配置：all / errors_only / slow_only / off
    - 慢请求、错误请求、性能监控（P50/P95/P99）、异常调用检测
    - 支持批量写入

数据库表：audit_api_calls
"""

from __future__ import annotations

import json
import os
import re
import sys
import uuid
from datetime import datetime, timedelta
from typing import Any, Dict, List, Optional

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from utils.logger import log  # noqa: E402
from utils.database import db  # noqa: E402

# 敏感字段关键字（命中即脱敏）
SENSITIVE_KEYS = {
    "password", "passwd", "pwd", "token", "access_token", "refresh_token",
    "secret", "api_key", "apikey", "authorization", "cookie",
    "id_card", "idcard", "身份证", "手机", "phone", "mobile",
    "ssn", "private_key", "privatekey",
}
# 正文最大长度（避免超大 body 撑爆库）
MAX_BODY_LEN = 4096
# 默认慢请求阈值（毫秒）
DEFAULT_SLOW_THRESHOLD_MS = 1000
# 记录级别
VALID_LEVELS = {"all", "errors_only", "slow_only", "off"}


def _now_iso() -> str:
    return datetime.now().isoformat(timespec="seconds")


def _percentile(sorted_vals: List[float], p: float) -> float:
    """计算百分位数，p ∈ [0,100]。"""
    if not sorted_vals:
        return 0.0
    if len(sorted_vals) == 1:
        return float(sorted_vals[0])
    k = (len(sorted_vals) - 1) * (p / 100.0)
    f = int(k)
    c = min(f + 1, len(sorted_vals) - 1)
    if f == c:
        return float(sorted_vals[f])
    return float(sorted_vals[f] + (sorted_vals[c] - sorted_vals[f]) * (k - f))


def mask_phone(text: str) -> str:
    """手机号脱敏：保留前3后4。"""
    return re.sub(r"\b1[3-9]\d{9}\b", lambda m: m.group(0)[:3] + "****" + m.group(0)[-4:], text)


def mask_idcard(text: str) -> str:
    """身份证号脱敏。"""
    return re.sub(r"\b\d{17}[\dXx]\b", lambda m: m.group(0)[:4] + "**********" + m.group(0)[-4:], text)


def sanitize_value(key: str, value: Any) -> Any:
    """递归脱敏字典中的敏感字段。"""
    kl = (key or "").lower()
    if any(s in kl for s in SENSITIVE_KEYS):
        return "***REDACTED***"
    if isinstance(value, dict):
        return {k: sanitize_value(k, v) for k, v in value.items()}
    if isinstance(value, list):
        return [sanitize_value("", v) for v in value]
    if isinstance(value, str):
        return mask_idcard(mask_phone(value))
    return value


def sanitize_obj(obj: Any) -> Any:
    """对任意对象做脱敏。"""
    try:
        return sanitize_value("", obj)
    except Exception:
        return "***REDACTED***"


def _fire_alert(title: str, message: str, severity: str = "warning",
               details: Optional[Dict[str, Any]] = None) -> None:
    """调用全局告警管理器（失败静默）。"""
    try:
        from tools.alert_manager import alert_manager
        alert_manager.create_alert(
            title=title, message=message, severity=severity,
            category="security", details=details or {}, auto_notify=True)
    except Exception as e:  # pragma: no cover
        log.warning(f"API 异常告警写入失败: {e}")


class ApiCallLogger:
    """API 调用日志记录器（单例）。"""

    def __init__(self, record_level: str = "all",
                 slow_threshold_ms: int = DEFAULT_SLOW_THRESHOLD_MS):
        """
        Args:
            record_level: all / errors_only / slow_only / off
            slow_threshold_ms: 慢请求阈值（毫秒）
        """
        self.record_level = record_level if record_level in VALID_LEVELS else "all"
        self.slow_threshold_ms = slow_threshold_ms
        self._init_table()

    def _init_table(self) -> None:
        conn = db._get_connection()
        try:
            conn.execute("""
                CREATE TABLE IF NOT EXISTS audit_api_calls (
                    id TEXT PRIMARY KEY,
                    request_id TEXT,
                    api_endpoint TEXT NOT NULL,
                    request_method TEXT,
                    request_params TEXT,
                    request_headers TEXT,
                    request_body TEXT,
                    response_status_code INTEGER,
                    response_time_ms REAL,
                    request_ip TEXT,
                    user_agent TEXT,
                    api_key TEXT,
                    call_time TEXT NOT NULL,
                    error_message TEXT,
                    tenant_id TEXT
                )
            """)
            conn.execute("CREATE INDEX IF NOT EXISTS idx_api_endpoint ON audit_api_calls(api_endpoint)")
            conn.execute("CREATE INDEX IF NOT EXISTS idx_api_status ON audit_api_calls(response_status_code)")
            conn.execute("CREATE INDEX IF NOT EXISTS idx_api_time ON audit_api_calls(call_time)")
            conn.execute("CREATE INDEX IF NOT EXISTS idx_api_ip ON audit_api_calls(request_ip)")
            conn.execute("CREATE INDEX IF NOT EXISTS idx_api_key ON audit_api_calls(api_key)")
            conn.commit()
        except Exception as e:  # pragma: no cover
            log.error(f"API 调用日志建表失败: {e}")
        finally:
            conn.close()

    # ==================== 写入 ====================

    def _should_record(self, status_code: int, resp_ms: float) -> bool:
        """根据记录级别决定是否落库。"""
        if self.record_level == "off":
            return False
        if self.record_level == "all":
            return True
        if self.record_level == "errors_only":
            return status_code >= 400
        if self.record_level == "slow_only":
            return resp_ms >= self.slow_threshold_ms or status_code >= 500
        return True

    def log_api_call(
        self,
        api_endpoint: str,
        request_method: str = "GET",
        request_params: Optional[Dict[str, Any]] = None,
        request_headers: Optional[Dict[str, Any]] = None,
        request_body: Any = None,
        response_status_code: int = 200,
        response_time_ms: float = 0.0,
        request_ip: str = "",
        user_agent: str = "",
        api_key: str = "",
        error_message: str = "",
        tenant_id: str = "",
        request_id: str = "",
        call_time: Optional[str] = None,
    ) -> Optional[str]:
        """记录一次 API 调用。"""
        if not self._should_record(response_status_code, response_time_ms):
            return None
        call_id = str(uuid.uuid4())
        safe_params = sanitize_obj(request_params or {})
        safe_headers = sanitize_obj(request_headers or {})
        # body 截断 + 脱敏
        try:
            raw_body = json.dumps(sanitize_obj(request_body), ensure_ascii=False, default=str)
        except Exception:
            raw_body = str(request_body)
        if len(raw_body) > MAX_BODY_LEN:
            raw_body = raw_body[:MAX_BODY_LEN] + "...[TRUNCATED]"
        # api_key 脱敏存储（只留后4位）
        masked_key = ""
        if api_key:
            masked_key = ("***" + api_key[-4:]) if len(api_key) > 4 else "***"
        conn = db._get_connection()
        try:
            conn.execute("""
                INSERT INTO audit_api_calls
                    (id, request_id, api_endpoint, request_method, request_params,
                     request_headers, request_body, response_status_code, response_time_ms,
                     request_ip, user_agent, api_key, call_time, error_message, tenant_id)
                VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)
            """, (
                call_id, request_id, api_endpoint, request_method,
                json.dumps(safe_params, ensure_ascii=False),
                json.dumps(safe_headers, ensure_ascii=False),
                raw_body, response_status_code, response_time_ms,
                request_ip, user_agent, masked_key,
                call_time or _now_iso(), error_message, tenant_id,
            ))
            conn.commit()
            return call_id
        except Exception as e:  # pragma: no cover
            log.error(f"写入 API 调用日志失败: {e}")
            return None
        finally:
            conn.close()

    def batch_log_api_calls(self, records: List[Dict[str, Any]]) -> int:
        """批量写入 API 调用日志。"""
        if not records:
            return 0
        rows = []
        for rec in records:
            status = int(rec.get("response_status_code", 200))
            ms = float(rec.get("response_time_ms", 0) or 0)
            if not self._should_record(status, ms):
                continue
            safe_params = sanitize_obj(rec.get("request_params") or {})
            safe_headers = sanitize_obj(rec.get("request_headers") or {})
            try:
                raw_body = json.dumps(sanitize_obj(rec.get("request_body")),
                                      ensure_ascii=False, default=str)
            except Exception:
                raw_body = str(rec.get("request_body", ""))
            if len(raw_body) > MAX_BODY_LEN:
                raw_body = raw_body[:MAX_BODY_LEN] + "...[TRUNCATED]"
            ak = rec.get("api_key", "") or ""
            masked_key = ("***" + ak[-4:]) if len(ak) > 4 else "***" if ak else ""
            rows.append((
                str(uuid.uuid4()), rec.get("request_id", ""),
                rec.get("api_endpoint", ""), rec.get("request_method", "GET"),
                json.dumps(safe_params, ensure_ascii=False),
                json.dumps(safe_headers, ensure_ascii=False),
                raw_body, status, ms,
                rec.get("request_ip", ""), rec.get("user_agent", ""), masked_key,
                rec.get("call_time") or _now_iso(),
                rec.get("error_message", ""), rec.get("tenant_id", ""),
            ))
        if not rows:
            return 0
        conn = db._get_connection()
        try:
            conn.executemany("""
                INSERT INTO audit_api_calls
                    (id, request_id, api_endpoint, request_method, request_params,
                     request_headers, request_body, response_status_code, response_time_ms,
                     request_ip, user_agent, api_key, call_time, error_message, tenant_id)
                VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)
            """, rows)
            conn.commit()
            return len(rows)
        except Exception as e:  # pragma: no cover
            log.error(f"批量写入 API 调用日志失败: {e}")
            return 0
        finally:
            conn.close()

    # ==================== 查询 ====================

    @staticmethod
    def _row(row) -> Dict[str, Any]:
        d = dict(row)
        for f in ("request_params", "request_headers", "request_body"):
            try:
                d[f] = json.loads(d.get(f) or "{}")
            except Exception:
                d[f] = d.get(f)
        return d

    def get_api_call(self, call_id: str) -> Optional[Dict[str, Any]]:
        conn = db._get_connection()
        try:
            row = conn.execute("SELECT * FROM audit_api_calls WHERE id = ?", (call_id,)).fetchone()
            return self._row(row) if row else None
        finally:
            conn.close()

    def list_api_calls(
        self,
        endpoint: Optional[str] = None,
        method: Optional[str] = None,
        status_code: Optional[int] = None,
        request_ip: Optional[str] = None,
        api_key: Optional[str] = None,
        start_time: Optional[str] = None,
        end_time: Optional[str] = None,
        page: int = 1,
        page_size: int = 20,
    ) -> Dict[str, Any]:
        where, params = ["1=1"], []
        if endpoint:
            where.append("api_endpoint LIKE ?"); params.append(f"%{endpoint}%")
        if method:
            where.append("request_method = ?"); params.append(method.upper())
        if status_code is not None:
            where.append("response_status_code = ?"); params.append(status_code)
        if request_ip:
            where.append("request_ip = ?"); params.append(request_ip)
        if api_key:
            where.append("api_key = ?"); params.append(api_key)
        if start_time:
            where.append("call_time >= ?"); params.append(start_time)
        if end_time:
            where.append("call_time <= ?"); params.append(end_time)
        where_sql = " AND ".join(where)
        page = max(1, int(page)); page_size = max(1, min(500, int(page_size)))
        offset = (page - 1) * page_size
        conn = db._get_connection()
        try:
            total = conn.execute(
                f"SELECT COUNT(*) AS c FROM audit_api_calls WHERE {where_sql}", params).fetchone()["c"]
            rows = conn.execute(
                f"SELECT * FROM audit_api_calls WHERE {where_sql} "
                f"ORDER BY call_time DESC LIMIT ? OFFSET ?",
                params + [page_size, offset]).fetchall()
            return {"total": total, "page": page, "page_size": page_size,
                    "items": [self._row(r) for r in rows]}
        finally:
            conn.close()

    def get_slow_requests(self, threshold_ms: Optional[int] = None,
                          limit: int = 100) -> List[Dict[str, Any]]:
        """慢请求列表。"""
        threshold = threshold_ms or self.slow_threshold_ms
        conn = db._get_connection()
        try:
            rows = conn.execute(
                "SELECT * FROM audit_api_calls WHERE response_time_ms >= ? "
                "ORDER BY response_time_ms DESC LIMIT ?",
                (threshold, limit)).fetchall()
            return [self._row(r) for r in rows]
        finally:
            conn.close()

    def get_error_requests(self, limit: int = 100) -> List[Dict[str, Any]]:
        """4xx/5xx 错误请求列表。"""
        conn = db._get_connection()
        try:
            rows = conn.execute(
                "SELECT * FROM audit_api_calls WHERE response_status_code >= 400 "
                "ORDER BY call_time DESC LIMIT ?", (limit,)).fetchall()
            return [self._row(r) for r in rows]
        finally:
            conn.close()

    # ==================== 统计与性能 ====================

    def get_api_stats(
        self,
        start_time: Optional[str] = None,
        end_time: Optional[str] = None,
    ) -> Dict[str, Any]:
        """按端点/方法/状态码/API Key 统计调用量。"""
        where, params = ["1=1"], []
        if start_time:
            where.append("call_time >= ?"); params.append(start_time)
        if end_time:
            where.append("call_time <= ?"); params.append(end_time)
        where_sql = " AND ".join(where)
        conn = db._get_connection()
        try:
            total = conn.execute(
                f"SELECT COUNT(*) AS c FROM audit_api_calls WHERE {where_sql}", params).fetchone()["c"]
            by_endpoint = [dict(r) for r in conn.execute(
                f"SELECT api_endpoint AS name, COUNT(*) AS count, "
                f"AVG(response_time_ms) AS avg_ms FROM audit_api_calls "
                f"WHERE {where_sql} GROUP BY api_endpoint ORDER BY count DESC LIMIT 30",
                params).fetchall()]
            by_method = [dict(r) for r in conn.execute(
                f"SELECT request_method AS name, COUNT(*) AS count FROM audit_api_calls "
                f"WHERE {where_sql} GROUP BY request_method", params).fetchall()]
            by_status = [dict(r) for r in conn.execute(
                f"SELECT response_status_code AS name, COUNT(*) AS count FROM audit_api_calls "
                f"WHERE {where_sql} GROUP BY response_status_code ORDER BY count DESC",
                params).fetchall()]
            by_apikey = [dict(r) for r in conn.execute(
                f"SELECT api_key AS name, COUNT(*) AS count FROM audit_api_calls "
                f"WHERE {where_sql} AND api_key <> '' GROUP BY api_key "
                f"ORDER BY count DESC LIMIT 20", params).fetchall()]
            return {
                "total": total,
                "by_endpoint": by_endpoint,
                "by_method": by_method,
                "by_status": by_status,
                "by_api_key": by_apikey,
            }
        finally:
            conn.close()

    def get_performance_monitor(
        self,
        start_time: Optional[str] = None,
        end_time: Optional[str] = None,
    ) -> Dict[str, Any]:
        """性能监控：平均/P50/P95/P99 响应时间、错误率、调用量趋势。"""
        where, params = ["1=1"], []
        if start_time:
            where.append("call_time >= ?"); params.append(start_time)
        if end_time:
            where.append("call_time <= ?"); params.append(end_time)
        where_sql = " AND ".join(where)
        conn = db._get_connection()
        try:
            rows = conn.execute(
                f"SELECT response_time_ms, response_status_code FROM audit_api_calls "
                f"WHERE {where_sql}", params).fetchall()
            times = sorted(float(r["response_time_ms"] or 0) for r in rows)
            total = len(times)
            errors = sum(1 for r in rows if (r["response_status_code"] or 0) >= 400)
            by_day = [dict(r) for r in conn.execute(
                f"SELECT substr(call_time,1,10) AS date, COUNT(*) AS count, "
                f"AVG(response_time_ms) AS avg_ms FROM audit_api_calls "
                f"WHERE {where_sql} GROUP BY date ORDER BY date DESC LIMIT 30",
                params).fetchall()]
            return {
                "total_calls": total,
                "avg_response_ms": round(sum(times) / total, 2) if total else 0.0,
                "p50_ms": round(_percentile(times, 50), 2),
                "p95_ms": round(_percentile(times, 95), 2),
                "p99_ms": round(_percentile(times, 99), 2),
                "error_count": errors,
                "error_rate": round(errors / total * 100, 2) if total else 0.0,
                "trend": by_day,
            }
        finally:
            conn.close()

    # ==================== 异常检测 ====================

    def detect_anomalies(self, window_hours: int = 1) -> List[Dict[str, Any]]:
        """检测 API 异常：调用量突增、响应时间异常、错误率异常、异常 IP。"""
        anomalies: List[Dict[str, Any]] = []
        since = (datetime.now() - timedelta(hours=window_hours)).isoformat(timespec="seconds")
        conn = db._get_connection()
        try:
            # 错误率异常
            row = conn.execute(
                "SELECT COUNT(*) AS total, "
                "SUM(CASE WHEN response_status_code >= 400 THEN 1 ELSE 0 END) AS errs "
                "FROM audit_api_calls WHERE call_time >= ?", [since]).fetchone()
            total = row["total"] or 0
            errs = row["errs"] or 0
            if total >= 50:
                rate = errs / total
                if rate >= 0.3:
                    anomalies.append({
                        "type": "high_error_rate", "severity": "high",
                        "detail": f"近{window_hours}小时错误率 {rate*100:.1f}%（{errs}/{total}）",
                    })
            # 响应时间异常（> P99 或 > 5s）
            slow = conn.execute(
                "SELECT api_endpoint, request_ip, response_time_ms, call_time "
                "FROM audit_api_calls WHERE call_time >= ? AND response_time_ms >= 5000 "
                "ORDER BY response_time_ms DESC LIMIT 10", [since]).fetchall()
            for r in slow:
                anomalies.append({
                    "type": "slow_outlier", "severity": "warning",
                    "endpoint": r["api_endpoint"], "ip": r["request_ip"],
                    "detail": f"极慢请求 {r['response_time_ms']}ms @ {r['api_endpoint']}",
                })
            # 异常 IP 调用量
            rows = conn.execute(
                "SELECT request_ip, COUNT(*) AS c FROM audit_api_calls "
                "WHERE call_time >= ? AND request_ip <> '' "
                "GROUP BY request_ip HAVING c >= 500 ORDER BY c DESC LIMIT 10",
                [since]).fetchall()
            for r in rows:
                anomalies.append({
                    "type": "ip_rate_anomaly", "severity": "high",
                    "ip": r["request_ip"],
                    "detail": f"IP {r['request_ip']} 近{window_hours}小时调用 {r['c']} 次",
                })
        finally:
            conn.close()
        return anomalies

    def alert_on_anomaly(self, window_hours: int = 1) -> None:
        """对检测到的 API 异常生成告警。"""
        for a in self.detect_anomalies(window_hours=window_hours)[:10]:
            _fire_alert(
                title=f"[审计] API 异常: {a['type']}",
                message=a.get("detail", "API 调用异常"),
                severity=a.get("severity", "warning"),
                details=a,
            )


_api_logger: Optional[ApiCallLogger] = None


def get_api_logger(record_level: str = "all",
                   slow_threshold_ms: int = DEFAULT_SLOW_THRESHOLD_MS) -> ApiCallLogger:
    """获取全局 API 调用日志器单例。"""
    global _api_logger
    if _api_logger is None:
        _api_logger = ApiCallLogger(record_level=record_level,
                                    slow_threshold_ms=slow_threshold_ms)
    return _api_logger
