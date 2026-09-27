# -*- coding: utf-8 -*-
"""
data_access_log.py - 数据访问审计日志模块。

功能：
    - 记录敏感数据的访问行为（查询/导出/下载/打印/分享）
    - 批量访问检测：短时间内大量查询或导出
    - 数据泄露检测：异常导出/下载/分享
    - 敏感数据访问报告

数据库表：audit_data_access
"""

from __future__ import annotations

import os
import sys
import uuid
from datetime import datetime, timedelta
from typing import Any, Dict, List, Optional

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from utils.logger import log  # noqa: E402
from utils.database import db  # noqa: E402

VALID_ACCESS_TYPES = {"query", "export", "download", "print", "share"}
VALID_DATA_TYPES = {"vulnerability", "asset", "report", "incident", "user", "config"}
SENSITIVE_DATA_TYPES = {"vulnerability", "user", "config"}

# 阈值
BATCH_QUERY_THRESHOLD = 50      # 短时查询次数
BATCH_WINDOW_MINUTES = 5        # 时间窗
LEAK_EXPORT_THRESHOLD = 10      # 单次导出条数阈值（近似）


def _now_iso() -> str:
    return datetime.now().isoformat(timespec="seconds")


def _fire_alert(title: str, message: str, severity: str = "warning",
               details: Optional[Dict[str, Any]] = None) -> None:
    try:
        from tools.alert_manager import alert_manager
        alert_manager.create_alert(
            title=title, message=message, severity=severity,
            category="security", details=details or {}, auto_notify=True)
    except Exception as e:  # pragma: no cover
        log.warning(f"数据访问告警写入失败: {e}")


class DataAccessLogger:
    """数据访问日志记录器（单例）。"""

    def __init__(self) -> None:
        self._init_table()

    def _init_table(self) -> None:
        conn = db._get_connection()
        try:
            conn.execute("""
                CREATE TABLE IF NOT EXISTS audit_data_access (
                    id TEXT PRIMARY KEY,
                    access_user TEXT NOT NULL,
                    access_type TEXT NOT NULL,
                    data_type TEXT NOT NULL,
                    data_id TEXT,
                    data_summary TEXT,
                    access_time TEXT NOT NULL,
                    ip_address TEXT,
                    user_agent TEXT,
                    result TEXT DEFAULT 'success',
                    tenant_id TEXT
                )
            """)
            conn.execute("CREATE INDEX IF NOT EXISTS idx_da_user ON audit_data_access(access_user)")
            conn.execute("CREATE INDEX IF NOT EXISTS idx_da_type ON audit_data_access(data_type)")
            conn.execute("CREATE INDEX IF NOT EXISTS idx_da_access ON audit_data_access(access_type)")
            conn.execute("CREATE INDEX IF NOT EXISTS idx_da_time ON audit_data_access(access_time)")
            conn.commit()
        except Exception as e:  # pragma: no cover
            log.error(f"数据访问日志建表失败: {e}")
        finally:
            conn.close()

    # ==================== 写入 ====================

    def log_data_access(
        self,
        access_user: str,
        access_type: str,
        data_type: str,
        data_id: str = "",
        data_summary: str = "",
        ip_address: str = "",
        user_agent: str = "",
        result: str = "success",
        tenant_id: str = "",
        auto_detect: bool = True,
    ) -> str:
        """记录一次数据访问。"""
        if access_type not in VALID_ACCESS_TYPES:
            access_type = "query"
        if data_type not in VALID_DATA_TYPES:
            data_type = "vulnerability"
        access_id = str(uuid.uuid4())
        conn = db._get_connection()
        try:
            conn.execute("""
                INSERT INTO audit_data_access
                    (id, access_user, access_type, data_type, data_id, data_summary,
                     access_time, ip_address, user_agent, result, tenant_id)
                VALUES (?,?,?,?,?,?,?,?,?,?,?)
            """, (access_id, access_user, access_type, data_type, data_id, data_summary,
                  _now_iso(), ip_address, user_agent, result, tenant_id))
            conn.commit()
        except Exception as e:  # pragma: no cover
            log.error(f"写入数据访问日志失败: {e}")
        finally:
            conn.close()

        # 敏感数据访问触发检测
        if auto_detect and data_type in SENSITIVE_DATA_TYPES:
            try:
                self.alert_on_abnormal_access(user=access_user)
            except Exception:
                pass
        return access_id

    # ==================== 查询 ====================

    @staticmethod
    def _row(row) -> Dict[str, Any]:
        return dict(row) if row else {}

    def get_data_access(self, access_id: str) -> Optional[Dict[str, Any]]:
        conn = db._get_connection()
        try:
            row = conn.execute(
                "SELECT * FROM audit_data_access WHERE id = ?", (access_id,)).fetchone()
            return self._row(row) if row else None
        finally:
            conn.close()

    def list_data_access(
        self,
        access_user: Optional[str] = None,
        data_type: Optional[str] = None,
        access_type: Optional[str] = None,
        ip_address: Optional[str] = None,
        start_time: Optional[str] = None,
        end_time: Optional[str] = None,
        page: int = 1,
        page_size: int = 20,
    ) -> Dict[str, Any]:
        where, params = ["1=1"], []
        if access_user:
            where.append("access_user LIKE ?"); params.append(f"%{access_user}%")
        if data_type:
            where.append("data_type = ?"); params.append(data_type)
        if access_type:
            where.append("access_type = ?"); params.append(access_type)
        if ip_address:
            where.append("ip_address = ?"); params.append(ip_address)
        if start_time:
            where.append("access_time >= ?"); params.append(start_time)
        if end_time:
            where.append("access_time <= ?"); params.append(end_time)
        where_sql = " AND ".join(where)
        page = max(1, int(page)); page_size = max(1, min(500, int(page_size)))
        offset = (page - 1) * page_size
        conn = db._get_connection()
        try:
            total = conn.execute(
                f"SELECT COUNT(*) AS c FROM audit_data_access WHERE {where_sql}", params).fetchone()["c"]
            rows = conn.execute(
                f"SELECT * FROM audit_data_access WHERE {where_sql} "
                f"ORDER BY access_time DESC LIMIT ? OFFSET ?",
                params + [page_size, offset]).fetchall()
            return {"total": total, "page": page, "page_size": page_size,
                    "items": [self._row(r) for r in rows]}
        finally:
            conn.close()

    # ==================== 异常检测 ====================

    def detect_batch_access(self, user: Optional[str] = None,
                            window_minutes: int = BATCH_WINDOW_MINUTES) -> List[Dict[str, Any]]:
        """批量访问检测：短时间内大量查询/导出。"""
        since = (datetime.now() - timedelta(minutes=window_minutes)).isoformat(timespec="seconds")
        where, params = ["access_time >= ?"], [since]
        if user:
            where.append("access_user = ?"); params.append(user)
        conn = db._get_connection()
        try:
            rows = conn.execute(
                f"SELECT access_user, data_type, access_type, COUNT(*) AS c "
                f"FROM audit_data_access WHERE {' AND '.join(where)} "
                f"GROUP BY access_user, data_type, access_type HAVING c >= ?",
                params + [BATCH_QUERY_THRESHOLD]).fetchall()
            return [{
                "type": "batch_access",
                "severity": "high",
                "user": r["access_user"],
                "data_type": r["data_type"],
                "access_type": r["access_type"],
                "detail": f"{window_minutes}分钟内 {r['access_user']} {r['access_type']} "
                          f"{r['data_type']} 达 {r['c']} 次",
            } for r in rows]
        finally:
            conn.close()

    def detect_data_leak(self, user: Optional[str] = None,
                         window_hours: int = 1) -> List[Dict[str, Any]]:
        """数据泄露检测：异常导出/下载/分享敏感数据。"""
        since = (datetime.now() - timedelta(hours=window_hours)).isoformat(timespec="seconds")
        where, params = [
            "access_time >= ?",
            "access_type IN ('export','download','share')",
            "data_type IN ('vulnerability','user','config')",
        ], [since]
        if user:
            where.append("access_user = ?"); params.append(user)
        conn = db._get_connection()
        try:
            rows = conn.execute(
                f"SELECT access_user, access_type, data_type, COUNT(*) AS c, "
                f"GROUP_CONCAT(DISTINCT data_id) AS ids "
                f"FROM audit_data_access WHERE {' AND '.join(where)} "
                f"GROUP BY access_user, access_type, data_type HAVING c >= ?",
                params + [LEAK_EXPORT_THRESHOLD]).fetchall()
            return [{
                "type": "possible_data_leak",
                "severity": "critical",
                "user": r["access_user"],
                "data_type": r["data_type"],
                "access_type": r["access_type"],
                "detail": f"疑似数据泄露：{r['access_user']} 在 {window_hours}h 内 "
                          f"{r['access_type']} 敏感数据 {r['c']} 条",
                "sample_ids": (r["ids"] or "").split(",")[:10],
            } for r in rows]
        finally:
            conn.close()

    def get_abnormal_access(self, window_hours: int = 1) -> List[Dict[str, Any]]:
        """汇总批量访问与数据泄露异常。"""
        try:
            return self.detect_batch_access() + self.detect_data_leak(window_hours=window_hours)
        except Exception as e:  # pragma: no cover
            log.error(f"异常数据访问检测失败: {e}")
            return []

    def alert_on_abnormal_access(self, user: Optional[str] = None) -> None:
        """对异常数据访问生成告警。"""
        for a in self.get_abnormal_access():
            if user and a.get("user") != user:
                continue
            _fire_alert(
                title=f"[审计] 异常数据访问: {a['type']}",
                message=a.get("detail", "异常数据访问行为"),
                severity=a.get("severity", "warning"),
                details=a,
            )

    # ==================== 统计与报告 ====================

    def get_access_stats(
        self,
        start_time: Optional[str] = None,
        end_time: Optional[str] = None,
    ) -> Dict[str, Any]:
        where, params = ["1=1"], []
        if start_time:
            where.append("access_time >= ?"); params.append(start_time)
        if end_time:
            where.append("access_time <= ?"); params.append(end_time)
        where_sql = " AND ".join(where)
        conn = db._get_connection()
        try:
            total = conn.execute(
                f"SELECT COUNT(*) AS c FROM audit_data_access WHERE {where_sql}", params).fetchone()["c"]
            by_user = [dict(r) for r in conn.execute(
                f"SELECT access_user AS name, COUNT(*) AS count FROM audit_data_access "
                f"WHERE {where_sql} GROUP BY access_user ORDER BY count DESC LIMIT 20", params).fetchall()]
            by_data_type = [dict(r) for r in conn.execute(
                f"SELECT data_type AS name, COUNT(*) AS count FROM audit_data_access "
                f"WHERE {where_sql} GROUP BY data_type", params).fetchall()]
            by_access_type = [dict(r) for r in conn.execute(
                f"SELECT access_type AS name, COUNT(*) AS count FROM audit_data_access "
                f"WHERE {where_sql} GROUP BY access_type", params).fetchall()]
            return {
                "total": total,
                "by_user": by_user,
                "by_data_type": by_data_type,
                "by_access_type": by_access_type,
            }
        finally:
            conn.close()

    def get_sensitive_access_report(self, limit: int = 200) -> List[Dict[str, Any]]:
        """敏感数据访问报告：谁在什么时间访问了什么敏感数据。"""
        conn = db._get_connection()
        try:
            rows = conn.execute(
                f"SELECT access_user, access_type, data_type, data_id, data_summary, "
                f"access_time, ip_address FROM audit_data_access "
                f"WHERE data_type IN ('vulnerability','user','config') "
                f"ORDER BY access_time DESC LIMIT ?", (limit,)).fetchall()
            return [dict(r) for r in rows]
        finally:
            conn.close()


_data_access_logger: Optional[DataAccessLogger] = None


def get_data_access_logger() -> DataAccessLogger:
    """获取全局数据访问日志器单例。"""
    global _data_access_logger
    if _data_access_logger is None:
        _data_access_logger = DataAccessLogger()
    return _data_access_logger
