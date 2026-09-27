# -*- coding: utf-8 -*-
"""
login_log.py - 登录日志与会话审计模块。

功能：
    - 记录登录/登出事件（成功/失败、失败原因、登录方式、地点、UA）
    - 维护会话生命周期（创建、活跃、过期、撤销）
    - 异常登录检测：异地登录、异常时间、多次失败、新设备、暴力破解
    - 异常时自动生成告警

数据库表：audit_logins, audit_sessions
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

# 合法失败原因
VALID_FAILURE_REASONS = {
    "password_error", "user_not_found", "account_locked", "2fa_failure",
}
# 合法登录方式
VALID_LOGIN_METHODS = {"password", "sso", "api_key", "2fa"}

# 异常检测阈值
BRUTE_FORCE_THRESHOLD = 5          # 同用户名短时失败次数阈值
BRUTE_FORCE_WINDOW_MINUTES = 10    # 暴力破解检测时间窗
ABNORMAL_HOURS = (0, 5)            # 异常时间段（凌晨0-5点）


def _now_iso() -> str:
    """当前时间 ISO 字符串。"""
    return datetime.now().isoformat(timespec="seconds")


def _fire_alert(title: str, message: str, severity: str = "warning",
               details: Optional[Dict[str, Any]] = None) -> None:
    """调用全局告警管理器生成告警（失败不影响主流程）。"""
    try:
        from tools.alert_manager import alert_manager  # 延迟导入
        alert_manager.create_alert(
            title=title, message=message, severity=severity,
            category="security", target=details.get("username") if details else None,
            details=details or {}, auto_notify=True,
        )
    except Exception as e:  # pragma: no cover
        log.warning(f"登录告警写入失败（已降级为日志记录）: {e}")


class LoginLogger:
    """登录日志与会话管理器（单例）。"""

    def __init__(self) -> None:
        """初始化并建表。"""
        self._init_table()

    def _init_table(self) -> None:
        """创建登录日志表与会话表及索引。"""
        conn = db._get_connection()
        try:
            conn.execute("""
                CREATE TABLE IF NOT EXISTS audit_logins (
                    id TEXT PRIMARY KEY,
                    username TEXT NOT NULL,
                    login_time TEXT NOT NULL,
                    login_ip TEXT,
                    login_location TEXT,
                    user_agent TEXT,
                    result TEXT NOT NULL,
                    failure_reason TEXT,
                    session_id TEXT,
                    login_method TEXT,
                    logout_time TEXT,
                    tenant_id TEXT
                )
            """)
            conn.execute("""
                CREATE TABLE IF NOT EXISTS audit_sessions (
                    id TEXT PRIMARY KEY,
                    session_id TEXT UNIQUE NOT NULL,
                    username TEXT NOT NULL,
                    login_ip TEXT,
                    login_time TEXT,
                    last_active_time TEXT,
                    status TEXT DEFAULT 'active',
                    user_agent TEXT,
                    tenant_id TEXT
                )
            """)
            conn.execute("CREATE INDEX IF NOT EXISTS idx_logins_user ON audit_logins(username)")
            conn.execute("CREATE INDEX IF NOT EXISTS idx_logins_ip ON audit_logins(login_ip)")
            conn.execute("CREATE INDEX IF NOT EXISTS idx_logins_result ON audit_logins(result)")
            conn.execute("CREATE INDEX IF NOT EXISTS idx_logins_time ON audit_logins(login_time)")
            conn.execute("CREATE INDEX IF NOT EXISTS idx_logins_sid ON audit_logins(session_id)")
            conn.execute("CREATE INDEX IF NOT EXISTS idx_sessions_user ON audit_sessions(username)")
            conn.execute("CREATE INDEX IF NOT EXISTS idx_sessions_status ON audit_sessions(status)")
            conn.execute("CREATE INDEX IF NOT EXISTS idx_sessions_sid ON audit_sessions(session_id)")
            conn.commit()
        except Exception as e:  # pragma: no cover
            log.error(f"登录审计建表失败: {e}")
        finally:
            conn.close()

    # ==================== 写入 ====================

    def log_login(
        self,
        username: str,
        result: str = "success",
        login_ip: str = "",
        login_location: str = "",
        user_agent: str = "",
        failure_reason: str = "",
        login_method: str = "password",
        session_id: str = "",
        tenant_id: str = "",
        auto_detect: bool = True,
    ) -> str:
        """记录一次登录事件。

        Returns:
            登录日志 id。
        """
        if login_method not in VALID_LOGIN_METHODS:
            login_method = "password"
        if failure_reason and failure_reason not in VALID_FAILURE_REASONS:
            failure_reason = "password_error" if result == "failure" else ""
        log_id = str(uuid.uuid4())
        login_time = _now_iso()
        conn = db._get_connection()
        try:
            conn.execute("""
                INSERT INTO audit_logins
                    (id, username, login_time, login_ip, login_location, user_agent,
                     result, failure_reason, session_id, login_method, tenant_id)
                VALUES (?,?,?,?,?,?,?,?,?,?,?)
            """, (log_id, username, login_time, login_ip, login_location, user_agent,
                  result, failure_reason, session_id, login_method, tenant_id))
            conn.commit()
        except Exception as e:  # pragma: no cover
            log.error(f"写入登录日志失败: {e}")
        finally:
            conn.close()

        # 异步式异常检测（同步执行，量小）
        if auto_detect and result == "failure":
            try:
                self.alert_on_abnormal(username=username, login_ip=login_ip,
                                       user_agent=user_agent, login_time=login_time)
            except Exception:  # pragma: no cover
                pass
        return log_id

    def log_logout(self, session_id: str, username: str = "") -> bool:
        """记录登出：补写登出时间并将会话置为 expired。"""
        logout_time = _now_iso()
        conn = db._get_connection()
        try:
            conn.execute(
                "UPDATE audit_logins SET logout_time = ? WHERE session_id = ?",
                (logout_time, session_id))
            conn.execute(
                "UPDATE audit_sessions SET status = 'expired', last_active_time = ? "
                "WHERE session_id = ? AND status = 'active'",
                (logout_time, session_id))
            conn.commit()
            return True
        except Exception as e:  # pragma: no cover
            log.error(f"记录登出失败: {e}")
            return False
        finally:
            conn.close()

    def create_session(
        self,
        session_id: str,
        username: str,
        login_ip: str = "",
        user_agent: str = "",
        tenant_id: str = "",
    ) -> str:
        """创建会话记录。"""
        sid = session_id or str(uuid.uuid4())
        now = _now_iso()
        conn = db._get_connection()
        try:
            conn.execute("""
                INSERT OR REPLACE INTO audit_sessions
                    (id, session_id, username, login_ip, login_time,
                     last_active_time, status, user_agent, tenant_id)
                VALUES (?,?,?,?,?,?,?,?,?)
            """, (str(uuid.uuid4()), sid, username, login_ip, now, now,
                  "active", user_agent, tenant_id))
            conn.commit()
        except Exception as e:  # pragma: no cover
            log.error(f"创建会话记录失败: {e}")
        finally:
            conn.close()
        return sid

    # ==================== 查询 ====================

    @staticmethod
    def _row(row) -> Dict[str, Any]:
        return dict(row) if row else {}

    def get_login(self, login_id: str) -> Optional[Dict[str, Any]]:
        """获取单条登录日志。"""
        conn = db._get_connection()
        try:
            row = conn.execute("SELECT * FROM audit_logins WHERE id = ?", (login_id,)).fetchone()
            return self._row(row) if row else None
        finally:
            conn.close()

    def list_logins(
        self,
        username: Optional[str] = None,
        login_ip: Optional[str] = None,
        result: Optional[str] = None,
        login_method: Optional[str] = None,
        start_time: Optional[str] = None,
        end_time: Optional[str] = None,
        page: int = 1,
        page_size: int = 20,
    ) -> Dict[str, Any]:
        """多条件查询登录日志。"""
        where, params = ["1=1"], []
        if username:
            where.append("username LIKE ?"); params.append(f"%{username}%")
        if login_ip:
            where.append("login_ip = ?"); params.append(login_ip)
        if result:
            where.append("result = ?"); params.append(result)
        if login_method:
            where.append("login_method = ?"); params.append(login_method)
        if start_time:
            where.append("login_time >= ?"); params.append(start_time)
        if end_time:
            where.append("login_time <= ?"); params.append(end_time)
        where_sql = " AND ".join(where)
        page = max(1, int(page)); page_size = max(1, min(500, int(page_size)))
        offset = (page - 1) * page_size
        conn = db._get_connection()
        try:
            total = conn.execute(
                f"SELECT COUNT(*) AS c FROM audit_logins WHERE {where_sql}", params).fetchone()["c"]
            rows = conn.execute(
                f"SELECT * FROM audit_logins WHERE {where_sql} "
                f"ORDER BY login_time DESC LIMIT ? OFFSET ?",
                params + [page_size, offset]).fetchall()
            return {"total": total, "page": page, "page_size": page_size,
                    "items": [dict(r) for r in rows]}
        finally:
            conn.close()

    def list_active_sessions(self, username: Optional[str] = None) -> List[Dict[str, Any]]:
        """活跃会话列表（status=active）。"""
        where, params = ["status = 'active'"], []
        if username:
            where.append("username = ?"); params.append(username)
        conn = db._get_connection()
        try:
            rows = conn.execute(
                f"SELECT * FROM audit_sessions WHERE {' AND '.join(where)} "
                f"ORDER BY last_active_time DESC", params).fetchall()
            return [dict(r) for r in rows]
        finally:
            conn.close()

    def get_session(self, session_id: str) -> Optional[Dict[str, Any]]:
        """会话详情。"""
        conn = db._get_connection()
        try:
            row = conn.execute(
                "SELECT * FROM audit_sessions WHERE session_id = ?", (session_id,)).fetchone()
            return dict(row) if row else None
        finally:
            conn.close()

    def revoke_session(self, session_id: str, operator: str = "admin") -> bool:
        """强制登出：将会话状态置为 revoked。"""
        conn = db._get_connection()
        try:
            cur = conn.execute(
                "UPDATE audit_sessions SET status = 'revoked' WHERE session_id = ? AND status = 'active'",
                (session_id,))
            conn.commit()
            self._record_system_event(
                operator=operator, action="revoke_session",
                detail=f"强制撤销会话 {session_id}")
            return cur.rowcount > 0
        except Exception as e:  # pragma: no cover
            log.error(f"撤销会话失败: {e}")
            return False
        finally:
            conn.close()

    # ==================== 异常检测 ====================

    def detect_abnormal_logins(
        self,
        username: Optional[str] = None,
        window_hours: int = 24,
    ) -> List[Dict[str, Any]]:
        """异常登录检测，返回异常事件列表。"""
        anomalies: List[Dict[str, Any]] = []
        since = (datetime.now() - timedelta(hours=window_hours)).isoformat(timespec="seconds")
        conn = db._get_connection()
        try:
            # 1) 暴力破解：同用户在时间窗内失败次数超阈值
            brute_window = (datetime.now() - timedelta(minutes=BRUTE_FORCE_WINDOW_MINUTES)).isoformat(timespec="seconds")
            where = "result = 'failure' AND login_time >= ?"
            params: List[Any] = [brute_window]
            if username:
                where += " AND username = ?"; params.append(username)
            rows = conn.execute(
                f"SELECT username, login_ip, COUNT(*) AS fail_count FROM audit_logins "
                f"WHERE {where} GROUP BY username, login_ip HAVING fail_count >= ?",
                params + [BRUTE_FORCE_THRESHOLD]).fetchall()
            for r in rows:
                anomalies.append({
                    "type": "brute_force",
                    "severity": "critical",
                    "username": r["username"],
                    "ip": r["login_ip"],
                    "detail": f"{BRUTE_FORCE_WINDOW_MINUTES}分钟内失败 {r['fail_count']} 次",
                })

            # 2) 异常时间登录（凌晨时段）
            rows = conn.execute(
                "SELECT * FROM audit_logins WHERE result='success' AND login_time >= ? "
                "AND CAST(substr(login_time,12,2) AS INTEGER) BETWEEN ? AND ? "
                "ORDER BY login_time DESC LIMIT 200",
                [since, ABNORMAL_HOURS[0], ABNORMAL_HOURS[1]]).fetchall()
            for r in rows:
                d = dict(r)
                u = username or d["username"]
                if username and d["username"] != username:
                    continue
                anomalies.append({
                    "type": "off_hours",
                    "severity": "warning",
                    "username": d["username"],
                    "ip": d["login_ip"],
                    "detail": f"异常时间段登录 {d['login_time']}",
                })

            # 3) 异地登录：同用户近期成功登录 IP 集合发生变化
            rows = conn.execute(
                "SELECT username, login_ip, login_location, login_time, user_agent "
                "FROM audit_logins WHERE result='success' AND login_time >= ? "
                "ORDER BY login_time DESC", [since]).fetchall()
            seen_ips: Dict[str, set] = {}
            for r in rows:
                d = dict(r)
                seen_ips.setdefault(d["username"], set()).add(d["login_ip"])
            for r in rows:
                d = dict(r)
                if username and d["username"] != username:
                    continue
                # 若该用户在窗口内出现过 2 个及以上不同 IP，则标注最近一次为异地
                if len(seen_ips.get(d["username"], set())) >= 2:
                    anomalies.append({
                        "type": "remote_login",
                        "severity": "high",
                        "username": d["username"],
                        "ip": d["login_ip"],
                        "detail": f"检测到异地登录 IP={d['login_ip']} 地点={d['login_location'] or '未知'}",
                    })

            # 4) 新设备登录：UA 首次出现
            rows = conn.execute(
                "SELECT a.* FROM audit_logins a WHERE a.result='success' AND a.login_time >= ? "
                "AND NOT EXISTS ("
                "  SELECT 1 FROM audit_logins b WHERE b.username=a.username "
                "  AND b.user_agent=a.user_agent AND b.login_time < a.login_time "
                "  AND b.result='success')", [since]).fetchall()
            for r in rows:
                d = dict(r)
                if username and d["username"] != username:
                    continue
                anomalies.append({
                    "type": "new_device",
                    "severity": "warning",
                    "username": d["username"],
                    "ip": d["login_ip"],
                    "detail": f"新设备登录，UA={d['user_agent'][:80] if d['user_agent'] else '未知'}",
                })
        finally:
            conn.close()
        return anomalies

    def get_abnormal_logins(self, window_hours: int = 24) -> List[Dict[str, Any]]:
        """对外暴露的异常登录列表。"""
        try:
            return self.detect_abnormal_logins(window_hours=window_hours)
        except Exception as e:  # pragma: no cover
            log.error(f"异常登录检测失败: {e}")
            return []

    def alert_on_abnormal(
        self,
        username: str = "",
        login_ip: str = "",
        user_agent: str = "",
        login_time: str = "",
    ) -> None:
        """触发一次异常评估并对命中项生成告警。"""
        anomalies = self.detect_abnormal_logins(username=username or None)
        # 仅告警与本次相关的项，避免历史重复告警
        if username:
            anomalies = [a for a in anomalies if a.get("username") == username]
        for a in anomalies[:5]:  # 单次最多 5 条
            _fire_alert(
                title=f"[审计] 异常登录: {a['type']}",
                message=f"用户 {a.get('username')} 触发异常登录（{a['detail']}）",
                severity=a.get("severity", "warning"),
                details=a,
            )

    # ==================== 统计 ====================

    def get_login_stats(
        self,
        start_time: Optional[str] = None,
        end_time: Optional[str] = None,
    ) -> Dict[str, Any]:
        """登录统计：次数、成功率、失败原因、按用户/IP/天分布。"""
        where, params = ["1=1"], []
        if start_time:
            where.append("login_time >= ?"); params.append(start_time)
        if end_time:
            where.append("login_time <= ?"); params.append(end_time)
        where_sql = " AND ".join(where)
        conn = db._get_connection()
        try:
            total = conn.execute(
                f"SELECT COUNT(*) AS c FROM audit_logins WHERE {where_sql}", params).fetchone()["c"]
            success = conn.execute(
                f"SELECT COUNT(*) AS c FROM audit_logins WHERE {where_sql} AND result='success'",
                params).fetchone()["c"]
            fail = total - success
            fail_reasons = [dict(r) for r in conn.execute(
                f"SELECT failure_reason AS name, COUNT(*) AS count FROM audit_logins "
                f"WHERE {where_sql} AND result='failure' AND failure_reason <> '' "
                f"GROUP BY failure_reason", params).fetchall()]
            by_user = [dict(r) for r in conn.execute(
                f"SELECT username AS name, COUNT(*) AS count FROM audit_logins "
                f"WHERE {where_sql} GROUP BY username ORDER BY count DESC LIMIT 20", params).fetchall()]
            by_ip = [dict(r) for r in conn.execute(
                f"SELECT login_ip AS name, COUNT(*) AS count FROM audit_logins "
                f"WHERE {where_sql} AND login_ip <> '' GROUP BY login_ip "
                f"ORDER BY count DESC LIMIT 20", params).fetchall()]
            by_day = [dict(r) for r in conn.execute(
                f"SELECT substr(login_time,1,10) AS date, "
                f"SUM(CASE WHEN result='success' THEN 1 ELSE 0 END) AS success, "
                f"SUM(CASE WHEN result='failure' THEN 1 ELSE 0 END) AS failure "
                f"FROM audit_logins WHERE {where_sql} GROUP BY date "
                f"ORDER BY date DESC LIMIT 30", params).fetchall()]
            abnormal = len(self.detect_abnormal_logins())
            return {
                "total": total,
                "success": success,
                "failure": fail,
                "success_rate": round(success / total * 100, 2) if total else 0.0,
                "abnormal_count": abnormal,
                "by_failure_reason": fail_reasons,
                "by_user": by_user,
                "by_ip": by_ip,
                "by_day": by_day,
            }
        finally:
            conn.close()

    # ==================== 内部工具 ====================

    @staticmethod
    def _record_system_event(operator: str, action: str, detail: str) -> None:
        """把本模块自身动作写入操作审计日志（失败静默）。"""
        try:
            from audit.operation_log import get_operation_logger
            get_operation_logger().log_operation(
                operator=operator, operation_type="execute",
                operation_object="audit_session",
                operation_detail={"action": action, "message": detail},
                result="success",
            )
        except Exception:
            pass


_login_logger: Optional[LoginLogger] = None


def get_login_logger() -> LoginLogger:
    """获取全局登录日志器单例。"""
    global _login_logger
    if _login_logger is None:
        _login_logger = LoginLogger()
    return _login_logger
