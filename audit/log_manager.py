# -*- coding: utf-8 -*-
"""
log_manager.py - 日志管理器。

功能：
    - 跨日志类型全文搜索
    - 审计报表聚合
    - 历史日志归档（JSON 文件）与恢复
    - 按保留策略清理过期日志
    - 哈希链完整性总校验
    - 日志配置（保留天数、记录级别、批量大小）
    - 日志总览

数据库表：audit_log_config, audit_log_archives
"""

from __future__ import annotations

import json
import os
import sys
import uuid
from datetime import datetime, timedelta
from pathlib import Path
from typing import Any, Dict, List, Optional

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from utils.logger import log  # noqa: E402
from utils.database import db  # noqa: E402

# 归档文件存放目录
ARCHIVE_DIR = Path(__file__).parent.parent / "data" / "audit_archives"

DEFAULT_CONFIG = {
    "retention_days": "180",
    "record_level": "all",
    "batch_size": "500",
    "mask_sensitive": "true",
    "slow_threshold_ms": "1000",
}


def _now_iso() -> str:
    return datetime.now().isoformat(timespec="seconds")


class LogManager:
    """日志管理器（单例）。"""

    def __init__(self) -> None:
        ARCHIVE_DIR.mkdir(parents=True, exist_ok=True)
        self._init_table()
        self._ensure_config()

    def _init_table(self) -> None:
        conn = db._get_connection()
        try:
            conn.execute("""
                CREATE TABLE IF NOT EXISTS audit_log_config (
                    id TEXT PRIMARY KEY,
                    config_key TEXT UNIQUE NOT NULL,
                    config_value TEXT,
                    description TEXT,
                    updated_at TEXT
                )
            """)
            conn.execute("""
                CREATE TABLE IF NOT EXISTS audit_log_archives (
                    id TEXT PRIMARY KEY,
                    archive_name TEXT UNIQUE NOT NULL,
                    log_type TEXT NOT NULL,
                    date_range TEXT,
                    file_path TEXT NOT NULL,
                    record_count INTEGER DEFAULT 0,
                    archived_at TEXT,
                    created_at TEXT
                )
            """)
            conn.commit()
        except Exception as e:  # pragma: no cover
            log.error(f"日志管理器建表失败: {e}")
        finally:
            conn.close()

    def _ensure_config(self) -> None:
        """写入默认配置项。"""
        descs = {
            "retention_days": "日志保留天数，超过将被清理",
            "record_level": "API 日志记录级别：all/errors_only/slow_only/off",
            "batch_size": "批量写入大小",
            "mask_sensitive": "是否对敏感数据脱敏 true/false",
            "slow_threshold_ms": "慢请求阈值（毫秒）",
        }
        conn = db._get_connection()
        try:
            for k, v in DEFAULT_CONFIG.items():
                conn.execute(
                    "INSERT OR IGNORE INTO audit_log_config "
                    "(id, config_key, config_value, description, updated_at) "
                    "VALUES (?,?,?,?,?)",
                    (str(uuid.uuid4()), k, v, descs.get(k, ""), _now_iso()))
            conn.commit()
        except Exception as e:  # pragma: no cover
            log.error(f"初始化日志配置失败: {e}")
        finally:
            conn.close()

    # ==================== 配置 ====================

    def get_log_config(self) -> Dict[str, Any]:
        conn = db._get_connection()
        try:
            rows = conn.execute(
                "SELECT config_key, config_value, description FROM audit_log_config").fetchall()
            return {r["config_key"]: {"value": r["config_value"], "description": r["description"]}
                    for r in rows}
        finally:
            conn.close()

    def update_log_config(self, updates: Dict[str, str]) -> Dict[str, Any]:
        if not updates:
            return {"success": False, "error": "无更新项"}
        conn = db._get_connection()
        applied = []
        try:
            for k, v in updates.items():
                cur = conn.execute(
                    "SELECT id FROM audit_log_config WHERE config_key = ?", (k,)).fetchone()
                if cur:
                    conn.execute(
                        "UPDATE audit_log_config SET config_value=?, updated_at=? WHERE config_key=?",
                        (str(v), _now_iso(), k))
                else:
                    conn.execute(
                        "INSERT INTO audit_log_config (id, config_key, config_value, updated_at) "
                        "VALUES (?,?,?,?)",
                        (str(uuid.uuid4()), k, str(v), _now_iso()))
                applied.append(k)
            conn.commit()
            return {"success": True, "updated": applied}
        except Exception as e:  # pragma: no cover
            return {"success": False, "error": str(e)}
        finally:
            conn.close()

    # ==================== 跨表搜索 ====================

    def search_all_logs(
        self,
        keyword: str = "",
        time_range: Optional[str] = None,
        user: Optional[str] = None,
        ip: Optional[str] = None,
        limit: int = 50,
    ) -> Dict[str, Any]:
        """跨操作/登录/API/数据访问日志的关联搜索。"""
        result: Dict[str, Any] = {}
        if keyword:
            like = f"%{keyword}%"
            conn = db._get_connection()
            try:
                # 操作日志
                result["operations"] = [dict(r) for r in conn.execute(
                    "SELECT id, operator, operation_type, operation_object, operation_time "
                    "FROM audit_operations WHERE operator LIKE ? OR operation_detail LIKE ? "
                    "ORDER BY operation_time DESC LIMIT ?",
                    [like, like, limit]).fetchall()]
                # 登录日志
                result["logins"] = [dict(r) for r in conn.execute(
                    "SELECT id, username, login_ip, login_time, result FROM audit_logins "
                    "WHERE username LIKE ? OR login_ip LIKE ? "
                    "ORDER BY login_time DESC LIMIT ?", [like, like, limit]).fetchall()]
            except Exception as e:  # pragma: no cover
                log.warning(f"跨表搜索失败: {e}")
            finally:
                conn.close()

        # API 与数据访问日志按 user/ip 过滤（不依赖 keyword）
        try:
            from audit.api_log import get_api_logger
            st = et = None
            if time_range == "today":
                st = datetime.now().strftime("%Y-%m-%d") + "T00:00:00"
            elif time_range == "week":
                st = (datetime.now() - timedelta(days=7)).isoformat(timespec="seconds")
            res = get_api_logger().list_api_calls(
                request_ip=ip, start_time=st, end_time=et, page=1, page_size=limit)
            result["api_calls"] = res.get("items", [])
        except Exception:
            result["api_calls"] = []
        try:
            from audit.data_access_log import get_data_access_logger
            result["data_access"] = get_data_access_logger().list_data_access(
                access_user=user, ip_address=ip, page=1, page_size=limit).get("items", [])
        except Exception:
            result["data_access"] = []
        return result

    # ==================== 报表与总览 ====================

    def get_audit_report(self) -> Dict[str, Any]:
        """聚合四类日志 + 异常行为统计。"""
        report: Dict[str, Any] = {"generated_at": _now_iso()}
        try:
            from audit.operation_log import get_operation_logger
            report["operations"] = get_operation_logger().get_operation_stats()
        except Exception as e:
            report["operations"] = {"error": str(e)}
        try:
            from audit.login_log import get_login_logger
            report["logins"] = get_login_logger().get_login_stats()
        except Exception as e:
            report["logins"] = {"error": str(e)}
        try:
            from audit.api_log import get_api_logger
            report["api"] = get_api_logger().get_api_stats()
            report["api_performance"] = get_api_logger().get_performance_monitor()
        except Exception as e:
            report["api"] = {"error": str(e)}
        try:
            from audit.data_access_log import get_data_access_logger
            report["data_access"] = get_data_access_logger().get_access_stats()
        except Exception as e:
            report["data_access"] = {"error": str(e)}
        # 异常行为汇总
        abnormal: List[Dict[str, Any]] = []
        try:
            from audit.login_log import get_login_logger
            abnormal += [{"source": "login", **a} for a in get_login_logger().get_abnormal_logins()]
        except Exception:
            pass
        try:
            from audit.api_log import get_api_logger
            abnormal += [{"source": "api", **a} for a in get_api_logger().detect_anomalies()]
        except Exception:
            pass
        try:
            from audit.data_access_log import get_data_access_logger
            abnormal += [{"source": "data_access", **a} for a in get_data_access_logger().get_abnormal_access()]
        except Exception:
            pass
        report["abnormal_behaviors"] = abnormal
        report["abnormal_count"] = len(abnormal)
        return report

    def get_log_overview(self) -> Dict[str, Any]:
        """日志总览：总量/今日新增/异常数/完整性状态。"""
        conn = db._get_connection()
        today = datetime.now().strftime("%Y-%m-%d")
        try:
            def _count(table: str, time_col: str) -> Dict[str, int]:
                total = conn.execute(f"SELECT COUNT(*) AS c FROM {table}").fetchone()["c"]
                today_n = conn.execute(
                    f"SELECT COUNT(*) AS c FROM {table} WHERE {time_col} LIKE ?",
                    [today + "%"]).fetchone()["c"]
                return {"total": total, "today": today_n}

            overview = {
                "operations": _count("audit_operations", "operation_time"),
                "logins": _count("audit_logins", "login_time"),
                "api_calls": _count("audit_api_calls", "call_time"),
                "data_access": _count("audit_data_access", "access_time"),
            }
        finally:
            conn.close()

        # 异常数量
        abnormal = 0
        try:
            from audit.login_log import get_login_logger
            abnormal += len(get_login_logger().get_abnormal_logins())
        except Exception:
            pass
        try:
            from audit.api_log import get_api_logger
            abnormal += len(get_api_logger().detect_anomalies())
        except Exception:
            pass
        try:
            from audit.data_access_log import get_data_access_logger
            abnormal += len(get_data_access_logger().get_abnormal_access())
        except Exception:
            pass
        overview["abnormal_count"] = abnormal

        # 完整性状态
        try:
            overview["integrity"] = self.verify_all_integrity()
        except Exception as e:
            overview["integrity"] = {"intact": False, "error": str(e)}
        return overview

    # ==================== 归档与清理 ====================

    def archive_logs(self, log_type: str, days_ago: int = 30) -> Dict[str, Any]:
        """将 N 天前的历史日志归档为 JSON 文件，并从库中删除。

        Args:
            log_type: operations / logins / api_calls / data_access
            days_ago: 归档该天数之前的数据
        """
        cutoff = (datetime.now() - timedelta(days=days_ago)).isoformat(timespec="seconds")
        table_map = {
            "operations": ("audit_operations", "operation_time"),
            "logins": ("audit_logins", "login_time"),
            "api_calls": ("audit_api_calls", "call_time"),
            "data_access": ("audit_data_access", "access_time"),
        }
        if log_type not in table_map:
            return {"success": False, "error": f"未知日志类型: {log_type}"}
        table, tcol = table_map[log_type]
        archive_id = str(uuid.uuid4())
        archive_name = f"{log_type}_{datetime.now().strftime('%Y%m%d_%H%M%S')}_{archive_id[:8]}"
        file_path = ARCHIVE_DIR / f"{archive_name}.json"

        conn = db._get_connection()
        try:
            rows = conn.execute(
                f"SELECT * FROM {table} WHERE {tcol} < ?", (cutoff,)).fetchall()
            items = [dict(r) for r in rows]
            with open(file_path, "w", encoding="utf-8") as f:
                json.dump({
                    "archive_name": archive_name,
                    "log_type": log_type,
                    "cutoff": cutoff,
                    "archived_at": _now_iso(),
                    "count": len(items),
                    "items": items,
                }, f, ensure_ascii=False, indent=2)
            # 从库中删除已归档数据
            cur = conn.execute(f"DELETE FROM {table} WHERE {tcol} < ?", (cutoff,))
            conn.execute("""
                INSERT INTO audit_log_archives
                    (id, archive_name, log_type, date_range, file_path,
                     record_count, archived_at, created_at)
                VALUES (?,?,?,?,?,?,?,?)
            """, (archive_id, archive_name, log_type,
                  f"< {cutoff}", str(file_path), len(items),
                  _now_iso(), _now_iso()))
            conn.commit()
            return {
                "success": True, "archive_name": archive_name,
                "record_count": len(items), "deleted": cur.rowcount,
                "file_path": str(file_path),
            }
        except Exception as e:  # pragma: no cover
            log.error(f"归档日志失败: {e}")
            return {"success": False, "error": str(e)}
        finally:
            conn.close()

    def list_archives(self) -> List[Dict[str, Any]]:
        conn = db._get_connection()
        try:
            rows = conn.execute(
                "SELECT * FROM audit_log_archives ORDER BY archived_at DESC").fetchall()
            return [dict(r) for r in rows]
        finally:
            conn.close()

    def restore_archive(self, archive_name: str) -> Dict[str, Any]:
        """从归档文件恢复日志到原表。"""
        conn = db._get_connection()
        try:
            row = conn.execute(
                "SELECT * FROM audit_log_archives WHERE archive_name = ?",
                (archive_name,)).fetchone()
            if not row:
                return {"success": False, "error": "归档不存在"}
            file_path = row["file_path"]
            if not os.path.exists(file_path):
                return {"success": False, "error": "归档文件丢失"}
            with open(file_path, "r", encoding="utf-8") as f:
                data = json.load(f)
            items = data.get("items", [])
            log_type = data.get("log_type")
            table_map = {
                "operations": "audit_operations",
                "logins": "audit_logins",
                "api_calls": "audit_api_calls",
                "data_access": "audit_data_access",
            }
            table = table_map.get(log_type)
            if not table or not items:
                return {"success": False, "error": "归档内容无效"}
            restored = 0
            for it in items:
                cols = list(it.keys())
                placeholders = ",".join(["?"] * len(cols))
                try:
                    conn.execute(
                        f"INSERT OR IGNORE INTO {table} ({','.join(cols)}) VALUES ({placeholders})",
                        [it[c] for c in cols])
                    restored += 1
                except Exception:
                    continue
            conn.commit()
            return {"success": True, "restored": restored, "archive_name": archive_name}
        except Exception as e:  # pragma: no cover
            return {"success": False, "error": str(e)}
        finally:
            conn.close()

    def clean_expired_logs(self) -> Dict[str, Any]:
        """按保留策略清理过期日志，返回清理数量。"""
        cfg = self.get_log_config()
        try:
            retention = int(cfg.get("retention_days", {}).get("value", "180"))
        except Exception:
            retention = 180
        cutoff = (datetime.now() - timedelta(days=retention)).isoformat(timespec="seconds")
        targets = [
            ("audit_operations", "operation_time"),
            ("audit_logins", "login_time"),
            ("audit_api_calls", "call_time"),
            ("audit_data_access", "access_time"),
        ]
        cleaned: Dict[str, int] = {}
        conn = db._get_connection()
        try:
            for table, tcol in targets:
                try:
                    cur = conn.execute(f"DELETE FROM {table} WHERE {tcol} < ?", (cutoff,))
                    cleaned[table] = cur.rowcount
                except Exception:
                    cleaned[table] = 0
            conn.commit()
            return {"success": True, "retention_days": retention,
                    "cutoff": cutoff, "cleaned": cleaned,
                    "total_cleaned": sum(cleaned.values())}
        except Exception as e:  # pragma: no cover
            return {"success": False, "error": str(e)}
        finally:
            conn.close()

    # ==================== 完整性总校验 ====================

    def verify_all_integrity(self) -> Dict[str, Any]:
        """验证所有日志类型的哈希链完整性（当前仅操作日志带哈希链）。"""
        result: Dict[str, Any] = {"checked_at": _now_iso(), "types": {}}
        try:
            from audit.operation_log import get_operation_logger
            op = get_operation_logger().verify_integrity()
            result["types"]["operations"] = op
            result["intact"] = bool(op.get("intact"))
            result["tampered"] = bool(op.get("tampered"))
        except Exception as e:
            result["types"]["operations"] = {"intact": False, "error": str(e)}
            result["intact"] = False
            result["tampered"] = False
        # 其余类型无哈希链，仅返回记录数
        conn = db._get_connection()
        try:
            for t in ("audit_logins", "audit_api_calls", "audit_data_access"):
                n = conn.execute(f"SELECT COUNT(*) AS c FROM {t}").fetchone()["c"]
                result["types"][t] = {"record_count": n, "note": "无哈希链"}
        finally:
            conn.close()
        return result


_log_manager: Optional[LogManager] = None


def get_log_manager() -> LogManager:
    """获取全局日志管理器单例。"""
    global _log_manager
    if _log_manager is None:
        _log_manager = LogManager()
    return _log_manager
