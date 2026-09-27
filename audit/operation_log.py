# -*- coding: utf-8 -*-
"""
operation_log.py - 操作审计日志模块。

功能：
    - 记录用户/系统的关键操作（增删改查、登录登出、配置变更等）
    - 基于 SHA256 哈希链防止日志被篡改：每条日志保存 prev_hash 与自身 hash
    - 支持批量写入、全文搜索、多维度统计、CSV/JSON 导出
    - 支持哈希链完整性校验，定位篡改位置

数据库表：audit_operations
"""

from __future__ import annotations

import csv
import hashlib
import io
import json
import os
import sys
import uuid
from datetime import datetime, timedelta
from typing import Any, Dict, List, Optional

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from utils.logger import log  # noqa: E402
from utils.database import db  # noqa: E402

# 合法操作类型白名单
VALID_OPERATION_TYPES = {
    "create", "read", "update", "delete", "execute",
    "export", "import", "login", "logout", "config_change",
}

# 默认日志保留天数
DEFAULT_RETENTION_DAYS = 180


def _now_iso() -> str:
    """返回当前时间的 ISO 格式字符串（本地时间）。"""
    return datetime.now().isoformat(timespec="seconds")


def _compute_hash(prev_hash: str, payload: str) -> str:
    """计算单条日志哈希：SHA256(prev_hash + 规范化内容)。"""
    return hashlib.sha256(f"{prev_hash}|{payload}".encode("utf-8")).hexdigest()


class OperationLogger:
    """操作审计日志记录器（单例）。"""

    def __init__(self, retention_days: int = DEFAULT_RETENTION_DAYS):
        """初始化记录器并建表。

        Args:
            retention_days: 日志保留天数，超过则可被清理。
        """
        self.retention_days = retention_days
        self._init_table()

    # ==================== 表结构 ====================

    def _init_table(self) -> None:
        """创建 audit_operations 表及索引（幂等）。"""
        conn = db._get_connection()
        try:
            conn.execute("""
                CREATE TABLE IF NOT EXISTS audit_operations (
                    id TEXT PRIMARY KEY,
                    operator TEXT NOT NULL,
                    operation_type TEXT NOT NULL,
                    operation_object TEXT,
                    object_id TEXT,
                    operation_detail TEXT,
                    ip_address TEXT,
                    user_agent TEXT,
                    operation_time TEXT NOT NULL,
                    result TEXT DEFAULT 'success',
                    failure_reason TEXT,
                    tenant_id TEXT,
                    prev_hash TEXT,
                    hash TEXT NOT NULL
                )
            """)
            # 常用查询索引
            conn.execute("CREATE INDEX IF NOT EXISTS idx_audit_ops_operator ON audit_operations(operator)")
            conn.execute("CREATE INDEX IF NOT EXISTS idx_audit_ops_type ON audit_operations(operation_type)")
            conn.execute("CREATE INDEX IF NOT EXISTS idx_audit_ops_time ON audit_operations(operation_time)")
            conn.execute("CREATE INDEX IF NOT EXISTS idx_audit_ops_result ON audit_operations(result)")
            conn.execute("CREATE INDEX IF NOT EXISTS idx_audit_ops_ip ON audit_operations(ip_address)")
            conn.execute("CREATE INDEX IF NOT EXISTS idx_audit_ops_obj ON audit_operations(operation_object)")
            conn.commit()
        except Exception as e:  # pragma: no cover
            log.error(f"audit_operations 建表失败: {e}")
        finally:
            conn.close()

    # ==================== 哈希链核心 ====================

    def _last_hash(self, conn) -> str:
        """获取链尾最后一条日志的哈希。"""
        row = conn.execute(
            "SELECT hash FROM audit_operations ORDER BY operation_time DESC, rowid DESC LIMIT 1"
        ).fetchone()
        return row["hash"] if row else "GENESIS"

    def _build_payload(self, record: Dict[str, Any]) -> str:
        """构造参与哈希计算的规范化内容串（不含 hash/prev_hash 字段）。"""
        detail = record.get("operation_detail") or {}
        if isinstance(detail, dict):
            detail_str = json.dumps(detail, ensure_ascii=False, sort_keys=True)
        else:
            detail_str = str(detail)
        parts = [
            record.get("operator", ""),
            record.get("operation_type", ""),
            record.get("operation_object", ""),
            str(record.get("object_id", "")),
            detail_str,
            record.get("ip_address", ""),
            record.get("operation_time", ""),
            record.get("result", ""),
            record.get("tenant_id", "") or "",
        ]
        return "|".join(parts)

    # ==================== 写入 ====================

    def log_operation(
        self,
        operator: str,
        operation_type: str,
        operation_object: str = "",
        object_id: str = "",
        operation_detail: Optional[Dict[str, Any]] = None,
        ip_address: str = "",
        user_agent: str = "",
        result: str = "success",
        failure_reason: str = "",
        tenant_id: str = "",
        operation_time: Optional[str] = None,
    ) -> Optional[str]:
        """记录单条操作日志，自动维护哈希链。

        Returns:
            写入日志的 id；失败返回 None。
        """
        if operation_type not in VALID_OPERATION_TYPES:
            # 宽容处理：未知类型降级为 execute，但不阻断业务
            operation_type = "execute"
        record = {
            "id": str(uuid.uuid4()),
            "operator": operator,
            "operation_type": operation_type,
            "operation_object": operation_object,
            "object_id": str(object_id),
            "operation_detail": operation_detail or {},
            "ip_address": ip_address,
            "user_agent": user_agent,
            "operation_time": operation_time or _now_iso(),
            "result": result,
            "failure_reason": failure_reason,
            "tenant_id": tenant_id,
        }
        conn = db._get_connection()
        try:
            prev_hash = self._last_hash(conn)
            payload = self._build_payload(record)
            cur_hash = _compute_hash(prev_hash, payload)
            record["prev_hash"] = prev_hash
            record["hash"] = cur_hash
            conn.execute("""
                INSERT INTO audit_operations
                    (id, operator, operation_type, operation_object, object_id,
                     operation_detail, ip_address, user_agent, operation_time,
                     result, failure_reason, tenant_id, prev_hash, hash)
                VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?)
            """, (
                record["id"], record["operator"], record["operation_type"],
                record["operation_object"], record["object_id"],
                json.dumps(record["operation_detail"], ensure_ascii=False),
                record["ip_address"], record["user_agent"], record["operation_time"],
                record["result"], record["failure_reason"], record["tenant_id"],
                record["prev_hash"], record["hash"],
            ))
            conn.commit()
            return record["id"]
        except Exception as e:  # pragma: no cover
            log.error(f"写入操作审计日志失败: {e}")
            return None
        finally:
            conn.close()

    def batch_log(self, records: List[Dict[str, Any]]) -> int:
        """批量写入操作日志（在同一连接内顺序计算哈希链）。

        Args:
            records: 字段同 log_operation，仅 operator/operation_type 为必填。
        Returns:
            成功写入条数。
        """
        if not records:
            return 0
        conn = db._get_connection()
        written = 0
        try:
            prev_hash = self._last_hash(conn)
            rows = []
            for rec in records:
                op_type = rec.get("operation_type", "execute")
                if op_type not in VALID_OPERATION_TYPES:
                    op_type = "execute"
                item = {
                    "id": str(uuid.uuid4()),
                    "operator": rec.get("operator", "unknown"),
                    "operation_type": op_type,
                    "operation_object": rec.get("operation_object", ""),
                    "object_id": str(rec.get("object_id", "")),
                    "operation_detail": rec.get("operation_detail") or {},
                    "ip_address": rec.get("ip_address", ""),
                    "user_agent": rec.get("user_agent", ""),
                    "operation_time": rec.get("operation_time") or _now_iso(),
                    "result": rec.get("result", "success"),
                    "failure_reason": rec.get("failure_reason", ""),
                    "tenant_id": rec.get("tenant_id", ""),
                }
                payload = self._build_payload(item)
                cur_hash = _compute_hash(prev_hash, payload)
                item["prev_hash"] = prev_hash
                item["hash"] = cur_hash
                prev_hash = cur_hash
                rows.append((
                    item["id"], item["operator"], item["operation_type"],
                    item["operation_object"], item["object_id"],
                    json.dumps(item["operation_detail"], ensure_ascii=False),
                    item["ip_address"], item["user_agent"], item["operation_time"],
                    item["result"], item["failure_reason"], item["tenant_id"],
                    item["prev_hash"], item["hash"],
                ))
            conn.executemany("""
                INSERT INTO audit_operations
                    (id, operator, operation_type, operation_object, object_id,
                     operation_detail, ip_address, user_agent, operation_time,
                     result, failure_reason, tenant_id, prev_hash, hash)
                VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?)
            """, rows)
            conn.commit()
            written = len(rows)
        except Exception as e:  # pragma: no cover
            log.error(f"批量写入操作审计日志失败: {e}")
        finally:
            conn.close()
        return written

    # ==================== 查询 ====================

    @staticmethod
    def _row_to_dict(row) -> Dict[str, Any]:
        """将数据库行转换为字典并解析 JSON 字段。"""
        d = dict(row)
        try:
            d["operation_detail"] = json.loads(d.get("operation_detail") or "{}")
        except Exception:
            d["operation_detail"] = {}
        return d

    def get_operation(self, log_id: str) -> Optional[Dict[str, Any]]:
        """获取单条操作日志详情。"""
        conn = db._get_connection()
        try:
            row = conn.execute(
                "SELECT * FROM audit_operations WHERE id = ?", (log_id,)
            ).fetchone()
            return self._row_to_dict(row) if row else None
        finally:
            conn.close()

    def list_operations(
        self,
        operator: Optional[str] = None,
        operation_type: Optional[str] = None,
        operation_object: Optional[str] = None,
        ip_address: Optional[str] = None,
        result: Optional[str] = None,
        start_time: Optional[str] = None,
        end_time: Optional[str] = None,
        page: int = 1,
        page_size: int = 20,
        order: str = "desc",
    ) -> Dict[str, Any]:
        """多条件查询操作日志，分页返回。"""
        where, params = ["1=1"], []
        if operator:
            where.append("operator LIKE ?")
            params.append(f"%{operator}%")
        if operation_type:
            where.append("operation_type = ?")
            params.append(operation_type)
        if operation_object:
            where.append("operation_object LIKE ?")
            params.append(f"%{operation_object}%")
        if ip_address:
            where.append("ip_address = ?")
            params.append(ip_address)
        if result:
            where.append("result = ?")
            params.append(result)
        if start_time:
            where.append("operation_time >= ?")
            params.append(start_time)
        if end_time:
            where.append("operation_time <= ?")
            params.append(end_time)
        where_sql = " AND ".join(where)
        order_sql = "ASC" if str(order).lower() == "asc" else "DESC"
        page = max(1, int(page))
        page_size = max(1, min(500, int(page_size)))
        offset = (page - 1) * page_size

        conn = db._get_connection()
        try:
            total = conn.execute(
                f"SELECT COUNT(*) AS c FROM audit_operations WHERE {where_sql}", params
            ).fetchone()["c"]
            rows = conn.execute(
                f"SELECT * FROM audit_operations WHERE {where_sql} "
                f"ORDER BY operation_time {order_sql}, rowid {order_sql} LIMIT ? OFFSET ?",
                params + [page_size, offset],
            ).fetchall()
            return {
                "total": total,
                "page": page,
                "page_size": page_size,
                "items": [self._row_to_dict(r) for r in rows],
            }
        finally:
            conn.close()

    def search_operations(
        self,
        keyword: str,
        start_time: Optional[str] = None,
        end_time: Optional[str] = None,
        page: int = 1,
        page_size: int = 20,
    ) -> Dict[str, Any]:
        """全文搜索操作详情（对 operation_detail 与 object_id 做 LIKE 匹配）。"""
        if not keyword:
            return {"total": 0, "items": []}
        where, params = ["operation_detail LIKE ?", "object_id LIKE ?", "operator LIKE ?"]
        like = f"%{keyword}%"
        params.extend([like, like, like])
        if start_time:
            where.append("operation_time >= ?")
            params.append(start_time)
        if end_time:
            where.append("operation_time <= ?")
            params.append(end_time)
        page = max(1, int(page))
        page_size = max(1, min(500, int(page_size)))
        offset = (page - 1) * page_size
        conn = db._get_connection()
        try:
            where_sql = " OR ".join([f"({w})" for w in where[:3]])
            time_sql = " AND ".join(where[3:])
            full = where_sql + (" AND " + time_sql if time_sql else "")
            total = conn.execute(
                f"SELECT COUNT(*) AS c FROM audit_operations WHERE {full}", params
            ).fetchone()["c"]
            rows = conn.execute(
                f"SELECT * FROM audit_operations WHERE {full} "
                f"ORDER BY operation_time DESC LIMIT ? OFFSET ?",
                params + [page_size, offset],
            ).fetchall()
            return {"total": total, "page": page, "page_size": page_size,
                    "items": [self._row_to_dict(r) for r in rows]}
        finally:
            conn.close()

    # ==================== 统计 ====================

    def get_operation_stats(
        self,
        start_time: Optional[str] = None,
        end_time: Optional[str] = None,
    ) -> Dict[str, Any]:
        """按操作类型/操作人/结果/日期聚合统计。"""
        where, params = ["1=1"], []
        if start_time:
            where.append("operation_time >= ?")
            params.append(start_time)
        if end_time:
            where.append("operation_time <= ?")
            params.append(end_time)
        where_sql = " AND ".join(where)
        conn = db._get_connection()
        try:
            by_type = [dict(r) for r in conn.execute(
                f"SELECT operation_type AS name, COUNT(*) AS count FROM audit_operations "
                f"WHERE {where_sql} GROUP BY operation_type", params).fetchall()]
            by_operator = [dict(r) for r in conn.execute(
                f"SELECT operator AS name, COUNT(*) AS count FROM audit_operations "
                f"WHERE {where_sql} GROUP BY operator ORDER BY count DESC LIMIT 20", params).fetchall()]
            by_result = [dict(r) for r in conn.execute(
                f"SELECT result AS name, COUNT(*) AS count FROM audit_operations "
                f"WHERE {where_sql} GROUP BY result", params).fetchall()]
            by_day = [dict(r) for r in conn.execute(
                f"SELECT substr(operation_time,1,10) AS date, COUNT(*) AS count "
                f"FROM audit_operations WHERE {where_sql} "
                f"GROUP BY date ORDER BY date DESC LIMIT 30", params).fetchall()]
            total = conn.execute(
                f"SELECT COUNT(*) AS c FROM audit_operations WHERE {where_sql}", params
            ).fetchone()["c"]
            return {
                "total": total,
                "by_operation_type": by_type,
                "by_operator": by_operator,
                "by_result": by_result,
                "by_day": by_day,
            }
        finally:
            conn.close()

    # ==================== 导出 ====================

    def export_operations(
        self,
        fmt: str = "csv",
        start_time: Optional[str] = None,
        end_time: Optional[str] = None,
        operator: Optional[str] = None,
    ) -> Dict[str, Any]:
        """导出操作日志为 CSV 或 JSON。

        Returns:
            {"format": ..., "filename": ..., "content": ...}，content 为字符串。
        """
        result = self.list_operations(
            operator=operator, start_time=start_time, end_time=end_time,
            page=1, page_size=100000,
        )
        items = result["items"]
        fmt = (fmt or "csv").lower()
        if fmt == "json":
            content = json.dumps({
                "exported_at": _now_iso(),
                "count": len(items),
                "items": items,
            }, ensure_ascii=False, indent=2)
            return {"format": "json", "filename": f"operations_{_now_iso()}.json",
                    "content": content, "count": len(items)}

        # CSV
        buf = io.StringIO()
        writer = csv.writer(buf)
        writer.writerow(["id", "operator", "operation_type", "operation_object",
                         "object_id", "operation_time", "result", "ip_address",
                         "tenant_id", "failure_reason", "operation_detail"])
        for it in items:
            writer.writerow([
                it.get("id"), it.get("operator"), it.get("operation_type"),
                it.get("operation_object"), it.get("object_id"),
                it.get("operation_time"), it.get("result"), it.get("ip_address"),
                it.get("tenant_id"), it.get("failure_reason"),
                json.dumps(it.get("operation_detail") or {}, ensure_ascii=False),
            ])
        return {"format": "csv", "filename": f"operations_{_now_iso()}.csv",
                "content": buf.getvalue(), "count": len(items)}

    # ==================== 完整性校验 ====================

    def get_log_chain(
        self,
        start_time: Optional[str] = None,
        end_time: Optional[str] = None,
        limit: int = 10000,
    ) -> List[Dict[str, Any]]:
        """获取指定时间范围内按时间升序排列的日志链（用于审计/校验）。"""
        where, params = ["1=1"], []
        if start_time:
            where.append("operation_time >= ?")
            params.append(start_time)
        if end_time:
            where.append("operation_time <= ?")
            params.append(end_time)
        conn = db._get_connection()
        try:
            rows = conn.execute(
                f"SELECT * FROM audit_operations WHERE {' AND '.join(where)} "
                f"ORDER BY operation_time ASC, rowid ASC LIMIT ?",
                params + [limit],
            ).fetchall()
            return [dict(r) for r in rows]
        finally:
            conn.close()

    def verify_integrity(
        self,
        start_time: Optional[str] = None,
        end_time: Optional[str] = None,
    ) -> Dict[str, Any]:
        """校验哈希链完整性。

        Returns:
            {"intact": bool, "checked": int, "tampered": bool,
             "violations": [{"index", "id", "reason"}], "message": ...}
        """
        chain = self.get_log_chain(start_time=start_time, end_time=end_time)
        violations: List[Dict[str, Any]] = []
        prev_hash = "GENESIS"
        for idx, row in enumerate(chain):
            stored_prev = row.get("prev_hash") or "GENESIS"
            stored_hash = row.get("hash", "")
            # 还原 payload：与写入时保持一致，operation_detail 需先解析回 dict
            detail_raw = row.get("operation_detail") or "{}"
            try:
                detail_obj = json.loads(detail_raw)
            except Exception:
                detail_obj = detail_raw
            record = {
                "operator": row.get("operator", ""),
                "operation_type": row.get("operation_type", ""),
                "operation_object": row.get("operation_object", ""),
                "object_id": str(row.get("object_id", "")),
                "operation_detail": detail_obj,
                "ip_address": row.get("ip_address", ""),
                "operation_time": row.get("operation_time", ""),
                "result": row.get("result", ""),
                "tenant_id": row.get("tenant_id", "") or "",
            }
            payload = self._build_payload(record)
            expect = _compute_hash(stored_prev, payload)
            if stored_prev != prev_hash:
                violations.append({"index": idx, "id": row.get("id"),
                                   "reason": "prev_hash 与上一条日志不连续（链断裂）"})
            elif expect != stored_hash:
                violations.append({"index": idx, "id": row.get("id"),
                                   "reason": "日志内容被篡改（自身哈希校验失败）"})
            prev_hash = stored_hash

        return {
            "intact": len(violations) == 0,
            "tampered": len(violations) > 0,
            "checked": len(chain),
            "violations": violations,
            "message": "哈希链完整" if not violations else f"发现 {len(violations)} 处异常",
        }


# ==================== 单例 ====================

_operation_logger: Optional[OperationLogger] = None


def get_operation_logger() -> OperationLogger:
    """获取全局操作日志记录器单例。"""
    global _operation_logger
    if _operation_logger is None:
        _operation_logger = OperationLogger()
    return _operation_logger
