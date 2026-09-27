"""
告警管理器（Alert Manager）

模块功能：
    - 安全告警的接收、确认、抑制、聚合
    - 告警规则定义与阈值触发
    - 未确认告警自动升级

合法定位：
    本模块为防御视角的告警收敛与运营系统，仅记录与展示检测结果。

注意事项：
    - 本模块仅用于授权的安全运营
    - 请勿用于非法用途
"""
import json
import uuid
from datetime import datetime, timedelta
from typing import Optional, List, Dict, Any

from utils.database import db
from utils.logger import log


VALID_ALERT_STATUS = ("active", "acknowledged", "suppressed", "resolved")
VALID_ALERT_SEVERITY = ("critical", "high", "medium", "low", "info")


class AlertManager:
    """告警管理器：告警生命周期 + 规则引擎 + 聚合/升级"""

    def __init__(self):
        """初始化告警管理器，自动建表"""
        self._init_tables()

    # ==================== 数据库初始化 ====================

    def _init_tables(self):
        """初始化告警相关数据表（幂等）"""
        conn = db._get_connection()
        try:
            cur = conn.cursor()
            # 告警主表
            cur.execute("""
                CREATE TABLE IF NOT EXISTS soc_alerts (
                    id TEXT PRIMARY KEY,
                    title TEXT NOT NULL,
                    description TEXT,
                    severity TEXT DEFAULT 'medium',
                    status TEXT DEFAULT 'active',
                    source TEXT,
                    rule_id TEXT,
                    triggered_at TEXT,
                    incident_id TEXT,
                    asset_id TEXT,
                    aggregation_key TEXT,
                    acknowledged_by TEXT,
                    acknowledged_at TEXT,
                    tenant_id TEXT DEFAULT 'default',
                    created_at TEXT NOT NULL
                )
            """)
            # 告警规则表
            cur.execute("""
                CREATE TABLE IF NOT EXISTS soc_alert_rules (
                    id TEXT PRIMARY KEY,
                    name TEXT NOT NULL,
                    description TEXT,
                    condition TEXT,
                    threshold INTEGER DEFAULT 1,
                    severity TEXT DEFAULT 'medium',
                    notification_channels TEXT,
                    suppression_rules TEXT,
                    enabled INTEGER DEFAULT 1,
                    created_at TEXT NOT NULL
                )
            """)
            cur.execute("CREATE INDEX IF NOT EXISTS idx_soc_alert_status ON soc_alerts(status)")
            cur.execute("CREATE INDEX IF NOT EXISTS idx_soc_alert_sev ON soc_alerts(severity)")
            cur.execute("CREATE INDEX IF NOT EXISTS idx_soc_alert_agg ON soc_alerts(aggregation_key)")
            cur.execute("CREATE INDEX IF NOT EXISTS idx_soc_alert_triggered ON soc_alerts(triggered_at)")
            cur.execute("CREATE INDEX IF NOT EXISTS idx_soc_alert_asset ON soc_alerts(asset_id)")
            conn.commit()
            log.info("✅ SOC告警表初始化完成")
        except Exception as e:
            log.error(f"SOC告警表初始化失败: {e}")
        finally:
            conn.close()

    # ==================== 工具方法 ====================

    @staticmethod
    def _now() -> str:
        return datetime.now().isoformat()

    @staticmethod
    def _row_to_dict(row) -> dict:
        if row is None:
            return {}
        return dict(row)

    # ==================== 告警CRUD ====================

    def create_alert(self, title: str, description: str = "",
                     severity: str = "medium", source: str = "manual",
                     rule_id: str = None, asset_id: str = None,
                     incident_id: str = None, aggregation_key: str = None,
                     triggered_at: str = None, tenant_id: str = "default") -> dict:
        """创建告警；若同aggregation_key存在未关闭告警则自动聚合"""
        if severity not in VALID_ALERT_SEVERITY:
            severity = "medium"
        alert_id = str(uuid.uuid4())
        now = self._now()
        triggered_at = triggered_at or now
        conn = db._get_connection()
        try:
            conn.execute("""
                INSERT INTO soc_alerts (
                    id, title, description, severity, status, source, rule_id,
                    triggered_at, incident_id, asset_id, aggregation_key,
                    acknowledged_by, acknowledged_at, tenant_id, created_at
                ) VALUES (?, ?, ?, ?, 'active', ?, ?, ?, ?, ?, ?, NULL, NULL, ?, ?)
            """, (
                alert_id, title, description, severity, source, rule_id,
                triggered_at, incident_id, asset_id, aggregation_key, tenant_id, now,
            ))
            conn.commit()
        finally:
            conn.close()
        log.info(f"✅ 创建告警: {alert_id} - [{severity}] {title}")
        return self.get_alert(alert_id) or {"id": alert_id}

    def get_alert(self, alert_id: str) -> Optional[dict]:
        conn = db._get_connection()
        try:
            row = conn.execute("SELECT * FROM soc_alerts WHERE id = ?", (alert_id,)).fetchone()
            return self._row_to_dict(row) if row else None
        finally:
            conn.close()

    def list_alerts(self, status: Optional[str] = None,
                    severity: Optional[str] = None,
                    source: Optional[str] = None,
                    rule_id: Optional[str] = None,
                    asset_id: Optional[str] = None,
                    start_time: Optional[str] = None,
                    end_time: Optional[str] = None,
                    keyword: Optional[str] = None,
                    page: int = 1, page_size: int = 20) -> Dict[str, Any]:
        """查询告警列表，支持多维筛选与分页"""
        page = max(1, int(page))
        page_size = max(1, min(500, int(page_size)))
        where = ["1=1"]
        params: list = []
        if status:
            where.append("status = ?")
            params.append(status)
        if severity:
            where.append("severity = ?")
            params.append(severity)
        if source:
            where.append("source = ?")
            params.append(source)
        if rule_id:
            where.append("rule_id = ?")
            params.append(rule_id)
        if asset_id:
            where.append("asset_id = ?")
            params.append(asset_id)
        if start_time:
            where.append("triggered_at >= ?")
            params.append(start_time)
        if end_time:
            where.append("triggered_at <= ?")
            params.append(end_time)
        if keyword:
            where.append("(title LIKE ? OR description LIKE ?)")
            like = f"%{keyword}%"
            params.extend([like, like])

        where_sql = " AND ".join(where)
        conn = db._get_connection()
        try:
            total = conn.execute(
                f"SELECT COUNT(*) c FROM soc_alerts WHERE {where_sql}", params
            ).fetchone()["c"]
            rows = conn.execute(
                f"""SELECT * FROM soc_alerts WHERE {where_sql}
                    ORDER BY triggered_at DESC LIMIT ? OFFSET ?""",
                params + [page_size, (page - 1) * page_size],
            ).fetchall()
            return {"items": [self._row_to_dict(r) for r in rows],
                    "total": total, "page": page, "page_size": page_size}
        finally:
            conn.close()

    def update_alert(self, alert_id: str, **fields) -> Optional[dict]:
        """更新告警字段"""
        allowed = {"title", "description", "severity", "status", "source",
                   "rule_id", "incident_id", "asset_id", "aggregation_key"}
        updates = []
        params: list = []
        for k, v in fields.items():
            if k in allowed and v is not None:
                updates.append(f"{k} = ?")
                params.append(v)
        if not updates:
            return self.get_alert(alert_id)
        params.append(alert_id)
        conn = db._get_connection()
        try:
            cur = conn.execute(
                f"UPDATE soc_alerts SET {', '.join(updates)} WHERE id = ?", params
            )
            conn.commit()
            return self.get_alert(alert_id) if cur.rowcount else None
        finally:
            conn.close()

    def acknowledge_alert(self, alert_id: str, operator: str = "system") -> Optional[dict]:
        """确认告警"""
        now = self._now()
        conn = db._get_connection()
        try:
            cur = conn.execute(
                """UPDATE soc_alerts SET status='acknowledged',
                   acknowledged_by=?, acknowledged_at=? WHERE id=?""",
                (operator, now, alert_id),
            )
            conn.commit()
            return self.get_alert(alert_id) if cur.rowcount else None
        finally:
            conn.close()

    def suppress_alert(self, alert_id: str, operator: str = "system",
                        reason: str = "") -> Optional[dict]:
        """抑制告警（不通知/不升级）"""
        conn = db._get_connection()
        try:
            cur = conn.execute(
                "UPDATE soc_alerts SET status='suppressed' WHERE id=?", (alert_id,)
            )
            conn.commit()
            log.info(f"告警 {alert_id} 被 {operator} 抑制，原因: {reason}")
            return self.get_alert(alert_id) if cur.rowcount else None
        finally:
            conn.close()

    def aggregate_alerts(self, aggregation_key: str, window_hours: int = 24) -> Dict[str, Any]:
        """将相同aggregation_key的告警聚合为一组

        Returns:
            {"aggregation_key": ..., "count": int, "alerts": [...], "top_severity": ...}
        """
        since = (datetime.now() - timedelta(hours=window_hours)).isoformat()
        conn = db._get_connection()
        try:
            rows = conn.execute(
                """SELECT * FROM soc_alerts
                   WHERE aggregation_key = ? AND triggered_at >= ?
                   ORDER BY triggered_at DESC""",
                (aggregation_key, since),
            ).fetchall()
            items = [self._row_to_dict(r) for r in rows]
            order = ["info", "low", "medium", "high", "critical"]
            top = "info"
            for it in items:
                if it.get("severity") in order:
                    if order.index(it["severity"]) > order.index(top):
                        top = it["severity"]
            return {"aggregation_key": aggregation_key,
                    "count": len(items), "alerts": items, "top_severity": top}
        finally:
            conn.close()

    # ==================== 告警规则 ====================

    def create_rule(self, name: str, description: str = "",
                    condition: dict = None, threshold: int = 1,
                    severity: str = "medium",
                    notification_channels: list = None,
                    suppression_rules: list = None,
                    enabled: bool = True) -> dict:
        """创建告警规则"""
        rule_id = str(uuid.uuid4())
        now = self._now()
        conn = db._get_connection()
        try:
            conn.execute("""
                INSERT INTO soc_alert_rules (
                    id, name, description, condition, threshold, severity,
                    notification_channels, suppression_rules, enabled, created_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """, (
                rule_id, name, description,
                json.dumps(condition or {}, ensure_ascii=False),
                threshold, severity,
                json.dumps(notification_channels or [], ensure_ascii=False),
                json.dumps(suppression_rules or [], ensure_ascii=False),
                1 if enabled else 0, now,
            ))
            conn.commit()
        finally:
            conn.close()
        log.info(f"✅ 创建告警规则: {rule_id} - {name}")
        return self._get_rule(rule_id) or {"id": rule_id, "name": name}

    def _get_rule(self, rule_id: str) -> Optional[dict]:
        conn = db._get_connection()
        try:
            row = conn.execute("SELECT * FROM soc_alert_rules WHERE id=?", (rule_id,)).fetchone()
            if not row:
                return None
            item = dict(row)
            for jf in ("condition", "notification_channels", "suppression_rules"):
                raw = item.get(jf)
                if isinstance(raw, str):
                    try:
                        item[jf] = json.loads(raw)
                    except (json.JSONDecodeError, TypeError):
                        item[jf] = [] if jf != "condition" else {}
            return item
        finally:
            conn.close()

    def list_rules(self, enabled_only: bool = False) -> List[dict]:
        conn = db._get_connection()
        try:
            sql = "SELECT * FROM soc_alert_rules"
            if enabled_only:
                sql += " WHERE enabled = 1"
            sql += " ORDER BY created_at DESC"
            rows = conn.execute(sql).fetchall()
            return [self._get_rule(r["id"]) for r in rows]
        finally:
            conn.close()

    def update_rule(self, rule_id: str, **fields) -> Optional[dict]:
        """更新告警规则"""
        allowed = {"name", "description", "threshold", "severity", "enabled"}
        json_fields = {"condition", "notification_channels", "suppression_rules"}
        updates = []
        params: list = []
        for k, v in fields.items():
            if k in allowed and v is not None:
                updates.append(f"{k} = ?")
                params.append(1 if k == "enabled" and isinstance(v, bool) else v)
            elif k in json_fields and v is not None:
                updates.append(f"{k} = ?")
                params.append(json.dumps(v, ensure_ascii=False))
        if not updates:
            return self._get_rule(rule_id)
        params.append(rule_id)
        conn = db._get_connection()
        try:
            conn.execute(f"UPDATE soc_alert_rules SET {', '.join(updates)} WHERE id=?", params)
            conn.commit()
            return self._get_rule(rule_id)
        finally:
            conn.close()

    def delete_rule(self, rule_id: str) -> bool:
        conn = db._get_connection()
        try:
            cur = conn.execute("DELETE FROM soc_alert_rules WHERE id=?", (rule_id,))
            conn.commit()
            return cur.rowcount > 0
        finally:
            conn.close()

    # ==================== 统计与自动升级 ====================

    def get_alert_stats(self, days: int = 7) -> dict:
        """告警统计：按状态/严重级别/来源/规则TOP"""
        since = (datetime.now() - timedelta(days=days)).isoformat()
        conn = db._get_connection()
        try:
            cond = "WHERE triggered_at >= ?"
            params = [since]

            def group_by(col: str) -> dict:
                rows = conn.execute(
                    f"SELECT {col} AS k, COUNT(*) c FROM soc_alerts {cond} GROUP BY {col}",
                    params,
                ).fetchall()
                return {r["k"]: r["c"] for r in rows}

            stats = {
                "total": conn.execute(f"SELECT COUNT(*) c FROM soc_alerts {cond}", params).fetchone()["c"],
                "active": conn.execute(f"SELECT COUNT(*) c FROM soc_alerts {cond} AND status='active'", params).fetchone()["c"],
                "by_status": group_by("status"),
                "by_severity": group_by("severity"),
                "by_source": group_by("source"),
            }
            # 规则TOP10
            rows = conn.execute(
                f"""SELECT rule_id, COUNT(*) c FROM soc_alerts {cond}
                   AND rule_id IS NOT NULL GROUP BY rule_id ORDER BY c DESC LIMIT 10""",
                params,
            ).fetchall()
            stats["top_rules"] = [{"rule_id": r["rule_id"], "count": r["c"]} for r in rows]
            return stats
        finally:
            conn.close()

    def auto_escalate(self, threshold_minutes: int = 30) -> Dict[str, Any]:
        """未确认告警自动升级：超过阈值时间仍为active的critical/high告警升级严重级别"""
        cutoff = (datetime.now() - timedelta(minutes=threshold_minutes)).isoformat()
        conn = db._get_connection()
        try:
            rows = conn.execute(
                """SELECT id, severity, title, triggered_at FROM soc_alerts
                   WHERE status='active' AND severity IN ('critical','high','medium')
                   AND triggered_at <= ?""",
                (cutoff,),
            ).fetchall()
            order = ["info", "low", "medium", "high", "critical"]
            escalated = []
            for r in rows:
                sev = r["severity"]
                idx = order.index(sev) if sev in order else 2
                new_sev = order[min(idx + 1, len(order) - 1)]
                conn.execute(
                    "UPDATE soc_alerts SET severity=? WHERE id=?", (new_sev, r["id"])
                )
                escalated.append({"id": r["id"], "title": r["title"],
                                  "from": sev, "to": new_sev})
            conn.commit()
            log.warning(f"⚠️ 告警自动升级 {len(escalated)} 条（>={threshold_minutes}分钟未确认）")
            return {"escalated_count": len(escalated), "escalated": escalated}
        except Exception as e:
            log.error(f"告警自动升级失败: {e}")
            return {"escalated_count": 0, "error": str(e)}
        finally:
            conn.close()


# 全局单例
alert_manager = AlertManager()
