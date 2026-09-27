"""
安全事件管理器（Incident Manager）

模块功能：
    - 安全事件的全生命周期管理（创建/分析/升级/关闭）
    - 事件时间线记录
    - 多维度统计与自动关联（资产/漏洞/告警）
    - 严重事件自动升级

合法定位：
    本模块为防御视角的事件响应记录系统，用于企业内部安全运营。

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


# 合法枚举约束
VALID_SEVERITIES = ("critical", "high", "medium", "low", "info")
VALID_STATUSES = ("new", "analyzing", "resolved", "closed", "false_positive")
VALID_CATEGORIES = ("intrusion", "malware", "data_breach", "ddos",
                    "insider_threat", "misconfiguration", "other")
VALID_SOURCES = ("ids", "scan", "manual", "threat_intel", "external")


class IncidentManager:
    """安全事件管理器：负责任务事件的全生命周期与统计分析"""

    def __init__(self):
        """初始化事件管理器，自动建表"""
        self._init_tables()

    # ==================== 数据库初始化 ====================

    def _init_tables(self):
        """初始化事件相关数据表（幂等）"""
        conn = db._get_connection()
        try:
            cur = conn.cursor()
            # 事件主表
            cur.execute("""
                CREATE TABLE IF NOT EXISTS soc_incidents (
                    id TEXT PRIMARY KEY,
                    title TEXT NOT NULL,
                    description TEXT,
                    severity TEXT DEFAULT 'medium',
                    status TEXT DEFAULT 'new',
                    category TEXT DEFAULT 'other',
                    source TEXT DEFAULT 'manual',
                    asset_id TEXT,
                    vulnerability_id TEXT,
                    assigned_to TEXT,
                    discovered_at TEXT,
                    analyzed_at TEXT,
                    resolved_at TEXT,
                    closed_at TEXT,
                    processing_log TEXT,
                    tenant_id TEXT DEFAULT 'default',
                    created_at TEXT NOT NULL,
                    updated_at TEXT NOT NULL
                )
            """)
            # 事件时间线表
            cur.execute("""
                CREATE TABLE IF NOT EXISTS soc_incident_timeline (
                    id TEXT PRIMARY KEY,
                    incident_id TEXT NOT NULL,
                    action TEXT NOT NULL,
                    operator TEXT,
                    detail TEXT,
                    timestamp TEXT NOT NULL
                )
            """)
            # 索引
            cur.execute("CREATE INDEX IF NOT EXISTS idx_soc_inc_status ON soc_incidents(status)")
            cur.execute("CREATE INDEX IF NOT EXISTS idx_soc_inc_sev ON soc_incidents(severity)")
            cur.execute("CREATE INDEX IF NOT EXISTS idx_soc_inc_cat ON soc_incidents(category)")
            cur.execute("CREATE INDEX IF NOT EXISTS idx_soc_inc_src ON soc_incidents(source)")
            cur.execute("CREATE INDEX IF NOT EXISTS idx_soc_inc_created ON soc_incidents(created_at)")
            cur.execute("CREATE INDEX IF NOT EXISTS idx_soc_timeline_inc ON soc_incident_timeline(incident_id)")
            conn.commit()
            log.info("✅ SOC事件表初始化完成")
        except Exception as e:
            log.error(f"SOC事件表初始化失败: {e}")
        finally:
            conn.close()

    # ==================== 工具方法 ====================

    @staticmethod
    def _now() -> str:
        """返回当前ISO时间字符串"""
        return datetime.now().isoformat()

    @staticmethod
    def _row_to_dict(row) -> dict:
        """将SQLite Row转为字典，并反序列化JSON字段"""
        if row is None:
            return {}
        item = dict(row)
        for jf in ("processing_log",):
            raw = item.get(jf)
            if isinstance(raw, str):
                try:
                    item[jf] = json.loads(raw)
                except (json.JSONDecodeError, TypeError):
                    item[jf] = []
            elif raw is None:
                item[jf] = []
        return item

    def _append_timeline(self, incident_id: str, action: str,
                         operator: str = "", detail: Any = None):
        """向事件时间线追加一条记录"""
        conn = db._get_connection()
        try:
            conn.execute("""
                INSERT INTO soc_incident_timeline (id, incident_id, action, operator, detail, timestamp)
                VALUES (?, ?, ?, ?, ?, ?)
            """, (
                str(uuid.uuid4()),
                incident_id,
                action,
                operator,
                json.dumps(detail, ensure_ascii=False) if not isinstance(detail, str) else detail,
                self._now(),
            ))
            conn.commit()
        except Exception as e:
            log.error(f"追加事件时间线失败: {e}")
        finally:
            conn.close()

    def _append_processing_log(self, incident_id: str, entry: dict):
        """向事件处理日志追加一条记录（JSON数组）"""
        conn = db._get_connection()
        try:
            row = conn.execute(
                "SELECT processing_log FROM soc_incidents WHERE id = ?", (incident_id,)
            ).fetchone()
            if not row:
                return
            try:
                logs = json.loads(row["processing_log"]) if row["processing_log"] else []
            except (json.JSONDecodeError, TypeError):
                logs = []
            logs.append(entry)
            conn.execute(
                "UPDATE soc_incidents SET processing_log = ?, updated_at = ? WHERE id = ?",
                (json.dumps(logs, ensure_ascii=False), self._now(), incident_id),
            )
            conn.commit()
        except Exception as e:
            log.error(f"追加处理日志失败: {e}")
        finally:
            conn.close()

    # ==================== 核心CRUD ====================

    def create_incident(self, title: str, description: str = "",
                        severity: str = "medium", category: str = "other",
                        source: str = "manual", asset_id: str = None,
                        vulnerability_id: str = None, assigned_to: str = None,
                        discovered_at: str = None, tenant_id: str = "default",
                        operator: str = "system") -> dict:
        """创建安全事件

        Args:
            title: 事件标题
            description: 事件描述
            severity: 严重级别 critical/high/medium/low/info
            category: 事件分类 intrusion/malware/data_breach/ddos/insider_threat/misconfiguration/other
            source: 来源 ids/scan/manual/threat_intel/external
            asset_id: 关联资产ID
            vulnerability_id: 关联漏洞ID
            assigned_to: 指派处理人
            discovered_at: 发现时间（ISO），缺省为当前时间
            tenant_id: 租户ID
            operator: 操作人（时间线记录用）

        Returns:
            创建后的事件字典
        """
        if severity not in VALID_SEVERITIES:
            severity = "medium"
        if category not in VALID_CATEGORIES:
            category = "other"
        if source not in VALID_SOURCES:
            source = "manual"

        incident_id = str(uuid.uuid4())
        now = self._now()
        discovered_at = discovered_at or now
        processing_log = [
            {"time": now, "action": "created", "operator": operator,
             "detail": f"事件创建，初始严重级别={severity}"}
        ]
        conn = db._get_connection()
        try:
            conn.execute("""
                INSERT INTO soc_incidents (
                    id, title, description, severity, status, category, source,
                    asset_id, vulnerability_id, assigned_to, discovered_at,
                    analyzed_at, resolved_at, closed_at, processing_log,
                    tenant_id, created_at, updated_at
                ) VALUES (?, ?, ?, ?, 'new', ?, ?, ?, ?, ?, ?, NULL, NULL, NULL, ?, ?, ?, ?)
            """, (
                incident_id, title, description, severity, category, source,
                asset_id, vulnerability_id, assigned_to, discovered_at,
                json.dumps(processing_log, ensure_ascii=False), tenant_id, now, now,
            ))
            conn.commit()
        except Exception as e:
            log.error(f"创建安全事件失败: {e}")
            raise
        finally:
            conn.close()

        self._append_timeline(incident_id, "created", operator,
                              {"title": title, "severity": severity, "source": source})
        # 严重事件自动升级
        if severity in ("critical", "high"):
            self.escalate_incident(incident_id, reason=f"创建时严重级别={severity}，自动升级")
        log.info(f"✅ 创建安全事件: {incident_id} - {title}")
        return self.get_incident(incident_id) or {"id": incident_id, "title": title}

    def get_incident(self, incident_id: str) -> Optional[dict]:
        """根据ID获取事件详情"""
        conn = db._get_connection()
        try:
            row = conn.execute(
                "SELECT * FROM soc_incidents WHERE id = ?", (incident_id,)
            ).fetchone()
            return self._row_to_dict(row) if row else None
        finally:
            conn.close()

    def list_incidents(self, status: Optional[str] = None,
                       severity: Optional[str] = None,
                       category: Optional[str] = None,
                       source: Optional[str] = None,
                       start_time: Optional[str] = None,
                       end_time: Optional[str] = None,
                       keyword: Optional[str] = None,
                       assigned_to: Optional[str] = None,
                       tenant_id: Optional[str] = None,
                       page: int = 1, page_size: int = 20) -> Dict[str, Any]:
        """查询事件列表，支持多维筛选与分页

        Returns:
            {"items": [...], "total": int, "page": int, "page_size": int}
        """
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
        if category:
            where.append("category = ?")
            params.append(category)
        if source:
            where.append("source = ?")
            params.append(source)
        if assigned_to:
            where.append("assigned_to = ?")
            params.append(assigned_to)
        if tenant_id:
            where.append("tenant_id = ?")
            params.append(tenant_id)
        if start_time:
            where.append("discovered_at >= ?")
            params.append(start_time)
        if end_time:
            where.append("discovered_at <= ?")
            params.append(end_time)
        if keyword:
            where.append("(title LIKE ? OR description LIKE ?)")
            like = f"%{keyword}%"
            params.extend([like, like])

        where_sql = " AND ".join(where)
        conn = db._get_connection()
        try:
            total = conn.execute(
                f"SELECT COUNT(*) AS c FROM soc_incidents WHERE {where_sql}", params
            ).fetchone()["c"]
            rows = conn.execute(
                f"""SELECT * FROM soc_incidents WHERE {where_sql}
                    ORDER BY discovered_at DESC LIMIT ? OFFSET ?""",
                params + [page_size, (page - 1) * page_size],
            ).fetchall()
            return {
                "items": [self._row_to_dict(r) for r in rows],
                "total": total,
                "page": page,
                "page_size": page_size,
            }
        finally:
            conn.close()

    def update_incident(self, incident_id: str, operator: str = "system",
                        **fields) -> Optional[dict]:
        """更新事件字段（title/description/severity/status/category/source/asset_id/
        vulnerability_id/assigned_to 等）"""
        allowed = {"title", "description", "severity", "status", "category",
                   "source", "asset_id", "vulnerability_id", "assigned_to"}
        updates = []
        params: list = []
        for k, v in fields.items():
            if k in allowed and v is not None:
                if k == "severity" and v not in VALID_SEVERITIES:
                    continue
                if k == "status" and v not in VALID_STATUSES:
                    continue
                updates.append(f"{k} = ?")
                params.append(v)

        if not updates:
            return self.get_incident(incident_id)

        now = self._now()
        # 状态联动时间戳
        new_status = fields.get("status")
        if new_status == "analyzing":
            updates.append("analyzed_at = ?")
            params.append(now)
        elif new_status == "resolved":
            updates.append("resolved_at = ?")
            params.append(now)
        elif new_status == "closed":
            updates.append("closed_at = ?")
            params.append(now)

        updates.append("updated_at = ?")
        params.append(now)
        params.append(incident_id)

        conn = db._get_connection()
        try:
            cur = conn.execute(
                f"UPDATE soc_incidents SET {', '.join(updates)} WHERE id = ?", params
            )
            conn.commit()
            if cur.rowcount == 0:
                return None
        finally:
            conn.close()

        self._append_timeline(incident_id, "updated", operator, fields)
        self._append_processing_log(incident_id, {
            "time": now, "action": "update", "operator": operator, "detail": fields
        })
        return self.get_incident(incident_id)

    def delete_incident(self, incident_id: str) -> bool:
        """删除事件及其时间线"""
        conn = db._get_connection()
        try:
            cur = conn.execute("DELETE FROM soc_incidents WHERE id = ?", (incident_id,))
            conn.execute("DELETE FROM soc_incident_timeline WHERE incident_id = ?", (incident_id,))
            conn.commit()
            return cur.rowcount > 0
        except Exception as e:
            log.error(f"删除事件失败: {e}")
            return False
        finally:
            conn.close()

    def assign_incident(self, incident_id: str, assignee: str,
                        operator: str = "system") -> Optional[dict]:
        """指派事件处理人"""
        if not assignee:
            return self.get_incident(incident_id)
        now = self._now()
        conn = db._get_connection()
        try:
            conn.execute(
                "UPDATE soc_incidents SET assigned_to = ?, updated_at = ? WHERE id = ?",
                (assignee, now, incident_id),
            )
            conn.commit()
        finally:
            conn.close()
        self._append_timeline(incident_id, "assigned", operator, {"assignee": assignee})
        self._append_processing_log(incident_id, {
            "time": now, "action": "assign", "operator": operator, "assignee": assignee
        })
        log.info(f"事件 {incident_id} 已指派给 {assignee}")
        return self.get_incident(incident_id)

    def escalate_incident(self, incident_id: str, reason: str = "",
                          operator: str = "system") -> Optional[dict]:
        """升级事件：提升严重级别（若已为critical则标记escalated时间线）"""
        incident = self.get_incident(incident_id)
        if not incident:
            return None
        order = ["info", "low", "medium", "high", "critical"]
        current = incident.get("severity", "medium")
        if current in order:
            idx = order.index(current)
            new_sev = order[min(idx + 1, len(order) - 1)]
        else:
            new_sev = "high"

        now = self._now()
        conn = db._get_connection()
        try:
            conn.execute(
                "UPDATE soc_incidents SET severity = ?, updated_at = ? WHERE id = ?",
                (new_sev, now, incident_id),
            )
            conn.commit()
        finally:
            conn.close()

        self._append_timeline(incident_id, "escalated", operator,
                              {"from": current, "to": new_sev, "reason": reason})
        self._append_processing_log(incident_id, {
            "time": now, "action": "escalate", "operator": operator,
            "from": current, "to": new_sev, "reason": reason,
        })
        log.warning(f"⚠️ 事件 {incident_id} 已升级: {current} -> {new_sev}，原因: {reason}")
        return self.get_incident(incident_id)

    def get_incident_timeline(self, incident_id: str) -> List[dict]:
        """获取事件完整时间线"""
        conn = db._get_connection()
        try:
            rows = conn.execute(
                """SELECT * FROM soc_incident_timeline WHERE incident_id = ?
                   ORDER BY timestamp ASC""", (incident_id,)
            ).fetchall()
            result = []
            for r in rows:
                item = dict(r)
                raw = item.get("detail")
                if isinstance(raw, str):
                    try:
                        item["detail"] = json.loads(raw)
                    except (json.JSONDecodeError, TypeError):
                        pass
                result.append(item)
            return result
        finally:
            conn.close()

    def get_incident_stats(self, days: int = 30,
                           tenant_id: Optional[str] = None) -> dict:
        """事件统计：按状态/严重程度/类型/时间/来源聚合"""
        since = (datetime.now() - timedelta(days=days)).isoformat()
        conn = db._get_connection()
        try:
            cond = "WHERE discovered_at >= ?"
            params: list = [since]
            if tenant_id:
                cond += " AND tenant_id = ?"
                params.append(tenant_id)

            def group_by(col: str) -> dict:
                rows = conn.execute(
                    f"SELECT {col} AS k, COUNT(*) AS c FROM soc_incidents {cond} GROUP BY {col}",
                    params,
                ).fetchall()
                return {r["k"]: r["c"] for r in rows}

            stats = {
                "total": conn.execute(f"SELECT COUNT(*) c FROM soc_incidents {cond}", params).fetchone()["c"],
                "by_status": group_by("status"),
                "by_severity": group_by("severity"),
                "by_category": group_by("category"),
                "by_source": group_by("source"),
            }
            # 按天趋势
            rows = conn.execute(
                f"""SELECT substr(discovered_at, 1, 10) AS d, COUNT(*) AS c
                    FROM soc_incidents {cond} GROUP BY d ORDER BY d""",
                params,
            ).fetchall()
            stats["trend_by_day"] = [{"date": r["d"], "count": r["c"]} for r in rows]
            return stats
        finally:
            conn.close()

    def auto_correlate(self, incident_id: str) -> dict:
        """自动关联资产/漏洞/告警

        规则：
            - 同asset_id的告警自动挂接到本事件
            - 同vulnerability_id的事件合并标记
            - 同时将事件状态推进为analyzing
        """
        incident = self.get_incident(incident_id)
        if not incident:
            return {"success": False, "error": "事件不存在"}

        result: Dict[str, Any] = {"incident_id": incident_id,
                                  "linked_alerts": [], "linked_incidents": []}
        asset_id = incident.get("asset_id")
        vuln_id = incident.get("vulnerability_id")

        conn = db._get_connection()
        try:
            # 关联同资产的活跃告警
            if asset_id:
                rows = conn.execute(
                    """SELECT id, title, severity FROM soc_alerts
                       WHERE asset_id = ? AND status IN ('active','acknowledged')
                       ORDER BY triggered_at DESC LIMIT 50""",
                    (asset_id,),
                ).fetchall()
                result["linked_alerts"] = [dict(r) for r in rows]
                if rows:
                    conn.execute(
                        """UPDATE soc_alerts SET incident_id = ?
                           WHERE asset_id = ? AND incident_id IS NULL""",
                        (incident_id, asset_id),
                    )
            # 关联同漏洞的其他未关闭事件
            if vuln_id:
                rows = conn.execute(
                    """SELECT id, title, severity, status FROM soc_incidents
                       WHERE vulnerability_id = ? AND id != ?
                       AND status NOT IN ('closed','false_positive')""",
                    (vuln_id, incident_id),
                ).fetchall()
                result["linked_incidents"] = [dict(r) for r in rows]
            conn.commit()
        except Exception as e:
            log.error(f"自动关联失败: {e}")
            result["error"] = str(e)
        finally:
            conn.close()

        # 推进状态
        self.update_incident(incident_id, operator="system",
                             status="analyzing")
        self._append_timeline(incident_id, "auto_correlated", "system", result)
        result["success"] = True
        return result


# 全局单例
incident_manager = IncidentManager()
