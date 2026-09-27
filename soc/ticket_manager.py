"""
工单管理器（Ticket Manager）

模块功能：
    - 安全工单全生命周期（漏洞修复/加固/事件响应）
    - 工单评论与模板
    - 自动分配（按技能/负载/轮询）
    - SLA超时检测与自动升级

合法定位：
    本模块为防御视角的安全运营工单系统。

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


VALID_PRIORITIES = ("urgent", "high", "medium", "low")
VALID_TICKET_STATUS = ("open", "in_progress", "resolved", "closed")
VALID_TICKET_TYPES = ("vuln_fix", "hardening", "incident_response", "other")

# SLA时长（小时）：按优先级
SLA_HOURS = {"urgent": 4, "high": 24, "medium": 72, "low": 168}

# 技能标签映射（自动分配用）
SKILL_MAP = {
    "vuln_fix": ["dev", "secops", "soc"],
    "hardening": ["secops", "infrastructure", "soc"],
    "incident_response": ["soc", "ir", "secops"],
    "other": ["soc"],
}


class TicketManager:
    """工单管理器：工单/评论/模板 + SLA + 自动分配"""

    def __init__(self):
        """初始化工单管理器，自动建表"""
        self._init_tables()

    # ==================== 数据库初始化 ====================

    def _init_tables(self):
        """初始化工单相关数据表（幂等）"""
        conn = db._get_connection()
        try:
            cur = conn.cursor()
            # 工单主表
            cur.execute("""
                CREATE TABLE IF NOT EXISTS soc_tickets (
                    id TEXT PRIMARY KEY,
                    title TEXT NOT NULL,
                    description TEXT,
                    priority TEXT DEFAULT 'medium',
                    status TEXT DEFAULT 'open',
                    type TEXT DEFAULT 'other',
                    incident_id TEXT,
                    vulnerability_id TEXT,
                    assigned_to TEXT,
                    created_by TEXT,
                    due_date TEXT,
                    sla_deadline TEXT,
                    processing_log TEXT,
                    tenant_id TEXT DEFAULT 'default',
                    created_at TEXT NOT NULL,
                    updated_at TEXT NOT NULL
                )
            """)
            # 工单评论表
            cur.execute("""
                CREATE TABLE IF NOT EXISTS soc_ticket_comments (
                    id TEXT PRIMARY KEY,
                    ticket_id TEXT NOT NULL,
                    author TEXT,
                    content TEXT,
                    mentions TEXT,
                    created_at TEXT NOT NULL
                )
            """)
            # 工单模板表
            cur.execute("""
                CREATE TABLE IF NOT EXISTS soc_ticket_templates (
                    id TEXT PRIMARY KEY,
                    name TEXT NOT NULL,
                    type TEXT,
                    title TEXT,
                    description TEXT,
                    default_priority TEXT DEFAULT 'medium',
                    created_at TEXT NOT NULL
                )
            """)
            cur.execute("CREATE INDEX IF NOT EXISTS idx_soc_ticket_status ON soc_tickets(status)")
            cur.execute("CREATE INDEX IF NOT EXISTS idx_soc_ticket_pri ON soc_tickets(priority)")
            cur.execute("CREATE INDEX IF NOT EXISTS idx_soc_ticket_type ON soc_tickets(type)")
            cur.execute("CREATE INDEX IF NOT EXISTS idx_soc_ticket_assignee ON soc_tickets(assigned_to)")
            cur.execute("CREATE INDEX IF NOT EXISTS idx_soc_comment_ticket ON soc_ticket_comments(ticket_id)")
            conn.commit()
            log.info("✅ SOC工单表初始化完成")
        except Exception as e:
            log.error(f"SOC工单表初始化失败: {e}")
        finally:
            conn.close()

    # ==================== 工具方法 ====================

    @staticmethod
    def _now() -> str:
        return datetime.now().isoformat()

    def _row_to_dict(self, row) -> dict:
        if row is None:
            return {}
        item = dict(row)
        raw = item.get("processing_log")
        if isinstance(raw, str):
            try:
                item["processing_log"] = json.loads(raw)
            except (json.JSONDecodeError, TypeError):
                item["processing_log"] = []
        elif raw is None:
            item["processing_log"] = []
        return item

    def _append_log(self, ticket_id: str, entry: dict):
        conn = db._get_connection()
        try:
            row = conn.execute(
                "SELECT processing_log FROM soc_tickets WHERE id=?", (ticket_id,)
            ).fetchone()
            if not row:
                return
            try:
                logs = json.loads(row["processing_log"]) if row["processing_log"] else []
            except (json.JSONDecodeError, TypeError):
                logs = []
            logs.append(entry)
            conn.execute(
                "UPDATE soc_tickets SET processing_log=?, updated_at=? WHERE id=?",
                (json.dumps(logs, ensure_ascii=False), self._now(), ticket_id),
            )
            conn.commit()
        finally:
            conn.close()

    # ==================== 工单CRUD ====================

    def create_ticket(self, title: str, description: str = "",
                      priority: str = "medium", ticket_type: str = "other",
                      incident_id: str = None, vulnerability_id: str = None,
                      assigned_to: str = None, created_by: str = "system",
                      due_date: str = None, tenant_id: str = "default",
                      auto_assign: bool = True) -> dict:
        """创建工单，自动计算SLA截止时间，可选自动分配"""
        if priority not in VALID_PRIORITIES:
            priority = "medium"
        if ticket_type not in VALID_TICKET_TYPES:
            ticket_type = "other"

        ticket_id = str(uuid.uuid4())
        now = self._now()
        sla_hours = SLA_HOURS.get(priority, 72)
        sla_deadline = (datetime.now() + timedelta(hours=sla_hours)).isoformat()
        if not due_date:
            due_date = sla_deadline

        # 自动分配
        if not assigned_to and auto_assign:
            assigned_to = self._auto_pick_assignee(ticket_type)

        processing_log = [{"time": now, "action": "created",
                           "operator": created_by, "detail": f"工单创建，优先级={priority}"}]
        conn = db._get_connection()
        try:
            conn.execute("""
                INSERT INTO soc_tickets (
                    id, title, description, priority, status, type,
                    incident_id, vulnerability_id, assigned_to, created_by,
                    due_date, sla_deadline, processing_log, tenant_id,
                    created_at, updated_at
                ) VALUES (?, ?, ?, ?, 'open', ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """, (
                ticket_id, title, description, priority, ticket_type,
                incident_id, vulnerability_id, assigned_to, created_by,
                due_date, sla_deadline,
                json.dumps(processing_log, ensure_ascii=False), tenant_id, now, now,
            ))
            conn.commit()
        finally:
            conn.close()
        log.info(f"✅ 创建工单: {ticket_id} - [{priority}] {title} -> {assigned_to}")
        return self.get_ticket(ticket_id) or {"id": ticket_id}

    def get_ticket(self, ticket_id: str) -> Optional[dict]:
        conn = db._get_connection()
        try:
            row = conn.execute("SELECT * FROM soc_tickets WHERE id=?", (ticket_id,)).fetchone()
            return self._row_to_dict(row) if row else None
        finally:
            conn.close()

    def list_tickets(self, status: Optional[str] = None,
                     priority: Optional[str] = None,
                     ticket_type: Optional[str] = None,
                     assigned_to: Optional[str] = None,
                     incident_id: Optional[str] = None,
                     keyword: Optional[str] = None,
                     page: int = 1, page_size: int = 20) -> Dict[str, Any]:
        """查询工单列表，支持多维筛选与分页"""
        page = max(1, int(page))
        page_size = max(1, min(500, int(page_size)))
        where = ["1=1"]
        params: list = []
        if status:
            where.append("status = ?")
            params.append(status)
        if priority:
            where.append("priority = ?")
            params.append(priority)
        if ticket_type:
            where.append("type = ?")
            params.append(ticket_type)
        if assigned_to:
            where.append("assigned_to = ?")
            params.append(assigned_to)
        if incident_id:
            where.append("incident_id = ?")
            params.append(incident_id)
        if keyword:
            where.append("(title LIKE ? OR description LIKE ?)")
            like = f"%{keyword}%"
            params.extend([like, like])
        where_sql = " AND ".join(where)
        conn = db._get_connection()
        try:
            total = conn.execute(
                f"SELECT COUNT(*) c FROM soc_tickets WHERE {where_sql}", params
            ).fetchone()["c"]
            rows = conn.execute(
                f"""SELECT * FROM soc_tickets WHERE {where_sql}
                    ORDER BY created_at DESC LIMIT ? OFFSET ?""",
                params + [page_size, (page - 1) * page_size],
            ).fetchall()
            return {"items": [self._row_to_dict(r) for r in rows],
                    "total": total, "page": page, "page_size": page_size}
        finally:
            conn.close()

    def update_ticket(self, ticket_id: str, operator: str = "system",
                      **fields) -> Optional[dict]:
        """更新工单字段"""
        allowed = {"title", "description", "priority", "status", "type",
                   "incident_id", "vulnerability_id", "assigned_to", "due_date"}
        updates = []
        params: list = []
        for k, v in fields.items():
            if k in allowed and v is not None:
                updates.append(f"{k} = ?")
                params.append(v)
        if not updates:
            return self.get_ticket(ticket_id)
        updates.append("updated_at = ?")
        params.append(self._now())
        params.append(ticket_id)
        conn = db._get_connection()
        try:
            conn.execute(
                f"UPDATE soc_tickets SET {', '.join(updates)} WHERE id=?", params
            )
            conn.commit()
        finally:
            conn.close()
        self._append_log(ticket_id, {"time": self._now(), "action": "update",
                                     "operator": operator, "detail": fields})
        return self.get_ticket(ticket_id)

    def assign_ticket(self, ticket_id: str, assignee: str = None,
                      operator: str = "system",
                      strategy: str = "auto") -> Optional[dict]:
        """分配工单：assignee为空时按strategy自动分配

        strategy:
            - auto: 综合技能匹配 + 负载均衡
            - round_robin: 轮询当前open/in_progress最少者
            - skill: 仅按技能标签匹配
        """
        ticket = self.get_ticket(ticket_id)
        if not ticket:
            return None
        if not assignee:
            if strategy == "round_robin":
                assignee = self._pick_least_loaded()
            else:
                assignee = self._auto_pick_assignee(ticket.get("type", "other"))
        now = self._now()
        conn = db._get_connection()
        try:
            conn.execute(
                "UPDATE soc_tickets SET assigned_to=?, updated_at=? WHERE id=?",
                (assignee, now, ticket_id),
            )
            conn.commit()
        finally:
            conn.close()
        self._append_log(ticket_id, {"time": now, "action": "assign",
                                     "operator": operator, "assignee": assignee,
                                     "strategy": strategy})
        log.info(f"工单 {ticket_id} 分配给 {assignee}（策略={strategy}）")
        return self.get_ticket(ticket_id)

    def _auto_pick_assignee(self, ticket_type: str) -> str:
        """按技能+负载自动选择处理人"""
        skills = SKILL_MAP.get(ticket_type, ["soc"])
        # 候选=技能标签对应的虚拟成员
        candidates = [f"{skill}_engineer" for skill in skills]
        return self._pick_least_loaded(candidates)

    def _pick_least_loaded(self, candidates: List[str] = None) -> str:
        """选择当前open/in_progress工单最少的人（轮询负载均衡）"""
        conn = db._get_connection()
        try:
            rows = conn.execute(
                """SELECT assigned_to, COUNT(*) c FROM soc_tickets
                   WHERE status IN ('open','in_progress') AND assigned_to IS NOT NULL
                   GROUP BY assigned_to"""
            ).fetchall()
            load = {r["assigned_to"]: r["c"] for r in rows}
            pool = candidates or list(load.keys()) or ["soc_engineer"]
            # 选择负载最小者，平局时按名字取第一个（稳定）
            best = sorted(pool, key=lambda x: (load.get(x, 0), x))[0]
            return best
        finally:
            conn.close()

    # ==================== 评论与模板 ====================

    def add_comment(self, ticket_id: str, content: str, author: str = "system",
                    mentions: list = None) -> dict:
        """添加工单评论"""
        comment_id = str(uuid.uuid4())
        now = self._now()
        conn = db._get_connection()
        try:
            conn.execute("""
                INSERT INTO soc_ticket_comments (id, ticket_id, author, content, mentions, created_at)
                VALUES (?, ?, ?, ?, ?, ?)
            """, (comment_id, ticket_id, author, content,
                  json.dumps(mentions or [], ensure_ascii=False), now))
            conn.commit()
        finally:
            conn.close()
        self._append_log(ticket_id, {"time": now, "action": "comment",
                                     "operator": author, "comment": content})
        return {"id": comment_id, "ticket_id": ticket_id, "author": author,
                "content": content, "created_at": now}

    def list_comments(self, ticket_id: str) -> List[dict]:
        conn = db._get_connection()
        try:
            rows = conn.execute(
                "SELECT * FROM soc_ticket_comments WHERE ticket_id=? ORDER BY created_at ASC",
                (ticket_id,),
            ).fetchall()
            result = []
            for r in rows:
                item = dict(r)
                raw = item.get("mentions")
                if isinstance(raw, str):
                    try:
                        item["mentions"] = json.loads(raw)
                    except (json.JSONDecodeError, TypeError):
                        item["mentions"] = []
                result.append(item)
            return result
        finally:
            conn.close()

    def list_templates(self) -> List[dict]:
        conn = db._get_connection()
        try:
            rows = conn.execute(
                "SELECT * FROM soc_ticket_templates ORDER BY created_at DESC"
            ).fetchall()
            return [dict(r) for r in rows]
        finally:
            conn.close()

    def create_template(self, name: str, ticket_type: str = "other",
                        title: str = "", description: str = "",
                        default_priority: str = "medium") -> dict:
        """创建工单模板"""
        tpl_id = str(uuid.uuid4())
        now = self._now()
        conn = db._get_connection()
        try:
            conn.execute("""
                INSERT INTO soc_ticket_templates (id, name, type, title, description,
                                                  default_priority, created_at)
                VALUES (?, ?, ?, ?, ?, ?, ?)
            """, (tpl_id, name, ticket_type, title, description, default_priority, now))
            conn.commit()
        finally:
            conn.close()
        return {"id": tpl_id, "name": name, "type": ticket_type,
                "title": title, "description": description,
                "default_priority": default_priority}

    # ==================== 统计与SLA ====================

    def get_ticket_stats(self) -> dict:
        """工单统计：按状态/优先级/类型/分配人"""
        conn = db._get_connection()
        try:
            def group_by(col: str) -> dict:
                rows = conn.execute(
                    f"SELECT {col} AS k, COUNT(*) c FROM soc_tickets GROUP BY {col}"
                ).fetchall()
                return {r["k"]: r["c"] for r in rows}

            stats = {
                "total": conn.execute("SELECT COUNT(*) c FROM soc_tickets").fetchone()["c"],
                "open": conn.execute("SELECT COUNT(*) c FROM soc_tickets WHERE status='open'").fetchone()["c"],
                "in_progress": conn.execute("SELECT COUNT(*) c FROM soc_tickets WHERE status='in_progress'").fetchone()["c"],
                "resolved": conn.execute("SELECT COUNT(*) c FROM soc_tickets WHERE status='resolved'").fetchone()["c"],
                "closed": conn.execute("SELECT COUNT(*) c FROM soc_tickets WHERE status='closed'").fetchone()["c"],
                "by_priority": group_by("priority"),
                "by_type": group_by("type"),
                "by_assignee": group_by("assigned_to"),
            }
            return stats
        finally:
            conn.close()

    def check_sla(self) -> Dict[str, Any]:
        """检查SLA：超时未完成工单自动升级优先级

        Returns:
            {"overdue_count": int, "escalated": [...]}
        """
        now_iso = self._now()
        conn = db._get_connection()
        try:
            rows = conn.execute(
                """SELECT id, title, priority, sla_deadline, assigned_to FROM soc_tickets
                   WHERE status IN ('open','in_progress')
                   AND sla_deadline IS NOT NULL AND sla_deadline < ?""",
                (now_iso,),
            ).fetchall()
            order = ["low", "medium", "high", "urgent"]
            escalated = []
            for r in rows:
                pri = r["priority"]
                idx = order.index(pri) if pri in order else 1
                new_pri = order[min(idx + 1, len(order) - 1)]
                conn.execute(
                    "UPDATE soc_tickets SET priority=?, updated_at=? WHERE id=?",
                    (new_pri, now_iso, r["id"]),
                )
                escalated.append({"id": r["id"], "title": r["title"],
                                  "from": pri, "to": new_pri,
                                  "sla_deadline": r["sla_deadline"]})
            conn.commit()
            log.warning(f"⚠️ SLA超时升级 {len(escalated)} 张工单")
            return {"overdue_count": len(rows), "escalated": escalated}
        except Exception as e:
            log.error(f"SLA检查失败: {e}")
            return {"overdue_count": 0, "error": str(e)}
        finally:
            conn.close()


# 全局单例
ticket_manager = TicketManager()
