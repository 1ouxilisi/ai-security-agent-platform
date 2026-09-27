"""
SOC仪表盘数据生成器（SOC Dashboard）

模块功能：
    - 实时概览指标（活跃事件/告警/工单/今日新增/MTTR/MTTD）
    - 事件与告警趋势
    - 工单看板与SLA合规率
    - MTTR/MTTD 计算
    - 资产×事件类型风险热力图

所有数据从数据库实时查询计算，不做缓存。

合法定位：
    本模块为防御视角的安全运营可视化统计。

注意事项：
    - 本模块仅用于授权的安全运营
    - 请勿用于非法用途
"""
from datetime import datetime, timedelta
from typing import Optional, List, Dict, Any

from utils.database import db
from utils.logger import log


class SOCDashboard:
    """SOC仪表盘数据聚合器"""

    def __init__(self):
        """初始化仪表盘生成器"""
        log.info("✅ SOC仪表盘生成器初始化完成")

    # ==================== 工具方法 ====================

    @staticmethod
    def _now() -> str:
        return datetime.now().isoformat()

    @staticmethod
    def _parse_dt(s: Optional[str]) -> Optional[datetime]:
        """宽松解析ISO时间字符串"""
        if not s:
            return None
        try:
            return datetime.fromisoformat(s)
        except (ValueError, TypeError):
            return None

    # ==================== 概览 ====================

    def get_overview(self) -> dict:
        """实时概览：6个核心指标"""
        today_start = datetime.now().replace(hour=0, minute=0, second=0, microsecond=0).isoformat()
        conn = db._get_connection()
        try:
            active_incidents = conn.execute(
                """SELECT COUNT(*) c FROM soc_incidents
                   WHERE status IN ('new','analyzing')"""
            ).fetchone()["c"]
            active_alerts = conn.execute(
                "SELECT COUNT(*) c FROM soc_alerts WHERE status='active'"
            ).fetchone()["c"]
            pending_tickets = conn.execute(
                """SELECT COUNT(*) c FROM soc_tickets
                   WHERE status IN ('open','in_progress')"""
            ).fetchone()["c"]
            today_incidents = conn.execute(
                "SELECT COUNT(*) c FROM soc_incidents WHERE discovered_at >= ?",
                (today_start,),
            ).fetchone()["c"]

            # 平均响应时间（小时）：analyzed_at - discovered_at
            row = conn.execute(
                """SELECT AVG((julianday(analyzed_at) - julianday(discovered_at)) * 24.0) AS avg_resp
                   FROM soc_incidents
                   WHERE analyzed_at IS NOT NULL AND discovered_at IS NOT NULL"""
            ).fetchone()
            avg_response_hours = round(row["avg_resp"], 2) if row and row["avg_resp"] else 0.0

            # 平均解决时间（小时）：resolved_at - discovered_at
            row = conn.execute(
                """SELECT AVG((julianday(resolved_at) - julianday(discovered_at)) * 24.0) AS avg_res
                   FROM soc_incidents
                   WHERE resolved_at IS NOT NULL AND discovered_at IS NOT NULL"""
            ).fetchone()
            avg_resolution_hours = round(row["avg_res"], 2) if row and row["avg_res"] else 0.0

            return {
                "active_incidents": active_incidents,
                "active_alerts": active_alerts,
                "pending_tickets": pending_tickets,
                "today_new_incidents": today_incidents,
                "avg_response_hours": avg_response_hours,
                "avg_resolution_hours": avg_resolution_hours,
                "generated_at": self._now(),
            }
        finally:
            conn.close()

    # ==================== 趋势 ====================

    def get_incident_trends(self, days: int = 14) -> dict:
        """事件趋势：按天数量 + 严重程度分布 + 类型分布"""
        since = (datetime.now() - timedelta(days=days)).isoformat()
        conn = db._get_connection()
        try:
            # 按天趋势
            rows = conn.execute(
                """SELECT substr(discovered_at, 1, 10) AS d, COUNT(*) c
                   FROM soc_incidents WHERE discovered_at >= ?
                   GROUP BY d ORDER BY d""",
                (since,),
            ).fetchall()
            daily = [{"date": r["d"], "count": r["c"]} for r in rows]

            # 严重程度分布
            rows = conn.execute(
                """SELECT severity, COUNT(*) c FROM soc_incidents
                   WHERE discovered_at >= ? GROUP BY severity""",
                (since,),
            ).fetchall()
            sev_dist = {r["severity"]: r["c"] for r in rows}

            # 类型分布
            rows = conn.execute(
                """SELECT category, COUNT(*) c FROM soc_incidents
                   WHERE discovered_at >= ? GROUP BY category""",
                (since,),
            ).fetchall()
            cat_dist = {r["category"]: r["c"] for r in rows}

            return {"daily": daily, "severity_distribution": sev_dist,
                    "category_distribution": cat_dist, "days": days}
        finally:
            conn.close()

    def get_alert_trends(self, days: int = 7) -> dict:
        """告警趋势：按天数量 + 来源分布 + 规则TOP10"""
        since = (datetime.now() - timedelta(days=days)).isoformat()
        conn = db._get_connection()
        try:
            rows = conn.execute(
                """SELECT substr(triggered_at, 1, 10) AS d, COUNT(*) c
                   FROM soc_alerts WHERE triggered_at >= ?
                   GROUP BY d ORDER BY d""",
                (since,),
            ).fetchall()
            daily = [{"date": r["d"], "count": r["c"]} for r in rows]

            rows = conn.execute(
                """SELECT source, COUNT(*) c FROM soc_alerts
                   WHERE triggered_at >= ? GROUP BY source""",
                (since,),
            ).fetchall()
            source_dist = {r["source"]: r["c"] for r in rows}

            rows = conn.execute(
                """SELECT rule_id, COUNT(*) c FROM soc_alerts
                   WHERE triggered_at >= ? AND rule_id IS NOT NULL
                   GROUP BY rule_id ORDER BY c DESC LIMIT 10""",
                (since,),
            ).fetchall()
            top_rules = [{"rule_id": r["rule_id"], "count": r["c"]} for r in rows]

            return {"daily": daily, "source_distribution": source_dist,
                    "top_rules": top_rules, "days": days}
        finally:
            conn.close()

    # ==================== 工单看板 ====================

    def get_ticket_board(self) -> dict:
        """工单看板：按状态/优先级/分配人分组"""
        conn = db._get_connection()
        try:
            def group_by(col: str) -> dict:
                rows = conn.execute(
                    f"SELECT {col} AS k, COUNT(*) c FROM soc_tickets GROUP BY {col}"
                ).fetchall()
                return {r["k"] or "未分配": r["c"] for r in rows}

            # 按状态分列的工单ID
            columns: Dict[str, List[dict]] = {}
            for st in ("open", "in_progress", "resolved", "closed"):
                rows = conn.execute(
                    """SELECT id, title, priority, assigned_to FROM soc_tickets
                       WHERE status=? ORDER BY created_at DESC LIMIT 50""",
                    (st,),
                ).fetchall()
                columns[st] = [dict(r) for r in rows]

            return {"by_status": group_by("status"),
                    "by_priority": group_by("priority"),
                    "by_assignee": group_by("assigned_to"),
                    "columns": columns}
        finally:
            conn.close()

    # ==================== SLA / MTTR ====================

    def get_sla_compliance(self) -> dict:
        """SLA合规率 + 事件响应时间达标率"""
        now_iso = self._now()
        conn = db._get_connection()
        try:
            # 工单SLA：未超时(open/in_progress且未过deadline) + 已在deadline前关闭
            total_active = conn.execute(
                "SELECT COUNT(*) c FROM soc_tickets WHERE status IN ('open','in_progress')"
            ).fetchone()["c"]
            overdue_active = conn.execute(
                """SELECT COUNT(*) c FROM soc_tickets
                   WHERE status IN ('open','in_progress')
                   AND sla_deadline IS NOT NULL AND sla_deadline < ?""",
                (now_iso,),
            ).fetchone()["c"]
            sla_compliance = round(
                (total_active - overdue_active) / total_active * 100, 1
            ) if total_active else 100.0

            # 事件响应达标：analyzed_at在discovered_at之后24小时内
            total_analyzed = conn.execute(
                """SELECT COUNT(*) c FROM soc_incidents
                   WHERE analyzed_at IS NOT NULL"""
            ).fetchone()["c"]
            met = conn.execute(
                """SELECT COUNT(*) c FROM soc_incidents
                   WHERE analyzed_at IS NOT NULL AND discovered_at IS NOT NULL
                   AND (julianday(analyzed_at) - julianday(discovered_at)) <= 1.0"""
            ).fetchone()["c"]
            response_compliance = round(met / total_analyzed * 100, 1) if total_analyzed else 100.0

            return {
                "ticket_sla_compliance_pct": sla_compliance,
                "active_tickets": total_active,
                "overdue_tickets": overdue_active,
                "incident_response_compliance_pct": response_compliance,
                "total_analyzed_incidents": total_analyzed,
            }
        finally:
            conn.close()

    def get_mttr_mttd(self, days: int = 30) -> dict:
        """MTTD/MTTR/MTTR(解决)：单位小时

        - MTTD (Mean Time To Detect): discovered_at - 最早信号时间（近似用source=scan/ids时的created_at）
        - MTTR (Mean Time To Respond): analyzed_at - discovered_at
        - MTTR(Resolution): resolved_at - discovered_at
        """
        since = (datetime.now() - timedelta(days=days)).isoformat()
        conn = db._get_connection()
        try:
            # MTTR 响应
            row = conn.execute(
                """SELECT AVG((julianday(analyzed_at) - julianday(discovered_at)) * 24.0) v
                   FROM soc_incidents
                   WHERE analyzed_at IS NOT NULL AND discovered_at IS NOT NULL
                   AND discovered_at >= ?""",
                (since,),
            ).fetchone()
            mttr_respond = round(row["v"], 2) if row and row["v"] else 0.0

            # 解决
            row = conn.execute(
                """SELECT AVG((julianday(resolved_at) - julianday(discovered_at)) * 24.0) v
                   FROM soc_incidents
                   WHERE resolved_at IS NOT NULL AND discovered_at IS NOT NULL
                   AND discovered_at >= ?""",
                (since,),
            ).fetchone()
            mttr_resolve = round(row["v"], 2) if row and row["v"] else 0.0

            # MTTD：告警触发 -> 关联事件发现的平均间隔（小时）
            row = conn.execute(
                """SELECT AVG((julianday(i.discovered_at) - julianday(a.triggered_at)) * 24.0) v
                   FROM soc_alerts a JOIN soc_incidents i ON a.incident_id = i.id
                   WHERE a.triggered_at IS NOT NULL AND i.discovered_at IS NOT NULL
                   AND i.discovered_at >= ?""",
                (since,),
            ).fetchone()
            mttd = round(row["v"], 2) if row and row["v"] else 0.0

            return {"mttd_hours": mttd,
                    "mttr_respond_hours": mttr_respond,
                    "mttr_resolve_hours": mttr_resolve,
                    "window_days": days}
        finally:
            conn.close()

    # ==================== 风险热力图 ====================

    def get_risk_heatmap(self, days: int = 30) -> dict:
        """资产 × 事件类型 的风险热力图

        Returns:
            {"assets": [...], "categories": [...], "matrix": [[row...]]}
            cell值=该资产该类型的事件数量（含严重度加权）
        """
        since = (datetime.now() - timedelta(days=days)).isoformat()
        sev_weight = {"critical": 4, "high": 3, "medium": 2, "low": 1, "info": 0.5}
        conn = db._get_connection()
        try:
            rows = conn.execute(
                """SELECT asset_id, category, severity, COUNT(*) c
                   FROM soc_incidents
                   WHERE discovered_at >= ? AND asset_id IS NOT NULL
                   GROUP BY asset_id, category, severity""",
                (since,),
            ).fetchall()
        finally:
            conn.close()

        assets_set, cats_set = set(), set()
        cell: Dict[str, Dict[str, float]] = {}
        for r in rows:
            a = r["asset_id"]
            c = r["category"]
            w = sev_weight.get(r["severity"], 1)
            assets_set.add(a)
            cats_set.add(c)
            cell.setdefault(a, {})
            cell[a][c] = cell[a].get(c, 0.0) + r["c"] * w

        assets = sorted(assets_set)[:30]
        cats = sorted(cats_set)
        matrix = []
        for a in assets:
            matrix.append([round(cell.get(a, {}).get(c, 0.0), 1) for c in cats])
        return {"assets": assets, "categories": cats, "matrix": matrix,
                "window_days": days}


# 全局单例
soc_dashboard = SOCDashboard()
