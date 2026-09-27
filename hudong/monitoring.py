"""
护网持续监控器（Monitoring Manager）

模块功能：
    - 持续监控任务的启动/暂停/状态跟踪
    - 告警管理（DDoS/扫描/暴力破解/异常登录/Web攻击），支持确认与处置
    - 威胁检测（IOC匹配/异常行为/攻击特征/威胁情报关联）
    - 攻击监测（模拟检测生成告警）
    - 告警自动聚合（相同类型/相同资产）
    - 态势感知（整体态势/攻击趋势/威胁分布/资产风险变化）
    - 生成护网监控日报/周报

合法定位：
    本模块为防御视角的监测预警系统，用于己方资产的护网监控。

注意事项：
    - 本模块仅用于授权的护网演练与安全运营
    - 请勿用于非法用途
"""
import json
import uuid
import hashlib
import random
from datetime import datetime, timedelta
from typing import Optional, List, Dict, Any

from utils.database import db
from utils.logger import log


# 合法枚举约束
VALID_MON_STATUS = ("pending", "running", "paused", "completed")
VALID_ALERT_TYPE = ("ddos", "scan", "brute_force", "anomaly_login", "web_attack", "other")
VALID_ALERT_SEVERITY = ("critical", "high", "medium", "low")
VALID_ALERT_STATUS = ("active", "acknowledged", "resolved")
VALID_THREAT_STATUS = ("active", "mitigated", "expired")


class MonitoringManager:
    """护网持续监控器：负责监控、告警、威胁与态势"""

    def __init__(self):
        """初始化监控器，自动建表"""
        self._init_tables()

    # ==================== 数据库初始化 ====================

    def _init_tables(self):
        """初始化护网监控相关数据表（幂等）"""
        conn = db._get_connection()
        try:
            cur = conn.cursor()
            # 监控任务表
            cur.execute("""
                CREATE TABLE IF NOT EXISTS hd_monitorings (
                    id TEXT PRIMARY KEY,
                    preparation_id TEXT,
                    name TEXT NOT NULL,
                    status TEXT DEFAULT 'pending',
                    started_at TEXT,
                    ended_at TEXT,
                    alert_count INTEGER DEFAULT 0,
                    event_count INTEGER DEFAULT 0,
                    created_at TEXT NOT NULL
                )
            """)
            # 监控告警表
            cur.execute("""
                CREATE TABLE IF NOT EXISTS hd_monitor_alerts (
                    id TEXT PRIMARY KEY,
                    monitoring_id TEXT NOT NULL,
                    alert_type TEXT NOT NULL,
                    severity TEXT DEFAULT 'medium',
                    source TEXT,
                    title TEXT NOT NULL,
                    description TEXT,
                    asset_id TEXT,
                    status TEXT DEFAULT 'active',
                    detected_at TEXT NOT NULL,
                    details TEXT,
                    created_at TEXT NOT NULL
                )
            """)
            # 威胁表
            cur.execute("""
                CREATE TABLE IF NOT EXISTS hd_threats (
                    id TEXT PRIMARY KEY,
                    monitoring_id TEXT NOT NULL,
                    threat_type TEXT,
                    ioc TEXT,
                    value TEXT,
                    severity TEXT DEFAULT 'medium',
                    source TEXT,
                    first_seen TEXT,
                    last_seen TEXT,
                    status TEXT DEFAULT 'active',
                    created_at TEXT NOT NULL
                )
            """)
            # 索引
            cur.execute("CREATE INDEX IF NOT EXISTS idx_hd_mon_status ON hd_monitorings(status)")
            cur.execute("CREATE INDEX IF NOT EXISTS idx_hd_alert_mon ON hd_monitor_alerts(monitoring_id)")
            cur.execute("CREATE INDEX IF NOT EXISTS idx_hd_alert_type ON hd_monitor_alerts(alert_type)")
            cur.execute("CREATE INDEX IF NOT EXISTS idx_hd_alert_sev ON hd_monitor_alerts(severity)")
            cur.execute("CREATE INDEX IF NOT EXISTS idx_hd_alert_status ON hd_monitor_alerts(status)")
            cur.execute("CREATE INDEX IF NOT EXISTS idx_hd_threat_mon ON hd_threats(monitoring_id)")
            conn.commit()
            log.info("✅ 护网监控表初始化完成")
        except Exception as e:
            log.error(f"护网监控表初始化失败: {e}")
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
        raw = item.get("details")
        if isinstance(raw, str):
            try:
                item["details"] = json.loads(raw)
            except (json.JSONDecodeError, TypeError):
                item["details"] = {}
        elif raw is None:
            item["details"] = {}
        return item

    @staticmethod
    def _seed(mon_id: str) -> random.Random:
        """根据监控任务ID生成确定性随机源"""
        h = hashlib.md5(mon_id.encode("utf-8")).hexdigest()
        return random.Random(int(h[:8], 16))

    # ==================== 监控任务 ====================

    def start_monitoring(self, preparation_id: str = "", name: str = "") -> dict:
        """启动持续监控

        Args:
            preparation_id: 关联的准备任务ID（可选）
            name: 监控任务名称

        Returns:
            创建后的监控任务字典
        """
        mon_id = str(uuid.uuid4())
        now = self._now()
        name = name or f"护网监控-{datetime.now().strftime('%Y%m%d-%H%M%S')}"

        conn = db._get_connection()
        try:
            conn.execute("""
                INSERT INTO hd_monitorings (
                    id, preparation_id, name, status, started_at,
                    alert_count, event_count, created_at
                ) VALUES (?, ?, ?, 'running', ?, 0, 0, ?)
            """, (mon_id, preparation_id, name, now, now))
            conn.commit()
        finally:
            conn.close()

        # 启动即模拟一批攻击监测
        self.detect_attacks(mon_id)
        log.info(f"✅ 护网监控已启动: {mon_id} - {name}")
        return self.get_monitoring_status(mon_id)

    def get_monitoring_status(self, monitoring_id: str) -> Optional[dict]:
        """获取监控任务状态"""
        conn = db._get_connection()
        try:
            row = conn.execute(
                "SELECT * FROM hd_monitorings WHERE id = ?", (monitoring_id,)
            ).fetchone()
            return dict(row) if row else None
        finally:
            conn.close()

    def _refresh_counts(self, monitoring_id: str):
        """刷新监控任务的告警/事件计数"""
        conn = db._get_connection()
        try:
            alert_count = conn.execute(
                "SELECT COUNT(*) c FROM hd_monitor_alerts WHERE monitoring_id = ?",
                (monitoring_id,),
            ).fetchone()["c"]
            conn.execute(
                "UPDATE hd_monitorings SET alert_count = ? WHERE id = ?",
                (alert_count, monitoring_id),
            )
            conn.commit()
        finally:
            conn.close()

    # ==================== 告警管理 ====================

    def list_alerts(self, monitoring_id: str,
                    alert_type: Optional[str] = None,
                    severity: Optional[str] = None,
                    status: Optional[str] = None,
                    start_time: Optional[str] = None,
                    end_time: Optional[str] = None,
                    page: int = 1, page_size: int = 20) -> Dict[str, Any]:
        """告警列表，支持按类型/严重度/状态/时间筛选与分页"""
        page = max(1, int(page))
        page_size = max(1, min(500, int(page_size)))
        where = ["monitoring_id = ?"]
        params: list = [monitoring_id]
        if alert_type:
            where.append("alert_type = ?")
            params.append(alert_type)
        if severity:
            where.append("severity = ?")
            params.append(severity)
        if status:
            where.append("status = ?")
            params.append(status)
        if start_time:
            where.append("detected_at >= ?")
            params.append(start_time)
        if end_time:
            where.append("detected_at <= ?")
            params.append(end_time)
        where_sql = " AND ".join(where)

        conn = db._get_connection()
        try:
            total = conn.execute(
                f"SELECT COUNT(*) c FROM hd_monitor_alerts WHERE {where_sql}", params
            ).fetchone()["c"]
            rows = conn.execute(
                f"""SELECT * FROM hd_monitor_alerts WHERE {where_sql}
                    ORDER BY detected_at DESC LIMIT ? OFFSET ?""",
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

    def acknowledge_alert(self, alert_id: str) -> Optional[dict]:
        """确认告警：active -> acknowledged"""
        conn = db._get_connection()
        try:
            cur = conn.execute(
                "UPDATE hd_monitor_alerts SET status = 'acknowledged' WHERE id = ? AND status = 'active'",
                (alert_id,),
            )
            conn.commit()
            if cur.rowcount == 0:
                row = conn.execute("SELECT * FROM hd_monitor_alerts WHERE id = ?", (alert_id,)).fetchone()
                return self._row_to_dict(row) if row else None
            row = conn.execute("SELECT * FROM hd_monitor_alerts WHERE id = ?", (alert_id,)).fetchone()
            return self._row_to_dict(row) if row else None
        finally:
            conn.close()

    def resolve_alert(self, alert_id: str, result: str = "已处置") -> Optional[dict]:
        """处置告警：-> resolved"""
        conn = db._get_connection()
        try:
            conn.execute(
                "UPDATE hd_monitor_alerts SET status = 'resolved' WHERE id = ?",
                (alert_id,),
            )
            conn.commit()
            row = conn.execute("SELECT * FROM hd_monitor_alerts WHERE id = ?", (alert_id,)).fetchone()
            item = self._row_to_dict(row) if row else None
            if item:
                item["details"] = {**(item.get("details") or {}), "resolve_result": result}
            return item
        finally:
            conn.close()

    # ==================== 威胁检测 ====================

    def list_threats(self, monitoring_id: str,
                     threat_type: Optional[str] = None,
                     severity: Optional[str] = None) -> List[dict]:
        """威胁列表：IOC匹配/异常行为/攻击特征/威胁情报关联"""
        where = ["monitoring_id = ?"]
        params: list = [monitoring_id]
        if threat_type:
            where.append("threat_type = ?")
            params.append(threat_type)
        if severity:
            where.append("severity = ?")
            params.append(severity)
        conn = db._get_connection()
        try:
            rows = conn.execute(
                f"""SELECT * FROM hd_threats WHERE {" AND ".join(where)}
                    ORDER BY last_seen DESC""", params
            ).fetchall()
            return [dict(r) for r in rows]
        finally:
            conn.close()

    # ==================== 攻击监测（模拟） ====================

    def detect_attacks(self, monitoring_id: str, round_no: int = 1) -> List[dict]:
        """攻击监测：模拟检测DDoS/扫描/暴力破解/异常登录/Web攻击，生成告警

        Args:
            monitoring_id: 监控任务ID
            round_no: 监测轮次（用于区分多次调用）

        Returns:
            本轮新生成的告警列表
        """
        mon = self.get_monitoring_status(monitoring_id)
        if not mon:
            return []

        rng = self._seed(f"{monitoring_id}:detect:{round_no}")
        attack_templates = [
            ("ddos", "critical", "外部", "检测到DDoS攻击流量", "目标带宽被占满，流量峰值异常"),
            ("scan", "low", "外部", "端口扫描行为", "单源对多端口高频探测"),
            ("brute_force", "high", "外部", "SSH暴力破解", "5分钟内同一IP失败登录>100次"),
            ("anomaly_login", "medium", "外部", "异常时间/异地登录", "凌晨2点非常用IP登录管理后台"),
            ("web_attack", "high", "外部", "Web攻击尝试", "WAF检测到SQL注入/XSSpayload"),
        ]
        new_alerts = []
        now = self._now()
        conn = db._get_connection()
        try:
            # 每轮随机生成 3~6 条告警
            n = rng.randint(3, 6)
            for i in range(n):
                atype, sev, source, title, desc = attack_templates[
                    rng.randrange(len(attack_templates))]
                alert_id = str(uuid.uuid4())
                src_ip = f"{rng.randint(1,223)}.{rng.randint(0,255)}.{rng.randint(0,255)}.{rng.randint(1,254)}"
                asset_id = f"asset-{rng.randint(1,12):03d}"
                detected = (datetime.now() - timedelta(minutes=rng.randint(0, 120))).isoformat()
                details = {
                    "source_ip": src_ip,
                    "request_count": rng.randint(100, 50000),
                    "payload_samples": [f"payload-{i}"],
                    "confidence": round(rng.uniform(0.6, 0.99), 2),
                }
                conn.execute("""
                    INSERT INTO hd_monitor_alerts (
                        id, monitoring_id, alert_type, severity, source,
                        title, description, asset_id, status, detected_at,
                        details, created_at
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, 'active', ?, ?, ?)
                """, (
                    alert_id, monitoring_id, atype, sev, source,
                    title, desc, asset_id, detected,
                    json.dumps(details, ensure_ascii=False), now,
                ))
                # 同时写入威胁情报
                tid = str(uuid.uuid4())
                conn.execute("""
                    INSERT INTO hd_threats (
                        id, monitoring_id, threat_type, ioc, value, severity,
                        source, first_seen, last_seen, status, created_at
                    ) VALUES (?, ?, ?, 'ip', ?, ?, ?, ?, ?, 'active', ?)
                """, (
                    tid, monitoring_id, atype, src_ip, sev,
                    "威胁情报库+流量监测", detected, detected, now,
                ))
                new_alerts.append({
                    "id": alert_id, "alert_type": atype, "severity": sev,
                    "title": title, "source_ip": src_ip,
                })
            conn.commit()
        except Exception as e:
            log.error(f"攻击监测写入失败: {e}")
        finally:
            conn.close()

        self._refresh_counts(monitoring_id)
        log.info(f"✅ 监控 {monitoring_id} 第{round_no}轮监测，新增告警 {len(new_alerts)} 条")
        return new_alerts

    # ==================== 告警聚合 ====================

    def aggregate_alerts(self, monitoring_id: str) -> dict:
        """告警聚合：相同类型/相同资产的告警自动聚合"""
        conn = db._get_connection()
        try:
            rows = conn.execute(
                """SELECT alert_type, asset_id, COUNT(*) AS cnt, severity
                   FROM hd_monitor_alerts
                   WHERE monitoring_id = ? AND status = 'active'
                   GROUP BY alert_type, asset_id
                   HAVING cnt > 1""",
                (monitoring_id,),
            ).fetchall()
            groups = [dict(r) for r in rows]
            return {
                "monitoring_id": monitoring_id,
                "aggregated_groups": groups,
                "group_count": len(groups),
                "message": f"聚合出 {len(groups)} 组重复告警，建议合并处置",
            }
        finally:
            conn.close()

    # ==================== 态势感知 ====================

    def get_situation(self, monitoring_id: str) -> dict:
        """态势感知：整体安全态势/攻击趋势/威胁分布/资产风险变化"""
        conn = db._get_connection()
        try:
            # 按类型统计
            type_rows = conn.execute(
                """SELECT alert_type, COUNT(*) c FROM hd_monitor_alerts
                   WHERE monitoring_id = ? GROUP BY alert_type""",
                (monitoring_id,),
            ).fetchall()
            by_type = {r["alert_type"]: r["c"] for r in type_rows}

            # 按严重度统计
            sev_rows = conn.execute(
                """SELECT severity, COUNT(*) c FROM hd_monitor_alerts
                   WHERE monitoring_id = ? GROUP BY severity""",
                (monitoring_id,),
            ).fetchall()
            by_severity = {r["severity"]: r["c"] for r in sev_rows}

            # 按状态统计
            st_rows = conn.execute(
                """SELECT status, COUNT(*) c FROM hd_monitor_alerts
                   WHERE monitoring_id = ? GROUP BY status""",
                (monitoring_id,),
            ).fetchall()
            by_status = {r["status"]: r["c"] for r in st_rows}

            # 按天趋势
            trend_rows = conn.execute(
                """SELECT substr(detected_at,1,10) d, COUNT(*) c
                   FROM hd_monitor_alerts WHERE monitoring_id = ?
                   GROUP BY d ORDER BY d""",
                (monitoring_id,),
            ).fetchall()
            trend = [{"date": r["d"], "count": r["c"]} for r in trend_rows]

            threat_rows = conn.execute(
                """SELECT threat_type, COUNT(*) c FROM hd_threats
                   WHERE monitoring_id = ? AND status = 'active'
                   GROUP BY threat_type""",
                (monitoring_id,),
            ).fetchall()
            threat_dist = {r["threat_type"]: r["c"] for r in threat_rows}

            total = sum(by_severity.values())
            critical = by_severity.get("critical", 0)
            posture = "严峻" if critical > 0 else ("紧张" if by_severity.get("high", 0) > 2 else "平稳")
            resolved = by_status.get("resolved", 0)
            handle_rate = round(resolved / total * 100, 1) if total else 0.0

            return {
                "monitoring_id": monitoring_id,
                "overall_posture": posture,
                "total_alerts": total,
                "by_type": by_type,
                "by_severity": by_severity,
                "by_status": by_status,
                "attack_trend": trend,
                "threat_distribution": threat_dist,
                "handle_rate": handle_rate,
                "asset_risk_change": "较准备阶段下降" if resolved else "持续监测中",
            }
        finally:
            conn.close()

    # ==================== 监控报告 ====================

    def generate_monitoring_report(self, monitoring_id: str, period: str = "日报") -> dict:
        """生成护网监控日报/周报：监控概况/告警统计/威胁分析/处置情况/态势评估"""
        mon = self.get_monitoring_status(monitoring_id)
        if not mon:
            return {}
        situation = self.get_situation(monitoring_id)
        unacked = self.list_alerts(monitoring_id, status="active", page=1, page_size=1)

        now = self._now()
        return {
            "report_type": "monitoring",
            "monitoring_id": monitoring_id,
            "period": period,
            "title": f"护网监控{period} - {mon['name']}",
            "generated_at": now,
            "overview": {
                "name": mon["name"],
                "status": mon["status"],
                "started_at": mon["started_at"],
                "total_alerts": situation["total_alerts"],
            },
            "alert_stats": situation["by_severity"],
            "threat_analysis": situation["threat_distribution"],
            "handling": {
                "by_status": situation["by_status"],
                "handle_rate": situation["handle_rate"],
                "pending_acknowledge": unacked["total"],
            },
            "posture": situation["overall_posture"],
            "trend": situation["attack_trend"],
        }


# 全局单例
monitoring_manager = MonitoringManager()
