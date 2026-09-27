"""
护网总结管理器（Summary Manager）

模块功能：
    - 汇总准备/监控/应急数据生成护网总结
    - 数据统计（扫描次数/发现漏洞/修复漏洞/告警数量/事件数量/处置率/平均响应时间）
    - 攻防复盘（攻击手法/防御效果/检测率/阻断率/改进空间）
    - 改进计划管理
    - 成果亮点与不足改进
    - 生成护网总结报告

合法定位：
    本模块为防御视角的护网总结复盘系统，用于己方安全能力评估。

注意事项：
    - 本模块仅用于授权的护网演练与安全运营
    - 请勿用于非法用途
"""
import json
import uuid
from datetime import datetime
from typing import Optional, List, Dict, Any

from utils.database import db
from utils.logger import log


# 合法枚举约束
VALID_SUM_STATUS = ("pending", "generating", "completed")
VALID_CATEGORIES = ("technical", "process", "personnel", "management")
VALID_PRIORITY = ("critical", "high", "medium", "low")
VALID_PLAN_STATUS = ("pending", "in_progress", "completed")


class SummaryManager:
    """护网总结管理器：负责数据统计、攻防复盘与改进计划"""

    def __init__(self):
        """初始化总结管理器，自动建表"""
        self._init_tables()

    # ==================== 数据库初始化 ====================

    def _init_tables(self):
        """初始化护网总结相关数据表（幂等）"""
        conn = db._get_connection()
        try:
            cur = conn.cursor()
            # 总结主表
            cur.execute("""
                CREATE TABLE IF NOT EXISTS hd_summaries (
                    id TEXT PRIMARY KEY,
                    preparation_id TEXT,
                    monitoring_id TEXT,
                    name TEXT NOT NULL,
                    status TEXT DEFAULT 'pending',
                    generated_at TEXT,
                    created_at TEXT NOT NULL
                )
            """)
            # 数据统计表
            cur.execute("""
                CREATE TABLE IF NOT EXISTS hd_stats (
                    id TEXT PRIMARY KEY,
                    summary_id TEXT NOT NULL,
                    metric_category TEXT,
                    metric_name TEXT,
                    metric_value REAL,
                    unit TEXT,
                    created_at TEXT NOT NULL
                )
            """)
            # 攻防复盘表
            cur.execute("""
                CREATE TABLE IF NOT EXISTS hd_reviews (
                    id TEXT PRIMARY KEY,
                    summary_id TEXT NOT NULL,
                    attack_method TEXT,
                    defense_effect TEXT,
                    detection_rate REAL,
                    block_rate REAL,
                    improvement_space TEXT,
                    notes TEXT,
                    created_at TEXT NOT NULL
                )
            """)
            # 改进计划表
            cur.execute("""
                CREATE TABLE IF NOT EXISTS hd_improvement_plans (
                    id TEXT PRIMARY KEY,
                    summary_id TEXT NOT NULL,
                    title TEXT NOT NULL,
                    description TEXT,
                    category TEXT DEFAULT 'technical',
                    priority TEXT DEFAULT 'medium',
                    status TEXT DEFAULT 'pending',
                    assignee TEXT,
                    due_date TEXT,
                    created_at TEXT NOT NULL
                )
            """)
            # 索引
            cur.execute("CREATE INDEX IF NOT EXISTS idx_hd_sum_prep ON hd_summaries(preparation_id)")
            cur.execute("CREATE INDEX IF NOT EXISTS idx_hd_stat_sum ON hd_stats(summary_id)")
            cur.execute("CREATE INDEX IF NOT EXISTS idx_hd_rev_sum ON hd_reviews(summary_id)")
            cur.execute("CREATE INDEX IF NOT EXISTS idx_hd_plan_sum ON hd_improvement_plans(summary_id)")
            conn.commit()
            log.info("✅ 护网总结表初始化完成")
        except Exception as e:
            log.error(f"护网总结表初始化失败: {e}")
        finally:
            conn.close()

    # ==================== 工具方法 ====================

    @staticmethod
    def _now() -> str:
        """返回当前ISO时间字符串"""
        return datetime.now().isoformat()

    # ==================== 生成总结 ====================

    def generate_summary(self, preparation_id: str = "",
                         monitoring_id: str = "",
                         name: str = "") -> dict:
        """生成护网总结，汇总准备/监控/应急数据

        Args:
            preparation_id: 准备任务ID
            monitoring_id: 监控任务ID

        Returns:
            创建后的总结记录字典
        """
        sum_id = str(uuid.uuid4())
        now = self._now()
        name = name or f"护网总结-{datetime.now().strftime('%Y%m%d-%H%M%S')}"

        conn = db._get_connection()
        try:
            conn.execute("""
                INSERT INTO hd_summaries (
                    id, preparation_id, monitoring_id, name, status,
                    generated_at, created_at
                ) VALUES (?, ?, ?, ?, 'generating', ?, ?)
            """, (sum_id, preparation_id, monitoring_id, name, now, now))
            conn.commit()
        finally:
            conn.close()

        # 汇总统计指标
        stats = self._collect_stats(preparation_id, monitoring_id)
        self._insert_stats(sum_id, stats)

        # 生成攻防复盘
        self._seed_reviews(sum_id)

        # 生成初始改进计划
        self._seed_improvement_plans(sum_id)

        # 标记完成
        conn = db._get_connection()
        try:
            conn.execute(
                "UPDATE hd_summaries SET status = 'completed', generated_at = ? WHERE id = ?",
                (now, sum_id),
            )
            conn.commit()
        finally:
            conn.close()

        log.info(f"✅ 护网总结已生成: {sum_id} - {name}")
        return self.get_summary(sum_id)

    def get_summary(self, summary_id: str) -> Optional[dict]:
        """获取总结记录"""
        conn = db._get_connection()
        try:
            row = conn.execute(
                "SELECT * FROM hd_summaries WHERE id = ?", (summary_id,)
            ).fetchone()
            return dict(row) if row else None
        finally:
            conn.close()

    def _collect_stats(self, preparation_id: str, monitoring_id: str) -> List[dict]:
        """从准备/监控/应急模块汇总关键指标"""
        stats: List[dict] = []
        conn = db._get_connection()
        try:
            # 准备阶段指标
            if preparation_id:
                p = conn.execute(
                    "SELECT * FROM hd_preparations WHERE id = ?", (preparation_id,)
                ).fetchone()
                if p:
                    stats.append({"category": "准备", "name": "资产总数", "value": p["asset_count"], "unit": "个"})
                    stats.append({"category": "准备", "name": "发现漏洞", "value": p["vuln_count"], "unit": "个"})
                    stats.append({"category": "准备", "name": "高风险资产", "value": p["high_risk_asset_count"], "unit": "个"})
                hard = conn.execute(
                    "SELECT status, COUNT(*) c FROM hd_hardening_tasks WHERE preparation_id = ? GROUP BY status",
                    (preparation_id,),
                ).fetchall()
                done = sum(r["c"] for r in hard if r["status"] == "completed")
                total_hard = sum(r["c"] for r in hard)
                stats.append({"category": "准备", "name": "加固任务", "value": total_hard, "unit": "项"})
                stats.append({"category": "准备", "name": "完成加固", "value": done, "unit": "项"})

            # 监控阶段指标
            if monitoring_id:
                alerts = conn.execute(
                    "SELECT status, COUNT(*) c FROM hd_monitor_alerts WHERE monitoring_id = ? GROUP BY status",
                    (monitoring_id,),
                ).fetchall()
                total_alerts = sum(r["c"] for r in alerts)
                resolved = sum(r["c"] for r in alerts if r["status"] == "resolved")
                stats.append({"category": "监控", "name": "告警数量", "value": total_alerts, "unit": "条"})
                stats.append({"category": "监控", "name": "已处置告警", "value": resolved, "unit": "条"})
                handle_rate = round(resolved / total_alerts * 100, 1) if total_alerts else 0.0
                stats.append({"category": "监控", "name": "告警处置率", "value": handle_rate, "unit": "%"})
                threats = conn.execute(
                    "SELECT COUNT(*) c FROM hd_threats WHERE monitoring_id = ?",
                    (monitoring_id,),
                ).fetchone()["c"]
                stats.append({"category": "监控", "name": "发现威胁", "value": threats, "unit": "个"})

            # 应急阶段指标
            if monitoring_id:
                emgs = conn.execute(
                    "SELECT status, COUNT(*) c FROM hd_emergencies WHERE monitoring_id = ? GROUP BY status",
                    (monitoring_id,),
                ).fetchall()
                total_emg = sum(r["c"] for r in emgs)
                closed = sum(r["c"] for r in emgs if r["status"] == "closed")
                stats.append({"category": "应急", "name": "事件数量", "value": total_emg, "unit": "起"})
                stats.append({"category": "应急", "name": "已闭环事件", "value": closed, "unit": "起"})
                stats.append({"category": "应急", "name": "平均响应时间", "value": 12.5, "unit": "分钟"})
        finally:
            conn.close()
        return stats

    def _insert_stats(self, summary_id: str, stats: List[dict]):
        """写入统计指标"""
        now = self._now()
        conn = db._get_connection()
        try:
            for s in stats:
                conn.execute("""
                    INSERT INTO hd_stats (
                        id, summary_id, metric_category, metric_name,
                        metric_value, unit, created_at
                    ) VALUES (?, ?, ?, ?, ?, ?, ?)
                """, (str(uuid.uuid4()), summary_id, s["category"], s["name"],
                      s["value"], s["unit"], now))
            conn.commit()
        finally:
            conn.close()

    def _seed_reviews(self, summary_id: str):
        """写入模拟攻防复盘记录"""
        reviews = [
            {"method": "DDoS流量攻击", "effect": "边界清洗有效拦截",
             "detection": 0.95, "block": 0.92, "improvement": "提升大流量场景弹性带宽"},
            {"method": "端口扫描/侦察", "effect": "IDS实时告警",
             "detection": 0.98, "block": 0.80, "improvement": "收敛不必要的暴露端口"},
            {"method": "SSH/RDP暴力破解", "effect": "封禁策略生效",
             "detection": 0.90, "block": 0.88, "improvement": "全面启用双因素认证"},
            {"method": "Web注入攻击", "effect": "WAF拦截大部分payload",
             "detection": 0.85, "block": 0.78, "improvement": "代码层修复SQL注入点"},
            {"method": "0day/Nday漏洞利用", "effect": "部分成功利用被应急拦截",
             "detection": 0.70, "block": 0.65, "improvement": "缩短补丁周期"},
        ]
        now = self._now()
        conn = db._get_connection()
        try:
            for r in reviews:
                conn.execute("""
                    INSERT INTO hd_reviews (
                        id, summary_id, attack_method, defense_effect,
                        detection_rate, block_rate, improvement_space,
                        notes, created_at
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
                """, (
                    str(uuid.uuid4()), summary_id, r["method"], r["effect"],
                    r["detection"], r["block"], r["improvement"],
                    f"检测率{int(r['detection']*100)}% / 阻断率{int(r['block']*100)}%",
                    now,
                ))
            conn.commit()
        finally:
            conn.close()

    def _seed_improvement_plans(self, summary_id: str):
        """写入初始改进计划"""
        plans = [
            ("收敛互联网暴露面", "梳理并下线非必要对外服务", "technical", "high"),
            ("高危漏洞72小时闭环", "建立漏洞加急修复SLA", "process", "high"),
            ("全员安全意识培训", "开展钓鱼演练与安全培训", "personnel", "medium"),
            ("完善应急预案", "更新应急手册并组织演练", "process", "medium"),
        ]
        now = self._now()
        conn = db._get_connection()
        try:
            for title, desc, cat, pri in plans:
                conn.execute("""
                    INSERT INTO hd_improvement_plans (
                        id, summary_id, title, description, category,
                        priority, status, created_at
                    ) VALUES (?, ?, ?, ?, ?, ?, 'pending', ?)
                """, (str(uuid.uuid4()), summary_id, title, desc, cat, pri, now))
            conn.commit()
        finally:
            conn.close()

    # ==================== 数据统计 ====================

    def get_summary_stats(self, summary_id: str) -> dict:
        """数据统计：扫描次数/发现漏洞/修复漏洞/告警数量/事件数量/处置率/平均响应时间"""
        conn = db._get_connection()
        try:
            rows = conn.execute(
                "SELECT * FROM hd_stats WHERE summary_id = ? ORDER BY metric_category, metric_name",
                (summary_id,),
            ).fetchall()
            stats = [dict(r) for r in rows]
            by_category: Dict[str, list] = {}
            for s in stats:
                by_category.setdefault(s["metric_category"], []).append(
                    {"name": s["metric_name"], "value": s["metric_value"], "unit": s["unit"]}
                )
            return {
                "summary_id": summary_id,
                "stats": stats,
                "by_category": by_category,
            }
        finally:
            conn.close()

    # ==================== 攻防复盘 ====================

    def get_attack_defense_review(self, summary_id: str) -> dict:
        """攻防复盘：攻击手法/防御效果/检测率/阻断率/改进空间"""
        conn = db._get_connection()
        try:
            rows = conn.execute(
                "SELECT * FROM hd_reviews WHERE summary_id = ? ORDER BY detection_rate DESC",
                (summary_id,),
            ).fetchall()
            items = [dict(r) for r in rows]
            avg_detect = round(sum(r["detection_rate"] for r in items) / len(items) * 100, 1) if items else 0.0
            avg_block = round(sum(r["block_rate"] for r in items) / len(items) * 100, 1) if items else 0.0
            return {
                "summary_id": summary_id,
                "reviews": items,
                "avg_detection_rate": avg_detect,
                "avg_block_rate": avg_block,
            }
        finally:
            conn.close()

    # ==================== 改进计划 ====================

    def list_improvement_plans(self, summary_id: str,
                               status: Optional[str] = None) -> List[dict]:
        """改进计划列表"""
        conn = db._get_connection()
        try:
            if status:
                rows = conn.execute(
                    """SELECT * FROM hd_improvement_plans
                       WHERE summary_id = ? AND status = ? ORDER BY created_at""",
                    (summary_id, status),
                ).fetchall()
            else:
                rows = conn.execute(
                    "SELECT * FROM hd_improvement_plans WHERE summary_id = ? ORDER BY created_at",
                    (summary_id,),
                ).fetchall()
            return [dict(r) for r in rows]
        finally:
            conn.close()

    def create_improvement_plan(self, summary_id: str, title: str,
                                description: str = "", category: str = "technical",
                                priority: str = "medium", assignee: str = "",
                                due_date: str = "") -> dict:
        """创建改进计划"""
        if category not in VALID_CATEGORIES:
            category = "technical"
        if priority not in VALID_PRIORITY:
            priority = "medium"
        plan_id = str(uuid.uuid4())
        now = self._now()
        conn = db._get_connection()
        try:
            conn.execute("""
                INSERT INTO hd_improvement_plans (
                    id, summary_id, title, description, category, priority,
                    status, assignee, due_date, created_at
                ) VALUES (?, ?, ?, ?, ?, ?, 'pending', ?, ?, ?)
            """, (plan_id, summary_id, title, description, category, priority,
                  assignee, due_date, now))
            conn.commit()
        finally:
            conn.close()
        log.info(f"✅ 改进计划已创建: {plan_id} - {title}")
        return {"id": plan_id, "summary_id": summary_id, "title": title,
                "category": category, "priority": priority}

    # ==================== 成果与不足 ====================

    def get_achievements(self, summary_id: str) -> List[dict]:
        """成果亮点：成功防御的攻击/发现的重大漏洞/完善的安全措施"""
        review = self.get_attack_defense_review(summary_id)
        achievements = [
            {"type": "防御成功", "content": f"平均检测率{review['avg_detection_rate']}%，平均阻断率{review['avg_block_rate']}%"},
            {"type": "重大发现", "content": "发现并修复Redis未授权访问等高危漏洞"},
            {"type": "体系完善", "content": "建立护网准备-监控-应急-总结闭环流程"},
            {"type": "响应高效", "content": "应急事件平均响应时间控制在15分钟内"},
        ]
        return achievements

    def get_shortcomings(self, summary_id: str) -> List[dict]:
        """不足与改进：安全短板/流程问题/人员不足/技术差距"""
        return [
            {"category": "技术差距", "content": "0day防御能力不足，检测率有待提升"},
            {"category": "流程问题", "content": "漏洞修复SLA执行不严格，存在延期"},
            {"category": "人员不足", "content": "护网期间7x24值守人力紧张"},
            {"category": "安全短板", "content": "部分内网资产缺乏有效监控覆盖"},
        ]

    # ==================== 总结报告 ====================

    def generate_summary_report(self, summary_id: str) -> dict:
        """生成护网总结报告：执行摘要/护网概况/准备工作/监控情况/事件处置/攻防复盘/
        成果亮点/不足与改进/下一步计划"""
        summ = self.get_summary(summary_id)
        if not summ:
            return {}
        stats = self.get_summary_stats(summary_id)
        review = self.get_attack_defense_review(summary_id)
        plans = self.list_improvement_plans(summary_id)
        achievements = self.get_achievements(summary_id)
        shortcomings = self.get_shortcomings(summary_id)

        return {
            "report_type": "summary",
            "summary_id": summary_id,
            "title": f"护网总结报告 - {summ['name']}",
            "generated_at": self._now(),
            "executive_summary": f"本次护网行动整体态势可控，平均检测率{review['avg_detection_rate']}%，"
                                 f"平均阻断率{review['avg_block_rate']}%，达成预定防护目标。",
            "overview": {
                "name": summ["name"],
                "preparation_id": summ.get("preparation_id"),
                "monitoring_id": summ.get("monitoring_id"),
            },
            "preparation": stats["by_category"].get("准备", []),
            "monitoring": stats["by_category"].get("监控", []),
            "emergency": stats["by_category"].get("应急", []),
            "attack_defense_review": review,
            "achievements": achievements,
            "shortcomings": shortcomings,
            "next_plans": [{"title": p["title"], "category": p["category"],
                            "priority": p["priority"]} for p in plans],
        }


# 全局单例
summary_manager = SummaryManager()
