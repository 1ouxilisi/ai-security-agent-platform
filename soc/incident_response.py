"""
应急响应管理器（Incident Response，遵循 NIST SP 800-61）

模块功能：
    - 应急预案库管理
    - 为事件启动标准化响应流程：准备→识别→遏制→根除→恢复→总结
    - 响应任务跟踪与证据采集
    - 复盘报告（Debrief）生成
    - 应急演练记录

合法定位：
    本模块为防御视角的应急响应流程编排，所有操作均针对自有授权资产。

注意事项：
    - 本模块仅用于授权的安全运营
    - 请勿用于非法用途
"""
import json
import uuid
from datetime import datetime
from typing import Optional, List, Dict, Any

from utils.database import db
from utils.logger import log


# NIST SP 800-61 响应阶段
RESPONSE_PHASES = ["准备(Preparation)", "识别(Identification)", "遏制(Containment)",
                   "根除(Eradication)", "恢复(Recovery)", "总结(Lessons Learned)"]

# 各阶段默认任务模板
DEFAULT_PHASE_STEPS = {
    "准备(Preparation)": [
        "确认响应团队与值班联系人",
        "准备取证工具与隔离环境",
        "评估事件影响范围与业务连续性需求",
    ],
    "识别(Identification)": [
        "确认事件真实性，排除误报",
        "确定受影响资产与攻击路径",
        "记录事件时间线与IOC",
    ],
    "遏制(Containment)": [
        "隔离受影响资产（网络/主机）",
        "冻结相关账号与会话",
        "保留现场证据（内存/磁盘快照）",
    ],
    "根除(Eradication)": [
        "清除恶意程序/后门/异常账号",
        "修补被利用的漏洞",
        "重置被泄露凭证",
    ],
    "恢复(Recovery)": [
        "从干净备份恢复系统与数据",
        "验证系统完整性与业务功能",
        "加强监控与日志审计",
    ],
    "总结(Lessons Learned)": [
        "编写复盘报告",
        "更新检测规则与应急预案",
        "组织团队复盘会议",
    ],
}


class IncidentResponse:
    """应急响应管理器：预案/任务/证据/复盘/演练"""

    def __init__(self):
        """初始化应急响应管理器，自动建表"""
        self._init_tables()

    # ==================== 数据库初始化 ====================

    def _init_tables(self):
        """初始化应急响应相关数据表（幂等）"""
        conn = db._get_connection()
        try:
            cur = conn.cursor()
            # 应急预案表
            cur.execute("""
                CREATE TABLE IF NOT EXISTS soc_response_plans (
                    id TEXT PRIMARY KEY,
                    name TEXT NOT NULL,
                    incident_type TEXT,
                    severity TEXT,
                    steps TEXT,
                    responsible_roles TEXT,
                    communication_templates TEXT,
                    created_at TEXT NOT NULL
                )
            """)
            # 响应任务表
            cur.execute("""
                CREATE TABLE IF NOT EXISTS soc_response_tasks (
                    id TEXT PRIMARY KEY,
                    incident_id TEXT NOT NULL,
                    plan_id TEXT,
                    step_name TEXT NOT NULL,
                    description TEXT,
                    assignee TEXT,
                    status TEXT DEFAULT 'pending',
                    completed_at TEXT,
                    created_at TEXT NOT NULL
                )
            """)
            # 证据表
            cur.execute("""
                CREATE TABLE IF NOT EXISTS soc_response_evidence (
                    id TEXT PRIMARY KEY,
                    incident_id TEXT NOT NULL,
                    evidence_type TEXT,
                    description TEXT,
                    file_path TEXT,
                    hash TEXT,
                    collected_by TEXT,
                    collected_at TEXT NOT NULL
                )
            """)
            # 应急演练表
            cur.execute("""
                CREATE TABLE IF NOT EXISTS soc_response_exercises (
                    id TEXT PRIMARY KEY,
                    name TEXT NOT NULL,
                    exercise_type TEXT,
                    scenario TEXT,
                    participants TEXT,
                    result TEXT,
                    improvement_actions TEXT,
                    conducted_at TEXT NOT NULL,
                    created_at TEXT NOT NULL
                )
            """)
            cur.execute("CREATE INDEX IF NOT EXISTS idx_soc_resp_task_inc ON soc_response_tasks(incident_id)")
            cur.execute("CREATE INDEX IF NOT EXISTS idx_soc_resp_task_status ON soc_response_tasks(status)")
            cur.execute("CREATE INDEX IF NOT EXISTS idx_soc_resp_ev_inc ON soc_response_evidence(incident_id)")
            conn.commit()
            log.info("✅ SOC应急响应表初始化完成")
        except Exception as e:
            log.error(f"SOC应急响应表初始化失败: {e}")
        finally:
            conn.close()

    # ==================== 工具方法 ====================

    @staticmethod
    def _now() -> str:
        return datetime.now().isoformat()

    # ==================== 预案管理 ====================

    def list_plans(self, incident_type: Optional[str] = None) -> List[dict]:
        """列出应急预案"""
        conn = db._get_connection()
        try:
            sql = "SELECT * FROM soc_response_plans"
            params: list = []
            if incident_type:
                sql += " WHERE incident_type = ?"
                params.append(incident_type)
            sql += " ORDER BY created_at DESC"
            rows = conn.execute(sql, params).fetchall()
            result = []
            for r in rows:
                item = dict(r)
                for jf in ("steps", "responsible_roles", "communication_templates"):
                    raw = item.get(jf)
                    if isinstance(raw, str):
                        try:
                            item[jf] = json.loads(raw)
                        except (json.JSONDecodeError, TypeError):
                            item[jf] = [] if jf != "steps" else []
                result.append(item)
            return result
        finally:
            conn.close()

    def create_plan(self, name: str, incident_type: str = "other",
                    severity: str = "medium", steps: List[str] = None,
                    responsible_roles: List[str] = None,
                    communication_templates: Dict[str, str] = None) -> dict:
        """创建应急预案"""
        plan_id = str(uuid.uuid4())
        now = self._now()
        # 未提供steps时按默认阶段生成
        if not steps:
            steps = []
            for phase, task_list in DEFAULT_PHASE_STEPS.items():
                steps.append({"phase": phase, "tasks": task_list})
        conn = db._get_connection()
        try:
            conn.execute("""
                INSERT INTO soc_response_plans (
                    id, name, incident_type, severity, steps,
                    responsible_roles, communication_templates, created_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?)
            """, (
                plan_id, name, incident_type, severity,
                json.dumps(steps, ensure_ascii=False),
                json.dumps(responsible_roles or ["soc_oncall"], ensure_ascii=False),
                json.dumps(communication_templates or {}, ensure_ascii=False),
                now,
            ))
            conn.commit()
        finally:
            conn.close()
        log.info(f"✅ 创建应急预案: {plan_id} - {name}")
        return {"id": plan_id, "name": name, "incident_type": incident_type,
                "severity": severity, "steps": steps}

    # ==================== 响应流程 ====================

    def start_response(self, incident_id: str, plan_id: str = None,
                       assignee: str = "soc_oncall") -> Dict[str, Any]:
        """为事件启动应急响应，按NIST阶段自动生成任务清单

        Args:
            incident_id: 事件ID
            plan_id: 可选预案ID，缺省使用默认阶段模板
            assignee: 默认任务处理人
        """
        now = self._now()
        # 解析任务步骤
        phase_steps: List[dict] = []
        if plan_id:
            conn = db._get_connection()
            try:
                row = conn.execute(
                    "SELECT steps FROM soc_response_plans WHERE id=?", (plan_id,)
                ).fetchone()
            finally:
                conn.close()
            if row and row["steps"]:
                try:
                    phase_steps = json.loads(row["steps"])
                except (json.JSONDecodeError, TypeError):
                    phase_steps = []
        if not phase_steps:
            phase_steps = [{"phase": p, "tasks": ts} for p, ts in DEFAULT_PHASE_STEPS.items()]

        # 生成任务
        task_ids = []
        conn = db._get_connection()
        try:
            for block in phase_steps:
                phase = block.get("phase", "未分组")
                for task_name in block.get("tasks", []):
                    task_id = str(uuid.uuid4())
                    conn.execute("""
                        INSERT INTO soc_response_tasks (
                            id, incident_id, plan_id, step_name, description,
                            assignee, status, completed_at, created_at
                        ) VALUES (?, ?, ?, ?, ?, ?, 'pending', NULL, ?)
                    """, (task_id, incident_id, plan_id,
                          f"[{phase}] {task_name}", task_name, assignee, now))
                    task_ids.append(task_id)
            conn.commit()
        finally:
            conn.close()
        log.info(f"🚨 事件 {incident_id} 启动应急响应，生成 {len(task_ids)} 个任务")
        return {"incident_id": incident_id, "plan_id": plan_id,
                "task_ids": task_ids, "task_count": len(task_ids)}

    def get_response_tasks(self, incident_id: str) -> List[dict]:
        """获取事件的响应任务列表"""
        conn = db._get_connection()
        try:
            rows = conn.execute(
                """SELECT * FROM soc_response_tasks WHERE incident_id=?
                   ORDER BY created_at ASC""", (incident_id,)
            ).fetchall()
            return [dict(r) for r in rows]
        finally:
            conn.close()

    def complete_task(self, incident_id: str, task_id: str,
                      operator: str = "system") -> Optional[dict]:
        """标记响应任务完成"""
        now = self._now()
        conn = db._get_connection()
        try:
            cur = conn.execute(
                """UPDATE soc_response_tasks SET status='completed', completed_at=?
                   WHERE id=? AND incident_id=?""",
                (now, task_id, incident_id),
            )
            conn.commit()
            if cur.rowcount == 0:
                return None
            row = conn.execute(
                "SELECT * FROM soc_response_tasks WHERE id=?", (task_id,)
            ).fetchone()
            return dict(row) if row else None
        finally:
            conn.close()

    # ==================== 证据采集 ====================

    def collect_evidence(self, incident_id: str, evidence_type: str,
                        description: str = "", file_path: str = "",
                        hash_value: str = "",
                        collected_by: str = "system") -> dict:
        """采集并登记响应证据（日志/快照/内存/网络流量）"""
        ev_id = str(uuid.uuid4())
        now = self._now()
        conn = db._get_connection()
        try:
            conn.execute("""
                INSERT INTO soc_response_evidence (
                    id, incident_id, evidence_type, description, file_path,
                    hash, collected_by, collected_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?)
            """, (ev_id, incident_id, evidence_type, description, file_path,
                  hash_value, collected_by, now))
            conn.commit()
        finally:
            conn.close()
        log.info(f"📸 事件 {incident_id} 采集证据 {ev_id} ({evidence_type})")
        return {"id": ev_id, "incident_id": incident_id,
                "evidence_type": evidence_type, "file_path": file_path,
                "hash": hash_value, "collected_by": collected_by,
                "collected_at": now}

    def list_evidence(self, incident_id: str) -> List[dict]:
        """列出事件已采集的证据"""
        conn = db._get_connection()
        try:
            rows = conn.execute(
                """SELECT * FROM soc_response_evidence WHERE incident_id=?
                   ORDER BY collected_at DESC""", (incident_id,)
            ).fetchall()
            return [dict(r) for r in rows]
        finally:
            conn.close()

    # ==================== 复盘报告 ====================

    def generate_debrief_report(self, incident_id: str) -> dict:
        """生成复盘报告（时间线/根因/影响/改进措施）"""
        # 取事件基础信息
        from soc.incident_manager import incident_manager
        incident = incident_manager.get_incident(incident_id)
        timeline = incident_manager.get_incident_timeline(incident_id)
        tasks = self.get_response_tasks(incident_id)
        evidence = self.list_evidence(incident_id)

        # 任务完成率
        total_tasks = len(tasks)
        done_tasks = sum(1 for t in tasks if t.get("status") == "completed")
        completion_rate = round(done_tasks / total_tasks * 100, 1) if total_tasks else 0.0

        # 时间线摘要
        summary_events = [
            {"time": t.get("timestamp"), "action": t.get("action"),
             "operator": t.get("operator")}
            for t in timeline
        ]

        # 改进措施：基于未完成任务与证据缺口推导
        improvements = []
        for t in tasks:
            if t.get("status") != "completed":
                improvements.append(f"完成未关闭任务：{t.get('step_name')}")
        if not evidence:
            improvements.append("补充取证：当前事件未采集任何电子证据")
        if incident and incident.get("severity") in ("critical", "high"):
            improvements.append("更新检测规则：针对该事件IOC补充IDS/EDR规则")

        report = {
            "incident_id": incident_id,
            "title": (incident or {}).get("title", "未知事件"),
            "severity": (incident or {}).get("severity", "unknown"),
            "category": (incident or {}).get("category", "other"),
            "generated_at": self._now(),
            "timeline": summary_events,
            "root_cause": (incident or {}).get("description", "（待补充根因分析）"),
            "impact": {
                "affected_asset": (incident or {}).get("asset_id"),
                "related_vulnerability": (incident or {}).get("vulnerability_id"),
                "evidence_count": len(evidence),
            },
            "response_execution": {
                "total_tasks": total_tasks,
                "completed_tasks": done_tasks,
                "completion_rate": completion_rate,
            },
            "evidence_inventory": [
                {"type": e.get("evidence_type"), "file": e.get("file_path"),
                 "hash": e.get("hash")} for e in evidence
            ],
            "improvement_actions": improvements or [
                "组织团队复盘会议",
                "更新应急预案与检测规则"
            ],
        }
        log.info(f"📋 事件 {incident_id} 复盘报告已生成")
        return report

    # ==================== 应急演练 ====================

    def list_exercises(self) -> List[dict]:
        """列出应急演练记录"""
        conn = db._get_connection()
        try:
            rows = conn.execute(
                "SELECT * FROM soc_response_exercises ORDER BY conducted_at DESC"
            ).fetchall()
            result = []
            for r in rows:
                item = dict(r)
                for jf in ("participants", "improvement_actions"):
                    raw = item.get(jf)
                    if isinstance(raw, str):
                        try:
                            item[jf] = json.loads(raw)
                        except (json.JSONDecodeError, TypeError):
                            item[jf] = []
                result.append(item)
            return result
        finally:
            conn.close()

    def create_exercise(self, name: str, exercise_type: str = "tabletop",
                        scenario: str = "", participants: List[str] = None,
                        result: str = "", improvement_actions: List[str] = None) -> dict:
        """创建应急演练记录"""
        ex_id = str(uuid.uuid4())
        now = self._now()
        conn = db._get_connection()
        try:
            conn.execute("""
                INSERT INTO soc_response_exercises (
                    id, name, exercise_type, scenario, participants,
                    result, improvement_actions, conducted_at, created_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
            """, (
                ex_id, name, exercise_type, scenario,
                json.dumps(participants or [], ensure_ascii=False),
                result,
                json.dumps(improvement_actions or [], ensure_ascii=False),
                now, now,
            ))
            conn.commit()
        finally:
            conn.close()
        log.info(f"✅ 创建应急演练: {ex_id} - {name}")
        return {"id": ex_id, "name": name, "exercise_type": exercise_type,
                "scenario": scenario, "conducted_at": now}


# 全局单例
incident_response = IncidentResponse()
