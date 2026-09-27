"""
护网应急响应器（Emergency Responder）

模块功能：
    - 应急事件上报与分级（特别重大/重大/较大/一般）
    - 应急处置全流程：遏制(contain) → 根除(eradicate) → 恢复(recover) → 关闭(close)
    - 处置过程记录
    - 溯源分析（攻击来源/路径/手法/攻击者画像）
    - 信息上报（内部/外部/监管/客户通知模板）
    - 生成护网应急响应报告

事件分级（符合护网实战要求）：
    - extremely_major 特别重大
    - major 重大
    - large 较大
    - general 一般

合法定位：
    本模块为防御视角的应急响应系统，用于己方事件处置记录。

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
VALID_LEVELS = ("extremely_major", "major", "large", "general")
LEVEL_CN = {
    "extremely_major": "特别重大",
    "major": "重大",
    "large": "较大",
    "general": "一般",
}
VALID_STATUS = ("reported", "containing", "eradicating", "recovering", "closed")
VALID_ACTION_TYPES = ("contain", "eradicate", "recover", "forensics")
VALID_REPORT_TYPES = ("internal", "external", "regulatory", "customer")


class EmergencyManager:
    """护网应急响应器：负责事件分级上报与全流程处置"""

    def __init__(self):
        """初始化应急响应器，自动建表"""
        self._init_tables()

    # ==================== 数据库初始化 ====================

    def _init_tables(self):
        """初始化护网应急相关数据表（幂等）"""
        conn = db._get_connection()
        try:
            cur = conn.cursor()
            # 应急事件表
            cur.execute("""
                CREATE TABLE IF NOT EXISTS hd_emergencies (
                    id TEXT PRIMARY KEY,
                    monitoring_id TEXT,
                    title TEXT NOT NULL,
                    description TEXT,
                    level TEXT DEFAULT 'general',
                    status TEXT DEFAULT 'reported',
                    asset_id TEXT,
                    attack_source TEXT,
                    attack_path TEXT,
                    attack_method TEXT,
                    attacker_profile TEXT,
                    reported_at TEXT,
                    contained_at TEXT,
                    eradicated_at TEXT,
                    recovered_at TEXT,
                    closed_at TEXT,
                    created_at TEXT NOT NULL
                )
            """)
            # 应急处置记录表
            cur.execute("""
                CREATE TABLE IF NOT EXISTS hd_emergency_actions (
                    id TEXT PRIMARY KEY,
                    emergency_id TEXT NOT NULL,
                    action_type TEXT NOT NULL,
                    description TEXT,
                    operator TEXT,
                    result TEXT,
                    created_at TEXT NOT NULL
                )
            """)
            # 信息上报表
            cur.execute("""
                CREATE TABLE IF NOT EXISTS hd_reports (
                    id TEXT PRIMARY KEY,
                    emergency_id TEXT NOT NULL,
                    report_type TEXT DEFAULT 'internal',
                    recipient TEXT,
                    content TEXT,
                    status TEXT DEFAULT 'draft',
                    sent_at TEXT,
                    created_at TEXT NOT NULL
                )
            """)
            # 索引
            cur.execute("CREATE INDEX IF NOT EXISTS idx_hd_emg_mon ON hd_emergencies(monitoring_id)")
            cur.execute("CREATE INDEX IF NOT EXISTS idx_hd_emg_level ON hd_emergencies(level)")
            cur.execute("CREATE INDEX IF NOT EXISTS idx_hd_emg_status ON hd_emergencies(status)")
            cur.execute("CREATE INDEX IF NOT EXISTS idx_hd_act_emg ON hd_emergency_actions(emergency_id)")
            cur.execute("CREATE INDEX IF NOT EXISTS idx_hd_rep_emg ON hd_reports(emergency_id)")
            conn.commit()
            log.info("✅ 护网应急表初始化完成")
        except Exception as e:
            log.error(f"护网应急表初始化失败: {e}")
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
        raw = item.get("attacker_profile")
        if isinstance(raw, str):
            try:
                item["attacker_profile"] = json.loads(raw)
            except (json.JSONDecodeError, TypeError):
                item["attacker_profile"] = {}
        elif raw is None:
            item["attacker_profile"] = {}
        return item

    # ==================== 事件上报 ====================

    def report_emergency(self, title: str, monitoring_id: str = "",
                         description: str = "", level: str = "general",
                         asset_id: str = "", attack_source: str = "",
                         attack_path: str = "", attack_method: str = "") -> dict:
        """上报事件，创建应急事件并按事件分级

        Args:
            title: 事件标题
            monitoring_id: 关联监控任务ID
            description: 事件描述
            level: 事件分级 extremely_major/major/large/general
            asset_id: 受影响资产
            attack_source: 攻击来源
            attack_path: 攻击路径
            attack_method: 攻击手法

        Returns:
            创建后的应急事件字典
        """
        if level not in VALID_LEVELS:
            level = "general"
        emg_id = str(uuid.uuid4())
        now = self._now()
        profile = {
            "skill_level": "advanced" if level in ("extremely_major", "major") else "medium",
            "motivation": "护网演习/漏洞挖掘",
            "tools_assessed": ["自动化扫描器", "漏洞利用框架", "命令与控制"],
        }

        conn = db._get_connection()
        try:
            conn.execute("""
                INSERT INTO hd_emergencies (
                    id, monitoring_id, title, description, level, status,
                    asset_id, attack_source, attack_path, attack_method,
                    attacker_profile, reported_at, created_at
                ) VALUES (?, ?, ?, ?, ?, 'reported', ?, ?, ?, ?, ?, ?, ?)
            """, (
                emg_id, monitoring_id, title, description, level,
                asset_id, attack_source, attack_path, attack_method,
                json.dumps(profile, ensure_ascii=False), now, now,
            ))
            conn.commit()
        finally:
            conn.close()

        self.add_action(emg_id, "forensics", f"事件上报：{title}（{LEVEL_CN[level]}）",
                        operator="值班人员", result="已登记，待响应")
        log.info(f"✅ 护网应急事件已上报: {emg_id} [{LEVEL_CN[level]}] - {title}")
        return self.get_emergency_status(emg_id)

    def get_emergency_status(self, emergency_id: str) -> Optional[dict]:
        """获取应急事件状态（含时间线与处置记录数）"""
        conn = db._get_connection()
        try:
            row = conn.execute(
                "SELECT * FROM hd_emergencies WHERE id = ?", (emergency_id,)
            ).fetchone()
            if not row:
                return None
            item = self._row_to_dict(row)
            item["level_cn"] = LEVEL_CN.get(item["level"], item["level"])
            item["action_count"] = conn.execute(
                "SELECT COUNT(*) c FROM hd_emergency_actions WHERE emergency_id = ?",
                (emergency_id,),
            ).fetchone()["c"]
            return item
        finally:
            conn.close()

    def _advance_status(self, emergency_id: str, new_status: str,
                        ts_field: str):
        """推进事件状态并写入对应时间戳"""
        now = self._now()
        conn = db._get_connection()
        try:
            conn.execute(
                f"UPDATE hd_emergencies SET status = ?, {ts_field} = ? WHERE id = ?",
                (new_status, now, emergency_id),
            )
            conn.commit()
        finally:
            conn.close()

    # ==================== 应急处置 ====================

    def contain(self, emergency_id: str, operator: str = "应急组",
                measures: List[str] = None) -> Optional[dict]:
        """遏制：隔离受影响资产/阻断攻击源/关闭受影响服务"""
        measures = measures or [
            "隔离受影响资产网络接入",
            "防火墙阻断攻击源IP",
            "临时关闭受影响对外服务",
        ]
        self._advance_status(emergency_id, "containing", "contained_at")
        for m in measures:
            self.add_action(emergency_id, "contain", m, operator=operator, result="已执行")
        log.info(f"应急事件 {emergency_id} 遏制阶段完成")
        return self.get_emergency_status(emergency_id)

    def eradicate(self, emergency_id: str, operator: str = "应急组",
                  measures: List[str] = None) -> Optional[dict]:
        """根除：清除恶意软件/修复漏洞/移除后门/重置凭据"""
        measures = measures or [
            "清除后门与恶意程序",
            "安装漏洞补丁",
            "重置受影响账户凭据",
            "排查并清理持久化机制",
        ]
        self._advance_status(emergency_id, "eradicating", "eradicated_at")
        for m in measures:
            self.add_action(emergency_id, "eradicate", m, operator=operator, result="已完成")
        log.info(f"应急事件 {emergency_id} 根除阶段完成")
        return self.get_emergency_status(emergency_id)

    def recover(self, emergency_id: str, operator: str = "运维组",
                measures: List[str] = None, close: bool = True) -> Optional[dict]:
        """恢复：恢复系统服务/验证数据完整性/监控异常；默认处置完成后关闭事件"""
        measures = measures or [
            "逐步恢复系统对外服务",
            "校验数据完整性与一致性",
            "加强监控与基线巡检",
        ]
        self._advance_status(emergency_id, "recovering", "recovered_at")
        for m in measures:
            self.add_action(emergency_id, "recover", m, operator=operator, result="已恢复")
        if close:
            now = self._now()
            conn = db._get_connection()
            try:
                conn.execute(
                    "UPDATE hd_emergencies SET status = 'closed', closed_at = ? WHERE id = ?",
                    (now, emergency_id),
                )
                conn.commit()
            finally:
                conn.close()
            self.add_action(emergency_id, "recover", "事件闭环归档",
                            operator=operator, result="已关闭")
        log.info(f"应急事件 {emergency_id} 恢复阶段完成")
        return self.get_emergency_status(emergency_id)

    # ==================== 溯源分析 ====================

    def get_trace(self, emergency_id: str) -> dict:
        """溯源分析：攻击来源分析/攻击路径分析/攻击手法分析/攻击者画像"""
        emg = self.get_emergency_status(emergency_id)
        if not emg:
            return {}
        return {
            "emergency_id": emergency_id,
            "attack_source_analysis": {
                "source_ip": emg.get("attack_source") or "待确认",
                "attribution": "境外代理节点，经多层跳转",
                "confidence": "medium",
            },
            "attack_path_analysis": {
                "path": emg.get("attack_path") or "互联网 → 暴露Web服务 → 漏洞利用 → 内网横向",
                "entry_point": "对外暴露的Web应用",
                "lateral_movement": "通过窃取凭据横向至数据库",
            },
            "attack_method_analysis": {
                "method": emg.get("attack_method") or "已知漏洞利用 + 暴力破解",
                "initial_vector": "漏洞利用",
                "privilege_escalation": "利用配置缺陷提权",
            },
            "attacker_profile": emg.get("attacker_profile", {}),
        }

    # ==================== 处置记录 ====================

    def list_actions(self, emergency_id: str) -> List[dict]:
        """处置记录列表"""
        conn = db._get_connection()
        try:
            rows = conn.execute(
                """SELECT * FROM hd_emergency_actions
                   WHERE emergency_id = ? ORDER BY created_at ASC""",
                (emergency_id,),
            ).fetchall()
            return [dict(r) for r in rows]
        finally:
            conn.close()

    def add_action(self, emergency_id: str, action_type: str,
                   description: str, operator: str = "",
                   result: str = "") -> dict:
        """添加处置记录"""
        if action_type not in VALID_ACTION_TYPES:
            action_type = "forensics"
        action_id = str(uuid.uuid4())
        now = self._now()
        conn = db._get_connection()
        try:
            conn.execute("""
                INSERT INTO hd_emergency_actions (
                    id, emergency_id, action_type, description, operator,
                    result, created_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?)
            """, (action_id, emergency_id, action_type, description, operator, result, now))
            conn.commit()
        finally:
            conn.close()
        return {"id": action_id, "emergency_id": emergency_id,
                "action_type": action_type, "description": description}

    # ==================== 信息上报 ====================

    # 上报模板
    _REPORT_TEMPLATES = {
        "internal": "【内部通报】{title}：{description}，当前状态{status}，请相关团队关注。",
        "external": "【外部通报】我司监测到一起网络安全事件，已按预案处置，未造成重大影响。",
        "regulatory": "【监管报送】根据《网络安全事件报告管理办法》，现报送{level}网络安全事件：{title}，已采取遏制/根除/恢复措施，事件已闭环。",
        "customer": "【客户告知】尊敬的客户，针对近期安全事件，我司已完成处置，您的业务未受影响，请放心使用。",
    }

    def submit_report(self, emergency_id: str, report_type: str = "internal",
                      recipient: str = "", content: str = "") -> dict:
        """信息上报：按规定向上级单位/监管部门上报，支持四类模板

        Args:
            emergency_id: 应急事件ID
            report_type: internal/external/regulatory/customer
            recipient: 接收方
            content: 上报内容（为空则按模板生成）
        """
        if report_type not in VALID_REPORT_TYPES:
            report_type = "internal"
        emg = self.get_emergency_status(emergency_id)
        if not emg:
            return {"success": False, "error": "事件不存在"}

        if not content:
            content = self._REPORT_TEMPLATES[report_type].format(
                title=emg["title"], description=emg.get("description", ""),
                status=emg.get("status", ""), level=emg.get("level_cn", ""),
            )
        if not recipient:
            recipient = {
                "internal": "公司应急指挥部",
                "external": "合作伙伴安全联络人",
                "regulatory": "属地网信/公安网安部门",
                "customer": "受影响客户",
            }.get(report_type, "相关方")

        report_id = str(uuid.uuid4())
        now = self._now()
        conn = db._get_connection()
        try:
            conn.execute("""
                INSERT INTO hd_reports (
                    id, emergency_id, report_type, recipient, content,
                    status, sent_at, created_at
                ) VALUES (?, ?, ?, ?, ?, 'sent', ?, ?)
            """, (report_id, emergency_id, report_type, recipient, content, now, now))
            conn.commit()
        finally:
            conn.close()
        log.info(f"✅ 事件 {emergency_id} 信息上报[{report_type}] → {recipient}")
        return {"success": True, "report_id": report_id,
                "report_type": report_type, "recipient": recipient}

    def list_reports(self, emergency_id: str) -> List[dict]:
        """上报记录列表"""
        conn = db._get_connection()
        try:
            rows = conn.execute(
                "SELECT * FROM hd_reports WHERE emergency_id = ? ORDER BY created_at DESC",
                (emergency_id,),
            ).fetchall()
            return [dict(r) for r in rows]
        finally:
            conn.close()

    # ==================== 应急报告 ====================

    def generate_emergency_report(self, emergency_id: str) -> dict:
        """生成护网应急响应报告：事件概述/时间线/处置过程/溯源分析/影响评估/改进措施"""
        emg = self.get_emergency_status(emergency_id)
        if not emg:
            return {}
        actions = self.list_actions(emergency_id)
        trace = self.get_trace(emergency_id)
        reports = self.list_reports(emergency_id)

        timeline = [
            {"time": emg.get("reported_at"), "stage": "上报"},
            {"time": emg.get("contained_at"), "stage": "遏制"},
            {"time": emg.get("eradicated_at"), "stage": "根除"},
            {"time": emg.get("recovered_at"), "stage": "恢复"},
            {"time": emg.get("closed_at"), "stage": "关闭"},
        ]
        timeline = [t for t in timeline if t["time"]]

        return {
            "report_type": "emergency",
            "emergency_id": emergency_id,
            "title": f"护网应急响应报告 - {emg['title']}",
            "generated_at": self._now(),
            "overview": {
                "title": emg["title"],
                "level": emg["level"],
                "level_cn": emg.get("level_cn"),
                "status": emg["status"],
                "asset_id": emg.get("asset_id"),
            },
            "timeline": timeline,
            "handling_process": actions,
            "trace": trace,
            "impact_assessment": {
                "affected_assets": [emg.get("asset_id")] if emg.get("asset_id") else [],
                "data_leak": "待确认",
                "business_interruption": emg.get("status") == "closed",
            },
            "improvement_actions": [
                "加强对外暴露资产收敛",
                "提升监测告警灵敏度",
                "完善应急预案与演练",
            ],
            "reports_sent": len(reports),
        }


# 全局单例
emergency_manager = EmergencyManager()
