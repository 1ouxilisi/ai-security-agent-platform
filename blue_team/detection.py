# -*- coding: utf-8 -*-
"""
蓝队防御检测器（Blue Team Detection）

模块功能：
    - 检测规则管理（bt_detection_rules）
    - 检测任务管理（bt_detections）
    - 检测告警管理（bt_detection_alerts）
    - 日志分析、告警关联（模拟）
    - 防御有效性评估、防御盲区识别与改进建议
    - 蓝队评估报告生成

安全声明：
    - 本模块对日志/告警的分析为基于规则的模拟推演，不直接接入真实生产流量
"""
import json
import uuid
import random
from datetime import datetime
from typing import Any, Dict, List, Optional

from utils.database import db
from utils.logger import log


# ==================== 常量定义 ====================

class RuleType:
    """检测规则类型"""
    IDS = "ids"
    IPS = "ips"
    EDR = "edr"
    SIEM = "siem"
    LOG = "log"


# 预定义检测规则种子（>=30 条），覆盖常见 ATT&CK 技术检测
def _seed_rules() -> List[Dict[str, Any]]:
    """构造预定义检测规则种子数据"""
    return [
        # ---- 进程创建检测 (EDR) ----
        {"name": "可疑进程创建检测", "description": "检测可疑子进程创建（如 office 进程衍生 cmd/powershell）",
         "attack_technique": "进程创建", "ttp": "T1204.002", "rule_type": RuleType.EDR,
         "severity": "high", "rule_content": {"event": "process_create", "parent_in": ["winword.exe", "excel.exe"],
                                              "child_in": ["cmd.exe", "powershell.exe"]}},
        {"name": "PowerShell 混淆执行检测", "description": "检测含编码/混淆参数的 PowerShell 执行",
         "attack_technique": "命令执行", "ttp": "T1059.001", "rule_type": RuleType.EDR,
         "severity": "high", "rule_content": {"event": "process_create", "image": "powershell.exe",
                                              "keywords": ["-enc", "-EncodedCommand", "IEX"]}},
        {"name": "命令行异常参数检测", "description": "检测含下载/cradle 特征的命令行",
         "attack_technique": "命令执行", "ttp": "T1059.003", "rule_type": RuleType.EDR,
         "severity": "medium", "rule_content": {"event": "process_create",
                                              "keywords": ["certutil", "bitsadmin", "curl", "wget"]}},
        {"name": "rundll32 异常加载检测", "description": "检测 rundll32 加载可疑 DLL/脚本",
         "attack_technique": "命令执行", "ttp": "T1218.011", "rule_type": RuleType.EDR,
         "severity": "high", "rule_content": {"event": "process_create", "image": "rundll32.exe",
                                              "suspicious": True}},
        {"name": "regsvr32 脚本加载检测", "description": "检测 regsvr32 远程脚本加载(Squiblydoo)",
         "attack_technique": "命令执行", "ttp": "T1218.010", "rule_type": RuleType.EDR,
         "severity": "high", "rule_content": {"event": "process_create", "image": "regsvr32.exe",
                                              "keywords": ["scrobj", "http"]}},
        # ---- 网络连接检测 (IDS/SIEM) ----
        {"name": "异常外联 C2 检测", "description": "检测终端向已知恶意/可疑域名外联",
         "attack_technique": "命令控制", "ttp": "T1071", "rule_type": RuleType.IDS,
         "severity": "critical", "rule_content": {"event": "net_conn", "dst_risk": "high"}},
        {"name": "横向 SMB 连接检测", "description": "检测非常规 SMB 横向连接",
         "attack_technique": "横向移动", "ttp": "T1021.002", "rule_type": RuleType.IDS,
         "severity": "high", "rule_content": {"event": "net_conn", "port": 445, "lateral": True}},
        {"name": "RDP 异常登录检测", "description": "检测非常规时段/来源 RDP 登录",
         "attack_technique": "横向移动", "ttp": "T1021.001", "rule_type": RuleType.IDS,
         "severity": "high", "rule_content": {"event": "net_conn", "port": 3389}},
        {"name": "DNS 隧道检测", "description": "检测超长子域/高频 DNS 查询隧道",
         "attack_technique": "数据渗出", "ttp": "T1048.003", "rule_type": RuleType.IDS,
         "severity": "high", "rule_content": {"event": "dns_query", "subdomain_len_gt": 40}},
        {"name": "异常出站大流量检测", "description": "检测终端向外部异常大流量（数据渗出）",
         "attack_technique": "数据渗出", "ttp": "T1041", "rule_type": RuleType.SIEM,
         "severity": "critical", "rule_content": {"event": "net_flow", "out_mb_gt": 500}},
        {"name": "WebShell HTTP 访问检测", "description": "检测对已知 WebShell 路径的访问",
         "attack_technique": "持久化", "ttp": "T1505.003", "rule_type": RuleType.IDS,
         "severity": "critical", "rule_content": {"event": "http_access",
                                              "keywords": [".php?", "shell", "cmd="]}},
        # ---- 注册表/启动项检测 (EDR) ----
        {"name": "自启动注册表修改检测", "description": "检测 Run/RunOnce 键值异常写入",
         "attack_technique": "持久化", "ttp": "T1547.001", "rule_type": RuleType.EDR,
         "severity": "high", "rule_content": {"event": "reg_modify",
                                              "keys": ["HKCU\\..\\Run", "HKLM\\..\\Run"]}},
        {"name": "服务注册表创建检测", "description": "检测新服务注册用于持久化",
         "attack_technique": "持久化", "ttp": "T1543.003", "rule_type": RuleType.EDR,
         "severity": "high", "rule_content": {"event": "reg_modify", "hive": "HKLM\\Services"}},
        {"name": "安全工具禁用注册表检测", "description": "检测关闭 Defender/UAC 等注册表改动",
         "attack_technique": "防御规避", "ttp": "T1562.001", "rule_type": RuleType.EDR,
         "severity": "critical", "rule_content": {"event": "reg_modify",
                                              "keywords": ["DisableAntiSpyware", "DisableRealtimeMonitoring"]}},
        # ---- 文件创建检测 (EDR/LOG) ----
        {"name": "临时目录可执行文件落地检测", "description": "检测 Temp 目录落地可执行文件",
         "attack_technique": "安装", "ttp": "T1204.002", "rule_type": RuleType.EDR,
         "severity": "high", "rule_content": {"event": "file_create", "dir": "%TEMP%",
                                              "ext_in": [".exe", ".dll", ".ps1"]}},
        {"name": "勒索软件批量加密行为检测", "description": "检测短时间大量文件重命名/加密",
         "attack_technique": "勒索软件", "ttp": "T1486", "rule_type": RuleType.EDR,
         "severity": "critical", "rule_content": {"event": "file_rename_burst", "count_gt": 50}},
        {"name": "WebShell 落盘检测", "description": "检测 Web 目录下新增可疑脚本文件",
         "attack_technique": "持久化", "ttp": "T1505.003", "rule_type": RuleType.LOG,
         "severity": "critical", "rule_content": {"event": "file_create", "web_dir": True,
                                              "ext_in": [".php", ".jsp", ".aspx"]}},
        {"name": "可疑压缩包外传检测", "description": "检测大量数据被打包压缩",
         "attack_technique": "数据渗出", "ttp": "T1560.001", "rule_type": RuleType.EDR,
         "severity": "medium", "rule_content": {"event": "file_create", "ext_in": [".zip", ".rar", ".7z"]}},
        # ---- 权限提升检测 (LOG/SIEM) ----
        {"name": "异常权限提升检测", "description": "检测普通进程获取 SeDebugPrivilege 等特权",
         "attack_technique": "权限提升", "ttp": "T1068", "rule_type": RuleType.LOG,
         "severity": "high", "rule_content": {"event": "priv_use", "priv": "SeDebugPrivilege"}},
        {"name": "服务错误利用检测", "description": "检测服务路径/二进制被替换利用",
         "attack_technique": "权限提升", "ttp": "T1574.011", "rule_type": RuleType.EDR,
         "severity": "high", "rule_content": {"event": "service_change", "unquoted_path": True}},
        {"name": "令牌窃取检测", "description": "检测令牌操纵/模拟行为",
         "attack_technique": "权限提升", "ttp": "T1134", "rule_type": RuleType.EDR,
         "severity": "high", "rule_content": {"event": "token_manip"}},
        # ---- 凭证相关检测 (SIEM/LOG) ----
        {"name": "凭证转储行为检测", "description": "检测 LSASS 内存读取（Mimikatz 特征）",
         "attack_technique": "凭证访问", "ttp": "T1003.001", "rule_type": RuleType.EDR,
         "severity": "critical", "rule_content": {"event": "mem_access", "target": "lsass.exe"}},
        {"name": "暴力破解登录检测", "description": "检测短时间多次失败登录",
         "attack_technique": "凭证访问", "ttp": "T1110", "rule_type": RuleType.LOG,
         "severity": "high", "rule_content": {"event": "login_fail", "count_gt": 10, "window_min": 5}},
        {"name": "异常账户创建检测", "description": "检测新增隐藏/特权账户",
         "attack_technique": "持久化", "ttp": "T1136.001", "rule_type": RuleType.LOG,
         "severity": "high", "rule_content": {"event": "account_create", "privileged": True}},
        {"name": "Pass-the-Hash 检测", "description": "检测使用哈希的异常认证",
         "attack_technique": "横向移动", "ttp": "T1550.002", "rule_type": RuleType.SIEM,
         "severity": "critical", "rule_content": {"event": "auth", "type": "ntlm_hop"}},
        # ---- 横向移动检测 (SIEM) ----
        {"name": "WMI 远程执行检测", "description": "检测 Win32_Process Create 远程调用",
         "attack_technique": "横向移动", "ttp": "T1047", "rule_type": RuleType.SIEM,
         "severity": "high", "rule_content": {"event": "wmi_exec", "remote": True}},
        {"name": "计划任务远程创建检测", "description": "检测远程计划任务创建",
         "attack_technique": "横向移动", "ttp": "T1053.005", "rule_type": RuleType.SIEM,
         "severity": "high", "rule_content": {"event": "task_create", "remote": True}},
        # ---- 钓鱼检测 (SIEM/IDS) ----
        {"name": "钓鱼邮件附件检测", "description": "检测含恶意附件/链接的邮件",
         "attack_technique": "钓鱼", "ttp": "T1566.001", "rule_type": RuleType.SIEM,
         "severity": "high", "rule_content": {"event": "mail", "malicious_attachment": True}},
        {"name": "可疑链接点击检测", "description": "检测用户点击恶意短链接",
         "attack_technique": "钓鱼", "ttp": "T1566.002", "rule_type": RuleType.SIEM,
         "severity": "medium", "rule_content": {"event": "web_click", "url_risk": "high"}},
        {"name": "SPF/DKIM 失败检测", "description": "检测伪造发件人邮件",
         "attack_technique": "钓鱼", "ttp": "T1598.003", "rule_type": RuleType.IDS,
         "severity": "medium", "rule_content": {"event": "mail_auth", "fail": True}},
        # ---- 勒索/破坏行为 (SIEM) ----
        {"name": "备份服务停止检测", "description": "检测 VSS/备份服务被异常停止",
         "attack_technique": "勒索软件", "ttp": "T1490", "rule_type": RuleType.LOG,
         "severity": "critical", "rule_content": {"event": "service_stop", "name_in": ["VSS", "backup"]}},
        {"name": "磁盘批量删除检测", "description": "检测批量删除影子副本",
         "attack_technique": "勒索软件", "ttp": "T1490", "rule_type": RuleType.EDR,
         "severity": "critical", "rule_content": {"event": "vss_delete"}},
        # ---- C2/渗出 (IDS) ----
        {"name": "心跳式 C2 通信检测", "description": "检测周期性 Beacon 型流量",
         "attack_technique": "命令控制", "ttp": "T1071.001", "rule_type": RuleType.IDS,
         "severity": "high", "rule_content": {"event": "net_flow", "periodic": True}},
        {"name": "加密隧道出站检测", "description": "检测异常 TLS 客户端/非标准端口出站",
         "attack_technique": "命令控制", "ttp": "T1573", "rule_type": RuleType.IDS,
         "severity": "medium", "rule_content": {"event": "tls_out", "nonstandard_port": True}},
        # ---- 社会工程/内部威胁 (SIEM) ----
        {"name": "非工作时间批量下载检测", "description": "检测非工作时间大量数据下载",
         "attack_technique": "内部威胁", "ttp": "T1005", "rule_type": RuleType.SIEM,
         "severity": "high", "rule_content": {"event": "file_download", "offhour": True, "count_gt": 20}},
        {"name": "权限越界访问检测", "description": "检测账户访问非职责范围资源",
         "attack_technique": "内部威胁", "ttp": "T1078", "rule_type": RuleType.SIEM,
         "severity": "medium", "rule_content": {"event": "access", "out_of_scope": True}},
        # ---- DDoS/供应链 (IDS) ----
        {"name": "流量突增异常检测", "description": "检测单位时间流量异常激增",
         "attack_technique": "拒绝服务", "ttp": "T1498", "rule_type": RuleType.IDS,
         "severity": "medium", "rule_content": {"event": "traffic_burst", "ratio_gt": 5}},
        {"name": "异常软件源更新检测", "description": "检测来自非官方源的包/更新",
         "attack_technique": "供应链", "ttp": "T1195.002", "rule_type": RuleType.LOG,
         "severity": "high", "rule_content": {"event": "pkg_install", "unofficial_source": True}},
    ]


class BlueTeamDetector:
    """蓝队防御检测器"""

    def __init__(self):
        """初始化：建表并写入预定义检测规则"""
        self._init_tables()
        self._seed_rules()

    def _get_conn(self):
        return db._get_connection()

    def _init_tables(self):
        """初始化蓝队相关数据表"""
        conn = self._get_conn()
        cur = conn.cursor()
        cur.execute("""
            CREATE TABLE IF NOT EXISTS bt_detection_rules (
                id TEXT PRIMARY KEY,
                name TEXT NOT NULL,
                description TEXT,
                attack_technique TEXT,
                ttp TEXT,
                rule_type TEXT NOT NULL,
                rule_content TEXT,
                severity TEXT DEFAULT 'medium',
                enabled INTEGER DEFAULT 1,
                created_at TEXT NOT NULL
            )
        """)
        cur.execute("""
            CREATE TABLE IF NOT EXISTS bt_detections (
                id TEXT PRIMARY KEY,
                simulation_id TEXT,
                name TEXT,
                status TEXT DEFAULT 'pending',
                started_at TEXT,
                completed_at TEXT,
                detection_rate REAL,
                block_rate REAL,
                alerts_count INTEGER DEFAULT 0,
                created_at TEXT NOT NULL
            )
        """)
        cur.execute("""
            CREATE TABLE IF NOT EXISTS bt_detection_alerts (
                id TEXT PRIMARY KEY,
                detection_id TEXT,
                rule_id TEXT,
                attack_step TEXT,
                technique TEXT,
                alert_severity TEXT,
                detected_at TEXT,
                details TEXT,
                created_at TEXT NOT NULL
            )
        """)
        cur.execute("CREATE INDEX IF NOT EXISTS idx_bt_rule_type ON bt_detection_rules(rule_type)")
        cur.execute("CREATE INDEX IF NOT EXISTS idx_bt_det_sim ON bt_detections(simulation_id)")
        cur.execute("CREATE INDEX IF NOT EXISTS idx_bt_alert_det ON bt_detection_alerts(detection_id)")
        conn.commit()
        conn.close()
        log.info("✅ 蓝队数据表初始化完成")

    def _seed_rules(self):
        """若规则表为空，批量写入预定义检测规则"""
        conn = self._get_conn()
        count = conn.execute("SELECT COUNT(*) FROM bt_detection_rules").fetchone()[0]
        conn.close()
        if count > 0:
            return
        now = datetime.now().isoformat()
        rules = _seed_rules()
        conn = self._get_conn()
        for r in rules:
            conn.execute("""
                INSERT INTO bt_detection_rules
                (id, name, description, attack_technique, ttp, rule_type, rule_content,
                 severity, enabled, created_at)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """, (
                str(uuid.uuid4()), r["name"], r["description"], r["attack_technique"],
                r["ttp"], r["rule_type"],
                json.dumps(r["rule_content"], ensure_ascii=False),
                r["severity"], 1, now,
            ))
        conn.commit()
        conn.close()
        log.info(f"✅ 蓝队预定义检测规则写入完成: {len(rules)} 条")

    # ---------- 工具方法 ----------

    @staticmethod
    def _row_to_rule(row) -> Dict[str, Any]:
        d = dict(row)
        try:
            d["rule_content"] = json.loads(d["rule_content"]) if d.get("rule_content") else {}
        except Exception:
            d["rule_content"] = {}
        d["enabled"] = bool(d.get("enabled"))
        return d

    # ---------- 检测规则管理 ----------

    def list_rules(self, rule_type: Optional[str] = None, severity: Optional[str] = None,
                   enabled: Optional[bool] = None) -> List[Dict[str, Any]]:
        """获取检测规则列表，支持按类型/严重性/启用状态筛选"""
        conn = self._get_conn()
        query = "SELECT * FROM bt_detection_rules WHERE 1=1"
        params: List[Any] = []
        if rule_type:
            query += " AND rule_type = ?"
            params.append(rule_type)
        if severity:
            query += " AND severity = ?"
            params.append(severity)
        if enabled is not None:
            query += " AND enabled = ?"
            params.append(1 if enabled else 0)
        query += " ORDER BY created_at ASC"
        rows = conn.execute(query, params).fetchall()
        conn.close()
        return [self._row_to_rule(r) for r in rows]

    def create_rule(self, name: str, description: str = "", attack_technique: str = "",
                    ttp: str = "", rule_type: str = "siem", rule_content: Optional[Dict] = None,
                    severity: str = "medium") -> Dict[str, Any]:
        """创建检测规则"""
        rid = str(uuid.uuid4())
        now = datetime.now().isoformat()
        conn = self._get_conn()
        conn.execute("""
            INSERT INTO bt_detection_rules
            (id, name, description, attack_technique, ttp, rule_type, rule_content,
             severity, enabled, created_at)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """, (rid, name, description, attack_technique, ttp, rule_type,
              json.dumps(rule_content or {}, ensure_ascii=False), severity, 1, now))
        conn.commit()
        conn.close()
        return self.list_rules()[0] and self._get_rule(rid)

    def _get_rule(self, rule_id: str) -> Optional[Dict[str, Any]]:
        conn = self._get_conn()
        row = conn.execute(
            "SELECT * FROM bt_detection_rules WHERE id = ?", (rule_id,)).fetchone()
        conn.close()
        return self._row_to_rule(row) if row else None

    def update_rule(self, rule_id: str, **kwargs) -> Optional[Dict[str, Any]]:
        """更新检测规则（名称/描述/启用状态等）"""
        allowed = {"name", "description", "severity", "enabled", "rule_type", "attack_technique", "ttp"}
        sets = []
        params: List[Any] = []
        for k, v in kwargs.items():
            if k in allowed:
                if k == "enabled":
                    v = 1 if v else 0
                sets.append(f"{k} = ?")
                params.append(v)
        if not sets:
            return self._get_rule(rule_id)
        params.append(rule_id)
        conn = self._get_conn()
        conn.execute(f"UPDATE bt_detection_rules SET {', '.join(sets)} WHERE id = ?", params)
        conn.commit()
        conn.close()
        return self._get_rule(rule_id)

    def delete_rule(self, rule_id: str) -> bool:
        """删除检测规则"""
        conn = self._get_conn()
        conn.execute("DELETE FROM bt_detection_rules WHERE id = ?", (rule_id,))
        conn.commit()
        conn.close()
        return True

    # ---------- 日志分析与告警关联（模拟） ----------

    def analyze_logs(self, log_source: str = "system",
                     simulation_context: Optional[Dict] = None) -> Dict[str, Any]:
        """分析系统/安全/应用/网络日志，检测攻击迹象（模拟分析）

        根据日志来源与模拟上下文，返回命中的规则与告警候选。
        """
        rules = self.list_rules(enabled=True)
        # 简单模拟：按日志来源筛选相关规则
        source_map = {
            "system": [RuleType.EDR, RuleType.LOG],
            "security": [RuleType.LOG, RuleType.SIEM],
            "application": [RuleType.SIEM, RuleType.LOG],
            "network": [RuleType.IDS, RuleType.IPS, RuleType.SIEM],
        }
        relevant = source_map.get(log_source, [RuleType.SIEM])
        hits = [r for r in rules if r["rule_type"] in relevant]
        return {
            "log_source": log_source,
            "analyzed_rules": len(rules),
            "relevant_rules": len(hits),
            "candidate_alerts": [
                {"rule_id": r["id"], "rule_name": r["name"], "ttp": r["ttp"],
                 "severity": r["severity"]} for r in hits[:10]
            ],
        }

    def correlate_alerts(self, alerts: List[Dict[str, Any]]) -> Dict[str, Any]:
        """关联多个告警，识别完整攻击链"""
        if not alerts:
            return {"chains": [], "clusters": 0}
        # 按 technique/ttp 聚类，形成攻击链
        chains: Dict[str, List[Dict]] = {}
        for a in alerts:
            key = a.get("technique") or a.get("ttp") or "unknown"
            chains.setdefault(key, []).append(a)
        return {
            "chains": [{"technique": k, "alerts": v, "count": len(v)}
                       for k, v in chains.items()],
            "clusters": len(chains),
            "total_alerts": len(alerts),
        }

    # ---------- 防御检测任务 ----------

    def start_detection(self, simulation_id: str, name: str = "") -> Dict[str, Any]:
        """启动防御检测

        基于红队模拟结果分析检测能力，模拟日志分析与告警关联。
        不接入真实日志流，为规则推演。
        """
        from red_team.simulation import RedTeamSimulator
        rt = RedTeamSimulator()
        sim = rt.get_simulation_result(simulation_id)
        if not sim:
            raise ValueError(f"红队模拟任务不存在: {simulation_id}")

        now = datetime.now().isoformat()
        det_id = str(uuid.uuid4())

        # 红队攻击路径中涉及的技术
        attack_steps = sim.get("attack_path_detail", []) or []
        ttps = set()
        for s in attack_steps:
            for t in (s.get("details", {}) or {}).get("ttps", []):
                ttps.add(t)
        scenario = sim.get("scenario") or {}
        for t in scenario.get("ttps", []):
            ttps.add(t)

        rules = self.list_rules(enabled=True)
        # 命中规则：规则 ttp 落在攻击 ttps 集合内
        matched = [r for r in rules if r.get("ttp") in ttps]
        total_steps = max(1, len(attack_steps))
        # 检测率 = 命中规则能覆盖的攻击步骤占比（模拟）
        detection_rate = min(0.95, 0.4 + len(matched) * 0.08)
        block_rate = max(0.0, detection_rate * 0.7)

        # 生成告警
        conn = self._get_conn()
        conn.execute("""
            INSERT INTO bt_detections
            (id, simulation_id, name, status, started_at, completed_at,
             detection_rate, block_rate, alerts_count, created_at)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """, (det_id, simulation_id, name or f"防御检测-{scenario.get('name', '')}",
              "completed", now, now, round(detection_rate, 4), round(block_rate, 4),
              len(matched), now))
        for i, r in enumerate(matched):
            conn.execute("""
                INSERT INTO bt_detection_alerts
                (id, detection_id, rule_id, attack_step, technique, alert_severity,
                 detected_at, details, created_at)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
            """, (
                str(uuid.uuid4()), det_id, r["id"],
                attack_steps[i % total_steps].get("step_name", "") if attack_steps else "",
                r["attack_technique"], r["severity"], now,
                json.dumps({"ttp": r["ttp"], "rule": r["name"],
                            "type": r["rule_type"]}, ensure_ascii=False),
                now,
            ))
        conn.commit()
        conn.close()
        log.info(f"✅ 蓝队防御检测完成: {det_id} 检测率={detection_rate:.2%}")
        return self.get_detection_result(det_id)

    def get_detection_result(self, detection_id: str) -> Optional[Dict[str, Any]]:
        """获取检测结果：命中规则/告警分析/防御有效性"""
        conn = self._get_conn()
        row = conn.execute(
            "SELECT * FROM bt_detections WHERE id = ?", (detection_id,)).fetchone()
        if not row:
            conn.close()
            return None
        det = dict(row)
        alerts = conn.execute(
            "SELECT * FROM bt_detection_alerts WHERE detection_id = ? ORDER BY rowid",
            (detection_id,)).fetchall()
        conn.close()
        alert_list = []
        for a in alerts:
            ad = dict(a)
            try:
                ad["details"] = json.loads(ad["details"]) if ad["details"] else {}
            except Exception:
                ad["details"] = {}
            alert_list.append(ad)
        det["alerts"] = alert_list
        det["alert_analysis"] = self.correlate_alerts(alert_list)
        return det

    def get_detection_alerts(self, detection_id: str) -> List[Dict[str, Any]]:
        """获取检测到的告警列表"""
        result = self.get_detection_result(detection_id)
        return result.get("alerts", []) if result else []

    # ---------- 防御评估 ----------

    def assess_defense_effectiveness(self, simulation_id: Optional[str] = None) -> Dict[str, Any]:
        """评估现有防御措施对攻击场景的检测率/阻断率"""
        conn = self._get_conn()
        if simulation_id:
            rows = conn.execute(
                "SELECT * FROM bt_detections WHERE simulation_id = ? ORDER BY created_at DESC",
                (simulation_id,)).fetchall()
        else:
            rows = conn.execute(
                "SELECT * FROM bt_detections ORDER BY created_at DESC LIMIT 20").fetchall()
        conn.close()
        if not rows:
            return {"avg_detection_rate": 0.0, "avg_block_rate": 0.0, "evaluations": []}
        dets = [dict(r) for r in rows]
        avg_det = sum(d["detection_rate"] or 0 for d in dets) / len(dets)
        avg_block = sum(d["block_rate"] or 0 for d in dets) / len(dets)
        return {
            "avg_detection_rate": round(avg_det, 4),
            "avg_block_rate": round(avg_block, 4),
            "evaluations": dets,
        }

    def analyze_defense_gaps(self, simulation_id: str) -> List[Dict[str, Any]]:
        """识别防御盲区：未被检测规则覆盖的攻击技术"""
        from red_team.simulation import RedTeamSimulator
        rt = RedTeamSimulator()
        sim = rt.get_simulation_result(simulation_id)
        if not sim:
            return []
        scenario = sim.get("scenario") or {}
        attack_ttps = set(scenario.get("ttps", []))
        rules = self.list_rules(enabled=True)
        covered = {r.get("ttp") for r in rules}
        gaps = [t for t in attack_ttps if t not in covered]
        return [{"technique": t, "reason": "无对应检测规则覆盖"} for t in gaps]

    def get_defense_suggestions(self, simulation_id: str) -> List[Dict[str, Any]]:
        """针对防御差距的改进建议"""
        gaps = self.analyze_defense_gaps(simulation_id)
        suggestions = []
        for g in gaps:
            suggestions.append({
                "category": "detection_rule",
                "priority": "high",
                "title": f"新增针对 {g['technique']} 的检测规则",
                "description": f"该攻击技术当前无检测覆盖（{g['reason']}），建议新增 EDR/SIEM 规则",
            })
        # 通用建议
        suggestions.append({"category": "tool", "priority": "medium",
                            "title": "部署/优化 EDR 与 SIEM 联动",
                            "description": "提升端点告警与日志关联分析能力"})
        suggestions.append({"category": "personnel", "priority": "medium",
                            "title": "定期开展安全意识与钓鱼演练",
                            "description": "降低社会工程与钓鱼类攻击成功率"})
        return suggestions

    def generate_blue_team_report(self, detection_id: str) -> Dict[str, Any]:
        """生成蓝队评估报告：检测规则/告警分析/防御有效性/差距/建议"""
        result = self.get_detection_result(detection_id)
        if not result:
            raise ValueError(f"检测任务不存在: {detection_id}")
        sim_id = result.get("simulation_id")
        gaps = self.analyze_defense_gaps(sim_id) if sim_id else []
        suggestions = self.get_defense_suggestions(sim_id) if sim_id else []
        report = {
            "report_type": "blue_team",
            "title": f"蓝队评估报告 - {result.get('name', '')}",
            "overview": {
                "status": result.get("status"),
                "detection_rate": result.get("detection_rate"),
                "block_rate": result.get("block_rate"),
                "alerts_count": result.get("alerts_count"),
            },
            "alert_analysis": result.get("alert_analysis", {}),
            "alerts": result.get("alerts", []),
            "defense_gaps": gaps,
            "suggestions": suggestions,
            "generated_at": datetime.now().isoformat(),
        }
        log.info(f"✅ 蓝队报告生成: {detection_id}")
        return report
