# -*- coding: utf-8 -*-
"""
红队攻击模拟器（Red Team Attack Simulator）

模块功能：
    - 预定义与自定义攻击场景管理（rt_attack_scenarios）
    - 攻击模拟任务管理（rt_simulations）
    - 攻击路径建模与可视化数据（rt_attack_paths）
    - 基于 Cyber Kill Chain 7 阶段的攻击路径模拟
    - 攻击成功概率与业务影响评估
    - 红队评估报告生成

安全声明：
    - 本模块只做攻击模拟与评估，不执行真实攻击，不获取真实访问权限
    - 所有"攻击"均为基于规则与概率的推演，不产生任何实际网络/主机动作
"""
import json
import uuid
import random
from datetime import datetime
from typing import Any, Dict, List, Optional

from utils.database import db
from utils.logger import log


# ==================== 常量定义 ====================

class KillChain:
    """Cyber Kill Chain 七阶段模型"""
    RECON = "侦察"
    WEAPONIZATION = "武器化"
    DELIVERY = "投递"
    EXPLOITATION = "利用"
    INSTALLATION = "安装"
    C2 = "命令控制"
    ACTIONS = "行动"

    ORDER = [RECON, WEAPONIZATION, DELIVERY, EXPLOITATION, INSTALLATION, C2, ACTIONS]


class AttackCategory:
    """攻击场景分类"""
    PHISHING = "phishing"
    RANSOMWARE = "ransomware"
    DATA_THEFT = "data_theft"
    LATERAL_MOVEMENT = "lateral_movement"
    PRIVILEGE_ESCALATION = "privilege_escalation"
    PERSISTENCE = "persistence"
    WEB_APP = "web_application"
    SUPPLY_CHAIN = "supply_chain"
    INSIDER_THREAT = "insider_threat"
    DDOS = "ddos"
    ZERO_DAY = "zero_day"
    SOCIAL_ENGINEERING = "social_engineering"


# 难度 -> 基础成功概率映射
_DIFFICULTY_BASE_PROB = {
    "basic": 0.78,
    "intermediate": 0.55,
    "advanced": 0.35,
}

# 严重性 -> 业务影响权重
_SEVERITY_IMPACT = {
    "low": 0.25,
    "medium": 0.5,
    "high": 0.75,
    "critical": 0.95,
}


# ==================== 预定义攻击场景种子数据 ====================
# 每个场景：kill_chain_steps 为 Cyber Kill Chain 七阶段；
# ttps 为 MITRE ATT&CK 技术 ID；tools 为常用工具（仅名称，不实际调用）；
# iocs 为入侵指标特征（仅描述性）。

def _seed_scenarios() -> List[Dict[str, Any]]:
    """构造 13 个预定义攻击场景的种子数据"""
    return [
        {
            "name": "钓鱼邮件投递攻击",
            "description": "通过伪造可信发件人投递含恶意附件或链接的钓鱼邮件，诱导目标执行。",
            "category": AttackCategory.PHISHING,
            "difficulty": "basic",
            "severity": "high",
            "ttps": ["T1566.001", "T1566.002", "T1204.002", "T1190"],
            "tools": ["鱼叉邮件模板", "附件打包器", "邮件代理（模拟）"],
            "iocs": ["可疑发件域名", "恶意附件哈希", "短链接跳转域"],
            "kill_chain_steps": [
                {"phase": KillChain.RECON, "technique": "收集目标组织与员工信息", "probability": 0.85},
                {"phase": KillChain.WEAPONIZATION, "technique": "构造带宏的恶意 Office 文档", "probability": 0.8},
                {"phase": KillChain.DELIVERY, "technique": "发送鱼叉钓鱼邮件", "probability": 0.7},
                {"phase": KillChain.EXPLOITATION, "technique": "用户启用宏触发代码执行", "probability": 0.45},
                {"phase": KillChain.INSTALLATION, "technique": "投放远控木马", "probability": 0.6},
                {"phase": KillChain.C2, "technique": "回连 C2 服务器", "probability": 0.65},
                {"phase": KillChain.ACTIONS, "technique": "横向收集敏感数据", "probability": 0.5},
            ],
        },
        {
            "name": "勒索软件加密攻击",
            "description": "获取初始立足点后横向扩散并加密关键业务数据，索要赎金。",
            "category": AttackCategory.RANSOMWARE,
            "difficulty": "advanced",
            "severity": "critical",
            "ttps": ["T1486", "T1021.001", "T1567", "T1490"],
            "tools": ["横向扫描（模拟）", "加密载荷（模拟）", "策略破坏工具（模拟）"],
            "iocs": ["异常大批量文件修改", "勒索信文本", "备份服务停止"],
            "kill_chain_steps": [
                {"phase": KillChain.RECON, "technique": "梳理内网共享与备份位置", "probability": 0.6},
                {"phase": KillChain.WEAPONIZATION, "technique": "编译配置加密载荷", "probability": 0.7},
                {"phase": KillChain.DELIVERY, "technique": "通过钓鱼/漏洞投递", "probability": 0.5},
                {"phase": KillChain.EXPLOITATION, "technique": "利用弱口令获取初始权限", "probability": 0.55},
                {"phase": KillChain.INSTALLATION, "technique": "部署勒索主程序", "probability": 0.6},
                {"phase": KillChain.C2, "technique": "接收加密指令与密钥", "probability": 0.65},
                {"phase": KillChain.ACTIONS, "technique": "批量加密并破坏备份", "probability": 0.7},
            ],
        },
        {
            "name": "敏感数据外泄攻击",
            "description": "窃取数据库与文件服务器中的客户/财务数据并外传。",
            "category": AttackCategory.DATA_THEFT,
            "difficulty": "intermediate",
            "severity": "critical",
            "ttps": ["T1005", "T1041", "T1567.002", "T1020"],
            "tools": ["数据打包（模拟）", "外传通道（模拟）"],
            "iocs": ["异常出站大流量", "数据库批量导出查询"],
            "kill_chain_steps": [
                {"phase": KillChain.RECON, "technique": "定位高价值数据资产", "probability": 0.7},
                {"phase": KillChain.WEAPONIZATION, "technique": "准备数据打包与加密", "probability": 0.75},
                {"phase": KillChain.DELIVERY, "technique": "建立初始访问", "probability": 0.6},
                {"phase": KillChain.EXPLOITATION, "technique": "利用数据库弱权限", "probability": 0.55},
                {"phase": KillChain.INSTALLATION, "technique": "部署数据收集器", "probability": 0.6},
                {"phase": KillChain.C2, "technique": "与外传通道通信", "probability": 0.6},
                {"phase": KillChain.ACTIONS, "technique": "打包并外传数据", "probability": 0.55},
            ],
        },
        {
            "name": "内网横向移动",
            "description": "从失陷主机通过 SMB/RDP 等协议横向渗透到核心业务服务器。",
            "category": AttackCategory.LATERAL_MOVEMENT,
            "difficulty": "advanced",
            "severity": "high",
            "ttps": ["T1021.002", "T1550.002", "T1047", "T1082"],
            "tools": ["凭证转储（模拟）", "SMB 扫描（模拟）", "远程执行（模拟）"],
            "iocs": ["异常 SMB 连接", "Pass-the-Hash 行为", "WMI 远程调用"],
            "kill_chain_steps": [
                {"phase": KillChain.RECON, "technique": "内网资产与账户枚举", "probability": 0.65},
                {"phase": KillChain.WEAPONIZATION, "technique": "构造横向执行载荷", "probability": 0.6},
                {"phase": KillChain.DELIVERY, "technique": "获取跳板机访问", "probability": 0.6},
                {"phase": KillChain.EXPLOITATION, "technique": "转储凭证并复用", "probability": 0.5},
                {"phase": KillChain.INSTALLATION, "technique": "在目标机植入代理", "probability": 0.55},
                {"phase": KillChain.C2, "technique": "建立多节点 C2", "probability": 0.6},
                {"phase": KillChain.ACTIONS, "technique": "控制核心业务服务器", "probability": 0.45},
            ],
        },
        {
            "name": "权限提升攻击",
            "description": "从普通用户权限提升至管理员/系统权限。",
            "category": AttackCategory.PRIVILEGE_ESCALATION,
            "difficulty": "intermediate",
            "severity": "high",
            "ttps": ["T1068", "T1548.002", "T1055", "T1134"],
            "tools": ["提权枚举（模拟）", "漏洞利用（模拟）"],
            "iocs": ["异常服务路径", "提权工具执行", "令牌操纵"],
            "kill_chain_steps": [
                {"phase": KillChain.RECON, "technique": "枚举系统配置与漏洞", "probability": 0.7},
                {"phase": KillChain.WEAPONIZATION, "technique": "准备提权利用代码", "probability": 0.6},
                {"phase": KillChain.DELIVERY, "technique": "在目标机落地", "probability": 0.65},
                {"phase": KillChain.EXPLOITATION, "technique": "触发提权漏洞/错误配置", "probability": 0.5},
                {"phase": KillChain.INSTALLATION, "technique": "植入高权限后门", "probability": 0.55},
                {"phase": KillChain.C2, "technique": "高权限回连", "probability": 0.6},
                {"phase": KillChain.ACTIONS, "technique": "接管系统关键账户", "probability": 0.55},
            ],
        },
        {
            "name": "持久化驻留攻击",
            "description": "通过启动项、计划任务、服务等手段实现长期驻留。",
            "category": AttackCategory.PERSISTENCE,
            "difficulty": "basic",
            "severity": "medium",
            "ttps": ["T1543.003", "T1053.005", "T1547.001", "T1136"],
            "tools": ["启动项修改（模拟）", "计划任务（模拟）"],
            "iocs": ["新增自启动项", "异常计划任务", "新增隐藏账户"],
            "kill_chain_steps": [
                {"phase": KillChain.RECON, "technique": "分析自启动机制", "probability": 0.75},
                {"phase": KillChain.WEAPONIZATION, "technique": "制作驻留载荷", "probability": 0.75},
                {"phase": KillChain.DELIVERY, "technique": "获取初始访问", "probability": 0.65},
                {"phase": KillChain.EXPLOITATION, "technique": "利用现有权限落盘", "probability": 0.7},
                {"phase": KillChain.INSTALLATION, "technique": "写入自启动/计划任务", "probability": 0.75},
                {"phase": KillChain.C2, "technique": "周期性回连", "probability": 0.7},
                {"phase": KillChain.ACTIONS, "technique": "长期维持控制", "probability": 0.7},
            ],
        },
        {
            "name": "Web应用攻击",
            "description": "针对 Web 应用的注入、上传、未授权访问等漏洞利用。",
            "category": AttackCategory.WEB_APP,
            "difficulty": "intermediate",
            "severity": "high",
            "ttps": ["T1190", "T1133", "T1059.003", "T1078"],
            "tools": ["漏洞扫描（模拟）", "注入利用（模拟）", "文件上传（模拟）"],
            "iocs": ["异常请求参数", "WebShell 特征", "批量探测路径"],
            "kill_chain_steps": [
                {"phase": KillChain.RECON, "technique": "指纹识别与目录探测", "probability": 0.75},
                {"phase": KillChain.WEAPONIZATION, "technique": "构造注入/上传 payload", "probability": 0.65},
                {"phase": KillChain.DELIVERY, "technique": "通过 HTTP 投递", "probability": 0.7},
                {"phase": KillChain.EXPLOITATION, "technique": "触发注入/文件上传", "probability": 0.5},
                {"phase": KillChain.INSTALLATION, "technique": "部署 WebShell", "probability": 0.55},
                {"phase": KillChain.C2, "technique": "通过 Web 接口通信", "probability": 0.6},
                {"phase": KillChain.ACTIONS, "technique": "窃取数据库/服务器权限", "probability": 0.5},
            ],
        },
        {
            "name": "供应链污染攻击",
            "description": "通过污染第三方依赖或更新分发通道植入恶意组件。",
            "category": AttackCategory.SUPPLY_CHAIN,
            "difficulty": "advanced",
            "severity": "critical",
            "ttps": ["T1195.002", "T1071", "T1565.002", "T1027"],
            "tools": ["依赖投毒（模拟）", "更新劫持（模拟）"],
            "iocs": ["异常包来源", "更新签名异常", "新增依赖仓"],
            "kill_chain_steps": [
                {"phase": KillChain.RECON, "technique": "分析依赖与更新机制", "probability": 0.55},
                {"phase": KillChain.WEAPONIZATION, "technique": "制作恶意组件", "probability": 0.6},
                {"phase": KillChain.DELIVERY, "technique": "发布/替换被污染组件", "probability": 0.45},
                {"phase": KillChain.EXPLOITATION, "technique": "目标拉取并安装", "probability": 0.5},
                {"phase": KillChain.INSTALLATION, "technique": "随合法软件安装", "probability": 0.55},
                {"phase": KillChain.C2, "technique": "合法流量中隐藏通信", "probability": 0.6},
                {"phase": KillChain.ACTIONS, "technique": "规模化影响下游用户", "probability": 0.5},
            ],
        },
        {
            "name": "内部威胁滥用",
            "description": "滥用内部人员合法权限进行数据窃取或破坏。",
            "category": AttackCategory.INSIDER_THREAT,
            "difficulty": "intermediate",
            "severity": "high",
            "ttps": ["T1078", "T1530", "T1213.002", "T1005"],
            "tools": ["合法账户", "数据下载（模拟）"],
            "iocs": ["非工作时间访问", "异常批量下载", "权限越界访问"],
            "kill_chain_steps": [
                {"phase": KillChain.RECON, "technique": "熟悉内部系统与权限", "probability": 0.85},
                {"phase": KillChain.WEAPONIZATION, "technique": "准备数据藏匿方式", "probability": 0.8},
                {"phase": KillChain.DELIVERY, "technique": "合法登录进入系统", "probability": 0.9},
                {"phase": KillChain.EXPLOITATION, "technique": "利用过度授权", "probability": 0.75},
                {"phase": KillChain.INSTALLATION, "technique": "无驻留，直接操作", "probability": 0.85},
                {"phase": KillChain.C2, "technique": "使用合法通道外传", "probability": 0.7},
                {"phase": KillChain.ACTIONS, "technique": "批量导出敏感数据", "probability": 0.65},
            ],
        },
        {
            "name": "分布式拒绝服务攻击",
            "description": "利用大量受控节点消耗目标带宽/资源，导致服务不可用。",
            "category": AttackCategory.DDOS,
            "difficulty": "intermediate",
            "severity": "medium",
            "ttps": ["T1498", "T1499", "T1499.003", "T1090"],
            "tools": ["反射放大（模拟）", "流量调度（模拟）"],
            "iocs": ["流量突增", "异常来源分布", "连接数饱和"],
            "kill_chain_steps": [
                {"phase": KillChain.RECON, "technique": "探测目标带宽与防护", "probability": 0.7},
                {"phase": KillChain.WEAPONIZATION, "technique": "构建流量源", "probability": 0.6},
                {"phase": KillChain.DELIVERY, "technique": "调度攻击节点", "probability": 0.65},
                {"phase": KillChain.EXPLOITATION, "technique": "发起反射/连接攻击", "probability": 0.7},
                {"phase": KillChain.INSTALLATION, "technique": "无安装阶段（直接压测）", "probability": 0.9},
                {"phase": KillChain.C2, "technique": "持续维持流量", "probability": 0.65},
                {"phase": KillChain.ACTIONS, "technique": "耗尽资源致服务中断", "probability": 0.6},
            ],
        },
        {
            "name": "零日漏洞利用",
            "description": "利用未公开漏洞实现高可靠初始访问与提权。",
            "category": AttackCategory.ZERO_DAY,
            "difficulty": "advanced",
            "severity": "critical",
            "ttps": ["T1190", "T1203", "T1068", "T1027.001"],
            "tools": ["0day 利用链（模拟）", "漏洞分析（模拟）"],
            "iocs": ["异常崩溃/重启", "内存可疑分配", "无补丁利用痕迹"],
            "kill_chain_steps": [
                {"phase": KillChain.RECON, "technique": "发现可利用组件", "probability": 0.4},
                {"phase": KillChain.WEAPONIZATION, "technique": "开发稳定利用链", "probability": 0.45},
                {"phase": KillChain.DELIVERY, "technique": "定向投递触发", "probability": 0.5},
                {"phase": KillChain.EXPLOITATION, "technique": "利用 0day 获取代码执行", "probability": 0.5},
                {"phase": KillChain.INSTALLATION, "technique": "部署难以检测的载荷", "probability": 0.55},
                {"phase": KillChain.C2, "technique": "低噪声 C2 通信", "probability": 0.6},
                {"phase": KillChain.ACTIONS, "technique": "实现战略目标", "probability": 0.55},
            ],
        },
        {
            "name": "社会工程诱导",
            "description": "通过电话、 impersonation 等手段诱导人员泄露信息或执行操作。",
            "category": AttackCategory.SOCIAL_ENGINEERING,
            "difficulty": "basic",
            "severity": "medium",
            "ttps": ["T1598.003", "T1656", "T1566", "T1136.001"],
            "tools": ["伪装话术（模拟）", "信息收集（模拟）"],
            "iocs": ["可疑来电", "诱导转账/开权限请求", "异常账户申请"],
            "kill_chain_steps": [
                {"phase": KillChain.RECON, "technique": "搜集组织架构与人员", "probability": 0.8},
                {"phase": KillChain.WEAPONIZATION, "technique": "设计伪装话术", "probability": 0.8},
                {"phase": KillChain.DELIVERY, "technique": "电话/IM 接触目标", "probability": 0.75},
                {"phase": KillChain.EXPLOITATION, "technique": "诱导泄露凭证/操作", "probability": 0.55},
                {"phase": KillChain.INSTALLATION, "technique": "用泄露信息登录", "probability": 0.6},
                {"phase": KillChain.C2, "technique": "合法会话维持", "probability": 0.65},
                {"phase": KillChain.ACTIONS, "technique": "获取受限资源", "probability": 0.55},
            ],
        },
        {
            "name": "凭证窃取与滥用",
            "description": "通过键盘记录、钓鱼、凭证转储获取账户凭证并滥用。",
            "category": AttackCategory.PHISHING,
            "difficulty": "intermediate",
            "severity": "high",
            "ttps": ["T1555.003", "T1056.001", "T1552.001", "T1078"],
            "tools": ["键盘记录（模拟）", "凭证读取（模拟）"],
            "iocs": ["可疑登录地", "凭证存储读取", "异常登录时间"],
            "kill_chain_steps": [
                {"phase": KillChain.RECON, "technique": "识别高价值账户", "probability": 0.7},
                {"phase": KillChain.WEAPONIZATION, "technique": "制作凭证收集器", "probability": 0.65},
                {"phase": KillChain.DELIVERY, "technique": "投递到目标终端", "probability": 0.6},
                {"phase": KillChain.EXPLOITATION, "technique": "采集键盘/存储凭证", "probability": 0.55},
                {"phase": KillChain.INSTALLATION, "technique": "定期回传凭证", "probability": 0.6},
                {"phase": KillChain.C2, "technique": "使用凭证建立会话", "probability": 0.65},
                {"phase": KillChain.ACTIONS, "technique": "以合法身份访问资源", "probability": 0.6},
            ],
        },
    ]


# ==================== 红队模拟器主类 ====================

class RedTeamSimulator:
    """红队攻击模拟器

    负责攻击场景管理、攻击模拟推演、攻击路径生成、影响评估与报告生成。
    所有推演均基于概率模型，不执行任何真实攻击动作。
    """

    def __init__(self):
        """初始化：建表并写入预定义攻击场景"""
        self._init_tables()
        self._seed_scenarios()

    # ---------- 数据库基础 ----------

    def _get_conn(self):
        """获取数据库连接（WAL 模式）"""
        return db._get_connection()

    def _init_tables(self):
        """初始化红队相关数据表"""
        conn = self._get_conn()
        cur = conn.cursor()
        cur.execute("""
            CREATE TABLE IF NOT EXISTS rt_attack_scenarios (
                id TEXT PRIMARY KEY,
                name TEXT NOT NULL,
                description TEXT,
                category TEXT NOT NULL,
                kill_chain_steps TEXT,
                ttps TEXT,
                tools TEXT,
                iocs TEXT,
                difficulty TEXT DEFAULT 'intermediate',
                severity TEXT DEFAULT 'medium',
                created_at TEXT NOT NULL
            )
        """)
        cur.execute("""
            CREATE TABLE IF NOT EXISTS rt_simulations (
                id TEXT PRIMARY KEY,
                scenario_id TEXT,
                name TEXT,
                target_scope TEXT,
                status TEXT DEFAULT 'pending',
                started_at TEXT,
                completed_at TEXT,
                success_probability REAL,
                impact_scope TEXT,
                business_impact TEXT,
                attack_paths TEXT,
                created_at TEXT NOT NULL
            )
        """)
        cur.execute("""
            CREATE TABLE IF NOT EXISTS rt_attack_paths (
                id TEXT PRIMARY KEY,
                simulation_id TEXT,
                path_order INTEGER,
                step_name TEXT,
                technique TEXT,
                from_asset TEXT,
                to_asset TEXT,
                success_probability REAL,
                details TEXT,
                created_at TEXT NOT NULL
            )
        """)
        cur.execute("CREATE INDEX IF NOT EXISTS idx_rt_sim_scenario ON rt_simulations(scenario_id)")
        cur.execute("CREATE INDEX IF NOT EXISTS idx_rt_path_sim ON rt_attack_paths(simulation_id)")
        conn.commit()
        conn.close()
        log.info("✅ 红队数据表初始化完成")

    def _seed_scenarios(self):
        """若场景表为空，批量写入预定义攻击场景"""
        conn = self._get_conn()
        count = conn.execute("SELECT COUNT(*) FROM rt_attack_scenarios").fetchone()[0]
        conn.close()
        if count > 0:
            return
        now = datetime.now().isoformat()
        conn = self._get_conn()
        for s in _seed_scenarios():
            conn.execute("""
                INSERT INTO rt_attack_scenarios
                (id, name, description, category, kill_chain_steps, ttps, tools, iocs,
                 difficulty, severity, created_at)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """, (
                str(uuid.uuid4()), s["name"], s["description"], s["category"],
                json.dumps(s["kill_chain_steps"], ensure_ascii=False),
                json.dumps(s["ttps"], ensure_ascii=False),
                json.dumps(s["tools"], ensure_ascii=False),
                json.dumps(s["iocs"], ensure_ascii=False),
                s["difficulty"], s["severity"], now,
            ))
        conn.commit()
        conn.close()
        log.info(f"✅ 红队预定义攻击场景写入完成: {len(_seed_scenarios())} 个")

    # ---------- 工具方法 ----------

    @staticmethod
    def _row_to_scenario(row) -> Dict[str, Any]:
        """把数据库行转换为场景字典（解析 JSON 字段）"""
        d = dict(row)
        for f in ("kill_chain_steps", "ttps", "tools", "iocs"):
            try:
                d[f] = json.loads(d[f]) if d.get(f) else []
            except Exception:
                d[f] = []
        return d

    @staticmethod
    def _row_to_simulation(row) -> Dict[str, Any]:
        """把数据库行转换为模拟任务字典"""
        d = dict(row)
        for f in ("target_scope", "impact_scope", "business_impact", "attack_paths"):
            try:
                d[f] = json.loads(d[f]) if d.get(f) else ({} if f == "business_impact" else [])
            except Exception:
                d[f] = []
        return d

    # ---------- 攻击场景管理 ----------

    def list_scenarios(self, category: Optional[str] = None,
                       severity: Optional[str] = None,
                       difficulty: Optional[str] = None) -> List[Dict[str, Any]]:
        """获取攻击场景列表，支持按分类/严重性/难度筛选"""
        conn = self._get_conn()
        query = "SELECT * FROM rt_attack_scenarios WHERE 1=1"
        params: List[Any] = []
        if category:
            query += " AND category = ?"
            params.append(category)
        if severity:
            query += " AND severity = ?"
            params.append(severity)
        if difficulty:
            query += " AND difficulty = ?"
            params.append(difficulty)
        query += " ORDER BY created_at ASC"
        rows = conn.execute(query, params).fetchall()
        conn.close()
        return [self._row_to_scenario(r) for r in rows]

    def get_scenario(self, scenario_id: str) -> Optional[Dict[str, Any]]:
        """获取单个攻击场景详情"""
        conn = self._get_conn()
        row = conn.execute(
            "SELECT * FROM rt_attack_scenarios WHERE id = ?", (scenario_id,)).fetchone()
        conn.close()
        return self._row_to_scenario(row) if row else None

    def create_scenario(self, name: str, description: str = "", category: str = "phishing",
                        kill_chain_steps: Optional[List[Dict]] = None,
                        ttps: Optional[List[str]] = None, tools: Optional[List[str]] = None,
                        iocs: Optional[List[str]] = None, difficulty: str = "intermediate",
                        severity: str = "medium") -> Dict[str, Any]:
        """创建自定义攻击场景"""
        scenario_id = str(uuid.uuid4())
        now = datetime.now().isoformat()
        steps = kill_chain_steps or [{"phase": ph, "technique": "", "probability": 0.5}
                                     for ph in KillChain.ORDER]
        conn = self._get_conn()
        conn.execute("""
            INSERT INTO rt_attack_scenarios
            (id, name, description, category, kill_chain_steps, ttps, tools, iocs,
             difficulty, severity, created_at)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """, (
            scenario_id, name, description, category,
            json.dumps(steps, ensure_ascii=False),
            json.dumps(ttps or [], ensure_ascii=False),
            json.dumps(tools or [], ensure_ascii=False),
            json.dumps(iocs or [], ensure_ascii=False),
            difficulty, severity, now,
        ))
        conn.commit()
        conn.close()
        log.info(f"✅ 创建自定义攻击场景: {name}")
        return self.get_scenario(scenario_id)

    # ---------- 攻击模拟 ----------

    def simulate_attack_path(self, scenario: Dict[str, Any],
                            target_scope: Dict[str, Any]) -> List[Dict[str, Any]]:
        """基于资产与漏洞信息模拟可能的攻击路径

        从入口到目标，逐阶段计算成功概率（前一阶段成功概率作为后一阶段基础）。
        本方法只做概率推演，不连接任何真实资产。
        """
        steps = scenario.get("kill_chain_steps") or []
        # 目标范围防御强度系数：范围越小/越聚焦，成功率越高
        asset_count = len(target_scope.get("assets", [])) if target_scope else 0
        defense_factor = 1.0 - min(0.3, asset_count * 0.03)
        path: List[Dict[str, Any]] = []
        cum_prob = 1.0
        from_asset = target_scope.get("entry_asset", "外部攻击者") if target_scope else "外部攻击者"
        for idx, step in enumerate(steps):
            base = float(step.get("probability", 0.5))
            # 引入小幅确定性扰动，使结果可复现但不呆板
            perturb = 1 + 0.05 * (((idx + 1) % 3) - 1) * 0.5
            step_prob = max(0.05, min(0.98, base * defense_factor * perturb))
            cum_prob *= step_prob
            to_asset = target_scope.get("target_asset", "核心业务资产") if (
                idx == len(steps) - 1 and target_scope) else f"阶段{idx + 1}:{step.get('phase', '')}"
            path.append({
                "path_order": idx + 1,
                "step_name": step.get("phase", ""),
                "technique": step.get("technique", ""),
                "from_asset": from_asset,
                "to_asset": to_asset,
                "success_probability": round(step_prob, 4),
                "details": {
                    "phase": step.get("phase", ""),
                    "ttps": scenario.get("ttps", []),
                    "cumulative_probability": round(cum_prob, 4),
                },
            })
            from_asset = to_asset
        return path

    def assess_impact(self, scenario: Dict[str, Any],
                      success_probability: float,
                      target_scope: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
        """评估攻击成功的业务影响

        输出数据泄露/服务中断/财务损失/声誉影响四个维度的评分与等级。
        """
        sev = scenario.get("severity", "medium")
        weight = _SEVERITY_IMPACT.get(sev, 0.5)
        # 综合影响 = 严重性权重 × 成功概率，再按维度差异化
        base = weight * max(0.1, success_probability)
        scope = target_scope or {}
        scale = min(1.0, 0.6 + len(scope.get("assets", [])) * 0.08)

        def lvl(score: float) -> str:
            if score >= 0.75:
                return "严重"
            if score >= 0.5:
                return "高"
            if score >= 0.25:
                return "中"
            return "低"

        cat = scenario.get("category", "")
        data_leak = base * (1.1 if cat in ("data_theft", "insider_threat", "phishing") else 0.8) * scale
        svc_down = base * (1.15 if cat in ("ransomware", "ddos", "supply_chain") else 0.7) * scale
        financial = base * (1.2 if cat in ("ransomware", "supply_chain") else 0.85) * scale
        reputation = base * (1.05 if cat in ("data_theft", "social_engineering") else 0.9) * scale

        return {
            "data_breach": {"score": round(min(1.0, data_leak), 3), "level": lvl(data_leak)},
            "service_disruption": {"score": round(min(1.0, svc_down), 3), "level": lvl(svc_down)},
            "financial_loss": {"score": round(min(1.0, financial), 3), "level": lvl(financial)},
            "reputation": {"score": round(min(1.0, reputation), 3), "level": lvl(reputation)},
            "overall_severity": sev,
        }

    def start_simulation(self, scenario_id: str, name: str = "",
                         target_scope: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
        """启动攻击模拟

        基于场景与目标范围推演攻击路径，计算成功概率与业务影响。
        不执行真实攻击，不获取真实访问权限。
        """
        scenario = self.get_scenario(scenario_id)
        if not scenario:
            raise ValueError(f"攻击场景不存在: {scenario_id}")

        target_scope = target_scope or {}
        sim_id = str(uuid.uuid4())
        now = datetime.now().isoformat()

        # 推演攻击路径
        path = self.simulate_attack_path(scenario, target_scope)
        # 整体成功概率 = 最后一步累计概率
        success_prob = path[-1]["details"]["cumulative_probability"] if path else 0.0
        impact = self.assess_impact(scenario, success_prob, target_scope)

        impact_scope = {
            "targets": target_scope.get("assets", []),
            "entry": target_scope.get("entry_asset", "外部"),
            "objective": target_scope.get("target_asset", "核心资产"),
        }

        conn = self._get_conn()
        conn.execute("""
            INSERT INTO rt_simulations
            (id, scenario_id, name, target_scope, status, started_at, completed_at,
             success_probability, impact_scope, business_impact, attack_paths, created_at)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """, (
            sim_id, scenario_id, name or scenario["name"],
            json.dumps(target_scope, ensure_ascii=False),
            "completed", now, now, round(success_prob, 4),
            json.dumps(impact_scope, ensure_ascii=False),
            json.dumps(impact, ensure_ascii=False),
            json.dumps(path, ensure_ascii=False), now,
        ))
        # 写入攻击路径明细
        for p in path:
            conn.execute("""
                INSERT INTO rt_attack_paths
                (id, simulation_id, path_order, step_name, technique, from_asset,
                 to_asset, success_probability, details, created_at)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """, (
                str(uuid.uuid4()), sim_id, p["path_order"], p["step_name"], p["technique"],
                p["from_asset"], p["to_asset"], p["success_probability"],
                json.dumps(p["details"], ensure_ascii=False), now,
            ))
        conn.commit()
        conn.close()
        log.info(f"✅ 红队攻击模拟完成: {sim_id} 成功率={success_prob:.2%}")
        return self.get_simulation_result(sim_id)

    def get_simulation_result(self, simulation_id: str) -> Optional[Dict[str, Any]]:
        """获取模拟结果：场景/攻击路径/成功概率/影响范围/业务影响"""
        conn = self._get_conn()
        row = conn.execute(
            "SELECT * FROM rt_simulations WHERE id = ?", (simulation_id,)).fetchone()
        if not row:
            conn.close()
            return None
        sim = self._row_to_simulation(row)
        scenario = self.get_scenario(sim.get("scenario_id"))
        paths = conn.execute(
            "SELECT * FROM rt_attack_paths WHERE simulation_id = ? ORDER BY path_order",
            (simulation_id,)).fetchall()
        conn.close()
        path_list = []
        for p in paths:
            pd = dict(p)
            try:
                pd["details"] = json.loads(pd["details"]) if pd["details"] else {}
            except Exception:
                pd["details"] = {}
            path_list.append(pd)
        sim["scenario"] = scenario
        sim["attack_path_detail"] = path_list
        return sim

    def get_attack_paths(self, simulation_id: str) -> Dict[str, Any]:
        """获取模拟的攻击路径（供前端可视化）"""
        result = self.get_simulation_result(simulation_id)
        if not result:
            return {"nodes": [], "edges": []}
        paths = result.get("attack_path_detail") or result.get("attack_paths") or []
        nodes = []
        edges = []
        for i, p in enumerate(paths):
            nodes.append({
                "id": f"step_{i}",
                "label": f"{p.get('step_name', '')}: {p.get('technique', '')}",
                "probability": p.get("success_probability"),
            })
            if i > 0:
                edges.append({"from": f"step_{i-1}", "to": f"step_{i}"})
        return {"nodes": nodes, "edges": edges, "steps": paths}

    def generate_red_team_report(self, simulation_id: str) -> Dict[str, Any]:
        """生成红队评估报告：场景/攻击路径/成功概率/影响/建议"""
        result = self.get_simulation_result(simulation_id)
        if not result:
            raise ValueError(f"模拟任务不存在: {simulation_id}")
        scenario = result.get("scenario") or {}
        impact = result.get("business_impact") or {}
        success = result.get("success_probability", 0)

        suggestions = []
        for dim, val in impact.items():
            if isinstance(val, dict) and val.get("score", 0) >= 0.5:
                suggestions.append(f"针对{dim}: 加强对应控制措施，降低{val.get('level', '')}风险")
        if success >= 0.6:
            suggestions.append("攻击成功率偏高，建议优先修补初始访问向量并强化监控")
        suggestions.append("定期开展钓鱼/社会工程演练，提升人员安全意识")

        report = {
            "report_type": "red_team",
            "title": f"红队评估报告 - {scenario.get('name', result.get('name', ''))}",
            "overview": {
                "scenario": scenario.get("name"),
                "category": scenario.get("category"),
                "difficulty": scenario.get("difficulty"),
                "severity": scenario.get("severity"),
                "success_probability": success,
            },
            "attack_path": result.get("attack_path_detail", []),
            "impact": impact,
            "ttps": scenario.get("ttps", []),
            "iocs": scenario.get("iocs", []),
            "suggestions": suggestions,
            "generated_at": datetime.now().isoformat(),
        }
        log.info(f"✅ 红队报告生成: {simulation_id}")
        return report
