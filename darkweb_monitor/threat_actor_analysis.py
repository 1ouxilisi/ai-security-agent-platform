# -*- coding: utf-8 -*-
"""
threat_actor_analysis.py — 威胁Actor与团伙分析器（第13轮升级）。

功能：
- 威胁Actor画像：名称/别名/类型(国家支持/犯罪团伙/黑客活动主义/脚本小子)/动机/目标行业/地区。
- 作案手法(TTPs)：初始访问/执行/持久化/权限提升/防御规避/凭据访问/发现/横向移动/收集/数据渗漏/影响。
- 攻击工具：恶意软件/漏洞利用/扫描器/暴力破解/C2框架/代理/清理工具。
- 关联分析：Actor间关联/工具共享/基础设施共享/TTPs相似/时间与目标关联。
- 团伙识别：成员/结构/分工/指挥链/资金流/沟通渠道。
- 历史活动与能力演进。
- 威胁等级评估（低/中/高/严重/关键）。

说明：威胁Actor库与TTPs模板内嵌（MITRE ATT&CK风格），
仅用于防御性威胁情报；第三方库 try-import，不可用时用模拟数据。
"""

from __future__ import annotations

import hashlib
import time
from dataclasses import asdict, dataclass, field
from typing import Any, Dict, List, Optional


# ==================== 威胁Actor库（公开威胁情报，防御用） ====================

THREAT_ACTOR_DB: List[Dict[str, Any]] = [
    {
        "id": "TA-APT001", "name": "LockBit团伙", "aliases": ["LockBit", "BlackMatter(关联)"],
        "type": "犯罪团伙", "motivation": "经济利益",
        "target_industries": ["医疗", "制造", "政府", "金融"],
        "target_regions": ["北美", "欧洲", "全球"],
        "capability": "高", "resources": "充足", "active_since": 2019,
        "tools": ["LockBit勒索器", "Cobalt Strike", "Rclone", "AnyDesk"],
        "ttps": ["钓鱼邮件", "利用RDP", "凭证窃取", "横向移动", "双重勒索"],
        "threat_level": "严重",
    },
    {
        "id": "TA-APT002", "name": "Scattered Spider", "aliases": ["Roasted 0ktapus", "Starfraud"],
        "type": "犯罪团伙", "motivation": "经济利益",
        "target_industries": ["BPO", "电信", "云服务", "游戏"],
        "target_regions": ["北美", "欧洲", "亚太"],
        "capability": "高", "resources": "中等", "active_since": 2022,
        "tools": ["社会工程", "Helpdesk诈骗", "SAML滥用", "AAD内部应用"],
        "ttps": ["语音钓鱼", "身份验证绕过", "云租户接管", "数据渗漏"],
        "threat_level": "高",
    },
    {
        "id": "TA-APT003", "name": "LAPSUS$", "aliases": ["DELL(历史名)", "Curious Nekomata"],
        "type": "犯罪团伙", "motivation": "名望+经济",
        "target_industries": ["科技", "游戏", "互联网大厂"],
        "target_regions": ["全球"],
        "capability": "中", "resources": "中等", "active_since": 2021,
        "tools": ["社工", "票据重置", "内部人员收买", "匿名代理"],
        "ttps": ["身份验证社工", " OAuth滥用", "数据公开泄露"],
        "threat_level": "高",
    },
    {
        "id": "TA-APT004", "name": "Criminal IP爬虫群", "aliases": ["扫描botnet"],
        "type": "脚本小子/自动化", "motivation": "机会主义",
        "target_industries": ["全行业"],
        "target_regions": ["全球"],
        "capability": "低", "resources": "低", "active_since": 2020,
        "tools": ["masscan", "nmap", "默认凭证扫描"],
        "ttps": ["端口扫描", "默认口令爆破", "漏洞利用"],
        "threat_level": "低",
    },
    {
        "id": "TA-APT005", "name": "信息窃取者联盟", "aliases": ["Infostealer Crew"],
        "type": "犯罪团伙", "motivation": "经济利益",
        "target_industries": ["全行业(员工终端)"],
        "target_regions": ["全球"],
        "capability": "中", "resources": "中等", "active_since": 2022,
        "tools": ["RedLine", "Raccoon Stealer", "Telegram外泄频道"],
        "ttps": ["钓鱼投递", "信息窃取", "凭证出售", "账户接管"],
        "threat_level": "高",
    },
]

# MITRE ATT&CK 风格 TTPs 模板（按战术）
ATTACK_TTP_TEMPLATE: Dict[str, List[Dict[str, str]]] = {
    "初始访问": [
        {"id": "TA0001", "technique": "钓鱼邮件(T1566)", "note": "投递恶意附件/链接"},
        {"id": "TA0001", "technique": "利用面向公众应用(T1190)", "note": "暴露Web服务漏洞"},
        {"id": "TA0001", "technique": "有效账户(T1078)", "note": "泄露凭证登录"},
    ],
    "执行": [
        {"id": "TA0002", "technique": "命令脚本解释器(T1059)", "note": "PowerShell/Bash执行"},
    ],
    "持久化": [
        {"id": "TA0003", "technique": "启动项/服务(T1543)", "note": "开机自启"},
    ],
    "权限提升": [
        {"id": "TA0004", "technique": "利用漏洞提权(T08)", "note": "本地提权"},
    ],
    "防御规避": [
        {"id": "TA0005", "technique": "混淆文件/信息(T1027)", "note": "加壳/加密"},
    ],
    "凭据访问": [
        {"id": "TA0006", "technique": "凭证转储(T1003)", "note": "LSASS/数据库"},
    ],
    "发现": [
        {"id": "TA0007", "technique": "网络服务扫描(T1046)", "note": "内网探测"},
    ],
    "横向移动": [
        {"id": "TA0008", "technique": "远程服务(T1021)", "note": "RDP/SMB"},
    ],
    "收集": [
        {"id": "TA0009", "technique": "数据打包(T1560)", "note": "压缩归档"},
    ],
    "数据渗漏": [
        {"id": "TA0010", "technique": "渗漏覆盖C2(T1041)", "note": "外发数据"},
    ],
    "影响": [
        {"id": "TA0040", "technique": "数据加密勒索(T1486)", "note": "勒索/双重勒索"},
    ],
}

# 威胁等级权重
THREAT_LEVEL_SCORE = {"低": 10, "中": 30, "高": 60, "严重": 85, "关键": 95}


# ==================== 威胁Actor分析器 ====================

class ThreatActorAnalyzer:
    """威胁Actor与团伙分析器"""

    def __init__(self) -> None:
        self.db: List[Dict[str, Any]] = list(THREAT_ACTOR_DB)

    @staticmethod
    def _seed(text: str) -> int:
        return int(hashlib.md5(text.encode("utf-8", "ignore")).hexdigest(), 16)

    # ---------- Actor 列表 ----------

    def list_actors(self) -> Dict[str, Any]:
        by_type: Dict[str, int] = {}
        by_level: Dict[str, int] = {}
        for a in self.db:
            by_type[a["type"]] = by_type.get(a["type"], 0) + 1
            by_level[a["threat_level"]] = by_level.get(a["threat_level"], 0) + 1
        return {
            "total_actors": len(self.db),
            "by_type": by_type,
            "by_threat_level": by_level,
            "actors": [{"id": a["id"], "name": a["name"], "aliases": a["aliases"],
                         "type": a["type"], "motivation": a["motivation"],
                         "threat_level": a["threat_level"],
                         "target_industries": a["target_industries"]} for a in self.db],
        }

    # ---------- Actor 画像 ----------

    def get_profile(self, actor_id: str) -> Optional[Dict[str, Any]]:
        a = next((x for x in self.db if x["id"] == actor_id), None)
        return dict(a) if a else None

    # ---------- TTPs ----------

    def get_ttps(self, actor_id: Optional[str] = None) -> Dict[str, Any]:
        if actor_id:
            a = self.get_profile(actor_id)
            if not a:
                return {"error": "Actor不存在", "tactics": ATTACK_TTP_TEMPLATE}
            # 以 Actor 实际 TTP 为主，叠加模板结构
            return {
                "actor": a["name"],
                "observed_ttps": a["ttps"],
                "tools": a["tools"],
                "tactic_template": ATTACK_TTP_TEMPLATE,
            }
        return {"tactics": ATTACK_TTP_TEMPLATE, "total_tactics": len(ATTACK_TTP_TEMPLATE)}

    # ---------- 关联分析 ----------

    def correlation_analysis(self) -> Dict[str, Any]:
        # 基于工具/TTP 共享构建关联
        links: List[Dict[str, Any]] = []
        for i, a in enumerate(self.db):
            for b in self.db[i + 1:]:
                shared_tools = set(a["tools"]) & set(b["tools"])
                shared_ttps = set(a["ttps"]) & set(b["ttps"])
                if shared_tools or shared_ttps:
                    links.append({
                        "actor_a": a["name"], "actor_b": b["name"],
                        "shared_tools": sorted(shared_tools),
                        "shared_ttps": sorted(shared_ttps),
                        "relation_strength": "high" if len(shared_tools) >= 2 else "medium",
                    })
        return {
            "total_actors": len(self.db),
            "correlations": links,
            "correlation_count": len(links),
        }

    # ---------- 团伙识别 ----------

    def group_identification(self, actor_id: str = "TA-APT001") -> Dict[str, Any]:
        a = self.get_profile(actor_id) or self.db[0]
        return {
            "actor": a["name"],
            "structure": "分层结构(核心开发+Affiliate分销)",
            "members_estimate": 15 + (self._seed(actor_id) % 30),
            "division_of_labor": ["初始访问(钓鱼)", "横向移动", "数据渗漏", "谈判/赎金"],
            "command_chain": ["上游C2", "Affiliate", "受害者"],
            "money_flow": "加密货币赎金 + Affiliate分成",
            "communication_channels": ["加密即时通讯", "地下论坛"],
        }

    # ---------- 历史活动 ----------

    def history(self, actor_id: str = "TA-APT001") -> Dict[str, Any]:
        a = self.get_profile(actor_id) or self.db[0]
        seed = self._seed(actor_id)
        return {
            "actor": a["name"],
            "active_since": a["active_since"],
            "attack_timeline": [
                {"year": 2023, "events": 4 + seed % 3, "target": "医疗/制造"},
                {"year": 2024, "events": 6 + seed % 4, "target": "扩展至金融"},
                {"year": 2025, "events": 5 + seed % 3, "target": "亚太地区上升"},
                {"year": 2026, "events": 3 + seed % 2, "target": "双重勒索常态化"},
            ],
            "capability_evolution": "从单阶段勒索演进为初始访问即服务(IaaS)+双重勒索",
        }

    # ---------- 威胁等级评估 ----------

    def assess_threat_level(self, actor_id: str,
                            overlap: bool = False) -> Dict[str, Any]:
        a = self.get_profile(actor_id) or self.db[0]
        base = THREAT_LEVEL_SCORE.get(a["threat_level"], 30)
        if overlap:
            base = min(100, base + 15)
        level = a["threat_level"]
        if overlap and base >= 85:
            level = "关键"
        return {
            "actor": a["name"],
            "capability": a["capability"],
            "motivation": a["motivation"],
            "resources": a["resources"],
            "target_overlap": overlap,
            "threat_score": base,
            "threat_level": level,
            "reasoning": (f"能力({a['capability']})+动机({a['motivation']})+"
                          f"{'目标重叠' if overlap else '无明显目标重叠'}"),
        }

    # ---------- 报告 ----------

    def generate_report(self, actor_id: Optional[str] = None) -> Dict[str, Any]:
        prof = self.get_profile(actor_id) if actor_id else None
        corr = self.correlation_analysis()
        top = sorted(self.db,
                     key=lambda x: THREAT_LEVEL_SCORE.get(x["threat_level"], 0),
                     reverse=True)[0]
        return {
            "report_title": "威胁Actor与团伙分析报告",
            "generated_at": time.strftime("%Y-%m-%d %H:%M:%S"),
            "executive_summary": (
                f"监控 {len(self.db)} 个威胁Actor，最高威胁等级为 "
                f"{top['name']}({top['threat_level']})。"
                f"识别 {corr['correlation_count']} 组Actor关联关系。"),
            "watchlist": [{"name": a["name"], "level": a["threat_level"],
                            "type": a["type"]} for a in self.db],
            "top_actor": {"name": top["name"], "ttps": top["ttps"], "tools": top["tools"]},
            "correlations": corr,
            "profile_detail": prof,
            "legal_boundary": "威胁情报仅用于防御、狩猎与预警，不用于攻击第三方。",
        }


# ==================== 工厂函数 ====================

_actor_singleton: Optional[ThreatActorAnalyzer] = None


def get_threat_actor_analyzer() -> ThreatActorAnalyzer:
    global _actor_singleton
    if _actor_singleton is None:
        _actor_singleton = ThreatActorAnalyzer()
    return _actor_singleton
