# -*- coding: utf-8 -*-
"""
threat_actor.py — 威胁Actor与TTPs（第23轮升级方向3，全内存重写版）。

功能：
- 威胁Actor画像：名称/别名/国籍/动机/目标行业/攻击手法/工具/基础设施/历史攻击
- TTPs管理：ATT&CK矩阵映射/战术/技术/过程/软件/分组/描述/检测/缓解
- 攻击链分析：杀伤链/ATT&CK路径/攻击阶段识别/技术关联/工具关联
- 威胁狩猎：假设驱动/IOC驱动/TTP驱动/行为分析/异常检测/关联分析
- 威胁报告：Actor报告/TTPs报告/活动报告/行业报告/趋势
- 威胁模拟：攻击模拟/红队演练/紫队协作/防御有效性评估/改进建议

保留旧版 ThreatActorManager/Motivations/ActorSeverity 名称以兼容。
"""

from __future__ import annotations

import uuid
from datetime import datetime, timedelta
from typing import Any, Dict, List, Optional


# ==================== 兼容常量 ====================

class Motivations:
    ECONOMIC = "economic"
    POLITICAL = "political"
    ESPIONAGE = "espionage"
    SABOTAGE = "sabotage"
    OTHER = "other"


class ActorSeverity:
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"


# ==================== ATT&CK 矩阵（种子） ====================

ATTACK_TACTICS: List[Dict[str, str]] = [
    {"id": "TA0001", "name": "侦察 Reconnaissance"},
    {"id": "TA0002", "name": "资源开发 Resource Development"},
    {"id": "TA0003", "name": "初始访问 Initial Access"},
    {"id": "TA0004", "name": "执行 Execution"},
    {"id": "TA0005", "name": "持久化 Persistence"},
    {"id": "TA0006", "name": "权限提升 Privilege Escalation"},
    {"id": "TA0007", "name": "防御绕过 Defense Evasion"},
    {"id": "TA0008", "name": "凭证访问 Credential Access"},
    {"id": "TA0009", "name": "发现 Discovery"},
    {"id": "TA0010", "name": "横向移动 Lateral Movement"},
    {"id": "TA0011", "name": "收集 Collection"},
    {"id": "TA0011", "name": "命令与控制 Command & Control"},
    {"id": "TA0010", "name": "数据渗出 Exfiltration"},
    {"id": "TA0040", "name": "影响 Impact"},
]

ATTACK_TECHNIQUES: List[Dict[str, Any]] = [
    {"id": "T1566", "name": "鱼叉式钓鱼 Spearphishing", "tactic": "TA0003",
     "software": "BEC/PhishKit", "detection": "邮件网关IOC/发件人SPF异常",
     "mitigation": "安全意识培训+DMARC"},
    {"id": "T1190", "name": "利用面向公众的应用", "tactic": "TA0003",
     "software": "Exploit", "detection": "WAF异常请求/漏洞利用特征",
     "mitigation": "补丁+WAF+最小暴露"},
    {"id": "T1059", "name": "命令与脚本解释器", "tactic": "TA0004",
     "software": "PowerShell", "detection": "ETW脚本日志/异常进程树",
     "mitigation": "应用白名单/Constrained Language Mode"},
    {"id": "T1078", "name": "有效账户 Valid Accounts", "tactic": "TA0008",
     "software": "RDP/SSH", "detection": "异常登录地点/时间/频率",
     "mitigation": "MFA+条件访问"},
    {"id": "T1021", "name": "远程服务会话", "tactic": "TA0010",
     "software": "RDP/WinRM", "detection": "横向登录链/异常RDP",
     "mitigation": "网络分段+JEA"},
    {"id": "T1041", "name": "通过C2通道渗出", "tactic": "TA0010",
     "software": "Cobalt Strike", "detection": "异常外联/大流量出站",
     "mitigation": "出口代理+DLP"},
    {"id": "T1486", "name": "数据加密以影响", "tactic": "TA0040",
     "software": "勒索软件", "detection": "大量文件重命名/加密",
     "mitigation": "离线备份+EDR行为阻断"},
]


# ==================== 威胁Actor库（种子） ====================

ACTOR_LIBRARY: List[Dict[str, Any]] = [
    {"id": "apt41", "name": "APT41", "aliases": ["Barium", "Winnti Group", "Bronze Atlas"],
     "nationality": "中国", "motivation": "espionage+economic",
     "target_industries": ["科技", "游戏", "电信", "医疗"],
     "severity": "critical",
     "tools": ["Cobalt Strike", "PlugX", "Hikinni"],
     "infrastructure": ["bulletproof hosting", "compromised CDN"],
     "ttps": ["T1190", "T1059", "T1078", "T1041"],
     "history": "2020-2024 多起供应链+双重勒索活动"},
    {"id": "cl0p", "name": "Cl0p", "aliases": ["Clop", "Mustang Panda(误称)"],
     "nationality": "俄罗斯", "motivation": "economic",
     "target_industries": ["制造业", "物流", "政企"],
     "severity": "critical",
     "tools": ["Clop Ransomware", "GoBear"],
     "infrastructure": "暗网泄漏站",
     "ttps": ["T1190", "T1021", "T1486"],
     "history": "2023 MOVEit Transfer大规模数据窃取"},
    {"id": "emotet", "name": "Emotet", "aliases": ["Heodo"],
     "nationality": "俄罗斯", "motivation": "economic",
     "target_industries": ["全行业"],
     "severity": "high",
     "tools": ["Emotet loader", "TrickBot"],
     "infrastructure": "僵尸网络",
     "ttps": ["T1566", "T1059", "T1041"],
     "history": "2014-2023 垃圾邮件分发器"},
    {"id": "apt29", "name": "APT29", "aliases": ["Cozy Bear", "Nobelium"],
     "nationality": "俄罗斯", "motivation": "espionage",
     "target_industries": ["政府", "外交", "医疗"],
     "severity": "critical",
     "tools": ["CozyCar", "SUNSPOT"],
     "infrastructure": " compromised SSO",
     "ttps": ["T1566", "T1190", "T1078"],
     "history": "2020 SolarWinds供应链攻击"},
    {"id": "lazarus", "name": "Lazarus", "aliases": ["Hidden Cobra"],
     "nationality": "朝鲜", "motivation": "economic+espionage",
     "target_industries": ["金融", "加密货币"],
     "severity": "critical",
     "tools": ["HIDDENCOBRA", "DeltaCharlie"],
     "infrastructure": "长期C2",
     "ttps": ["T1566", "T1190", "T1486"],
     "history": "2014索尼影业攻击/2022 加密货币盗窃"},
]


class ThreatActorManager:
    """威胁Actor与TTPs管理，全内存模拟。"""

    def __init__(self) -> None:
        self.actors: Dict[str, Dict[str, Any]] = {}
        self.hunting_history: List[Dict[str, Any]] = []
        self.simulation_results: List[Dict[str, Any]] = []
        self._seed()

    @staticmethod
    def _now(days: int = 0) -> str:
        return (datetime.now() - timedelta(days=days)).isoformat()

    def _seed(self) -> None:
        for a in ACTOR_LIBRARY:
            self.actors[a["id"]] = {**a, "first_seen": self._now(days=365),
                                    "last_seen": self._now(), "activity_level": "active"}

    # ---------- Actor查询 ----------
    def list_actors(self, severity: Optional[str] = None,
                    industry: str = "", q: str = "") -> List[Dict[str, Any]]:
        out = list(self.actors.values())
        if severity:
            out = [a for a in out if a["severity"] == severity]
        if industry:
            out = [a for a in out if industry in a["target_industries"]]
        if q:
            ql = q.lower()
            out = [a for a in out if ql in a["name"].lower()
                   or any(ql in x.lower() for x in a["aliases"])
                   or ql in a["motivation"].lower()]
        return out

    def get_actor(self, aid: str) -> Optional[Dict[str, Any]]:
        return self.actors.get(aid)

    # ---------- TTPs / ATT&CK ----------
    def list_techniques(self, tactic: Optional[str] = None) -> List[Dict[str, Any]]:
        out = list(ATTACK_TECHNIQUES)
        if tactic:
            out = [t for t in out if t["tactic"] == tactic]
        return out

    def list_tactics(self) -> List[Dict[str, str]]:
        # 去重
        seen = set()
        out = []
        for t in ATTACK_TACTICS:
            if t["id"] not in seen:
                seen.add(t["id"])
                out.append(t)
        return out

    def actor_ttps(self, aid: str) -> List[Dict[str, Any]]:
        a = self.actors.get(aid)
        if not a:
            raise KeyError(f"Actor不存在: {aid}")
        ttp_ids = a.get("ttps", [])
        return [t for t in ATTACK_TECHNIQUES if t["id"] in ttp_ids]

    # ---------- 攻击链分析 ----------
    def kill_chain(self, aid: str) -> Dict[str, Any]:
        a = self.actors.get(aid)
        if not a:
            raise KeyError(f"Actor不存在: {aid}")
        stages = [
            ("侦察", "TA0001", ["收集目标公开信息/员工邮箱"]),
            ("初始访问", "TA0003", [t["name"] for t in self.actor_ttps(aid)
                                    if t["tactic"] == "TA0003"]),
            ("执行", "TA0004", [t["name"] for t in self.actor_ttps(aid)
                                if t["tactic"] == "TA0004"]),
            ("凭证访问", "TA0008", [t["name"] for t in self.actor_ttps(aid)
                                    if t["tactic"] == "TA0008"]),
            ("横向移动", "TA0010", [t["name"] for t in self.actor_ttps(aid)
                                    if t["tactic"] == "TA0010"]),
            ("渗出/影响", "TA0040", [t["name"] for t in self.actor_ttps(aid)
                                     if t["tactic"] == "TA0040"]),
        ]
        return {"actor": a["name"], "kill_chain": stages,
                "tools": a["tools"], "infrastructure": a["infrastructure"]}

    # ---------- 威胁狩猎 ----------
    def hunt(self, mode: str = "ttp", query: str = "") -> Dict[str, Any]:
        """假设/IOC/TTP驱动狩猎。"""
        findings = []
        if mode == "ttp":
            techs = self.list_techniques()
            findings = [{"technique": t["name"], "id": t["id"],
                         "detection_hint": t["detection"]} for t in techs[:5]]
        elif mode == "ioc":
            actors = self.list_actors(q=query)
            findings = [{"actor": a["name"], "ttps": a["ttps"],
                         "tools": a["tools"]} for a in actors]
        else:  # hypothesis
            findings = [{"hypothesis": "近期钓鱼邮件投递 loader",
                         "expected_ttps": ["T1566", "T1059"],
                         "data_source": "邮件日志/EDR进程"}]
        rec = {"time": self._now(), "mode": mode, "query": query,
               "findings": findings, "result_count": len(findings)}
        self.hunting_history.append(rec)
        return rec

    def list_hunting(self) -> List[Dict[str, Any]]:
        return self.hunting_history[-50:]

    # ---------- 报告 ----------
    def report(self, report_type: str = "actor") -> Dict[str, Any]:
        if report_type == "actor":
            return {"type": "actor", "generated": self._now(),
                    "actors": list(self.actors.values())}
        if report_type == "industry":
            return {"type": "industry", "generated": self._now(),
                    "summary": "金融/制造为近期重点目标，勒索与供应链为主"}
        return {"type": report_type, "generated": self._now(),
                "actors": len(self.actors),
                "techniques": len(ATTACK_TECHNIQUES)}

    # ---------- 威胁模拟 ----------
    def simulate(self, actor_id: str = "cl0p",
                 target_profile: str = "制造业") -> Dict[str, Any]:
        a = self.actors.get(actor_id, list(self.actors.values())[0])
        chain = self.kill_chain(a["id"])
        # 防御有效性评分：基于TTPS覆盖度
        covered = sum(1 for t in a["ttps"] if t in
                      ["T1190", "T1059"]) / max(1, len(a["ttps"]))
        result = {
            "time": self._now(), "actor": a["name"],
            "target": target_profile,
            "attack_path": chain["kill_chain"],
            "defense_effectiveness": round(covered * 100, 1),
            "gap": ["加强邮件钓鱼检测", "强化漏洞补丁时效", "部署EDR行为阻断"],
            "recommendation": "紫队演练：以Cl0p剧本验证横向移动检测",
        }
        self.simulation_results.append(result)
        return result

    def stats(self) -> Dict[str, Any]:
        sev: Dict[str, int] = {}
        for a in self.actors.values():
            sev[a["severity"]] = sev.get(a["severity"], 0) + 1
        return {"total_actors": len(self.actors),
                "by_severity": sev,
                "techniques": len(ATTACK_TECHNIQUES),
                "tactics": len({t["id"] for t in ATTACK_TACTICS}),
                "hunts": len(self.hunting_history)}


_manager: Optional[ThreatActorManager] = None


def get_threat_actor_manager() -> ThreatActorManager:
    global _manager
    if _manager is None:
        _manager = ThreatActorManager()
    return _manager
