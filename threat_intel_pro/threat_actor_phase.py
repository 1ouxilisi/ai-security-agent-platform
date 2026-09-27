# -*- coding: utf-8 -*-
"""
threat_actor_phase.py — 方向2 威胁情报 Pro：阶段4 威胁 Actor 画像。

内置 20+ 知名黑客组织画像，含:
    名称/别名/所属国家、动机、TTPs(MITRE ATT&CK 映射)、目标行业、
    常用工具/恶意软件、历史攻击事件、攻击能力评估。

支持 Actor 关联分析（工具共享 / 基础设施共享 / TTP 相似度）与搜索。
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional


@dataclass
class ThreatActor:
    actor_id: str = ""
    name: str = ""
    aliases: List[str] = field(default_factory=list)
    country: str = ""
    motivation: str = ""          # economic/political/espionage/destructive
    target_industries: List[str] = field(default_factory=list)
    ttps: List[str] = field(default_factory=list)   # ATT&CK technique ids
    tools: List[str] = field(default_factory=list)
    malware: List[str] = field(default_factory=list)
    notable_events: List[str] = field(default_factory=list)
    capability: str = "medium"     # low/medium/high/advanced
    first_seen: str = ""
    description: str = ""

    def to_dict(self) -> Dict[str, Any]:
        return {
            "actor_id": self.actor_id, "name": self.name,
            "aliases": self.aliases, "country": self.country,
            "motivation": self.motivation,
            "target_industries": self.target_industries,
            "ttps": self.ttps, "tools": self.tools,
            "malware": self.malware,
            "notable_events": self.notable_events,
            "capability": self.capability,
            "first_seen": self.first_seen,
            "description": self.description,
        }


# --------------------------------------------------------------------------- #
# 20+ 知名组织画像（公开报告整理）
# --------------------------------------------------------------------------- #
ACTOR_PROFILES: List[Dict[str, Any]] = [
    {
        "name": "Lazarus Group", "aliases": ["Hidden Cobra", "ZINC",
            "Diamond Sleet"], "country": "朝鲜 (KP)",
        "motivation": "economic/espionage",
        "target_industries": ["金融", "加密货币", "关键基础设施", "政府"],
        "ttps": ["T1566", "T1204.002", "T1059.003", "T1486",
                 "T1105", "T1078"],
        "tools": ["ObliqueRAT", "DeltaCharlie"],
        "malware": ["Andariel", "Marai", "Olympic Destroyer", "WannaCrypt0r"],
        "notable_events": ["2014 Sony Pictures 攻击",
            "2016 Bank of Bangladesh 抢劫 8100 万美元",
            "2023 加密货币钓鱼/假应用"],
        "capability": "advanced", "first_seen": "2009",
        "description": "朝鲜国家背景组织，兼具间谍与金融抢劫能力，"
                       "以高度定制化载荷和长潜伏期著称。",
    },
    {
        "name": "APT28 (Fancy Bear)", "aliases": ["Sofacy", "Sednit",
            "STRONTIUM", "Pawn Storm"], "country": "俄罗斯 (RU)",
        "motivation": "espionage/political",
        "target_industries": ["政府", "军事", "外交", "选举机构", "媒体"],
        "ttps": ["T1566.001", "T1595", "T1037.001", "T1071.001",
                 "T1203", "T1189"],
        "tools": ["Cobalt Strike", "Zebrocy"],
        "malware": ["X-Agent", "Sofacy Trojan", "ComRAT", "Downdelph"],
        "notable_events": ["2015 DNC 邮件泄露",
            "2016 DNC 黑客事件", "2017 奥运会 WannaCry 关联"],
        "capability": "advanced", "first_seen": "2004",
        "description": "俄罗斯 GRU 所属网络间谍单位，针对性钓鱼与"
                       "零日利用，政治导向明显。",
    },
    {
        "name": "APT29 (Cozy Bear)", "aliases": ["Nobelium", "UNC2452",
            "Blue Kitsune"], "country": "俄罗斯 (RU)",
        "motivation": "espionage",
        "target_industries": ["政府", "外交", "智库", "医疗", "科技"],
        "ttps": ["T1566.001", "T1136.003", "T1090", "T1528",
                 "T1568", "T1078.004"],
        "tools": ["SolarWinds Orion", "HUI Loader"],
        "malware": ["SUNBURST", "TEARDROP", "Nobelium Malware"],
        "notable_events": ["2020 SolarWinds 供应链攻击",
            "2021 HAFNIUM 关联 Exchange 攻击"],
        "capability": "advanced", "first_seen": "2008",
        "description": "俄罗斯 SVR 所属，以长期潜伏、静默侦察见长，"
                       "擅长供应链与云身份攻击。",
    },
    {
        "name": "APT41", "aliases": ["Winnti Group", "Barium",
            "Feathered Ticket"], "country": "中国 (CN)",
        "motivation": "espionage/economic",
        "target_industries": ["游戏", "科技", "电信", "金融", "视频游戏"],
        "ttps": ["T1190", "T1078", "T1486", "T1059.001",
                 "T1036.005", "T1543.003"],
        "tools": ["Cobalt Strike", "Huarong"],
        "malware": ["HighBLand", "Picker", "UltraVNC"],
        "notable_events": ["2020 游戏公司源代码盗窃",
            "2021 多起勒索软件事件"],
        "capability": "advanced", "first_seen": "2012",
        "description": "中国背景复合组织，兼具间谍与犯罪双重目标，"
                       "滥用零日与勒索软件。",
    },
    {
        "name": "APT33 (Elfin)", "aliases": ["Holmium", "Refined Kitten"],
        "country": "伊朗 (IR)", "motivation": "espionage",
        "target_industries": ["石化", "能源", "航空", "金融"],
        "ttps": ["T1566.001", "T1105", "T1048.003", "T1059.001",
                 "T1555.003"],
        "tools": ["Cobalt Strike"],
        "malware": ["StoneDrill", "Myler", "Bokmek"],
        "notable_events": ["2017 石化行业钓鱼",
            "2018 与 Sandworm 关联的破坏性攻击"],
        "capability": "high", "first_seen": "2013",
        "description": "伊朗网络间谍组织，聚焦中东能源与航空业。",
    },
    {
        "name": "APT29-Nobelium", "aliases": ["UNC2452"],
        "country": "俄罗斯 (RU)", "motivation": "espionage",
        "target_industries": ["政府", "NGO", "医疗"],
        "ttps": ["T1528", "T1090.004"],
        "tools": [], "malware": ["SUNBURST"],
        "notable_events": ["SolarWinds"],
        "capability": "advanced", "first_seen": "2020",
        "description": "Nobelium 子活动集，聚焦云身份与邮件。",
    },
    {
        "name": "FIN7", "aliases": ["Carbanak", "GOLD NIAGARA"],
        "country": "俄罗斯 (RU)", "motivation": "economic",
        "target_industries": ["零售", "餐饮", "酒店", "金融"],
        "ttps": ["T1566.001", "T1059.001", "T1036.005", "T1078",
                 "T1059.003"],
        "tools": ["Carbanak", "PowerSploit"],
        "malware": ["Carbanak", "Dridex", "Maze"],
        "notable_events": ["2013-2018 全球金融机构盗窃超 10 亿美元",
            "2020 美国餐饮 POS 攻击"],
        "capability": "advanced", "first_seen": "2013",
        "description": "俄罗斯网络犯罪集团，以金融盗窃和零售 POS 入侵著称。",
    },
    {
        "name": "LAPSUS$", "aliases": ["DEV-0537"],
        "country": "巴西/英国/韩国 (无归属)", "motivation": "economic/political",
        "target_industries": ["科技", "游戏", "云服务商", "电信"],
        "ttps": ["T1589.001", "T1078", "T1213.003", "T1555.003",
                 "T1598.004"],
        "tools": ["OSINT", "SIM 交换"],
        "malware": [],
        "notable_events": ["2022 Microsoft/NVIDIA/三星数据勒索",
            "2022 Okta 源代码泄露"],
        "capability": "high", "first_seen": "2021",
        "description": "青少年为主的黑产组织，靠社会工程与凭证重用入侵大牌。",
    },
    {
        "name": "REvil (Sodinokibi)", "aliases": ["GOLD SOUTHFIELD"],
        "country": "俄罗斯 (RU)", "motivation": "economic",
        "target_industries": ["制造业", "科技", "医疗", "教育"],
        "ttps": ["T1486", "T1566.001", "T1105", "T1059.003",
                 "T1021.001"],
        "tools": ["RaaS 平台"],
        "malware": ["Sodinokibi", "REvil"],
        "notable_events": ["2021 Kaseya MSP 大规模勒索",
            "2021 高露洁 Palmer 数据泄露"],
        "capability": "advanced", "first_seen": "2019",
        "description": "大型 RaaS 运营方，双重勒索（加密+泄露）。",
    },
    {
        "name": "Conti Group", "aliases": ["Wizard Spider",
            "UNC1878"], "country": "俄罗斯 (RU)",
        "motivation": "economic",
        "target_industries": ["医疗", "政府", "关键基础设施", "制造"],
        "ttps": ["T1021.001", "T1078", "T1486", "T1059.003",
                 "T1505.003"],
        "tools": ["Cobalt Strike", "Rclone"],
        "malware": ["Conti", "TrickBot", "Ryuk", "Bazar"],
        "notable_events": ["2020 爱尔兰健康系统 HSE 攻击",
            "2021 全球医院勒索潮"],
        "capability": "advanced", "first_seen": "2018",
        "description": "TrickBot 投递链 + Ryuk/Conti 勒索，工业化运营。",
    },
    {
        "name": "Emotet Team", "aliases": ["Heodo", "Mealybug"],
        "country": "俄罗斯/东欧", "motivation": "economic",
        "target_industries": ["全行业", "制造", "政府"],
        "ttps": ["T1566.001", "T1204.002", "T1105", "T1059.001",
                 "T1047"],
        "tools": [],
        "malware": ["Emotet", "TrickBot", "IcedID"],
        "notable_events": ["2018-2021 全球垃圾邮件分发之王",
            "2021 执法 takedown"],
        "capability": "high", "first_seen": "2014",
        "description": "模块化银行木马兼恶意软件分发平台，蠕虫式横向传播。",
    },
    {
        "name": "Volt Typhoon", "aliases": ["BRONZE SILHOUETTE",
            "DEV-0391"], "country": "中国 (CN)",
        "motivation": "espionage",
        "target_industries": ["关键基础设施", "电力", "通信", "水利"],
        "ttps": ["T1078", "T1590", "T1021.001", "T1090",
                 "T1003.005"],
        "tools": ["lotl 工具", "Fast Reverse Proxy"],
        "malware": [],
        "notable_events": ["2023 美国关键基础设施潜伏侦察",
            "2024 关岛相关目标测绘"],
        "capability": "advanced", "first_seen": "2021",
        "description": "中国背景针对美关键基础设施的长期潜伏侦察，"
                       "强调低调与现存凭证滥用。",
    },
    {
        "name": "Kimsuky", "aliases": ["Black Banshee", "TA427"],
        "country": "朝鲜 (KP)", "motivation": "espionage",
        "target_industries": ["韩国政府", "智库", "脱北者", "媒体"],
        "ttps": ["T1566.001", "T1204.002", "T1059.003",
                 "T1553.002"],
        "tools": [],
        "malware": ["TRANSLATEXT", "TRANSLATEGO", "APPLESEED"],
        "notable_events": ["2023 韩语社会工程钓鱼",
            "2024 伪装成脱北者社群 App"],
        "capability": "high", "first_seen": "2018",
        "description": "朝鲜对韩间谍组织，高度本地化社会工程。",
    },
    {
        "name": "Scattered Spider", "aliases": ["Roasted 0ktapus",
            "Storm-0875"], "country": "美国/英国",
        "motivation": "economic",
        "target_industries": ["呼叫中心", "云服务商", "MSSP", "酒店"],
        "ttps": ["T1589", "T1598", "T1078", "T1090.004",
                 "T1486"],
        "tools": [],
        "malware": [],
        "notable_events": ["2023 MGM Resorts 入侵",
            "2023 多个呼叫中心社会工程"],
        "capability": "high", "first_seen": "2022",
        "description": "英语母语社会工程团伙，靠冒充 IT 人员接管云租户。",
    },
    {
        "name": "Sandworm Team", "aliases": ["Telebots", "Voodoo Bear"],
        "country": "俄罗斯 (RU)", "motivation": "destructive/political",
        "target_industries": ["乌克兰", "格鲁吉亚", "关键基础设施"],
        "ttps": ["T1489", "T1499", "T1190", "T1078",
                 "T1566.001"],
        "tools": ["NotPetya", "CrashOverride"],
        "malware": ["BlackEnergy", "NotPetya", "Industroyer"],
        "notable_events": ["2015/2016 乌克兰电网断电",
            "2017 NotPetya 全球扩散", "2022 乌克兰电力攻击"],
        "capability": "advanced", "first_seen": "2009",
        "description": "俄罗斯 GRU 破坏性攻击单位，以工控与关键基础设施"
                       "破坏著称。",
    },
    {
        "name": "Equation Group", "aliases": ["Temple of Oak"],
        "country": "美国 (US)", "motivation": "espionage",
        "target_industries": ["全球政府", "金融", "能源"],
        "ttps": ["T1564.005", "T1070.006", "T1124",
                 "T1480.001"],
        "tools": ["GrayFish", "Fanny"],
        "malware": ["EquationDrug", "GrayFish", "FsOmen"],
        "notable_events": ["2015 Equation Group 工具泄露",
            "硬盘固件级 Rootkit"],
        "capability": "advanced", "first_seen": "2001",
        "description": "NSA 所属顶级精英组织，具备硬盘固件植入能力。",
    },
    {
        "name": "APT1 (Comment Crew)", "aliases": ["Comment Group",
            "Bone Dragon"], "country": "中国 (CN)",
        "motivation": "espionage",
        "target_industries": ["全球企业", "政府", "制造业"],
        "ttps": ["T1566.001", "T1003.001", "T1074.001",
                 "T1059.003"],
        "tools": ["Cobalt Strike"],
        "malware": ["PoisonIvy", "Hydraq", "gh0st RAT"],
        "notable_events": ["2013 Mandiant APT1 报告",
            "2010-2013 大规模企业间谍"],
        "capability": "high", "first_seen": "2006",
        "description": "首个被公开点名的中国 APT 组织，65 万人被窃。",
    },
    {
        "name": "Dragonfly (Energetic Bear)", "aliases": ["Berserk Bear"],
        "country": "俄罗斯 (RU)", "motivation": "espionage",
        "target_industries": ["能源", "工控", "电力", "水务"],
        "ttps": ["T1190", "T1078", "T1560", "T1059.003"],
        "tools": ["Crimson"],
        "malware": ["Backdoor.Oldrea", "Hamertag"],
        "notable_events": ["2017 美国水务/电力公司入侵",
            "2021 全球能源供应链钓鱼"],
        "capability": "high", "first_seen": "2010",
        "description": "俄罗斯聚焦能源与工控的侦察组织。",
    },
    {
        "name": "Turla", "aliases": ["Waterbug", "WhiteBear",
            "Belugasturgeon"], "country": "俄罗斯 (RU)",
        "motivation": "espionage",
        "target_industries": ["政府", "外交", "军事", "科研"],
        "ttps": ["T1059.005", "T1071.001", "T1546.005",
                 "T1112"],
        "tools": ["Uroburos"],
        "malware": ["Uroburos", "SNAKEMILO", "LunarWeb"],
        "notable_events": ["2014 德国外长办公室被入侵",
            "多年驻欧洲使馆间谍活动"],
        "capability": "advanced", "first_seen": "2004",
        "description": "俄罗斯 SVR 长期间谍组织，模块化高度定制。",
    },
    {
        "name": "Chimera", "aliases": ["BRONZE FLEETWOOD",
            "Cinnamon Tempest"], "country": "中国 (CN)",
        "motivation": "espionage",
        "target_industries": ["半导体", "科技", "国防", "金融"],
        "ttps": ["T1190", "T1566.001", "T1078", "T1059.003"],
        "tools": ["Cobalt Strike"],
        "malware": ["PlugX", "SodaMaster"],
        "notable_events": ["2021 台湾半导体公司入侵",
            "2022 全球科技业供应链攻击"],
        "capability": "advanced", "first_seen": "2018",
        "description": "中国聚焦半导体与高科技产业的 APT 组织。",
    },
    {
        "name": "GALLIUM", "aliases": ["Granit Typhoon"],
        "country": "中国 (CN)", "motivation": "espionage",
        "target_industries": ["电信", "互联网服务提供商"],
        "ttps": ["T1190", "T1078", "T1090", "T1059.003"],
        "tools": ["PoisonIvy"],
        "malware": ["China Chopper", "PlugX"],
        "notable_events": ["2018 东南亚电信入侵",
            "2020 美国电信入侵"],
        "capability": "high", "first_seen": "2012",
        "description": "中国针对电信基础设施的 APT 组织。",
    },
    {
        "name": "Mustang Panda", "aliases": ["TA419", "Bronze President"],
        "country": "中国 (CN)", "motivation": "espionage",
        "target_industries": ["政府", "外交", "军事", "科研", "NGO"],
        "ttps": ["T1566.001", "T1204.002", "T1059.003",
                 "T1106"],
        "tools": [],
        "malware": ["HiZor", "Proton", "Tropic Trooper"],
        "notable_events": ["2012 起针对藏区流亡政府",
            "多年外交政策机构钓鱼"],
        "capability": "high", "first_seen": "2012",
        "description": "中国针对藏区/外交/科研的长期钓鱼组织。",
    },
    {
        "name": "ToddyCat", "aliases": ["NastyShrew"],
        "country": "中国 (CN)", "motivation": "espionage",
        "target_industries": ["政府", "军事", "关键基础设施"],
        "ttps": ["T1190", "T1090", "T1059.003", "T1543.003"],
        "tools": [],
        "malware": ["Samurai", "Ninja"],
        "notable_events": ["2023 欧洲政府网络入侵",
            "2024 多国军事目标"],
        "capability": "advanced", "first_seen": "2020",
        "description": "新兴高度隐蔽 APT，自研 Samurai/Ninja 加载器。",
    },
]


class ThreatActorPhase:
    """阶段4: 威胁 Actor 画像。"""

    def __init__(self) -> None:
        self._actors: Dict[str, ThreatActor] = {}
        for idx, p in enumerate(ACTOR_PROFILES):
            a = ThreatActor(
                actor_id=f"actor_{idx+1:02d}",
                name=p["name"], aliases=p.get("aliases", []),
                country=p.get("country", ""),
                motivation=p.get("motivation", ""),
                target_industries=p.get("target_industries", []),
                ttps=p.get("ttps", []), tools=p.get("tools", []),
                malware=p.get("malware", []),
                notable_events=p.get("notable_events", []),
                capability=p.get("capability", "medium"),
                first_seen=p.get("first_seen", ""),
                description=p.get("description", ""))
            self._actors[a.actor_id] = a

    # ------------------------------------------------------------------ #
    def list_actors(self, country: str = "", capability: str = "",
                    motivation: str = "",
                    limit: int = 100) -> Dict[str, Any]:
        out = list(self._actors.values())
        if country:
            out = [a for a in out if country.lower() in a.country.lower()]
        if capability:
            out = [a for a in out if a.capability == capability]
        if motivation:
            out = [a for a in out if motivation in a.motivation]
        return {"total": len(out),
                "items": [a.to_dict() for a in out[:limit]]}

    def get(self, actor_id: str) -> Optional[Dict[str, Any]]:
        a = self._actors.get(actor_id)
        return a.to_dict() if a else None

    def search(self, keyword: str, limit: int = 20) -> Dict[str, Any]:
        kw = keyword.lower()
        out: List[ThreatActor] = []
        for a in self._actors.values():
            hay = " ".join([a.name, a.country, a.motivation,
                            a.description] + a.aliases + a.malware
                           + a.tools + a.target_industries).lower()
            if kw in hay:
                out.append(a)
        return {"keyword": keyword, "total": len(out),
                "items": [a.to_dict() for a in out[:limit]]}

    # ------------------------------------------------------------------ #
    # 关联分析: 工具共享 / TTP 相似 / 恶意软件共享
    # ------------------------------------------------------------------ #
    def correlate(self, actor_id: str,
                  min_shared: int = 1) -> Dict[str, Any]:
        a = self._actors.get(actor_id)
        if a is None:
            return {"error": "actor not found"}
        related: List[Dict[str, Any]] = []
        for other in self._actors.values():
            if other.actor_id == actor_id:
                continue
            shared_tools = set(a.tools) & set(other.tools)
            shared_malware = set(a.malware) & set(other.malware)
            shared_ttps = set(a.ttps) & set(other.ttps)
            score = (len(shared_tools) * 3 + len(shared_malware) * 2
                     + len(shared_ttps) * 1)
            if score >= min_shared:
                related.append({
                    "actor_id": other.actor_id,
                    "name": other.name, "country": other.country,
                    "score": score,
                    "shared_tools": sorted(shared_tools),
                    "shared_malware": sorted(shared_malware),
                    "shared_ttps": sorted(shared_ttps),
                })
        related.sort(key=lambda x: x["score"], reverse=True)
        return {"actor": a.to_dict(), "related": related}

    def stats(self) -> Dict[str, Any]:
        by_country: Dict[str, int] = {}
        by_cap: Dict[str, int] = {}
        by_motiv: Dict[str, int] = {}
        for a in self._actors.values():
            by_country[a.country] = by_country.get(a.country, 0) + 1
            by_cap[a.capability] = by_cap.get(a.capability, 0) + 1
            for m in a.motivation.split("/"):
                by_motiv[m] = by_motiv.get(m, 0) + 1
        return {"total": len(self._actors),
                "by_country": by_country, "by_capability": by_cap,
                "by_motivation": by_motiv}

    # ------------------------------------------------------------------ #
    # IOC -> Actor 推断
    # ------------------------------------------------------------------ #
    def infer_from_iocs(self, malware_names: List[str]) -> List[Dict[str, Any]]:
        out: List[Dict[str, Any]] = []
        for a in self._actors.values():
            hits = [m for m in malware_names if m in a.malware
                    or any(m.lower() in x.lower() for x in a.malware)]
            if hits:
                out.append({"actor_id": a.actor_id, "name": a.name,
                            "country": a.country, "capability": a.capability,
                            "matched_malware": hits})
        out.sort(key=lambda x: len(x["matched_malware"]), reverse=True)
        return out


_phase: Optional[ThreatActorPhase] = None


def get_actor_phase() -> ThreatActorPhase:
    global _phase
    if _phase is None:
        _phase = ThreatActorPhase()
    return _phase
