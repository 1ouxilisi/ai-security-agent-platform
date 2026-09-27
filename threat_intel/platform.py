#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
platform模块，提供相关安全测试功能。

模块功能：
    - 提供相关安全测试功能
    - 支持API调用和命令行使用
    - 与其他模块集成协作

注意事项：
    - 本模块仅用于授权的安全测试
    - 请勿用于非法用途
    - 使用前请确保已获得相关授权
"""
import json
import os
import time
import uuid
from typing import Any, Dict, List, Optional, Set
from dataclasses import dataclass, field
from collections import defaultdict, Counter
from datetime import datetime, timedelta

from utils.logger import log


class IOCTypes:
    """IOC类型"""
    IP = "ip"
    DOMAIN = "domain"
    URL = "url"
    HASH = "hash"  # MD5/SHA1/SHA256
    EMAIL = "email"
    FILENAME = "filename"
    REGISTRY = "registry"
    MUTEX = "mutex"
    CERTIFICATE = "certificate"
    USER_AGENT = "user_agent"


class ThreatLevels:
    """威胁等级"""
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"
    UNKNOWN = "unknown"


@dataclass
class IOC:
    """威胁指标（IOC）"""
    ioc_id: str
    type: str  # ip/domain/url/hash/email等
    value: str
    threat_level: str = "unknown"
    confidence: int = 0  # 0-100
    source: str = ""
    source_count: int = 1  # 来源数量
    first_seen: float = field(default_factory=time.time)
    last_seen: float = field(default_factory=time.time)
    description: str = ""
    tags: List[str] = field(default_factory=list)
    related_malware: List[str] = field(default_factory=list)
    related_actors: List[str] = field(default_factory=list)
    attack_patterns: List[str] = field(default_factory=list)  # MITRE ATT&CK
    references: List[str] = field(default_factory=list)
    false_positive_rate: float = 0.0
    status: str = "active"  # active/revoked/expired/false_positive
    metadata: Dict[str, Any] = field(default_factory=dict)
    created_at: float = field(default_factory=time.time)
    updated_at: float = field(default_factory=time.time)

    def to_dict(self) -> Dict[str, Any]:
        """执行相关操作。

        Returns:
            操作结果。
        """
        return {
            "ioc_id": self.ioc_id,
            "type": self.type,
            "value": self.value,
            "threat_level": self.threat_level,
            "confidence": self.confidence,
            "source": self.source,
            "source_count": self.source_count,
            "first_seen": self.first_seen,
            "last_seen": self.last_seen,
            "description": self.description,
            "tags": self.tags,
            "related_malware": self.related_malware,
            "related_actors": self.related_actors,
            "attack_patterns": self.attack_patterns,
            "references": self.references,
            "false_positive_rate": self.false_positive_rate,
            "status": self.status,
            "metadata": self.metadata,
            "created_at": self.created_at,
            "updated_at": self.updated_at
        }


@dataclass
class IntelligenceSource:
    """情报源"""
    source_id: str
    name: str
    type: str  # commercial/open_source/community/internal
    url: str = ""
    api_key: str = ""
    quality_score: int = 0  # 0-100
    reliability: str = "unknown"  # A/B/C/D/F
    coverage: List[str] = field(default_factory=list)  # 覆盖的IOC类型
    update_frequency: str = ""  # realtime/hourly/daily/weekly
    enabled: bool = True
    last_sync: float = 0
    total_iocs: int = 0
    false_positive_count: int = 0
    created_at: float = field(default_factory=time.time)
    tags: List[str] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        """执行相关操作。

        Returns:
            操作结果。
        """
        return {
            "source_id": self.source_id,
            "name": self.name,
            "type": self.type,
            "url": self.url,
            "quality_score": self.quality_score,
            "reliability": self.reliability,
            "coverage": self.coverage,
            "update_frequency": self.update_frequency,
            "enabled": self.enabled,
            "last_sync": self.last_sync,
            "total_iocs": self.total_iocs,
            "false_positive_count": self.false_positive_count,
            "tags": self.tags
        }


@dataclass
class ThreatActor:
    """威胁行为者"""
    actor_id: str
    name: str
    aliases: List[str] = field(default_factory=list)
    origin: str = ""
    motivation: str = ""  # financial/espionage/sabotage/activism
    sophistication: str = "unknown"  # advanced/intermediate/beginner
    associated_malware: List[str] = field(default_factory=list)
    attack_patterns: List[str] = field(default_factory=list)
    target_industries: List[str] = field(default_factory=list)
    target_regions: List[str] = field(default_factory=list)
    first_seen: float = 0
    last_seen: float = 0
    description: str = ""
    references: List[str] = field(default_factory=list)
    tags: List[str] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        """执行相关操作。

        Returns:
            操作结果。
        """
        return {
            "actor_id": self.actor_id,
            "name": self.name,
            "aliases": self.aliases,
            "origin": self.origin,
            "motivation": self.motivation,
            "sophistication": self.sophistication,
            "associated_malware": self.associated_malware,
            "attack_patterns": self.attack_patterns,
            "target_industries": self.target_industries,
            "target_regions": self.target_regions,
            "first_seen": self.first_seen,
            "last_seen": self.last_seen,
            "description": self.description,
            "references": self.references,
            "tags": self.tags
        }


@dataclass
class Malware:
    """恶意软件"""
    malware_id: str
    name: str
    aliases: List[str] = field(default_factory=list)
    type: str = ""  # ransomware/trojan/worm/backdoor/rootkit/spyware
    family: str = ""
    associated_actors: List[str] = field(default_factory=list)
    ioc_ids: List[str] = field(default_factory=list)
    attack_patterns: List[str] = field(default_factory=list)
    first_seen: float = 0
    last_seen: float = 0
    description: str = ""
    mitigation: str = ""
    references: List[str] = field(default_factory=list)
    tags: List[str] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        """执行相关操作。

        Returns:
            操作结果。
        """
        return {
            "malware_id": self.malware_id,
            "name": self.name,
            "aliases": self.aliases,
            "type": self.type,
            "family": self.family,
            "associated_actors": self.associated_actors,
            "ioc_count": len(self.ioc_ids),
            "attack_patterns": self.attack_patterns,
            "first_seen": self.first_seen,
            "last_seen": self.last_seen,
            "description": self.description,
            "mitigation": self.mitigation,
            "references": self.references,
            "tags": self.tags
        }


class ThreatIntelPlatform:
    """威胁情报平台"""

    def __init__(self, data_dir: str = "data/threat_intel"):
        """初始化ThreatIntelPlatform实例。

        Args:
            self: 类实例。
        """
        self.data_dir = data_dir
        self.iocs: Dict[str, IOC] = {}
        self.sources: Dict[str, IntelligenceSource] = {}
        self.actors: Dict[str, ThreatActor] = {}
        self.malwares: Dict[str, Malware] = {}
        os.makedirs(data_dir, exist_ok=True)
        self._load_data()
        self._init_default_sources()
        self._init_default_iocs()

    def _load_data(self):
        """从文件加载数据"""
        # 加载IOC
        iocs_file = os.path.join(self.data_dir, "iocs.json")
        if os.path.exists(iocs_file):
            try:
                with open(iocs_file, 'r', encoding='utf-8') as f:
                    data = json.load(f)
                for iid, idata in data.items():
                    self.iocs[iid] = IOC(
                        ioc_id=idata["ioc_id"],
                        type=idata["type"],
                        value=idata["value"],
                        threat_level=idata.get("threat_level", "unknown"),
                        confidence=idata.get("confidence", 0),
                        source=idata.get("source", ""),
                        source_count=idata.get("source_count", 1),
                        first_seen=idata.get("first_seen", time.time()),
                        last_seen=idata.get("last_seen", time.time()),
                        description=idata.get("description", ""),
                        tags=idata.get("tags", []),
                        related_malware=idata.get("related_malware", []),
                        related_actors=idata.get("related_actors", []),
                        attack_patterns=idata.get("attack_patterns", []),
                        references=idata.get("references", []),
                        false_positive_rate=idata.get("false_positive_rate", 0),
                        status=idata.get("status", "active"),
                        metadata=idata.get("metadata", {})
                    )
            except Exception as e:
                log.error(f"加载IOC失败: {e}")

        # 加载情报源
        sources_file = os.path.join(self.data_dir, "sources.json")
        if os.path.exists(sources_file):
            try:
                with open(sources_file, 'r', encoding='utf-8') as f:
                    data = json.load(f)
                for sid, sdata in data.items():
                    self.sources[sid] = IntelligenceSource(
                        source_id=sdata["source_id"],
                        name=sdata["name"],
                        type=sdata.get("type", "open_source"),
                        url=sdata.get("url", ""),
                        quality_score=sdata.get("quality_score", 0),
                        reliability=sdata.get("reliability", "unknown"),
                        coverage=sdata.get("coverage", []),
                        update_frequency=sdata.get("update_frequency", ""),
                        enabled=sdata.get("enabled", True),
                        last_sync=sdata.get("last_sync", 0),
                        total_iocs=sdata.get("total_iocs", 0),
                        false_positive_count=sdata.get("false_positive_count", 0),
                        tags=sdata.get("tags", [])
                    )
            except Exception as e:
                log.error(f"加载情报源失败: {e}")

        # 加载威胁行为者
        actors_file = os.path.join(self.data_dir, "actors.json")
        if os.path.exists(actors_file):
            try:
                with open(actors_file, 'r', encoding='utf-8') as f:
                    data = json.load(f)
                for aid, adata in data.items():
                    self.actors[aid] = ThreatActor(
                        actor_id=adata["actor_id"],
                        name=adata["name"],
                        aliases=adata.get("aliases", []),
                        origin=adata.get("origin", ""),
                        motivation=adata.get("motivation", ""),
                        sophistication=adata.get("sophistication", "unknown"),
                        associated_malware=adata.get("associated_malware", []),
                        attack_patterns=adata.get("attack_patterns", []),
                        target_industries=adata.get("target_industries", []),
                        target_regions=adata.get("target_regions", []),
                        first_seen=adata.get("first_seen", 0),
                        last_seen=adata.get("last_seen", 0),
                        description=adata.get("description", ""),
                        references=adata.get("references", []),
                        tags=adata.get("tags", [])
                    )
            except Exception as e:
                log.error(f"加载威胁行为者失败: {e}")

        # 加载恶意软件
        malwares_file = os.path.join(self.data_dir, "malwares.json")
        if os.path.exists(malwares_file):
            try:
                with open(malwares_file, 'r', encoding='utf-8') as f:
                    data = json.load(f)
                for mid, mdata in data.items():
                    self.malwares[mid] = Malware(
                        malware_id=mdata["malware_id"],
                        name=mdata["name"],
                        aliases=mdata.get("aliases", []),
                        type=mdata.get("type", ""),
                        family=mdata.get("family", ""),
                        associated_actors=mdata.get("associated_actors", []),
                        ioc_ids=mdata.get("ioc_ids", []),
                        attack_patterns=mdata.get("attack_patterns", []),
                        first_seen=mdata.get("first_seen", 0),
                        last_seen=mdata.get("last_seen", 0),
                        description=mdata.get("description", ""),
                        mitigation=mdata.get("mitigation", ""),
                        references=mdata.get("references", []),
                        tags=mdata.get("tags", [])
                    )
            except Exception as e:
                log.error(f"加载恶意软件失败: {e}")

    def _save_data(self):
        """保存数据到文件"""
        # 保存IOC（只保存最近5000条）
        iocs_file = os.path.join(self.data_dir, "iocs.json")
        try:
            sorted_iocs = sorted(self.iocs.values(), key=lambda x: x.last_seen, reverse=True)[:5000]
            data = {i.ioc_id: i.to_dict() for i in sorted_iocs}
            with open(iocs_file, 'w', encoding='utf-8') as f:
                json.dump(data, f, ensure_ascii=False, indent=2, default=str)
        except Exception as e:
            log.error(f"保存IOC失败: {e}")

        # 保存情报源
        sources_file = os.path.join(self.data_dir, "sources.json")
        try:
            data = {sid: s.to_dict() for sid, s in self.sources.items()}
            with open(sources_file, 'w', encoding='utf-8') as f:
                json.dump(data, f, ensure_ascii=False, indent=2, default=str)
        except Exception as e:
            log.error(f"保存情报源失败: {e}")

        # 保存威胁行为者
        actors_file = os.path.join(self.data_dir, "actors.json")
        try:
            data = {aid: a.to_dict() for aid, a in self.actors.items()}
            with open(actors_file, 'w', encoding='utf-8') as f:
                json.dump(data, f, ensure_ascii=False, indent=2, default=str)
        except Exception as e:
            log.error(f"保存威胁行为者失败: {e}")

        # 保存恶意软件
        malwares_file = os.path.join(self.data_dir, "malwares.json")
        try:
            data = {mid: m.to_dict() for mid, m in self.malwares.items()}
            with open(malwares_file, 'w', encoding='utf-8') as f:
                json.dump(data, f, ensure_ascii=False, indent=2, default=str)
        except Exception as e:
            log.error(f"保存恶意软件失败: {e}")

    def _init_default_sources(self):
        """初始化默认情报源"""
        if self.sources:
            return

        default_sources = [
            {"name": "AlienVault OTX", "type": "open_source", "url": "https://otx.alienvault.com", "quality_score": 75, "reliability": "B", "coverage": ["ip", "domain", "url", "hash"], "update_frequency": "realtime"},
            {"name": "VirusTotal", "type": "commercial", "url": "https://www.virustotal.com", "quality_score": 90, "reliability": "A", "coverage": ["ip", "domain", "url", "hash"], "update_frequency": "realtime"},
            {"name": "AbuseIPDB", "type": "open_source", "url": "https://www.abuseipdb.com", "quality_score": 70, "reliability": "B", "coverage": ["ip"], "update_frequency": "realtime"},
            {"name": "URLhaus", "type": "open_source", "url": "https://urlhaus.abuse.ch", "quality_score": 80, "reliability": "A", "coverage": ["url", "domain"], "update_frequency": "realtime"},
            {"name": "MalwareBazaar", "type": "open_source", "url": "https://bazaar.abuse.ch", "quality_score": 85, "reliability": "A", "coverage": ["hash"], "update_frequency": "realtime"},
            {"name": "ThreatFox", "type": "open_source", "url": "https://threatfox.abuse.ch", "quality_score": 80, "reliability": "A", "coverage": ["ip", "domain", "url", "hash"], "update_frequency": "realtime"},
            {"name": "Feodo Tracker", "type": "open_source", "url": "https://feodotracker.abuse.ch", "quality_score": 85, "reliability": "A", "coverage": ["ip", "domain"], "update_frequency": "hourly"},
            {"name": "SSL Blacklist", "type": "open_source", "url": "https://sslbl.abuse.ch", "quality_score": 75, "reliability": "B", "coverage": ["hash", "certificate"], "update_frequency": "daily"},
            {"name": "MISP", "type": "open_source", "url": "https://www.misp-project.org", "quality_score": 80, "reliability": "B", "coverage": ["ip", "domain", "url", "hash", "email"], "update_frequency": "realtime"},
            {"name": "MITRE ATT&CK", "type": "open_source", "url": "https://attack.mitre.org", "quality_score": 95, "reliability": "A", "coverage": ["attack_patterns"], "update_frequency": "quarterly"},
            {"name": "内部威胁情报", "type": "internal", "url": "", "quality_score": 90, "reliability": "A", "coverage": ["ip", "domain", "url", "hash", "email"], "update_frequency": "realtime"},
        ]

        for source_data in default_sources:
            source_id = f"src-{uuid.uuid4().hex[:8]}"
            source = IntelligenceSource(
                source_id=source_id,
                name=source_data["name"],
                type=source_data["type"],
                url=source_data["url"],
                quality_score=source_data["quality_score"],
                reliability=source_data["reliability"],
                coverage=source_data["coverage"],
                update_frequency=source_data["update_frequency"]
            )
            self.sources[source_id] = source

        self._save_data()
        log.info(f"初始化 {len(default_sources)} 个默认情报源")

    def _init_default_iocs(self):
        """初始化默认IOC（示例数据）"""
        if self.iocs:
            return

        # 示例IOC数据
        default_iocs = [
            {"type": "ip", "value": "192.168.1.100", "threat_level": "high", "confidence": 80, "source": "内部威胁情报", "description": "已知C2服务器IP", "tags": ["c2", "malware"], "attack_patterns": ["T1071"]},
            {"type": "domain", "value": "malicious-example.com", "threat_level": "critical", "confidence": 90, "source": "URLhaus", "description": "已知恶意域名，分发勒索软件", "tags": ["ransomware", "distribution"], "related_malware": ["LockBit"], "attack_patterns": ["T1189"]},
            {"type": "url", "value": "http://malicious-example.com/payload.exe", "threat_level": "high", "confidence": 85, "source": "URLhaus", "description": "恶意下载URL", "tags": ["malware", "download"], "attack_patterns": ["T1105"]},
            {"type": "hash", "value": "d41d8cd98f00b204e9800998ecf8427e", "threat_level": "medium", "confidence": 70, "source": "MalwareBazaar", "description": "已知恶意软件MD5哈希", "tags": ["trojan"], "related_malware": ["Emotet"], "attack_patterns": ["T1059"]},
            {"type": "ip", "value": "10.0.0.50", "threat_level": "medium", "confidence": 60, "source": "AbuseIPDB", "description": "可疑扫描IP", "tags": ["scanner", "reconnaissance"], "attack_patterns": ["T1595"]},
            {"type": "domain", "value": "phishing-example-login.com", "threat_level": "high", "confidence": 85, "source": "内部威胁情报", "description": "钓鱼网站域名，仿冒银行登录", "tags": ["phishing", "credential_theft"], "attack_patterns": ["T1566"]},
            {"type": "email", "value": "attacker@malicious-example.com", "threat_level": "high", "confidence": 75, "source": "内部威胁情报", "description": "已知恶意发件人邮箱", "tags": ["phishing", "spam"], "attack_patterns": ["T1566"]},
            {"type": "hash", "value": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855", "threat_level": "critical", "confidence": 95, "source": "VirusTotal", "description": "已知勒索软件SHA256哈希", "tags": ["ransomware", "encryption"], "related_malware": ["Conti"], "attack_patterns": ["T1486"]},
        ]

        for ioc_data in default_iocs:
            ioc_id = f"ioc-{uuid.uuid4().hex[:8]}"
            ioc = IOC(
                ioc_id=ioc_id,
                type=ioc_data["type"],
                value=ioc_data["value"],
                threat_level=ioc_data["threat_level"],
                confidence=ioc_data["confidence"],
                source=ioc_data["source"],
                description=ioc_data["description"],
                tags=ioc_data.get("tags", []),
                related_malware=ioc_data.get("related_malware", []),
                attack_patterns=ioc_data.get("attack_patterns", [])
            )
            self.iocs[ioc_id] = ioc

        self._save_data()
        log.info(f"初始化 {len(default_iocs)} 个示例IOC")

    # ===== IOC管理 =====
    def add_ioc(self, type: str, value: str, threat_level: str = "unknown",
                confidence: int = 0, source: str = "", description: str = "",
                tags: List[str] = None, related_malware: List[str] = None,
                related_actors: List[str] = None, attack_patterns: List[str] = None) -> str:
        """添加IOC"""
        # 检查是否已存在
        existing = self.search_ioc(value)
        if existing:
            # 更新已有IOC
            existing_ioc = self.iocs[existing["ioc_id"]]
            existing_ioc.source_count += 1
            existing_ioc.last_seen = time.time()
            if confidence > existing_ioc.confidence:
                existing_ioc.confidence = confidence
            if threat_level != "unknown" and existing_ioc.threat_level == "unknown":
                existing_ioc.threat_level = threat_level
            if source and source not in existing_ioc.source:
                existing_ioc.source += f", {source}"
            if tags:
                existing_ioc.tags = list(set(existing_ioc.tags + tags))
            self._save_data()
            return existing["ioc_id"]

        ioc_id = f"ioc-{uuid.uuid4().hex[:8]}"
        ioc = IOC(
            ioc_id=ioc_id,
            type=type,
            value=value,
            threat_level=threat_level,
            confidence=confidence,
            source=source,
            description=description,
            tags=tags or [],
            related_malware=related_malware or [],
            related_actors=related_actors or [],
            attack_patterns=attack_patterns or []
        )
        self.iocs[ioc_id] = ioc
        self._save_data()
        log.info(f"添加IOC: {type} - {value} (威胁等级: {threat_level})")
        return ioc_id

    def search_ioc(self, value: str) -> Optional[Dict[str, Any]]:
        """搜索IOC"""
        for ioc in self.iocs.values():
            if ioc.value.lower() == value.lower():
                return ioc.to_dict()
        return None

    def get_ioc_detail(self, ioc_id: str) -> Optional[Dict[str, Any]]:
        """获取IOC详情"""
        ioc = self.iocs.get(ioc_id)
        if not ioc:
            return None
        data = ioc.to_dict()
        # 关联分析
        data["related_iocs"] = self.get_related_iocs(ioc_id)
        return data

    def get_iocs(self, type: str = None, threat_level: str = None,
                  source: str = None, status: str = "active",
                  min_confidence: int = 0, limit: int = 100) -> List[Dict[str, Any]]:
        """获取IOC列表"""
        results = []
        for ioc in self.iocs.values():
            if type and ioc.type != type:
                continue
            if threat_level and ioc.threat_level != threat_level:
                continue
            if source and source not in ioc.source:
                continue
            if status and ioc.status != status:
                continue
            if ioc.confidence < min_confidence:
                continue
            results.append(ioc.to_dict())
        results.sort(key=lambda x: x["last_seen"], reverse=True)
        return results[:limit]

    def update_ioc_status(self, ioc_id: str, status: str,
                          false_positive_rate: float = None) -> bool:
        """更新IOC状态"""
        ioc = self.iocs.get(ioc_id)
        if not ioc:
            return False
        ioc.status = status
        if false_positive_rate is not None:
            ioc.false_positive_rate = false_positive_rate
        ioc.updated_at = time.time()
        self._save_data()
        return True

    def batch_add_iocs(self, iocs: List[Dict[str, Any]]) -> Dict[str, Any]:
        """批量添加IOC"""
        added = 0
        updated = 0
        for ioc_data in iocs:
            existing = self.search_ioc(ioc_data.get("value", ""))
            if existing:
                updated += 1
                existing_ioc = self.iocs[existing["ioc_id"]]
                existing_ioc.source_count += 1
                existing_ioc.last_seen = time.time()
            else:
                self.add_ioc(
                    type=ioc_data.get("type", ""),
                    value=ioc_data.get("value", ""),
                    threat_level=ioc_data.get("threat_level", "unknown"),
                    confidence=ioc_data.get("confidence", 0),
                    source=ioc_data.get("source", ""),
                    description=ioc_data.get("description", ""),
                    tags=ioc_data.get("tags", []),
                    related_malware=ioc_data.get("related_malware", []),
                    related_actors=ioc_data.get("related_actors", []),
                    attack_patterns=ioc_data.get("attack_patterns", [])
                )
                added += 1
        return {"total": len(iocs), "added": added, "updated": updated}

    # ===== 情报质量评分 =====
    def calculate_ioc_quality(self, ioc_id: str) -> Dict[str, Any]:
        """计算IOC质量评分"""
        ioc = self.iocs.get(ioc_id)
        if not ioc:
            return {"error": "IOC不存在"}

        score = 0
        factors = {}

        # 来源数量（最多20分）
        source_score = min(ioc.source_count * 5, 20)
        factors["source_count"] = source_score
        score += source_score

        # 置信度（最多20分）
        confidence_score = ioc.confidence / 5
        factors["confidence"] = confidence_score
        score += confidence_score

        # 威胁等级（最多15分）
        threat_scores = {"critical": 15, "high": 12, "medium": 8, "low": 4, "info": 2, "unknown": 0}
        threat_score = threat_scores.get(ioc.threat_level, 0)
        factors["threat_level"] = threat_score
        score += threat_score

        # 时效性（最多15分）
        age_days = (time.time() - ioc.last_seen) / 86400
        if age_days < 1:
            timeliness_score = 15
        elif age_days < 7:
            timeliness_score = 12
        elif age_days < 30:
            timeliness_score = 8
        elif age_days < 90:
            timeliness_score = 4
        else:
            timeliness_score = 1
        factors["timeliness"] = timeliness_score
        score += timeliness_score

        # 关联丰富度（最多15分）
        richness = 0
        if ioc.related_malware:
            richness += 5
        if ioc.related_actors:
            richness += 5
        if ioc.attack_patterns:
            richness += 5
        factors["richness"] = richness
        score += richness

        # 误报率扣分
        fp_penalty = ioc.false_positive_rate * 10
        factors["false_positive_penalty"] = -fp_penalty
        score -= fp_penalty

        # 状态扣分
        if ioc.status == "false_positive":
            score = 0
        elif ioc.status == "expired":
            score *= 0.3
        elif ioc.status == "revoked":
            score *= 0.5

        score = max(0, min(100, score))

        return {
            "ioc_id": ioc_id,
            "value": ioc.value,
            "quality_score": round(score, 2),
            "factors": factors,
            "quality_level": "excellent" if score >= 80 else "good" if score >= 60 else "fair" if score >= 40 else "poor"
        }

    # ===== 情报关联分析 =====
    def get_related_iocs(self, ioc_id: str, depth: int = 1) -> List[Dict[str, Any]]:
        """获取关联IOC"""
        ioc = self.iocs.get(ioc_id)
        if not ioc:
            return []

        related = []
        seen = {ioc_id}

        # 通过恶意软件关联
        for malware_name in ioc.related_malware:
            for other_ioc in self.iocs.values():
                if other_ioc.ioc_id not in seen and malware_name in other_ioc.related_malware:
                    related.append({
                        "ioc_id": other_ioc.ioc_id,
                        "value": other_ioc.value,
                        "type": other_ioc.type,
                        "relation": f"共享恶意软件: {malware_name}",
                        "threat_level": other_ioc.threat_level
                    })
                    seen.add(other_ioc.ioc_id)

        # 通过攻击模式关联
        for pattern in ioc.attack_patterns:
            for other_ioc in self.iocs.values():
                if other_ioc.ioc_id not in seen and pattern in other_ioc.attack_patterns:
                    related.append({
                        "ioc_id": other_ioc.ioc_id,
                        "value": other_ioc.value,
                        "type": other_ioc.type,
                        "relation": f"共享攻击模式: {pattern}",
                        "threat_level": other_ioc.threat_level
                    })
                    seen.add(other_ioc.ioc_id)

        # 通过标签关联
        for tag in ioc.tags:
            for other_ioc in self.iocs.values():
                if other_ioc.ioc_id not in seen and tag in other_ioc.tags:
                    related.append({
                        "ioc_id": other_ioc.ioc_id,
                        "value": other_ioc.value,
                        "type": other_ioc.type,
                        "relation": f"共享标签: {tag}",
                        "threat_level": other_ioc.threat_level
                    })
                    seen.add(other_ioc.ioc_id)

        return related[:20]

    def correlate_alerts_with_iocs(self, alerts: List[Dict[str, Any]]) -> Dict[str, Any]:
        """将告警与IOC关联"""
        correlated = []
        for alert in alerts:
            alert_iocs = []
            # 检查告警中的IP
            for field in ["source_ip", "destination_ip"]:
                ip = alert.get(field, "")
                if ip:
                    ioc = self.search_ioc(ip)
                    if ioc:
                        alert_iocs.append({"field": field, "value": ip, "ioc": ioc})
            # 检查告警中的域名/URL
            for field in ["domain", "url"]:
                value = alert.get(field, "")
                if value:
                    ioc = self.search_ioc(value)
                    if ioc:
                        alert_iocs.append({"field": field, "value": value, "ioc": ioc})

            if alert_iocs:
                correlated.append({
                    "alert_id": alert.get("alert_id", ""),
                    "alert_name": alert.get("rule_name", ""),
                    "matched_iocs": alert_iocs,
                    "risk_level": "critical" if any(i["ioc"]["threat_level"] == "critical" for i in alert_iocs) else "high" if any(i["ioc"]["threat_level"] == "high" for i in alert_iocs) else "medium"
                })

        return {
            "total_alerts": len(alerts),
            "correlated_alerts": len(correlated),
            "correlation_rate": round(len(correlated) / len(alerts) * 100, 2) if alerts else 0,
            "correlated": correlated
        }

    # ===== 威胁狩猎 =====
    def threat_hunt(self, query: Dict[str, Any]) -> Dict[str, Any]:
        """威胁狩猎查询"""
        results = []

        # 按IOC类型和威胁等级搜索
        ioc_type = query.get("type")
        threat_level = query.get("threat_level")
        tags = query.get("tags", [])
        attack_patterns = query.get("attack_patterns", [])
        time_range = query.get("time_range", 86400 * 30)  # 默认30天

        cutoff = time.time() - time_range

        for ioc in self.iocs.values():
            if ioc.last_seen < cutoff:
                continue
            if ioc_type and ioc.type != ioc_type:
                continue
            if threat_level and ioc.threat_level != threat_level:
                continue
            if tags and not any(t in ioc.tags for t in tags):
                continue
            if attack_patterns and not any(p in ioc.attack_patterns for p in attack_patterns):
                continue
            results.append(ioc.to_dict())

        # 按时间排序
        results.sort(key=lambda x: x["last_seen"], reverse=True)

        return {
            "query": query,
            "total_results": len(results),
            "results": results[:100],
            "by_type": dict(Counter(r["type"] for r in results)),
            "by_threat_level": dict(Counter(r["threat_level"] for r in results))
        }

    def hunt_by_ttps(self, ttps: List[str]) -> Dict[str, Any]:
        """按TTP（战术、技术、程序）狩猎"""
        return self.threat_hunt({"attack_patterns": ttps})

    def hunt_by_malware(self, malware_name: str) -> Dict[str, Any]:
        """按恶意软件家族狩猎"""
        results = []
        for ioc in self.iocs.values():
            if malware_name.lower() in [m.lower() for m in ioc.related_malware]:
                results.append(ioc.to_dict())
        return {
            "malware": malware_name,
            "total_iocs": len(results),
            "iocs": results
        }

    # ===== 统计分析 =====
    def get_statistics(self) -> Dict[str, Any]:
        """获取统计信息"""
        total_iocs = len(self.iocs)
        active_iocs = sum(1 for i in self.iocs.values() if i.status == "active")

        by_type = Counter(i.type for i in self.iocs.values())
        by_threat_level = Counter(i.threat_level for i in self.iocs.values())
        by_source = Counter(i.source for i in self.iocs.values())
        by_status = Counter(i.status for i in self.iocs.values())

        # 高置信度IOC
        high_confidence = sum(1 for i in self.iocs.values() if i.confidence >= 80)

        # 最近7天新增
        week_ago = time.time() - 86400 * 7
        recent_iocs = sum(1 for i in self.iocs.values() if i.created_at >= week_ago)

        # 情报源统计
        source_stats = {}
        for source in self.sources.values():
            source_stats[source.name] = {
                "type": source.type,
                "quality_score": source.quality_score,
                "reliability": source.reliability,
                "enabled": source.enabled,
                "coverage": source.coverage
            }

        return {
            "total_iocs": total_iocs,
            "active_iocs": active_iocs,
            "by_type": dict(by_type),
            "by_threat_level": dict(by_threat_level),
            "by_source": dict(by_source.most_common(10)),
            "by_status": dict(by_status),
            "high_confidence_iocs": high_confidence,
            "recent_iocs_7d": recent_iocs,
            "total_sources": len(self.sources),
            "enabled_sources": sum(1 for s in self.sources.values() if s.enabled),
            "total_actors": len(self.actors),
            "total_malwares": len(self.malwares),
            "source_stats": source_stats
        }

    # ===== 情报源管理 =====
    def add_source(self, name: str, type: str, url: str = "",
                   quality_score: int = 0, reliability: str = "unknown",
                   coverage: List[str] = None) -> str:
        """添加情报源"""
        source_id = f"src-{uuid.uuid4().hex[:8]}"
        source = IntelligenceSource(
            source_id=source_id,
            name=name,
            type=type,
            url=url,
            quality_score=quality_score,
            reliability=reliability,
            coverage=coverage or []
        )
        self.sources[source_id] = source
        self._save_data()
        return source_id

    def get_sources(self, type: str = None, enabled: bool = None) -> List[Dict[str, Any]]:
        """获取情报源列表"""
        results = []
        for source in self.sources.values():
            if type and source.type != type:
                continue
            if enabled is not None and source.enabled != enabled:
                continue
            results.append(source.to_dict())
        return results

    # ===== 威胁行为者和恶意软件 =====
    def add_actor(self, name: str, aliases: List[str] = None,
                  origin: str = "", motivation: str = "",
                  sophistication: str = "unknown",
                  description: str = "") -> str:
        """添加威胁行为者"""
        actor_id = f"actor-{uuid.uuid4().hex[:8]}"
        actor = ThreatActor(
            actor_id=actor_id,
            name=name,
            aliases=aliases or [],
            origin=origin,
            motivation=motivation,
            sophistication=sophistication,
            description=description
        )
        self.actors[actor_id] = actor
        self._save_data()
        return actor_id

    def add_malware(self, name: str, type: str = "", family: str = "",
                    description: str = "", mitigation: str = "") -> str:
        """添加恶意软件"""
        malware_id = f"mal-{uuid.uuid4().hex[:8]}"
        malware = Malware(
            malware_id=malware_id,
            name=name,
            type=type,
            family=family,
            description=description,
            mitigation=mitigation
        )
        self.malwares[malware_id] = malware
        self._save_data()
        return malware_id

    def get_actors(self) -> List[Dict[str, Any]]:
        """获取威胁行为者列表"""
        return [a.to_dict() for a in self.actors.values()]

    def get_malwares(self) -> List[Dict[str, Any]]:
        """获取恶意软件列表"""
        return [m.to_dict() for m in self.malwares.values()]


# 全局实例
threat_intel = ThreatIntelPlatform()
