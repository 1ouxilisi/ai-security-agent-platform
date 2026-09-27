#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
知识图谱记忆系统（Knowledge Graph Memory）

借鉴PentAGI的Neo4j知识图谱设计，实现：
1. 实体提取 - 从发现中提取IP、域名、端口、漏洞、凭证等实体
2. 关系构建 - 实体间关系（IP→端口、端口→服务、服务→漏洞）
3. 记忆存储 - 持久化存储历史扫描结果
4. 关联推理 - 基于图谱进行跨目标关联分析
5. 攻击路径发现 - 从图谱中发现潜在攻击路径

不依赖Neo4j，使用纯Python实现轻量级知识图谱。
"""

import json
import os
from typing import Dict, List, Optional, Any, Set, Tuple
from dataclasses import dataclass, field
from enum import Enum
from collections import defaultdict


class EntityType(Enum):
    """实体类型"""
    IP_ADDRESS = "ip_address"
    DOMAIN = "domain"
    PORT = "port"
    SERVICE = "service"
    VULNERABILITY = "vulnerability"
    CREDENTIAL = "credential"
    TECHNOLOGY = "technology"
    USER = "user"
    FILE = "file"
    API_ENDPOINT = "api_endpoint"
    CERTIFICATE = "certificate"
    MALWARE = "malware"


class RelationType(Enum):
    """关系类型"""
    HAS_PORT = "has_port"
    RUNS_SERVICE = "runs_service"
    HAS_VULNERABILITY = "has_vulnerability"
    USES_TECHNOLOGY = "uses_technology"
    RESOLVES_TO = "resolves_to"
    CONTAINS_CREDENTIAL = "contains_credential"
    HAS_USER = "has_user"
    EXPLOITS = "exploits"
    LEADS_TO = "leads_to"
    COMMUNICATES_WITH = "communicates_with"
    HAS_API = "has_api"
    OWNS = "owns"


@dataclass
class Entity:
    """实体"""
    entity_id: str
    entity_type: EntityType
    name: str
    properties: Dict[str, Any] = field(default_factory=dict)
    sources: List[str] = field(default_factory=list)
    first_seen: str = ""
    last_seen: str = ""

    def to_dict(self) -> Dict:
        return {
            "entity_id": self.entity_id,
            "entity_type": self.entity_type.value,
            "name": self.name,
            "properties": self.properties,
            "sources": self.sources,
            "first_seen": self.first_seen,
            "last_seen": self.last_seen,
        }


@dataclass
class Relation:
    """关系"""
    relation_id: str
    source_id: str
    target_id: str
    relation_type: RelationType
    properties: Dict[str, Any] = field(default_factory=dict)
    confidence: float = 1.0

    def to_dict(self) -> Dict:
        return {
            "relation_id": self.relation_id,
            "source_id": self.source_id,
            "target_id": self.target_id,
            "relation_type": self.relation_type.value,
            "properties": self.properties,
            "confidence": self.confidence,
        }


@dataclass
class AttackPath:
    """攻击路径"""
    path_id: str
    entities: List[str]  # 实体ID列表
    relations: List[str]  # 关系ID列表
    risk_score: float = 0.0
    description: str = ""


class KnowledgeGraph:
    """
    知识图谱记忆系统

    轻量级纯Python实现，支持实体提取、关系构建、关联推理。
    """

    def __init__(self, storage_path: str = None):
        self.entities: Dict[str, Entity] = {}
        self.relations: Dict[str, Relation] = {}
        self.entity_index: Dict[str, Set[str]] = defaultdict(set)  # type -> entity_ids
        self.relation_index: Dict[str, List[str]] = defaultdict(list)  # entity_id -> relation_ids
        self.storage_path = storage_path
        self._relation_counter = 0

        if storage_path and os.path.exists(storage_path):
            self._load()

    def add_entity(self, entity_type: EntityType, name: str,
                   properties: Dict = None, source: str = "") -> Entity:
        """添加或更新实体"""
        entity_id = f"{entity_type.value}:{name.lower()}"

        if entity_id in self.entities:
            entity = self.entities[entity_id]
            if properties:
                entity.properties.update(properties)
            if source and source not in entity.sources:
                entity.sources.append(source)
            entity.last_seen = self._now()
        else:
            entity = Entity(
                entity_id=entity_id,
                entity_type=entity_type,
                name=name,
                properties=properties or {},
                sources=[source] if source else [],
                first_seen=self._now(),
                last_seen=self._now(),
            )
            self.entities[entity_id] = entity
            self.entity_index[entity_type.value].add(entity_id)

        return entity

    def add_relation(self, source_id: str, target_id: str,
                     relation_type: RelationType,
                     properties: Dict = None,
                     confidence: float = 1.0) -> Optional[Relation]:
        """添加关系"""
        if source_id not in self.entities or target_id not in self.entities:
            return None

        self._relation_counter += 1
        relation_id = f"rel_{self._relation_counter}"

        relation = Relation(
            relation_id=relation_id,
            source_id=source_id,
            target_id=target_id,
            relation_type=relation_type,
            properties=properties or {},
            confidence=confidence,
        )
        self.relations[relation_id] = relation
        self.relation_index[source_id].append(relation_id)
        self.relation_index[target_id].append(relation_id)

        return relation

    def extract_entities_from_findings(self, findings: List[Dict],
                                       source: str = "scan") -> List[Entity]:
        """从发现列表中提取实体"""
        entities = []

        for finding in findings:
            ftype = finding.get('type', '').lower()

            # IP地址
            if 'ip' in finding:
                ip = finding['ip']
                entity = self.add_entity(EntityType.IP_ADDRESS, ip,
                                        properties=finding, source=source)
                entities.append(entity)

            # 域名
            if 'domain' in finding:
                domain = finding['domain']
                entity = self.add_entity(EntityType.DOMAIN, domain,
                                        properties=finding, source=source)
                entities.append(entity)

            # 端口
            if 'port' in finding:
                port = str(finding['port'])
                entity = self.add_entity(EntityType.PORT, port,
                                        properties=finding, source=source)
                entities.append(entity)

            # 服务
            if 'service' in finding:
                service = finding['service']
                entity = self.add_entity(EntityType.SERVICE, service,
                                        properties=finding, source=source)
                entities.append(entity)

            # 漏洞
            if ftype in ['vulnerability', 'web_vuln'] or 'cve' in str(finding.get('name', '')).lower():
                name = finding.get('name', ftype)
                entity = self.add_entity(EntityType.VULNERABILITY, name,
                                        properties=finding, source=source)
                entities.append(entity)

            # 凭证
            if ftype in ['hardcoded_key', 'credential', 'password'] or 'api_key' in ftype:
                name = finding.get('name', 'credential')
                entity = self.add_entity(EntityType.CREDENTIAL, name,
                                        properties=finding, source=source)
                entities.append(entity)

            # 技术栈
            if 'technology' in finding or 'tech' in ftype:
                tech = finding.get('technology', finding.get('name', 'tech'))
                entity = self.add_entity(EntityType.TECHNOLOGY, tech,
                                        properties=finding, source=source)
                entities.append(entity)

            # API端点
            if 'api' in ftype or 'endpoint' in ftype:
                api = finding.get('name', 'api_endpoint')
                entity = self.add_entity(EntityType.API_ENDPOINT, api,
                                        properties=finding, source=source)
                entities.append(entity)

        # 自动构建关系
        self._auto_build_relations(findings)

        return entities

    def _auto_build_relations(self, findings: List[Dict]):
        """自动构建实体间关系"""
        for finding in findings:
            ip = finding.get('ip')
            port = finding.get('port')
            service = finding.get('service')
            domain = finding.get('domain')

            # IP → Port
            if ip and port:
                ip_id = f"ip_address:{ip.lower()}"
                port_id = f"port:{str(port).lower()}"
                self.add_relation(ip_id, port_id, RelationType.HAS_PORT,
                                properties={"port": port})

            # Port → Service
            if port and service:
                port_id = f"port:{str(port).lower()}"
                service_id = f"service:{service.lower()}"
                self.add_relation(port_id, service_id, RelationType.RUNS_SERVICE)

            # Domain → IP
            if domain and ip:
                domain_id = f"domain:{domain.lower()}"
                ip_id = f"ip_address:{ip.lower()}"
                self.add_relation(domain_id, ip_id, RelationType.RESOLVES_TO)

    def get_related_entities(self, entity_id: str,
                             relation_type: RelationType = None) -> List[Entity]:
        """获取与指定实体相关的所有实体"""
        related = []
        for rel_id in self.relation_index.get(entity_id, []):
            rel = self.relations[rel_id]
            if relation_type and rel.relation_type != relation_type:
                continue
            other_id = rel.target_id if rel.source_id == entity_id else rel.source_id
            if other_id in self.entities:
                related.append(self.entities[other_id])
        return related

    def find_attack_paths(self, start_type: EntityType = EntityType.IP_ADDRESS,
                          max_depth: int = 4) -> List[AttackPath]:
        """发现潜在攻击路径"""
        paths = []
        start_entities = [e for e in self.entities.values()
                         if e.entity_type == start_type]

        for start in start_entities:
            visited = set()
            self._dfs_attack_path(start.entity_id, [], [], visited,
                                 max_depth, paths)

        # 按风险评分排序
        for path in paths:
            path.risk_score = self._calculate_path_risk(path)
        paths.sort(key=lambda p: p.risk_score, reverse=True)

        return paths[:10]  # 返回前10条

    def _dfs_attack_path(self, entity_id: str, path_entities: List[str],
                         path_relations: List[str], visited: Set[str],
                         max_depth: int, paths: List[AttackPath]):
        """DFS发现攻击路径"""
        if len(path_entities) >= max_depth:
            if len(path_entities) >= 2:
                paths.append(AttackPath(
                    path_id=f"path_{len(paths)}",
                    entities=path_entities + [entity_id],
                    relations=path_relations,
                    description=self._describe_path(path_entities + [entity_id]),
                ))
            return

        visited.add(entity_id)
        path_entities.append(entity_id)

        for rel_id in self.relation_index.get(entity_id, []):
            rel = self.relations[rel_id]
            next_id = rel.target_id if rel.source_id == entity_id else rel.source_id
            if next_id not in visited:
                path_relations.append(rel_id)
                self._dfs_attack_path(next_id, path_entities, path_relations,
                                     visited, max_depth, paths)
                path_relations.pop()

        path_entities.pop()
        visited.remove(entity_id)

    def _calculate_path_risk(self, path: AttackPath) -> float:
        """计算路径风险评分"""
        score = 0
        for entity_id in path.entities:
            if entity_id in self.entities:
                entity = self.entities[entity_id]
                if entity.entity_type == EntityType.VULNERABILITY:
                    severity = entity.properties.get('severity', 'medium')
                    score += {'critical': 30, 'high': 20, 'medium': 10, 'low': 5}.get(severity, 5)
                elif entity.entity_type == EntityType.CREDENTIAL:
                    score += 25
                elif entity.entity_type == EntityType.PORT:
                    score += 5
        return min(100, score)

    def _describe_path(self, entity_ids: List[str]) -> str:
        """描述攻击路径"""
        names = []
        for eid in entity_ids:
            if eid in self.entities:
                e = self.entities[eid]
                names.append(f"{e.entity_type.value}({e.name})")
        return " → ".join(names)

    def get_statistics(self) -> Dict[str, Any]:
        """获取图谱统计"""
        type_counts = defaultdict(int)
        for entity in self.entities.values():
            type_counts[entity.entity_type.value] += 1

        relation_counts = defaultdict(int)
        for rel in self.relations.values():
            relation_counts[rel.relation_type.value] += 1

        return {
            "total_entities": len(self.entities),
            "total_relations": len(self.relations),
            "entities_by_type": dict(type_counts),
            "relations_by_type": dict(relation_counts),
            "attack_paths_found": len(self.find_attack_paths()),
        }

    def _now(self) -> str:
        from datetime import datetime
        return datetime.now().isoformat()

    def save(self, path: str = None):
        """保存图谱到文件"""
        save_path = path or self.storage_path
        if not save_path:
            return

        data = {
            "entities": [e.to_dict() for e in self.entities.values()],
            "relations": [r.to_dict() for r in self.relations.values()],
        }
        with open(save_path, 'w', encoding='utf-8') as f:
            json.dump(data, f, ensure_ascii=False, indent=2)

    def _load(self):
        """从文件加载图谱"""
        try:
            with open(self.storage_path, 'r', encoding='utf-8') as f:
                data = json.load(f)

            for e_data in data.get("entities", []):
                entity = Entity(
                    entity_id=e_data["entity_id"],
                    entity_type=EntityType(e_data["entity_type"]),
                    name=e_data["name"],
                    properties=e_data.get("properties", {}),
                    sources=e_data.get("sources", []),
                    first_seen=e_data.get("first_seen", ""),
                    last_seen=e_data.get("last_seen", ""),
                )
                self.entities[entity.entity_id] = entity
                self.entity_index[entity.entity_type.value].add(entity.entity_id)

            for r_data in data.get("relations", []):
                relation = Relation(
                    relation_id=r_data["relation_id"],
                    source_id=r_data["source_id"],
                    target_id=r_data["target_id"],
                    relation_type=RelationType(r_data["relation_type"]),
                    properties=r_data.get("properties", {}),
                    confidence=r_data.get("confidence", 1.0),
                )
                self.relations[relation.relation_id] = relation
                self.relation_index[relation.source_id].append(relation.relation_id)
                self.relation_index[relation.target_id].append(relation.relation_id)
                self._relation_counter += 1
        except Exception:
            pass  # 加载失败时忽略


# 单例模式
_graph_instance: Optional[KnowledgeGraph] = None

def get_knowledge_graph(storage_path: str = None) -> KnowledgeGraph:
    """获取全局知识图谱实例"""
    global _graph_instance
    if _graph_instance is None:
        _graph_instance = KnowledgeGraph(storage_path)
    return _graph_instance
