# -*- coding: utf-8 -*-
"""
intel_sharing_phase.py — 方向2 威胁情报 Pro：阶段8 情报共享。

STIX 2.1 支持:
    - Domain Object (indicator / malware / campaign / intrusion-set /
      observed-data / identity)
    - Relationship Object (indicates / uses / targets)
TAXII 2.1 服务器/客户端框架（内存模拟，不真正起 HTTP 服务）。
情报共享管理（内部 / 合作伙伴 / 社区）+ 质量评估 + 溯源。
"""

from __future__ import annotations

import json
import time
import uuid
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional


@dataclass
class SharingGroup:
    group_id: str = ""
    name: str = ""
    scope: str = "internal"        # internal/partner/community
    members: List[str] = field(default_factory=list)
    created_at: str = ""

    def to_dict(self) -> Dict[str, Any]:
        return {"group_id": self.group_id, "name": self.name,
                "scope": self.scope, "members": self.members,
                "created_at": self.created_at}


class IntelSharingPhase:
    """阶段8: 情报共享 (STIX/TAXII 框架)。"""

    def __init__(self) -> None:
        self._groups: Dict[str, SharingGroup] = {}
        self._taxii_collections: Dict[str, Dict[str, Any]] = {
            "coll-default": {"id": "coll-default",
                             "title": "默认情报集合",
                             "objects": []},
        }
        self._provenance: Dict[str, str] = {}
        self._init_default_group()

    def _init_default_group(self) -> None:
        g = SharingGroup(
            group_id=uuid.uuid4().hex[:12],
            name="内部 SOC", scope="internal",
            members=["soc@internal"],
            created_at=time.strftime("%Y-%m-%d %H:%M:%S"))
        self._groups[g.group_id] = g

    # ------------------------------------------------------------------ #
    # STIX 2.1 构造
    # ------------------------------------------------------------------ #
    def ioc_to_stix(self, ioc: Dict[str, Any]) -> Dict[str, Any]:
        """把一条 IOC 转成 STIX 2.1 Indicator + Relationship。"""
        ioc_id = f"indicator--{uuid.uuid4()}"
        value = ioc.get("value", "")
        itype = ioc.get("type", "domain")
        # pattern
        if itype == "ip":
            pat = f"[ipv4-addr:value = '{value}']"
        elif itype == "domain":
            pat = f"[domain-name:value = '{value}']"
        elif itype == "url":
            pat = f"[url:value = '{value}']"
        elif itype == "hash":
            algo = ioc.get("hash_algo", "SHA256").lower()
            pat = f"[file:hashes.'{algo}' = '{value}']"
        elif itype == "email":
            pat = f"[email-addr:value = '{value}']"
        elif itype == "cve":
            pat = f"[vulnerability:cve = '{value}']"
        else:
            pat = f"[domain-name:value = '{value}']"
        indicator = {
            "type": "indicator", "spec_version": "2.1", "id": ioc_id,
            "created": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
            "modified": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
            "name": f"{ioc.get('malware','malicious')} indicator: {value}",
            "pattern": pat,
            "valid_from": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
            "indicator_types": ioc.get("tags", ["unknown"]),
            "confidence": ioc.get("confidence", 50),
        }
        rel = {
            "type": "relationship", "spec_version": "2.1",
            "id": f"relationship--{uuid.uuid4()}",
            "created": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
            "relationship_type": "indicates",
            "source_ref": ioc_id,
            "target_ref": f"malware--{uuid.uuid4()}",
        }
        return {"type": "bundle", "id": f"bundle--{uuid.uuid4()}",
                "objects": [indicator, rel]}

    # ------------------------------------------------------------------ #
    # STIX 导入
    # ------------------------------------------------------------------ #
    def import_stix(self, bundle: Dict[str, Any]) -> Dict[str, Any]:
        objects = bundle.get("objects", [])
        imported = 0
        for obj in objects:
            if obj.get("type") == "indicator":
                # 粗解析 pattern 里的值
                pat = obj.get("pattern", "")
                m = pat.split("'")
                if len(m) >= 2:
                    val = m[1]
                    self._taxii_collections["coll-default"]["objects"].append({
                        "type": "indicator", "value": val,
                        "name": obj.get("name", ""),
                        "tags": obj.get("indicator_types", []),
                        "confidence": obj.get("confidence", 50),
                    })
                    imported += 1
        return {"imported": imported, "total_objects": len(objects)}

    # ------------------------------------------------------------------ #
    # TAXII 集合（模拟）
    # ------------------------------------------------------------------ #
    def list_collections(self) -> List[Dict[str, Any]]:
        return [{"id": c["id"], "title": c["title"],
                 "object_count": len(c["objects"])}
                for c in self._taxii_collections.values()]

    def add_to_collection(self, coll_id: str, obj: Dict[str, Any]) -> Dict[str, Any]:
        coll = self._taxii_collections.get(coll_id)
        if coll is None:
            return {"error": "collection not found"}
        coll["objects"].append(obj)
        return {"added": True, "collection": coll_id,
                "total": len(coll["objects"])}

    def taxii_discovery(self) -> Dict[str, Any]:
        """模拟 TAXII 2.1 discovery 端点。"""
        return {
            "title": "AI Hacking Agent TAXII Server",
            "versions": ["application/taxii+json;version=2.1"],
            "default": "/taxii2/",
            "collections_url": "/taxii2/collections/",
            "note": "本服务为内存模拟，未监听真实端口。",
        }

    # ------------------------------------------------------------------ #
    # 共享组管理
    # ------------------------------------------------------------------ #
    def create_group(self, name: str, scope: str,
                     members: Optional[List[str]] = None) -> Dict[str, Any]:
        g = SharingGroup(
            group_id=uuid.uuid4().hex[:12], name=name, scope=scope,
            members=members or [],
            created_at=time.strftime("%Y-%m-%d %H:%M:%S"))
        self._groups[g.group_id] = g
        return g.to_dict()

    def list_groups(self) -> List[Dict[str, Any]]:
        return [g.to_dict() for g in self._groups.values()]

    # ------------------------------------------------------------------ #
    # 质量评估 / 溯源
    # ------------------------------------------------------------------ #
    def quality_score(self, ioc: Dict[str, Any]) -> Dict[str, Any]:
        score = 0
        checks = []
        if ioc.get("confidence", 0) >= 75:
            score += 30
            checks.append("高置信度")
        if ioc.get("first_seen"):
            score += 15
            checks.append("有首见时间")
        if ioc.get("country"):
            score += 15
            checks.append("有地理标注")
        if ioc.get("tags"):
            score += 20
            checks.append("有威胁标签")
        if ioc.get("malware"):
            score += 20
            checks.append("关联恶意软件")
        score = min(score, 100)
        grade = "A" if score >= 85 else ("B" if score >= 70 else
                                        ("C" if score >= 50 else "D"))
        return {"score": score, "grade": grade, "checks": checks}

    def set_provenance(self, ioc_value: str, source: str,
                       raw_ref: str = "") -> Dict[str, Any]:
        self._provenance[ioc_value] = json.dumps(
            {"source": source, "raw_ref": raw_ref,
             "ts": time.strftime("%Y-%m-%d %H:%M:%S")}, ensure_ascii=False)
        return {"ioc": ioc_value, "provenance": self._provenance[ioc_value]}

    def get_provenance(self, ioc_value: str) -> Dict[str, Any]:
        raw = self._provenance.get(ioc_value, "")
        return {"ioc": ioc_value, "provenance": json.loads(raw) if raw else None}

    # ------------------------------------------------------------------ #
    # 导出 STIX bundle
    # ------------------------------------------------------------------ #
    def export_bundle(self, iocs: List[Dict[str, Any]]) -> Dict[str, Any]:
        objects: List[Dict[str, Any]] = []
        for ioc in iocs[:100]:
            bundle = self.ioc_to_stix(ioc)
            objects.extend(bundle["objects"])
        return {"type": "bundle", "id": f"bundle--{uuid.uuid4()}",
                "objects": objects,
                "object_count": len(objects)}


_phase: Optional[IntelSharingPhase] = None


def get_sharing_phase() -> IntelSharingPhase:
    global _phase
    if _phase is None:
        _phase = IntelSharingPhase()
    return _phase
