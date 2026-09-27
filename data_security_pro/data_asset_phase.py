# -*- coding: utf-8 -*-
"""
data_asset_phase.py — 阶段3：数据资产盘点。

- 资产清单（数据库/表/字段/文件/存储桶）
- 数据流向图（来源 -> 经过系统 -> 去向）
- 数据所有者 / 管理员
- 分类统计 / 价值评估 / 变更监控 / 资产地图
"""

from __future__ import annotations

import time
import uuid
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional


@dataclass
class DataAsset:
    asset_id: str = ""
    name: str = ""
    kind: str = "table"          # db/table/field/file/bucket
    location: str = ""
    owner: str = "未分配"
    admin: str = "未分配"
    sensitivity: str = "internal"
    value_score: int = 50        # 0-100
    size_mb: float = 0.0
    source_system: str = ""
    dest_system: str = ""
    updated_at: str = ""

    def to_dict(self) -> Dict[str, Any]:
        return {
            "asset_id": self.asset_id, "name": self.name,
            "kind": self.kind, "location": self.location,
            "owner": self.owner, "admin": self.admin,
            "sensitivity": self.sensitivity,
            "value_score": self.value_score,
            "size_mb": self.size_mb,
            "source_system": self.source_system,
            "dest_system": self.dest_system,
            "updated_at": self.updated_at,
        }


class DataAssetPhase:
    """阶段3：数据资产盘点。"""

    def __init__(self) -> None:
        self._assets: Dict[str, DataAsset] = {}
        self._flows: List[Dict[str, Any]] = []
        self._changes: List[Dict[str, Any]] = []
        self._seed_mock()

    # ------------------------------------------------------------------ #
    def _seed_mock(self) -> None:
        seed = [
            ("用户主库", "db", "mysql://10.0.0.11:3306/crm", "张工",
             "DBA组", "confidential", 85, 1200.0, "业务中台", "数仓"),
            ("用户表 users", "table", "crm.users", "张工", "DBA组",
             "top_secret", 90, 480.0, "用户主库", "数仓ods"),
            ("订单表 orders", "table", "crm.orders", "李工", "DBA组",
             "confidential", 80, 800.0, "交易系统", "数仓"),
            ("敏感字段 id_card", "field", "crm.users.id_card", "张工",
             "DBA组", "top_secret", 95, 0.0, "用户主库", "数仓"),
            ("财务报表 xlsx", "file", "nas://finance/2026Q2.xlsx",
             "财务-王姐", "财务部", "confidential", 70, 12.5,
             "ERP", "财务共享"),
            ("OSS 备份桶", "bucket", "oss://prod-backup-01", "运维-赵",
             "运维部", "internal", 55, 10240.0, "数据库", "异地容灾"),
        ]
        for name, kind, loc, owner, admin, sens, val, sz, src, dst in seed:
            a = DataAsset(
                asset_id="A" + uuid.uuid4().hex[:8],
                name=name, kind=kind, location=loc,
                owner=owner, admin=admin, sensitivity=sens,
                value_score=val, size_mb=sz,
                source_system=src, dest_system=dst,
                updated_at=time.strftime("%Y-%m-%d %H:%M:%S"))
            self._assets[a.asset_id] = a
        self._flows = [
            {"id": "F1", "source": "用户主库", "system": "ETL-Job-01",
             "dest": "数仓ods", "volume_mb": 480.0, "freq": "每日"},
            {"id": "F2", "source": "交易系统", "system": "CDC",
             "dest": "数仓dwd", "volume_mb": 800.0, "freq": "实时"},
            {"id": "F3", "source": "ERP", "system": "FTP",
             "dest": "财务共享", "volume_mb": 12.5, "freq": "每周"},
        ]

    # ------------------------------------------------------------------ #
    def list_assets(self, kind: Optional[str] = None) -> List[Dict[str, Any]]:
        items = list(self._assets.values())
        if kind:
            items = [a for a in items if a.kind == kind]
        return [a.to_dict() for a in items]

    def get_asset(self, asset_id: str) -> Optional[Dict[str, Any]]:
        a = self._assets.get(asset_id)
        return a.to_dict() if a else None

    # ------------------------------------------------------------------ #
    def add_asset(self, name: str, kind: str = "table",
                  location: str = "", owner: str = "未分配",
                  admin: str = "未分配", sensitivity: str = "internal",
                  value_score: int = 50, size_mb: float = 0.0,
                  source_system: str = "", dest_system: str = "",
                  ) -> Dict[str, Any]:
        a = DataAsset(
            asset_id="A" + uuid.uuid4().hex[:8],
            name=name, kind=kind, location=location,
            owner=owner, admin=admin, sensitivity=sensitivity,
            value_score=max(0, min(100, value_score)), size_mb=size_mb,
            source_system=source_system, dest_system=dest_system,
            updated_at=time.strftime("%Y-%m-%d %H:%M:%S"))
        self._assets[a.asset_id] = a
        self._changes.append({
            "ts": time.strftime("%Y-%m-%d %H:%M:%S"),
            "type": "add", "asset_id": a.asset_id, "name": name})
        return a.to_dict()

    # ------------------------------------------------------------------ #
    def summary(self) -> Dict[str, Any]:
        assets = list(self._assets.values())
        by_kind: Dict[str, int] = {}
        by_sens: Dict[str, int] = {}
        total_size = 0.0
        value_sum = 0
        for a in assets:
            by_kind[a.kind] = by_kind.get(a.kind, 0) + 1
            by_sens[a.sensitivity] = by_sens.get(a.sensitivity, 0) + 1
            total_size += a.size_mb
            value_sum += a.value_score
        return {
            "total_assets": len(assets),
            "by_kind": by_kind,
            "by_sensitivity": by_sens,
            "total_size_mb": round(total_size, 1),
            "avg_value": round(value_sum / len(assets), 1) if assets else 0,
        }

    # ------------------------------------------------------------------ #
    def data_flows(self) -> List[Dict[str, Any]]:
        return list(self._flows)

    # ------------------------------------------------------------------ #
    def asset_map(self) -> Dict[str, Any]:
        """资产地图：节点+边。"""
        nodes = []
        for a in self._assets.values():
            nodes.append({
                "id": a.asset_id, "name": a.name,
                "kind": a.kind, "sensitivity": a.sensitivity,
                "value": a.value_score,
            })
        edges = []
        for f in self._flows:
            edges.append({
                "source": f["source"], "target": f["dest"],
                "via": f["system"], "label": f"{f['freq']} {f['volume_mb']}MB",
            })
        return {"nodes": nodes, "edges": edges}

    # ------------------------------------------------------------------ #
    def changes(self, limit: int = 30) -> List[Dict[str, Any]]:
        return list(self._changes[-limit:])


_default_phase: Optional[DataAssetPhase] = None


def get_data_asset_phase() -> DataAssetPhase:
    global _default_phase
    if _default_phase is None:
        _default_phase = DataAssetPhase()
    return _default_phase


__all__ = ["DataAssetPhase", "DataAsset", "get_data_asset_phase"]
