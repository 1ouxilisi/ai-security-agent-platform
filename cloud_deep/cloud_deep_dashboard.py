# -*- coding: utf-8 -*-
"""
cloud_deep_dashboard.py — 云安全深度控制台聚合（方向4）。
"""
from __future__ import annotations

import time
import uuid
from typing import Any, Dict, Optional

from .cloud_client import CloudClient
from .config_checker import ConfigChecker
from .asset_discovery import AssetDiscovery
from .risk_rater import RiskRater


class CloudDeepDashboard:
    """控制台聚合。"""

    def __init__(self) -> None:
        self.checker = ConfigChecker()
        self.rater = RiskRater()
        self._reports: Dict[str, Dict[str, Any]] = {}

    # ------------------------------------------------------------------ #
    # 环境
    # ------------------------------------------------------------------ #
    def env(self, provider: str = "aws", region: str = "") -> Dict[str, Any]:
        return CloudClient(provider=provider, region=region).describe()

    # ------------------------------------------------------------------ #
    # 真实扫描
    # ------------------------------------------------------------------ #
    def real_scan(self, provider: str = "aws",
                  region: str = "") -> Dict[str, Any]:
        client = CloudClient(provider=provider, region=region)
        discovery = AssetDiscovery(client)
        assets = discovery.discover()
        if not assets.get("discovered"):
            return {
                "scan_id": "n/a",
                "scanned": False,
                "reason": assets.get("reason"),
                "describe": assets.get("describe"),
            }
        # 把 discovery 结果拼成 evidence
        evidence = {
            "security_groups": [x for x in assets["security_groups"]
                                if "error" not in x],
            "buckets": [x for x in assets["buckets"]
                        if "error" not in x],
            "iam_users": [x for x in assets["iam_users"]
                          if "error" not in x],
            "ebs_volumes": [x for x in assets["ebs_volumes"]
                            if "error" not in x],
            "rds_instances": [x for x in assets["rds_instances"]
                              if "error" not in x],
            "network_acls": [x for x in assets["network_acls"]
                             if "error" not in x],
        }
        chk = self.checker.check(evidence)
        rating = self.rater.rate(chk["findings"])
        rid = "cloud-" + uuid.uuid4().hex[:10]
        report = {
            "scan_id": rid,
            "scanned": True,
            "provider": provider,
            "region": region,
            "created_at": time.time(),
            "assets": assets["summary"],
            "check": chk,
            "risk": rating,
        }
        self._reports[rid] = report
        return report

    # ------------------------------------------------------------------ #
    # 离线演示（用 demo evidence）
    # ------------------------------------------------------------------ #
    def demo_scan(self) -> Dict[str, Any]:
        evidence = AssetDiscovery().demo_evidence()
        chk = self.checker.check(evidence)
        rating = self.rater.rate(chk["findings"])
        rid = "cloud-demo-" + uuid.uuid4().hex[:8]
        report = {
            "scan_id": rid,
            "scanned": True,
            "mode": "demo",
            "created_at": time.time(),
            "assets": {k: len(v) for k, v in evidence.items()},
            "check": chk,
            "risk": rating,
        }
        self._reports[rid] = report
        return report

    # ------------------------------------------------------------------ #
    # 报告列表 / 详情
    # ------------------------------------------------------------------ #
    def list_reports(self) -> list:
        return [{"scan_id": r["scan_id"],
                 "provider": r.get("provider"),
                 "risk_level": r.get("risk", {}).get("risk_level"),
                 "created_at": r.get("created_at")}
                for r in self._reports.values()]

    def get_report(self, rid: str) -> Optional[Dict[str, Any]]:
        return self._reports.get(rid)

    def list_rules(self) -> Dict[str, Any]:
        return self.checker.list_rules()
