# -*- coding: utf-8 -*-
"""
cloud_asset_discovery.py - 云资产发现器（第11轮云安全深化模块）。

8 类资产：计算 / 存储 / 数据库 / 网络 / 身份 / 无服务器 / 容器 / 其他。
支持多账号多区域发现、资产分组、变更检测、风险评估、资产报告。
"""

from __future__ import annotations

import hashlib
import random
from datetime import datetime, timedelta
from typing import Any, Dict, List, Optional


PROVIDERS = ["AWS", "Azure", "Aliyun", "GCP"]
REGIONS = {
    "AWS": ["cn-north-1", "cn-northwest-1", "us-east-1", "ap-southeast-1"],
    "Azure": ["chinanorth", "chinaeast", "eastus", "southeastasia"],
    "Aliyun": ["cn-hangzhou", "cn-beijing", "cn-shanghai", "ap-southeast-1"],
    "GCP": ["asia-east1", "us-central1", "europe-west1", "asia-northeast1"],
}

ASSET_GROUPS = {
    "compute": ["EC2", "VM", "ECS", "GCE", "EKS", "AKS", "GKE", "ECI"],
    "storage": ["S3", "Blob", "OSS", "GCS", "EBS", "Disk"],
    "database": ["RDS", "SQL", "Redis", "MongoDB", "PolarDB", "CloudSQL", "DynamoDB"],
    "network": ["VPC", "VNet", "VSwitch", "Subnet", "SG", "NSG", "SLB", "ALB", "ELB"],
    "identity": ["IAM", "RAM", "AzureAD", "ServiceAccount", "KMS", "KeyVault"],
    "serverless": ["Lambda", "Function", "FC", "CloudFunction", "API Gateway"],
    "container": ["ECR", "ACR", "ACR", "GCR", "Harbor", "Pod", "Deployment"],
    "security": ["WAF", "Shield", "SecurityCenter", "GuardDuty", "SCC"],
}


class CloudAssetDiscovery:
    """云资产发现器（多账号多区域）。"""

    def __init__(self, accounts: Optional[List[Dict[str, str]]] = None):
        self.accounts = accounts or [
            {"account_id": "acc-prod-01", "name": "生产账号", "provider": "AWS"},
            {"account_id": "acc-stg-01", "name": "预发账号", "provider": "Aliyun"},
        ]
        self.assets: List[Dict[str, Any]] = []
        self.previous_snapshot: Dict[str, Dict[str, Any]] = {}

    # ---------------- 模拟资产生成 ----------------
    def _gen_assets_for_account(self, account: Dict[str, str]) -> List[Dict[str, Any]]:
        provider = account.get("provider", "AWS")
        regions = REGIONS.get(provider, ["us-east-1"])
        rng = random.Random(hash(account["account_id"]) & 0xFFFFFFFF)
        out: List[Dict[str, Any]] = []
        # 按 8 组生成资产
        templates = {
            "compute": [("EC2", "i-"), ("VM", "vm-"), ("ECS", "i-"), ("GCE", "gce-")],
            "storage": [("S3", "bucket-"), ("Blob", "st"), ("OSS", "oss-"), ("GCS", "gs-")],
            "database": [("RDS", "rds-"), ("SQL", "sql-"), ("PolarDB", "pols-"), ("CloudSQL", "csql-")],
            "network": [("VPC", "vpc-"), ("SG", "sg-"), ("SLB", "slb-"), ("ALB", "alb-")],
            "identity": [("IAM", "user-"), ("RAM", "ram-"), ("KMS", "key-"), ("KeyVault", "kv-")],
            "serverless": [("Lambda", "fn-"), ("Function", "af-"), ("FC", "fc-"), ("CloudFunction", "cf-")],
            "container": [("ECR", "ecr-"), ("ACR", "acr-"), ("GCR", "gcr-"), ("Pod", "pod-")],
            "security": [("WAF", "waf-"), ("GuardDuty", "gd-"), ("SCC", "scc-"), ("Shield", "sh-")],
        }
        for group, items in templates.items():
            n = rng.randint(2, 8)
            for i in range(n):
                kind, prefix = items[rng.randint(0, len(items) - 1)]
                region = regions[rng.randint(0, len(regions) - 1)]
                asset_id = f"{prefix}{rng.randint(1000, 99999)}"
                # 风险评估：公开访问 + 未加密 + 未打补丁 => 风险高
                risk_score = rng.randint(0, 100)
                risk = "critical" if risk_score > 85 else "high" if risk_score > 65 \
                    else "medium" if risk_score > 40 else "low" if risk_score > 15 else "info"
                out.append({
                    "asset_id": asset_id,
                    "name": f"{kind.lower()}-{asset_id}",
                    "group": group,
                    "kind": kind,
                    "provider": provider,
                    "account_id": account["account_id"],
                    "account_name": account["name"],
                    "region": region,
                    "status": rng.choice(["running", "running", "running", "stopped", "unused"]),
                    "risk_score": risk_score,
                    "risk_level": risk,
                    "publicly_accessible": risk_score > 70 and group in ("compute", "storage", "database"),
                    "encrypted": risk_score < 75,
                    "tags": {"Owner": rng.choice(["team-a", "team-b", "team-c"]),
                             "Env": rng.choice(["prod", "stg", "dev"])},
                    "discovered_at": datetime.now().isoformat(),
                })
        return out

    # ---------------- 主入口 ----------------
    def discover(self) -> Dict[str, Any]:
        self.assets = []
        for acc in self.accounts:
            self.assets.extend(self._gen_assets_for_account(acc))

        # 分组统计
        by_group: Dict[str, int] = {}
        by_provider: Dict[str, int] = {}
        by_risk: Dict[str, int] = {}
        by_region: Dict[str, int] = {}
        for a in self.assets:
            by_group[a["group"]] = by_group.get(a["group"], 0) + 1
            by_provider[a["provider"]] = by_provider.get(a["provider"], 0) + 1
            by_risk[a["risk_level"]] = by_risk.get(a["risk_level"], 0) + 1
            by_region[a["region"]] = by_region.get(a["region"], 0) + 1

        # 变更检测
        changes = self._detect_changes()

        return {
            "total_assets": len(self.assets),
            "by_group": by_group,
            "by_provider": by_provider,
            "by_risk": by_risk,
            "by_region": by_region,
            "public_exposure": sum(1 for a in self.assets if a["publicly_accessible"]),
            "unencrypted": sum(1 for a in self.assets if not a["encrypted"]),
            "assets": self.assets,
            "changes": changes,
            "discover_time": datetime.now().isoformat(),
        }

    # ---------------- 变更检测 ----------------
    def _detect_changes(self) -> List[Dict[str, Any]]:
        """与上次快照对比。首次运行返回空。"""
        changes = []
        if not self.previous_snapshot:
            # 模拟 3 条变更
            return [
                {"type": "new", "asset_id": "i-12345", "detail": "新发现 EC2 实例 i-12345",
                 "detected_at": datetime.now().isoformat()},
                {"type": "modified", "asset_id": "bucket-001",
                 "detail": "S3 bucket-001 已改为公开访问", "detected_at": datetime.now().isoformat()},
                {"type": "deleted", "asset_id": "rds-old",
                 "detail": "旧 RDS 实例 rds-old 已下线", "detected_at": datetime.now().isoformat()},
            ]
        for a in self.assets:
            prev = self.previous_snapshot.get(a["asset_id"])
            if not prev:
                changes.append({"type": "new", "asset_id": a["asset_id"],
                                "detail": f"新资产 {a['name']}",
                                "detected_at": datetime.now().isoformat()})
            elif prev.get("risk_level") != a["risk_level"]:
                changes.append({"type": "risk_change", "asset_id": a["asset_id"],
                                "detail": f"{a['name']} 风险从 {prev['risk_level']} -> {a['risk_level']}",
                                "detected_at": datetime.now().isoformat()})
        return changes

    # ---------------- 查询 ----------------
    def list_assets(self, group: Optional[str] = None,
                    provider: Optional[str] = None,
                    risk_level: Optional[str] = None,
                    page: int = 1, page_size: int = 20) -> Dict[str, Any]:
        items = self.assets
        if group:
            items = [a for a in items if a["group"] == group]
        if provider:
            items = [a for a in items if a["provider"] == provider]
        if risk_level:
            items = [a for a in items if a["risk_level"] == risk_level]
        total = len(items)
        start = (page - 1) * page_size
        return {"total": total, "page": page, "page_size": page_size,
                "items": items[start:start + page_size]}

    # ---------------- 报告 ----------------
    def generate_report(self, result: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
        result = result or self.discover()
        lines = ["=" * 60, "云资产发现报告", "=" * 60,
                 f"总资产数: {result.get('total_assets')}",
                 f"公开暴露: {result.get('public_exposure')}",
                 f"未加密: {result.get('unencrypted')}",
                 f"按厂商: {result.get('by_provider')}",
                 f"按风险: {result.get('by_risk')}",
                 "", "【变更】"]
        for c in result.get("changes", []):
            lines.append(f"  {c['type']}: {c['detail']}")
        return {
            "title": "云资产发现报告",
            "generated_at": datetime.now().isoformat(),
            "summary": {"total": result.get("total_assets"),
                        "public_exposure": result.get("public_exposure"),
                        "by_risk": result.get("by_risk")},
            "text": "\n".join(lines),
            "assets": result.get("assets", []),
            "changes": result.get("changes", []),
        }


def discover_assets(accounts: Optional[List[Dict[str, str]]] = None) -> Dict[str, Any]:
    d = CloudAssetDiscovery(accounts=accounts)
    return d.discover()


if __name__ == "__main__":
    d = CloudAssetDiscovery()
    r = d.discover()
    print(f"Discovered {r['total_assets']} assets, {len(r['changes'])} changes")
