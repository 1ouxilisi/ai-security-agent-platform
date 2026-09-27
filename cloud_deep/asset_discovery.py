# -*- coding: utf-8 -*-
"""
asset_discovery.py — 云资产自动发现（方向4）。

通过 CloudClient 调用真实云 API；未配置凭证时返回明确提示，不 mock。
采集资源：EC2 实例、安全组、S3 桶、IAM 用户、EBS、RDS、NACL。
"""
from __future__ import annotations

from typing import Any, Dict, List, Optional

from .cloud_client import CloudClient


class AssetDiscovery:
    """云资产发现器。"""

    def __init__(self, client: Optional[CloudClient] = None) -> None:
        self.client = client or CloudClient()

    # ------------------------------------------------------------------ #
    # 主入口
    # ------------------------------------------------------------------ #
    def discover(self) -> Dict[str, Any]:
        desc = self.client.describe()
        if not desc["ready"]:
            return {
                "discovered": False,
                "reason": "云凭证未就绪：" + desc.get("hint", ""),
                "describe": desc,
            }
        out: Dict[str, Any] = {
            "discovered": True,
            "provider": self.client.provider,
            "region": self.client.region,
            "security_groups": self._security_groups(),
            "buckets": self._buckets(),
            "iam_users": self._iam_users(),
            "ebs_volumes": self._ebs_volumes(),
            "rds_instances": self._rds_instances(),
            "network_acls": self._network_acls(),
        }
        out["summary"] = {
            k: len(v) if isinstance(v, list) else 0
            for k, v in out.items()
        }
        return out

    # ------------------------------------------------------------------ #
    # 各资源
    # ------------------------------------------------------------------ #
    def _security_groups(self) -> List[Dict[str, Any]]:
        resp = self.client.aws_call("ec2", "describe_security_groups")
        if not resp["ok"]:
            return [{"error": resp["error"]}]
        out: List[Dict[str, Any]] = []
        for sg in resp["response"].get("SecurityGroups", []):
            for perm in sg.get("IpPermissions", []):
                for ip in perm.get("IpRanges", []) + perm.get("Ipv6Ranges", []):
                    out.append({
                        "id": sg.get("GroupId"),
                        "name": sg.get("GroupName"),
                        "port_range_from": perm.get("FromPort"),
                        "port_range_to": perm.get("ToPort"),
                        "ip_protocol": perm.get("IpProtocol"),
                        "source": ip.get("CidrIp") or ip.get("CidrIpv6"),
                    })
        return out

    def _buckets(self) -> List[Dict[str, Any]]:
        resp = self.client.aws_call("s3", "list_buckets")
        if not resp["ok"]:
            return [{"error": resp["error"]}]
        out: List[Dict[str, Any]] = []
        for b in resp["response"].get("Buckets", []):
            # 真实环境应再调 get_bucket_acl / get_bucket_encryption /
            # get_bucket_versioning；这里先返回名字
            out.append({
                "name": b.get("Name"),
                "id": b.get("Name"),
                "creation_date": str(b.get("CreationDate")),
                "note": "详细 ACL/加密需进一步调用 get_bucket_*",
            })
        return out

    def _iam_users(self) -> List[Dict[str, Any]]:
        resp = self.client.aws_call("iam", "list_users")
        if not resp["ok"]:
            return [{"error": resp["error"]}]
        out: List[Dict[str, Any]] = []
        for u in resp["response"].get("Users", []):
            out.append({
                "name": u.get("UserName"),
                "arn": u.get("Arn"),
                "create_date": str(u.get("CreateDate")),
            })
        return out

    def _ebs_volumes(self) -> List[Dict[str, Any]]:
        resp = self.client.aws_call("ec2", "describe_volumes")
        if not resp["ok"]:
            return [{"error": resp["error"]}]
        out: List[Dict[str, Any]] = []
        for v in resp["response"].get("Volumes", []):
            out.append({
                "id": v.get("VolumeId"),
                "encrypted": bool(v.get("Encrypted", False)),
                "size": v.get("Size"),
                "state": v.get("State"),
            })
        return out

    def _rds_instances(self) -> List[Dict[str, Any]]:
        resp = self.client.aws_call("rds", "describe_db_instances")
        if not resp["ok"]:
            return [{"error": resp["error"]}]
        out: List[Dict[str, Any]] = []
        for db in resp["response"].get("DBInstances", []):
            out.append({
                "id": db.get("DBInstanceIdentifier"),
                "storage_encrypted": bool(db.get("StorageEncrypted", False)),
                "backup_enabled": bool(db.get("BackupRetentionDays", 0) > 0),
                "engine": db.get("Engine"),
            })
        return out

    def _network_acls(self) -> List[Dict[str, Any]]:
        resp = self.client.aws_call("ec2", "describe_network_acls")
        if not resp["ok"]:
            return [{"error": resp["error"]}]
        out: List[Dict[str, Any]] = []
        for nacl in resp["response"].get("NetworkAcls", []):
            for entry in nacl.get("Entries", []):
                out.append({
                    "id": nacl.get("NetworkAclId"),
                    "rule_number": entry.get("RuleNumber"),
                    "protocol": entry.get("Protocol"),
                    "rule_action": entry.get("RuleAction"),
                    "cidr": entry.get("CidrBlock"),
                })
        return out

    # ------------------------------------------------------------------ #
    # 离线演示证据（仅用于控制台演示，不代表真实环境）
    # ------------------------------------------------------------------ #
    def demo_evidence(self) -> Dict[str, Any]:
        return {
            "security_groups": [
                {"id": "sg-001", "name": "web", "port_range_from": 22,
                 "ip_protocol": "tcp", "source": "0.0.0.0/0"},
                {"id": "sg-001", "name": "web", "port_range_from": 443,
                 "ip_protocol": "tcp", "source": "0.0.0.0/0"},
                {"id": "sg-002", "name": "db", "port_range_from": 3306,
                 "ip_protocol": "tcp", "source": "10.0.0.0/8"},
                {"id": "sg-003", "name": "redis", "port_range_from": 6379,
                 "ip_protocol": "tcp", "source": "0.0.0.0/0"},
            ],
            "buckets": [
                {"name": "prod-backup-2024", "id": "prod-backup-2024",
                 "public_read": True, "enforced": True,
                 "default_encryption": False, "versioning": "Disabled",
                 "policy_all_principal": True},
                {"name": "prod-logs", "id": "prod-logs",
                 "public_read": False, "enforced": True,
                 "default_encryption": True, "versioning": "Enabled",
                 "policy_all_principal": False},
            ],
            "iam_users": [
                {"name": "alice", "arn": "arn:aws:iam::111:user/alice",
                 "mfa_enabled": False, "age_days": 120},
                {"name": "bob", "arn": "arn:aws:iam::111:user/bob",
                 "mfa_enabled": True, "age_days": 30},
                {"name": "root", "arn": "arn:aws:iam::111:root",
                 "is_root": True, "has_access_key": True,
                 "mfa_enabled": False},
            ],
            "ebs_volumes": [
                {"id": "vol-a", "encrypted": False, "size": 100,
                 "state": "in-use"},
                {"id": "vol-b", "encrypted": True, "size": 50,
                 "state": "in-use"},
            ],
            "rds_instances": [
                {"id": "db-01", "storage_encrypted": False,
                 "backup_enabled": True, "engine": "mysql"},
                {"id": "db-02", "storage_encrypted": True,
                 "backup_enabled": False, "engine": "postgres"},
            ],
            "network_acls": [
                {"id": "nacl-01", "rule_number": 100,
                 "protocol": "-1", "rule_action": "allow",
                 "cidr": "0.0.0.0/0"},
            ],
        }
