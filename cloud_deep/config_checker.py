# -*- coding: utf-8 -*-
"""
config_checker.py — 云配置检查规则引擎（方向4）。

规则域：
    - 安全组（0.0.0.0/0 开放高危端口）
    - 存储桶（S3/OSS 公开读写）
    - 防火墙 / NetworkACL
    - IAM（未启用 MFA、AccessKey 长期未轮换、root 有 AK）
    - 加密（S3 默认未加密、EBs 未加密、RDS 未加密）

输入既可以来自真实 cloud_client.aws_call()，也可以传入已采集的 dict 做离线评估。
"""
from __future__ import annotations

from typing import Any, Callable, Dict, List


# --------------------------------------------------------------------------- #
# 规则定义
# --------------------------------------------------------------------------- #
RULES: List[Dict[str, Any]] = [
    # ---- 安全组 ----
    {
        "rule_id": "SG-001",
        "domain": "security_group",
        "title": "安全组对 0.0.0.0/0 开放 22 端口",
        "severity": "critical",
        "check": lambda c: (
            c.get("port_range_from") == 22
            and c.get("source") in ("0.0.0.0/0", "::/0")),
        "fix": "限制源 IP 为运维跳板机白名单",
    },
    {
        "rule_id": "SG-002",
        "domain": "security_group",
        "title": "安全组对 0.0.0.0/0 开放 3389 (RDP)",
        "severity": "critical",
        "check": lambda c: (
            c.get("port_range_from") == 3389
            and c.get("source") in ("0.0.0.0/0", "::/0")),
        "fix": "限制 RDP 源 IP",
    },
    {
        "rule_id": "SG-003",
        "domain": "security_group",
        "title": "安全组对 0.0.0.0/0 开放 3306 (MySQL)",
        "severity": "high",
        "check": lambda c: (
            c.get("port_range_from") == 3306
            and c.get("source") in ("0.0.0.0/0", "::/0")),
        "fix": "数据库端口不对公网开放",
    },
    {
        "rule_id": "SG-004",
        "domain": "security_group",
        "title": "安全组对 0.0.0.0/0 开放 6379 (Redis)",
        "severity": "critical",
        "check": lambda c: (
            c.get("port_range_from") == 6379
            and c.get("source") in ("0.0.0.0/0", "::/0")),
        "fix": "Redis 永不暴露公网",
    },
    {
        "rule_id": "SG-005",
        "domain": "security_group",
        "title": "安全组对 0.0.0.0/0 开放任意端口 (-1)",
        "severity": "high",
        "check": lambda c: (
            c.get("ip_protocol") == "-1"
            and c.get("source") in ("0.0.0.0/0", "::/0")),
        "fix": "按需开放最小端口集",
    },
    # ---- 存储桶 ----
    {
        "rule_id": "S3-001",
        "domain": "storage",
        "title": "S3/OSS 存储桶允许公开读",
        "severity": "critical",
        "check": lambda c: (
            c.get("public_read", False) is True
            and c.get("enforced", True) is not False),
        "fix": "关闭 public access block 之外的公开 ACL",
    },
    {
        "rule_id": "S3-002",
        "domain": "storage",
        "title": "S3 未开启默认加密",
        "severity": "high",
        "check": lambda c: c.get("default_encryption", False) is False,
        "fix": "启用 SSE-S3 或 SSE-KMS",
    },
    {
        "rule_id": "S3-003",
        "domain": "storage",
        "title": "S3 未启用版本控制",
        "severity": "medium",
        "check": lambda c: c.get("versioning", "Disabled") != "Enabled",
        "fix": "开启 Versioning 防误删",
    },
    {
        "rule_id": "S3-004",
        "domain": "storage",
        "title": "S3 Bucket Policy 允许 * 主体",
        "severity": "critical",
        "check": lambda c: c.get("policy_all_principal", False) is True,
        "fix": "收敛 Principal 到具体 ARN",
    },
    # ---- IAM ----
    {
        "rule_id": "IAM-001",
        "domain": "iam",
        "title": "IAM 用户未启用 MFA",
        "severity": "high",
        "check": lambda c: c.get("mfa_enabled", True) is False,
        "fix": "强制开启虚拟 MFA / U2F",
    },
    {
        "rule_id": "IAM-002",
        "domain": "iam",
        "title": "AccessKey 超过 90 天未轮换",
        "severity": "medium",
        "check": lambda c: (c.get("age_days", 0) or 0) > 90,
        "fix": "AK 90 天轮换 + 闲置 30 天禁用",
    },
    {
        "rule_id": "IAM-003",
        "domain": "iam",
        "title": "Root 账户存在 AccessKey",
        "severity": "critical",
        "check": lambda c: c.get("is_root", False) is True
        and c.get("has_access_key", False) is True,
        "fix": "删除 Root AccessKey，改用 IAM 用户",
    },
    {
        "rule_id": "IAM-004",
        "domain": "iam",
        "title": "策略包含 Action:* / Resource:*",
        "severity": "high",
        "check": lambda c: c.get("admin_full_star", False) is True,
        "fix": "按最小权限拆分策略",
    },
    # ---- 加密 ----
    {
        "rule_id": "ENC-001",
        "domain": "encryption",
        "title": "EBS 卷未加密",
        "severity": "medium",
        "check": lambda c: c.get("encrypted", True) is False,
        "fix": "新卷默认开启 EBS 加密",
    },
    {
        "rule_id": "ENC-002",
        "domain": "encryption",
        "title": "RDS 未开启存储加密",
        "severity": "high",
        "check": lambda c: c.get("storage_encrypted", True) is False,
        "fix": "RDS 落盘加密 (KMS)",
    },
    {
        "rule_id": "ENC-003",
        "domain": "encryption",
        "title": "RDS 未开启自动备份",
        "severity": "low",
        "check": lambda c: c.get("backup_enabled", True) is False,
        "fix": "开启 7 天以上自动备份",
    },
    # ---- 网络 ----
    {
        "rule_id": "NET-001",
        "domain": "network",
        "title": "NetworkACL 入站允许所有 (0.0.0.0/0)",
        "severity": "medium",
        "check": lambda c: c.get("nacl_allow_all_inbound", False) is True,
        "fix": "NACL 按子网收敛",
    },
]


class ConfigChecker:
    """配置检查规则引擎。"""

    def __init__(self) -> None:
        self.rules = RULES

    # ------------------------------------------------------------------ #
    # 规则清单
    # ------------------------------------------------------------------ #
    def list_rules(self) -> Dict[str, Any]:
        return {
            "total": len(self.rules),
            "by_domain": {
                d: [r["rule_id"] for r in self.rules if r["domain"] == d]
                for d in ("security_group", "storage", "iam",
                          "encryption", "network")
            },
        }

    # ------------------------------------------------------------------ #
    # 对一组证据运行规则
    # ------------------------------------------------------------------ #
    def check(self, evidence: Dict[str, Any]) -> Dict[str, Any]:
        """evidence 形如 {"security_groups": [...], "buckets": [...], ...}。"""
        findings: List[Dict[str, Any]] = []
        buckets_map = {
            "security_groups": "security_group",
            "buckets": "storage",
            "iam_users": "iam",
            "iam_policies": "iam",
            "ebs_volumes": "encryption",
            "rds_instances": "encryption",
            "network_acls": "network",
        }
        for key, domain in buckets_map.items():
            for item in evidence.get(key, []):
                for rule in self.rules:
                    if rule["domain"] != domain:
                        continue
                    try:
                        hit = bool(rule["check"](item))
                    except Exception:
                        hit = False
                    if hit:
                        findings.append({
                            "rule_id": rule["rule_id"],
                            "domain": domain,
                            "title": rule["title"],
                            "severity": rule["severity"],
                            "resource_id": item.get("id")
                            or item.get("name") or item.get("arn"),
                            "evidence": item,
                            "fix": rule["fix"],
                        })
        sev_rank = {"critical": 4, "high": 3, "medium": 2, "low": 1}
        findings.sort(key=lambda f: -sev_rank.get(f["severity"], 0))
        counts = {"critical": 0, "high": 0, "medium": 0, "low": 0}
        for f in findings:
            counts[f["severity"]] = counts.get(f["severity"], 0) + 1
        return {
            "findings": findings,
            "counts": counts,
            "total": len(findings),
        }
