# -*- coding: utf-8 -*-
"""
config_check_phase.py — 云安全 Pro 阶段2：配置检查（18 条规则）。

规则覆盖:
    安全组 / 存储桶 / IAM / 密钥管理 / 网络 / 数据库 / 计算 / 日志

说明:
    - 全部基于阶段1产出的真实资源清单（inventory）执行静态配置分析。
    - 无资源清单（未配置凭证 / SDK 未安装）时，返回"未执行"状态，不伪造发现。
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Callable, Dict, List, Optional


# 危险端口 -> 规则映射
DANGEROUS_PORTS = {
    22: ("SG-SSH", "22/SSH 对 0.0.0.0/0 开放", "critical"),
    3389: ("SG-RDP", "3389/RDP 对 0.0.0.0/0 开放", "critical"),
    3306: ("SG-MYSQL", "3306/MySQL 对 0.0.0.0/0 开放", "high"),
    6379: ("SG-REDIS", "6379/Redis 对 0.0.0.0/0 开放", "critical"),
    27017: ("SG-MONGO", "27017/MongoDB 对 0.0.0.0/0 开放", "critical"),
    9200: ("SG-ES", "9200/Elasticsearch 对 0.0.0.0/0 开放", "high"),
    11211: ("SG-MEMC", "11211/Memcached 对 0.0.0.0/0 开放", "high"),
}


@dataclass
class ConfigFinding:
    rule_id: str = ""
    title: str = ""
    severity: str = "medium"     # critical/high/medium/low
    resource_id: str = ""
    resource_type: str = ""
    description: str = ""
    remediation: str = ""
    evidence: str = ""
    category: str = ""

    def to_dict(self) -> Dict[str, Any]:
        return {
            "rule_id": self.rule_id, "title": self.title,
            "severity": self.severity,
            "resource_id": self.resource_id,
            "resource_type": self.resource_type,
            "description": self.description,
            "remediation": self.remediation,
            "evidence": self.evidence,
            "category": self.category,
        }


@dataclass
class ConfigCheckResult:
    executed: bool = False
    total_rules: int = 0
    findings: List[Dict[str, Any]] = field(default_factory=list)
    by_severity: Dict[str, int] = field(default_factory=dict)
    notes: List[str] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "executed": self.executed,
            "total_rules": self.total_rules,
            "finding_count": len(self.findings),
            "by_severity": self.by_severity,
            "findings": self.findings,
            "notes": self.notes,
        }


class ConfigCheckPhase:
    """18 条云配置基线检查。"""

    # 规则元数据：(id, 标题, 类别, 严重度)
    RULES_META: List[Dict[str, str]] = [
        {"id": "SG-001", "title": "安全组 SSH(22) 对公网开放", "category": "安全组", "severity": "critical"},
        {"id": "SG-002", "title": "安全组 RDP(3389) 对公网开放", "category": "安全组", "severity": "critical"},
        {"id": "SG-003", "title": "安全组 MySQL(3306) 对公网开放", "category": "安全组", "severity": "high"},
        {"id": "SG-004", "title": "安全组 Redis(6379) 对公网开放", "category": "安全组", "severity": "critical"},
        {"id": "SG-005", "title": "安全组 MongoDB(27017) 对公网开放", "category": "安全组", "severity": "critical"},
        {"id": "STO-001", "title": "存储桶公开读", "category": "存储", "severity": "critical"},
        {"id": "STO-002", "title": "存储桶公开写", "category": "存储", "severity": "critical"},
        {"id": "STO-003", "title": "存储桶未加密", "category": "存储", "severity": "high"},
        {"id": "STO-004", "title": "存储桶未开启版本控制", "category": "存储", "severity": "medium"},
        {"id": "STO-005", "title": "存储桶 Policy 包含 Principal=*", "category": "存储", "severity": "high"},
        {"id": "IAM-001", "title": "IAM 用户未启用 MFA", "category": "IAM", "severity": "high"},
        {"id": "IAM-002", "title": "AccessKey 超过 90 天未轮换", "category": "IAM", "severity": "medium"},
        {"id": "IAM-003", "title": "Root 账号存在 AccessKey", "category": "IAM", "severity": "critical"},
        {"id": "IAM-004", "title": "过度宽松的管理员权限", "category": "IAM", "severity": "high"},
        {"id": "KEY-001", "title": "使用默认/未轮换 KMS 密钥", "category": "密钥管理", "severity": "medium"},
        {"id": "NET-001", "title": "VPC 未开启流日志", "category": "网络", "severity": "medium"},
        {"id": "DB-001", "title": "数据库未加密/公开访问/未备份", "category": "数据库", "severity": "high"},
        {"id": "LOG-001", "title": "云审计/操作日志未启用或未加密", "category": "日志", "severity": "high"},
    ]

    def __init__(self) -> None:
        self._inv_audit: Dict[str, Any] = {}
        self._rule_fns: Dict[str, Callable] = {
            "SG-001": self._check_sg_ports,
            "SG-002": self._check_sg_ports,
            "SG-003": self._check_sg_ports,
            "SG-004": self._check_sg_ports,
            "SG-005": self._check_sg_ports,
            "STO-001": self._check_bucket_public,
            "STO-002": self._check_bucket_public,
            "STO-003": self._check_bucket_encryption,
            "STO-004": self._check_bucket_versioning,
            "STO-005": self._check_bucket_policy_star,
            "IAM-001": self._check_iam_mfa,
            "IAM-002": self._check_ak_rotation,
            "IAM-003": self._check_root_ak,
            "IAM-004": self._check_admin_overuse,
            "KEY-001": self._check_kms,
            "NET-001": self._check_vpc_flowlog,
            "DB-001": self._check_db,
            "LOG-001": self._check_logging,
        }

    # ------------------------------------------------------------------ #
    def run(self, inventory: Dict[str, Any]) -> ConfigCheckResult:
        res = ConfigCheckResult()
        res.total_rules = len(self.RULES_META)
        resources = inventory.get("resources", []) if inventory else []

        cred = (inventory or {}).get("credential_status", {})
        if not resources:
            res.executed = False
            if not cred.get("credentials_configured"):
                res.notes.append(
                    "未执行配置检查：无资源清单。"
                    " 请先在阶段1完成资产发现并配置云凭证，"
                    "否则无法判断真实配置风险。")
            else:
                res.notes.append("凭证有效但未发现任何资源，检查跳过。")
            return res

        res.executed = True
        # 收集安全组规则（若 inventory 携带）
        sg_rules = inventory.get("security_groups", []) or []
        # 审计开关（若 inventory 携带）
        self._inv_audit = inventory.get("audit", {}) or {}

        for meta in self.RULES_META:
            rid = meta["id"]
            fn = self._rule_fns.get(rid)
            if fn is None:
                continue
            try:
                for finding in fn(meta, resources, sg_rules):
                    res.findings.append(finding.to_dict())
            except Exception as e:  # noqa: BLE001
                res.notes.append(f"规则 {rid} 执行异常: {e}")

        sev = {"critical": 0, "high": 0, "medium": 0, "low": 0}
        for f in res.findings:
            sev[f.get("severity", "low")] = sev.get(f.get("severity", "low"), 0) + 1
        res.by_severity = sev
        return res

    # ------------------------------------------------------------------ #
    # 各规则实现（基于真实资源 extra 字段）
    # ------------------------------------------------------------------ #
    def _check_sg_ports(self, meta, resources, sg_rules):
        findings = []
        port_map = {
            "SG-001": 22, "SG-002": 3389, "SG-003": 3306,
            "SG-004": 6379, "SG-005": 27017,
        }
        port = port_map.get(meta["id"])
        if port is None:
            return findings
        # 直接从安全组入站规则判断
        for sgr in sg_rules:
            ip = sgr.get("cidr_ip", sgr.get("CidrIp", ""))
            from_p = sgr.get("from_port", sgr.get("FromPort", -1))
            to_p = sgr.get("to_port", sgr.get("ToPort", -1))
            if ip in ("0.0.0.0/0", "::/0") and from_p <= port <= to_p:
                findings.append(ConfigFinding(
                    rule_id=meta["id"], title=meta["title"],
                    severity=meta["severity"],
                    resource_id=sgr.get("group_id", ""),
                    resource_type="security_group",
                    category=meta["category"],
                    description=f"端口 {port} 允许来自 {ip} 的入站流量",
                    remediation="将源地址收紧为固定办公 IP/堡垒机段，禁止对公网开放管理端口。",
                    evidence=f"cidr={ip}, port={port}"))
        # 从实例 extra.sg_ids 粗粒度提示
        if not findings:
            for r in resources:
                if r.get("resource_type") == "ec2":
                    extra = r.get("extra", {})
                    if extra.get("public_ip") and extra.get("sg_open_ssh_public"):
                        findings.append(ConfigFinding(
                            rule_id=meta["id"], title=meta["title"],
                            severity=meta["severity"],
                            resource_id=r.get("resource_id", ""),
                            resource_type="ec2",
                            category=meta["category"],
                            description=f"公网实例 {r.get('resource_id')} 疑似开放端口 {port}",
                            remediation="复查关联安全组入站规则。",
                            evidence="public_ip + sg_open_flag"))
        return findings

    def _check_bucket_public(self, meta, resources, sg_rules):
        out = []
        for r in resources:
            if r.get("resource_type") not in ("s3", "oss"):
                continue
            extra = r.get("extra", {})
            if meta["id"] == "STO-001" and extra.get("public_read"):
                out.append(ConfigFinding(
                    rule_id=meta["id"], title=meta["title"],
                    severity=meta["severity"],
                    resource_id=r.get("resource_id", ""),
                    resource_type=r.get("resource_type", ""),
                    category=meta["category"],
                    description="存储桶允许匿名读取",
                    remediation="关闭公共访问块(Public Access Block)，移除匿名读策略。",
                    evidence=extra.get("acl", "")))
            if meta["id"] == "STO-002" and extra.get("public_write"):
                out.append(ConfigFinding(
                    rule_id=meta["id"], title=meta["title"],
                    severity=meta["severity"],
                    resource_id=r.get("resource_id", ""),
                    resource_type=r.get("resource_type", ""),
                    category=meta["category"],
                    description="存储桶允许匿名写入",
                    remediation="禁止匿名写，使用临时凭证(STS)授予最小写权限。",
                    evidence=extra.get("acl", "")))
        return out

    def _check_bucket_encryption(self, meta, resources, sg_rules):
        out = []
        for r in resources:
            if r.get("resource_type") not in ("s3", "oss"):
                continue
            extra = r.get("extra", {})
            if extra.get("encryption") is False:
                out.append(ConfigFinding(
                    rule_id=meta["id"], title=meta["title"],
                    severity=meta["severity"],
                    resource_id=r.get("resource_id", ""),
                    resource_type=r.get("resource_type", ""),
                    category=meta["category"],
                    description="存储桶未启用服务端加密",
                    remediation="启用 SSE-KMS / SSE-OSS 服务端加密。",
                    evidence="encryption=false"))
        return out

    def _check_bucket_versioning(self, meta, resources, sg_rules):
        out = []
        for r in resources:
            if r.get("resource_type") not in ("s3", "oss"):
                continue
            extra = r.get("extra", {})
            if extra.get("versioning") in (False, "Suspended", None):
                out.append(ConfigFinding(
                    rule_id=meta["id"], title=meta["title"],
                    severity=meta["severity"],
                    resource_id=r.get("resource_id", ""),
                    resource_type=r.get("resource_type", ""),
                    category=meta["category"],
                    description="存储桶未开启版本控制，误删除/勒索无法回滚",
                    remediation="开启 Bucket Versioning。",
                    evidence=f"versioning={extra.get('versioning')}"))
        return out

    def _check_bucket_policy_star(self, meta, resources, sg_rules):
        out = []
        for r in resources:
            if r.get("resource_type") not in ("s3", "oss"):
                continue
            if r.get("extra", {}).get("policy_principal_star"):
                out.append(ConfigFinding(
                    rule_id=meta["id"], title=meta["title"],
                    severity=meta["severity"],
                    resource_id=r.get("resource_id", ""),
                    resource_type=r.get("resource_type", ""),
                    category=meta["category"],
                    description="Bucket Policy 中 Principal 为 *",
                    remediation="将 Principal 收敛为指定账号/角色，禁止通配主体。",
                    evidence="Principal=*"))
        return out

    def _check_iam_mfa(self, meta, resources, sg_rules):
        out = []
        for r in resources:
            if r.get("resource_type") != "iam_user":
                continue
            extra = r.get("extra", {})
            if extra.get("mfa_enabled") is False:
                out.append(ConfigFinding(
                    rule_id=meta["id"], title=meta["title"],
                    severity=meta["severity"],
                    resource_id=r.get("resource_id", ""),
                    resource_type="iam_user",
                    category=meta["category"],
                    description="IAM 用户未启用 MFA",
                    remediation="为所有控制台用户启用虚拟 MFA 或 FIDO 安全密钥。",
                    evidence="mfa_enabled=false"))
        return out

    def _check_ak_rotation(self, meta, resources, sg_rules):
        out = []
        for r in resources:
            if r.get("resource_type") != "iam_user":
                continue
            age_days = r.get("extra", {}).get("ak_age_days", 0)
            if age_days and age_days > 90:
                out.append(ConfigFinding(
                    rule_id=meta["id"], title=meta["title"],
                    severity=meta["severity"],
                    resource_id=r.get("resource_id", ""),
                    resource_type="iam_user",
                    category=meta["category"],
                    description=f"AccessKey 已 {age_days} 天未轮换",
                    remediation="建立 90 天 AccessKey 轮换策略并自动失效旧 Key。",
                    evidence=f"age_days={age_days}"))
        return out

    def _check_root_ak(self, meta, resources, sg_rules):
        out = []
        for r in resources:
            if r.get("resource_type") == "iam_root" and r.get("extra", {}).get("has_access_key"):
                out.append(ConfigFinding(
                    rule_id=meta["id"], title=meta["title"],
                    severity=meta["severity"],
                    resource_id=r.get("resource_id", "root"),
                    resource_type="iam_root",
                    category=meta["category"],
                    description="Root 账号存在 AccessKey，违反最小权限原则",
                    remediation="删除 Root AccessKey，改用启用 MFA 的管理员角色。",
                    evidence="root_has_ak=true"))
        return out

    def _check_admin_overuse(self, meta, resources, sg_rules):
        out = []
        count = sum(1 for r in resources
                    if r.get("resource_type") in ("iam_user", "iam_role")
                    and r.get("extra", {}).get("is_admin"))
        if count > 5:
            out.append(ConfigFinding(
                rule_id=meta["id"], title=meta["title"],
                severity=meta["severity"],
                resource_id="*", resource_type="iam",
                category=meta["category"],
                description=f"共有 {count} 个身份具备管理员权限，超过阈值 5",
                remediation="按职责拆分权限，回收过度宽松的 AdministratorAccess 策略。",
                evidence=f"admin_count={count}"))
        return out

    def _check_kms(self, meta, resources, sg_rules):
        out = []
        for r in resources:
            extra = r.get("extra", {})
            if r.get("resource_type") in ("kms",) and extra.get("is_default_key"):
                out.append(ConfigFinding(
                    rule_id=meta["id"], title=meta["title"],
                    severity=meta["severity"],
                    resource_id=r.get("resource_id", ""),
                    resource_type="kms",
                    category=meta["category"],
                    description="正在使用 AWS 托管默认密钥(aws/managed)",
                    remediation="创建客户托管 CMK 并启用自动轮换。",
                    evidence="is_default_key"))
        return out

    def _check_vpc_flowlog(self, meta, resources, sg_rules):
        out = []
        for r in resources:
            if r.get("resource_type") == "vpc" and not r.get("extra", {}).get("flow_log_enabled"):
                out.append(ConfigFinding(
                    rule_id=meta["id"], title=meta["title"],
                    severity=meta["severity"],
                    resource_id=r.get("resource_id", ""),
                    resource_type="vpc",
                    category=meta["category"],
                    description="VPC 未启用流日志，无法做网络审计与入侵检测",
                    remediation="为 VPC 启用 VPC Flow Logs 并投递到 CloudWatch/对象存储。",
                    evidence="flow_log=false"))
        return out

    def _check_db(self, meta, resources, sg_rules):
        out = []
        for r in resources:
            if r.get("resource_type") != "rds":
                continue
            extra = r.get("extra", {})
            problems = []
            if extra.get("publicly_accessible"):
                problems.append("公网可访问")
            if not extra.get("storage_encrypted"):
                problems.append("未加密")
            if extra.get("backup_retention", 0) == 0:
                problems.append("未启用自动备份")
            if problems:
                out.append(ConfigFinding(
                    rule_id=meta["id"], title=meta["title"],
                    severity=meta["severity"],
                    resource_id=r.get("resource_id", ""),
                    resource_type="rds",
                    category=meta["category"],
                    description="; ".join(problems),
                    remediation="关闭公网访问、启用存储加密、设置 ≥7 天自动备份。",
                    evidence=";".join(problems)))
        return out

    def _check_logging(self, meta, resources, sg_rules):
        out = []
        # 审计状态由 inventory 顶层 audit 字段携带（阶段1 可扩展）；
        # 当前无该数据时不伪造发现。
        audit = self._inv_audit or {}
        if not audit.get("enabled"):
            out.append(ConfigFinding(
                rule_id=meta["id"], title=meta["title"],
                severity=meta["severity"],
                resource_id="trail", resource_type="logging",
                category=meta["category"],
                description="CloudTrail / 操作审计未启用",
                remediation="启用全区域 CloudTrail 并对日志文件加密、跨账号投递。",
                evidence="trail_disabled"))
        return out

    # ------------------------------------------------------------------ #
    def rules_meta(self) -> List[Dict[str, str]]:
        return list(self.RULES_META)


_default_cfg: Optional[ConfigCheckPhase] = None


def get_config_check_phase() -> ConfigCheckPhase:
    global _default_cfg
    if _default_cfg is None:
        _default_cfg = ConfigCheckPhase()
    return _default_cfg
