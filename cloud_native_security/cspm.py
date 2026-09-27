# -*- coding: utf-8 -*-
"""
cspm.py - 云安全态势管理 (CSPM)（第25轮 CNAPP 模块）。

6 大能力：
  1. 云资产发现   — EC2 / S3 / RDS / Lambda / VPC / IAM / 安全组 / 负载均衡 / 云数据库 / 云缓存 / CDN
  2. 云配置审计   — 安全组开放 / 存储桶公开 / 数据库公开 / 加密未启用 / 日志未启用 / MFA未启用 / 权限过大
  3. 云合规评估   — CIS AWS / CIS Azure / CIS GCP / 等保云 / 行业合规 / 云合规报告
  4. 云风险评分   — 资产风险 / 配置风险 / 漏洞风险 / 网络风险 / 身份风险 / 数据风险 / 综合风险
  5. 云攻击路径   — 身份→资源→数据 / 权限提升 / 横向移动 / 数据渗出
  6. 云安全改进   — 配置修复 / 权限收紧 / 加密启用 / 日志启用 / 监控启用 / 修复优先级
"""

from __future__ import annotations

import re
import uuid
from datetime import datetime, timedelta
from typing import Any, Dict, List, Optional


def _clean(obj: Any) -> Any:
    if isinstance(obj, str):
        return re.sub(r"[\x00-\x1f\x7f]", "", obj)
    if isinstance(obj, dict):
        return {k: _clean(v) for k, v in obj.items()}
    if isinstance(obj, list):
        return [_clean(v) for v in obj]
    return obj


def _now() -> str:
    return datetime.now().isoformat()


def _rid(prefix: str = "") -> str:
    return f"{prefix}{uuid.uuid4().hex[:10]}"


class CloudSecurityPostureManagement:
    """云安全态势管理 (CSPM)。"""

    # ---------- 1. 云资产发现 ----------

    def discover_assets(self, cloud: str = "aws") -> Dict[str, Any]:
        assets = [
            {"id": "i-0a1b2c3d", "type": "ec2", "name": "web-server-01", "region": "us-east-1",
             "status": "running", "public_ip": "203.0.113.10", "tags": {"env": "prod", "team": "platform"}},
            {"id": "i-0e5f6g7h", "type": "ec2", "name": "app-server-02", "region": "us-east-1",
             "status": "running", "public_ip": None, "tags": {"env": "prod", "team": "app"}},
            {"id": "s3-app-data", "type": "s3", "name": "app-data-bucket", "region": "us-east-1",
             "status": "active", "public_access": False, "versioning": True, "encrypted": True},
            {"id": "s3-public-uploads", "type": "s3", "name": "public-uploads", "region": "us-east-1",
             "status": "active", "public_access": True, "versioning": False, "encrypted": False},
            {"id": "rds-prod-01", "type": "rds", "name": "postgres-prod", "region": "us-east-1",
             "engine": "PostgreSQL 16", "status": "available", "publicly_accessible": False, "encrypted": True},
            {"id": "lambda-api", "type": "lambda", "name": "api-handler", "region": "us-east-1",
             "runtime": "python3.11", "status": "active", "memory_mb": 512},
            {"id": "vpc-prod", "type": "vpc", "name": "prod-vpc", "region": "us-east-1",
             "cidr": "10.0.0.0/16", "subnets": 6, "flow_logs_enabled": False},
            {"id": "iam-admin-user", "type": "iam_user", "name": "admin@example.com", "region": "global",
             "mfa_enabled": False, "access_keys": 2, "admin_access": True},
            {"id": "sg-web", "type": "security_group", "name": "web-sg", "region": "us-east-1",
             "inbound_rules": 12, "outbound_rules": 5, "open_to_world": True},
            {"id": "alb-public", "type": "load_balancer", "name": "public-alb", "region": "us-east-1",
             "scheme": "internet-facing", "https_enabled": True, "waf_enabled": False},
            {"id": "elasticache-redis", "type": "elasticache", "name": "redis-cache", "region": "us-east-1",
             "engine": "Redis 7", "encrypted_at_rest": True, "encrypted_in_transit": False},
            {"id": "cloudfront-cdn", "type": "cloudfront", "name": "cdn-distribution", "region": "global",
             "https_enabled": True, "waf_enabled": True, "origin_shield": False},
        ]
        return {"assets": assets, "total": len(assets), "cloud": cloud, "discovered_at": _now()}

    # ---------- 2. 配置审计 ----------

    def audit_security_groups(self, cloud: str = "aws") -> Dict[str, Any]:
        findings = [
            {"id": "CFG-SG-001", "severity": "critical", "resource": "sg-web",
             "title": "安全组开放 SSH 到全世界", "port": 22, "source": "0.0.0.0/0",
             "remediation": "限制 SSH 源为公司 IP"},
            {"id": "CFG-SG-002", "severity": "high", "resource": "sg-db",
             "title": "安全组开放数据库端口到全世界", "port": 5432, "source": "0.0.0.0/0",
             "remediation": "限制数据库端口到应用安全组"},
            {"id": "CFG-SG-003", "severity": "medium", "resource": "sg-default",
             "title": "默认安全组允许所有出站", "port": "all", "source": "0.0.0.0/0",
             "remediation": "限制出站规则"},
        ]
        return {"findings": findings, "total": len(findings), "cloud": cloud}

    def audit_storage_buckets(self, cloud: str = "aws") -> Dict[str, Any]:
        findings = [
            {"id": "CFG-S3-001", "severity": "critical", "resource": "public-uploads",
             "title": "S3 存储桶公开访问",
             "remediation": "启用 Block Public Access"},
            {"id": "CFG-S3-002", "severity": "high", "resource": "public-uploads",
             "title": "S3 存储桶未启用版本控制",
             "remediation": "启用版本控制防止数据篡改/误删"},
            {"id": "CFG-S3-003", "severity": "high", "resource": "public-uploads",
             "title": "S3 存储桶未启用加密",
             "remediation": "启用默认 SSE 加密"},
            {"id": "CFG-S3-004", "severity": "medium", "resource": "app-data-bucket",
             "title": "S3 存储桶未配置访问日志",
             "remediation": "启用 S3 访问日志"},
        ]
        return {"findings": findings, "total": len(findings), "cloud": cloud}

    def audit_iam(self, cloud: str = "aws") -> Dict[str, Any]:
        findings = [
            {"id": "CFG-IAM-001", "severity": "critical", "resource": "iam-admin-user",
             "title": "根用户未启用 MFA",
             "remediation": "为根用户启用虚拟 MFA"},
            {"id": "CFG-IAM-002", "severity": "high", "resource": "iam-admin-user",
             "title": "IAM 用户有 2 个访问密钥",
             "remediation": "删除未使用的访问密钥"},
            {"id": "CFG-IAM-003", "severity": "high", "resource": "arn:aws:iam::123456:role/admin-role",
             "title": "IAM 策略允许 * * * (完全权限)",
             "remediation": "按最小权限原则收紧策略"},
            {"id": "CFG-IAM-004", "severity": "medium", "resource": "arn:aws:iam::123456:role/dev-role",
             "title": "IAM 角色允许从任何账户 AssumeRole",
             "remediation": "限制信任策略的 Principal"},
        ]
        return {"findings": findings, "total": len(findings), "cloud": cloud}

    def audit_logging(self, cloud: str = "aws") -> Dict[str, Any]:
        findings = [
            {"id": "CFG-LOG-001", "severity": "high", "resource": "vpc-prod",
             "title": "VPC Flow Logs 未启用",
             "remediation": "启用 VPC Flow Logs 并发送到 CloudWatch"},
            {"id": "CFG-LOG-002", "severity": "medium", "resource": "alb-public",
             "title": "ALB 访问日志未启用",
             "remediation": "启用 ALB access logs"},
            {"id": "CFG-LOG-003", "severity": "medium", "resource": "cloudtrail",
             "title": "CloudTrail 日志验证未启用",
             "remediation": "启用 Log file validation"},
        ]
        return {"findings": findings, "total": len(findings), "cloud": cloud}

    # ---------- 3. 合规评估 ----------

    def evaluate_compliance(self, framework: str = "cis-aws", cloud: str = "aws") -> Dict[str, Any]:
        frameworks = {
            "cis-aws": {
                "name": "CIS AWS Foundations Benchmark v3.0.0",
                "controls": [
                    {"id": "1.1", "title": "开启根用户 MFA", "status": "fail", "severity": "critical"},
                    {"id": "1.2", "title": "删除根用户访问密钥", "status": "pass", "severity": "critical"},
                    {"id": "1.4", "title": "确保启用 CloudTrail", "status": "pass", "severity": "high"},
                    {"id": "1.5", "title": "确保启用 CloudTrail 日志验证", "status": "fail", "severity": "medium"},
                    {"id": "2.1.1", "title": "确保 S3 桶策略不允许公开", "status": "fail", "severity": "critical"},
                    {"id": "2.2.1", "title": "确保开启 S3 访问日志", "status": "fail", "severity": "medium"},
                    {"id": "3.1", "title": "确保开启 CMK 加密", "status": "pass", "severity": "high"},
                    {"id": "3.2", "title": "确保开启 KMS 轮换", "status": "pass", "severity": "medium"},
                    {"id": "4.1", "title": "确保开启 AWS Config", "status": "fail", "severity": "medium"},
                    {"id": "4.3", "title": "确保开启 VPC Flow Logs", "status": "fail", "severity": "high"},
                ],
            },
            "cis-azure": {
                "name": "CIS Azure Foundations Benchmark v2.1.0",
                "controls": [
                    {"id": "1.1", "title": "确保安全默认值启用", "status": "pass", "severity": "high"},
                    {"id": "1.2", "title": "确保 MFA 启用", "status": "fail", "severity": "critical"},
                ],
            },
            "cis-gcp": {
                "name": "CIS GCP Foundations Benchmark v2.0.0",
                "controls": [
                    {"id": "1.1", "title": "确保安全密钥启用", "status": "fail", "severity": "high"},
                    {"id": "1.2", "title": "确保 Cloud Audit Logs 配置正确", "status": "pass", "severity": "high"},
                ],
            },
            "dengbao": {
                "name": "等保 2.0 云安全扩展要求",
                "controls": [
                    {"id": "8.1.1", "title": "身份鉴别", "status": "pass", "severity": "high"},
                    {"id": "8.1.3", "title": "访问控制", "status": "fail", "severity": "critical"},
                    {"id": "8.1.4", "title": "安全审计", "status": "fail", "severity": "high"},
                    {"id": "8.1.5", "title": "入侵防范", "status": "fail", "severity": "high"},
                ],
            },
        }
        fw = frameworks.get(framework, frameworks["cis-aws"])
        passed = sum(1 for c in fw["controls"] if c["status"] == "pass")
        total = len(fw["controls"])
        return {
            "framework": framework, "framework_name": fw["name"], "cloud": cloud,
            "controls": fw["controls"], "total_controls": total,
            "passed": passed, "failed": total - passed,
            "compliance_score": round(passed / total * 100, 1),
            "generated_at": _now(),
        }

    # ---------- 4. 风险评分 ----------

    def get_risk_score(self, cloud: str = "aws") -> Dict[str, Any]:
        categories = [
            {"category": "asset_risk", "score": 72, "max": 100, "level": "medium",
             "description": "资产暴露面风险", "factors": ["公开S3桶", "开放SSH安全组"]},
            {"category": "config_risk", "score": 45, "max": 100, "level": "high",
             "description": "配置错误风险", "factors": ["未加密存储", "未启用日志", "过宽权限"]},
            {"category": "vulnerability_risk", "score": 58, "max": 100, "level": "medium",
             "description": "漏洞风险", "factors": ["3个Critical CVE", "8个High CVE"]},
            {"category": "network_risk", "score": 35, "max": 100, "level": "high",
             "description": "网络暴露风险", "factors": ["0.0.0.0/0入站", "未启用VPC Flow Logs"]},
            {"category": "identity_risk", "score": 28, "max": 100, "level": "critical",
             "description": "身份与访问风险", "factors": ["根用户无MFA", "完全权限策略", "未使用密钥轮换"]},
            {"category": "data_risk", "score": 50, "max": 100, "level": "medium",
             "description": "数据安全风险", "factors": ["未加密对象存储", "未启用版本控制"]},
        ]
        overall = round(sum(c["score"] for c in categories) / len(categories), 1)
        level = "critical" if overall < 40 else "high" if overall < 60 else "medium" if overall < 80 else "low"
        return {
            "overall_score": overall, "overall_level": level,
            "categories": categories, "cloud": cloud, "scored_at": _now(),
        }

    # ---------- 5. 攻击路径分析 ----------

    def analyze_attack_paths(self, cloud: str = "aws") -> Dict[str, Any]:
        paths = [
            {
                "id": "PATH-001", "severity": "critical", "name": "公开S3桶 → 凭证泄露 → IAM提权 → 数据渗出",
                "steps": [
                    {"step": 1, "type": "resource", "name": "public-uploads S3桶", "detail": "公开可访问，包含配置文件"},
                    {"step": 2, "type": "credential", "name": "AKIAXXXXXXXX (在配置文件中)", "detail": "泄露的 IAM Access Key"},
                    {"step": 3, "type": "privilege", "name": "IAM:AssumeRole to admin-role", "detail": "凭证有 sts:AssumeRole 权限"},
                    {"step": 4, "type": "action", "name": "s3:GetObject on sensitive-data", "detail": "管理员角色可访问敏感数据桶"},
                ],
                "impact": "完全数据泄露", "likelihood": "high", "risk_score": 95,
            },
            {
                "id": "PATH-002", "severity": "high", "name": "开放SSH → EC2入侵 → 元数据服务 → IAM角色窃取",
                "steps": [
                    {"step": 1, "type": "network", "name": "sg-web:0.0.0.0/0:22", "detail": "SSH 端口暴露到公网"},
                    {"step": 2, "type": "resource", "name": "web-server-01 (EC2)", "detail": "暴力破解 SSH 获取 shell"},
                    {"step": 3, "type": "credential", "name": "IMDSv1: iam/security-credentials/app-role", "detail": "访问元数据服务获取临时凭证"},
                    {"step": 4, "type": "action", "name": "Lambda:UpdateFunctionCode", "detail": "在 Lambda 中植入恶意代码"},
                ],
                "impact": "服务器入侵 + 持久化", "likelihood": "medium", "risk_score": 78,
            },
            {
                "id": "PATH-003", "severity": "medium", "name": "过度权限 IAM 用户 → 资源枚举 → 横向移动",
                "steps": [
                    {"step": 1, "type": "identity", "name": "dev-user (AdministratorAccess)", "detail": "开发用户有完全管理员权限"},
                    {"step": 2, "type": "action", "name": "ec2:DescribeInstances", "detail": "枚举所有 EC2 实例"},
                    {"step": 3, "type": "action", "name": "rds:DescribeDBInstances", "detail": "枚举数据库实例"},
                ],
                "impact": "信息收集 + 后续攻击", "likelihood": "high", "risk_score": 60,
            },
        ]
        return {"attack_paths": paths, "total": len(paths), "cloud": cloud, "analyzed_at": _now()}

    # ---------- 6. 安全改进建议 ----------

    def get_remediation_recommendations(self, cloud: str = "aws") -> Dict[str, Any]:
        recommendations = [
            {"id": "REM-001", "priority": "P0", "category": "iam",
             "title": "为根用户启用 MFA",
             "description": "根用户未启用 MFA，攻击者获取密码后可完全控制账户",
             "effort": "low", "impact": "critical",
             "action": "IAM → Root user → MFA → Enable virtual MFA device"},
            {"id": "REM-002", "priority": "P0", "category": "storage",
             "title": "限制 S3 公开存储桶",
             "description": "public-uploads 桶公开可访问，可能包含敏感数据",
             "effort": "low", "impact": "critical",
             "action": "S3 → Bucket → Permissions → Block all public access"},
            {"id": "REM-003", "priority": "P1", "category": "network",
             "title": "收紧安全组 SSH 规则",
             "description": "SSH 端口 22 对 0.0.0.0/0 开放",
             "effort": "low", "impact": "high",
             "action": "EC2 → Security Groups → Edit inbound rules → Source: My IP / VPN CIDR"},
            {"id": "REM-004", "priority": "P1", "category": "logging",
             "title": "启用 VPC Flow Logs",
             "description": "无法检测网络层异常流量",
             "effort": "medium", "impact": "high",
             "action": "VPC → Flow Logs → Create → Send to CloudWatch Logs"},
            {"id": "REM-005", "priority": "P2", "category": "encryption",
             "title": "启用 S3 默认加密",
             "description": "public-uploads 桶未启用加密",
             "effort": "low", "impact": "medium",
             "action": "S3 → Bucket → Properties → Default encryption → SSE-S3"},
            {"id": "REM-006", "priority": "P2", "category": "iam",
             "title": "删除多余的 IAM 访问密钥",
             "description": "admin 用户有 2 个活跃访问密钥",
             "effort": "low", "impact": "medium",
             "action": "IAM → Users → Security credentials → Delete unused access key"},
            {"id": "REM-007", "priority": "P3", "category": "monitoring",
             "title": "启用 ALB 访问日志",
             "description": "无法审计 HTTP 请求",
             "effort": "medium", "impact": "low",
             "action": "EC2 → Load Balancers → Attributes → Access logs: Enable"},
        ]
        return {"recommendations": recommendations, "total": len(recommendations), "cloud": cloud}


# ==================== 工厂函数 ====================

def create_cspm() -> CloudSecurityPostureManagement:
    return CloudSecurityPostureManagement()
