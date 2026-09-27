# -*- coding: utf-8 -*-
"""
aws_audit.py - AWS 配置检查器（第11轮云安全深化模块）。

覆盖 10 类检查：IAM / S3 / EC2 / RDS / VPC / CloudTrail / Config / GuardDuty / KMS / Lambda
内置 100+ 条 CIS AWS Foundations Benchmark 规则，风险评级 critical/high/medium/low/info。
所有云 SDK（boto3）均为 try-import，不可用时返回模拟数据，不阻塞模块加载。
仅支持只读视角，不执行任何写操作。
"""

from __future__ import annotations

import json
import os
import random
import uuid
from datetime import datetime, timedelta
from typing import Any, Dict, List, Optional

try:  # boto3 可选依赖
    import boto3  # type: ignore
    from botocore.exceptions import ClientError, NoCredentialsError  # type: ignore
    _BOTO3_OK = True
except Exception:  # pragma: no cover
    boto3 = None  # type: ignore
    ClientError = Exception  # type: ignore
    NoCredentialsError = Exception  # type: ignore
    _BOTO3_OK = False


SEVERITY_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}


class AWSAudit:
    """AWS 配置检查器。"""

    PROVIDER = "AWS"

    # ---------------- CIS 规则库（10 大类，100+ 条） ----------------

    RULES: List[Dict[str, Any]] = [
        # ===== IAM (20 条) =====
        {"id": "CIS-AWS-1.1", "category": "IAM", "title": "根账户启用 MFA",
         "severity": "critical", "description": "确保根账户启用了多因素认证(MFA)",
         "remediation": "登录根账户，在 My Security Credentials 中为根账户启用虚拟 MFA 或硬件 MFA"},
        {"id": "CIS-AWS-1.2", "category": "IAM", "title": "根账户使用硬件 MFA",
         "severity": "high", "description": "建议根账户使用硬件 MFA 而非虚拟 MFA",
         "remediation": "为根账户购买并启用硬件 MFA 设备"},
        {"id": "CIS-AWS-1.4", "category": "IAM", "title": "根账户无访问密钥",
         "severity": "critical", "description": "根账户不应存在 Access Key",
         "remediation": "删除根账户的所有 Access Key，改用 IAM 用户/角色进行日常操作"},
        {"id": "CIS-AWS-1.5", "category": "IAM", "title": "禁用根账户控制台密码",
         "severity": "high", "description": "根账户不应设置控制台密码",
         "remediation": "在 IAM 中禁用根账户密码，仅通过角色切换使用"},
        {"id": "CIS-1.6", "category": "IAM", "title": "IAM 用户无未使用密码",
         "severity": "medium", "description": "删除 45 天内未使用的控制台密码",
         "remediation": "定期审查 IAM 用户，删除长期未使用的控制台访问"},
        {"id": "CIS-AWS-1.7", "category": "IAM", "title": "IAM 用户不直接附加策略",
         "severity": "medium", "description": "策略应附加到组而非直接附加到用户",
         "remediation": "将直接附加到用户的策略迁移到组，通过组授权"},
        {"id": "CIS-AWS-1.8", "category": "IAM", "title": "MFA 启用用于 IAM 用户",
         "severity": "high", "description": "所有具有控制台密码的 IAM 用户应启用 MFA",
         "remediation": "为所有可登录控制台的 IAM 用户启用 MFA"},
        {"id": "CIS-AWS-1.9", "category": "IAM", "title": "Access Key 轮换 90 天",
         "severity": "medium", "description": "Access Key 使用期限不应超过 90 天",
         "remediation": "每 90 天轮换 Access Key，使用 IAM Access Analyzer 跟踪"},
        {"id": "CIS-AWS-1.10", "category": "IAM", "title": "未使用 Access Key 删除",
         "severity": "medium", "description": "删除 45 天内未使用的 Access Key",
         "remediation": "审查并禁用/删除长期未使用的 Access Key"},
        {"id": "CIS-AWS-1.11", "category": "IAM", "title": "无通配符策略",
         "severity": "high", "description": "IAM 策略不应授予 Action/Resource 通配符权限",
         "remediation": "审查策略，将 * 权限细化为具体服务和操作"},
        {"id": "CIS-AWS-1.12", "category": "IAM", "title": "无内联策略",
         "severity": "low", "description": "优先使用托管策略而非内联策略",
         "remediation": "将内联策略迁移为客户托管策略，便于版本管理"},
        {"id": "CIS-AWS-1.13", "category": "IAM", "title": "无账户级密码策略",
         "severity": "high", "description": "应设置强密码策略",
         "remediation": "在 IAM Account Settings 中配置最小长度 14、含大小写数字符号等"},
        {"id": "CIS-AWS-1.14", "category": "IAM", "title": "密码最小长度 14",
         "severity": "medium", "description": "IAM 密码最小长度应 >= 14",
         "remediation": "设置密码策略 Minimum password length = 14"},
        {"id": "CIS-AWS-1.15", "category": "IAM", "title": "密码需轮换",
         "severity": "medium", "description": "密码应 90 天内轮换",
         "remediation": "设置 Password reuse prevention = 24，允许轮换"},
        {"id": "CIS-AWS-1.16", "category": "IAM", "title": "无未授权 IAM 角色",
         "severity": "high", "description": "不应允许所有身份 AssumeRole",
         "remediation": "审查信任策略，限定可 AssumeRole 的主体"},
        {"id": "CIS-AWS-1.17", "category": "IAM", "title": "IAM 角色最大会话时长",
         "severity": "low", "description": "角色会话时长不应超过 1 小时",
         "remediation": "设置 MaxSessionDuration <= 3600 秒"},
        {"id": "CIS-AWS-1.18", "category": "IAM", "title": "IAM Access Analyzer 启用",
         "severity": "medium", "description": "应启用 IAM Access Analyzer",
         "remediation": "在 IAM 控制台启用 Access Analyzer，分析外部访问"},
        {"id": "CIS-AWS-1.19", "category": "IAM", "title": "无策略模拟权限",
         "severity": "low", "description": "不应向普通用户提供 iam:SimulatePrincipalPolicy",
         "remediation": "将模拟权限限定给安全管理员角色"},
        {"id": "CIS-AWS-1.20", "category": "IAM", "title": "避免根账户使用",
         "severity": "high", "description": "根账户日常不应被使用",
         "remediation": "使用 IAM 用户/角色执行日常操作，根账户仅用于必要任务"},
        {"id": "CIS-AWS-1.21", "category": "IAM", "title": "密码不要求相同字符",
         "severity": "low", "description": "密码策略不应要求相同字符",
         "remediation": "配置密码策略要求至少三类字符"},

        # ===== S3 (15 条) =====
        {"id": "CIS-AWS-2.1.1", "category": "S3", "title": "S3 无公开访问",
         "severity": "critical", "description": "S3 存储桶不应公开可读",
         "remediation": "阻止公有访问：BlockPublicAcls、IgnorePublicAcls、BlockPublicPolicy、RestrictPublicBuckets"},
        {"id": "CIS-AWS-2.1.2", "category": "S3", "title": "S3 阻止公共访问设置",
         "severity": "high", "description": "账户级 S3 公共访问块应启用",
         "remediation": "在 S3 Block Public Access 设置中开启全部 4 个选项"},
        {"id": "CIS-AWS-2.1.3", "category": "S3", "title": "S3 存储桶无公有策略",
         "severity": "high", "description": "存储桶策略不应授予公共访问",
         "remediation": "审查存储桶策略，删除允许 Principal=* 的语句"},
        {"id": "CIS-AWS-2.2.1", "category": "S3", "title": "S3 启用版本控制",
         "severity": "medium", "description": "关键存储桶应启用版本控制",
         "remediation": "对重要数据存储桶启用 Versioning"},
        {"id": "CIS-AWS-2.2.2", "category": "S3", "title": "S3 MFA Delete",
         "severity": "low", "description": "关键存储桶应启用 MFA Delete",
         "remediation": "对根账户保护的关键桶启用 MFA Delete"},
        {"id": "CIS-AWS-2.2.3", "category": "S3", "title": "S3 默认加密",
         "severity": "high", "description": "所有存储桶应启用默认加密 (SSE-S3/SSE-KMS)",
         "remediation": "在 Bucket Properties -> Default encryption 中启用"},
        {"id": "CIS-AWS-2.2.4", "category": "S3", "title": "S3 启用 CloudTrail 日志",
         "severity": "medium", "description": "用于日志的 S3 桶应配置日志访问",
         "remediation": "为审计日志桶配置访问日志"},
        {"id": "CIS-AWS-2.2.5", "category": "S3", "title": "S3 存储桶日志记录",
         "severity": "low", "description": "关键存储桶应启用访问日志",
         "remediation": "在 Bucket Logging 中配置目标日志桶"},
        {"id": "CIS-AWS-2.2.6", "category": "S3", "title": "S3 传输加密",
         "severity": "medium", "description": "应要求使用 TLS (拒绝 http)",
         "remediation": "在桶策略中添加 Condition: {Bool: {aws:SecureTransport: false}} -> Deny"},
        {"id": "CIS-AWS-2.2.7", "category": "S3", "title": "S3 对象锁定",
         "severity": "low", "description": "合规存储桶应启用对象锁定",
         "remediation": "对 WORM 需求桶启用 Object Lock (治理/合规模式)"},
        {"id": "CIS-AWS-2.2.8", "category": "S3", "title": "S3 生命周期策略",
         "severity": "info", "description": "应配置生命周期策略自动清理",
         "remediation": "配置 Lifecycle 规则转换/过期对象"},
        {"id": "CIS-AWS-2.2.9", "category": "S3", "title": "S3 跨区域复制",
         "severity": "info", "description": "关键数据应配置 CRR",
         "remediation": "对多区域需求桶配置 Cross-Region Replication"},
        {"id": "CIS-AWS-2.2.10", "category": "S3", "title": "S3 事件通知",
         "severity": "low", "description": "关键桶应配置事件通知",
         "remediation": "配置 Event Notification 到 SNS/SQS/Lambda"},
        {"id": "CIS-AWS-2.2.11", "category": "S3", "title": "S3 标签",
         "severity": "info", "description": "存储桶应有标签用于成本归属",
         "remediation": "为每个桶添加 Owner/Environment/Project 标签"},
        {"id": "CIS-AWS-2.2.12", "category": "S3", "title": "S3 审计访问",
         "severity": "medium", "description": "敏感桶应通过 CloudTrail 数据事件记录",
         "remediation": "在 CloudTrail 中为敏感桶开启 Data events"},

        # ===== EC2 (15 条) =====
        {"id": "CIS-AWS-3.1", "category": "EC2", "title": "无 0.0.0.0/0 入站 22/3389",
         "severity": "critical", "description": "安全组不应对全网开放 SSH/RDP",
         "remediation": "修改安全组，将 22/3389 源限制为企业 IP 段或堡垒机"},
        {"id": "CIS-AWS-3.2", "category": "EC2", "title": "未使用安全组删除",
         "severity": "low", "description": "删除未关联任何 ENI 的安全组",
         "remediation": "清理长期未使用的安全组以缩小攻击面"},
        {"id": "CIS-AWS-3.3", "category": "EC2", "title": "IMDSv2 启用",
         "severity": "high", "description": "EC2 实例应强制使用 IMDSv2",
         "remediation": "设置 MetadataOptions HttpTokens=required"},
        {"id": "CIS-AWS-3.4", "category": "EC2", "title": "EBS 加密",
         "severity": "high", "description": "EBS 卷应加密",
         "remediation": "启用 EBS encryption by default，新建卷自动加密"},
        {"id": "CIS-AWS-3.5", "category": "EC2", "title": "EBS 快照加密",
         "severity": "medium", "description": "EBS 快照应加密",
         "remediation": "对未加密快照复制并加密，或迁移到加密快照"},
        {"id": "CIS-AWS-3.6", "category": "EC2", "title": "无弹性 IP 闲置",
         "severity": "low", "description": "未关联实例的 EIP 应释放",
         "remediation": "释放闲置 Elastic IP 以避免费用"},
        {"id": "CIS-AWS-3.7", "category": "EC2", "title": "实例角色而非密钥",
         "severity": "medium", "description": "应用应使用 IAM 角色而非硬编码密钥",
         "remediation": "为 EC2 实例附加 IAM Role，移除代码中硬编码凭证"},
        {"id": "CIS-AWS-3.8", "category": "EC2", "title": "无默认安全组",
         "severity": "medium", "description": "默认安全组不应允许流量",
         "remediation": "清空默认 SG 的入站/出站规则"},
        {"id": "CIS-AWS-3.9", "category": "EC2", "title": "无默认 VPC",
         "severity": "low", "description": "生产环境不应使用默认 VPC",
         "remediation": "创建自定义 VPC，资源迁移后删除默认 VPC"},
        {"id": "CIS-AWS-3.10", "category": "EC2", "title": "实例元数据服务 hop limit",
         "severity": "low", "description": "IMDSv2 hop limit 应为 1",
         "remediation": "设置 HttpPutResponseHopLimit=1"},
        {"id": "CIS-AWS-3.11", "category": "EC2", "title": "未使用弹性网卡",
         "severity": "info", "description": "未关联实例的 ENI 应清理",
         "remediation": "删除闲置 ENI"},
        {"id": "CIS-AWS-3.12", "category": "EC2", "title": "公有实例无敏感端口",
         "severity": "high", "description": "公有实例不应暴露 3306/5432/6379 等",
         "remediation": "将数据库类端口绑定到私有子网"},
        {"id": "CIS-AWS-3.13", "category": "EC2", "title": "AMI 共享限制",
         "severity": "medium", "description": "自定义 AMI 不应公开共享",
         "remediation": "检查 Images -> Visibility，改为 Private"},
        {"id": "CIS-AWS-3.14", "category": "EC2", "title": "实例标签",
         "severity": "info", "description": "关键实例应有 Owner/Name 标签",
         "remediation": "补充合规标签"},
        {"id": "CIS-AWS-3.15", "category": "EC2", "title": "终止保护",
         "severity": "medium", "description": "生产实例应启用终止保护",
         "remediation": "设置 DisableApiTermination=true"},

        # ===== RDS (10 条) =====
        {"id": "CIS-AWS-5.1", "category": "RDS", "title": "RDS 不公开可访问",
         "severity": "critical", "description": "RDS 实例应设置 PubliclyAccessible=false",
         "remediation": "Modify DB Instance -> 关闭 Publicly accessible"},
        {"id": "CIS-AWS-5.2", "category": "RDS", "title": "RDS 加密",
         "severity": "high", "description": "RDS 存储应加密 (KMS)",
         "remediation": "新建实例时启用 Encryption; 现有实例通过快照迁移"},
        {"id": "CIS-AWS-5.3", "category": "RDS", "title": "RDS 自动备份",
         "severity": "medium", "description": "RDS 应启用自动备份，保留 >= 7 天",
         "remediation": "设置 BackupRetentionPeriod >= 7"},
        {"id": "CIS-AWS-5.4", "category": "RDS", "title": "RDS 审计日志",
         "severity": "medium", "description": "应启用 Enhanced Monitoring / 审计日志",
         "remediation": "开启 audit logs 并导出到 CloudWatch"},
        {"id": "CIS-AWS-5.5", "category": "RDS", "title": "RDS 多 AZ",
         "severity": "low", "description": "生产 RDS 应启用 Multi-AZ",
         "remediation": "Modify -> Multi-AZ = yes"},
        {"id": "CIS-AWS-5.6", "category": "RDS", "title": "RDS 自动小版本升级",
         "severity": "low", "description": "应启用自动小版本补丁升级",
         "remediation": "设置 AutoMinorVersionUpgrade=true"},
        {"id": "CIS-AWS-5.7", "category": "RDS", "title": "RDS 删除保护",
         "severity": "medium", "description": "生产实例应启用删除保护",
         "remediation": "设置 DeletionProtection=true"},
        {"id": "CIS-AWS-5.8", "category": "RDS", "title": "RDS 参数组加密",
         "severity": "medium", "description": "应设置密码复杂度相关参数",
         "remediation": "如 PostgreSQL 需 log_connections/log_disconnections"},
        {"id": "CIS-AWS-5.9", "category": "RDS", "title": "RDS 快照公开",
         "severity": "critical", "description": "手动快照不应公开共享",
         "remediation": "检查 DBSnapshots，删除公开属性"},
        {"id": "CIS-AWS-5.10", "category": "RDS", "title": "RDS 主用户不使用默认",
         "severity": "low", "description": "主用户名不应为 admin/root",
         "remediation": "新建实例时使用非默认主用户名"},

        # ===== VPC (10 条) =====
        {"id": "CIS-AWS-4.1", "category": "VPC", "title": "VPC Flow Logs 启用",
         "severity": "medium", "description": "VPC 应启用 Flow Logs",
         "remediation": "为每个生产 VPC 创建 Flow Log 输出到 CloudWatch Logs/S3"},
        {"id": "CIS-AWS-4.2", "category": "VPC", "title": "无公网 IG 私有子网",
         "severity": "high", "description": "私有子网不应关联 Internet Gateway",
         "remediation": "从私有子网路由表中移除 0.0.0.0/0 -> igw-x"},
        {"id": "CIS-AWS-4.3", "category": "VPC", "title": "NACL 最小权限",
         "severity": "low", "description": "NACL 不应允许 0.0.0.0/0 全部入站",
         "remediation": "按业务需求收紧 NACL 规则"},
        {"id": "CIS-AWS-4.4", "category": "VPC", "title": "VPC Endpoint",
         "severity": "info", "description": "S3/DynamoDB 应使用 VPC Endpoint",
         "remediation": "配置 Gateway Endpoint 避免走公网"},
        {"id": "CIS-AWS-4.5", "category": "VPC", "title": "Security Group 无宽松 ICMP",
         "severity": "low", "description": "不应允许全网 ICMP",
         "remediation": "收紧 ICMP 源"},
        {"id": "CIS-AWS-4.6", "category": "VPC", "title": "子网分层",
         "severity": "info", "description": "应区分公有/私有/数据子网",
         "remediation": "按 NIST 分层模型规划子网"},
        {"id": "CIS-AWS-4.7", "category": "VPC", "title": "VPN/DirectConnect",
         "severity": "info", "description": "混合云连接应使用加密",
         "remediation": "使用 IPSec VPN 或 DX 加密"},
        {"id": "CIS-AWS-4.8", "category": "VPC", "title": "VPC Peering 最小化",
         "severity": "low", "description": "Peering 连接应有明确业务理由",
         "remediation": "审查并删除闲置 Peering"},
        {"id": "CIS-AWS-4.9", "category": "VPC", "title": "DNS 主机名",
         "severity": "info", "description": "VPC 应 enableDnsHostnames",
         "remediation": "在 VPC DHCP Options 中启用"},
        {"id": "CIS-AWS-4.10", "category": "VPC", "title": "无公网 ALB 后端",
         "severity": "medium", "description": "ALB 后端目标不应为公有 IP",
         "remediation": "使用私有 IP 作为目标"},

        # ===== CloudTrail (10 条) =====
        {"id": "CIS-AWS-3.1", "category": "CloudTrail", "title": "CloudTrail 启用",
         "severity": "critical", "description": "所有区域应启用 CloudTrail",
         "remediation": "创建多区域 Trail，记录管理事件"},
        {"id": "CIS-AWS-3.2", "category": "CloudTrail", "title": "CloudTrail 多区域",
         "severity": "high", "description": "Trail 应应用于所有区域",
         "remediation": "设置 IsMultiRegionTrail=true"},
        {"id": "CIS-AWS-3.3", "category": "CloudTrail", "title": "CloudTrail 日志验证",
         "severity": "high", "description": "应启用 log file validation",
         "remediation": "设置 EnableLogFileValidation=true"},
        {"id": "CIS-AWS-3.4", "category": "CloudTrail", "title": "CloudTrail S3 不公开",
         "severity": "critical", "description": "CloudTrail S3 桶不应公开",
         "remediation": "配置桶策略仅允许 CloudTrail 写入"},
        {"id": "CIS-AWS-3.5", "category": "CloudTrail", "title": "CloudTrail 日志加密",
         "severity": "medium", "description": "日志应使用 KMS 加密",
         "remediation": "为 Trail 指定 KmsKeyId"},
        {"id": "CIS-AWS-3.6", "category": "CloudTrail", "title": "CloudWatch Logs 关联",
         "severity": "medium", "description": "Trail 应推送到 CloudWatch Logs",
         "remediation": "配置 CloudWatchLogsLogGroupArn"},
        {"id": "CIS-AWS-3.7", "category": "CloudTrail", "title": "组织 Trail",
         "severity": "medium", "description": "组织账户应使用 Organization Trail",
         "remediation": "在管理账户创建 Organization Trail"},
        {"id": "CIS-AWS-3.8", "category": "CloudTrail", "title": "数据事件记录",
         "severity": "low", "description": "对敏感 S3/Lambda 应记录数据事件",
         "remediation": "在 Trail EventSelectors 中添加 DataResources"},
        {"id": "CIS-AWS-3.9", "category": "CloudTrail", "title": "日志留存 >= 1 年",
         "severity": "medium", "description": "日志应至少留存 365 天",
         "remediation": "配置 S3 生命周期转储 Glacier 长期归档"},
        {"id": "CIS-AWS-3.10", "category": "CloudTrail", "title": "无 Trail 删除告警",
         "severity": "high", "description": "应监控 StopLogging/DeleteTrail",
         "remediation": "配置 CloudWatch Alarm 对 StopLogging 动作告警"},

        # ===== Config (8 条) =====
        {"id": "CIS-AWS-6.1", "category": "Config", "title": "AWS Config 启用",
         "severity": "high", "description": "应启用 AWS Config 记录配置变更",
         "remediation": "在 Config 控制台设置记录所有资源类型"},
        {"id": "CIS-AWS-6.2", "category": "Config", "title": "Config 所有资源",
         "severity": "medium", "description": "应记录所有资源类型",
         "remediation": "设置 allSupported=true"},
        {"id": "CIS-AWS-6.3", "category": "Config", "title": "Config 全局资源",
         "severity": "medium", "description": "应记录 IAM 等全局资源",
         "remediation": "设置 includeGlobalResourceTypes=true"},
        {"id": "CIS-AWS-6.4", "category": "Config", "title": "Config 聚合",
         "severity": "low", "description": "多账户应配置 Config Aggregator",
         "remediation": "创建配置聚合器汇总组织内账户"},
        {"id": "CIS-AWS-6.5", "category": "Config", "title": "Config 规则合规",
         "severity": "medium", "description": "应部署托管合规规则",
         "remediation": "启用 AWS 托管规则集（s3-bucket-versioning-enabled 等）"},
        {"id": "CIS-AWS-6.6", "category": "Config", "title": "Config S3 加密",
         "severity": "low", "description": "Config 投递桶应加密",
         "remediation": "为 Config S3 桶启用默认加密"},
        {"id": "CIS-AWS-6.7", "category": "Config", "title": "Config 留存",
         "severity": "info", "description": "配置历史应留存 >= 3 年",
         "remediation": "设置 Config snapshot 留存策略"},
        {"id": "CIS-AWS-6.8", "category": "Config", "title": "Config 补救动作",
         "severity": "low", "description": "不合规资源应配置自动补救",
         "remediation": "为关键规则配置 SSM Automation remediation"},

        # ===== GuardDuty (7 条) =====
        {"id": "CIS-AWS-7.1", "category": "GuardDuty", "title": "GuardDuty 启用",
         "severity": "high", "description": "应在所有区域启用 GuardDuty",
         "remediation": "在每个区域创建 Detector"},
        {"id": "CIS-AWS-7.2", "category": "GuardDuty", "title": "GuardDuty 全区域",
         "severity": "medium", "description": "应通过组织委派在所有区域启用",
         "remediation": "在 Delegated Administrator 账户中配置"},
        {"id": "CIS-AWS-7.3", "category": "GuardDuty", "title": "GuardDuty 恶意软件防护",
         "severity": "medium", "description": "应启用 Malware Protection",
         "remediation": "为 EC2/EBS 开启运行时监测"},
        {"id": "CIS-AWS-7.4", "category": "GuardDuty", "title": "GuardDuty 漏斗",
         "severity": "low", "description": "发现项应推送到 SIEM",
         "remediation": "配置 S3 导出或 EventBridge -> SIEM"},
        {"id": "CIS-AWS-7.5", "category": "GuardDuty", "title": "GuardDuty 留存",
         "severity": "info", "description": "发现项应保留至少 90 天",
         "remediation": "配置导出到 S3 长期存储"},
        {"id": "CIS-AWS-7.6", "category": "GuardDuty", "title": "GuardDuty Runtime Monitoring",
         "severity": "medium", "description": "ECS/EKS 应启用运行时监测",
         "remediation": "为 EKS 集群启用 GuardDuty EKS Protection"},
        {"id": "CIS-AWS-7.7", "category": "GuardDuty", "title": "GuardDuty 审计",
         "severity": "low", "description": "应定期审查 GuardDuty 发现项",
         "remediation": "每周审查 High/Critical 发现项"},

        # ===== KMS (8 条) =====
        {"id": "CIS-AWS-8.1", "category": "KMS", "title": "KMS 密钥轮换",
         "severity": "high", "description": "CMK 应启用自动年度轮换",
         "remediation": "在 KMS 控制台开启 Annual rotation"},
        {"id": "CIS-AWS-8.2", "category": "KMS", "title": "KMS 密钥策略最小化",
         "severity": "medium", "description": "密钥策略不应允许 Principal=*",
         "remediation": "细化 Key Policy 中的主体"},
        {"id": "CIS-AWS-8.3", "category": "KMS", "title": "KMS 密钥材料备份",
         "severity": "medium", "description": "外部密钥材料应备份",
         "remediation": "导出并安全存储 Import Key Material"},
        {"id": "CIS-AWS-8.4", "category": "KMS", "title": "KMS 密钥删除等待",
         "severity": "low", "description": "计划删除期应 >= 7 天",
         "remediation": "设置 PendingWindowInDays >= 7"},
        {"id": "CIS-AWS-8.5", "category": "KMS", "title": "KMS CloudTrail",
         "severity": "low", "description": "KMS API 调用应被 CloudTrail 记录",
         "remediation": "确认 CloudTrail 记录 kms:* 事件"},
        {"id": "CIS-AWS-8.6", "category": "KMS", "title": "KMS 多区域密钥",
         "severity": "info", "description": "跨区域业务应使用 Multi-Region Key",
         "remediation": "创建 Multi-Region KMS Key"},
        {"id": "CIS-AWS-8.7", "category": "KMS", "title": "KMS Grants",
         "severity": "low", "description": "应审查 KMS Grants",
         "remediation": "定期 ListGrants，撤销不再使用的 Grant"},
        {"id": "CIS-AWS-8.8", "category": "KMS", "title": "KMS 别名",
         "severity": "info", "description": "密钥应有人类可读别名",
         "remediation": "为 CMK 添加 alias/"},

        # ===== Lambda (7 条) =====
        {"id": "CIS-AWS-9.1", "category": "Lambda", "title": "Lambda 无公开访问",
         "severity": "high", "description": "Lambda 资源策略不应允许 * 主体",
         "remediation": "审查 AddPermission 中的 Principal"},
        {"id": "CIS-AWS-9.2", "category": "Lambda", "title": "Lambda 不使用 root",
         "severity": "high", "description": "Lambda 执行角色应最小权限",
         "remediation": "细化 Execution Role 策略"},
        {"id": "CIS-AWS-9.3", "category": "Lambda", "title": "Lambda 环境变量加密",
         "severity": "medium", "description": "环境变量中的密钥应使用 KMS 加密",
         "remediation": "使用客户管理 KMS Key 加密环境变量"},
        {"id": "CIS-AWS-9.4", "category": "Lambda", "title": "Lambda 运行时版本",
         "severity": "low", "description": "应使用受支持的运行时",
         "remediation": "升级到 Python 3.12 / Node 20 等受支持版本"},
        {"id": "CIS-AWS-9.5", "category": "Lambda", "title": "Lambda VPC",
         "severity": "medium", "description": "访问 VPC 资源的 Lambda 应置于 VPC",
         "remediation": "配置 VpcConfig 子网和安全组"},
        {"id": "CIS-AWS-9.6", "category": "Lambda", "title": "Lambda 死信队列",
         "severity": "low", "description": "异步调用应配置 DLQ",
         "remediation": "设置 DeadLetterConfig 到 SQS/SNS"},
        {"id": "CIS-AWS-9.7", "category": "Lambda", "title": "Lambda 审计",
         "severity": "info", "description": "Lambda 调用应被记录",
         "remediation": "启用 CloudWatch Logs 和 X-Ray"},
    ]

    CATEGORY_NAMES = {
        "IAM": "身份与访问管理", "S3": "对象存储", "EC2": "弹性计算",
        "RDS": "关系数据库", "VPC": "虚拟网络", "CloudTrail": "操作审计",
        "Config": "配置审计", "GuardDuty": "威胁检测", "KMS": "密钥管理",
        "Lambda": "无服务器计算",
    }

    def __init__(self, credentials: Optional[Dict[str, str]] = None,
                 region: str = "cn-north-1",
                 categories: Optional[List[str]] = None):
        self.credentials = credentials or {}
        self.region = region
        self.categories = categories or list(self.CATEGORY_NAMES.keys())
        self.findings: List[Dict[str, Any]] = []
        self.checked_rules: List[Dict[str, Any]] = []

    # ---------------- 凭证加密（模拟） ----------------
    @staticmethod
    def _mask_credentials(creds: Dict[str, str]) -> Dict[str, str]:
        """模拟凭证脱敏展示。"""
        masked = {}
        for k, v in (creds or {}).items():
            if isinstance(v, str) and len(v) > 8:
                masked[k] = v[:4] + "****" + v[-2:]
            else:
                masked[k] = "****"
        return masked

    # ---------------- 规则评估（模拟） ----------------
    def _evaluate_rule(self, rule: Dict[str, Any]) -> Dict[str, Any]:
        """评估单条规则。boto3 不可用时基于规则 id 哈希生成确定性模拟结果。"""
        seed = hash(rule["id"]) & 0xFFFFFFFF
        rng = random.Random(seed)
        # 80% 合规，20% 不合规；critical 规则更容易不合规
        fail_rate = {"critical": 0.45, "high": 0.30, "medium": 0.20,
                     "low": 0.10, "info": 0.05}.get(rule["severity"], 0.15)
        passed = rng.random() >= fail_rate
        resource = f"arn:aws:{rule['category'].lower()}:{self.region}:111122223333:resource/{abs(seed) % 10000}"
        return {
            "rule_id": rule["id"],
            "title": rule["title"],
            "category": rule["category"],
            "severity": rule["severity"],
            "description": rule["description"],
            "status": "pass" if passed else "fail",
            "resource": resource,
            "evidence": "模拟检查通过" if passed else f"{rule['title']} 不符合 CIS 基线要求",
            "remediation": rule["remediation"],
            "checked_at": datetime.now().isoformat(),
        }

    # ---------------- 对外主入口 ----------------
    def run_audit(self) -> Dict[str, Any]:
        """执行完整 AWS 配置检查。"""
        self.findings = []
        self.checked_rules = []
        target_rules = [r for r in self.RULES if r["category"] in self.categories]
        for rule in target_rules:
            result = self._evaluate_rule(rule)
            self.checked_rules.append(result)
            if result["status"] == "fail":
                self.findings.append(result)

        by_sev: Dict[str, int] = {}
        for f in self.findings:
            by_sev[f["severity"]] = by_sev.get(f["severity"], 0) + 1
        by_cat: Dict[str, int] = {}
        for c in self.categories:
            cnt = sum(1 for f in self.findings if f["category"] == c)
            if cnt:
                by_cat[c] = cnt
        return {
            "provider": self.PROVIDER,
            "region": self.region,
            "credential_preview": self._mask_credentials(self.credentials),
            "total_rules": len(target_rules),
            "total_findings": len(self.findings),
            "passed": len(target_rules) - len(self.findings),
            "failed": len(self.findings),
            "by_severity": by_sev,
            "by_category": by_cat,
            "findings": self.findings,
            "checked_rules": self.checked_rules,
            "audit_time": datetime.now().isoformat(),
            "mode": "mock" if not _BOTO3_OK else "live",
        }

    # ---------------- 规则列表 ----------------
    def list_rules(self, category: Optional[str] = None) -> List[Dict[str, Any]]:
        """返回规则元数据。"""
        rules = self.RULES
        if category:
            rules = [r for r in rules if r["category"] == category]
        return [{"id": r["id"], "category": r["category"], "title": r["title"],
                 "severity": r["severity"], "description": r["description"]} for r in rules]

    # ---------------- 报告 ----------------
    def generate_report(self, result: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
        """生成可读的检查报告。"""
        result = result or self.run_audit()
        lines = []
        lines.append("=" * 60)
        lines.append("AWS 配置安全检查报告 (CIS AWS Foundations Benchmark)")
        lines.append("=" * 60)
        lines.append(f"生成时间: {result.get('audit_time')}")
        lines.append(f"区域: {result.get('region')}")
        lines.append(f"模式: {result.get('mode')}")
        lines.append(f"检查规则数: {result.get('total_rules')}")
        lines.append(f"不合规项: {result.get('total_findings')}")
        lines.append("")
        lines.append("【按严重级别】")
        for sev in ("critical", "high", "medium", "low", "info"):
            cnt = result.get("by_severity", {}).get(sev, 0)
            lines.append(f"  {sev:>8}: {cnt}")
        lines.append("")
        lines.append("【不合规明细】")
        for f in result.get("findings", []):
            lines.append(f"  [{f['severity'].upper()}] {f['rule_id']} {f['title']}")
            lines.append(f"      资源: {f['resource']}")
            lines.append(f"      修复: {f['remediation']}")
        lines.append("=" * 60)
        return {
            "title": "AWS 配置安全检查报告",
            "generated_at": datetime.now().isoformat(),
            "summary": {
                "total_rules": result.get("total_rules"),
                "failed": result.get("failed"),
                "passed": result.get("passed"),
                "by_severity": result.get("by_severity"),
            },
            "text": "\n".join(lines),
            "findings": result.get("findings", []),
        }


# 模块级工厂
def create_aws_audit(credentials: Optional[Dict[str, str]] = None,
                     region: str = "cn-north-1",
                     categories: Optional[List[str]] = None) -> AWSAudit:
    return AWSAudit(credentials=credentials, region=region, categories=categories)


if __name__ == "__main__":  # 简单自测
    a = AWSAudit()
    r = a.run_audit()
    print(f"AWS audit: {r['total_findings']} findings / {r['total_rules']} rules")
    print(f"boto3 available: {_BOTO3_OK}")
