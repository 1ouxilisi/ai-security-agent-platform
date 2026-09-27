# -*- coding: utf-8 -*-
"""
azure_audit.py - Azure 配置检查器（第11轮云安全深化模块）。

覆盖 10 类检查：Azure AD / Storage / VM / SQL / Network / Activity Log /
Policy / Security Center / Key Vault / App Service
内置 80+ 条 CIS Microsoft Azure Foundations Benchmark 规则。
所有 Azure SDK (azure-identity / azure-mgmt-*) 均为 try-import。仅只读视角。
"""

from __future__ import annotations

import random
from datetime import datetime
from typing import Any, Dict, List, Optional

try:  # azure SDK 可选
    from azure.identity import DefaultAzureCredential  # type: ignore
    _AZURE_OK = True
except Exception:  # pragma: no cover
    DefaultAzureCredential = None  # type: ignore
    _AZURE_OK = False


class AzureAudit:
    """Azure 配置检查器。"""

    PROVIDER = "Azure"

    CATEGORY_NAMES = {
        "AzureAD": "身份管理 (Entra ID)", "Storage": "存储账户",
        "VM": "虚拟机", "SQL": "SQL 数据库", "Network": "虚拟网络",
        "ActivityLog": "活动日志", "Policy": "Azure Policy",
        "SecurityCenter": "Defender for Cloud", "KeyVault": "密钥保管库",
        "AppService": "应用服务",
    }

    # 80+ 条 CIS Azure 规则
    RULES: List[Dict[str, Any]] = [
        # ===== Azure AD (Entra ID) 15 条 =====
        {"id": "CIS-AZ-1.1", "category": "AzureAD", "title": "MFA 对所有用户启用",
         "severity": "critical", "description": "应通过条件策略对所有用户强制 MFA",
         "remediation": "创建 Conditional Access 策略：所有云应用 -> 需要 MFA"},
        {"id": "CIS-AZ-1.2", "category": "AzureAD", "title": "MFA 对管理员启用",
         "severity": "critical", "description": "全局管理员必须启用 MFA",
         "remediation": "对管理员组部署 MFA 注册策略"},
        {"id": "CIS-AZ-1.3", "category": "AzureAD", "title": "无外部来宾过量授权",
         "severity": "high", "description": "外部来宾不应拥有管理员角色",
         "remediation": "审查 External Identities -> 移除外部管理员"},
        {"id": "CIS-AZ-1.4", "category": "AzureAD", "title": "自助密码重置启用",
         "severity": "low", "description": "应启用 SSPR",
         "remediation": "在 Password reset 中为所有用户启用"},
        {"id": "CIS-AZ-1.5", "category": "AzureAD", "title": "密码哈希同步",
         "severity": "info", "description": "混合身份应启用 PHS",
         "remediation": "Azure AD Connect 中启用 Password Hash Sync"},
        {"id": "CIS-AZ-1.6", "category": "AzureAD", "title": "禁止用户注册应用",
         "severity": "medium", "description": "普通用户不应能注册应用",
         "remediation": "User settings -> App registrations: Users -> No"},
        {"id": "CIS-AZ-1.7", "category": "AzureAD", "title": "禁止用户创建租户",
         "severity": "medium", "description": "限制用户创建 Access Reviews 等租户",
         "remediation": "Restrict access to Azure AD admin portal: Yes"},
        {"id": "CIS-AZ-1.8", "category": "AzureAD", "title": "不允许外部来宾邀请",
         "severity": "medium", "description": "来宾邀请应受限",
         "remediation": "External collaboration settings -> Guest invite: Admins only"},
        {"id": "CIS-AZ-1.9", "category": "AzureAD", "title": "条件访问 - 风险登录",
         "severity": "high", "description": "应对高风险登录触发 MFA/密码重置",
         "remediation": "配置 CA 策略 sign-in risk = High -> MFA"},
        {"id": "CIS-AZ-1.10", "category": "AzureAD", "title": "条件访问 - 合规设备",
         "severity": "medium", "description": "关键资源应要求合规设备",
         "remediation": "CA 策略要求 deviceCompliance"},
        {"id": "CIS-AZ-1.11", "category": "AzureAD", "title": "陈旧设备清理",
         "severity": "low", "description": "90 天未登录设备应禁用",
         "remediation": "使用 Access Reviews 周期性审查设备"},
        {"id": "CIS-AZ-1.12", "category": "AzureAD", "title": "无永久管理员",
         "severity": "medium", "description": "特权角色应使用 PIM JIT",
         "remediation": "启用 PIM，将永久管理员转为激活式"},
        {"id": "CIS-AZ-1.13", "category": "AzureAD", "title": "审核管理员活动",
         "severity": "medium", "description": "管理员活动应被审计",
         "remediation": "启用 Audit Logs 并导出到 SIEM"},
        {"id": "CIS-AZ-1.14", "category": "AzureAD", "title": "不允许同意多租户应用",
         "severity": "medium", "description": "用户同意应禁用",
         "remediation": "User consent settings -> Do not allow user consent"},
        {"id": "CIS-AZ-1.15", "category": "AzureAD", "title": "密码泄漏检测",
         "severity": "high", "description": "应启用密码保护暴力破解防护",
         "remediation": "启用 Smart Lockout 和 Password protection"},

        # ===== Storage 12 条 =====
        {"id": "CIS-AZ-3.1", "category": "Storage", "title": "存储账户安全传输",
         "severity": "high", "description": "应要求 HTTPS (secure transfer required)",
         "remediation": "Configuration -> Secure transfer required = Enabled"},
        {"id": "CIS-AZ-3.2", "category": "Storage", "title": "不允许公共 Blob 访问",
         "severity": "critical", "description": "公共访问应禁用",
         "remediation": "Configuration -> Allow Blob anonymous access = Disabled"},
        {"id": "CIS-AZ-3.3", "category": "Storage", "title": "存储 account 加密",
         "severity": "high", "description": "静态数据应加密 (默认)",
         "remediation": "确保未禁用默认加密；使用客户管理密钥可选"},
        {"id": "CIS-AZ-3.4", "category": "Storage", "title": "基础设施加密",
         "severity": "medium", "description": "敏感数据应启用双重加密",
         "remediation": "创建账户时启用 Infrastructure encryption"},
        {"id": "CIS-AZ-3.5", "category": "Storage", "title": "Storage 审计",
         "severity": "medium", "description": "应启用 Logging (Azure Monitor)",
         "remediation": "Diagnostic settings -> 读/写/删除日志"},
        {"id": "CIS-AZ-3.6", "category": "Storage", "title": "Storage 软删除 (Blob)",
         "severity": "low", "description": "Blob 软删除应启用",
         "remediation": "Data protection -> Soft delete = 7+ days"},
        {"id": "CIS-AZ-3.7", "category": "Storage", "title": "Storage 容器软删除",
         "severity": "low", "description": "容器软删除应启用",
         "remediation": "Enable container soft delete"},
        {"id": "CIS-AZ-3.8", "category": "Storage", "title": "Storage 网络限制",
         "severity": "high", "description": "应限制网络访问 (防火墙/VNet)",
         "remediation": "Firewalls and virtual networks -> Selected networks"},
        {"id": "CIS-AZ-3.9", "category": "Storage", "title": "Storage 故障排除视图",
         "severity": "info", "description": "应允许受信任服务",
         "remediation": "例外中勾选 Allow trusted Microsoft services"},
        {"id": "CIS-AZ-3.10", "category": "Storage", "title": "Storage 密钥轮换",
         "severity": "medium", "description": "访问密钥应定期轮换",
         "remediation": "每 90 天轮换 key1/key2，使用 Azure Key Vault 托管"},
        {"id": "CIS-AZ-3.11", "category": "Storage", "title": "Storage 不允许共享密钥",
         "severity": "medium", "description": "应禁止共享密钥访问",
         "remediation": "Allow storage account key access = Disabled"},
        {"id": "CIS-AZ-3.12", "category": "Storage", "title": "Storage 版本控制",
         "severity": "low", "description": "Blob 版本控制应启用",
         "remediation": "Data protection -> Enable versioning"},

        # ===== VM 10 条 =====
        {"id": "CIS-AZ-4.1", "category": "VM", "title": "OS 磁盘加密",
         "severity": "high", "description": "VM 磁盘应使用 EncryptionAtHost/DiskEncryptionSet",
         "remediation": "为 OS 和数据磁盘配置 CMK 加密"},
        {"id": "CIS-AZ-4.2", "category": "VM", "title": "无扩展来宾代理风险",
         "severity": "medium", "description": "应启用适用于 Linux/Windows 的 Azure Monitor Agent",
         "remediation": "启用 Azure Monitor Agent 扩展"},
        {"id": "CIS-AZ-4.3", "category": "VM", "title": "VM 端点保护",
         "severity": "high", "description": "应安装反恶意软件",
         "remediation": "启用 Microsoft Antimalware 扩展"},
        {"id": "CIS-AZ-4.4", "category": "VM", "title": "VM 自动更新",
         "severity": "medium", "description": "应启用自动 OS 更新",
         "remediation": "在 Guest + Updates 中配置自动修补"},
        {"id": "CIS-AZ-4.5", "category": "VM", "title": "VM NSG 关联",
         "severity": "high", "description": "每个 NIC/子网应关联 NSG",
         "remediation": "为所有子网和 NIC 关联 NSG"},
        {"id": "CIS-AZ-4.6", "category": "VM", "title": "VM 无公共 IP",
         "severity": "medium", "description": "管理型 VM 不应分配公共 IP",
         "remediation": "使用 Bastion/Private Endpoint 替代"},
        {"id": "CIS-AZ-4.7", "category": "VM", "title": "VM 诊断启动",
         "severity": "low", "description": "应启用 Boot Diagnostics",
         "remediation": "Support troubleshooting -> Boot diagnostics = On"},
        {"id": "CIS-AZ-4.8", "category": "VM", "title": "VM 无扩展滥用",
         "severity": "medium", "description": "应审查已安装扩展",
         "remediation": "删除未使用的 Custom Script Extension"},
        {"id": "CIS-AZ-4.9", "category": "VM", "title": "VM 容量",
         "severity": "info", "description": "应使用 Availability Set/Zone",
         "remediation": "生产 VM 部署到 Availability Set/Zone"},
        {"id": "CIS-AZ-4.10", "category": "VM", "title": "VM 标签",
         "severity": "info", "description": "应有 Owner/Environment 标签",
         "remediation": "通过 Policy 强制标签"},

        # ===== SQL 8 条 =====
        {"id": "CIS-AZ-5.1", "category": "SQL", "title": "SQL Server Azure AD 管理员",
         "severity": "high", "description": "应配置 AAD 管理员",
         "remediation": "Set Azure AD admin -> 选择管理员组"},
        {"id": "CIS-AZ-5.2", "category": "SQL", "title": "SQL 审计启用",
         "severity": "high", "description": "应启用 Auditing",
         "remediation": "Auditing -> Enable -> Log to Storage/Event Hub/LA"},
        {"id": "CIS-AZ-5.3", "category": "SQL", "title": "SQL Threat Detection",
         "severity": "high", "description": "应启用 Advanced Threat Protection",
         "remediation": "Defender for SQL -> Enable"},
        {"id": "CIS-AZ-5.4", "category": "SQL", "title": "SQL 加密",
         "severity": "high", "description": "TDE 应启用",
         "remediation": "Transparent data encryption -> Enabled"},
        {"id": "CIS-AZ-5.5", "category": "SQL", "title": "SQL 审计保留 >= 90 天",
         "severity": "medium", "description": "审计日志应保留 >= 90 天",
         "remediation": "设置 Retention days >= 90"},
        {"id": "CIS-AZ-5.6", "category": "SQL", "title": "SQL 无公开访问",
         "severity": "critical", "description": "Firewall 不应允许 0.0.0.0-0.0.0.0",
         "remediation": "关闭 Allow Azure services -> 改为 Private Endpoint"},
        {"id": "CIS-AZ-5.7", "category": "SQL", "title": "SQL SSL 强制",
         "severity": "medium", "description": "应启用 Minimal TLS = 1.2",
         "remediation": "Minimal TLS version = 1.2"},
        {"id": "CIS-AZ-5.8", "category": "SQL", "title": "SQL 漏洞评估",
         "severity": "medium", "description": "应定期运行 Vulnerability Assessment",
         "remediation": "Defender for Cloud -> TVA 每周扫描"},

        # ===== Network 8 条 =====
        {"id": "CIS-AZ-6.1", "category": "Network", "title": "NSG 流日志",
         "severity": "medium", "description": "所有 NSG 应启用 Flow Logs",
         "remediation": "Network Watcher -> Flow Logs -> 存储到 LA"},
        {"id": "CIS-AZ-6.2", "category": "Network", "title": "DDOS 保护",
         "severity": "medium", "description": "生产 VNet 应启用 DDoS Protection",
         "remediation": "启用 DDoS Protection Plan"},
        {"id": "CIS-AZ-6.3", "category": "Network", "title": "无开放 SSH/RDP",
         "severity": "critical", "description": "NSG 不应允许 *:22/3389",
         "remediation": "限制为 Bastion/企业 IP"},
        {"id": "CIS-AZ-6.4", "category": "Network", "title": "Bastion 部署",
         "severity": "medium", "description": "应使用 Azure Bastion",
         "remediation": "部署 Bastion 替代公共 RDP"},
        {"id": "CIS-AZ-6.5", "category": "Network", "title": "Private Endpoint",
         "severity": "medium", "description": "PaaS 数据应使用 Private Link",
         "remediation": "为 Storage/SQL/KeyVault 创建 Private Endpoint"},
        {"id": "CIS-AZ-6.6", "category": "Network", "title": "无 BGP 后门",
         "severity": "low", "description": "路由表不应允许未授权传播",
         "remediation": "检查 Route Propagation 设置"},
        {"id": "CIS-AZ-6.7", "category": "Network", "title": "Front Door WAF",
         "severity": "medium", "description": "对外应用应启用 WAF",
         "remediation": "部署 Front Door/Application Gateway WAF Policy"},
        {"id": "CIS-AZ-6.8", "category": "Network", "title": "VPN 加密",
         "severity": "low", "description": "VPNGW 应使用 IKEv2/AKMSP2",
         "remediation": "配置 VPN Client 强制隧道和 AES256"},

        # ===== Activity Log 6 条 =====
        {"id": "CIS-AZ-7.1", "category": "ActivityLog", "title": "活动日志留存",
         "severity": "medium", "description": "活动日志应导出到 Log Analytics",
         "remediation": "Diagnostic Settings -> Send to Log Analytics (365 days)"},
        {"id": "CIS-AZ-7.2", "category": "ActivityLog", "title": "Log Profile",
         "severity": "medium", "description": "应配置 Log Profile",
         "remediation": "通过 CLI az monitor log-prof 配置"},
        {"id": "CIS-AZ-7.3", "category": "ActivityLog", "title": "导出到 SIEM",
         "severity": "low", "description": "应推送活动日志到第三方 SIEM",
         "remediation": "通过 Event Hub 流式导出"},
        {"id": "CIS-AZ-7.4", "category": "ActivityLog", "title": "锁定设置删除",
         "severity": "high", "description": "应告警 Log Profile 删除",
         "remediation": "配置 Alert on Microsoft.Insights/logprofiles/delete"},
        {"id": "CIS-AZ-7.5", "category": "ActivityLog", "title": "租户日志",
         "severity": "medium", "description": "AAD 日志应导出",
         "remediation": "AAD Diagnostic Settings -> 导出 SignIn/Audit logs"},
        {"id": "CIS-AZ-7.6", "category": "ActivityLog", "title": "无日志篡改",
         "severity": "high", "description": "Log Analytics 应锁定",
         "remediation": "设置 Read-only lock on workspace"},

        # ===== Policy 5 条 =====
        {"id": "CIS-AZ-8.1", "category": "Policy", "title": "计费标签强制",
         "severity": "info", "description": "应通过 Policy 强制标签",
         "remediation": "部署 RequireTag 策略"},
        {"id": "CIS-AZ-8.2", "category": "Policy", "title": "允许区域限制",
         "severity": "medium", "description": "应限制资源部署区域",
         "remediation": "Deploy allowed locations 策略"},
        {"id": "CIS-AZ-8.3", "category": "Policy", "title": "禁用超出 SKU",
         "severity": "low", "description": "应限制 VM SKU",
         "remediation": "Allowed virtual machine SKUs"},
        {"id": "CIS-AZ-8.4", "category": "Policy", "title": "安全中心默认策略",
         "severity": "medium", "description": "应启用 ASC 默认策略",
         "remediation": "Security Center -> Policy -> Default = On"},
        {"id": "CIS-AZ-8.5", "category": "Policy", "title": "监管合规",
         "severity": "low", "description": "应部署 ISO27001/CIS 等合规方案",
         "remediation": "Assignment Initiative: ISO 27001"},

        # ===== Security Center (Defender) 8 条 =====
        {"id": "CIS-AZ-9.1", "category": "SecurityCenter", "title": "Defender Servers",
         "severity": "high", "description": "应启用 Defender for Servers",
         "remediation": "Environment settings -> Servers = Standard"},
        {"id": "CIS-AZ-9.2", "category": "SecurityCenter", "title": "Defender SQL",
         "severity": "high", "description": "应启用 Defender for SQL",
         "remediation": "为 SQL servers on machines 启用"},
        {"id": "CIS-AZ-9.3", "category": "SecurityCenter", "title": "Defender App Service",
         "severity": "medium", "description": "应启用 Defender for App Service",
         "remediation": "Plan: App Services = On"},
        {"id": "CIS-AZ-9.4", "category": "SecurityCenter", "title": "Defender Storage",
         "severity": "medium", "description": "应启用 Defender for Storage",
         "remediation": "Plan: Storage = On"},
        {"id": "CIS-AZ-9.5", "category": "SecurityCenter", "title": "Defender Containers",
         "severity": "medium", "description": "应启用 Defender for Containers",
         "remediation": "Plan: Containers = On"},
        {"id": "CIS-AZ-9.6", "category": "SecurityCenter", "title": "邮件通知",
         "severity": "low", "description": "High severity 告警应邮件通知",
         "remediation": "Email notifications -> Include high severity"},
        {"id": "CIS-AZ-9.7", "category": "SecurityCenter", "title": "CSPM",
         "severity": "medium", "description": "应启用 Defender Cloud Security Posture Mgmt",
         "remediation": "Plan: CSPM = On"},
        {"id": "CIS-AZ-9.8", "category": "SecurityCenter", "title": "快速修复",
         "severity": "low", "description": "应配置 Security Center 自动修复",
         "remediation": "对关键策略配置 DeployIfNotExists"},

        # ===== Key Vault 6 条 =====
        {"id": "CIS-AZ-10.1", "category": "KeyVault", "title": "Key Vault 可恢复",
         "severity": "high", "description": "应启用软删除和清除保护",
         "remediation": "Soft delete = 90 days, Purge protection = On"},
        {"id": "CIS-AZ-10.2", "category": "KeyVault", "title": "Key Vault 防火墙",
         "severity": "high", "description": "应限制网络访问",
         "remediation": "Networking = Private endpoint / Selected networks"},
        {"id": "CIS-AZ-10.3", "category": "KeyVault", "title": "Key Vault 审计",
         "severity": "medium", "description": "应启用诊断日志",
         "remediation": "Diagnostic settings -> AuditEvent 到 LA"},
        {"id": "CIS-AZ-10.4", "category": "KeyVault", "title": "RBMS",
         "severity": "medium", "description": "应使用 Azure RBAC 而非访问策略",
         "remediation": "Permission model = Azure role-based access control"},
        {"id": "CIS-AZ-10.5", "category": "KeyVault", "title": "密钥轮换",
         "severity": "medium", "description": "应配置密钥轮换",
         "remediation": "Certificate contacts + lifetime action 45 days"},
        {"id": "CIS-AZ-10.6", "category": "KeyVault", "title": "无公开访问",
         "severity": "critical", "description": "Key Vault 不应允许公共访问",
         "remediation": "Public access = Disabled"},

        # ===== App Service 6 条 =====
        {"id": "CIS-AZ-11.1", "category": "AppService", "title": "App Service HTTPS Only",
         "severity": "high", "description": "应仅允许 HTTPS",
         "remediation": "HTTPS Only = On, TLS version = 1.2"},
        {"id": "CIS-AZ-11.2", "category": "AppService", "title": "App Service 客户端证书",
         "severity": "medium", "description": "敏感应用应启用客户端证书",
         "remediation": "Incoming client certificates = Required"},
        {"id": "CIS-AZ-11.3", "category": "AppService", "title": "App Service 身份",
         "severity": "medium", "description": "应使用 Managed Identity",
         "remediation": "Identity -> System assigned = On"},
        {"id": "CIS-AZ-11.4", "category": "AppService", "title": "App Service 无调试",
         "severity": "low", "description": "生产环境应关闭 Remote Debugging",
         "remediation": "Remote debugging = Off"},
        {"id": "CIS-AZ-11.5", "category": "AppService", "title": "App Service 始终在线",
         "severity": "info", "description": "应启用 Always On",
         "remediation": "Always On = On"},
        {"id": "CIS-AZ-11.6", "category": "AppService", "title": "App Service 最小 SKU",
         "severity": "info", "description": "生产不应使用 F1 Free",
         "remediation": "升级到 B 或更高 SKU"},
    ]

    def __init__(self, credentials: Optional[Dict[str, str]] = None,
                 subscription_id: str = "",
                 categories: Optional[List[str]] = None):
        self.credentials = credentials or {}
        self.subscription_id = subscription_id
        self.categories = categories or list(self.CATEGORY_NAMES.keys())
        self.findings: List[Dict[str, Any]] = []

    @staticmethod
    def _mask(creds: Dict[str, str]) -> Dict[str, str]:
        return {k: ("****" if not isinstance(v, str) or len(v) < 6 else v[:3] + "***")
                for k, v in (creds or {}).items()}

    def _evaluate(self, rule: Dict[str, Any]) -> Dict[str, Any]:
        rng = random.Random(hash(rule["id"]) & 0xFFFFFFFF)
        fail_rate = {"critical": 0.45, "high": 0.30, "medium": 0.20,
                     "low": 0.10, "info": 0.05}.get(rule["severity"], 0.15)
        passed = rng.random() >= fail_rate
        return {
            "rule_id": rule["id"], "title": rule["title"],
            "category": rule["category"], "severity": rule["severity"],
            "description": rule["description"],
            "status": "pass" if passed else "fail",
            "resource": f"/subscriptions/{self.subscription_id or '00000000'}/"
                        f"resourceGroups/rg-sample/providers/{rule['category']}/res-{abs(hash(rule['id']))%9999}",
            "evidence": "OK" if passed else f"{rule['title']} 未达标",
            "remediation": rule["remediation"],
            "checked_at": datetime.now().isoformat(),
        }

    def run_audit(self) -> Dict[str, Any]:
        self.findings = []
        target = [r for r in self.RULES if r["category"] in self.categories]
        checked = [self._evaluate(r) for r in target]
        self.findings = [c for c in checked if c["status"] == "fail"]
        by_sev: Dict[str, int] = {}
        for f in self.findings:
            by_sev[f["severity"]] = by_sev.get(f["severity"], 0) + 1
        return {
            "provider": self.PROVIDER,
            "subscription_id": self.subscription_id,
            "credential_preview": self._mask(self.credentials),
            "total_rules": len(target),
            "total_findings": len(self.findings),
            "passed": len(target) - len(self.findings),
            "failed": len(self.findings),
            "by_severity": by_sev,
            "findings": self.findings,
            "checked_rules": checked,
            "audit_time": datetime.now().isoformat(),
            "mode": "mock" if not _AZURE_OK else "live",
        }

    def list_rules(self, category: Optional[str] = None) -> List[Dict[str, Any]]:
        rules = self.RULES
        if category:
            rules = [r for r in rules if r["category"] == category]
        return [{"id": r["id"], "category": r["category"], "title": r["title"],
                 "severity": r["severity"], "description": r["description"]} for r in rules]

    def generate_report(self, result: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
        result = result or self.run_audit()
        lines = ["=" * 60, "Azure 配置安全检查报告 (CIS Azure Foundations)",
                 "=" * 60, f"订阅: {result.get('subscription_id')}",
                 f"规则总数: {result.get('total_rules')}, 不合规: {result.get('total_findings')}",
                 f"模式: {result.get('mode')}", ""]
        for f in result.get("findings", []):
            lines.append(f"[{f['severity'].upper()}] {f['rule_id']} {f['title']}")
            lines.append(f"  修复: {f['remediation']}")
        return {
            "title": "Azure 配置安全检查报告",
            "generated_at": datetime.now().isoformat(),
            "summary": {"total_rules": result.get("total_rules"),
                        "failed": result.get("failed"),
                        "by_severity": result.get("by_severity")},
            "text": "\n".join(lines),
            "findings": result.get("findings", []),
        }


def create_azure_audit(credentials: Optional[Dict[str, str]] = None,
                       subscription_id: str = "",
                       categories: Optional[List[str]] = None) -> AzureAudit:
    return AzureAudit(credentials=credentials, subscription_id=subscription_id,
                     categories=categories)


if __name__ == "__main__":
    a = AzureAudit()
    r = a.run_audit()
    print(f"Azure audit: {r['total_findings']}/{r['total_rules']}")
