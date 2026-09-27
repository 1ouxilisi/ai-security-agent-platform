#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
intel_monitor模块，提供相关安全测试功能。

模块功能：
    - 提供相关安全测试功能
    - 支持API调用和命令行使用
    - 与其他模块集成协作

注意事项：
    - 本模块仅用于授权的安全测试
    - 请勿用于非法用途
    - 使用前请确保已获得相关授权
"""
import json
import os
import time
import uuid
import asyncio
import urllib.request
import urllib.parse
from typing import Any, Dict, List, Optional
from dataclasses import dataclass, field
from enum import Enum

from utils.logger import log


class VulnSeverity(str, Enum):
    """漏洞严重程度"""
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


class AlertStatus(str, Enum):
    """告警状态"""
    NEW = "new"
    ACKNOWLEDGED = "acknowledged"
    RESOLVED = "resolved"
    IGNORED = "ignored"


class IntelligenceSource(str, Enum):
    """情报源"""
    NVD = "nvd"  # 美国国家漏洞数据库
    CVE_DETAILS = "cve_details"  # CVE详情
    EXPLOIT_DB = "exploit_db"  # Exploit-DB
    GITHUB_ADVISORIES = "github_advisories"  # GitHub安全公告
    CNVD = "cnvd"  # 中国国家信息安全漏洞共享平台
    CNNVD = "cnnvd"  # 中国国家信息安全漏洞库


@dataclass
class VulnerabilityIntel:
    """漏洞情报"""
    intel_id: str
    cve_id: str = ""
    title: str = ""
    description: str = ""
    severity: VulnSeverity = VulnSeverity.MEDIUM
    cvss_score: float = 0.0
    source: IntelligenceSource = IntelligenceSource.NVD
    published_at: float = 0
    updated_at: float = 0
    affected_products: List[str] = field(default_factory=list)
    references: List[str] = field(default_factory=list)
    exploit_available: bool = False
    exploit_urls: List[str] = field(default_factory=list)
    patch_available: bool = False
    patch_urls: List[str] = field(default_factory=list)
    tags: List[str] = field(default_factory=list)
    in_the_wild: bool = False  # 在野利用

    def to_dict(self) -> Dict[str, Any]:
        """执行相关操作。

        Returns:
            操作结果。
        """
        return {
            "intel_id": self.intel_id,
            "cve_id": self.cve_id,
            "title": self.title,
            "description": self.description,
            "severity": self.severity.value,
            "cvss_score": self.cvss_score,
            "source": self.source.value,
            "published_at": self.published_at,
            "updated_at": self.updated_at,
            "affected_products": self.affected_products,
            "references": self.references,
            "exploit_available": self.exploit_available,
            "exploit_urls": self.exploit_urls,
            "patch_available": self.patch_available,
            "patch_urls": self.patch_urls,
            "tags": self.tags,
            "in_the_wild": self.in_the_wild
        }


@dataclass
class AlertRule:
    """告警规则"""
    rule_id: str
    name: str
    description: str = ""
    enabled: bool = True
    severity_threshold: VulnSeverity = VulnSeverity.HIGH
    keywords: List[str] = field(default_factory=list)  # 关键词匹配
    affected_products: List[str] = field(default_factory=list)  # 影响产品匹配
    sources: List[str] = field(default_factory=list)  # 情报源过滤
    require_exploit: bool = False  # 仅告警有利用代码的
    require_in_the_wild: bool = False  # 仅告警在野利用的
    notification_channels: List[str] = field(default_factory=list)  # 通知渠道
    created_at: float = field(default_factory=time.time)
    last_triggered: Optional[float] = None
    trigger_count: int = 0

    def to_dict(self) -> Dict[str, Any]:
        """执行相关操作。

        Returns:
            操作结果。
        """
        return {
            "rule_id": self.rule_id,
            "name": self.name,
            "description": self.description,
            "enabled": self.enabled,
            "severity_threshold": self.severity_threshold.value,
            "keywords": self.keywords,
            "affected_products": self.affected_products,
            "sources": self.sources,
            "require_exploit": self.require_exploit,
            "require_in_the_wild": self.require_in_the_wild,
            "notification_channels": self.notification_channels,
            "created_at": self.created_at,
            "last_triggered": self.last_triggered,
            "trigger_count": self.trigger_count
        }


@dataclass
class Alert:
    """告警"""
    alert_id: str
    rule_id: str = ""
    rule_name: str = ""
    intel_id: str = ""
    cve_id: str = ""
    title: str = ""
    severity: VulnSeverity = VulnSeverity.MEDIUM
    description: str = ""
    status: AlertStatus = AlertStatus.NEW
    created_at: float = field(default_factory=time.time)
    acknowledged_at: Optional[float] = None
    resolved_at: Optional[float] = None
    notification_sent: bool = False
    notification_channels: List[str] = field(default_factory=list)
    notes: str = ""

    def to_dict(self) -> Dict[str, Any]:
        """执行相关操作。

        Returns:
            操作结果。
        """
        return {
            "alert_id": self.alert_id,
            "rule_id": self.rule_id,
            "rule_name": self.rule_name,
            "intel_id": self.intel_id,
            "cve_id": self.cve_id,
            "title": self.title,
            "severity": self.severity.value,
            "description": self.description,
            "status": self.status.value,
            "created_at": self.created_at,
            "acknowledged_at": self.acknowledged_at,
            "resolved_at": self.resolved_at,
            "notification_sent": self.notification_sent,
            "notification_channels": self.notification_channels,
            "notes": self.notes
        }


class VulnerabilityIntelligenceMonitor:
    """漏洞情报监控系统"""

    def __init__(self, data_dir: str = "data/intelligence"):
        """初始化VulnerabilityIntelligenceMonitor实例。

        Args:
            self: 类实例。
        """
        self.data_dir = data_dir
        self.intel: Dict[str, VulnerabilityIntel] = {}
        self.alert_rules: Dict[str, AlertRule] = {}
        self.alerts: Dict[str, Alert] = {}
        self.subscriptions: Dict[str, List[str]] = {}  # product -> cve_ids
        self.last_fetch: Dict[str, float] = {}
        self.fetch_interval: int = 3600  # 1小时

        os.makedirs(data_dir, exist_ok=True)
        self._init_default_rules()
        self._load_data()
        self._init_sample_intel()

    def _init_default_rules(self):
        """初始化默认告警规则"""
        default_rules = [
            AlertRule(
                rule_id="rule-critical",
                name="严重漏洞告警",
                description="所有CVSS评分>=9.0的严重漏洞",
                severity_threshold=VulnSeverity.CRITICAL,
                notification_channels=["console", "log"]
            ),
            AlertRule(
                rule_id="rule-high-exploit",
                name="高危可利用漏洞告警",
                description="高危且有公开利用代码的漏洞",
                severity_threshold=VulnSeverity.HIGH,
                require_exploit=True,
                notification_channels=["console", "log"]
            ),
            AlertRule(
                rule_id="rule-in-the-wild",
                name="在野利用漏洞告警",
                description="检测到在野利用的漏洞",
                severity_threshold=VulnSeverity.MEDIUM,
                require_in_the_wild=True,
                notification_channels=["console", "log"]
            ),
        ]
        for rule in default_rules:
            self.alert_rules[rule.rule_id] = rule

    def _init_sample_intel(self):
        """初始化示例漏洞情报"""
        if self.intel:
            return

        samples = [
            VulnerabilityIntel(
                intel_id="intel-001",
                cve_id="CVE-2024-1234",
                title="Apache Struts2 远程代码执行漏洞",
                description="Apache Struts2 存在远程代码执行漏洞，攻击者可通过构造恶意请求执行任意代码",
                severity=VulnSeverity.CRITICAL,
                cvss_score=9.8,
                source=IntelligenceSource.NVD,
                published_at=time.time() - 86400,
                affected_products=["Apache Struts2 2.5.0-2.5.32"],
                exploit_available=True,
                exploit_urls=["https://exploit-db.com/exploits/12345"],
                patch_available=True,
                in_the_wild=True,
                tags=["RCE", "Apache", "Struts2"]
            ),
            VulnerabilityIntel(
                intel_id="intel-002",
                cve_id="CVE-2024-5678",
                title="OpenSSL 拒绝服务漏洞",
                description="OpenSSL 存在拒绝服务漏洞，攻击者可通过特制证书导致服务崩溃",
                severity=VulnSeverity.HIGH,
                cvss_score=7.5,
                source=IntelligenceSource.NVD,
                published_at=time.time() - 172800,
                affected_products=["OpenSSL 3.0.0-3.0.12"],
                exploit_available=False,
                patch_available=True,
                tags=["DoS", "OpenSSL"]
            ),
            VulnerabilityIntel(
                intel_id="intel-003",
                cve_id="CVE-2024-9012",
                title="WordPress 插件 SQL注入漏洞",
                description="某WordPress插件存在SQL注入漏洞，攻击者可通过构造恶意请求提取数据库数据",
                severity=VulnSeverity.HIGH,
                cvss_score=8.1,
                source=IntelligenceSource.EXPLOIT_DB,
                published_at=time.time() - 3600,
                affected_products=["WordPress Plugin XYZ 1.0-2.5"],
                exploit_available=True,
                exploit_urls=["https://exploit-db.com/exploits/67890"],
                patch_available=False,
                tags=["SQL Injection", "WordPress", "Plugin"]
            ),
            VulnerabilityIntel(
                intel_id="intel-004",
                cve_id="CVE-2024-3456",
                title="Linux 内核权限提升漏洞",
                description="Linux内核存在权限提升漏洞，本地攻击者可利用该漏洞提升到root权限",
                severity=VulnSeverity.HIGH,
                cvss_score=7.8,
                source=IntelligenceSource.GITHUB_ADVISORIES,
                published_at=time.time() - 7200,
                affected_products=["Linux Kernel 5.15-6.5"],
                exploit_available=True,
                exploit_urls=["https://github.com/exploit/CVE-2024-3456"],
                patch_available=True,
                in_the_wild=False,
                tags=["Privilege Escalation", "Linux", "Kernel"]
            ),
            VulnerabilityIntel(
                intel_id="intel-005",
                cve_id="CVE-2024-7890",
                title="Nginx 信息泄露漏洞",
                description="Nginx在特定配置下存在信息泄露漏洞，攻击者可获取敏感配置信息",
                severity=VulnSeverity.MEDIUM,
                cvss_score=5.3,
                source=IntelligenceSource.NVD,
                published_at=time.time() - 86400 * 3,
                affected_products=["Nginx 1.18-1.24"],
                exploit_available=False,
                patch_available=True,
                tags=["Information Disclosure", "Nginx"]
            ),
        ]
        for sample in samples:
            self.intel[sample.intel_id] = sample

    def _load_data(self):
        """从文件加载数据"""
        # 加载情报
        intel_file = os.path.join(self.data_dir, "intel.json")
        if os.path.exists(intel_file):
            try:
                with open(intel_file, 'r', encoding='utf-8') as f:
                    intel_data = json.load(f)
                for intel_id, data in intel_data.items():
                    self.intel[intel_id] = VulnerabilityIntel(
                        intel_id=data["intel_id"],
                        cve_id=data.get("cve_id", ""),
                        title=data.get("title", ""),
                        description=data.get("description", ""),
                        severity=VulnSeverity(data.get("severity", "medium")),
                        cvss_score=data.get("cvss_score", 0),
                        source=IntelligenceSource(data.get("source", "nvd")),
                        published_at=data.get("published_at", 0),
                        affected_products=data.get("affected_products", []),
                        exploit_available=data.get("exploit_available", False),
                        exploit_urls=data.get("exploit_urls", []),
                        patch_available=data.get("patch_available", False),
                        in_the_wild=data.get("in_the_wild", False),
                        tags=data.get("tags", [])
                    )
            except Exception as e:
                log.error(f"加载漏洞情报失败: {e}")

        # 加载告警
        alerts_file = os.path.join(self.data_dir, "alerts.json")
        if os.path.exists(alerts_file):
            try:
                with open(alerts_file, 'r', encoding='utf-8') as f:
                    alerts_data = json.load(f)
                for alert_id, data in alerts_data.items():
                    self.alerts[alert_id] = Alert(
                        alert_id=data["alert_id"],
                        rule_id=data.get("rule_id", ""),
                        rule_name=data.get("rule_name", ""),
                        intel_id=data.get("intel_id", ""),
                        cve_id=data.get("cve_id", ""),
                        title=data.get("title", ""),
                        severity=VulnSeverity(data.get("severity", "medium")),
                        description=data.get("description", ""),
                        status=AlertStatus(data.get("status", "new")),
                        created_at=data.get("created_at", time.time()),
                        notification_sent=data.get("notification_sent", False),
                        notification_channels=data.get("notification_channels", [])
                    )
            except Exception as e:
                log.error(f"加载告警失败: {e}")

    def _save_data(self):
        """保存数据到文件"""
        # 保存情报
        intel_file = os.path.join(self.data_dir, "intel.json")
        try:
            intel_data = {iid: i.to_dict() for iid, i in self.intel.items()}
            with open(intel_file, 'w', encoding='utf-8') as f:
                json.dump(intel_data, f, ensure_ascii=False, indent=2, default=str)
        except Exception as e:
            log.error(f"保存漏洞情报失败: {e}")

        # 保存告警
        alerts_file = os.path.join(self.data_dir, "alerts.json")
        try:
            alerts_data = {aid: a.to_dict() for aid, a in self.alerts.items()}
            with open(alerts_file, 'w', encoding='utf-8') as f:
                json.dump(alerts_data, f, ensure_ascii=False, indent=2, default=str)
        except Exception as e:
            log.error(f"保存告警失败: {e}")

    # ===== 情报查询 =====
    def search_intel(self, keyword: str = "", severity: str = "",
                     source: str = "", has_exploit: bool = None,
                     in_the_wild: bool = None, limit: int = 50) -> List[Dict[str, Any]]:
        """搜索漏洞情报"""
        results = []
        for intel in self.intel.values():
            if keyword and keyword.lower() not in intel.title.lower() and keyword.lower() not in intel.description.lower():
                continue
            if severity and intel.severity.value != severity:
                continue
            if source and intel.source.value != source:
                continue
            if has_exploit is not None and intel.exploit_available != has_exploit:
                continue
            if in_the_wild is not None and intel.in_the_wild != in_the_wild:
                continue
            results.append(intel.to_dict())

        results.sort(key=lambda x: x["published_at"], reverse=True)
        return results[:limit]

    def get_intel_by_cve(self, cve_id: str) -> Optional[Dict[str, Any]]:
        """根据CVE ID查询情报"""
        for intel in self.intel.values():
            if intel.cve_id.upper() == cve_id.upper():
                return intel.to_dict()
        return None

    # ===== 告警规则管理 =====
    def create_alert_rule(self, name: str, description: str = "",
                          severity_threshold: str = "high",
                          keywords: List[str] = None,
                          affected_products: List[str] = None,
                          require_exploit: bool = False,
                          require_in_the_wild: bool = False) -> str:
        """创建告警规则"""
        rule_id = f"rule-{uuid.uuid4().hex[:8]}"
        rule = AlertRule(
            rule_id=rule_id,
            name=name,
            description=description,
            severity_threshold=VulnSeverity(severity_threshold),
            keywords=keywords or [],
            affected_products=affected_products or [],
            require_exploit=require_exploit,
            require_in_the_wild=require_in_the_wild,
            notification_channels=["console", "log"]
        )
        self.alert_rules[rule_id] = rule
        self._save_data()
        log.info(f"创建告警规则: {name} ({rule_id})")
        return rule_id

    def evaluate_alerts(self) -> List[Dict[str, Any]]:
        """评估所有情报，触发告警规则"""
        new_alerts = []
        severity_order = {"critical": 4, "high": 3, "medium": 2, "low": 1, "info": 0}

        for intel in self.intel.values():
            for rule in self.alert_rules.values():
                if not rule.enabled:
                    continue

                # 检查是否已告警
                alert_exists = any(
                    a.intel_id == intel.intel_id and a.rule_id == rule.rule_id
                    for a in self.alerts.values()
                )
                if alert_exists:
                    continue

                # 严重程度检查
                if severity_order.get(intel.severity.value, 0) < severity_order.get(rule.severity_threshold.value, 0):
                    continue

                # 利用代码检查
                if rule.require_exploit and not intel.exploit_available:
                    continue

                # 在野利用检查
                if rule.require_in_the_wild and not intel.in_the_wild:
                    continue

                # 关键词检查
                if rule.keywords:
                    text = f"{intel.title} {intel.description} {' '.join(intel.tags)}".lower()
                    if not any(kw.lower() in text for kw in rule.keywords):
                        continue

                # 触发告警
                alert = Alert(
                    alert_id=f"alert-{uuid.uuid4().hex[:8]}",
                    rule_id=rule.rule_id,
                    rule_name=rule.name,
                    intel_id=intel.intel_id,
                    cve_id=intel.cve_id,
                    title=intel.title,
                    severity=intel.severity,
                    description=intel.description[:200],
                    notification_channels=rule.notification_channels
                )
                self.alerts[alert.alert_id] = alert
                new_alerts.append(alert.to_dict())

                rule.last_triggered = time.time()
                rule.trigger_count += 1

                # 发送通知
                self._send_notification(alert, rule)

        self._save_data()
        log.info(f"告警评估完成: 新增{len(new_alerts)}个告警")
        return new_alerts

    def _send_notification(self, alert: Alert, rule: AlertRule):
        """发送通知"""
        for channel in rule.notification_channels:
            if channel == "console":
                log.warning(f"[告警] {alert.severity.value.upper()}: {alert.title} (CVE: {alert.cve_id})")
            elif channel == "log":
                # 已通过log记录
                pass
        alert.notification_sent = True

    # ===== 告警管理 =====
    def get_alerts(self, status: str = None, severity: str = None, limit: int = 50) -> List[Dict[str, Any]]:
        """获取告警列表"""
        results = []
        for alert in self.alerts.values():
            if status and alert.status.value != status:
                continue
            if severity and alert.severity.value != severity:
                continue
            results.append(alert.to_dict())
        results.sort(key=lambda x: x["created_at"], reverse=True)
        return results[:limit]

    def acknowledge_alert(self, alert_id: str) -> bool:
        """确认告警"""
        alert = self.alerts.get(alert_id)
        if not alert:
            return False
        alert.status = AlertStatus.ACKNOWLEDGED
        alert.acknowledged_at = time.time()
        self._save_data()
        return True

    def resolve_alert(self, alert_id: str, notes: str = "") -> bool:
        """解决告警"""
        alert = self.alerts.get(alert_id)
        if not alert:
            return False
        alert.status = AlertStatus.RESOLVED
        alert.resolved_at = time.time()
        alert.notes = notes
        self._save_data()
        return True

    # ===== 统计 =====
    def get_statistics(self) -> Dict[str, Any]:
        """获取系统统计"""
        severity_counts = {sev: 0 for sev in ["critical", "high", "medium", "low"]}
        for intel in self.intel.values():
            if intel.severity.value in severity_counts:
                severity_counts[intel.severity.value] += 1

        alert_status_counts = {status: 0 for status in ["new", "acknowledged", "resolved", "ignored"]}
        for alert in self.alerts.values():
            if alert.status.value in alert_status_counts:
                alert_status_counts[alert.status.value] += 1

        return {
            "total_intel": len(self.intel),
            "intel_by_severity": severity_counts,
            "exploit_available_count": sum(1 for i in self.intel.values() if i.exploit_available),
            "in_the_wild_count": sum(1 for i in self.intel.values() if i.in_the_wild),
            "total_alert_rules": len(self.alert_rules),
            "enabled_alert_rules": sum(1 for r in self.alert_rules.values() if r.enabled),
            "total_alerts": len(self.alerts),
            "alerts_by_status": alert_status_counts,
            "new_alerts": alert_status_counts.get("new", 0),
            "sources": list(set(i.source.value for i in self.intel.values()))
        }


# 全局实例
intel_monitor = VulnerabilityIntelligenceMonitor()
