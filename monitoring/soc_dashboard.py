#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
soc_dashboard模块，提供相关安全测试功能。

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
from typing import Any, Dict, List, Optional
from dataclasses import dataclass, field
from enum import Enum

from utils.logger import log


class EventSeverity(str, Enum):
    """事件严重程度"""
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


class EventStatus(str, Enum):
    """事件状态"""
    NEW = "new"  # 新建
    TRIAGED = "triaged"  # 已分诊
    INVESTIGATING = "investigating"  # 调查中
    CONTAINED = "contained"  # 已遏制
    ERADICATED = "eradicated"  # 已根除
    RECOVERED = "recovered"  # 已恢复
    CLOSED = "closed"  # 已关闭
    FALSE_POSITIVE = "false_positive"  # 误报


class EventCategory(str, Enum):
    """事件类别"""
    MALWARE = "malware"  # 恶意软件
    PHISHING = "phishing"  # 钓鱼
    UNAUTHORIZED_ACCESS = "unauthorized_access"  # 未授权访问
    DATA_BREACH = "data_breach"  # 数据泄露
    DOS = "dos"  # 拒绝服务
    VULNERABILITY = "vulnerability"  # 漏洞
    MISCONFIGURATION = "misconfiguration"  # 配置错误
    INSIDER_THREAT = "insider_threat"  # 内部威胁
    OTHER = "other"  # 其他


@dataclass
class SecurityEvent:
    """安全事件"""
    event_id: str
    title: str
    description: str = ""
    severity: EventSeverity = EventSeverity.MEDIUM
    category: EventCategory = EventCategory.OTHER
    status: EventStatus = EventStatus.NEW
    source: str = ""  # 事件来源（如：IDS/IPS/WAF/EDR/人工报告）
    source_ip: str = ""
    target_ip: str = ""
    affected_assets: List[str] = field(default_factory=list)
    indicators: List[Dict[str, Any]] = field(default_factory=list)  # IOC
    created_at: float = field(default_factory=time.time)
    updated_at: float = field(default_factory=time.time)
    first_seen: Optional[float] = None
    last_seen: Optional[float] = None
    assigned_to: str = ""
    sla_due: Optional[float] = None  # SLA截止时间
    resolution: str = ""
    timeline: List[Dict[str, Any]] = field(default_factory=list)  # 事件时间线
    tags: List[str] = field(default_factory=list)
    false_positive: bool = False

    def to_dict(self) -> Dict[str, Any]:
        """执行相关操作。

        Returns:
            操作结果。
        """
        return {
            "event_id": self.event_id,
            "title": self.title,
            "description": self.description,
            "severity": self.severity.value,
            "category": self.category.value,
            "status": self.status.value,
            "source": self.source,
            "source_ip": self.source_ip,
            "target_ip": self.target_ip,
            "affected_assets": self.affected_assets,
            "indicators": self.indicators,
            "created_at": self.created_at,
            "updated_at": self.updated_at,
            "first_seen": self.first_seen,
            "last_seen": self.last_seen,
            "assigned_to": self.assigned_to,
            "sla_due": self.sla_due,
            "resolution": self.resolution,
            "timeline": self.timeline,
            "tags": self.tags,
            "false_positive": self.false_positive
        }


@dataclass
class SecurityAlert:
    """安全告警"""
    alert_id: str
    title: str
    description: str = ""
    severity: EventSeverity = EventSeverity.MEDIUM
    source: str = ""
    rule_id: str = ""
    status: str = "new"  # new/acknowledged/resolved/ignored
    created_at: float = field(default_factory=time.time)
    acknowledged_at: Optional[float] = None
    resolved_at: Optional[float] = None
    related_event_id: str = ""
    details: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        """执行相关操作。

        Returns:
            操作结果。
        """
        return {
            "alert_id": self.alert_id,
            "title": self.title,
            "description": self.description,
            "severity": self.severity.value,
            "source": self.source,
            "rule_id": self.rule_id,
            "status": self.status,
            "created_at": self.created_at,
            "acknowledged_at": self.acknowledged_at,
            "resolved_at": self.resolved_at,
            "related_event_id": self.related_event_id,
            "details": self.details
        }


@dataclass
class Asset:
    """受保护资产"""
    asset_id: str
    name: str
    type: str = ""  # server/network_device/database/application/endpoint
    ip_address: str = ""
    hostname: str = ""
    os: str = ""
    criticality: str = "medium"  # critical/high/medium/low
    status: str = "active"  # active/inactive/maintenance
    vulnerabilities: List[Dict[str, Any]] = field(default_factory=list)
    last_scan: Optional[float] = None
    tags: List[str] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        """执行相关操作。

        Returns:
            操作结果。
        """
        return {
            "asset_id": self.asset_id,
            "name": self.name,
            "type": self.type,
            "ip_address": self.ip_address,
            "hostname": self.hostname,
            "os": self.os,
            "criticality": self.criticality,
            "status": self.status,
            "vulnerabilities": self.vulnerabilities,
            "last_scan": self.last_scan,
            "tags": self.tags
        }


class SecurityOperationsDashboard:
    """安全运营仪表盘系统"""

    def __init__(self, data_dir: str = "data/soc"):
        """初始化SecurityOperationsDashboard实例。

        Args:
            self: 类实例。
        """
        self.data_dir = data_dir
        self.events: Dict[str, SecurityEvent] = {}
        self.alerts: Dict[str, SecurityAlert] = {}
        self.assets: Dict[str, Asset] = {}
        self.incident_response_playbooks: Dict[str, Dict[str, Any]] = {}

        os.makedirs(data_dir, exist_ok=True)
        self._init_playbooks()
        self._init_sample_data()
        self._load_data()

    def _init_playbooks(self):
        """初始化事件响应剧本"""
        self.incident_response_playbooks = {
            "malware": {
                "name": "恶意软件事件响应",
                "steps": [
                    "1. 隔离受感染主机（断开网络连接）",
                    "2. 收集恶意软件样本和IOC（IP/域名/文件哈希）",
                    "3. 分析恶意软件行为（沙箱分析）",
                    "4. 检查横向移动迹象",
                    "5. 清除恶意软件并修复系统",
                    "6. 恢复系统并验证完整性",
                    "7. 更新防护规则（防火墙/IDS/EDR）",
                    "8. 复盘并改进防护措施"
                ],
                "sla_hours": 4
            },
            "phishing": {
                "name": "钓鱼事件响应",
                "steps": [
                    "1. 收集钓鱼邮件样本（含完整邮件头）",
                    "2. 分析钓鱼URL和附件",
                    "3. 检查是否有用户点击或输入凭据",
                    "4. 重置受影响用户密码",
                    "5. 封锁钓鱼域名和IP",
                    "6. 通知所有用户提高警惕",
                    "7. 复盘并改进邮件安全策略"
                ],
                "sla_hours": 2
            },
            "unauthorized_access": {
                "name": "未授权访问事件响应",
                "steps": [
                    "1. 确认未授权访问的真实性和范围",
                    "2. 立即禁用受影响账号",
                    "3. 检查访问日志，确定访问时间和操作",
                    "4. 检查是否有数据被访问或窃取",
                    "5. 修复导致未授权访问的漏洞",
                    "6. 强制相关用户修改密码",
                    "7. 加强监控，防止再次发生",
                    "8. 如涉及数据泄露，启动数据泄露响应流程"
                ],
                "sla_hours": 1
            },
            "data_breach": {
                "name": "数据泄露事件响应",
                "steps": [
                    "1. 确认数据泄露的真实性和范围",
                    "2. 立即遏制泄露（关闭访问/修复漏洞）",
                    "3. 评估泄露数据的类型和敏感程度",
                    "4. 确定受影响的用户/客户数量",
                    "5. 保留证据（日志/访问记录）",
                    "6. 通知相关方（管理层/法务/监管机构）",
                    "7. 向受影响用户发出通知",
                    "8. 修复漏洞并加强防护",
                    "9. 复盘并改进数据安全措施"
                ],
                "sla_hours": 1
            },
            "dos": {
                "name": "拒绝服务事件响应",
                "steps": [
                    "1. 确认攻击类型（DDoS/DoS/应用层攻击）",
                    "2. 启用DDoS防护或流量清洗",
                    "3. 封锁攻击源IP",
                    "4. 检查服务可用性和性能",
                    "5. 分析攻击流量特征",
                    "6. 更新防护规则",
                    "7. 复盘并改进抗DDoS能力"
                ],
                "sla_hours": 1
            },
            "vulnerability": {
                "name": "漏洞事件响应",
                "steps": [
                    "1. 确认漏洞的真实性和影响范围",
                    "2. 评估漏洞的可利用性和风险等级",
                    "3. 制定临时缓解措施（WAF规则/访问控制）",
                    "4. 制定修复计划（补丁/配置更改）",
                    "5. 在测试环境验证修复",
                    "6. 在生产环境部署修复",
                    "7. 验证修复效果",
                    "8. 复盘并改进漏洞管理流程"
                ],
                "sla_hours": 24
            }
        }

    def _init_sample_data(self):
        """初始化示例数据"""
        if self.assets:
            return

        # 示例资产
        sample_assets = [
            Asset("asset-001", "Web服务器-01", "server", "192.168.1.10", "web01.example.com", "Ubuntu 22.04", "critical", "active"),
            Asset("asset-002", "数据库服务器-01", "database", "192.168.1.20", "db01.example.com", "CentOS 8", "critical", "active"),
            Asset("asset-003", "防火墙", "network_device", "192.168.1.1", "fw01.example.com", "FortiOS", "critical", "active"),
            Asset("asset-004", "应用服务器-01", "server", "192.168.1.30", "app01.example.com", "Windows Server 2022", "high", "active"),
            Asset("asset-005", "测试服务器", "server", "192.168.1.40", "test01.example.com", "Ubuntu 20.04", "low", "maintenance"),
        ]
        for asset in sample_assets:
            self.assets[asset.asset_id] = asset

        # 示例告警
        sample_alerts = [
            SecurityAlert("alert-001", "检测到SQL注入尝试", "在Web请求中检测到SQL注入payload", EventSeverity.HIGH, "WAF", "waf-sqli-001"),
            SecurityAlert("alert-002", "异常登录行为", "用户从非常用IP地址登录", EventSeverity.MEDIUM, "SIEM", "siem-login-001"),
            SecurityAlert("alert-003", "端口扫描检测", "检测到来自外部IP的端口扫描", EventSeverity.LOW, "IDS", "ids-scan-001"),
            SecurityAlert("alert-004", "恶意文件检测", "在终端检测到恶意软件", EventSeverity.CRITICAL, "EDR", "edr-malware-001"),
        ]
        for alert in sample_alerts:
            self.alerts[alert.alert_id] = alert

    def _load_data(self):
        """从文件加载数据"""
        # 加载事件
        events_file = os.path.join(self.data_dir, "events.json")
        if os.path.exists(events_file):
            try:
                with open(events_file, 'r', encoding='utf-8') as f:
                    events_data = json.load(f)
                for event_id, data in events_data.items():
                    self.events[event_id] = SecurityEvent(
                        event_id=data["event_id"],
                        title=data.get("title", ""),
                        description=data.get("description", ""),
                        severity=EventSeverity(data.get("severity", "medium")),
                        category=EventCategory(data.get("category", "other")),
                        status=EventStatus(data.get("status", "new")),
                        source=data.get("source", ""),
                        source_ip=data.get("source_ip", ""),
                        target_ip=data.get("target_ip", ""),
                        affected_assets=data.get("affected_assets", []),
                        indicators=data.get("indicators", []),
                        created_at=data.get("created_at", time.time()),
                        assigned_to=data.get("assigned_to", ""),
                        resolution=data.get("resolution", ""),
                        timeline=data.get("timeline", []),
                        tags=data.get("tags", [])
                    )
            except Exception as e:
                log.error(f"加载安全事件失败: {e}")

    def _save_data(self):
        """保存数据到文件"""
        # 保存事件
        events_file = os.path.join(self.data_dir, "events.json")
        try:
            events_data = {eid: e.to_dict() for eid, e in self.events.items()}
            with open(events_file, 'w', encoding='utf-8') as f:
                json.dump(events_data, f, ensure_ascii=False, indent=2, default=str)
        except Exception as e:
            log.error(f"保存安全事件失败: {e}")

        # 保存告警
        alerts_file = os.path.join(self.data_dir, "alerts.json")
        try:
            alerts_data = {aid: a.to_dict() for aid, a in self.alerts.items()}
            with open(alerts_file, 'w', encoding='utf-8') as f:
                json.dump(alerts_data, f, ensure_ascii=False, indent=2, default=str)
        except Exception as e:
            log.error(f"保存安全告警失败: {e}")

        # 保存资产
        assets_file = os.path.join(self.data_dir, "assets.json")
        try:
            assets_data = {aid: a.to_dict() for aid, a in self.assets.items()}
            with open(assets_file, 'w', encoding='utf-8') as f:
                json.dump(assets_data, f, ensure_ascii=False, indent=2, default=str)
        except Exception as e:
            log.error(f"保存资产失败: {e}")

    # ===== 事件管理 =====
    def create_event(self, title: str, description: str = "", severity: str = "medium",
                     category: str = "other", source: str = "", source_ip: str = "",
                     target_ip: str = "", affected_assets: List[str] = None,
                     indicators: List[Dict] = None, tags: List[str] = None) -> str:
        """创建安全事件"""
        event_id = f"evt-{uuid.uuid4().hex[:8]}"
        event = SecurityEvent(
            event_id=event_id,
            title=title,
            description=description,
            severity=EventSeverity(severity),
            category=EventCategory(category),
            source=source,
            source_ip=source_ip,
            target_ip=target_ip,
            affected_assets=affected_assets or [],
            indicators=indicators or [],
            tags=tags or []
        )

        # 设置SLA
        sla_hours = {"critical": 1, "high": 4, "medium": 24, "low": 72}.get(severity, 24)
        event.sla_due = time.time() + sla_hours * 3600

        # 添加时间线
        event.timeline.append({
            "time": time.time(),
            "action": "事件创建",
            "description": f"事件由{source or '系统'}创建"
        })

        self.events[event_id] = event
        self._save_data()
        log.info(f"创建安全事件: {event_id}, 严重程度={severity}, 标题={title}")
        return event_id

    def update_event_status(self, event_id: str, status: str,
                             resolution: str = "", assigned_to: str = "") -> bool:
        """更新事件状态"""
        event = self.events.get(event_id)
        if not event:
            return False

        old_status = event.status
        event.status = EventStatus(status)
        event.updated_at = time.time()

        if resolution:
            event.resolution = resolution
        if assigned_to:
            event.assigned_to = assigned_to

        # 添加时间线
        event.timeline.append({
            "time": time.time(),
            "action": "状态变更",
            "description": f"状态从{old_status.value}变更为{status}"
        })

        if status == "closed":
            event.timeline.append({
                "time": time.time(),
                "action": "事件关闭",
                "description": resolution or "事件已关闭"
            })

        self._save_data()
        return True

    def get_events(self, status: str = None, severity: str = None,
                   category: str = None, limit: int = 50) -> List[Dict[str, Any]]:
        """获取事件列表"""
        results = []
        for event in self.events.values():
            if status and event.status.value != status:
                continue
            if severity and event.severity.value != severity:
                continue
            if category and event.category.value != category:
                continue
            results.append(event.to_dict())
        results.sort(key=lambda x: x["created_at"], reverse=True)
        return results[:limit]

    def get_event_detail(self, event_id: str) -> Optional[Dict[str, Any]]:
        """获取事件详情"""
        event = self.events.get(event_id)
        if not event:
            return None
        return event.to_dict()

    def get_incident_playbook(self, category: str) -> Optional[Dict[str, Any]]:
        """获取事件响应剧本"""
        return self.incident_response_playbooks.get(category)

    # ===== 告警管理 =====
    def create_alert(self, title: str, description: str = "", severity: str = "medium",
                     source: str = "", rule_id: str = "", details: Dict = None) -> str:
        """创建安全告警"""
        alert_id = f"alert-{uuid.uuid4().hex[:8]}"
        alert = SecurityAlert(
            alert_id=alert_id,
            title=title,
            description=description,
            severity=EventSeverity(severity),
            source=source,
            rule_id=rule_id,
            details=details or {}
        )
        self.alerts[alert_id] = alert
        self._save_data()
        log.info(f"创建安全告警: {alert_id}, 严重程度={severity}, 标题={title}")
        return alert_id

    def acknowledge_alert(self, alert_id: str) -> bool:
        """确认告警"""
        alert = self.alerts.get(alert_id)
        if not alert:
            return False
        alert.status = "acknowledged"
        alert.acknowledged_at = time.time()
        self._save_data()
        return True

    def resolve_alert(self, alert_id: str, related_event_id: str = "") -> bool:
        """解决告警"""
        alert = self.alerts.get(alert_id)
        if not alert:
            return False
        alert.status = "resolved"
        alert.resolved_at = time.time()
        if related_event_id:
            alert.related_event_id = related_event_id
        self._save_data()
        return True

    def get_alerts(self, status: str = None, severity: str = None, limit: int = 50) -> List[Dict[str, Any]]:
        """获取告警列表"""
        results = []
        for alert in self.alerts.values():
            if status and alert.status != status:
                continue
            if severity and alert.severity.value != severity:
                continue
            results.append(alert.to_dict())
        results.sort(key=lambda x: x["created_at"], reverse=True)
        return results[:limit]

    # ===== 仪表盘数据 =====
    def get_dashboard_data(self) -> Dict[str, Any]:
        """获取仪表盘汇总数据"""
        now = time.time()
        today_start = now - 86400
        week_start = now - 7 * 86400

        # 事件统计
        total_events = len(self.events)
        open_events = sum(1 for e in self.events.values() if e.status not in [EventStatus.CLOSED, EventStatus.FALSE_POSITIVE])
        critical_events = sum(1 for e in self.events.values() if e.severity == EventSeverity.CRITICAL and e.status not in [EventStatus.CLOSED, EventStatus.FALSE_POSITIVE])
        high_events = sum(1 for e in self.events.values() if e.severity == EventSeverity.HIGH and e.status not in [EventStatus.CLOSED, EventStatus.FALSE_POSITIVE])
        events_today = sum(1 for e in self.events.values() if e.created_at >= today_start)
        events_this_week = sum(1 for e in self.events.values() if e.created_at >= week_start)

        # SLA违规
        sla_breached = sum(1 for e in self.events.values() if e.sla_due and e.sla_due < now and e.status not in [EventStatus.CLOSED, EventStatus.FALSE_POSITIVE])

        # 告警统计
        total_alerts = len(self.alerts)
        new_alerts = sum(1 for a in self.alerts.values() if a.status == "new")
        alerts_today = sum(1 for a in self.alerts.values() if a.created_at >= today_start)

        # 资产统计
        total_assets = len(self.assets)
        critical_assets = sum(1 for a in self.assets.values() if a.criticality == "critical")
        assets_with_vulns = sum(1 for a in self.assets.values() if a.vulnerabilities)

        # 事件按类别统计
        events_by_category = {}
        for event in self.events.values():
            cat = event.category.value
            events_by_category[cat] = events_by_category.get(cat, 0) + 1

        # 事件按严重程度统计
        events_by_severity = {
            "critical": sum(1 for e in self.events.values() if e.severity == EventSeverity.CRITICAL),
            "high": sum(1 for e in self.events.values() if e.severity == EventSeverity.HIGH),
            "medium": sum(1 for e in self.events.values() if e.severity == EventSeverity.MEDIUM),
            "low": sum(1 for e in self.events.values() if e.severity == EventSeverity.LOW),
        }

        # 平均响应时间（简化计算）
        closed_events = [e for e in self.events.values() if e.status == EventStatus.CLOSED and e.timeline]
        avg_response_time = 0
        if closed_events:
            response_times = []
            for e in closed_events:
                if len(e.timeline) >= 2:
                    rt = e.timeline[1]["time"] - e.timeline[0]["time"]
                    response_times.append(rt)
            if response_times:
                avg_response_time = sum(response_times) / len(response_times)

        # 安全态势评分（0-100，越高越安全）
        risk_score = 100
        risk_score -= critical_events * 10
        risk_score -= high_events * 5
        risk_score -= sla_breached * 5
        risk_score -= assets_with_vulns * 2
        risk_score = max(0, min(100, risk_score))

        return {
            "timestamp": now,
            "security_posture_score": risk_score,
            "events": {
                "total": total_events,
                "open": open_events,
                "critical": critical_events,
                "high": high_events,
                "today": events_today,
                "this_week": events_this_week,
                "sla_breached": sla_breached,
                "by_category": events_by_category,
                "by_severity": events_by_severity
            },
            "alerts": {
                "total": total_alerts,
                "new": new_alerts,
                "today": alerts_today
            },
            "assets": {
                "total": total_assets,
                "critical": critical_assets,
                "with_vulnerabilities": assets_with_vulns
            },
            "performance": {
                "avg_response_time_seconds": round(avg_response_time, 2),
                "mean_time_to_respond": "需更多数据计算",
                "mean_time_to_resolve": "需更多数据计算"
            },
            "top_priorities": [
                {"priority": 1, "item": f"{critical_events}个严重事件待处理", "action": "立即响应严重事件"},
                {"priority": 2, "item": f"{sla_breached}个事件SLA违规", "action": "优先处理SLA违规事件"},
                {"priority": 3, "item": f"{new_alerts}个新告警待确认", "action": "确认并分诊新告警"},
            ]
        }

    # ===== 统计 =====
    def get_statistics(self) -> Dict[str, Any]:
        """获取系统统计"""
        return {
            "total_events": len(self.events),
            "open_events": sum(1 for e in self.events.values() if e.status not in [EventStatus.CLOSED, EventStatus.FALSE_POSITIVE]),
            "total_alerts": len(self.alerts),
            "new_alerts": sum(1 for a in self.alerts.values() if a.status == "new"),
            "total_assets": len(self.assets),
            "playbooks": len(self.incident_response_playbooks),
            "event_categories": [c.value for c in EventCategory],
            "event_severities": [s.value for s in EventSeverity],
            "event_statuses": [s.value for s in EventStatus]
        }


# 全局实例
soc_dashboard = SecurityOperationsDashboard()
