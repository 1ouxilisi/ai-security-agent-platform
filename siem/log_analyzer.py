#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
log_analyzer模块，提供相关安全测试功能。

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
import re
import time
import uuid
from typing import Any, Dict, List, Optional, Set
from dataclasses import dataclass, field
from collections import defaultdict, Counter
from datetime import datetime, timedelta

from utils.logger import log


@dataclass
class LogEvent:
    """日志事件"""
    event_id: str
    timestamp: float
    source: str  # syslog/windows/web/nginx/apache/custom
    source_ip: str = ""
    destination_ip: str = ""
    source_port: int = 0
    destination_port: int = 0
    protocol: str = ""
    username: str = ""
    hostname: str = ""
    event_type: str = ""  # auth/login/firewall/web/process/file/network
    action: str = ""  # accept/deny/allow/block/success/failure
    status: str = ""
    message: str = ""
    raw_log: str = ""
    severity: str = "info"  # critical/high/medium/low/info
    tags: List[str] = field(default_factory=list)
    metadata: Dict[str, Any] = field(default_factory=dict)
    received_at: float = field(default_factory=time.time)

    def to_dict(self) -> Dict[str, Any]:
        """执行相关操作。

        Returns:
            操作结果。
        """
        return {
            "event_id": self.event_id,
            "timestamp": self.timestamp,
            "source": self.source,
            "source_ip": self.source_ip,
            "destination_ip": self.destination_ip,
            "source_port": self.source_port,
            "destination_port": self.destination_port,
            "protocol": self.protocol,
            "username": self.username,
            "hostname": self.hostname,
            "event_type": self.event_type,
            "action": self.action,
            "status": self.status,
            "message": self.message,
            "severity": self.severity,
            "tags": self.tags,
            "metadata": self.metadata,
            "received_at": self.received_at
        }


@dataclass
class DetectionRule:
    """检测规则"""
    rule_id: str
    name: str
    description: str
    severity: str  # critical/high/medium/low
    category: str  # auth/firewall/web/process/network/malware/anomaly
    condition: Dict[str, Any]  # 规则条件
    enabled: bool = True
    created_at: float = field(default_factory=time.time)
    triggered_count: int = 0
    tags: List[str] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        """执行相关操作。

        Returns:
            操作结果。
        """
        return {
            "rule_id": self.rule_id,
            "name": self.name,
            "description": self.description,
            "severity": self.severity,
            "category": self.category,
            "condition": self.condition,
            "enabled": self.enabled,
            "triggered_count": self.triggered_count,
            "tags": self.tags
        }


@dataclass
class SIEMAlert:
    """SIEM告警"""
    alert_id: str
    rule_id: str
    rule_name: str
    severity: str
    category: str
    description: str
    events: List[Dict[str, Any]] = field(default_factory=list)
    source_ip: str = ""
    username: str = ""
    hostname: str = ""
    status: str = "new"  # new/investigating/resolved/false_positive
    confidence: str = "medium"  # high/medium/low
    created_at: float = field(default_factory=time.time)
    updated_at: float = field(default_factory=time.time)
    assignee: str = ""
    notes: str = ""
    tags: List[str] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        """执行相关操作。

        Returns:
            操作结果。
        """
        return {
            "alert_id": self.alert_id,
            "rule_id": self.rule_id,
            "rule_name": self.rule_name,
            "severity": self.severity,
            "category": self.category,
            "description": self.description,
            "events_count": len(self.events),
            "events": self.events[:10],  # 只返回前10个事件
            "source_ip": self.source_ip,
            "username": self.username,
            "hostname": self.hostname,
            "status": self.status,
            "confidence": self.confidence,
            "created_at": self.created_at,
            "updated_at": self.updated_at,
            "assignee": self.assignee,
            "notes": self.notes,
            "tags": self.tags
        }


class LightweightSIEM:
    """轻量级SIEM"""

    def __init__(self, data_dir: str = "data/siem"):
        """初始化LightweightSIEM实例。

        Args:
            self: 类实例。
        """
        self.data_dir = data_dir
        self.events: Dict[str, LogEvent] = {}
        self.rules: Dict[str, DetectionRule] = {}
        self.alerts: Dict[str, SIEMAlert] = {}
        os.makedirs(data_dir, exist_ok=True)
        self._load_data()
        self._init_default_rules()

    def _load_data(self):
        """从文件加载数据"""
        # 加载事件
        events_file = os.path.join(self.data_dir, "events.json")
        if os.path.exists(events_file):
            try:
                with open(events_file, 'r', encoding='utf-8') as f:
                    data = json.load(f)
                for eid, edata in data.items():
                    self.events[eid] = LogEvent(
                        event_id=edata["event_id"],
                        timestamp=edata.get("timestamp", time.time()),
                        source=edata.get("source", "custom"),
                        source_ip=edata.get("source_ip", ""),
                        destination_ip=edata.get("destination_ip", ""),
                        source_port=edata.get("source_port", 0),
                        destination_port=edata.get("destination_port", 0),
                        protocol=edata.get("protocol", ""),
                        username=edata.get("username", ""),
                        hostname=edata.get("hostname", ""),
                        event_type=edata.get("event_type", ""),
                        action=edata.get("action", ""),
                        status=edata.get("status", ""),
                        message=edata.get("message", ""),
                        severity=edata.get("severity", "info"),
                        tags=edata.get("tags", []),
                        metadata=edata.get("metadata", {})
                    )
            except Exception as e:
                log.error(f"加载事件失败: {e}")

        # 加载规则
        rules_file = os.path.join(self.data_dir, "rules.json")
        if os.path.exists(rules_file):
            try:
                with open(rules_file, 'r', encoding='utf-8') as f:
                    data = json.load(f)
                for rid, rdata in data.items():
                    self.rules[rid] = DetectionRule(
                        rule_id=rdata["rule_id"],
                        name=rdata["name"],
                        description=rdata.get("description", ""),
                        severity=rdata.get("severity", "medium"),
                        category=rdata.get("category", "anomaly"),
                        condition=rdata.get("condition", {}),
                        enabled=rdata.get("enabled", True),
                        triggered_count=rdata.get("triggered_count", 0),
                        tags=rdata.get("tags", [])
                    )
            except Exception as e:
                log.error(f"加载规则失败: {e}")

        # 加载告警
        alerts_file = os.path.join(self.data_dir, "alerts.json")
        if os.path.exists(alerts_file):
            try:
                with open(alerts_file, 'r', encoding='utf-8') as f:
                    data = json.load(f)
                for aid, adata in data.items():
                    self.alerts[aid] = SIEMAlert(
                        alert_id=adata["alert_id"],
                        rule_id=adata.get("rule_id", ""),
                        rule_name=adata.get("rule_name", ""),
                        severity=adata.get("severity", "medium"),
                        category=adata.get("category", "anomaly"),
                        description=adata.get("description", ""),
                        events=adata.get("events", []),
                        source_ip=adata.get("source_ip", ""),
                        username=adata.get("username", ""),
                        hostname=adata.get("hostname", ""),
                        status=adata.get("status", "new"),
                        confidence=adata.get("confidence", "medium"),
                        created_at=adata.get("created_at", time.time()),
                        updated_at=adata.get("updated_at", time.time()),
                        assignee=adata.get("assignee", ""),
                        notes=adata.get("notes", ""),
                        tags=adata.get("tags", [])
                    )
            except Exception as e:
                log.error(f"加载告警失败: {e}")

    def _save_data(self):
        """保存数据到文件"""
        # 保存事件（只保存最近10000条）
        events_file = os.path.join(self.data_dir, "events.json")
        try:
            sorted_events = sorted(self.events.values(), key=lambda x: x.received_at, reverse=True)[:10000]
            data = {e.event_id: e.to_dict() for e in sorted_events}
            with open(events_file, 'w', encoding='utf-8') as f:
                json.dump(data, f, ensure_ascii=False, indent=2, default=str)
        except Exception as e:
            log.error(f"保存事件失败: {e}")

        # 保存规则
        rules_file = os.path.join(self.data_dir, "rules.json")
        try:
            data = {rid: r.to_dict() for rid, r in self.rules.items()}
            with open(rules_file, 'w', encoding='utf-8') as f:
                json.dump(data, f, ensure_ascii=False, indent=2, default=str)
        except Exception as e:
            log.error(f"保存规则失败: {e}")

        # 保存告警
        alerts_file = os.path.join(self.data_dir, "alerts.json")
        try:
            data = {aid: a.to_dict() for aid, a in self.alerts.items()}
            with open(alerts_file, 'w', encoding='utf-8') as f:
                json.dump(data, f, ensure_ascii=False, indent=2, default=str)
        except Exception as e:
            log.error(f"保存告警失败: {e}")

    def _init_default_rules(self):
        """初始化默认检测规则"""
        if self.rules:
            return  # 已有规则，不重复初始化

        default_rules = [
            {
                "name": "暴力破解检测",
                "description": "同一IP在5分钟内登录失败超过10次",
                "severity": "high",
                "category": "auth",
                "condition": {
                    "event_type": "auth",
                    "action": "failure",
                    "group_by": "source_ip",
                    "threshold": 10,
                    "time_window": 300  # 5分钟
                }
            },
            {
                "name": "异常登录时间检测",
                "description": "用户在非工作时间（凌晨2-6点）登录成功",
                "severity": "medium",
                "category": "auth",
                "condition": {
                    "event_type": "auth",
                    "action": "success",
                    "time_range": [2, 6],  # 凌晨2-6点
                    "group_by": "username"
                }
            },
            {
                "name": "端口扫描检测",
                "description": "同一IP在1分钟内访问超过50个不同端口",
                "severity": "high",
                "category": "network",
                "condition": {
                    "event_type": "network",
                    "group_by": "source_ip",
                    "distinct_field": "destination_port",
                    "threshold": 50,
                    "time_window": 60
                }
            },
            {
                "name": "Web攻击检测",
                "description": "请求中包含SQL注入/XSS/命令注入特征",
                "severity": "high",
                "category": "web",
                "condition": {
                    "event_type": "web",
                    "pattern_match": ["union select", "<script", "or 1=1", "; cat /", "cmd.exe", "powershell"],
                    "field": "message"
                }
            },
            {
                "name": "敏感文件访问",
                "description": "访问敏感文件（/etc/passwd、.env、.git等）",
                "severity": "medium",
                "category": "web",
                "condition": {
                    "event_type": "web",
                    "pattern_match": ["/etc/passwd", "/.env", "/.git", "web.config", "wp-config.php"],
                    "field": "message"
                }
            },
            {
                "name": "可疑进程启动",
                "description": "启动可疑进程（cmd.exe、powershell、bash、nc等）",
                "severity": "high",
                "category": "process",
                "condition": {
                    "event_type": "process",
                    "pattern_match": ["cmd.exe", "powershell", "bash", "nc.exe", "netcat", "mimikatz", "cobalt"],
                    "field": "message"
                }
            },
            {
                "name": "防火墙大量拒绝",
                "description": "防火墙在1分钟内拒绝超过100个连接",
                "severity": "medium",
                "category": "firewall",
                "condition": {
                    "event_type": "firewall",
                    "action": "deny",
                    "threshold": 100,
                    "time_window": 60
                }
            },
            {
                "name": "异常数据外发",
                "description": "单连接外发数据超过100MB",
                "severity": "critical",
                "category": "network",
                "condition": {
                    "event_type": "network",
                    "field": "metadata.bytes_out",
                    "operator": ">",
                    "value": 104857600  # 100MB
                }
            },
            {
                "name": "新用户首次登录",
                "description": "新用户首次登录系统",
                "severity": "low",
                "category": "auth",
                "condition": {
                    "event_type": "auth",
                    "action": "success",
                    "first_seen": True,
                    "group_by": "username"
                }
            },
            {
                "name": "多次403/401错误",
                "description": "同一IP在5分钟内收到超过20个403/401响应",
                "severity": "medium",
                "category": "web",
                "condition": {
                    "event_type": "web",
                    "status_in": ["401", "403"],
                    "group_by": "source_ip",
                    "threshold": 20,
                    "time_window": 300
                }
            },
        ]

        for rule_data in default_rules:
            rule_id = f"rule-{uuid.uuid4().hex[:8]}"
            rule = DetectionRule(
                rule_id=rule_id,
                name=rule_data["name"],
                description=rule_data["description"],
                severity=rule_data["severity"],
                category=rule_data["category"],
                condition=rule_data["condition"]
            )
            self.rules[rule_id] = rule

        self._save_data()
        log.info(f"初始化 {len(default_rules)} 条默认检测规则")

    # ===== 日志采集和解析 =====
    def ingest_log(self, raw_log: str, source: str = "custom") -> str:
        """采集并解析日志"""
        event_id = f"evt-{uuid.uuid4().hex[:8]}"
        event = LogEvent(
            event_id=event_id,
            timestamp=time.time(),
            source=source,
            raw_log=raw_log
        )

        # 根据来源解析日志
        if source == "nginx":
            self._parse_nginx_log(event, raw_log)
        elif source == "apache":
            self._parse_apache_log(event, raw_log)
        elif source == "windows":
            self._parse_windows_log(event, raw_log)
        elif source == "syslog":
            self._parse_syslog(event, raw_log)
        elif source == "web":
            self._parse_web_log(event, raw_log)
        else:
            event.message = raw_log
            event.event_type = "custom"

        self.events[event_id] = event
        self._save_data()

        # 实时检测
        self._check_rules_for_event(event)

        return event_id

    def _parse_nginx_log(self, event: LogEvent, raw_log: str):
        """解析Nginx日志"""
        # 常见Nginx格式: $remote_addr - $remote_user [$time_local] "$request" $status $body_bytes_sent "$http_referer" "$http_user_agent"
        pattern = r'(\d+\.\d+\.\d+\.\d+) - (\S+) \[([^\]]+)\] "(\S+) (\S+) (\S+)" (\d+) (\d+) "([^"]*)" "([^"]*)"'
        match = re.match(pattern, raw_log)
        if match:
            event.source_ip = match.group(1)
            event.username = match.group(2) if match.group(2) != "-" else ""
            event.method = match.group(4)
            event.message = f"{match.group(4)} {match.group(5)}"
            event.status = match.group(7)
            event.event_type = "web"
            event.metadata = {
                "request_path": match.group(5),
                "protocol": match.group(6),
                "bytes_sent": int(match.group(8)),
                "referer": match.group(9),
                "user_agent": match.group(10)
            }
            # 简单的严重程度判断
            if event.status in ["401", "403"]:
                event.severity = "low"
                event.action = "failure"
            elif event.status.startswith("5"):
                event.severity = "medium"
            else:
                event.severity = "info"
                event.action = "success"
        else:
            event.message = raw_log
            event.event_type = "web"

    def _parse_apache_log(self, event: LogEvent, raw_log: str):
        """解析Apache日志（格式类似Nginx）"""
        self._parse_nginx_log(event, raw_log)
        event.source = "apache"

    def _parse_windows_log(self, event: LogEvent, raw_log: str):
        """解析Windows事件日志"""
        # 简化的Windows日志解析
        event.event_type = "windows"
        event.message = raw_log

        # 提取常见字段
        if "EventID" in raw_log or "Event ID" in raw_log:
            event_id_match = re.search(r'EventID[=:]\s*(\d+)', raw_log, re.IGNORECASE)
            if event_id_match:
                event.metadata["windows_event_id"] = event_id_match.group(1)
                # 根据EventID判断类型
                eid = event_id_match.group(1)
                if eid in ["4624", "4625"]:
                    event.event_type = "auth"
                    event.action = "success" if eid == "4624" else "failure"
                elif eid in ["4688"]:
                    event.event_type = "process"
                elif eid in ["5140", "5145"]:
                    event.event_type = "network"

        if "AccountName" in raw_log:
            user_match = re.search(r'AccountName[=:]\s*(\S+)', raw_log, re.IGNORECASE)
            if user_match:
                event.username = user_match.group(1)

        if "IpAddress" in raw_log or "Client Address" in raw_log:
            ip_match = re.search(r'(?:IpAddress|Client Address)[=:]\s*(\d+\.\d+\.\d+\.\d+)', raw_log, re.IGNORECASE)
            if ip_match:
                event.source_ip = ip_match.group(1)

    def _parse_syslog(self, event: LogEvent, raw_log: str):
        """解析Syslog日志"""
        # 简化的Syslog解析
        pattern = r'<(\d+)>(\w+\s+\d+\s+\d+:\d+:\d+)\s+(\S+)\s+(.*)'
        match = re.match(pattern, raw_log)
        if match:
            priority = int(match.group(1))
            facility = priority // 8
            severity = priority % 8
            event.hostname = match.group(3)
            event.message = match.group(4)
            event.event_type = "syslog"
            event.metadata = {"facility": facility, "syslog_severity": severity}

            severity_map = {0: "critical", 1: "high", 2: "high", 3: "medium", 4: "low", 5: "info", 6: "info", 7: "info"}
            event.severity = severity_map.get(severity, "info")
        else:
            event.message = raw_log
            event.event_type = "syslog"

    def _parse_web_log(self, event: LogEvent, raw_log: str):
        """解析通用Web日志"""
        event.event_type = "web"
        event.message = raw_log

        # 提取IP
        ip_match = re.search(r'(\d+\.\d+\.\d+\.\d+)', raw_log)
        if ip_match:
            event.source_ip = ip_match.group(1)

        # 提取状态码
        status_match = re.search(r'\s(200|301|302|400|401|403|404|500|502|503)\s', raw_log)
        if status_match:
            event.status = status_match.group(1)

    def batch_ingest(self, logs: List[str], source: str = "custom") -> Dict[str, Any]:
        """批量采集日志"""
        event_ids = []
        for log in logs:
            eid = self.ingest_log(log, source)
            event_ids.append(eid)
        return {
            "ingested_count": len(event_ids),
            "event_ids": event_ids
        }

    # ===== 规则检测引擎 =====
    def _check_rules_for_event(self, event: LogEvent):
        """对单个事件检查所有规则"""
        for rule in self.rules.values():
            if not rule.enabled:
                continue
            if self._match_rule(event, rule):
                self._trigger_alert(rule, [event])

    def _match_rule(self, event: LogEvent, rule: DetectionRule) -> bool:
        """检查事件是否匹配规则"""
        condition = rule.condition

        # 事件类型匹配
        if "event_type" in condition and event.event_type != condition["event_type"]:
            return False

        # 动作匹配
        if "action" in condition and event.action != condition["action"]:
            return False

        # 状态匹配
        if "status_in" in condition and event.status not in condition["status_in"]:
            return False

        # 模式匹配
        if "pattern_match" in condition and "field" in condition:
            field_value = getattr(event, condition["field"], "") or event.metadata.get(condition["field"].split(".")[-1], "")
            if not any(pattern.lower() in str(field_value).lower() for pattern in condition["pattern_match"]):
                return False

        # 阈值类规则需要聚合检查（这里只做简单标记，实际聚合在analyze中做）
        if "threshold" in condition and "group_by" in condition:
            # 简单匹配：事件类型和动作匹配，聚合在analyze中做
            return True

        # 简单条件匹配
        if "operator" in condition and "field" in condition and "value" in condition:
            field_value = event.metadata.get(condition["field"].split(".")[-1], 0)
            try:
                field_value = float(field_value)
                if condition["operator"] == ">" and field_value > condition["value"]:
                    return True
                elif condition["operator"] == "<" and field_value < condition["value"]:
                    return True
                elif condition["operator"] == "==" and field_value == condition["value"]:
                    return True
            except (ValueError, TypeError):
                pass
            return False

        return True

    def _trigger_alert(self, rule: DetectionRule, events: List[LogEvent]):
        """触发告警"""
        alert_id = f"alert-{uuid.uuid4().hex[:8]}"

        # 提取关键信息
        source_ip = events[0].source_ip if events else ""
        username = events[0].username if events else ""
        hostname = events[0].hostname if events else ""

        alert = SIEMAlert(
            alert_id=alert_id,
            rule_id=rule.rule_id,
            rule_name=rule.name,
            severity=rule.severity,
            category=rule.category,
            description=rule.description,
            events=[e.to_dict() for e in events],
            source_ip=source_ip,
            username=username,
            hostname=hostname,
            confidence="high" if len(events) > 5 else "medium",
            tags=rule.tags
        )

        self.alerts[alert_id] = alert
        rule.triggered_count += 1
        self._save_data()

        log.warning(f"触发告警: {rule.name} (严重程度: {rule.severity})")

    def analyze_events(self, time_window: int = 3600) -> Dict[str, Any]:
        """分析历史事件，执行聚合规则检测"""
        now = time.time()
        cutoff = now - time_window
        recent_events = [e for e in self.events.values() if e.timestamp >= cutoff]

        new_alerts = []

        for rule in self.rules.values():
            if not rule.enabled:
                continue
            condition = rule.condition

            # 聚合类规则
            if "threshold" in condition and "group_by" in condition:
                group_field = condition["group_by"]
                threshold = condition["threshold"]
                window = condition.get("time_window", time_window)

                # 按字段分组
                groups = defaultdict(list)
                for event in recent_events:
                    if self._match_rule(event, rule):
                        group_value = getattr(event, group_field, "")
                        if group_value:
                            groups[group_value].append(event)

                # 检查阈值
                for group_value, group_events in groups.items():
                    if "distinct_field" in condition:
                        distinct_values = set(getattr(e, condition["distinct_field"], "") for e in group_events)
                        if len(distinct_values) >= threshold:
                            self._trigger_alert(rule, group_events[:20])
                            new_alerts.append(rule.name)
                    elif len(group_events) >= threshold:
                        self._trigger_alert(rule, group_events[:20])
                        new_alerts.append(rule.name)

        return {
            "analyzed_events": len(recent_events),
            "time_window_seconds": time_window,
            "new_alerts": len(new_alerts),
            "alert_names": list(set(new_alerts))
        }

    # ===== 告警管理 =====
    def update_alert_status(self, alert_id: str, status: str, notes: str = "",
                            assignee: str = "") -> bool:
        """更新告警状态"""
        alert = self.alerts.get(alert_id)
        if not alert:
            return False
        alert.status = status
        if notes:
            alert.notes = notes
        if assignee:
            alert.assignee = assignee
        alert.updated_at = time.time()
        self._save_data()
        return True

    def get_alerts(self, status: str = None, severity: str = None,
                   category: str = None) -> List[Dict[str, Any]]:
        """获取告警列表"""
        results = []
        for alert in self.alerts.values():
            if status and alert.status != status:
                continue
            if severity and alert.severity != severity:
                continue
            if category and alert.category != category:
                continue
            results.append(alert.to_dict())
        results.sort(key=lambda x: x["created_at"], reverse=True)
        return results

    # ===== 日志查询 =====
    def search_events(self, query: str = "", source_ip: str = "",
                      username: str = "", event_type: str = "",
                      severity: str = "", start_time: float = None,
                      end_time: float = None, limit: int = 100) -> List[Dict[str, Any]]:
        """搜索日志事件"""
        results = []
        for event in self.events.values():
            if source_ip and event.source_ip != source_ip:
                continue
            if username and event.username != username:
                continue
            if event_type and event.event_type != event_type:
                continue
            if severity and event.severity != severity:
                continue
            if start_time and event.timestamp < start_time:
                continue
            if end_time and event.timestamp > end_time:
                continue
            if query and query.lower() not in event.message.lower() and query.lower() not in event.raw_log.lower():
                continue
            results.append(event.to_dict())

        results.sort(key=lambda x: x["timestamp"], reverse=True)
        return results[:limit]

    # ===== 统计分析 =====
    def get_statistics(self, time_window: int = 86400) -> Dict[str, Any]:
        """获取统计信息"""
        now = time.time()
        cutoff = now - time_window
        recent_events = [e for e in self.events.values() if e.timestamp >= cutoff]

        # 按事件类型统计
        by_type = Counter(e.event_type for e in recent_events)
        # 按严重程度统计
        by_severity = Counter(e.severity for e in recent_events)
        # 按来源IP统计（Top 10）
        by_source_ip = Counter(e.source_ip for e in recent_events if e.source_ip).most_common(10)
        # 按用户名统计（Top 10）
        by_username = Counter(e.username for e in recent_events if e.username).most_common(10)
        # 按来源统计
        by_source = Counter(e.source for e in recent_events)

        # 告警统计
        recent_alerts = [a for a in self.alerts.values() if a.created_at >= cutoff]
        alert_by_severity = Counter(a.severity for a in recent_alerts)
        alert_by_status = Counter(a.status for a in recent_alerts)
        alert_by_category = Counter(a.category for a in recent_alerts)

        return {
            "time_window_seconds": time_window,
            "total_events": len(recent_events),
            "events_by_type": dict(by_type),
            "events_by_severity": dict(by_severity),
            "events_by_source": dict(by_source),
            "top_source_ips": by_source_ip,
            "top_usernames": by_username,
            "total_alerts": len(recent_alerts),
            "alerts_by_severity": dict(alert_by_severity),
            "alerts_by_status": dict(alert_by_status),
            "alerts_by_category": dict(alert_by_category),
            "total_rules": len(self.rules),
            "enabled_rules": sum(1 for r in self.rules.values() if r.enabled)
        }

    # ===== 规则管理 =====
    def add_rule(self, name: str, description: str, severity: str,
                 category: str, condition: Dict[str, Any]) -> str:
        """添加检测规则"""
        rule_id = f"rule-{uuid.uuid4().hex[:8]}"
        rule = DetectionRule(
            rule_id=rule_id,
            name=name,
            description=description,
            severity=severity,
            category=category,
            condition=condition
        )
        self.rules[rule_id] = rule
        self._save_data()
        return rule_id

    def get_rules(self, category: str = None, enabled: bool = None) -> List[Dict[str, Any]]:
        """获取规则列表"""
        results = []
        for rule in self.rules.values():
            if category and rule.category != category:
                continue
            if enabled is not None and rule.enabled != enabled:
                continue
            results.append(rule.to_dict())
        return results


# 全局实例
siem = LightweightSIEM()
