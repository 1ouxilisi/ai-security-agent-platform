#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
audit_log企业级功能模块，提供相关企业级安全管理和认证功能。

模块功能：
    - 提供相关安全测试功能
    - 支持API调用和命令行使用
    - 与其他模块集成协作

注意事项：
    - 本模块仅用于授权的安全测试
    - 请勿用于非法用途
    - 使用前请确保已获得相关授权
"""

import os
import json
import uuid
import hashlib
from typing import Any, Dict, List, Optional
from dataclasses import dataclass, field, asdict
from collections import Counter
from datetime import datetime, timedelta
from enum import Enum

from utils.logger import log


class AuditAction(Enum):
    """审计操作类型"""
    # 认证相关
    LOGIN = "user.login"
    LOGOUT = "user.logout"
    LOGIN_FAILED = "user.login_failed"
    PASSWORD_CHANGE = "user.password_change"
    MFA_ENABLE = "user.mfa_enable"
    MFA_DISABLE = "user.mfa_disable"
    TOKEN_CREATE = "user.token_create"
    TOKEN_REVOKE = "user.token_revoke"

    # 数据相关
    DATA_CREATE = "data.create"
    DATA_READ = "data.read"
    DATA_UPDATE = "data.update"
    DATA_DELETE = "data.delete"
    DATA_EXPORT = "data.export"
    DATA_IMPORT = "data.import"
    DATA_QUERY = "data.query"

    # 安全相关
    SCAN_START = "scan.start"
    SCAN_COMPLETE = "scan.complete"
    SCAN_FAILED = "scan.failed"
    VULN_FOUND = "vuln.found"
    VULN_EXPLOIT = "vuln.exploit"
    VULN_VERIFY = "vuln.verify"
    REPORT_GENERATE = "report.generate"
    REPORT_DOWNLOAD = "report.download"

    # 配置相关
    CONFIG_CHANGE = "config.change"
    CONFIG_CREATE = "config.create"
    CONFIG_DELETE = "config.delete"
    ROLE_CREATE = "role.create"
    ROLE_UPDATE = "role.update"
    ROLE_DELETE = "role.delete"
    PERMISSION_GRANT = "permission.grant"
    PERMISSION_REVOKE = "permission.revoke"

    # 系统相关
    SYSTEM_START = "system.start"
    SYSTEM_STOP = "system.stop"
    SYSTEM_UPDATE = "system.update"
    BACKUP_CREATE = "backup.create"
    BACKUP_RESTORE = "backup.restore"
    API_CALL = "api.call"
    API_ERROR = "api.error"

    # 管理相关
    USER_CREATE = "admin.user_create"
    USER_UPDATE = "admin.user_update"
    USER_DELETE = "admin.user_delete"
    USER_DISABLE = "admin.user_disable"
    USER_ENABLE = "admin.user_enable"
    AUDIT_LOG_VIEW = "audit.view"
    AUDIT_LOG_EXPORT = "audit.export"


class AuditSeverity(Enum):
    """审计严重程度"""
    INFO = "info"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


@dataclass
class AuditEvent:
    """审计事件"""
    event_id: str
    timestamp: str
    action: str
    severity: str
    user_id: str = ""
    username: str = ""
    source_ip: str = ""
    user_agent: str = ""
    resource_type: str = ""
    resource_id: str = ""
    description: str = ""
    details: Dict[str, Any] = field(default_factory=dict)
    result: str = "success"  # success/failure/denied
    error_message: str = ""
    request_id: str = ""
    session_id: str = ""
    duration_ms: int = 0
    hash_chain: str = ""  # 哈希链，防止篡改

    def to_dict(self) -> Dict[str, Any]:
        """执行相关操作。

        Returns:
            操作结果。
        """
        return asdict(self)

    def calculate_hash(self, previous_hash: str = "") -> str:
        """计算事件哈希（用于防篡改）"""
        content = json.dumps({
            "event_id": self.event_id,
            "timestamp": self.timestamp,
            "action": self.action,
            "user_id": self.user_id,
            "source_ip": self.source_ip,
            "resource_id": self.resource_id,
            "result": self.result,
            "previous_hash": previous_hash
        }, sort_keys=True)
        return hashlib.sha256(content.encode()).hexdigest()


class AuditLogger:
    """企业级审计日志器"""

    def __init__(self, data_dir: str = "data/audit"):
        """初始化AuditLogger实例。

        Args:
            self: 类实例。
        """
        self.data_dir = data_dir
        self.events: List[AuditEvent] = []
        self.last_hash: str = ""
        self.event_counter = 0
        os.makedirs(data_dir, exist_ok=True)
        self._load()

    def _load(self):
        """从文件加载审计日志"""
        log_file = os.path.join(self.data_dir, "audit_log.json")
        if os.path.exists(log_file):
            try:
                with open(log_file, 'r', encoding='utf-8') as f:
                    data = json.load(f)
                self.events = [AuditEvent(**e) for e in data.get("events", [])]
                self.last_hash = data.get("last_hash", "")
                self.event_counter = len(self.events)
            except Exception as e:
                log.error(f"加载审计日志失败: {e}")

    def _save(self):
        """保存审计日志到文件"""
        log_file = os.path.join(self.data_dir, "audit_log.json")
        try:
            data = {
                "events": [e.to_dict() for e in self.events[-10000:]],  # 最多保留10000条
                "last_hash": self.last_hash,
                "total_events": self.event_counter,
                "last_updated": datetime.now().isoformat()
            }
            with open(log_file, 'w', encoding='utf-8') as f:
                json.dump(data, f, ensure_ascii=False, indent=2, default=str)
        except Exception as e:
            log.error(f"保存审计日志失败: {e}")

    def log_event(self, action: str, severity: str = "info",
                  user_id: str = "", username: str = "",
                  source_ip: str = "", user_agent: str = "",
                  resource_type: str = "", resource_id: str = "",
                  description: str = "", details: Dict[str, Any] = None,
                  result: str = "success", error_message: str = "",
                  request_id: str = "", session_id: str = "",
                  duration_ms: int = 0) -> str:
        """记录审计事件"""
        self.event_counter += 1
        event_id = f"AUD-{self.event_counter:08d}"

        event = AuditEvent(
            event_id=event_id,
            timestamp=datetime.now().isoformat(),
            action=action,
            severity=severity,
            user_id=user_id,
            username=username,
            source_ip=source_ip,
            user_agent=user_agent,
            resource_type=resource_type,
            resource_id=resource_id,
            description=description,
            details=details or {},
            result=result,
            error_message=error_message,
            request_id=request_id,
            session_id=session_id,
            duration_ms=duration_ms
        )

        # 计算哈希链
        event.hash_chain = event.calculate_hash(self.last_hash)
        self.last_hash = event.hash_chain

        self.events.append(event)
        self._save()

        # 高严重程度事件实时告警
        if severity in ["high", "critical"]:
            self._alert(event)

        return event_id

    def _alert(self, event: AuditEvent):
        """高严重程度事件告警"""
        alert_file = os.path.join(self.data_dir, "alerts.json")
        try:
            alerts = []
            if os.path.exists(alert_file):
                with open(alert_file, 'r', encoding='utf-8') as f:
                    alerts = json.load(f)

            alerts.append({
                "event_id": event.event_id,
                "timestamp": event.timestamp,
                "action": event.action,
                "severity": event.severity,
                "description": event.description,
                "source_ip": event.source_ip,
                "username": event.username,
                "acknowledged": False
            })

            with open(alert_file, 'w', encoding='utf-8') as f:
                json.dump(alerts[-1000:], f, ensure_ascii=False, indent=2)
        except Exception as e:
            log.error(f"告警记录失败: {e}")

    # ===== 查询方法 =====
    def query_events(self, action: str = None, severity: str = None,
                     user_id: str = None, source_ip: str = None,
                     resource_type: str = None, result: str = None,
                     start_time: str = None, end_time: str = None,
                     keyword: str = None, limit: int = 100,
                     offset: int = 0) -> Dict[str, Any]:
        """查询审计事件"""
        results = []
        for event in reversed(self.events):
            if action and event.action != action:
                continue
            if severity and event.severity != severity:
                continue
            if user_id and event.user_id != user_id:
                continue
            if source_ip and event.source_ip != source_ip:
                continue
            if resource_type and event.resource_type != resource_type:
                continue
            if result and event.result != result:
                continue
            if start_time and event.timestamp < start_time:
                continue
            if end_time and event.timestamp > end_time:
                continue
            if keyword:
                search_text = json.dumps(event.to_dict(), ensure_ascii=False).lower()
                if keyword.lower() not in search_text:
                    continue
            results.append(event.to_dict())

        total = len(results)
        paginated = results[offset:offset + limit]

        return {
            "total": total,
            "limit": limit,
            "offset": offset,
            "events": paginated
        }

    def get_statistics(self, days: int = 30) -> Dict[str, Any]:
        """获取审计统计信息"""
        cutoff = (datetime.now() - timedelta(days=days)).isoformat()
        recent_events = [e for e in self.events if e.timestamp >= cutoff]

        by_action = Counter(e.action for e in recent_events)
        by_severity = Counter(e.severity for e in recent_events)
        by_user = Counter(e.username for e in recent_events if e.username)
        by_ip = Counter(e.source_ip for e in recent_events if e.source_ip)
        by_result = Counter(e.result for e in recent_events)
        by_hour = Counter()
        for e in recent_events:
            try:
                hour = datetime.fromisoformat(e.timestamp).strftime("%Y-%m-%d %H:00")
                by_hour[hour] += 1
            except:
                pass

        # 失败登录统计
        failed_logins = [e for e in recent_events if e.action == "user.login_failed"]
        failed_login_ips = Counter(e.source_ip for e in failed_logins if e.source_ip)

        # 高风险事件
        high_risk = [e for e in recent_events if e.severity in ["high", "critical"]]

        return {
            "period_days": days,
            "total_events": len(recent_events),
            "by_action": dict(by_action.most_common(20)),
            "by_severity": dict(by_severity),
            "by_user": dict(by_user.most_common(10)),
            "by_ip": dict(by_ip.most_common(10)),
            "by_result": dict(by_result),
            "by_hour": dict(sorted(by_hour.items())[-48:]),  # 最近48小时
            "failed_logins": {
                "total": len(failed_logins),
                "by_ip": dict(failed_login_ips.most_common(10))
            },
            "high_risk_events": {
                "total": len(high_risk),
                "recent": [e.to_dict() for e in high_risk[-10:]]
            },
            "unique_users": len(by_user),
            "unique_ips": len(by_ip),
            "hash_chain_intact": self._verify_hash_chain()
        }

    def _verify_hash_chain(self) -> bool:
        """验证哈希链完整性（防篡改）"""
        if len(self.events) < 2:
            return True
        try:
            for i in range(1, len(self.events)):
                prev = self.events[i - 1]
                curr = self.events[i]
                expected = curr.calculate_hash(prev.hash_chain)
                if expected != curr.hash_chain:
                    return False
            return True
        except:
            return False

    def get_alerts(self, acknowledged: bool = None, limit: int = 50) -> List[Dict[str, Any]]:
        """获取告警列表"""
        alert_file = os.path.join(self.data_dir, "alerts.json")
        if not os.path.exists(alert_file):
            return []
        try:
            with open(alert_file, 'r', encoding='utf-8') as f:
                alerts = json.load(f)
            if acknowledged is not None:
                alerts = [a for a in alerts if a.get("acknowledged", False) == acknowledged]
            return alerts[-limit:]
        except:
            return []

    def acknowledge_alert(self, event_id: str) -> bool:
        """确认告警"""
        alert_file = os.path.join(self.data_dir, "alerts.json")
        if not os.path.exists(alert_file):
            return False
        try:
            with open(alert_file, 'r', encoding='utf-8') as f:
                alerts = json.load(f)
            for alert in alerts:
                if alert.get("event_id") == event_id:
                    alert["acknowledged"] = True
                    alert["acknowledged_at"] = datetime.now().isoformat()
                    break
            with open(alert_file, 'w', encoding='utf-8') as f:
                json.dump(alerts, f, ensure_ascii=False, indent=2)
            return True
        except:
            return False

    def export_logs(self, format: str = "json",
                    start_time: str = None, end_time: str = None) -> str:
        """导出审计日志"""
        events = self.events
        if start_time:
            events = [e for e in events if e.timestamp >= start_time]
        if end_time:
            events = [e for e in events if e.timestamp <= end_time]

        export_file = os.path.join(self.data_dir, f"audit_export_{datetime.now().strftime('%Y%m%d_%H%M%S')}.{format}")

        if format == "json":
            with open(export_file, 'w', encoding='utf-8') as f:
                json.dump([e.to_dict() for e in events], f, ensure_ascii=False, indent=2, default=str)
        elif format == "csv":
            import csv
            with open(export_file, 'w', encoding='utf-8-sig', newline='') as f:
                writer = csv.writer(f)
                writer.writerow(["event_id", "timestamp", "action", "severity", "user_id",
                                 "username", "source_ip", "resource_type", "resource_id",
                                 "description", "result", "error_message", "duration_ms"])
                for e in events:
                    writer.writerow([e.event_id, e.timestamp, e.action, e.severity,
                                    e.user_id, e.username, e.source_ip, e.resource_type,
                                    e.resource_id, e.description, e.result, e.error_message,
                                    e.duration_ms])

        return export_file

    # ===== 便捷方法 =====
    def log_login(self, username: str, source_ip: str = "", success: bool = True,
                  user_agent: str = "", user_id: str = "") -> str:
        """记录登录事件"""
        action = "user.login" if success else "user.login_failed"
        severity = "info" if success else "medium"
        result = "success" if success else "failure"
        description = f"用户 {username} 登录{'成功' if success else '失败'}"
        return self.log_event(action=action, severity=severity, username=username,
                             user_id=user_id, source_ip=source_ip, user_agent=user_agent,
                             description=description, result=result)

    def log_scan(self, scan_type: str, target: str, username: str = "",
                 source_ip: str = "", result: str = "success",
                 vuln_count: int = 0, duration_ms: int = 0) -> str:
        """记录扫描事件"""
        action = "scan.complete" if result == "success" else "scan.failed"
        severity = "info" if result == "success" else "medium"
        description = f"{scan_type}扫描目标 {target}，发现 {vuln_count} 个漏洞"
        return self.log_event(action=action, severity=severity, username=username,
                             source_ip=source_ip, resource_type="scan", resource_id=target,
                             description=description, result=result, duration_ms=duration_ms,
                             details={"scan_type": scan_type, "target": target, "vuln_count": vuln_count})

    def log_vuln_exploit(self, vuln_id: str, target: str, username: str = "",
                         source_ip: str = "", success: bool = True) -> str:
        """记录漏洞利用事件"""
        severity = "high" if success else "medium"
        result = "success" if success else "failure"
        description = f"漏洞利用 {vuln_id} 目标 {target} {'成功' if success else '失败'}"
        return self.log_event(action="vuln.exploit", severity=severity, username=username,
                             source_ip=source_ip, resource_type="vulnerability", resource_id=vuln_id,
                             description=description, result=result,
                             details={"vuln_id": vuln_id, "target": target})

    def log_config_change(self, config_key: str, old_value: str, new_value: str,
                          username: str = "", source_ip: str = "") -> str:
        """记录配置变更"""
        description = f"配置 {config_key} 从 {old_value} 变更为 {new_value}"
        return self.log_event(action="config.change", severity="medium", username=username,
                             source_ip=source_ip, resource_type="config", resource_id=config_key,
                             description=description,
                             details={"old_value": old_value, "new_value": new_value})


# 全局实例
audit_logger = AuditLogger()
