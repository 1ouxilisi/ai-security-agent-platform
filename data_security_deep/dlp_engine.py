#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
dlp_engine.py — DLP 数据防泄漏深度引擎（Round24 方向3）。

覆盖：
    1. 数据传输监控：网络流量/邮件/即时消息/文件传输/云上传/API传输
    2. 数据使用监控：数据库/文件/应用/终端/打印/截屏/复制粘贴
    3. 敏感数据检测：传输/使用内容检测，正则/指纹/ML/上下文
    4. 泄漏防护策略：按数据分级/用户角色/场景/目的地/时间/组合策略
    5. 防护动作：阻断/告警/加密/脱敏/水印/审批/隔离/删除/记录
    6. 泄漏事件管理：检测/告警/调查/处置/复盘/统计/趋势

设计定位：仅做检测、监控与策略模拟，不做真实网络阻断或数据删除。
"""

from __future__ import annotations

import hashlib
import re
import uuid
from datetime import datetime
from typing import Any, Dict, List, Optional


# DLP 策略预置
DLP_PROFILES: Dict[str, Dict[str, Any]] = {
    "strict": {
        "name": "严格模式", "desc": "阻断所有敏感数据外发，仅允许审批后放行",
        "default_action": "block", "alert_level": "critical",
    },
    "balanced": {
        "name": "均衡模式", "desc": "敏感数据外发自动脱敏+告警，非敏感放行",
        "default_action": "mask", "alert_level": "high",
    },
    "permissive": {
        "name": "宽松模式", "desc": "仅告警不阻断，记录所有敏感数据传输",
        "default_action": "log", "alert_level": "medium",
    },
}

PROTECTION_ACTIONS: Dict[str, Dict[str, Any]] = {
    "block": {"name": "阻断", "desc": "完全阻止数据传输/操作", "severity": "high"},
    "alert": {"name": "告警", "desc": "允许操作但触发告警通知", "severity": "medium"},
    "encrypt": {"name": "加密", "desc": "对传输内容自动加密", "severity": "medium"},
    "mask": {"name": "脱敏", "desc": "对敏感字段自动脱敏后放行", "severity": "low"},
    "watermark": {"name": "水印", "desc": "添加溯源水印后放行", "severity": "low"},
    "approval": {"name": "审批", "desc": "暂停操作等待人工审批", "severity": "high"},
    "isolate": {"name": "隔离", "desc": "将文件/数据隔离到安全区", "severity": "high"},
    "log": {"name": "记录", "desc": "仅记录不干预", "severity": "info"},
}

# 敏感数据指纹库（模拟：基于已知数据集的哈希指纹）
FINGERPRINT_DB: Dict[str, Dict[str, Any]] = {
    "FP-CUSTOMER-10K": {"name": "客户名单1万条", "type": "customer_list", "size": "10k rows"},
    "FP-EMPLOYEE-HR": {"name": "员工HR全量", "type": "hr_data", "size": "full"},
    "FP-FINANCE-Q2": {"name": "Q2财务报表", "type": "financial", "size": "quarterly"},
}

# 监控通道
MONITOR_CHANNELS: Dict[str, Dict[str, Any]] = {
    "network": {"name": "网络流量监控", "direction": "both", "protocol": "http/https/tcp"},
    "email": {"name": "邮件监控", "direction": "outbound", "protocol": "smtp/mapi"},
    "im": {"name": "即时消息监控", "direction": "outbound", "protocol": "wechat/teams/slack"},
    "file_transfer": {"name": "文件传输监控", "direction": "outbound", "protocol": "ftp/scp/sftp"},
    "cloud_upload": {"name": "云上传监控", "direction": "outbound", "protocol": "s3/oss/webdav"},
    "api_transfer": {"name": "API数据传输监控", "direction": "both", "protocol": "rest/graphql"},
}


class DLPEngineDeep:
    """DLP 数据防泄漏深度引擎"""

    def __init__(self) -> None:
        self.policies: Dict[str, Dict[str, Any]] = {}
        self.events: Dict[str, Dict[str, Any]] = {}
        self.monitoring_logs: List[Dict[str, Any]] = []
        self.violation_rules: List[Dict[str, Any]] = []
        self._init_default_policies()
        self._seed_sample_events()

    def _init_default_policies(self) -> None:
        self.policies = {
            "pol-001": {
                "policy_id": "pol-001", "name": "禁止外发客户身份证",
                "scope": "confidential", "trigger": "sensitive:id_card",
                "action": "block", "enabled": True, "priority": 100,
            },
            "pol-002": {
                "policy_id": "pol-002", "name": "外发财务数据脱敏",
                "scope": "financial", "trigger": "sensitive:bank_card",
                "action": "mask", "enabled": True, "priority": 80,
            },
            "pol-003": {
                "policy_id": "pol-003", "name": "U盘拷贝加水印",
                "scope": "file_transfer", "trigger": "channel:usb",
                "action": "watermark", "enabled": True, "priority": 50,
            },
            "pol-004": {
                "policy_id": "pol-004", "name": "非工作时间导出告警",
                "scope": "time", "trigger": "time:off_hours",
                "action": "alert", "enabled": True, "priority": 40,
            },
            "pol-005": {
                "policy_id": "pol-005", "name": "批量导出需审批",
                "scope": "volume", "trigger": "volume:gt_1000_rows",
                "action": "approval", "enabled": True, "priority": 90,
            },
        }

    def _seed_sample_events(self) -> None:
        samples = [
            {"type": "block", "channel": "email", "user": "zhangsan",
             "detail": "外发邮件附件含身份证号", "severity": "high"},
            {"type": "mask", "channel": "im", "user": "lisi",
             "detail": "即时消息中手机号已自动脱敏", "severity": "medium"},
            {"type": "alert", "channel": "network", "user": "wangwu",
             "detail": "非工作时间大量数据库查询", "severity": "high"},
        ]
        for s in samples:
            eid = f"event-{uuid.uuid4().hex[:10]}"
            self.events[eid] = {
                "event_id": eid, "status": "open",
                "detected_at": datetime.now().isoformat(timespec="seconds"),
                **s,
            }

    # ---------- 1. 数据传输监控 ----------
    def monitor_transfer(self, channel: str, content: str, user: str = "",
                        destination: str = "") -> Dict[str, Any]:
        """监控一次数据传输，检测敏感数据并执行策略"""
        try:
            # 检测敏感内容
            detections = self._detect_content(content)
            triggered_policies = []
            action_taken = "log"
            # 匹配策略
            for pol in self.policies.values():
                if not pol.get("enabled", True):
                    continue
                trig = pol.get("trigger", "")
                if trig.startswith("sensitive:"):
                    stype = trig.split(":", 1)[1]
                    if any(d["type"] == stype for d in detections):
                        triggered_policies.append(pol["name"])
                        action_taken = pol["action"]
                elif trig == "channel:usb" and channel == "file_transfer":
                    triggered_policies.append(pol["name"])
                    action_taken = pol["action"]
            # 记录事件
            event_id = f"event-{uuid.uuid4().hex[:10]}"
            event = {
                "event_id": event_id, "channel": channel, "user": user,
                "destination": destination, "content_length": len(content),
                "detections": len(detections), "triggered_policies": triggered_policies,
                "action": action_taken,
                "detected_at": datetime.now().isoformat(timespec="seconds"),
                "status": "open" if action_taken in ("block", "approval") else "auto_handled",
            }
            self.events[event_id] = event
            self.monitoring_logs.append(event)
            return {
                "event_id": event_id, "action": action_taken,
                "triggered_policies": triggered_policies,
                "detections": detections,
                "protection_action": PROTECTION_ACTIONS.get(action_taken, {}).get("name", action_taken),
            }
        except Exception as e:
            return {"error": str(e)}

    def _detect_content(self, content: str) -> List[Dict[str, Any]]:
        """内容检测：正则+指纹"""
        detections = []
        patterns = {
            "id_card": r"\b[1-9]\d{5}(18|19|20)\d{2}(0[1-9]|1[0-2])(0[1-9]|[12]\d|3[01])\d{3}[\dXx]\b",
            "mobile_phone": r"\b1[3-9]\d{9}\b",
            "bank_card": r"\b[1-9]\d{14,18}\b",
            "email": r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b",
        }
        for ptype, pat in patterns.items():
            for m in re.finditer(pat, content):
                detections.append({
                    "type": ptype, "method": "regex",
                    "match_preview": m.group(0)[:3] + "***",
                })
        # 指纹匹配（模拟）
        content_hash = hashlib.md5(content.encode()).hexdigest()[:12]
        for fp_id, fp_info in FINGERPRINT_DB.items():
            if content_hash[:6] in fp_id.lower():
                detections.append({
                    "type": "fingerprint_match", "method": "fingerprint",
                    "fingerprint_id": fp_id, "name": fp_info["name"],
                })
        return detections

    # ---------- 2. 数据使用监控 ----------
    def monitor_usage(self, usage_type: str, user: str,
                     resource: str, operation: str = "read",
                     data_volume: int = 0) -> Dict[str, Any]:
        """监控数据使用行为"""
        usage_types = ["database", "file", "application", "terminal",
                       "print", "screenshot", "copy_paste"]
        if usage_type not in usage_types:
            return {"error": f"不支持的监控类型: {usage_type}"}
        # 异常检测：大批量导出
        anomaly = False
        reasons = []
        if data_volume > 10000:
            anomaly = True
            reasons.append(f"数据量过大({data_volume}条)")
        if operation == "export" and user == "anonymous":
            anomaly = True
            reasons.append("匿名用户导出")
        record = {
            "usage_id": f"usage-{uuid.uuid4().hex[:10]}",
            "usage_type": usage_type, "user": user,
            "resource": resource, "operation": operation,
            "data_volume": data_volume, "anomaly": anomaly,
            "anomaly_reasons": reasons,
            "recorded_at": datetime.now().isoformat(timespec="seconds"),
        }
        self.monitoring_logs.append(record)
        if anomaly:
            eid = f"event-{uuid.uuid4().hex[:10]}"
            self.events[eid] = {
                "event_id": eid, "type": "anomaly_usage",
                "channel": usage_type, "user": user,
                "detail": "; ".join(reasons), "severity": "high",
                "detected_at": datetime.now().isoformat(timespec="seconds"),
                "status": "open",
            }
        return record

    # ---------- 3. 策略管理 ----------
    def list_policies(self) -> List[Dict[str, Any]]:
        return list(self.policies.values())

    def create_policy(self, name: str, scope: str, trigger: str,
                     action: str, priority: int = 50) -> Dict[str, Any]:
        pid = f"pol-{uuid.uuid4().hex[:8]}"
        self.policies[pid] = {
            "policy_id": pid, "name": name, "scope": scope,
            "trigger": trigger, "action": action,
            "priority": priority, "enabled": True,
            "created_at": datetime.now().isoformat(timespec="seconds"),
        }
        return {"policy_id": pid, "created": True}

    def update_policy(self, policy_id: str, updates: Dict[str, Any]) -> Dict[str, Any]:
        if policy_id not in self.policies:
            return {"error": "策略不存在"}
        self.policies[policy_id].update(updates)
        return {"policy_id": policy_id, "updated": True}

    def toggle_policy(self, policy_id: str) -> Dict[str, Any]:
        if policy_id not in self.policies:
            return {"error": "策略不存在"}
        self.policies[policy_id]["enabled"] = not self.policies[policy_id]["enabled"]
        return {"policy_id": policy_id,
                "enabled": self.policies[policy_id]["enabled"]}

    # ---------- 4. 泄漏事件管理 ----------
    def list_events(self, status: Optional[str] = None,
                   severity: Optional[str] = None,
                   channel: Optional[str] = None) -> List[Dict[str, Any]]:
        items = list(self.events.values())
        if status:
            items = [e for e in items if e.get("status") == status]
        if severity:
            items = [e for e in items if e.get("severity") == severity]
        if channel:
            items = [e for e in items if e.get("channel") == channel]
        return items

    def get_event_detail(self, event_id: str) -> Dict[str, Any]:
        return self.events.get(event_id, {"error": "事件不存在"})

    def handle_event(self, event_id: str, action: str,
                    handler: str = "", note: str = "") -> Dict[str, Any]:
        if event_id not in self.events:
            return {"error": "事件不存在"}
        self.events[event_id]["status"] = "handled"
        self.events[event_id]["resolution"] = action
        self.events[event_id]["handler"] = handler
        self.events[event_id]["note"] = note
        self.events[event_id]["handled_at"] = datetime.now().isoformat(timespec="seconds")
        return {"event_id": event_id, "status": "handled", "action": action}

    def event_statistics(self) -> Dict[str, Any]:
        total = len(self.events)
        by_status: Dict[str, int] = {}
        by_severity: Dict[str, int] = {}
        by_channel: Dict[str, int] = {}
        for e in self.events.values():
            s = e.get("status", "unknown")
            by_status[s] = by_status.get(s, 0) + 1
            sev = e.get("severity", "unknown")
            by_severity[sev] = by_severity.get(sev, 0) + 1
            ch = e.get("channel", "unknown")
            by_channel[ch] = by_channel.get(ch, 0) + 1
        return {
            "total_events": total,
            "by_status": by_status, "by_severity": by_severity,
            "by_channel": by_channel,
            "open_events": by_status.get("open", 0),
            "handled_events": by_status.get("handled", 0),
        }

    def event_trend(self, days: int = 7) -> List[Dict[str, Any]]:
        """事件趋势（模拟）"""
        trend = []
        for i in range(days):
            trend.append({
                "day": f"D-{days - i}",
                "blocked": 5 + i * 2,
                "alerted": 8 + i,
                "masked": 12 + i * 3,
                "total": 25 + i * 6,
            })
        return trend

    # ---------- 5. 防护动作库 ----------
    def get_actions_library(self) -> Dict[str, Any]:
        return PROTECTION_ACTIONS

    def get_profiles(self) -> Dict[str, Any]:
        return DLP_PROFILES

    def get_channels(self) -> Dict[str, Any]:
        return MONITOR_CHANNELS

    # ---------- 6. 统计 ----------
    def stats(self) -> Dict[str, Any]:
        return {
            "policies_total": len(self.policies),
            "policies_enabled": sum(1 for p in self.policies.values() if p.get("enabled")),
            "events_total": len(self.events),
            "open_events": sum(1 for e in self.events.values() if e.get("status") == "open"),
            "logs_recorded": len(self.monitoring_logs),
            "profiles": len(DLP_PROFILES),
            "actions": len(PROTECTION_ACTIONS),
            "channels": len(MONITOR_CHANNELS),
        }


_instance: Optional[DLPEngineDeep] = None


def get_dlp_engine() -> DLPEngineDeep:
    global _instance
    if _instance is None:
        _instance = DLPEngineDeep()
    return _instance
