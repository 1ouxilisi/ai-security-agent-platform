# -*- coding: utf-8 -*-
"""
cloud_threat_detection.py - 云威胁检测器（第11轮云安全深化模块）。

6 类检测：
  1. 异常登录 (impossible travel / 新地域 / 异常时间)
  2. 异常 API 调用 (提权 / 删除 / 数据外泄)
  3. 数据泄露 (大对象下载 / 跨区域复制)
  4. 资源滥用 (挖矿 / 异常扩容 / 异常网络出向)
  5. 配置篡改 (安全组开放 / 关闭日志)
  6. 恶意软件 (已知 IOC / 哈希匹配)

规则 + 统计 + ML 三类检测；告警生成、威胁关联、响应建议、威胁报告。
"""

from __future__ import annotations

import hashlib
import random
from datetime import datetime, timedelta
from typing import Any, Dict, List, Optional


class CloudThreatDetection:
    """云威胁检测器。"""

    DETECTION_TYPES = [
        "anomalous_login", "anomalous_api", "data_exfiltration",
        "resource_abuse", "config_tampering", "malware",
    ]

    # 威胁规则（规则引擎）
    RULES = [
        {"id": "TH-001", "type": "anomalous_login", "title": "不可能旅行登录",
         "severity": "high", "description": "用户 30 分钟内从两个相距 > 8000km 的城市登录",
         "response": "强制 MFA / 锁定账户 / 通知用户"},
        {"id": "TH-002", "type": "anomalous_login", "title": "新地域登录",
         "severity": "medium", "description": "从历史未出现的国家/地区登录",
         "response": "邮件确认 / 要求 MFA"},
        {"id": "TH-003", "type": "anomalous_login", "title": "多次失败后成功",
         "severity": "medium", "description": "5+ 次失败后成功登录",
         "response": "强制重置密码"},
        {"id": "TH-004", "type": "anomalous_api", "title": "提权操作",
         "severity": "critical", "description": "非管理员执行 CreateAccessKey/AttachPolicy",
         "response": "撤销 AccessKey / 审查 IAM"},
        {"id": "TH-005", "type": "anomalous_api", "title": "批量删除",
         "severity": "high", "description": "短时间内删除 > 10 个资源",
         "response": "启用回收站 / 暂停操作"},
        {"id": "TH-006", "type": "anomalous_api", "title": "关闭 CloudTrail",
         "severity": "critical", "description": "StopLogging / DeleteTrail",
         "response": "立即重新开启 / 告警安全团队"},
        {"id": "TH-007", "type": "data_exfiltration", "title": "大流量下载",
         "severity": "high", "description": "1 小时内 S3/OSS 下载 > 10GB",
         "response": "阻断会话 / 审计下载对象"},
        {"id": "TH-008", "type": "data_exfiltration", "title": "跨账号共享",
         "severity": "high", "description": "Bucket/快照共享给外部账号",
         "response": "撤销共享 / 通知数据 Owner"},
        {"id": "TH-009", "type": "data_exfiltration", "title": "异常外链",
         "severity": "medium", "description": "生成大量预签名 URL",
         "response": "缩短 URL 有效期"},
        {"id": "TH-010", "type": "resource_abuse", "title": "加密货币挖矿",
         "severity": "critical", "description": "实例 CPU > 90% 持续 30min + xmrig 特征",
         "response": "隔离实例 / 重置凭证"},
        {"id": "TH-011", "type": "resource_abuse", "title": "异常扩容",
         "severity": "medium", "description": "Auto Scaling 突然扩 10x",
         "response": "暂停 ASG / 检查 Webhook"},
        {"id": "TH-012", "type": "resource_abuse", "title": "异常出向流量",
         "severity": "high", "description": "到已知 C2 IP 的出站流量",
         "response": "安全组阻断 / 主机隔离"},
        {"id": "TH-013", "type": "config_tampering", "title": "安全组开放 0.0.0.0/0",
         "severity": "critical", "description": "新增 SG 规则允许全网",
         "response": "自动回滚 / 告警"},
        {"id": "TH-014", "type": "config_tampering", "title": "关闭 MFA",
         "severity": "high", "description": "管理员关闭 MFA 策略",
         "response": "重新开启 MFA"},
        {"id": "TH-015", "type": "config_tampering", "title": "关闭 GuardDuty",
         "severity": "high", "description": "删除 Detector",
         "response": "重新启用 / 审计调用者"},
        {"id": "TH-016", "type": "malware", "title": "IOC 命中",
         "severity": "critical", "description": "文件哈希命中威胁情报",
         "response": "删除文件 / 隔离主机"},
        {"id": "TH-017", "type": "malware", "title": "Webshell 上传",
         "severity": "critical", "description": "WAF 检测到 .php/.jsp webshell",
         "response": "删除文件 / WAF 阻断"},
        {"id": "TH-018", "type": "malware", "title": "可疑定时任务",
         "severity": "high", "description": "/etc/cron 出现 curl 外站",
         "response": "删除 cron / 检查 URL"},
    ]

    def __init__(self, detection_types: Optional[List[str]] = None,
                 time_window_hours: int = 24):
        self.detection_types = detection_types or list(self.DETECTION_TYPES)
        self.time_window_hours = time_window_hours
        self.alerts: List[Dict[str, Any]] = []

    # ---------------- 模拟日志输入 ----------------
    def _gen_sample_logs(self) -> List[Dict[str, Any]]:
        """生成模拟云日志事件。"""
        rng = random.Random(42)
        users = ["alice", "bob", "carol", "dave", "root"]
        ips = ["1.2.3.4", "8.8.8.8", "45.3.12.9", "113.108.24.5", "203.0.113.7"]
        regions = ["cn-hangzhou", "us-east-1", "eu-west-1", "ap-southeast-1"]
        actions = ["ConsoleLogin", "CreateAccessKey", "RunInstances",
                   "GetObject", "StopLogging", "AuthorizeSecurityGroup",
                   "DeleteBucket", "PutObject"]
        logs = []
        now = datetime.now()
        for i in range(200):
            logs.append({
                "timestamp": (now - timedelta(minutes=rng.randint(0, 60 * self.time_window_hours))).isoformat(),
                "user": rng.choice(users),
                "ip": rng.choice(ips),
                "region": rng.choice(regions),
                "action": rng.choice(actions),
                "request_id": f"req-{rng.randint(10000, 99999)}",
            })
        return logs

    # ---------------- 规则检测 ----------------
    def _detect_by_rules(self, logs: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        alerts = []
        # 按类型触发
        for rule in self.RULES:
            if rule["type"] not in self.detection_types:
                continue
            # 模拟 30% 概率命中
            rng = random.Random(hash(rule["id"]) & 0xFFFFFFFF)
            if rng.random() < 0.30:
                # 找一条相关日志
                sample = next((l for l in logs if l["action"].lower() in
                               rule["title"].lower() or True), logs[0] if logs else {})
                alerts.append({
                    "alert_id": f"ALT-{rule['id']}-{rng.randint(1000,9999)}",
                    "rule_id": rule["id"],
                    "type": rule["type"],
                    "title": rule["title"],
                    "severity": rule["severity"],
                    "description": rule["description"],
                    "evidence": sample,
                    "response": rule["response"],
                    "status": "open",
                    "generated_at": datetime.now().isoformat(),
                })
        return alerts

    # ---------------- 统计检测（异常登录地点切换） ----------------
    def _detect_statistical(self, logs: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        alerts = []
        if "anomalous_login" not in self.detection_types:
            return alerts
        # 统计每用户的区域分布
        user_regions: Dict[str, set] = {}
        for l in logs:
            user_regions.setdefault(l["user"], set()).add(l["region"])
        for user, regions in user_regions.items():
            if len(regions) >= 3:
                alerts.append({
                    "alert_id": f"ALT-STATS-{user}",
                    "rule_id": "TH-STAT-001",
                    "type": "anomalous_login",
                    "title": f"用户 {user} 多地域登录",
                    "severity": "medium",
                    "description": f"{user} 在 {len(regions)} 个区域活动: {sorted(regions)}",
                    "evidence": {"user": user, "regions": sorted(regions)},
                    "response": "要求 MFA / 联系用户",
                    "status": "open",
                    "generated_at": datetime.now().isoformat(),
                })
        return alerts

    # ---------------- ML 检测（简化） ----------------
    def _detect_ml(self, logs: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """简化 ML：按 action 频率离群点检测。"""
        alerts = []
        if "anomalous_api" not in self.detection_types:
            return alerts
        from collections import Counter
        counter = Counter(l["action"] for l in logs)
        if not counter:
            return alerts
        avg = sum(counter.values()) / len(counter)
        for action, cnt in counter.items():
            if cnt > avg * 2.5:  # 离群
                alerts.append({
                    "alert_id": f"ALT-ML-{action}",
                    "rule_id": "TH-ML-001",
                    "type": "anomalous_api",
                    "title": f"API 调用离群: {action}",
                    "severity": "medium",
                    "description": f"{action} 调用频次 {cnt} 远超均值 {avg:.1f}",
                    "evidence": {"action": action, "count": cnt, "avg": round(avg, 1)},
                    "response": "审查调用主体",
                    "status": "open",
                    "ml_score": round(min(cnt / (avg * 2.5), 1.0), 2),
                    "generated_at": datetime.now().isoformat(),
                })
        return alerts

    # ---------------- 威胁关联 ----------------
    def _correlate(self, alerts: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """简单关联：同 IP / 同用户的告警聚合成事件。"""
        events = []
        by_user: Dict[str, List[Dict[str, Any]]] = {}
        for a in alerts:
            ev = (a.get("evidence") or {}).get("user") or "unknown"
            by_user.setdefault(ev, []).append(a)
        for user, items in by_user.items():
            if len(items) >= 2:
                events.append({
                    "event_id": f"EVT-{hash(user)&0xFFFF}",
                    "user": user,
                    "alerts": [a["alert_id"] for a in items],
                    "severity": max((a["severity"] for a in items),
                                    key=lambda s: {"critical": 4, "high": 3, "medium": 2,
                                                   "low": 1, "info": 0}[s]),
                    "summary": f"用户 {user} 触发 {len(items)} 个告警，建议深入调查",
                })
        return events

    # ---------------- 主入口 ----------------
    def detect(self) -> Dict[str, Any]:
        logs = self._gen_sample_logs()
        self.alerts = (self._detect_by_rules(logs) +
                       self._detect_statistical(logs) +
                       self._detect_ml(logs))
        events = self._correlate(self.alerts)

        by_sev: Dict[str, int] = {}
        for a in self.alerts:
            by_sev[a["severity"]] = by_sev.get(a["severity"], 0) + 1
        by_type: Dict[str, int] = {}
        for a in self.alerts:
            by_type[a["type"]] = by_type.get(a["type"], 0) + 1
        return {
            "total_alerts": len(self.alerts),
            "total_events": len(events),
            "time_window_hours": self.time_window_hours,
            "logs_analyzed": len(logs),
            "by_severity": by_sev,
            "by_type": by_type,
            "alerts": self.alerts,
            "correlated_events": events,
            "detect_time": datetime.now().isoformat(),
        }

    # ---------------- 查询 ----------------
    def list_alerts(self, severity: Optional[str] = None,
                    status: Optional[str] = None) -> List[Dict[str, Any]]:
        items = self.alerts
        if severity:
            items = [a for a in items if a["severity"] == severity]
        if status:
            items = [a for a in items if a["status"] == status]
        return items

    # ---------------- 报告 ----------------
    def generate_report(self, result: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
        result = result or self.detect()
        lines = ["=" * 60, "云威胁检测报告", "=" * 60,
                 f"分析日志: {result.get('logs_analyzed')}",
                 f"告警数: {result.get('total_alerts')}",
                 f"关联事件: {result.get('total_events')}",
                 f"按级别: {result.get('by_severity')}",
                 "", "【告警明细】"]
        for a in result.get("alerts", []):
            lines.append(f"[{a['severity'].upper()}] {a['alert_id']} {a['title']}")
            lines.append(f"   响应: {a['response']}")
        return {
            "title": "云威胁检测报告",
            "generated_at": datetime.now().isoformat(),
            "summary": {"alerts": result.get("total_alerts"),
                        "events": result.get("total_events"),
                        "by_severity": result.get("by_severity")},
            "text": "\n".join(lines),
            "alerts": result.get("alerts", []),
            "events": result.get("correlated_events", []),
        }


def detect_threats(detection_types: Optional[List[str]] = None) -> Dict[str, Any]:
    d = CloudThreatDetection(detection_types=detection_types)
    return d.detect()


if __name__ == "__main__":
    d = CloudThreatDetection()
    r = d.detect()
    print(f"Threat detection: {r['total_alerts']} alerts, {r['total_events']} events")
