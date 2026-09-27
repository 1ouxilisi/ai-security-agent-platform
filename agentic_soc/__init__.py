#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Agentic SOC 威胁狩猎引擎（Agentic Security Operations Center）

对标 Black Hat USA 2026 "Agentic SOC" 核心主题：
- AI驱动的安全运营中心
- 自主威胁狩猎
- 日志分析与异常检测
- 威胁情报关联
- 自动告警与响应

核心能力：
- 多源日志收集与解析（Web/系统/网络/认证日志）
- Sigma规则检测引擎
- 异常行为基线检测
- 威胁情报IOC匹配
- 自动事件分级与响应建议
- 狩猎查询生成
"""

import re
import json
import time
import hashlib
from typing import Dict, List, Optional, Any, Tuple
from dataclasses import dataclass, field
from enum import Enum
from collections import Counter, defaultdict
from datetime import datetime, timedelta


class Severity(Enum):
    """事件严重程度"""
    INFO = "info"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class EventStatus(Enum):
    """事件状态"""
    NEW = "new"
    INVESTIGATING = "investigating"
    CONFIRMED = "confirmed"
    FALSE_POSITIVE = "false_positive"
    RESOLVED = "resolved"


@dataclass
class LogEntry:
    """日志条目"""
    timestamp: float
    source: str  # web/system/network/auth/app
    raw: str
    parsed: Dict = field(default_factory=dict)
    ip: str = ""
    user: str = ""
    action: str = ""
    status: str = ""


@dataclass
class SecurityEvent:
    """安全事件"""
    event_id: str
    timestamp: float
    title: str
    description: str
    severity: str
    source: str
    raw_logs: List[str] = field(default_factory=list)
    iocs: List[str] = field(default_factory=list)
    mitre_techniques: List[str] = field(default_factory=list)
    status: str = "new"
    assignee: str = ""
    recommendation: str = ""
    score: float = 0.0


@dataclass
class ThreatIntel:
    """威胁情报"""
    ioc: str
    ioc_type: str  # ip/domain/hash/url
    threat_type: str  # malware/c2/phishing/scanner
    source: str
    first_seen: float = 0
    last_seen: float = 0
    confidence: float = 0.0


class SigmaRuleEngine:
    """
    Sigma规则检测引擎

    支持Sigma格式的检测规则，用于日志分析。
    """

    def __init__(self):
        self.rules: List[Dict] = self._load_builtin_rules()

    def _load_builtin_rules(self) -> List[Dict]:
        """加载内置Sigma规则"""
        return [
            {
                "id": "SIG-001",
                "title": "SQL注入尝试",
                "severity": "high",
                "logsource": {"category": "web"},
                "detection": {
                    "keywords": ["union select", "or 1=1", "' or '", "sleep(", "benchmark("],
                },
                "mitre": ["T1190"],
            },
            {
                "id": "SIG-002",
                "title": "XSS攻击尝试",
                "severity": "medium",
                "logsource": {"category": "web"},
                "detection": {
                    "keywords": ["<script>", "javascript:", "onerror=", "onload=", "alert("],
                },
                "mitre": ["T1190"],
            },
            {
                "id": "SIG-003",
                "title": "路径遍历尝试",
                "severity": "medium",
                "logsource": {"category": "web"},
                "detection": {
                    "keywords": ["../", "..\\", "%2e%2e", "/etc/passwd", "c:\\windows"],
                },
                "mitre": ["T1190"],
            },
            {
                "id": "SIG-004",
                "title": "暴力破解登录",
                "severity": "high",
                "logsource": {"category": "auth"},
                "detection": {
                    "condition": "failed_login_count > 5 in 60s",
                },
                "mitre": ["T1110"],
            },
            {
                "id": "SIG-005",
                "title": "异常用户代理扫描器",
                "severity": "low",
                "logsource": {"category": "web"},
                "detection": {
                    "keywords": ["sqlmap", "nikto", "nmap", "acunetix", "nessus", "burp"],
                },
                "mitre": ["T1595"],
            },
            {
                "id": "SIG-006",
                "title": "敏感文件访问",
                "severity": "medium",
                "logsource": {"category": "web"},
                "detection": {
                    "keywords": [".env", "wp-config", "config.php", "id_rsa", ".git/", "web.config"],
                },
                "mitre": ["T1083"],
            },
            {
                "id": "SIG-007",
                "title": "命令注入尝试",
                "severity": "high",
                "logsource": {"category": "web"},
                "detection": {
                    "keywords": [";ls", "|whoami", "&&id", "$(whoami)", "`id`"],
                },
                "mitre": ["T1059"],
            },
            {
                "id": "SIG-008",
                "title": "SSRF尝试",
                "severity": "high",
                "logsource": {"category": "web"},
                "detection": {
                    "keywords": ["169.254.169.254", "metadata.google", "100.100.100.200"],
                },
                "mitre": ["T1190"],
            },
            {
                "id": "SIG-009",
                "title": "异常出站连接",
                "severity": "medium",
                "logsource": {"category": "network"},
                "detection": {
                    "keywords": ["port 4444", "port 31337", "reverse shell"],
                },
                "mitre": ["T1071"],
            },
            {
                "id": "SIG-010",
                "title": "权限提升尝试",
                "severity": "high",
                "logsource": {"category": "system"},
                "detection": {
                    "keywords": ["sudo ", "su root", "runas", "setuid", "chmod 4755"],
                },
                "mitre": ["T1068"],
            },
        ]

    def match(self, log: LogEntry) -> List[Dict]:
        """匹配日志 against 规则"""
        matched = []
        text = log.raw.lower()

        for rule in self.rules:
            # 检查日志来源
            if rule["logsource"]["category"] != log.source:
                continue

            # 关键词匹配
            if "keywords" in rule["detection"]:
                for kw in rule["detection"]["keywords"]:
                    if kw.lower() in text:
                        matched.append({
                            "rule_id": rule["id"],
                            "title": rule["title"],
                            "severity": rule["severity"],
                            "matched_keyword": kw,
                            "mitre": rule.get("mitre", []),
                        })
                        break

        return matched


class AnomalyDetector:
    """
    异常行为检测器

    基于统计基线的异常检测：
    - 登录频率异常
    - 请求量异常
    - 错误率异常
    - 时间异常
    - IP地理异常
    """

    def __init__(self):
        self.baselines: Dict[str, Dict] = {}
        self.window_size = 300  # 5分钟窗口

    def update_baseline(self, key: str, value: float):
        """更新基线"""
        if key not in self.baselines:
            self.baselines[key] = {"values": [], "mean": 0, "std": 0, "count": 0}

        b = self.baselines[key]
        b["values"].append(value)
        if len(b["values"]) > 100:
            b["values"].pop(0)
        b["count"] = len(b["values"])
        if b["count"] > 1:
            b["mean"] = sum(b["values"]) / b["count"]
            variance = sum((v - b["mean"]) ** 2 for v in b["values"]) / b["count"]
            b["std"] = variance ** 0.5

    def detect_anomaly(self, key: str, value: float) -> Dict:
        """检测异常"""
        if key not in self.baselines or self.baselines[key]["count"] < 5:
            return {"is_anomaly": False, "reason": "insufficient_data"}

        b = self.baselines[key]
        if b["std"] == 0:
            return {"is_anomaly": value != b["mean"], "reason": "zero_std"}

        z_score = abs(value - b["mean"]) / b["std"]
        is_anomaly = z_score > 3.0  # 3σ

        return {
            "is_anomaly": is_anomaly,
            "z_score": round(z_score, 2),
            "baseline_mean": round(b["mean"], 2),
            "baseline_std": round(b["std"], 2),
            "current_value": value,
            "deviation": f"{round((value - b['mean']) / b['mean'] * 100, 1)}%" if b["mean"] else "N/A",
        }


class ThreatIntelDB:
    """威胁情报数据库"""

    def __init__(self):
        self.indicators: List[ThreatIntel] = self._load_builtin_iocs()

    def _load_builtin_iocs(self) -> List[ThreatIntel]:
        """加载内置IOC（示例数据）"""
        return [
            ThreatIntel(ioc="192.168.1.100", ioc_type="ip", threat_type="scanner",
                        source="internal", confidence=0.8),
            ThreatIntel(ioc="evil.com", ioc_type="domain", threat_type="c2",
                        source="community", confidence=0.9),
            ThreatIntel(ioc="malware.exe", ioc_type="hash", threat_type="malware",
                        source="virustotal", confidence=0.95),
            ThreatIntel(ioc="http://phish.example.com/login", ioc_type="url",
                        threat_type="phishing", source="openphish", confidence=0.85),
        ]

    def match(self, value: str) -> Optional[ThreatIntel]:
        """匹配IOC"""
        for ioc in self.indicators:
            if ioc.ioc.lower() in value.lower():
                return ioc
        return None

    def add_ioc(self, ioc: str, ioc_type: str, threat_type: str,
                source: str, confidence: float = 0.7):
        """添加IOC"""
        self.indicators.append(ThreatIntel(
            ioc=ioc, ioc_type=ioc_type, threat_type=threat_type,
            source=source, confidence=confidence,
            first_seen=time.time(), last_seen=time.time(),
        ))


class AgenticSOC:
    """
    Agentic SOC 威胁狩猎引擎（主类）

    整合日志分析 + Sigma规则 + 异常检测 + 威胁情报，提供完整的安全运营能力。
    """

    def __init__(self):
        self.sigma_engine = SigmaRuleEngine()
        self.anomaly_detector = AnomalyDetector()
        self.threat_intel = ThreatIntelDB()
        self.events: List[SecurityEvent] = []
        self.log_buffer: List[LogEntry] = []
        self.hunting_queries: List[Dict] = self._generate_hunting_queries()

    def ingest_log(self, raw_log: str, source: str = "web") -> List[SecurityEvent]:
        """
        摄入并分析单条日志

        Returns:
            触发的安全事件列表
        """
        log = self._parse_log(raw_log, source)
        self.log_buffer.append(log)
        if len(self.log_buffer) > 10000:
            self.log_buffer.pop(0)

        new_events = []

        # 1. Sigma规则匹配
        sigma_matches = self.sigma_engine.match(log)
        for match in sigma_matches:
            event = self._create_event(
                title=match["title"],
                description=f"Sigma规则 {match['rule_id']} 匹配: {match['matched_keyword']}",
                severity=match["severity"],
                source=source,
                raw_logs=[raw_log],
                mitre=match["mitre"],
                iocs=[log.ip] if log.ip else [],
            )
            new_events.append(event)

        # 2. 威胁情报匹配
        if log.ip:
            ti_match = self.threat_intel.match(log.ip)
            if ti_match:
                event = self._create_event(
                    title=f"威胁情报匹配: {ti_match.threat_type}",
                    description=f"IP {log.ip} 匹配威胁情报 ({ti_match.source}), 置信度 {ti_match.confidence}",
                    severity="high" if ti_match.confidence > 0.8 else "medium",
                    source="threat_intel",
                    raw_logs=[raw_log],
                    iocs=[log.ip, ti_match.ioc],
                )
                new_events.append(event)

        # 3. 异常检测（基于IP的请求频率）
        if log.ip:
            self.anomaly_detector.update_baseline(f"req_rate_{log.ip}", 1)
            # 简化：统计该IP最近请求数
            recent = [l for l in self.log_buffer[-100:]
                      if l.ip == log.ip and time.time() - l.timestamp < 60]
            if len(recent) > 50:
                anomaly = self.anomaly_detector.detect_anomaly(f"req_rate_{log.ip}", len(recent))
                if anomaly.get("is_anomaly"):
                    event = self._create_event(
                        title="异常请求频率",
                        description=f"IP {log.ip} 请求频率异常: {len(recent)}/分钟 (基线 {anomaly.get('baseline_mean', '?')})",
                        severity="medium",
                        source="anomaly",
                        raw_logs=[raw_log],
                        iocs=[log.ip],
                    )
                    new_events.append(event)

        return new_events

    def ingest_logs_batch(self, logs: List[str], source: str = "web") -> Dict:
        """批量摄入日志"""
        all_events = []
        for log in logs:
            events = self.ingest_log(log, source)
            all_events.extend(events)

        return {
            "logs_processed": len(logs),
            "events_triggered": len(all_events),
            "events": [self._event_to_dict(e) for e in all_events],
            "by_severity": dict(Counter(e.severity for e in all_events)),
        }

    def run_hunt(self, query_type: str = "all", target: str = "") -> Dict:
        """
        执行威胁狩猎查询

        Args:
            query_type: 狩猎类型 (all/web/auth/network/anomaly/ioc)
            target: 目标IP/用户
        """
        results = {
            "query_type": query_type,
            "target": target,
            "timestamp": time.time(),
            "findings": [],
            "summary": "",
        }

        # 分析日志缓冲区
        recent_logs = self.log_buffer[-500:]

        if query_type in ["all", "web"]:
            # Web攻击狩猎
            web_attacks = self._hunt_web_attacks(recent_logs, target)
            results["findings"].extend(web_attacks)

        if query_type in ["all", "auth"]:
            # 认证异常狩猎
            auth_anomalies = self._hunt_auth_anomalies(recent_logs, target)
            results["findings"].extend(auth_anomalies)

        if query_type in ["all", "ioc"]:
            # IOC狩猎
            ioc_hits = self._hunt_ioc(recent_logs, target)
            results["findings"].extend(ioc_hits)

        if query_type in ["all", "anomaly"]:
            # 异常狩猎
            anomalies = self._hunt_anomalies(recent_logs, target)
            results["findings"].extend(anomalies)

        results["total_findings"] = len(results["findings"])
        results["by_severity"] = dict(Counter(
            f.get("severity", "info") for f in results["findings"]
        ))
        results["summary"] = (
            f"狩猎完成: 分析 {len(recent_logs)} 条日志, "
            f"发现 {len(results['findings'])} 个可疑项"
        )

        return results

    def generate_hunt_query(self, hypothesis: str) -> Dict:
        """
        基于假设生成狩猎查询（AI辅助）

        Args:
            hypothesis: 狩猎假设，如"攻击者可能通过SQL注入获取数据"
        """
        # 规则模拟AI生成
        query = {
            "hypothesis": hypothesis,
            "generated_at": time.time(),
            "data_sources": [],
            "search_terms": [],
            "time_range": "last_24h",
            "false_positive_risk": "medium",
        }

        hypothesis_lower = hypothesis.lower()
        if any(kw in hypothesis_lower for kw in ["sql", "注入", "injection"]):
            query["data_sources"] = ["web_logs", "database_logs"]
            query["search_terms"] = ["union select", "or 1=1", "sleep(", "information_schema"]
        elif any(kw in hypothesis_lower for kw in ["xss", "跨站"]):
            query["data_sources"] = ["web_logs"]
            query["search_terms"] = ["<script>", "javascript:", "onerror="]
        elif any(kw in hypothesis_lower for kw in ["暴力", "brute", "登录"]):
            query["data_sources"] = ["auth_logs"]
            query["search_terms"] = ["failed login", "401", "403"]
        elif any(kw in hypothesis_lower for kw in ["横向", "lateral", "内网"]):
            query["data_sources"] = ["network_logs", "auth_logs"]
            query["search_terms"] = ["smb", "winrm", "psexec", "wmi"]
        else:
            query["data_sources"] = ["all_logs"]
            query["search_terms"] = ["error", "denied", "unauthorized"]

        return query

    def get_dashboard(self) -> Dict:
        """获取SOC仪表盘数据"""
        recent_events = [e for e in self.events if time.time() - e.timestamp < 86400]
        return {
            "total_events": len(self.events),
            "events_24h": len(recent_events),
            "open_events": sum(1 for e in self.events if e.status == "new"),
            "by_severity": dict(Counter(e.severity for e in recent_events)),
            "by_status": dict(Counter(e.status for e in self.events)),
            "top_sources": dict(Counter(e.source for e in recent_events).most_common(5)),
            "logs_in_buffer": len(self.log_buffer),
            "sigma_rules": len(self.sigma_engine.rules),
            "ioc_count": len(self.threat_intel.indicators),
            "hunting_queries": len(self.hunting_queries),
        }

    def _parse_log(self, raw: str, source: str) -> LogEntry:
        """解析日志"""
        log = LogEntry(timestamp=time.time(), source=source, raw=raw)

        # 提取IP
        ip_match = re.search(r'\b(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\b', raw)
        if ip_match:
            log.ip = ip_match.group(1)

        # 提取用户
        user_match = re.search(r'user[=:]\s*["\']?(\w+)', raw, re.IGNORECASE)
        if user_match:
            log.user = user_match.group(1)

        # 提取状态码
        status_match = re.search(r'\b(200|301|302|400|401|403|404|500|502|503)\b', raw)
        if status_match:
            log.status = status_match.group(1)

        return log

    def _create_event(self, title, description, severity, source,
                      raw_logs=None, mitre=None, iocs=None) -> SecurityEvent:
        """创建安全事件"""
        event = SecurityEvent(
            event_id=hashlib.md5(f"{title}{time.time()}".encode()).hexdigest()[:12],
            timestamp=time.time(),
            title=title,
            description=description,
            severity=severity,
            source=source,
            raw_logs=raw_logs or [],
            mitre_techniques=mitre or [],
            iocs=iocs or [],
            recommendation=self._get_recommendation(severity, title),
        )
        self.events.append(event)
        return event

    def _get_recommendation(self, severity: str, title: str) -> str:
        """获取响应建议"""
        recs = {
            "critical": "立即响应：隔离受影响系统，启动应急响应流程，通知安全团队",
            "high": "优先处理：调查事件详情，验证是否为真实攻击，采取遏制措施",
            "medium": "尽快调查：分析相关日志，确认攻击范围，修复漏洞",
            "low": "记录观察：监控后续行为，纳入定期审查",
            "info": "信息记录：无需立即行动",
        }
        return recs.get(severity, "调查确认")

    def _event_to_dict(self, event: SecurityEvent) -> Dict:
        return {
            "event_id": event.event_id,
            "timestamp": event.timestamp,
            "title": event.title,
            "description": event.description,
            "severity": event.severity,
            "source": event.source,
            "status": event.status,
            "iocs": event.iocs,
            "mitre": event.mitre_techniques,
            "recommendation": event.recommendation,
        }

    def _hunt_web_attacks(self, logs, target):
        findings = []
        attack_patterns = {
            "SQL注入": ["union select", "or 1=1", "sleep("],
            "XSS": ["<script>", "javascript:"],
            "路径遍历": ["../", "/etc/passwd"],
            "命令注入": [";ls", "|whoami"],
        }
        for attack_type, patterns in attack_patterns.items():
            hits = [l for l in logs if any(p in l.raw.lower() for p in patterns)
                    if (not target or target in l.raw)]
            if hits:
                findings.append({
                    "type": attack_type,
                    "count": len(hits),
                    "severity": "high",
                    "sample_logs": [l.raw[:100] for l in hits[:3]],
                    "source_ips": list(set(l.ip for l in hits if l.ip)),
                })
        return findings

    def _hunt_auth_anomalies(self, logs, target):
        findings = []
        failed_logins = [l for l in logs if "401" in l.status or "failed" in l.raw.lower()]
        if failed_logins:
            by_ip = Counter(l.ip for l in failed_logins if l.ip)
            for ip, count in by_ip.most_common(5):
                if count > 5:
                    findings.append({
                        "type": "暴力破解嫌疑",
                        "ip": ip,
                        "failed_count": count,
                        "severity": "high",
                    })
        return findings

    def _hunt_ioc(self, logs, target):
        findings = []
        for log in logs:
            if log.ip:
                ti = self.threat_intel.match(log.ip)
                if ti and (not target or target in log.raw):
                    findings.append({
                        "type": "IOC匹配",
                        "ioc": ti.ioc,
                        "threat_type": ti.threat_type,
                        "confidence": ti.confidence,
                        "severity": "high",
                    })
        return findings

    def _hunt_anomalies(self, logs, target):
        findings = []
        # 错误率异常
        errors = [l for l in logs if l.status in ["400", "401", "403", "404", "500"]]
        if logs and len(errors) / len(logs) > 0.3:
            findings.append({
                "type": "高错误率",
                "error_rate": f"{len(errors)/len(logs)*100:.1f}%",
                "severity": "medium",
            })
        return findings

    def _generate_hunting_queries(self) -> List[Dict]:
        """生成内置狩猎查询"""
        return [
            {"id": "HQ-001", "name": "初始访问狩猎", "hypothesis": "攻击者通过Web漏洞获取初始访问",
             "data_sources": ["web_logs"], "severity": "high"},
            {"id": "HQ-002", "name": "凭证访问狩猎", "hypothesis": "攻击者尝试窃取用户凭证",
             "data_sources": ["auth_logs", "system_logs"], "severity": "high"},
            {"id": "HQ-003", "name": "横向移动狩猎", "hypothesis": "攻击者在内网横向移动",
             "data_sources": ["network_logs", "auth_logs"], "severity": "critical"},
            {"id": "HQ-004", "name": "数据渗出狩猎", "hypothesis": "攻击者正在渗出敏感数据",
             "data_sources": ["network_logs", "proxy_logs"], "severity": "critical"},
            {"id": "HQ-005", "name": "持久化狩猎", "hypothesis": "攻击者建立持久化机制",
             "data_sources": ["system_logs", "registry_logs"], "severity": "high"},
        ]


# 单例模式
_soc_instance: Optional[AgenticSOC] = None

def get_agentic_soc() -> AgenticSOC:
    """获取全局Agentic SOC实例"""
    global _soc_instance
    if _soc_instance is None:
        _soc_instance = AgenticSOC()
    return _soc_instance
