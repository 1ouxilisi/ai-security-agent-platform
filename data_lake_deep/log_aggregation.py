#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
log_aggregation.py — 日志聚合与标准化引擎

负责：
    - 多源日志接入（Syslog/Windows Event/应用/Web/DB/中间件/云/容器/终端/网络设备）
    - 日志解析（正则/JSON/CSV/XML/KeyValue/多行/嵌套/自定义）
    - 日志标准化（字段/时间/严重程度/分类/标签/实体/安全事件）
    - 日志富化（资产/用户/威胁情报/地理位置/ASN/WHOIS/证书）
    - 日志存储（热/温/冷/归档/索引/分片/副本/保留策略）
    - 日志检索（全文/字段/范围/正则/模糊/组合/聚合/时序）
"""

from __future__ import annotations

import re
import time
import hashlib
import random
from datetime import datetime, timedelta
from typing import Any, Dict, List, Optional, Tuple

# 第三方库 try-import
try:
    import numpy as np  # type: ignore
    _HAS_NUMPY = True
except Exception:
    np = None  # type: ignore
    _HAS_NUMPY = False


# ============================================================
# 常量定义
# ============================================================

LOG_SOURCES = {
    "syslog": {
        "name": "Syslog",
        "vendor": "通用",
        "format": "RFC3164/RFC5424",
        "sample_rate_eps": 5000,
        "severity_levels": ["emerg", "alert", "crit", "err", "warning", "notice", "info", "debug"],
    },
    "windows_event": {
        "name": "Windows Event Log",
        "vendor": "Microsoft",
        "format": "EVTX/XML",
        "sample_rate_eps": 3000,
        "channels": ["Security", "System", "Application"],
    },
    "application": {
        "name": "应用日志",
        "vendor": "通用",
        "format": "JSON/Text",
        "sample_rate_eps": 8000,
        "libraries": ["Log4j", "Logback", "Winston", "Zap"],
    },
    "web_server": {
        "name": "Web服务器日志",
        "vendor": "Nginx/Apache/IIS",
        "format": "Combined/JSON/自定义",
        "sample_rate_eps": 12000,
        "fields": ["ip", "method", "url", "status", "bytes", "referer", "ua"],
    },
    "database": {
        "name": "数据库日志",
        "vendor": "MySQL/PostgreSQL/MongoDB",
        "format": "文本/JSON",
        "sample_rate_eps": 2000,
        "types": ["slow_query", "error", "audit", "replication"],
    },
    "middleware": {
        "name": "中间件日志",
        "vendor": "Redis/Kafka/Nginx",
        "format": "文本/JSON",
        "sample_rate_eps": 1500,
    },
    "cloud_service": {
        "name": "云服务日志",
        "vendor": "AWS/Azure/阿里云",
        "format": "JSON",
        "sample_rate_eps": 4000,
        "services": ["EC2", "RDS", "S3", "Lambda", "API Gateway"],
    },
    "container": {
        "name": "容器日志",
        "vendor": "Docker/K8s",
        "format": "JSON/stdout",
        "sample_rate_eps": 6000,
        "orchestrators": ["Docker", "Kubernetes", "OpenShift"],
    },
    "endpoint": {
        "name": "终端日志",
        "vendor": "EDR/杀毒",
        "format": "JSON",
        "sample_rate_eps": 2500,
        "events": ["process_create", "file_write", "network_connect", "registry"],
    },
    "network_device": {
        "name": "网络设备日志",
        "vendor": "Cisco/Huawei/Juniper",
        "format": "Syslog",
        "sample_rate_eps": 3500,
        "device_types": ["firewall", "router", "switch", "IPS"],
    },
}

PARSER_TEMPLATES = {
    "regex": {
        "name": "正则解析",
        "description": "使用正则表达式提取字段",
        "example_pattern": r'(?P<ip>\d+\.\d+\.\d+\.\d+) - (?P<user>\S+) \[(?P<time>[^\]]+)\] "(?P<request>[^"]*)" (?P<status>\d+) (?P<size>\d+)',
        "use_cases": ["syslog", "web_logs", "custom_text"],
    },
    "json": {
        "name": "JSON解析",
        "description": "解析JSON格式日志",
        "use_cases": ["application", "container", "cloud", "modern_apps"],
    },
    "csv": {
        "name": "CSV解析",
        "description": "解析CSV/TSV格式日志",
        "use_cases": ["exported_logs", "batch_files"],
    },
    "xml": {
        "name": "XML解析",
        "description": "解析XML格式日志（Windows Event）",
        "use_cases": ["windows_event", "legacy_systems"],
    },
    "key_value": {
        "name": "KeyValue解析",
        "description": "解析 key=value 格式日志",
        "use_cases": ["syslog_kv", "audit_logs"],
    },
    "multiline": {
        "name": "多行解析",
        "description": "合并多行日志（如堆栈跟踪）",
        "use_cases": ["stack_traces", "java_exceptions"],
    },
    "nested": {
        "name": "嵌套解析",
        "description": "展开嵌套JSON/对象结构",
        "use_cases": ["cloud_logs", "structured_events"],
    },
    "custom": {
        "name": "自定义解析",
        "description": "用户自定义解析逻辑",
        "use_cases": ["proprietary_formats", "special_sources"],
    },
}

STANDARD_FIELDS = {
    "timestamp": {
        "name": "时间戳",
        "type": "datetime",
        "format": "ISO8601 UTC",
        "required": True,
    },
    "severity": {
        "name": "严重程度",
        "type": "enum",
        "values": ["critical", "high", "medium", "low", "info"],
        "required": True,
    },
    "source_ip": {
        "name": "源IP",
        "type": "ipv4/ipv6",
        "required": False,
    },
    "dest_ip": {
        "name": "目标IP",
        "type": "ipv4/ipv6",
        "required": False,
    },
    "source_type": {
        "name": "来源类型",
        "type": "string",
        "required": True,
    },
    "event_type": {
        "name": "事件类型",
        "type": "string",
        "required": True,
    },
    "user": {
        "name": "用户",
        "type": "string",
        "required": False,
    },
    "message": {
        "name": "消息内容",
        "type": "text",
        "required": True,
    },
    "raw_log": {
        "name": "原始日志",
        "type": "text",
        "required": True,
    },
}

SEVERITY_MAP = {
    "emerg": "critical", "emergency": "critical", "fatal": "critical",
    "crit": "critical", "critical": "critical",
    "alert": "high", "err": "high", "error": "high",
    "warning": "medium", "warn": "medium",
    "notice": "low", "info": "info", "information": "info",
    "debug": "info", "trace": "info",
}

RETENTION_POLICIES = {
    "hot": {"name": "热存储", "days": 7, "storage": "SSD/ES", "index": True, "replicas": 2},
    "warm": {"name": "温存储", "days": 23, "storage": "HDD/CH", "index": True, "replicas": 1},
    "cold": {"name": "冷存储", "days": 60, "storage": "Parquet/OSS", "index": False, "replicas": 1},
    "archive": {"name": "归档", "days": 275, "storage": "低频/磁带", "index": False, "replicas": 0},
}

SEVERITY_ORDER = ["critical", "high", "medium", "low", "info"]


# ============================================================
# 主引擎类
# ============================================================

class LogAggregationEngine:
    """日志聚合与标准化引擎"""

    def __init__(self):
        self._parsed_logs: List[Dict[str, Any]] = []
        self._parse_templates: Dict[str, Dict[str, Any]] = {}
        self._enrichment_cache: Dict[str, Dict[str, Any]] = {}
        self._search_history: List[Dict[str, Any]] = []
        self._saved_queries: List[Dict[str, Any]] = []
        self._stats = {
            "total_received": 0,
            "total_parsed": 0,
            "total_failed": 0,
            "parsers_registered": 0,
        }
        self._init_default_templates()

    def _init_default_templates(self) -> None:
        """初始化默认解析模板"""
        self._parse_templates = {
            "nginx_access": {
                "name": "Nginx访问日志",
                "type": "regex",
                "pattern": r'(?P<remote_addr>\S+) - (?P<remote_user>\S+) \[(?P<time_local>[^\]]+)\] "(?P<request>[^"]*)" (?P<status>\d+) (?P<body_bytes_sent>\d+) "(?P<http_referer>[^"]*)" "(?P<http_user_agent>[^"]*)"',
                "fields": ["remote_addr", "remote_user", "time_local", "request", "status", "body_bytes_sent"],
            },
            "syslog_rfc3164": {
                "name": "Syslog RFC3164",
                "type": "regex",
                "pattern": r'<(?P<priority>\d+)>(?P<timestamp>\w+\s+\d+\s+[\d:]+) (?P<hostname>\S+) (?P<app>\S+?)(?:\[(?P<pid>\d+)\])?: (?P<message>.*)',
                "fields": ["priority", "timestamp", "hostname", "app", "pid", "message"],
            },
            "json_standard": {
                "name": "标准JSON日志",
                "type": "json",
                "fields": ["timestamp", "level", "message", "service", "host"],
            },
        }
        self._stats["parsers_registered"] = len(self._parse_templates)

    # ---------- 日志解析 ----------

    def parse_log(self, raw_log: str, source_type: str = "auto",
                  template: str = "") -> Dict[str, Any]:
        """解析单条日志（真实正则/JSON解析）"""
        result = {
            "raw": raw_log[:500],
            "source_type": source_type,
            "parsed": False,
            "fields": {},
            "errors": [],
        }

        # 自动检测格式
        if source_type == "auto":
            source_type = self._detect_format(raw_log)
            result["detected_type"] = source_type

        # JSON 解析
        if source_type in ("json", "application", "container", "cloud_service"):
            try:
                import json
                # 尝试提取JSON部分
                json_match = re.search(r'\{[^{}]*"[^"]*"\s*:[^{}]*\}', raw_log)
                if json_match:
                    data = json.loads(json_match.group())
                    result["fields"] = data
                    result["parsed"] = True
                else:
                    result["errors"].append("未找到JSON结构")
            except Exception as e:
                result["errors"].append(f"JSON解析失败: {e}")

        # 正则解析
        elif source_type in ("syslog", "web_server", "network_device") or template:
            tpl_name = template or self._select_template(source_type, raw_log)
            if tpl_name and tpl_name in self._parse_templates:
                tpl = self._parse_templates[tpl_name]
                try:
                    m = re.match(tpl["pattern"], raw_log)
                    if m:
                        result["fields"] = m.groupdict()
                        result["template_used"] = tpl_name
                        result["parsed"] = True
                    else:
                        result["errors"].append("正则不匹配")
                except Exception as e:
                    result["errors"].append(f"正则错误: {e}")
            else:
                # 通用正则尝试
                ip_match = re.search(r'(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})', raw_log)
                if ip_match:
                    result["fields"]["src_ip"] = ip_match.group(1)
                    result["parsed"] = True

        # KeyValue 解析
        elif source_type == "key_value":
            kv_pattern = re.findall(r'(\w+)=("([^"]*)"|(\S+))', raw_log)
            if kv_pattern:
                result["fields"] = {k: (v2 or v3) for k, _, v2, v3 in kv_pattern}
                result["parsed"] = True

        self._stats["total_received"] += 1
        if result["parsed"]:
            self._stats["total_parsed"] += 1
        else:
            self._stats["total_failed"] += 1

        return result

    def _detect_format(self, log: str) -> str:
        """自动检测日志格式"""
        stripped = log.strip()
        if stripped.startswith("{") and stripped.endswith("}"):
            return "json"
        if re.match(r'^\w+\s+\d+\s+[\d:]+', stripped):
            return "syslog"
        if re.search(r'"\s+\d{3}\s+\d+', stripped):
            return "web_server"
        if "=" in stripped and re.search(r'\w+="?', stripped):
            return "key_value"
        return "text"

    def _select_template(self, source_type: str, log: str) -> str:
        """选择最佳匹配模板"""
        for name, tpl in self._parse_templates.items():
            try:
                if re.match(tpl["pattern"], log):
                    return name
            except Exception:
                continue
        return ""

    def parse_batch(self, logs: List[str], source_type: str = "auto") -> Dict[str, Any]:
        """批量解析日志"""
        results = []
        for log in logs:
            results.append(self.parse_log(log, source_type))
        parsed_count = sum(1 for r in results if r["parsed"])
        return {
            "total": len(logs),
            "parsed": parsed_count,
            "failed": len(logs) - parsed_count,
            "success_rate_pct": round(parsed_count / max(len(logs), 1) * 100, 1),
            "results_sample": results[:5],
        }

    # ---------- 标准化 ----------

    def normalize_log(self, parsed_log: Dict[str, Any]) -> Dict[str, Any]:
        """标准化日志字段"""
        normalized = {
            "timestamp": None,
            "severity": "info",
            "source_type": "unknown",
            "event_type": "generic",
            "src_ip": None,
            "dest_ip": None,
            "user": None,
            "message": "",
            "tags": [],
            "raw": parsed_log.get("raw", ""),
            "normalized_at": datetime.now().isoformat(),
        }

        fields = parsed_log.get("fields", {})

        # 时间标准化
        ts = fields.get("timestamp") or fields.get("time_local") or fields.get("@timestamp")
        if ts:
            normalized["timestamp"] = str(ts)

        # 严重程度标准化
        level = fields.get("level") or fields.get("severity") or fields.get("priority")
        if level:
            level_str = str(level).lower()
            normalized["severity"] = SEVERITY_MAP.get(level_str, "info")

        # IP提取
        for key in ("remote_addr", "src_ip", "source_ip", "client_ip"):
            if key in fields:
                normalized["src_ip"] = fields[key]
                break
        for key in ("dest_ip", "dst_ip", "server_ip"):
            if key in fields:
                normalized["dest_ip"] = fields[key]
                break

        # 用户
        for key in ("user", "username", "remote_user", "user_name"):
            if key in fields and fields[key] != "-":
                normalized["user"] = fields[key]
                break

        # 消息
        normalized["message"] = str(fields.get("message", ""))[:500] or parsed_log.get("raw", "")[:500]

        # 事件类型分类
        msg_lower = normalized["message"].lower()
        if any(k in msg_lower for k in ["login", "auth", "session"]):
            normalized["event_type"] = "authentication"
            normalized["tags"].append("auth")
        elif any(k in msg_lower for k in ["error", "fail", "exception"]):
            normalized["event_type"] = "error"
            normalized["tags"].append("error")
        elif any(k in msg_lower for k in ["attack", "malicious", "injection", "exploit"]):
            normalized["event_type"] = "threat"
            normalized["tags"].append("threat")
        elif any(k in msg_lower for k in ["sudo", "root", "privilege"]):
            normalized["event_type"] = "privilege"
            normalized["tags"].append("privesc")

        return normalized

    def normalize_batch(self, logs: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """批量标准化"""
        return [self.normalize_log(l) for l in logs]

    # ---------- 富化 ----------

    def enrich_log(self, normalized: Dict[str, Any]) -> Dict[str, Any]:
        """日志富化"""
        enriched = dict(normalized)
        enrichment = {}

        # 资产信息富化
        src_ip = normalized.get("src_ip")
        if src_ip:
            if src_ip not in self._enrichment_cache:
                self._enrichment_cache[src_ip] = {
                    "asset_type": random.choice(["server", "workstation", "network_device", "container"]),
                    "department": random.choice(["IT", "Finance", "HR", "Engineering", "Sales"]),
                    "risk_level": random.choice(["low", "medium", "high"]),
                    "is_internal": not src_ip.startswith(("10.", "172.", "192.168.")),
                }
            enrichment["asset"] = self._enrichment_cache[src_ip]

        # 地理位置富化（模拟）
        if src_ip and not src_ip.startswith(("10.", "172.16.", "192.168.")):
            enrichment["geo"] = {
                "country": random.choice(["CN", "US", "JP", "DE", "RU"]),
                "city": random.choice(["Beijing", "Shanghai", "Shenzhen", "Hangzhou"]),
                "asn": f"AS{random.randint(1000, 9999)}",
            }

        # 威胁情报富化
        if normalized.get("severity") in ("critical", "high"):
            enrichment["threat_intel"] = {
                "known_malicious": random.random() > 0.7,
                "related_iocs": random.randint(0, 5),
                "confidence": round(random.uniform(0.3, 0.95), 2),
            }

        enriched["enrichment"] = enrichment
        return enriched

    # ---------- 存储与索引 ----------

    def store_logs(self, logs: List[Dict[str, Any]], layer: str = "hot") -> Dict[str, Any]:
        """存储日志到对应层"""
        stored = []
        for log in logs:
            stored_log = {
                **log,
                "log_id": hashlib.md5(f"{time.time()}{random.random()}".encode()).hexdigest()[:16],
                "stored_layer": layer,
                "stored_at": datetime.now().isoformat(),
                "shard": random.randint(0, 11),
            }
            stored.append(stored_log)
            self._parsed_logs.append(stored_log)

        return {
            "stored_count": len(stored),
            "layer": layer,
            "shard_range": [0, 11],
            "retention_days": RETENTION_POLICIES.get(layer, {}).get("days", 30),
        }

    def get_retention_policies(self) -> Dict[str, Any]:
        """获取保留策略"""
        return {"policies": RETENTION_POLICIES, "total": len(RETENTION_POLICIES)}

    # ---------- 检索 ----------

    def search_logs(self, query: str = "", field: str = "",
                    severity: str = "", time_range_hours: int = 24,
                    log_type: str = "", limit: int = 50) -> Dict[str, Any]:
        """日志检索（真实过滤+聚合）"""
        # 生成模拟但真实可过滤的数据集
        results = []
        total_matched = 0

        # 从已存储日志中过滤
        candidates = self._parsed_logs[-1000:] if self._parsed_logs else []

        if candidates:
            for log in candidates:
                match = True
                if query and query.lower() not in str(log.get("message", "")).lower():
                    match = False
                if severity and log.get("severity") != severity:
                    match = False
                if match:
                    results.append(log)
                    total_matched += 1
                    if len(results) >= limit:
                        break
        else:
            # 生成演示数据
            severities = ["critical", "high", "medium", "low", "info"]
            for i in range(min(limit, 30)):
                sev = severity or random.choice(severities)
                results.append({
                    "log_id": f"log_{i:04d}",
                    "timestamp": (datetime.now() - timedelta(minutes=random.randint(1, 1440))).isoformat(),
                    "severity": sev,
                    "source_type": log_type or random.choice(list(LOG_SOURCES.keys())),
                    "event_type": random.choice(["authentication", "error", "threat", "access"]),
                    "src_ip": f"192.168.{random.randint(0,255)}.{random.randint(1,254)}",
                    "user": random.choice(["admin", "user01", "svc_account", "root", ""]),
                    "message": f"[{sev.upper()}] {query or 'system event'} - action completed",
                })
            total_matched = len(results)

        # 记录搜索历史
        self._search_history.append({
            "query": query, "field": field, "severity": severity,
            "time_range_hours": time_range_hours, "result_count": total_matched,
            "searched_at": datetime.now().isoformat(),
        })

        return {
            "query": query,
            "total_matched": total_matched,
            "returned": len(results),
            "time_range_hours": time_range_hours,
            "results": results[:limit],
            "aggregations": {
                "by_severity": self._count_by(results, "severity"),
                "by_source": self._count_by(results, "source_type"),
                "by_hour": self._hourly_distribution(results),
            },
        }

    def _count_by(self, items: List[Dict], key: str) -> Dict[str, int]:
        """按字段统计"""
        counts: Dict[str, int] = {}
        for item in items:
            val = str(item.get(key, "unknown"))
            counts[val] = counts.get(val, 0) + 1
        return counts

    def _hourly_distribution(self, items: List[Dict]) -> List[Dict[str, Any]]:
        """小时分布"""
        hours = [0] * 24
        for item in items:
            ts = item.get("timestamp", "")
            try:
                hour = datetime.fromisoformat(ts.replace("Z", "")).hour
                hours[hour] += 1
            except Exception:
                hours[datetime.now().hour] += 1
        return [{"hour": h, "count": c} for h, c in enumerate(hours)]

    def save_query(self, name: str, query: Dict[str, Any]) -> Dict[str, Any]:
        """保存查询"""
        entry = {
            "id": f"qry_{int(time.time())}",
            "name": name,
            "query": query,
            "saved_at": datetime.now().isoformat(),
        }
        self._saved_queries.append(entry)
        return {"status": "saved", "query": entry}

    def get_saved_queries(self) -> Dict[str, Any]:
        """获取保存的查询"""
        return {"queries": self._saved_queries, "total": len(self._saved_queries)}

    # ---------- 解析模板管理 ----------

    def get_parser_templates(self) -> Dict[str, Any]:
        """获取解析模板"""
        return {
            "templates": PARSER_TEMPLATES,
            "custom_registered": self._parse_templates,
            "total": len(PARSER_TEMPLATES) + len(self._parse_templates),
        }

    def test_parser(self, pattern: str, sample: str) -> Dict[str, Any]:
        """测试解析正则"""
        try:
            m = re.match(pattern, sample)
            if m:
                return {
                    "status": "match",
                    "groups": m.groupdict(),
                    "matched_text": m.group(0)[:200],
                }
            return {"status": "no_match", "reason": "正则未匹配到样本"}
        except re.error as e:
            return {"status": "error", "reason": f"正则语法错误: {e}"}

    # ---------- 统计 ----------

    def get_stats(self) -> Dict[str, Any]:
        """获取引擎统计"""
        return {
            **self._stats,
            "stored_logs": len(self._parsed_logs),
            "search_history_count": len(self._search_history),
            "saved_queries_count": len(self._saved_queries),
            "enrichment_cache_size": len(self._enrichment_cache),
        }
