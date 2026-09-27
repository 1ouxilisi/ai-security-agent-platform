# -*- coding: utf-8 -*-
"""
hunt_data_manager.py — 狩猎数据管理。

提供数据源管理、跨源搜索、数据管道、数据质量监控和狩猎数据导出五大子系统。

设计定位：仅用于经过授权的防御性数据管理与质量监控。
"""

from __future__ import annotations

import hashlib
import time
import uuid
from typing import Any, Dict, List, Optional


# --------------------------------------------------------------------------- #
# 数据源管理
# --------------------------------------------------------------------------- #
class DataSourceManager:
    """数据源管理器。"""

    def __init__(self) -> None:
        self._sources: Dict[str, Dict[str, Any]] = {}
        self._seed_default_sources()

    def _seed_default_sources(self) -> None:
        """预置默认数据源。"""
        defaults = [
            {"name": "Windows Event Logs", "log_type": "winevent", "collection": "WEF Subscription",
             "retention_days": 90, "index_status": "healthy", "data_volume_gb": 45.2, "freshness_seconds": 30},
            {"name": "Sysmon Logs", "log_type": "sysmon", "collection": "Agent Forwarder",
             "retention_days": 60, "index_status": "healthy", "data_volume_gb": 120.5, "freshness_seconds": 15},
            {"name": "Network Flow / Zeek", "log_type": "network_flow", "collection": "Span Port",
             "retention_days": 30, "index_status": "healthy", "data_volume_gb": 300.0, "freshness_seconds": 5},
            {"name": "DNS Logs", "log_type": "dns", "collection": "DNS Server Export",
             "retention_days": 45, "index_status": "degraded", "data_volume_gb": 25.8, "freshness_seconds": 120},
            {"name": "Authentication Logs", "log_type": "auth", "collection": "AD Connector",
             "retention_days": 180, "index_status": "healthy", "data_volume_gb": 15.3, "freshness_seconds": 10},
            {"name": "Web Proxy Logs", "log_type": "proxy", "collection": "Syslog",
             "retention_days": 30, "index_status": "healthy", "data_volume_gb": 80.1, "freshness_seconds": 20},
            {"name": "EDR Telemetry", "log_type": "edr", "collection": "EDR API",
             "retention_days": 90, "index_status": "healthy", "data_volume_gb": 200.0, "freshness_seconds": 5},
        ]
        for d in defaults:
            self.register_source(**d)

    def register_source(self, name: str, log_type: str, collection: str,
                        retention_days: int = 90, index_status: str = "healthy",
                        data_volume_gb: float = 0.0, freshness_seconds: int = 60) -> Dict[str, Any]:
        """注册数据源。"""
        sid = uuid.uuid4().hex[:12]
        entry = {
            "source_id": sid,
            "name": name,
            "log_type": log_type,
            "collection_method": collection,
            "retention_days": retention_days,
            "index_status": index_status,
            "data_volume_gb": data_volume_gb,
            "freshness_seconds": freshness_seconds,
            "registered_at": time.strftime("%Y-%m-%d %H:%M:%S"),
        }
        self._sources[sid] = entry
        return entry

    def list_sources(self) -> List[Dict[str, Any]]:
        return list(self._sources.values())

    def get_source(self, source_id: str) -> Optional[Dict[str, Any]]:
        return self._sources.get(source_id)

    def update_source(self, source_id: str, **kwargs) -> Optional[Dict[str, Any]]:
        s = self._sources.get(source_id)
        if not s:
            return None
        for k, v in kwargs.items():
            if k in s:
                s[k] = v
        return s


# --------------------------------------------------------------------------- #
# 跨源搜索
# --------------------------------------------------------------------------- #
class CrossSourceSearcher:
    """跨源搜索器。"""

    def __init__(self, source_manager: Optional[DataSourceManager] = None) -> None:
        self._sources = source_manager or DataSourceManager()

    def search(self, query: str, time_range: str = "last_24h",
               fields: Optional[List[str]] = None,
               sources: Optional[List[str]] = None,
               aggregation: Optional[str] = None,
               group_by: Optional[str] = None,
               sort_by: str = "timestamp",
               sort_dir: str = "desc",
               page: int = 1, page_size: int = 20) -> Dict[str, Any]:
        """跨数据源搜索。"""
        # 模拟搜索结果
        results = [
            {"timestamp": "2026-09-14 08:15:00", "source": "sysmon", "hostname": "WIN-PC-01",
             "event_type": "process_create", "process_name": "powershell.exe",
             "command_line": "powershell -enc SQBFAFgA...", "user": "jsmith"},
            {"timestamp": "2026-09-14 08:16:00", "source": "edr", "hostname": "WIN-PC-01",
             "event_type": "network_connect", "destination_ip": "45.132.9.87",
             "destination_port": 443, "user": "jsmith"},
            {"timestamp": "2026-09-14 09:22:00", "source": "network_flow", "hostname": "WIN-PC-02",
             "event_type": "flow", "destination_ip": "185.220.101.45",
             "destination_port": 8080, "bytes": 120000, "user": "ajones"},
            {"timestamp": "2026-09-14 10:30:00", "source": "winevent", "hostname": "WEB01",
             "event_type": "file_create", "file_path": "C:\\inetpub\\wwwroot\\shell.aspx",
             "user": "iis_apppool"},
            {"timestamp": "2026-09-14 07:55:00", "source": "auth", "hostname": "WIN-PC-01",
             "event_type": "login_success", "user": "jsmith", "source_ip": "45.132.9.87",
             "service": "rdp"},
        ]

        total = len(results)
        start = (page - 1) * page_size
        page_results = results[start:start + page_size]

        return {
            "query": query,
            "time_range": time_range,
            "total_matches": total,
            "returned": len(page_results),
            "page": page,
            "page_size": page_size,
            "results": page_results,
            "sources_queried": [s["name"] for s in self._sources.list_sources()],
            "search_time_ms": 45,
            "aggregation": aggregation,
            "group_by": group_by,
        }


# --------------------------------------------------------------------------- #
# 数据管道
# --------------------------------------------------------------------------- #
class DataPipeline:
    """狩猎数据管道。"""

    PIPELINE_STAGES = ["ingest", "parse", "normalize", "enrich", "store", "index", "quality_check"]

    def __init__(self) -> None:
        self._pipelines: Dict[str, Dict[str, Any]] = {}
        self._seed_default_pipelines()

    def _seed_default_pipelines(self) -> None:
        """预置默认管道。"""
        defaults = [
            {"name": "Sysmon → Normalize → Index", "source": "Sysmon Logs",
             "stages": ["ingest", "parse", "normalize", "enrich", "store", "index"],
             "status": "running"},
            {"name": "DNS → Extract Threats → Alert", "source": "DNS Logs",
             "stages": ["ingest", "parse", "normalize", "enrich", "store", "index"],
             "status": "running"},
            {"name": "Auth Logs → Anomaly Detect", "source": "Authentication Logs",
             "stages": ["ingest", "parse", "normalize", "enrich", "store", "index", "quality_check"],
             "status": "running"},
        ]
        for d in defaults:
            self.create_pipeline(**d)

    def create_pipeline(self, name: str, source: str,
                        stages: List[str] = None,
                        status: str = "running") -> Dict[str, Any]:
        """创建数据管道。"""
        pid = uuid.uuid4().hex[:12]
        entry = {
            "pipeline_id": pid,
            "name": name,
            "source": source,
            "stages": stages or self.PIPELINE_STAGES,
            "status": status,
            "created_at": time.strftime("%Y-%m-%d %H:%M:%S"),
            "events_processed": 12500000,
            "events_per_second": 1450,
            "last_processed": time.strftime("%Y-%m-%d %H:%M:%S"),
        }
        self._pipelines[pid] = entry
        return entry

    def list_pipelines(self) -> List[Dict[str, Any]]:
        return list(self._pipelines.values())

    def get_pipeline(self, pipeline_id: str) -> Optional[Dict[str, Any]]:
        return self._pipelines.get(pipeline_id)


# --------------------------------------------------------------------------- #
# 数据质量监控
# --------------------------------------------------------------------------- #
class DataQualityMonitor:
    """数据质量监控器。"""

    def __init__(self) -> None:
        self._metrics: Dict[str, Dict[str, Any]] = {}
        self._seed_default_metrics()

    def _seed_default_metrics(self) -> None:
        """预置默认质量指标。"""
        sources = ["Windows Event Logs", "Sysmon Logs", "Network Flow", "DNS Logs",
                   "Authentication Logs", "Web Proxy Logs", "EDR Telemetry"]
        for s in sources:
            self._metrics[s] = {
                "source": s,
                "completeness_pct": 98.5 if s != "DNS Logs" else 87.2,
                "latency_seconds": 15 if s != "DNS Logs" else 120,
                "lost_events_pct": 0.5 if s != "DNS Logs" else 3.2,
                "duplicate_pct": 0.8,
                "format_errors": 12 if s == "DNS Logs" else 2,
                "missing_fields": ["user", "process_id"] if s == "DNS Logs" else [],
                "status": "healthy" if s != "DNS Logs" else "degraded",
                "checked_at": time.strftime("%Y-%m-%d %H:%M:%S"),
            }

    def check_quality(self) -> List[Dict[str, Any]]:
        """执行数据质量检查。"""
        return list(self._metrics.values())

    def get_source_quality(self, source: str) -> Optional[Dict[str, Any]]:
        return self._metrics.get(source)

    def quality_summary(self) -> Dict[str, Any]:
        """质量摘要。"""
        items = list(self._metrics.values())
        healthy = sum(1 for i in items if i["status"] == "healthy")
        degraded = sum(1 for i in items if i["status"] == "degraded")
        return {
            "total_sources": len(items),
            "healthy": healthy,
            "degraded": degraded,
            "avg_completeness": round(sum(i["completeness_pct"] for i in items) / len(items), 1),
            "avg_latency_seconds": round(sum(i["latency_seconds"] for i in items) / len(items), 1),
        }


# --------------------------------------------------------------------------- #
# 狩猎数据导出
# --------------------------------------------------------------------------- #
class HuntDataExporter:
    """狩猎数据导出器。"""

    def __init__(self) -> None:
        self._exports: Dict[str, Dict[str, Any]] = {}

    def export_evidence(self, evidence_type: str, query: str,
                        include_logs: bool = True, include_screenshots: bool = True,
                        include_pcap: bool = False) -> Dict[str, Any]:
        """导出证据包。"""
        eid = uuid.uuid4().hex[:12]
        evidence_data = [
            {"timestamp": "2026-09-14 08:15:00", "type": "process", "host": "WIN-PC-01",
             "detail": "powershell.exe -enc SQBFAFgA..."},
            {"timestamp": "2026-09-14 08:16:00", "type": "network", "host": "WIN-PC-01",
             "detail": "OUTBOUND 45.132.9.87:443 TCP"},
        ]

        # 计算哈希校验
        evidence_str = json.dumps(evidence_data, sort_keys=True)
        sha256 = hashlib.sha256(evidence_str.encode()).hexdigest()

        entry = {
            "export_id": eid,
            "evidence_type": evidence_type,
            "query": query,
            "include_logs": include_logs,
            "include_screenshots": include_screenshots,
            "include_pcap": include_pcap,
            "evidence_items": len(evidence_data),
            "evidence_preview": evidence_data[:5],
            "sha256_checksum": sha256,
            "file_size_kb": 256,
            "exported_at": time.strftime("%Y-%m-%d %H:%M:%S"),
            "status": "ready",
        }
        self._exports[eid] = entry
        return entry

    def list_exports(self) -> List[Dict[str, Any]]:
        return list(self._exports.values())

    def get_export(self, export_id: str) -> Optional[Dict[str, Any]]:
        return self._exports.get(export_id)


# 需要json用于哈希计算
import json  # noqa: E402
