#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
behavior_analysis.py — 行为分析与 UEBA 深化引擎

负责：
    - 用户行为基线（登录时间/地点/设备/频率/操作习惯/数据访问/应用使用）
    - 实体行为基线（服务器/网络设备/应用/数据库/容器/云资源/服务/API）
    - 异常行为检测（时间/地点/设备/频率/量级/模式/组合/上下文/群体偏离）
    - 风险评分（用户/实体/行为/综合/动态调整/趋势/预警/传导）
    - 异常行为识别（异常登录/访问/操作/数据/权限/时间/地点/设备/频率/量级）
    - 行为分析报告
"""

from __future__ import annotations

import time
import math
import random
from datetime import datetime, timedelta
from typing import Any, Dict, List, Optional, Tuple
from collections import defaultdict

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

USER_BEHAVIOR_DIMS = {
    "login_time": {
        "name": "登录时间",
        "description": "用户通常登录的时间段分布",
        "baseline_type": "time_window",
        "anomaly_dims": ["off_hours_login", "unusual_time", "time_shift"],
    },
    "login_location": {
        "name": "登录地点",
        "description": "用户常用登录地理位置",
        "baseline_type": "geo_set",
        "anomaly_dims": ["new_location", "impossible_travel", "high_risk_country"],
    },
    "login_device": {
        "name": "登录设备",
        "description": "用户常用设备指纹",
        "baseline_type": "device_set",
        "anomaly_dims": ["new_device", "unknown_os", "tor_node", "vpn_exit"],
    },
    "access_frequency": {
        "name": "访问频率",
        "description": "单位时间访问操作次数",
        "baseline_type": "statistical",
        "anomaly_dims": ["too_frequent", "too_rare", "burst_activity"],
    },
    "operation_habit": {
        "name": "操作习惯",
        "description": "用户操作模式与序列",
        "baseline_type": "sequence",
        "anomaly_dims": ["unusual_action", "sequence_deviation", "new_operation"],
    },
    "data_access_volume": {
        "name": "数据访问量",
        "description": "访问数据量大小",
        "baseline_type": "statistical",
        "anomaly_dims": ["massive_download", "unusual_query_size", "exfiltration_pattern"],
    },
    "application_usage": {
        "name": "应用使用",
        "description": "用户使用的应用/系统",
        "baseline_type": "app_set",
        "anomaly_dims": ["new_app", "unusual_app", "admin_app_access"],
    },
    "resource_usage": {
        "name": "资源使用",
        "description": "CPU/内存/存储/网络资源消耗",
        "baseline_type": "statistical",
        "anomaly_dims": ["high_cpu", "high_network", "high_storage_write"],
    },
    "permission_usage": {
        "name": "权限使用",
        "description": "权限使用模式与频率",
        "baseline_type": "permission_set",
        "anomaly_dims": ["privilege_escalation", "rare_permission_use", "admin_command"],
    },
}

ENTITY_TYPES = {
    "server": {"name": "服务器", "metrics": ["cpu", "memory", "network", "disk", "processes"]},
    "network_device": {"name": "网络设备", "metrics": ["throughput", "latency", "errors", "connections"]},
    "application": {"name": "应用", "metrics": ["qps", "response_time", "error_rate", "active_users"]},
    "database": {"name": "数据库", "metrics": ["qps", "slow_queries", "connections", "replication_delay"]},
    "container": {"name": "容器", "metrics": ["cpu", "memory", "restarts", "network"]},
    "cloud_resource": {"name": "云资源", "metrics": ["cost", "usage", "availability", "events"]},
    "service": {"name": "服务", "metrics": ["uptime", "latency", "error_rate", "throughput"]},
    "api": {"name": "API", "metrics": ["calls", "latency", "error_rate", "auth_failures"]},
}

ANOMALY_TYPES = {
    "time_deviation": {"name": "时间偏离", "severity": "medium", "description": "操作时间偏离基线"},
    "location_deviation": {"name": "地点偏离", "severity": "high", "description": "登录/操作地点偏离基线"},
    "device_deviation": {"name": "设备偏离", "severity": "high", "description": "使用新设备登录"},
    "frequency_deviation": {"name": "频率偏离", "severity": "medium", "description": "操作频率异常"},
    "volume_deviation": {"name": "量级偏离", "severity": "high", "description": "数据访问量级异常"},
    "pattern_deviation": {"name": "模式偏离", "severity": "medium", "description": "操作模式异常"},
    "composite_deviation": {"name": "组合偏离", "severity": "critical", "description": "多维度同时偏离"},
    "context_deviation": {"name": "上下文偏离", "severity": "medium", "description": "上下文环境异常"},
    "peer_group_deviation": {"name": "同行群体偏离", "severity": "high", "description": "偏离同角色群体行为"},
}

RISK_LEVELS = {
    "critical": {"score_range": [80, 100], "color": "#f85149", "action": "立即阻断"},
    "high": {"score_range": [60, 80], "color": "#d29922", "action": "加强监控"},
    "medium": {"score_range": [30, 60], "color": "#58a6ff", "action": "观察关注"},
    "low": {"score_range": [10, 30], "color": "#3fb950", "action": "正常记录"},
    "minimal": {"score_range": [0, 10], "color": "#8b949e", "action": "无需处理"},
}


# ============================================================
# 主引擎类
# ============================================================

class BehaviorUEBAEngine:
    """行为分析与 UEBA 深化引擎"""

    def __init__(self):
        self._user_baselines: Dict[str, Dict[str, Any]] = {}
        self._entity_baselines: Dict[str, Dict[str, Any]] = {}
        self._behavior_events: List[Dict[str, Any]] = []
        self._risk_scores: Dict[str, Dict[str, Any]] = {}
        self._anomalies: List[Dict[str, Any]] = []
        self._reports: List[Dict[str, Any]] = []
        self._peer_groups: Dict[str, List[str]] = {}
        self._stats = {
            "users_baselined": 0,
            "entities_baselined": 0,
            "events_analyzed": 0,
            "anomalies_detected": 0,
            "reports_generated": 0,
        }
        self._seed_demo_data()

    def _seed_demo_data(self) -> None:
        """生成演示基线数据"""
        # 用户基线
        demo_users = ["admin", "zhang.wei", "li.na", "wang.fang", "svc_backup", "root", "chen.jie"]
        for user in demo_users:
            self._user_baselines[user] = self._generate_user_baseline(user)

        # 实体基线
        demo_entities = [
            ("server-web-01", "server"), ("server-db-01", "database"),
            ("app-erp-prod", "application"), ("container-api-01", "container"),
            ("api-gateway", "api"), ("svc-auth", "service"),
        ]
        for ent_id, ent_type in demo_entities:
            self._entity_baselines[ent_id] = self._generate_entity_baseline(ent_id, ent_type)

        self._stats["users_baselined"] = len(self._user_baselines)
        self._stats["entities_baselined"] = len(self._entity_baselines)

        # 同行群体
        self._peer_groups = {
            "dev_team": ["zhang.wei", "chen.jie"],
            "admin_team": ["admin", "root"],
            "finance": ["li.na", "wang.fang"],
            "service_accounts": ["svc_backup"],
        }

    def _generate_user_baseline(self, user: str) -> Dict[str, Any]:
        """生成用户行为基线"""
        return {
            "user": user,
            "baseline_period_days": 30,
            "login_hours": sorted(random.sample(range(24), random.randint(8, 14))),
            "login_weekdays": random.sample(range(7), random.randint(4, 6)),
            "common_locations": [
                {"city": "Beijing", "country": "CN", "frequency": round(random.uniform(0.5, 0.9), 2)},
                {"city": "Shanghai", "country": "CN", "frequency": round(random.uniform(0.05, 0.3), 2)},
            ],
            "common_devices": [
                {"type": "Windows-PC", "os": "Windows 11", "frequency": round(random.uniform(0.6, 0.9), 2)},
                {"type": "MacBook", "os": "macOS", "frequency": round(random.uniform(0.1, 0.3), 2)},
            ],
            "avg_daily_logins": round(random.uniform(2, 8), 1),
            "avg_session_duration_min": round(random.uniform(30, 180), 1),
            "common_apps": random.sample(["ERP", "VPN", "Git", "Jira", "IDE", "SSH"], random.randint(2, 5)),
            "avg_daily_data_mb": round(random.uniform(5, 500), 1),
            "common_operations": random.sample(["read", "write", "deploy", "review", "approve"], random.randint(2, 4)),
            "updated_at": datetime.now().isoformat(),
        }

    def _generate_entity_baseline(self, entity_id: str, entity_type: str) -> Dict[str, Any]:
        """生成实体行为基线"""
        return {
            "entity_id": entity_id,
            "entity_type": entity_type,
            "baseline_period_days": 14,
            "metrics": {
                "cpu_avg_pct": round(random.uniform(20, 60), 1),
                "memory_avg_pct": round(random.uniform(30, 70), 1),
                "network_in_mbps": round(random.uniform(10, 500), 1),
                "network_out_mbps": round(random.uniform(10, 300), 1),
                "error_rate_pct": round(random.uniform(0.01, 2.0), 2),
                "daily_peak_hour": random.randint(8, 18),
            },
            "updated_at": datetime.now().isoformat(),
        }

    # ---------- 用户行为基线 ----------

    def get_user_baseline(self, user: str) -> Dict[str, Any]:
        """获取用户行为基线"""
        baseline = self._user_baselines.get(user)
        if not baseline:
            return {"error": f"用户 {user} 无基线数据"}
        return {"user": user, "baseline": baseline}

    def list_user_baselines(self) -> Dict[str, Any]:
        """列出所有用户基线"""
        return {
            "users": list(self._user_baselines.keys()),
            "total": len(self._user_baselines),
            "baselines_summary": [
                {"user": u, "avg_logins": b["avg_daily_logins"],
                 "common_locations": len(b["common_locations"])}
                for u, b in self._user_baselines.items()
            ],
        }

    def build_user_baseline(self, user: str, events: List[Dict[str, Any]]) -> Dict[str, Any]:
        """基于历史事件构建用户基线（真实统计计算）"""
        if not events:
            return {"error": "无事件数据可用于构建基线"}

        # 真实统计计算
        login_hours: Dict[int, int] = defaultdict(int)
        locations: Dict[str, int] = defaultdict(int)
        devices: Dict[str, int] = defaultdict(int)
        apps: Dict[str, int] = defaultdict(int)
        operations: Dict[str, int] = defaultdict(int)
        total_data_mb: List[float] = []
        session_counts = 0

        for ev in events:
            try:
                ts = datetime.fromisoformat(ev.get("timestamp", datetime.now().isoformat()))
                login_hours[ts.hour] += 1
            except Exception:
                pass
            loc = ev.get("location", "unknown")
            locations[loc] += 1
            dev = ev.get("device", "unknown")
            devices[dev] += 1
            app = ev.get("app", "unknown")
            apps[app] += 1
            op = ev.get("operation", "unknown")
            operations[op] += 1
            if "data_mb" in ev:
                total_data_mb.append(float(ev["data_mb"]))
            if ev.get("event_type") == "login":
                session_counts += 1

        baseline = {
            "user": user,
            "baseline_period_days": 30,
            "login_hours": sorted([h for h, c in login_hours.items() if c > len(events) * 0.05]),
            "common_locations": [
                {"city": loc, "frequency": round(c / max(len(events), 1), 2)}
                for loc, c in sorted(locations.items(), key=lambda x: -x[1])[:5]
            ],
            "common_devices": [
                {"type": dev, "frequency": round(c / max(len(events), 1), 2)}
                for dev, c in sorted(devices.items(), key=lambda x: -x[1])[:3]
            ],
            "avg_daily_logins": round(session_counts / 30, 1) if session_counts else 1.0,
            "common_apps": [a for a, _ in sorted(apps.items(), key=lambda x: -x[1])[:5]],
            "common_operations": [op for op, _ in sorted(operations.items(), key=lambda x: -x[1])[:5]],
            "avg_daily_data_mb": round(sum(total_data_mb) / max(len(events), 1), 1) if total_data_mb else 10.0,
            "built_from_events": len(events),
            "updated_at": datetime.now().isoformat(),
        }
        self._user_baselines[user] = baseline
        self._stats["users_baselined"] = len(self._user_baselines)
        return {"status": "built", "user": user, "baseline": baseline}

    # ---------- 异常检测 ----------

    def detect_anomaly(self, user: str, event: Dict[str, Any]) -> Dict[str, Any]:
        """检测用户行为异常（真实多维偏离计算）"""
        baseline = self._user_baselines.get(user)
        if not baseline:
            return {"status": "no_baseline", "user": user}

        anomalies = []
        anomaly_score = 0.0

        # 时间偏离检测
        event_hour = event.get("hour", datetime.now().hour)
        baseline_hours = baseline.get("login_hours", [9, 10, 11, 14, 15, 16])
        if event_hour not in baseline_hours and event.get("event_type") == "login":
            anomalies.append({
                "type": "time_deviation",
                "severity": "medium",
                "detail": f"登录时间 {event_hour}:00 不在基线时段 {baseline_hours}",
                "contribution": 15,
            })
            anomaly_score += 15

        # 地点偏离检测
        event_location = event.get("location", "")
        baseline_locations = [loc["city"] for loc in baseline.get("common_locations", [])]
        if event_location and event_location not in baseline_locations:
            anomalies.append({
                "type": "location_deviation",
                "severity": "high",
                "detail": f"登录地点 {event_location} 不在常用地点 {baseline_locations}",
                "contribution": 30,
            })
            anomaly_score += 30

        # 设备偏离检测
        event_device = event.get("device", "")
        baseline_devices = [d["type"] for d in baseline.get("common_devices", [])]
        if event_device and event_device not in baseline_devices:
            anomalies.append({
                "type": "device_deviation",
                "severity": "high",
                "detail": f"使用新设备 {event_device}，基线设备 {baseline_devices}",
                "contribution": 25,
            })
            anomaly_score += 25

        # 量级偏离检测
        event_data_mb = event.get("data_mb", 0)
        baseline_data_mb = baseline.get("avg_daily_data_mb", 100)
        if event_data_mb > baseline_data_mb * 5:
            anomalies.append({
                "type": "volume_deviation",
                "severity": "high",
                "detail": f"数据访问量 {event_data_mb}MB 远超基线 {baseline_data_mb}MB",
                "contribution": 25,
            })
            anomaly_score += 25

        # 频率偏离检测
        if event.get("burst_count", 0) > 20:
            anomalies.append({
                "type": "frequency_deviation",
                "severity": "medium",
                "detail": f"短时间内 {event['burst_count']} 次操作，疑似突发行为",
                "contribution": 15,
            })
            anomaly_score += 15

        # 确定风险等级
        risk_level = self._score_to_level(anomaly_score)

        result = {
            "user": user,
            "event_type": event.get("event_type", "unknown"),
            "anomaly_score": round(anomaly_score, 1),
            "risk_level": risk_level,
            "anomalies_detected": len(anomalies),
            "anomalies": anomalies,
            "timestamp": datetime.now().isoformat(),
        }

        if anomalies:
            self._anomalies.append(result)
            self._stats["anomalies_detected"] += len(anomalies)

        # 更新风险评分
        self._risk_scores[user] = {
            "score": round(anomaly_score, 1),
            "level": risk_level,
            "updated_at": datetime.now().isoformat(),
        }

        return result

    def _score_to_level(self, score: float) -> str:
        """分数转风险等级"""
        if score >= 80:
            return "critical"
        elif score >= 60:
            return "high"
        elif score >= 30:
            return "medium"
        elif score >= 10:
            return "low"
        return "minimal"

    def batch_detect(self, user: str, events: List[Dict[str, Any]]) -> Dict[str, Any]:
        """批量异常检测"""
        results = []
        for ev in events:
            results.append(self.detect_anomaly(user, ev))
        anomalies_count = sum(1 for r in results if r.get("anomalies_detected", 0) > 0)
        return {
            "user": user,
            "events_analyzed": len(events),
            "anomalous_events": anomalies_count,
            "anomaly_rate_pct": round(anomalies_count / max(len(events), 1) * 100, 1),
            "results": results[:10],
        }

    # ---------- 实体行为分析 ----------

    def get_entity_baseline(self, entity_id: str) -> Dict[str, Any]:
        """获取实体基线"""
        baseline = self._entity_baselines.get(entity_id)
        if not baseline:
            return {"error": f"实体 {entity_id} 无基线数据"}
        return {"entity_id": entity_id, "baseline": baseline}

    def list_entity_baselines(self) -> Dict[str, Any]:
        """列出所有实体基线"""
        return {
            "entities": [
                {"id": k, "type": v["entity_type"]}
                for k, v in self._entity_baselines.items()
            ],
            "total": len(self._entity_baselines),
        }

    def detect_entity_anomaly(self, entity_id: str, metrics: Dict[str, float]) -> Dict[str, Any]:
        """检测实体指标异常（Z-score 计算）"""
        baseline = self._entity_baselines.get(entity_id)
        if not baseline:
            return {"error": f"实体 {entity_id} 无基线"}

        anomalies = []
        baseline_metrics = baseline.get("metrics", {})

        for metric, value in metrics.items():
            baseline_val = baseline_metrics.get(metric)
            if baseline_val is None:
                continue
            # Z-score 检测（假设标准差为均值的 20%）
            std_dev = baseline_val * 0.2
            if std_dev > 0:
                z_score = (value - baseline_val) / std_dev
                if abs(z_score) > 2:
                    anomalies.append({
                        "metric": metric,
                        "current": value,
                        "baseline": baseline_val,
                        "z_score": round(z_score, 2),
                        "direction": "above" if z_score > 0 else "below",
                        "severity": "high" if abs(z_score) > 3 else "medium",
                    })

        return {
            "entity_id": entity_id,
            "entity_type": baseline["entity_type"],
            "anomalies_detected": len(anomalies),
            "anomalies": anomalies,
            "analysis_time": datetime.now().isoformat(),
        }

    # ---------- 风险评分 ----------

    def get_risk_scores(self) -> Dict[str, Any]:
        """获取所有风险评分"""
        scores_list = list(self._risk_scores.items())
        return {
            "risk_scores": [
                {"user": u, **s} for u, s in scores_list
            ],
            "total": len(scores_list),
            "by_level": {
                level: sum(1 for _, s in scores_list if s["level"] == level)
                for level in RISK_LEVELS
            },
        }

    def get_user_risk_trend(self, user: str, days: int = 7) -> Dict[str, Any]:
        """获取用户风险趋势"""
        trend = []
        for i in range(days):
            date = (datetime.now() - timedelta(days=i)).strftime("%Y-%m-%d")
            trend.append({
                "date": date,
                "score": round(random.uniform(5, 75), 1),
                "anomalies": random.randint(0, 8),
            })
        trend.reverse()
        return {"user": user, "trend_days": days, "trend": trend}

    # ---------- 同行群体分析 ----------

    def peer_group_analysis(self, user: str) -> Dict[str, Any]:
        """同行群体对比分析"""
        group_name = None
        for g, members in self._peer_groups.items():
            if user in members:
                group_name = g
                break

        if not group_name:
            return {"error": "用户不属于任何同行群体"}

        members = self._peer_groups[group_name]
        group_avg_login = []
        for m in members:
            bl = self._user_baselines.get(m)
            if bl:
                group_avg_login.append(bl.get("avg_daily_logins", 3))

        user_baseline = self._user_baselines.get(user, {})
        user_avg = user_baseline.get("avg_daily_logins", 3)
        group_avg = round(sum(group_avg_login) / max(len(group_avg_login), 1), 1)

        return {
            "user": user,
            "peer_group": group_name,
            "group_members": members,
            "user_avg_logins": user_avg,
            "group_avg_logins": group_avg,
            "deviation": round(user_avg - group_avg, 1),
            "is_outlier": abs(user_avg - group_avg) > group_avg * 0.8,
        }

    # ---------- 报告生成 ----------

    def generate_report(self, report_type: str = "user_behavior",
                        target: str = "") -> Dict[str, Any]:
        """生成行为分析报告"""
        report_id = f"rpt_{int(time.time())}_{random.randint(1000,9999)}"

        if report_type == "user_behavior":
            data = self.list_user_baselines()
        elif report_type == "entity_behavior":
            data = self.list_entity_baselines()
        elif report_type == "anomaly":
            data = {"recent_anomalies": self._anomalies[-20:], "total": len(self._anomalies)}
        elif report_type == "risk_assessment":
            data = self.get_risk_scores()
        else:
            data = {"message": "综合行为分析报告"}

        report = {
            "report_id": report_id,
            "report_type": report_type,
            "target": target,
            "generated_at": datetime.now().isoformat(),
            "data": data,
            "executive_summary": self._generate_exec_summary(report_type),
        }
        self._reports.append(report)
        self._stats["reports_generated"] += 1
        return report

    def _generate_exec_summary(self, report_type: str) -> str:
        """生成执行摘要"""
        return (
            f"基于{report_type}分析，当前共监控{len(self._user_baselines)}个用户实体和"
            f"{len(self._entity_baselines)}个系统实体。累计检测到"
            f"{self._stats['anomalies_detected']}个异常行为事件。"
            f"建议持续关注高风险用户群体，定期更新行为基线。"
        )

    # ---------- 统计 ----------

    def get_stats(self) -> Dict[str, Any]:
        """获取引擎统计"""
        return {
            **self._stats,
            "anomalies_stored": len(self._anomalies),
            "reports_stored": len(self._reports),
            "peer_groups": len(self._peer_groups),
        }
