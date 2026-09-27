# -*- coding: utf-8 -*-
"""
behavior_analysis.py — 行为分析引擎。

提供用户行为基线、实体行为画像、异常行为检测、
行为链分析和行为评分五大子系统。

设计定位：仅用于经过授权的防御性行为分析与异常检测。
"""

from __future__ import annotations

import hashlib
import math
import statistics
import time
import uuid
from typing import Any, Dict, List, Optional, Tuple


# --------------------------------------------------------------------------- #
# 用户行为基线
# --------------------------------------------------------------------------- #
class BehaviorBaselineBuilder:
    """用户行为基线构建器。"""

    def __init__(self) -> None:
        self._baselines: Dict[str, Dict[str, Any]] = {}
        self._seed_default_baselines()

    def _seed_default_baselines(self) -> None:
        """预置默认行为基线。"""
        baselines = {
            "jsmith": {
                "user": "jsmith",
                "typical_login_hours": [9, 10, 11, 14, 15, 16],
                "typical_locations": ["Office-Building-A", "Home-VPN"],
                "typical_devices": ["WIN-PC-01", "LAPTOP-JS1"],
                "avg_logins_per_day": 3,
                "typical_weekdays": [1, 2, 3, 4, 5],
                "typical_processes": ["outlook.exe", "chrome.exe", "excel.exe", "winword.exe"],
                "typical_servers_accessed": ["FILESERVER01", "MAIL01"],
            },
            "admin": {
                "user": "admin",
                "typical_login_hours": [8, 9, 10, 11, 13, 14, 15, 16],
                "typical_locations": ["DataCenter-Bastion", "Office-Building-B"],
                "typical_devices": ["BASTION01", "WIN-PC-ADMIN"],
                "avg_logins_per_day": 8,
                "typical_weekdays": [1, 2, 3, 4, 5],
                "typical_processes": ["mmc.exe", "powershell.exe", "cmd.exe", "mmc.exe"],
                "typical_servers_accessed": ["DC01", "DC02", "WIN-SRV01", "WIN-SRV02"],
            },
        }
        self._baselines = baselines

    def build_baseline(self, user: str, observations: List[Dict[str, Any]]) -> Dict[str, Any]:
        """基于观测数据构建用户行为基线。"""
        login_hours = {}
        locations = set()
        devices = set()
        for obs in observations:
            hour = obs.get("hour", 12)
            login_hours[hour] = login_hours.get(hour, 0) + 1
            if obs.get("location"):
                locations.add(obs["location"])
            if obs.get("device"):
                devices.add(obs["device"])

        entry = {
            "user": user,
            "typical_login_hours": sorted(login_hours.keys(), key=lambda h: -login_hours[h])[:8],
            "typical_locations": sorted(locations),
            "typical_devices": sorted(devices),
            "avg_logins_per_day": max(1, len(observations) // 30),
            "typical_weekdays": [1, 2, 3, 4, 5],
            "built_at": time.strftime("%Y-%m-%d %H:%M:%S"),
            "sample_size": len(observations),
        }
        self._baselines[user] = entry
        return entry

    def get_baseline(self, user: str) -> Optional[Dict[str, Any]]:
        return self._baselines.get(user)

    def list_baselines(self) -> List[Dict[str, Any]]:
        return list(self._baselines.values())


# --------------------------------------------------------------------------- #
# 实体行为画像
# --------------------------------------------------------------------------- #
class EntityProfiler:
    """实体行为画像器。"""

    ENTITY_TYPES = {"host", "user", "process", "network_connection"}

    def __init__(self) -> None:
        self._profiles: Dict[str, Dict[str, Any]] = {}
        self._seed_default_profiles()

    def _seed_default_profiles(self) -> None:
        """预置默认实体画像。"""
        profiles = {
            "host:WIN-PC-01": {
                "entity_type": "host",
                "entity_id": "WIN-PC-01",
                "os": "Windows 10 Pro",
                "ip_addresses": ["192.168.1.21"],
                "typical_users": ["jsmith"],
                "typical_processes": ["outlook.exe", "chrome.exe", "explorer.exe"],
                "typical_connections": ["MAIL01:443", "FILESERVER01:445"],
                "risk_score": 15,
                "profile_age_days": 45,
            },
            "host:WEB01": {
                "entity_type": "host",
                "entity_id": "WEB01",
                "os": "Windows Server 2019",
                "ip_addresses": ["192.168.1.30"],
                "typical_users": ["svc_iis"],
                "typical_processes": ["w3wp.exe", "iisreset.exe"],
                "typical_connections": ["DB01:1433", "Internet:443"],
                "risk_score": 35,
                "profile_age_days": 90,
            },
            "user:jsmith": {
                "entity_type": "user",
                "entity_id": "jsmith",
                "department": "Finance",
                "role": "Financial Analyst",
                "typical_hours": "9:00-18:00",
                "typical_locations": ["Office-A"],
                "privilege_level": "standard",
                "risk_score": 10,
                "profile_age_days": 60,
            },
        }
        self._profiles = profiles

    def build_profile(self, entity_type: str, entity_id: str,
                      observations: List[Dict[str, Any]]) -> Dict[str, Any]:
        """构建实体行为画像。"""
        key = f"{entity_type}:{entity_id}"
        entry = {
            "entity_type": entity_type,
            "entity_id": entity_id,
            "observations_count": len(observations),
            "built_at": time.strftime("%Y-%m-%d %H:%M:%S"),
            "features": self._extract_features(observations),
        }
        self._profiles[key] = entry
        return entry

    def _extract_features(self, observations: List[Dict[str, Any]]) -> Dict[str, Any]:
        """从观测数据提取行为特征。"""
        if not observations:
            return {}
        features: Dict[str, Any] = {
            "total_events": len(observations),
            "unique_hours": len(set(o.get("hour", 0) for o in observations)),
            "unique_locations": list(set(o.get("location", "") for o in observations if o.get("location"))),
        }
        return features

    def get_profile(self, entity_type: str, entity_id: str) -> Optional[Dict[str, Any]]:
        return self._profiles.get(f"{entity_type}:{entity_id}")

    def list_profiles(self, entity_type: Optional[str] = None) -> List[Dict[str, Any]]:
        items = list(self._profiles.values())
        if entity_type:
            items = [p for p in items if p["entity_type"] == entity_type]
        return items


# --------------------------------------------------------------------------- #
# 异常行为检测
# --------------------------------------------------------------------------- #
class AnomalyDetector:
    """异常行为检测器。"""

    ANOMALY_TYPES = [
        "deviation_from_baseline", "rare_behavior", "burst_behavior",
        "impossible_travel", "abnormal_time", "unusual_location",
    ]

    def __init__(self, baseline_builder: Optional[BehaviorBaselineBuilder] = None) -> None:
        self._baselines = baseline_builder or BehaviorBaselineBuilder()
        self._detected: List[Dict[str, Any]] = []

    def detect(self, observations: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """检测观测数据中的异常行为。"""
        anomalies: List[Dict[str, Any]] = []
        for obs in observations:
            user = obs.get("user", "")
            baseline = self._baselines.get_baseline(user)
            if not baseline:
                continue

            # 异常时间检测
            hour = obs.get("hour", 12)
            if baseline.get("typical_login_hours") and hour not in baseline["typical_login_hours"]:
                anomalies.append(self._make_anomaly(
                    obs, "abnormal_time",
                    f"用户 {user} 在非典型时间 {hour}:00 登录",
                    severity="medium",
                ))

            # 异常位置检测
            location = obs.get("location", "")
            if location and baseline.get("typical_locations") and location not in baseline["typical_locations"]:
                anomalies.append(self._make_anomaly(
                    obs, "unusual_location",
                    f"用户 {user} 从非常用位置 {location} 登录",
                    severity="high",
                ))

            # 不可能旅行检测
            if obs.get("travel_distance_km", 0) > 500:
                anomalies.append(self._make_anomaly(
                    obs, "impossible_travel",
                    f"用户 {user} 在短时间内跨越 {obs.get('travel_distance_km')}km 距离",
                    severity="critical",
                ))

            # 突发行为检测
            if obs.get("event_count_recent", 0) > obs.get("baseline_avg", 5) * 5:
                anomalies.append(self._make_anomaly(
                    obs, "burst_behavior",
                    f"用户 {user} 行为频率突增: {obs.get('event_count_recent')} vs 基线 {obs.get('baseline_avg')}",
                    severity="medium",
                ))

        self._detected.extend(anomalies)
        return anomalies

    def _make_anomaly(self, obs: Dict[str, Any], atype: str,
                      description: str, severity: str = "medium") -> Dict[str, Any]:
        return {
            "anomaly_id": uuid.uuid4().hex[:12],
            "type": atype,
            "description": description,
            "severity": severity,
            "user": obs.get("user", ""),
            "hostname": obs.get("hostname", ""),
            "timestamp": obs.get("timestamp", time.strftime("%Y-%m-%d %H:%M:%S")),
            "evidence": obs,
            "detected_at": time.strftime("%Y-%m-%d %H:%M:%S"),
        }

    def list_anomalies(self, anomaly_type: Optional[str] = None,
                       severity: Optional[str] = None) -> List[Dict[str, Any]]:
        items = list(self._detected)
        if anomaly_type:
            items = [a for a in items if a["type"] == anomaly_type]
        if severity:
            items = [a for a in items if a["severity"] == severity]
        return items


# --------------------------------------------------------------------------- #
# 行为链分析
# --------------------------------------------------------------------------- #
class BehaviorChainAnalyzer:
    """行为链分析器。"""

    def __init__(self) -> None:
        self._chains: Dict[str, Dict[str, Any]] = {}

    def analyze(self, events: List[Dict[str, Any]],
                window_seconds: int = 3600) -> List[Dict[str, Any]]:
        """分析事件序列，重建行为链/攻击路径。"""
        chains: List[Dict[str, Any]] = []
        # 按时间排序
        sorted_events = sorted(events, key=lambda e: e.get("timestamp", ""))

        # 简单链检测：同主机短时间内多事件关联
        host_events: Dict[str, List[Dict[str, Any]]] = {}
        for evt in sorted_events:
            host = evt.get("hostname", "unknown")
            host_events.setdefault(host, []).append(evt)

        for host, evts in host_events.items():
            if len(evts) < 2:
                continue
            chain_id = uuid.uuid4().hex[:12]
            chain = {
                "chain_id": chain_id,
                "hostname": host,
                "events": evts,
                "event_count": len(evts),
                "time_span": f"{evts[0].get('timestamp', '')} ~ {evts[-1].get('timestamp', '')}",
                "attack_chain_stage": self._classify_chain(evts),
                "reconstructed_at": time.strftime("%Y-%m-%d %H:%M:%S"),
            }
            chains.append(chain)
            self._chains[chain_id] = chain

        return chains

    def _classify_chain(self, events: List[Dict[str, Any]]) -> str:
        """根据事件序列推断攻击链阶段。"""
        stages = set()
        for evt in events:
            etype = evt.get("event_type", "")
            name = evt.get("process_name", evt.get("service", ""))
            if name in ("outlook.exe", "winword.exe") or etype == "email_open":
                stages.add("initial_access")
            elif name in ("powershell.exe", "cmd.exe", "wscript.exe"):
                stages.add("execution")
            elif etype == "registry_modify" or name in ("reg.exe",):
                stages.add("persistence")
            elif evt.get("destination_port") in (445, 135, 5985):
                stages.add("lateral_movement")
            elif evt.get("bytes_sent", 0) > 1000000:
                stages.add("exfiltration")
        return " -> ".join(sorted(stages)) if stages else "unknown"

    def list_chains(self) -> List[Dict[str, Any]]:
        return list(self._chains.values())

    def get_chain(self, chain_id: str) -> Optional[Dict[str, Any]]:
        return self._chains.get(chain_id)


# --------------------------------------------------------------------------- #
# 行为评分
# --------------------------------------------------------------------------- #
class BehaviorScorer:
    """行为风险评分器。"""

    RULES = [
        {"rule": "abnormal_time_login", "weight": 15, "description": "非工作时间登录"},
        {"rule": "impossible_travel", "weight": 30, "description": "不可能旅行"},
        {"rule": "rare_process", "weight": 20, "description": "罕见进程执行"},
        {"rule": "suspicious_command_line", "weight": 25, "description": "可疑命令行"},
        {"rule": "unusual_network", "weight": 20, "description": "异常网络连接"},
        {"rule": "multiple_failures", "weight": 10, "description": "多次登录失败"},
        {"rule": "privilege_escalation", "weight": 35, "description": "疑似权限提升"},
    ]

    def score(self, observations: List[Dict[str, Any]]) -> Dict[str, Any]:
        """对行为观测进行风险评分（0-100）。"""
        total_score = 0
        triggered: List[Dict[str, Any]] = []

        for obs in observations:
            # 检查规则触发
            if obs.get("abnormal_time"):
                total_score += 15
                triggered.append({"rule": "abnormal_time_login", "weight": 15})
            if obs.get("impossible_travel"):
                total_score += 30
                triggered.append({"rule": "impossible_travel", "weight": 30})
            if obs.get("rare_process"):
                total_score += 20
                triggered.append({"rule": "rare_process", "weight": 20})
            if obs.get("suspicious_cmd"):
                total_score += 25
                triggered.append({"rule": "suspicious_command_line", "weight": 25})
            if obs.get("unusual_network"):
                total_score += 20
                triggered.append({"rule": "unusual_network", "weight": 20})
            if obs.get("multiple_failures"):
                total_score += 10
                triggered.append({"rule": "multiple_failures", "weight": 10})
            if obs.get("privilege_escalation"):
                total_score += 35
                triggered.append({"rule": "privilege_escalation", "weight": 35})

        score = min(100, total_score)
        confidence = min(0.95, 0.5 + len(triggered) * 0.1)

        return {
            "risk_score": score,
            "risk_level": self._level(score),
            "confidence": round(confidence, 2),
            "triggered_rules": triggered,
            "total_rules": len(self.RULES),
            "scored_at": time.strftime("%Y-%m-%d %H:%M:%S"),
        }

    def _level(self, score: int) -> str:
        if score >= 80:
            return "critical"
        elif score >= 60:
            return "high"
        elif score >= 40:
            return "medium"
        elif score >= 20:
            return "low"
        return "informational"

    def list_rules(self) -> List[Dict[str, Any]]:
        return self.RULES
