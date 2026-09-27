#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
ueba_engine.py — UEBA 用户实体行为分析引擎
============================================

功能：
    1. 用户行为基线：登录时间/地点/设备/频率/操作习惯/数据访问量/异常行为检测
    2. 实体行为基线：服务器/网络设备/应用/数据库/容器/云资源的正常行为基线
    3. 行为偏离检测：时间/地点/设备/频率/量级/模式/组合偏离
    4. 风险评分：用户/实体/行为/综合风险评分、动态调整、风险趋势
    5. 同行群体分析：同部门/同角色/同级别/同岗位行为对比与异常偏离识别
    6. UEBA 告警：高风险/异常登录/异常访问/异常操作/异常数据告警、分级与响应

全部内存字典模拟，支持 scikit-learn/numpy 可选导入。
"""
from __future__ import annotations

import math
import random
import uuid
from datetime import datetime, timedelta
from typing import Any, Dict, List, Optional, Tuple

# 可选第三方库
try:
    import numpy as np  # type: ignore
    _HAS_NUMPY = True
except Exception:
    _HAS_NUMPY = False

try:
    from sklearn.ensemble import IsolationForest  # type: ignore
    from sklearn.svm import OneClassSVM  # type: ignore
    from sklearn.neighbors import LocalOutlierFactor  # type: ignore
    _HAS_SKLEARN = True
except Exception:
    _HAS_SKLEARN = False


def _now() -> str:
    return datetime.now().isoformat(timespec="seconds")


def _ts(offset_min: int = 0) -> str:
    return (datetime.now() - timedelta(minutes=offset_min)).isoformat(timespec="seconds")


# ==================== 用户与实体种子数据 ====================

_DEPARTMENTS = ["研发部", "安全部", "运维部", "财务部", "人事部", "市场部", "法务部"]
_ROLES = ["工程师", "高级工程师", "主管", "经理", "总监", "管理员", "分析师"]
_LOCATIONS = [
    {"city": "北京", "region": "华北", "lat": 39.90, "lon": 116.40},
    {"city": "上海", "region": "华东", "lat": 31.23, "lon": 121.47},
    {"city": "深圳", "region": "华南", "lat": 22.54, "lon": 114.06},
    {"city": "昆明", "region": "西南", "lat": 25.04, "lon": 102.71},
    {"city": "成都", "region": "西南", "lat": 30.57, "lon": 104.07},
    {"city": "远程-VPN", "region": "远程", "lat": 0.0, "lon": 0.0},
]
_DEVICES = ["Win10-Desktop", "Win11-Laptop", "MacBook-Pro", "Linux-Workstation", "iPhone-Mobile", "Android-Tablet"]


def _gen_users(n: int = 30) -> List[Dict[str, Any]]:
    users = []
    for i in range(1, n + 1):
        dept = random.choice(_DEPARTMENTS)
        role = random.choice(_ROLES)
        base_loc = random.choice(_LOCATIONS)
        base_hour = random.randint(8, 10)
        users.append({
            "user_id": f"U{i:04d}",
            "username": f"user{i:03d}",
            "display_name": f"用户{i:03d}",
            "department": dept,
            "role": role,
            "level": random.randint(1, 6),
            "position": f"{dept}-{role}",
            "base_location": base_loc,
            "base_login_hour": base_hour,
            "base_logout_hour": random.randint(17, 19),
            "base_daily_logins": random.randint(1, 4),
            "base_data_access_mb": round(random.uniform(50, 500), 1),
            "base_apps": random.sample(["OA", "邮箱", "VPN", "SSH", "RDP", "Git", "CI/CD", "数据库"], k=random.randint(3, 6)),
            "primary_device": random.choice(_DEVICES),
            "join_date": (datetime.now() - timedelta(days=random.randint(30, 3000))).strftime("%Y-%m-%d"),
            "status": "active",
            "risk_score": 0,
            "risk_level": "low",
        })
    return users


def _gen_entities(n: int = 25) -> List[Dict[str, Any]]:
    types = ["服务器", "网络设备", "应用", "数据库", "容器", "云资源"]
    entities = []
    for i in range(1, n + 1):
        etype = random.choice(types)
        entities.append({
            "entity_id": f"E{i:04d}",
            "name": f"{etype}-{i:03d}",
            "type": etype,
            "ip": f"10.{random.randint(0,255)}.{random.randint(0,255)}.{random.randint(1,254)}",
            "os": random.choice(["Linux", "Windows", "ESXi", "Container", "Cloud"]),
            "owner_dept": random.choice(_DEPARTMENTS),
            "base_cpu_pct": round(random.uniform(20, 60), 1),
            "base_mem_pct": round(random.uniform(30, 70), 1),
            "base_net_in_mbps": round(random.uniform(10, 200), 1),
            "base_net_out_mbps": round(random.uniform(5, 150), 1),
            "base_conn_count": random.randint(50, 500),
            "base_query_per_min": random.randint(100, 2000),
            "status": random.choice(["online", "online", "online", "maintenance"]),
            "risk_score": 0,
        })
    return entities


# ==================== UEBA 引擎主类 ====================

class UEBAAnalyzer:
    """UEBA 用户实体行为分析引擎。"""

    def __init__(self) -> None:
        self.users: List[Dict[str, Any]] = _gen_users(30)
        self.entities: List[Dict[str, Any]] = _gen_entities(25)
        self._build_baselines()
        self.alerts: List[Dict[str, Any]] = []
        self.anomaly_events: List[Dict[str, Any]] = []
        self.peer_groups: Dict[str, List[str]] = self._build_peer_groups()
        self.risk_history: Dict[str, List[Dict[str, Any]]] = {}

    # ---------- 基线构建 ----------

    def _build_baselines(self) -> None:
        """为每个用户/实体建立行为基线统计量。"""
        for u in self.users:
            u["baseline"] = {
                "login_hours": {
                    "mean": u["base_login_hour"] + random.uniform(-0.5, 0.5),
                    "std": 1.5,
                    "range": [u["base_login_hour"] - 2, u["base_login_hour"] + 2],
                },
                "locations": [u["base_location"]["city"]],
                "devices": [u["primary_device"]],
                "daily_login_count": {
                    "mean": u["base_daily_logins"],
                    "std": 0.8,
                },
                "data_access_mb": {
                    "mean": u["base_data_access_mb"],
                    "std": u["base_data_access_mb"] * 0.3,
                },
                "apps": u["base_apps"],
                "workdays": ["周一", "周二", "周三", "周四", "周五"],
                "operations_per_day": random.randint(50, 300),
            }
        for e in self.entities:
            e["baseline"] = {
                "cpu_pct": {"mean": e["base_cpu_pct"], "std": 8.0},
                "mem_pct": {"mean": e["base_mem_pct"], "std": 10.0},
                "net_in_mbps": {"mean": e["base_net_in_mbps"], "std": 30.0},
                "net_out_mbps": {"mean": e["base_net_out_mbps"], "std": 25.0},
                "conn_count": {"mean": e["base_conn_count"], "std": 80},
                "query_per_min": {"mean": e["base_query_per_min"], "std": 300},
            }

    def _build_peer_groups(self) -> Dict[str, List[str]]:
        """按部门+角色构建同行群体。"""
        groups: Dict[str, List[str]] = {}
        for u in self.users:
            key = f"{u['department']}|{u['role']}"
            groups.setdefault(key, []).append(u["user_id"])
        return groups

    # ---------- 行为偏离检测 ----------

    def _z_score(self, value: float, mean: float, std: float) -> float:
        if std <= 0:
            return 0.0
        return (value - mean) / std

    def detect_deviation(self, user_id: str, event: Dict[str, Any]) -> Dict[str, Any]:
        """检测单个用户事件的多维行为偏离。"""
        user = next((u for u in self.users if u["user_id"] == user_id), None)
        if not user:
            return {"error": f"用户 {user_id} 不存在"}

        bl = user["baseline"]
        deviations: List[Dict[str, Any]] = []
        score = 0.0

        # 时间偏离
        event_hour = event.get("login_hour", datetime.now().hour)
        hour_mean = bl["login_hours"]["mean"]
        hour_std = bl["login_hours"]["std"]
        z = self._z_score(event_hour, hour_mean, hour_std)
        if abs(z) > 2:
            sev = "high" if abs(z) > 3 else "medium"
            deviations.append({
                "type": "时间偏离", "detail": f"登录时间 {event_hour}:00 偏离基线均值 {hour_mean:.1f} (Z={z:.2f})",
                "severity": sev, "weight": min(abs(z) * 8, 40),
            })
            score += min(abs(z) * 8, 40)

        # 地点偏离
        event_loc = event.get("location", user["base_location"]["city"])
        if event_loc not in bl["locations"]:
            deviations.append({
                "type": "地点偏离", "detail": f"从新地点 '{event_loc}' 登录，基线地点: {bl['locations']}",
                "severity": "high", "weight": 35,
            })
            score += 35

        # 设备偏离
        event_dev = event.get("device", user["primary_device"])
        if event_dev not in bl["devices"]:
            deviations.append({
                "type": "设备偏离", "detail": f"使用新设备 '{event_dev}' 登录，基线设备: {bl['devices']}",
                "severity": "medium", "weight": 25,
            })
            score += 25

        # 频率偏离
        event_logins = event.get("login_count_today", 1)
        freq_mean = bl["daily_login_count"]["mean"]
        freq_std = bl["daily_login_count"]["std"]
        z_freq = self._z_score(event_logins, freq_mean, freq_std)
        if z_freq > 2:
            deviations.append({
                "type": "频率偏离", "detail": f"今日登录 {event_logins} 次，基线 {freq_mean:.1f} (Z={z_freq:.2f})",
                "severity": "medium", "weight": min(z_freq * 6, 30),
            })
            score += min(z_freq * 6, 30)

        # 量级偏离（数据访问量）
        event_data = event.get("data_access_mb", 0)
        data_mean = bl["data_access_mb"]["mean"]
        data_std = bl["data_access_mb"]["std"]
        z_data = self._z_score(event_data, data_mean, data_std)
        if z_data > 2.5:
            deviations.append({
                "type": "量级偏离", "detail": f"数据访问 {event_data}MB，基线 {data_mean:.1f}MB (Z={z_data:.2f})",
                "severity": "high" if z_data > 4 else "medium", "weight": min(z_data * 7, 45),
            })
            score += min(z_data * 7, 45)

        # 模式偏离（非工作日登录）
        event_weekday = event.get("weekday", datetime.now().strftime("%A"))
        weekday_map = {"Monday": "周一", "Tuesday": "周二", "Wednesday": "周三",
                       "Thursday": "周四", "Friday": "周五", "Saturday": "周六", "Sunday": "周日"}
        cn_day = weekday_map.get(event_weekday, event_weekday)
        if cn_day not in bl["workdays"]:
            deviations.append({
                "type": "模式偏离", "detail": f"非工作日 ({cn_day}) 登录，基线工作日: {bl['workdays']}",
                "severity": "medium", "weight": 20,
            })
            score += 20

        # 组合偏离（多维度同时偏离）
        if len(deviations) >= 3:
            deviations.append({
                "type": "组合偏离", "detail": f"同时出现 {len(deviations)} 种偏离模式，组合风险显著升高",
                "severity": "critical", "weight": 30,
            })
            score += 30

        risk_level = self._score_to_level(score)

        result = {
            "user_id": user_id,
            "username": user["username"],
            "event": event,
            "deviations": deviations,
            "total_score": round(score, 1),
            "risk_level": risk_level,
            "timestamp": _now(),
        }

        if deviations:
            self.anomaly_events.append(result)
            if risk_level in ("high", "critical"):
                self._raise_alert(user_id, result)

        return result

    # ---------- 实体偏离检测 ----------

    def detect_entity_deviation(self, entity_id: str, metrics: Dict[str, float]) -> Dict[str, Any]:
        """检测实体（服务器/网络设备等）行为偏离。"""
        ent = next((e for e in self.entities if e["entity_id"] == entity_id), None)
        if not ent:
            return {"error": f"实体 {entity_id} 不存在"}

        bl = ent.get("baseline", {})
        deviations = []
        score = 0.0

        for metric_name, current_val in metrics.items():
            bl_key = metric_name.replace("_pct", "").replace("_mbps", "").replace("_count", "").replace("_per_min", "")
            # 尝试匹配基线
            for bl_metric, bl_stats in bl.items():
                if bl_metric in metric_name or metric_name in bl_metric:
                    z = self._z_score(current_val, bl_stats["mean"], bl_stats["std"])
                    if abs(z) > 2:
                        sev = "high" if abs(z) > 3 else "medium"
                        w = min(abs(z) * 6, 35)
                        deviations.append({
                            "metric": metric_name, "current": current_val,
                            "baseline_mean": bl_stats["mean"], "z_score": round(z, 2),
                            "severity": sev, "weight": w,
                        })
                        score += w
                    break

        risk_level = self._score_to_level(score)
        result = {
            "entity_id": entity_id, "entity_name": ent["name"], "entity_type": ent["type"],
            "deviations": deviations, "total_score": round(score, 1),
            "risk_level": risk_level, "timestamp": _now(),
        }
        return result

    # ---------- 风险评分 ----------

    def _score_to_level(self, score: float) -> str:
        if score >= 80:
            return "critical"
        if score >= 50:
            return "high"
        if score >= 25:
            return "medium"
        return "low"

    def compute_user_risk(self, user_id: str) -> Dict[str, Any]:
        """计算用户综合风险评分（动态调整）。"""
        user = next((u for u in self.users if u["user_id"] == user_id), None)
        if not user:
            return {"error": f"用户 {user_id} 不存在"}

        # 收集该用户近期异常事件
        events = [e for e in self.anomaly_events if e["user_id"] == user_id]
        recent = [e for e in events if (datetime.now() - datetime.fromisoformat(e["timestamp"])).days <= 7]

        behavior_score = sum(e["total_score"] for e in recent[-10:]) / max(len(recent[-10:]), 1)
        alert_score = len([a for a in self.alerts if a["user_id"] == user_id and a["status"] != "closed"]) * 15

        # 同行对比
        peer_key = f"{user['department']}|{user['role']}"
        peer_ids = self.peer_groups.get(peer_key, [])
        peer_users = [u for u in self.users if u["user_id"] in peer_ids]
        peer_avg_risk = sum(u["risk_score"] for u in peer_users) / max(len(peer_users), 1)
        peer_deviation = behavior_score - peer_avg_risk

        comprehensive = min(behavior_score * 0.5 + alert_score * 0.3 + max(peer_deviation, 0) * 0.2, 100)
        level = self._score_to_level(comprehensive)

        user["risk_score"] = round(comprehensive, 1)
        user["risk_level"] = level

        # 记录风险趋势
        self.risk_history.setdefault(user_id, []).append({
            "timestamp": _now(), "score": round(comprehensive, 1), "level": level,
        })

        return {
            "user_id": user_id, "username": user["username"],
            "behavior_score": round(behavior_score, 1),
            "alert_penalty": alert_score,
            "peer_avg_risk": round(peer_avg_risk, 1),
            "peer_deviation": round(peer_deviation, 1),
            "comprehensive_score": round(comprehensive, 1),
            "risk_level": level,
            "recent_event_count": len(recent),
            "trend_7d": self.risk_history.get(user_id, [])[-7:],
        }

    # ---------- 同行群体分析 ----------

    def peer_group_analysis(self, department: Optional[str] = None, role: Optional[str] = None) -> Dict[str, Any]:
        """同部门/同角色用户行为对比与异常偏离识别。"""
        if department and role:
            keys = [f"{department}|{role}"]
        elif department:
            keys = [k for k in self.peer_groups if k.startswith(department)]
        else:
            keys = list(self.peer_groups.keys())

        results = []
        for key in keys:
            user_ids = self.peer_groups.get(key, [])
            members = [u for u in self.users if u["user_id"] in user_ids]
            if not members:
                continue
            avg_score = sum(u["risk_score"] for u in members) / len(members)
            avg_data = sum(u["base_data_access_mb"] for u in members) / len(members)
            outliers = []
            for m in members:
                if m["risk_score"] > avg_score + 20:
                    outliers.append({
                        "user_id": m["user_id"], "username": m["username"],
                        "risk_score": m["risk_score"],
                        "deviation_from_peer": round(m["risk_score"] - avg_score, 1),
                    })
            results.append({
                "group": key, "member_count": len(members),
                "avg_risk_score": round(avg_score, 1),
                "avg_data_access_mb": round(avg_data, 1),
                "outliers": outliers,
                "outlier_count": len(outliers),
            })

        return {"groups": results, "total_groups": len(results)}

    # ---------- UEBA 告警 ----------

    def _raise_alert(self, user_id: str, event: Dict[str, Any]) -> Dict[str, Any]:
        """生成 UEBA 告警。"""
        user = next((u for u in self.users if u["user_id"] == user_id), {})
        alert_types = {
            "时间偏离": "异常时间告警",
            "地点偏离": "异常登录告警",
            "设备偏离": "异常设备告警",
            "频率偏离": "异常频率告警",
            "量级偏离": "异常数据告警",
            "组合偏离": "复合异常告警",
        }
        primary_dev = event["deviations"][0] if event["deviations"] else {}
        alert_type = alert_types.get(primary_dev.get("type", ""), "高风险行为告警")

        alert = {
            "alert_id": f"UEBA-{uuid.uuid4().hex[:8].upper()}",
            "user_id": user_id,
            "username": user.get("username", ""),
            "department": user.get("department", ""),
            "alert_type": alert_type,
            "severity": event["risk_level"],
            "risk_score": event["total_score"],
            "deviation_count": len(event["deviations"]),
            "details": event["deviations"],
            "status": "open",
            "timestamp": _now(),
            "assignee": None,
            "response": None,
        }
        self.alerts.append(alert)
        return alert

    def list_alerts(self, severity: Optional[str] = None, status: Optional[str] = None,
                    user_id: Optional[str] = None) -> List[Dict[str, Any]]:
        """查询 UEBA 告警列表。"""
        result = self.alerts
        if severity:
            result = [a for a in result if a["severity"] == severity]
        if status:
            result = [a for a in result if a["status"] == status]
        if user_id:
            result = [a for a in result if a["user_id"] == user_id]
        return list(reversed(result))

    def respond_alert(self, alert_id: str, action: str, assignee: Optional[str] = None) -> Dict[str, Any]:
        """响应 UEBA 告警。"""
        alert = next((a for a in self.alerts if a["alert_id"] == alert_id), None)
        if not alert:
            return {"error": f"告警 {alert_id} 不存在"}
        alert["status"] = action
        alert["assignee"] = assignee
        alert["response"] = {
            "action": action, "responded_at": _now(),
            "operator": assignee or "system",
        }
        return alert

    # ---------- ML 模拟：孤立森林 ----------

    def ml_detect(self, user_id: str, features: List[float]) -> Dict[str, Any]:
        """使用孤立森林（或模拟）进行异常检测。"""
        if _HAS_SKLEARN and _HAS_NUMPY:
            try:
                X = np.array(features).reshape(1, -1)
                # 用历史数据拟合（简化：用同用户特征均值作为正常样本）
                hist = np.array([
                    [random.uniform(0, 10), random.uniform(0, 10), random.uniform(0, 10),
                     random.uniform(0, 10), random.uniform(0, 10)]
                    for _ in range(50)
                ])
                clf = IsolationForest(contamination=0.1, random_state=42)
                clf.fit(hist)
                pred = clf.predict(X)[0]
                score = -clf.score_samples(X)[0]
                is_anomaly = pred == -1
                return {
                    "user_id": user_id,
                    "algorithm": "IsolationForest",
                    "is_anomaly": bool(is_anomaly),
                    "anomaly_score": round(float(score), 4),
                    "features_used": len(features),
                    "engine": "sklearn",
                }
            except Exception:
                pass

        # 模拟回退
        anomaly_score = random.uniform(0.1, 0.9)
        return {
            "user_id": user_id,
            "algorithm": "IsolationForest(simulated)",
            "is_anomaly": anomaly_score > 0.7,
            "anomaly_score": round(anomaly_score, 4),
            "features_used": len(features),
            "engine": "simulated",
        }

    # ---------- 概览 ----------

    def overview(self) -> Dict[str, Any]:
        """UEBA 总览统计。"""
        critical = [a for a in self.alerts if a["severity"] == "critical"]
        high = [a for a in self.alerts if a["severity"] == "high"]
        open_alerts = [a for a in self.alerts if a["status"] == "open"]
        high_risk_users = [u for u in self.users if u["risk_score"] >= 50]
        return {
            "total_users": len(self.users),
            "total_entities": len(self.entities),
            "total_alerts": len(self.alerts),
            "critical_alerts": len(critical),
            "high_alerts": len(high),
            "open_alerts": len(open_alerts),
            "high_risk_users": len(high_risk_users),
            "peer_groups": len(self.peer_groups),
            "anomaly_events_recorded": len(self.anomaly_events),
            "users_by_department": {d: len([u for u in self.users if u["department"] == d]) for d in _DEPARTMENTS},
        }


# 单例
ueba_engine = UEBAAnalyzer()
