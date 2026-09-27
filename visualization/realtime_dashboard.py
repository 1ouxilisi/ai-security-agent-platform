# -*- coding: utf-8 -*-
"""
realtime_dashboard 模块 —— 实时监控大屏数据生成器（第10轮升级 / 数据可视化深化模块）

模块功能：
    - 实时安全状态数据（事件数 / 告警数 / 漏洞数 / 资产数 / 在线率 / 今日新增）
    - 实时趋势数据（事件 / 告警 / 漏洞 / 流量，按小时或5分钟聚合）
    - 攻击来源 TOP10 / 攻击类型 TOP10
    - 攻击来源地图数据（经纬度 / 国家 / 省份 / 城市 / 攻击次数 / 严重程度）
    - 最新告警滚动数据（含严重程度颜色编码）
    - 关键指标卡片数据（MTTD / MTTR / SLA / 修复率 等）
    - 大屏专用布局配置（16:9 / 4:3，深色主题，大字体）
    - 内置模拟数据生成器，无真实数据时自动生成合理展示数据

定位说明：
    本模块为授权安全运营 / 防御检测产品的可视化组件，所有数据均为防御视角，
    用于帮助安全运营中心（SOC）监控整体安全态势，请勿用于非法用途。
"""

import os
import json
import math
import time
import random
import threading
from datetime import datetime, timedelta
from typing import Any, Dict, List, Optional

# 严重程度颜色编码（与前端大屏一致）
SEVERITY_COLORS: Dict[str, str] = {
    "critical": "#ff3b3b",   # 红
    "high": "#ff9f2e",       # 橙
    "medium": "#ffd93b",     # 黄
    "low": "#3b9dff",        # 蓝
    "info": "#9aa4b2",       # 灰
}

# 攻击类型池（用于模拟数据）
_ATTACK_TYPES: List[str] = [
    "SQL注入", "XSS跨站脚本", "暴力破解", "端口扫描", "DDoS攻击",
    "命令注入", "文件包含", "未授权访问", "缓冲区溢出", "木马后门",
    "钓鱼攻击", "CSRF", "目录遍历", "凭证填充", "恶意软件传播",
]

# 常见攻击来源国家/地区（含经纬度，简化内置库）
_SOURCE_LOCATIONS: List[Dict[str, Any]] = [
    {"country": "美国", "country_code": "US", "lat": 39.0, "lng": -98.0, "city": "弗吉尼亚"},
    {"country": "俄罗斯", "country_code": "RU", "lat": 61.0, "lng": 90.0, "city": "莫斯科"},
    {"country": "中国", "country_code": "CN", "lat": 35.0, "lng": 105.0, "city": "上海"},
    {"country": "荷兰", "country_code": "NL", "lat": 52.3, "lng": 5.5, "city": "阿姆斯特丹"},
    {"country": "德国", "country_code": "DE", "lat": 51.0, "lng": 9.0, "city": "法兰克福"},
    {"country": "巴西", "country_code": "BR", "lat": -14.0, "lng": -52.0, "city": "圣保罗"},
    {"country": "印度", "country_code": "IN", "lat": 21.0, "lng": 78.0, "city": "孟买"},
    {"country": "韩国", "country_code": "KR", "lat": 37.5, "lng": 127.0, "city": "首尔"},
    {"country": "日本", "country_code": "JP", "lat": 36.0, "lng": 138.0, "city": "东京"},
    {"country": "新加坡", "country_code": "SG", "lat": 1.35, "lng": 103.8, "city": "新加坡"},
    {"country": "英国", "country_code": "GB", "lat": 54.0, "lng": -2.0, "city": "伦敦"},
    {"country": "加拿大", "country_code": "CA", "lat": 56.0, "lng": -106.0, "city": "多伦多"},
]

# 受保护目标（默认位于中国北京机房）
_TARGET_LOCATION: Dict[str, Any] = {
    "country": "中国", "country_code": "CN",
    "province": "北京", "city": "北京",
    "lat": 39.9042, "lng": 116.4074,
    "name": "核心业务机房",
}

_DATA_DIR = os.path.join(
    os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
    "data", "visualization",
)


class RealtimeDashboard:
    """实时监控大屏数据生成器（单例）。

    负责生成实时大屏所需的全部数据：实时状态、趋势、告警、指标、
    攻击来源地图、TOP 排名等。无真实数据源时使用内置模拟数据生成器。
    """

    def __init__(self) -> None:
        """初始化实时大屏数据管理器。"""
        self._lock = threading.Lock()
        self._cache: Dict[str, Any] = {}
        self._last_refresh: float = 0.0
        os.makedirs(_DATA_DIR, exist_ok=True)
        random.seed(int(time.time()))
        # 初始化一批基线模拟数据
        self.refresh_data()

    # ------------------------------------------------------------------ #
    # 内部工具
    # ------------------------------------------------------------------ #
    @staticmethod
    def _severity_list(n: int) -> List[str]:
        """随机生成 n 条严重程度。"""
        weights = ["critical"] * 1 + ["high"] * 3 + ["medium"] * 5 + ["low"] * 6 + ["info"] * 8
        return [random.choice(weights) for _ in range(n)]

    def _gen_alerts(self, n: int) -> List[Dict[str, Any]]:
        """生成 n 条模拟告警。"""
        alerts: List[Dict[str, Any]] = []
        severities = self._severity_list(n)
        now = datetime.now()
        for i in range(n):
            sev = severities[i]
            atype = random.choice(_ATTACK_TYPES)
            loc = random.choice(_SOURCE_LOCATIONS)
            ts = now - timedelta(minutes=random.randint(0, 60 * 12))
            alerts.append({
                "id": f"ALT-{int(ts.timestamp())}-{i:04d}",
                "timestamp": ts.strftime("%Y-%m-%d %H:%M:%S"),
                "severity": sev,
                "color": SEVERITY_COLORS.get(sev, "#9aa4b2"),
                "type": atype,
                "source_ip": f"{random.randint(1,223)}.{random.randint(0,255)}."
                             f"{random.randint(0,255)}.{random.randint(1,254)}",
                "source_location": f"{loc['country']} {loc['city']}",
                "target": random.choice(["web-01", "db-master", "api-gateway", "mail-srv", "vpn-01"]),
                "message": f"检测到{atype}行为，风险等级 {sev.upper()}",
                "status": random.choice(["new", "investigating", "resolved"]),
            })
        alerts.sort(key=lambda a: a["timestamp"], reverse=True)
        return alerts

    def _gen_trend(self, points: int, base: int, volatility: float) -> List[Dict[str, Any]]:
        """生成折线趋势序列。"""
        series: List[Dict[str, Any]] = []
        now = datetime.now().replace(minute=0, second=0, microsecond=0)
        value = base
        for i in range(points - 1, -1, -1):
            ts = now - timedelta(hours=i)
            value = max(0, int(value + random.uniform(-volatility, volatility) + base * 0.05))
            series.append({"time": ts.strftime("%H:00"), "value": value})
        return series

    def _gen_flow_trend(self, points: int) -> List[Dict[str, Any]]:
        """生成每5分钟聚合的流量趋势（Mbps）。"""
        series: List[Dict[str, Any]] = []
        now = datetime.now().replace(second=0, microsecond=0)
        for i in range(points - 1, -1, -1):
            ts = now - timedelta(minutes=5 * i)
            # 模拟白天高、夜间低的流量曲线 + 噪声
            hour_factor = 0.5 + 0.5 * math.sin((ts.hour - 6) / 24.0 * 2 * math.pi)
            value = int(800 * hour_factor + random.uniform(-60, 60))
            series.append({"time": ts.strftime("%H:%M"), "value": max(200, value)})
        return series

    # ------------------------------------------------------------------ #
    # 公开方法
    # ------------------------------------------------------------------ #
    def refresh_data(self) -> Dict[str, Any]:
        """刷新全部大屏数据（轮询入口）。

        重新生成一批实时状态、趋势、告警、地图与 TOP 数据并写入缓存。
        :return: 本次刷新后的实时状态摘要
        """
        with self._lock:
            now = datetime.now()
            event_count = random.randint(12000, 18000)
            alert_count = random.randint(800, 1500)
            vuln_count = random.randint(320, 600)
            asset_total = random.randint(850, 1050)
            online_rate = round(random.uniform(96.0, 99.8), 1)
            today_new_events = random.randint(180, 420)

            status = {
                "timestamp": now.strftime("%Y-%m-%d %H:%M:%S"),
                "event_count": event_count,
                "alert_count": alert_count,
                "vuln_count": vuln_count,
                "asset_total": asset_total,
                "asset_online": int(asset_total * online_rate / 100),
                "online_rate": online_rate,
                "today_new_events": today_new_events,
                "today_new_alerts": random.randint(30, 90),
                "system_status": "operational",
            }

            self._cache = {
                "status": status,
                "alerts": self._gen_alerts(40),
                "event_trend": self._gen_trend(24, 300, 80),
                "alert_trend": self._gen_trend(24, 40, 15),
                "vuln_trend": self._gen_trend(24, 12, 5),
                "flow_trend": self._gen_flow_trend(24 * 12),
            }
            self._last_refresh = time.time()
            return status

    def get_realtime_data(self) -> Dict[str, Any]:
        """获取实时综合数据（状态 + 地图 + TOP + 指标摘要）。"""
        if not self._cache or time.time() - self._last_refresh > 30:
            self.refresh_data()
        with self._lock:
            return {
                "status": self._cache.get("status", {}),
                "attack_map": self.get_attack_map_data(),
                "top_sources": self.get_top_attack_sources(10),
                "top_types": self.get_top_attack_types(10),
                "metrics": self.get_metrics(),
                "generated_at": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            }

    def get_alerts(self, limit: int = 20) -> List[Dict[str, Any]]:
        """获取最新告警滚动列表。

        :param limit: 返回条数，默认 20
        :return: 告警列表（按时间倒序）
        """
        if not self._cache:
            self.refresh_data()
        with self._lock:
            alerts = self._cache.get("alerts", [])
            return alerts[: max(1, int(limit))]

    def get_metrics(self) -> Dict[str, Any]:
        """获取关键指标卡片数据。"""
        if not self._cache:
            self.refresh_data()
        status = self._cache.get("status", {})
        critical_vulns = int((status.get("vuln_count", 0)) * random.uniform(0.08, 0.15))
        return {
            "mttd_seconds": random.randint(40, 180),           # 平均检测时间（秒）
            "mttr_minutes": random.randint(8, 40),              # 平均响应时间（分钟）
            "sla_compliance": round(random.uniform(92.0, 99.5), 1),
            "fix_rate": round(random.uniform(70.0, 95.0), 1),
            "total_vulns": status.get("vuln_count", 0),
            "critical_vulns": critical_vulns,
            "today_events": status.get("today_new_events", 0),
            "today_alerts": status.get("today_new_alerts", 0),
        }

    def get_trends(self, hours: int = 24) -> Dict[str, Any]:
        """获取实时趋势数据（按小时截取）。

        :param hours: 最近 N 小时，默认 24
        """
        if not self._cache:
            self.refresh_data()
        with self._lock:
            n = max(1, min(168, int(hours)))
            def tail(seq: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
                return seq[-n:] if len(seq) >= n else seq
            return {
                "hours": n,
                "event_trend": tail(self._cache.get("event_trend", [])),
                "alert_trend": tail(self._cache.get("alert_trend", [])),
                "vuln_trend": tail(self._cache.get("vuln_trend", [])),
                "flow_trend": self._cache.get("flow_trend", []),
            }

    def get_attack_map_data(self) -> Dict[str, Any]:
        """获取攻击来源地图数据（数据点 + 源到目标的连线）。"""
        points: List[Dict[str, Any]] = []
        paths: List[Dict[str, Any]] = []
        severities = self._severity_list(len(_SOURCE_LOCATIONS))
        for i, loc in enumerate(_SOURCE_LOCATIONS):
            count = random.randint(20, 800)
            sev = severities[i]
            points.append({
                "lat": loc["lat"], "lng": loc["lng"],
                "country": loc["country"], "city": loc["city"],
                "count": count, "severity": sev,
                "color": SEVERITY_COLORS.get(sev, "#9aa4b2"),
            })
            paths.append({
                "source": {"lat": loc["lat"], "lng": loc["lng"], "name": f"{loc['country']} {loc['city']}"},
                "target": {"lat": _TARGET_LOCATION["lat"], "lng": _TARGET_LOCATION["lng"],
                           "name": _TARGET_LOCATION["name"]},
                "count": count,
                "severity": sev,
                "color": SEVERITY_COLORS.get(sev, "#9aa4b2"),
                "width": max(1, min(6, count / 120)),
                "animated": True,
            })
        points.sort(key=lambda p: p["count"], reverse=True)
        return {
            "map_type": "world",
            "target": _TARGET_LOCATION,
            "points": points,
            "paths": paths,
            "total_attacks": sum(p["count"] for p in points),
        }

    def get_top_attack_sources(self, limit: int = 10) -> List[Dict[str, Any]]:
        """获取攻击来源 TOP N。"""
        points = self.get_attack_map_data()["points"]
        out: List[Dict[str, Any]] = []
        for i, p in enumerate(points[: max(1, int(limit))]):
            out.append({
                "rank": i + 1,
                "country": p["country"],
                "city": p["city"],
                "count": p["count"],
                "severity": p["severity"],
            })
        return out

    def get_top_attack_types(self, limit: int = 10) -> List[Dict[str, Any]]:
        """获取攻击类型 TOP N。"""
        pool = _ATTACK_TYPES * 1
        scored = [(t, random.randint(50, 900)) for t in pool]
        scored.sort(key=lambda x: x[1], reverse=True)
        return [
            {"rank": i + 1, "type": t, "count": c}
            for i, (t, c) in enumerate(scored[: max(1, int(limit))])
        ]

    def get_layout_config(self) -> Dict[str, Any]:
        """获取大屏专用布局配置。"""
        return {
            "resolutions": ["1920x1080", "2560x1440", "3840x2160"],
            "aspect_ratio": "16:9",
            "supported_ratios": ["16:9", "4:3"],
            "theme": {
                "background": "#0a0e17",
                "panel_bg": "#111827",
                "border": "#1e3a5f",
                "text_primary": "#e6f1ff",
                "text_secondary": "#7a8ba6",
                "neon": "#00e5ff",
            },
            "fonts": {
                "title": "32px", "panel_title": "18px",
                "metric_value": "36px", "metric_label": "14px",
                "body": "14px",
            },
            "grid": {
                "left_columns": 3, "center_columns": 6, "right_columns": 3,
                "rows": 4,
            },
            "refresh_interval_seconds": 5,
        }


# 模块级单例
realtime_dashboard = RealtimeDashboard()
