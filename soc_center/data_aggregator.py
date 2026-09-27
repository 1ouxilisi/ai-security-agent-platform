# -*- coding: utf-8 -*-
"""
data_aggregator.py — 统一数据聚合层。

职责:
    1. 统一数据模型（任务/告警/漏洞/资产/事件/日志 的统一字段定义）
    2. 各领域数据适配器（将各领域数据转换为统一格式）
    3. 统一数据查询 API（跨领域查询/聚合/统计/筛选）
    4. 统一数据缓存（内存缓存 + 定时刷新）

全部内存字典模拟存储。
"""

from __future__ import annotations

import random
import threading
import time
from typing import Any, Dict, List, Optional


# --------------------------------------------------------------------------- #
# 十六大核心领域元数据
# --------------------------------------------------------------------------- #
DOMAINS: List[Dict[str, str]] = [
    {"key": "web-pentest-pro", "name": "Web 渗透", "icon": "🕸", "route": "/web-pentest-pro"},
    {"key": "internal-pentest-pro", "name": "内网渗透", "icon": "🖥", "route": "/internal-pentest-pro"},
    {"key": "mobile-pentest-pro", "name": "移动安全", "icon": "📱", "route": "/mobile-pentest-pro"},
    {"key": "cloud-security-pro", "name": "云安全", "icon": "☁️", "route": "/cloud-security-pro"},
    {"key": "red-blue-pro", "name": "红蓝对抗", "icon": "⚔️", "route": "/red-blue-pro"},
    {"key": "supply-chain-pro", "name": "供应链安全", "icon": "🔗", "route": "/supply-chain-pro"},
    {"key": "devsecops-pro", "name": "DevSecOps", "icon": "🔁", "route": "/devsecops-pro"},
    {"key": "soc-pro", "name": "SOC 运营", "icon": "🛡", "route": "/soc-pro"},
    {"key": "threat-intel-pro", "name": "威胁情报", "icon": "🕵️", "route": "/threat-intel-pro"},
    {"key": "data-security-pro", "name": "数据安全", "icon": "🗄", "route": "/data-security-pro"},
    {"key": "compliance-pro", "name": "合规审计", "icon": "📋", "route": "/compliance-pro"},
    {"key": "forensics-pro", "name": "数字取证", "icon": "🔍", "route": "/forensics-pro"},
    {"key": "iot-ot-pro", "name": "工控 IoT", "icon": "🏭", "route": "/iot-ot-pro"},
    {"key": "ctf-pro", "name": "CTF", "icon": "🏁", "route": "/ctf-pro"},
    {"key": "src-platform-pro", "name": "SRC 平台", "icon": "📮", "route": "/src-platform-pro"},
    {"key": "security-training-pro", "name": "安全培训", "icon": "🎓", "route": "/security-training-pro"},
]

DOMAIN_KEYS: List[str] = [d["key"] for d in DOMAINS]
DOMAIN_NAME_MAP: Dict[str, str] = {d["key"]: d["name"] for d in DOMAINS}

SEVERITY_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}


def _now() -> float:
    return time.time()


class UnifiedDataAggregator:
    """统一数据聚合层（单例，线程安全）。"""

    def __init__(self) -> None:
        self._lock = threading.RLock()
        self.tasks: Dict[str, Dict[str, Any]] = {}
        self.alerts: Dict[str, Dict[str, Any]] = {}
        self.vulns: Dict[str, Dict[str, Any]] = {}
        self.assets: Dict[str, Dict[str, Any]] = {}
        self.events: Dict[str, Dict[str, Any]] = {}
        self.logs: Dict[str, Dict[str, Any]] = {}
        self._cache: Dict[str, Any] = {}
        self._cache_ts: Dict[str, float] = {}
        self._seq = random.randint(100000, 999999)
        self._seed_demo_data()

    # ------------------------------------------------------------------ #
    def _next_id(self, prefix: str) -> str:
        self._seq += 1
        return f"{prefix}-{int(_now())}-{self._seq}"

    # ------------------------------------------------------------------ #
    # 统一字段适配器：各领域数据 -> 统一格式
    # ------------------------------------------------------------------ #
    def adapt_task(self, raw: Dict[str, Any]) -> Dict[str, Any]:
        return {
            "id": raw.get("id") or self._next_id("task"),
            "domain": raw.get("domain", "soc-pro"),
            "domain_name": DOMAIN_NAME_MAP.get(raw.get("domain", "soc-pro"), "未知"),
            "title": raw.get("title", "未命名任务"),
            "status": raw.get("status", "pending"),  # pending/running/done/failed
            "progress": int(raw.get("progress", 0)),
            "created_at": raw.get("created_at", _now()),
            "updated_at": raw.get("updated_at", _now()),
            "owner": raw.get("owner", "system"),
        }

    def adapt_alert(self, raw: Dict[str, Any]) -> Dict[str, Any]:
        return {
            "id": raw.get("id") or self._next_id("alert"),
            "domain": raw.get("domain", "soc-pro"),
            "domain_name": DOMAIN_NAME_MAP.get(raw.get("domain", "soc-pro"), "未知"),
            "title": raw.get("title", "未知告警"),
            "severity": raw.get("severity", "medium"),
            "status": raw.get("status", "new"),  # new/confirmed/processing/closed/false_positive
            "source": raw.get("source", ""),
            "detail": raw.get("detail", ""),
            "assignee": raw.get("assignee", ""),
            "created_at": raw.get("created_at", _now()),
            "updated_at": raw.get("updated_at", _now()),
        }

    def adapt_vuln(self, raw: Dict[str, Any]) -> Dict[str, Any]:
        return {
            "id": raw.get("id") or self._next_id("vuln"),
            "domain": raw.get("domain", "web-pentest-pro"),
            "domain_name": DOMAIN_NAME_MAP.get(raw.get("domain", "web-pentest-pro"), "未知"),
            "title": raw.get("title", "未知漏洞"),
            "severity": raw.get("severity", "medium"),
            "status": raw.get("status", "open"),  # open/fixed/ignored
            "cve": raw.get("cve", ""),
            "asset": raw.get("asset", ""),
            "cvss": float(raw.get("cvss", 5.0)),
            "detail": raw.get("detail", ""),
            "created_at": raw.get("created_at", _now()),
            "updated_at": raw.get("updated_at", _now()),
        }

    def adapt_asset(self, raw: Dict[str, Any]) -> Dict[str, Any]:
        return {
            "id": raw.get("id") or self._next_id("asset"),
            "domain": raw.get("domain", "soc-pro"),
            "domain_name": DOMAIN_NAME_MAP.get(raw.get("domain", "soc-pro"), "未知"),
            "name": raw.get("name", "未命名资产"),
            "type": raw.get("type", "host"),
            "ip": raw.get("ip", ""),
            "status": raw.get("status", "online"),  # online/offline/risk
            "risk_level": raw.get("risk_level", "low"),
            "owner": raw.get("owner", ""),
            "updated_at": raw.get("updated_at", _now()),
        }

    def adapt_event(self, raw: Dict[str, Any]) -> Dict[str, Any]:
        return {
            "id": raw.get("id") or self._next_id("evt"),
            "domain": raw.get("domain", "soc-pro"),
            "domain_name": DOMAIN_NAME_MAP.get(raw.get("domain", "soc-pro"), "未知"),
            "type": raw.get("type", "info"),
            "message": raw.get("message", ""),
            "detail": raw.get("detail", ""),
            "created_at": raw.get("created_at", _now()),
        }

    def adapt_log(self, raw: Dict[str, Any]) -> Dict[str, Any]:
        return {
            "id": raw.get("id") or self._next_id("log"),
            "user": raw.get("user", "system"),
            "action": raw.get("action", ""),
            "target": raw.get("target", ""),
            "domain": raw.get("domain", ""),
            "detail": raw.get("detail", ""),
            "ip": raw.get("ip", "127.0.0.1"),
            "created_at": raw.get("created_at", _now()),
        }

    # ------------------------------------------------------------------ #
    # 写入入口（供联动引擎/其他领域调用）
    # ------------------------------------------------------------------ #
    def ingest_task(self, raw: Dict[str, Any]) -> Dict[str, Any]:
        with self._lock:
            t = self.adapt_task(raw)
            self.tasks[t["id"]] = t
            self._bust_cache()
            return t

    def ingest_alert(self, raw: Dict[str, Any]) -> Dict[str, Any]:
        with self._lock:
            a = self.adapt_alert(raw)
            self.alerts[a["id"]] = a
            self._bust_cache()
            return a

    def ingest_vuln(self, raw: Dict[str, Any]) -> Dict[str, Any]:
        with self._lock:
            v = self.adapt_vuln(raw)
            self.vulns[v["id"]] = v
            self._bust_cache()
            return v

    def ingest_asset(self, raw: Dict[str, Any]) -> Dict[str, Any]:
        with self._lock:
            a = self.adapt_asset(raw)
            self.assets[a["id"]] = a
            self._bust_cache()
            return a

    def ingest_event(self, raw: Dict[str, Any]) -> Dict[str, Any]:
        with self._lock:
            e = self.adapt_event(raw)
            # 事件流只保留最近 500 条
            if len(self.events) > 500:
                old = sorted(self.events,
                             key=lambda k: self.events[k]["created_at"])[:100]
                for k in old:
                    self.events.pop(k, None)
            self.events[e["id"]] = e
            return e

    def ingest_log(self, raw: Dict[str, Any]) -> Dict[str, Any]:
        with self._lock:
            l = self.adapt_log(raw)
            if len(self.logs) > 800:
                old = sorted(self.logs,
                             key=lambda k: self.logs[k]["created_at"])[:150]
                for k in old:
                    self.logs.pop(k, None)
            self.logs[l["id"]] = l
            return l

    # ------------------------------------------------------------------ #
    # 查询
    # ------------------------------------------------------------------ #
    def list_tasks(self, domain: Optional[str] = None,
                   status: Optional[str] = None,
                   keyword: Optional[str] = None,
                   limit: int = 200) -> List[Dict[str, Any]]:
        with self._lock:
            items = list(self.tasks.values())
        if domain:
            items = [i for i in items if i["domain"] == domain]
        if status:
            items = [i for i in items if i["status"] == status]
        if keyword:
            kw = keyword.lower()
            items = [i for i in items if kw in i["title"].lower()]
        items.sort(key=lambda x: x["updated_at"], reverse=True)
        return items[:limit]

    def list_alerts(self, domain: Optional[str] = None,
                    severity: Optional[str] = None,
                    status: Optional[str] = None,
                    limit: int = 200) -> List[Dict[str, Any]]:
        with self._lock:
            items = list(self.alerts.values())
        if domain:
            items = [i for i in items if i["domain"] == domain]
        if severity:
            items = [i for i in items if i["severity"] == severity]
        if status:
            items = [i for i in items if i["status"] == status]
        items.sort(key=lambda x: (SEVERITY_ORDER.get(x["severity"], 9),
                                  -x["created_at"]))
        return items[:limit]

    def list_vulns(self, domain: Optional[str] = None,
                    severity: Optional[str] = None,
                    status: Optional[str] = None,
                    limit: int = 200) -> List[Dict[str, Any]]:
        with self._lock:
            items = list(self.vulns.values())
        if domain:
            items = [i for i in items if i["domain"] == domain]
        if severity:
            items = [i for i in items if i["severity"] == severity]
        if status:
            items = [i for i in items if i["status"] == status]
        items.sort(key=lambda x: (SEVERITY_ORDER.get(x["severity"], 9),
                                  -x["created_at"]))
        return items[:limit]

    def list_assets(self, domain: Optional[str] = None,
                    status: Optional[str] = None,
                    limit: int = 200) -> List[Dict[str, Any]]:
        with self._lock:
            items = list(self.assets.values())
        if domain:
            items = [i for i in items if i["domain"] == domain]
        if status:
            items = [i for i in items if i["status"] == status]
        items.sort(key=lambda x: x["name"])
        return items[:limit]

    def list_events(self, domain: Optional[str] = None,
                     limit: int = 100) -> List[Dict[str, Any]]:
        with self._lock:
            items = list(self.events.values())
        if domain:
            items = [i for i in items if i["domain"] == domain]
        items.sort(key=lambda x: x["created_at"], reverse=True)
        return items[:limit]

    def list_logs(self, keyword: Optional[str] = None,
                  user: Optional[str] = None,
                  limit: int = 200) -> List[Dict[str, Any]]:
        with self._lock:
            items = list(self.logs.values())
        if user:
            items = [i for i in items if i["user"] == user]
        if keyword:
            kw = keyword.lower()
            items = [i for i in items
                     if kw in i["action"].lower() or kw in i["target"].lower()]
        items.sort(key=lambda x: x["created_at"], reverse=True)
        return items[:limit]

    def get_alert(self, alert_id: str) -> Optional[Dict[str, Any]]:
        return self.alerts.get(alert_id)

    def update_alert(self, alert_id: str, **fields: Any) -> Optional[Dict[str, Any]]:
        with self._lock:
            a = self.alerts.get(alert_id)
            if a is None:
                return None
            a.update(fields)
            a["updated_at"] = _now()
            self._bust_cache()
            return a

    # ------------------------------------------------------------------ #
    # 聚合统计
    # ------------------------------------------------------------------ #
    def stats_summary(self) -> Dict[str, Any]:
        key = "summary"
        hit = self._cache_get(key)
        if hit is not None:
            return hit
        with self._lock:
            tasks = list(self.tasks.values())
            alerts = list(self.alerts.values())
            vulns = list(self.vulns.values())
            assets = list(self.assets.values())

        def cnt(lst: List[Dict[str, Any]], k: str, v: str) -> int:
            return sum(1 for i in lst if i.get(k) == v)

        result = {
            "tasks": {
                "total": len(tasks),
                "running": cnt(tasks, "status", "running"),
                "done": cnt(tasks, "status", "done"),
                "failed": cnt(tasks, "status", "failed"),
                "pending": cnt(tasks, "status", "pending"),
            },
            "alerts": {
                "total": len(alerts),
                "critical": cnt(alerts, "severity", "critical"),
                "high": cnt(alerts, "severity", "high"),
                "medium": cnt(alerts, "severity", "medium"),
                "low": cnt(alerts, "severity", "low"),
                "open": sum(1 for a in alerts
                            if a.get("status") in ("new", "confirmed",
                                                   "processing")),
                "closed": cnt(alerts, "status", "closed"),
                "false_positive": cnt(alerts, "status", "false_positive"),
            },
            "vulns": {
                "total": len(vulns),
                "critical": cnt(vulns, "severity", "critical"),
                "high": cnt(vulns, "severity", "high"),
                "medium": cnt(vulns, "severity", "medium"),
                "low": cnt(vulns, "severity", "low"),
                "open": cnt(vulns, "status", "open"),
                "fixed": cnt(vulns, "status", "fixed"),
            },
            "assets": {
                "total": len(assets),
                "online": cnt(assets, "status", "online"),
                "offline": cnt(assets, "status", "offline"),
                "risk": cnt(assets, "status", "risk"),
            },
        }
        self._cache_set(key, result, ttl=5)
        return result

    def domain_health(self) -> List[Dict[str, Any]]:
        """十六大领域健康度。"""
        with self._lock:
            tasks = list(self.tasks.values())
            alerts = list(self.alerts.values())
            vulns = list(self.vulns.values())
            assets = list(self.assets.values())
        out = []
        for d in DOMAINS:
            k = d["key"]
            dt = [t for t in tasks if t["domain"] == k]
            da = [a for a in alerts if a["domain"] == k]
            dv = [v for v in vulns if v["domain"] == k]
            dast = [a for a in assets if a["domain"] == k]
            open_alert = sum(1 for a in da
                             if a.get("status") in ("new", "confirmed",
                                                    "processing"))
            open_vuln = sum(1 for v in dv if v.get("status") == "open")
            # 综合评分 0-100：基数分 - 风险扣分
            score = 100 - open_alert * 3 - open_vuln * 2
            score = max(20, min(100, score))
            last_act = max([t["updated_at"] for t in dt] +
                           [a["created_at"] for a in da] +
                           [0.0]) if (dt or da) else 0.0
            if score >= 85:
                level = "healthy"
            elif score >= 60:
                level = "warning"
            else:
                level = "critical"
            out.append({
                "key": k, "name": d["name"], "icon": d["icon"],
                "route": d["route"], "score": score, "level": level,
                "tasks": len(dt), "alerts": len(da), "open_alerts": open_alert,
                "vulns": len(dv), "open_vulns": open_vuln,
                "assets": len(dast), "last_activity": last_act,
            })
        return out

    def security_score(self) -> Dict[str, Any]:
        summary = self.stats_summary()
        health = self.domain_health()
        avg = round(sum(h["score"] for h in health) / max(1, len(health)), 1)
        if avg >= 85:
            level = "安全"
        elif avg >= 70:
            level = "良好"
        elif avg >= 55:
            level = "中等风险"
        else:
            level = "高风险"
        return {
            "overall_score": avg,
            "risk_level": level,
            "domain_scores": [{"key": h["key"], "name": h["name"],
                               "score": h["score"], "level": h["level"]}
                              for h in health],
            "summary": summary,
        }

    def trend(self, days: int = 7) -> Dict[str, Any]:
        """生成安全趋势（基于现有数据做演示抖动）。"""
        rng = random.Random(days * 7 + 1)
        summary = self.stats_summary()
        alert_base = max(20, summary["alerts"]["total"])
        vuln_base = max(15, summary["vulns"]["total"])
        task_base = max(10, summary["tasks"]["total"])
        series = []
        now_day = time.time() - 86400 * days
        for i in range(days):
            ts = now_day + 86400 * i
            series.append({
                "label": time.strftime("%m-%d", time.localtime(ts)),
                "alerts": max(1, int(alert_base * (0.2 + rng.random() * 0.6))),
                "vulns": max(1, int(vuln_base * (0.2 + rng.random() * 0.6))),
                "tasks": max(1, int(task_base * (0.2 + rng.random() * 0.6))),
            })
        return {"days": days, "series": series}

    # ------------------------------------------------------------------ #
    # 全局搜索
    # ------------------------------------------------------------------ #
    def global_search(self, keyword: str, limit_per: int = 20) -> Dict[str, Any]:
        kw = (keyword or "").lower().strip()
        if not kw:
            return {"keyword": keyword, "results": {}}
        with self._lock:
            tasks = list(self.tasks.values())
            alerts = list(self.alerts.values())
            vulns = list(self.vulns.values())
            assets = list(self.assets.values())
            logs = list(self.logs.values())

        def hit(item: Dict[str, Any], fields: List[str]) -> bool:
            return any(kw in str(item.get(f, "")).lower() for f in fields)

        return {
            "keyword": keyword,
            "results": {
                "tasks": [t for t in tasks
                          if hit(t, ["title", "domain", "owner"])][:limit_per],
                "alerts": [a for a in alerts
                           if hit(a, ["title", "detail", "source"])][:limit_per],
                "vulns": [v for v in vulns
                          if hit(v, ["title", "cve", "asset", "detail"])][:limit_per],
                "assets": [a for a in assets
                           if hit(a, ["name", "ip", "type"])][:limit_per],
                "logs": [l for l in logs
                         if hit(l, ["action", "target", "user"])][:limit_per],
            },
        }

    # ------------------------------------------------------------------ #
    # 缓存
    # ------------------------------------------------------------------ #
    def _cache_get(self, key: str) -> Optional[Any]:
        ts = self._cache_ts.get(key, 0)
        if time.time() - ts > 30:  # 最长 30s
            return None
        return self._cache.get(key)

    def _cache_set(self, key: str, val: Any, ttl: int = 5) -> None:
        self._cache[key] = val
        self._cache_ts[key] = time.time()

    def _bust_cache(self) -> None:
        self._cache.clear()
        self._cache_ts.clear()

    # ------------------------------------------------------------------ #
    # 演示数据
    # ------------------------------------------------------------------ #
    def _seed_demo_data(self) -> None:
        rng = random.Random(20260920)
        sev_pool = ["critical", "high", "medium", "low"]
        task_titles = {
            "web-pentest-pro": ["主站 SQL 注入专项", "登录框 XSS 复测", "API 越权扫描"],
            "internal-pentest-pro": ["域控权限维持检查", "内网横向移动评估"],
            "mobile-pentest-pro": ["APP 加固检测", "通信加密审计"],
            "cloud-security-pro": ["AKSK 泄露巡检", "存储桶权限审计"],
            "red-blue-pro": ["红队钓鱼演练", "蓝队检测规则验证"],
            "supply-chain-pro": ["开源组件漏洞扫描", "镜像供应链溯源"],
            "devsecops-pro": ["流水线 SAST 接入", "IaC 安全扫描"],
            "soc-pro": ["告警收敛分析", "日志关联规则调优"],
            "threat-intel-pro": ["IOC 情报订阅", "团伙画像更新"],
            "data-security-pro": ["敏感数据发现", "数据分类分级"],
            "compliance-pro": ["等保2.0 差距分析", "PCI-DSS 整改"],
            "forensics-pro": ["终端取证镜像分析", "内存马提取"],
            "iot-ot-pro": ["PLC 固件逆向", "工控协议异常检测"],
            "ctf-pro": ["Web 题解复现", "Pwn 栈溢出练习"],
            "src-platform-pro": ["SRC 漏洞工单分诊", "奖励结算"],
            "security-training-pro": ["钓鱼演练培训", "应急响应演练"],
        }
        # 任务
        for dk, titles in task_titles.items():
            for title in titles:
                st = rng.choice(["running", "done", "done", "pending", "failed"])
                self.ingest_task({
                    "domain": dk, "title": title, "status": st,
                    "progress": rng.randint(0, 100) if st != "done" else 100,
                    "created_at": _now() - rng.randint(3600, 86400 * 5),
                })
        # 告警
        for d in DOMAINS:
            for _ in range(rng.randint(2, 6)):
                sev = rng.choices(sev_pool, weights=[1, 3, 4, 2])[0]
                self.ingest_alert({
                    "domain": d["key"],
                    "title": f"{d['name']}触发安全事件 #{rng.randint(100,999)}",
                    "severity": sev,
                    "status": rng.choice(["new", "confirmed", "processing", "closed"]),
                    "source": rng.choice(["hids", "edr", "waf", "siem", "manual"]),
                    "detail": "演示告警：检测到异常行为，需进一步研判。",
                    "created_at": _now() - rng.randint(60, 86400 * 3),
                })
        # 漏洞
        for d in DOMAINS:
            for _ in range(rng.randint(1, 4)):
                sev = rng.choices(sev_pool, weights=[1, 3, 4, 2])[0]
                self.ingest_vuln({
                    "domain": d["key"],
                    "title": f"演示漏洞-{rng.choice(['RCE','XSS','SSRF','越权','反序列化'])}",
                    "severity": sev,
                    "status": rng.choice(["open", "open", "fixed"]),
                    "cve": f"CVE-2026-{rng.randint(1000,9999)}" if rng.random() > 0.5 else "",
                    "asset": f"10.0.{rng.randint(1,254)}.{rng.randint(1,254)}",
                    "cvss": round(rng.uniform(3.0, 9.8), 1),
                })
        # 资产
        for d in DOMAINS:
            for _ in range(rng.randint(2, 5)):
                self.ingest_asset({
                    "domain": d["key"],
                    "name": f"{d['name']}-资产-{rng.randint(1,50)}",
                    "type": rng.choice(["host", "web", "api", "db", "container"]),
                    "ip": f"10.0.{rng.randint(1,254)}.{rng.randint(1,254)}",
                    "status": rng.choice(["online", "online", "online", "offline", "risk"]),
                    "risk_level": rng.choice(["low", "medium", "high"]),
                })
        # 事件 + 日志
        for _ in range(30):
            dk = rng.choice(DOMAIN_KEYS)
            self.ingest_event({
                "domain": dk, "type": rng.choice(["info", "alert", "task"]),
                "message": f"{DOMAIN_NAME_MAP[dk]}产生一条实时事件",
            })
        for _ in range(40):
            dk = rng.choice(DOMAIN_KEYS)
            self.ingest_log({
                "user": rng.choice(["admin", "analyst1", "soc-bot"]),
                "action": rng.choice(["登录", "处理告警", "创建任务", "查看报告", "更新配置"]),
                "target": f"{DOMAIN_NAME_MAP[dk]}模块",
                "domain": dk,
            })


_default: Optional[UnifiedDataAggregator] = None


def get_aggregator() -> UnifiedDataAggregator:
    global _default
    if _default is None:
        _default = UnifiedDataAggregator()
    return _default
