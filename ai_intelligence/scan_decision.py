#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
智能扫描决策引擎 (Scan Decision Engine)
=========================================

根据目标画像与约束，自动生成最优扫描策略并规划执行路径：

    1. 扫描策略自动生成：目标类型 / 资产规模 / 时间窗口 / 风险偏好 → 策略
    2. 扫描路径规划：端口 → 服务 → 漏洞 → 验证，动态调整
    3. 扫描深度自适应：按发现的服务 / 技术栈调整深度与 payload 集
    4. 结果智能分析：聚类 / 去重 / 误报过滤 / 风险优先级排序
    5. 任务自动调度：定时 / 变更触发 / 持续监控 / 资源感知
    6. 扫描质量评估：覆盖率 / 漏报率估算 / 一致性 / 改进建议

全部纯 Python 规则引擎 + 内存字典模拟，仅用于授权安全评估。
"""
from __future__ import annotations

import hashlib
import uuid
from datetime import datetime
from typing import Any, Dict, List, Optional


def _now() -> str:
    return datetime.now().isoformat(timespec="seconds")


# 常见端口 → 服务/技术栈指纹
_SERVICE_FINGERPRINTS: Dict[int, Dict[str, str]] = {
    22: {"service": "ssh", "stack": "linux", "default_depth": "deep"},
    80: {"service": "http", "stack": "web", "default_depth": "deep"},
    443: {"service": "https", "stack": "web", "default_depth": "deep"},
    445: {"service": "smb", "stack": "windows", "default_depth": "deep"},
    1433: {"service": "mssql", "stack": "database", "default_depth": "medium"},
    3306: {"service": "mysql", "stack": "database", "default_depth": "medium"},
    3389: {"service": "rdp", "stack": "windows", "default_depth": "medium"},
    6379: {"service": "redis", "stack": "cache", "default_depth": "deep"},
    8080: {"service": "http-proxy", "stack": "web", "default_depth": "medium"},
    9200: {"service": "elasticsearch", "stack": "search", "default_depth": "deep"},
}

# 风险偏好 → 策略参数
_RISK_PROFILES: Dict[str, Dict[str, Any]] = {
    "low": {"aggressiveness": 0.3, "avoid_stealth_violation": True, "rate_limit": 10},
    "medium": {"aggressiveness": 0.6, "avoid_stealth_violation": True, "rate_limit": 30},
    "high": {"aggressiveness": 0.9, "avoid_stealth_violation": False, "rate_limit": 80},
}

# 误报过滤规则：低危 + 无版本信息 + 通用 banner → 标记可疑误报
_FP_SIGNATURES = {
    "generic_server_header": ["nginx", "apache", "iis"],
    "low_info_finding": ["版本未披露", "banner 通用", "疑似默认页面"],
}


class ScanDecisionEngine:
    """智能扫描决策引擎（单例）。"""

    def __init__(self) -> None:
        self.strategies: Dict[str, Dict[str, Any]] = {}
        self.schedules: Dict[str, Dict[str, Any]] = {}
        self.results: Dict[str, Dict[str, Any]] = {}
        self.task_id_counter = 0

    # ------------------------------------------------------------------
    # 1. 扫描策略自动生成
    # ------------------------------------------------------------------
    def generate_strategy(
        self,
        target: str,
        target_type: str = "web",          # web / host / network / cloud
        asset_scale: str = "small",         # small / medium / large
        time_window_min: int = 30,
        risk_appetite: str = "medium",
    ) -> Dict[str, Any]:
        profile = _RISK_PROFILES.get(risk_appetite, _RISK_PROFILES["medium"])
        port_plan = {
            "small": "top100",
            "medium": "top1000",
            "large": "all-common",
        }.get(asset_scale, "top100")

        steps = [
            {"phase": "port_discovery", "tool": "nmap", "ports": port_plan,
             "expected_minutes": max(2, time_window_min // 6)},
            {"phase": "service_fingerprint", "tool": "nmap -sV",
             "expected_minutes": max(3, time_window_min // 4)},
            {"phase": "vuln_scan", "tool": "nuclei",
             "expected_minutes": max(5, time_window_min // 3)},
            {"phase": "verification", "tool": "poc-runner",
             "expected_minutes": max(2, time_window_min // 6)},
        ]

        sid = f"strat-{uuid.uuid4().hex[:8]}"
        strategy = {
            "strategy_id": sid,
            "target": target,
            "target_type": target_type,
            "asset_scale": asset_scale,
            "time_window_min": time_window_min,
            "risk_appetite": risk_appetite,
            "rate_limit": profile["rate_limit"],
            "aggressiveness": profile["aggressiveness"],
            "port_plan": port_plan,
            "steps": steps,
            "estimated_total_min": sum(s["expected_minutes"] for s in steps),
            "created_at": _now(),
        }
        self.strategies[sid] = strategy
        return strategy

    # ------------------------------------------------------------------
    # 2. 扫描路径规划（动态）
    # ------------------------------------------------------------------
    def plan_path(self, strategy_id: str, discovered_ports: Optional[List[int]] = None) -> Dict[str, Any]:
        strategy = self.strategies.get(strategy_id)
        if not strategy:
            return {"error": "strategy not found"}

        ports = discovered_ports or [80, 443]
        path: List[Dict[str, Any]] = []
        for p in ports:
            fp = _SERVICE_FINGERPRINTS.get(p, {"service": "unknown", "stack": "unknown"})
            path.append({
                "port": p,
                "service": fp["service"],
                "stack": fp["stack"],
                "next_action": "service_probe",
                "depth": fp["default_depth"],
            })
        # 动态调整：发现 web 服务则追加 web 漏洞步骤
        if any(x["stack"] == "web" for x in path):
            path.append({"phase": "web_fuzz", "tool": "nuclei + http-fuzz",
                         "reason": "发现 Web 服务，追加 Web 专项验证"})
        return {
            "strategy_id": strategy_id,
            "path": path,
            "dynamic_adjusted": len(path) > len(ports),
            "planned_at": _now(),
        }

    # ------------------------------------------------------------------
    # 3. 扫描深度自适应
    # ------------------------------------------------------------------
    def adapt_depth(self, service: str, stack: str, current_depth: str = "quick") -> Dict[str, Any]:
        deep_services = {"redis", "smb", "elasticsearch", "mysql", "mssql"}
        promoted = current_depth != "deep" and service in deep_services
        new_depth = "deep" if promoted else current_depth
        payload_set = {
            "quick": "nuclei:tech-detect",
            "medium": "nuclei:cves + misconfig",
            "deep": "nuclei:full + manual-poc",
        }.get(new_depth, "nuclei:tech-detect")
        return {
            "service": service,
            "stack": stack,
            "old_depth": current_depth,
            "new_depth": new_depth,
            "payload_set": payload_set,
            "promoted": promoted,
            "reason": f"{service} 属高价值服务，深度提升为 {new_depth}" if promoted else "维持当前深度",
        }

    # ------------------------------------------------------------------
    # 4. 结果智能分析（聚类/去重/误报过滤/优先级）
    # ------------------------------------------------------------------
    @staticmethod
    def _finding_key(f: Dict[str, Any]) -> str:
        raw = f"{f.get('host', '')}|{f.get('port', '')}|{f.get('plugin', f.get('name', ''))}"
        return hashlib.md5(raw.encode("utf-8")).hexdigest()[:12]

    def analyze_results(self, findings: List[Dict[str, Any]]) -> Dict[str, Any]:
        seen: Dict[str, Dict[str, Any]] = {}
        clusters: Dict[str, List[Dict[str, Any]]] = {}
        filtered_false_positives: List[Dict[str, Any]] = []

        for f in findings:
            key = self._finding_key(f)
            if key in seen:
                continue  # 去重
            seen[key] = f
            # 误报过滤
            banner = str(f.get("banner", "")).lower()
            if f.get("severity") == "low" and any(
                g in banner for g in _FP_SIGNATURES["generic_server_header"]
            ):
                filtered_false_positives.append({**f, "fp_reason": "通用 banner，低危，疑似误报"})
                continue
            # 聚类：按 (host, severity)
            ckey = f"{f.get('host', 'unknown')}#{f.get('severity', 'info')}"
            clusters.setdefault(ckey, []).append(f)

        # 优先级排序
        sev_order = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
        ranked = sorted(
            (f for fs in clusters.values() for f in fs),
            key=lambda x: sev_order.get(x.get("severity", "info"), 9),
        )
        return {
            "total_raw": len(findings),
            "after_dedup": len(seen),
            "false_positive_filtered": len(filtered_false_positives),
            "clusters": len(clusters),
            "priority_ranked": ranked[:50],
            "by_severity": {
                s: sum(1 for x in ranked if x.get("severity") == s)
                for s in ("critical", "high", "medium", "low", "info")
            },
            "analyzed_at": _now(),
        }

    # ------------------------------------------------------------------
    # 5. 任务自动调度
    # ------------------------------------------------------------------
    def schedule_scan(
        self,
        target: str,
        schedule_type: str = "scheduled",   # scheduled / change_trigger / continuous
        cron: str = "0 2 * * *",
        resource_aware: bool = True,
    ) -> Dict[str, Any]:
        sid = f"sch-{uuid.uuid4().hex[:8]}"
        item = {
            "schedule_id": sid,
            "target": target,
            "type": schedule_type,
            "cron": cron,
            "resource_aware": resource_aware,
            "active": True,
            "next_run_inferred": "每日 02:00" if schedule_type == "scheduled" else "事件触发",
            "created_at": _now(),
        }
        self.schedules[sid] = item
        return item

    def list_schedules(self) -> List[Dict[str, Any]]:
        return list(self.schedules.values())

    def pause_schedule(self, schedule_id: str) -> bool:
        item = self.schedules.get(schedule_id)
        if not item:
            return False
        item["active"] = False
        return True

    # ------------------------------------------------------------------
    # 6. 扫描质量评估
    # ------------------------------------------------------------------
    def quality_assess(
        self,
        strategy_id: str,
        scanned_ports: int,
        expected_ports: int,
        repeat_runs: Optional[List[List[Dict[str, Any]]]] = None,
    ) -> Dict[str, Any]:
        coverage = round(min(1.0, scanned_ports / max(1, expected_ports)), 2)
        # 漏报率粗估：覆盖率每低 10%，漏报率上升
        estimated_miss = round(max(0.0, (1.0 - coverage) * 0.4), 2)

        consistency = 1.0
        if repeat_runs and len(repeat_runs) >= 2:
            sets = [set(self._finding_key(f) for f in r) for r in repeat_runs]
            inter = len(sets[0] & sets[1])
            union = len(sets[0] | sets[1]) or 1
            consistency = round(inter / union, 2)

        suggestions: List[str] = []
        if coverage < 0.8:
            suggestions.append("提高端口覆盖率：扩大端口范围至 top1000")
        if consistency < 0.85:
            suggestions.append("提升扫描一致性：固定 payload 版本与超时参数")
        if estimated_miss > 0.2:
            suggestions.append("降低漏报：对高价值服务启用 deep 深度与手动 POC")
        if not suggestions:
            suggestions.append("当前扫描质量良好，保持现有策略即可")

        return {
            "strategy_id": strategy_id,
            "coverage": coverage,
            "estimated_miss_rate": estimated_miss,
            "consistency": consistency,
            "improvement_suggestions": suggestions,
            "assessed_at": _now(),
        }

    def stats(self) -> Dict[str, Any]:
        return {
            "strategy_count": len(self.strategies),
            "schedule_count": len(self.schedules),
            "active_schedules": sum(1 for s in self.schedules.values() if s["active"]),
        }


scan_decision_engine = ScanDecisionEngine()
