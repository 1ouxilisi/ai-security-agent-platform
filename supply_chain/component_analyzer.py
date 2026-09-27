#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
component_analyzer.py — 组件与依赖分析器。

覆盖：
    - 组件指纹识别（名称/版本/生态/PURL 哈希指纹）
    - 依赖图谱、传递依赖分析
    - 版本冲突检测、废弃组件检测、未维护组件识别
    - 组件健康度评分、流行度评估
    - 内置组件元数据库（30+ 常见组件维护状态/流行度）

设计定位：仅做组件分析与健康评估，输出分析报告与建议。
"""

from __future__ import annotations

import hashlib
import time
from typing import Any, Dict, List, Optional, Tuple


# --------------------------------------------------------------------------- #
# 组件健康度评分标准
# --------------------------------------------------------------------------- #
COMPONENT_HEALTH_CRITERIA: Dict[str, Dict[str, Any]] = {
    "maintenance_active": {
        "weight": 0.25, "name": "维护活跃度",
        "description": "最近 6 个月内是否有提交/发版",
    },
    "community_health": {
        "weight": 0.20, "name": "社区健康度",
        "description": "Star 数、Issue 响应、PR 合并率",
    },
    "version_freshness": {
        "weight": 0.15, "name": "版本新鲜度",
        "description": "当前版本与最新版本差距",
    },
    "security_patch_status": {
        "weight": 0.20, "name": "安全补丁状态",
        "description": "已知漏洞是否有修复版本",
    },
    "dependency_health": {
        "weight": 0.10, "name": "依赖健康度",
        "description": "传递依赖的健康程度",
    },
    "adoption_popularity": {
        "weight": 0.10, "name": "采用流行度",
        "description": "下载量、被依赖次数、行业采用率",
    },
}


# --------------------------------------------------------------------------- #
# 内置组件元数据库
# --------------------------------------------------------------------------- #
COMPONENT_META: Dict[str, Dict[str, Any]] = {
    "lodash": {
        "latest_version": "4.17.21", "deprecated": False, "unmaintained": False,
        "last_release": "2021-07-15", "stars": 60500, "downloads_monthly": 45000000,
        "maintainers": 12, "open_issues": 80, "health_score": 85,
        "popularity": "very_high", "category": "utility",
    },
    "axios": {
        "latest_version": "1.7.7", "deprecated": False, "unmaintained": False,
        "last_release": "2024-08-01", "stars": 105000, "downloads_monthly": 80000000,
        "maintainers": 8, "open_issues": 300, "health_score": 82,
        "popularity": "very_high", "category": "network",
    },
    "react": {
        "latest_version": "18.3.1", "deprecated": False, "unmaintained": False,
        "last_release": "2024-06-01", "stars": 228000, "downloads_monthly": 25000000,
        "maintainers": 30, "open_issues": 600, "health_score": 92,
        "popularity": "very_high", "category": "framework",
    },
    "django": {
        "latest_version": "5.1.3", "deprecated": False, "unmaintained": False,
        "last_release": "2024-10-01", "stars": 79000, "downloads_monthly": 5000000,
        "maintainers": 20, "open_issues": 200, "health_score": 90,
        "popularity": "high", "category": "framework",
    },
    "flask": {
        "latest_version": "3.0.3", "deprecated": False, "unmaintained": False,
        "last_release": "2024-05-01", "stars": 67000, "downloads_monthly": 8000000,
        "maintainers": 10, "open_issues": 50, "health_score": 88,
        "popularity": "high", "category": "framework",
    },
    "requests": {
        "latest_version": "2.32.3", "deprecated": False, "unmaintained": False,
        "last_release": "2024-05-01", "stars": 51000, "downloads_monthly": 30000000,
        "maintainers": 15, "open_issues": 2000, "health_score": 78,
        "popularity": "very_high", "category": "network",
    },
    "urllib3": {
        "latest_version": "2.2.3", "deprecated": False, "unmaintained": False,
        "last_release": "2024-09-01", "stars": 4000, "downloads_monthly": 50000000,
        "maintainers": 5, "open_issues": 100, "health_score": 80,
        "popularity": "very_high", "category": "network",
    },
    "numpy": {
        "latest_version": "2.1.3", "deprecated": False, "unmaintained": False,
        "last_release": "2024-10-01", "stars": 28000, "downloads_monthly": 18000000,
        "maintainers": 50, "open_issues": 1500, "health_score": 95,
        "popularity": "very_high", "category": "science",
    },
    "pandas": {
        "latest_version": "2.2.3", "deprecated": False, "unmaintained": False,
        "last_release": "2024-09-01", "stars": 46000, "downloads_monthly": 15000000,
        "maintainers": 40, "open_issues": 3000, "health_score": 90,
        "popularity": "very_high", "category": "data",
    },
    "fastapi": {
        "latest_version": "0.115.5", "deprecated": False, "unmaintained": False,
        "last_release": "2024-11-01", "stars": 81000, "downloads_monthly": 10000000,
        "maintainers": 8, "open_issues": 300, "health_score": 88,
        "popularity": "very_high", "category": "framework",
    },
    "uvicorn": {
        "latest_version": "0.32.0", "deprecated": False, "unmaintained": False,
        "last_release": "2024-10-01", "stars": 7500, "downloads_monthly": 20000000,
        "maintainers": 5, "open_issues": 50, "health_score": 85,
        "popularity": "high", "category": "server",
    },
    "sqlalchemy": {
        "latest_version": "2.0.36", "deprecated": False, "unmaintained": False,
        "last_release": "2024-11-01", "stars": 11000, "downloads_monthly": 8000000,
        "maintainers": 6, "open_issues": 300, "health_score": 87,
        "popularity": "high", "category": "database",
    },
    "redis": {
        "latest_version": "5.2.0", "deprecated": False, "unmaintained": False,
        "last_release": "2024-10-01", "stars": 15000, "downloads_monthly": 5000000,
        "maintainers": 10, "open_issues": 100, "health_score": 85,
        "popularity": "high", "category": "database",
    },
    "celery": {
        "latest_version": "5.4.0", "deprecated": False, "unmaintained": False,
        "last_release": "2024-07-01", "stars": 25000, "downloads_monthly": 3000000,
        "maintainers": 8, "open_issues": 400, "health_score": 78,
        "popularity": "high", "category": "task_queue",
    },
    "log4j-core": {
        "latest_version": "2.24.1", "deprecated": False, "unmaintained": False,
        "last_release": "2024-10-01", "stars": 1500, "downloads_monthly": 1000000,
        "maintainers": 20, "open_issues": 200, "health_score": 72,
        "popularity": "high", "category": "logging",
        "note": "2.14.1 版本存在 Log4Shell (CVE-2021-44228) 严重漏洞",
    },
    "spring-core": {
        "latest_version": "6.1.14", "deprecated": False, "unmaintained": False,
        "last_release": "2024-10-01", "stars": 45000, "downloads_monthly": 5000000,
        "maintainers": 30, "open_issues": 1000, "health_score": 85,
        "popularity": "very_high", "category": "framework",
    },
    "logback-classic": {
        "latest_version": "1.5.12", "deprecated": False, "unmaintained": False,
        "last_release": "2024-10-01", "stars": 3000, "downloads_monthly": 8000000,
        "maintainers": 5, "open_issues": 100, "health_score": 80,
        "popularity": "high", "category": "logging",
    },
    "jackson-databind": {
        "latest_version": "2.18.1", "deprecated": False, "unmaintained": False,
        "last_release": "2024-11-01", "stars": 9000, "downloads_monthly": 15000000,
        "maintainers": 10, "open_issues": 500, "health_score": 82,
        "popularity": "very_high", "category": "serialization",
    },
    "openssl": {
        "latest_version": "3.4.0", "deprecated": False, "unmaintained": False,
        "last_release": "2024-10-01", "stars": 25000, "downloads_monthly": 0,
        "maintainers": 50, "open_issues": 500, "health_score": 90,
        "popularity": "very_high", "category": "crypto",
        "note": "1.1.1k 已 EOL（2023-09-11），存在多个已知漏洞",
    },
    "nginx": {
        "latest_version": "1.27.2", "deprecated": False, "unmaintained": False,
        "last_release": "2024-09-01", "stars": 26000, "downloads_monthly": 0,
        "maintainers": 20, "open_issues": 300, "health_score": 88,
        "popularity": "very_high", "category": "server",
    },
    "mysql": {
        "latest_version": "9.1.0", "deprecated": False, "unmaintained": False,
        "last_release": "2024-10-01", "stars": 12000, "downloads_monthly": 0,
        "maintainers": 100, "open_issues": 5000, "health_score": 85,
        "popularity": "very_high", "category": "database",
    },
    "postgresql": {
        "latest_version": "17.2", "deprecated": False, "unmaintained": False,
        "last_release": "2024-11-01", "stars": 15000, "downloads_monthly": 0,
        "maintainers": 100, "open_issues": 2000, "health_score": 92,
        "popularity": "very_high", "category": "database",
    },
    "jquery": {
        "latest_version": "3.7.1", "deprecated": False, "unmaintained": False,
        "last_release": "2023-08-01", "stars": 59000, "downloads_monthly": 30000000,
        "maintainers": 8, "open_issues": 100, "health_score": 75,
        "popularity": "very_high", "category": "dom",
    },
    "webpack": {
        "latest_version": "5.96.1", "deprecated": False, "unmaintained": False,
        "last_release": "2024-11-01", "stars": 65000, "downloads_monthly": 20000000,
        "maintainers": 15, "open_issues": 150, "health_score": 85,
        "popularity": "very_high", "category": "build_tool",
    },
    "left-pad": {
        "latest_version": "1.3.0", "deprecated": True, "unmaintained": True,
        "last_release": "2016-04-01", "stars": 500, "downloads_monthly": 100000,
        "maintainers": 1, "open_issues": 50, "health_score": 20,
        "popularity": "low", "category": "utility",
        "note": "已废弃，建议使用原生 String.prototype.padStart",
    },
    "request": {
        "latest_version": "2.88.2", "deprecated": True, "unmaintained": True,
        "last_release": "2020-03-01", "stars": 25000, "downloads_monthly": 5000000,
        "maintainers": 5, "open_issues": 1000, "health_score": 30,
        "popularity": "medium", "category": "network",
        "note": "已废弃，官方推荐使用 undici / axios / fetch",
    },
    "coffeescript": {
        "latest_version": "2.7.0", "deprecated": False, "unmaintained": True,
        "last_release": "2022-10-01", "stars": 17000, "downloads_monthly": 500000,
        "maintainers": 3, "open_issues": 200, "health_score": 35,
        "popularity": "low", "category": "language",
        "note": "社区活跃度极低，建议迁移到 TypeScript",
    },
    "node-uuid": {
        "latest_version": "1.4.8", "deprecated": True, "unmaintained": True,
        "last_release": "2017-09-01", "stars": 3000, "downloads_monthly": 2000000,
        "maintainers": 2, "open_issues": 30, "health_score": 15,
        "popularity": "medium", "category": "utility",
        "note": "已重命名为 uuid，node-uuid 包已废弃",
    },
}


# --------------------------------------------------------------------------- #
# 组件与依赖分析器
# --------------------------------------------------------------------------- #
class ComponentAnalyzer:
    """组件与依赖分析器。"""

    def __init__(self) -> None:
        self._analyses: Dict[str, Dict[str, Any]] = {}

    # ---------------- 组件指纹识别 ---------------- #
    def fingerprint(self, name: str, version: str, ecosystem: str = "unknown") -> str:
        """生成组件唯一指纹。"""
        raw = f"{ecosystem}:{name}:{version}".lower()
        return hashlib.sha256(raw.encode()).hexdigest()[:24]

    def identify_component(self, name: str, version: str = "",
                           ecosystem: str = "") -> Dict[str, Any]:
        """识别组件信息并生成指纹。"""
        meta = COMPONENT_META.get(name, {})
        fp = self.fingerprint(name, version, ecosystem)
        return {
            "name": name,
            "version": version,
            "ecosystem": ecosystem or meta.get("ecosystem", "unknown"),
            "fingerprint": fp,
            "known": bool(meta),
            "latest_version": meta.get("latest_version"),
            "deprecated": meta.get("deprecated", False),
            "unmaintained": meta.get("unmaintained", False),
            "stars": meta.get("stars", 0),
            "popularity": meta.get("popularity", "unknown"),
            "category": meta.get("category", "unknown"),
            "note": meta.get("note", ""),
        }

    # ---------------- 依赖图谱 ---------------- #
    def build_dependency_graph(self, components: List[Dict[str, Any]]) -> Dict[str, Any]:
        """构建依赖图谱。"""
        nodes = []
        edges = []
        for c in components:
            name = c.get("name", "unknown")
            ver = c.get("version", "")
            nodes.append({
                "id": f"{name}@{ver}",
                "label": f"{name}@{ver}",
                "type": c.get("type", "library"),
                "ecosystem": c.get("ecosystem", "unknown"),
                "is_direct": c.get("is_direct", True),
                "health_score": self._compute_health(name, ver),
            })
            # 模拟传递依赖边
            dep_count = c.get("dep_count", 0)
            for i in range(min(dep_count, 3)):
                edges.append({
                    "source": f"{name}@{ver}",
                    "target": f"{name}-dep{i+1}@1.0.0",
                    "type": "transitive",
                })

        return {
            "nodes": nodes,
            "edges": edges,
            "total_nodes": len(nodes),
            "total_edges": len(edges),
            "direct_count": sum(1 for n in nodes if n["is_direct"]),
            "transitive_count": sum(1 for n in nodes if not n["is_direct"]),
        }

    # ---------------- 传递依赖分析 ---------------- #
    def analyze_transitive_deps(self, components: List[Dict[str, Any]]) -> Dict[str, Any]:
        """分析传递依赖。"""
        direct = [c for c in components if c.get("is_direct", True)]
        transitive = [c for c in components if not c.get("is_direct", True)]

        # 统计每个直接依赖引入的传递依赖数
        dep_tree = []
        for c in direct:
            dep_tree.append({
                "name": c["name"],
                "version": c.get("version", ""),
                "transitive_dep_count": c.get("dep_count", 0),
                "transitive_deps": [
                    {"name": f"{c['name']}-sub-dep-{i+1}", "version": "1.0.0"}
                    for i in range(min(c.get("dep_count", 0), 5))
                ],
            })

        return {
            "direct_deps": len(direct),
            "transitive_deps": len(transitive),
            "total": len(components),
            "transitive_ratio": round(len(transitive) / max(len(components), 1) * 100, 1),
            "dep_tree": dep_tree,
            "risk_note": "传递依赖占比越高，供应链攻击面越大",
        }

    # ---------------- 版本冲突检测 ---------------- #
    def detect_version_conflicts(self, components: List[Dict[str, Any]]) -> Dict[str, Any]:
        """检测版本冲突。"""
        # 按名称分组，检查是否有多个版本
        by_name: Dict[str, List[Dict[str, Any]]] = {}
        for c in components:
            name = c.get("name", "")
            by_name.setdefault(name, []).append(c)

        conflicts = []
        for name, versions in by_name.items():
            if len(versions) > 1:
                vlist = [v.get("version", "?") for v in versions]
                conflicts.append({
                    "name": name,
                    "versions": vlist,
                    "count": len(versions),
                    "severity": "high" if len(set(vlist)) > 1 else "low",
                    "recommendation": f"统一 {name} 到同一版本，建议升级到最新稳定版",
                })

        return {
            "total_conflicts": len(conflicts),
            "conflicts": conflicts,
            "components_checked": len(components),
        }

    # ---------------- 废弃组件检测 ---------------- #
    def detect_deprecated(self, components: List[Dict[str, Any]]) -> Dict[str, Any]:
        """检测废弃/未维护组件。"""
        deprecated = []
        unmaintained = []
        for c in components:
            name = c.get("name", "")
            meta = COMPONENT_META.get(name, {})
            if meta.get("deprecated"):
                deprecated.append({
                    "name": name, "version": c.get("version", ""),
                    "reason": meta.get("note", "该组件已被官方标记为废弃"),
                    "replacement": self._suggest_replacement(name),
                })
            elif meta.get("unmaintained"):
                unmaintained.append({
                    "name": name, "version": c.get("version", ""),
                    "reason": meta.get("note", "该组件已停止维护超过 12 个月"),
                    "replacement": self._suggest_replacement(name),
                })

        return {
            "deprecated": deprecated,
            "unmaintained": unmaintained,
            "total_deprecated": len(deprecated),
            "total_unmaintained": len(unmaintained),
            "total_flagged": len(deprecated) + len(unmaintained),
        }

    @staticmethod
    def _suggest_replacement(name: str) -> str:
        suggestions = {
            "left-pad": "String.prototype.padStart (原生 JS)",
            "request": "axios / undici / fetch",
            "node-uuid": "uuid",
            "coffeescript": "TypeScript",
        }
        return suggestions.get(name, "建议调研同类活跃替代方案")

    # ---------------- 组件健康度评分 ---------------- #
    def _compute_health(self, name: str, version: str = "") -> int:
        """计算组件健康度评分 (0-100)。"""
        meta = COMPONENT_META.get(name, {})
        if not meta:
            return 50  # 未知组件给中性分

        score = meta.get("health_score", 50)
        # 版本过旧扣分
        if version and meta.get("latest_version"):
            if self._version_tuple(version) < self._version_tuple(meta["latest_version"]):
                score -= 10
        if meta.get("deprecated"):
            score -= 30
        if meta.get("unmaintained"):
            score -= 20
        return max(0, min(100, score))

    def analyze_health(self, components: List[Dict[str, Any]]) -> Dict[str, Any]:
        """批量分析组件健康度。"""
        results = []
        for c in components:
            name = c.get("name", "")
            ver = c.get("version", "")
            score = self._compute_health(name, ver)
            meta = COMPONENT_META.get(name, {})
            grade = self._health_grade(score)
            results.append({
                "name": name, "version": ver,
                "health_score": score, "grade": grade,
                "latest_version": meta.get("latest_version"),
                "outdated": version_older(ver, meta.get("latest_version", "")),
                "deprecated": meta.get("deprecated", False),
                "unmaintained": meta.get("unmaintained", False),
                "stars": meta.get("stars", 0),
                "popularity": meta.get("popularity", "unknown"),
            })

        # 汇总
        scores = [r["health_score"] for r in results]
        avg = round(sum(scores) / max(len(scores), 1), 1)
        return {
            "components_analyzed": len(results),
            "average_health_score": avg,
            "overall_grade": self._health_grade(avg),
            "components": results,
            "grade_distribution": {
                "A (90+)": sum(1 for s in scores if s >= 90),
                "B (75-89)": sum(1 for s in scores if 75 <= s < 90),
                "C (60-74)": sum(1 for s in scores if 60 <= s < 75),
                "D (40-59)": sum(1 for s in scores if 40 <= s < 60),
                "F (<40)": sum(1 for s in scores if s < 40),
            },
        }

    @staticmethod
    def _health_grade(score: float) -> str:
        if score >= 90: return "A"
        if score >= 75: return "B"
        if score >= 60: return "C"
        if score >= 40: return "D"
        return "F"

    # ---------------- 流行度评估 ---------------- #
    def assess_popularity(self, components: List[Dict[str, Any]]) -> Dict[str, Any]:
        """评估组件流行度。"""
        tiers = {"very_high": [], "high": [], "medium": [], "low": [], "unknown": []}
        for c in components:
            name = c.get("name", "")
            meta = COMPONENT_META.get(name, {})
            tier = meta.get("popularity", "unknown")
            tiers.setdefault(tier, []).append({
                "name": name,
                "version": c.get("version", ""),
                "stars": meta.get("stars", 0),
                "monthly_downloads": meta.get("downloads_monthly", 0),
            })

        return {
            "popularity_distribution": {k: len(v) for k, v in tiers.items()},
            "very_high_popularity": tiers["very_high"],
            "high_popularity": tiers["high"],
            "medium_popularity": tiers["medium"],
            "low_popularity": tiers["low"],
            "unknown_popularity": tiers["unknown"],
            "risk_note": "低流行度组件供应链风险较高（维护者少、曝光低）",
        }

    # ---------------- 完整分析 ---------------- #
    def full_analysis(self, components: List[Dict[str, Any]]) -> Dict[str, Any]:
        """执行完整组件分析。"""
        analysis_id = f"CA-{int(time.time())}"
        result = {
            "analysis_id": analysis_id,
            "analyzed_at": time.strftime("%Y-%m-%d %H:%M:%S"),
            "total_components": len(components),
            "dependency_graph": self.build_dependency_graph(components),
            "transitive_deps": self.analyze_transitive_deps(components),
            "version_conflicts": self.detect_version_conflicts(components),
            "deprecated_components": self.detect_deprecated(components),
            "health_assessment": self.analyze_health(components),
            "popularity_assessment": self.assess_popularity(components),
        }
        self._analyses[analysis_id] = result
        return result

    def get_analysis(self, analysis_id: str) -> Optional[Dict[str, Any]]:
        return self._analyses.get(analysis_id)

    def list_analyses(self) -> List[Dict[str, Any]]:
        return [
            {"analysis_id": k, "total_components": v.get("total_components", 0),
             "analyzed_at": v.get("analyzed_at", "")}
            for k, v in self._analyses.items()
        ]

    def get_report_markdown(self, analysis_id: str) -> str:
        """生成分析报告 Markdown。"""
        a = self._analyses.get(analysis_id)
        if not a:
            return "# 分析未找到"
        lines = [
            f"# 组件与依赖分析报告", "",
            f"- 分析 ID: {analysis_id}",
            f"- 分析时间: {a.get('analyzed_at')}",
            f"- 组件总数: {a.get('total_components')}", "",
            "## 健康度概览",
            f"- 平均健康分: {a.get('health_assessment', {}).get('average_health_score')}",
            f"- 整体评级: {a.get('health_assessment', {}).get('overall_grade')}", "",
            "## 风险发现",
            f"- 版本冲突: {a.get('version_conflicts', {}).get('total_conflicts')}",
            f"- 废弃组件: {a.get('deprecated_components', {}).get('total_deprecated')}",
            f"- 未维护组件: {a.get('deprecated_components', {}).get('total_unmaintained')}",
        ]
        return "\n".join(lines)


def version_older(v1: str, v2: str) -> bool:
    """判断 v1 是否比 v2 旧。"""
    if not v1 or not v2:
        return False
    return ComponentAnalyzer._version_tuple(v1) < ComponentAnalyzer._version_tuple(v2)


# 补充版本比较方法到类
ComponentAnalyzer._version_tuple = staticmethod(  # type: ignore
    lambda v: tuple(
        int("".join(ch for ch in p if ch.isdigit()) or "0")
        for p in v.replace("-", ".").split(".")
    )
)
