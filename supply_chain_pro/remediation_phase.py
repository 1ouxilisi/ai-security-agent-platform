# -*- coding: utf-8 -*-
"""
remediation_phase.py — 方向2 供应链安全 Pro：阶段6 整改建议。

功能:
    - 自动生成升级建议（升级到哪个版本）
    - 替代组件推荐
    - 漏洞修复优先级排序
    - 许可证整改建议
    - 依赖优化建议
    - 整改路线图（短期 / 中期 / 长期）
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional


# 替代组件推荐表（名称子串 -> 替代方案）
ALTERNATIVES: Dict[str, Dict[str, str]] = {
    "log4j": {
        "name": "Log4j2",
        "alternative": "Logback / reload4j",
        "reason": "Log4j1 已 EOL，Log4j2 历史漏洞多，"
                  "Logback 同为 SLF4J 实现且漏洞少",
    },
    "shiro-core": {
        "name": "Shiro",
        "alternative": "Spring Security",
        "reason": "Shiro 反序列化漏洞频发，"
                  "Spring Security 维护活跃",
    },
    "fastjson": {
        "name": "Fastjson",
        "alternative": "Jackson / Gson",
        "reason": "Fastjson AutoType 绕过持续出现，"
                  "Jackson 生态成熟",
    },
    "snakeyaml": {
        "name": "SnakeYAML",
        "alternative": "SnakeYAML 2.x + SafeConstructor",
        "reason": "升级到 2.x 并使用 SafeConstructor",
    },
    "django": {
        "name": "Django",
        "alternative": "升级 LTS 版本",
        "reason": "升级到 4.2 LTS 或 5.x",
    },
    "requests": {
        "name": "requests",
        "alternative": "升级 requests >= 2.32",
        "reason": "修复证书泄露问题",
    },
    "axios": {
        "name": "axios",
        "alternative": "升级 axios >= 1.7.4",
        "reason": "修复 SSRF",
    },
    "lodash": {
        "name": "lodash",
        "alternative": "升级 lodash >= 4.17.21",
        "reason": "修复命令注入",
    },
}


@dataclass
class RemediationItem:
    priority: str = "P3"     # P0/P1/P2/P3
    component: str = ""
    current: str = ""
    target: str = ""
    action: str = ""
    reason: str = ""
    effort: str = "S"          # S/M/L
    type: str = "upgrade"      # upgrade/replace/license/policy

    def to_dict(self) -> Dict[str, Any]:
        return {
            "priority": self.priority, "component": self.component,
            "current": self.current, "target": self.target,
            "action": self.action, "reason": self.reason,
            "effort": self.effort, "type": self.type,
        }


@dataclass
class RoadmapItem:
    horizon: str = ""          # short/medium/long
    title: str = ""
    items: List[str] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        return {"horizon": self.horizon, "title": self.title,
                "items": self.items}


@dataclass
class RemediationPlan:
    items: List[RemediationItem] = field(default_factory=list)
    roadmap: List[RoadmapItem] = field(default_factory=list)
    summary: Dict[str, int] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "items": [i.to_dict() for i in self.items],
            "roadmap": [r.to_dict() for r in self.roadmap],
            "summary": self.summary,
            "item_count": len(self.items),
        }


def _priority(sev: str) -> str:
    return {"critical": "P0", "high": "P1",
            "medium": "P2", "low": "P3"}.get(sev, "P3")


def _effort(sev: str) -> str:
    return {"critical": "M", "high": "M",
            "medium": "S", "low": "S"}.get(sev, "S")


class RemediationPhase:
    """阶段6：整改建议。"""

    # ------------------------------------------------------------------ #
    def generate(self,
                 vulns: List[Dict[str, Any]],
                 license_issues: Optional[List[Dict[str, Any]]] = None,
                 dep_report: Optional[Dict[str, Any]] = None
                 ) -> RemediationPlan:
        license_issues = license_issues or []
        dep_report = dep_report or {}
        plan = RemediationPlan()

        # 1. 漏洞升级建议
        seen: set = set()
        for v in sorted(vulns,
                        key=lambda x: {"critical": 0, "high": 1,
                                       "medium": 2, "low": 3}.get(
                            x.get("severity", "low"), 9)):
            key = (v.get("component", "").lower(), v.get("cve_id", ""))
            if key in seen:
                continue
            seen.add(key)
            target = v.get("fixed", "") or "最新稳定版"
            action = (f"升级 {v.get('component')} "
                      f"{v.get('version','')} → {target}")
            item = RemediationItem(
                priority=_priority(v.get("severity", "low")),
                component=v.get("component", ""),
                current=v.get("version", ""),
                target=target,
                action=action,
                reason=f"{v.get('cve_id','')}: "
                       f"{v.get('title','')[:80]}",
                effort=_effort(v.get("severity", "low")),
                type="upgrade",
            )
            # 替代推荐
            low_name = (v.get("component", "") or "").lower()
            for hint, alt in ALTERNATIVES.items():
                if hint in low_name:
                    item.action += f"；或替换为 {alt['alternative']}"
                    item.reason += f"（替代: {alt['reason']}）"
                    break
            plan.items.append(item)

        # 2. 许可证整改
        for iss in license_issues:
            lic = iss.get("license", "Unknown")
            risk = iss.get("risk", "low")
            if risk in ("high", "critical", "medium") or lic == "Unknown":
                plan.items.append(RemediationItem(
                    priority="P1" if risk in ("critical", "high")
                    else "P2",
                    component=iss.get("component", ""),
                    current=lic, target="",
                    action=iss.get("suggestion", "审查许可证"),
                    reason=iss.get("message", ""),
                    effort="M", type="license"))

        # 3. 依赖优化
        for conflict in dep_report.get("conflicts", []):
            plan.items.append(RemediationItem(
                priority="P2",
                component=conflict.get("name", ""),
                current=" / ".join(conflict.get("versions", [])),
                target="统一版本",
                action=f"统一 {conflict.get('name')} 到单一版本",
                reason=conflict.get("message", ""),
                effort="M", type="policy"))
        for o in dep_report.get("outdated", []):
            plan.items.append(RemediationItem(
                priority="P3",
                component=o.get("name", ""),
                current=o.get("current", ""),
                target=o.get("recommended", ""),
                action=f"升级 {o.get('name')} → "
                       f"{o.get('recommended')}",
                reason=o.get("message", ""),
                effort="S", type="upgrade"))

        # 排序 P0 -> P3
        order = {"P0": 0, "P1": 1, "P2": 2, "P3": 3}
        plan.items.sort(key=lambda x: order.get(x.priority, 9))

        # 4. 路线图
        short = [i for i in plan.items if i.priority in ("P0", "P1")]
        medium = [i for i in plan.items if i.priority == "P2"]
        long = [i for i in plan.items if i.priority == "P3"]
        plan.roadmap = [
            RoadmapItem(horizon="short", title="短期 (0-2 周)",
                        items=[i.action for i in short[:10]]),
            RoadmapItem(horizon="medium", title="中期 (1-3 月)",
                        items=[i.action for i in medium[:10]]),
            RoadmapItem(horizon="long", title="长期 (3-12 月)",
                        items=[i.action for i in long[:10]]),
        ]

        # 5. 汇总
        plan.summary = {
            "P0": sum(1 for i in plan.items if i.priority == "P0"),
            "P1": sum(1 for i in plan.items if i.priority == "P1"),
            "P2": sum(1 for i in plan.items if i.priority == "P2"),
            "P3": sum(1 for i in plan.items if i.priority == "P3"),
            "total": len(plan.items),
        }
        return plan

    # ------------------------------------------------------------------ #
    def tools_status(self) -> Dict[str, Any]:
        return {
            "alternatives_known": list(ALTERNATIVES.keys()),
            "priorities": ["P0", "P1", "P2", "P3"],
            "horizons": ["short(0-2周)", "medium(1-3月)", "long(3-12月)"],
        }


_default_rm: Optional[RemediationPhase] = None


def get_remediation_phase() -> RemediationPhase:
    global _default_rm
    if _default_rm is None:
        _default_rm = RemediationPhase()
    return _default_rm
