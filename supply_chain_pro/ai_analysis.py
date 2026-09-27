# -*- coding: utf-8 -*-
"""
ai_analysis.py — 方向2 供应链安全 Pro：AI 分析。

功能:
    - AI 自动分析供应链风险
    - 生成整改优先级
    - 攻击路径分析（通过供应链漏洞入侵的路径）
    - 组件风险关联分析
    - 成本优化建议

纯规则/启发式"AI"分析，无外部 LLM 依赖（可替换为真实 LLM 接口）。
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional


@dataclass
class AttackPath:
    name: str = ""
    steps: List[str] = field(default_factory=list)
    severity: str = "high"
    affected_components: List[str] = field(default_factory=list)
    likelihood: str = "medium"

    def to_dict(self) -> Dict[str, Any]:
        return {
            "name": self.name, "steps": self.steps,
            "severity": self.severity,
            "affected_components": self.affected_components,
            "likelihood": self.likelihood,
        }


@dataclass
class AIAnalysis:
    summary: str = ""
    overall_risk: str = "medium"
    top_priorities: List[Dict[str, Any]] = field(default_factory=list)
    attack_paths: List[AttackPath] = field(default_factory=list)
    correlations: List[Dict[str, Any]] = field(default_factory=list)
    cost_tips: List[str] = field(default_factory=list)
    thinking: List[str] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "summary": self.summary,
            "overall_risk": self.overall_risk,
            "top_priorities": self.top_priorities,
            "attack_paths": [p.to_dict() for p in self.attack_paths],
            "correlations": self.correlations,
            "cost_tips": self.cost_tips,
            "thinking": self.thinking,
        }


class SupplyChainAIAnalysis:
    """供应链 AI 分析器（启发式）。"""

    # ------------------------------------------------------------------ #
    def analyze(self,
                sbom: Dict[str, Any],
                component_analysis: Dict[str, Any],
                license_report: Dict[str, Any],
                dep_report: Dict[str, Any],
                risk_report: Dict[str, Any],
                remediation: Dict[str, Any]) -> AIAnalysis:
        out = AIAnalysis()
        vulns = component_analysis.get("vulns", []) or []
        comps = sbom.get("components", []) or []

        out.thinking.append("[AI] 开始聚合六阶段产物…")
        out.thinking.append(
            f"[AI] SBOM 组件数={sbom.get('component_count', 0)}, "
            f"漏洞数={len(vulns)}")

        # 1. 整体风险
        out.overall_risk = risk_report.get("overall_band", "medium")
        out.summary = (
            f"供应链整体风险评级为「{out.overall_risk}」。"
            f"共扫描 {len(comps)} 个组件，发现 {len(vulns)} 个已知漏洞，"
            f"许可证问题 {len(license_report.get('issues', []))} 项，"
            f"依赖冲突 {len(dep_report.get('conflicts', []))} 项。"
            f"建议按 P0→P3 顺序修复。")

        # 2. Top 优先级
        items = remediation.get("items", []) or []
        out.top_priorities = items[:10]
        out.thinking.append(
            f"[AI] 从 {len(items)} 条整改建议中筛出 Top10 优先级。")

        # 3. 攻击路径分析
        out.attack_paths = self._attack_paths(vulns, comps)
        out.thinking.append(
            f"[AI] 生成 {len(out.attack_paths)} 条典型攻击路径。")

        # 4. 组件风险关联
        out.correlations = self._correlate(vulns, license_report,
                                           dep_report)
        out.thinking.append(
            f"[AI] 完成 {len(out.correlations)} 组关联分析。")

        # 5. 成本优化建议
        out.cost_tips = self._cost_tips(comps, dep_report)
        return out

    # ------------------------------------------------------------------ #
    def _attack_paths(self, vulns: List[Dict[str, Any]],
                      comps: List[Dict[str, Any]]) -> List[AttackPath]:
        paths: List[AttackPath] = []
        names = {c.get("name", "").lower() for c in comps}

        # 路径1：Log4Shell 式 RCE
        if any("log4j" in v.get("component", "").lower()
               for v in vulns) or "log4j" in " ".join(names):
            paths.append(AttackPath(
                name="供应链 RCE：日志库被植入 / 利用",
                steps=[
                    "攻击者在日志输入点注入 ${jndi:ldap://...}",
                    "受影响组件（如 Log4j）发起 JNDI 连接",
                    "远程类加载触发任意代码执行",
                    "以应用进程权限在内网横向移动",
                ],
                severity="critical",
                affected_components=["log4j"],
                likelihood="high"))

        # 路径2：依赖混淆 / 投毒
        paths.append(AttackPath(
            name="依赖混淆 / 包投毒",
            steps=[
                "攻击者在公共仓库注册与内部包同名的恶意包",
                "构建系统优先拉取公共仓库版本",
                "恶意包在 install 阶段执行 install script",
                "CI/CD 凭据与源码泄露",
            ],
            severity="high",
            affected_components=["所有外部依赖"],
            likelihood="medium"))

        # 路径3：反序列化链
        deser = [v for v in vulns
                 if "反序列化" in v.get("title", "")
                 or "CWE-502" in v.get("cwe", "")]
        if deser:
            paths.append(AttackPath(
                name="反序列化 Gadget 链",
                steps=[
                    "攻击者构造恶意序列化 payload",
                    "命中含反序列化 Gadget 的组件（Jackson/Fastjson 等）",
                    "实例化任意类执行命令",
                    "进入业务 RCE",
                ],
                severity="high",
                affected_components=[d.get("component", "")
                                    for d in deser[:3]],
                likelihood="medium"))

        # 路径4：AGPL 合规风险
        if any("AGPL" in (v.get("license", ""))
               for v in []):  # 由 license report 处理
            pass

        # 路径5：传递依赖隐藏漏洞
        paths.append(AttackPath(
            name="传递依赖隐藏漏洞",
            steps=[
                "直接依赖 A 引入了有漏洞的传递依赖 B",
                "B 未被业务代码直接 import，扫描工具可能漏报",
                "运行时 B 被实例化触发漏洞",
                "攻击面比 SBOM 直接依赖更大",
            ],
            severity="medium",
            affected_components=["传递依赖"],
            likelihood="medium"))
        return paths

    # ------------------------------------------------------------------ #
    def _correlate(self, vulns: List[Dict[str, Any]],
                   license_report: Dict[str, Any],
                   dep_report: Dict[str, Any]) -> List[Dict[str, Any]]:
        out: List[Dict[str, Any]] = []
        # 同一组件既漏洞又许可证问题
        risky = {i.get("component", "").lower()
                 for i in license_report.get("issues", [])}
        for v in vulns:
            if v.get("component", "").lower() in risky:
                out.append({
                    "type": "vuln+license",
                    "component": v.get("component"),
                    "detail": (f"既有漏洞 {v.get('cve_id')}，"
                               f"又有许可证风险，优先级提升"),
                })
        # 多版本冲突 + 漏洞
        for c in dep_report.get("conflicts", []):
            out.append({
                "type": "conflict+vuln",
                "component": c.get("name"),
                "detail": f"版本冲突: {c.get('message')}",
            })
        return out[:20]

    # ------------------------------------------------------------------ #
    def _cost_tips(self, comps: List[Dict[str, Any]],
                   dep_report: Dict[str, Any]) -> List[str]:
        tips: List[str] = []
        total = len(comps)
        if total > 200:
            tips.append(
                f"组件数量 {total} 偏多，建议做依赖瘦身，"
                "移除未使用依赖以降低攻击面与维护成本。")
        outdated = dep_report.get("outdated_count", 0)
        if outdated > 0:
            tips.append(
                f"有 {outdated} 个组件可升级，"
                "升级一次 CI 流水线即可完成，边际成本低。")
        conflicts = dep_report.get("conflict_count", 0)
        if conflicts > 0:
            tips.append(
                f"检测到 {conflicts} 处版本冲突，"
                "统一版本可减少重复下载与镜像体积。")
        tips.append(
            "优先用内置 CVE 库做日常扫描；"
            "关键版本发布前再跑一次 OSV/Snyk API 全量扫描。")
        tips.append(
            "建立 SBOM 基线后，新增依赖走 PR 审批，"
            "避免一次性大量引入新组件。")
        return tips


_default_ai: Optional[SupplyChainAIAnalysis] = None


def get_ai_analysis() -> SupplyChainAIAnalysis:
    global _default_ai
    if _default_ai is None:
        _default_ai = SupplyChainAIAnalysis()
    return _default_ai
