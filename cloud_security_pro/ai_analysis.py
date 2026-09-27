# -*- coding: utf-8 -*-
"""
ai_analysis.py — 云安全 Pro AI 分析。

能力:
    - 自动分析云安全风险（规则启发式 + 优先级排序）
    - 生成整改建议
    - 风险优先级排序（可处置性 / 暴露面 / 业务影响）
    - 攻击路径分析
    - 成本优化建议（闲置资源）
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional


@dataclass
class CloudAttackPath:
    name: str = ""
    difficulty: str = "medium"
    description: str = ""
    steps: List[Dict[str, str]] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        return {"name": self.name, "difficulty": self.difficulty,
                "description": self.description, "steps": self.steps}


class CloudAIAnalysis:
    """AI 风格风险分析（本地规则引擎，不依赖外部 LLM 也可运行）。"""

    # ------------------------------------------------------------------ #
    def analyze(self,
                inventory: Dict[str, Any],
                config: Dict[str, Any],
                risk: Dict[str, Any],
                vuln: Dict[str, Any],
                compliance: Dict[str, Any]) -> Dict[str, Any]:
        findings = config.get("findings", []) if config else []
        sev = risk.get("by_severity", {}) if risk else {}
        overall = (risk.get("level", "medium") if risk else "medium")

        priorities = self._prioritize(findings)
        paths = self._attack_paths(findings, vuln or {})
        cost = self._cost_tips(inventory or {})
        summary = self._executive_summary(
            overall, risk, sev, len(findings),
            vuln.get("count", 0) if vuln else 0,
            compliance.get("pass_rate", 0) if compliance else 0)

        return {
            "overall_risk": overall,
            "risk_score": risk.get("score", 0) if risk else 0,
            "risk_grade": risk.get("grade", "-") if risk else "-",
            "summary": summary,
            "priorities": priorities,
            "attack_paths": [p.to_dict() for p in paths],
            "cost_optimizations": cost,
            "compliance_gap": self._compliance_gap(compliance or {}),
            "action_plan": self._action_plan(priorities),
        }

    # ------------------------------------------------------------------ #
    def _executive_summary(self, overall, risk, sev,
                           n_findings: int, n_vuln: int,
                           pass_rate: float) -> str:
        label = {"critical": "严重", "high": "高危",
                 "medium": "中危", "low": "低危"}.get(overall, overall)
        return (f"本次云安全评估整体风险等级为【{label}】，"
                f"风险评分 {risk.get('score',0)}/100（等级 {risk.get('grade','-')}）。"
                f"共识别配置风险 {n_findings} 项（严重 {sev.get('critical',0)} / "
                f"高危 {sev.get('high',0)} / 中危 {sev.get('medium',0)}），"
                f"匹配云服务漏洞 {n_vuln} 个，"
                f"合规通过率 {pass_rate}%。建议优先处置对公网暴露的高危配置。")

    # ------------------------------------------------------------------ #
    def _prioritize(self, findings: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        # 评分：严重度 * 暴露面 * 可处置性
        sev_w = {"critical": 40, "high": 20, "medium": 8, "low": 2}
        scored = []
        for f in findings:
            s = f.get("severity", "low")
            score = sev_w.get(s, 1)
            # 公网暴露类额外加权
            if "0.0.0.0/0" in str(f.get("evidence", "")) or \
                    "公网" in f.get("description", ""):
                score += 10
            scored.append({
                "rule_id": f.get("rule_id"),
                "title": f.get("title"),
                "severity": s,
                "resource_id": f.get("resource_id"),
                "priority_score": score,
                "priority": "P0" if score >= 45 else (
                    "P1" if score >= 25 else (
                        "P2" if score >= 10 else "P3")),
                "remediation": f.get("remediation"),
            })
        scored.sort(key=lambda x: -x["priority_score"])
        return scored[:20]

    # ------------------------------------------------------------------ #
    def _attack_paths(self, findings: List[Dict[str, Any]],
                      vuln: Dict[str, Any]) -> List[CloudAttackPath]:
        paths: List[CloudAttackPath] = []
        ids = {f.get("rule_id") for f in findings}

        if {"SG-004", "SG-005"} & ids or "SG-001" in ids:
            paths.append(CloudAttackPath(
                name="公网暴露 -> 未授权访问 -> 数据外泄",
                difficulty="低",
                description="攻击者利用对公网开放的数据库/缓存端口，"
                            "在无认证情况下直接读取或篡改数据。",
                steps=[
                    {"order": "1", "phase": "侦察",
                     "action": "Shodan/ZoomEye 扫描公网 IP 的 6379/27017/22 端口"},
                    {"order": "2", "phase": "利用",
                     "action": "未授权直连 Redis/Mongo，导出数据或写计划任务"},
                    {"order": "3", "phase": "横向",
                     "action": "窃取内网凭证，通过 VPC 内网横向移动"},
                ]))

        if "STO-001" in ids or "STO-005" in ids:
            paths.append(CloudAttackPath(
                name="公开存储桶 -> 敏感数据泄露",
                difficulty="低",
                description="匿名读取 S3/OSS 桶，获取备份、密钥、用户数据。",
                steps=[
                    {"order": "1", "phase": "侦察",
                     "action": "枚举桶名并测试匿名读"},
                    {"order": "2", "phase": "利用",
                     "action": "下载备份/配置，提取 AK/SK"},
                    {"order": "3", "phase": "后渗透",
                     "action": "使用泄露的 AK/SK 调用云 API 提权"},
                ]))

        if "IAM-003" in ids or "IAM-004" in ids:
            paths.append(CloudAttackPath(
                name="过度权限 -> 云账号接管",
                difficulty="中",
                description="Root AccessKey 或过度管理员权限被利用后，"
                            "攻击者可接管整个云租户。",
                steps=[
                    {"order": "1", "phase": "初始访问",
                     "action": "通过泄露/钓鱼获取 AK/SK"},
                    {"order": "2", "phase": "提权",
                     "action": "利用 AdministratorAccess 创建后门凭证"},
                    {"order": "3", "phase": "持久化",
                     "action": "关闭 CloudTrail，部署持久化角色"},
                ]))

        for v in (vuln.get("vulns") or [])[:3]:
            if v.get("exploit_likelihood") == "high":
                paths.append(CloudAttackPath(
                    name=f"已知漏洞利用: {v.get('cve_id')}",
                    difficulty="中",
                    description=f"{v.get('title')}（CVSS {v.get('cvss')}）",
                    steps=[
                        {"order": "1", "phase": "侦察",
                         "action": f"识别 {v.get('product')} {v.get('version')}"},
                        {"order": "2", "phase": "利用",
                         "action": "使用公开 EXP 触发漏洞"},
                    ]))
        return paths

    # ------------------------------------------------------------------ #
    def _cost_tips(self, inventory: Dict[str, Any]) -> List[Dict[str, Any]]:
        tips: List[Dict[str, Any]] = []
        resources = inventory.get("resources", [])
        stopped_ec2 = [r for r in resources
                       if r.get("resource_type") == "ec2"
                       and r.get("state") in ("stopped", "stopping")]
        if stopped_ec2:
            tips.append({
                "item": f"{len(stopped_ec2)} 台已停机 EC2/ECS 仍计费",
                "advice": "停机不释放仍收磁盘费，建议改停机不收费或释放/转预留实例。",
                "saving_estimate": "按 EBS 磁盘 + 闲置实例计费估算 15%-40%",
            })
        unencrypted_vols = [r for r in resources
                            if r.get("resource_type") == "ebs"
                            and not r.get("extra", {}).get("encrypted")]
        if unencrypted_vols:
            tips.append({
                "item": f"{len(unencrypted_vols)} 块未加密 EBS 快照可能冗余",
                "advice": "清理无人引用的旧快照，切换到增量快照。",
                "saving_estimate": "快照存储 20%-50%",
            })
        if not tips:
            tips.append({"item": "未发现明显闲置资源",
                         "advice": "建议开启 Cost Explorer 与预算告警。",
                         "saving_estimate": "-"})
        return tips

    # ------------------------------------------------------------------ #
    def _compliance_gap(self, compliance: Dict[str, Any]) -> Dict[str, Any]:
        fw = compliance.get("frameworks", {})
        gaps = []
        for name, info in fw.items():
            if info.get("status") == "non_compliant":
                gaps.append(f"{name} 未通过任何检查项")
            elif info.get("status") == "partial":
                gaps.append(f"{name} 仅部分合规，通过率 {info.get('pass_rate')}%")
        return {"pass_rate": compliance.get("pass_rate", 0),
                "gaps": gaps or ["无显著合规缺口"]}

    # ------------------------------------------------------------------ #
    def _action_plan(self, priorities: List[Dict[str, Any]]) -> List[str]:
        plan = []
        for p in priorities:
            plan.append(f"[{p['priority']}] {p['title']} "
                        f"({p['resource_id']}) — {p['remediation']}")
        return plan[:10]


_default_ai: Optional[CloudAIAnalysis] = None


def get_ai_analysis() -> CloudAIAnalysis:
    global _default_ai
    if _default_ai is None:
        _default_ai = CloudAIAnalysis()
    return _default_ai
