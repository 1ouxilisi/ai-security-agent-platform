# -*- coding: utf-8 -*-
"""
ai_analysis.py — DevSecOps AI 分析。

功能:
    - AI 自动分析代码安全风险
    - 生成修复建议
    - 漏洞优先级排序
    - 攻击路径分析
    - 代码质量评估
    - 安全改进路线图

注意：本模块为规则驱动的 AI 风格分析器，不依赖外部 LLM；
当配置了 LLM_PROVIDER 环境变量时可对接真实 LLM（预留接口）。
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional


@dataclass
class AIDevSecOpsResult:
    overall_assessment: str = ""
    priority_list: List[Dict[str, Any]] = field(default_factory=list)
    attack_paths: List[Dict[str, Any]] = field(default_factory=list)
    fix_suggestions: List[Dict[str, Any]] = field(default_factory=list)
    code_quality: Dict[str, Any] = field(default_factory=dict)
    roadmap: List[Dict[str, Any]] = field(default_factory=list)
    thinking: List[str] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "overall_assessment": self.overall_assessment,
            "priority_list": self.priority_list,
            "attack_paths": self.attack_paths,
            "fix_suggestions": self.fix_suggestions,
            "code_quality": self.code_quality,
            "roadmap": self.roadmap,
            "thinking": self.thinking,
        }


SEV_RANK = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}


class DevSecOpsAIAnalysis:
    """AI 风格的 DevSecOps 分析器。"""

    def analyze(self,
                sast: Dict[str, Any],
                sca: Dict[str, Any],
                secrets: Dict[str, Any],
                iac: Dict[str, Any],
                container: Dict[str, Any],
                gate: Dict[str, Any],
                risk: Dict[str, Any]) -> AIDevSecOpsResult:
        out = AIDevSecOpsResult()
        thinking = out.thinking

        thinking.append("[AI] 汇总八阶段扫描结果…")

        # 收集所有发现
        all_items: List[Dict[str, Any]] = []
        for src, data in (("SAST", sast), ("SCA", sca), ("Secrets", secrets),
                          ("IaC", iac), ("Container", container)):
            for f in data.get("findings", []):
                item = dict(f)
                item["_source"] = src
                all_items.append(item)

        thinking.append(f"[AI] 共聚合 {len(all_items)} 条原始发现")

        # 优先级排序
        def _key(it: Dict[str, Any]):
            sev = str(it.get("severity", "low")).lower()
            return (SEV_RANK.get(sev, 9),
                    it.get("line", 0),
                    it.get("path") or it.get("file") or "")

        sorted_items = sorted(all_items, key=_key)
        for idx, it in enumerate(sorted_items[:15], 1):
            out.priority_list.append({
                "rank": idx,
                "source": it.get("_source"),
                "severity": it.get("severity"),
                "title": (it.get("message") or it.get("description")
                          or it.get("title") or it.get("cve")
                          or it.get("rule_id") or it.get("kind") or "-")[:140],
                "location": f"{it.get('path') or it.get('file') or it.get('artifact','')}:{it.get('line', '')}",
            })
        thinking.append(f"[AI] 已按严重度排序 Top {len(out.priority_list)} 项")

        # 修复建议
        seen = set()
        for it in sorted_items:
            title = (it.get("message") or it.get("description")
                     or it.get("title") or it.get("rule_id") or "")[:80]
            key = (it.get("_source"), title)
            if key in seen:
                continue
            seen.add(key)
            fix = it.get("fix") or it.get("guideline") or it.get("fixed")
            if not fix:
                sev = str(it.get("severity", "")).lower()
                if it.get("_source") == "SCA":
                    fix = f"升级到修复版本：{it.get('fixed', '最新稳定版')}"
                elif it.get("_source") == "Secrets":
                    fix = "立即吊销并轮换该密钥，改用环境变量/Secret Manager"
                elif sev == "critical":
                    fix = "立即下线相关功能，按安全公告紧急修复"
                else:
                    fix = "按行业最佳实践修复，并补充回归测试"
            out.fix_suggestions.append({
                "source": it.get("_source"),
                "severity": it.get("severity"),
                "issue": title,
                "recommended_fix": fix,
                "priority": "P0" if str(it.get("severity")).lower() == "critical"
                else "P1" if str(it.get("severity")).lower() == "high"
                else "P2",
            })
            if len(out.fix_suggestions) >= 20:
                break

        # 攻击路径分析
        paths = []
        if any(str(f.get("severity")).lower() == "critical"
               for f in sca.get("findings", [])):
            paths.append({
                "name": "依赖链远程利用",
                "steps": [
                    "攻击者公网访问服务",
                    "命中存在 RCE 的依赖（如 Log4Shell / Spring4Shell）",
                    "通过已知 PoC 构造恶意请求",
                    "在服务器上执行任意命令",
                ],
                "impact": "接管业务服务器，窃取数据/横向移动",
            })
        if secrets.get("findings"):
            paths.append({
                "name": "硬编码密钥泄露",
                "steps": [
                    "攻击者获取代码仓库访问（公开仓库/离职员工/CI 泄露）",
                    "grep 到硬编码 AccessKey/Token",
                    "使用密钥访问云资源/数据库/第三方 API",
                    "数据外泄或资源滥用挖矿",
                ],
                "impact": "云资源被劫持、数据泄露、账单爆炸",
            })
        if iac.get("findings"):
            paths.append({
                "name": "云配置错误",
                "steps": [
                    "S3 桶/防火墙配置为公开",
                    "攻击者通过互联网直接枚举/访问",
                    "下载公开对象或直达内部服务",
                ],
                "impact": "敏感数据公开、内网穿透",
            })
        out.attack_paths = paths
        thinking.append(f"[AI] 推断 {len(paths)} 条潜在攻击路径")

        # 代码质量评估
        counts = risk.get("breakdown", {}).get("counts", {})
        total = sum(counts.values()) if counts else len(all_items)
        quality_score = max(0, 100 - total * 2)
        out.code_quality = {
            "score": quality_score,
            "grade": "A" if quality_score >= 90 else "B" if quality_score >= 75
            else "C" if quality_score >= 60 else "D",
            "total_findings": total,
            "assessment": (
                "代码安全质量良好" if quality_score >= 85
                else "代码存在较多安全债，建议安排专项整改"
                if quality_score >= 60
                else "代码安全状况差，存在系统性风险"),
        }

        # 安全改进路线图
        out.roadmap = [
            {"phase": "0-7 天", "focus": "紧急修复",
             "items": [
                 "吊销并轮换所有硬编码密钥",
                 "升级存在 Critical CVE 的依赖",
                 "修复暴露公网的云配置错误",
             ]},
            {"phase": "1-4 周", "focus": "流程固化",
             "items": [
                 "将 semgrep/gitleaks/trivy 接入 CI 流水线",
                 "配置安全门禁（Critical 阻断）",
                 "建立漏洞 SLA：Critical 24h / High 7d",
             ]},
            {"phase": "1-3 月", "focus": "体系建设",
             "items": [
                 "引入 SCA 持续监控与 Dependabot/Renovate",
                 "建立安全基线与 IaC Policy as Code",
                 "开展开发人员安全培训（SDLC）",
             ]},
        ]

        out.overall_assessment = (
            f"综合评分 {risk.get('score', '-')}/100，"
            f"等级 {risk.get('level', '-')}。"
            f"当前最紧迫风险："
            + ("硬编码密钥泄露，须立即轮换" if secrets.get("findings")
               else "Critical 依赖 CVE，须紧急升级"
               if any(str(f.get('severity')).lower() == 'critical'
                      for f in sca.get('findings', []))
               else "IaC 公开暴露配置，须立即收紧"))
        thinking.append("[AI] 分析完成")
        return out


_default: Optional[DevSecOpsAIAnalysis] = None


def get_ai_analysis() -> DevSecOpsAIAnalysis:
    global _default
    if _default is None:
        _default = DevSecOpsAIAnalysis()
    return _default
