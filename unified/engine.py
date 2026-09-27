#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
全域安全评估引擎 - 统一调度四大领域评估模块

定义标准领域评估接口 DomainAssessor，各领域实现该接口后注册到引擎。
引擎负责：任务调度、结果聚合、风险计算、报告触发。
"""
import asyncio
import time
import traceback
from typing import Any, Callable, Dict, List, Optional

from unified.models import (
    DomainAssessment, DomainType, Finding, Severity,
    UnifiedAssessmentResult,
)
from unified.risk_scoring import RiskScorer, aggregate_domain_scores, risk_level_from_score
from unified.knowledge_base import get_knowledge_base


class DomainAssessor:
    """领域评估器基类 - 所有领域评估模块必须继承此类并实现 assess 方法

    标准接口：
        assess(target, options) -> DomainAssessment
    """

    domain: DomainType = DomainType.PENTEST
    name: str = "base"
    description: str = "基础评估器"

    def __init__(self):
        self.kb = get_knowledge_base()

    def assess(self, target: str, options: Optional[Dict] = None) -> DomainAssessment:
        """执行领域评估 - 子类必须实现

        Args:
            target: 评估目标（IP/域名/文件路径/合约地址/API端点）
            options: 评估选项

        Returns:
            DomainAssessment 评估结果
        """
        raise NotImplementedError("子类必须实现 assess 方法")

    def _make_finding(self, title: str, severity: str, category: str,
                      description: str = "", target: str = "", location: str = "",
                      evidence: str = "", cwe: str = "", owasp: str = "",
                      cvss: float = 0.0, recommendation: str = "",
                      extra: Optional[Dict] = None) -> Finding:
        """创建标准Finding对象的便捷方法"""
        return Finding(
            title=title,
            severity=Severity.from_str(severity),
            domain=self.domain,
            category=category,
            description=description,
            target=target,
            location=location,
            evidence=evidence,
            cwe=cwe,
            owasp=owasp,
            cvss=cvss,
            recommendation=recommendation,
            extra=extra or {},
        )

    def _complete_result(self, result: DomainAssessment, findings: List[Finding],
                         errors: Optional[List[str]] = None) -> DomainAssessment:
        """完成评估结果：计算风险分、统计、设置状态"""
        result.findings = findings
        result.completed_at = time.time()
        result.duration = result.completed_at - result.started_at
        result.errors = errors or []
        result.status = "completed" if not result.errors else "completed_with_errors"

        scorer = RiskScorer(domain=self.domain.value)
        result.risk_score = scorer.calculate(findings)
        result.risk_level = risk_level_from_score(result.risk_score)

        # 生成摘要
        sev_counts = result._severity_counts()
        result.summary = (
            f"{self.domain.label()}评估完成：发现 {len(findings)} 个问题 "
            f"(严重{sev_counts['critical']}/高危{sev_counts['high']}/"
            f"中危{sev_counts['medium']}/低危{sev_counts['low']}/信息{sev_counts['info']})，"
            f"风险等级：{result.risk_level}({result.risk_score}分)"
        )
        return result


class UnifiedAssessmentEngine:
    """全域安全评估引擎 - 调度并聚合四大领域评估"""

    def __init__(self):
        self._assessors: Dict[DomainType, DomainAssessor] = {}
        self.kb = get_knowledge_base()
        self._results_cache: Dict[str, UnifiedAssessmentResult] = {}

    def register(self, assessor: DomainAssessor) -> None:
        """注册领域评估器"""
        self._assessors[assessor.domain] = assessor

    def get_assessor(self, domain: DomainType) -> Optional[DomainAssessor]:
        return self._assessors.get(domain)

    def available_domains(self) -> List[Dict]:
        """获取已注册的领域列表"""
        return [
            {"domain": d.value, "label": d.label(), "name": a.name, "description": a.description}
            for d, a in self._assessors.items()
        ]

    def run_assessment(self, target: str, assessment_type: str = "comprehensive",
                       domains: Optional[List[str]] = None,
                       options: Optional[Dict] = None) -> UnifiedAssessmentResult:
        """执行全域安全评估

        Args:
            target: 评估目标
            assessment_type: pentest/mobile/blockchain/ai_agent/comprehensive
            domains: 指定领域列表（assessment_type=custom时使用）
            options: 各领域选项，key为领域名，value为该领域options

        Returns:
            UnifiedAssessmentResult 综合评估结果
        """
        options = options or {}
        result = UnifiedAssessmentResult(
            assessment_type=assessment_type,
            target=target,
            started_at=time.time(),
            status="running",
        )

        # 确定要执行的领域
        target_domains = self._resolve_domains(assessment_type, domains)

        # 逐领域执行（同步模式，后续可改为异步并行）
        all_findings: List[Finding] = []
        domain_scores: Dict[str, int] = {}

        for domain in target_domains:
            assessor = self._assessors.get(domain)
            da = DomainAssessment(domain=domain, target=target, started_at=time.time())

            if assessor is None:
                da.status = "skipped"
                da.summary = f"{domain.label()}评估器未注册，已跳过"
                da.errors.append("评估器未注册")
            else:
                try:
                    domain_opts = options.get(domain.value, {})
                    da = assessor.assess(target, domain_opts)
                except Exception as e:
                    da.status = "failed"
                    da.errors.append(f"{type(e).__name__}: {str(e)}")
                    da.errors.append(traceback.format_exc()[:500])
                    da.summary = f"{domain.label()}评估失败：{str(e)}"

            result.domain_results[domain.value] = da
            all_findings.extend(da.findings)
            if da.risk_score > 0:
                domain_scores[domain.value] = da.risk_score

        # 聚合结果
        result.all_findings = all_findings
        result.completed_at = time.time()
        result.duration = result.completed_at - result.started_at
        result.status = "completed"

        # 综合风险分
        if domain_scores:
            result.overall_risk_score = aggregate_domain_scores(domain_scores)
        else:
            result.overall_risk_score = 0
        result.overall_risk_level = risk_level_from_score(result.overall_risk_score)

        # 生成执行摘要
        result.executive_summary = self._generate_executive_summary(result)
        result.key_findings = self._extract_key_findings(result)
        result.recommendations = self._generate_recommendations(result)

        # 缓存
        self._results_cache[result.assessment_id] = result
        return result

    def _resolve_domains(self, assessment_type: str, domains: Optional[List[str]]) -> List[DomainType]:
        """解析要执行的领域列表"""
        if assessment_type == "comprehensive":
            return DomainType.all_domains()
        if assessment_type == "custom" and domains:
            result = []
            for d in domains:
                try:
                    result.append(DomainType(d))
                except ValueError:
                    pass
            return result
        # 单领域
        try:
            return [DomainType(assessment_type)]
        except ValueError:
            return DomainType.all_domains()

    def _generate_executive_summary(self, result: UnifiedAssessmentResult) -> str:
        """生成执行摘要"""
        sev = result._severity_counts()
        domains_count = len([d for d in result.domain_results.values() if d.status in ("completed", "completed_with_errors")])
        return (
            f"本次全域安全评估针对目标「{result.target}」，共执行 {domains_count} 个领域评估，"
            f"发现 {len(result.all_findings)} 个安全问题，其中严重 {sev['critical']} 个、"
            f"高危 {sev['high']} 个、中危 {sev['medium']} 个、低危 {sev['low']} 个。"
            f"综合风险等级为「{result.overall_risk_level}」（{result.overall_risk_score}分）。"
            f"评估耗时 {result.duration:.1f} 秒。"
        )

    def _extract_key_findings(self, result: UnifiedAssessmentResult, top_n: int = 5) -> List[str]:
        """提取关键发现（按严重程度排序取前N）"""
        sorted_findings = sorted(result.all_findings, key=lambda f: f.severity.score(), reverse=True)
        return [
            f"[{f.severity.label()}] {f.title} - {f.domain.label()} - {f.target or f.location}"
            for f in sorted_findings[:top_n]
        ]

    def _generate_recommendations(self, result: UnifiedAssessmentResult) -> List[str]:
        """生成修复建议"""
        recs = []
        seen_categories = set()

        # 按严重程度处理
        sorted_findings = sorted(result.all_findings, key=lambda f: f.severity.score(), reverse=True)
        for f in sorted_findings:
            if f.recommendation and f.category not in seen_categories:
                recs.append(f"[{f.severity.label()}] {f.category}：{f.recommendation}")
                seen_categories.add(f.category)
            if len(recs) >= 8:
                break

        # 通用建议
        if not recs:
            recs.append("未发现明显安全问题，建议持续进行安全评估和监控。")
        recs.append("建立持续安全评估机制，定期进行全领域安全扫描。")
        recs.append("对所有发现的问题制定修复计划，按严重程度优先级处理。")
        return recs

    def get_result(self, assessment_id: str) -> Optional[UnifiedAssessmentResult]:
        return self._results_cache.get(assessment_id)

    def list_results(self, limit: int = 20) -> List[Dict]:
        results = list(self._results_cache.values())[-limit:]
        return [
            {"assessment_id": r.assessment_id, "target": r.target, "type": r.assessment_type,
             "status": r.status, "risk_score": r.overall_risk_score, "risk_level": r.overall_risk_level,
             "findings_count": len(r.all_findings), "created_at": r.created_at}
            for r in reversed(results)
        ]


# 全局引擎单例
_engine: Optional[UnifiedAssessmentEngine] = None

def get_engine() -> UnifiedAssessmentEngine:
    global _engine
    if _engine is None:
        _engine = UnifiedAssessmentEngine()
    return _engine
