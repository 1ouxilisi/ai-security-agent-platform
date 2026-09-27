#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
统一风险评级算法 - 四大领域共享的风险计算引擎

基于漏洞数量、严重程度、CVSS、可利用性、影响范围等多维度计算综合风险分。
"""
import math
from typing import Dict, List, Optional

from unified.models import Finding, Severity


class RiskScorer:
    """风险评分器"""

    # 严重程度权重
    SEVERITY_WEIGHTS = {
        Severity.CRITICAL: 10.0,
        Severity.HIGH: 7.0,
        Severity.MEDIUM: 4.0,
        Severity.LOW: 1.5,
        Severity.INFO: 0.3,
    }

    # 领域权重（不同领域的风险影响系数）
    DOMAIN_WEIGHTS = {
        "pentest": 1.2,      # 渗透测试直接影响系统安全，权重最高
        "mobile": 1.0,       # 移动安全影响终端用户
        "blockchain": 1.1,   # 区块链安全涉及资产损失，权重较高
        "ai_agent": 1.15,    # AI安全可能导致连锁反应，权重较高
    }

    def __init__(self, domain: str = "general"):
        self.domain = domain

    def calculate(self, findings: List[Finding], extra_factors: Optional[Dict] = None) -> int:
        """计算综合风险分 (0-100)

        Args:
            findings: 漏洞发现列表
            extra_factors: 额外因子，如 exploitability(可利用性0-1), impact(影响范围0-1)

        Returns:
            0-100的整数风险分
        """
        if not findings:
            return 0

        extra_factors = extra_factors or {}

        # 1. 基础分：加权漏洞数量
        base_score = 0.0
        for f in findings:
            weight = self.SEVERITY_WEIGHTS.get(f.severity, 0.3)
            # CVSS加成
            cvss_factor = 1.0
            if f.cvss and f.cvss > 0:
                cvss_factor = 0.5 + (f.cvss / 10.0) * 0.5  # 0.5-1.0
            base_score += weight * cvss_factor

        # 2. 数量惩罚曲线（边际递减，避免线性爆炸）
        # 使用对数压缩：score = 100 * (1 - e^(-k * base))
        k = 0.08
        compressed = 100.0 * (1.0 - math.exp(-k * base_score))

        # 3. 领域权重调整
        domain_weight = self.DOMAIN_WEIGHTS.get(self.domain, 1.0)
        compressed *= domain_weight

        # 4. 额外因子调整
        exploitability = extra_factors.get("exploitability", 0.5)
        impact = extra_factors.get("impact", 0.5)
        factor_adjust = 0.7 + 0.3 * exploitability + 0.3 * impact  # 0.7-1.3
        compressed *= factor_adjust

        # 5. 严重漏洞保底：只要有critical，至少60分
        has_critical = any(f.severity == Severity.CRITICAL for f in findings)
        has_high = any(f.severity == Severity.HIGH for f in findings)
        if has_critical and compressed < 60:
            compressed = 60
        if has_high and compressed < 35:
            compressed = 35

        return max(0, min(100, int(round(compressed))))

    def level(self, score: int) -> str:
        """根据分数返回风险等级"""
        return risk_level_from_score(score)


def calculate_risk_score(findings: List[Finding], domain: str = "general",
                          extra_factors: Optional[Dict] = None) -> int:
    """便捷函数：计算风险分"""
    scorer = RiskScorer(domain=domain)
    return scorer.calculate(findings, extra_factors)


def risk_level_from_score(score: int) -> str:
    """根据风险分返回等级标签"""
    if score >= 80:
        return "严重"
    elif score >= 60:
        return "高危"
    elif score >= 40:
        return "中危"
    elif score >= 20:
        return "低危"
    elif score > 0:
        return "轻微"
    else:
        return "安全"


def aggregate_domain_scores(domain_scores: Dict[str, int]) -> int:
    """聚合多个领域的风险分为综合分

    取加权平均，高风险领域权重更大。
    """
    if not domain_scores:
        return 0

    # 加权平均：分数越高的领域权重越大（反映最薄弱环节）
    total_weight = 0.0
    weighted_sum = 0.0
    for domain, score in domain_scores.items():
        weight = 0.5 + (score / 100.0) * 1.5  # 0.5-2.0
        weighted_sum += score * weight
        total_weight += weight

    if total_weight == 0:
        return 0

    aggregate = weighted_sum / total_weight

    # 如果有任何领域达到严重，综合分至少70
    if any(s >= 80 for s in domain_scores.values()):
        aggregate = max(aggregate, 70)

    return max(0, min(100, int(round(aggregate))))
