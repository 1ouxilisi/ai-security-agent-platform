#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
CVSS v3.1 评分引擎
实现完整的CVSS v3.1基础指标评分
"""

import math
from typing import Dict, Optional, Tuple
from dataclasses import dataclass


@dataclass
class CVSSMetrics:
    """CVSS v3.1 指标"""
    # 攻击向量 (AV)
    attack_vector: str = "N"  # N=网络, A=相邻, L=本地, P=物理
    # 攻击复杂度 (AC)
    attack_complexity: str = "L"  # L=低, H=高
    # 权限要求 (PR)
    privileges_required: str = "N"  # N=无, L=低, H=高
    # 用户交互 (UI)
    user_interaction: str = "N"  # N=无, R=需要
    # 机密性影响 (C)
    confidentiality_impact: str = "N"  # H=高, L=低, N=无
    # 完整性影响 (I)
    integrity_impact: str = "N"  # H=高, L=低, N=无
    # 可用性影响 (A)
    availability_impact: str = "N"  # H=高, L=低, N=无
    # 范围 (S)
    scope: str = "U"  # U=不变, C=改变


class CVSSScorer:
    """CVSS v3.1 评分引擎"""

    # 指标值映射
    AV_VALUES = {"N": 0.85, "A": 0.62, "L": 0.55, "P": 0.2}
    AC_VALUES = {"L": 0.77, "H": 0.44}
    PR_VALUES_U = {"N": 0.85, "L": 0.62, "H": 0.27}  # 范围不变
    PR_VALUES_C = {"N": 0.85, "L": 0.68, "H": 0.5}   # 范围改变
    UI_VALUES = {"N": 0.85, "R": 0.62}
    CIA_VALUES = {"H": 0.56, "L": 0.22, "N": 0}

    def __init__(self):
        pass

    def calculate_base_score(self, metrics: CVSSMetrics) -> float:
        """
        计算CVSS v3.1基础分数

        Args:
            metrics: CVSS指标

        Returns:
            基础分数 (0.0-10.0)
        """
        # 1. 计算影响子分数 (ISS)
        iss = 1 - (
            (1 - self.CIA_VALUES[metrics.confidentiality_impact]) *
            (1 - self.CIA_VALUES[metrics.integrity_impact]) *
            (1 - self.CIA_VALUES[metrics.availability_impact])
        )

        # 2. 根据范围计算影响分数
        if metrics.scope == "U":
            # 范围不变
            impact = 6.42 * iss
        else:
            # 范围改变
            impact = 7.52 * (iss - 0.029) - 3.25 * (iss - 0.02) ** 15

        # 3. 计算可利用性子分数
        pr_values = self.PR_VALUES_C if metrics.scope == "C" else self.PR_VALUES_U
        exploitability = (
            8.22 *
            self.AV_VALUES[metrics.attack_vector] *
            self.AC_VALUES[metrics.attack_complexity] *
            pr_values[metrics.privileges_required] *
            self.UI_VALUES[metrics.user_interaction]
        )

        # 4. 计算基础分数
        if impact <= 0:
            base_score = 0
        elif metrics.scope == "U":
            base_score = min((impact + exploitability), 10)
        else:
            base_score = min(1.08 * (impact + exploitability), 10)

        # 四舍五入到1位小数
        return round(base_score, 1)

    def get_severity(self, score: float) -> str:
        """
        根据分数获取严重级别

        Args:
            score: CVSS分数

        Returns:
            严重级别 (None/Low/Medium/High/Critical)
        """
        if score == 0:
            return "None"
        elif score <= 3.9:
            return "Low"
        elif score <= 6.9:
            return "Medium"
        elif score <= 8.9:
            return "High"
        else:
            return "Critical"

    def get_vector_string(self, metrics: CVSSMetrics) -> str:
        """
        生成CVSS向量字符串

        Args:
            metrics: CVSS指标

        Returns:
            CVSS向量字符串
        """
        return (
            f"CVSS:3.1/AV:{metrics.attack_vector}"
            f"/AC:{metrics.attack_complexity}"
            f"/PR:{metrics.privileges_required}"
            f"/UI:{metrics.user_interaction}"
            f"/S:{metrics.scope}"
            f"/C:{metrics.confidentiality_impact}"
            f"/I:{metrics.integrity_impact}"
            f"/A:{metrics.availability_impact}"
        )

    def parse_vector_string(self, vector: str) -> Optional[CVSSMetrics]:
        """
        解析CVSS向量字符串

        Args:
            vector: CVSS向量字符串

        Returns:
            CVSS指标，解析失败返回None
        """
        try:
            metrics = CVSSMetrics()
            parts = vector.split("/")

            for part in parts:
                if ":" not in part:
                    continue
                key, value = part.split(":", 1)
                key = key.strip().upper()
                value = value.strip().upper()

                if key == "AV":
                    metrics.attack_vector = value
                elif key == "AC":
                    metrics.attack_complexity = value
                elif key == "PR":
                    metrics.privileges_required = value
                elif key == "UI":
                    metrics.user_interaction = value
                elif key == "S":
                    metrics.scope = value
                elif key == "C":
                    metrics.confidentiality_impact = value
                elif key == "I":
                    metrics.integrity_impact = value
                elif key == "A":
                    metrics.availability_impact = value

            return metrics
        except Exception:
            return None

    def quick_score(self, attack_vector: str = "N",
                    attack_complexity: str = "L",
                    privileges_required: str = "N",
                    user_interaction: str = "N",
                    scope: str = "U",
                    confidentiality: str = "N",
                    integrity: str = "N",
                    availability: str = "N") -> Tuple[float, str, str]:
        """
        快速计算分数

        Returns:
            (分数, 严重级别, 向量字符串)
        """
        metrics = CVSSMetrics(
            attack_vector=attack_vector,
            attack_complexity=attack_complexity,
            privileges_required=privileges_required,
            user_interaction=user_interaction,
            scope=scope,
            confidentiality_impact=confidentiality,
            integrity_impact=integrity,
            availability_impact=availability,
        )
        score = self.calculate_base_score(metrics)
        severity = self.get_severity(score)
        vector = self.get_vector_string(metrics)
        return score, severity, vector

    # ==================== 常见漏洞预设 ====================

    PRESET_SCORES = {
        "sql_injection": {
            "attack_vector": "N",
            "attack_complexity": "L",
            "privileges_required": "N",
            "user_interaction": "N",
            "scope": "U",
            "confidentiality": "H",
            "integrity": "H",
            "availability": "H",
        },
        "xss": {
            "attack_vector": "N",
            "attack_complexity": "L",
            "privileges_required": "N",
            "user_interaction": "R",
            "scope": "C",
            "confidentiality": "L",
            "integrity": "L",
            "availability": "N",
        },
        "rce": {
            "attack_vector": "N",
            "attack_complexity": "L",
            "privileges_required": "N",
            "user_interaction": "N",
            "scope": "U",
            "confidentiality": "H",
            "integrity": "H",
            "availability": "H",
        },
        "ssrf": {
            "attack_vector": "N",
            "attack_complexity": "L",
            "privileges_required": "N",
            "user_interaction": "N",
            "scope": "U",
            "confidentiality": "L",
            "integrity": "L",
            "availability": "N",
        },
        "lfi": {
            "attack_vector": "N",
            "attack_complexity": "L",
            "privileges_required": "N",
            "user_interaction": "N",
            "scope": "U",
            "confidentiality": "H",
            "integrity": "N",
            "availability": "N",
        },
        "path_traversal": {
            "attack_vector": "N",
            "attack_complexity": "L",
            "privileges_required": "N",
            "user_interaction": "N",
            "scope": "U",
            "confidentiality": "H",
            "integrity": "N",
            "availability": "N",
        },
        "command_injection": {
            "attack_vector": "N",
            "attack_complexity": "L",
            "privileges_required": "N",
            "user_interaction": "N",
            "scope": "U",
            "confidentiality": "H",
            "integrity": "H",
            "availability": "H",
        },
        "open_redirect": {
            "attack_vector": "N",
            "attack_complexity": "L",
            "privileges_required": "N",
            "user_interaction": "R",
            "scope": "U",
            "confidentiality": "N",
            "integrity": "L",
            "availability": "N",
        },
        "information_disclosure": {
            "attack_vector": "N",
            "attack_complexity": "L",
            "privileges_required": "N",
            "user_interaction": "N",
            "scope": "U",
            "confidentiality": "L",
            "integrity": "N",
            "availability": "N",
        },
        "authentication_bypass": {
            "attack_vector": "N",
            "attack_complexity": "L",
            "privileges_required": "N",
            "user_interaction": "N",
            "scope": "U",
            "confidentiality": "H",
            "integrity": "H",
            "availability": "H",
        },
        "privilege_escalation": {
            "attack_vector": "L",
            "attack_complexity": "L",
            "privileges_required": "L",
            "user_interaction": "N",
            "scope": "U",
            "confidentiality": "H",
            "integrity": "H",
            "availability": "H",
        },
        "csrf": {
            "attack_vector": "N",
            "attack_complexity": "L",
            "privileges_required": "N",
            "user_interaction": "R",
            "scope": "U",
            "confidentiality": "N",
            "integrity": "L",
            "availability": "N",
        },
        "deserialization": {
            "attack_vector": "N",
            "attack_complexity": "L",
            "privileges_required": "N",
            "user_interaction": "N",
            "scope": "U",
            "confidentiality": "H",
            "integrity": "H",
            "availability": "H",
        },
        "xxe": {
            "attack_vector": "N",
            "attack_complexity": "L",
            "privileges_required": "N",
            "user_interaction": "N",
            "scope": "U",
            "confidentiality": "H",
            "integrity": "N",
            "availability": "L",
        },
    }

    def score_by_type(self, vuln_type: str) -> Tuple[float, str, str]:
        """
        根据漏洞类型快速评分

        Args:
            vuln_type: 漏洞类型

        Returns:
            (分数, 严重级别, 向量字符串)
        """
        preset = self.PRESET_SCORES.get(vuln_type.lower())
        if preset:
            return self.quick_score(**preset)
        # 默认中危
        return self.quick_score(
            confidentiality="L", integrity="L", availability="N"
        )
