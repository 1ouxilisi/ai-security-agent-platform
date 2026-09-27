# -*- coding: utf-8 -*-
"""
security_gate_phase.py — 阶段7：安全门禁。

功能:
    - CI/CD 流水线安全门禁配置
    - 门禁规则：Critical 阻断 / High 警告 / Secrets 阻断 / 许可证阻断
    - 门禁评估引擎
    - 门禁结果：通过 / 警告 / 失败
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional


@dataclass
class GateRule:
    name: str = ""
    level: str = "block"  # block / warn
    threshold: int = 0
    description: str = ""

    def to_dict(self) -> Dict[str, Any]:
        return {
            "name": self.name, "level": self.level,
            "threshold": self.threshold, "description": self.description,
        }


@dataclass
class GateResult:
    decision: str = "pass"  # pass / warn / fail
    score: int = 0
    reasons: List[str] = field(default_factory=list)
    details: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "decision": self.decision, "score": self.score,
            "reasons": self.reasons, "details": self.details,
        }


DEFAULT_RULES: List[GateRule] = [
    GateRule("critical_block", "block", 0,
             "存在 Critical 漏洞即阻断（阈值 0）"),
    GateRule("high_warn", "warn", 5,
             "High 漏洞数 > 5 时警告"),
    GateRule("secrets_block", "block", 0,
             "存在 Secrets 泄露即阻断"),
    GateRule("license_block", "block", 0,
             "存在 GPL/AGPL 等强 Copyleft 许可证即阻断"),
    GateRule("medium_block", "block", 20,
             "Medium 漏洞数 > 20 时阻断"),
]


class SecurityGatePhase:
    """阶段7：安全门禁。"""

    def __init__(self, rules: Optional[List[GateRule]] = None) -> None:
        self.rules: List[GateRule] = rules or list(DEFAULT_RULES)

    # ------------------------------------------------------------------ #
    def list_rules(self) -> List[Dict[str, Any]]:
        return [r.to_dict() for r in self.rules]

    # ------------------------------------------------------------------ #
    def update_rule(self, name: str, level: Optional[str] = None,
                    threshold: Optional[int] = None) -> bool:
        for r in self.rules:
            if r.name == name:
                if level:
                    r.level = level
                if threshold is not None:
                    r.threshold = threshold
                return True
        return False

    # ------------------------------------------------------------------ #
    def evaluate(self, sast: Dict[str, Any],
                 sca: Dict[str, Any],
                 secrets: Dict[str, Any],
                 iac: Dict[str, Any],
                 container: Dict[str, Any]) -> GateResult:
        result = GateResult()
        reasons: List[str] = []

        # 汇总计数
        counts = {"critical": 0, "high": 0, "medium": 0, "low": 0}

        def _add(findings: List[Dict[str, Any]],
                 sev_key: str = "severity") -> None:
            for f in findings:
                sev = str(f.get(sev_key, "low")).lower()
                if sev in counts:
                    counts[sev] += 1

        _add(sast.get("findings", []))
        _add(sca.get("findings", []))
        _add(secrets.get("findings", []), "severity")
        _add(iac.get("findings", []))
        _add(container.get("findings", []))

        secret_count = len(secrets.get("findings", []))
        license_count = sca.get("license_blockers", 0)

        result.details = {
            "counts": counts,
            "secrets": secret_count,
            "license_blockers": license_count,
        }

        # 评估规则
        blocked = False
        warned = False
        for rule in self.rules:
            if rule.name == "critical_block":
                if counts["critical"] > rule.threshold:
                    msg = f"Critical 漏洞 {counts['critical']} 个，达到阻断阈值"
                    if rule.level == "block":
                        blocked = True
                        reasons.append("[BLOCK] " + msg)
                    else:
                        warned = True
                        reasons.append("[WARN] " + msg)
            elif rule.name == "high_warn":
                if counts["high"] > rule.threshold:
                    warned = True
                    reasons.append(
                        f"[WARN] High 漏洞 {counts['high']} 个 > {rule.threshold}")
            elif rule.name == "secrets_block":
                if secret_count > rule.threshold:
                    msg = f"Secrets 泄露 {secret_count} 个"
                    if rule.level == "block":
                        blocked = True
                        reasons.append("[BLOCK] " + msg)
                    else:
                        warned = True
                        reasons.append("[WARN] " + msg)
            elif rule.name == "license_block":
                if license_count > rule.threshold:
                    blocked = True
                    reasons.append(
                        f"[BLOCK] 强 Copyleft 许可证依赖 {license_count} 个")
            elif rule.name == "medium_block":
                if counts["medium"] > rule.threshold:
                    blocked = True
                    reasons.append(
                        f"[BLOCK] Medium 漏洞 {counts['medium']} 个 > {rule.threshold}")

        if blocked:
            result.decision = "fail"
        elif warned:
            result.decision = "warn"
        else:
            result.decision = "pass"
            reasons.append("所有门禁规则通过")

        # 评分：100 - 加权扣分
        score = 100 - counts["critical"] * 10 - counts["high"] * 3 \
            - counts["medium"] * 1 - secret_count * 5 - license_count * 10
        result.score = max(0, min(100, score))
        result.reasons = reasons
        return result


_default: Optional[SecurityGatePhase] = None


def get_gate_phase() -> SecurityGatePhase:
    global _default
    if _default is None:
        _default = SecurityGatePhase()
    return _default
