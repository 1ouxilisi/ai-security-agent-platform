# -*- coding: utf-8 -*-
"""rule_optimizer.py — 基于验证结果优化检测规则。

策略：
1. 统计每类规则的 FP 次数 / TP 次数。
2. FP 率高的规则自动收紧（提高证据要求、加白名单关键词）。
3. FN 多的规则放宽（增加证据关键词）。
4. 输出优化前后对比。
"""
from __future__ import annotations

from datetime import datetime
from typing import Any, Dict, List


class RuleOptimizer:
    """检测规则优化器：内存字典规则集 + 自动调参。"""

    def __init__(self) -> None:
        # 基线规则：type -> {evidence_keywords, min_severity, whitelist}
        self._baseline_rules: Dict[str, Dict[str, Any]] = {
            "sql_injection": {
                "evidence_keywords": ["' OR ", "UNION SELECT", "sleep(", "information_schema"],
                "min_severity": "high",
                "whitelist": [],
                "strict": False,
            },
            "xss_reflected": {
                "evidence_keywords": ["<script>", "onerror=", "javascript:"],
                "min_severity": "low",
                "whitelist": [],
                "strict": False,
            },
            "xss_stored": {
                "evidence_keywords": ["<script>", "onload="],
                "min_severity": "medium",
                "whitelist": [],
                "strict": False,
            },
            "command_injection": {
                "evidence_keywords": [";id", "&&id", "|whoami", "`id`"],
                "min_severity": "high",
                "whitelist": [],
                "strict": False,
            },
            "path_traversal": {
                "evidence_keywords": ["../../", "..\\", "/etc/passwd"],
                "min_severity": "medium",
                "whitelist": ["static", "assets"],
                "strict": False,
            },
            "sensitive_info": {
                "evidence_keywords": [".git", ".env", ".svn", "backup.sql"],
                "min_severity": "low",
                "whitelist": [],
                "strict": False,
            },
            "directory_listing": {
                "evidence_keywords": ["Index of /", "Parent Directory"],
                "min_severity": "low",
                "whitelist": [],
                "strict": False,
            },
        }
        self._current_rules: Dict[str, Dict[str, Any]] = {
            k: dict(v) for k, v in self._baseline_rules.items()
        }
        self._history: List[Dict[str, Any]] = []

    def get_rules(self) -> Dict[str, Any]:
        return {
            "baseline": self._baseline_rules,
            "current": self._current_rules,
            "history": self._history,
        }

    def optimize(self, fp_per_rule: Dict[str, int], tp_per_rule: Dict[str, int],
                 fn_per_rule: Dict[str, int]) -> Dict[str, Any]:
        """根据上一轮 FP/TP/FN 计数优化规则。

        规则：
          - FP 数 >= 2 且 FP/(TP+FP) > 0.3 → 收紧（strict=True，加白名单）
          - FN 数 >= 2 → 放宽（补证据关键词）
        """
        changes: List[Dict[str, Any]] = []
        all_types = set(list(self._current_rules.keys()) + list(fp_per_rule.keys()) +
                        list(fn_per_rule.keys()))
        for t in all_types:
            rule = self._current_rules.setdefault(t, {
                "evidence_keywords": [], "min_severity": "medium",
                "whitelist": [], "strict": False,
            })
            fp = int(fp_per_rule.get(t, 0))
            tp = int(tp_per_rule.get(t, 0))
            fn = int(fn_per_rule.get(t, 0))
            rate = fp / (tp + fp) if (tp + fp) > 0 else 0.0
            if fp >= 2 and rate > 0.3 and not rule.get("strict"):
                rule["strict"] = True
                rule["whitelist"] = sorted(set(rule.get("whitelist", []) + [
                    "demo", "example", "docs.example.com", "w3.org",
                ]))
                changes.append({"type": t, "action": "tighten",
                                "reason": f"fp={fp}, fp_rate={rate:.2f}"})
            elif fn >= 2 and not rule.get("strict"):
                extras = {
                    "sql_injection": ["' OR 1=1--", "UNION ALL SELECT"],
                    "xss_reflected": ["<img onerror", "<svg onload"],
                    "command_injection": ["; cat /etc/passwd", "| id"],
                    "path_traversal": ["....//", "..%2f"],
                }.get(t, [])
                merged = sorted(set(rule.get("evidence_keywords", []) + extras))
                rule["evidence_keywords"] = merged
                changes.append({"type": t, "action": "relax",
                                "reason": f"fn={fn}, added={extras}"})
        snapshot = {
            "ts": datetime.utcnow().isoformat() + "Z",
            "fp_per_rule": fp_per_rule,
            "tp_per_rule": tp_per_rule,
            "fn_per_rule": fn_per_rule,
            "changes": changes,
            "rules_snapshot": {k: dict(v) for k, v in self._current_rules.items()},
        }
        self._history.append(snapshot)
        return snapshot

    def apply_to_finding(self, rule_type: str, finding: Dict[str, Any]) -> bool:
        """判断在当前规则下该 finding 是否应被保留。返回 False 表示被规则过滤。"""
        rule = self._current_rules.get(rule_type)
        if not rule:
            return True
        text = " ".join(str(x) for x in (finding.get("name"), finding.get("detail"),
                                          finding.get("url")) if x).lower()
        if rule.get("strict"):
            for w in rule.get("whitelist", []):
                if w.lower() in text:
                    return False
            kws = [k.lower() for k in rule.get("evidence_keywords", [])]
            if kws and not any(k in text for k in kws):
                return False
        return True

    def reset(self) -> None:
        self._current_rules = {k: dict(v) for k, v in self._baseline_rules.items()}
        self._history.append({
            "ts": datetime.utcnow().isoformat() + "Z",
            "action": "reset",
        })


_singleton: RuleOptimizer | None = None


def get_optimizer() -> RuleOptimizer:
    global _singleton
    if _singleton is None:
        _singleton = RuleOptimizer()
    return _singleton
