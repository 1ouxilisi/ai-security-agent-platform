# -*- coding: utf-8 -*-
"""
data_classification_phase.py — 阶段2：数据分类分级。

四级分级:
    Public      公开
    Internal    内部
    Confidential 机密
    Top Secret  绝密

分类规则引擎: 基于数据类型 / 字段名 / 内容 / 上下文自动打标；
支持自定义规则、分类质量评估、自动打标。
"""

from __future__ import annotations

import time
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional


LEVEL_ORDER = ["public", "internal", "confidential", "top_secret"]
LEVEL_LABELS = {
    "public": "公开",
    "internal": "内部",
    "confidential": "机密",
    "top_secret": "绝密",
}

# 默认数据类型 -> 分级映射
DEFAULT_TYPE_LEVEL = {
    "id_card": "top_secret",
    "mobile": "confidential",
    "bank_card": "top_secret",
    "email": "internal",
    "password_assignment": "top_secret",
    "private_key": "top_secret",
    "unified_credit_code": "confidential",
    "name_addr": "confidential",
    "medical": "top_secret",
    "finance": "confidential",
}


@dataclass
class ClassificationRule:
    rule_id: str
    name: str
    field_pattern: str = ""      # 字段名匹配（子串）
    data_type: str = ""          # 数据类型匹配
    content_keyword: str = ""    # 内容关键词
    level: str = "internal"
    enabled: bool = True
    weight: int = 1

    def to_dict(self) -> Dict[str, Any]:
        return {
            "rule_id": self.rule_id, "name": self.name,
            "field_pattern": self.field_pattern,
            "data_type": self.data_type,
            "content_keyword": self.content_keyword,
            "level": self.level, "enabled": self.enabled,
            "weight": self.weight,
        }


class DataClassificationPhase:
    """阶段2：分类分级。"""

    def __init__(self) -> None:
        self.rules: List[ClassificationRule] = []
        self._seed_default_rules()
        self._labels: Dict[str, str] = {}   # asset_key -> level
        self._history: List[Dict[str, Any]] = []

    # ------------------------------------------------------------------ #
    def _seed_default_rules(self) -> None:
        defaults = [
            dict(rule_id="R001", name="身份证号->绝密", data_type="id_card",
                 level="top_secret", weight=10),
            dict(rule_id="R002", name="银行卡->绝密", data_type="bank_card",
                 level="top_secret", weight=10),
            dict(rule_id="R003", name="私钥->绝密", data_type="private_key",
                 level="top_secret", weight=10),
            dict(rule_id="R004", name="医疗记录->绝密", data_type="medical",
                 level="top_secret", weight=9),
            dict(rule_id="R005", name="手机号->机密", data_type="mobile",
                 level="confidential", weight=7),
            dict(rule_id="R006", name="信用代码->机密",
                 data_type="unified_credit_code",
                 level="confidential", weight=6),
            dict(rule_id="R007", name="财务数据->机密", data_type="finance",
                 level="confidential", weight=6),
            dict(rule_id="R008", name="邮箱->内部", data_type="email",
                 level="internal", weight=3),
            dict(rule_id="R009", name="字段含 password->绝密",
                 field_pattern="password",
                 level="top_secret", weight=10),
            dict(rule_id="R010", name="字段含 salary->机密",
                 field_pattern="salary",
                 level="confidential", weight=6),
        ]
        for kw in defaults:
            self.rules.append(ClassificationRule(**kw))

    # ------------------------------------------------------------------ #
    def add_rule(self, name: str, level: str,
                 field_pattern: str = "", data_type: str = "",
                 content_keyword: str = "", weight: int = 5,
                 ) -> ClassificationRule:
        rid = f"R{100 + len(self.rules):03d}"
        r = ClassificationRule(
            rule_id=rid, name=name, level=level,
            field_pattern=field_pattern.lower(),
            data_type=data_type,
            content_keyword=content_keyword.lower(),
            weight=weight)
        self.rules.append(r)
        return r

    def toggle_rule(self, rule_id: str) -> Dict[str, Any]:
        for r in self.rules:
            if r.rule_id == rule_id:
                r.enabled = not r.enabled
                return r.to_dict()
        return {"error": "rule not found"}

    def list_rules(self) -> List[Dict[str, Any]]:
        return [r.to_dict() for r in self.rules]

    # ------------------------------------------------------------------ #
    def classify_item(self, data_type: str = "", field_name: str = "",
                      content: str = "",
                      ) -> Dict[str, Any]:
        """对单个数据项做分类打分，返回最终分级与命中规则。"""
        fname = (field_name or "").lower()
        ctype = (content or "").lower()
        scores: Dict[str, int] = {lv: 0 for lv in LEVEL_ORDER}
        hit_rules: List[str] = []
        for r in self.rules:
            if not r.enabled:
                continue
            matched = False
            if r.data_type and r.data_type == data_type:
                matched = True
            if r.field_pattern and r.field_pattern in fname:
                matched = True
            if r.content_keyword and r.content_keyword in ctype:
                matched = True
            if matched:
                scores[r.level] += r.weight
                hit_rules.append(r.rule_id)
        # 兜底：按默认类型映射
        if not hit_rules and data_type in DEFAULT_TYPE_LEVEL:
            scores[DEFAULT_TYPE_LEVEL[data_type]] += 5
            hit_rules.append("default:" + data_type)
        # 取最高分；并列时取更高级别
        best_level = "internal"
        best_score = -1
        for lv in reversed(LEVEL_ORDER):   # 从高到低，同级先取高
            if scores[lv] > best_score:
                best_score = scores[lv]
                best_level = lv
        return {
            "data_type": data_type,
            "field_name": field_name,
            "level": best_level,
            "level_label": LEVEL_LABELS[best_level],
            "scores": scores,
            "hit_rules": hit_rules,
        }

    # ------------------------------------------------------------------ #
    def classify_batch(self, hits: List[Dict[str, Any]]) -> Dict[str, Any]:
        """批量对数据发现结果打标。"""
        results: List[Dict[str, Any]] = []
        for h in hits:
            item = self.classify_item(
                data_type=h.get("data_type", ""),
                field_name=h.get("table", ""),
                content=h.get("context_preview", ""))
            item["source_hit"] = h
            results.append(item)
            key = f"{h.get('table','-')}:{h.get('data_type','-')}"
            self._labels[key] = item["level"]
        by_level: Dict[str, int] = {lv: 0 for lv in LEVEL_ORDER}
        for r in results:
            by_level[r["level"]] += 1
        self._history.append({
            "ts": time.strftime("%Y-%m-%d %H:%M:%S"),
            "count": len(results), "by_level": by_level,
        })
        return {
            "results": results,
            "count": len(results),
            "by_level": by_level,
            "quality": self.assess_quality(results),
        }

    # ------------------------------------------------------------------ #
    def assess_quality(self, results: List[Dict[str, Any]]) -> Dict[str, Any]:
        """分类质量评估：覆盖率 / 平均置信 / 规则命中率。"""
        if not results:
            return {"coverage": 0, "avg_confidence": 0,
                    "rule_hit_rate": 0}
        covered = sum(1 for r in results if r["hit_rules"])
        conf = []
        for r in results:
            src = r.get("source_hit") or {}
            c = src.get("confidence")
            if isinstance(c, (int, float)):
                conf.append(float(c))
        return {
            "coverage": round(covered / len(results) * 100, 1),
            "avg_confidence": round(sum(conf) / len(conf), 2) if conf else 0,
            "rule_hit_rate": round(covered / len(results) * 100, 1),
            "total": len(results),
        }

    # ------------------------------------------------------------------ #
    def get_labels(self) -> Dict[str, str]:
        return dict(self._labels)

    def history(self) -> List[Dict[str, Any]]:
        return list(self._history[-50:])


_default_phase: Optional[DataClassificationPhase] = None


def get_data_classification_phase() -> DataClassificationPhase:
    global _default_phase
    if _default_phase is None:
        _default_phase = DataClassificationPhase()
    return _default_phase


__all__ = [
    "DataClassificationPhase", "ClassificationRule",
    "get_data_classification_phase",
    "LEVEL_ORDER", "LEVEL_LABELS",
]
