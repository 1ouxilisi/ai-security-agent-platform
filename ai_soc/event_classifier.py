#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
AI 事件自动分类器 (Event Classifier)
===================================

功能：
    - 分类 8 类事件：入侵 / 恶意软件 / 数据泄露 / 拒绝服务 /
      内部威胁 / 配置错误 / 异常行为 / 其他
    - 分类算法：
        1. 基于规则：关键词 / 特征 / 模式匹配（内置每类关键词与特征库）
        2. 基于机器学习：朴素贝叶斯文本分类（纯 Python 实现）
    - 严重程度评估：critical / high / medium / low / info
    - 自动分配：基于事件类型 / 严重程度 / 技能 / 负载
    - 自动升级：严重事件自动升级（通知 / 工单 / 应急响应触发）
    - 分类报告：分类统计 / 严重程度分布 / 处理效率

仅用于授权的安全运营场景。
"""
import os
import re
import json
import math
import uuid
from datetime import datetime
from typing import Any, Dict, List, Optional


def _now() -> str:
    return datetime.now().isoformat()


# ----------------------------------------------------------------------
# 纯 Python 朴素贝叶斯文本分类器
# ----------------------------------------------------------------------
class NaiveBayesTextClassifier:
    """多项式朴素贝叶斯文本分类器（纯 Python，含拉普拉斯平滑）"""

    def __init__(self):
        self.class_doc_count: Dict[str, int] = {}
        self.class_word_count: Dict[str, Dict[str, int]] = {}
        self.vocab: set = set()
        self.total_docs: int = 0

    @staticmethod
    def _tokenize(text: str) -> List[str]:
        return re.findall(r"[a-z\u4e00-\u9fa5]+", str(text).lower())

    def train(self, text: str, label: str) -> None:
        """训练单条样本"""
        self.class_doc_count.setdefault(label, 0)
        self.class_word_count.setdefault(label, {})
        self.class_doc_count[label] += 1
        self.total_docs += 1
        for w in self._tokenize(text):
            self.vocab.add(w)
            self.class_word_count[label][w] = self.class_word_count[label].get(w, 0) + 1

    def predict(self, text: str) -> Dict[str, float]:
        """返回各类别的对数后验概率"""
        tokens = self._tokenize(text)
        scores: Dict[str, float] = {}
        V = len(self.vocab) or 1
        for label, doc_n in self.class_doc_count.items():
            # 先验 P(c)
            log_prior = math.log(doc_n / max(self.total_docs, 1))
            words = self.class_word_count[label]
            total_words = sum(words.values()) or 1
            score = log_prior
            for w in tokens:
                count = words.get(w, 0)
                # 拉普拉斯平滑
                score += math.log((count + 1) / (total_words + V))
            scores[label] = score
        return scores


# ----------------------------------------------------------------------
# AI 事件自动分类器
# ----------------------------------------------------------------------
class EventClassifier:
    """AI 事件自动分类器"""

    # 8 类事件关键词 / 特征库（规则引擎）
    KEYWORD_LIBRARY: Dict[str, List[str]] = {
        "入侵": ["intrusion", "unauthorized access", "login brute", "ssh brute",
                "unusual login", "成功爆破", "入侵", "未授权访问"],
        "恶意软件": ["malware", "trojan", "ransomware", "virus", "backdoor",
                    "webshell", "c2 beacon", "挖矿", "木马", "勒索", "后门"],
        "数据泄露": ["data leak", "exfiltration", "data breach", "leaked",
                    "s3 exposure", "数据库导出", "数据泄露", "敏感数据外发"],
        "拒绝服务": ["dos", "ddos", "flood", "syn flood", "outage", "availability",
                    "拒绝服务", "流量攻击", "服务不可用"],
        "内部威胁": ["insider", "privilege abuse", "employee", "offboarding",
                    "内部", "越权", "离职账号", "可疑员工"],
        "配置错误": ["misconfiguration", "misconfig", "default credential",
                    "open port", "exposed", "配置错误", "默认口令", "错误配置"],
        "异常行为": ["anomalous", "anomaly", "unusual behavior", "unusual pattern",
                    "异常行为", "异常登录", "可疑行为"],
    }

    CATEGORIES = ["入侵", "恶意软件", "数据泄露", "拒绝服务",
                  "内部威胁", "配置错误", "异常行为", "其他"]

    # 处理人员池（按技能与负载分配）
    ANALYSTS = {
        "alice": {"skill": ["入侵", "恶意软件"], "load": 0},
        "bob": {"skill": ["数据泄露", "内部威胁"], "load": 0},
        "carol": {"skill": ["拒绝服务", "配置错误"], "load": 0},
        "dave": {"skill": ["异常行为", "其他"], "load": 0},
    }

    def __init__(self):
        self._classifications: Dict[str, Dict[str, Any]] = {}
        self._bayes = NaiveBayesTextClassifier()
        self._train_builtin()
        self._total_handled: int = 0
        self._avg_handle_time: float = 0.0
        self._data_dir = os.path.join(
            os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
            "data", "ai_soc", "event"
        )
        os.makedirs(self._data_dir, exist_ok=True)

    def _train_builtin(self) -> None:
        """用内置关键词样本预训练朴素贝叶斯"""
        for cat, words in self.KEYWORD_LIBRARY.items():
            for w in words:
                self._bayes.train(w, cat)

    # ---------------- 分类 ----------------
    def classify(self, event_data: Dict[str, Any]) -> Dict[str, Any]:
        """
        对事件自动分类，融合规则引擎与朴素贝叶斯。
        :return: 分类结果（event_id / category / confidence / severity）
        """
        event_id = event_data.get("event_id") or "evt-" + uuid.uuid4().hex[:10]
        text = " ".join(str(v) for v in event_data.values() if isinstance(v, str))
        text = text or event_data.get("title", event_data.get("message", ""))

        # 规则引擎：命中关键词计分
        rule_scores: Dict[str, int] = {c: 0 for c in self.CATEGORIES}
        low = str(text).lower()
        for cat, words in self.KEYWORD_LIBRARY.items():
            for w in words:
                if w.lower() in low:
                    rule_scores[cat] += 1

        # 朴素贝叶斯
        bayes_scores = self._bayes.predict(text)
        bayes_cat = max(bayes_scores, key=bayes_scores.get) if bayes_scores else "其他"

        # 融合：规则优先，否则用贝叶斯
        if rule_scores and max(rule_scores.values()) > 0:
            category = max(rule_scores, key=rule_scores.get)
            confidence = min(95.0, 50.0 + rule_scores[category] * 12.0)
        else:
            category = bayes_cat if bayes_cat in self.CATEGORIES else "其他"
            confidence = 60.0

        severity = self.assess_severity(event_data)["severity"]
        result = {
            "event_id": event_id,
            "category": category,
            "confidence": round(confidence, 1),
            "severity": severity,
            "source_text": str(text)[:200],
            "classified_at": _now(),
        }
        self._classifications[event_id] = result
        return result

    # ---------------- 严重程度评估 ----------------
    def assess_severity(self, event_data: Dict[str, Any]) -> Dict[str, Any]:
        """基于事件类型 / 影响范围 / 资产重要性 / 数据敏感性评估严重程度"""
        score = 20
        cat = str(event_data.get("category", ""))
        type_weight = {"数据泄露": 35, "入侵": 30, "恶意软件": 28, "拒绝服务": 25,
                       "内部威胁": 22, "配置错误": 15, "异常行为": 12, "其他": 5}.get(cat, 10)
        score += type_weight
        score += min(20, int(event_data.get("impact_scope", 0)))
        # 资产重要性
        asset = str(event_data.get("asset_criticality", "low")).lower()
        score += {"critical": 25, "high": 15, "medium": 8, "low": 3}.get(asset, 5)
        # 数据敏感性
        sens = str(event_data.get("data_sensitivity", "low")).lower()
        score += {"high": 20, "medium": 10, "low": 3}.get(sens, 5)

        if score >= 80:
            level = "critical"
        elif score >= 60:
            level = "high"
        elif score >= 40:
            level = "medium"
        elif score >= 20:
            level = "low"
        else:
            level = "info"
        return {"severity": level, "score": int(score)}

    # ---------------- 自动分配 ----------------
    def auto_assign(self, event: Dict[str, Any]) -> Dict[str, Any]:
        """基于事件类型 / 严重程度 / 技能 / 负载自动分配处理人员"""
        category = event.get("category")
        severity = str(event.get("severity", "low")).lower()
        # 按技能匹配，再按负载均衡
        candidates = [name for name, info in self.ANALYSTS.items() if category in info["skill"]]
        if not candidates:
            candidates = list(self.ANALYSTS.keys())
        # 负载最低者优先
        assignee = min(candidates, key=lambda n: self.ANALYSTS[n]["load"])
        self.ANALYSTS[assignee]["load"] += (20 if severity == "critical" else 10)
        event["assigned_to"] = assignee
        event["assigned_at"] = _now()
        event["assignment_reason"] = f"技能匹配({category}) + 负载均衡"
        # 自动升级
        escalation = self.auto_escalate(event)
        return {"event_id": event.get("event_id"), "assignee": assignee,
                "escalation": escalation, "event": event}

    # ---------------- 自动升级 ----------------
    def auto_escalate(self, event: Dict[str, Any]) -> Dict[str, Any]:
        """严重事件自动升级：通知 / 工单 / 应急响应触发"""
        severity = str(event.get("severity", "low")).lower()
        actions: List[str] = []
        if severity == "critical":
            actions = ["电话通知值班经理", "创建应急响应工单", "触发应急响应流程", "通知 CISO"]
        elif severity == "high":
            actions = ["邮件通知处理人", "创建高优先级工单"]
        elif severity == "medium":
            actions = ["记录到工单系统"]
        return {"escalated": bool(actions), "severity": severity, "actions": actions,
                "escalated_at": _now() if actions else None}

    # ---------------- 查询与统计 ----------------
    def get_classification(self, event_id: str) -> Dict[str, Any]:
        """获取单事件分类结果"""
        return self._classifications.get(event_id, {"event_id": event_id, "status": "not_found"})

    def get_stats(self) -> Dict[str, Any]:
        """分类统计：分类分布 / 严重程度分布 / 处理效率"""
        cat_dist: Dict[str, int] = {}
        sev_dist: Dict[str, int] = {}
        for r in self._classifications.values():
            cat_dist[r.get("category", "其他")] = cat_dist.get(r.get("category", "其他"), 0) + 1
            sev_dist[r.get("severity", "info")] = sev_dist.get(r.get("severity", "info"), 0) + 1
        return {
            "total_classified": len(self._classifications),
            "category_distribution": cat_dist,
            "severity_distribution": sev_dist,
            "handling_efficiency": {
                "total_handled": self._total_handled,
                "avg_handle_time_min": self._avg_handle_time,
            },
        }

    # ---------------- 报告 ----------------
    def generate_report(self) -> Dict[str, Any]:
        """生成事件分类报告"""
        stats = self.get_stats()
        return {
            "report_type": "event_classification",
            "generated_at": _now(),
            "statistics": stats,
            "analyst_load": self.ANALYSTS,
            "recommendations": [
                "对 critical/high 事件保证 30 分钟内响应",
                "定期复核分类误判，迭代关键词库",
                "均衡分析师负载，避免单点过载",
            ],
        }


# ---------------- 模块级单例 ----------------
_event_classifier_instance: Optional[EventClassifier] = None


def get_event_classifier() -> EventClassifier:
    global _event_classifier_instance
    if _event_classifier_instance is None:
        _event_classifier_instance = EventClassifier()
    return _event_classifier_instance


event_classifier: EventClassifier = get_event_classifier()
