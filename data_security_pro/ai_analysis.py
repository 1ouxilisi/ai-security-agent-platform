# -*- coding: utf-8 -*-
"""
ai_analysis.py — 数据安全 Pro：AI 分析。

- 自动分析数据安全风险
- 生成整改建议 / 优先级排序
- 敏感数据识别辅助 / 异常访问检测辅助 / 合规风险评估
- 数据安全改进路线图
"""

from __future__ import annotations

from typing import Any, Dict, List, Optional


class DataSecurityAIAnalysis:
    """规则化"AI"分析引擎（不依赖外部模型，本地可跑）。"""

    # ------------------------------------------------------------------ #
    def analyze_overall(self, risk: Dict[str, Any],
                        compliance: Optional[Dict[str, Any]] = None,
                        encryption: Optional[Dict[str, Any]] = None,
                        ) -> Dict[str, Any]:
        sub = risk.get("sub_scores", {})
        notes: List[str] = []
        # 风险点解读
        if sub.get("sensitivity", 0) >= 60:
            notes.append("敏感数据暴露面较大：存在 Top Secret 级数据未充分分类打标。")
        if sub.get("dlp", 0) >= 60:
            notes.append("DLP 存在 critical 级外发事件，建议立即启用阻断策略。")
        if sub.get("compliance_gap", 0) >= 40:
            notes.append("GDPR/PIPL 存在不符合项，需在 30 天内完成整改。")
        if sub.get("encryption", 0) >= 50:
            notes.append("发现弱算法或未加密字段，建议替换为 AES-256-GCM。")
        if sub.get("access", 0) >= 50:
            notes.append("存在异常访问行为，建议启用 UEBA 与特权账号审计。")
        if not notes:
            notes.append("整体风险可控，保持现有控制措施即可。")

        # 优先级整改
        top = risk.get("top_risks", [])
        actions = []
        for i, r in enumerate(top[:5], 1):
            actions.append({
                "priority": i,
                "risk": r["title"],
                "level": r["level"],
                "score": r["score"],
                "action": self._suggest_for(r["category"], r["score"]),
            })

        return {
            "overall_level": risk.get("overall_level"),
            "overall_score": risk.get("overall_score"),
            "interpretation": notes,
            "priority_actions": actions,
            "roadmap": self.roadmap(risk),
        }

    # ------------------------------------------------------------------ #
    def _suggest_for(self, category: str, score: int) -> str:
        table = {
            "数据敏感度": "完成敏感数据自动打标，加密 Top Secret 字段，限制访问范围。",
            "DLP": "对 critical 策略启用 block，复盘最近 7 天外发事件，培训员工。",
            "隐私合规": "30 天内关闭高优先级不符合项，更新隐私政策与同意机制。",
            "加密密钥": "替换 DES/3DES/MD5/SHA1，密钥轮换周期压缩到 90 天内。",
            "访问审计": "启用异常时间/地点/批量导出告警，回收冗余权限。",
        }
        return table.get(category, "建立监控指标并按月复盘。")

    # ------------------------------------------------------------------ #
    def roadmap(self, risk: Dict[str, Any]) -> List[Dict[str, Any]]:
        level = risk.get("overall_level", "medium")
        horizon = {
            "critical": [("0-7 天", "止血：阻断 critical DLP 事件，冻结外泄通道"),
                         ("8-30 天", "整改：加密 Top Secret 字段，关闭合规不符合项"),
                         ("31-90 天", "体系：UEBA、密钥 KMS、DLP 全通道覆盖")],
            "high": [("0-14 天", "整改：弱算法替换、权限回收"),
                     ("15-60 天", "加固：DLP 策略调优、合规补项"),
                     ("61-120 天", "度量：建立成熟度指标")],
            "medium": [("0-30 天", "补漏：补齐分类分级标签"),
                       ("31-90 天", "优化：自动化报告与告警闭环")],
            "low": [("持续", "保持控制，定期复盘")],
        }.get(level, [])
        return [{"window": w, "action": a} for w, a in horizon]

    # ------------------------------------------------------------------ #
    def assist_sensitive_recognition(self, hits: List[Dict[str, Any]]
                                     ) -> Dict[str, Any]:
        """对数据发现结果做辅助解读。"""
        by_type: Dict[str, int] = {}
        for h in hits:
            by_type[h.get("data_type", "unknown")] = \
                by_type.get(h.get("data_type", "unknown"), 0) + 1
        tips = []
        if by_type.get("id_card"):
            tips.append("身份证号命中多，建议字段级加密 + 脱敏展示。")
        if by_type.get("bank_card"):
            tips.append("银行卡号命中多，建议令牌化（tokenization）。")
        if by_type.get("private_key") or by_type.get("password_assignment"):
            tips.append("发现密钥/密码明文，立即轮换并扫描全代码仓库。")
        return {
            "by_type": by_type,
            "tips": tips or ["未发现高危敏感类型。"],
        }

    # ------------------------------------------------------------------ #
    def assist_access(self, anomalies: List[Dict[str, Any]]
                      ) -> Dict[str, Any]:
        atypes: Dict[str, int] = {}
        for a in anomalies:
            atypes[a.get("atype", "?")] = atypes.get(a.get("atype", "?"), 0) + 1
        verdict = "正常"
        if atypes.get("bulk_export", 0) > 0:
            verdict = "疑似数据导出，建议立即核查工单"
        elif atypes.get("unusual_location", 0) > 0:
            verdict = "疑似异地登录，建议强制二次认证"
        return {
            "anomaly_types": atypes,
            "verdict": verdict,
            "total": len(anomalies),
        }


_default_ai: Optional[DataSecurityAIAnalysis] = None


def get_ai_analysis() -> DataSecurityAIAnalysis:
    global _default_ai
    if _default_ai is None:
        _default_ai = DataSecurityAIAnalysis()
    return _default_ai


__all__ = ["DataSecurityAIAnalysis", "get_ai_analysis"]
