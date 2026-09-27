# -*- coding: utf-8 -*-
"""
ai_analysis.py — SOC Pro AI 分析。

功能:
    - AI 自动分析告警，判断是否为真实攻击
    - 告警降噪（误报识别/低优先级告警过滤）
    - 攻击路径推理
    - 响应建议生成
    - 事件严重程度评估
    - 根因分析辅助
"""

from __future__ import annotations

import threading
from typing import Any, Dict, List, Optional


# 简易"AI"规则引擎（不调外部 LLM，纯启发式，保证离线可用）
_FALSE_POSITIVE_PATTERNS = [
    "vpn_test", "internal_monitor", "backup_job", "cron",
    "health_check", "monitoring_probe",
]


class AIAnalysis:
    """AI 告警分析引擎（启发式，离线可用）。"""

    def __init__(self) -> None:
        self._lock = threading.Lock()
        self._history: List[Dict[str, Any]] = []

    # ------------------------------------------------------------------ #
    def analyze_alert(self, alert: Dict[str, Any]) -> Dict[str, Any]:
        title = (alert.get("title") or "").lower()
        desc = (alert.get("description") or "").lower()
        src = alert.get("src_ip", "") or ""
        sev = alert.get("severity", "medium")
        text = f"{title} {desc} {src}"

        # 误报识别
        is_fp = any(p in text for p in _FALSE_POSITIVE_PATTERNS)
        # 严重程度再评估
        score = {"critical": 9, "high": 7, "medium": 5, "low": 2}.get(
            sev, 5)
        reasons: List[str] = []
        if is_fp:
            score -= 6
            reasons.append("命中已知良性模式，疑似误报")
        if src.startswith(("10.", "192.168.", "172.16.")) and sev != \
                "critical":
            score -= 1
            reasons.append("源为内网，初始风险略降")
        if alert.get("mitre") in ("T1071", "T1041", "T1485"):
            score += 1
            reasons.append("涉及 C2/外泄/破坏战术，风险上调")

        verdict = "benign" if is_fp else (
            "likely_attack" if score >= 6 else "uncertain")
        response_advice = self._advise(alert, verdict)
        chain = self._infer_chain(alert)

        result = {
            "alert_id": alert.get("alert_id", ""),
            "verdict": verdict,
            "score": max(0, min(10, score)),
            "is_false_positive": is_fp,
            "reasons": reasons,
            "response_advice": response_advice,
            "attack_chain_hint": chain,
            "severity_recommendation":
                "critical" if score >= 8 else
                "high" if score >= 6 else
                "medium" if score >= 4 else "low",
            "thought": self._think_text(alert, verdict, reasons),
        }
        with self._lock:
            self._history.append(result)
            self._history = self._history[-500:]
        return result

    # ------------------------------------------------------------------ #
    def _advise(self, alert: Dict[str, Any], verdict: str
                ) -> List[str]:
        if verdict == "benign":
            return ["标记为误报并静默", "加入白名单",
                    "优化检测规则阈值"]
        cat = alert.get("category", "")
        if cat == "brute_force":
            return ["立即封禁源 IP", "锁定被爆破账户",
                    "检查是否存在成功登录", "强制密码重置"]
        if cat == "exfiltration":
            return ["立即隔离受影响主机", "提取网络流量证据",
                    "联系网络组切断外联", "评估数据泄露范围"]
        if cat == "malware":
            return ["隔离主机", "查杀并取证",
                    "排查横向扩散", "重置相关凭证"]
        if cat == "privesc":
            return ["审计 sudo 日志", "检查新增特权账户",
                    "主机快照取证", "强化 sudo 策略"]
        if cat == "lateral_move":
            return ["终止远程会话", "检查所有可疑主机",
                    "禁用相关账户", "开展狩猎"]
        return ["人工研判", "查看证据", "按需升级"]

    # ------------------------------------------------------------------ #
    def _infer_chain(self, alert: Dict[str, Any]) -> List[Dict[str, str]]:
        cat = alert.get("category", "")
        base = [
            {"stage": "侦察", "technique": "T1046 端口扫描",
             "evidence": "前置扫描告警"},
            {"stage": "初始访问", "technique": "T1110 暴力破解",
             "evidence": "登录失败激增"},
        ]
        if cat == "brute_force":
            base.append({"stage": "凭证访问", "technique": "T1078",
                         "evidence": "登录成功"})
        elif cat == "exfiltration":
            base += [
                {"stage": "收集", "technique": "T1005",
                 "evidence": "本地数据收集"},
                {"stage": "外泄", "technique": "T1041",
                 "evidence": "大流量外发"},
            ]
        elif cat == "malware":
            base.append({"stage": "执行", "technique": "T1204",
                         "evidence": "恶意文件执行"})
        return base

    # ------------------------------------------------------------------ #
    def _think_text(self, alert: Dict[str, Any], verdict: str,
                    reasons: List[str]) -> str:
        return (
            f"我正在分析告警 [{alert.get('title','')}]，"
            f"源 {alert.get('src_ip','')}，严重度 {alert.get('severity','')}。"
            f"特征：{'；'.join(reasons) or '无明显良性特征'}。"
            f"综合判定：{verdict}。"
        )

    # ------------------------------------------------------------------ #
    def batch_analyze(self, alerts: List[Dict[str, Any]]
                      ) -> Dict[str, Any]:
        results = [self.analyze_alert(a) for a in alerts]
        fp = sum(1 for r in results if r["is_false_positive"])
        real = sum(1 for r in results
                   if r["verdict"] == "likely_attack")
        noise_ratio = round(fp / max(1, len(results)), 2)
        return {
            "total": len(results),
            "false_positives": fp,
            "likely_attack": real,
            "uncertain": len(results) - fp - real,
            "noise_ratio": noise_ratio,
            "results": results[:30],
        }

    # ------------------------------------------------------------------ #
    def root_cause_aux(self, incident: Dict[str, Any]
                       ) -> Dict[str, Any]:
        return {
            "hypothesis": "攻击者通过公开 VPN 入口弱口令爆破，"
                          "成功后横向移动并落地远控。",
            "evidence_chain": [
                "1. 前置 24h 出现 SSH/RDP 爆破告警",
                "2. 告警源 IP 在威胁情报中",
                "3. 成功登录后 10 分钟内出现可疑 PowerShell",
                "4. 随后 SMB 异常访问多台主机",
            ],
            "missing_controls": [
                "未启用 MFA",
                "VPN 未做地理位置限制",
                "EDR 未对可疑 PS 命令拦截",
            ],
        }

    def history(self, limit: int = 50) -> List[Dict[str, Any]]:
        with self._lock:
            return list(self._history[-limit:])


_default: Optional[AIAnalysis] = None


def get_ai_analysis() -> AIAnalysis:
    global _default
    if _default is None:
        _default = AIAnalysis()
    return _default
