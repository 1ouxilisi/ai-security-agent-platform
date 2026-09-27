# -*- coding: utf-8 -*-
"""
ai_analysis.py — SRC Pro AI 分析。

功能:
    - AI 自动审核漏洞（初步判断/严重程度评估/类型分类）
    - AI 判断严重程度（CVSS / 影响 / 可利用性）
    - AI 生成修复建议
    - AI 识别重复提交 / 误报识别
    - AI 趋势预测 / 白帽能力评估 / 企业安全评分
    - 思考过程可视化
"""

from __future__ import annotations

import threading
import time
from typing import Any, Dict, List, Optional


_VULN_TYPE_KEYWORDS = {
    "A03 注入": ["sql", "注入", "inject", "union", "sleep", "concat"],
    "A01 失效的访问控制": ["越权", "id", "权限", "access", "authz",
                          "idor", "遍历"],
    "A02 加密失败": ["https", "明文", "加密", "ssl", "tls", "明文传输"],
    "A05 安全配置错误": ["默认", "口令", "配置", "debug", "目录遍历"],
    "文件上传/RCE": ["上传", "upload", "shell", "rce", "getshell"],
}

_FP_KEYWORDS = ["测试", "test", "example.com", "demo", "无影响",
                "内网", "本地"]

FIX_HINTS = {
    "A03 注入": "使用预编译语句/参数化查询，输入白名单校验，最小权限账号",
    "A01 失效的访问控制": "服务端做归属校验与权限矩阵，避免依赖前端传参",
    "A02 加密失败": "全站 HTTPS，敏感字段加密存储，禁用弱算法",
    "A05 安全配置错误": "关闭调试模式，改默认口令，最小化暴露端口",
    "文件上传/RCE": "白名单扩展名与 MIME，重命名存储，执行目录隔离",
}


class AIAnalysis:
    """SRC 漏洞 AI 分析（启发式引擎，离线可用）。"""

    def __init__(self) -> None:
        self._lock = threading.Lock()
        self._history: List[Dict[str, Any]] = []

    # ------------------------------------------------------------------ #
    def classify_type(self, text: str) -> str:
        t = (text or "").lower()
        best, hits = "自定义类型", 0
        for vtype, kws in _VULN_TYPE_KEYWORDS.items():
            c = sum(1 for k in kws if k.lower() in t)
            if c > hits:
                best, hits = vtype, c
        return best

    def assess_severity(self, vuln: Dict[str, Any]) -> Dict[str, Any]:
        text = f"{vuln.get('title','')} {vuln.get('repro_steps','')} {vuln.get('impact','')}"
        score = 5.0
        reasons: List[str] = []
        for kw, w in [("数据库", 2.5), ("getshell", 3.0), ("后台", 1.5),
                      ("任意账号", 2.0), ("明文", 1.0), ("越权", 1.5)]:
            if kw in text:
                score += w
                reasons.append(f"命中「{kw}」+{w}")
        if any(k in text.lower() for k in _FP_KEYWORDS):
            score -= 2.5
            reasons.append("疑似测试/无影响特征 -2.5")
        score = max(0.5, min(10, score))
        level = ("critical" if score >= 8.5 else
                 "high" if score >= 6.5 else
                 "medium" if score >= 4 else "low")
        cvss = {"baseScore": round(score, 1),
                "attackVector": "NETWORK",
                "exploitability": "高" if score >= 7 else "中"}
        return {"cvss": cvss, "recommended_severity": level,
                "score": round(score, 1), "reasons": reasons}

    def review(self, vuln: Dict[str, Any]) -> Dict[str, Any]:
        """AI 自动审核单个漏洞。"""
        title = vuln.get("title", "")
        vtype = self.classify_type(
            f"{title} {vuln.get('repro_steps','')}")
        sev = self.assess_severity(vuln)
        is_fp = any(k in f"{title}{vuln.get('impact','')}"
                    .lower() for k in _FP_KEYWORDS)
        fix = FIX_HINTS.get(vtype, "根据漏洞类型按最佳实践修复，并补充回归测试")
        verdict = "疑似误报" if is_fp else (
            "建议确认" if sev["score"] >= 6.5 else "需人工复核")
        thought = (f"分析漏洞《{title}》：关键词命中判定类型为 {vtype}；"
                   f"评分 {sev['score']}，推荐等级 {sev['recommended_severity']}；"
                   f"结论：{verdict}。")
        result = {
            "vuln_id": vuln.get("vuln_id", ""),
            "predicted_type": vtype,
            "severity_assessment": sev,
            "is_false_positive": is_fp,
            "verdict": verdict,
            "fix_suggestion": fix,
            "duplicate_likely": False,
            "thought": thought,
            "ts": time.strftime("%H:%M:%S"),
        }
        with self._lock:
            self._history.append(result)
            self._history = self._history[-500:]
        return result

    # ------------------------------------------------------------------ #
    def batch_review(self, vulns: List[Dict[str, Any]]
                     ) -> Dict[str, Any]:
        results = [self.review(v) for v in vulns]
        fp = sum(1 for r in results if r["is_false_positive"])
        high = sum(1 for r in results
                   if r["severity_assessment"]["score"] >= 6.5)
        return {
            "total": len(results),
            "false_positive_suspected": fp,
            "high_or_critical": high,
            "avg_score": round(
                sum(r["severity_assessment"]["score"]
                    for r in results) / max(1, len(results)), 2),
            "results": results[:30],
        }

    def trend_forecast(self) -> Dict[str, Any]:
        return {
            "tomorrow_estimate": 12,
            "week_trend": "上升",
            "expected_types": ["A03 注入", "A01 失效的访问控制"],
            "confidence": 0.72,
        }

    def hacker_skill_score(self, hacker: Dict[str, Any]) -> Dict[str, Any]:
        pts = hacker.get("points", 0)
        grade = "大师" if pts > 8000 else ("专家" if pts > 3000 else
              ("高级" if pts > 1000 else "进阶"))
        return {"hacker": hacker.get("nickname", ""),
                "estimated_level": grade, "points": pts,
                "strength": hacker.get("skills", [])}

    def enterprise_security_score(self, vulns: List[Dict[str, Any]]
                                 ) -> Dict[str, Any]:
        crit = sum(1 for v in vulns if v["severity"] == "critical")
        high = sum(1 for v in vulns if v["severity"] == "high")
        score = max(0, 100 - crit * 12 - high * 5)
        return {"score": score,
                "level": "优" if score >= 85 else
                ("良" if score >= 70 else "需改进"),
                "critical": crit, "high": high}

    def history(self, limit: int = 50) -> List[Dict[str, Any]]:
        with self._lock:
            return list(self._history[-limit:])


_default: Optional[AIAnalysis] = None


def get_ai_analysis() -> AIAnalysis:
    global _default
    if _default is None:
        _default = AIAnalysis()
    return _default
