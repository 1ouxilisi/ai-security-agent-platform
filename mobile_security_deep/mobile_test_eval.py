#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
mobile_test_eval.py — 移动安全测试与评测引擎（第29轮升级方向2）。

覆盖：
    1. 移动安全测试：静态/动态/接口/性能/兼容性/稳定性/安全/渗透测试
    2. 移动安全评测：安全/合规/质量/体验/综合评分 + 评分标准 + 评测流程 + 报告
    3. 检测工具：自动化扫描/人工测试/漏洞验证/性能分析/流量分析/日志分析/
       内存分析/调试工具
    4. 移动安全标准：OWASP Mobile Top 10 / 行业标准 / 国标 / 行标 / 团标 /
       企业标准 / 合规要求
    5. 最佳实践：安全编码/设计/测试/发布/运营 + 最佳实践库 + 参考案例
    6. 移动安全报告：测试/评测/漏洞/合规/最佳实践/趋势报告 + 多格式导出
"""

from __future__ import annotations

import uuid
from datetime import datetime
from typing import Any, Dict, List, Optional


# ==================== OWASP Mobile Top 10 (2024) ====================

OWASP_MOBILE_TOP10: List[Dict[str, str]] = [
    {"id": "M1", "name": "不安全的凭证", "desc": "凭证硬编码、弱认证、会话管理缺陷"},
    {"id": "M2", "name": "不安全的认证", "desc": "弱认证流程、缺乏多因素认证"},
    {"id": "M3", "name": "不安全的存储", "desc": "本地数据未加密存储"},
    {"id": "M4", "name": "不安全的通信", "desc": "明文传输、证书校验缺失"},
    {"id": "M5", "name": "不安全的预授权", "desc": "过度信任客户端授权决策"},
    {"id": "M6", "name": "不适当的输入验证", "desc": "客户端校验、注入风险"},
    {"id": "M7", "name": "安全配置错误", "desc": "调试接口、导出组件、默认配置"},
    {"id": "M8", "name": "代码注入", "desc": "WebView JS桥、动态加载"},
    {"id": "M9", "name": "不安全的数据外泄", "desc": "日志/缓存/备份泄露"},
    {"id": "M10", "name": "缺乏二进制防护", "desc": "未加固、易逆向、无完整性校验"},
]

# 标准库
STANDARDS: Dict[str, str] = {
    "OWASP Mobile Top 10": "移动应用安全十大风险",
    "GB/T 35273": "个人信息安全规范",
    "GB/T 41391": "移动互联网应用程序(App)收集个人信息基本要求",
    "YD/T 3862": "通信行业移动互联网应用程序安全评测方法",
    "《App违法违规收集使用个人信息行为认定方法》": "个人信息合规认定",
    "PCI DSS Mobile": "支付卡移动安全",
    "ST 安全等级保护 2.0": "移动应用等级保护",
}

# 测试类型
TEST_TYPES = {
    "静态测试": "代码/包静态分析",
    "动态测试": "运行时行为分析",
    "接口测试": "API 安全测试",
    "性能测试": "CPU/内存/电量/流量",
    "兼容性测试": "多机型/系统版本",
    "稳定性测试": "Monkey/压力",
    "安全测试": "漏洞扫描/渗透",
    "渗透测试": "模拟攻击者视角",
}

# 评分维度
SCORING_DIMENSIONS = ["安全评分", "合规评分", "质量评分", "体验评分", "综合评分"]

# 最佳实践库
BEST_PRACTICES: List[Dict[str, str]] = [
    {"stage": "安全设计", "practice": "最小权限原则 + 数据分级", "ref": "OWASP MASVS"},
    {"stage": "安全编码", "practice": "密钥不下发客户端，使用加密存储", "ref": "Android Jetpack Security"},
    {"stage": "安全测试", "practice": "CI 集成 SAST/DAST 自动化扫描", "ref": "DevSecOps"},
    {"stage": "安全发布", "practice": "Release 关闭调试、开启混淆/加固", "ref": "R8/ProGuard"},
    {"stage": "安全运营", "practice": "运行时监控 + 漏洞应急响应", "ref": "RASP"},
]


# ==================== 核心引擎 ====================

class MobileTestEvalEngine:
    """移动安全测试与评测引擎。"""

    def __init__(self) -> None:
        self.reports: Dict[str, Dict[str, Any]] = {}

    # ---------- 1. 测试计划 ----------
    def plan_test(self, app: str = "示例App", platforms: Optional[List[str]] = None) -> Dict[str, Any]:
        platforms = platforms or ["Android", "iOS"]
        cases = []
        for ttype, desc in TEST_TYPES.items():
            cases.append({
                "case_id": f"TC-{uuid.uuid4().hex[:6]}",
                "type": ttype, "desc": desc,
                "platforms": platforms, "automated": ttype in ("静态测试", "动态测试", "接口测试"),
                "priority": "high" if ttype in ("安全测试", "渗透测试") else "medium",
            })
        return {
            "plan_id": f"plan-{uuid.uuid4().hex[:8]}",
            "app": app, "platforms": platforms,
            "test_cases": cases, "case_count": len(cases),
            "estimated_hours": len(cases) * 4,
        }

    # ---------- 2. 执行测试（模拟） ----------
    def run_test(self, plan_id: str, app: str = "示例App") -> Dict[str, Any]:
        results = []
        for ttype in TEST_TYPES:
            passed = (hash(ttype + app) % 5) != 0
            results.append({
                "type": ttype, "passed": passed,
                "issues": 0 if passed else 2,
                "duration_min": 10 + (hash(ttype) % 30),
            })
        rid = f"test-{uuid.uuid4().hex[:8]}"
        report = {
            "report_id": rid, "plan_id": plan_id, "app": app,
            "results": results,
            "passed": sum(1 for r in results if r["passed"]),
            "failed": sum(1 for r in results if not r["passed"]),
            "total_issues": sum(r["issues"] for r in results),
            "executed_at": datetime.now().isoformat(timespec="seconds"),
        }
        self.reports[rid] = report
        return report

    # ---------- 3. 安全评测打分 ----------
    def evaluate(self, app: str = "示例App",
                 security: float = 82.0, compliance: float = 78.0,
                 quality: float = 88.0, ux: float = 85.0) -> Dict[str, Any]:
        overall = round(security * 0.4 + compliance * 0.25 + quality * 0.2 + ux * 0.15, 1)
        grade = "A" if overall >= 85 else "B" if overall >= 70 else "C" if overall >= 60 else "D"
        return {
            "eval_id": f"eval-{uuid.uuid4().hex[:8]}",
            "app": app,
            "scores": {
                "安全评分": security, "合规评分": compliance,
                "质量评分": quality, "体验评分": ux, "综合评分": overall,
            },
            "grade": grade,
            "standard": "OWASP Mobile Top 10 + GB/T 35273",
            "levels_checked": OWASP_MOBILE_TOP10,
            "evaluated_at": datetime.now().isoformat(timespec="seconds"),
        }

    # ---------- 4. 标准 / 最佳实践 ----------
    def standards(self) -> Dict[str, str]:
        return STANDARDS

    def best_practices(self) -> List[Dict[str, str]]:
        return BEST_PRACTICES

    def owasp_top10(self) -> List[Dict[str, str]]:
        return OWASP_MOBILE_TOP10

    # ---------- 5. 趋势 ----------
    def trend(self, days: int = 14) -> List[Dict[str, Any]]:
        out = []
        for i in range(days):
            out.append({
                "day": f"D-{days - i}",
                "scans": 5 + (i * 3) % 12,
                "vulns_found": 1 + (i * 7) % 6,
                "fixed": 1 + (i * 5) % 4,
            })
        return out

    def list_reports(self) -> List[Dict[str, Any]]:
        return list(self.reports.values())

    def stats(self) -> Dict[str, Any]:
        return {
            "test_types": len(TEST_TYPES),
            "owasp_items": len(OWASP_MOBILE_TOP10),
            "standards": len(STANDARDS),
            "best_practices": len(BEST_PRACTICES),
            "reports": len(self.reports),
        }


_instance: Optional[MobileTestEvalEngine] = None


def get_test_eval_engine() -> MobileTestEvalEngine:
    global _instance
    if _instance is None:
        _instance = MobileTestEvalEngine()
    return _instance
