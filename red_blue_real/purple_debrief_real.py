# -*- coding: utf-8 -*-
"""
purple_debrief_real.py — 方向4：真实紫队复盘。

能力:
    - compare_steps       攻击 vs 检测逐步对比（检测/未检测/延迟/误报）
    - detection_metrics   检测延迟 / 误报率 / 漏报率 / 覆盖率 / 质量评分
    - gap_analysis        哪些没检测到 / 为什么 / 怎么改进 / 优先级
    - improvement_plan   加规则/加日志/加监控/加培训/优化配置/加工具 + P0-P3 + 路线图

输入为真实红队攻击步骤与真实蓝队告警，纯 Python 计算，不 mock。
"""

from __future__ import annotations

import time
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional


@dataclass
class PurpleStep:
    name: str = ""
    tech: str = ""
    red_success: bool = True
    detected: bool = False
    delay_seconds: float = 0.0
    false_positive: bool = False
    note: str = ""


class PurpleDebriefReal:
    """真实紫队复盘。"""

    # ------------------------------------------------------------------ #
    def compare_steps(self,
                      red_steps: List[Dict[str, Any]],
                      blue_alerts: Optional[List[Dict[str, Any]]] = None
                      ) -> Dict[str, Any]:
        """逐攻击步骤比对是否被检测。"""
        blue_alerts = blue_alerts or []
        alerted_techs = {a.get("tech") for a in blue_alerts if a.get("tech")}
        rows: List[Dict[str, Any]] = []
        for i, step in enumerate(red_steps):
            tech = step.get("tech", "")
            detected = tech in alerted_techs
            delay = float(step.get("delay_seconds", 0))
            status = "detected" if detected else "missed"
            if detected and delay > 300:
                status = "delayed"
            rows.append({
                "idx": i, "name": step.get("name", tech),
                "tech": tech, "red_success": step.get("red_success", True),
                "detected": detected, "status": status,
                "delay_seconds": delay,
                "false_positive": step.get("false_positive", False),
            })
        return {"tech": "紫队复盘", "steps": rows,
                "step_count": len(rows),
                "detected_count": sum(1 for r in rows if r["detected"]),
                "missed_count": sum(1 for r in rows if not r["detected"]),
                "generated_at": time.strftime("%Y-%m-%d %H:%M:%S")}

    # ------------------------------------------------------------------ #
    def detection_metrics(self, comparison: Dict[str, Any],
                          total_fp: int = 0) -> Dict[str, Any]:
        rows = comparison.get("steps", [])
        n = len(rows) or 1
        detected = sum(1 for r in rows if r["detected"])
        missed = n - detected
        coverage = round(detected / n * 100, 1)
        delays = [r["delay_seconds"] for r in rows if r["detected"]]
        avg_delay = round(sum(delays) / len(delays), 2) if delays else -1.0
        fp_rate = round(total_fp / max(n, 1) * 100, 2)
        fn_rate = round(missed / n * 100, 2)
        # 检测质量评分（0-100）
        score = round(coverage * 0.5 +
                      (100 - min(fp_rate, 100)) * 0.2 +
                      (100 - min(fn_rate, 100)) * 0.2 +
                      (100 if avg_delay <= 60 else
                       (70 if avg_delay <= 300 else 30)) * 0.1, 1)
        return {"tech": "检测质量度量", "coverage_pct": coverage,
                "detected": detected, "missed": missed,
                "avg_delay_seconds": avg_delay,
                "false_positive_count": total_fp, "false_positive_rate_pct": fp_rate,
                "false_negative_rate_pct": fn_rate,
                "quality_score": score}

    # ------------------------------------------------------------------ #
    def gap_analysis(self, comparison: Dict[str, Any]) -> Dict[str, Any]:
        rows = comparison.get("steps", [])
        gaps: List[Dict[str, Any]] = []
        reason_map = {
            "T1566": "钓鱼邮件未接入邮件网关日志/用户点击无 UEBA",
            "T1059": "PowerShell 脚本块日志未开启（4104）",
            "T1547": "注册表持久化无 Sysmon EventID 13 监控",
            "T1068": "提权行为无 EDR 行为规则/无漏洞扫描",
            "T1003": "LSASS 访问/敏感注册表无告警",
            "T1021": "横向 SMB/WMI/WinRM 无异常会话基线",
            "T1041": "外网数据外泄无 DLPEgress/网络元数据基线",
        }
        fix_map = {
            "T1566": "部署邮件安全网关 + 钓鱼演练平台",
            "T1059": "开启 PowerShell ScriptBlock Logging + AMSI",
            "T1547": "Sysmon 配置监控 Run 键/服务创建",
            "T1068": "部署 EDR + 定期漏洞扫描与补丁",
            "T1003": "监控敏感 LSASS 句柄访问 + LSA Protection",
            "T1021": "横向移动检测基线（异常管理员/时间/源）",
            "T1041": "网络出口流量基线 + DLPEgress 阻断",
        }
        sev_order = {"critical": 0, "high": 1, "medium": 2, "low": 3}
        for r in rows:
            if r["detected"]:
                continue
            tech = r["tech"]
            root = next((v for k, v in reason_map.items() if k in tech),
                        "缺少对应日志源或检测规则")
            fix = next((v for k, v in fix_map.items() if k in tech),
                       "补充日志源并编写 Sigma/YARA 规则")
            sev = "high" if tech.startswith(("T1003", "T1021", "T1068")) else "medium"
            gaps.append({"name": r["name"], "tech": tech, "severity": sev,
                         "root_cause": root, "recommendation": fix,
                         "priority": sev_order[sev]})
        gaps.sort(key=lambda g: g["priority"])
        return {"tech": "差距分析", "gaps": gaps, "gap_count": len(gaps),
                "by_severity": {
                    s: sum(1 for g in gaps if g["severity"] == s)
                    for s in sev_order}}

    # ------------------------------------------------------------------ #
    def improvement_plan(self, gaps: Dict[str, Any]) -> Dict[str, Any]:
        g = gaps.get("gaps", [])
        plan: List[Dict[str, Any]] = []
        p0 = [x for x in g if x["severity"] == "high"]
        p1 = [x for x in g if x["severity"] == "medium"]
        for x in p0:
            plan.append({"priority": "P0", "action": x["recommendation"],
                         "gap": x["name"], "horizon": "0-7天紧急修复",
                         "owner": "安全运营/SOC"})
        for x in p1:
            plan.append({"priority": "P1", "action": x["recommendation"],
                         "gap": x["name"], "horizon": "1-4周流程固化",
                         "owner": "安全架构/蓝队"})
        plan.append({"priority": "P2", "action": "建设 UEBA 与威胁狩猎常态化机制",
                     "gap": "数据驱动狩猎", "horizon": "1-3月体系建设",
                     "owner": "SOC 狩猎团队"})
        plan.append({"priority": "P3", "action": "红蓝紫三方季度演练与培训",
                     "gap": "人员能力", "horizon": "持续运营",
                     "owner": "安全负责人"})
        return {"tech": "改进路线图", "plan": plan,
                "p0_count": len(p0), "p1_count": len(p1),
                "roadmap": {"urgent_7d": "P0", "process_4w": "P1",
                            "system_3m": "P2", "continuous": "P3"}}

    # ------------------------------------------------------------------ #
    def full_debrief(self, red_steps: List[Dict[str, Any]],
                     blue_alerts: Optional[List[Dict[str, Any]]] = None,
                     total_fp: int = 0) -> Dict[str, Any]:
        comparison = self.compare_steps(red_steps, blue_alerts)
        metrics = self.detection_metrics(comparison, total_fp)
        gaps = self.gap_analysis(comparison)
        plan = self.improvement_plan(gaps)
        return {"tech": "紫队复盘", "comparison": comparison,
                "metrics": metrics, "gaps": gaps,
                "improvement_plan": plan,
                "red_score": round(100 - metrics["quality_score"], 1),
                "blue_score": metrics["quality_score"],
                "coverage": metrics["coverage_pct"],
                "gap_count": gaps["gap_count"]}


_default: Optional[PurpleDebriefReal] = None


def get_purple_debrief_real() -> PurpleDebriefReal:
    global _default
    if _default is None:
        _default = PurpleDebriefReal()
    return _default
