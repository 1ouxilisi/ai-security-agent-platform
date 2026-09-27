# -*- coding: utf-8 -*-
"""
real_report_generator.py — 方向4：真实红蓝对抗报告生成。

输出 Markdown / HTML，落盘到 reports/red_blue_real/。
内容：执行摘要 / 红队攻击链 / 蓝队检测 / 紫队复盘 / 差距分析 / 改进建议 /
攻击覆盖图 / 检测覆盖图。全部基于真实运行结果，不用 demo 数据。
"""

from __future__ import annotations

import html
import os
import time
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional

REPORTS_DIR = os.path.join(
    os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
    "reports", "red_blue_real")


@dataclass
class RealReportData:
    task_id: str = ""
    target: str = ""
    started_at: str = ""
    finished_at: str = ""
    red: Dict[str, Any] = field(default_factory=dict)
    blue: Dict[str, Any] = field(default_factory=dict)
    purple: Dict[str, Any] = field(default_factory=dict)
    tools: Dict[str, Any] = field(default_factory=dict)
    navigator: Dict[str, Any] = field(default_factory=dict)


class RealReportGenerator:

    def generate_markdown(self, data: RealReportData) -> str:
        p = data.purple or {}
        lines: List[str] = []
        lines.append("# 真实红蓝对抗演练报告（方向4 · 真实化）")
        lines.append("")
        lines.append(f"- 任务编号: `{data.task_id}`")
        lines.append(f"- 目标: `{data.target}`")
        lines.append(f"- 开始: {data.started_at}")
        lines.append(f"- 结束: {data.finished_at}")
        lines.append("")
        lines.append("## 1. 执行摘要")
        lines.append("")
        lines.append(f"红队得分 **{p.get('red_score', 0)}**，"
                     f"蓝队得分 **{p.get('blue_score', 0)}**，"
                     f"检测覆盖率 **{p.get('coverage', 0)}%**，"
                     f"未检测差距 **{p.get('gap_count', 0)}** 项。")
        lines.append("")
        lines.append("## 2. 红队真实攻击链")
        lines.append("")
        for tactic in ("initial_access", "execution", "persistence",
                       "privilege_escalation", "defense_evasion",
                       "credential_access", "lateral_movement",
                       "exfiltration"):
            r = (data.red or {}).get(tactic, {}) or {}
            lines.append(f"### 2.{tactic}")
            if isinstance(r, dict):
                for k, v in list(r.items())[:6]:
                    lines.append(f"- {k}: {str(v)[:120]}")
            if not r:
                lines.append("- （本战术未产生真实结果，工具未安装/未执行）")
        lines.append("")
        lines.append("## 3. 蓝队真实检测")
        lines.append("")
        metrics = (p.get("metrics") or {})
        lines.append(f"- 告警数 / 覆盖率 / 误报率 / 漏报率")
        lines.append(f"  - 覆盖率: {metrics.get('coverage_pct', '-')}%")
        lines.append(f"  - 平均检测延迟: {metrics.get('avg_delay_seconds', '-')}s")
        lines.append(f"  - 误报率: {metrics.get('false_positive_rate_pct', '-')}%")
        lines.append(f"  - 漏报率: {metrics.get('false_negative_rate_pct', '-')}%")
        lines.append("")
        lines.append("## 4. 紫队差距分析")
        lines.append("")
        gaps = (p.get("gaps") or {}).get("gaps", [])
        for g in gaps:
            lines.append(f"- [{g.get('severity')}] {g.get('tech')} "
                         f"{g.get('name')}: {g.get('recommendation')}")
        if not gaps:
            lines.append("- 无差距（所有红队动作均被检测）")
        lines.append("")
        lines.append("## 5. 改进路线图")
        lines.append("")
        plan = (p.get("improvement_plan") or {}).get("plan", [])
        for it in plan:
            lines.append(f"- [{it.get('priority')}] ({it.get('horizon')}) "
                         f"{it.get('action')} — {it.get('owner')}")
        lines.append("")
        lines.append("## 6. 工具真实检测")
        lines.append("")
        for grp, info in (data.tools or {}).items():
            lines.append(f"### {grp}")
            lines.append("```json")
            lines.append(str(info)[:600])
            lines.append("```")
        lines.append("")
        return "\n".join(lines)

    def generate_html(self, data: RealReportData) -> str:
        md = self.generate_markdown(data)
        body = html.escape(md).replace("\n", "<br>")
        return ("<!doctype html><html lang=zh-CN><head><meta charset=utf-8>"
                "<title>真实红蓝对抗报告</title>"
                "<style>body{font-family:Microsoft YaHei;background:#0f1115;"
                "color:#e6e8ee;max-width:960px;margin:40px auto;padding:24px;"
                "line-height:1.7}h1{color:#e74c3c}code{color:#f1c40f}</style>"
                f"</head><body><pre style='white-space:pre-wrap'>{body}</pre>"
                "</body></html>")

    def save(self, data: RealReportData,
             fmt: str = "html") -> str:
        os.makedirs(REPORTS_DIR, exist_ok=True)
        ts = time.strftime("%Y%m%d_%H%M%S")
        if fmt == "md":
            p = os.path.join(REPORTS_DIR, f"report_{data.task_id}_{ts}.md")
            with open(p, "w", encoding="utf-8") as f:
                f.write(self.generate_markdown(data))
        else:
            p = os.path.join(REPORTS_DIR, f"report_{data.task_id}_{ts}.html")
            with open(p, "w", encoding="utf-8") as f:
                f.write(self.generate_html(data))
        return p


_default: Optional[RealReportGenerator] = None


def get_real_report_generator() -> RealReportGenerator:
    global _default
    if _default is None:
        _default = RealReportGenerator()
    return _default
