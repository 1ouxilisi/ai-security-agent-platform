# -*- coding: utf-8 -*-
"""
report_generator.py — 方向2 威胁情报 Pro：报告生成。

输出 Markdown / HTML 双格式专业威胁情报报告:
    执行摘要 / IOC 统计 / Actor 分析 / 攻击面评估 / 暗网监控 /
    威胁预警 / 趋势预测 / 改进建议 / 图表可视化。
"""

from __future__ import annotations

import os
import time
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional


@dataclass
class ReportData:
    task_id: str = ""
    target: str = ""
    started_at: str = ""
    finished_at: str = ""
    ioc_stats: Dict[str, Any] = field(default_factory=dict)
    match_stats: Dict[str, Any] = field(default_factory=dict)
    actor_stats: Dict[str, Any] = field(default_factory=dict)
    surface: Dict[str, Any] = field(default_factory=dict)
    darkweb: Dict[str, Any] = field(default_factory=dict)
    warnings: List[Dict[str, Any]] = field(default_factory=list)
    trend: Dict[str, Any] = field(default_factory=dict)
    ai_conclusion: Dict[str, Any] = field(default_factory=dict)
    iocs: List[Dict[str, Any]] = field(default_factory=list)


class ThreatIntelReportGenerator:
    """报告生成器。"""

    REPORTS_DIR = os.path.join(
        os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
        "reports", "threat_intel_pro")

    # ------------------------------------------------------------------ #
    def generate_markdown(self, d: ReportData) -> str:
        now = d.finished_at or time.strftime("%Y-%m-%d %H:%M:%S")
        im = d.ioc_stats or {}
        mm = d.match_stats or {}
        am = d.actor_stats or {}
        sm = d.surface or {}
        dm = d.darkweb or {}
        risk = d.ai_conclusion.get("overall_risk", "未知")
        lines: List[str] = []
        lines.append(f"# 威胁情报分析报告\n")
        lines.append(f"- 任务编号: `{d.task_id}`")
        lines.append(f"- 目标范围: `{d.target or '全组织'}`")
        lines.append(f"- 生成时间: {now}\n")
        lines.append("## 1. 执行摘要\n")
        lines.append(f"- **整体风险等级**: {risk}")
        lines.append(f"- IOC 总数: **{im.get('total',0)}**")
        lines.append(f"- 未处置告警: **{mm.get('open_alerts',0)}**")
        lines.append(f"- 关注 Actor: **{am.get('total',0)}** 个")
        lines.append(f"- 攻击面平均分: **{sm.get('avg_score',0)}/100**")
        lines.append(f"- 暗网关键告警: **{dm.get('alerts',0)}** 条\n")
        lines.append("## 2. IOC 统计\n")
        by_type = im.get("by_type", {})
        lines.append("| 类型 | 数量 |")
        lines.append("|---|---|")
        for k, v in sorted(by_type.items(), key=lambda x: -x[1]):
            lines.append(f"| {k} | {v} |")
        lines.append("")
        by_conf = im.get("by_confidence", {})
        lines.append("置信度分布: " +
                     " / ".join(f"{k}={v}" for k, v in by_conf.items()) + "\n")
        lines.append("## 3. 威胁 Actor 分析\n")
        lines.append(f"- 画像库共 {am.get('total',0)} 个组织")
        bc = am.get("by_country", {})
        lines.append("- 按国家/地区分布: " +
                     ", ".join(f"{k}:{v}" for k, v in
                               sorted(bc.items(), key=lambda x: -x[1])[:8]))
        lines.append("")
        lines.append("## 4. 攻击面评估\n")
        lines.append(f"- 暴露资产: {sm.get('total_assets',0)}")
        lines.append(f"- 高风险资产: {sm.get('high_risk_assets',0)}")
        lines.append(f"- 平均分: {sm.get('avg_score',0)}")
        lines.append("")
        lines.append("## 5. 暗网监控发现\n")
        lines.append(f"- 命中条目: {dm.get('total_hits',0)}")
        lines.append(f"- 关键告警: {dm.get('alerts',0)}")
        lines.append("")
        lines.append("## 6. 威胁预警\n")
        if d.warnings:
            for w in d.warnings:
                lines.append(f"- **[{w.get('severity','').upper()}] "
                             f"{w.get('title','')}**")
                lines.append(f"  - {w.get('summary','')}")
                for a in w.get("recommended_action", []):
                    lines.append(f"    - {a}")
        else:
            lines.append("- 当前无活跃预警。")
        lines.append("")
        lines.append("## 7. 攻击趋势预测\n")
        tr = d.trend or {}
        lines.append(f"- 趋势: **{tr.get('trend','-')}**")
        if tr.get("forecast_7d"):
            lines.append(f"- 7 日预测: {tr['forecast_7d']}")
        lines.append("")
        lines.append("## 8. 改进建议\n")
        for r in (d.ai_conclusion.get("recommendations") or
                  ["定期复盘 IOC 命中率", "完善暗网监控"]):
            lines.append(f"- {r}")
        lines.append("")
        lines.append("## 9. Top IOC 明细\n")
        lines.append("| 值 | 类型 | 恶意软件 | 置信度 |")
        lines.append("|---|---|---|---|")
        for ioc in d.iocs[:15]:
            lines.append(f"| {ioc.get('value','')} | "
                         f"{ioc.get('type','')} | "
                         f"{ioc.get('malware','')} | "
                         f"{ioc.get('confidence',0)} |")
        return "\n".join(lines)

    # ------------------------------------------------------------------ #
    def generate_html(self, d: ReportData) -> str:
        md = self.generate_markdown(d)
        # 极简 markdown -> html (仅支持标题/列表/表格/粗体)
        body = self._md_to_html(md)
        return f"""<!doctype html>
<html lang="zh-CN"><head><meta charset="utf-8">
<title>威胁情报报告 {d.task_id}</title>
<style>
body{{font-family:"Microsoft YaHei",sans-serif;background:#0f1115;color:#e6e8ee;
max-width:960px;margin:0 auto;padding:32px;line-height:1.7}}
h1,h2{{color:#4fc3f7}} table{{border-collapse:collapse;width:100%;margin:12px 0}}
th,td{{border:1px solid #2a2f3a;padding:6px 10px;text-align:left;font-size:14px}}
th{{background:#1f232c}} code{{background:#1f232c;padding:2px 6px;border-radius:4px}}
</style></head><body>{body}</body></html>"""

    @staticmethod
    def _md_to_html(md: str) -> str:
        out: List[str] = []
        in_table = False
        for line in md.splitlines():
            if line.startswith("# "):
                out.append(f"<h1>{line[2:]}</h1>")
            elif line.startswith("## "):
                out.append(f"<h2>{line[3:]}</h2>")
            elif line.startswith("|"):
                cells = [c.strip() for c in line.strip("|").split("|")]
                if all(set(c) <= set("-: ") for c in cells):
                    continue
                tag = "th" if not in_table else "td"
                out.append("<tr>" + "".join(
                    f"<{tag}>{c}</{tag}>" for c in cells) + "</tr>")
                if not in_table:
                    out.insert(len(out) - 1, "<table>")
                    in_table = True
            else:
                if in_table:
                    out.append("</table>")
                    in_table = False
                if line.startswith("- "):
                    out.append(f"<li>{line[2:]}</li>")
                elif line.strip():
                    out.append(f"<p>{line}</p>")
        if in_table:
            out.append("</table>")
        html = "\n".join(out)
        html = html.replace("**", "<b>", 1)  # 简化处理
        return html

    # ------------------------------------------------------------------ #
    def save(self, d: ReportData, fmt: str = "html") -> str:
        os.makedirs(self.REPORTS_DIR, exist_ok=True)
        ts = time.strftime("%Y%m%d_%H%M%S")
        if fmt == "md":
            path = os.path.join(self.REPORTS_DIR,
                                f"threat_intel_{d.task_id}_{ts}.md")
            with open(path, "w", encoding="utf-8") as f:
                f.write(self.generate_markdown(d))
        else:
            path = os.path.join(self.REPORTS_DIR,
                                f"threat_intel_{d.task_id}_{ts}.html")
            with open(path, "w", encoding="utf-8") as f:
                f.write(self.generate_html(d))
        return path


_gen: Optional[ThreatIntelReportGenerator] = None


def get_report_generator() -> ThreatIntelReportGenerator:
    global _gen
    if _gen is None:
        _gen = ThreatIntelReportGenerator()
    return _gen
