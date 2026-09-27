# -*- coding: utf-8 -*-
"""
report_generator.py — 报告生成引擎。

聚合模板 + 图表，输出完整专业报告。
"""

from __future__ import annotations

import time
import uuid
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional

from .report_templates import ReportTemplates, cvss_severity, VULN_DB
from .report_charts import ReportCharts, SEVERITY_LABELS


@dataclass
class ReportData:
    """一次报告的完整输入。"""
    report_id: str = ""
    title: str = "安全评估报告"
    target: str = ""
    consultant: str = "AI Report Pro"
    scope: str = "授权范围内的安全评估"
    started_at: str = ""
    finished_at: str = ""
    assets: List[Dict[str, Any]] = field(default_factory=list)
    findings: List[Dict[str, Any]] = field(default_factory=list)
    metadata: Dict[str, Any] = field(default_factory=dict)

    def __post_init__(self) -> None:
        if not self.report_id:
            self.report_id = "RPT-" + uuid.uuid4().hex[:8].upper()
        if not self.started_at:
            self.started_at = time.strftime("%Y-%m-%d %H:%M:%S")

    def severity_summary(self) -> Dict[str, int]:
        s: Dict[str, int] = {}
        for f in self.findings:
            sev = (f.get("severity") or "info").lower()
            s[sev] = s.get(sev, 0) + 1
        return s

    def overall_risk(self) -> str:
        s = self.severity_summary()
        if s.get("critical", 0) > 0:
            return "critical"
        if s.get("high", 0) > 0:
            return "high"
        if s.get("medium", 0) > 0:
            return "medium"
        if s.get("low", 0) > 0:
            return "low"
        return "info"


class ReportGenerator:
    """报告生成引擎。"""

    def __init__(self) -> None:
        self.tpl = ReportTemplates()
        self.charts = ReportCharts()

    # ------------------------------------------------------------------ #
    # 主入口：生成完整 HTML 报告
    # ------------------------------------------------------------------ #
    def generate_html(self, data: ReportData) -> str:
        sev = data.severity_summary()
        overall = data.overall_risk()
        # 排序：按严重程度
        order = {"critical": 0, "high": 1, "medium": 2,
                 "low": 3, "info": 4}
        findings = sorted(
            data.findings,
            key=lambda x: order.get((x.get("severity") or "info").lower(),
                                    99))

        # 漏洞详情
        vuln_html = "\n".join(
            self.tpl.render_vuln_detail(i + 1, v)
            for i, v in enumerate(findings))

        # 图表 JSON
        charts = self.charts.all_charts(
            findings, assets=data.assets)

        # 资产热力图 HTML
        heat_html = self.tpl.render_heatmap(data.assets)

        # 执行摘要
        summary = self.tpl.render_exec_summary(
            target=data.target, overall=overall, sev=sev,
            top_vulns=findings,
            report_id=data.report_id,
            date_str=data.finished_at or
                     time.strftime("%Y-%m-%d"))

        body = f"""
{summary}

<h2>2. 目标与范围</h2>
<div class="card"><div class="kv">
  <div class="k">目标</div><div>{data.target}</div>
  <div class="k">测试范围</div><div>{data.scope}</div>
  <div class="k">测试工程师</div><div>{data.consultant}</div>
  <div class="k">开始时间</div><div>{data.started_at}</div>
  <div class="k">结束时间</div><div>{data.finished_at or '-'}</div>
</div></div>

<h2>3. 风险概览</h2>
<div class="grid" style="display:grid;grid-template-columns:1fr 1fr;gap:12px">
  <div class="card"><h3>风险分布</h3><canvas id="pie" class="chart-box"></canvas></div>
  <div class="card"><h3>严重程度</h3><canvas id="barSev" class="chart-box"></canvas></div>
</div>
<div class="card"><h3>漏洞分类 Top10</h3>
  <canvas id="barCat" class="chart-box"></canvas></div>

<h2>4. 资产风险热力图</h2>
<div class="card">{heat_html}</div>

<h2>5. 漏洞详情（共 {len(findings)} 个）</h2>
{vuln_html or '<div class="card meta">未发现漏洞。</div>'}

<h2>6. 整改建议优先级</h2>
<div class="card"><ol>
"""
        for v in findings[:20]:
            sev_l = (v.get('severity') or 'info').lower()
            body += (f"<li><span class='badge b-{sev_l}'>"
                     f"{SEVERITY_LABELS.get(sev_l, sev_l).upper()}</span> "
                     f"<b>{v.get('name','')}</b> — "
                     f"{v.get('fix') or v.get('solution') or '请人工复核'}"
                     f"</li>")
        body += """</ol></div>

<div class="meta" style="margin-top:30px;text-align:center">
本报告由 AI Report Pro 自动生成 · 仅供授权评估使用
</div>

<script>
const CHARTS = """ + __import__("json").dumps(charts, ensure_ascii=False) + """;
new Chart(document.getElementById('pie'), CHARTS.pie);
new Chart(document.getElementById('barSev'), CHARTS.bar_severity);
new Chart(document.getElementById('barCat'), CHARTS.bar_category);
</script>
"""
        return self.tpl.render_skeleton(data.title, body)

    # ------------------------------------------------------------------ #
    # Markdown
    # ------------------------------------------------------------------ #
    def generate_markdown(self, data: ReportData) -> str:
        sev = data.severity_summary()
        lines = [
            f"# {data.title}",
            "",
            f"- 报告编号: {data.report_id}",
            f"- 目标: {data.target}",
            f"- 时间: {data.started_at} ~ {data.finished_at}",
            f"- 整体风险: **{data.overall_risk().upper()}**",
            "",
            "## 风险概览",
            "",
            "| 严重 | 高危 | 中危 | 低危 | 信息 |",
            "| ---- | ---- | ---- | ---- | ---- |",
            f"| {sev.get('critical',0)} | {sev.get('high',0)} | "
            f"{sev.get('medium',0)} | {sev.get('low',0)} | "
            f"{sev.get('info',0)} |",
            "",
            "## 漏洞详情",
            "",
        ]
        for i, v in enumerate(data.findings, 1):
            lines.append(f"### {i}. [{(v.get('severity') or 'info').upper()}] "
                         f"{v.get('name','')}")
            lines.append(f"- CVSS: {v.get('cvss_score', '-')} "
                         f"({v.get('cvss_vector', '')})")
            if v.get("cve"):
                lines.append(f"- CVE: {v.get('cve')}")
            if v.get("cwe"):
                lines.append(f"- CWE: {v.get('cwe')}")
            if v.get("url"):
                lines.append(f"- 位置: {v.get('url')}")
            if v.get("impact"):
                lines.append(f"- 影响: {v.get('impact')}")
            if v.get("repro"):
                lines.append(f"- 复现: {v.get('repro')}")
            if v.get("fix"):
                lines.append(f"- 修复: {v.get('fix')}")
            lines.append("")
        return "\n".join(lines)

    # ------------------------------------------------------------------ #
    # JSON
    # ------------------------------------------------------------------ #
    def generate_json(self, data: ReportData) -> str:
        import json
        payload = {
            "report_id": data.report_id,
            "title": data.title,
            "target": data.target,
            "overall_risk": data.overall_risk(),
            "severity_summary": data.severity_summary(),
            "findings": data.findings,
            "assets": data.assets,
            "charts": self.charts.all_charts(
                data.findings, assets=data.assets),
            "generated_at": time.strftime("%Y-%m-%d %H:%M:%S"),
        }
        return json.dumps(payload, ensure_ascii=False, indent=2,
                          default=str)


_default_gen: Optional[ReportGenerator] = None


def get_generator() -> ReportGenerator:
    global _default_gen
    if _default_gen is None:
        _default_gen = ReportGenerator()
    return _default_gen
