# -*- coding: utf-8 -*-
"""
report_generator.py — 红蓝对抗 Pro 报告生成。

输出:
    - 专业红蓝对抗报告（Markdown / HTML）
    - 执行摘要
    - 红队攻击详情
    - 蓝队检测详情
    - 紫队复盘分析
    - 差距分析
    - 改进建议
    - 攻击链图（SVG 内嵌）
    - 风险评级
"""

from __future__ import annotations

import html
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
    red: Dict[str, Any] = field(default_factory=dict)
    blue: Dict[str, Any] = field(default_factory=dict)
    purple: Dict[str, Any] = field(default_factory=dict)
    analysis: Dict[str, Any] = field(default_factory=dict)


SEV_COLOR = {
    "critical": "#e74c3c", "high": "#e67e22",
    "medium": "#f1c40f", "low": "#4fc3f7", "info": "#95a5a6",
}


class ReportGenerator:
    """红蓝对抗报告生成器。"""

    def generate_markdown(self, data: ReportData) -> str:
        a = data.analysis or {}
        sc = a.get("severity_counts", {})
        p = data.purple or {}
        lines: List[str] = []
        lines.append("# 红蓝对抗演练报告")
        lines.append("")
        lines.append(f"- 任务编号: `{data.task_id}`")
        lines.append(f"- 目标: `{data.target}`")
        lines.append(f"- 开始: {data.started_at}")
        lines.append(f"- 结束: {data.finished_at}")
        lines.append(f"- 整体风险: **{a.get('overall_risk','?').upper()}**")
        lines.append("")
        lines.append("## 1. 执行摘要")
        lines.append("")
        lines.append(f"本次红蓝对抗：红队六阶段全部走完，"
                     f"蓝队检测覆盖率 **{p.get('coverage',0)}%**，"
                     f"未检测差距 **{p.get('gap_count',0)}** 项。")
        lines.append(f"严重 {sc.get('critical',0)} / 高 {sc.get('high',0)} / "
                     f"中 {sc.get('medium',0)}。")
        lines.append("")
        # 红队
        lines.append("## 2. 红队攻击详情")
        lines.append("")
        for stage in ("recon", "initial_access", "execution",
                      "privesc", "lateral", "objective"):
            r = (data.red or {}).get(stage, {}) or {}
            lines.append(f"### 2.{stage}")
            lines.append(f"- 模块: {r.get('module','-')}")
            lines.append(f"- 工具: {r.get('tool','-')}")
            if r.get("subdomain_count"):
                lines.append(f"- 子域名: {r['subdomain_count']}")
            if r.get("email_count"):
                lines.append(f"- 邮箱: {r['email_count']}")
            if r.get("finding_count"):
                lines.append(f"- 发现: {r['finding_count']}")
            lines.append("")
        # 蓝队
        lines.append("## 3. 蓝队检测详情")
        lines.append("")
        for stage in ("detection", "response", "attribution"):
            b = (data.blue or {}).get(stage, {}) or {}
            lines.append(f"### 3.{stage}")
            lines.append(f"- 告警数: {b.get('alert_count',0)}")
            lines.append(f"- IOC 命中: {b.get('ioc_hit_count',0)}")
            lines.append("")
        # 紫队
        lines.append("## 4. 紫队复盘")
        lines.append("")
        lines.append(f"- 红队得分: {p.get('red_score',0)}")
        lines.append(f"- 蓝队得分: {p.get('blue_score',0)}")
        lines.append(f"- 检测覆盖率: {p.get('coverage',0)}%")
        lines.append("")
        lines.append("### 差距分析")
        for g in p.get("gaps", []):
            lines.append(f"- **[{g.get('severity','').upper()}] "
                         f"{g.get('attack','')}** 未检测 → "
                         f"{g.get('recommendation','')}")
        lines.append("")
        lines.append("### 改进建议")
        for rec in p.get("recommendations", []):
            lines.append(f"- {rec}")
        lines.append("")
        lines.append("---")
        lines.append("*本报告由 AI Hacking Agent 红蓝对抗 Pro 自动生成*")
        return "\n".join(lines)

    def _chain_svg(self, chain: Dict[str, Any]) -> str:
        nodes = chain.get("nodes", [])
        edges = chain.get("edges", [])
        if not nodes:
            return "<p class='muted'>无攻击链数据</p>"
        parts = ["<svg width='100%' height='200' "
                 "xmlns='http://www.w3.org/2000/svg'>"]
        n = len(nodes)
        xs = [40 + i * max(150, int(900 / max(n, 1))) for i in range(n)]
        for i, node in enumerate(nodes):
            x = xs[i]
            color = "#e74c3c" if node.get("side") == "red" else "#4fc3f7"
            parts.append(
                f"<rect x='{x}' y='70' width='130' height='46' rx='8' "
                f"fill='#1f232c' stroke='{color}' stroke-width='2'/>")
            label = html.escape(node.get("label", ""))
            parts.append(
                f"<text x='{x+65}' y='98' fill='#e6e8ee' "
                f"font-size='12' text-anchor='middle'>{label}</text>")
        for e in edges:
            si = next((i for i, nd in enumerate(nodes)
                       if nd.get("id") == e.get("src")), 0)
            di = next((i for i, nd in enumerate(nodes)
                       if nd.get("id") == e.get("dst")), n - 1)
            x1, x2 = xs[si] + 130, xs[di]
            parts.append(
                f"<line x1='{x1}' y1='93' x2='{x2}' y2='93' "
                f"stroke='#8a90a0' stroke-width='2' "
                f"marker-end='url(#arr)'/>")
        parts.append(
            "<defs><marker id='arr' markerWidth='10' markerHeight='10' "
            "refX='8' refY='3' orient='auto'><path d='M0,0 L0,6 L9,3 z' "
            "fill='#8a90a0'/></marker></defs>")
        parts.append("</svg>")
        return "".join(parts)

    def generate_html(self, data: ReportData) -> str:
        md = self.generate_markdown(data)
        a = data.analysis or {}
        sc = a.get("severity_counts", {})
        p = data.purple or {}
        chain_svg = self._chain_svg(a.get("attack_chain", {}))
        gap_rows = "".join(
            f"<tr><td><span class='sev {g.get('severity','info')}'>"
            f"{g.get('severity','').upper()}</span></td>"
            f"<td>{html.escape(g.get('attack',''))}</td>"
            f"<td>{'是' if g.get('detected') else '否'}</td>"
            f"<td>{html.escape(g.get('recommendation',''))}</td></tr>"
            for g in p.get("gaps", []))
        return f"""<!doctype html><html lang="zh-CN"><head><meta charset="utf-8">
<title>红蓝对抗报告 {html.escape(data.task_id)}</title>
<style>
body{{font-family:"Microsoft YaHei",sans-serif;background:#0f1115;color:#e6e8ee;
  margin:0;padding:24px;line-height:1.6}}
h1{{color:#e74c3c}} h2{{border-bottom:1px solid #2a2f3a;padding-bottom:6px}}
table{{width:100%;border-collapse:collapse;margin:12px 0;font-size:13px}}
th,td{{padding:8px;border:1px solid #2a2f3a;text-align:left}}
th{{background:#1f232c;color:#8a90a0}}
.sev{{padding:2px 8px;border-radius:4px;font-weight:bold;color:#000;font-size:11px}}
.sev.critical{{background:#e74c3c}} .sev.high{{background:#e67e22}}
.sev.medium{{background:#f1c40f}} .sev.low{{background:#4fc3f7}}
.sev.info{{background:#95a5a6;color:#fff}}
.kpi{{display:inline-block;margin:8px 16px 8px 0;padding:10px 18px;background:#171a21;
  border:1px solid #2a2f3a;border-radius:8px}}
.kpi b{{font-size:22px;display:block}}
pre{{background:#0a0c10;padding:12px;border-radius:6px;overflow:auto}}
</style></head><body>
<h1>红蓝对抗演练报告</h1>
<p>任务 {html.escape(data.task_id)} · 目标 {html.escape(data.target)}<br>
开始 {html.escape(data.started_at)} · 结束 {html.escape(data.finished_at)}</p>
<div>
<span class="kpi"><b style="color:{SEV_COLOR.get(a.get('overall_risk','info'))}">{html.escape((a.get('overall_risk','?') or '?').upper())}</b>整体风险</span>
<span class="kpi"><b>{sc.get('critical',0)}</b>严重</span>
<span class="kpi"><b style="color:#e67e22">{sc.get('high',0)}</b>高危</span>
<span class="kpi"><b style="color:#f1c40f">{sc.get('medium',0)}</b>中危</span>
<span class="kpi"><b style="color:#e74c3c">{p.get('red_score',0)}</b>红队分</span>
<span class="kpi"><b style="color:#4fc3f7">{p.get('blue_score',0)}</b>蓝队分</span>
<span class="kpi"><b>{p.get('coverage',0)}%</b>检测覆盖</span>
</div>
<h2>攻击链图</h2>{chain_svg}
<h2>差距分析</h2>
<table><tr><th>等级</th><th>攻击动作</th><th>是否检测</th><th>改进建议</th></tr>
{gap_rows or '<tr><td colspan=4 class=muted>无差距</td></tr>'}</table>
<h2>完整报告 (Markdown)</h2>
<pre>{html.escape(md)}</pre>
</body></html>"""

    def save(self, data: ReportData, out_dir: str,
             fmt: str = "html") -> str:
        os.makedirs(out_dir, exist_ok=True)
        ts = time.strftime("%Y%m%d_%H%M%S")
        if fmt == "md":
            path = os.path.join(out_dir, f"rb_report_{ts}.md")
            with open(path, "w", encoding="utf-8") as f:
                f.write(self.generate_markdown(data))
        else:
            path = os.path.join(out_dir, f"rb_report_{ts}.html")
            with open(path, "w", encoding="utf-8") as f:
                f.write(self.generate_html(data))
        return path


_default_report: Optional[ReportGenerator] = None


def get_report_generator() -> ReportGenerator:
    global _default_report
    if _default_report is None:
        _default_report = ReportGenerator()
    return _default_report
