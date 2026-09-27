# -*- coding: utf-8 -*-
"""
report_generator.py — 方向2 供应链安全 Pro：报告生成。

功能:
    - 专业供应链安全报告（MD / HTML）
    - 执行摘要 / SBOM 清单 / 漏洞详情 / 许可证合规 /
      依赖分析 / 风险评级 / 整改建议
    - 组件风险矩阵图 / 依赖树图（SVG 内嵌）
"""

from __future__ import annotations

import html
import os
import time
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional


SEV_COLOR = {
    "critical": "#e74c3c", "high": "#e67e22",
    "medium": "#f1c40f", "low": "#3498db", "info": "#95a5a6",
}
SEV_LABEL = {
    "critical": "严重", "high": "高危",
    "medium": "中危", "low": "低危", "info": "信息",
}


@dataclass
class ReportData:
    task_id: str = ""
    target: str = ""
    started_at: str = ""
    finished_at: str = ""
    sbom: Dict[str, Any] = field(default_factory=dict)
    component_analysis: Dict[str, Any] = field(default_factory=dict)
    license_report: Dict[str, Any] = field(default_factory=dict)
    dep_report: Dict[str, Any] = field(default_factory=dict)
    risk_report: Dict[str, Any] = field(default_factory=dict)
    remediation: Dict[str, Any] = field(default_factory=dict)
    ai: Dict[str, Any] = field(default_factory=dict)


class ReportGenerator:
    """供应链安全报告生成器。"""

    def __init__(self) -> None:
        self.company = "AI Hacking Agent · Supply Chain Pro"

    # ------------------------------------------------------------------ #
    def _sev_counts(self, vulns: List[Dict[str, Any]]) -> Dict[str, int]:
        out = {"critical": 0, "high": 0, "medium": 0, "low": 0}
        for v in vulns:
            s = v.get("severity", "low")
            out[s] = out.get(s, 0) + 1
        return out

    # ------------------------------------------------------------------ #
    def generate_markdown(self, d: ReportData) -> str:
        vulns = d.component_analysis.get("vulns", []) or []
        counts = self._sev_counts(vulns)
        risk = d.risk_report.get("overall_band", "medium")
        L: List[str] = []
        L.append(f"# 供应链安全评估报告")
        L.append("")
        L.append(f"- **目标**: {d.target}")
        L.append(f"- **任务 ID**: {d.task_id}")
        L.append(f"- **开始**: {d.started_at}")
        L.append(f"- **结束**: {d.finished_at}")
        L.append(f"- **整体风险**: {SEV_LABEL.get(risk, risk)} "
                 f"({d.risk_report.get('overall_score', 0)}/100)")
        L.append(f"- **生成方**: {self.company}")
        L.append("")
        L.append("---")
        L.append("")
        # 1. 执行摘要
        L.append("## 1. 执行摘要")
        L.append("")
        L.append(d.ai.get("summary", "") or
                 f"本次扫描发现 {len(vulns)} 个漏洞。")
        L.append("")
        L.append(f"- 组件总数: **{d.sbom.get('component_count', 0)}**")
        L.append(f"- 严重: {counts['critical']} / "
                 f"高危: {counts['high']} / "
                 f"中危: {counts['medium']} / "
                 f"低危: {counts['low']}")
        L.append(f"- 许可证问题: "
                 f"{len(d.license_report.get('issues', []))} 项")
        L.append(f"- 依赖冲突: "
                 f"{len(d.dep_report.get('conflicts', []))} 项")
        L.append("")
        # 2. SBOM
        L.append("## 2. SBOM 组件清单")
        L.append("")
        L.append(f"- 生成工具: {d.sbom.get('tool', 'builtin')} "
                 f"(兜底={d.sbom.get('fallback', False)})")
        L.append(f"- 格式: {d.sbom.get('format', 'cyclonedx')}")
        L.append(f"- 语言分布: {d.sbom.get('by_language', {})}")
        L.append("")
        L.append("| 组件 | 版本 | 语言 | 许可证 |")
        L.append("|------|------|------|--------|")
        for c in (d.sbom.get("components", []) or [])[:50]:
            L.append(f"| {c.get('name','')} | {c.get('version','')} "
                     f"| {c.get('language','')} "
                     f"| {c.get('license','')} |")
        L.append("")
        # 3. 漏洞详情
        L.append("## 3. 漏洞详情")
        L.append("")
        if not vulns:
            L.append("未发现已知漏洞。")
        for v in vulns[:50]:
            L.append(f"### {v.get('cve_id','')} · "
                     f"{SEV_LABEL.get(v.get('severity',''), v.get('severity',''))}")
            L.append(f"- 组件: {v.get('component','')} "
                     f"{v.get('version','')}")
            L.append(f"- CVSS: {v.get('cvss', 0)}  "
                     f"利用可能性: {v.get('exploitability','')}")
            L.append(f"- 修复版本: {v.get('fixed','')}")
            L.append(f"- 建议: {v.get('remediation','')}")
            L.append("")
        # 4. 许可证
        L.append("## 4. 许可证合规")
        L.append("")
        L.append(f"- 项目许可证: "
                 f"{d.license_report.get('project_license','')}")
        L.append(f"- 按许可证分布: "
                 f"{d.license_report.get('by_license', {})}")
        L.append("")
        for issue in (d.license_report.get("issues", []) or [])[:30]:
            L.append(f"- **[{issue.get('risk','')}]** "
                     f"{issue.get('component','')}: "
                     f"{issue.get('message','')} → "
                     f"{issue.get('suggestion','')}")
        L.append("")
        # 5. 依赖分析
        L.append("## 5. 依赖分析")
        L.append("")
        dr = d.dep_report or {}
        L.append(f"- 总依赖: {dr.get('total',0)}，"
                 f"直接 {dr.get('direct_count',0)}，"
                 f"传递 {dr.get('transitive_count',0)}")
        L.append(f"- 最大深度: {dr.get('max_depth',0)}")
        for c in dr.get("conflicts", []):
            L.append(f"- 冲突: {c.get('message','')}")
        L.append("")
        # 6. 风险评级
        L.append("## 6. 风险评级")
        L.append("")
        L.append(f"- 整体得分: "
                 f"{d.risk_report.get('overall_score',0)}/100 "
                 f"({SEV_LABEL.get(risk, risk)})")
        L.append("")
        L.append("| 组件 | 得分 | 等级 | 漏洞数 |")
        L.append("|------|------|------|--------|")
        for c in (d.risk_report.get("top_components", []) or [])[:20]:
            L.append(f"| {c.get('name','')} "
                     f"{c.get('version','')} "
                     f"| {c.get('total',0)} "
                     f"| {SEV_LABEL.get(c.get('band',''), c.get('band',''))} "
                     f"| {c.get('vuln_count',0)} |")
        L.append("")
        # 7. 整改建议
        L.append("## 7. 整改建议")
        L.append("")
        summary = d.remediation.get("summary", {})
        L.append(f"P0={summary.get('P0',0)}, "
                 f"P1={summary.get('P1',0)}, "
                 f"P2={summary.get('P2',0)}, "
                 f"P3={summary.get('P3',0)}")
        L.append("")
        for it in (d.remediation.get("items", []) or [])[:30]:
            L.append(f"- **[{it.get('priority','')}]** "
                     f"{it.get('action','')} — {it.get('reason','')}")
        L.append("")
        # 8. 攻击路径
        L.append("## 8. AI 攻击路径分析")
        L.append("")
        for p in (d.ai.get("attack_paths", []) or []):
            L.append(f"### {p.get('name','')}")
            for s in p.get("steps", []):
                L.append(f"  1. {s}")
            L.append("")
        return "\n".join(L)

    # ------------------------------------------------------------------ #
    def _svg_matrix(self, risk_report: Dict[str, Any]) -> str:
        rows = risk_report.get("matrix", []) or []
        bars = []
        max_w = 300
        max_count = max([r.get("count", 0) for r in rows] or [1])
        for r in rows:
            c = SEV_COLOR.get(r.get("severity", "info"), "#95a5a6")
            w = int(max_w * (r.get("count", 0) / max(1, max_count)))
            bars.append(
                f'<g><text x="0" y="{len(bars)*22+15}" '
                f'fill="#8a90a0" font-size="12">'
                f'{SEV_LABEL.get(r.get("severity",""),r.get("severity",""))}'
                f'</text>'
                f'<rect x="90" y="{len(bars)*22+5}" width="{w}" '
                f'height="14" fill="{c}"/>'
                f'<text x="{100+w}" y="{len(bars)*22+16}" fill="#e6e8ee" '
                f'font-size="12">{r.get("count",0)}</text></g>')
        return (f'<svg width="420" height="{len(rows)*22+20}" '
                f'xmlns="http://www.w3.org/2000/svg">'
                + "".join(bars) + "</svg>")

    # ------------------------------------------------------------------ #
    def generate_html(self, d: ReportData) -> str:
        vulns = d.component_analysis.get("vulns", []) or []
        counts = self._sev_counts(vulns)
        risk = d.risk_report.get("overall_band", "medium")
        color = SEV_COLOR.get(risk, "#95a5a6")
        md = self.generate_markdown(d)
        return f"""<!doctype html>
<html lang="zh-CN"><head><meta charset="utf-8">
<title>供应链安全报告 · {html.escape(d.target)}</title>
<style>
body{{font-family:"Segoe UI","Microsoft YaHei",sans-serif;
  background:#0f1115;color:#e6e8ee;max-width:1100px;margin:0 auto;
  padding:24px;line-height:1.6}}
h1{{color:#4fc3f7;border-bottom:2px solid #4fc3f7;padding-bottom:8px}}
h2{{color:#4fc3f7;margin-top:32px}}
table{{width:100%;border-collapse:collapse;margin:12px 0}}
th,td{{border:1px solid #2a2f3a;padding:6px 10px;font-size:13px;
  text-align:left}}
th{{background:#1f232c}}
.badge{{display:inline-block;padding:2px 10px;border-radius:999px;
  color:#000;font-weight:bold;background:{color}}}
pre{{background:#0a0c10;padding:12px;border-radius:6px;
  overflow-x:auto;font-size:12px}}
.kv{{display:grid;grid-template-columns:160px 1fr;gap:4px 12px}}
.kv dt{{color:#8a90a0}}.kv dd{{margin:0}}
</style></head><body>
<h1>🛡️ 供应链安全评估报告</h1>
<dl class="kv">
<dt>目标</dt><dd>{html.escape(d.target)}</dd>
<dt>任务 ID</dt><dd>{html.escape(d.task_id)}</dd>
<dt>开始/结束</dt><dd>{html.escape(d.started_at)} → {html.escape(d.finished_at)}</dd>
<dt>整体风险</dt><dd><span class="badge">{SEV_LABEL.get(risk,risk)} {d.risk_report.get('overall_score',0)}/100</span></dd>
</dl>
<h2>风险矩阵</h2>
{self._svg_matrix(d.risk_report)}
<h2>完整 Markdown 报告</h2>
<pre>{html.escape(md)}</pre>
<footer style="margin-top:40px;color:#8a90a0;font-size:12px">
{html.escape(self.company)} · 自动生成于 {time.strftime("%Y-%m-%d %H:%M:%S")}
</footer></body></html>"""

    # ------------------------------------------------------------------ #
    def save(self, d: ReportData, out_dir: str, fmt: str = "html"
             ) -> str:
        os.makedirs(out_dir, exist_ok=True)
        if fmt == "md":
            path = os.path.join(out_dir,
                                f"sbom_{d.task_id}.md")
            with open(path, "w", encoding="utf-8") as f:
                f.write(self.generate_markdown(d))
        else:
            path = os.path.join(out_dir,
                                f"sbom_{d.task_id}.html")
            with open(path, "w", encoding="utf-8") as f:
                f.write(self.generate_html(d))
        return path


_default_rg: Optional[ReportGenerator] = None


def get_report_generator() -> ReportGenerator:
    global _default_rg
    if _default_rg is None:
        _default_rg = ReportGenerator()
    return _default_rg
