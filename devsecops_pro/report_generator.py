# -*- coding: utf-8 -*-
"""
report_generator.py — DevSecOps 专业报告生成（MD / HTML）。

报告包含:
    - 执行摘要
    - SAST / SCA / Secrets / IaC / Container 扫描结果
    - 安全门禁结果
    - 风险评级
    - 修复建议
    - 安全趋势
"""

from __future__ import annotations

import html
import os
import time
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional


@dataclass
class DevSecOpsReportData:
    task_id: str = ""
    target: str = ""
    started_at: str = ""
    finished_at: str = ""
    cicd: Dict[str, Any] = field(default_factory=dict)
    sast: Dict[str, Any] = field(default_factory=dict)
    sca: Dict[str, Any] = field(default_factory=dict)
    secrets: Dict[str, Any] = field(default_factory=dict)
    iac: Dict[str, Any] = field(default_factory=dict)
    container: Dict[str, Any] = field(default_factory=dict)
    gate: Dict[str, Any] = field(default_factory=dict)
    risk: Dict[str, Any] = field(default_factory=dict)
    ai: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "task_id": self.task_id, "target": self.target,
            "started_at": self.started_at, "finished_at": self.finished_at,
            "cicd": self.cicd, "sast": self.sast, "sca": self.sca,
            "secrets": self.secrets, "iac": self.iac,
            "container": self.container, "gate": self.gate,
            "risk": self.risk, "ai": self.ai,
        }


SEV_COLOR = {
    "critical": "#e74c3c", "high": "#e67e22",
    "medium": "#f1c40f", "low": "#3498db", "info": "#95a5a6",
}
SEV_LABEL = {
    "critical": "严重", "high": "高危",
    "medium": "中危", "low": "低危", "info": "信息",
}


def _counts(findings: List[Dict[str, Any]]) -> Dict[str, int]:
    out = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
    for f in findings:
        s = str(f.get("severity", "info")).lower()
        out[s] = out.get(s, 0) + 1
    return out


class ReportGenerator:
    """DevSecOps 报告生成器。"""

    def generate_markdown(self, d: DevSecOpsReportData) -> str:
        L: List[str] = []
        L.append(f"# DevSecOps 专业报告")
        L.append("")
        L.append(f"- 任务 ID: `{d.task_id}`")
        L.append(f"- 扫描目标: `{d.target}`")
        L.append(f"- 开始时间: {d.started_at}")
        L.append(f"- 完成时间: {d.finished_at}")
        L.append("")

        # 执行摘要
        risk = d.risk or {}
        gate = d.gate or {}
        L.append("## 1. 执行摘要")
        L.append("")
        L.append(f"- **综合风险评分**: {risk.get('score', '-')}/100")
        L.append(f"- **风险等级**: {risk.get('level', '-')}")
        L.append(f"- **安全成熟度**: {risk.get('maturity', '-')}")
        L.append(f"- **门禁结论**: {gate.get('decision', '-')} "
                 f"(评分 {gate.get('score', '-')})")
        L.append("")
        if risk.get("summary"):
            L.append(f"> {risk['summary']}")
            L.append("")

        # 各阶段计数
        L.append("## 2. 扫描结果概览")
        L.append("")
        L.append("| 阶段 | Critical | High | Medium | Low | 总数 |")
        L.append("|------|----------|------|--------|-----|------|")
        for name, key in (("SAST 静态分析", "sast"),
                          ("SCA 依赖漏洞", "sca"),
                          ("Secrets 泄露", "secrets"),
                          ("IaC 配置", "iac"),
                          ("容器安全", "container")):
            data = getattr(d, key, {}) or {}
            c = _counts(data.get("findings", []))
            total = sum(c.values())
            L.append(f"| {name} | {c['critical']} | {c['high']} | "
                     f"{c['medium']} | {c['low']} | {total} |")
        L.append("")

        # Top 风险
        L.append("## 3. Top 风险项")
        L.append("")
        for it in (risk.get("top_risks") or [])[:10]:
            L.append(f"- **[{it.get('severity','').upper()}] "
                     f"{it.get('title','')}**")
            L.append(f"  - 来源: {it.get('source','')} | "
                     f"位置: {it.get('path','')}:{it.get('line','')}")
        L.append("")

        # AI 分析
        ai = d.ai or {}
        L.append("## 4. AI 分析")
        L.append("")
        L.append(f"### 4.1 总体评估")
        L.append(ai.get("overall_assessment", "-"))
        L.append("")
        L.append("### 4.2 攻击路径")
        for p in ai.get("attack_paths", []):
            L.append(f"- **{p.get('name')}**: {p.get('impact','')}")
        L.append("")
        L.append("### 4.3 修复建议（P0/P1/P2）")
        for s in (ai.get("fix_suggestions") or [])[:15]:
            L.append(f"- [{s.get('priority','')}] "
                     f"{s.get('issue','')} → {s.get('recommended_fix','')}")
        L.append("")
        L.append("### 4.4 改进路线图")
        for r in ai.get("roadmap", []):
            L.append(f"- **{r.get('phase','')}**（{r.get('focus','')}）")
            for it in r.get("items", []):
                L.append(f"  - {it}")
        L.append("")

        L.append("---")
        L.append("*本报告由 AI Hacking Agent · DevSecOps Pro 自动生成*")
        return "\n".join(L)

    # ------------------------------------------------------------------ #
    def generate_html(self, d: DevSecOpsReportData) -> str:
        risk = d.risk or {}
        gate = d.gate or {}
        sev = risk.get("level", "medium")
        color = SEV_COLOR.get(sev, "#f1c40f")
        body: List[str] = []

        body.append("<h2>执行摘要</h2>")
        body.append(
            f'<div class="summary">'
            f'<div class="kpi"><div class="num">{risk.get("score","-")}</div>'
            f'<div class="lbl">风险评分</div></div>'
            f'<div class="kpi"><div class="num" style="color:{color}">'
            f'{SEV_LABEL.get(sev, sev)}</div><div class="lbl">风险等级</div></div>'
            f'<div class="kpi"><div class="num">{risk.get("maturity","-")}</div>'
            f'<div class="lbl">成熟度</div></div>'
            f'<div class="kpi"><div class="num">{gate.get("decision","-")}</div>'
            f'<div class="lbl">门禁结论</div></div>'
            f"</div>")

        body.append("<h2>扫描结果概览</h2><table>"
                    "<tr><th>阶段</th><th>Critical</th><th>High</th>"
                    "<th>Medium</th><th>Low</th><th>总数</th></tr>")
        for name, key in (("SAST", "sast"), ("SCA", "sca"),
                          ("Secrets", "secrets"), ("IaC", "iac"),
                          ("Container", "container")):
            data = getattr(d, key, {}) or {}
            c = _counts(data.get("findings", []))
            body.append(
                f"<tr><td>{name}</td><td>{c['critical']}</td>"
                f"<td>{c['high']}</td><td>{c['medium']}</td>"
                f"<td>{c['low']}</td><td>{sum(c.values())}</td></tr>")
        body.append("</table>")

        body.append("<h2>Top 风险项</h2><ul>")
        for it in (risk.get("top_risks") or [])[:10]:
            body.append(
                f'<li><span class="sev {it.get("severity","low")}">'
                f'{SEV_LABEL.get(it.get("severity","low"), it.get("severity",""))}'
                f'</span> {html.escape(str(it.get("title","")))} '
                f'<span class="muted">[{it.get("source","")} '
                f'{html.escape(str(it.get("path","")))}:{it.get("line","")}]</span></li>')
        body.append("</ul>")

        ai = d.ai or {}
        body.append("<h2>AI 分析</h2>")
        body.append(f"<p>{html.escape(ai.get('overall_assessment',''))}</p>")
        body.append("<h3>攻击路径</h3><ul>")
        for p in ai.get("attack_paths", []):
            body.append(f"<li><b>{html.escape(str(p.get('name','')))}</b>: "
                        f"{html.escape(str(p.get('impact','')))}</li>")
        body.append("</ul>")

        return f"""<!doctype html>
<html lang="zh-CN"><head><meta charset="utf-8">
<title>DevSecOps 报告 {d.task_id}</title>
<style>
body{{font-family:-apple-system,"Segoe UI","Microsoft YaHei",sans-serif;
  background:#0f1115;color:#e6e8ee;max-width:1100px;margin:0 auto;padding:24px}}
h2{{color:#4fc3f7;border-bottom:1px solid #2a2f3a;padding-bottom:6px;margin-top:28px}}
table{{width:100%;border-collapse:collapse;margin:12px 0}}
th,td{{padding:8px;border:1px solid #2a2f3a;text-align:left;font-size:14px}}
.kpi{{display:inline-block;margin:8px 16px 8px 0;padding:14px 22px;
  background:#171a21;border:1px solid #2a2f3a;border-radius:10px}}
.kpi .num{{font-size:26px;font-weight:bold}}
.kpi .lbl{{font-size:12px;color:#8a90a0}}
.sev{{padding:2px 8px;border-radius:4px;font-size:11px;font-weight:bold;color:#000}}
.sev.critical{{background:#e74c3c}}.sev.high{{background:#e67e22}}
.sev.medium{{background:#f1c40f}}.sev.low{{background:#3498db}}
.muted{{color:#8a90a0;font-size:12px}}
</style></head><body>
<h1>DevSecOps 专业报告</h1>
<p class="muted">任务 {d.task_id} · {html.escape(d.target)} · {d.finished_at}</p>
{''.join(body)}
<footer class="muted">本报告由 AI Hacking Agent · DevSecOps Pro 自动生成</footer>
</body></html>"""

    # ------------------------------------------------------------------ #
    def save(self, d: DevSecOpsReportData, out_dir: str,
             fmt: str = "html") -> str:
        os.makedirs(out_dir, exist_ok=True)
        ts = time.strftime("%Y%m%d_%H%M%S")
        if fmt == "markdown":
            path = os.path.join(out_dir, f"devsecops_{d.task_id}_{ts}.md")
            with open(path, "w", encoding="utf-8") as f:
                f.write(self.generate_markdown(d))
        else:
            path = os.path.join(out_dir, f"devsecops_{d.task_id}_{ts}.html")
            with open(path, "w", encoding="utf-8") as f:
                f.write(self.generate_html(d))
        return path


_default: Optional[ReportGenerator] = None


def get_report_generator() -> ReportGenerator:
    global _default
    if _default is None:
        _default = ReportGenerator()
    return _default
