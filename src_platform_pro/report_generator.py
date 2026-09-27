# -*- coding: utf-8 -*-
"""
report_generator.py — 专业 SRC 运营报告生成（MD/HTML）。

章节:
    执行摘要 / 平台概况 / 漏洞分析 / 白帽分析 / 企业分析
    / 赏金分析 / 趋势分析 / ROI 分析 / 改进建议 / 图表可视化
"""

from __future__ import annotations

import os
from datetime import datetime
from typing import Any, Dict, Optional

REPORTS_DIR = os.path.join(
    os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
    "reports", "src_platform_pro")


class ReportGenerator:
    """SRC 运营报告生成器。"""

    def __init__(self) -> None:
        os.makedirs(REPORTS_DIR, exist_ok=True)

    # ------------------------------------------------------------------ #
    def collect_data(self) -> Dict[str, Any]:
        from .src_dashboard import get_dashboard
        from .platform_management_phase import \
            get_platform_management_phase
        from .bounty_management_phase import get_bounty_phase
        dash = get_dashboard().full_screen()
        pm = get_platform_management_phase().stats()
        bm = get_bounty_phase().stats()
        return {
            "generated_at": datetime.now().isoformat(timespec="seconds"),
            "dashboard": dash, "platform": pm, "bounty": bm,
        }

    # ------------------------------------------------------------------ #
    def to_markdown(self, data: Optional[Dict[str, Any]] = None
                    ) -> str:
        d = data or self.collect_data()
        dash = d["dashboard"]
        kpi = dash["kpi"]
        lines: list = []
        lines.append("# SRC 漏洞平台运营报告")
        lines.append("")
        lines.append(f"- 生成时间：{d['generated_at']}")
        lines.append("")
        lines.append("## 1. 执行摘要")
        lines.append("")
        lines.append(f"- 漏洞总数：**{kpi['total_vulns']}**")
        lines.append(f"- 待审核：{kpi['pending_review']}，"
                     f"修复中：{kpi['fixing']}，"
                     f"已修复：{kpi['fixed']}")
        lines.append(f"- 白帽：{kpi['hackers']}，"
                     f"企业：{kpi['enterprises']}，"
                     f"累计赏金：¥{kpi['total_bounty']}")
        lines.append("")
        lines.append("## 2. 平台概况")
        lines.append("")
        lines.append(f"- 平台数：{d['platform']['platforms']}")
        lines.append(f"- 企业数：{d['platform']['enterprises_total']}")
        lines.append("")
        lines.append("## 3. 漏洞分析")
        lines.append("")
        lines.append("| 等级 | 数量 |")
        lines.append("|---|---|")
        for k, v in dash["severity_distribution"].items():
            lines.append(f"| {k} | {v} |")
        lines.append("")
        lines.append("## 4. 白帽分析（赏金榜 Top）")
        lines.append("")
        for r in dash["hacker_ranking"][:5]:
            lines.append(f"- {r['hacker_id']}: ¥{r['bounty']} "
                         f"({r['count']} 条)")
        lines.append("")
        lines.append("## 5. 企业分析")
        lines.append("")
        ep = dash["enterprise_posture"]
        lines.append(f"- 企业数：{ep.get('count', 0)}，"
                     f"平均安全分：{ep.get('avg_score', '-')}，"
                     f"修复率：{ep.get('fix_rate', '-')}")
        lines.append("")
        lines.append("## 6. 赏金分析")
        lines.append("")
        lines.append(f"- 累计发放：¥{d['bounty']['total_gross']}")
        lines.append(f"- 代扣个税：¥{d['bounty']['total_tax']}")
        lines.append("")
        lines.append("## 7. 趋势与 ROI")
        lines.append("")
        fe = dash.get("risk", {})
        lines.append(f"- 整体风险等级：{fe.get('risk_level', '-')} "
                     f"(score={fe.get('risk_score', '-')})")
        lines.append("")
        lines.append("## 8. 改进建议")
        lines.append("")
        lines.append("1. 优先处置 critical/high 漏洞，守住修复 SLA")
        lines.append("2. 引导白帽提升报告质量，减少误报与重复提交")
        lines.append("3. 扩充知识库与 PoC 库，沉淀企业修复经验")
        lines.append("4. 完善赏金激励，活跃 Top 白帽社区")
        lines.append("")
        return "\n".join(lines)

    # ------------------------------------------------------------------ #
    def to_html(self, md: str) -> str:
        import html as _h
        body = _h.escape(md)
        return f"""<!doctype html>
<html lang="zh-CN"><head><meta charset="utf-8">
<title>SRC 运营报告</title><style>
body{{font-family:-apple-system,Segoe UI,Microsoft YaHei,sans-serif;
background:#0b0f14;color:#e6edf3;padding:32px;line-height:1.7;}}
pre{{white-space:pre-wrap;background:#121821;padding:20px;border-radius:8px;
border:1px solid #243040;}}
h1,h2{{color:#4fc3f7;}}</style></head><body>
<pre>{body}</pre></body></html>"""

    # ------------------------------------------------------------------ #
    def generate(self, fmt: str = "both") -> Dict[str, Any]:
        data = self.collect_data()
        md = self.to_markdown(data)
        ts = datetime.now().strftime("%Y%m%d_%H%M%S")
        md_path = os.path.join(REPORTS_DIR, f"src_report_{ts}.md")
        html_path = os.path.join(REPORTS_DIR, f"src_report_{ts}.html")
        with open(md_path, "w", encoding="utf-8") as f:
            f.write(md)
        html = self.to_html(md)
        with open(html_path, "w", encoding="utf-8") as f:
            f.write(html)
        return {"md_path": md_path, "html_path": html_path,
                "markdown": md, "html": html,
                "stats": {"total": data["dashboard"]["kpi"]["total_vulns"],
                          "bounty": data["dashboard"]["kpi"]["total_bounty"]}}


_default: Optional[ReportGenerator] = None


def get_report_generator() -> ReportGenerator:
    global _default
    if _default is None:
        _default = ReportGenerator()
    return _default
