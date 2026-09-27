# -*- coding: utf-8 -*-
"""
report_generator.py — 合规审计报告生成（MD/HTML）。

内容:
    执行摘要 / 合规状态总览 / 各框架详情 / 差距清单 /
    整改建议 / 整改进度 / 证据附件 / 附录
"""

from __future__ import annotations

import os
from datetime import datetime
from typing import Any, Dict, Optional

REPORTS_DIR = os.path.join(
    os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
    "reports", "compliance_pro")


class ReportGenerator:
    """合规审计报告生成器。"""

    def __init__(self) -> None:
        os.makedirs(REPORTS_DIR, exist_ok=True)

    # ------------------------------------------------------------------ #
    def collect_data(self) -> Dict[str, Any]:
        from .compliance_report_phase import (
            get_compliance_report_phase)
        from .ai_analysis import get_ai_analysis
        phase = get_compliance_report_phase()
        data = phase.build()
        data["generated_at"] = datetime.now().isoformat(timespec="seconds")
        data["ai_advice"] = get_ai_analysis().analyze_gaps().get("advice", [])
        return data

    # ------------------------------------------------------------------ #
    def to_markdown(self, data: Optional[Dict[str, Any]] = None) -> str:
        d = data or self.collect_data()
        es = d["executive_summary"]
        lines = []
        lines.append("# 合规审计报告")
        lines.append("")
        lines.append(f"- 生成时间：{d['generated_at']}")
        lines.append(f"- 报告类型：合规审计（等保2.0/ISO27001/PCI-DSS/SOC2）")
        lines.append("")
        lines.append("## 1. 执行摘要")
        lines.append("")
        lines.append(f"- 整体合规率：**{es['overall_score']}%**")
        lines.append(f"- 资产总数：{es['asset_total']}")
        lines.append(f"- 基线检查通过率：{es['baseline_pass_rate']}%")
        lines.append(f"- 差距总数：{es['gap_total']}"
                     f"（critical {es['critical']} / high {es['high']}）")
        lines.append(f"- 整改已完成：{es['remediation_done']}，"
                     f"已延期：{es['remediation_overdue']}")
        lines.append(f"- 复测通过率：{es['retest_pass_rate']}%")
        lines.append("")
        lines.append("## 2. 各框架合规详情")
        lines.append("")
        lines.append("| 框架 | 得分 | 通过 | 部分 | 未通过 |")
        lines.append("|---|---|---|---|---|")
        for fw, v in d["frameworks"].items():
            lines.append(f"| {v['name']} | {v['score']}% | "
                         f"{v['pass']} | {v['partial']} | {v['fail']} |")
        lines.append("")
        lines.append("## 3. 差距清单（Top）")
        lines.append("")
        for g in d["gap_top"][:15]:
            lines.append(f"- **[{g['severity'].upper()}]** "
                         f"{g['title']} — {g.get('impact','')}")
        lines.append("")
        lines.append("## 4. 整改建议")
        lines.append("")
        for a in d.get("ai_advice", [])[:8]:
            lines.append(f"- {a}")
        lines.append("")
        lines.append("## 5. 整改进度")
        lines.append("")
        rm = d["remediation"]["sla"]
        lines.append(f"- 未开始：{rm['not_started']}")
        lines.append(f"- 进行中：{rm['in_progress']}")
        lines.append(f"- 已完成：{rm['completed']}")
        lines.append(f"- 已延期：{rm['overdue']}")
        lines.append("")
        lines.append("## 6. 附录")
        lines.append("")
        lines.append(f"- 资产分类：{d['asset_summary']['by_type']}")
        lines.append(f"- 基线规则总数："
                     f"{d['baseline_stats']['total_rules']}")
        lines.append("")
        return "\n".join(lines)

    # ------------------------------------------------------------------ #
    def to_html(self, md: str) -> str:
        import html as _h
        body = _h.escape(md)
        return f"""<!doctype html>
<html lang="zh-CN"><head><meta charset="utf-8">
<title>合规审计报告</title>
<style>
body{{font-family:-apple-system,Segoe UI,Microsoft YaHei,sans-serif;
background:#0f1419;color:#e6e6e6;padding:32px;line-height:1.7;}}
pre{{white-space:pre-wrap;background:#1a2029;padding:20px;border-radius:8px;
border:1px solid #2a3441;}}
h1,h2{{color:#4fc3f7;}}
table{{border-collapse:collapse;}} th,td{{border:1px solid #2a3441;padding:4px 10px;}}
</style></head><body>
<pre>{body}</pre>
</body></html>"""

    # ------------------------------------------------------------------ #
    def generate(self, fmt: str = "both") -> Dict[str, Any]:
        data = self.collect_data()
        md = self.to_markdown(data)
        ts = datetime.now().strftime("%Y%m%d_%H%M%S")
        md_path = os.path.join(REPORTS_DIR, f"compliance_report_{ts}.md")
        html_path = os.path.join(REPORTS_DIR, f"compliance_report_{ts}.html")
        with open(md_path, "w", encoding="utf-8") as f:
            f.write(md)
        html = self.to_html(md)
        with open(html_path, "w", encoding="utf-8") as f:
            f.write(html)
        return {"md_path": md_path, "html_path": html_path,
                "markdown": md, "html": html,
                "stats": {"overall": data["executive_summary"]}}


_default: Optional[ReportGenerator] = None


def get_report_generator() -> ReportGenerator:
    global _default
    if _default is None:
        _default = ReportGenerator()
    return _default
