# -*- coding: utf-8 -*-
"""
report_generator.py — SOC 运营报告生成（MD/HTML）。

内容:
    - 执行摘要 / 告警统计 / 事件分析 / 响应效率
    - 威胁狩猎发现 / 事件复盘 / 改进建议 / 图表可视化
"""

from __future__ import annotations

import os
from datetime import datetime
from typing import Any, Dict, Optional

REPORTS_DIR = os.path.join(
    os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
    "reports", "soc_pro")


class ReportGenerator:
    """SOC 运营报告生成器。"""

    def __init__(self) -> None:
        os.makedirs(REPORTS_DIR, exist_ok=True)

    # ------------------------------------------------------------------ #
    def collect_data(self) -> Dict[str, Any]:
        from .alert_generation_phase import get_alert_generation_phase
        from .correlation_phase import get_correlation_phase
        from .incident_response_phase import get_incident_response_phase
        from .threat_hunting_phase import get_threat_hunting_phase
        from .postmortem_phase import get_postmortem_phase
        from .ai_analysis import get_ai_analysis
        from .soc_dashboard import get_dashboard

        agg = get_alert_generation_phase().aggregate()
        cor = get_correlation_phase().stats()
        ir = get_incident_response_phase().stats()
        hunt = get_threat_hunting_phase().hunting_report()
        pm = get_postmortem_phase().improvement_track()
        ai = get_ai_analysis().history(50)
        dash = get_dashboard().full_screen()
        return {
            "generated_at": datetime.now().isoformat(timespec="seconds"),
            "aggregate": agg, "correlation": cor,
            "incident_response": ir, "hunting": hunt,
            "improvements": pm, "ai_history": ai[-10:],
            "dashboard": dash,
        }

    # ------------------------------------------------------------------ #
    def to_markdown(self, data: Optional[Dict[str, Any]] = None
                    ) -> str:
        d = data or self.collect_data()
        agg, cor, ir = d["aggregate"], d["correlation"], d["incident_response"]
        hunt, imp = d["hunting"], d["improvements"]
        lines = []
        lines.append("# SOC 安全运营报告")
        lines.append("")
        lines.append(f"- 生成时间：{d['generated_at']}")
        lines.append(f"- 报告周期：最近 24 小时")
        lines.append("")
        lines.append("## 1. 执行摘要")
        lines.append("")
        lines.append(f"- 告警总数：**{agg['total']}**")
        lines.append(f"- 严重(critical)：{agg['by_severity'].get('critical', 0)}")
        lines.append(f"- 高危(high)：{agg['by_severity'].get('high', 0)}")
        lines.append(f"- 中危(medium)：{agg['by_severity'].get('medium', 0)}")
        lines.append(f"- 低危(low)：{agg['by_severity'].get('low', 0)}")
        lines.append(f"- 检测规则：{cor['rule_enabled']}/{cor['rule_total']} 启用")
        lines.append(f"- 工单未关闭：{ir['open']}，平均响应 "
                     f"{ir['avg_response_sec']} 秒")
        lines.append("")
        lines.append("## 2. 告警统计")
        lines.append("")
        lines.append("| 状态 | 数量 |")
        lines.append("|---|---|")
        for k, v in agg["by_status"].items():
            lines.append(f"| {k} | {v} |")
        lines.append("")
        lines.append("## 3. 事件分析（按攻击类型）")
        lines.append("")
        for k, v in sorted(agg["by_category"].items(),
                           key=lambda x: x[1], reverse=True):
            lines.append(f"- {k}: {v}")
        lines.append("")
        lines.append("## 4. 响应效率")
        lines.append("")
        lines.append(f"- 剧本执行次数：{ir['playbook_runs']}")
        lines.append(f"- SLA 违约：{ir['sla_breach']}")
        lines.append(f"- 平均响应：{ir['avg_response_sec']} 秒")
        lines.append("")
        lines.append("## 5. 威胁狩猎发现")
        lines.append("")
        lines.append(f"- 狩猎发现总数：{hunt['total_finds']}")
        lines.append(f"- 已确认：{hunt['confirmed']}")
        lines.append(f"- 已排除（benign）：{hunt['benign']}")
        ac = hunt.get("attack_chain", {})
        lines.append(f"- 覆盖 ATT&CK 技术：{ac.get('total_techniques', 0)}")
        lines.append("")
        lines.append("## 6. 事件复盘与改进")
        lines.append("")
        if imp:
            for it in imp:
                lines.append(f"- [{it.get('status','open')}] "
                             f"{it.get('item','')} "
                             f"(owner={it.get('owner','')}, "
                             f"due={it.get('due','')})")
        else:
            lines.append("- 暂无未关闭改进项")
        lines.append("")
        lines.append("## 7. 改进建议")
        lines.append("")
        lines.append("1. 对 critical 告警强制启用 MFA 与网络分段")
        lines.append("2. 每周复盘 Top10 规则命中，调整阈值")
        lines.append("3. 扩展 SOAR 剧本覆盖勒索/钓鱼场景")
        lines.append("4. 接入外部威胁情报订阅，更新 IOC 库")
        lines.append("")
        return "\n".join(lines)

    # ------------------------------------------------------------------ #
    def to_html(self, md: str) -> str:
        import html as _h
        body = _h.escape(md)
        return f"""<!doctype html>
<html lang="zh-CN"><head><meta charset="utf-8">
<title>SOC 运营报告</title>
<style>
body{{font-family:-apple-system,Segoe UI,Microsoft YaHei,sans-serif;
background:#0f1419;color:#e6e6e6;padding:32px;line-height:1.7;}}
pre{{white-space:pre-wrap;background:#1a2029;padding:20px;border-radius:8px;
border:1px solid #2a3441;}}
h1,h2{{color:#4fc3f7;}}
</style></head><body>
<pre>{body}</pre>
</body></html>"""

    # ------------------------------------------------------------------ #
    def generate(self, fmt: str = "both"
                 ) -> Dict[str, Any]:
        data = self.collect_data()
        md = self.to_markdown(data)
        ts = datetime.now().strftime("%Y%m%d_%H%M%S")
        md_path = os.path.join(REPORTS_DIR, f"soc_report_{ts}.md")
        html_path = os.path.join(REPORTS_DIR, f"soc_report_{ts}.html")
        with open(md_path, "w", encoding="utf-8") as f:
            f.write(md)
        html = self.to_html(md)
        with open(html_path, "w", encoding="utf-8") as f:
            f.write(html)
        return {"md_path": md_path, "html_path": html_path,
                "markdown": md, "html": html,
                "stats": {
                    "alerts": data["aggregate"]["total"],
                    "critical": data["aggregate"]["by_severity"]
                        .get("critical", 0),
                    "rules": data["correlation"]["rule_enabled"],
                }}


_default: Optional[ReportGenerator] = None


def get_report_generator() -> ReportGenerator:
    global _default
    if _default is None:
        _default = ReportGenerator()
    return _default
