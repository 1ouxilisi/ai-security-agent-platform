# -*- coding: utf-8 -*-
"""
report_generator.py — 数据安全报告生成（MD / HTML）。

包含: 执行摘要 / 数据发现 / 分类分级 / 资产盘点 / DLP / 隐私合规 /
加密密钥 / 访问审计 / 风险评级 / 整改建议 / 图表占位。
"""

from __future__ import annotations

import html
import os
import time
from typing import Any, Dict, Optional


REPORTS_DIR = os.path.join(
    os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
    "reports", "data_security_pro")


class DataSecurityReportGenerator:
    """生成专业数据安全报告。"""

    # ------------------------------------------------------------------ #
    def generate_markdown(self, ctx: Dict[str, Any]) -> str:
        risk = ctx.get("risk", {})
        comp = ctx.get("compliance", {})
        enc = ctx.get("encryption", {})
        acc = ctx.get("access", {})
        lines = [
            "# 数据安全评估报告",
            "",
            f"- 生成时间: {time.strftime('%Y-%m-%d %H:%M:%S')}",
            f"- 整体风险: **{risk.get('overall_level','-')}** "
            f"(评分 {risk.get('overall_score','-')}/100)",
            f"- 成熟度: {risk.get('maturity',{}).get('name','-')}",
            "",
            "## 一、执行摘要",
            "",
        ]
        for note in ctx.get("ai", {}).get("interpretation",
                                          ["（无）"]):
            lines.append(f"- {note}")
        lines += ["", "## 二、数据发现结果", ""]
        disc = ctx.get("discovery", {})
        lines.append(f"- 扫描表数: {disc.get('scanned_tables', 0)}")
        lines.append(f"- 敏感命中: {disc.get('hit_count', 0)}")
        lines.append(f"- 分布: {disc.get('by_type', {})}")
        lines += ["", "## 三、数据分类分级", ""]
        cls = ctx.get("classification", {})
        lines.append(f"- 分级分布: {cls.get('by_level', {})}")
        lines.append(f"- 分类质量: {cls.get('quality', {})}")
        lines += ["", "## 四、数据资产盘点", ""]
        ast = ctx.get("asset_summary", {})
        lines.append(f"- 资产总数: {ast.get('total_assets', 0)}")
        lines.append(f"- 敏感分布: {ast.get('by_sensitivity', {})}")
        lines += ["", "## 五、DLP 防泄漏", ""]
        dlp = ctx.get("dlp", {})
        lines.append(f"- 策略总数: {dlp.get('policy_total', 0)}")
        lines.append(f"- 启用: {dlp.get('policy_enabled', 0)}")
        lines.append(f"- 告警: {dlp.get('alert_total', 0)}")
        lines.append(f"- 按级别: {dlp.get('alerts_by_level', {})}")
        lines += ["", "## 六、隐私合规评估", ""]
        lines.append(f"- 整体合规分: {comp.get('overall_score', '-')}")
        lines.append(f"- 各框架: {comp.get('framework_scores', {})}")
        lines += ["", "## 七、加密与密钥审计", ""]
        lines.append(f"- 加密覆盖率: "
                     f"{enc.get('coverage', {}).get('encryption_coverage_pct', '-')}%")
        lines.append(f"- 弱算法数: "
                     f"{enc.get('coverage', {}).get('weak_algo_count', 0)}")
        lines += ["", "## 八、数据访问审计", ""]
        lines.append(f"- 日志: {acc.get('log_total', 0)}")
        lines.append(f"- 异常: {acc.get('anomaly_total', 0)}")
        lines += ["", "## 九、风险评级", ""]
        for r in risk.get("top_risks", []):
            lines.append(f"- [{r['level'].upper()}] {r['title']} "
                         f"({r['score']}): {r['detail']}")
        lines += ["", "## 十、整改建议（优先级）", ""]
        for a in ctx.get("ai", {}).get("priority_actions", []):
            lines.append(f"{a['priority']}. [{a['level']}] "
                         f"{a['risk']}: {a['action']}")
        lines += ["", "## 十一、改进路线图", ""]
        for s in ctx.get("ai", {}).get("roadmap", []):
            lines.append(f"- **{s['window']}**: {s['action']}")
        return "\n".join(lines)

    # ------------------------------------------------------------------ #
    def generate_html(self, ctx: Dict[str, Any]) -> str:
        md = self.generate_markdown(ctx)
        body = html.escape(md).replace("\n", "<br>")
        risk = ctx.get("risk", {})
        return f"""<!doctype html>
<html lang="zh-CN"><head><meta charset="utf-8">
<title>数据安全评估报告</title>
<style>
body{{font-family:"Microsoft YaHei",sans-serif;background:#0f1115;
color:#e6e8ee;padding:32px;max-width:960px;margin:auto}}
.badge{{background:#e74c3c;color:#fff;padding:4px 12px;border-radius:999px}}
pre{{background:#171a21;padding:16px;border-radius:8px}}
</style></head><body>
<h1>🛡️ 数据安全评估报告
<span class="badge">{html.escape(str(risk.get('overall_level','')))}</span></h1>
<pre>{body}</pre>
</body></html>"""

    # ------------------------------------------------------------------ #
    def save(self, ctx: Dict[str, Any], out_dir: Optional[str] = None,
             fmt: str = "html") -> str:
        out_dir = out_dir or REPORTS_DIR
        os.makedirs(out_dir, exist_ok=True)
        ts = time.strftime("%Y%m%d_%H%M%S")
        path = os.path.join(out_dir, f"data_security_report_{ts}.{fmt}")
        content = (self.generate_html(ctx) if fmt == "html"
                   else self.generate_markdown(ctx))
        with open(path, "w", encoding="utf-8") as f:
            f.write(content)
        return path


_default_gen: Optional[DataSecurityReportGenerator] = None


def get_report_generator() -> DataSecurityReportGenerator:
    global _default_gen
    if _default_gen is None:
        _default_gen = DataSecurityReportGenerator()
    return _default_gen


__all__ = ["DataSecurityReportGenerator", "get_report_generator",
           "REPORTS_DIR"]
