# -*- coding: utf-8 -*-
"""
real_report_generator.py — 真实云安全报告生成（MD / HTML，真实结果落盘）。

报告章节:
    执行摘要 / 资产概览 / 检查详情 / 风险评级 / 合规状态 / 修复建议 / CIS 基线结果
落盘:
    reports/cloud_security_real/
"""

from __future__ import annotations

import html
import os
import time
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional


REPORTS_DIR = os.path.join(
    os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
    "reports", "cloud_security_real")

SEV_LABEL = {"critical": "严重", "high": "高危", "medium": "中危",
             "low": "低危", "info": "信息"}
SEV_COLOR = {"critical": "#e74c3c", "high": "#e67e22", "medium": "#f1c40f",
             "low": "#3498db", "info": "#95a5a6"}


@dataclass
class RealReportData:
    task_id: str = ""
    provider: str = "aws"
    started_at: str = ""
    finished_at: str = ""
    credential_status: Dict[str, Any] = field(default_factory=dict)
    summary: Dict[str, Any] = field(default_factory=dict)
    by_service: Dict[str, Any] = field(default_factory=dict)
    findings: List[Dict[str, Any]] = field(default_factory=list)
    cis: Dict[str, Any] = field(default_factory=dict)
    container: Dict[str, Any] = field(default_factory=dict)


class RealReportGenerator:
    """真实云安全报告生成器。"""

    company = "AI Hacking Agent · 云安全真实版 (cloud_security_real)"

    # ------------------------------------------------------------------ #
    def generate_markdown(self, d: RealReportData) -> str:
        L: List[str] = []
        s = d.summary or {}
        L.append(f"# 真实云安全评估报告（{d.provider.upper()}）")
        L.append("")
        L.append(f"- **任务 ID**: {d.task_id}")
        L.append(f"- **云厂商**: {d.provider}")
        L.append(f"- **开始**: {d.started_at}  **结束**: {d.finished_at}")
        cred = d.credential_status or {}
        if cred:
            L.append(f"- **SDK 安装**: {cred.get('sdk_installed')}  "
                     f"**凭证配置**: {cred.get('credentials_configured')}")
            L.append(f"- **状态提示**: {cred.get('hint','')}")
        L.append("")
        L.append("---")
        L.append("")
        # 执行摘要
        L.append("## 1. 执行摘要")
        L.append("")
        by_sev = s.get("by_severity", {})
        L.append(f"- 检查项总数: **{s.get('total',0)}**，合规 {s.get('passed',0)}，"
                 f"不合规 {s.get('failed',0)}，调用错误 {s.get('errors',0)}")
        L.append(f"- 合规率: **{s.get('pass_rate',0)}%**")
        L.append(f"- 严重 {by_sev.get('critical',0)} / 高危 {by_sev.get('high',0)} / "
                 f"中危 {by_sev.get('medium',0)} / 低危 {by_sev.get('low',0)}")
        if not cred.get("credentials_configured"):
            L.append("")
            L.append("> 注意：未配置云凭证，本报告未发起真实调用，"
                     "以下为检查项定义与配置指引，不包含任何 mock 资产数据。")
        L.append("")
        # 资产/服务概览
        L.append("## 2. 服务概览")
        L.append("")
        L.append("| 服务 | 检查项 | 合规 | 不合规 | 合规率 |")
        L.append("|------|--------|------|--------|--------|")
        for svc, info in (d.by_service or {}).items():
            L.append(f"| {svc} | {info.get('total',0)} | "
                     f"{info.get('passed',0)} | {info.get('failed',0)} | "
                     f"{info.get('pass_rate',0)}% |")
        L.append("")
        # 检查详情
        L.append("## 3. 检查详情与修复建议")
        L.append("")
        fails = [f for f in d.findings if f.get("status") == "fail"]
        if not fails:
            L.append("本次未发现不合规项（或因未配置凭证未执行真实检查）。")
            L.append("")
        for i, f in enumerate(fails[:50], 1):
            L.append(f"### 3.{i} [{SEV_LABEL.get(f.get('severity','info'),'')}] "
                     f"{f.get('title','')}")
            L.append("")
            L.append(f"- 检查ID: `{f.get('check_id','')}`  服务: `{f.get('service','')}`  "
                     f"资源: `{f.get('resource','')}`")
            L.append(f"- 描述: {f.get('description','')}")
            L.append(f"- 检查方法: {f.get('method','')}")
            L.append(f"- 预期: {f.get('expected','')}  /  实际: {f.get('actual','')}")
            L.append(f"- **修复建议**: {f.get('remediation','')}")
            L.append("")
        # CIS 基线
        L.append("## 4. CIS 合规基线结果")
        L.append("")
        for fw, info in (d.cis or {}).items():
            pr = info.get("pass_rate")
            pr_text = "N/A（未真实评估）" if pr is None else f"{pr}%"
            L.append(f"- **{info.get('name',fw)}**: 共 {info.get('total',0)} 项，"
                     f"不合规 {info.get('failed',0)}，"
                     f"未评估 {info.get('unknown',0)}，"
                     f"合规率 {pr_text}")
        L.append("")
        # 容器扫描
        if d.container:
            L.append("## 5. 容器安全")
            L.append("")
            k = d.container.get("k8s") or {}
            dr = d.container.get("docker") or {}
            L.append(f"- K8s 检查项: {k.get('summary',{}).get('total',0)}，"
                     f"不合规 {k.get('summary',{}).get('failed',0)}")
            L.append(f"- Docker 检查项: {dr.get('summary',{}).get('total',0)}，"
                     f"不合规 {dr.get('summary',{}).get('failed',0)}")
            L.append("")
        L.append("---")
        L.append(f"_{self.company} 自动生成 · 仅用于授权安全评估_")
        L.append("")
        return "\n".join(L)

    # ------------------------------------------------------------------ #
    def generate_html(self, d: RealReportData) -> str:
        md = self.generate_markdown(d)
        esc = html.escape(md)
        body: List[str] = []
        for line in esc.split("\n"):
            if line.startswith("# "):
                body.append(f"<h1>{line[2:]}</h1>")
            elif line.startswith("## "):
                body.append(f"<h2>{line[3:]}</h2>")
            elif line.startswith("### "):
                body.append(f"<h3>{line[4:]}</h3>")
            elif line.startswith("---"):
                body.append("<hr/>")
            elif line.startswith("> "):
                body.append(f"<blockquote>{line[2:]}</blockquote>")
            elif line.startswith("- "):
                body.append(f"<li>{line[2:]}</li>")
            elif line.startswith("|"):
                body.append(f"<code style='white-space:pre'>{line}</code><br/>")
            elif line.strip():
                body.append(f"<p>{line}</p>")
        s = d.summary or {}
        color = "#e74c3c" if s.get("failed", 0) else "#2ecc71"
        return f"""<!doctype html><html lang="zh-CN"><head><meta charset="utf-8">
<title>真实云安全报告 {html.escape(d.provider)}</title>
<style>
body{{font-family:-apple-system,"Segoe UI","Microsoft YaHei",sans-serif;
max-width:980px;margin:2rem auto;padding:0 1rem;background:#0f1115;color:#e6e8ee}}
h1{{border-bottom:3px solid {color};padding-bottom:.5rem}}
h2{{color:#4fc3f7;margin-top:2rem}} h3{{color:#9b59b6}}
li{{margin:.3rem 0}} code{{background:#1f232c;padding:2px 6px;border-radius:4px}}
blockquote{{border-left:3px solid #f1c40f;background:#1a1a10;padding:8px 12px}}
.badge{{display:inline-block;padding:4px 14px;border-radius:999px;background:{color};
color:#fff;font-weight:bold}}
.footer{{margin-top:3rem;color:#888;font-size:.85rem;text-align:center}}
</style></head><body>
<span class="badge">合规率 {s.get('pass_rate',0)}% · {s.get('failed',0)} 项不合规</span>
{''.join(body)}
<p class="footer">{html.escape(self.company)}</p>
</body></html>"""

    # ------------------------------------------------------------------ #
    def save(self, d: RealReportData, fmt: str = "html") -> str:
        os.makedirs(REPORTS_DIR, exist_ok=True)
        ts = time.strftime("%Y%m%d_%H%M%S")
        path = os.path.join(REPORTS_DIR,
                            f"cloud_real_{d.provider}_{d.task_id}_{ts}.{fmt}")
        with open(path, "w", encoding="utf-8") as f:
            f.write(self.generate_html(d) if fmt == "html"
                    else self.generate_markdown(d))
        return path


_default_rep: Optional[RealReportGenerator] = None


def get_real_report_generator() -> RealReportGenerator:
    global _default_rep
    if _default_rep is None:
        _default_rep = RealReportGenerator()
    return _default_rep
