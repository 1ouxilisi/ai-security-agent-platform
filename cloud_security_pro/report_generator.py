# -*- coding: utf-8 -*-
"""
report_generator.py — 云安全 Pro 报告生成。

输出:
    - Markdown / HTML 专业云安全报告
    - 执行摘要 / 风险详情 / 整改建议 / 合规状态 / 风险评级 / 资产风险热力图
"""

from __future__ import annotations

import html
import os
import time
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional


REPORTS_DIR = os.path.join(
    os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
    "reports", "cloud_security_pro")


SEV_COLOR = {"critical": "#e74c3c", "high": "#e67e22",
             "medium": "#f1c40f", "low": "#3498db", "info": "#95a5a6"}
SEV_LABEL = {"critical": "严重", "high": "高危",
             "medium": "中危", "low": "低危", "info": "信息"}


@dataclass
class CloudReportData:
    task_id: str = ""
    provider: str = ""
    started_at: str = ""
    finished_at: str = ""
    inventory: Dict[str, Any] = field(default_factory=dict)
    config: Dict[str, Any] = field(default_factory=dict)
    risk: Dict[str, Any] = field(default_factory=dict)
    vuln: Dict[str, Any] = field(default_factory=dict)
    compliance: Dict[str, Any] = field(default_factory=dict)
    ai: Dict[str, Any] = field(default_factory=dict)


class CloudReportGenerator:
    """云安全报告生成器。"""

    def __init__(self) -> None:
        self.company = "AI Hacking Agent · 云安全 Pro"

    # ------------------------------------------------------------------ #
    def generate_markdown(self, d: CloudReportData) -> str:
        L: List[str] = []
        risk = d.risk or {}
        findings = d.config.get("findings", []) if d.config else []
        sev = risk.get("by_severity", {})

        L.append(f"# 云安全评估报告（{d.provider.upper()}）")
        L.append("")
        L.append(f"- **任务 ID**: {d.task_id}")
        L.append(f"- **云厂商**: {d.provider}")
        L.append(f"- **开始**: {d.started_at}  **结束**: {d.finished_at}")
        L.append(f"- **风险评分**: {risk.get('score','-')}/100 "
                 f"（等级 {risk.get('grade','-')}，"
                 f"{SEV_LABEL.get(risk.get('level','info'),'-')}）")
        L.append("")
        L.append("---")
        L.append("")
        # 执行摘要
        L.append("## 1. 执行摘要")
        L.append("")
        L.append((d.ai or {}).get("summary", "（无摘要）"))
        L.append("")
        L.append(f"- 配置风险: 严重 {sev.get('critical',0)} / "
                 f"高危 {sev.get('high',0)} / "
                 f"中危 {sev.get('medium',0)} / 低危 {sev.get('low',0)}")
        L.append(f"- 云服务漏洞: {(d.vuln or {}).get('count',0)} 个")
        L.append(f"- 合规通过率: {(d.compliance or {}).get('pass_rate',0)}%")
        L.append("")
        # 资产概览
        inv = d.inventory or {}
        L.append("## 2. 资产概览")
        L.append("")
        L.append(f"- 资源总数: {inv.get('resource_count',0)}")
        bt = inv.get("by_type", {})
        if bt:
            L.append("- 资源分布: " + ", ".join(
                f"{k}×{v}" for k, v in bt.items()))
        cred = inv.get("credential_status", {})
        if not cred.get("credentials_configured"):
            L.append(f"- ⚠️ 凭证状态: {cred.get('hint','未配置凭证')}")
        L.append("")
        # 资产风险热力图（文本）
        L.append("### 2.1 资产风险热力图")
        L.append("")
        L.append("| 资源类型 | 数量 | 关联风险数 | 风险密度 |")
        L.append("|----------|------|-----------|----------|")
        ft_by_type: Dict[str, int] = {}
        for f in findings:
            rt = f.get("resource_type", "other")
            ft_by_type[rt] = ft_by_type.get(rt, 0) + 1
        for rt, cnt in (bt or {}).items():
            rc = ft_by_type.get(rt, 0)
            density = round(rc / max(cnt, 1), 2)
            bar = "█" * min(10, int(density * 20))
            L.append(f"| {rt} | {cnt} | {rc} | {bar} {density} |")
        L.append("")
        # 风险详情
        L.append("## 3. 风险详情与整改建议")
        L.append("")
        if not findings:
            L.append("未发现配置风险（或因未配置凭证未执行真实检查）。")
            L.append("")
        for i, f in enumerate(findings[:30], 1):
            L.append(f"### 3.{i} [{SEV_LABEL.get(f.get('severity','info'),'')}] "
                     f"{f.get('title','')}")
            L.append("")
            L.append(f"- 规则: `{f.get('rule_id','')}`  资源: `{f.get('resource_id','')}`")
            L.append(f"- 描述: {f.get('description','')}")
            L.append(f"- 证据: {f.get('evidence','')}")
            L.append(f"- **整改**: {f.get('remediation','')}")
            L.append("")
        # 漏洞
        vulns = (d.vuln or {}).get("vulns", [])
        if vulns:
            L.append("## 4. 云服务漏洞")
            L.append("")
            L.append("| CVE | 产品 | 版本 | 严重度 | CVSS | 可利用性 |")
            L.append("|-----|------|------|--------|------|----------|")
            for v in vulns[:20]:
                L.append(f"| {v.get('cve_id','')} | {v.get('product','')} | "
                         f"{v.get('version','')} | "
                         f"{SEV_LABEL.get(v.get('severity','info'),'')} | "
                         f"{v.get('cvss','')} | {v.get('exploit_likelihood','')} |")
            L.append("")
        # 合规
        comp = d.compliance or {}
        L.append("## 5. 合规状态")
        L.append("")
        for fw, info in comp.get("frameworks", {}).items():
            L.append(f"- **{fw}**: {info.get('pass_rate')}% "
                     f"({info.get('pass')}/{info.get('total')}) "
                     f"[{info.get('status')}]")
        L.append("")
        # 攻击路径
        paths = (d.ai or {}).get("attack_paths", [])
        if paths:
            L.append("## 6. 攻击路径分析")
            L.append("")
            for p in paths:
                L.append(f"### {p.get('name','')}（难度 {p.get('difficulty','')}）")
                L.append("")
                L.append(p.get("description", ""))
                L.append("")
                for s in p.get("steps", []):
                    L.append(f"  {s.get('order')}. [{s.get('phase')}] {s.get('action')}")
                L.append("")
        # 成本优化
        cost = (d.ai or {}).get("cost_optimizations", [])
        if cost:
            L.append("## 7. 成本优化建议")
            L.append("")
            for c in cost:
                L.append(f"- **{c.get('item')}**: {c.get('advice')} "
                         f"（预估节省 {c.get('saving_estimate','-')}）")
            L.append("")
        L.append("---")
        L.append(f"_{self.company} 自动生成，仅供授权评估使用_")
        L.append("")
        return "\n".join(L)

    # ------------------------------------------------------------------ #
    def generate_html(self, d: CloudReportData) -> str:
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
            elif line.startswith("- "):
                body.append(f"<li>{line[2:]}</li>")
            elif line.startswith("|"):
                body.append(f"<code style='white-space:pre'>{line}</code><br/>")
            elif line.strip():
                body.append(f"<p>{line}</p>")
        risk = d.risk or {}
        color = SEV_COLOR.get(risk.get("level", "info"), "#95a5a6")
        return f"""<!doctype html><html lang="zh-CN"><head><meta charset="utf-8">
<title>云安全评估报告 {html.escape(d.provider)}</title>
<style>
body{{font-family:-apple-system,"Segoe UI","Microsoft YaHei",sans-serif;
max-width:980px;margin:2rem auto;padding:0 1rem;background:#0f1115;color:#e6e8ee}}
h1{{border-bottom:3px solid {color};padding-bottom:.5rem}}
h2{{color:#4fc3f7;margin-top:2rem}} h3{{color:#9b59b6}}
li{{margin:.3rem 0}} code{{background:#1f232c;padding:2px 6px;border-radius:4px}}
.badge{{display:inline-block;padding:4px 14px;border-radius:999px;background:{color};
color:#fff;font-weight:bold}}
.footer{{margin-top:3rem;color:#888;font-size:.85rem;text-align:center}}
</style></head><body>
<span class="badge">风险评分 {risk.get('score','-')}/100 · {SEV_LABEL.get(risk.get('level','info'),'')}</span>
{''.join(body)}
<p class="footer">{html.escape(self.company)}</p>
</body></html>"""

    # ------------------------------------------------------------------ #
    def save(self, d: CloudReportData, fmt: str = "html") -> str:
        os.makedirs(REPORTS_DIR, exist_ok=True)
        ts = time.strftime("%Y%m%d_%H%M%S")
        path = os.path.join(REPORTS_DIR,
                            f"cloud_security_{d.task_id}_{ts}.{fmt}")
        with open(path, "w", encoding="utf-8") as f:
            f.write(self.generate_html(d) if fmt == "html"
                    else self.generate_markdown(d))
        return path


_default_rep: Optional[CloudReportGenerator] = None


def get_report_generator() -> CloudReportGenerator:
    global _default_rep
    if _default_rep is None:
        _default_rep = CloudReportGenerator()
    return _default_rep
