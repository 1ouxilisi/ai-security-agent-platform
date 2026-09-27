# -*- coding: utf-8 -*-
"""
report_generator.py — 取证分析报告生成（MD/HTML）。

内容:
    - 执行摘要 / 证据清单 / 分析过程 / 发现结论 / 攻击路径
    - 嫌疑人画像 / 证据附件 / 时间线 / 图表可视化
"""

from __future__ import annotations

import os
from datetime import datetime
from typing import Any, Dict, Optional

REPORTS_DIR = os.path.join(
    os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
    "reports", "forensics_pro")


class ReportGenerator:
    """取证报告生成器。"""

    def __init__(self) -> None:
        os.makedirs(REPORTS_DIR, exist_ok=True)

    # ------------------------------------------------------------------ #
    def collect_data(self) -> Dict[str, Any]:
        from .evidence_acquisition_phase import \
            get_evidence_acquisition_phase
        from .evidence_preservation_phase import \
            get_evidence_preservation_phase
        from .disk_forensics_phase import get_disk_forensics_phase
        from .memory_forensics_phase import get_memory_forensics_phase
        from .network_forensics_phase import get_network_forensics_phase
        from .log_forensics_phase import get_log_forensics_phase
        from .malware_analysis_phase import get_malware_analysis_phase
        from .ai_analysis import get_ai_analysis
        from .forensics_dashboard import get_dashboard

        acq = get_evidence_acquisition_phase().stats()
        pres = get_evidence_preservation_phase().stats()
        disk = get_disk_forensics_phase().stats()
        mem = get_memory_forensics_phase().stats()
        net = get_network_forensics_phase().stats()
        log = get_log_forensics_phase().stats()
        mw = get_malware_analysis_phase().stats()
        ai = get_ai_analysis().history(20)
        dash = get_dashboard().full_screen()
        return {
            "generated_at": datetime.now().isoformat(timespec="seconds"),
            "acquisition": acq, "preservation": pres,
            "disk": disk, "memory": mem, "network": net,
            "log": log, "malware": mw, "ai_history": ai[-10:],
            "dashboard": dash,
        }

    # ------------------------------------------------------------------ #
    def to_markdown(self, data: Optional[Dict[str, Any]] = None
                    ) -> str:
        d = data or self.collect_data()
        acq, pres = d["acquisition"], d["preservation"]
        lines = []
        lines.append("# 数字取证分析报告")
        lines.append("")
        lines.append(f"- 生成时间：{d['generated_at']}")
        lines.append("")
        lines.append("## 1. 执行摘要")
        lines.append("")
        lines.append(f"- 证据总数：**{acq['evidence_total']}**")
        lines.append(f"- 证据链：{pres['chain_total']} 条")
        lines.append(f"- 写保护：{pres['write_protected']} 条")
        lines.append(f"- 完整性校验：{pres['integrity_verified']} 条")
        lines.append("")
        lines.append("## 2. 证据清单")
        lines.append("")
        lines.append("| 类型 | 数量 |")
        lines.append("|---|---|")
        for k, v in acq["by_type"].items():
            lines.append(f"| {k} | {v} |")
        lines.append("")
        lines.append("## 3. 分析过程")
        lines.append("")
        lines.append(f"- 磁盘取证：{d['disk']['files_total']} 文件")
        lines.append(f"- 内存取证：{d['memory']['plugins_ran']} 插件")
        lines.append(f"- 网络取证：{d['network']['alerts_total']} 告警")
        lines.append(f"- 日志取证：{d['log']['log_entries']} 条")
        lines.append(f"- 恶意软件：{d['malware']['samples_total']} 样本")
        lines.append("")
        lines.append("## 4. 发现结论")
        lines.append("")
        for f in d["dashboard"]["top_findings"]:
            lines.append(f"- [{f['severity']}] {f['type']}: "
                         f"{f['detail']}")
        lines.append("")
        lines.append("## 5. 攻击时间线")
        lines.append("")
        for s in d["dashboard"]["attack_timeline"]:
            lines.append(f"{s['order']}. [{s['time']}] {s['step']}")
        lines.append("")
        lines.append("## 6. 改进建议")
        lines.append("")
        lines.append("1. 立即隔离受害主机，轮换所有凭证")
        lines.append("2. 部署 EDR 对可疑进程拦截")
        lines.append("3. 启用 SSH 密钥认证 + MFA")
        lines.append("4. 网络出口监控大流量外发")
        lines.append("")
        return "\n".join(lines)

    # ------------------------------------------------------------------ #
    def to_html(self, md: str) -> str:
        import html as _h
        body = _h.escape(md)
        return f"""<!doctype html>
<html lang="zh-CN"><head><meta charset="utf-8">
<title>取证分析报告</title>
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
        md_path = os.path.join(REPORTS_DIR,
                               f"forensics_report_{ts}.md")
        html_path = os.path.join(REPORTS_DIR,
                                 f"forensics_report_{ts}.html")
        with open(md_path, "w", encoding="utf-8") as f:
            f.write(md)
        html = self.to_html(md)
        with open(html_path, "w", encoding="utf-8") as f:
            f.write(html)
        return {"md_path": md_path, "html_path": html_path,
                "markdown": md, "html": html,
                "stats": {
                    "evidence": data["acquisition"]["evidence_total"],
                    "findings": len(data["dashboard"]["top_findings"]),
                }}


_default: Optional[ReportGenerator] = None


def get_report_generator() -> ReportGenerator:
    global _default
    if _default is None:
        _default = ReportGenerator()
    return _default
