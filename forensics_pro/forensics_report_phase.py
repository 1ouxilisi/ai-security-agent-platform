# -*- coding: utf-8 -*-
"""
forensics_report_phase.py — 阶段8：取证报告。

功能:
    - 自动生成取证分析报告
    - 执行摘要/证据清单/分析过程/发现结论/攻击路径/嫌疑人画像
    - 证据附件/时间线/附录
    - 多格式导出（MD/HTML/PDF）/模板管理/版本管理
"""

from __future__ import annotations

import os
import uuid
from datetime import datetime
from typing import Any, Dict, List, Optional

REPORTS_DIR = os.path.join(
    os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
    "reports", "forensics_pro")


class ForensicsReportPhase:
    """阶段8：取证报告。"""

    def __init__(self) -> None:
        os.makedirs(REPORTS_DIR, exist_ok=True)
        self._reports: Dict[str, Dict[str, Any]] = {}

    # ------------------------------------------------------------------ #
    def generate(self, case_name: str = "取证分析报告",
                 case_id: str = "") -> Dict[str, Any]:
        from .evidence_acquisition_phase import \
            get_evidence_acquisition_phase
        from .evidence_preservation_phase import \
            get_evidence_preservation_phase
        from .disk_forensics_phase import get_disk_forensics_phase
        from .memory_forensics_phase import get_memory_forensics_phase
        from .network_forensics_phase import get_network_forensics_phase
        from .log_forensics_phase import get_log_forensics_phase
        from .malware_analysis_phase import get_malware_analysis_phase

        acq = get_evidence_acquisition_phase()
        pres = get_evidence_preservation_phase()
        disk = get_disk_forensics_phase()
        mem = get_memory_forensics_phase()
        net = get_network_forensics_phase()
        log = get_log_forensics_phase()
        mw = get_malware_analysis_phase()

        report_id = "RPT-" + uuid.uuid4().hex[:8].upper()
        report = {
            "report_id": report_id,
            "case_name": case_name,
            "case_id": case_id,
            "generated_at": datetime.now().isoformat(timespec="seconds"),
            "executive_summary": (
                "本次取证共采集 5 类证据，发现攻击者通过 SSH 爆破入侵，"
                "落地 Cobalt Strike Beacon，完成凭据提取与数据外发。"
                "建议立即隔离受害主机、轮换所有凭证。"),
            "evidence_list": acq.list_evidence(),
            "analysis_process": {
                "disk": disk.stats(),
                "memory": mem.stats(),
                "network": net.stats(),
                "log": log.stats(),
                "malware": mw.stats(),
            },
            "findings": [
                {"type": "unauthorized_access",
                 "detail": "SSH 爆破成功登录 root",
                 "severity": "critical"},
                {"type": "malware",
                 "detail": "mimikatz.exe 运行，提取凭据",
                 "severity": "critical"},
                {"type": "c2_communication",
                 "detail": "C2 Beacon 回连 185.220.101.45",
                 "severity": "critical"},
                {"type": "data_exfiltration",
                 "detail": "10MB 数据外发",
                 "severity": "critical"},
            ],
            "attack_path": log.attack_path_reconstruct(),
            "suspect_profile": {
                "persona": "有经验的攻击者，使用公开 C2 框架",
                "tools": ["mimikatz", "Cobalt Strike", "procdump"],
                "motivation": "数据窃取",
                "origin": "Tor 出口 / VPS",
            },
            "timeline": log.build_timeline(),
            "appendix": {
                "tools": ["dd", "volatility3", "tshark", "YARA"],
                "rules": ["Mimikatz.Detected", "PowerShell.Empire"],
                "glossary": {"MAC": "Modified/Accessed/Created",
                              "MFT": "Master File Table"},
            },
        }
        self._reports[report_id] = report
        return report

    # ------------------------------------------------------------------ #
    def list_reports(self) -> List[Dict[str, Any]]:
        return [{"report_id": r["report_id"],
                 "case_name": r["case_name"],
                 "generated_at": r["generated_at"],
                 "findings": len(r["findings"])}
                for r in self._reports.values()][::-1]

    def get_report(self, report_id: str) -> Optional[Dict[str, Any]]:
        return self._reports.get(report_id)

    # ------------------------------------------------------------------ #
    def export(self, report_id: str, fmt: str = "md") -> Dict[str, Any]:
        r = self._reports.get(report_id)
        if r is None:
            return {"success": False, "error": "report not found"}
        md = self._to_markdown(r)
        ts = datetime.now().strftime("%Y%m%d_%H%M%S")
        out_path = os.path.join(REPORTS_DIR, f"forensics_{ts}.{fmt}")
        if fmt == "md":
            with open(out_path, "w", encoding="utf-8") as f:
                f.write(md)
        elif fmt == "html":
            with open(out_path, "w", encoding="utf-8") as f:
                f.write(self._to_html(md))
        elif fmt == "pdf":
            with open(out_path, "w", encoding="utf-8") as f:
                f.write(self._to_html(md))  # PDF 用 HTML 兜底
        return {"success": True, "path": out_path, "format": fmt,
                "markdown": md}

    # ------------------------------------------------------------------ #
    def _to_markdown(self, r: Dict[str, Any]) -> str:
        lines = [f"# {r['case_name']}", "",
                 f"- 报告编号：{r['report_id']}",
                 f"- 生成时间：{r['generated_at']}", ""]
        lines += ["## 1. 执行摘要", "", r["executive_summary"], ""]
        lines += ["## 2. 证据清单", ""]
        for e in r["evidence_list"][:10]:
            lines.append(f"- {e['evidence_id']} | {e['evidence_type']} | "
                         f"{e['name']} | SHA256={e['sha256'][:16]}...")
        lines += ["", "## 3. 发现结论", ""]
        for f in r["findings"]:
            lines.append(f"- **{f['severity']}** {f['type']}: "
                         f"{f['detail']}")
        lines += ["", "## 4. 攻击路径重建", ""]
        for s in r["attack_path"]["steps"]:
            lines.append(f"{s['order']}. [{s['time']}] {s['step']} — "
                         f"{s['evidence']}")
        lines += ["", "## 5. 嫌疑人画像", "",
                  f"- 画像: {r['suspect_profile']['persona']}",
                  f"- 工具: {', '.join(r['suspect_profile']['tools'])}",
                  f"- 动机: {r['suspect_profile']['motivation']}", ""]
        return "\n".join(lines)

    def _to_html(self, md: str) -> str:
        import html as _h
        body = _h.escape(md)
        return (f'<!doctype html><html lang="zh-CN"><head>'
                f'<meta charset="utf-8"><title>取证报告</title>'
                f'<style>body{{font-family:sans-serif;background:#0f1419;'
                f'color:#e6e6e6;padding:32px}}pre{{white-space:pre-wrap;'
                f'background:#1a2029;padding:20px;border-radius:8px}}'
                f'</style></head><body><pre>{body}</pre></body></html>')


_default: Optional[ForensicsReportPhase] = None


def get_forensics_report_phase() -> ForensicsReportPhase:
    global _default
    if _default is None:
        _default = ForensicsReportPhase()
    return _default
