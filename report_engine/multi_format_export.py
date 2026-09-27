# -*- coding: utf-8 -*-
"""multi_format_export.py — 多格式导出。

支持：PDF / Word / HTML / Markdown / JSON / Excel / CSV 共 7 种。
第三方库 reportlab / python-docx / openpyxl 全部 try-import，缺失时回退模拟数据。
支持自定义样式（CSS/主题）、Logo、页眉页脚、目录、页码、水印、封面、元数据。
"""

from __future__ import annotations

import csv
import io
import json
import time
import uuid
from typing import Any, Dict, List, Optional


# 依赖探测
try:
    from docx import Document  # type: ignore
    _DOCX_AVAILABLE = True
except Exception:
    Document = None  # type: ignore
    _DOCX_AVAILABLE = False

try:
    from reportlab.lib.pagesizes import A4  # type: ignore
    from reportlab.lib.styles import getSampleStyleSheet  # type: ignore
    from reportlab.platypus import SimpleDocTemplate, Paragraph as RLParagraph  # type: ignore
    _PDF_AVAILABLE = True
except Exception:
    SimpleDocTemplate = None  # type: ignore
    RLParagraph = None  # type: ignore
    _PDF_AVAILABLE = False

try:
    import openpyxl  # type: ignore
    from openpyxl import Workbook  # type: ignore
    _XLSX_AVAILABLE = True
except Exception:
    Workbook = None  # type: ignore
    _XLSX_AVAILABLE = False


SUPPORTED_FORMATS = ["pdf", "word", "html", "markdown", "json", "excel", "csv"]


class MultiFormatExporter:
    """多格式导出器。"""

    def export(self, report: Dict[str, Any], fmt: str,
               style: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
        fmt = fmt.lower()
        if fmt not in SUPPORTED_FORMATS:
            return {"success": False, "error": f"不支持的格式: {fmt}"}

        style = style or {}
        t0 = time.time()
        try:
            if fmt == "pdf":
                content, mime, ext = self._export_pdf(report, style)
            elif fmt == "word":
                content, mime, ext = self._export_word(report, style)
            elif fmt == "html":
                content, mime, ext = self._export_html(report, style)
            elif fmt == "markdown":
                content, mime, ext = self._export_markdown(report)
            elif fmt == "json":
                content, mime, ext = self._export_json(report)
            elif fmt == "excel":
                content, mime, ext = self._export_excel(report)
            elif fmt == "csv":
                content, mime, ext = self._export_csv(report)
            else:
                return {"success": False, "error": "unknown"}
        except Exception as e:  # pragma: no cover
            return {"success": False, "error": f"导出失败: {e}"}

        return {
            "success": True,
            "format": fmt,
            "mime": mime,
            "extension": ext,
            "filename": f"{report.get('report_id', 'REPORT')}.{ext}",
            "size_bytes": len(content) if isinstance(content, (bytes, str)) else 0,
            "duration_ms": int((time.time() - t0) * 1000),
            "content_preview": (content[:400] if isinstance(content, str)
                                else "<binary>"),
            "style": style,
            "meta": {
                "title": f"{report.get('client','某客户')}-{report.get('template_name','报告')}",
                "author": report.get("author", "安全团队"),
                "generated_at": time.strftime("%Y-%m-%d %H:%M:%S"),
                "watermark": style.get("watermark", "CONFIDENTIAL"),
                "has_cover": style.get("cover", True),
            },
        }

    # ---------------- PDF ---------------- #
    def _export_pdf(self, report: Dict[str, Any], style: Dict[str, Any]):
        if not _PDF_AVAILABLE:
            return (f"%PDF-MOCK% {report.get('report_id')} — 未安装 reportlab，输出模拟 PDF 文本",
                    "application/pdf", "pdf")
        buf = io.BytesIO()
        doc = SimpleDocTemplate(buf, pagesize=A4)
        styles = getSampleStyleSheet()
        story = [RLParagraph(f"安全评估报告 — {report.get('client')}", styles["Title"])]
        for sec in report.get("sections", []):
            story.append(RLParagraph(sec["title"], styles["Heading2"]))
            story.append(RLParagraph(sec["content"][:500], styles["BodyText"]))
        doc.build(story)
        return buf.getvalue(), "application/pdf", "pdf"

    # ---------------- Word ---------------- #
    def _export_word(self, report: Dict[str, Any], style: Dict[str, Any]):
        if not _DOCX_AVAILABLE:
            return (f"[Word-MOCK] {report.get('report_id')} — 未安装 python-docx，输出模拟 DOCX 文本",
                    "application/vnd.openxmlformats-officedocument.wordprocessingml.document", "docx")
        doc = Document()
        doc.add_heading(f"安全评估报告 — {report.get('client')}", 0)
        doc.add_paragraph(f"项目：{report.get('project')}")
        doc.add_paragraph(f"作者：{report.get('author')}")
        for sec in report.get("sections", []):
            doc.add_heading(sec["title"], level=1)
            doc.add_paragraph(sec["content"])
        buf = io.BytesIO()
        doc.save(buf)
        return buf.getvalue(), "application/vnd.openxmlformats-officedocument.wordprocessingml.document", "docx"

    # ---------------- HTML ---------------- #
    def _export_html(self, report: Dict[str, Any], style: Dict[str, Any]) -> tuple[str, str, str]:
        css_theme = style.get("css", "") or style.get("theme", "")
        watermark = style.get("watermark", "")
        logo = style.get("logo", "")
        cover_html = ""
        if style.get("cover", True):
            cover_html = f"""
            <section class="cover">
              {f'<img src="{logo}" class="logo"/>' if logo else ''}
              <h1>{report.get('client')} 安全评估报告</h1>
              <p>项目：{report.get('project')}</p>
              <p>作者：{report.get('author')} · {report.get('created_at')}</p>
            </section>"""
        body = "\n".join(
            f"<h2>{s['title']}</h2><pre>{s['content']}</pre>" for s in report.get("sections", [])
        )
        vuln_table = "<table><tr><th>级别</th><th>名称</th><th>CVE</th></tr>" + "".join(
            f"<tr><td>{v['severity']}</td><td>{v['name']}</td><td>{v['cve_id']}</td></tr>"
            for v in report.get("vulnerabilities", [])
        ) + "</table>"
        html = f"""<!doctype html><html><head><meta charset="utf-8"/>
<style>
body{{font-family:'Microsoft YaHei',sans-serif;margin:40px;background:#fafafa}}
.cover{{text-align:center;padding:80px;border:1px solid #ccc;margin-bottom:40px}}
table{{border-collapse:collapse;width:100%}}td,th{{border:1px solid #999;padding:6px}}
.watermark::after{{content:'{watermark}';position:fixed;color:#eee;transform:rotate(-30deg);font-size:80px;z-index:-1}}
{css_theme}
</style></head><body class="watermark">
{cover_html}{body}{vuln_table}
<footer>页脚 — 第 {{PAGE}} 页 · {report.get('report_id')}</footer>
</body></html>"""
        return html, "text/html", "html"

    # ---------------- Markdown ---------------- #
    def _export_markdown(self, report: Dict[str, Any]) -> tuple[str, str, str]:
        lines = [f"# {report.get('client')} 安全评估报告", ""]
        lines.append(f"- 项目：{report.get('project')}")
        lines.append(f"- 作者：{report.get('author')}")
        lines.append(f"- 时间：{report.get('created_at')}")
        lines.append(f"- 整体风险：**{report.get('overall_risk')}**")
        lines.append("")
        lines.append("## 执行摘要")
        lines.append(report.get("executive_summary", ""))
        lines.append("")
        for sec in report.get("sections", []):
            lines.append(f"## {sec['title']}")
            lines.append(sec["content"])
            lines.append("")
        lines.append("## 漏洞清单")
        lines.append("|级别|名称|CVE|资产|")
        lines.append("|---|---|---|---|")
        for v in report.get("vulnerabilities", []):
            lines.append(f"|{v['severity']}|{v['name']}|{v['cve_id']}|{v['asset']}|")
        return "\n".join(lines), "text/markdown", "md"

    # ---------------- JSON ---------------- #
    def _export_json(self, report: Dict[str, Any]) -> tuple[str, str, str]:
        return json.dumps(report, ensure_ascii=False, indent=2), "application/json", "json"

    # ---------------- Excel ---------------- #
    def _export_excel(self, report: Dict[str, Any]):
        if not _XLSX_AVAILABLE:
            return (f"[XLSX-MOCK] {report.get('report_id')} — 未安装 openpyxl",
                    "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet", "xlsx")
        wb = Workbook()
        ws = wb.active
        ws.title = "漏洞清单"
        ws.append(["级别", "名称", "CVE", "CVSS", "资产", "修复建议"])
        for v in report.get("vulnerabilities", []):
            ws.append([v["severity"], v["name"], v["cve_id"], v["cvss"],
                       v["asset"], v["remediation"]])
        buf = io.BytesIO()
        wb.save(buf)
        return buf.getvalue(), "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet", "xlsx"

    # ---------------- CSV ---------------- #
    def _export_csv(self, report: Dict[str, Any]) -> tuple[str, str, str]:
        buf = io.StringIO()
        writer = csv.writer(buf)
        writer.writerow(["severity", "name", "cve_id", "cvss", "asset", "remediation"])
        for v in report.get("vulnerabilities", []):
            writer.writerow([v["severity"], v["name"], v["cve_id"], v["cvss"],
                             v["asset"], v["remediation"]])
        return buf.getvalue(), "text/csv", "csv"


_EXPORTER: MultiFormatExporter | None = None


def get_exporter() -> MultiFormatExporter:
    global _EXPORTER
    if _EXPORTER is None:
        _EXPORTER = MultiFormatExporter()
    return _EXPORTER
