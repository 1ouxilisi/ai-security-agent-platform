#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
PDF 导出器 - 基于 reportlab 生成专业排版的中文安全评估报告

功能:
- 封面页（标题/公司/Logo/日期/报告编号）
- 自动目录、页眉页脚、页码
- 中文支持（微软雅黑 / 宋体 / 内置 CID 字体降级）
- 漏洞详情按严重程度分组，表格展示，颜色标记
- 端口列表、修复建议、附录
"""
import os
import time
from datetime import datetime
from typing import Any, Dict, List, Optional

from reporting._common import (
    SEVERITY_LABELS_ZH,
    SEVERITY_ORDER,
    SEVERITY_RGB,
    normalize_assessment,
    severity_counts,
)

try:
    from reportlab.lib import colors
    from reportlab.lib.pagesizes import A4
    from reportlab.lib.styles import ParagraphStyle, getSampleStyleSheet
    from reportlab.lib.units import mm
    from reportlab.pdfbase import pdfmetrics
    from reportlab.pdfbase.ttfonts import TTFont
    from reportlab.platypus import (
        BaseDocTemplate,
        Frame,
        PageBreak,
        PageTemplate,
        Paragraph,
        Spacer,
        Table,
        TableStyle,
    )
    from reportlab.platypus.tableofcontents import TableOfContents
    REPORTLAB_AVAILABLE = True
except ImportError:  # 降级方案
    REPORTLAB_AVAILABLE = False


# 候选中文字体路径
_FONT_CANDIDATES = [
    ("MSYaHei", r"C:\Windows\Fonts\msyh.ttc", 0),
    ("MSYaHeiBold", r"C:\Windows\Fonts\msyhbd.ttc", 0),
    ("SimSun", r"C:\Windows\Fonts\simsun.ttc", 0),
]


def _register_chinese_font():
    """注册中文字体，返回 (regular_name, bold_name, status_msg)"""
    if not REPORTLAB_AVAILABLE:
        return ("Helvetica", "Helvetica", "reportlab 不可用")

    reg_name = None
    bold_name = None

    # 尝试微软雅黑
    for font_name, path, idx in _FONT_CANDIDATES:
        if os.path.exists(path) and os.path.splitext(path)[1].lower() == ".ttc":
            try:
                pdfmetrics.registerFont(TTFont(font_name, path, subfontIndex=idx))
                if "Bold" in font_name:
                    bold_name = font_name
                elif reg_name is None:
                    reg_name = font_name
            except Exception:
                continue

    # 降级到 reportlab 内置中文 CID 字体
    if reg_name is None:
        try:
            from reportlab.pdfbase.cidfonts import UnicodeCIDFont
            pdfmetrics.registerFont(UnicodeCIDFont("STSong-Light"))
            reg_name = "STSong-Light"
            bold_name = "STSong-Light"
            return reg_name, bold_name, "使用内置 CID 字体 STSong-Light"
        except Exception:
            pass

    if bold_name is None:
        bold_name = reg_name
    status = f"中文字体: {reg_name}"
    return reg_name, bold_name, status


class _NumberedDocTemplate(BaseDocTemplate):
    """带目录和页码的文档模板"""

    def __init__(self, filename, **kw):
        super().__init__(filename, **kw)
        frame = Frame(self.leftMargin, self.bottomMargin,
                      self.width, self.height, id="normal")
        self.template_header = kw.get("header_text", "")
        self.addPageTemplates([
            PageTemplate(id="All", frames=[frame],
                         onPage=self._draw_page_decoration)
        ])
        self._toc = TableOfContents()
        self._toc.levelStyles = [
            ParagraphStyle(name="TOC1", fontName=kw.get("font", "Helvetica"),
                           fontSize=12, leading=20, leftIndent=10),
        ]

    def _draw_page_decoration(self, canvas, doc):
        """页眉页脚"""
        canvas.saveState()
        width, height = A4
        # 页眉
        if self.template_header:
            canvas.setFont(doc.font_name or "Helvetica", 8)
            canvas.setFillColor(colors.gray)
            canvas.drawString(20 * mm, height - 12 * mm, self.template_header)
            canvas.setStrokeColor(colors.lightgrey)
            canvas.line(20 * mm, height - 14 * mm, width - 20 * mm, height - 14 * mm)
        # 页脚页码
        canvas.setFont("Helvetica", 9)
        canvas.setFillColor(colors.gray)
        canvas.drawCentredString(width / 2.0, 10 * mm, f"- {doc.page} -")
        canvas.restoreState()

    def afterFlowable(self, flowable):
        """收集章节标题到目录"""
        if hasattr(flowable, "style") and getattr(flowable, "_toc_level", None) is not None:
            level = flowable._toc_level
            text = flowable.getPlainText()
            key = f"section-{self.page}-{id(flowable)}"
            self.canv.bookmarkPage(key)
            self.notify("TOCEntry", (level, text, self.page, key))


class PDFExporter:
    """PDF 报告导出器"""

    def __init__(self):
        self.font_name, self.font_bold, self.font_status = _register_chinese_font()

    # ---------------- 公共入口 ----------------

    def export(self, assessment_data: Dict[str, Any],
               output_path: str,
               template_config: Optional[Dict[str, Any]] = None) -> str:
        """导出 PDF 报告

        Args:
            assessment_data: 评估数据（dict 或 UnifiedAssessmentResult）
            output_path: 输出 PDF 文件路径
            template_config: 模板配置（公司名/Logo/页眉页脚等）

        Returns:
            生成的 PDF 文件绝对路径
        """
        if not REPORTLAB_AVAILABLE:
            raise ImportError("reportlab 未安装，无法生成 PDF")

        data = normalize_assessment(assessment_data)
        tpl = template_config or {}
        company = tpl.get("company_name") or "AI Hacking Agent"
        report_title = tpl.get("report_title") or "安全评估报告"
        logo_path = tpl.get("logo_path") or ""
        report_no = tpl.get("report_no") or data.get("assessment_id") or f"RPT-{int(time.time())}"
        header_text = tpl.get("header_text") or f"{company} · {report_title}"
        footer_text = tpl.get("footer_text") or "本报告仅用于授权安全测试"
        language = tpl.get("language", "zh")

        os.makedirs(os.path.dirname(os.path.abspath(output_path)) or ".", exist_ok=True)

        doc = _NumberedDocTemplate(
            output_path,
            pagesize=A4,
            leftMargin=20 * mm, rightMargin=20 * mm,
            topMargin=20 * mm, bottomMargin=18 * mm,
            header_text=header_text,
            font=self.font_name,
            title=report_title,
            author=company,
        )
        doc.font_name = self.font_name

        styles = self._build_styles()
        story: List[Any] = []

        # 1. 封面
        self._build_cover(story, styles, data, tpl, company, report_title,
                          report_no, logo_path)
        story.append(PageBreak())

        # 2. 目录
        story.append(Paragraph("目 录" if language == "zh" else "Contents", styles["h1"]))
        story.append(Spacer(1, 6 * mm))
        story.append(doc._toc)
        story.append(PageBreak())

        # 3. 各章节
        sections = tpl.get("sections") or [
            "executive_summary", "vulnerability_details",
            "port_list", "remediation", "appendix",
        ]
        for sec in sections:
            if sec == "executive_summary":
                self._section_executive_summary(story, styles, data)
            elif sec == "vulnerability_details":
                self._section_vuln_details(story, styles, data)
            elif sec == "port_list":
                self._section_port_list(story, styles, data)
            elif sec == "remediation":
                self._section_remediation(story, styles, data)
            elif sec == "appendix":
                self._section_appendix(story, styles, data)
            story.append(Spacer(1, 8 * mm))

        doc.multiBuild(story)
        return os.path.abspath(output_path)

    # ---------------- 样式 ----------------

    def _build_styles(self) -> Dict[str, ParagraphStyle]:
        base = self.font_name
        bold = self.font_bold
        return {
            "h1": ParagraphStyle("h1", fontName=bold, fontSize=18, leading=24,
                                 spaceAfter=10, textColor=colors.HexColor("#1e3a8a")),
            "h2": ParagraphStyle("h2", fontName=bold, fontSize=14, leading=20,
                                 spaceBefore=12, spaceAfter=6,
                                 textColor=colors.HexColor("#1e40af")),
            "body": ParagraphStyle("body", fontName=base, fontSize=10.5, leading=16,
                                   spaceAfter=4),
            "small": ParagraphStyle("small", fontName=base, fontSize=9, leading=13),
            "cover_title": ParagraphStyle("cover_title", fontName=bold, fontSize=30,
                                          leading=40, alignment=1,
                                          textColor=colors.HexColor("#0f172a")),
            "cover_meta": ParagraphStyle("cover_meta", fontName=base, fontSize=12,
                                         leading=20, alignment=1,
                                         textColor=colors.HexColor("#334155")),
            "cell": ParagraphStyle("cell", fontName=base, fontSize=8.5, leading=11),
            "cell_head": ParagraphStyle("cell_head", fontName=bold, fontSize=9,
                                        leading=12, textColor=colors.white),
        }

    @staticmethod
    def _h(text: str, style: ParagraphStyle, level: int = 1) -> Paragraph:
        p = Paragraph(text, style)
        p._toc_level = level
        return p

    # ---------------- 各章节 ----------------

    def _build_cover(self, story, styles, data, tpl, company,
                     report_title, report_no, logo_path):
        now = datetime.now().strftime("%Y-%m-%d")
        story.append(Spacer(1, 40 * mm))
        if logo_path and os.path.exists(logo_path):
            try:
                from reportlab.platypus import Image
                img = Image(logo_path, width=60 * mm, height=60 * mm)
                img.hAlign = "CENTER"
                story.append(img)
                story.append(Spacer(1, 10 * mm))
            except Exception:
                pass
        story.append(Paragraph(report_title, styles["cover_title"]))
        story.append(Spacer(1, 8 * mm))
        story.append(Paragraph(company, styles["cover_meta"]))
        story.append(Spacer(1, 20 * mm))

        cover_table = Table([
            ["评估目标", str(data.get("target") or "-")],
            ["评估类型", str(data.get("assessment_type") or "-")],
            ["报告编号", str(report_no)],
            ["报告日期", now],
            ["综合风险", f"{data.get('overall_risk_level')}（{data.get('overall_risk_score')} 分）"],
        ], colWidths=[40 * mm, 100 * mm])
        cover_table.setStyle(TableStyle([
            ("FONTNAME", (0, 0), (-1, -1), self.font_name),
            ("FONTSIZE", (0, 0), (-1, -1), 10.5),
            ("BACKGROUND", (0, 0), (0, -1), colors.HexColor("#f1f5f9")),
            ("GRID", (0, 0), (-1, -1), 0.5, colors.lightgrey),
            ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
            ("LEFTPADDING", (0, 0), (-1, -1), 8),
            ("TOPPADDING", (0, 0), (-1, -1), 6),
            ("BOTTOMPADDING", (0, 0), (-1, -1), 6),
        ]))
        cover_table.hAlign = "CENTER"
        story.append(cover_table)

    def _section_executive_summary(self, story, styles, data):
        story.append(self._h("一、执行摘要", styles["h1"], 0))
        summary = data.get("executive_summary") or "本次评估未提供执行摘要。"
        story.append(Paragraph(summary, styles["body"]))

        counts = severity_counts(data["findings"])
        story.append(Spacer(1, 3 * mm))
        rows = [["严重程度", "数量"]]
        for sev in SEVERITY_ORDER:
            rows.append([SEVERITY_LABELS_ZH[sev], str(counts.get(sev, 0))])
        rows.append(["合计", str(len(data["findings"]))])
        t = Table(rows, colWidths=[60 * mm, 40 * mm])
        tstyle = [
            ("FONTNAME", (0, 0), (-1, -1), self.font_name),
            ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#1e40af")),
            ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
            ("GRID", (0, 0), (-1, -1), 0.5, colors.lightgrey),
            ("ALIGN", (1, 0), (1, -1), "CENTER"),
        ]
        for i, sev in enumerate(SEVERITY_ORDER, start=1):
            r, g, b = SEVERITY_RGB[sev]
            tstyle.append(("BACKGROUND", (0, i), (0, i), colors.Color(r / 255, g / 255, b / 255)))
            tstyle.append(("TEXTCOLOR", (0, i), (0, i), colors.white))
        t.setStyle(TableStyle(tstyle))
        story.append(t)

        if data.get("key_findings"):
            story.append(Spacer(1, 3 * mm))
            story.append(Paragraph("关键发现：", styles["h2"]))
            for kf in data["key_findings"]:
                story.append(Paragraph(f"• {kf}", styles["body"]))

    def _section_vuln_details(self, story, styles, data):
        story.append(self._h("二、漏洞详情", styles["h1"], 0))
        findings = data["findings"]
        if not findings:
            story.append(Paragraph("本次评估未发现漏洞。", styles["body"]))
            return

        for sev in SEVERITY_ORDER:
            group = [f for f in findings if f["severity"] == sev]
            if not group:
                continue
            r, g, b = SEVERITY_RGB[sev]
            sev_color = colors.Color(r / 255, g / 255, b / 255)
            story.append(self._h(
                f"{SEVERITY_LABELS_ZH[sev]}（{len(group)} 项）", styles["h2"], 1))

            head = ["CVE", "漏洞名称", "严重", "描述", "证据", "修复建议"]
            rows = [[Paragraph(c, styles["cell_head"]) for c in head]]
            for f in group:
                rows.append([
                    Paragraph(str(f.get("cve") or "-"), styles["cell"]),
                    Paragraph(str(f.get("title") or "-"), styles["cell"]),
                    Paragraph(SEVERITY_LABELS_ZH[sev], styles["cell"]),
                    Paragraph(str(f.get("description") or "-"), styles["cell"]),
                    Paragraph(str(f.get("evidence") or "-")[:200], styles["cell"]),
                    Paragraph(str(f.get("recommendation") or "-")[:200], styles["cell"]),
                ])
            col_widths = [22 * mm, 35 * mm, 14 * mm, 40 * mm, 30 * mm, 30 * mm]
            t = Table(rows, colWidths=col_widths, repeatRows=1)
            t.setStyle(TableStyle([
                ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#334155")),
                ("GRID", (0, 0), (-1, -1), 0.4, colors.grey),
                ("VALIGN", (0, 0), (-1, -1), "TOP"),
                ("BACKGROUND", (0, 1), (0, -1), sev_color),
                ("TEXTCOLOR", (0, 1), (0, -1), colors.white),
                ("ROWBACKGROUNDS", (1, 1), (-1, -1),
                 [colors.white, colors.HexColor("#f8fafc")]),
            ]))
            story.append(t)
            story.append(Spacer(1, 4 * mm))

    def _section_port_list(self, story, styles, data):
        story.append(self._h("三、端口清单", styles["h1"], 0))
        ports = data["ports"]
        if not ports:
            story.append(Paragraph("未提供端口信息。", styles["body"]))
            return
        head = ["端口", "协议", "服务", "版本", "状态"]
        rows = [[Paragraph(c, styles["cell_head"]) for c in head]]
        for p in ports:
            rows.append([
                Paragraph(str(p.get("port")), styles["cell"]),
                Paragraph(str(p.get("protocol")), styles["cell"]),
                Paragraph(str(p.get("service") or "-"), styles["cell"]),
                Paragraph(str(p.get("version") or "-"), styles["cell"]),
                Paragraph(str(p.get("status")), styles["cell"]),
            ])
        t = Table(rows, colWidths=[25 * mm, 25 * mm, 45 * mm, 45 * mm, 25 * mm], repeatRows=1)
        t.setStyle(TableStyle([
            ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#334155")),
            ("GRID", (0, 0), (-1, -1), 0.4, colors.grey),
            ("ROWBACKGROUNDS", (0, 1), (-1, -1),
             [colors.white, colors.HexColor("#f8fafc")]),
        ]))
        story.append(t)

    def _section_remediation(self, story, styles, data):
        story.append(self._h("四、修复建议", styles["h1"], 0))
        recs = data.get("recommendations") or []
        if not recs:
            story.append(Paragraph("暂无修复建议。", styles["body"]))
            return
        for i, rec in enumerate(recs, 1):
            story.append(Paragraph(f"{i}. {rec}", styles["body"]))

    def _section_appendix(self, story, styles, data):
        story.append(self._h("五、附录", styles["h1"], 0))
        tools = data.get("tools_used") or []
        story.append(Paragraph(f"使用工具（{len(tools)}）：", styles["h2"]))
        story.append(Paragraph("、".join(tools) or "无", styles["body"]))
        checks = data.get("checks_run") or []
        story.append(Paragraph(f"检测项（{len(checks)}）：", styles["h2"]))
        story.append(Paragraph("、".join(checks) or "无", styles["body"]))
        story.append(Spacer(1, 5 * mm))
        story.append(Paragraph(
            f"报告生成时间：{datetime.now().strftime('%Y-%m-%d %H:%M:%S')}　|　{self.font_status}",
            styles["small"]))
