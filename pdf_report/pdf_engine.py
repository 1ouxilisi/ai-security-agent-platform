# -*- coding: utf-8 -*-
"""
pdf_engine.py — 统一 PDF 生成引擎。

策略：
    1. 优先 weasyprint（HTML->PDF，CSS 排版，效果最佳）
    2. 兜底 reportlab（platypus 编程式，内置中文 CID 字体）
    3. 都不可用则明确报错提示安装

输入结构化 ReportContent -> 输出 PDF 文件路径。
含：封面 / 目录 / 执行摘要 / 详情 / 图表 / 附录 / 页眉页脚 / 水印。
"""

from __future__ import annotations

import datetime as _dt
import os
from typing import Any, Dict, List, Optional, Tuple

from . import chart_generator as cg
from .pdf_styles import WEASYPRINT_CSS, register_reportlab_fonts

ENGINE_AVAILABLE: Dict[str, bool] = {}
_PROBE_MSG: Dict[str, str] = {}


def detect_backend() -> str:
    """探测可用后端，返回 'weasyprint' / 'reportlab' / 'none'。

    weasyprint 仅 import 成功不够（Windows 常缺 GTK/Pango 原生库），
    必须做一次最小真实渲染探针；失败则诚实标记不可用并回退。
    """
    global ENGINE_AVAILABLE, _PROBE_MSG
    # --- weasyprint 真实探针 ---
    try:
        import io
        from weasyprint import HTML
        HTML(string="<p>probe 测试</p>").write_pdf(io.BytesIO())
        ENGINE_AVAILABLE["weasyprint"] = True
        _PROBE_MSG["weasyprint"] = "OK"
    except Exception as e:
        ENGINE_AVAILABLE["weasyprint"] = False
        _PROBE_MSG["weasyprint"] = f"不可用：{type(e).__name__}: {str(e)[:120]}"
    # --- reportlab 探针 ---
    try:
        import io
        from reportlab.pdfgen.canvas import Canvas
        from reportlab.lib.pagesizes import A4
        c = Canvas(io.BytesIO(), pagesize=A4)
        c.drawString(72, 720, "probe")
        c.save()
        ENGINE_AVAILABLE["reportlab"] = True
        _PROBE_MSG["reportlab"] = "OK"
    except Exception as e:
        ENGINE_AVAILABLE["reportlab"] = False
        _PROBE_MSG["reportlab"] = f"不可用：{type(e).__name__}: {str(e)[:120]}"
    if ENGINE_AVAILABLE.get("weasyprint"):
        return "weasyprint"
    if ENGINE_AVAILABLE.get("reportlab"):
        return "reportlab"
    return "none"


# 初始化探测
_BACKEND = detect_backend()


def backend() -> str:
    return _BACKEND


# --------------------------------------------------------------------------- #
# 内容模型构造
# --------------------------------------------------------------------------- #
def build_content(*, title: str, subtitle: str = "", company: str = "AI Hacking Agent",
                  confidential: str = "机密", version: str = "v1.0",
                  executive_summary: Optional[List[str]] = None,
                  sections: Optional[List[Dict[str, Any]]] = None,
                  charts: Optional[List[Dict[str, Any]]] = None,
                  appendix: Optional[List[Dict[str, Any]]] = None,
                  extra: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
    """构造标准报告内容字典。"""
    return {
        "title": title, "subtitle": subtitle, "company": company,
        "confidential": confidential, "version": version,
        "date": _dt.datetime.now().strftime("%Y-%m-%d %H:%M"),
        "executive_summary": executive_summary or [],
        "sections": sections or [],
        "charts": charts or [],
        "appendix": appendix or [],
        "extra": extra or {},
    }


# --------------------------------------------------------------------------- #
# HTML 构造（weasyprint 用，也用于预览）
# --------------------------------------------------------------------------- #
def _html_escape(s: str) -> str:
    import html as _h
    return _h.escape(str(s))


def content_to_html(c: Dict[str, Any], tpl: Dict[str, Any],
                    chart_dir: str) -> str:
    parts: List[str] = []
    # 封面
    parts.append(f"""<div class="cover" style="background:linear-gradient(135deg,
{tpl.get('cover_bg','#0b5394')},{tpl.get('cover_bg','#08305a')});">
<div class="conf">{_html_escape(c.get('confidential','机密'))}</div>
<div class="badge">{_html_escape(c.get('company',''))}</div>
<h1>{_html_escape(c.get('title','安全报告'))}</h1>
<div class="sub">{_html_escape(c.get('subtitle',''))}</div>
<div class="meta">版本：{_html_escape(c.get('version',''))}<br/>
生成时间：{_html_escape(c.get('date',''))}<br/>
保密等级：{_html_escape(c.get('confidential','机密'))}</div></div>""")

    # 目录
    parts.append('<div class="toc"><h2>目录</h2><ul>')
    parts.append("<li>1. 执行摘要</li>")
    for i, s in enumerate(c.get("sections", []), 2):
        parts.append(f"<li>{i}. {_html_escape(s.get('heading','章节'))}</li>")
    parts.append("<li>附录</li></ul></div>")

    # 执行摘要
    parts.append("<h1>执行摘要</h1>")
    for line in c.get("executive_summary", []):
        parts.append(f"<p>{_html_escape(line)}</p>")

    # 图表
    for ch in c.get("charts", []):
        img = os.path.join(chart_dir, ch["file"])
        parts.append(f'<h2>{_html_escape(ch.get("title","图表"))}</h2>'
                     f'<img class="chart" src="file:///{img.replace(os.sep,"/")}"/>')

    # 章节
    for s in c.get("sections", []):
        parts.append(f"<h2>{_html_escape(s.get('heading','章节'))}</h2>")
        for p in s.get("paragraphs", []):
            parts.append(f"<p>{_html_escape(p)}</p>")
        for tbl in s.get("tables", []):
            rows = tbl.get("rows", [])
            if not rows:
                continue
            parts.append("<table>")
            for ri, row in enumerate(rows):
                tag = "th" if ri == 0 else "td"
                cells = "".join(f"<{tag}>{_html_escape(v)}</{tag}>" for v in row)
                parts.append(f"<tr>{cells}</tr>")
            parts.append("</table>")
        for code in s.get("code_blocks", []):
            parts.append(f"<pre>{_html_escape(code)}</pre>")

    # 附录
    if c.get("appendix"):
        parts.append("<h1>附录</h1>")
        for ap in c["appendix"]:
            parts.append(f"<h3>{_html_escape(ap.get('heading','附录'))}</h3>")
            for p in ap.get("paragraphs", []):
                parts.append(f"<p>{_html_escape(p)}</p>")
            for tbl in ap.get("tables", []):
                rows = tbl.get("rows", [])
                if rows:
                    parts.append("<table>")
                    for ri, row in enumerate(rows):
                        tag = "th" if ri == 0 else "td"
                        cells = "".join(f"<{tag}>{_html_escape(v)}</{tag}" for v in row)
                        parts.append(f"<tr>{cells}</tr>")
                    parts.append("</table>")

    return f"<html><head><meta charset='utf-8'><style>{WEASYPRINT_CSS}</style></head><body>" + \
           "".join(parts) + "</body></html>"


# --------------------------------------------------------------------------- #
# reportlab 实现
# --------------------------------------------------------------------------- #
def _reportlab_build(c: Dict[str, Any], tpl: Dict[str, Any],
                     out_path: str, chart_dir: str) -> None:
    from reportlab.lib import colors
    from reportlab.lib.pagesizes import A4
    from reportlab.lib.styles import ParagraphStyle, getSampleStyleSheet
    from reportlab.lib.units import cm
    from reportlab.platypus import (BaseDocTemplate, Frame, Image,
                                    NextPageTemplate, PageBreak,
                                    PageTemplate, Paragraph, Spacer,
                                    Table, TableStyle)

    fonts = register_reportlab_fonts()
    cjk = fonts["cjk"]
    primary = colors.HexColor(tpl.get("primary_color", "#0b5394"))
    watermark_text = tpl.get("watermark", "机密")

    styles = getSampleStyleSheet()
    st_title = ParagraphStyle("t", parent=styles["Title"], fontName=cjk,
                              fontSize=26, textColor=primary, leading=32)
    st_h1 = ParagraphStyle("h1", fontName=cjk, fontSize=17, textColor=primary,
                           spaceBefore=14, spaceAfter=8, leading=22)
    st_h2 = ParagraphStyle("h2", fontName=cjk, fontSize=13, textColor=colors.HexColor("#333"),
                           spaceBefore=10, spaceAfter=5, leading=18)
    st_body = ParagraphStyle("b", fontName=cjk, fontSize=10.5, leading=17,
                             spaceAfter=5)
    st_small = ParagraphStyle("s", fontName=cjk, fontSize=9, leading=13,
                              textColor=colors.HexColor("#666"))
    st_cover = ParagraphStyle("cv", fontName=cjk, fontSize=34, leading=44,
                               textColor=colors.white, spaceBefore=120)

    def _decor(canvas, doc):
        canvas.saveState()
        # 水印
        canvas.setFont(cjk, 60)
        canvas.setFillColor(colors.Color(0.8, 0.8, 0.8, alpha=0.12))
        canvas.translate(A4[0] / 2, A4[1] / 2)
        canvas.rotate(35)
        canvas.drawCentredString(0, 0, watermark_text)
        canvas.restoreState()
        canvas.saveState()
        # 页眉页脚（非封面）
        if doc.page > 1:
            canvas.setFont(cjk, 8.5)
            canvas.setFillColor(colors.HexColor("#666"))
            canvas.drawString(2 * cm, A4[1] - 1.2 * cm, c.get("title", ""))
            canvas.drawRightString(A4[0] - 2 * cm, A4[1] - 1.2 * cm,
                                   c.get("company", ""))
            canvas.setStrokeColor(colors.HexColor("#ccc"))
            canvas.line(2 * cm, A4[1] - 1.35 * cm,
                        A4[0] - 2 * cm, A4[1] - 1.35 * cm)
            canvas.drawString(2 * cm, 1.2 * cm, "机密 - 仅供授权阅读")
            canvas.drawRightString(A4[0] - 2 * cm, 1.2 * cm, f"第 {doc.page} 页")
        canvas.restoreState()

    def _cover(canvas, doc):
        canvas.saveState()
        canvas.setFillColor(colors.HexColor(tpl.get("cover_bg", "#0b5394")))
        canvas.rect(0, 0, A4[0], A4[1], fill=1, stroke=0)
        canvas.setFillColor(colors.HexColor("#ffd54f"))
        canvas.rect(A4[0] - 6 * cm, A4[1] - 3 * cm, 4 * cm, 1 * cm,
                    fill=0, stroke=1)
        canvas.setFont(cjk, 11)
        canvas.drawCentredString(A4[0] - 4 * cm, A4[1] - 2.55 * cm,
                                 c.get("confidential", "机密"))
        canvas.restoreState()

    doc = BaseDocTemplate(out_path, pagesize=A4,
                          leftMargin=2 * cm, rightMargin=2 * cm,
                          topMargin=2 * cm, bottomMargin=2 * cm)
    frame_cover = Frame(0, 0, A4[0], A4[1], id="cover")
    frame = Frame(2 * cm, 1.6 * cm, A4[0] - 4 * cm, A4[1] - 3.6 * cm, id="main")
    doc.addPageTemplates([
        PageTemplate(id="Cover", frames=[frame_cover], onPage=_cover),
        PageTemplate(id="Main", frames=[frame], onPage=_decor),
    ])

    story: List[Any] = []
    # 封面
    story.append(Spacer(1, 3 * cm))
    story.append(Paragraph(c.get("company", ""), st_small))
    story.append(Paragraph(c.get("title", "安全报告"), st_cover))
    story.append(Paragraph(c.get("subtitle", ""), st_body))
    story.append(Spacer(1, 6 * cm))
    story.append(Paragraph(f"版本：{c.get('version','')}", st_body))
    story.append(Paragraph(f"生成时间：{c.get('date','')}", st_body))
    story.append(Paragraph(f"保密等级：{c.get('confidential','')}", st_body))
    story.append(NextPageTemplate("Main"))
    story.append(PageBreak())

    # 目录
    story.append(Paragraph("目录", st_h1))
    story.append(Paragraph("1. 执行摘要", st_body))
    for i, s in enumerate(c.get("sections", []), 2):
        story.append(Paragraph(f"{i}. {s.get('heading','章节')}", st_body))
    story.append(Paragraph("附录", st_body))
    story.append(PageBreak())

    # 执行摘要
    story.append(Paragraph("执行摘要", st_h1))
    for line in c.get("executive_summary", []):
        story.append(Paragraph("• " + line, st_body))

    # 图表
    for ch in c.get("charts", []):
        story.append(Paragraph(ch.get("title", "图表"), st_h2))
        img = os.path.join(chart_dir, ch["file"])
        if os.path.exists(img):
            story.append(Image(img, width=15 * cm, height=8 * cm))

    # 章节
    for s in c.get("sections", []):
        story.append(Paragraph(s.get("heading", "章节"), st_h1))
        for p in s.get("paragraphs", []):
            story.append(Paragraph(p, st_body))
        for tbl in s.get("tables", []):
            rows = tbl.get("rows", [])
            if not rows:
                continue
            t = Table(rows, hAlign="LEFT", repeatRows=1)
            t.setStyle(TableStyle([
                ("FONTNAME", (0, 0), (-1, -1), cjk),
                ("FONTSIZE", (0, 0), (-1, -1), 8.5),
                ("BACKGROUND", (0, 0), (-1, 0), primary),
                ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
                ("GRID", (0, 0), (-1, -1), 0.5, colors.HexColor("#ccc")),
                ("ROWBACKGROUNDS", (0, 1), (-1, -1),
                 [colors.white, colors.HexColor("#f3f7fb")]),
                ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
                ("TOPPADDING", (0, 0), (-1, -1), 4),
                ("BOTTOMPADDING", (0, 0), (-1, -1), 4),
            ]))
            story.append(Spacer(1, 4))
            story.append(t)
            story.append(Spacer(1, 6))

    # 附录
    if c.get("appendix"):
        story.append(Paragraph("附录", st_h1))
        for ap in c["appendix"]:
            story.append(Paragraph(ap.get("heading", "附录"), st_h2))
            for p in ap.get("paragraphs", []):
                story.append(Paragraph(p, st_body))

    doc.build(story)


# --------------------------------------------------------------------------- #
# 统一入口
# --------------------------------------------------------------------------- #
def generate(c: Dict[str, Any], tpl: Dict[str, Any], out_dir: str,
             filename: Optional[str] = None) -> Dict[str, Any]:
    """生成 PDF。返回 {path, backend, size_kb, charts}。"""
    os.makedirs(out_dir, exist_ok=True)
    chart_dir = os.path.join(out_dir, "_charts")
    os.makedirs(chart_dir, exist_ok=True)

    # 渲染图表到磁盘
    chart_files: List[str] = []
    for ch in c.get("charts", []):
        kind = ch.get("kind", "bar")
        title = ch.get("title", "图表")
        payload = ch.get("payload", {})
        fn = f"chart_{len(chart_files)}.png"
        cg.render_chart(kind, title, payload, os.path.join(chart_dir, fn))
        ch["file"] = fn
        chart_files.append(fn)

    fname = filename or f"report_{_dt.datetime.now().strftime('%Y%m%d_%H%M%S')}.pdf"
    out_path = os.path.join(out_dir, fname)

    be = backend()
    if be == "weasyprint":
        html = content_to_html(c, tpl, chart_dir)
        from weasyprint import HTML
        HTML(string=html, base_url=out_dir).write_pdf(out_path)
    elif be == "reportlab":
        _reportlab_build(c, tpl, out_path, chart_dir)
    else:
        raise RuntimeError("未安装 weasyprint 与 reportlab，无法生成 PDF。"
                           "请执行: pip install weasyprint 或 pip install reportlab")

    size_kb = round(os.path.getsize(out_path) / 1024, 1)
    return {"path": out_path, "backend": be, "size_kb": size_kb,
            "charts": chart_files, "filename": fname}


def engine_info() -> Dict[str, Any]:
    return {"backend": backend(), "available": ENGINE_AVAILABLE,
            "probe": _PROBE_MSG,
            "cjk_font": cg.cjk_font_name()}
