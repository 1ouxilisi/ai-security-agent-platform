# -*- coding: utf-8 -*-
"""
pdf_styles.py — PDF 统一样式定义。

包含：
    - WEASYPRINT_CSS : 供 weasyprint 的完整 CSS（封面/页眉页脚/水印/表格/代码块）
    - reportlab 字体注册辅助（中文 CID 字体兜底）
"""

from __future__ import annotations

import os
from typing import Any, Dict

# --------------------------------------------------------------------------- #
# weasyprint 用 CSS
# --------------------------------------------------------------------------- #
WEASYPRINT_CSS = """
@page {
  size: A4;
  margin: 2.2cm 2cm 2.4cm 2cm;
  @top-left   { content: string(report-title); font-size: 9px; color:#555; }
  @top-right  { content: string(company-name); font-size: 9px; color:#555; }
  @bottom-left  { content: "机密 - 仅供授权阅读"; font-size: 8px; color:#999; }
  @bottom-center { content: counter(page) " / " counter(pages); font-size: 9px; color:#555; }
}
@page cover { margin: 0; @top-left { content: none; } @top-right { content: none; }
  @bottom-left { content: none; } @bottom-center { content: none; } }
body { font-family: "Microsoft YaHei","SimSun","Source Han Sans SC",sans-serif;
       font-size: 11px; line-height: 1.75; color:#222; }
h1 { string-set: report-title content(); color:#0b5394; font-size: 24px;
     border-bottom: 3px solid #0b5394; padding-bottom:8px; margin-top:24px; }
h2 { color:#0b5394; font-size: 16px; margin-top:18px;
     border-left: 5px solid #4fc3f7; padding-left:8px; }
h3 { color:#333; font-size: 13px; margin-top:14px; }
table { width:100%; border-collapse: collapse; margin:10px 0; font-size:10px; }
th { background:#0b5394; color:#fff; padding:6px 8px; border:1px solid #ccc; }
td { padding:5px 8px; border:1px solid #ccc; }
tr:nth-child(even) td { background:#f3f7fb; }
code, pre { font-family: Consolas,"Courier New",monospace; }
pre { background:#f5f5f5; border:1px solid #ddd; border-left:4px solid #888;
      padding:10px; white-space:pre-wrap; font-size:9.5px; }
.cover { page: cover; height: 297mm; position:relative;
         background: linear-gradient(135deg,#0b5394,#08305a); color:#fff;
         padding: 60px 50px; box-sizing:border-box; }
.cover .badge { font-size:13px; letter-spacing:4px; opacity:.85; }
.cover h1 { color:#fff; border:none; font-size:38px; margin-top:120px; string-set:none; }
.cover .sub { font-size:18px; opacity:.9; margin-top:10px; }
.cover .meta { position:absolute; bottom:70px; left:50px; font-size:12px; line-height:2; }
.cover .conf { position:absolute; top:40px; right:50px; border:2px solid #ffd54f;
               color:#ffd54f; padding:4px 14px; border-radius:4px; letter-spacing:2px; }
.toc { page-break-after: always; }
.toc ul { list-style:none; padding-left:0; }
.toc li { padding:4px 0; border-bottom:1px dotted #bbb; }
img.chart { max-width:90%; display:block; margin:12px auto; }
.sev-critical { color:#b71c1c; font-weight:bold; }
.sev-high { color:#e65100; font-weight:bold; }
.sev-medium { color:#f9a825; }
.sev-low { color:#2e7d32; }
"""


# --------------------------------------------------------------------------- #
# reportlab 中文 CID 字体
# --------------------------------------------------------------------------- #
_FONT_REGISTERED = False


def register_reportlab_fonts() -> Dict[str, str]:
    """注册 reportlab 字体。返回 {"cjk": 字体名, "mono": 等宽字体名}。"""
    global _FONT_REGISTERED
    from reportlab.pdfbase import pdfmetrics
    from reportlab.pdfbase.cidfonts import UnicodeCIDFont

    cjk = "Helvetica"
    mono = "Courier"
    try:
        # Windows 自带 TTF，优先使用，渲染效果好
        for ttf, name in [
            (r"C:\Windows\Fonts\msyh.ttc", "MSYH"),
            (r"C:\Windows\Fonts\msyh.ttf", "MSYH"),
            (r"C:\Windows\Fonts\simhei.ttf", "SimHei"),
        ]:
            if os.path.exists(ttf):
                try:
                    from reportlab.pdfbase.ttfonts import TTFont
                    pdfmetrics.registerFont(TTFont(name, ttf))
                    cjk = name
                    break
                except Exception:
                    continue
    except Exception:
        cjk = "Helvetica"

    # CID 兜底（reportlab 内置，无需文件）
    if cjk == "Helvetica":
        try:
            pdfmetrics.registerFont(UnicodeCIDFont("STSong-Light"))
            cjk = "STSong-Light"
        except Exception:
            cjk = "Helvetica"

    _FONT_REGISTERED = True
    return {"cjk": cjk, "mono": mono}


def default_template_props() -> Dict[str, Any]:
    """默认模板属性。"""
    return {
        "name": "默认企业模板",
        "description": "蓝白主色，A4，含封面/目录/水印",
        "company": "AI Hacking Agent",
        "title": "安全评估报告",
        "subtitle": "专业安全测试与分析",
        "confidential": "机密",
        "watermark": "机密",
        "logo": "",
        "primary_color": "#0b5394",
        "cover_bg": "#0b5394",
        "author": "AI Hacking Agent",
        "version": "v1.0",
    }
