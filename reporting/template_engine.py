#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
报告模板引擎 - 9个标准章节的模板渲染

不依赖 Jinja2，基于 string.Template + 简单的条件/循环语法实现。
支持变量替换 {key}、条件片段 {#if key}...{/if}、循环 {#for item in list}...{/for}。
"""
import re
from datetime import datetime
from string import Template
from typing import Any, Dict, List, Optional


# 9个标准章节ID
SECTION_IDS = [
    "cover",
    "toc",
    "executive_summary",
    "target_info",
    "methodology",
    "vuln_details",
    "risk_assessment",
    "remediation",
    "appendix",
]

SECTION_LABELS = {
    "cover": "封面",
    "toc": "目录",
    "executive_summary": "执行摘要",
    "target_info": "目标信息",
    "methodology": "扫描方法",
    "vuln_details": "漏洞详情",
    "risk_assessment": "风险评估",
    "remediation": "修复建议",
    "appendix": "附录",
}


# 默认各章节内容模板（使用 {var} 与 {#if}/{#for} 语法）
_DEFAULT_CONTENT_TEMPLATES: Dict[str, str] = {
    "cover": "",  # 封面由专门函数渲染
    "toc": "",  # 目录由专门函数渲染
    "executive_summary": (
        "<h2>{executive_summary_title}</h2>"
        "<p>本次安全评估总体风险评分为 <strong>{risk_score}</strong> 分。</p>"
        "<p>共发现漏洞 {vuln_total} 个，其中严重 {critical_count}、高危 {high_count}、"
        "中危 {medium_count}、低危 {low_count}。</p>"
        "{#if key_findings}<h3>关键发现</h3><ul>{#for finding in key_findings}"
        "<li>{finding}</li>{/for}</ul>{/if}"
    ),
    "target_info": (
        "<h2>{target_info_title}</h2>"
        "<p>扫描时间：{scan_time}</p>"
        "<h3>目标列表</h3><ul>{#for t in targets}<li>{t}</li>{/for}</ul>"
        "<h3>扫描范围</h3><p>{scan_scope}</p>"
    ),
    "methodology": (
        "<h2>{methodology_title}</h2>"
        "<h3>使用工具</h3><ul>{#for tool in tools}<li>{tool}</li>{/for}</ul>"
        "<h3>测试方法</h3><p>{test_methods}</p>"
        "<h3>测试标准</h3><p>{test_standard}</p>"
    ),
    "vuln_details": (
        "<h2>{vuln_details_title}</h2>"
        "{#for v in vuln_list}"
        "<div class='vuln-item'><h4>[{v.severity}] {v.name}</h4>"
        "<p>目标：{v.target}　位置：{v.location}</p>"
        "<p>{v.description}</p></div>{/for}"
    ),
    "risk_assessment": (
        "<h2>{risk_assessment_title}</h2>"
        "<p>风险矩阵等级：<strong>{risk_level}</strong></p>"
        "<p>总体影响评估：{impact_assessment}</p>"
        "{#if trend_analysis}<h3>趋势分析</h3><p>{trend_analysis}</p>{/if}"
    ),
    "remediation": (
        "<h2>{remediation_title}</h2>"
        "{#for r in remediation_list}"
        "<div class='remedi-item'><h4>优先级 {r.priority}: {r.title}</h4>"
        "<p>{r.action}</p></div>{/for}"
    ),
    "appendix": (
        "<h2>{appendix_title}</h2>"
        "<h3>术语表</h3><p>{glossary}</p>"
        "<h3>参考链接</h3><ul>{#for ref in references}<li>{ref}</li>{/for}</ul>"
        "<h3>工具版本</h3><p>{tool_versions}</p>"
    ),
}


class ReportTemplateEngine:
    """报告模板引擎"""

    # ---------------- 章节管理 ----------------
    def get_default_sections(self) -> List[Dict[str, Any]]:
        """返回9个默认章节定义"""
        try:
            sections = []
            for idx, sid in enumerate(SECTION_IDS):
                sections.append({
                    "section_id": sid,
                    "title": SECTION_LABELS.get(sid, sid),
                    "visible": True,
                    "order": idx + 1,
                    "content_template": _DEFAULT_CONTENT_TEMPLATES.get(sid, ""),
                })
            return sections
        except Exception:
            return []

    # ---------------- 样式控制 ----------------
    def generate_css(self, style_vars: Dict[str, str]) -> str:
        """根据样式变量生成内联CSS"""
        try:
            sv = style_vars or {}
            primary = sv.get("primary_color", "#000000")
            secondary = sv.get("secondary_color", "#666666")
            font_family = sv.get("font_family", "Arial")
            font_size = sv.get("font_size", "12px")
            heading_color = sv.get("heading_color", primary)
            border_color = sv.get("border_color", secondary)
            background = sv.get("background_color", "#FFFFFF")
            page_margin = sv.get("page_margin", "20px")
            css = (
                f"body{{font-family:'{font_family}',Arial,sans-serif;"
                f"font-size:{font_size};color:{heading_color};"
                f"background:{background};margin:{page_margin};}}"
                f"h1,h2,h3{{color:{heading_color};border-bottom:2px solid {primary};}}"
                f"a{{color:{primary};}}"
                f".vuln-item,.remedi-item{{border:1px solid {border_color};"
                f"padding:10px;margin:8px 0;}}"
                f".cover{{text-align:center;padding:80px 20px;}}"
                f".cover h1{{color:{primary};font-size:32px;border:none;}}"
                f".toc li{{margin:4px 0;}}"
            )
            return css
        except Exception:
            return "body{font-family:Arial;}"

    # ---------------- 简单模板语法 ----------------
    def _substitute(self, text: str, data: Dict[str, Any]) -> str:
        """先处理条件与循环，再做 {var} 替换"""
        try:
            text = self._process_loops(text, data)
            text = self._process_conditionals(text, data)
            # string.Template 用 $ 语法，这里我们用自定义 {var} 正则替换
            text = self._replace_vars(text, data)
            return text
        except Exception:
            return text

    def _replace_vars(self, text: str, data: Dict[str, Any]) -> str:
        """替换顶层 {var}"""
        try:
            def repl(m):
                key = m.group(1).strip()
                val = data.get(key, "")
                return "" if val is None else str(val)
            return re.sub(r"\{([a-zA-Z_][a-zA-Z0-9_]*)\}", repl, text)
        except Exception:
            return text

    def _process_conditionals(self, text: str, data: Dict[str, Any]) -> str:
        """处理 {#if key}...{/if}"""
        try:
            pattern = re.compile(r"\{#if\s+([a-zA-Z_][a-zA-Z0-9_]*)\}(.*?)\{/if\}", re.DOTALL)

            def repl(m):
                key = m.group(1)
                inner = m.group(2)
                val = data.get(key)
                if val:
                    return self._replace_vars(inner, data)
                return ""
            # 反复处理嵌套
            prev = None
            while prev != text:
                prev = text
                text = pattern.sub(repl, text)
            return text
        except Exception:
            return text

    def _process_loops(self, text: str, data: Dict[str, Any]) -> str:
        """处理 {#for item in list}...{/for}，支持 {item.field}"""
        try:
            pattern = re.compile(
                r"\{#for\s+([a-zA-Z_][a-zA-Z0-9_]*)\s+in\s+"
                r"([a-zA-Z_][a-zA-Z0-9_]*)\}(.*?)\{/for\}",
                re.DOTALL,
            )

            def repl(m):
                item_var = m.group(1)
                list_name = m.group(2)
                inner = m.group(3)
                items = data.get(list_name)
                if not isinstance(items, (list, tuple)):
                    return ""
                out_parts = []
                for item in items:
                    seg = inner
                    # 支持 {item_var} 和 {item_var.field}
                    if isinstance(item, dict):
                        for fk, fv in item.items():
                            seg = seg.replace("{%s.%s}" % (item_var, fk),
                                              "" if fv is None else str(fv))
                    seg = seg.replace("{%s}" % item_var, str(item))
                    out_parts.append(seg)
                return "".join(out_parts)
            prev = None
            while prev != text:
                prev = text
                text = pattern.sub(repl, text)
            return text
        except Exception:
            return text

    # ---------------- 封面 / 目录 ----------------
    def render_cover(self, data: Dict[str, Any], style_vars: Dict[str, str]) -> str:
        """渲染封面HTML"""
        try:
            sv = style_vars or {}
            primary = sv.get("primary_color", "#000000")
            logo = data.get("logo_html") or (
                f"<div style='color:{primary};font-size:40px;'>&#9673;</div>"
            )
            return (
                "<div class='cover'>"
                f"{logo}"
                f"<h1>{data.get('project_name', '安全评估报告')}</h1>"
                f"<h2 style='color:{sv.get('secondary_color', '#666666')};'>"
                f"{data.get('client_name', '')}</h2>"
                f"<p>扫描日期：{data.get('scan_date', '')}</p>"
                f"<p>扫描人员：{data.get('analyst', '')}</p>"
                f"<p>版本：v{data.get('version', '1.0')}</p>"
                f"<p style='margin-top:40px;color:{sv.get('secondary_color', '#666666')};'>"
                f"{data.get('confidentiality', '保密声明：本报告含敏感信息，未经授权不得传播。')}</p>"
                "</div>"
            )
        except Exception:
            return "<div class='cover'></div>"

    def render_toc(self, sections: List[Dict[str, Any]]) -> str:
        """根据可见章节生成目录HTML"""
        try:
            ordered = self.sort_sections(sections)
            items = []
            for s in ordered:
                if s.get("visible", True):
                    items.append(f"<li>{s.get('order', '')}. {s.get('title', s.get('section_id',''))}</li>")
            return "<div class='toc'><h2>目录</h2><ul>" + "".join(items) + "</ul></div>"
        except Exception:
            return "<div class='toc'></div>"

    # ---------------- 排序 ----------------
    def sort_sections(self, sections: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """根据 order 字段排序"""
        try:
            return sorted(sections, key=lambda s: s.get("order", 999))
        except Exception:
            return sections or []

    # ---------------- 章节渲染 ----------------
    def render_section(self, section: Dict[str, Any], data: Dict[str, Any]) -> str:
        """渲染单个章节"""
        try:
            sid = section.get("section_id", "")
            if sid == "cover":
                return self.render_cover(data, data.get("_style_vars", {}))
            if sid == "toc":
                return self.render_toc(data.get("_all_sections", self.get_default_sections()))
            tmpl = section.get("content_template", "")
            # 补充标题变量
            ctx = dict(data)
            ctx.setdefault("%s_title" % sid, section.get("title", sid))
            return self._substitute(tmpl, ctx)
        except Exception:
            return ""

    def render_report(self, template_config: Dict[str, Any], data: Dict[str, Any]) -> Dict[str, str]:
        """渲染完整报告，返回各章节内容字典 {section_id: html}"""
        try:
            style_vars = (template_config or {}).get("style_vars", {}) or {}
            data = dict(data)
            data["_style_vars"] = style_vars
            sections = (template_config or {}).get("sections") or self.get_default_sections()
            data["_all_sections"] = sections
            ordered = self.sort_sections(sections)

            # 预计算统计
            vuln_list = data.get("vuln_list") or []
            sev_map = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
            for v in vuln_list:
                if isinstance(v, dict):
                    sev = str(v.get("severity", "")).lower()
                    if sev in sev_map:
                        sev_map[sev] += 1
            data.setdefault("vuln_total", len(vuln_list))
            data.setdefault("critical_count", sev_map["critical"])
            data.setdefault("high_count", sev_map["high"])
            data.setdefault("medium_count", sev_map["medium"])
            data.setdefault("low_count", sev_map["low"])
            data.setdefault("scan_date", datetime.now().strftime("%Y-%m-%d"))
            data.setdefault("scan_time", datetime.now().strftime("%Y-%m-%d %H:%M"))

            result: Dict[str, str] = {}
            for sec in ordered:
                try:
                    if sec.get("visible", True):
                        result[sec.get("section_id")] = self.render_section(sec, data)
                except Exception:
                    result[sec.get("section_id")] = ""
            return result
        except Exception:
            return {}


# 便捷模块级单例
_engine = ReportTemplateEngine()


def get_default_sections() -> List[Dict[str, Any]]:
    return _engine.get_default_sections()


def render_report(template_config: Dict[str, Any], data: Dict[str, Any]) -> Dict[str, str]:
    return _engine.render_report(template_config, data)


def render_section(section: Dict[str, Any], data: Dict[str, Any]) -> str:
    return _engine.render_section(section, data)
