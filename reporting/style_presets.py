#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
报告样式预设库 - 5套预定义样式

样式变量:
primary_color / secondary_color / font_family / font_size /
heading_color / border_color / background_color /
header_style / footer_style / page_margin
"""
from typing import Any, Dict, List


_PRESETS: Dict[str, Dict[str, Any]] = {
    "classic_bw": {
        "preset_id": "classic_bw",
        "name": "经典黑白",
        "description": "简洁黑白风格，正式通用",
        "style_vars": {
            "primary_color": "#000000",
            "secondary_color": "#666666",
            "font_family": "Arial",
            "font_size": "12px",
            "heading_color": "#000000",
            "border_color": "#CCCCCC",
            "background_color": "#FFFFFF",
            "header_style": "plain",
            "footer_style": "plain",
            "page_margin": "20px",
        },
    },
    "tech_blue": {
        "preset_id": "tech_blue",
        "name": "科技蓝",
        "description": "科技感蓝色调，技术报告",
        "style_vars": {
            "primary_color": "#0066CC",
            "secondary_color": "#00A0FF",
            "font_family": "Segoe UI",
            "font_size": "12px",
            "heading_color": "#003366",
            "border_color": "#00A0FF",
            "background_color": "#F5FAFF",
            "header_style": "gradient",
            "footer_style": "gradient",
            "page_margin": "24px",
        },
    },
    "security_red": {
        "preset_id": "security_red",
        "name": "安全红",
        "description": "红色警示风格，突出风险",
        "style_vars": {
            "primary_color": "#CC0000",
            "secondary_color": "#FF4444",
            "font_family": "Arial",
            "font_size": "12px",
            "heading_color": "#8B0000",
            "border_color": "#FF4444",
            "background_color": "#FFF8F8",
            "header_style": "warning",
            "footer_style": "warning",
            "page_margin": "20px",
        },
    },
    "business_gray": {
        "preset_id": "business_gray",
        "name": "商务灰",
        "description": "商务灰色调，管理层汇报",
        "style_vars": {
            "primary_color": "#4A4A4A",
            "secondary_color": "#888888",
            "font_family": "Helvetica",
            "font_size": "11px",
            "heading_color": "#2C2C2C",
            "border_color": "#BBBBBB",
            "background_color": "#FAFAFA",
            "header_style": "business",
            "footer_style": "business",
            "page_margin": "28px",
        },
    },
    "custom": {
        "preset_id": "custom",
        "name": "自定义",
        "description": "用户自定义所有样式变量",
        "style_vars": {
            "primary_color": "#333333",
            "secondary_color": "#888888",
            "font_family": "Arial",
            "font_size": "12px",
            "heading_color": "#333333",
            "border_color": "#CCCCCC",
            "background_color": "#FFFFFF",
            "header_style": "plain",
            "footer_style": "plain",
            "page_margin": "20px",
        },
    },
}


def list_presets() -> List[Dict[str, Any]]:
    """返回5个预设概要"""
    try:
        return [
            {
                "preset_id": p["preset_id"],
                "name": p["name"],
                "description": p["description"],
                "primary_color": p["style_vars"]["primary_color"],
                "secondary_color": p["style_vars"]["secondary_color"],
            }
            for p in _PRESETS.values()
        ]
    except Exception:
        return []


def get_preset(preset_id: str) -> Dict[str, Any]:
    """返回预设完整样式变量，未知ID回退到custom"""
    try:
        p = _PRESETS.get(preset_id)
        if not p:
            p = _PRESETS["custom"]
        return {
            "preset_id": p["preset_id"],
            "name": p["name"],
            "description": p["description"],
            "style_vars": dict(p["style_vars"]),
        }
    except Exception:
        return {"preset_id": "custom", "name": "自定义", "style_vars": {}}


def apply_preset(template_config: Dict[str, Any], preset_id: str) -> Dict[str, Any]:
    """将样式预设应用到模板配置，返回更新后的配置"""
    try:
        cfg = dict(template_config or {})
        preset = get_preset(preset_id)
        cfg["style_vars"] = dict(preset["style_vars"])
        cfg["style_preset"] = preset_id
        return cfg
    except Exception:
        return template_config or {}


def generate_css(style_vars: Dict[str, str]) -> str:
    """根据样式变量生成CSS字符串"""
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
        return (
            f"body{{font-family:'{font_family}',Arial,sans-serif;"
            f"font-size:{font_size};color:{heading_color};"
            f"background:{background};margin:{page_margin};}}"
            f"h1,h2,h3{{color:{heading_color};border-bottom:2px solid {primary};}}"
            f"a{{color:{primary};}}"
            f".box{{border:1px solid {border_color};padding:10px;margin:8px 0;}}"
        )
    except Exception:
        return "body{font-family:Arial;}"
