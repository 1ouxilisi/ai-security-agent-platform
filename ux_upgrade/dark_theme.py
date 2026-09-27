# -*- coding: utf-8 -*-
"""
ux_upgrade/dark_theme.py — 暗色主题

专业安全工具风格：#0d1117 背景 / #161b22 卡片 / #58a6ff 强调色。
提供色板、主题切换状态、各组件颜色映射。
"""
from __future__ import annotations

from typing import Any, Dict

# 全局主题状态（内存）
THEME_STATE = {"mode": "dark", "user_id": "default"}

DARK_PALETTE = {
    "name": "dark",
    "background": "#0d1117",
    "card": "#161b22",
    "border": "#30363d",
    "foreground": "#e6edf3",
    "muted": "#8b949e",
    "accent": "#58a6ff",
    "success": "#3fb950",
    "danger": "#f85149",
    "warning": "#ff9800",
    "info": "#ffd33d",
    "semantic": {
        "critical": "#f85149", "high": "#ff9800",
        "medium": "#ffd33d", "low": "#58a6ff", "info": "#8b949e",
    },
}

LIGHT_PALETTE = {
    "name": "light",
    "background": "#ffffff", "card": "#f6f8fa", "border": "#d0d7de",
    "foreground": "#1f2328", "muted": "#57606a", "accent": "#0969da",
    "success": "#1a7f37", "danger": "#cf222e", "warning": "#9a6700",
    "info": "#bf8700",
}


class DarkTheme:
    def palette(self) -> Dict[str, Any]:
        return DARK_PALETTE

    def current(self) -> Dict[str, Any]:
        pal = DARK_PALETTE if THEME_STATE["mode"] == "dark" else LIGHT_PALETTE
        return {"mode": THEME_STATE["mode"], "palette": pal}

    def set_mode(self, mode: str) -> Dict[str, Any]:
        if mode in ("dark", "light"):
            THEME_STATE["mode"] = mode
        return self.current()

    def toggle(self) -> Dict[str, Any]:
        THEME_STATE["mode"] = "light" if THEME_STATE["mode"] == "dark" else "dark"
        return self.current()

    def css_variables(self) -> Dict[str, str]:
        pal = DARK_PALETTE
        return {
            "--bg": pal["background"], "--card": pal["card"],
            "--border": pal["border"], "--fg": pal["foreground"],
            "--muted": pal["muted"], "--accent": pal["accent"],
        }


_theme_singleton: DarkTheme | None = None


def get_dark_theme() -> DarkTheme:
    global _theme_singleton
    if _theme_singleton is None:
        _theme_singleton = DarkTheme()
    return _theme_singleton
