# -*- coding: utf-8 -*-
"""
chart_generator.py — 图表生成（matplotlib），输出 PNG 字节流/文件，供 PDF 嵌入。

支持：趋势图 / 分布图 / 对比图 / 饼图 / 柱状图 / 折线图。
全部返回 PNG 图片路径或字节，无界面 Agg 后端。
"""

from __future__ import annotations

import io
import os
from typing import Any, Dict, List, Optional, Tuple

import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt  # noqa: E402
from matplotlib import font_manager  # noqa: E402

# 中文字体探测：Windows 微软雅黑 / 思源黑体，找不到则用默认并降级
_CJK_CANDIDATES = [
    "Microsoft YaHei", "SimHei", "SimSun",
    "Source Han Sans SC", "Noto Sans CJK SC", "WenQuanYi Zen Hei",
    "PingFang SC", "Heiti SC",
]


def _setup_cjk_font() -> Optional[str]:
    available = {f.name for f in font_manager.fontManager.ttflist}
    for name in _CJK_CANDIDATES:
        if name in available:
            plt.rcParams["font.sans-serif"] = [name]
            plt.rcParams["axes.unicode_minus"] = False
            return name
    plt.rcParams["axes.unicode_minus"] = False
    return None


_CJK_FONT = _setup_cjk_font()

# 统一配色（与深色控制台呼应）
PALETTE = ["#4fc3f7", "#66bb6a", "#ffa726", "#ef5350",
           "#ab47bc", "#26c6da", "#ffca28", "#78909c"]


def _new_fig(figsize: Tuple[float, float] = (7.0, 3.6)):
    fig, ax = plt.subplots(figsize=figsize, dpi=130)
    fig.patch.set_facecolor("white")
    ax.set_facecolor("#fafafa")
    return fig, ax


def _save(fig, out_path: Optional[str] = None) -> Tuple[str, bytes]:
    buf = io.BytesIO()
    fig.tight_layout()
    fig.savefig(buf, format="png", bbox_inches="tight", facecolor="white")
    plt.close(fig)
    data = buf.getvalue()
    if out_path:
        os.makedirs(os.path.dirname(out_path) or ".", exist_ok=True)
        with open(out_path, "wb") as f:
            f.write(data)
        return out_path, data
    return "", data


def trend_chart(title: str, labels: List[str], series: Dict[str, List[float]],
                out_path: Optional[str] = None) -> Tuple[str, bytes]:
    """折线趋势图。series: {名称: [值...]}。"""
    fig, ax = _new_fig()
    x = list(range(len(labels)))
    for i, (name, vals) in enumerate(series.items()):
        ax.plot(x, vals, marker="o", label=name,
                color=PALETTE[i % len(PALETTE)], linewidth=2)
    ax.set_title(title, fontsize=13, fontweight="bold")
    ax.set_xticks(x)
    ax.set_xticklabels(labels, rotation=30, ha="right", fontsize=8)
    ax.grid(True, linestyle="--", alpha=0.4)
    ax.legend(fontsize=8, loc="best")
    return _save(fig, out_path)


def bar_chart(title: str, categories: List[str], values: List[float],
              ylabel: str = "", out_path: Optional[str] = None
              ) -> Tuple[str, bytes]:
    """柱状对比图。"""
    fig, ax = _new_fig()
    bars = ax.bar(categories, values,
                  color=[PALETTE[i % len(PALETTE)] for i in range(len(categories))])
    ax.set_title(title, fontsize=13, fontweight="bold")
    ax.set_ylabel(ylabel)
    ax.grid(True, axis="y", linestyle="--", alpha=0.4)
    for b, v in zip(bars, values):
        ax.text(b.get_x() + b.get_width() / 2, v, str(v),
                ha="center", va="bottom", fontsize=8)
    plt.setp(ax.get_xticklabels(), rotation=30, ha="right", fontsize=8)
    return _save(fig, out_path)


def pie_chart(title: str, labels: List[str], values: List[float],
              out_path: Optional[str] = None) -> Tuple[str, bytes]:
    """分布饼图。"""
    fig, ax = plt.subplots(figsize=(6.0, 3.8), dpi=130)
    fig.patch.set_facecolor("white")
    ax.pie(values, labels=labels, autopct="%1.1f%%",
           colors=[PALETTE[i % len(PALETTE)] for i in range(len(labels))],
           textprops={"fontsize": 9})
    ax.set_title(title, fontsize=13, fontweight="bold")
    return _save(fig, out_path)


def grouped_bar_chart(title: str, categories: List[str],
                      series: Dict[str, List[float]],
                      out_path: Optional[str] = None) -> Tuple[str, bytes]:
    """分组柱状图（多系列对比）。"""
    import numpy as np
    fig, ax = _new_fig()
    x = np.arange(len(categories))
    width = 0.8 / max(len(series), 1)
    for i, (name, vals) in enumerate(series.items()):
        ax.bar(x + i * width - 0.4 + width / 2, vals, width,
               label=name, color=PALETTE[i % len(PALETTE)])
    ax.set_xticks(x)
    ax.set_xticklabels(categories, rotation=30, ha="right", fontsize=8)
    ax.set_title(title, fontsize=13, fontweight="bold")
    ax.grid(True, axis="y", linestyle="--", alpha=0.4)
    ax.legend(fontsize=8)
    return _save(fig, out_path)


def render_chart(kind: str, title: str, payload: Dict[str, Any],
                 out_path: Optional[str] = None) -> Tuple[str, bytes]:
    """统一入口。kind: trend/bar/pie/grouped_bar。"""
    kind = (kind or "bar").lower()
    if kind == "trend":
        return trend_chart(title, payload.get("labels", []),
                           payload.get("series", {}), out_path)
    if kind == "pie":
        return pie_chart(title, payload.get("labels", []),
                         payload.get("values", []), out_path)
    if kind == "grouped_bar":
        return grouped_bar_chart(title, payload.get("labels", []),
                                 payload.get("series", {}), out_path)
    return bar_chart(title, payload.get("labels", []),
                     payload.get("values", []),
                     payload.get("ylabel", ""), out_path)


def cjk_font_name() -> Optional[str]:
    return _CJK_FONT
