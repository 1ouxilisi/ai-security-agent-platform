# -*- coding: utf-8 -*-
"""
brand_website — 品牌官网落地页模块。

六个核心子模块：
  - content_manager   官网内容管理（页面/编辑器/媒体/导航/多语言/SEO）
  - product_showcase  产品展示与功能介绍
  - pricing_purchase  定价与购买
  - docs_support      文档与支持中心
  - blog_marketing    博客与内容营销
  - brand_dashboard   品牌官网控制台（聚合总览）

全部内存字典模拟，不依赖数据库；可真实生成落地页 HTML。
"""

from __future__ import annotations

__version__ = "21.0.0"

__all__ = [
    "content_manager",
    "product_showcase",
    "pricing_purchase",
    "docs_support",
    "blog_marketing",
    "brand_dashboard",
    "api_routes",
]
