# -*- coding: utf-8 -*-
"""
demo_mode — 一键 Demo 模式包（第22轮升级方向1）。

子模块：
    - demo_dataset       Demo 数据集管理（场景库 / 生成 / 导入导出 / 重置 / 定制 / 统计）
    - demo_engine        自动演示引擎（脚本 / 执行 / 控制 / 录制 / 旁白 / 交互）
    - interactive_guide  交互式引导（新手 / 功能 / 场景 / 引导管理 / 提示 / 帮助中心）
    - quick_experience   3 分钟快速体验（流程 / 场景 / 引导 / 数据 / 转化 / 分析）
    - demo_branding      Demo 品牌定制（品牌 / 白标 / 模板 / 分享 / 嵌入 / 分析）
    - demo_dashboard     Demo 管理控制台（总览 / 管理 / 演示 / 引导 / 分析 / 设置）

设计原则：
    - 全部内存字典模拟，不建数据库表
    - 第三方库 try-import，缺失时回退模拟
    - 统一对外提供纯函数 / 字典读写，供 api_server/demo_mode_routes.py 调用
"""

from __future__ import annotations

__version__ = "22.1.0"
__all__ = [
    "demo_dataset",
    "demo_engine",
    "interactive_guide",
    "quick_experience",
    "demo_branding",
    "demo_dashboard",
]
