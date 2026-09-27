# -*- coding: utf-8 -*-
"""
interactive_tutorial — 交互式教程与实战演练模块包。

第21轮升级方向4：交互式教程。
本包提供6大核心能力：
  1. tutorial_content   — 教程内容管理（创建/结构/编辑器/模板/分类/版本）
  2. interactive_env    — 交互式学习环境（终端/代码/浏览器/API/DB/沙箱）
  3. learning_path      — 学习路径与课程（路径/课程/章节/知识点/练习/项目）
  4. progress_evaluation— 学习进度与评估（进度/掌握度/测验/证书/分析/报告）
  5. scenario_practice — 场景化实战演练（真实场景/配置/引导/自由/攻防/评估）
  6. tutorial_dashboard— 运营控制台（总览/教程/学习/内容/评估/设置）

全部基于内存字典模拟，不依赖任何数据库表；第三方库 try-import，缺失即回退模拟。
"""

from __future__ import annotations

__version__ = "21.4.0"
__all__ = [
    "tutorial_content",
    "interactive_env",
    "learning_path",
    "progress_evaluation",
    "scenario_practice",
    "tutorial_dashboard",
]
