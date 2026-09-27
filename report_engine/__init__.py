# -*- coding: utf-8 -*-
"""report_engine — 专业报告引擎（第14轮升级方向3）。

包含7个核心模块：
- template_library       模板库（行业/类型/CRUD/版本/导入导出）
- smart_generator        智能报告生成（数据填充/风险评级/摘要/图表/证据链）
- quality_checker        报告质量校验（完整性/一致性/评分/查重）
- multi_format_export    多格式导出（PDF/Word/HTML/MD/JSON/Excel/CSV）
- collaboration_approval 协作审批（版本/diff/审批流/签名/归档）
- report_analytics        报告管理与分析（库/搜索/统计/仪表盘）
- report_workflow        综合工作流（模板→数据→生成→质检→审批→导出→归档）
"""

from __future__ import annotations

__version__ = "14.3.0"
__all__ = [
    "template_library",
    "smart_generator",
    "quality_checker",
    "multi_format_export",
    "collaboration_approval",
    "report_analytics",
    "report_workflow",
]
