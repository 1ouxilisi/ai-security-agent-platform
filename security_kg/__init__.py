# -*- coding: utf-8 -*-
"""
security_kg — 安全知识图谱与智能推理平台（第27轮升级方向1）。

模块清单：
    kg_builder        安全知识图谱构建（实体/关系/融合/对齐/补全/清洗/验证/存储/更新/质量）
    attack_path       攻击路径推理（攻击图/攻击树/杀伤链/A*搜索/路径分析/预测/可视化）
    vuln_correlation  漏洞关联分析（关联/传播/影响/优先级/趋势/知识库）
    threat_propagation 威胁传播建模（SIR/SEIR/网络传播/蒙特卡洛模拟/阻断策略）
    reasoning_engine  知识推理引擎（规则/演绎归纳/前后向链/多跳/不确定性/可解释）
    kg_qa             智能问答系统（检索/答案生成/审核/统计/知识库）
    kg_dashboard      数据聚合层（总览/统计/质量/活动）
"""
from __future__ import annotations

__version__ = "27.1.0"
__all__ = [
    "kg_builder",
    "attack_path",
    "vuln_correlation",
    "threat_propagation",
    "reasoning_engine",
    "kg_qa",
    "kg_dashboard",
]
