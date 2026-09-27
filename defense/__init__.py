# -*- coding: utf-8 -*-
"""
防御侧安全模块（Defense Module）

将项目从纯攻击评估升级为攻防兼备。本包仅包含防御 / 检测 / 评估视角的能力：
    - ids_engine          入侵检测引擎（基于规则，类 Suricata/Snort 语法）
    - log_analyzer        日志解析与异常检测
    - baseline_checker    安全配置基线检查（Web/OS/DB/容器）
    - remediation_verifier 漏洞修复验证
    - threat_hunting      威胁狩猎引擎

重要约束：
    - 所有检测逻辑为纯 Python 实现，不包含真实攻击工具代码。
    - 不依赖 scapy 等外部库，PCAP 分析为文本格式基础版。
    - 告警/结果统一以 dict 返回，便于 JSON 序列化。
"""

__version__ = "1.0.0"
__all__ = [
    "ids_engine",
    "log_analyzer",
    "baseline_checker",
    "remediation_verifier",
    "threat_hunting",
]
