#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
移动安全AI模型模块

借鉴架构：
- A2 (a2-android.github.io): 智能体漏洞发现 + 多模态验证
- Thorfinn (PhonePe): APK逆向 + 污点流追踪 + 动态利用
- Decepticon mobile-android: 15类移动端漏洞检测

核心能力：
1. APK静态分析 - Manifest解析、权限分析、组件暴露检测
2. AI驱动漏洞检测 - 15类移动端漏洞模式识别
3. 污点流分析 - Source→Sink数据流追踪
4. 动态分析规划 - Frida Hook方案生成
5. 漏洞验证计划 - 多模态攻击面验证
"""

from .apk_parser import APKParser, get_apk_parser, APKInfo
from .vulnerability_scanner import MobileVulnerabilityScanner, get_mobile_vulnerability_scanner, Vulnerability, Severity
from .mobile_ai_analyzer import (
    MobileAIAnalyzer,
    MobileVulnerability as AIVuln,
    MobileSeverity,
    get_mobile_analyzer,
)

__all__ = [
    'APKParser',
    'get_apk_parser',
    'APKInfo',
    'MobileVulnerabilityScanner',
    'get_mobile_vulnerability_scanner',
    'Vulnerability',
    'Severity',
    'MobileAIAnalyzer',
    'AIVuln',
    'MobileSeverity',
    'get_mobile_analyzer',
]

__version__ = "2.0.0"
