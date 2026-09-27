# -*- coding: utf-8 -*-
"""
mobile_security_deep — 移动端安全深度分析平台（第29轮升级方向2）。

覆盖三大移动生态：
    - Android 深度安全（android_deep）：Manifest/组件/存储/网络/代码/运行时
    - iOS 深度安全（ios_deep）：Info.plist/Keychain/ATS/代码/运行时防护
    - 鸿蒙深度安全（harmonyos_deep）：HAP/分布式安全/ArkTS 代码安全
    - 移动漏洞库与 POC（mobile_vuln_poc）：CVE/CNVD 漏洞库 + POC/EXP
    - 移动隐私合规（privacy_compliance）：个人信息识别/SDK 合规/权限/跨境
    - 移动安全测试与评测（mobile_test_eval）：静态/动态测试/评分/标准
    - 移动安全深度控制台（mobile_security_dashboard）：数据聚合层

设计定位：纯内存模拟 + 真实静态分析能力（Manifest/Info.plist/HAP 包结构
解析、组件暴露识别、硬编码密钥检测、个人信息正则识别、SDK 行为库匹配）。
所有分析对授权安全测试场景生效。
"""

from __future__ import annotations

__version__ = "29.2.0"
__round__ = 29
__direction__ = "移动端安全深度（iOS+Android+鸿蒙）"

__all__ = [
    "android_deep",
    "ios_deep",
    "harmonyos_deep",
    "mobile_vuln_poc",
    "privacy_compliance",
    "mobile_test_eval",
    "mobile_security_dashboard",
]
