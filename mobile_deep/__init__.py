# -*- coding: utf-8 -*-
"""
mobile_deep — 专业级移动 APK 深度分析模块（第20轮升级 方向3）。

子模块：
    apk_deep_parser     APK 结构 / DEX / Manifest / 资源 / 反编译 / 原生库
    security_vuln_detector  组件 / 存储 / 网络 / 代码 / 权限 / WebView 漏洞检测
    privacy_compliance  个人信息 / 第三方SDK / 隐私政策 / 跨境 / 儿童隐私 / 合规报告
    malware_analysis    静态行为 / 网络 / 数据窃取 / 支付欺诈 / 持久化 / 家族分类
    dynamic_analysis    行为监控 / 内存 / 流量 / Frida / UI自动化 / 动态报告
    mobile_dashboard    APK库 / 任务 / 漏洞管理 / 合规 / 恶意分析 / 报告

方向3（移动安全深度做实）新增：
    apk_deep_analyzer       APK 深度画像（包名/版本/权限/组件/签名/资源）
    static_code_scanner     Smali/DEX 静态扫描（硬编码密钥/不安全API）
    permission_risk_rater   基于 CVSS 的权限风险打分
    vuln_detector           WebView/日志/备份/导出组件/不安全存储
    dynamic_framework       Frida/objection 集成框架
    mobile_deep_dashboard   控制台聚合

设计原则：仅用于授权的安全分析 / 检测 / 评估，全部为防御与加固视角。
第三方工具（jadx / apktool / dex2jar / frida 等）try-import，缺失时回退模拟数据。
"""
from __future__ import annotations

__version__ = "33.1.0"
__all__ = [
    "apk_deep_parser",
    "security_vuln_detector",
    "privacy_compliance",
    "malware_analysis",
    "dynamic_analysis",
    "mobile_dashboard",
    "apk_deep_analyzer",
    "static_code_scanner",
    "permission_risk_rater",
    "vuln_detector",
    "dynamic_framework",
    "mobile_deep_dashboard",
]

try:  # noqa: SIM105
    from . import apk_deep_analyzer, static_code_scanner, permission_risk_rater  # noqa: F401
    from . import vuln_detector, dynamic_framework, mobile_deep_dashboard  # noqa: F401
except Exception:
    pass
