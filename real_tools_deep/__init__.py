# -*- coding: utf-8 -*-
"""
real_tools_deep — 第28轮升级方向1：真实工具集成深度增强。

定位：仅用于经过授权的网络安全评估与渗透测试环境。
所有模块输出检测报告、风险评级与修复建议，不包含任何可直接用于
未授权攻击的完整利用代码。

包含：
- nmap_deep: Nmap 深度集成（命令构建/XML解析/报告生成/工具管理）
- sqlmap_deep: SQLMap 深度集成（注入检测/数据提取/Shell/报告）
- metasploit_deep: Metasploit 深度集成（msfconsole/msfrpcd/模块/会话）
- other_tools: Nikto/Hydra/John/nuclei 集成
- tool_orchestration: 工具编排与工作流引擎
- real_tools_dashboard: 控制台数据聚合层
"""

from __future__ import annotations

__version__ = "28.1.0"
__all__ = [
    "nmap_deep",
    "sqlmap_deep",
    "metasploit_deep",
    "other_tools",
    "tool_orchestration",
    "real_tools_dashboard",
]
