# -*- coding: utf-8 -*-
import os, sys
ROOT = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, ROOT)
from tools.integration import tool_integration, tool_health_checker, ToolHealthChecker
print("integration import OK, tools=", tool_integration.list_tools())
r = tool_health_checker.get_health_report()
print("health total=", r["total"], "available=", r["available_count"],
      "unavailable=", r["unavailable_count"])
# 验证 fallback 函数
from tools.integration import _fallback_result, tool_is_available, tool_install_guide
fb = _fallback_result("nmap", "test")
print("fallback status=", fb["status"])
print("nmap available=", tool_is_available("nmap"))
print("guide sample=", tool_install_guide("nmap")[:40])
