# -*- coding: utf-8 -*-
"""动态分析：检测 frida/objection/adb，可用则做基础动态操作；不可用明确提示。"""
from __future__ import annotations

import shutil
from typing import Any, Dict, List


class DynamicAnalyzer:
    def __init__(self) -> None:
        self.tools = {
            "frida": shutil.which("frida"),
            "objection": shutil.which("objection"),
            "adb": shutil.which("adb"),
        }

    def status(self) -> Dict[str, Any]:
        return {
            "available": bool(self.tools["adb"]),
            "tools": self.tools,
            "note": "adb 可用时可做基础动态分析；frida/objection 用于 hook。" if self.tools["adb"]
                    else "未检测到 adb/frida/objection，动态分析不可用。请安装 platform-tools 与 pip install objection frida-tools。",
        }

    def list_devices(self) -> Dict[str, Any]:
        if not self.tools["adb"]:
            return {"success": False, "error": "adb 未安装"}
        import subprocess
        try:
            out = subprocess.run(["adb", "devices"], capture_output=True, text=True, timeout=30)
            return {"success": True, "data": out.stdout}
        except Exception as e:  # noqa: BLE001
            return {"success": False, "error": str(e)}

    def start_objection(self, package: str) -> Dict[str, Any]:
        if not self.tools["objection"]:
            return {"success": False, "error": "objection 未安装，无法启动动态探索。pip install objection"}
        return {"success": True, "data": f"请在终端执行: objection -g {package} explore",
                "note": "objection 需连接 root 或Frida-gadget 设备"}
