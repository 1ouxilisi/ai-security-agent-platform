# -*- coding: utf-8 -*-
"""被 install_all_tools_v2.bat 调用：列出已装/缺失工具，输出供 bat 写入报告。"""
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from tools.tool_installer import ToolInstaller

if __name__ == "__main__":
    inst = ToolInstaller()
    rep = inst.generate_install_report()
    print("=" * 60)
    print(f"工具安装状态检测  {rep['generated_at']}")
    print("=" * 60)
    print(f"总计: {rep['total']}  已安装: {rep['installed_count']}  "
          f"缺失: {rep['missing_count']}")
    print("已安装:", ", ".join(rep["installed"]) or "无")
    print("缺  失:", ", ".join(rep["missing"]) or "无")
    for k, v in rep["details"].items():
        flag = "[OK]" if v.get("installed") else "[--]"
        print(f"  {flag} {k:18s} {v.get('version', ''):10s} {v.get('error', '')}")
