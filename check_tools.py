#!/usr/bin/env python3
"""安全工具安装状态检查与诊断脚本。

用法: python check_tools.py
功能: 检查5个安全工具的安装状态，显示安装建议，验证配置文件
"""
import os
import sys
import json

# 切换到项目根目录
os.chdir(os.path.dirname(os.path.abspath(__file__)))

# 添加项目路径
sys.path.insert(0, os.getcwd())

from tools.integration import tool_manager, _load_tools_config, _CONFIG_PATH


def main():
    print("=" * 70)
    print("  AI Hacking Agent - 安全工具状态诊断")
    print("=" * 70)
    
    # 1. 工具状态
    print("\n【1】工具安装状态")
    print("-" * 70)
    status = tool_manager.get_tool_status()
    
    for tool in status["tools"]:
        avail_icon = "✅" if tool["available"] else "❌"
        enabled_icon = "🔓" if tool["enabled"] else "🚫"
        path_info = tool["path"] or "未找到"
        wrapper_info = f" (包装器: {tool['wrapper']})" if tool["wrapper"] else ""
        print(f"  {avail_icon} {enabled_icon} {tool['name']:10s} -> {path_info}{wrapper_info}")
    
    print(f"\n  总计: {status['total_tools']} 个工具")
    print(f"  已安装: {status['available_tools']} 个")
    print(f"  未安装: {status['missing_tools']} 个")
    
    # 2. 配置文件
    print("\n【2】工具配置文件")
    print("-" * 70)
    print(f"  配置文件路径: {_CONFIG_PATH}")
    print(f"  配置文件存在: {'✅ 是' if os.path.exists(_CONFIG_PATH) else '❌ 否'}")
    
    if os.path.exists(_CONFIG_PATH):
        config = _load_tools_config()
        configured_tools = list(config.get("tools", {}).keys())
        print(f"  已配置工具: {', '.join(configured_tools)}")
    
    # 3. 依赖环境
    print("\n【3】依赖环境检查")
    print("-" * 70)
    from shutil import which
    deps = {
        "Python": which("python"),
        "Git": which("git"),
        "Perl": which("perl"),
        "Nmap": which("nmap"),
        "Nuclei": which("nuclei"),
    }
    for name, path in deps.items():
        icon = "✅" if path else "❌"
        print(f"  {icon} {name:10s} -> {path or '未安装'}")
    
    # 4. 安装建议
    print("\n【4】安装建议")
    print("-" * 70)
    diagnosis = tool_manager.run_quick_diagnosis()
    print(f"  建议: {diagnosis['recommendation']}")
    
    if diagnosis["install_guides"]["missing_count"] > 0:
        print("\n  缺失工具安装指南:")
        for tool in diagnosis["install_guides"]["tools"]:
            print(f"\n  📦 {tool['name']}:")
            if tool["guide"]:
                if os.name == "nt":
                    print(f"     Windows:")
                    for line in tool["guide"]["windows"].split("\n"):
                        print(f"       {line}")
                else:
                    print(f"     Linux: {tool['guide']['linux']}")
    
    # 5. 一键安装脚本
    print("\n【5】一键安装")
    print("-" * 70)
    install_script = os.path.join(os.getcwd(), "install_tools.bat")
    if os.path.exists(install_script):
        print(f"  ✅ 安装脚本已存在: {install_script}")
        print(f"  运行方式: 双击 install_tools.bat 或在命令行执行")
        print(f"  支持自动安装: sqlmap / Strawberry Perl / nikto")
        print(f"  masscan 需手动配置 (推荐WSL)")
    else:
        print(f"  ❌ 安装脚本不存在")
    
    # 6. 手动配置方式
    print("\n【6】手动配置方式")
    print("-" * 70)
    print("  如果自动安装失败，可手动配置:")
    print("  1. 下载工具到任意目录")
    print(f"  2. 编辑配置文件: {_CONFIG_PATH}")
    print("  3. 在对应工具的 path 或 windows_path 中填写完整路径")
    print("  4. 对于Python/Perl工具，设置 wrapper 字段 (如 python/perl)")
    print("  5. 重新运行此脚本验证")
    
    # 总结
    print("\n" + "=" * 70)
    if status["available_tools"] == status["total_tools"]:
        print("  🎉 所有安全工具已安装，环境完整！")
    else:
        print(f"  ⚠️  有 {status['missing_tools']} 个工具未安装")
        print("  核心工具 (nmap/nuclei) 已可用，不影响基础功能")
        print("  运行 install_tools.bat 可自动安装其余工具")
    print("=" * 70 + "\n")
    
    # 保存诊断报告
    report = {
        "check_time": __import__("datetime").datetime.now().isoformat(),
        "tool_status": status,
        "dependencies": deps,
        "recommendation": diagnosis["recommendation"],
        "config_file": _CONFIG_PATH
    }
    try:
        with open("data/tool_diagnosis.json", "w", encoding="utf-8") as f:
            json.dump(report, f, ensure_ascii=False, indent=2)
        print("  📄 诊断报告已保存: data/tool_diagnosis.json")
    except Exception:
        pass


if __name__ == "__main__":
    main()
