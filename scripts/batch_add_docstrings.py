#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
batch_add_docstrings脚本工具模块，提供相关的命令行工具和自动化脚本。

模块功能：
    - 提供相关安全测试功能
    - 支持API调用和命令行使用
    - 与其他模块集成协作

注意事项：
    - 本模块仅用于授权的安全测试
    - 请勿用于非法用途
    - 使用前请确保已获得相关授权
"""
import os
import sys
import ast
import re

sys.path.insert(0, '.')

# 需要处理的文件列表
TARGET_FILES = [
    'internal/smb_scanner.py',
    'internal/ldap_query.py',
    'internal/kerberos.py',
    'internal/hash_pass.py',
    'internal/lateral_movement.py',
    'internal/port_forward.py',
    'internal/dns_enum.py',
    'internal/ad_assessment.py',
    'exploit/payload_generator.py',
    'exploit/post_exploitation.py',
    'exploit/metasploit.py',
    'exploit/poc_library.py',
    'distributed/scheduler.py',
    'distributed/worker_node.py',
    'distributed/result_aggregator.py',
    'distributed/proxy_pool.py',
    'tools/network_scanners.py',
    'tools/directory_bruteforce.py',
    'tools/password_attacks.py',
    'tools/web_scanners.py',
    'tools/tool_manager.py',
    'api_server/internal_routes.py',
    'api_server/exploit_routes.py',
    'api_server/tools_routes.py',
    'api_server/distributed_routes.py',
]

def has_docstring(node):
    """检查节点是否有文档字符串"""
    if not node.body:
        return False
    first = node.body[0]
    if isinstance(first, ast.Expr) and isinstance(first.value, (ast.Constant, ast.Str)):
        return True
    return False

def generate_class_docstring(node, module_name):
    """生成类文档字符串"""
    class_name = node.name
    bases = [ast.unparse(b) for b in node.bases] if hasattr(node, 'bases') else []

    # 根据类名生成描述
    descriptions = {
        'SMBScanner': 'SMB协议扫描器，支持共享枚举、空会话测试和SMB漏洞检测。',
        'LDAPQuerier': 'LDAP/AD查询器，支持用户、计算机、组、GPO等多种对象查询。',
        'KerberosTools': 'Kerberos攻击工具集，支持Kerberoasting、AS-REP Roasting、黄金票据等。',
        'HashPasser': '哈希传递工具，支持SMB、RDP、WinRM、WMI、MSSQL等多种协议。',
        'LateralMover': '横向移动工具，支持PsExec、WMI、WinRM、DCOM、SSH等多种方法。',
        'PortForwarder': '端口转发与隧道工具，支持本地转发、远程转发和动态隧道。',
        'DNSEnumerator': 'DNS枚举工具，支持子域名爆破、记录查询、区域传输测试。',
        'ADAssessor': 'Active Directory安全评估器，检测AD配置漏洞和攻击路径。',
        'PayloadGenerator': 'Payload生成器，支持9种语言的反向Shell、WebShell、持久化等。',
        'PostExploitation': '后渗透模块，支持信息收集、凭证转储、权限提升、痕迹清除。',
        'MetasploitClient': 'Metasploit RPC API客户端，支持模块列表、任务执行和会话管理。',
        'POCLibrary': 'PoC漏洞验证脚本库，支持分类管理、搜索和执行。',
        'DistributedScheduler': '分布式任务调度器，支持优先级队列、依赖管理和负载均衡。',
        'WorkerManager': '工作节点管理器，支持节点注册、心跳监控和负载分配。',
        'ResultAggregator': '结果汇总器，支持多节点扫描结果合并、漏洞去重和风险评分。',
        'ProxyPool': '代理池管理器，支持多种代理类型、健康检查和轮换策略。',
        'NmapAdvanced': 'Nmap高级扫描器，支持7种扫描类型和服务版本探测。',
        'MasscanScanner': 'Masscan高速端口扫描器，支持大规模网段快速扫描。',
        'Gobuster': 'Gobuster目录爆破工具，支持目录、文件和DNS子域名爆破。',
        'FFuF': 'FFuF模糊测试工具，支持高速目录和参数模糊测试。',
        'Dirsearch': 'Dirsearch目录扫描工具，支持递归扫描和多种扩展名。',
        'Hydra': 'Hydra在线暴力破解工具，支持12种服务协议。',
        'JohnTheRipper': 'John the Ripper密码破解工具，支持多种哈希算法。',
        'HashIdentifier': '哈希类型识别工具，支持50+种哈希算法识别。',
        'Nikto': 'Nikto Web服务器漏洞扫描器。',
        'WhatWeb': 'WhatWeb技术指纹识别工具。',
        'WPScan': 'WPScan WordPress安全扫描器。',
        'ToolManager': '安全工具管理器，支持57+工具的统一管理和调用。',
    }

    desc = descriptions.get(class_name, f'{class_name}类，提供相关功能封装。')

    docstring = f'    """{desc}\n\n'
    docstring += f'    Attributes:\n'
    docstring += f'        各类实例属性，具体见__init__方法。\n'
    docstring += f'    """\n'

    return docstring

def generate_function_docstring(node, class_name=None):
    """生成函数文档字符串"""
    func_name = node.name
    args = [a.arg for a in node.args.args if a.arg != 'self'] if hasattr(node, 'args') else []

    # 跳过特殊方法
    if func_name.startswith('__') and func_name.endswith('__'):
        if func_name == '__init__':
            return f'        """初始化{class_name or "对象"}实例。\n\n        Args:\n            self: 类实例。\n        """\n'
        return None

    # 根据函数名生成描述
    action_map = {
        'scan': '执行扫描操作',
        'enumerate': '执行枚举操作',
        'query': '执行查询操作',
        'generate': '生成Payload',
        'execute': '执行操作',
        'get': '获取数据',
        'list': '列出数据',
        'search': '搜索数据',
        'add': '添加数据',
        'remove': '移除数据',
        'update': '更新数据',
        'delete': '删除数据',
        'create': '创建数据',
        'start': '启动操作',
        'stop': '停止操作',
        'connect': '建立连接',
        'disconnect': '断开连接',
        'check': '检查状态',
        'verify': '验证数据',
        'validate': '验证数据',
        'load': '加载数据',
        'save': '保存数据',
        'export': '导出数据',
        'import': '导入数据',
        'run': '运行操作',
        'submit': '提交任务',
        'cancel': '取消任务',
        'register': '注册节点',
        'unregister': '注销节点',
        'aggregate': '汇总结果',
        'identify': '识别类型',
        'brute': '暴力破解',
        'crack': '密码破解',
        'dump': '转储数据',
        'escalate': '权限提升',
        'clean': '清除痕迹',
        'gather': '收集信息',
        'assess': '安全评估',
        'forward': '端口转发',
        'tunnel': '建立隧道',
    }

    desc = '执行相关操作'
    for key, value in action_map.items():
        if key in func_name.lower():
            desc = value
            break

    # 构建参数文档
    args_doc = ''
    if args:
        args_doc = '\n        Args:\n'
        for arg in args:
            args_doc += f'            {arg}: 相关参数。\n'

    # 构建返回值文档
    returns_doc = '\n        Returns:\n            操作结果。\n'

    indent = '        ' if class_name else '    '
    docstring = f'{indent}"""{desc}。\n{args_doc}{returns_doc}{indent}"""\n'

    return docstring

def add_docstrings_to_file(filepath):
    """为文件中缺少文档字符串的函数和类添加文档字符串"""
    try:
        with open(filepath, 'r', encoding='utf-8') as f:
            source = f.read()

        tree = ast.parse(source)
        lines = source.split('\n')

        # 收集需要添加文档字符串的节点
        additions = []

        for node in ast.walk(tree):
            if isinstance(node, ast.ClassDef):
                if not has_docstring(node):
                    # 找到类定义后的第一行
                    insert_line = node.lineno
                    # 找到类体的第一行
                    if node.body:
                        first_body = node.body[0]
                        insert_at = first_body.lineno - 1  # 0-indexed
                        docstring = generate_class_docstring(node, filepath)
                        additions.append((insert_at, docstring))

            elif isinstance(node, ast.FunctionDef):
                if not has_docstring(node):
                    # 检查是否在类中
                    class_name = None
                    for parent in ast.walk(tree):
                        if isinstance(parent, ast.ClassDef):
                            if node in parent.body:
                                class_name = parent.name
                                break

                    if node.body:
                        first_body = node.body[0]
                        insert_at = first_body.lineno - 1  # 0-indexed
                        docstring = generate_function_docstring(node, class_name)
                        if docstring:
                            additions.append((insert_at, docstring))

        if not additions:
            return 0, 0

        # 按行号倒序插入，避免行号偏移
        additions.sort(key=lambda x: x[0], reverse=True)

        for insert_at, docstring in additions:
            lines.insert(insert_at, docstring.rstrip('\n'))

        new_source = '\n'.join(lines)

        with open(filepath, 'w', encoding='utf-8') as f:
            f.write(new_source)

        classes_added = sum(1 for _, d in additions if 'Attributes:' in d)
        funcs_added = len(additions) - classes_added

        return classes_added, funcs_added

    except Exception as e:
        print(f'  错误: {filepath}: {e}')
        return 0, 0

def main():
    """在...中。

        Returns:
            操作结果。
    """
    print('=' * 60)
    print('批量添加文档字符串')
    print('=' * 60)
    print()

    total_classes = 0
    total_funcs = 0
    processed_files = 0

    for filepath in TARGET_FILES:
        if not os.path.isfile(filepath):
            print(f'[跳过] {filepath} (文件不存在)')
            continue

        print(f'处理: {filepath}')
        classes, funcs = add_docstrings_to_file(filepath)
        if classes > 0 or funcs > 0:
            print(f'  添加: {classes}个类文档, {funcs}个函数文档')
            total_classes += classes
            total_funcs += funcs
            processed_files += 1
        else:
            print(f'  无需添加')

    print()
    print('=' * 60)
    print(f'处理完成: {processed_files}个文件')
    print(f'添加类文档: {total_classes}个')
    print(f'添加函数文档: {total_funcs}个')
    print(f'总计: {total_classes + total_funcs}个文档字符串')
    print('=' * 60)

if __name__ == '__main__':
    main()
