#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
full_add_docstrings脚本工具模块，提供相关的命令行工具和自动化脚本。

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

sys.path.insert(0, '.')

def has_docstring(node):
    """检查节点是否有文档字符串"""
    if not node.body:
        return False
    first = node.body[0]
    if isinstance(first, ast.Expr) and isinstance(first.value, ast.Constant):
        if isinstance(first.value.value, str):
            return True
    return False

def generate_class_docstring(node):
    """生成类文档字符串"""
    class_name = node.name

    # 根据类名生成描述
    name_lower = class_name.lower()
    if 'scanner' in name_lower:
        desc = f'{class_name}扫描器类，提供相关扫描功能封装。'
    elif 'manager' in name_lower:
        desc = f'{class_name}管理器类，提供相关资源的统一管理。'
    elif 'generator' in name_lower:
        desc = f'{class_name}生成器类，提供相关内容生成功能。'
    elif 'client' in name_lower:
        desc = f'{class_name}客户端类，提供与外部服务的交互封装。'
    elif 'library' in name_lower:
        desc = f'{class_name}库类，提供相关数据和功能的集合。'
    elif 'scheduler' in name_lower:
        desc = f'{class_name}调度器类，提供任务调度和负载均衡功能。'
    elif 'aggregator' in name_lower:
        desc = f'{class_name}汇总器类，提供多源数据汇总和分析功能。'
    elif 'pool' in name_lower:
        desc = f'{class_name}池类，提供资源池管理和分配功能。'
    elif 'exploit' in name_lower:
        desc = f'{class_name}漏洞利用类，提供相关漏洞利用功能。'
    elif 'payload' in name_lower:
        desc = f'{class_name}Payload类，提供相关Payload生成和管理。'
    elif 'request' in name_lower or 'model' in name_lower:
        desc = f'{class_name}数据模型类，定义相关数据结构和验证规则。'
    elif 'result' in name_lower:
        desc = f'{class_name}结果类，封装相关操作结果数据。'
    elif 'config' in name_lower or 'settings' in name_lower:
        desc = f'{class_name}配置类，管理相关配置参数。'
    elif 'error' in name_lower or 'exception' in name_lower:
        desc = f'{class_name}异常类，表示相关错误情况。'
    elif 'test' in name_lower:
        desc = f'{class_name}测试类，包含相关单元测试用例。'
    elif 'route' in name_lower or 'endpoint' in name_lower or 'api' in name_lower:
        desc = f'{class_name}API路由请求模型，定义接口请求数据结构。'
    else:
        desc = f'{class_name}类，提供相关功能封装。'

    docstring = f'    """{desc}\n\n'
    docstring += f'    Attributes:\n'
    docstring += f'        各类实例属性，具体见__init__方法。\n'
    docstring += f'    """\n'

    return docstring

def generate_function_docstring(node, class_name=None):
    """生成函数文档字符串"""
    func_name = node.name

    # 跳过特殊方法
    if func_name.startswith('__') and func_name.endswith('__'):
        if func_name == '__init__':
            return f'        """初始化{class_name or "对象"}实例。\n\n        Args:\n            self: 类实例。\n        """\n'
        return None

    # 获取参数
    args = []
    if hasattr(node, 'args'):
        args = [a.arg for a in node.args.args if a.arg != 'self' and a.arg != 'cls']

    # 根据函数名生成描述
    name_lower = func_name.lower()
    action_map = {
        'scan': '执行扫描操作',
        'enumerate': '执行枚举操作',
        'query': '执行查询操作',
        'generate': '生成相关内容',
        'execute': '执行相关操作',
        'run': '运行相关操作',
        'get': '获取相关数据',
        'list': '列出相关数据',
        'search': '搜索相关数据',
        'find': '查找相关数据',
        'add': '添加相关数据',
        'remove': '移除相关数据',
        'update': '更新相关数据',
        'delete': '删除相关数据',
        'create': '创建相关数据',
        'start': '启动相关操作',
        'stop': '停止相关操作',
        'connect': '建立连接',
        'disconnect': '断开连接',
        'check': '检查相关状态',
        'verify': '验证相关数据',
        'validate': '验证相关数据',
        'load': '加载相关数据',
        'save': '保存相关数据',
        'export': '导出相关数据',
        'import': '导入相关数据',
        'submit': '提交相关任务',
        'cancel': '取消相关任务',
        'register': '注册相关节点',
        'unregister': '注销相关节点',
        'aggregate': '汇总相关结果',
        'identify': '识别相关类型',
        'brute': '执行暴力破解',
        'crack': '执行密码破解',
        'dump': '转储相关数据',
        'escalate': '执行权限提升',
        'clean': '清除相关痕迹',
        'gather': '收集相关信息',
        'assess': '执行安全评估',
        'forward': '执行端口转发',
        'tunnel': '建立相关隧道',
        'parse': '解析相关数据',
        'format': '格式化相关数据',
        'convert': '转换相关数据',
        'encode': '编码相关数据',
        'decode': '解码相关数据',
        'encrypt': '加密相关数据',
        'decrypt': '解密相关数据',
        'hash': '计算相关哈希',
        'filter': '过滤相关数据',
        'sort': '排序相关数据',
        'merge': '合并相关数据',
        'split': '分割相关数据',
        'init': '初始化相关组件',
        'setup': '设置相关配置',
        'configure': '配置相关参数',
        'reset': '重置相关状态',
        'refresh': '刷新相关数据',
        'reload': '重新加载相关数据',
        'close': '关闭相关资源',
        'open': '打开相关资源',
        'read': '读取相关数据',
        'write': '写入相关数据',
        'send': '发送相关数据',
        'receive': '接收相关数据',
        'request': '发送相关请求',
        'response': '处理相关响应',
        'handle': '处理相关事件',
        'process': '处理相关数据',
        'analyze': '分析相关数据',
        'evaluate': '评估相关数据',
        'calculate': '计算相关数值',
        'compare': '比较相关数据',
        'match': '匹配相关模式',
        'extract': '提取相关信息',
        'transform': '转换相关数据',
        'map': '映射相关数据',
        'reduce': '归约相关数据',
        'group': '分组相关数据',
        'count': '统计相关数量',
        'sum': '求和相关数值',
        'average': '计算平均值',
        'max': '获取最大值',
        'min': '获取最小值',
        'first': '获取第一个',
        'last': '获取最后一个',
        'next': '获取下一个',
        'previous': '获取上一个',
        'current': '获取当前',
        'previous': '获取上一个',
        'exists': '检查是否存在',
        'contains': '检查是否包含',
        'empty': '检查是否为空',
        'null': '检查是否为null',
        'true': '检查是否为true',
        'false': '检查是否为false',
        'equal': '检查是否相等',
        'not_equal': '检查是否不相等',
        'greater': '检查是否大于',
        'less': '检查是否小于',
        'between': '检查是否在范围内',
        'in': '检查是否在集合中',
        'not_in': '检查是否不在集合中',
        'and': '逻辑与操作',
        'or': '逻辑或操作',
        'not': '逻辑非操作',
        'if': '条件判断',
        'else': '否则分支',
        'elif': '否则如果分支',
        'for': '循环遍历',
        'while': '条件循环',
        'do': '执行循环',
        'break': '跳出循环',
        'continue': '继续循环',
        'return': '返回结果',
        'yield': '生成结果',
        'raise': '抛出异常',
        'try': '尝试执行',
        'catch': '捕获异常',
        'finally': '最终执行',
        'with': '上下文管理',
        'as': '别名赋值',
        'pass': '空操作',
        'assert': '断言检查',
        'global': '全局声明',
        'nonlocal': '非局部声明',
        'lambda': '匿名函数',
        'def': '函数定义',
        'class': '类定义',
        'import': '导入模块',
        'from': '从...导入',
        'in': '在...中',
        'is': '是...',
        'not': '不...',
        'and': '和...',
        'or': '或...',
    }

    desc = '执行相关操作'
    for key, value in action_map.items():
        if key in name_lower:
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

def process_file(filepath):
    """处理单个文件，为缺少文档字符串的函数和类添加文档字符串"""
    try:
        with open(filepath, 'r', encoding='utf-8') as f:
            source = f.read()

        tree = ast.parse(source)
        lines = source.split('\n')

        additions = []

        for node in ast.walk(tree):
            if isinstance(node, ast.ClassDef):
                if not has_docstring(node):
                    if node.body:
                        first_body = node.body[0]
                        insert_at = first_body.lineno - 1
                        docstring = generate_class_docstring(node)
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

                    # 跳过嵌套函数（缩进太深的）
                    if node.col_offset > 12:
                        continue

                    if node.body:
                        first_body = node.body[0]
                        insert_at = first_body.lineno - 1
                        docstring = generate_function_docstring(node, class_name)
                        if docstring:
                            additions.append((insert_at, docstring))

        if not additions:
            return 0, 0

        # 按行号倒序插入
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
    print('全面批量添加文档字符串（整个项目）')
    print('=' * 60)
    print()

    # 收集所有Python文件
    py_files = []
    for root, dirs, files in os.walk('.'):
        dirs[:] = [d for d in dirs if not d.startswith('.') and d != '__pycache__' and d != 'venv' and d != '.venv']
        for f in files:
            if f.endswith('.py'):
                py_files.append(os.path.join(root, f))

    print(f'找到 {len(py_files)} 个Python文件')
    print()

    total_classes = 0
    total_funcs = 0
    processed_files = 0

    for i, filepath in enumerate(py_files, 1):
        classes, funcs = process_file(filepath)
        if classes > 0 or funcs > 0:
            print(f'[{i}/{len(py_files)}] {filepath}: +{classes}类 +{funcs}函数')
            total_classes += classes
            total_funcs += funcs
            processed_files += 1

    print()
    print('=' * 60)
    print(f'处理完成: {processed_files}/{len(py_files)}个文件')
    print(f'添加类文档: {total_classes}个')
    print(f'添加函数文档: {total_funcs}个')
    print(f'总计: {total_classes + total_funcs}个文档字符串')
    print('=' * 60)

if __name__ == '__main__':
    main()
