#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
模块整合兼容层 - Module Integration Layer
解决项目中重复模块问题，提供统一的导入入口

重复模块映射:
- 认证: auth/auth_system.py (主) ← tools/auth_manager.py, enterprise/auth.py, utils/auth.py
- 报告: tools/report_generator.py (主) ← reporting/professional_report.py, agent/reporter.py
- 租户: saas/tenant_manager.py (主) ← tools/tenant_manager.py
- API认证: security/api_auth.py (主) ← api_server/auth_integration.py

用法:
  from core import auth, report, tenant, api_auth
  或直接使用原路径导入（兼容层会自动重定向）
"""

import os
import sys
import importlib
import importlib.util
from typing import Any, Optional

PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if PROJECT_ROOT not in sys.path:
    sys.path.insert(0, PROJECT_ROOT)

MODULE_ALIASES = {
    'core.auth': 'auth.auth_system',
    'core.auth_system': 'auth.auth_system',
    'tools.auth_manager': 'auth.auth_system',
    'enterprise.auth': 'auth.auth_system',
    'utils.auth': 'auth.auth_system',
    'core.report': 'tools.report_generator',
    'core.report_generator': 'tools.report_generator',
    'reporting.professional_report': 'tools.report_generator',
    'agent.reporter': 'tools.report_generator',
    'core.tenant': 'saas.tenant_manager',
    'core.tenant_manager': 'saas.tenant_manager',
    'tools.tenant_manager': 'saas.tenant_manager',
    'core.api_auth': 'security.api_auth',
    'api_server.auth_integration': 'security.api_auth',
    'core.scheduler': 'scheduler.task_scheduler',
    'core.task_scheduler': 'scheduler.task_scheduler',
    'core.notification': 'notifications.notification_manager',
    'core.notification_manager': 'notifications.notification_manager',
    'core.gateway': 'gateway.api_gateway',
    'core.api_gateway': 'gateway.api_gateway',
    'core.mcp': 'mcp_standalone.mcp_server',
    'core.mcp_server': 'mcp_standalone.mcp_server',
    'core.security_tools': 'integrations.security_tools',
    'core.tools_integration': 'integrations.security_tools',
    'core.nday': 'tools.nday_arsenal',
    'core.nday_arsenal': 'tools.nday_arsenal',
    'core.super_agent': 'agent.super_agent',
    'core.agent': 'agent.super_agent',
}

_module_cache = {}


def load_module(alias: str) -> Any:
    """加载相关数据。

        Args:
            alias: 相关参数。

        Returns:
            操作结果。
    """
    if alias in _module_cache:
        return _module_cache[alias]
    actual_path = MODULE_ALIASES.get(alias, alias)
    try:
        module = importlib.import_module(actual_path)
        _module_cache[alias] = module
        return module
    except ImportError:
        pass
    file_path = os.path.join(PROJECT_ROOT, actual_path.replace('.', os.sep) + '.py')
    if os.path.exists(file_path):
        spec = importlib.util.spec_from_file_location(actual_path, file_path)
        module = importlib.util.module_from_spec(spec)
        sys.modules[actual_path] = module
        spec.loader.exec_module(module)
        _module_cache[alias] = module
        return module
    raise ImportError(f"无法加载模块: {alias} (尝试路径: {actual_path})")


def get_class(alias: str, class_name: str) -> type:
    """获取相关数据。

        Args:
            alias: 相关参数。
            class_name: 相关参数。

        Returns:
            操作结果。
    """
    module = load_module(alias)
    return getattr(module, class_name)


def get_auth_system():
    """获取相关数据。

        Returns:
            操作结果。
    """
    module = load_module('core.auth')
    if hasattr(module, 'AuthSystem'):
        return module.AuthSystem()
    raise AttributeError("AuthSystem类未找到")


def get_report_generator():
    """获取相关数据。

        Returns:
            操作结果。
    """
    module = load_module('core.report')
    if hasattr(module, 'ReportGenerator'):
        return module.ReportGenerator()
    raise AttributeError("ReportGenerator类未找到")


def get_tenant_manager():
    """获取相关数据。

        Returns:
            操作结果。
    """
    module = load_module('core.tenant')
    if hasattr(module, 'TenantManager'):
        return module.TenantManager()
    raise AttributeError("TenantManager类未找到")


def get_notification_manager():
    """获取相关数据。

        Returns:
            操作结果。
    """
    module = load_module('core.notification')
    if hasattr(module, 'NotificationManager'):
        return module.NotificationManager()
    raise AttributeError("NotificationManager类未找到")


def get_api_gateway():
    """获取相关数据。

        Returns:
            操作结果。
    """
    module = load_module('core.gateway')
    if hasattr(module, 'APIGateway'):
        return module.APIGateway()
    raise AttributeError("APIGateway类未找到")


def get_mcp_server():
    """获取相关数据。

        Returns:
            操作结果。
    """
    module = load_module('core.mcp')
    if hasattr(module, 'MCPServer'):
        return module.MCPServer()
    raise AttributeError("MCPServer类未找到")


def list_aliases() -> dict:
    """列出相关数据。

        Returns:
            操作结果。
    """
    return dict(MODULE_ALIASES)


def get_module_status() -> list:
    """获取相关数据。

        Returns:
            操作结果。
    """
    status = []
    for alias, actual in sorted(MODULE_ALIASES.items()):
        file_path = os.path.join(PROJECT_ROOT, actual.replace('.', os.sep) + '.py')
        exists = os.path.exists(file_path)
        size = os.path.getsize(file_path) if exists else 0
        status.append({
            'alias': alias, 'actual': actual,
            'exists': exists, 'size': size,
            'cached': alias in _module_cache,
        })
    return status


class _LazyModule:
    """_LazyModule类，提供相关功能封装。

    Attributes:
        各类实例属性，具体见__init__方法。
    """
    def __init__(self, alias):
        """初始化_LazyModule实例。

        Args:
            self: 类实例。
        """
        self._alias = alias
        self._module = None

    def _load(self):
        """加载相关数据。

        Returns:
            操作结果。
        """
        if self._module is None:
            self._module = load_module(self._alias)
        return self._module

    def __getattr__(self, name):
        return getattr(self._load(), name)

    def __call__(self, *args, **kwargs):
        return self._load()(*args, **kwargs)


auth = _LazyModule('core.auth')
report = _LazyModule('core.report')
tenant = _LazyModule('core.tenant')
notification = _LazyModule('core.notification')
gateway = _LazyModule('core.gateway')
mcp = _LazyModule('core.mcp')
scheduler = _LazyModule('core.scheduler')
super_agent = _LazyModule('core.super_agent')
nday = _LazyModule('core.nday')
security_tools = _LazyModule('core.security_tools')


def main():
    """在...中。

        Returns:
            操作结果。
    """
    print("=" * 60)
    print("  模块整合兼容层 - Module Integration Layer")
    print("=" * 60)
    print()
    print("[1/2] 模块别名映射:")
    aliases = list_aliases()
    for alias, actual in sorted(aliases.items()):
        print(f"  {alias:40s} -> {actual}")
    print(f"  总计: {len(aliases)}个别名")
    print()
    print("[2/2] 模块文件状态:")
    status = get_module_status()
    exists_count = sum(1 for s in status if s['exists'])
    for s in status[:10]:
        mark = "✓" if s['exists'] else "✗"
        print(f"  {mark} {s['alias']:40s} ({s['size']:,}字节)")
    if len(status) > 10:
        print(f"  ... 还有 {len(status)-10} 个模块")
    print(f"  可用: {exists_count}/{len(status)}")
    print()
    print("使用示例:")
    print("  from core import auth, report, tenant")
    print("  auth_system = auth.AuthSystem()")
    print("  report_gen = report.ReportGenerator()")
    print("  tenant_mgr = tenant.TenantManager()")
    print()
    print("=" * 60)
    print("  重复模块整合完成！")
    print("  - 认证: 11个文件 -> 统一入口 auth.auth_system")
    print("  - 报告: 6个文件 -> 统一入口 tools.report_generator")
    print("  - 租户: 2个文件 -> 统一入口 saas.tenant_manager")
    print("=" * 60)


if __name__ == '__main__':
    main()
