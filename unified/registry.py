#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
领域评估器自动注册模块

提供 register_all_domains(engine) 函数，自动导入并注册四大领域评估器。
某个领域导入失败不影响其他领域。
"""
import traceback
from typing import List, Tuple

from unified.engine import UnifiedAssessmentEngine


def register_all_domains(engine: UnifiedAssessmentEngine) -> Tuple[List[str], List[str]]:
    """自动注册所有已实现的领域评估器

    Returns:
        (成功注册的领域列表, 失败的领域列表)
    """
    success = []
    failed = []

    # 领域评估器注册映射：模块路径 -> register函数
    domain_registrars = [
        ("unified.pentest_assessor", "渗透测试"),
        ("unified.mobile_assessor", "移动安全"),
        ("unified.blockchain_assessor", "区块链安全"),
        ("unified.ai_assessor", "AI智能体安全"),
    ]

    for module_path, domain_name in domain_registrars:
        try:
            import importlib
            module = importlib.import_module(module_path)
            if hasattr(module, "register"):
                module.register(engine)
                success.append(domain_name)
            else:
                failed.append(f"{domain_name}(模块缺少register函数)")
        except ImportError as e:
            failed.append(f"{domain_name}(模块未找到: {e})")
        except Exception as e:
            failed.append(f"{domain_name}(注册失败: {type(e).__name__}: {e})")
            traceback.print_exc()

    return success, failed


def get_domain_status() -> dict:
    """获取各领域评估器的可用状态（不实际注册，仅检查可导入性）"""
    status = {}
    domain_registrars = [
        ("pentest", "unified.pentest_assessor", "渗透测试"),
        ("mobile", "unified.mobile_assessor", "移动安全"),
        ("blockchain", "unified.blockchain_assessor", "区块链安全"),
        ("ai_agent", "unified.ai_assessor", "AI智能体安全"),
    ]
    for key, module_path, name in domain_registrars:
        try:
            import importlib
            importlib.import_module(module_path)
            status[key] = {"name": name, "available": True, "error": None}
        except Exception as e:
            status[key] = {"name": name, "available": False, "error": str(e)}
    return status
