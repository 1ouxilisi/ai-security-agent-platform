"""
攻击面管理（Attack Surface Management, ASM）模块
核心能力：资产发现 → 暴露面评估 → 攻击路径分析 → 风险优先级排序 → 持续监控
"""
from .asm_manager import ASMManager

__all__ = ["ASMManager"]
__version__ = "1.0.0"
