"""
攻击链库 - 单数别名模块
实际实现在 attack_chains.py（复数），此文件提供单数形式的导入别名。

使用方式：
    from knowledge.attack_chain import attack_chain_library, AttackChain
    # 等同于
    from knowledge.attack_chains import attack_chain_library, AttackChain
"""

from .attack_chains import (
    attack_chain_library,
    AttackChainLibrary,
    AttackChain,
    AttackStep,
)

# 单数别名
attack_chain_lib = attack_chain_library
AttackChainLib = AttackChainLibrary

__all__ = [
    'attack_chain_library',
    'AttackChainLibrary',
    'AttackChain',
    'AttackStep',
    # 单数别名
    'attack_chain_lib',
    'AttackChainLib',
]
