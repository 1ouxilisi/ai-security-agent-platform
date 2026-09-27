# -*- coding: utf-8 -*-
"""
binary_reverse — 二进制逆向与漏洞挖掘平台（第27轮升级方向3）。

模块：
    disassembler      反汇编引擎（x86/x86-64/ARM/ARM64/MIPS/PowerPC/RISC-V/SPARC/SystemZ）
    decompiler        反编译引擎（IR/类型恢复/伪代码生成）
    vuln_miner        二进制漏洞挖掘（污点分析/符号执行/模糊测试）
    patch_diff        补丁对比分析
    malware_analysis  恶意代码分析
    pack_unpack       壳检测与脱壳
    binary_dashboard  逆向控制台数据聚合层
"""

from __future__ import annotations

__version__ = "27.3.0"
__all__ = [
    "disassembler",
    "decompiler",
    "vuln_miner",
    "patch_diff",
    "malware_analysis",
    "pack_unpack",
    "binary_dashboard",
]
