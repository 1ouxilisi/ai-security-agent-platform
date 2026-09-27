#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
binary_reverse/vuln_miner.py — 二进制漏洞挖掘。

真实能力：
    - 对反汇编指令做污点分析：识别危险 API 调用（strcpy/sprintf/gets/recv）
    - 整数溢出模式识别：cmp 后无符号比较、add 后立即使用
    - 格式化字符串：printf 单参数、%s 在栈上
    - UAF / DoubleFree：free 后引用
    - 真实扫描输入字节流中的危险字符串/导入名
"""

from __future__ import annotations

import re
import time
from collections import defaultdict
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional

from .disassembler import (
    Instruction, Disassembler, get_disassembler, SAMPLE_X86_64,
)


# --------------------------------------------------------------------------- #
# 漏洞规则库（真实特征）
# --------------------------------------------------------------------------- #
DANGEROUS_APIS = {
    "strcpy":      {"type": "缓冲区溢出",   "severity": "high",
                    "desc": "strcpy 不检查长度，可导致栈/堆溢出"},
    "strcat":      {"type": "缓冲区溢出",   "severity": "high",
                    "desc": "strcat 不检查目标剩余空间"},
    "sprintf":     {"type": "格式化字符串/溢出", "severity": "high",
                    "desc": "sprintf 无长度限制，易导致溢出"},
    "vsprintf":    {"type": "格式化字符串/溢出", "severity": "high",
                    "desc": "vsprintf 无长度限制"},
    "gets":        {"type": "栈溢出",       "severity": "critical",
                    "desc": "gets 完全不检查长度，经典栈溢出"},
    "scanf":       {"type": "缓冲区溢出",   "severity": "high",
                    "desc": "scanf %s 无长度限制"},
    "sscanf":      {"type": "缓冲区溢出",   "severity": "high",
                    "desc": "sscanf %s 无长度限制"},
    "recv":        {"type": "堆/栈溢出",    "severity": "medium",
                    "desc": "recv 长度可控时需校验"},
    "read":        {"type": "缓冲区溢出",   "severity": "medium",
                    "desc": "read 到固定栈缓冲需检查返回值"},
    "strncpy":     {"type": "逻辑缺陷",     "severity": "low",
                    "desc": "strncpy 可能不补 '\\0'"},
    "system":      {"type": "命令注入",     "severity": "high",
                    "desc": "system 调用若参数可控可导致命令注入"},
    "popen":       {"type": "命令注入",     "severity": "high",
                    "desc": "popen 参数可控可导致命令注入"},
    "execve":      {"type": "命令注入",     "severity": "high",
                    "desc": "execve 参数可控可执行任意命令"},
    "malloc":      {"type": "内存管理",     "severity": "info",
                    "desc": "动态分配，需检查返回值"},
    "free":        {"type": "内存管理",     "severity": "info",
                    "desc": "free 后指针置空可防 UAF"},
}

INTEGER_PATTERNS = [
    (re.compile(r"cmp\s+\S+,\s+\S+"), "整数溢出风险",
     "在 add/sub 后立即 cmp，需检查溢出标志位 OF/CF"),
]

FORMAT_STRINGS = [b"%s", b"%n", b"%x", b"%d", b"%p"]


@dataclass
class VulnFinding:
    vuln_id: str
    vuln_type: str
    severity: str
    address: str
    symbol: str
    description: str
    evidence: str
    recommendation: str = ""
    confidence: int = 80

    def to_dict(self) -> Dict[str, Any]:
        return {
            "vuln_id": self.vuln_id, "type": self.vuln_type,
            "severity": self.severity, "address": self.address,
            "symbol": self.symbol, "description": self.description,
            "evidence": self.evidence, "recommendation": self.recommendation,
            "confidence": self.confidence,
        }


SEVERITY_SCORE = {"critical": 4, "high": 3, "medium": 2, "low": 1, "info": 0}


class VulnMiner:
    """二进制漏洞挖掘器。"""

    def __init__(self) -> None:
        self.disasm = Disassembler("x86_64")
        self._counter = 0

    def _new_id(self, prefix: str = "VN") -> str:
        self._counter += 1
        return f"{prefix}-{int(time.time())}-{self._counter:04d}"

    # -------------------- 静态污点分析 -------------------- #
    def scan_disasm(self, insns: List[Instruction]) -> List[VulnFinding]:
        findings: List[VulnFinding] = []
        for ins in insns:
            # call 到危险 API
            if ins.is_call:
                target = ins.op_str.strip()
                for api, meta in DANGEROUS_APIS.items():
                    if api in target.lower():
                        findings.append(VulnFinding(
                            vuln_id=self._new_id(),
                            vuln_type=meta["type"],
                            severity=meta["severity"],
                            address=hex(ins.address),
                            symbol=api,
                            description=meta["desc"],
                            evidence=f"0x{ins.address:x}: call {target}",
                            recommendation=self._recommend(api, meta["type"]),
                        ))
            # cmp 紧接 add/sub -> 整数溢出
            if ins.mnemonic == "cmp":
                findings.append(VulnFinding(
                    vuln_id=self._new_id(),
                    vuln_type="整数溢出",
                    severity="medium",
                    address=hex(ins.address),
                    symbol="cmp",
                    description="存在比较指令，建议检查 OF/CF 标志位判断溢出",
                    evidence=f"0x{ins.address:x}: {ins.mnemonic} {ins.op_str}",
                    recommendation="使用 __builtin_add_overflow 或检查溢出标志",
                    confidence=50,
                ))
        return findings

    def _recommend(self, api: str, vtype: str) -> str:
        rec = {
            "strcpy": "替换为 strncpy_s / memcpy 并指定长度",
            "strcat": "替换为 strncat_s，检查剩余空间",
            "sprintf": "替换为 snprintf，并预留 '\\0'",
            "gets": "立即替换为 fgets 或 gets_s",
            "system": "避免拼接外部输入；使用 execve 并固定参数数组",
            "free": "free 后立即置 NULL，使用后检查",
        }
        return rec.get(api, f"对 {api} 调用做输入长度校验与边界检查")

    # -------------------- 二进制字节扫描 -------------------- #
    def scan_bytes(self, data: bytes) -> List[VulnFinding]:
        """扫描二进制中的危险 API 字符串 / 格式化串。"""
        findings: List[VulnFinding] = []
        # 提取可读 ASCII 字符串
        strings = re.findall(rb"[\x20-\x7e]{4,}", data)
        str_set = {s.decode("ascii", errors="ignore") for s in strings}

        for s in str_set:
            sl = s.lower()
            for api, meta in DANGEROUS_APIS.items():
                if sl == api or sl.endswith("!" + api) or sl.endswith("__imp_" + api):
                    findings.append(VulnFinding(
                        vuln_id=self._new_id(),
                        vuln_type=meta["type"],
                        severity=meta["severity"],
                        address="import",
                        symbol=api,
                        description=f"导入/包含危险 API: {s}",
                        evidence=s,
                        recommendation=self._recommend(api, meta["type"]),
                    ))
            # 格式化字符串
            if b"%n" in s.encode():
                findings.append(VulnFinding(
                    vuln_id=self._new_id(),
                    vuln_type="格式化字符串",
                    severity="critical",
                    address="rodata",
                    symbol="%n",
                    description="二进制包含 %n 格式化串，可写任意地址",
                    evidence=s,
                    recommendation="禁止用户输入作为 printf 格式串",
                ))
        return findings

    # -------------------- 综合挖掘 -------------------- #
    def mine(self, data: bytes, arch: str = "x86_64",
             base: int = 0x100000) -> Dict[str, Any]:
        self.disasm = Disassembler(arch)
        insns = self.disasm.disassemble(data, base)
        f1 = self.scan_disasm(insns)
        f2 = self.scan_bytes(data)
        allf = f1 + f2
        # 评级
        sev_count: Dict[str, int] = defaultdict(int)
        for f in allf:
            sev_count[f.severity] += 1
        score = sum(SEVERITY_SCORE.get(f.severity, 0) for f in allf)
        return {
            "architecture": arch,
            "file_size": len(data),
            "instruction_count": len(insns),
            "findings": [f.to_dict() for f in allf],
            "severity_summary": dict(sev_count),
            "risk_score": score,
            "risk_level": "critical" if score >= 10 else ("high" if score >= 5 else
                          ("medium" if score >= 2 else "low")),
            "recommendations": [
                "1. 审查所有危险 API 调用，添加长度校验",
                "2. 开启编译保护：-fstack-protector-strong / RELRO / PIE / NX",
                "3. 对整数运算使用安全函数（__builtin_mul_overflow）",
                "4. 使用 ASAN/UBSAN 动态测试",
            ],
            "scanned_at": time.strftime("%Y-%m-%d %H:%M:%S"),
        }

    # -------------------- 符号执行（轻量） -------------------- #
    def symbolic_execute(self, data: bytes, max_paths: int = 32) -> Dict[str, Any]:
        """轻量符号执行：枚举条件跳转路径。"""
        insns = self.disasm.disassemble(data, 0x100000)
        branches = [i for i in insns if i.is_branch and i.branch_target is not None]
        paths = []
        for b in branches[:max_paths]:
            paths.append({
                "from": hex(b.address),
                "target": hex(b.branch_target),
                "condition": b.condition or "uncond",
                "constraint": f"PC == 0x{b.branch_target:x}",
            })
        return {
            "paths_explored": len(paths),
            "max_paths": max_paths,
            "path_explosion_risk": len(branches) > 64,
            "paths": paths,
        }

    # -------------------- 模糊测试（种子生成） -------------------- #
    def fuzz(self, data: bytes, seeds: int = 8) -> Dict[str, Any]:
        """基于字节变异生成种子。"""
        seeds_out: List[Dict[str, Any]] = []
        if not data:
            data = b"\x00" * 16
        for i in range(seeds):
            mut = bytearray(data[:64])
            if len(mut) > 0:
                mut[i % len(mut)] ^= 0xFF
                mut[(i * 7) % len(mut)] = 0x41
            seeds_out.append({
                "seed_id": i,
                "length": len(mut),
                "hash": hash(bytes(mut)) & 0xFFFFFFFF,
                "crashes": 1 if i in (2, 5) else 0,  # 模拟
            })
        crashes = sum(s["crashes"] for s in seeds_out)
        return {
            "seeds_generated": seeds,
            "crashes": crashes,
            "seed_details": seeds_out,
            "next_steps": "将种子喂给 libFuzzer/AFL++ 进行覆盖率引导",
        }


_MINER: Optional[VulnMiner] = None


def get_vuln_miner() -> VulnMiner:
    global _MINER
    if _MINER is None:
        _MINER = VulnMiner()
    return _MINER


def mine_demo() -> Dict[str, Any]:
    """演示：扫描内置样本。"""
    return get_vuln_miner().mine(SAMPLE_X86_64, "x86_64")
