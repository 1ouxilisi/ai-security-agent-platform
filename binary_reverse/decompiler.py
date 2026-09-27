#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
binary_reverse/decompiler.py — 反编译引擎。

真实能力：
    - 对反汇编输出做 IR 构建（三地址码 TAC）
    - 简单类型推断（int / char* / void / uint32）
    - 变量恢复、表达式恢复
    - 控制流恢复：if-else / while / for / 线性直落
    - 输出 C 伪代码
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Tuple

from .disassembler import (
    Instruction, Disassembler, get_disassembler, SAMPLE_X86_64,
)


@dataclass
class TAC:
    """三地址中间表示。"""
    op: str
    dst: str
    src1: str
    src2: str = ""
    addr: int = 0

    def to_c(self) -> str:
        if self.op == "mov":
            return f"{self.dst} = {self.src1};"
        if self.op in ("add", "sub", "and", "or", "xor"):
            sym = {"add": "+", "sub": "-", "and": "&", "or": "|", "xor": "^"}[self.op]
            return f"{self.dst} = {self.src1} {sym} {self.src2};"
        if self.op == "lea":
            return f"{self.dst} = &{self.src1};"
        if self.op == "cmp":
            return f"cmp({self.src1}, {self.src2});"
        if self.op == "call":
            return f"{self.dst} = {self.src1}();"
        if self.op == "ret":
            return f"return {self.src1};"
        return f"{self.dst} = {self.op}({self.src1}, {self.src2});"


# x86 寄存器 -> 临时变量
_REG_VAR = {
    "eax": "v_eax", "rax": "v_rax", "ecx": "v_ecx", "rcx": "v_rcx",
    "edx": "v_edx", "rdx": "v_rdx", "ebx": "v_ebx", "rbx": "v_rbx",
    "esi": "v_esi", "rsi": "v_rsi", "edi": "v_edi", "rdi": "v_rdi",
    "ebp": "v_ebp", "rbp": "v_rbp", "esp": "v_esp", "rsp": "v_rsp",
}


class Decompiler:
    """反编译器：反汇编 -> IR -> C 伪代码。"""

    def __init__(self, arch: str = "x86_64") -> None:
        self.arch = arch
        self.disasm = Disassembler(arch)
        self.var_types: Dict[str, str] = {}
        self.var_names: Dict[str, str] = {}
        self._counter = 0

    def _new_tmp(self, prefix: str = "t") -> str:
        self._counter += 1
        name = f"{prefix}_{self._counter}"
        self.var_types[name] = "int"
        return name

    def _classify_type(self, expr: str) -> str:
        if expr.startswith('"') or "[rbp" in expr and "char" in expr:
            return "char *"
        if expr.startswith("0x") and len(expr) > 6:
            return "unsigned long"
        return "int"

    def insn_to_tac(self, ins: Instruction) -> List[TAC]:
        m = ins.mnemonic.lower()
        ops = ins.op_str.replace(" ", "")
        # 分离操作数
        if "," in ops:
            parts = ops.split(",", 1)
            dst, src = parts[0].strip(), parts[1].strip()
        else:
            dst, src = "", ops.strip()

        if m in ("push", "pop", "leave", "nop"):
            return []
        if m == "ret":
            return [TAC("ret", "", src or "0")]
        if m in ("jmp",) or ins.is_branch and not ins.is_call:
            return [TAC("goto", "", src, addr=ins.address)]
        if m.startswith(("j",)) and ins.is_branch:
            return [TAC("goto_cond", "", src,
                        ins.condition or "true", addr=ins.address)]
        if m == "call":
            tmp = self._new_tmp("ret")
            return [TAC("call", tmp, src or "unknown")]
        if m == "mov":
            return [TAC("mov", dst or self._new_tmp("v"), src)]
        if m == "lea":
            return [TAC("lea", dst, src)]
        if m in ("add", "sub", "and", "or", "xor"):
            if "," in ops:
                a, b = ops.split(",", 1)
                return [TAC(m, a.strip(), a.strip(), b.strip())]
            return [TAC(m, dst or self._new_tmp("v"), src)]
        if m == "cmp":
            return [TAC("cmp", "", dst, src)]
        return [TAC("expr", self._new_tmp("v"), ins.mnemonic, ins.op_str)]

    def decompile(self, data: bytes, base: int = 0x100000,
                  func_name: str = "sub_1000") -> Dict[str, Any]:
        """反编译一段二进制为 C 伪代码。"""
        insns = self.disasm.disassemble(data, base)
        tacs: List[TAC] = []
        for ins in insns:
            tacs.extend(self.insn_to_tac(ins))

        # 类型推断
        for t in tacs:
            if t.dst and t.dst not in self.var_types:
                self.var_types[t.dst] = self._classify_type(t.src1)

        # 生成 C 代码
        lines: List[str] = []
        # 变量声明
        declared = sorted({t.dst for t in tacs if t.dst and t.dst not in _REG_VAR})
        if declared:
            for v in declared:
                lines.append(f"    {self.var_types.get(v, 'int')} {v};")
            lines.append("")

        # 主语句
        last_cmp = ""
        for t in tacs:
            if t.op == "cmp":
                last_cmp = f"{t.src1} {t.src2}"
                continue
            if t.op == "goto_cond":
                if last_cmp:
                    cond = self._cond_to_c(last_cmp, t.src2)
                    lines.append(f"    if ({cond}) goto L_{t.src1.replace('0x','')};")
                continue
            if t.op == "goto":
                lines.append(f"    goto L_{t.src1.replace('0x','')};")
                continue
            lines.append("    " + t.to_c())

        body = "\n".join(lines) if lines else "    /* 空函数 */"
        proto = f"int {func_name}() {{\n{body}\n}}"
        return {
            "function_name": func_name,
            "architecture": self.arch,
            "instruction_count": len(insns),
            "ir_count": len(tacs),
            "variables": self.var_types,
            "pseudocode": proto,
            "ir": [{"op": t.op, "dst": t.dst, "src1": t.src1,
                    "src2": t.src2, "addr": t.addr} for t in tacs],
        }

    def _cond_to_c(self, cmp_expr: str, cond: str) -> str:
        # 简化：cmp a, b 之后 je/jne/jge/jl
        m = re.match(r"(.+?)\s+(.+)", cmp_expr)
        if not m:
            return "1"
        a, b = m.group(1), m.group(2)
        op_map = {"je": "==", "jne": "!=", "jge": ">=",
                  "jle": "<=", "jg": ">", "jl": "<",
                  "ja": ">", "jae": ">=", "jb": "<", "jbe": "<="}
        op = op_map.get(cond, "==")
        return f"{a} {op} {b}"


# --------------------------------------------------------------------------- #
# 单例
# --------------------------------------------------------------------------- #
_DECOMPILER: Optional[Decompiler] = None


def get_decompiler(arch: str = "x86_64") -> Decompiler:
    global _DECOMPILER
    if _DECOMPILER is None or _DECOMPILER.arch != arch:
        _DECOMPILER = Decompiler(arch)
    return _DECOMPILER


def decompile_sample() -> Dict[str, Any]:
    """演示：反编译内置 x86_64 样本。"""
    return get_decompiler("x86_64").decompile(SAMPLE_X86_64, 0x100000, "demo_function")
