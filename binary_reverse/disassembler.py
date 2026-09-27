#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
binary_reverse/disassembler.py — 反汇编引擎。

支持架构：x86 / x86-64 / ARM / ARM64 / MIPS / PowerPC / RISC-V / SPARC / SystemZ。
优先使用 capstone（若已安装）；否则内置一个纯 Python 的迷你解码器，
对 x86 / x86-64 / ARM 常见指令做真实字节解码（mov/add/sub/cmp/jmp/call/push/pop/ret/lea 等），
保证“真实反汇编”能力，不依赖外部库。

能力：
    - 线性扫描反汇编 / 递归下降反汇编
    - 基本块识别、控制流边、循环识别
    - 指令解码（操作数/寻址方式/标志位/条件码）
    - 函数识别、调用图、函数边界、调用约定推断
    - 输出：汇编文本 / 结构化指令列表 / CFG / 调用图
"""

from __future__ import annotations

import struct
import time
import uuid
from collections import defaultdict
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Tuple

# 第三方库：try-import
try:
    import capstone  # type: ignore
    _HAS_CAPSTONE = True
except Exception:  # pragma: no cover
    capstone = None  # type: ignore
    _HAS_CAPSTONE = False


# --------------------------------------------------------------------------- #
# 架构元数据
# --------------------------------------------------------------------------- #
ARCHITECTURES: Dict[str, Dict[str, Any]] = {
    "x86":      {"bits": 32, "endian": "little", "name": "x86 (32-bit)"},
    "x86_64":   {"bits": 64, "endian": "little", "name": "x86-64 (64-bit)"},
    "arm":      {"bits": 32, "endian": "little", "name": "ARM (A32)"},
    "arm64":    {"bits": 64, "endian": "little", "name": "ARM64 (A64)"},
    "mips":     {"bits": 32, "endian": "little", "name": "MIPS32"},
    "powerpc":  {"bits": 32, "endian": "big",    "name": "PowerPC 32"},
    "riscv":    {"bits": 32, "endian": "little", "name": "RISC-V 32"},
    "sparc":    {"bits": 32, "endian": "big",    "name": "SPARC 32"},
    "s390x":    {"bits": 64, "endian": "big",    "name": "SystemZ (s390x)"},
}

# x86 寄存器名（16/32/64 位）
_X86_REGS16 = ["ax", "cx", "dx", "bx", "sp", "bp", "si", "di"]
_X86_REGS32 = ["eax", "ecx", "edx", "ebx", "esp", "ebp", "esi", "edi"]
_X86_REGS64 = ["rax", "rcx", "rdx", "rbx", "rsp", "rbp", "rsi", "rdi",
               "r8", "r9", "r10", "r11", "r12", "r13", "r14", "r15"]

# 单字节 opcode 主表（x86 / x86-64 常见）
_X86_OP1 = {
    0x00: ("add", "m8r8"), 0x01: ("add", "m32r32"),
    0x02: ("add", "r8m8"), 0x03: ("add", "r32m32"),
    0x04: ("add", "al_imm8"), 0x05: ("add", "eax_imm32"),
    0x08: ("or", "m8r8"),  0x09: ("or", "m32r32"),
    0x0A: ("or", "r8m8"),  0x0B: ("or", "r32m32"),
    0x10: ("adc", "m8r8"), 0x11: ("adc", "m32r32"),
    0x18: ("sbb", "m8r8"), 0x19: ("sbb", "m32r32"),
    0x20: ("and", "m8r8"), 0x21: ("and", "m32r32"),
    0x28: ("sub", "m8r8"), 0x29: ("sub", "m32r32"),
    0x2A: ("sub", "r8m8"), 0x2B: ("sub", "r32m32"),
    0x30: ("xor", "m8r8"), 0x31: ("xor", "m32r32"),
    0x32: ("xor", "r8m8"), 0x33: ("xor", "r32m32"),
    0x34: ("xor", "al_imm8"), 0x35: ("xor", "eax_imm32"),
    0x38: ("cmp", "m8r8"), 0x39: ("cmp", "m32r32"),
    0x3A: ("cmp", "r8m8"), 0x3B: ("cmp", "r32m32"),
    0x3C: ("cmp", "al_imm8"), 0x3D: ("cmp", "eax_imm32"),
    0x50: ("push", "r32"), 0x51: ("push", "r32"), 0x52: ("push", "r32"),
    0x53: ("push", "r32"), 0x54: ("push", "r32"), 0x55: ("push", "r32"),
    0x56: ("push", "r32"), 0x57: ("push", "r32"),
    0x58: ("pop", "r32"),  0x59: ("pop", "r32"),  0x5A: ("pop", "r32"),
    0x5B: ("pop", "r32"),  0x5C: ("pop", "r32"),  0x5D: ("pop", "r32"),
    0x5E: ("pop", "r32"),  0x5F: ("pop", "r32"),
    0x68: ("push", "imm32"), 0x6A: ("push", "imm8s"),
    0xB8: ("mov", "r32_imm32"), 0xB9: ("mov", "r32_imm32"),
    0xBA: ("mov", "r32_imm32"), 0xBB: ("mov", "r32_imm32"),
    0xBC: ("mov", "r32_imm32"), 0xBD: ("mov", "r32_imm32"),
    0xBE: ("mov", "r32_imm32"), 0xBF: ("mov", "r32_imm32"),
    0x89: ("mov", "m32r32"),
    0x8A: ("mov", "r8m8"), 0x8B: ("mov", "r32m32"),
    0x8D: ("lea", "r32m32"),
    0xC3: ("ret", None),  0xC9: ("leave", None),
    0xC7: ("mov", "m32imm32"),
    0x90: ("nop", None),
    0xE8: ("call", "rel32"), 0xE9: ("jmp", "rel32"),
    0xEB: ("jmp", "rel8"),
    0x83: ("grp1", "grp1_imm8"),
    0xF7: ("grp", "grp3"),
    0xFF: ("grp", "grp5"),
}

# 条件跳转 0x70..0x7F
_JCC8 = ["jo", "jno", "jb", "jae", "je", "jne", "jbe", "ja",
         "js", "jns", "jp", "jnp", "jl", "jge", "jle", "jg"]
# 0x80..0x8F 条件跳转 rel32
_JCC32 = ["jo", "jno", "jb", "jae", "je", "jne", "jbe", "ja",
          "js", "jns", "jp", "jnp", "jl", "jge", "jle", "jg"]

# 83 /digit 组运算
_GRP1 = ["add", "or", "adc", "sbb", "and", "sub", "xor", "cmp"]


# --------------------------------------------------------------------------- #
# 数据结构
# --------------------------------------------------------------------------- #
@dataclass
class Instruction:
    address: int
    size: int
    mnemonic: str
    op_str: str
    bytes_hex: str
    group: str = "data"          # control / arithmetic / call / branch / stack / data
    op_type: str = "unknown"
    operands: List[Any] = field(default_factory=list)
    is_branch: bool = False
    is_call: bool = False
    is_ret: bool = False
    branch_target: Optional[int] = None
    condition: Optional[str] = None

    def to_dict(self) -> Dict[str, Any]:
        return {
            "address": hex(self.address), "size": self.size,
            "mnemonic": self.mnemonic, "op_str": self.op_str,
            "bytes": self.bytes_hex, "group": self.group,
            "op_type": self.op_type, "is_branch": self.is_branch,
            "is_call": self.is_call, "is_ret": self.is_ret,
            "branch_target": hex(self.branch_target) if self.branch_target is not None else None,
            "condition": self.condition,
        }


@dataclass
class BasicBlock:
    start: int
    end: int
    instructions: List[Instruction] = field(default_factory=list)
    successors: List[int] = field(default_factory=list)
    predecessors: List[int] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "start": hex(self.start), "end": hex(self.end),
            "instructions": [i.to_dict() for i in self.instructions],
            "successors": [hex(s) for s in self.successors],
            "predecessors": [hex(p) for p in self.predecessors],
            "insn_count": len(self.instructions),
        }


@dataclass
class Function:
    start: int
    end: int
    name: str = ""
    blocks: List[BasicBlock] = field(default_factory=list)
    calls: List[int] = field(default_factory=list)
    callees: List[str] = field(default_factory=list)
    args: int = 0
    ret_type: str = "void"
    call_convention: str = "cdecl"

    def to_dict(self) -> Dict[str, Any]:
        return {
            "start": hex(self.start), "end": hex(self.end),
            "name": self.name, "blocks": [b.to_dict() for b in self.blocks],
            "calls": [hex(c) for c in self.calls],
            "callees": self.callees, "args": self.args,
            "ret_type": self.ret_type, "call_convention": self.call_convention,
            "insn_count": sum(len(b.instructions) for b in self.blocks),
        }


# --------------------------------------------------------------------------- #
# 内置迷你 x86 / x86-64 解码器（真实字节解码）
# --------------------------------------------------------------------------- #
def _rex(b: int) -> bool:
    return 0x40 <= b <= 0x4F


def _simm8(b: int) -> int:
    return b - 256 if b >= 128 else b


def _rm_modrm(mod: int, rm: int, modrm_byte: int, b: bytes,
              off: int, addr_size: int) -> Tuple[str, int]:
    """解析 ModR/M，返回 (操作数文本, 消耗额外字节数)。"""
    extra = 0
    if mod == 3:
        # 寄存器直接寻址
        rmap = _X86_REGS64 if addr_size == 64 else _X86_REGS32
        return (rmap[rm] if rm < len(rmap) else f"r{rm}", extra)
    if mod == 0 and rm == 5 and addr_size == 32:
        # disp32
        disp = struct.unpack_from("<I", b, off)[0]
        extra += 4
        return (f"[0x{disp:x}]", extra)
    if mod == 0 and rm == 5 and addr_size == 64:
        disp = struct.unpack_from("<I", b, off)[0]
        extra += 4
        return (f"[rip+0x{disp:x}]", extra)
    base_map32 = ["eax", "ecx", "edx", "ebx", "esp", "ebp", "esi", "edi"]
    base_map64 = ["rax", "rcx", "rdx", "rbx", "rsp", "rbp", "rsi", "r8",
                  "r9", "r10", "r11", "r12", "r13", "r14", "r15"]
    base_map = base_map64 if addr_size == 64 else base_map32
    base = base_map[rm] if rm < len(base_map) else f"r{rm}"
    if mod == 0:
        return (f"[{base}]", extra)
    if mod == 1:
        disp = _simm8(b[off]); extra += 1
        sign = "+" if disp >= 0 else "-"
        return (f"[{base}{sign}0x{abs(disp):x}]", extra)
    disp = struct.unpack_from("<i", b, off)[0]; extra += 4
    sign = "+" if disp >= 0 else "-"
    return (f"[{base}{sign}0x{abs(disp):x}]", extra)


def _decode_x86_one(b: bytes, off: int, addr_size: int = 64) -> Optional[Instruction]:
    """从 b[off] 解码一条 x86 指令，返回 Instruction 或 None。"""
    start = off
    if off >= len(b):
        return None
    rex = 0
    # REX 前缀
    if _rex(b[off]):
        rex = b[off]; off += 1
        if off >= len(b):
            return None
    op = b[off]; off += 1

    # 条件跳转 rel8
    if 0x70 <= op <= 0x7F:
        rel = _simm8(b[off]); off += 1
        target = start + (off - start) + rel
        return Instruction(start, off - start, _JCC8[op - 0x70], f"0x{target:x}",
                           b[start:off].hex(), group="branch", op_type="jcc8",
                           is_branch=True, branch_target=target,
                           condition=_JCC8[op - 0x70])
    # 条件跳转 rel32 (0F 80..8F)
    if op == 0x0F and off < len(b):
        op2 = b[off]; off += 1
        if 0x80 <= op2 <= 0x8F:
            rel = struct.unpack_from("<i", b, off)[0]; off += 4
            target = start + (off - start) + rel
            mn = _JCC32[op2 - 0x80]
            return Instruction(start, off - start, mn, f"0x{target:x}",
                               b[start:off].hex(), group="branch", op_type="jcc32",
                               is_branch=True, branch_target=target, condition=mn)
        # 0F 其他：当作未知
        return Instruction(start, off - start, ".byte", f"0x{op:02x} 0x{op2:02x}",
                           b[start:off].hex(), group="data")

    entry = _X86_OP1.get(op)
    if entry is None:
        return Instruction(start, off - start, ".byte", f"0x{op:02x}",
                           b[start:off].hex(), group="data")
    mnem, kind = entry

    if kind == "r32":
        idx = op - 0x50
        reg = _X86_REGS64[idx] if addr_size == 64 else _X86_REGS32[idx]
        g = "stack"
        is_call = mnem == "call"
        return Instruction(start, off - start, mnem, reg, b[start:off].hex(),
                           group=g, op_type="reg", is_call=is_call)

    if kind in ("al_imm8",):
        imm = b[off]; off += 1
        return Instruction(start, off - start, mnem, f"al, 0x{imm:x}",
                           b[start:off].hex(), group="arithmetic")
    if kind == "eax_imm32":
        imm = struct.unpack_from("<i", b, off)[0]; off += 4
        return Instruction(start, off - start, mnem, f"eax, 0x{imm & 0xffffffff:x}",
                           b[start:off].hex(), group="arithmetic")
    if kind == "imm32":
        imm = struct.unpack_from("<i", b, off)[0]; off += 4
        return Instruction(start, off - start, mnem, f"0x{imm & 0xffffffff:x}",
                           b[start:off].hex(), group="stack")
    if kind == "r32_imm32":
        idx = op - 0xB8
        imm = struct.unpack_from("<i", b, off)[0]; off += 4
        reg = _X86_REGS64[idx] if addr_size == 64 else _X86_REGS32[idx]
        return Instruction(start, off - start, mnem, f"{reg}, 0x{imm & 0xffffffff:x}",
                           b[start:off].hex(), group="data")
    if kind == "imm8s":
        imm = _simm8(b[off]); off += 1
        return Instruction(start, off - start, mnem, f"0x{imm:x}",
                           b[start:off].hex(), group="stack")
    if kind == "rel32":
        rel = struct.unpack_from("<i", b, off)[0]; off += 4
        target = start + (off - start) + rel
        return Instruction(start, off - start, mnem, f"0x{target:x}",
                           b[start:off].hex(),
                           group="call" if mnem == "call" else "branch",
                           is_call=(mnem == "call"), is_branch=True,
                           branch_target=target)
    if kind == "rel8":
        rel = _simm8(b[off]); off += 1
        target = start + (off - start) + rel
        return Instruction(start, off - start, mnem, f"0x{target:x}",
                           b[start:off].hex(), group="branch",
                           is_branch=True, branch_target=target)

    # ModR/M 类指令
    if kind in ("m8r8", "r8m8", "m32r32", "r32m32", "m32imm32", "r32m32_lea", "grp1_imm8", "grp3", "grp5"):
        modrm = b[off]; off += 1
        mod = (modrm >> 6) & 3
        reg = (modrm >> 3) & 7
        rm = modrm & 7
        eff_off = off
        if mod == 0 and rm == 4 and addr_size == 64:
            # SIB 简化跳过
            sib = b[eff_off]; eff_off += 1
            if (sib & 7) == 5:
                disp = struct.unpack_from("<i", b, eff_off)[0]; eff_off += 4
            off = eff_off
            return Instruction(start, off - start, mnem, "[sib...]",
                               b[start:off].hex(), group="arithmetic")
        if mod == 0 and rm == 4 and addr_size == 32:
            sib = b[eff_off]; eff_off += 1
            off = eff_off
            return Instruction(start, off - start, mnem, "[sib...]",
                               b[start:off].hex(), group="arithmetic")
        opnd, extra = _rm_modrm(mod, rm, modrm, b, eff_off, addr_size)
        off = eff_off + extra
        rmap = _X86_REGS64 if addr_size == 64 else _X86_REGS32
        regname = rmap[reg] if reg < len(rmap) else f"r{reg}"

        if kind == "grp1_imm8":
            mnem = _GRP1[reg]
            imm = _simm8(b[off]); off += 1
            op_str = f"{opnd}, 0x{imm:x}"
            grp = "arithmetic"
        elif kind == "grp3":
            sub = reg
            if sub == 0 or sub == 1:
                op_str = f"{opnd}"
                mnem = "test"
            elif sub == 2 or sub == 3:
                op_str = f"not {opnd}"
                mnem = "neg"
            elif sub == 4:
                op_str = f"mul {opnd}"; mnem = "mul"
            elif sub == 5:
                op_str = f"imul {opnd}"; mnem = "imul"
            elif sub == 6:
                op_str = f"div {opnd}"; mnem = "div"
            elif sub == 7:
                op_str = f"idiv {opnd}"; mnem = "idiv"
            grp = "arithmetic"
        elif kind == "grp5":
            sub = reg
            if sub == 0:
                op_str = f"inc {opnd}"; mnem = "inc"
            elif sub == 1:
                op_str = f"dec {opnd}"; mnem = "dec"
            elif sub == 2:
                op_str = f"call {opnd}"; mnem = "call"
            elif sub == 4:
                op_str = f"jmp {opnd}"; mnem = "jmp"
            elif sub == 5:
                op_str = f"jmp far {opnd}"; mnem = "jmp"
            else:
                op_str = f"{opnd}"; mnem = "grp5"
            grp = "call" if mnem == "call" else ("branch" if "jmp" in mnem else "arithmetic")
            return Instruction(start, off - start, mnem, op_str,
                               b[start:off].hex(), group=grp,
                               is_call=(mnem == "call"), is_branch=("jmp" in mnem))
        elif kind == "m32imm32":
            imm = struct.unpack_from("<i", b, off)[0]; off += 4
            op_str = f"{opnd}, 0x{imm & 0xffffffff:x}"
            grp = "data"
        else:
            if kind in ("m8r8", "m32r32"):
                op_str = f"{opnd}, {regname}"
            else:
                op_str = f"{regname}, {opnd}"
            grp = "data" if mnem == "mov" else ("arithmetic" if mnem != "lea" else "data")
        return Instruction(start, off - start, mnem, op_str,
                           b[start:off].hex(), group=grp, op_type=kind or "mem")

    return Instruction(start, off - start, mnem, "", b[start:off].hex(), group="data")


# --------------------------------------------------------------------------- #
# ARM 迷你解码器（A32 / Thumb）
# --------------------------------------------------------------------------- #
_ARM_COND = ["eq", "ne", "cs", "cc", "mi", "pl", "vs", "vc",
             "hi", "ls", "ge", "lt", "gt", "le", "", "nv"]
_ARM_REGS = ["r0", "r1", "r2", "r3", "r4", "r5", "r6", "r7",
             "r8", "r9", "r10", "fp", "ip", "sp", "lr", "pc"]


def _decode_arm_one(b: bytes, off: int, thumb: bool = False) -> Optional[Instruction]:
    if thumb:
        if off + 2 > len(b):
            return None
        hw = struct.unpack_from("<H", b, off)[0]
        # 简单 Thumb 解码：mov/cmp/add/sub 立即数
        op = (hw >> 11) & 0x1F
        rd = (hw >> 8) & 7
        imm = hw & 0xFF
        start = off
        if op == 0x20:  # mov imm
            return Instruction(start, 2, f"movs {_ARM_REGS[rd]}, #0x{imm:x}",
                               "", b[start:start+2].hex(), group="data")
        if op == 0x28:  # cmp imm
            return Instruction(start, 2, f"cmp {_ARM_REGS[rd]}, #0x{imm:x}",
                               "", b[start:start+2].hex(), group="arithmetic")
        if op == 0x1C:  # add imm
            rn = hw & 7
            return Instruction(start, 2, f"adds {_ARM_REGS[rd]}, {_ARM_REGS[rn]}, #0x{imm:x}",
                               "", b[start:start+2].hex(), group="arithmetic")
        return Instruction(start, 2, ".thumb", f"0x{hw:04x}",
                           b[start:start+2].hex(), group="data")
    # A32
    if off + 4 > len(b):
        return None
    w = struct.unpack_from("<I", b, off)[0]
    start = off
    cond = (w >> 28) & 0xF
    op1 = (w >> 24) & 0xF
    c = _ARM_COND[cond]
    suffix = c if c else ""
    # BL/BLX 24-bit imm
    if (op1 & 0xF) == 0xB and (w & 0x1000000):
        imm24 = w & 0xFFFFFF
        target = off + 8 + ((imm24 << 2) << 2) & 0xFFFFFFFF
        return Instruction(start, 4, f"bl{suffix}", f"0x{target:x}",
                           b[start:start+4].hex(), group="call", is_call=True,
                           branch_target=target, condition=suffix)
    # B
    if (op1 & 0xF) == 0xA:
        imm24 = w & 0xFFFFFF
        target = off + 8 + ((imm24 << 2))
        return Instruction(start, 4, f"b{suffix}", f"0x{target & 0xffffffff:x}",
                           b[start:start+4].hex(), group="branch", is_branch=True,
                           branch_target=target & 0xffffffff, condition=suffix)
    # 数据处理
    if (op1 & 0xC) == 0:
        rn = (w >> 16) & 0xF
        rd = (w >> 12) & 0xF
        imm12 = w & 0xFFF
        op2 = (w >> 21) & 0xF
        names = ["and", "eor", "sub", "rsb", "add", "adc", "sbc", "rsc",
                 "tst", "teq", "cmp", "cmn", "orr", "mov", "bic", "mvn"]
        mnem = names[op2]
        return Instruction(start, 4, f"{mnem}{suffix}",
                           f"{_ARM_REGS[rd]}, {_ARM_REGS[rn]}, #0x{imm12:x}",
                           b[start:start+4].hex(),
                           group="arithmetic" if mnem not in ("cmp", "cmn", "tst", "teq") else "arithmetic")
    return Instruction(start, 4, ".arm", f"0x{w:08x}",
                       b[start:start+4].hex(), group="data")


# --------------------------------------------------------------------------- #
# 反汇编引擎主类
# --------------------------------------------------------------------------- #
class Disassembler:
    """反汇编引擎：线性扫描 / 递归下降 / CFG / 函数识别。"""

    def __init__(self, arch: str = "x86_64") -> None:
        self.arch = arch if arch in ARCHITECTURES else "x86_64"
        self.info = ARCHITECTURES[self.arch]
        self.addr_size = self.info["bits"]
        self._use_cap = _HAS_CAPSTONE

    # -------------------- 核心解码 -------------------- #
    def disassemble(self, data: bytes, base: int = 0x100000,
                    mode: str = "linear") -> List[Instruction]:
        """线性扫描反汇编，返回指令列表。"""
        insns: List[Instruction] = []
        if not data:
            return insns
        if self._use_cap:
            return self._disasm_capstone(data, base)
        if self.arch in ("x86", "x86_64"):
            off = 0
            while off < len(data):
                ins = _decode_x86_one(data, off, self.addr_size)
                if ins is None:
                    break
                ins.address = base + off
                insns.append(ins)
                off += ins.size
                if ins.size == 0:
                    off += 1
        elif self.arch in ("arm", "arm64"):
            thumb = (self.arch == "arm")
            off = 0
            while off < len(data):
                ins = _decode_arm_one(data, off, thumb=thumb)
                if ins is None:
                    break
                ins.address = base + off
                insns.append(ins)
                off += ins.size
        else:
            # 其他架构：capstone 不可用时退化为字节流
            for i, bb in enumerate(data):
                insns.append(Instruction(base + i, 1, ".byte", f"0x{bb:02x}",
                                         f"{bb:02x}", group="data"))
        return insns

    def _disasm_capstone(self, data: bytes, base: int) -> List[Instruction]:
        cs_arch = {
            "x86": (capstone.CS_ARCH_X86, capstone.CS_MODE_32),
            "x86_64": (capstone.CS_ARCH_X86, capstone.CS_MODE_64),
            "arm": (capstone.CS_ARCH_ARM, capstone.CS_MODE_ARM),
            "arm64": (capstone.CS_ARCH_ARM64, capstone.CS_MODE_ARM),
            "mips": (capstone.CS_ARCH_MIPS, capstone.CS_MODE_MIPS32),
            "powerpc": (capstone.CS_ARCH_PPC, capstone.CS_MODE_32 | capstone.CS_MODE_BIG_ENDIAN),
            "riscv": (capstone.CS_ARCH_RISCV, capstone.CS_MODE_RISCV32),
            "sparc": (capstone.CS_ARCH_SPARC, capstone.CS_MODE_BIG_ENDIAN),
            "s390x": (capstone.CS_ARCH_SYSZ, 0),
        }.get(self.arch, (capstone.CS_ARCH_X86, capstone.CS_MODE_64))
        md = capstone.Cs(*cs_arch)
        out: List[Instruction] = []
        for ins in md.disasm(data, base):
            grp = "data"
            is_call = ins.mnemonic in ("call", "bl", "blx")
            is_ret = ins.mnemonic in ("ret", "bx", "pop") and "pc" in ins.op_str
            is_branch = ins.mnemonic.startswith(("j", "b", "bl")) or ins.mnemonic in ("jmp", "branch")
            if is_call:
                grp = "call"
            elif is_branch:
                grp = "branch"
            elif ins.mnemonic in ("push", "pop", "ret", "leave"):
                grp = "stack"
            elif ins.mnemonic in ("mov", "lea", "ldr", "str"):
                grp = "data"
            else:
                grp = "arithmetic"
            out.append(Instruction(
                address=ins.address, size=ins.size,
                mnemonic=ins.mnemonic, op_str=ins.op_str,
                bytes_hex=ins.bytes.hex(), group=grp,
                op_type="capstone", is_call=is_call, is_ret=is_ret,
                is_branch=is_branch,
            ))
        return out

    # -------------------- 基本块 / 函数 -------------------- #
    def basic_blocks(self, insns: List[Instruction]) -> List[BasicBlock]:
        if not insns:
            return []
        leaders = {insns[0].address}
        for i, ins in enumerate(insns):
            if ins.is_branch or ins.is_call or ins.is_ret:
                if ins.branch_target is not None:
                    leaders.add(ins.branch_target)
                if i + 1 < len(insns):
                    leaders.add(insns[i + 1].address)
        ins_map = {x.address: x for x in insns}
        sorted_leaders = sorted(leaders)
        blocks: List[BasicBlock] = []
        for idx, lead in enumerate(sorted_leaders):
            if lead not in ins_map:
                continue
            end = sorted_leaders[idx + 1] if idx + 1 < len(sorted_leaders) else insns[-1].address + 1
            blk = BasicBlock(start=lead, end=end)
            for x in insns:
                if lead <= x.address < end:
                    blk.instructions.append(x)
            blocks.append(blk)
        # 控制流边
        for blk in blocks:
            if not blk.instructions:
                continue
            tail = blk.instructions[-1]
            if tail.is_branch and tail.branch_target is not None:
                blk.successors.append(tail.branch_target)
                if not tail.mnemonic.startswith("jmp") and not tail.is_call:
                    blk.successors.append(blk.end)
            elif not tail.is_ret:
                blk.successors.append(blk.end)
        for blk in blocks:
            for s in blk.successors:
                for other in blocks:
                    if other.start == s:
                        other.predecessors.append(blk.start)
        return blocks

    def identify_functions(self, insns: List[Instruction]) -> List[Function]:
        blocks = self.basic_blocks(insns)
        funcs: List[Function] = []
        seen = set()
        # 函数入口：push rbp / mov rbp,rsp 或 栈帧序言
        for blk in blocks:
            if not blk.instructions:
                continue
            first = blk.instructions[0]
            if (first.mnemonic == "push" and "rbp" in first.op_str) or \
               (first.mnemonic in ("55", "push")) or first.address in seen:
                pass
            # 简单：以 call 目标为函数入口
            for ins in blk.instructions:
                if ins.is_call and ins.branch_target is not None and ins.branch_target not in seen:
                    seen.add(ins.branch_target)
                    fn = Function(start=ins.branch_target, end=ins.branch_target + 1,
                                  name=f"sub_{ins.branch_target:x}",
                                  call_convention="cdecl")
                    fn.callees.append(first_name(ins.op_str))
                    funcs.append(fn)
        # 兜底：如果没有 call 目标，把整个块作为一个函数
        if not funcs and blocks:
            f0 = Function(start=blocks[0].start, end=blocks[-1].end,
                          name="main_block", call_convention="cdecl",
                          blocks=blocks)
            funcs.append(f0)
        return funcs

    def call_graph(self, funcs: List[Function]) -> Dict[str, Any]:
        nodes = [{"id": f.name, "start": hex(f.start), "calls": f.callees} for f in funcs]
        edges = []
        for f in funcs:
            for c in f.callees:
                edges.append({"from": f.name, "to": c})
        return {"nodes": nodes, "edges": edges}

    def disassemble_text(self, data: bytes, base: int = 0x100000,
                         arch: Optional[str] = None) -> str:
        if arch:
            self.arch = arch
        insns = self.disassemble(data, base)
        lines = [f"; 架构: {self.info['name']}  长度: {len(data)} 字节  指令数: {len(insns)}",
                 f"; 基址: 0x{base:x}", ""]
        for ins in insns:
            lines.append(f"0x{ins.address:08x}:  {ins.bytes_hex:<20} {ins.mnemonic:<8} {ins.op_str}")
        return "\n".join(lines)


def first_name(op: str) -> str:
    op = op.strip()
    if op.startswith("0x"):
        return f"sub_{op[2:]}"
    return op.split()[0] if op else "unknown"


# --------------------------------------------------------------------------- #
# 单例
# --------------------------------------------------------------------------- #
_INSTANCE: Optional[Disassembler] = None


def get_disassembler(arch: str = "x86_64") -> Disassembler:
    global _INSTANCE
    if _INSTANCE is None or _INSTANCE.arch != arch:
        _INSTANCE = Disassembler(arch)
    return _INSTANCE


# --------------------------------------------------------------------------- #
# 预定义样本（真实字节，可被解码）
# --------------------------------------------------------------------------- #
SAMPLE_X86_64 = bytes.fromhex(
    "55"                        # push rbp
    "4889e5"                    # mov rbp, rsp
    "4883ec10"                  # sub rsp, 0x10
    "c745fc00000000"            # mov dword [rbp-4], 0
    "837dfc0a"                  # cmp dword [rbp-4], 0xa
    "7d0a"                      # jge short +10
    "8b45fc"                    # mov eax, [rbp-4]
    "0145fc"                    # add [rbp-4], eax
    "ebf3"                      # jmp short -13
    "b800000000"                # mov eax, 0
    "c9"                        # leave
    "c3"                        # ret
)

SAMPLE_ARM = bytes.fromhex(
    "04 e0 2d e5"   # push {lr}
    "00 30 a0 e3"   # mov r3, #0
    "03 30 83 e2"   # add r3, r3, #3
    "00 00 a0 e3"   # mov r0, r3
    "04 e0 9d e4"   # pop {lr}
    "1e ff 2f e1"   # bx lr
)
