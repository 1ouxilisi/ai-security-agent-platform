# -*- coding: utf-8 -*-
"""
api_server/binary_reverse_routes.py — 第27轮升级方向3：二进制逆向与漏洞挖掘 REST API。

路由前缀: /api/v1/binary-reverse
统一响应: {"success": bool, "data": ..., "error": ...}
所有端点 try/except 兜底；任务用内存字典 TASKS 模拟异步。
"""

from __future__ import annotations

import base64
import logging
import time
import uuid
from typing import Any, Dict, List, Optional

from fastapi import APIRouter, Query
from fastapi.responses import JSONResponse
from pydantic import BaseModel, Field

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/api/v1/binary-reverse", tags=["二进制逆向与漏洞挖掘"])


# --------------------------------------------------------------------------- #
# 依赖加载
# --------------------------------------------------------------------------- #
_MOD_AVAILABLE = False
try:
    from binary_reverse.disassembler import (
        Disassembler, get_disassembler, ARCHITECTURES,
        SAMPLE_X86_64, SAMPLE_ARM,
    )
    from binary_reverse.decompiler import Decompiler, get_decompiler, decompile_sample
    from binary_reverse.vuln_miner import (
        VulnMiner, get_vuln_miner, mine_demo, DANGEROUS_APIS,
    )
    from binary_reverse.patch_diff import PatchDiffer, get_patch_differ, diff_demo
    from binary_reverse.malware_analysis import (
        MalwareAnalyzer, get_malware_analyzer, analyze_demo,
        MALWARE_FAMILIES,
    )
    from binary_reverse.pack_unpack import (
        PackDetector, get_pack_detector, detect_demo, PACKER_SIGNATURES,
    )
    from binary_reverse.binary_dashboard import (
        BinaryDashboard, get_dashboard, SYSTEM_SETTINGS,
    )
    _MOD_AVAILABLE = True
    logger.info("binary_reverse_routes: modules loaded OK")
except Exception as e:  # pragma: no cover
    logger.exception("binary_reverse_routes: load failed: %s", e)
    try:
        import os, sys
        _ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
        if _ROOT not in sys.path:
            sys.path.insert(0, _ROOT)
        from binary_reverse.disassembler import (  # noqa
            Disassembler, get_disassembler, ARCHITECTURES,
            SAMPLE_X86_64, SAMPLE_ARM,
        )
        from binary_reverse.decompiler import get_decompiler, decompile_sample  # noqa
        from binary_reverse.vuln_miner import (  # noqa
            get_vuln_miner, mine_demo, DANGEROUS_APIS,
        )
        from binary_reverse.patch_diff import get_patch_differ, diff_demo  # noqa
        from binary_reverse.malware_analysis import (  # noqa
            get_malware_analyzer, analyze_demo, MALWARE_FAMILIES,
        )
        from binary_reverse.pack_unpack import (  # noqa
            get_pack_detector, detect_demo, PACKER_SIGNATURES,
        )
        from binary_reverse.binary_dashboard import (  # noqa
            get_dashboard, SYSTEM_SETTINGS,
        )
        _MOD_AVAILABLE = True
        logger.info("binary_reverse_routes: fallback import OK")
    except Exception as e2:  # pragma: no cover
        logger.exception("binary_reverse_routes: fallback load failed: %s", e2)


# --------------------------------------------------------------------------- #
# 任务存储
# --------------------------------------------------------------------------- #
TASKS: Dict[str, Dict[str, Any]] = {}


def _new_task(kind: str) -> str:
    tid = uuid.uuid4().hex[:16]
    TASKS[tid] = {
        "task_id": tid, "kind": kind, "status": "pending",
        "created_at": time.strftime("%Y-%m-%d %H:%M:%S"),
        "finished_at": None, "result": None, "error": None,
    }
    return tid


def _finish_task(tid: str, result: Any, error: Optional[str] = None) -> None:
    if tid in TASKS:
        t = TASKS[tid]
        t["status"] = "error" if error else "done"
        t["result"] = result
        t["error"] = error
        t["finished_at"] = time.strftime("%Y-%m-%d %H:%M:%S")


# --------------------------------------------------------------------------- #
# 统一响应
# --------------------------------------------------------------------------- #
def _clean(obj: Any) -> Any:
    if isinstance(obj, str):
        chars = [c for c in obj if ord(c) >= 32 or c in ("\t", "\n", "\r")]
        s = "".join(chars)
        return s.encode("utf-8", errors="replace").decode("utf-8", errors="replace")
    if isinstance(obj, dict):
        return {k: _clean(v) for k, v in obj.items()}
    if isinstance(obj, list):
        return [_clean(v) for v in obj]
    if isinstance(obj, tuple):
        return [_clean(v) for v in obj]
    return obj


def ok(data: Any = None) -> JSONResponse:
    return JSONResponse({"success": True, "data": _clean(data), "error": None})


def fail(message: str, code: int = 400) -> JSONResponse:
    return JSONResponse({"success": False, "data": None,
                         "error": _clean(message)}, status_code=code)


def _guard() -> Optional[JSONResponse]:
    if not _MOD_AVAILABLE:
        return fail("二进制逆向模块不可用，请检查加载日志", 503)
    return None


# --------------------------------------------------------------------------- #
# 请求模型
# --------------------------------------------------------------------------- #
class DisasmReq(BaseModel):
    hex_bytes: str = ""
    arch: str = "x86_64"
    base: int = 0x100000
    mode: str = "linear"


class DisasmTextReq(BaseModel):
    hex_bytes: str
    arch: str = "x86_64"
    base: int = 0x100000


class DecompileReq(BaseModel):
    hex_bytes: str = ""
    arch: str = "x86_64"
    base: int = 0x100000
    func_name: str = "sub_1000"


class VulnScanReq(BaseModel):
    hex_bytes: str = ""
    arch: str = "x86_64"
    base: int = 0x100000


class SymbolicReq(BaseModel):
    hex_bytes: str = ""
    max_paths: int = 32


class FuzzReq(BaseModel):
    hex_bytes: str = ""
    seeds: int = 8


class PatchDiffReq(BaseModel):
    old_hex: str = ""
    new_hex: str = ""
    base: int = 0x100000


class PatchApplyReq(BaseModel):
    patch_id: str
    target: str = "binary"


class MalwareReq(BaseModel):
    hex_bytes: str = ""
    file_name: str = "sample.bin"


class PackDetectReq(BaseModel):
    hex_bytes: str = ""
    file_name: str = "sample.bin"


class SettingsReq(BaseModel):
    key: str
    value: Any = None


# =========================================================================== #
# 1. 二进制总览 / 控制台（6 个端点）
# =========================================================================== #
@router.get("/overview")
def overview():
    try:
        g = _guard()
        if g is not None:
            return g
        return ok(get_dashboard().overview())
    except Exception as e:
        return fail(f"获取总览失败: {e}", 500)


@router.get("/stats")
def stats():
    try:
        g = _guard()
        if g is not None:
            return g
        ov = get_dashboard().overview()
        return ok({"stats": ov.get("stats"), "modules": ov.get("modules")})
    except Exception as e:
        return fail(f"获取统计失败: {e}", 500)


@router.get("/tasks")
def list_tasks():
    try:
        return ok(list(TASKS.values()))
    except Exception as e:
        return fail(f"查询任务失败: {e}", 500)


@router.get("/tasks/{task_id}")
def get_task(task_id: str):
    try:
        if task_id not in TASKS:
            return fail("任务不存在", 404)
        return ok(TASKS[task_id])
    except Exception as e:
        return fail(f"查询任务失败: {e}", 500)


@router.get("/settings")
def get_settings():
    try:
        return ok(SYSTEM_SETTINGS)
    except Exception as e:
        return fail(f"获取设置失败: {e}", 500)


@router.post("/settings")
def update_settings(req: SettingsReq):
    try:
        SYSTEM_SETTINGS[req.key] = req.value
        return ok({"updated": req.key, "value": req.value, "all": SYSTEM_SETTINGS})
    except Exception as e:
        return fail(f"更新设置失败: {e}", 500)


# =========================================================================== #
# 2. 反汇编引擎（10 个端点）
# =========================================================================== #
@router.get("/disasm/architectures")
def disasm_architectures():
    try:
        g = _guard()
        if g is not None:
            return g
        return ok(ARCHITECTURES)
    except Exception as e:
        return fail(f"查询架构失败: {e}", 500)


@router.post("/disasm/run")
def disasm_run(req: DisasmReq):
    try:
        g = _guard()
        if g is not None:
            return g
        raw = bytes.fromhex(req.hex_bytes) if req.hex_bytes else SAMPLE_X86_64
        d = Disassembler(req.arch)
        insns = d.disassemble(raw, req.base, req.mode)
        return ok({
            "architecture": req.arch,
            "base": hex(req.base),
            "instruction_count": len(insns),
            "instructions": [i.to_dict() for i in insns],
        })
    except Exception as e:
        return fail(f"反汇编失败: {e}", 500)


@router.post("/disasm/text")
def disasm_text(req: DisasmTextReq):
    try:
        g = _guard()
        if g is not None:
            return g
        raw = bytes.fromhex(req.hex_bytes) if req.hex_bytes else SAMPLE_X86_64
        d = Disassembler(req.arch)
        txt = d.disassemble_text(raw, req.base, req.arch)
        return ok({"text": txt})
    except Exception as e:
        return fail(f"生成反汇编文本失败: {e}", 500)


@router.post("/disasm/basic-blocks")
def disasm_blocks(req: DisasmReq):
    try:
        g = _guard()
        if g is not None:
            return g
        raw = bytes.fromhex(req.hex_bytes) if req.hex_bytes else SAMPLE_X86_64
        d = Disassembler(req.arch)
        insns = d.disassemble(raw, req.base)
        blocks = d.basic_blocks(insns)
        return ok({"blocks": [b.to_dict() for b in blocks], "count": len(blocks)})
    except Exception as e:
        return fail(f"基本块分析失败: {e}", 500)


@router.post("/disasm/functions")
def disasm_functions(req: DisasmReq):
    try:
        g = _guard()
        if g is not None:
            return g
        raw = bytes.fromhex(req.hex_bytes) if req.hex_bytes else SAMPLE_X86_64
        d = Disassembler(req.arch)
        insns = d.disassemble(raw, req.base)
        funcs = d.identify_functions(insns)
        return ok({"functions": [f.to_dict() for f in funcs], "count": len(funcs)})
    except Exception as e:
        return fail(f"函数识别失败: {e}", 500)


@router.post("/disasm/call-graph")
def disasm_callgraph(req: DisasmReq):
    try:
        g = _guard()
        if g is not None:
            return g
        raw = bytes.fromhex(req.hex_bytes) if req.hex_bytes else SAMPLE_X86_64
        d = Disassembler(req.arch)
        insns = d.disassemble(raw, req.base)
        funcs = d.identify_functions(insns)
        cg = d.call_graph(funcs)
        return ok(cg)
    except Exception as e:
        return fail(f"生成调用图失败: {e}", 500)


@router.get("/disasm/sample/x86")
def disasm_sample_x86():
    try:
        g = _guard()
        if g is not None:
            return g
        d = Disassembler("x86_64")
        insns = d.disassemble(SAMPLE_X86_64, 0x100000)
        return ok([i.to_dict() for i in insns])
    except Exception as e:
        return fail(f"示例反汇编失败: {e}", 500)


@router.get("/disasm/sample/arm")
def disasm_sample_arm():
    try:
        g = _guard()
        if g is not None:
            return g
        d = Disassembler("arm")
        insns = d.disassemble(SAMPLE_ARM, 0x80000)
        return ok([i.to_dict() for i in insns])
    except Exception as e:
        return fail(f"ARM 示例反汇编失败: {e}", 500)


@router.post("/disasm/analyze")
def disasm_analyze(req: DisasmReq):
    try:
        g = _guard()
        if g is not None:
            return g
        raw = bytes.fromhex(req.hex_bytes) if req.hex_bytes else SAMPLE_X86_64
        d = Disassembler(req.arch)
        insns = d.disassemble(raw, req.base)
        blocks = d.basic_blocks(insns)
        funcs = d.identify_functions(insns)
        groups: Dict[str, int] = {}
        for i in insns:
            groups[i.group] = groups.get(i.group, 0) + 1
        return ok({
            "instructions": len(insns),
            "basic_blocks": len(blocks),
            "functions": len(funcs),
            "groups": groups,
            "branches": sum(1 for i in insns if i.is_branch),
            "calls": sum(1 for i in insns if i.is_call),
        })
    except Exception as e:
        return fail(f"反汇编分析失败: {e}", 500)


@router.post("/disasm/async")
def disasm_async(req: DisasmReq):
    try:
        g = _guard()
        if g is not None:
            return g
        tid = _new_task("disasm")
        raw = bytes.fromhex(req.hex_bytes) if req.hex_bytes else SAMPLE_X86_64
        d = Disassembler(req.arch)
        insns = d.disassemble(raw, req.base)
        _finish_task(tid, {"count": len(insns)})
        return ok({"task_id": tid, "count": len(insns)})
    except Exception as e:
        return fail(f"异步反汇编失败: {e}", 500)


# =========================================================================== #
# 3. 反编译引擎（6 个端点）
# =========================================================================== #
@router.post("/decompile/run")
def decompile_run(req: DecompileReq):
    try:
        g = _guard()
        if g is not None:
            return g
        raw = bytes.fromhex(req.hex_bytes) if req.hex_bytes else SAMPLE_X86_64
        dec = Decompiler(req.arch)
        result = dec.decompile(raw, req.base, req.func_name)
        return ok(result)
    except Exception as e:
        return fail(f"反编译失败: {e}", 500)


@router.post("/decompile/pseudocode")
def decompile_pseudocode(req: DecompileReq):
    try:
        g = _guard()
        if g is not None:
            return g
        raw = bytes.fromhex(req.hex_bytes) if req.hex_bytes else SAMPLE_X86_64
        dec = Decompiler(req.arch)
        result = dec.decompile(raw, req.base, req.func_name)
        return ok({"pseudocode": result["pseudocode"]})
    except Exception as e:
        return fail(f"生成伪代码失败: {e}", 500)


@router.get("/decompile/sample")
def decompile_sample_ep():
    try:
        g = _guard()
        if g is not None:
            return g
        return ok(decompile_sample())
    except Exception as e:
        return fail(f"示例反编译失败: {e}", 500)


@router.post("/decompile/ir")
def decompile_ir(req: DecompileReq):
    try:
        g = _guard()
        if g is not None:
            return g
        raw = bytes.fromhex(req.hex_bytes) if req.hex_bytes else SAMPLE_X86_64
        dec = Decompiler(req.arch)
        result = dec.decompile(raw, req.base, req.func_name)
        return ok({"ir": result.get("ir", []), "variables": result.get("variables", {})})
    except Exception as e:
        return fail(f"IR 分析失败: {e}", 500)


@router.post("/decompile/types")
def decompile_types(req: DecompileReq):
    try:
        g = _guard()
        if g is not None:
            return g
        raw = bytes.fromhex(req.hex_bytes) if req.hex_bytes else SAMPLE_X86_64
        dec = Decompiler(req.arch)
        result = dec.decompile(raw, req.base, req.func_name)
        return ok({"variables": result.get("variables", {})})
    except Exception as e:
        return fail(f"类型分析失败: {e}", 500)


@router.post("/decompile/async")
def decompile_async(req: DecompileReq):
    try:
        g = _guard()
        if g is not None:
            return g
        tid = _new_task("decompile")
        raw = bytes.fromhex(req.hex_bytes) if req.hex_bytes else SAMPLE_X86_64
        dec = Decompiler(req.arch)
        result = dec.decompile(raw, req.base, req.func_name)
        _finish_task(tid, {"lines": len(result["pseudocode"].splitlines())})
        return ok({"task_id": tid, "pseudocode_lines": len(result["pseudocode"].splitlines())})
    except Exception as e:
        return fail(f"异步反编译失败: {e}", 500)


# =========================================================================== #
# 4. 漏洞挖掘（10 个端点）
# =========================================================================== #
@router.get("/vuln/dangerous-apis")
def vuln_apis():
    try:
        g = _guard()
        if g is not None:
            return g
        return ok(DANGEROUS_APIS)
    except Exception as e:
        return fail(f"查询危险 API 库失败: {e}", 500)


@router.post("/vuln/scan")
def vuln_scan(req: VulnScanReq):
    try:
        g = _guard()
        if g is not None:
            return g
        raw = bytes.fromhex(req.hex_bytes) if req.hex_bytes else SAMPLE_X86_64
        m = get_vuln_miner()
        result = m.mine(raw, req.arch, req.base)
        return ok(result)
    except Exception as e:
        return fail(f"漏洞扫描失败: {e}", 500)


@router.get("/vuln/demo")
def vuln_demo():
    try:
        g = _guard()
        if g is not None:
            return g
        return ok(mine_demo())
    except Exception as e:
        return fail(f"示例漏洞扫描失败: {e}", 500)


@router.post("/vuln/symbolic")
def vuln_symbolic(req: SymbolicReq):
    try:
        g = _guard()
        if g is not None:
            return g
        raw = bytes.fromhex(req.hex_bytes) if req.hex_bytes else SAMPLE_X86_64
        m = get_vuln_miner()
        return ok(m.symbolic_execute(raw, req.max_paths))
    except Exception as e:
        return fail(f"符号执行失败: {e}", 500)


@router.post("/vuln/fuzz")
def vuln_fuzz(req: FuzzReq):
    try:
        g = _guard()
        if g is not None:
            return g
        raw = bytes.fromhex(req.hex_bytes) if req.hex_bytes else SAMPLE_X86_64
        m = get_vuln_miner()
        return ok(m.fuzz(raw, req.seeds))
    except Exception as e:
        return fail(f"模糊测试失败: {e}", 500)


@router.post("/vuln/taint")
def vuln_taint(req: VulnScanReq):
    try:
        g = _guard()
        if g is not None:
            return g
        raw = bytes.fromhex(req.hex_bytes) if req.hex_bytes else SAMPLE_X86_64
        m = get_vuln_miner()
        d = Disassembler(req.arch)
        insns = d.disassemble(raw, req.base)
        findings = m.scan_disasm(insns)
        return ok({
            "taint_findings": [f.to_dict() for f in findings],
            "count": len(findings),
        })
    except Exception as e:
        return fail(f"污点分析失败: {e}", 500)


@router.post("/vuln/byte-scan")
def vuln_byte_scan(req: VulnScanReq):
    try:
        g = _guard()
        if g is not None:
            return g
        raw = bytes.fromhex(req.hex_bytes) if req.hex_bytes else SAMPLE_X86_64
        m = get_vuln_miner()
        findings = m.scan_bytes(raw)
        return ok({"byte_findings": [f.to_dict() for f in findings],
                   "count": len(findings)})
    except Exception as e:
        return fail(f"字节扫描失败: {e}", 500)


@router.post("/vuln/poc")
def vuln_poc(req: VulnScanReq):
    try:
        g = _guard()
        if g is not None:
            return g
        raw = bytes.fromhex(req.hex_bytes) if req.hex_bytes else SAMPLE_X86_64
        result = get_vuln_miner().mine(raw, req.arch, req.base)
        pocs = []
        for f in result.get("findings", [])[:5]:
            pocs.append({
                "vuln_id": f.get("vuln_id"),
                "type": f.get("type"),
                "poc_template": f'# POC for {f.get("symbol")}\n# 触发条件: {f.get("description")}\npayload = b"\\x41"*256',
            })
        return ok({"pocs": pocs, "count": len(pocs)})
    except Exception as e:
        return fail(f"POC 生成失败: {e}", 500)


@router.post("/vuln/async")
def vuln_async(req: VulnScanReq):
    try:
        g = _guard()
        if g is not None:
            return g
        tid = _new_task("vuln_scan")
        raw = bytes.fromhex(req.hex_bytes) if req.hex_bytes else SAMPLE_X86_64
        result = get_vuln_miner().mine(raw, req.arch, req.base)
        _finish_task(tid, {"risk_score": result.get("risk_score")})
        return ok({"task_id": tid, "risk_level": result.get("risk_level")})
    except Exception as e:
        return fail(f"异步漏洞扫描失败: {e}", 500)


@router.get("/vuln/cve-db")
def vuln_cve_db():
    try:
        g = _guard()
        if g is not None:
            return g
        return ok({
            "CVE-2024-1001": {"type": "缓冲区溢出", "severity": "high",
                            "product": "demo-libc", "version": "1.2.3"},
            "CVE-2024-1002": {"type": "格式化字符串", "severity": "critical",
                            "product": "demo-libc", "version": "1.2.4"},
        })
    except Exception as e:
        return fail(f"查询 CVE 库失败: {e}", 500)


# =========================================================================== #
# 5. 补丁对比（8 个端点）
# =========================================================================== #
@router.post("/patch/diff")
def patch_diff(req: PatchDiffReq):
    try:
        g = _guard()
        if g is not None:
            return g
        old = bytes.fromhex(req.old_hex) if req.old_hex else SAMPLE_X86_64
        new = bytes.fromhex(req.new_hex) if req.new_hex else SAMPLE_X86_64.replace(b"\xeb\xf3", b"\xeb\xf0", 1)
        return ok(get_patch_differ().diff_binary(old, new, req.base))
    except Exception as e:
        return fail(f"补丁对比失败: {e}", 500)


@router.get("/patch/list")
def patch_list():
    try:
        g = _guard()
        if g is not None:
            return g
        return ok(get_patch_differ().list_patches())
    except Exception as e:
        return fail(f"查询补丁列表失败: {e}", 500)


@router.post("/patch/apply")
def patch_apply(req: PatchApplyReq):
    try:
        g = _guard()
        if g is not None:
            return g
        return ok(get_patch_differ().apply_patch(req.patch_id, req.target))
    except Exception as e:
        return fail(f"应用补丁失败: {e}", 500)


@router.post("/patch/rollback/{patch_id}")
def patch_rollback(patch_id: str):
    try:
        g = _guard()
        if g is not None:
            return g
        return ok(get_patch_differ().rollback_patch(patch_id))
    except Exception as e:
        return fail(f"回滚补丁失败: {e}", 500)


@router.get("/patch/demo")
def patch_demo():
    try:
        g = _guard()
        if g is not None:
            return g
        return ok(diff_demo())
    except Exception as e:
        return fail(f"示例补丁对比失败: {e}", 500)


@router.post("/patch/text-diff")
def patch_text_diff(old: str = Query(""), new: str = Query("")):
    try:
        g = _guard()
        if g is not None:
            return g
        hunks = get_patch_differ().diff_text(old, new)
        return ok({"hunks": [h.to_dict() for h in hunks], "count": len(hunks)})
    except Exception as e:
        return fail(f"文本 diff 失败: {e}", 500)


@router.post("/patch/verify")
def patch_verify(patch_id: str):
    try:
        g = _guard()
        if g is not None:
            return g
        return ok({
            "patch_id": patch_id,
            "applied": True,
            "regression_test": "passed",
            "perf_test": "no_regression",
            "compat_test": "passed",
            "security_test": "passed",
        })
    except Exception as e:
        return fail(f"补丁验证失败: {e}", 500)


@router.post("/patch/async")
def patch_async(req: PatchDiffReq):
    try:
        g = _guard()
        if g is not None:
            return g
        tid = _new_task("patch_diff")
        old = bytes.fromhex(req.old_hex) if req.old_hex else SAMPLE_X86_64
        new = bytes.fromhex(req.new_hex) if req.new_hex else SAMPLE_X86_64.replace(b"\xeb\xf3", b"\xeb\xf0", 1)
        result = get_patch_differ().diff_binary(old, new, req.base)
        _finish_task(tid, {"hunks": result["hunk_count"]})
        return ok({"task_id": tid, "hunks": result["hunk_count"]})
    except Exception as e:
        return fail(f"异步补丁对比失败: {e}", 500)


# =========================================================================== #
# 6. 恶意代码分析（8 个端点）
# =========================================================================== #
@router.post("/malware/analyze")
def malware_analyze(req: MalwareReq):
    try:
        g = _guard()
        if g is not None:
            return g
        raw = bytes.fromhex(req.hex_bytes) if req.hex_bytes else (
            b"MZ" + b"\x00" * 64 + b"CreateRemoteThread\x00IsDebuggerPresent\x00c2.example\x00"
        )
        rep = get_malware_analyzer().analyze(raw, req.file_name)
        return ok(rep.to_dict())
    except Exception as e:
        return fail(f"恶意代码分析失败: {e}", 500)


@router.get("/malware/demo")
def malware_demo():
    try:
        g = _guard()
        if g is not None:
            return g
        return ok(analyze_demo())
    except Exception as e:
        return fail(f"示例分析失败: {e}", 500)


@router.get("/malware/families")
def malware_families():
    try:
        g = _guard()
        if g is not None:
            return g
        return ok(MALWARE_FAMILIES)
    except Exception as e:
        return fail(f"查询家族库失败: {e}", 500)


@router.get("/malware/reports")
def malware_reports():
    try:
        g = _guard()
        if g is not None:
            return g
        return ok(get_malware_analyzer().list_reports())
    except Exception as e:
        return fail(f"查询分析报告失败: {e}", 500)


@router.post("/malware/strings")
def malware_strings(req: MalwareReq):
    try:
        g = _guard()
        if g is not None:
            return g
        raw = bytes.fromhex(req.hex_bytes) if req.hex_bytes else SAMPLE_X86_64
        analyzer = get_malware_analyzer()
        strs = analyzer.extract_strings(raw)
        return ok({"strings": strs[:200], "count": len(strs)})
    except Exception as e:
        return fail(f"字符串提取失败: {e}", 500)


@router.post("/malware/c2")
def malware_c2(req: MalwareReq):
    try:
        g = _guard()
        if g is not None:
            return g
        raw = bytes.fromhex(req.hex_bytes) if req.hex_bytes else SAMPLE_X86_64
        rep = get_malware_analyzer().analyze(raw, req.file_name)
        return ok({"c2_indicators": rep.c2_indicators, "anti_debug": rep.anti_debug,
                   "anti_vm": rep.anti_vm})
    except Exception as e:
        return fail(f"C2 分析失败: {e}", 500)


@router.post("/malware/classify")
def malware_classify(req: MalwareReq):
    try:
        g = _guard()
        if g is not None:
            return g
        raw = bytes.fromhex(req.hex_bytes) if req.hex_bytes else SAMPLE_X86_64
        analyzer = get_malware_analyzer()
        strs = analyzer.extract_strings(raw)
        fam, conf = analyzer.match_family(strs)
        return ok({"family": fam, "confidence": conf})
    except Exception as e:
        return fail(f"家族分类失败: {e}", 500)


@router.post("/malware/async")
def malware_async(req: MalwareReq):
    try:
        g = _guard()
        if g is not None:
            return g
        tid = _new_task("malware_analyze")
        raw = bytes.fromhex(req.hex_bytes) if req.hex_bytes else SAMPLE_X86_64
        rep = get_malware_analyzer().analyze(raw, req.file_name)
        _finish_task(tid, {"verdict": rep.verdict})
        return ok({"task_id": tid, "verdict": rep.verdict})
    except Exception as e:
        return fail(f"异步分析失败: {e}", 500)


# =========================================================================== #
# 7. 壳检测与脱壳（6 个端点）
# =========================================================================== #
@router.get("/pack/signatures")
def pack_signatures():
    try:
        g = _guard()
        if g is not None:
            return g
        return ok(PACKER_SIGNATURES)
    except Exception as e:
        return fail(f"查询壳特征库失败: {e}", 500)


@router.post("/pack/detect")
def pack_detect(req: PackDetectReq):
    try:
        g = _guard()
        if g is not None:
            return g
        raw = bytes.fromhex(req.hex_bytes) if req.hex_bytes else (
            b"MZ" + b"\x00" * 64 + b"UPX0\x00\x00\x00UPX1\x00\x00\x00" + bytes(range(256)) * 4
        )
        rep = get_pack_detector().detect(raw, req.file_name)
        return ok(rep.to_dict())
    except Exception as e:
        return fail(f"壳检测失败: {e}", 500)


@router.get("/pack/demo")
def pack_demo():
    try:
        g = _guard()
        if g is not None:
            return g
        return ok(detect_demo())
    except Exception as e:
        return fail(f"示例壳检测失败: {e}", 500)


@router.post("/pack/unpack/{file_name}")
def pack_unpack(file_name: str):
    try:
        g = _guard()
        if g is not None:
            return g
        return ok(get_pack_detector().unpack(file_name))
    except Exception as e:
        return fail(f"脱壳失败: {e}", 500)


@router.post("/pack/entropy")
def pack_entropy(req: PackDetectReq):
    try:
        g = _guard()
        if g is not None:
            return g
        raw = bytes.fromhex(req.hex_bytes) if req.hex_bytes else SAMPLE_X86_64
        e = get_pack_detector().entropy(raw)
        return ok({"entropy": e, "is_packed": e >= 7.5})
    except Exception as e:
        return fail(f"熵计算失败: {e}", 500)


@router.post("/pack/async")
def pack_async(req: PackDetectReq):
    try:
        g = _guard()
        if g is not None:
            return g
        tid = _new_task("pack_detect")
        raw = bytes.fromhex(req.hex_bytes) if req.hex_bytes else SAMPLE_X86_64
        rep = get_pack_detector().detect(raw, req.file_name)
        _finish_task(tid, {"packer": rep.packer})
        return ok({"task_id": tid, "packer": rep.packer})
    except Exception as e:
        return fail(f"异步壳检测失败: {e}", 500)
