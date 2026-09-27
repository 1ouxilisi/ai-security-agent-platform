# -*- coding: utf-8 -*-
"""
fuzzing_platform_routes.py — 第27轮升级方向2：安全 Fuzzing 与模糊测试平台 REST API。

路由前缀: /api/v1/fuzzing-platform
统一响应: {"success": bool, "data": ..., "error": ...}
所有端点 try/except 兜底；任务用内存字典 TASKS 模拟异步。
"""

from __future__ import annotations

import logging
import time
import uuid
from typing import Any, Dict, List, Optional

from fastapi import APIRouter, Query
from fastapi.responses import JSONResponse
from pydantic import BaseModel, Field

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/api/v1/fuzzing-platform", tags=["Fuzzing Platform 安全模糊测试"])


# --------------------------------------------------------------------------- #
# 依赖加载（try-import，带 fallback）
# --------------------------------------------------------------------------- #
_MOD_AVAILABLE = False
try:
    from fuzzing_platform.protocol_fuzzer import (
        get_protocol_fuzzer, PROTOCOLS, MUTATION_STRATEGIES, CRASH_TYPES,
        EXECUTION_MODES,
    )
    from fuzzing_platform.file_fuzzer import (
        get_file_fuzzer, FILE_FORMATS, MUTATION_STRATEGIES as FILE_STRATEGIES,
        CRASH_TYPES as FILE_CRASHES, TARGET_TYPES,
    )
    from fuzzing_platform.api_fuzzer import (
        get_api_fuzzer, HTTP_METHODS, CONTENT_TYPES, PROTOCOLS as API_PROTOS,
        PAYLOADS, VULN_SIGNATURES, PARAMETER_TYPES, parse_openapi,
    )
    from fuzzing_platform.browser_fuzzer import (
        get_browser_fuzzer, BROWSERS, ENGINES, TEST_TARGETS, MUTATION_TYPES as BROWSER_MUTS,
    )
    from fuzzing_platform.kernel_fuzzer import (
        get_kernel_fuzzer, KERNELS, KERNEL_TARGETS, MUTATION_TYPES as KERNEL_MUTS,
        EXEC_MODES,
    )
    from fuzzing_platform.fuzzing_manager import (
        get_fuzzing_manager, PROJECT_STATUSES, TASK_PRIORITIES, TASK_STATUSES,
        COVERAGE_TYPES, REPORT_TYPES,
    )
    from fuzzing_platform.fuzzing_dashboard import (
        get_fuzzing_dashboard, SYSTEM_SETTINGS,
    )
    _MOD_AVAILABLE = True
    logger.info("fuzzing_platform_routes: modules loaded OK")
except Exception as e:  # pragma: no cover
    logger.exception("fuzzing_platform_routes: load failed: %s", e)
    try:
        import os, sys
        _ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
        if _ROOT not in sys.path:
            sys.path.insert(0, _ROOT)
        from fuzzing_platform.protocol_fuzzer import (  # noqa
            get_protocol_fuzzer, PROTOCOLS, MUTATION_STRATEGIES, CRASH_TYPES,
            EXECUTION_MODES,
        )
        from fuzzing_platform.file_fuzzer import (  # noqa
            get_file_fuzzer, FILE_FORMATS, MUTATION_STRATEGIES as FILE_STRATEGIES,
            CRASH_TYPES as FILE_CRASHES, TARGET_TYPES,
        )
        from fuzzing_platform.api_fuzzer import (  # noqa
            get_api_fuzzer, HTTP_METHODS, CONTENT_TYPES, PROTOCOLS as API_PROTOS,
            PAYLOADS, VULN_SIGNATURES, PARAMETER_TYPES, parse_openapi,
        )
        from fuzzing_platform.browser_fuzzer import (  # noqa
            get_browser_fuzzer, BROWSERS, ENGINES, TEST_TARGETS, MUTATION_TYPES as BROWSER_MUTS,
        )
        from fuzzing_platform.kernel_fuzzer import (  # noqa
            get_kernel_fuzzer, KERNELS, KERNEL_TARGETS, MUTATION_TYPES as KERNEL_MUTS,
            EXEC_MODES,
        )
        from fuzzing_platform.fuzzing_manager import (  # noqa
            get_fuzzing_manager, PROJECT_STATUSES, TASK_PRIORITIES, TASK_STATUSES,
            COVERAGE_TYPES, REPORT_TYPES,
        )
        from fuzzing_platform.fuzzing_dashboard import (  # noqa
            get_fuzzing_dashboard, SYSTEM_SETTINGS,
        )
        _MOD_AVAILABLE = True
        logger.info("fuzzing_platform_routes: fallback import OK")
    except Exception as e2:  # pragma: no cover
        logger.exception("fuzzing_platform_routes: fallback load failed: %s", e2)


# --------------------------------------------------------------------------- #
# 任务存储（内存字典模拟异步）
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
        return fail("Fuzzing Platform 模块不可用，请检查加载日志", 503)
    return None


# --------------------------------------------------------------------------- #
# 请求模型
# --------------------------------------------------------------------------- #
class ProtoGenReq(BaseModel):
    protocol: str = "http"
    strategy: str = "random"


class ProtoBatchReq(BaseModel):
    protocol: str = "http"
    count: int = 20
    strategy: str = "random"


class ProtoRunReq(BaseModel):
    protocol: str = "http"
    count: int = 50
    strategy: str = "random"
    mode: str = "serial"


class FileGenReq(BaseModel):
    fmt: str = "png"
    strategy: str = "bitflip"
    target: str = "parser"


class FileBatchReq(BaseModel):
    fmt: str = "png"
    count: int = 20
    strategy: str = "bitflip"


class FileRunReq(BaseModel):
    fmt: str = "png"
    count: int = 50
    strategy: str = "bitflip"
    target: str = "parser"


class ApiDiscoverReq(BaseModel):
    base_url: str = "https://api.example.com"
    wordlist: Optional[List[str]] = None
    detect_methods: bool = True


class ApiOpenapiReq(BaseModel):
    spec: str
    base_url: str = ""


class ApiMutateReq(BaseModel):
    name: str = "id"
    param_type: str = "string"
    vtype: str = "value"


class ApiRunReq(BaseModel):
    endpoint_id: str
    count: int = 30
    protocol: str = "REST"


class BrowserGenReq(BaseModel):
    browser: str = "chrome"
    target: str = "html_parser"
    mtype: str = "html"


class BrowserRunReq(BaseModel):
    browser: str = "chrome"
    target: str = "js_engine"
    count: int = 30
    mtype: str = "js"
    headless: bool = True


class KernelSeqReq(BaseModel):
    length: int = 10
    mtype: str = "sequence"


class KernelRunReq(BaseModel):
    target: str = "syscall"
    count: int = 30
    length: int = 10
    mode: str = "vm"


class ProjectCreateReq(BaseModel):
    name: str
    target: str = ""
    fuzz_type: str = "protocol"
    team: Optional[List[str]] = None


class ProjectUpdateReq(BaseModel):
    name: Optional[str] = None
    target: Optional[str] = None
    fuzz_type: Optional[str] = None
    status: Optional[str] = None
    version: Optional[str] = None
    team: Optional[List[str]] = None
    progress: Optional[float] = None


class TaskCreateReq(BaseModel):
    project_id: str
    name: str
    fuzz_type: str = "protocol"
    priority: str = "medium"
    config: Optional[Dict[str, Any]] = None


class TaskUpdateReq(BaseModel):
    status: Optional[str] = None
    priority: Optional[str] = None
    progress: Optional[float] = None
    log: Optional[str] = None
    log_level: str = "info"


class TaskScheduleReq(BaseModel):
    when: str
    cron: bool = False


class ResultCreateReq(BaseModel):
    project_id: str
    kind: str = "crash"
    data: Dict[str, Any] = Field(default_factory=dict)


class ReportCreateReq(BaseModel):
    report_type: str = "fuzzing"
    project_id: Optional[str] = None


# =========================================================================== #
# 一、控制台总览
# =========================================================================== #
@router.get("/overview")
def dash_overview():
    try:
        g = _guard()
        if g is not None:
            return g
        return ok(get_fuzzing_dashboard().overview())
    except Exception as e:
        return fail(f"总览查询失败: {e}", 500)


@router.get("/crash-wall")
def dash_crash_wall():
    try:
        g = _guard()
        if g is not None:
            return g
        return ok(get_fuzzing_dashboard().crash_wall())
    except Exception as e:
        return fail(f"崩溃墙查询失败: {e}", 500)


@router.get("/coverage-matrix")
def dash_coverage_matrix():
    try:
        g = _guard()
        if g is not None:
            return g
        return ok(get_fuzzing_dashboard().coverage_matrix())
    except Exception as e:
        return fail(f"覆盖率矩阵查询失败: {e}", 500)


@router.get("/performance-matrix")
def dash_performance_matrix():
    try:
        g = _guard()
        if g is not None:
            return g
        return ok(get_fuzzing_dashboard().performance_matrix())
    except Exception as e:
        return fail(f"性能矩阵查询失败: {e}", 500)


@router.get("/supported")
def dash_supported():
    try:
        g = _guard()
        if g is not None:
            return g
        return ok(get_fuzzing_dashboard().supported())
    except Exception as e:
        return fail(f"支持能力查询失败: {e}", 500)


@router.get("/health")
def dash_health():
    try:
        g = _guard()
        if g is not None:
            return g
        return ok(get_fuzzing_dashboard().health())
    except Exception as e:
        return fail(f"健康检查失败: {e}", 500)


# =========================================================================== #
# 二、协议 Fuzzing
# =========================================================================== #
@router.get("/protocol/protocols")
def protocol_list():
    try:
        g = _guard()
        if g is not None:
            return g
        return ok(PROTOCOLS)
    except Exception as e:
        return fail(f"协议列表查询失败: {e}", 500)


@router.get("/protocol/strategies")
def protocol_strategies():
    try:
        g = _guard()
        if g is not None:
            return g
        return ok(MUTATION_STRATEGIES)
    except Exception as e:
        return fail(f"变异策略查询失败: {e}", 500)


@router.get("/protocol/crash-types")
def protocol_crash_types():
    try:
        g = _guard()
        if g is not None:
            return g
        return ok(CRASH_TYPES)
    except Exception as e:
        return fail(f"崩溃类型查询失败: {e}", 500)


@router.get("/protocol/exec-modes")
def protocol_exec_modes():
    try:
        g = _guard()
        if g is not None:
            return g
        return ok(EXECUTION_MODES)
    except Exception as e:
        return fail(f"执行模式查询失败: {e}", 500)


@router.post("/protocol/generate")
def protocol_generate(req: ProtoGenReq):
    try:
        g = _guard()
        if g is not None:
            return g
        return ok(get_protocol_fuzzer().generate_case(req.protocol, req.strategy))
    except Exception as e:
        return fail(f"协议用例生成失败: {e}", 500)


@router.post("/protocol/generate-batch")
def protocol_generate_batch(req: ProtoBatchReq):
    try:
        g = _guard()
        if g is not None:
            return g
        cases = get_protocol_fuzzer().generate_batch(req.protocol, req.count, req.strategy)
        return ok({"count": len(cases), "cases": cases})
    except Exception as e:
        return fail(f"协议批量生成失败: {e}", 500)


@router.post("/protocol/genetic")
def protocol_genetic(req: ProtoBatchReq):
    try:
        g = _guard()
        if g is not None:
            return g
        history = get_protocol_fuzzer().genetic_generate(req.protocol, rounds=3,
                                                         population=req.count)
        return ok({"count": len(history), "history": history})
    except Exception as e:
        return fail(f"遗传算法生成失败: {e}", 500)


@router.post("/protocol/annealing")
def protocol_annealing(req: ProtoBatchReq):
    try:
        g = _guard()
        if g is not None:
            return g
        history = get_protocol_fuzzer().annealing_generate(req.protocol, steps=req.count)
        return ok({"count": len(history), "history": history})
    except Exception as e:
        return fail(f"模拟退火生成失败: {e}", 500)


@router.post("/protocol/run")
def protocol_run(req: ProtoRunReq):
    try:
        g = _guard()
        if g is not None:
            return g
        tid = _new_task("protocol_run")
        result = get_protocol_fuzzer().run(req.protocol, req.count, req.strategy, req.mode)
        _finish_task(tid, result)
        return ok({"task_id": tid, "run": result})
    except Exception as e:
        return fail(f"协议 Fuzzing 执行失败: {e}", 500)


@router.get("/protocol/cases")
def protocol_cases(proto: str = "", limit: int = 50):
    try:
        g = _guard()
        if g is not None:
            return g
        return ok(get_protocol_fuzzer().list_cases(proto or None, limit))
    except Exception as e:
        return fail(f"协议用例查询失败: {e}", 500)


@router.get("/protocol/crashes")
def protocol_crashes(limit: int = 50):
    try:
        g = _guard()
        if g is not None:
            return g
        return ok(get_protocol_fuzzer().list_crashes(limit))
    except Exception as e:
        return fail(f"协议崩溃查询失败: {e}", 500)


@router.post("/protocol/dedup")
def protocol_dedup():
    try:
        g = _guard()
        if g is not None:
            return g
        return ok(get_protocol_fuzzer().dedup())
    except Exception as e:
        return fail(f"协议用例去重失败: {e}", 500)


@router.get("/protocol/classify")
def protocol_classify(proto: str = ""):
    try:
        g = _guard()
        if g is not None:
            return g
        return ok(get_protocol_fuzzer().classify(proto or None))
    except Exception as e:
        return fail(f"协议用例分类失败: {e}", 500)


@router.get("/protocol/stats")
def protocol_stats():
    try:
        g = _guard()
        if g is not None:
            return g
        return ok(get_protocol_fuzzer().stats())
    except Exception as e:
        return fail(f"协议统计查询失败: {e}", 500)


# =========================================================================== #
# 三、文件 Fuzzing
# =========================================================================== #
@router.get("/file/formats")
def file_formats():
    try:
        g = _guard()
        if g is not None:
            return g
        return ok(FILE_FORMATS)
    except Exception as e:
        return fail(f"文件格式查询失败: {e}", 500)


@router.get("/file/strategies")
def file_strategies():
    try:
        g = _guard()
        if g is not None:
            return g
        return ok(FILE_STRATEGIES)
    except Exception as e:
        return fail(f"文件变异策略查询失败: {e}", 500)


@router.get("/file/targets")
def file_targets():
    try:
        g = _guard()
        if g is not None:
            return g
        return ok(TARGET_TYPES)
    except Exception as e:
        return fail(f"文件测试目标查询失败: {e}", 500)


@router.post("/file/generate")
def file_generate(req: FileGenReq):
    try:
        g = _guard()
        if g is not None:
            return g
        return ok(get_file_fuzzer().generate_case(req.fmt, req.strategy, req.target))
    except Exception as e:
        return fail(f"文件用例生成失败: {e}", 500)


@router.post("/file/generate-batch")
def file_generate_batch(req: FileBatchReq):
    try:
        g = _guard()
        if g is not None:
            return g
        cases = get_file_fuzzer().generate_batch(req.fmt, req.count, req.strategy)
        return ok({"count": len(cases), "cases": cases})
    except Exception as e:
        return fail(f"文件批量生成失败: {e}", 500)


@router.post("/file/run")
def file_run(req: FileRunReq):
    try:
        g = _guard()
        if g is not None:
            return g
        tid = _new_task("file_run")
        result = get_file_fuzzer().run(req.fmt, req.count, req.strategy, req.target)
        _finish_task(tid, result)
        return ok({"task_id": tid, "run": result})
    except Exception as e:
        return fail(f"文件 Fuzzing 执行失败: {e}", 500)


@router.get("/file/cases")
def file_cases(fmt: str = "", limit: int = 50):
    try:
        g = _guard()
        if g is not None:
            return g
        return ok(get_file_fuzzer().list_cases(fmt or None, limit))
    except Exception as e:
        return fail(f"文件用例查询失败: {e}", 500)


@router.get("/file/crashes")
def file_crashes(limit: int = 50):
    try:
        g = _guard()
        if g is not None:
            return g
        return ok(get_file_fuzzer().list_crashes(limit))
    except Exception as e:
        return fail(f"文件崩溃查询失败: {e}", 500)


@router.post("/file/dedup")
def file_dedup():
    try:
        g = _guard()
        if g is not None:
            return g
        return ok(get_file_fuzzer().dedup())
    except Exception as e:
        return fail(f"文件用例去重失败: {e}", 500)


@router.get("/file/classify")
def file_classify(fmt: str = ""):
    try:
        g = _guard()
        if g is not None:
            return g
        return ok(get_file_fuzzer().classify(fmt or None))
    except Exception as e:
        return fail(f"文件用例分类失败: {e}", 500)


@router.get("/file/stats")
def file_stats():
    try:
        g = _guard()
        if g is not None:
            return g
        return ok(get_file_fuzzer().stats())
    except Exception as e:
        return fail(f"文件统计查询失败: {e}", 500)


# =========================================================================== #
# 四、API Fuzzing
# =========================================================================== #
@router.get("/api-fuzz/methods")
def apifuzz_methods():
    try:
        g = _guard()
        if g is not None:
            return g
        return ok({"methods": HTTP_METHODS, "content_types": CONTENT_TYPES,
                   "protocols": API_PROTOS, "param_types": PARAMETER_TYPES})
    except Exception as e:
        return fail(f"API 能力查询失败: {e}", 500)


@router.get("/api-fuzz/payloads")
def apifuzz_payloads():
    try:
        g = _guard()
        if g is not None:
            return g
        return ok(PAYLOADS)
    except Exception as e:
        return fail(f"Payload 库查询失败: {e}", 500)


@router.get("/api-fuzz/signatures")
def apifuzz_signatures():
    try:
        g = _guard()
        if g is not None:
            return g
        return ok(VULN_SIGNATURES)
    except Exception as e:
        return fail(f"漏洞特征查询失败: {e}", 500)


@router.post("/api-fuzz/discover")
def apifuzz_discover(req: ApiDiscoverReq):
    try:
        g = _guard()
        if g is not None:
            return g
        eps = get_api_fuzzer().discover(req.base_url, req.wordlist, req.detect_methods)
        return ok({"count": len(eps), "endpoints": eps})
    except Exception as e:
        return fail(f"端点发现失败: {e}", 500)


@router.post("/api-fuzz/import-openapi")
def apifuzz_import_openapi(req: ApiOpenapiReq):
    try:
        g = _guard()
        if g is not None:
            return g
        eps = get_api_fuzzer().import_openapi(req.spec, req.base_url)
        return ok({"count": len(eps), "endpoints": eps})
    except Exception as e:
        return fail(f"OpenAPI 导入失败: {e}", 500)


@router.post("/api-fuzz/mutate-param")
def apifuzz_mutate_param(req: ApiMutateReq):
    try:
        g = _guard()
        if g is not None:
            return g
        return ok(get_api_fuzzer().mutate_param(req.name, req.param_type, req.vtype))
    except Exception as e:
        return fail(f"参数变异失败: {e}", 500)


@router.post("/api-fuzz/run")
def apifuzz_run(req: ApiRunReq):
    try:
        g = _guard()
        if g is not None:
            return g
        tid = _new_task("api_fuzz_run")
        result = get_api_fuzzer().run(req.endpoint_id, req.count, req.protocol)
        _finish_task(tid, result)
        return ok({"task_id": tid, "run": result})
    except Exception as e:
        return fail(f"API Fuzzing 执行失败: {e}", 500)


@router.get("/api-fuzz/endpoints")
def apifuzz_endpoints():
    try:
        g = _guard()
        if g is not None:
            return g
        return ok(get_api_fuzzer().list_endpoints())
    except Exception as e:
        return fail(f"端点列表查询失败: {e}", 500)


@router.get("/api-fuzz/cases")
def apifuzz_cases(limit: int = 50):
    try:
        g = _guard()
        if g is not None:
            return g
        return ok(get_api_fuzzer().list_cases(limit))
    except Exception as e:
        return fail(f"API 用例查询失败: {e}", 500)


@router.get("/api-fuzz/vulns")
def apifuzz_vulns(limit: int = 50):
    try:
        g = _guard()
        if g is not None:
            return g
        return ok(get_api_fuzzer().list_vulns(limit))
    except Exception as e:
        return fail(f"API 漏洞查询失败: {e}", 500)


@router.post("/api-fuzz/dedup")
def apifuzz_dedup():
    try:
        g = _guard()
        if g is not None:
            return g
        return ok(get_api_fuzzer().dedup())
    except Exception as e:
        return fail(f"API 用例去重失败: {e}", 500)


@router.get("/api-fuzz/stats")
def apifuzz_stats():
    try:
        g = _guard()
        if g is not None:
            return g
        return ok(get_api_fuzzer().stats())
    except Exception as e:
        return fail(f"API 统计查询失败: {e}", 500)


# =========================================================================== #
# 五、浏览器 Fuzzing
# =========================================================================== #
@router.get("/browser/browsers")
def browser_browsers():
    try:
        g = _guard()
        if g is not None:
            return g
        return ok({"browsers": BROWSERS, "engines": ENGINES,
                   "targets": TEST_TARGETS, "mutations": BROWSER_MUTS})
    except Exception as e:
        return fail(f"浏览器能力查询失败: {e}", 500)


@router.post("/browser/generate")
def browser_generate(req: BrowserGenReq):
    try:
        g = _guard()
        if g is not None:
            return g
        return ok(get_browser_fuzzer().generate_case(req.browser, req.target, req.mtype))
    except Exception as e:
        return fail(f"浏览器用例生成失败: {e}", 500)


@router.post("/browser/genetic")
def browser_genetic(req: BrowserGenReq):
    try:
        g = _guard()
        if g is not None:
            return g
        history = get_browser_fuzzer().genetic_generate(req.browser, rounds=3, pop=6)
        return ok({"count": len(history), "history": history})
    except Exception as e:
        return fail(f"浏览器遗传生成失败: {e}", 500)


@router.post("/browser/run")
def browser_run(req: BrowserRunReq):
    try:
        g = _guard()
        if g is not None:
            return g
        tid = _new_task("browser_run")
        result = get_browser_fuzzer().run(req.browser, req.target, req.count,
                                          req.mtype, req.headless)
        _finish_task(tid, result)
        return ok({"task_id": tid, "run": result})
    except Exception as e:
        return fail(f"浏览器 Fuzzing 执行失败: {e}", 500)


@router.get("/browser/cases")
def browser_cases(limit: int = 50):
    try:
        g = _guard()
        if g is not None:
            return g
        return ok(get_browser_fuzzer().list_cases(limit))
    except Exception as e:
        return fail(f"浏览器用例查询失败: {e}", 500)


@router.get("/browser/crashes")
def browser_crashes(limit: int = 50):
    try:
        g = _guard()
        if g is not None:
            return g
        return ok(get_browser_fuzzer().list_crashes(limit))
    except Exception as e:
        return fail(f"浏览器崩溃查询失败: {e}", 500)


@router.post("/browser/dedup")
def browser_dedup():
    try:
        g = _guard()
        if g is not None:
            return g
        return ok(get_browser_fuzzer().dedup())
    except Exception as e:
        return fail(f"浏览器用例去重失败: {e}", 500)


@router.get("/browser/classify")
def browser_classify():
    try:
        g = _guard()
        if g is not None:
            return g
        return ok(get_browser_fuzzer().classify())
    except Exception as e:
        return fail(f"浏览器用例分类失败: {e}", 500)


@router.get("/browser/stats")
def browser_stats():
    try:
        g = _guard()
        if g is not None:
            return g
        return ok(get_browser_fuzzer().stats())
    except Exception as e:
        return fail(f"浏览器统计查询失败: {e}", 500)


# =========================================================================== #
# 六、内核 Fuzzing
# =========================================================================== #
@router.get("/kernel/kernels")
def kernel_kernels():
    try:
        g = _guard()
        if g is not None:
            return g
        return ok({"kernels": KERNELS, "targets": KERNEL_TARGETS,
                   "mutations": KERNEL_MUTS, "exec_modes": EXEC_MODES})
    except Exception as e:
        return fail(f"内核能力查询失败: {e}", 500)


@router.get("/kernel/syscalls")
def kernel_syscalls():
    try:
        g = _guard()
        if g is not None:
            return g
        return ok(get_kernel_fuzzer().syscall_table())
    except Exception as e:
        return fail(f"系统调用表查询失败: {e}", 500)


@router.post("/kernel/generate-seq")
def kernel_generate_seq(req: KernelSeqReq):
    try:
        g = _guard()
        if g is not None:
            return g
        return ok(get_kernel_fuzzer().generate_sequence(req.length, req.mtype))
    except Exception as e:
        return fail(f"系统调用序列生成失败: {e}", 500)


@router.get("/kernel/symbolic")
def kernel_symbolic(scno: int = 0):
    try:
        g = _guard()
        if g is not None:
            return g
        return ok({"scno": scno, "constraints": get_kernel_fuzzer().symbolic_hint(scno)})
    except Exception as e:
        return fail(f"符号执行提示查询失败: {e}", 500)


@router.post("/kernel/run")
def kernel_run(req: KernelRunReq):
    try:
        g = _guard()
        if g is not None:
            return g
        tid = _new_task("kernel_run")
        result = get_kernel_fuzzer().run(req.target, req.count, req.length, req.mode)
        _finish_task(tid, result)
        return ok({"task_id": tid, "run": result})
    except Exception as e:
        return fail(f"内核 Fuzzing 执行失败: {e}", 500)


@router.get("/kernel/cases")
def kernel_cases(limit: int = 50):
    try:
        g = _guard()
        if g is not None:
            return g
        return ok(get_kernel_fuzzer().list_cases(limit))
    except Exception as e:
        return fail(f"内核用例查询失败: {e}", 500)


@router.get("/kernel/crashes")
def kernel_crashes(limit: int = 50):
    try:
        g = _guard()
        if g is not None:
            return g
        return ok(get_kernel_fuzzer().list_crashes(limit))
    except Exception as e:
        return fail(f"内核崩溃查询失败: {e}", 500)


@router.post("/kernel/dedup")
def kernel_dedup():
    try:
        g = _guard()
        if g is not None:
            return g
        return ok(get_kernel_fuzzer().dedup())
    except Exception as e:
        return fail(f"内核用例去重失败: {e}", 500)


@router.get("/kernel/classify")
def kernel_classify():
    try:
        g = _guard()
        if g is not None:
            return g
        return ok(get_kernel_fuzzer().classify())
    except Exception as e:
        return fail(f"内核用例分类失败: {e}", 500)


@router.get("/kernel/stats")
def kernel_stats():
    try:
        g = _guard()
        if g is not None:
            return g
        return ok(get_kernel_fuzzer().stats())
    except Exception as e:
        return fail(f"内核统计查询失败: {e}", 500)


# =========================================================================== #
# 七、Fuzzing 管理平台
# =========================================================================== #
@router.get("/manager/meta")
def manager_meta():
    try:
        g = _guard()
        if g is not None:
            return g
        return ok({"project_statuses": PROJECT_STATUSES,
                   "task_priorities": TASK_PRIORITIES,
                   "task_statuses": TASK_STATUSES,
                   "coverage_types": COVERAGE_TYPES,
                   "report_types": REPORT_TYPES})
    except Exception as e:
        return fail(f"管理元数据查询失败: {e}", 500)


@router.post("/manager/projects")
def manager_create_project(req: ProjectCreateReq):
    try:
        g = _guard()
        if g is not None:
            return g
        return ok(get_fuzzing_manager().create_project(req.name, req.target,
                                                       req.fuzz_type, req.team))
    except Exception as e:
        return fail(f"项目创建失败: {e}", 500)


@router.get("/manager/projects")
def manager_list_projects(status: str = ""):
    try:
        g = _guard()
        if g is not None:
            return g
        return ok(get_fuzzing_manager().list_projects(status or None))
    except Exception as e:
        return fail(f"项目列表查询失败: {e}", 500)


@router.get("/manager/projects/{pid}")
def manager_get_project(pid: str):
    try:
        g = _guard()
        if g is not None:
            return g
        p = get_fuzzing_manager().get_project(pid)
        if not p:
            return fail(f"项目 {pid} 不存在", 404)
        return ok(p)
    except Exception as e:
        return fail(f"项目详情查询失败: {e}", 500)


@router.put("/manager/projects/{pid}")
def manager_update_project(pid: str, req: ProjectUpdateReq):
    try:
        g = _guard()
        if g is not None:
            return g
        body = req.model_dump(exclude_none=True)
        p = get_fuzzing_manager().update_project(pid, **body)
        if not p:
            return fail(f"项目 {pid} 不存在", 404)
        return ok(p)
    except Exception as e:
        return fail(f"项目更新失败: {e}", 500)


@router.post("/manager/tasks")
def manager_create_task(req: TaskCreateReq):
    try:
        g = _guard()
        if g is not None:
            return g
        return ok(get_fuzzing_manager().create_task(req.project_id, req.name,
                                                    req.fuzz_type, req.priority, req.config))
    except Exception as e:
        return fail(f"任务创建失败: {e}", 500)


@router.get("/manager/tasks")
def manager_list_tasks(project_id: str = "", status: str = ""):
    try:
        g = _guard()
        if g is not None:
            return g
        return ok(get_fuzzing_manager().list_tasks(project_id or None, status or None))
    except Exception as e:
        return fail(f"任务列表查询失败: {e}", 500)


@router.put("/manager/tasks/{tid}")
def manager_update_task(tid: str, req: TaskUpdateReq):
    try:
        g = _guard()
        if g is not None:
            return g
        body = req.model_dump(exclude_none=True)
        t = get_fuzzing_manager().update_task(tid, **body)
        if not t:
            return fail(f"任务 {tid} 不存在", 404)
        return ok(t)
    except Exception as e:
        return fail(f"任务更新失败: {e}", 500)


@router.post("/manager/tasks/{tid}/schedule")
def manager_schedule_task(tid: str, req: TaskScheduleReq):
    try:
        g = _guard()
        if g is not None:
            return g
        t = get_fuzzing_manager().schedule_task(tid, req.when, req.cron)
        if not t:
            return fail(f"任务 {tid} 不存在", 404)
        return ok(t)
    except Exception as e:
        return fail(f"任务调度失败: {e}", 500)


@router.post("/manager/results")
def manager_record_result(req: ResultCreateReq):
    try:
        g = _guard()
        if g is not None:
            return g
        return ok(get_fuzzing_manager().record_result(req.project_id, req.kind, req.data))
    except Exception as e:
        return fail(f"结果记录失败: {e}", 500)


@router.get("/manager/results")
def manager_list_results(project_id: str = "", kind: str = ""):
    try:
        g = _guard()
        if g is not None:
            return g
        return ok(get_fuzzing_manager().list_results(project_id or None, kind or None))
    except Exception as e:
        return fail(f"结果列表查询失败: {e}", 500)


@router.post("/manager/dedup-crashes")
def manager_dedup_crashes():
    try:
        g = _guard()
        if g is not None:
            return g
        return ok(get_fuzzing_manager().dedup_crashes())
    except Exception as e:
        return fail(f"崩溃去重失败: {e}", 500)


@router.get("/manager/coverage")
def manager_coverage(project_id: str = ""):
    try:
        g = _guard()
        if g is not None:
            return g
        return ok(get_fuzzing_manager().coverage_report(project_id or None))
    except Exception as e:
        return fail(f"覆盖率报告查询失败: {e}", 500)


@router.get("/manager/performance")
def manager_performance(project_id: str = ""):
    try:
        g = _guard()
        if g is not None:
            return g
        return ok(get_fuzzing_manager().performance_report(project_id or None))
    except Exception as e:
        return fail(f"性能报告查询失败: {e}", 500)


@router.post("/manager/reports")
def manager_generate_report(req: ReportCreateReq):
    try:
        g = _guard()
        if g is not None:
            return g
        return ok(get_fuzzing_manager().generate_report(req.report_type, req.project_id))
    except Exception as e:
        return fail(f"报告生成失败: {e}", 500)


@router.get("/manager/reports")
def manager_list_reports():
    try:
        g = _guard()
        if g is not None:
            return g
        return ok(get_fuzzing_manager().list_reports())
    except Exception as e:
        return fail(f"报告列表查询失败: {e}", 500)


@router.get("/manager/overview")
def manager_overview():
    try:
        g = _guard()
        if g is not None:
            return g
        return ok(get_fuzzing_manager().overview())
    except Exception as e:
        return fail(f"管理总览查询失败: {e}", 500)


# =========================================================================== #
# 八、异步任务查询
# =========================================================================== #
@router.get("/tasks/{tid}")
def get_task(tid: str):
    try:
        g = _guard()
        if g is not None:
            return g
        if tid not in TASKS:
            return fail(f"任务 {tid} 不存在", 404)
        return ok(TASKS[tid])
    except Exception as e:
        return fail(f"任务查询失败: {e}", 500)


@router.get("/tasks")
def list_tasks():
    try:
        g = _guard()
        if g is not None:
            return g
        return ok({"count": len(TASKS), "tasks": list(TASKS.values())})
    except Exception as e:
        return fail(f"任务列表查询失败: {e}", 500)


# =========================================================================== #
# 九、系统设置
# =========================================================================== #
@router.get("/settings")
def get_settings():
    try:
        g = _guard()
        if g is not None:
            return g
        return ok(SYSTEM_SETTINGS)
    except Exception as e:
        return fail(f"系统设置查询失败: {e}", 500)
