# -*- coding: utf-8 -*-
"""
tools_installer/tool_installer.py — 真实工具安装器

- 一键安装单个工具（按注册表 install.cmd 执行）
- 批量安装所有未安装工具
- 失败自动重试（最多 3 次）
- 每个工具最多 300 秒超时
- 实时日志收集到内存字典，供前端轮询/WebSocket 推送
- 支持用户自定义安装命令
- 升级 / 卸载 / 修复
"""
from __future__ import annotations

import threading
import time
import uuid
from typing import Any, Dict, List, Optional

from . import tool_registry as reg
from .package_manager import detect_all, run_stream

INSTALL_TIMEOUT = 300
MAX_RETRY = 3

# task_id -> task_info
_TASKS: Dict[str, Dict[str, Any]] = {}
_LOCK = threading.Lock()


def _new_task(tool_name: str, cmd: str, mode: str) -> str:
    tid = uuid.uuid4().hex[:12]
    with _LOCK:
        _TASKS[tid] = {
            "task_id": tid,
            "tool": tool_name,
            "cmd": cmd,
            "mode": mode,
            "status": "queued",  # queued/running/success/failed/warning
            "progress": 0,
            "logs": [],
            "started_at": time.time(),
            "finished_at": None,
            "retries": 0,
            "error": None,
        }
    return tid


def _append_log(tid: str, line: str) -> None:
    with _LOCK:
        if tid in _TASKS:
            _TASKS[tid]["logs"].append(line)
            # 控制日志长度
            if len(_TASKS[tid]["logs"]) > 2000:
                _TASKS[tid]["logs"] = _TASKS[tid]["logs"][-1500:]


def _set(tid: str, **kw: Any) -> None:
    with _LOCK:
        if tid in _TASKS:
            _TASKS[tid].update(kw)


def _parse_cmd(tool: Dict[str, Any]) -> List[str]:
    """把注册表中的 cmd 字符串拆成 list，供 subprocess 执行。"""
    cmd = tool.get("install", {}).get("cmd", "")
    if not cmd:
        return []
    # 简单按空格切分，含引号的路径由调用方使用自定义命令
    parts = []
    buf = ""
    in_quote = False
    for ch in cmd:
        if ch == '"':
            in_quote = not in_quote
            continue
        if ch == " " and not in_quote:
            if buf:
                parts.append(buf)
                buf = ""
        else:
            buf += ch
    if buf:
        parts.append(buf)
    return parts


def install_tool(tool_name: str, custom_cmd: Optional[str] = None,
                 run_async: bool = True) -> Dict[str, Any]:
    """安装单个工具。返回 task_id。"""
    tool = reg.find_tool(tool_name)
    if not tool:
        return {"success": False, "error": f"未知工具 {tool_name}"}

    cmd_str = custom_cmd or tool.get("install", {}).get("cmd", "")
    if not cmd_str:
        return {"success": False, "error": f"工具 {tool_name} 未配置安装命令"}

    # 检查包管理器是否就绪
    pm = detect_all()
    method = tool.get("install", {}).get("method", "")
    pm_ready = True
    pm_hint = None
    if method == "choco" and not pm["choco"]["available"]:
        pm_ready = False
        pm_hint = f"未检测到 Chocolatey，请先安装：{pm['choco'].get('install_cmd')}"
    elif method == "scoop" and not pm["scoop"]["available"]:
        pm_ready = False
        pm_hint = f"未检测到 Scoop，请先安装：{pm['scoop'].get('install_cmd')}"
    elif method == "pip" and not pm["pip"]["available"]:
        pm_ready = False
        pm_hint = f"未检测到 pip，请先安装 Python/pip"
    elif method == "npm" and not pm["npm"]["available"]:
        pm_ready = False
        pm_hint = f"未检测到 npm，请先安装 Node.js"
    elif method == "docker" and not pm["docker"]["available"]:
        pm_ready = False
        pm_hint = f"未检测到 Docker，请先安装 Docker Desktop：{pm['docker'].get('install_cmd')}"
    elif method == "go" and not pm["go"]["available"]:
        pm_ready = False
        pm_hint = f"未检测到 Go，请先安装：{pm['go'].get('install_cmd')}"
    elif method == "gem" and not pm["gem"]["available"]:
        pm_ready = False
        pm_hint = f"未检测到 Ruby/gem，请先安装：{pm['gem'].get('install_cmd')}"
    elif method == "git" and not pm["git"]["available"]:
        pm_ready = False
        pm_hint = f"未检测到 git，请先安装"

    tid = _new_task(tool_name, cmd_str, "install")
    if not pm_ready:
        _append_log(tid, f"[ERROR] {pm_hint}")
        _set(tid, status="failed", error=pm_hint,
             finished_at=time.time(), progress=100)
        return {"success": True, "task_id": tid, "status": "failed",
                "pm_hint": pm_hint}

    def _worker() -> None:
        _set(tid, status="running", progress=5)
        _append_log(tid, f"[START] 安装 {tool_name}，命令: {cmd_str}")
        cmd_parts = _parse_cmd(tool) if not custom_cmd else cmd_str.split()
        last_out = ""
        for attempt in range(1, MAX_RETRY + 1):
            _set(tid, retries=attempt - 1,
                 progress=10 + attempt * 20)
            _append_log(tid, f"[TRY] 第 {attempt}/{MAX_RETRY} 次尝试")
            r = run_stream(cmd_parts, timeout=INSTALL_TIMEOUT,
                           on_line=lambda line: _append_log(tid, line))
            last_out = r.get("stdout", "")
            if r["returncode"] == 0:
                _set(tid, status="success", progress=100,
                     finished_at=time.time())
                _append_log(tid, f"[OK] {tool_name} 安装成功")
                return
            if r.get("timed_out"):
                _append_log(tid, "[WARN] 安装超时")
            else:
                _append_log(tid, f"[WARN] 退出码 {r.get('returncode')}")
        _set(tid, status="failed", progress=100,
             finished_at=time.time(),
             error=f"安装失败（重试 {MAX_RETRY} 次），最后输出: {last_out[-500:]}")
        _append_log(tid, f"[FAIL] {tool_name} 安装失败")

    if run_async:
        t = threading.Thread(target=_worker, daemon=True)
        t.start()
    else:
        _worker()
    return {"success": True, "task_id": tid, "status": "running"}


def install_all_uninstalled(run_async: bool = True) -> Dict[str, Any]:
    """批量安装所有未安装工具（顺序执行）。"""
    from .tool_detector import detect_all_tools
    detected = detect_all_tools()
    pending: List[str] = []
    for section in ("native", "python_libs", "docker_images"):
        for item in detected[section]["items"]:
            if not item["installed"]:
                pending.append(item["name"])

    master_id = uuid.uuid4().hex[:12]
    with _LOCK:
        _TASKS[master_id] = {
            "task_id": master_id, "tool": "__batch__",
            "cmd": "batch install all", "mode": "batch_install",
            "status": "queued", "progress": 0,
            "logs": [f"批量安装队列：{len(pending)} 个工具"],
            "started_at": time.time(), "finished_at": None,
            "retries": 0, "error": None,
            "sub_tasks": [], "pending": pending,
        }

    def _worker() -> None:
        _set(master_id, status="running", progress=2)
        results = []
        for i, name in enumerate(pending):
            _append_log(master_id, f"[{i+1}/{len(pending)}] 安装 {name} ...")
            sub = install_tool(name, run_async=False)
            sub_id = sub.get("task_id")
            with _LOCK:
                if master_id in _TASKS:
                    _TASKS[master_id]["sub_tasks"].append(sub_id)
            if sub_id:
                # 等待子任务结束
                for _ in range(INSTALL_TIMEOUT * 2):
                    with _LOCK:
                        st = _TASKS.get(sub_id, {}).get("status")
                    if st in ("success", "failed", "warning"):
                        break
                    time.sleep(0.5)
                with _LOCK:
                    sub_status = _TASKS.get(sub_id, {}).get("status")
                results.append({"tool": name, "status": sub_status})
            _set(master_id, progress=int((i + 1) / max(len(pending), 1) * 100))
        ok = sum(1 for r in results if r["status"] == "success")
        _set(master_id, status="success", progress=100,
             finished_at=time.time(),
             result={"total": len(pending), "success": ok,
                     "failed": len(pending) - ok, "details": results})

    if run_async:
        threading.Thread(target=_worker, daemon=True).start()
    else:
        _worker()
    return {"success": True, "task_id": master_id,
            "pending": pending, "count": len(pending)}


def upgrade_tool(tool_name: str) -> Dict[str, Any]:
    """升级工具（重新执行安装命令）。"""
    tool = reg.find_tool(tool_name)
    if not tool:
        return {"success": False, "error": f"未知工具 {tool_name}"}
    cmd = tool.get("install", {}).get("cmd", "")
    method = tool.get("install", {}).get("method", "")
    # 升级命令优先
    if method == "choco":
        cmd = f"choco upgrade {tool['install'].get('package', tool_name)} -y"
    elif method == "pip":
        cmd = f"pip install --upgrade {tool['install'].get('package', tool_name)}"
    elif method == "npm":
        cmd = f"npm install -g {tool['install'].get('package', tool_name)}"
    elif method == "docker":
        cmd = f"docker pull {tool['install'].get('package', tool_name)}"
    return install_tool(tool_name, custom_cmd=cmd)


def uninstall_tool(tool_name: str, run_async: bool = True) -> Dict[str, Any]:
    """卸载工具。"""
    tool = reg.find_tool(tool_name)
    if not tool:
        return {"success": False, "error": f"未知工具 {tool_name}"}
    method = tool.get("install", {}).get("method", "")
    pkg = tool.get("install", {}).get("package", tool_name)
    cmd_map = {
        "choco": f"choco uninstall {pkg} -y",
        "scoop": f"scoop uninstall {pkg}",
        "pip": f"pip uninstall -y {pkg}",
        "npm": f"npm uninstall -g {pkg}",
        "docker": f"docker rmi {pkg}",
        "gem": f"gem uninstall {pkg} -x",
    }
    cmd = cmd_map.get(method)
    if not cmd:
        return {"success": False,
                "error": f"工具 {tool_name} 不支持自动卸载（method={method}）"}
    return install_tool(tool_name, custom_cmd=cmd, run_async=run_async)


def get_task(task_id: str) -> Dict[str, Any]:
    with _LOCK:
        t = _TASKS.get(task_id)
        if not t:
            return {"success": False, "error": "任务不存在"}
        return {"success": True, "data": dict(t, logs=t["logs"][-200:])}


def list_tasks(limit: int = 50) -> Dict[str, Any]:
    with _LOCK:
        items = sorted(_TASKS.values(),
                       key=lambda x: x.get("started_at", 0), reverse=True)
        out = []
        for t in items[:limit]:
            out.append({k: v for k, v in t.items() if k != "logs"})
            out[-1]["log_lines"] = len(t.get("logs", []))
    return {"success": True, "data": out, "total": len(_TASKS)}


def fix_tool(tool_name: str) -> Dict[str, Any]:
    """修复：重新安装。"""
    return install_tool(tool_name)
