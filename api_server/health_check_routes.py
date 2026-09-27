# -*- coding: utf-8 -*-
"""
health_check_routes.py - 系统健康自检中心 API 路由

全面检测：系统信息/数据库/真实工具/API模块/AI链路/端口/Docker/数据文件。
生成健康评分和诊断报告，自动发现问题并给出修复建议。

路由前缀：/api/v1/health-check
"""
from __future__ import annotations
import os, sys, json, sqlite3, shutil, platform, time, importlib
from datetime import datetime
from typing import Any, Dict, List
from fastapi import APIRouter, Depends
from fastapi.responses import JSONResponse
from pydantic import BaseModel

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from utils.logger import log

try:
    from api_server.auth_integration import verify_auth
    _AUTH_OK = True
except Exception:
    _AUTH_OK = False
    async def verify_auth() -> dict:
        return {"user_id": "admin", "username": "admin", "role": "admin"}

router = APIRouter(prefix="/api/v1/health-check", tags=["系统健康自检"])

PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

def _ok(data: Any) -> JSONResponse:
    return JSONResponse({"code": 0, "data": data})

def _err(status: int, message: str) -> JSONResponse:
    return JSONResponse({"code": status, "error": message}, status_code=status)

# 真实工具路径配置
TOOLS = {
    "nmap": r"C:\Program Files (x86)\Nmap\nmap.exe",
    "nuclei": r"C:\Users\ASUS\tools\nuclei.exe",
    "sqlmap": r"C:\Users\ASUS\tools\sqlmap.bat",
    "nikto": r"C:\Users\ASUS\tools\nikto.bat",
    "subfinder": r"C:\Users\ASUS\bin\subfinder.exe",
    "httpx": r"C:\Users\ASUS\AppData\Local\Doubao\User Data\sandbox_runtime\bases\c98c5042338ed152c6f10ecd8591889f\python\Scripts\httpx.exe",
}

# API路由模块列表（用于检测可导入性）
API_MODULES = [
    "real_tools_routes", "mcp_server_routes", "agent_team_routes", "weapon_manual_routes",
    "recon_workflow_routes", "target_lab_routes", "report_engine_routes", "scan_history_routes",
    "monitor_routes", "vuln_management_routes", "asset_management_routes", "system_config_routes",
    "export_routes", "webhook_routes", "audit_log_routes", "approval_routes", "kill_chain_routes",
    "rag_knowledge_routes", "workflow_engine_routes", "mobile_security_routes",
    "recon_enhanced_routes", "report_v2_routes", "api_security_routes", "compliance_routes",
    "soc_routes", "soc_center_routes", "soc_deep_routes", "soc_pro_routes",
    "cloud_security_v2_routes", "cloud_security_real_routes", "cloud_native_security_routes",
    "container_security_routes", "soar_routes", "soar_deep_routes",
    "devsecops_routes", "devsecops_deep_routes", "threat_hunt_routes",
    "llm_provider_routes", "rbac_routes",
]

# 数据文件检查
DATA_FILES = {
    "CVE漏洞库": os.path.join(PROJECT_ROOT, "data", "vuln_database.json"),
    "系统配置": os.path.join(PROJECT_ROOT, "data", "system_config.json"),
    "控制台页面": os.path.join(PROJECT_ROOT, "api_server", "console.html"),
}

# SQLite数据库文件
DB_FILES = {
    "扫描历史": os.path.join(PROJECT_ROOT, "data", "scan_history.db"),
    "持续监控": os.path.join(PROJECT_ROOT, "data", "monitor.db"),
    "漏洞管理": os.path.join(PROJECT_ROOT, "data", "vuln_management.db"),
    "资产管理": os.path.join(PROJECT_ROOT, "data", "assets.db"),
    "审计日志": os.path.join(PROJECT_ROOT, "data", "audit_log.db"),
    "人工审批": os.path.join(PROJECT_ROOT, "data", "approvals.db"),
    "工作流": os.path.join(PROJECT_ROOT, "data", "workflow_tasks.db"),
    "LLM提供商": os.path.join(PROJECT_ROOT, "data", "llm_providers.db"),
    "RBAC": os.path.join(PROJECT_ROOT, "data", "rbac.db"),
}

# ==================== 系统信息 ====================

def _check_system() -> dict:
    """系统信息检测"""
    try:
        mem = None
        disk = None
        try:
            import psutil
            mem = {"total_gb": round(psutil.virtual_memory().total / 1024**3, 1),
                   "available_gb": round(psutil.virtual_memory().available / 1024**3, 1),
                   "percent": psutil.virtual_memory().percent}
            disk_usage = shutil.disk_usage(PROJECT_ROOT)
            disk = {"total_gb": round(disk_usage.total / 1024**3, 1),
                    "used_gb": round(disk_usage.used / 1024**3, 1),
                    "free_gb": round(disk_usage.free / 1024**3, 1),
                    "percent": round(disk_usage.used / disk_usage.total * 100, 1)}
        except ImportError:
            disk_usage = shutil.disk_usage(PROJECT_ROOT)
            disk = {"total_gb": round(disk_usage.total / 1024**3, 1),
                    "free_gb": round(disk_usage.free / 1024**3, 1)}
        return {
            "status": "healthy",
            "os": platform.system(),
            "os_version": platform.version(),
            "python_version": platform.python_version(),
            "machine": platform.machine(),
            "processor": platform.processor(),
            "memory": mem,
            "disk": disk,
            "project_root": PROJECT_ROOT,
            "project_size_mb": round(_get_dir_size(PROJECT_ROOT) / 1024 / 1024, 1),
        }
    except Exception as e:
        return {"status": "error", "error": str(e)}

def _get_dir_size(path: str) -> int:
    total = 0
    for dirpath, dirnames, filenames in os.walk(path):
        # 跳过.git和__pycache__
        dirnames[:] = [d for d in dirnames if d not in ('.git', '__pycache__', 'node_modules')]
        for f in filenames:
            try:
                fp = os.path.join(dirpath, f)
                total += os.path.getsize(fp)
            except OSError:
                pass
    return total

# ==================== 工具检测 ====================

def _check_tools() -> dict:
    """真实工具可用性检测"""
    results = {}
    available = 0
    for name, path in TOOLS.items():
        exists = os.path.exists(path)
        results[name] = {"path": path, "exists": exists, "status": "available" if exists else "missing"}
        if exists:
            available += 1
    # Nuclei模板检查
    nuclei_templates = r"C:\Users\ASUS\nuclei-templates"
    template_count = 0
    if os.path.exists(nuclei_templates):
        for _, _, files in os.walk(nuclei_templates):
            template_count += len([f for f in files if f.endswith('.yaml') or f.endswith('.yml')])
    return {"tools": results, "available": available, "total": len(TOOLS),
            "nuclei_templates": {"path": nuclei_templates, "count": template_count, "exists": os.path.exists(nuclei_templates)}}

# ==================== 模块检测 ====================

def _check_modules() -> dict:
    """API路由模块可导入性检测"""
    results = {}
    importable = 0
    errors = []
    for mod_name in API_MODULES:
        try:
            mod = importlib.import_module(f"api_server.{mod_name}")
            router_obj = getattr(mod, "router", None)
            route_count = len(router_obj.routes) if router_obj else 0
            results[mod_name] = {"status": "ok", "routes": route_count}
            importable += 1
        except Exception as e:
            results[mod_name] = {"status": "error", "error": str(e)[:200]}
            errors.append({"module": mod_name, "error": str(e)[:200]})
    total_routes = sum(r.get("routes", 0) for r in results.values())
    return {"modules": results, "importable": importable, "total": len(API_MODULES),
            "failed": len(errors), "total_routes": total_routes, "errors": errors[:10]}

# ==================== 数据库检测 ====================

def _check_databases() -> dict:
    """SQLite数据库检测"""
    results = {}
    ok = 0
    for name, path in DB_FILES.items():
        exists = os.path.exists(path)
        size_kb = round(os.path.getsize(path) / 1024, 1) if exists else 0
        can_connect = False
        table_count = 0
        if exists:
            try:
                conn = sqlite3.connect(path)
                tables = conn.execute("SELECT name FROM sqlite_master WHERE type='table'").fetchall()
                table_count = len(tables)
                conn.close()
                can_connect = True
                ok += 1
            except Exception:
                pass
        results[name] = {"path": path, "exists": exists, "size_kb": size_kb,
                         "can_connect": can_connect, "tables": table_count}
    return {"databases": results, "ok": ok, "total": len(DB_FILES)}

# ==================== 数据文件检测 ====================

def _check_data_files() -> dict:
    """关键数据文件检测"""
    results = {}
    ok = 0
    for name, path in DATA_FILES.items():
        exists = os.path.exists(path)
        size_kb = round(os.path.getsize(path) / 1024, 1) if exists else 0
        results[name] = {"path": path, "exists": exists, "size_kb": size_kb}
        if exists:
            ok += 1
    # CVE漏洞库条目数
    cve_count = 0
    cve_path = DATA_FILES.get("CVE漏洞库", "")
    if os.path.exists(cve_path):
        try:
            with open(cve_path, "r", encoding="utf-8") as f:
                data = json.load(f)
                if isinstance(data, list):
                    cve_count = len(data)
                elif isinstance(data, dict):
                    cve_count = len(data.get("cves", data.get("vulnerabilities", [])))
        except Exception:
            pass
    return {"files": results, "ok": ok, "total": len(DATA_FILES), "cve_count": cve_count}

# ==================== 端口检测 ====================

def _check_ports() -> dict:
    """端口监听状态检测"""
    import socket
    ports = {8000: "完整版API", 8001: "轻量版API", 8080: "DVWA靶场", 3000: "Juice Shop靶场"}
    results = {}
    for port, desc in ports.items():
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(1)
            result = sock.connect_ex(("127.0.0.1", port))
            sock.close()
            listening = result == 0
            results[port] = {"description": desc, "listening": listening, "status": "up" if listening else "down"}
        except Exception:
            results[port] = {"description": desc, "listening": False, "status": "error"}
    return {"ports": results, "listening": sum(1 for p in results.values() if p["listening"])}

# ==================== Docker检测 ====================

def _check_docker() -> dict:
    """Docker状态检测"""
    try:
        import subprocess
        result = subprocess.run(["docker", "--version"], capture_output=True, text=True, timeout=5)
        version = result.stdout.strip() if result.returncode == 0 else "unknown"
        # 检查运行中的容器
        result2 = subprocess.run(["docker", "ps", "--format", "{{.Names}}"], capture_output=True, text=True, timeout=5)
        containers = [c for c in result2.stdout.strip().split("\n") if c] if result2.returncode == 0 else []
        return {"installed": result.returncode == 0, "version": version,
                "running_containers": containers, "container_count": len(containers), "status": "healthy" if result.returncode == 0 else "missing"}
    except Exception as e:
        return {"installed": False, "status": "missing", "error": str(e)}

# ==================== AI链路检测 ====================

def _check_ai() -> dict:
    """AI链路状态检测"""
    llm_db = os.path.join(PROJECT_ROOT, "data", "llm_providers.db")
    providers = []
    if os.path.exists(llm_db):
        try:
            conn = sqlite3.connect(llm_db)
            conn.row_factory = sqlite3.Row
            providers = [dict(r) for r in conn.execute("SELECT name,provider_type,model,enabled,status,latency_ms FROM providers ORDER BY priority").fetchall()]
            conn.close()
        except Exception:
            pass
    configured = len(providers)
    available = sum(1 for p in providers if p.get("status") == "available")
    enabled = sum(1 for p in providers if p.get("enabled"))
    return {
        "providers_configured": configured,
        "providers_enabled": enabled,
        "providers_available": available,
        "providers": providers,
        "ai_chain_ready": available > 0,
        "note": "至少需要1个可用的LLM提供商才能启用AI分析链路" if available == 0 else "AI链路就绪",
    }

# ==================== 综合健康检查 ====================

@router.get("/full")
def full_health_check(user: dict = Depends(verify_auth)):
    """全面健康检查（所有维度）"""
    start = time.time()
    system = _check_system()
    tools = _check_tools()
    modules = _check_modules()
    databases = _check_databases()
    data_files = _check_data_files()
    ports = _check_ports()
    docker = _check_docker()
    ai = _check_ai()
    latency = round((time.time() - start) * 1000, 0)

    # 健康评分（0-100）
    score = 100
    issues = []
    # 工具
    if tools["available"] < tools["total"]:
        missing = [k for k, v in tools["tools"].items() if not v["exists"]]
        score -= (len(missing) * 3)
        issues.append({"severity": "medium", "category": "tools", "message": f"缺少工具: {', '.join(missing)}", "fix": "安装对应工具并在系统配置中更新路径"})
    # 模块
    if modules["failed"] > 0:
        score -= (modules["failed"] * 2)
        issues.append({"severity": "high", "category": "modules", "message": f"{modules['failed']}个模块导入失败", "fix": "检查模块依赖和语法错误"})
    # 数据库
    if databases["ok"] < databases["total"]:
        score -= 5
        issues.append({"severity": "low", "category": "databases", "message": "部分数据库文件不存在（首次运行会自动创建）", "fix": "访问对应API会自动初始化数据库"})
    # AI
    if not ai["ai_chain_ready"]:
        score -= 15
        issues.append({"severity": "critical", "category": "ai", "message": "AI链路不可用（没有可用的LLM提供商）", "fix": "在 /llm/providers 添加API Key并测试连通性"})
    # 端口
    if not any(p["listening"] for p in ports["ports"].values()):
        score -= 10
        issues.append({"severity": "high", "category": "ports", "message": "没有API服务在运行", "fix": "运行 python app_lite.py 启动轻量版服务"})
    # 磁盘
    if system.get("disk", {}).get("percent", 0) > 90:
        score -= 5
        issues.append({"severity": "medium", "category": "system", "message": "磁盘使用率超过90%", "fix": "清理磁盘空间"})
    # 内存
    if system.get("memory", {}).get("percent", 0) > 90:
        score -= 5
        issues.append({"severity": "medium", "category": "system", "message": "内存使用率超过90%", "fix": "关闭不必要的程序或增加内存"})

    score = max(0, min(100, score))
    level = "excellent" if score >= 90 else ("good" if score >= 70 else ("fair" if score >= 50 else "critical"))

    report = {
        "health_score": score,
        "health_level": level,
        "checked_at": datetime.now().isoformat(),
        "check_duration_ms": latency,
        "system": system,
        "tools": tools,
        "modules": {"importable": modules["importable"], "total": modules["total"],
                     "failed": modules["failed"], "total_routes": modules["total_routes"]},
        "databases": {"ok": databases["ok"], "total": databases["total"]},
        "data_files": {"ok": data_files["ok"], "total": data_files["total"], "cve_count": data_files["cve_count"]},
        "ports": ports,
        "docker": {"installed": docker["installed"], "version": docker.get("version", ""), "container_count": docker.get("container_count", 0)},
        "ai": ai,
        "issues": issues,
        "issue_count": len(issues),
        "critical_issues": sum(1 for i in issues if i["severity"] == "critical"),
    }
    return _ok(report)

@router.get("/quick")
def quick_health_check(user: dict = Depends(verify_auth)):
    """快速健康检查（仅关键指标）"""
    tools = _check_tools()
    ports = _check_ports()
    ai = _check_ai()
    api_running = ports["ports"].get(8001, {}).get("listening", False) or ports["ports"].get(8000, {}).get("listening", False)
    return _ok({
        "status": "healthy" if (api_running and tools["available"] >= 4) else "degraded",
        "api_running": api_running,
        "tools_available": f"{tools['available']}/{tools['total']}",
        "ai_ready": ai["ai_chain_ready"],
        "checked_at": datetime.now().isoformat(),
    })

@router.get("/tools")
def check_tools(user: dict = Depends(verify_auth)):
    """仅检测工具"""
    return _ok(_check_tools())

@router.get("/modules")
def check_modules(user: dict = Depends(verify_auth)):
    """仅检测模块"""
    return _ok(_check_modules())

@router.get("/databases")
def check_databases(user: dict = Depends(verify_auth)):
    """仅检测数据库"""
    return _ok(_check_databases())

@router.get("/system")
def check_system(user: dict = Depends(verify_auth)):
    """仅检测系统信息"""
    return _ok(_check_system())

@router.get("/ai")
def check_ai(user: dict = Depends(verify_auth)):
    """仅检测AI链路"""
    return _ok(_check_ai())

@router.get("/diagnose")
def diagnose_issues(user: dict = Depends(verify_auth)):
    """问题诊断与修复建议"""
    full = full_health_check(user)
    data = full.body if hasattr(full, 'body') else {}
    if isinstance(data, bytes):
        data = json.loads(data)
    issues = data.get("data", {}).get("issues", [])
    # 按严重程度排序
    severity_order = {"critical": 0, "high": 1, "medium": 2, "low": 3}
    issues.sort(key=lambda x: severity_order.get(x["severity"], 9))
    return _ok({
        "total_issues": len(issues),
        "critical": sum(1 for i in issues if i["severity"] == "critical"),
        "high": sum(1 for i in issues if i["severity"] == "high"),
        "medium": sum(1 for i in issues if i["severity"] == "medium"),
        "low": sum(1 for i in issues if i["severity"] == "low"),
        "issues": issues,
        "summary": "所有检查通过，系统运行正常" if not issues else f"发现{len(issues)}个问题，建议优先处理critical级别",
    })
