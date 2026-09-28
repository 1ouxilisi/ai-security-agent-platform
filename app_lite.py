#!/usr/bin/env python3
"""
AI Hacking Agent - 轻量快速启动入口
只加载核心功能模块，启动时间从5分钟降到30秒内
核心功能：真实工具链 + MCP服务 + AI代理队 + 武器手册 + 侦察工作流 + 统一控制台
"""
import sys
import os
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent))

from fastapi import FastAPI, Request
from fastapi.responses import HTMLResponse, JSONResponse
from fastapi.middleware.cors import CORSMiddleware
import uvicorn

app = FastAPI(title="AI Hacking Agent - Core", version="9.0-lite", docs_url="/docs")

app.add_middleware(
    CORSMiddleware, allow_origins=["*"], allow_credentials=True,
    allow_methods=["*"], allow_headers=["*"],
)

API_KEY = os.environ.get("API_AUTH_KEY", "cF_fK3wzzFd3sDU-WykQzDbAKNhn_Jjoyphbmh-adLtwx5ShhU8oLpt94aV_uECT")

@app.middleware("http")
async def auth_middleware(request: Request, call_next):
    if request.url.path.startswith("/api/v1/"):
        key = request.headers.get("X-API-Key", "")
        if key != API_KEY:
            return JSONResponse(status_code=401, content={"error": "Unauthorized", "detail": "需要X-API-Key头"})
    return await call_next(request)

@app.get("/health")
async def health():
    routes = [r.path for r in app.routes if hasattr(r, 'path')]
    return {"status": "ok", "version": "9.0-lite", "routes": {"total": len(routes)}, "mode": "core-lite"}

@app.get("/", response_class=HTMLResponse)
async def root():
    return '<html><body style="background:#0a0e17;color:#e2e8f0;font-family:system-ui;padding:40px"><h1>AI Hacking Agent v9.0 Core</h1><p>统一控制台: <a href="/console" style="color:#38bdf8">/console</a></p><p>API文档: <a href="/docs" style="color:#38bdf8">/docs</a></p><p>健康检查: <a href="/health" style="color:#38bdf8">/health</a></p></body></html>'

# 注册核心路由 — v14: 砍掉Web渗透，聚焦AI安全/移动/区块链
# 保留产品基础（v12: DB+登录+任务队列+报告）和v13新方向
from api_server.v10_ultimate_routes import router as v10_router
from api_server.v11_mcp_routes import router as v11_router
from api_server.v12_product_routes import router as v12_router
from api_server.v13_ai_mobile_chain import router as v13_router
from api_server.system_config_routes import router as system_config_router
from api_server.audit_log_routes import router as audit_router
from api_server.export_routes import router as export_router

# === 只保留AI安全相关的高价值模块 ===
_EXTRA_ROUTERS = []
for _mod in [
    "api_server.ai_assessment_routes",
    "api_server.llm_engine_routes",
    "api_server.blockchain_security_routes",
    "api_server.ai_v47_routes",
    "api_server.ai_decision_engine_routes",
]:
    try:
        _m = __import__(_mod, fromlist=["router"])
        _EXTRA_ROUTERS.append(_m.router)
        print(f"[OK] 已注册: {_mod}")
    except Exception as _e:
        print(f"[SKIP] {_mod}: {_e}")

# 注册保留的路由
app.include_router(v10_router)
app.include_router(v11_router)
app.include_router(v12_router)
app.include_router(v13_router)
app.include_router(system_config_router)
app.include_router(audit_router)
app.include_router(export_router)

# 批量注册AI安全模块
for _r in _EXTRA_ROUTERS:
    app.include_router(_r)

# 统一控制台页面
@app.get("/dashboard")
async def dashboard_redirect():
    return JSONResponse({"status": "redirect", "message": "请访问 /console 查看统一作战控制台", "console_url": "/console"})

@app.get("/console", response_class=HTMLResponse)
async def console_page():
    console_path = os.path.join(os.path.dirname(__file__), "api_server", "console.html")
    with open(console_path, "r", encoding="utf-8") as f:
        return f.read()


@app.get("/v12-console", response_class=HTMLResponse)
async def v12_console_page():
    console_path = os.path.join(os.path.dirname(__file__), "v12_console.html")
    with open(console_path, "r", encoding="utf-8") as f:
        return f.read()

@app.get("/ai-console", response_class=HTMLResponse)
async def ai_decision_console_page():
    console_path = os.path.join(os.path.dirname(__file__), "api_server", "ai_decision_console.html")
    with open(console_path, "r", encoding="utf-8") as f:
        return f.read()

@app.get("/auto-pentest", response_class=HTMLResponse)
async def auto_pentest_console_page():
    """自动化渗透控制台 - 一键6阶段流水线"""
    console_path = os.path.join(os.path.dirname(__file__), "api_server", "auto_pentest_console.html")
    with open(console_path, "r", encoding="utf-8") as f:
        return f.read()

@app.get("/multi-domain-console", response_class=HTMLResponse)
async def multi_domain_console_page():
    """12领域作战控制台 - 全领域Fireteam编排"""
    console_path = os.path.join(os.path.dirname(__file__), "api_server", "multi_domain_console.html")
    with open(console_path, "r", encoding="utf-8") as f:
        return f.read()

@app.get("/war-room", response_class=HTMLResponse)
async def war_room_console_page():
    """智能作战中心 - 6大高级模块统一控制台（知识图谱/红蓝绿/MITRE/PoC/Agent安全/任务流）"""
    console_path = os.path.join(os.path.dirname(__file__), "api_server", "war_room_console.html")
    with open(console_path, "r", encoding="utf-8") as f:
        return f.read()

@app.get("/v47-combat", response_class=HTMLResponse)
async def v47_combat_console_page():
    """v4.7 AI安全作战中心 - 遗传算法进化/多轮攻击编排/MCP深度扫描"""
    console_path = os.path.join(os.path.dirname(__file__), "api_server", "v47_combat_console.html")
    with open(console_path, "r", encoding="utf-8") as f:
        return f.read()

@app.get("/ai-assessment", response_class=HTMLResponse)
async def ai_assessment_console_page():
    """AI大模型安全评估控制台"""
    console_path = os.path.join(os.path.dirname(__file__), "api_server", "ai_assessment_console.html")
    with open(console_path, "r", encoding="utf-8") as f:
        return f.read()

@app.get("/ai-security", response_class=HTMLResponse)
async def ai_security_console():
    """AI大模型安全统一作战中心"""
    p = os.path.join(os.path.dirname(__file__), "api_server", "ai_security_console.html")
    with open(p, "r", encoding="utf-8") as f:
        return f.read()
@app.get("/deep-pentest", response_class=HTMLResponse)
async def deep_pentest_console_page():
    """深度渗透攻击链引擎控制台 - 五大深度引擎统一控制台"""
    console_path = os.path.join(os.path.dirname(__file__), "api_server", "deep_pentest_console.html")
    with open(console_path, "r", encoding="utf-8") as f:
        return f.read()

if __name__ == "__main__":
    print("=" * 60)
    print("  AI Hacking Agent v9.0 Core (轻量快速启动)")
    print("  统一控制台: http://127.0.0.1:8001/console")
    print("  12领域控制台: http://127.0.0.1:8001/multi-domain-console")
    print("  智能作战中心: http://127.0.0.1:8001/war-room")
    print("  v4.7作战中心: http://127.0.0.1:8001/v47-combat")
    print("  深度渗透引擎: http://127.0.0.1:8001/deep-pentest")
    print("  AI安全评估:  http://127.0.0.1:8001/ai-assessment")
    print("  API文档:   http://127.0.0.1:8001/docs")
    print("=" * 60)
    uvicorn.run(app, host="127.0.0.1", port=8001, log_level="info")




