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

# 注册核心路由
from api_server.real_tools_routes import router as real_tools_router
from api_server.mcp_server_routes import router as mcp_router
from api_server.agent_team_routes import router as agent_team_router
from api_server.weapon_manual_routes import router as weapon_manual_router
from api_server.recon_workflow_routes import router as recon_workflow_router
from api_server.target_lab_routes import router as target_lab_router
from api_server.report_engine_routes import router as report_router
from api_server.scan_history_routes import router as scan_history_router
from api_server.monitor_routes import router as monitor_router
from api_server.vuln_management_routes import router as vuln_mgmt_router
from api_server.asset_management_routes import router as asset_mgmt_router
from api_server.system_config_routes import router as system_config_router
from api_server.export_routes import router as export_router
from api_server.webhook_routes import router as webhook_router
from api_server.audit_log_routes import router as audit_router
from api_server.approval_routes import router as approval_router
from api_server.kill_chain_routes import router as killchain_router
from api_server.rag_knowledge_routes import router as rag_router
from api_server.workflow_engine_routes import router as workflow_router
from api_server.mobile_security_routes import router as mobile_router
from api_server.recon_enhanced_routes import router as recon_enhanced_router
from api_server.report_v2_routes import router as report_v2_router
from api_server.deep_pentest_routes import router as deep_pentest_router
from api_server.core_upgrade_routes import router as core_upgrade_router

# === 批量注册高价值模块（try-except容错，单个失败不影响启动） ===
_EXTRA_ROUTERS = []
for _mod in [
    "api_server.api_security_routes",
    "api_server.compliance_routes",
    "api_server.soc_routes",
    "api_server.soc_center_routes",
    "api_server.soc_deep_routes",
    "api_server.soc_pro_routes",
    "api_server.cloud_security_v2_routes",
    "api_server.cloud_security_real_routes",
    "api_server.cloud_native_security_routes",
    "api_server.container_security_routes",
    "api_server.soar_routes",
    "api_server.soar_deep_routes",
    "api_server.devsecops_routes",
    "api_server.devsecops_deep_routes",
    "api_server.threat_hunt_routes",
    "api_server.llm_provider_routes",
    "api_server.rbac_routes",
    "api_server.health_check_routes",
    "api_server.ai_decision_engine_routes",
    "api_server.report_v3_routes",
    "api_server.vuln_verification_routes",
    "api_server.blockchain_security_routes",
    # === 对标CyberStrike四大升级 - 新模块路由 ===
    "api_server.scanner_engine_routes",
    "api_server.exploit_framework_routes",
    "api_server.report_engine_v2_routes",
    "api_server.owasp_library_routes",
    "api_server.intelligence_layer_routes",
    "api_server.pipeline_routes",
    # === 多领域智能体编排层（新增 v2.0） ===
    "api_server.multi_domain_routes",
    # === 高级模块 v4.0（知识图谱/红蓝绿/MITRE/PoC/Agent安全/任务流） ===
    "api_server.advanced_modules_routes",
    # === 靶场与实战验证 v4.1（DVWA/Juice Shop/端到端验证） ===
    "api_server.range_validation_routes",
    # === API渗透引擎 + Agent守卫 v4.2（JS分析/Katana/Source Map/Jev审批） ===
    "api_server.api_pentest_guardian_routes",
    # === LLM智能引擎 v4.3（真实大模型驱动/自然语言指挥/AI分析） ===
    "api_server.llm_engine_routes",
    # === v4.4 防御增强（AI恶意软件检测/Agentic SOC/MCP安全扫描） ===
    "api_server.v44_defense_routes",
    # === v4.5 统一平台+知识库（安全运营中心/PoC库/攻击链/修复方案/指纹） ===
    "api_server.knowledge_base_routes",
    # === v4.6 AI大模型安全评估（提示注入/数据泄露/Agent安全/赏金报告） ===
    "api_server.ai_assessment_routes",
    # === v4.7 GitHub搜索升级（遗传算法进化/多轮攻击/MCP深度扫描） ===
    "api_server.ai_v47_routes",
]:
    try:
        _m = __import__(_mod, fromlist=["router"])
        _EXTRA_ROUTERS.append(_m.router)
        print(f"[OK] 已注册: {_mod}")
    except Exception as _e:
        print(f"[WARN] {_mod} 注册失败: {_e}")

app.include_router(real_tools_router)
app.include_router(mcp_router)
app.include_router(agent_team_router)
app.include_router(weapon_manual_router)
app.include_router(recon_workflow_router)
app.include_router(target_lab_router)
app.include_router(report_router)
app.include_router(scan_history_router)
app.include_router(monitor_router)
app.include_router(vuln_mgmt_router)
app.include_router(asset_mgmt_router)
app.include_router(system_config_router)
app.include_router(export_router)
app.include_router(webhook_router)
app.include_router(audit_router)
app.include_router(approval_router)
app.include_router(killchain_router)
app.include_router(rag_router)
app.include_router(workflow_router)
app.include_router(mobile_router)
app.include_router(recon_enhanced_router)
app.include_router(report_v2_router)
app.include_router(deep_pentest_router)
app.include_router(core_upgrade_router)

# 批量注册高价值模块
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
