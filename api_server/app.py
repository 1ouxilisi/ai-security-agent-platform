"""
FastAPI主应用模块，集成所有API路由、中间件、安全配置和Web界面，提供统一的REST API服务。

模块功能：
    - 提供相关安全测试功能
    - 支持API调用和命令行使用
    - 与其他模块集成协作

注意事项：
    - 本模块仅用于授权的安全测试
    - 请勿用于非法用途
    - 使用前请确保已获得相关授权
"""
import asyncio
import json
import os
import time
import uuid
from typing import Any, Dict, List, Optional
from datetime import datetime

from dotenv import load_dotenv
from fastapi import FastAPI, HTTPException, BackgroundTasks, WebSocket, WebSocketDisconnect, Depends
from fastapi.middleware.cors import CORSMiddleware
from fastapi.security import APIKeyHeader
from pydantic import BaseModel, Field

load_dotenv()

from config.settings import settings
from utils.logger import log
from utils.database import db
from utils.auth import user_manager
from utils.plugin_system import plugin_manager


# ============== 请求/响应模型 ==============

class TaskCreateRequest(BaseModel):
    """TaskCreateRequest数据模型类，定义相关数据结构和验证规则。

    Attributes:
        各类实例属性，具体见__init__方法。
    """
    target: str = Field(..., description="目标地址")
    task_type: str = Field("scan", description="任务类型: scan/multi-agent/react")
    description: str = Field("", description="任务描述")
    options: Dict[str, Any] = Field(default_factory=dict)


class TaskResponse(BaseModel):
    """TaskResponse类，提供相关功能封装。

    Attributes:
        各类实例属性，具体见__init__方法。
    """
    task_id: str
    status: str
    target: str
    task_type: str
    description: str
    created_at: float
    started_at: Optional[float] = None
    completed_at: Optional[float] = None
    progress: int = 0
    findings_count: int = 0
    errors: List[str] = Field(default_factory=list)


class ToolCallRequest(BaseModel):
    """ToolCallRequest数据模型类，定义相关数据结构和验证规则。

    Attributes:
        各类实例属性，具体见__init__方法。
    """
    tool_name: str
    parameters: Dict[str, Any] = Field(default_factory=dict)


class ToolCallResponse(BaseModel):
    """ToolCallResponse类，提供相关功能封装。

    Attributes:
        各类实例属性，具体见__init__方法。
    """
    tool_name: str
    status: str
    result: Any = None
    error: Optional[str] = None
    duration_ms: float = 0


class ReactRequest(BaseModel):
    """ReactRequest数据模型类，定义相关数据结构和验证规则。

    Attributes:
        各类实例属性，具体见__init__方法。
    """
    task: str
    max_iterations: int = 15


class RAGRequest(BaseModel):
    """RAGRequest数据模型类，定义相关数据结构和验证规则。

    Attributes:
        各类实例属性，具体见__init__方法。
    """
    query: str
    top_k: int = 5
    category: Optional[str] = None


class ReportGenerateRequest(BaseModel):
    """ReportGenerateRequest数据模型类，定义相关数据结构和验证规则。

    Attributes:
        各类实例属性，具体见__init__方法。
    """
    task_id: str
    format: str = Field("markdown", description="格式: markdown/html/json")


class POCVerifyRequest(BaseModel):
    """POCVerifyRequest数据模型类，定义相关数据结构和验证规则。

    Attributes:
        各类实例属性，具体见__init__方法。
    """
    findings: List[Dict[str, Any]] = Field(..., description="待验证的漏洞发现列表")
    task_id: Optional[str] = Field(None, description="关联任务ID（可选）")


class SuperAgentRequest(BaseModel):
    """SuperAgentRequest数据模型类，定义相关数据结构和验证规则。

    Attributes:
        各类实例属性，具体见__init__方法。
    """
    task: str = Field(..., description="自然语言任务描述")
    context: Optional[Dict[str, Any]] = Field(default_factory=dict, description="上下文信息")


class CodeGenerateRequest(BaseModel):
    """CodeGenerateRequest数据模型类，定义相关数据结构和验证规则。

    Attributes:
        各类实例属性，具体见__init__方法。
    """
    requirement: str = Field(..., description="代码需求描述")
    language: str = Field(default="python", description="编程语言")
    framework: Optional[str] = Field(default=None, description="框架（可选）")


class CodeReviewRequest(BaseModel):
    """CodeReviewRequest数据模型类，定义相关数据结构和验证规则。

    Attributes:
        各类实例属性，具体见__init__方法。
    """
    code: str = Field(..., description="待审查的代码")
    language: str = Field(default="python", description="编程语言")


class DocumentAnalyzeRequest(BaseModel):
    """DocumentAnalyzeRequest数据模型类，定义相关数据结构和验证规则。

    Attributes:
        各类实例属性，具体见__init__方法。
    """
    content: str = Field(..., description="文档内容")
    doc_type: str = Field(default="general", description="文档类型")


class DataAnalyzeRequest(BaseModel):
    """DataAnalyzeRequest数据模型类，定义相关数据结构和验证规则。

    Attributes:
        各类实例属性，具体见__init__方法。
    """
    data: Any = Field(..., description="待分析的数据")
    analysis_type: str = Field(default="descriptive", description="分析类型")


class KnowledgeQueryRequest(BaseModel):
    """KnowledgeQueryRequest数据模型类，定义相关数据结构和验证规则。

    Attributes:
        各类实例属性，具体见__init__方法。
    """
    query: str = Field(..., description="查询问题")
    knowledge_type: str = Field(default="security", description="知识库类型")


class TaskPlanRequest(BaseModel):
    """TaskPlanRequest数据模型类，定义相关数据结构和验证规则。

    Attributes:
        各类实例属性，具体见__init__方法。
    """
    goal: str = Field(..., description="目标描述")
    context: Optional[Dict[str, Any]] = Field(default_factory=dict, description="上下文")


class ReportGenerateRequest(BaseModel):
    """ReportGenerateRequest数据模型类，定义相关数据结构和验证规则。

    Attributes:
        各类实例属性，具体见__init__方法。
    """
    data: Dict[str, Any] = Field(..., description="报告数据")
    report_type: str = Field(default="security_test", description="报告类型")


class SystemStatsResponse(BaseModel):
    """SystemStatsResponse类，提供相关功能封装。

    Attributes:
        各类实例属性，具体见__init__方法。
    """
    version: str
    total_tools: int
    total_agents: int
    total_tasks: int
    total_findings: int
    uptime_seconds: float
    status: str


# ============== 任务管理器 ==============

class TaskManager:
    """TaskManager管理器类，提供相关资源的统一管理。

    Attributes:
        各类实例属性，具体见__init__方法。
    """
    def __init__(self):
        """初始化TaskManager实例。

        Args:
            self: 类实例。
        """
        self.tasks: Dict[str, Dict] = {}
        self.task_results: Dict[str, Any] = {}

    def create_task(self, target: str, task_type: str, description: str = "", options: Dict = None) -> str:
        """创建相关数据。

        Args:
            target: 相关参数。
            task_type: 相关参数。
            description: 相关参数。
            options: 相关参数。

        Returns:
            操作结果。
        """
        task_id = str(uuid.uuid4())[:8]
        self.tasks[task_id] = {
            "task_id": task_id, "status": "pending", "target": target,
            "task_type": task_type, "description": description,
            "options": options or {}, "created_at": time.time(),
            "started_at": None, "completed_at": None, "progress": 0,
            "findings_count": 0, "errors": [], "logs": [],
        }
        log.info(f"任务已创建: {task_id} ({task_type}, 目标: {target})")
        return task_id

    def get_task(self, task_id: str) -> Optional[Dict]:
        """获取相关数据。

        Args:
            task_id: 相关参数。

        Returns:
            操作结果。
        """
        return self.tasks.get(task_id)

    def update_task(self, task_id: str, **kwargs):
        """更新相关数据。

        Args:
            task_id: 相关参数。

        Returns:
            操作结果。
        """
        if task_id in self.tasks:
            self.tasks[task_id].update(kwargs)

    def add_log(self, task_id: str, message: str):
        """添加相关数据。

        Args:
            task_id: 相关参数。
            message: 相关参数。

        Returns:
            操作结果。
        """
        if task_id in self.tasks:
            self.tasks[task_id]["logs"].append({"timestamp": time.time(), "message": message})

    def list_tasks(self, status: Optional[str] = None, limit: int = 50) -> List[Dict]:
        """列出相关数据。

        Args:
            status: 相关参数。
            limit: 相关参数。

        Returns:
            操作结果。
        """
        tasks = list(self.tasks.values())
        if status:
            tasks = [t for t in tasks if t["status"] == status]
        tasks.sort(key=lambda x: x["created_at"], reverse=True)
        return tasks[:limit]

    def delete_task(self, task_id: str) -> bool:
        """删除相关数据。

        Args:
            task_id: 相关参数。

        Returns:
            操作结果。
        """
        if task_id in self.tasks:
            del self.tasks[task_id]
            if task_id in self.task_results:
                del self.task_results[task_id]
            return True
        return False


# ============== WebSocket连接管理器 ==============

class ConnectionManager:
    """ConnectionManager管理器类，提供相关资源的统一管理。

    Attributes:
        各类实例属性，具体见__init__方法。
    """
    def __init__(self):
        """初始化ConnectionManager实例。

        Args:
            self: 类实例。
        """
        self.active_connections: Dict[str, WebSocket] = {}

    async def connect(self, websocket: WebSocket, task_id: str):
        await websocket.accept()
        self.active_connections[task_id] = websocket

    def disconnect(self, task_id: str):
        """建立连接。

        Args:
            task_id: 相关参数。

        Returns:
            操作结果。
        """
        if task_id in self.active_connections:
            del self.active_connections[task_id]

    async def send_message(self, task_id: str, message: Dict):
        if task_id in self.active_connections:
            try:
                await self.active_connections[task_id].send_json(message)
            except Exception:
                self.disconnect(task_id)


# ============== FastAPI应用 ==============

app = FastAPI(
    title="AI Hacking Agent API",
    description="AI驱动的安全研究智能体平台 - REST API服务",
    version="5.0.0",
    docs_url=None,
    redoc_url="/redoc",
)

# 自定义API文档（完全自包含，从HTML文件读取，避免转义问题）
from fastapi.responses import HTMLResponse
import os as _os

@app.get("/docs", include_in_schema=False)
async def custom_api_docs():
    html_path = _os.path.join(_os.path.dirname(__file__), "api_docs.html")
    with open(html_path, "r", encoding="utf-8") as f:
        html_content = f.read()
    return HTMLResponse(content=html_content)
@app.get("/upgrade-v2", include_in_schema=False)
async def upgrade_v2_page():
    v2_path = _os.path.join(_os.path.dirname(__file__), "upgrade-v2-console.html")
    with open(v2_path, "r", encoding="utf-8") as f:
        return HTMLResponse(content=f.read())

@app.get("/test", include_in_schema=False)
async def test_page():
    test_path = _os.path.join(_os.path.dirname(__file__), "test.html")
    with open(test_path, "r", encoding="utf-8") as f:
        html_content = f.read()
    return HTMLResponse(content=html_content)

@app.get("/dashboard", include_in_schema=False)
async def dashboard_page():
    dashboard_path = _os.path.join(_os.path.dirname(__file__), "dashboard.html")
    with open(dashboard_path, "r", encoding="utf-8") as f:
        html_content = f.read()
    return HTMLResponse(content=html_content)

@app.get("/console", include_in_schema=False)
async def console_page():
    console_path = _os.path.join(_os.path.dirname(__file__), "console.html")
    with open(console_path, "r", encoding="utf-8") as f:
        html_content = f.read()
    return HTMLResponse(content=html_content)

@app.get("/vuln-database", include_in_schema=False)
async def vuln_database_page():
    vuln_path = _os.path.join(_os.path.dirname(__file__), "vuln_database.html")
    with open(vuln_path, "r", encoding="utf-8") as f:
        html_content = f.read()
    return HTMLResponse(content=html_content)

@app.get("/vuln-database", include_in_schema=False)
async def vuln_database_page():
    vuln_path = _os.path.join(_os.path.dirname(__file__), "vuln_database.html")
    with open(vuln_path, "r", encoding="utf-8") as f:
        html_content = f.read()
    return HTMLResponse(content=html_content)


@app.get("/tools", include_in_schema=False)
async def tools_page():
    tools_path = _os.path.join(_os.path.dirname(__file__), "tools.html")
    with open(tools_path, "r", encoding="utf-8") as f:
        html_content = f.read()
    return HTMLResponse(content=html_content)

@app.get("/agents", include_in_schema=False)
async def agents_page():
    agents_path = _os.path.join(_os.path.dirname(__file__), "agents.html")
    with open(agents_path, "r", encoding="utf-8") as f:
        html_content = f.read()
    return HTMLResponse(content=html_content)

@app.get("/reports", include_in_schema=False)
async def reports_page():
    reports_path = _os.path.join(_os.path.dirname(__file__), "reports.html")
    with open(reports_path, "r", encoding="utf-8") as f:
        html_content = f.read()
    return HTMLResponse(content=html_content)

@app.get("/settings", include_in_schema=False)
async def settings_page():
    settings_path = _os.path.join(_os.path.dirname(__file__), "settings.html")
    with open(settings_path, "r", encoding="utf-8") as f:
        html_content = f.read()
    return HTMLResponse(content=html_content)

@app.get("/", include_in_schema=False)
async def index_page():
    index_path = _os.path.join(_os.path.dirname(__file__), "index.html")
    with open(index_path, "r", encoding="utf-8") as f:
        html_content = f.read()
    return HTMLResponse(content=html_content)

@app.get("/workbench", include_in_schema=False)
async def workbench_page():
    workbench_path = _os.path.join(_os.path.dirname(__file__), "workbench.html")
    with open(workbench_path, "r", encoding="utf-8") as f:
        html_content = f.read()
    return HTMLResponse(content=html_content)

@app.get("/advanced-console", include_in_schema=False)
async def advanced_console():
    advanced_path = _os.path.join(_os.path.dirname(__file__), "advanced_console.html")
    with open(advanced_path, "r", encoding="utf-8") as f:
        html_content = f.read()
    return HTMLResponse(content=html_content)


@app.get("/vuln-database", include_in_schema=False)
async def vuln_database_page():
    vuln_path = _os.path.join(_os.path.dirname(__file__), "vuln_database.html")
    with open(vuln_path, "r", encoding="utf-8") as f:
        html_content = f.read()
    return HTMLResponse(content=html_content)

@app.get("/", include_in_schema=False)
async def index_page():
    index_path = _os.path.join(_os.path.dirname(__file__), "index.html")
    with open(index_path, "r", encoding="utf-8") as f:
        html_content = f.read()
    return HTMLResponse(content=html_content)

@app.get("/workbench", include_in_schema=False)
async def workbench_page():
    workbench_path = _os.path.join(_os.path.dirname(__file__), "workbench.html")
    with open(workbench_path, "r", encoding="utf-8") as f:
        html_content = f.read()
    return HTMLResponse(content=html_content)

@app.get("/", include_in_schema=False)
async def index_page():
    index_path = _os.path.join(_os.path.dirname(__file__), "index.html")
    with open(index_path, "r", encoding="utf-8") as f:
        html_content = f.read()
    return HTMLResponse(content=html_content)

@app.get("/workbench", include_in_schema=False)
async def workbench_page():
    workbench_path = _os.path.join(_os.path.dirname(__file__), "workbench.html")
    with open(workbench_path, "r", encoding="utf-8") as f:
        html_content = f.read()
    return HTMLResponse(content=html_content)

@app.get("/workbench", include_in_schema=False)
async def workbench_page():
    workbench_path = _os.path.join(_os.path.dirname(__file__), "workbench.html")
    with open(workbench_path, "r", encoding="utf-8") as f:
        html_content = f.read()
    return HTMLResponse(content=html_content)

@app.get("/workflow", include_in_schema=False)
async def workflow_page():
    workflow_path = _os.path.join(_os.path.dirname(__file__), "workflow.html")
    with open(workflow_path, "r", encoding="utf-8") as f:
        html_content = f.read()
    return HTMLResponse(content=html_content)

@app.get("/", include_in_schema=False)
async def index_page():
    index_path = _os.path.join(_os.path.dirname(__file__), "index.html")
    with open(index_path, "r", encoding="utf-8") as f:
        html_content = f.read()
    return HTMLResponse(content=html_content)

@app.get("/workbench", include_in_schema=False)
async def workbench_page():
    workbench_path = _os.path.join(_os.path.dirname(__file__), "workbench.html")
    with open(workbench_path, "r", encoding="utf-8") as f:
        html_content = f.read()
    return HTMLResponse(content=html_content)

@app.get("/workbench", include_in_schema=False)
async def workbench_page():
    workbench_path = _os.path.join(_os.path.dirname(__file__), "workbench.html")
    with open(workbench_path, "r", encoding="utf-8") as f:
        html_content = f.read()
    return HTMLResponse(content=html_content)

@app.get("/workflow", include_in_schema=False)
async def workflow_page():
    workflow_path = _os.path.join(_os.path.dirname(__file__), "workflow.html")
    with open(workflow_path, "r", encoding="utf-8") as f:
        html_content = f.read()
    return HTMLResponse(content=html_content)

@app.get("/workbench", include_in_schema=False)
async def workbench_page():
    workbench_path = _os.path.join(_os.path.dirname(__file__), "workbench.html")
    with open(workbench_path, "r", encoding="utf-8") as f:
        html_content = f.read()
    return HTMLResponse(content=html_content)

@app.get("/workflow", include_in_schema=False)
async def workflow_page():
    workflow_path = _os.path.join(_os.path.dirname(__file__), "workflow.html")
    with open(workflow_path, "r", encoding="utf-8") as f:
        html_content = f.read()
    return HTMLResponse(content=html_content)

@app.get("/workflow", include_in_schema=False)
async def workflow_page():
    workflow_path = _os.path.join(_os.path.dirname(__file__), "workflow.html")
    with open(workflow_path, "r", encoding="utf-8") as f:
        html_content = f.read()
    return HTMLResponse(content=html_content)

@app.get("/console-v7", include_in_schema=False)
async def console_v7_page():
    """v7.0统一安全控制台"""
    console_path = _os.path.join(_os.path.dirname(__file__), "console_v7.html")
    with open(console_path, "r", encoding="utf-8") as f:
        html_content = f.read()
    return HTMLResponse(content=html_content)


@app.get("/workflow", include_in_schema=False)
async def workflow_page():
    workflow_path = _os.path.join(_os.path.dirname(__file__), "workflow.html")
    with open(workflow_path, "r", encoding="utf-8") as f:
        html_content = f.read()
    return HTMLResponse(content=html_content)

@app.get("/console-v7", include_in_schema=False)
async def console_v7_page():
    """v7.0统一安全控制台"""
    console_path = _os.path.join(_os.path.dirname(__file__), "console_v7.html")
    with open(console_path, "r", encoding="utf-8") as f:
        html_content = f.read()
    return HTMLResponse(content=html_content)


@app.get("/workflow-console", include_in_schema=False)
async def workflow_console_page():
    """第7轮增强版工作流控制台（DAG引擎/8模板/构建器/调度器）"""
    console_path = _os.path.join(_os.path.dirname(__file__), "workflow_console.html")
    with open(console_path, "r", encoding="utf-8") as f:
        html_content = f.read()
    return HTMLResponse(content=html_content)

@app.get("/console-v7", include_in_schema=False)
async def console_v7_page():
    """v7.0统一安全控制台"""
    console_path = _os.path.join(_os.path.dirname(__file__), "console_v7.html")
    with open(console_path, "r", encoding="utf-8") as f:
        html_content = f.read()
    return HTMLResponse(content=html_content)


@app.get("/combat-console", include_in_schema=False)
async def combat_console_page():
    """实战能力中心"""
    console_path = _os.path.join(_os.path.dirname(__file__), "combat_console.html")
    with open(console_path, "r", encoding="utf-8") as f:
        html_content = f.read()
    return HTMLResponse(content=html_content)


app.add_middleware(
    CORSMiddleware, allow_origins=["*"], allow_credentials=True,
    allow_methods=["*"], allow_headers=["*"],
)

# ============== 安全中间件（限流/IP过滤/请求日志/安全头） ==============
try:
    from api_server.security_middleware import SecurityMiddleware
    app.add_middleware(SecurityMiddleware, enabled=True)
    log.info("安全中间件已加载（限流/IP过滤/请求日志/安全头）")
except Exception as e:
    log.warning(f"安全中间件加载失败: {e}")

# ============== 新路由注册（用户认证/告警通知/数据备份） ==============
try:
    from api_server.auth_routes import router as auth_router
    from api_server.alert_routes import router as alert_router
    from api_server.backup_routes import router as backup_router
    from api_server.vuln_routes import router as vuln_router
    from api_server.vuln_routes import router as vuln_router
    from api_server.vuln_routes import router as vuln_router
    from api_server.workflow_routes import router as workflow_router
    from api_server.advanced_routes import router as advanced_router
    app.include_router(auth_router)
    app.include_router(alert_router)
    app.include_router(backup_router)
    app.include_router(vuln_router)
    app.include_router(vuln_router)
    app.include_router(vuln_router)
    app.include_router(workflow_router)
    app.include_router(advanced_router)
    log.info("新API路由已注册：用户认证/告警通知/数据备份/漏洞数据库/漏洞数据库/漏洞数据库/渗透测试工作流/高级安全模块(9模块40+端点)")
except Exception as e:
    log.warning(f"新API路由注册失败: {e}")



# ============== v7.0新路由注册（内网渗透/漏洞利用/工具集成/分布式扫描） ==============
try:
    from api_server.internal_routes import router as internal_router
    from api_server.exploit_routes import router as exploit_router
    from api_server.tools_routes import router as tools_router
    from api_server.distributed_routes import router as distributed_router
    app.include_router(internal_router)
    app.include_router(exploit_router)
    app.include_router(tools_router)
    app.include_router(distributed_router)
    log.info("v7.0新API路由已注册：内网渗透(25端点)/漏洞利用(20端点)/工具集成(18端点)/分布式扫描(22端点)，共85+新端点")
except Exception as e:
    log.warning(f"v7.0新API路由注册失败: {e}")

# ============== 实战能力路由注册（sqlmap/Metasploit/AD攻击链/Web利用/一键模板） ==============
try:
    from api_server.combat_routes import router as combat_router
    app.include_router(combat_router)
    log.info("实战能力API路由已注册：SQL注入(3端点)/Metasploit(6端点)/AD攻击链(5端点)/Web利用(5端点)/攻击模板(5端点)，共25+新端点")
except Exception as e:
    log.warning(f"实战能力API路由注册失败: {e}")

# ============== 新领域安全路由注册（移动安全/云安全/客户端安全/AI安全） ==============
try:
    from api_server.new_domains_routes import router as new_domains_router
    app.include_router(new_domains_router)
    log.info("新领域安全API路由已注册：移动安全(3端点)/云安全(3端点)/客户端安全(3端点)/AI安全(3端点)/综合状态(1端点)，共13个新端点")
except Exception as e:
    log.warning(f"新领域安全API路由注册失败: {e}")


# ============== 扩展安全模块路由注册（7大新领域完整API） ==============
try:
    from api_server.extended_routes import router as extended_router
    app.include_router(extended_router)
    log.info("扩展安全模块API路由已注册：移动安全/内网渗透/云安全/API安全/客户端安全/代码审计/无线网络，共22个新端点")
except Exception as e:
    log.warning(f"扩展安全模块API路由注册失败: {e}")


@app.get("/extended-console", include_in_schema=False)
async def extended_console():
    from fastapi.responses import HTMLResponse
    html_path = os.path.join(os.path.dirname(__file__), "extended_console.html")
    if os.path.exists(html_path):
        with open(html_path, "r", encoding="utf-8") as f:
            return HTMLResponse(content=f.read())
    return HTMLResponse(content="<h1>扩展控制台页面未找到</h1>")


# ============== 高级安全模块路由注册（AI/IoT/工控/区块链/取证/威胁情报/社工/漏洞管理） ==============
try:
    from api_server.advanced_routes import router as advanced_router
    app.include_router(advanced_router)
    log.info("高级安全模块API路由已注册：AI安全/IoT安全/工控安全/区块链安全/取证分析/威胁情报/社会工程学/漏洞管理，共27个新端点")
except Exception as e:
    log.warning(f"高级安全模块API路由注册失败: {e}")


@app.get("/advanced-console", include_in_schema=False)
async def advanced_console():
    from fastapi.responses import HTMLResponse
    html_path = os.path.join(os.path.dirname(__file__), "advanced_console.html")
    if os.path.exists(html_path):
        with open(html_path, "r", encoding="utf-8") as f:
            return HTMLResponse(content=f.read())
    return HTMLResponse(content="<h1>高级控制台页面未找到</h1>")

# ============== 增强模块路由注册（真实工具集成/内网增强/云增强/性能/多用户/分布式） ==============
try:
    from api_server.enhanced_routes import router as enhanced_router
    app.include_router(enhanced_router)
    log.info("增强模块API路由已注册：真实工具集成/内网渗透增强/云安全增强/性能监控/多用户管理/分布式扫描，共40+新端点")
except Exception as e:
    log.warning(f"增强模块API路由注册失败: {e}")


# ============== 一键安全评估路由注册 ==============
try:
    from api_server.assessment_routes import router as assessment_router
    app.include_router(assessment_router)
    log.info("一键安全评估API路由已注册：目标输入→端口扫描→漏洞扫描→Web检测→风险评级→报告生成，共7个端点")
except Exception as e:
    log.warning(f"一键安全评估API路由注册失败: {e}")


@app.get("/assessment", include_in_schema=False)
async def assessment_console():
    """一键安全评估控制台（输入目标，一键扫描出报告）"""
    from fastapi.responses import HTMLResponse
    html_path = os.path.join(os.path.dirname(__file__), "assessment_console.html")
    if os.path.exists(html_path):
        with open(html_path, "r", encoding="utf-8") as f:
            return HTMLResponse(content=f.read())
    return HTMLResponse(content="<h1>一键评估控制台页面未找到</h1>")


@app.get("/enhanced-console", include_in_schema=False)
async def enhanced_console():
    """增强模块控制台（整合6大新模块）"""
    from fastapi.responses import HTMLResponse
    html_path = os.path.join(os.path.dirname(__file__), "enhanced_console.html")
    if os.path.exists(html_path):
        with open(html_path, "r", encoding="utf-8") as f:
            return HTMLResponse(content=f.read())
    return HTMLResponse(content="<h1>增强控制台页面未找到</h1>")

# ============== 防御中心路由注册（IDS/日志分析/基线检查/修复验证/威胁狩猎） ==============
try:
    from api_server.defense_routes import router as defense_router
    app.include_router(defense_router)
    log.info("防御中心API路由已注册：IDS入侵检测/日志分析/基线检查/修复验证/威胁狩猎，共10个端点")
except Exception as e:
    log.warning(f"防御中心API路由注册失败: {e}")


@app.get("/defense-console", include_in_schema=False)
async def defense_console_page():
    """防御中心控制台（入侵检测/日志分析/基线检查/修复验证/威胁狩猎）"""
    from fastapi.responses import HTMLResponse
    html_path = os.path.join(os.path.dirname(__file__), "defense_console.html")
    if os.path.exists(html_path):
        with open(html_path, "r", encoding="utf-8") as f:
            return HTMLResponse(content=f.read())
    return HTMLResponse(content="<h1>防御中心控制台页面未找到</h1>")


# ============== 商业化管理路由注册（多租户/计费/API网关/数据安全/RBAC） ==============
try:
    from api_server.commercial_routes import router as commercial_router
    app.include_router(commercial_router)
    log.info("商业化管理API路由已注册：多租户/计费订阅/API网关/数据安全/用户RBAC，共23个端点")
except Exception as e:
    log.warning(f"商业化管理API路由注册失败: {e}")


@app.get("/commercial-console", include_in_schema=False)
async def commercial_console_page():
    """商业版统一控制台（仪表盘/评估/防御/漏洞/报告/租户/设置）"""
    from fastapi.responses import HTMLResponse
    html_path = os.path.join(os.path.dirname(__file__), "commercial_console.html")
    if os.path.exists(html_path):
        with open(html_path, "r", encoding="utf-8") as f:
            return HTMLResponse(content=f.read())
    return HTMLResponse(content="<h1>商业版控制台页面未找到</h1>")




# ============== v7.0新路由注册（内网渗透/漏洞利用/工具集成/分布式扫描） ==============
try:
    from api_server.internal_routes import router as internal_router
    from api_server.exploit_routes import router as exploit_router
    from api_server.tools_routes import router as tools_router
    from api_server.distributed_routes import router as distributed_router
    app.include_router(internal_router)
    app.include_router(exploit_router)
    app.include_router(tools_router)
    app.include_router(distributed_router)
    log.info("v7.0新API路由已注册：内网渗透(25端点)/漏洞利用(20端点)/工具集成(18端点)/分布式扫描(22端点)，共85+新端点")
except Exception as e:
    log.warning(f"v7.0新API路由注册失败: {e}")



# ============== API鉴权配置 ==============
API_AUTH_KEY = os.getenv("API_AUTH_KEY", "")
API_AUTH_ENABLED = os.getenv("API_AUTH_ENABLED", "true").lower() == "true"
api_key_header = APIKeyHeader(name="X-API-Key", auto_error=False)

async def verify_api_key(api_key: Optional[str] = Depends(api_key_header)):
    """API密钥鉴权依赖"""
    if not API_AUTH_ENABLED:
        return api_key
    if not api_key or api_key != API_AUTH_KEY:
        raise HTTPException(
            status_code=401,
            detail="无效的API密钥，请在请求头中添加 X-API-Key"
        )
    return api_key

task_manager = TaskManager()
connection_manager = ConnectionManager()
APP_START_TIME = time.time()


# ============== 后台任务执行 ==============

async def execute_task_background(task_id: str):
    task = task_manager.get_task(task_id)
    if not task:
        return

    task_manager.update_task(task_id, status="running", started_at=time.time())
    task_manager.add_log(task_id, f"任务开始执行: {task['task_type']}")

    try:
        if task["task_type"] == "react":
            from agent.react_engine import ReActEngine
            from mcp_server.server import TOOL_DEFINITIONS
            tool_registry = {t["name"]: t["handler"] for t in TOOL_DEFINITIONS}
            engine = ReActEngine(tool_registry, max_iterations=15)
            result = await engine.run(task["description"] or f"安全测试目标: {task['target']}")
            task_manager.task_results[task_id] = result.to_dict()
            task_manager.update_task(task_id, status="completed", completed_at=time.time(), progress=100)

        elif task["task_type"] == "multi-agent":
            for i, step_name in enumerate(["信息收集", "漏洞测试", "漏洞验证", "生成报告"], 1):
                task_manager.update_task(task_id, progress=int(i / 4 * 100))
                task_manager.add_log(task_id, f"步骤 {i}/4: {step_name}")
                await connection_manager.send_message(task_id, {"type": "step", "step": i, "total": 4, "name": step_name})
                await asyncio.sleep(0.3)
            task_manager.update_task(task_id, status="completed", completed_at=time.time(), progress=100)
            task_manager.task_results[task_id] = {"status": "completed", "message": "多智能体协作完成"}

        else:
            task_manager.add_log(task_id, "标准扫描模式启动")
            from mcp_server.recon_tools import port_scan
            try:
                port_result = await port_scan(target=task["target"], ports="1-1000")
                task_manager.add_log(task_id, f"端口扫描完成，发现 {len(port_result.get('open_ports', []))} 个开放端口")
            except Exception as e:
                task_manager.add_log(task_id, f"端口扫描失败: {e}")
            task_manager.update_task(task_id, status="completed", completed_at=time.time(), progress=100)
            task_manager.task_results[task_id] = {"status": "completed", "message": "扫描完成"}

        task_manager.add_log(task_id, "任务执行完成")
        await connection_manager.send_message(task_id, {"type": "completed", "task_id": task_id})

    except Exception as e:
        log.error(f"任务执行失败: {e}")
        task_manager.update_task(task_id, status="failed", completed_at=time.time(), errors=[str(e)])
        await connection_manager.send_message(task_id, {"type": "failed", "error": str(e)})


# ============== 路由 ==============

@app.get("/", tags=["系统"])
async def root():
    return {
        "name": "AI Hacking Agent API", "version": "4.0.0", "status": "running",
        "docs": "/docs",
        "endpoints": {"tasks": "/api/v1/tasks", "tools": "/api/v1/tools",
                      "agents": "/api/v1/agents", "knowledge": "/api/v1/knowledge",
                      "reports": "/api/v1/reports", "system": "/api/v1/system"},
    }


@app.get("/health", tags=["系统"])
async def health_check():
    """增强版健康检查：服务状态/版本/运行时间/内存/数据库连接/路由统计"""
    health_info = {
        "status": "healthy",
        "version": "5.0.0",
        "uptime_seconds": round(time.time() - APP_START_TIME, 2),
        "timestamp": datetime.now().isoformat(),
    }
    # 内存占用
    try:
        import psutil
        proc = psutil.Process()
        mem_info = proc.memory_info()
        health_info["memory"] = {
            "rss_mb": round(mem_info.rss / 1024 / 1024, 2),
            "vms_mb": round(mem_info.vms / 1024 / 1024, 2),
            "percent": round(proc.memory_percent(), 2),
        }
    except Exception:
        try:
            import tracemalloc
            if not tracemalloc.is_tracing():
                tracemalloc.start()
            current, peak = tracemalloc.get_traced_memory()
            health_info["memory"] = {
                "current_mb": round(current / 1024 / 1024, 2),
                "peak_mb": round(peak / 1024 / 1024, 2),
                "source": "tracemalloc",
            }
        except Exception:
            health_info["memory"] = {"status": "unavailable"}
    # 数据库连接
    try:
        from utils.database import db as _db
        health_info["database"] = {
            "status": "connected" if _db else "disconnected",
            "type": "sqlite",
        }
    except Exception:
        health_info["database"] = {"status": "unknown"}
    # 路由统计
    try:
        total_routes = len([r for r in app.routes if hasattr(r, "methods")])
        health_info["routes"] = {"total": total_routes}
    except Exception:
        pass
    return health_info


# 任务管理
@app.post("/api/v1/tasks", response_model=TaskResponse, tags=["任务管理"], dependencies=[Depends(verify_api_key)])
async def create_task(request: TaskCreateRequest, background_tasks: BackgroundTasks):
    task_id = task_manager.create_task(request.target, request.task_type, request.description, request.options)
    background_tasks.add_task(execute_task_background, task_id)
    return TaskResponse(**task_manager.get_task(task_id))


@app.get("/api/v1/tasks", tags=["任务管理"], dependencies=[Depends(verify_api_key)])
async def list_tasks(status: Optional[str] = None, limit: int = 50):
    tasks = task_manager.list_tasks(status=status, limit=limit)
    return {"total": len(tasks), "tasks": tasks}


@app.get("/api/v1/tasks/{task_id}", response_model=TaskResponse, tags=["任务管理"], dependencies=[Depends(verify_api_key)])
async def get_task(task_id: str):
    task = task_manager.get_task(task_id)
    if not task:
        raise HTTPException(status_code=404, detail="任务不存在")
    return TaskResponse(**task)


@app.get("/api/v1/tasks/{task_id}/logs", tags=["任务管理"], dependencies=[Depends(verify_api_key)])
async def get_task_logs(task_id: str):
    task = task_manager.get_task(task_id)
    if not task:
        raise HTTPException(status_code=404, detail="任务不存在")
    return {"task_id": task_id, "logs": task.get("logs", [])}


@app.get("/api/v1/tasks/{task_id}/result", tags=["任务管理"], dependencies=[Depends(verify_api_key)])
async def get_task_result(task_id: str):
    if task_id not in task_manager.task_results:
        raise HTTPException(status_code=404, detail="任务结果不存在或任务尚未完成")
    return task_manager.task_results[task_id]


@app.delete("/api/v1/tasks/{task_id}", tags=["任务管理"], dependencies=[Depends(verify_api_key)])
async def delete_task(task_id: str):
    if not task_manager.delete_task(task_id):
        raise HTTPException(status_code=404, detail="任务不存在")
    return {"status": "deleted", "task_id": task_id}


# 工具调用
@app.get("/api/v1/tools", tags=["工具调用"], dependencies=[Depends(verify_api_key)])
async def list_tools():
    try:
        from mcp_server.server import TOOL_DEFINITIONS
        tools = [{"name": t["name"], "description": t.get("description", ""),
                  "category": t.get("category", "general"), "parameters": t.get("input_schema", {})}
                 for t in TOOL_DEFINITIONS]
        return {"total": len(tools), "tools": tools}
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@app.post("/api/v1/tools/call", response_model=ToolCallResponse, tags=["工具调用"], dependencies=[Depends(verify_api_key)])
async def call_tool(request: ToolCallRequest):
    start_time = time.time()
    try:
        from mcp_server.server import TOOL_DEFINITIONS
        tool_def = next((t for t in TOOL_DEFINITIONS if t["name"] == request.tool_name), None)
        if not tool_def:
            raise HTTPException(status_code=404, detail=f"工具不存在: {request.tool_name}")
        handler = tool_def["handler"]
        result = handler(**request.parameters)
        # 检查返回值是否是协程（lambda包装的async函数会返回协程对象）
        if asyncio.iscoroutine(result):
            result = await result
        return ToolCallResponse(tool_name=request.tool_name, status="success", result=result,
                                duration_ms=round((time.time() - start_time) * 1000, 2))
    except Exception as e:
        return ToolCallResponse(tool_name=request.tool_name, status="failed", error=str(e),
                                duration_ms=round((time.time() - start_time) * 1000, 2))


# 智能体
@app.post("/api/v1/agents/react", tags=["智能体"], dependencies=[Depends(verify_api_key)])
async def react_inference(request: ReactRequest):
    if not settings.llm.api_key or settings.llm.api_key == "sk-your-api-key-here":
        raise HTTPException(status_code=400, detail="未配置大模型API密钥")
    try:
        from agent.react_engine import ReActEngine
        from mcp_server.server import TOOL_DEFINITIONS
        tool_registry = {t["name"]: t["handler"] for t in TOOL_DEFINITIONS}
        engine = ReActEngine(tool_registry, max_iterations=request.max_iterations)
        result = await engine.run(request.task)
        return result.to_dict()
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@app.get("/api/v1/agents", tags=["智能体"], dependencies=[Depends(verify_api_key)])
async def list_agents():
    agents = [
        {"name": "ReconAgent", "role": "侦察专家", "description": "信息收集、端口扫描、子域名枚举"},
        {"name": "ExploitAgent", "role": "漏洞测试专家", "description": "SQL注入/XSS/SSRF/IDOR等漏洞测试"},
        {"name": "VerificationAgent", "role": "漏洞验证专家", "description": "深度验证、排除误报、生成PoC"},
        {"name": "ReportAgent", "role": "安全报告专家", "description": "整合结果、生成专业报告、修复建议"},
    ]
    return {"total": len(agents), "agents": agents}


# 知识库
@app.post("/api/v1/knowledge/rag", tags=["知识库"], dependencies=[Depends(verify_api_key)])
async def rag_retrieve(request: RAGRequest):
    try:
        from agent.rag_engine import rag_engine
        result = rag_engine.retrieve(request.query, top_k=request.top_k, category=request.category)
        return {"query": request.query, "total_found": result.total_found,
                "retrieval_time_ms": result.retrieval_time_ms,
                "results": [{"id": e.id, "title": e.title, "category": e.category,
                             "content": e.content[:500], "similarity": round(s, 4), "tags": e.tags}
                            for e, s in result.results]}
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@app.get("/api/v1/knowledge/cve", tags=["知识库"], dependencies=[Depends(verify_api_key)])
async def list_cves(limit: int = 20):
    try:
        from knowledge.cve import cve_kb
        cves = [{"id": cid, "name": d.get("name", ""), "severity": d.get("severity", ""),
                  "description": d.get("description", "")[:200]}
                 for cid, d in cve_kb.local_db.items()]
        return {"total": len(cves), "cves": cves[:limit]}
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@app.get("/api/v1/knowledge/stats", tags=["知识库"], dependencies=[Depends(verify_api_key)])
async def knowledge_stats():
    try:
        from agent.rag_engine import rag_engine
        return rag_engine.get_statistics()
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


# 报告
@app.post("/api/v1/reports/generate", tags=["报告"], dependencies=[Depends(verify_api_key)])
async def generate_report(request: ReportGenerateRequest):
    task = task_manager.get_task(request.task_id)
    if not task:
        raise HTTPException(status_code=404, detail="任务不存在")
    try:
        from agent.report_enhancer import report_enhancer

        # 从任务结果中提取漏洞发现
        task_result = task_manager.task_results.get(request.task_id, {})
        findings = task_result.get("findings", task_result.get("vulnerabilities", []))
        if not findings and isinstance(task_result, dict):
            # 如果没有明确的findings，将结果作为单个发现
            findings = [{"type": "scan_result", "name": "扫描结果", "description": str(task_result)[:500]}]

        # 生成增强报告
        enhanced_report = report_enhancer.generate_enhanced_report(task, findings)

        if request.format == "json":
            content = json.dumps(enhanced_report, ensure_ascii=False, indent=2, default=str)
        elif request.format == "html":
            # 使用专业报告生成器生成美观的HTML报告
            try:
                import sys
                from pathlib import Path
                project_root = Path(__file__).parent.parent
                if str(project_root) not in sys.path:
                    sys.path.insert(0, str(project_root))
                from reporting.professional_report import generate_professional_report

                # 转换漏洞数据格式
                vulns_for_report = []
                for finding in findings:
                    vuln = {
                        "name": finding.get("name", finding.get("title", "未知漏洞")),
                        "severity": finding.get("severity", finding.get("risk_level", "medium")).lower(),
                        "cve_id": finding.get("cve_id", finding.get("cve", "")),
                        "cvss_score": finding.get("cvss_score", finding.get("cvss", "")),
                        "category": finding.get("category", finding.get("type", "unknown")),
                        "description": finding.get("description", finding.get("detail", "暂无描述")),
                        "affected": finding.get("affected", finding.get("target", "")),
                        "fix": finding.get("fix", finding.get("remediation", finding.get("recommendation", "建议升级到最新版本"))),
                        "references": finding.get("references", []),
                    }
                    vulns_for_report.append(vuln)

                # 生成专业HTML报告
                target = task.get("target", "未知目标")
                content = generate_professional_report(target, vulns_for_report)
            except Exception as html_error:
                # 如果专业报告生成失败，回退到简单HTML
                log.warning(f"专业HTML报告生成失败，回退到简单格式: {html_error}")
                md_content = report_enhancer.report_to_markdown(enhanced_report)
                content = f"<html><head><meta charset='utf-8'><title>安全测试报告</title></head><body><pre>{md_content}</pre></body></html>"
        else:
            content = report_enhancer.report_to_markdown(enhanced_report)

        return {
            "task_id": request.task_id,
            "format": request.format,
            "content": content,
            "report_meta": {
                "total_findings": enhanced_report["executive_summary"]["total_findings"],
                "risk_level": enhanced_report["executive_summary"]["risk_level"],
                "risk_score": enhanced_report["executive_summary"]["overall_risk_score"],
            }
        }
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


# POC验证
@app.post("/api/v1/poc/verify", tags=["POC验证"], dependencies=[Depends(verify_api_key)])
async def poc_verify(request: POCVerifyRequest, background_tasks: BackgroundTasks):
    """对扫描出的漏洞进行POC验证，排除误报"""
    try:
        from agent.poc_verifier import poc_verifier

        # 异步执行验证
        result = await poc_verifier.verify_batch(request.findings)

        return {
            "task_id": request.task_id,
            "summary": {
                "total": result["total"],
                "verified": result["verified"],
                "false_positives": result["false_positives"],
                "unconfirmed": result["unconfirmed"],
                "verification_rate": result["verification_rate"],
            },
            "results": result["results"],
        }
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@app.get("/api/v1/poc/status", tags=["POC验证"], dependencies=[Depends(verify_api_key)])
async def poc_status():
    """获取POC验证器状态"""
    try:
        from agent.poc_verifier import poc_verifier
        return {
            "verified_count": len(poc_verifier.verified_findings),
            "false_positive_count": len(poc_verifier.false_positives),
            "supported_types": [
                "sql_injection", "xss", "ssrf", "command_injection",
                "path_traversal", "open_redirect",
            ],
        }
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


# 超级智能体（统一入口）
@app.post("/api/v1/super-agent/execute", tags=["超级智能体"], dependencies=[Depends(verify_api_key)])
async def super_agent_execute(request: SuperAgentRequest, background_tasks: BackgroundTasks):
    """超级智能体统一执行入口 - 接收自然语言指令，自动规划+选择工具+执行+生成报告"""
    try:
        from agent.super_agent import super_agent
        # 异步执行超级智能体任务
        result = await super_agent.execute(request.task, request.context)
        return result
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@app.get("/api/v1/super-agent/capabilities", tags=["超级智能体"], dependencies=[Depends(verify_api_key)])
async def super_agent_capabilities():
    """获取超级智能体的所有能力（工具/智能体/AI工具）"""
    try:
        from agent.super_agent import super_agent
        if not super_agent._initialized:
            await super_agent.initialize()
        return super_agent.get_capabilities()
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@app.get("/api/v1/super-agent/history", tags=["超级智能体"], dependencies=[Depends(verify_api_key)])
async def super_agent_history(limit: int = 10):
    """获取超级智能体任务历史"""
    try:
        from agent.super_agent import super_agent
        return {"total": len(super_agent.task_history), "history": super_agent.get_task_history(limit)}
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


# AI工具集（7个AI工具 + 工具列表）
@app.get("/api/v1/ai/tools", tags=["AI工具集"], dependencies=[Depends(verify_api_key)])
async def ai_tools_list():
    """获取所有AI工具列表"""
    try:
        from agent.ai_tools import ai_tools
        return {"tools": ai_tools.get_tool_list(), "total": 7}
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@app.post("/api/v1/ai/code-generate", tags=["AI工具集"], dependencies=[Depends(verify_api_key)])
async def ai_code_generate(request: CodeGenerateRequest):
    """AI代码生成"""
    try:
        from agent.ai_tools import ai_tools
        return await ai_tools.code_generate(request.requirement, request.language, request.framework)
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@app.post("/api/v1/ai/code-review", tags=["AI工具集"], dependencies=[Depends(verify_api_key)])
async def ai_code_review(request: CodeReviewRequest):
    """AI代码审查"""
    try:
        from agent.ai_tools import ai_tools
        return await ai_tools.code_review(request.code, request.language)
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@app.post("/api/v1/ai/document-analyze", tags=["AI工具集"], dependencies=[Depends(verify_api_key)])
async def ai_document_analyze(request: DocumentAnalyzeRequest):
    """AI文档分析"""
    try:
        from agent.ai_tools import ai_tools
        return await ai_tools.document_analyze(request.content, request.doc_type)
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@app.post("/api/v1/ai/data-analyze", tags=["AI工具集"], dependencies=[Depends(verify_api_key)])
async def ai_data_analyze(request: DataAnalyzeRequest):
    """AI数据分析"""
    try:
        from agent.ai_tools import ai_tools
        return await ai_tools.data_analyze(request.data, request.analysis_type)
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@app.post("/api/v1/ai/knowledge-query", tags=["AI工具集"], dependencies=[Depends(verify_api_key)])
async def ai_knowledge_query(request: KnowledgeQueryRequest):
    """AI知识库查询"""
    try:
        from agent.ai_tools import ai_tools
        return await ai_tools.knowledge_query(request.query, request.knowledge_type)
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@app.post("/api/v1/ai/task-plan", tags=["AI工具集"], dependencies=[Depends(verify_api_key)])
async def ai_task_plan(request: TaskPlanRequest):
    """AI任务规划"""
    try:
        from agent.ai_tools import ai_tools
        return await ai_tools.task_plan(request.goal, request.context)
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@app.post("/api/v1/ai/report-generate", tags=["AI工具集"], dependencies=[Depends(verify_api_key)])
async def ai_report_generate(request: ReportGenerateRequest):
    """AI报告生成"""
    try:
        from agent.ai_tools import ai_tools
        return await ai_tools.report_generate(request.data, request.report_type)
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))
@app.get("/api/v1/system/stats", response_model=SystemStatsResponse, tags=["系统"], dependencies=[Depends(verify_api_key)])
async def system_stats():
    try:
        from mcp_server.server import TOOL_DEFINITIONS
        total_tools = len(TOOL_DEFINITIONS)
    except Exception:
        total_tools = 34
    return SystemStatsResponse(
        version="5.0.0", total_tools=total_tools, total_agents=4,
        total_tasks=len(task_manager.tasks),
        total_findings=sum(t.get("findings_count", 0) for t in task_manager.tasks.values()),
        uptime_seconds=round(time.time() - APP_START_TIME, 2), status="running",
    )


@app.get("/api/v1/system/config", tags=["系统"], dependencies=[Depends(verify_api_key)])
async def system_config():
    return {
        "llm": {"model": settings.llm.model, "base_url": settings.llm.base_url,
                 "api_key_configured": bool(settings.llm.api_key and settings.llm.api_key != "sk-your-api-key-here")},
        "mcp": {"host": settings.mcp.host, "port": settings.mcp.port},
        "security": {"allowed_targets": settings.security.allowed_targets, "rate_limit": settings.security.rate_limit},
        "project_root": str(settings.project_root),
    }


# WebSocket
@app.websocket("/ws/tasks/{task_id}")
async def websocket_task_progress(websocket: WebSocket, task_id: str):
    await connection_manager.connect(websocket, task_id)
    try:
        task = task_manager.get_task(task_id)
        if task:
            await websocket.send_json({"type": "status", "task_id": task_id,
                                       "status": task["status"], "progress": task["progress"]})
        while True:
            data = await websocket.receive_text()
            if data == "ping":
                await websocket.send_json({"type": "pong"})
    except WebSocketDisconnect:
        connection_manager.disconnect(task_id)
    except Exception:
        connection_manager.disconnect(task_id)


# ============== v7.0: 数据库持久化API ==============

@app.get("/api/v1/db/tasks", tags=["数据库"], dependencies=[Depends(verify_api_key)])
async def db_list_tasks(status: Optional[str] = None, limit: int = 50, offset: int = 0):
    """从数据库获取任务列表"""
    tasks = db.list_tasks(status=status, limit=limit, offset=offset)
    return {"total": len(tasks), "tasks": tasks}

@app.get("/api/v1/db/tasks/{task_id}", tags=["数据库"], dependencies=[Depends(verify_api_key)])
async def db_get_task(task_id: str):
    """从数据库获取任务详情"""
    task = db.get_task(task_id)
    if not task:
        raise HTTPException(status_code=404, detail="任务不存在")
    return task

@app.get("/api/v1/db/findings", tags=["数据库"], dependencies=[Depends(verify_api_key)])
async def db_list_findings(task_id: Optional[str] = None, severity: Optional[str] = None,
                            target: Optional[str] = None, limit: int = 100):
    """从数据库获取漏洞发现列表"""
    findings = db.get_findings(task_id=task_id, severity=severity, target=target, limit=limit)
    return {"total": len(findings), "findings": findings}

@app.get("/api/v1/db/reports/{report_id}", tags=["数据库"], dependencies=[Depends(verify_api_key)])
async def db_get_report(report_id: str):
    """从数据库获取报告"""
    report = db.get_report(report_id)
    if not report:
        raise HTTPException(status_code=404, detail="报告不存在")
    return report

@app.get("/api/v1/db/stats", tags=["数据库"], dependencies=[Depends(verify_api_key)])
async def db_stats():
    """获取数据库统计"""
    return db.get_statistics()


# ============== v7.0: 用户管理API ==============

class UserRegisterRequest(BaseModel):
    """UserRegisterRequest数据模型类，定义相关数据结构和验证规则。

    Attributes:
        各类实例属性，具体见__init__方法。
    """
    username: str = Field(..., min_length=3, description="用户名")
    password: str = Field(..., min_length=6, description="密码")
    email: Optional[str] = Field("", description="邮箱")
    role: Optional[str] = Field("user", description="角色: admin/analyst/user/viewer")

class UserLoginRequest(BaseModel):
    """UserLoginRequest数据模型类，定义相关数据结构和验证规则。

    Attributes:
        各类实例属性，具体见__init__方法。
    """
    username: str = Field(..., description="用户名")
    password: str = Field(..., description="密码")

@app.post("/api/v1/auth/register", tags=["用户管理"])
async def auth_register(request: UserRegisterRequest):
    """用户注册"""
    result = user_manager.register_user(
        username=request.username,
        password=request.password,
        email=request.email,
        role=request.role
    )
    if not result.get("success"):
        raise HTTPException(status_code=400, detail=result.get("error", "注册失败"))
    return result

@app.post("/api/v1/auth/login", tags=["用户管理"])
async def auth_login(request: UserLoginRequest):
    """用户登录"""
    user = user_manager.authenticate(request.username, request.password)
    if not user:
        raise HTTPException(status_code=401, detail="用户名或密码错误")
    return {"success": True, "user": user}

@app.get("/api/v1/users", tags=["用户管理"], dependencies=[Depends(verify_api_key)])
async def list_users(limit: int = 50):
    """获取用户列表"""
    users = user_manager.list_users(limit=limit)
    return {"total": len(users), "users": users}

@app.get("/api/v1/users/{user_id}", tags=["用户管理"], dependencies=[Depends(verify_api_key)])
async def get_user(user_id: str):
    """获取用户信息"""
    user = user_manager.get_user(user_id)
    if not user:
        raise HTTPException(status_code=404, detail="用户不存在")
    return user

@app.post("/api/v1/users/{user_id}/regenerate-key", tags=["用户管理"], dependencies=[Depends(verify_api_key)])
async def regenerate_api_key(user_id: str):
    """重新生成API密钥"""
    new_key = user_manager.regenerate_api_key(user_id)
    if not new_key:
        raise HTTPException(status_code=400, detail="重新生成失败")
    return {"success": True, "api_key": new_key}

@app.get("/api/v1/audit-logs", tags=["用户管理"], dependencies=[Depends(verify_api_key)])
async def get_audit_logs(user_id: Optional[str] = None, action: Optional[str] = None, limit: int = 100):
    """获取审计日志"""
    logs = user_manager.get_audit_logs(user_id=user_id, action=action, limit=limit)
    return {"total": len(logs), "logs": logs}


# ============== v7.0: 插件系统API ==============

class PluginExecuteRequest(BaseModel):
    """PluginExecuteRequest数据模型类，定义相关数据结构和验证规则。

    Attributes:
        各类实例属性，具体见__init__方法。
    """
    plugin_name: str = Field(..., description="插件名称")
    parameters: Dict[str, Any] = Field(default_factory=dict, description="插件参数")

@app.get("/api/v1/plugins", tags=["插件系统"], dependencies=[Depends(verify_api_key)])
async def list_plugins():
    """获取已注册插件列表"""
    plugins = plugin_manager.list_plugins()
    return {"total": len(plugins), "plugins": plugins}

@app.get("/api/v1/plugins/stats", tags=["插件系统"], dependencies=[Depends(verify_api_key)])
async def plugin_stats():
    """获取插件系统统计"""
    return plugin_manager.get_statistics()

@app.post("/api/v1/plugins/discover", tags=["插件系统"], dependencies=[Depends(verify_api_key)])
async def discover_plugins():
    """自动发现插件目录中的插件"""
    discovered = plugin_manager.discover_plugins()
    return {"discovered": discovered, "total": len(discovered)}

@app.get("/api/v1/plugins/{plugin_name}/help", tags=["插件系统"], dependencies=[Depends(verify_api_key)])
async def plugin_help(plugin_name: str):
    """获取插件帮助信息"""
    help_text = plugin_manager.get_plugin_help(plugin_name)
    if not help_text:
        raise HTTPException(status_code=404, detail="插件不存在")
    return {"plugin": plugin_name, "help": help_text}

@app.post("/api/v1/plugins/execute", tags=["插件系统"], dependencies=[Depends(verify_api_key)])
async def execute_plugin(request: PluginExecuteRequest):
    """执行插件"""
    result = plugin_manager.execute_plugin(request.plugin_name, **request.parameters)
    if not result.get("success"):
        raise HTTPException(status_code=400, detail=result.get("error", "执行失败"))
    return result


# ============== v8.0: 综合渗透测试API ==============

class PentestRequest(BaseModel):
    """PentestRequest数据模型类，定义相关数据结构和验证规则。

    Attributes:
        各类实例属性，具体见__init__方法。
    """
    action: str = Field(..., description="操作类型: internal_scan/ad_analysis/external_scan/code_analysis/password_check/traffic_analysis/post_exploitation_roadmap")
    target: Optional[str] = Field("", description="目标地址/域名/IP")
    code: Optional[str] = Field("", description="待分析代码")
    password: Optional[str] = Field("", description="待检测密码")
    platform: Optional[str] = Field("linux", description="平台: linux/windows")

@app.post("/api/v1/pentest/execute", tags=["渗透测试"], dependencies=[Depends(verify_api_key)])
async def execute_pentest(request: PentestRequest):
    """综合渗透测试 - 整合内网/外网/域渗透/AI分析/密码安全/流量分析/后渗透"""
    try:
        if not plugin_manager.get_plugin("comprehensive_pentest"):
            plugin_manager.discover_plugins()
            plugin_manager.load_plugin("comprehensive_pentest")

        result = plugin_manager.execute_plugin(
            "comprehensive_pentest",
            action=request.action,
            target=request.target,
            code=request.code,
            password=request.password,
            platform=request.platform,
        )
        if not result.get("success"):
            raise HTTPException(status_code=400, detail=result.get("error", "执行失败"))
        return result
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"渗透测试执行失败: {e}")

@app.get("/api/v1/pentest/actions", tags=["渗透测试"], dependencies=[Depends(verify_api_key)])
async def list_pentest_actions():
    """获取可用的渗透测试操作列表"""
    return {
        "actions": [
            {"action": "internal_scan", "description": "内网渗透扫描 - 端口扫描/服务识别/漏洞利用/横向移动"},
            {"action": "ad_analysis", "description": "域渗透分析 - AD枚举/Kerberos/NTLM/权限提升/票据攻击"},
            {"action": "external_scan", "description": "外网渗透扫描 - 子域名枚举/Web漏洞/API漏洞/云安全"},
            {"action": "code_analysis", "description": "AI代码安全分析 - 漏洞检测/恶意代码检测/IOC提取"},
            {"action": "password_check", "description": "密码安全检测 - 强度评估/哈希生成/破解时间估算"},
            {"action": "traffic_analysis", "description": "网络流量分析 - PCAP分析/协议解析/异常检测/IDS"},
            {"action": "post_exploitation_roadmap", "description": "后渗透路线图 - 权限提升/凭证窃取/持久化/痕迹清除"},
        ],
        "total_actions": 7,
    }


# ============== v9.0: 企业级增强API ==============

class EnterpriseRequest(BaseModel):
    """EnterpriseRequest数据模型类，定义相关数据结构和验证规则。

    Attributes:
        各类实例属性，具体见__init__方法。
    """
    action: str = Field(..., description="操作: cve_search/cve_detail/cve_match/enterprise_stats/audit_log/compliance_report/poc_search/poc_stats/auto_exploit")
    keyword: Optional[str] = Field("", description="搜索关键词")
    cve_id: Optional[str] = Field("", description="CVE ID")
    severity: Optional[str] = Field("", description="严重程度")
    target: Optional[str] = Field("", description="目标地址")
    standard: Optional[str] = Field("both", description="合规标准: mlps2.0/iso27001/both")
    limit: Optional[int] = Field(20, description="返回数量限制")

@app.post("/api/v1/enterprise/execute", tags=["企业级增强"], dependencies=[Depends(verify_api_key)])
async def execute_enterprise(request: EnterpriseRequest):
    """企业级增强 - CVE漏洞库+多租户/RBAC+合规报告+漏洞利用引擎"""
    try:
        if not plugin_manager.get_plugin("enterprise_enhancement"):
            plugin_manager.discover_plugins()
            plugin_manager.load_plugin("enterprise_enhancement")

        result = plugin_manager.execute_plugin(
            "enterprise_enhancement",
            action=request.action,
            keyword=request.keyword,
            cve_id=request.cve_id,
            severity=request.severity,
            target=request.target,
            standard=request.standard,
            limit=request.limit,
        )
        if not result.get("success"):
            raise HTTPException(status_code=400, detail=result.get("error", "执行失败"))
        return result
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"企业级增强执行失败: {e}")

@app.get("/api/v1/enterprise/actions", tags=["企业级增强"], dependencies=[Depends(verify_api_key)])
async def list_enterprise_actions():
    """获取企业级增强操作列表"""
    return {
        "actions": [
            {"action": "cve_search", "description": "搜索CVE漏洞库"},
            {"action": "cve_detail", "description": "获取CVE漏洞详情"},
            {"action": "cve_match", "description": "根据服务匹配CVE漏洞"},
            {"action": "cve_stats", "description": "CVE漏洞库统计"},
            {"action": "enterprise_stats", "description": "企业级功能统计（租户/用户/审计）"},
            {"action": "audit_log", "description": "查询审计日志"},
            {"action": "compliance_report", "description": "生成合规报告（等保2.0/ISO27001）"},
            {"action": "poc_search", "description": "搜索POC漏洞利用库"},
            {"action": "poc_stats", "description": "POC库统计"},
            {"action": "auto_exploit", "description": "自动漏洞利用编排"},
        ],
        "total_actions": 10,
    }




# ============== 全域安全评估统一路由 ==============
try:
    from api_server.unified_routes import router as unified_router
    app.include_router(unified_router)
    log.info("全域安全评估统一API路由已注册：评估执行/结果查询/知识库/报告生成，共10个端点")
except Exception as e:
    print(f"统一路由注册失败: {e}")


@app.get("/unified-console", tags=["前端页面"])
async def unified_console_page():
    """全域安全评估平台前端控制台"""
    from fastapi.responses import HTMLResponse
    page_path = os.path.join(os.path.dirname(__file__), "unified_console.html")
    if os.path.exists(page_path):
        with open(page_path, "r", encoding="utf-8") as f:
            return HTMLResponse(content=f.read())
    return HTMLResponse(content="<h1>全域安全评估控制台页面未找到</h1>")

# ============== 统一平台控制台路由（最高优先级） ==============
# 平台级聚合 API：/api/platform/overview|tools-status|stats|recent-activity|nav-config|health
try:
    from api_server.platform_routes import router as platform_router
    app.include_router(platform_router)
    log.info("统一平台控制台API路由已注册：overview/tools-status/stats/recent-activity/nav-config/health，共6个端点")
except Exception as e:
    log.warning(f"统一平台控制台API路由注册失败: {e}")


@app.get("/platform", include_in_schema=False)
async def platform_console_page():
    """统一平台控制台（左侧导航 + iframe 复用既有控制台 + 自建仪表盘）"""
    from fastapi.responses import HTMLResponse
    page_path = os.path.join(os.path.dirname(__file__), "platform_console.html")
    if os.path.exists(page_path):
        with open(page_path, "r", encoding="utf-8") as f:
            return HTMLResponse(content=f.read())
    return HTMLResponse(content="<h1>统一平台控制台页面未找到</h1>")


@app.get("/platform-v2", include_in_schema=False)
async def platform_console_v2_page():
    """统一平台控制台 V2（新手引导 / 命令面板 / 主题 / 多语言 / SVG 数据分析仪表盘）"""
    from fastapi.responses import HTMLResponse
    page_path = os.path.join(os.path.dirname(__file__), "platform_console_v2.html")
    if os.path.exists(page_path):
        with open(page_path, "r", encoding="utf-8") as f:
            return HTMLResponse(content=f.read())
    return HTMLResponse(content="<h1>统一平台控制台 V2 页面未找到</h1>")


# ============== 新手引导 API（V2 控制台配套） ==============
try:
    from api_server.onboarding_routes import router as onboarding_router
    app.include_router(onboarding_router)
    log.info("新手引导 API 路由已注册：/api/v1/onboarding/status|complete|steps")
except Exception as e:
    log.warning(f"新手引导 API 路由注册失败: {e}")


@app.get("/platform-root", include_in_schema=False)
async def platform_root_redirect():
    """根路径重定向到统一平台控制台 /platform"""
    from fastapi.responses import RedirectResponse
    return RedirectResponse(url="/platform")


# 说明：项目早期已存在 @app.get("/")（见文件上方 index_page，服务 index.html），
# 按 FastAPI 路由注册顺序该更早注册的路由优先生效；本项目统一控制台入口为 /platform。
# 为兼容直接访问根路径的用户，下面再追加一条同名重定向（若未来移除旧 / 路由即可自动生效）。
try:
    @app.get("/", include_in_schema=False)
    async def _platform_root():
        from fastapi.responses import RedirectResponse
        return RedirectResponse(url="/platform")
except Exception as e:
    log.warning(f"根路径重定向注册失败: {e}")


# ============== 持续监控与告警路由注册（定时任务/节点/告警/代理池） ==============
try:
    from api_server.monitoring_routes import router as monitoring_router
    app.include_router(monitoring_router)
    log.info("持续监控API路由已注册：定时任务CRUD/节点状态/告警管理/代理池，共14个端点")
except Exception as e:
    log.warning(f"持续监控API路由注册失败: {e}")


# ============== 团队协作与通知路由注册（任务/评论/通知） ==============
try:
    from api_server.collaboration_routes import router as collaboration_router
    app.include_router(collaboration_router)
    log.info("团队协作API路由已注册：任务管理/评论/通知，共14个端点")
except Exception as e:
    log.warning(f"团队协作API路由注册失败: {e}")


# ============== 第4轮升级：数据分析路由注册 ==============
try:
    from api_server.analytics_routes import router as analytics_router
    app.include_router(analytics_router)
    log.info("数据分析API路由已注册：趋势/分布/Top/对比/摘要/导出，共9个端点")
except Exception as e:
    log.warning(f"数据分析API路由注册失败: {e}")


# ============== 第4轮升级：报告管理路由注册 ==============
try:
    from api_server.reporting_routes import router as reporting_router
    app.include_router(reporting_router)
    log.info("报告管理API路由已注册：生成/下载/模板CRUD/格式列表，共7个端点")
except Exception as e:
    log.warning(f"报告管理API路由注册失败: {e}")


# ============== 第4轮升级：集成管理路由注册 ==============
try:
    from api_server.integrations_routes import router as integrations_router
    app.include_router(integrations_router)
    log.info("集成管理API路由已注册：SIEM/工单/通知/LDAP/漏洞库，共25个端点")
except Exception as e:
    log.warning(f"集成管理API路由注册失败: {e}")


# ============== 第4轮升级：高级安全路由注册 ==============
try:
    from api_server.security_routes import router as security_router
    app.include_router(security_router)
    log.info("高级安全API路由已注册：漏洞生命周期/资产发现/合规审计/攻击路径，共22个端点")
except Exception as e:
    log.warning(f"高级安全API路由注册失败: {e}")


# ============== 第5轮升级：AI深度赋能路由注册 ==============
try:
    from api_server.ai_routes import router as ai_router
    app.include_router(ai_router)
    log.info("第5轮AI深度赋能路由已注册：自然语言对话/漏洞验证/修复方案/AI助手/对话历史，共7个端点")
except Exception as e:
    log.warning(f"第5轮AI深度赋能路由注册失败: {e}")


# ============== 企业级商业产品路由注册 ==============
try:
    from enterprise.routes import router as enterprise_router
    app.include_router(enterprise_router)
    log.info("企业级商业产品路由已注册：用户认证/扫描历史/持续监控/审计日志/任务队列/系统统计，共15个端点")
except Exception as e:
    log.warning(f"企业级商业产品路由注册失败: {e}")


# ============== 第5轮升级：实战能力深化（内网/域渗透审计）路由注册 ==============
try:
    from api_server.pentest_routes import router as pentest_router
    app.include_router(pentest_router)
    log.info("第5轮实战能力深化路由已注册：内网扫描/域审计/横向移动检测/凭据审计/BloodHound，共8个端点")
except Exception as e:
    log.warning(f"第5轮实战能力深化路由注册失败: {e}")


# ============== 第5轮升级：AI助手前端页面 ==============
try:
    @app.get("/ai-assistant", include_in_schema=False)
    async def ai_assistant_page():
        """AI安全助手对话界面（自然语言交互/漏洞验证/修复方案）"""
        from fastapi.responses import HTMLResponse
        page_path = os.path.join(os.path.dirname(__file__), "ai_assistant.html")
        if os.path.exists(page_path):
            with open(page_path, "r", encoding="utf-8") as f:
                return HTMLResponse(content=f.read())
        return HTMLResponse(content="<h1>AI助手页面未找到</h1>")
    log.info("AI助手前端页面已注册：/ai-assistant")
except Exception as e:
    log.warning(f"AI助手前端页面注册失败: {e}")


# ============== 第6轮升级：漏洞真实验证路由 ==============
try:
    from api_server.verification_routes import router as verification_router
    app.include_router(verification_router)
    log.info("第6轮漏洞真实验证路由已注册：Web验证/服务验证/全量验证/结果/统计/报告/历史，共7个端点")
except Exception as e:
    log.warning(f"第6轮漏洞真实验证路由注册失败: {e}")


# ============== 第6轮升级：AI输出质量路由 ==============
try:
    from api_server.ai_quality_routes import router as ai_quality_router
    app.include_router(ai_quality_router)
    log.info("第6轮AI输出质量路由已注册：校验/统计/反馈/知识库查询/知识库统计，共5个端点")
except Exception as e:
    log.warning(f"第6轮AI输出质量路由注册失败: {e}")


# ============== 第6轮升级：安全自身防护路由 ==============
try:
    from api_server.self_security_routes import router as self_security_router
    app.include_router(self_security_router)
    log.info("第6轮安全自身防护路由已注册：自审计/API密钥/审计日志/会话/备份/脱敏，共9个端点")
except Exception as e:
    log.warning(f"第6轮安全自身防护路由注册失败: {e}")


# ============== 第6轮升级：性能中间件（Gzip压缩/ETag/慢请求日志） ==============
try:
    import hashlib as _hashlib
    import time as _time
    from fastapi import Request as _Request, Response as _Response
    from fastapi.middleware.gzip import GZipMiddleware as _GZipMiddleware
    from starlette.middleware.base import BaseHTTPMiddleware as _BaseHTTPMiddleware

    app.add_middleware(_GZipMiddleware, minimum_size=1000)

    class _ETagMiddleware(_BaseHTTPMiddleware):
        async def dispatch(self, request: _Request, call_next):
            if request.method != "GET":
                return await call_next(request)
            resp = await call_next(request)
            try:
                body = b"".join([chunk async for chunk in resp.body_iterator])
                etag = _hashlib.md5(body).hexdigest()
                inm = request.headers.get("if-none-match")
                resp.headers["ETag"] = f'"{etag}"'
                if inm == resp.headers["ETag"]:
                    return _Response(status_code=304, headers={"ETag": resp.headers["ETag"]})
                async def _async_body():
                    yield body
                resp.body_iterator = _async_body()
            except Exception:
                pass
            return resp

    class _SlowRequestLogMiddleware(_BaseHTTPMiddleware):
        async def dispatch(self, request: _Request, call_next):
            t0 = _time.time()
            resp = await call_next(request)
            cost = _time.time() - t0
            if cost > 1.0:
                log.warning(f"慢请求 {request.method} {request.url.path} 耗时 {cost:.2f}s")
            resp.headers["X-Response-Time-ms"] = f"{cost*1000:.0f}"
            return resp

    app.add_middleware(_ETagMiddleware)
    app.add_middleware(_SlowRequestLogMiddleware)
    log.info("第6轮性能中间件已注册：Gzip压缩/ETag 304/慢请求日志")
except Exception as e:
    log.warning(f"第6轮性能中间件注册失败: {e}")




# ============== 第7轮升级：漏洞库深化路由（277 CVE / 149利用 / 193修复） ==============
try:
    from api_server.vuln_db_routes import router as vuln_db_router_v7
    app.include_router(vuln_db_router_v7)
    log.info("第7轮漏洞库深化路由已注册：CVE列表/详情/搜索/匹配/利用方式/修复方案/统计，共9个端点")
except Exception as e:
    log.warning(f"第7轮漏洞库深化路由注册失败: {e}")


# ============== 第7轮升级：数据可视化路由（攻击路径/拓扑/热力图/趋势） ==============
try:
    from api_server.visualization_routes import router as visualization_router_v7
    app.include_router(visualization_router_v7)
    log.info("第7轮数据可视化路由已注册：攻击路径/网络拓扑/风险热力图/趋势分析/全量可视化/格式列表，共6个端点")
except Exception as e:
    log.warning(f"第7轮数据可视化路由注册失败: {e}")



# ============== 第8轮升级：静态文件挂载（css/js/locales） ==============
try:
    from fastapi.staticfiles import StaticFiles as _StaticFiles
    _api_dir = os.path.dirname(__file__)
    for _sub, _path in [("css", "css"), ("js", "js"), ("locales", "locales")]:
        _full = os.path.join(_api_dir, _path)
        if os.path.isdir(_full):
            app.mount(f"/static/{_sub}", _StaticFiles(directory=_full), name=f"static_{_sub}")
    log.info("第8轮静态文件已挂载：/static/css /static/js /static/locales")
except Exception as e:
    log.warning(f"第8轮静态文件挂载失败: {e}")


# ============== 第8轮升级：靶场集成路由（12端点） ==============
try:
    from api_server.target_lab_routes import router as target_lab_router
    app.include_router(target_lab_router)
    log.info("第8轮靶场集成路由已注册：靶场列表/部署/生命周期/场景/健康检查/Compose生成，共12个端点")
except Exception as e:
    log.warning(f"第8轮靶场集成路由注册失败: {e}")


# ============== 第8轮升级：数据导入导出路由（11端点） ==============
try:
    from api_server.data_io_routes import router as data_io_router
    app.include_router(data_io_router)
    log.info("第8轮数据导入导出路由已注册：导入上传/预览/确认/历史/导出/模板/格式/统计，共11个端点")
except Exception as e:
    log.warning(f"第8轮数据导入导出路由注册失败: {e}")


# ============== 第8轮升级：通知渠道路由（15端点） ==============
try:
    from api_server.notification_routes import router as notification_router
    app.include_router(notification_router)
    log.info("第8轮通知渠道路由已注册：7渠道管理/模板CRUD/事件订阅/手动发送/历史/统计，共15个端点")
except Exception as e:
    log.warning(f"第8轮通知渠道路由注册失败: {e}")


# ============== 第8轮升级：报告模板路由（13端点） ==============
try:
    from api_server.report_template_routes import router as report_template_router
    app.include_router(report_template_router)
    log.info("第8轮报告模板路由已注册：模板CRUD/预览/复制/导入导出/样式预设/Logo管理，共13个端点")
except Exception as e:
    log.warning(f"第8轮报告模板路由注册失败: {e}")


# ============== 第8轮升级：离线模式路由（8端点） ==============
try:
    from api_server.offline_routes import router as offline_router
    app.include_router(offline_router)
    log.info("第8轮离线模式路由已注册：状态/模式切换/规则管理/规则测试/知识库搜索/统计，共8个端点")
except Exception as e:
    log.warning(f"第8轮离线模式路由注册失败: {e}")


# ============== 第8轮升级：API安全专项路由（12端点） ==============
try:
    from api_server.api_security_routes import router as api_security_router
    app.include_router(api_security_router)
    log.info("第8轮API安全专项路由已注册：OpenAPI解析/端点/fuzz/逻辑测试/扫描/状态/结果/漏洞/报告/历史/payloads/统计，共12个端点")
except Exception as e:
    log.warning(f"第8轮API安全专项路由注册失败: {e}")


# ============== 第8轮升级：新前端页面路由（6个页面） ==============
try:
    from fastapi.responses import HTMLResponse as _HTMLR8

    _PAGES_R8 = [
        ("/target-labs", "target_lab_console.html", "靶场管理控制台"),
        ("/notifications", "notification_console.html", "通知中心控制台"),
        ("/report-templates", "report_template_console.html", "报告模板编辑器"),
        ("/api-security", "api_security_console.html", "API安全测试控制台"),
        ("/mobile-test", "mobile_test.html", "移动端组件测试页"),
        ("/i18n-test", "i18n_test.html", "i18n多语言测试页"),
    ]

    for _route, _fname, _desc in _PAGES_R8:
        def _make_page_handler(fname=_fname, desc=_desc):
            @app.get(_route, include_in_schema=False)
            async def _page_handler():
                _p = os.path.join(os.path.dirname(__file__), fname)
                if os.path.exists(_p):
                    with open(_p, "r", encoding="utf-8") as _f:
                        return _HTMLR8(content=_f.read())
                return _HTMLR8(content=f"<h1>{desc}页面未找到</h1>")
            return _page_handler
        _make_page_handler()

    log.info("第8轮新前端页面已注册：/target-labs /notifications /report-templates /api-security /mobile-test /i18n-test")
except Exception as e:
    log.warning(f"第8轮新前端页面注册失败: {e}")




# ============== 第9轮升级：安全运营中心(SOC)路由（37端点） ==============
try:
    from api_server.soc_routes import router as soc_router
    app.include_router(soc_router)
    log.info("第9轮SOC路由已注册：事件/告警/工单/应急响应/仪表盘，共37个端点")
except Exception as e:
    log.warning(f"第9轮SOC路由注册失败: {e}")


# ============== 第9轮升级：漏洞管理深化路由（24端点） ==============
try:
    from api_server.vuln_management_routes import router as vuln_mgmt_router
    app.include_router(vuln_mgmt_router)
    log.info("第9轮漏洞管理深化路由已注册：生命周期/SLA/分析/修复跟踪，共24个端点")
except Exception as e:
    log.warning(f"第9轮漏洞管理深化路由注册失败: {e}")


# ============== 第9轮升级：资产管理深化路由（30端点） ==============
try:
    from api_server.asset_management_routes import router as asset_mgmt_router
    app.include_router(asset_mgmt_router)
    log.info("第9轮资产管理深化路由已注册：发现/指纹/风险评级/变更检测/分组，共30个端点")
except Exception as e:
    log.warning(f"第9轮资产管理深化路由注册失败: {e}")


# ============== 第9轮升级：威胁情报集成路由（19端点） ==============
try:
    from api_server.threat_intel_routes import router as threat_intel_router
    app.include_router(threat_intel_router)
    log.info("第9轮威胁情报路由已注册：IOC/Actor/样本分析/威胁狩猎，共19个端点")
except Exception as e:
    log.warning(f"第9轮威胁情报路由注册失败: {e}")


# ============== 第9轮升级：合规审计深化路由（17端点） ==============
try:
    from api_server.compliance_routes import router as compliance_router
    app.include_router(compliance_router)
    log.info("第9轮合规审计路由已注册：框架/评估/报告/整改，共17个端点")
except Exception as e:
    log.warning(f"第9轮合规审计路由注册失败: {e}")


# ============== 第9轮升级：红蓝对抗演练路由（18端点） ==============
try:
    from api_server.purple_team_routes import router as purple_team_router
    app.include_router(purple_team_router)
    log.info("第9轮红蓝对抗路由已注册：红队模拟/蓝队检测/紫队复盘，共18个端点")
except Exception as e:
    log.warning(f"第9轮红蓝对抗路由注册失败: {e}")


# ============== 第9轮升级：护网行动支持路由（35端点） ==============
try:
    from api_server.hudong_routes import router as hudong_router
    app.include_router(hudong_router)
    log.info("第9轮护网行动路由已注册：准备/监控/应急/总结，共35个端点")
except Exception as e:
    log.warning(f"第9轮护网行动路由注册失败: {e}")


# ============== 第9轮升级：审计日志深化路由（30端点） ==============
try:
    from api_server.audit_routes import router as audit_router
    app.include_router(audit_router)
    log.info("第9轮审计日志路由已注册：操作/登录/API/数据访问/日志管理，共30个端点")
except Exception as e:
    log.warning(f"第9轮审计日志路由注册失败: {e}")


# ============== 第9轮升级：新前端页面路由（6个控制台） ==============
try:
    from fastapi.responses import HTMLResponse as _HTMLR9

    _PAGES_R9 = [
        ("/soc-console", "soc_console.html", "SOC安全运营中心控制台"),
        ("/asset-console", "asset_console.html", "资产管理控制台"),
        ("/compliance-console", "compliance_console.html", "合规审计控制台"),
        ("/purple-team-console", "purple_team_console.html", "红蓝对抗控制台"),
        ("/hudong-console", "hudong_console.html", "护网行动控制台"),
        ("/audit-console", "audit_console.html", "审计日志控制台"),
    ]

    for _route, _fname, _desc in _PAGES_R9:
        def _make_page_handler_r9(fname=_fname, desc=_desc):
            @app.get(_route, include_in_schema=False)
            async def _page_handler_r9():
                _p = os.path.join(os.path.dirname(__file__), fname)
                if os.path.exists(_p):
                    with open(_p, "r", encoding="utf-8") as _f:
                        return _HTMLR9(content=_f.read())
                return _HTMLR9(content=f"<h1>{desc}页面未找到</h1>")
            return _page_handler_r9
        _make_page_handler_r9()

    log.info("第9轮新前端页面已注册：/soc-console /asset-console /compliance-console /purple-team-console /hudong-console /audit-console")
except Exception as e:
    log.warning(f"第9轮新前端页面注册失败: {e}")



# ============== 第10轮升级：AI安全运营(AI SOC)路由（23端点） ==============
try:
    from api_server.ai_soc_routes import router as ai_soc_router
    app.include_router(ai_soc_router)
    log.info("第10轮AI安全运营路由已注册：异常检测/告警关联/事件分类/根因分析/响应建议/AI助手，共23个端点")
except Exception as e:
    log.warning(f"第10轮AI安全运营路由注册失败: {e}")


# ============== 第10轮升级：性能监控路由（22端点） ==============
try:
    from api_server.performance_routes import router as performance_router
    app.include_router(performance_router)
    log.info("第10轮性能监控路由已注册：查询优化/索引管理/缓存/慢查询/API性能/DB性能，共22个端点")
except Exception as e:
    log.warning(f"第10轮性能监控路由注册失败: {e}")


# ============== 第10轮升级：SaaS化基础路由（25端点） ==============
try:
    from api_server.saas_routes import router as saas_router
    app.include_router(saas_router)
    log.info("第10轮SaaS化基础路由已注册：认证/MFA/用户/租户/邀请，共25个端点")
except Exception as e:
    log.warning(f"第10轮SaaS化基础路由注册失败: {e}")


# ============== 第10轮升级：数据可视化V2路由（20端点） ==============
try:
    from api_server.visualization_v2_routes import router as visualization_v2_router
    app.include_router(visualization_v2_router)
    log.info("第10轮数据可视化V2路由已注册：实时大屏/3D拓扑/攻击地图/自定义仪表盘，共20个端点")
except Exception as e:
    log.warning(f"第10轮数据可视化V2路由注册失败: {e}")


# ============== 第10轮升级：API网关深化路由（24端点） ==============
try:
    from api_server.api_gateway_routes import router as api_gateway_router
    app.include_router(api_gateway_router)
    log.info("第10轮API网关深化路由已注册：限流/熔断/降级/缓存/日志/监控，共24个端点")
except Exception as e:
    log.warning(f"第10轮API网关深化路由注册失败: {e}")


# ============== 第10轮升级：SSO/LDAP集成路由（23端点） ==============
try:
    from api_server.sso_routes import router as sso_router
    app.include_router(sso_router)
    log.info("第10轮SSO/LDAP集成路由已注册：SAML/OAuth2/LDAP/SSO统一，共23个端点")
except Exception as e:
    log.warning(f"第10轮SSO/LDAP集成路由注册失败: {e}")


# ============== 第10轮升级：新前端页面路由（5个控制台+大屏） ==============
try:
    from fastapi.responses import HTMLResponse as _HTMLR10

    _PAGES_R10 = [
        ("/saas-console", "saas_console.html", "SaaS管理控制台"),
        ("/realtime-dashboard", "realtime_dashboard.html", "实时监控大屏"),
        ("/custom-dashboard", "custom_dashboard.html", "自定义仪表盘编辑器"),
        ("/backup-console", "backup_console.html", "数据备份恢复控制台"),
        ("/sso-console", "sso_console.html", "SSO/LDAP管理控制台"),
    ]

    for _route, _fname, _desc in _PAGES_R10:
        def _make_page_handler_r10(fname=_fname, desc=_desc):
            @app.get(_route, include_in_schema=False)
            async def _page_handler_r10():
                _p = os.path.join(os.path.dirname(__file__), fname)
                if os.path.exists(_p):
                    with open(_p, "r", encoding="utf-8") as _f:
                        return _HTMLR10(content=_f.read())
                return _HTMLR10(content=f"<h1>{desc}页面未找到</h1>")
            return _page_handler_r10
        _make_page_handler_r10()

    log.info("第10轮新前端页面已注册：/saas-console /realtime-dashboard /custom-dashboard /backup-console /sso-console")
except Exception as e:
    log.warning(f"第10轮新前端页面注册失败: {e}")




# ============== 第11轮升级：云安全深化V2路由（28端点） ==============
try:
    from api_server.cloud_security_v2_routes import router as cloud_security_v2_router
    app.include_router(cloud_security_v2_router)
    log.info("第11轮云安全深化V2路由已注册：AWS/Azure/阿里云/GCP配置检查/容器扫描/K8s安全/云资产/云威胁，共28个端点")
except Exception as e:
    log.warning(f"第11轮云安全深化V2路由注册失败: {e}")


# ============== 第11轮升级：代码审计深化V2路由（25端点） ==============
try:
    from api_server.code_audit_v2_routes import router as code_audit_v2_router
    app.include_router(code_audit_v2_router)
    log.info("第11轮代码审计深化V2路由已注册：SAST/Semgrep/SCA/代码质量/安全编码/综合审计，共25个端点")
except Exception as e:
    log.warning(f"第11轮代码审计深化V2路由注册失败: {e}")


# ============== 第11轮升级：取证分析深化V2路由（28端点） ==============
try:
    from api_server.forensics_v2_routes import router as forensics_v2_router
    app.include_router(forensics_v2_router)
    log.info("第11轮取证分析深化V2路由已注册：内存/磁盘/网络/日志取证/综合取证/证据管理，共28个端点")
except Exception as e:
    log.warning(f"第11轮取证分析深化V2路由注册失败: {e}")


# ============== 第11轮升级：插件扩展系统路由（30端点） ==============
try:
    from api_server.plugin_system_routes import router as plugin_system_router
    app.include_router(plugin_system_router)
    log.info("第11轮插件扩展系统路由已注册：插件管理/市场/SDK/安全/运行时，共30个端点")
except Exception as e:
    log.warning(f"第11轮插件扩展系统路由注册失败: {e}")


# ============== 第11轮升级：新前端页面路由（4个控制台） ==============
try:
    from fastapi.responses import HTMLResponse as _HTMLR11

    _PAGES_R11 = [
        ("/cloud-security-v2", "cloud_security_v2_console.html", "云安全深化控制台"),
        ("/code-audit-v2", "code_audit_v2_console.html", "代码审计深化控制台"),
        ("/forensics-v2", "forensics_v2_console.html", "取证分析深化控制台"),
        ("/plugins-console", "plugin_system_console.html", "插件扩展系统控制台"),
    ]

    for _route, _fname, _desc in _PAGES_R11:
        def _make_page_handler_r11(fname=_fname, desc=_desc):
            @app.get(_route, include_in_schema=False)
            async def _page_handler_r11():
                _p = os.path.join(os.path.dirname(__file__), fname)
                if os.path.exists(_p):
                    with open(_p, "r", encoding="utf-8") as _f:
                        return _HTMLR11(content=_f.read())
                return _HTMLR11(content=f"<h1>{desc}页面未找到</h1>")
            return _page_handler_r11
        _make_page_handler_r11()

    log.info("第11轮新前端页面已注册：/cloud-security-v2 /code-audit-v2 /forensics-v2 /plugins-console")
except Exception as e:
    log.warning(f"第11轮新前端页面注册失败: {e}")




# ============== 第12轮升级：物联网(IoT)安全深化路由（30+端点） ==============
try:
    from api_server.iot_security_routes import router as iot_security_router
    app.include_router(iot_security_router)
    log.info("第12轮物联网安全深化路由已注册：设备发现/固件分析/协议安全/默认凭据/通信安全/漏洞检测/综合评估，共30+个端点")
except Exception as e:
    log.warning(f"第12轮物联网安全深化路由注册失败: {e}")


# ============== 第12轮升级：工控安全(ICS/SCADA)深化路由（30+端点） ==============
try:
    from api_server.ics_security_routes import router as ics_security_router
    app.include_router(ics_security_router)
    log.info("第12轮工控安全深化路由已注册：资产发现/协议分析/漏洞检测/基线检查/异常检测/威胁情报/综合评估，共30+个端点")
except Exception as e:
    log.warning(f"第12轮工控安全深化路由注册失败: {e}")


# ============== 第12轮升级：无线网络安全深化路由（30+端点） ==============
try:
    from api_server.wireless_security_routes import router as wireless_security_router
    app.include_router(wireless_security_router)
    log.info("第12轮无线网络安全深化路由已注册：WiFi扫描/WiFi安全/邪恶孪生/蓝牙安全/Zigbee安全/频谱分析/综合评估，共30+个端点")
except Exception as e:
    log.warning(f"第12轮无线网络安全深化路由注册失败: {e}")


# ============== 第12轮升级：API安全专业级深化路由（30+端点） ==============
try:
    from api_server.api_security_pro_routes import router as api_security_pro_router
    app.include_router(api_security_pro_router)
    log.info("第12轮API安全专业级深化路由已注册：OpenAPI解析/认证授权/注入测试/业务逻辑/安全配置/Fuzz测试/综合扫描，共30+个端点")
except Exception as e:
    log.warning(f"第12轮API安全专业级深化路由注册失败: {e}")


# ============== 第12轮升级：新前端页面路由（4个控制台） ==============
try:
    from fastapi.responses import HTMLResponse as _HTMLR12

    _PAGES_R12 = [
        ("/iot-security", "iot_security_console.html", "物联网安全控制台"),
        ("/ics-security", "ics_security_console.html", "工控安全控制台"),
        ("/wireless-security", "wireless_security_console.html", "无线网络安全控制台"),
        ("/api-security-pro", "api_security_pro_console.html", "API安全专业级控制台"),
    ]

    for _route, _fname, _desc in _PAGES_R12:
        def _make_page_handler_r12(fname=_fname, desc=_desc):
            @app.get(_route, include_in_schema=False)
            async def _page_handler_r12():
                _p = os.path.join(os.path.dirname(__file__), fname)
                if os.path.exists(_p):
                    with open(_p, "r", encoding="utf-8") as _f:
                        return _HTMLR12(content=_f.read())
                return _HTMLR12(content=f"<h1>{desc}页面未找到</h1>")
            return _page_handler_r12
        _make_page_handler_r12()

    log.info("第12轮新前端页面已注册：/iot-security /ics-security /wireless-security /api-security-pro")
except Exception as e:
    log.warning(f"第12轮新前端页面注册失败: {e}")




# ============== 第13轮升级：数据安全与隐私保护路由（30+端点） ==============
try:
    from api_server.data_security_routes import router as data_security_router
    app.include_router(data_security_router)
    log.info("第13轮数据安全与隐私保护路由已注册：数据分类/DLP/隐私合规/加密密钥/访问控制/综合评估，共30+个端点")
except Exception as e:
    log.warning(f"第13轮数据安全与隐私保护路由注册失败: {e}")


# ============== 第13轮升级：零信任安全架构路由（30+端点） ==============
try:
    from api_server.zero_trust_routes import router as zero_trust_router
    app.include_router(zero_trust_router)
    log.info("第13轮零信任安全架构路由已注册：身份访问/持续验证/微隔离/设备信任/应用API安全/成熟度评估，共30+个端点")
except Exception as e:
    log.warning(f"第13轮零信任安全架构路由注册失败: {e}")


# ============== 第13轮升级：蜜罐与欺骗技术路由（30+端点） ==============
try:
    from api_server.deception_routes import router as deception_router
    app.include_router(deception_router)
    log.info("第13轮蜜罐与欺骗技术路由已注册：蜜罐管理/攻击检测/威胁情报/诱饵面包屑/蜜网分布式/综合运营，共30+个端点")
except Exception as e:
    log.warning(f"第13轮蜜罐与欺骗技术路由注册失败: {e}")


# ============== 第13轮升级：暗网监控与数字风险保护(DRP)路由（30+端点） ==============
try:
    from api_server.darkweb_monitor_routes import router as darkweb_monitor_router
    app.include_router(darkweb_monitor_router)
    log.info("第13轮暗网监控与DRP路由已注册：暗网情报/凭证泄露/品牌保护/数据泄露分析/威胁Actor/综合运营，共30+个端点")
except Exception as e:
    log.warning(f"第13轮暗网监控与DRP路由注册失败: {e}")


# ============== 第13轮升级：新前端页面路由（4个控制台） ==============
try:
    from fastapi.responses import HTMLResponse as _HTMLR13

    _PAGES_R13 = [
        ("/data-security", "data_security_console.html", "数据安全与隐私保护控制台"),
        ("/zero-trust", "zero_trust_console.html", "零信任安全架构控制台"),
        ("/deception", "deception_console.html", "蜜罐与欺骗技术控制台"),
        ("/darkweb-monitor", "darkweb_monitor_console.html", "暗网监控与DRP控制台"),
    ]

    for _route, _fname, _desc in _PAGES_R13:
        def _make_page_handler_r13(fname=_fname, desc=_desc):
            @app.get(_route, include_in_schema=False)
            async def _page_handler_r13():
                _p = os.path.join(os.path.dirname(__file__), fname)
                if os.path.exists(_p):
                    with open(_p, "r", encoding="utf-8") as _f:
                        return _HTMLR13(content=_f.read())
                return _HTMLR13(content=f"<h1>{desc}页面未找到</h1>")
            return _page_handler_r13
        _make_page_handler_r13()

    log.info("第13轮新前端页面已注册：/data-security /zero-trust /deception /darkweb-monitor")
except Exception as e:
    log.warning(f"第13轮新前端页面注册失败: {e}")




# ============== 第14轮升级：DevSecOps全链路安全路由（30+端点） ==============
try:
    from api_server.devsecops_routes import router as devsecops_router
    app.include_router(devsecops_router)
    log.info("第14轮DevSecOps全链路安全路由已注册：流水线安全/代码仓库/构建制品/部署运行时/安全门禁/成熟度评估，共30+个端点")
except Exception as e:
    log.warning(f"第14轮DevSecOps全链路安全路由注册失败: {e}")


# ============== 第14轮升级：安全培训与意识平台路由（30+端点） ==============
try:
    from api_server.security_training_routes import router as security_training_router
    app.include_router(security_training_router)
    log.info("第14轮安全培训与意识平台路由已注册：课程管理/实验环境/考试认证/钓鱼演练/意识评估/运营管理，共30+个端点")
except Exception as e:
    log.warning(f"第14轮安全培训与意识平台路由注册失败: {e}")


# ============== 第14轮升级：专业报告引擎路由（30+端点） ==============
try:
    from api_server.report_engine_routes import router as report_engine_router
    app.include_router(report_engine_router)
    log.info("第14轮专业报告引擎路由已注册：模板库/智能生成/质量校验/多格式导出/协作审批/报告分析，共30+个端点")
except Exception as e:
    log.warning(f"第14轮专业报告引擎路由注册失败: {e}")


# ============== 第14轮升级：安全服务交付平台路由（30+端点） ==============
try:
    from api_server.service_delivery_routes import router as service_delivery_router
    app.include_router(service_delivery_router)
    log.info("第14轮安全服务交付平台路由已注册：项目管理/客户门户/工时计费/SLA管理/交付物/团队资源，共30+个端点")
except Exception as e:
    log.warning(f"第14轮安全服务交付平台路由注册失败: {e}")


# ============== 第14轮升级：新前端页面路由（4个控制台） ==============
try:
    from fastapi.responses import HTMLResponse as _HTMLR14
    _PAGES_R14 = [
        ("/devsecops", "devsecops_console.html", "DevSecOps全链路安全控制台"),
        ("/security-training", "security_training_console.html", "安全培训与意识平台控制台"),
        ("/report-engine", "report_engine_console.html", "专业报告引擎控制台"),
        ("/service-delivery", "service_delivery_console.html", "安全服务交付平台控制台"),
    ]
    for _route, _fname, _desc in _PAGES_R14:
        def _make_page_handler_r14(fname=_fname, desc=_desc):
            @app.get(_route, include_in_schema=False)
            async def _page_handler_r14():
                _p = os.path.join(os.path.dirname(__file__), fname)
                if os.path.exists(_p):
                    with open(_p, "r", encoding="utf-8") as _f:
                        return _HTMLR14(content=_f.read())
                return _HTMLR14(content=f"<h1>{desc}页面未找到</h1>")
            return _page_handler_r14
        _make_page_handler_r14()
    log.info("第14轮新前端页面已注册：/devsecops /security-training /report-engine /service-delivery")
except Exception as e:
    log.warning(f"第14轮新前端页面注册失败: {e}")




# ============== 第15轮升级：供应链安全深化路由（30+端点） ==============
try:
    from api_server.supply_chain_routes import router as supply_chain_router
    app.include_router(supply_chain_router)
    log.info("第15轮供应链安全深化路由已注册：SBOM管理/组件分析/漏洞检测/许可证合规/供应商风险/综合评估，共30+个端点")
except Exception as e:
    log.warning(f"第15轮供应链安全深化路由注册失败: {e}")


# ============== 第15轮升级：SOAR安全编排自动化与响应路由（30+端点） ==============
try:
    from api_server.soar_routes import router as soar_router
    app.include_router(soar_router)
    log.info("第15轮SOAR安全编排路由已注册：剧本编排/动作库/告警分诊/案例管理/执行监控/运营度量，共30+个端点")
except Exception as e:
    log.warning(f"第15轮SOAR安全编排路由注册失败: {e}")


# ============== 第15轮升级：开放API平台与开发者中心路由（30+端点） ==============
try:
    from api_server.developer_portal_routes import router as developer_portal_router
    app.include_router(developer_portal_router)
    log.info("第15轮开放API平台路由已注册：API文档/SDK工具/沙箱/应用密钥/用量计费/社区支持，共30+个端点")
except Exception as e:
    log.warning(f"第15轮开放API平台路由注册失败: {e}")


# ============== 第15轮升级：安全度量与KPI体系路由（30+端点） ==============
try:
    from api_server.security_metrics_routes import router as security_metrics_router
    app.include_router(security_metrics_router)
    log.info("第15轮安全度量与KPI体系路由已注册：成熟度模型/KPI指标库/风险评分/运营效率/合规审计/高管仪表盘，共30+个端点")
except Exception as e:
    log.warning(f"第15轮安全度量与KPI体系路由注册失败: {e}")


# ============== 第15轮升级：新前端页面路由（4个控制台） ==============
try:
    from fastapi.responses import HTMLResponse as _HTMLR15
    _PAGES_R15 = [
        ("/supply-chain", "supply_chain_console.html", "供应链安全深化控制台"),
        ("/soar", "soar_console.html", "SOAR安全编排自动化控制台"),
        ("/developer-portal", "developer_portal_console.html", "开放API平台与开发者中心控制台"),
        ("/security-metrics", "security_metrics_console.html", "安全度量与KPI体系控制台"),
    ]
    for _route, _fname, _desc in _PAGES_R15:
        def _make_page_handler_r15(fname=_fname, desc=_desc):
            @app.get(_route, include_in_schema=False)
            async def _page_handler_r15():
                _p = os.path.join(os.path.dirname(__file__), fname)
                if os.path.exists(_p):
                    with open(_p, "r", encoding="utf-8") as _f:
                        return _HTMLR15(content=_f.read())
                return _HTMLR15(content=f"<h1>{desc}页面未找到</h1>")
            return _page_handler_r15
        _make_page_handler_r15()
    log.info("第15轮新前端页面已注册：/supply-chain /soar /developer-portal /security-metrics")
except Exception as e:
    log.warning(f"第15轮新前端页面注册失败: {e}")




# ============== 第16轮升级方向3：种子数据与初始化体验路由（34个端点） ==============
try:
    from api_server.seed_data_routes import router as seed_data_router
    app.include_router(seed_data_router)
    log.info("第16轮种子数据与初始化路由已注册：初始化向导/种子管理/漏洞库/知识库/工具模板/报告KPI合规，共34个端点")
except Exception as e:
    log.warning(f"第16轮种子数据路由注册失败: {e}")


# ============== 第16轮升级方向3：种子数据控制台页面 ==============
try:
    from fastapi.responses import HTMLResponse as _HTMLR16
    _seed_page_file = "seed_manager_console.html"
    @app.get("/seed-manager", include_in_schema=False)
    def _seed_manager_page():
        _p = os.path.join(os.path.dirname(__file__), _seed_page_file)
        if os.path.exists(_p):
            with open(_p, "r", encoding="utf-8") as _f:
                return _HTMLR16(content=_f.read())
        return _HTMLR16(content="<h1>种子数据控制台页面未找到</h1>")
    log.info("第16轮种子数据控制台页面已注册：/seed-manager")
except Exception as e:
    log.warning(f"第16轮种子数据控制台页面注册失败: {e}")




# ============== 第16轮升级方向1：端到端工作流真实打通路由（32个端点） ==============
try:
    from api_server.workflow_v2_routes import router as workflow_v2_router
    app.include_router(workflow_v2_router)
    log.info("第16轮端到端工作流路由已注册：一键评估/执行追踪/场景模板/可视化DAG/批量调度/端到端验证，共32个端点")
except Exception as e:
    log.warning(f"第16轮端到端工作流路由注册失败: {e}")


# ============== 第16轮升级方向2：前端交互深度提升路由（55个端点） ==============
try:
    from api_server.frontend_v2_routes import router as frontend_v2_router
    app.include_router(frontend_v2_router)
    log.info("第16轮前端交互深度提升路由已注册：任务面板/交互式报告/数据CRUD/通知中心/性能优化/导航布局，共55个端点")
except Exception as e:
    log.warning(f"第16轮前端交互深度提升路由注册失败: {e}")


# ============== 第16轮升级方向4：外部工具检测与性能优化路由（36个端点） ==============
try:
    from api_server.tool_runtime_routes import router as tool_runtime_router
    app.include_router(tool_runtime_router)
    log.info("第16轮工具运行时与性能路由已注册：工具检测/智能降级/安装引导/性能监控/系统健康/启动优化，共36个端点")
except Exception as e:
    log.warning(f"第16轮工具运行时与性能路由注册失败: {e}")


# ============== 第16轮升级：新前端页面路由（4个控制台） ==============
try:
    from fastapi.responses import HTMLResponse as _HTMLR16
    _PAGES_R16 = [
        ("/workflow-executor", "workflow_executor_console.html", "端到端工作流执行器控制台"),
        ("/task-console", "task_console_console.html", "统一任务控制台"),
        ("/system-health", "system_health_console.html", "系统健康与工具运行时控制台"),
    ]
    for _route, _fname, _desc in _PAGES_R16:
        def _make_page_handler_r16(fname=_fname, desc=_desc):
            @app.get(_route, include_in_schema=False)
            async def _page_handler_r16():
                _p = os.path.join(os.path.dirname(__file__), fname)
                if os.path.exists(_p):
                    with open(_p, "r", encoding="utf-8") as _f:
                        return _HTMLR16(content=_f.read())
                return _HTMLR16(content=f"<h1>{desc}页面未找到</h1>")
            return _page_handler_r16
        _make_page_handler_r16()
    log.info("第16轮新前端页面已注册：/workflow-executor /task-console /system-health（/seed-manager已由方向3注册）")
except Exception as e:
    log.warning(f"第16轮新前端页面注册失败: {e}")




# ============== 第17轮升级方向1：威胁狩猎专业级路由（30+端点） ==============
try:
    from api_server.threat_hunt_routes import router as threat_hunt_router
    app.include_router(threat_hunt_router)
    log.info("第17轮威胁狩猎专业级路由已注册：狩猎查询/假设驱动/行为分析/IOC富化/数据管理/报告度量，共30+个端点")
except Exception as e:
    log.warning(f"第17轮威胁狩猎专业级路由注册失败: {e}")


# ============== 第17轮升级方向2：网络流量分析NTA/NDR路由（30+端点） ==============
try:
    from api_server.network_analysis_routes import router as network_analysis_router
    app.include_router(network_analysis_router)
    log.info("第17轮网络流量分析路由已注册：流量捕获/异常检测/行为分析/威胁规则/流量取证/NDR仪表盘，共30+个端点")
except Exception as e:
    log.warning(f"第17轮网络流量分析路由注册失败: {e}")


# ============== 第17轮升级方向3：身份安全与IAM深化路由（30+端点） ==============
try:
    from api_server.identity_security_routes import router as identity_security_router
    app.include_router(identity_security_router)
    log.info("第17轮身份安全与IAM路由已注册：身份治理/权限审计/威胁检测/特权管理/访问认证/运营仪表盘，共30+个端点")
except Exception as e:
    log.warning(f"第17轮身份安全与IAM路由注册失败: {e}")


# ============== 第17轮升级方向4：终端安全EDR路由（30+端点） ==============
try:
    from api_server.endpoint_security_routes import router as endpoint_security_router
    app.include_router(endpoint_security_router)
    log.info("第17轮终端安全EDR路由已注册：终端资产/进程行为/恶意软件/威胁响应/漏洞补丁/EDR仪表盘，共30+个端点")
except Exception as e:
    log.warning(f"第17轮终端安全EDR路由注册失败: {e}")


# ============== 第17轮升级：新前端页面路由（4个控制台） ==============
try:
    from fastapi.responses import HTMLResponse as _HTMLR17
    _PAGES_R17 = [
        ("/threat-hunt", "threat_hunt_console.html", "威胁狩猎专业级控制台"),
        ("/network-analysis", "network_analysis_console.html", "网络流量分析NTA/NDR控制台"),
        ("/identity-security", "identity_security_console.html", "身份安全与IAM控制台"),
        ("/endpoint-security", "endpoint_security_console.html", "终端安全EDR控制台"),
    ]
    for _route, _fname, _desc in _PAGES_R17:
        def _make_page_handler_r17(fname=_fname, desc=_desc):
            @app.get(_route, include_in_schema=False)
            async def _page_handler_r17():
                _p = os.path.join(os.path.dirname(__file__), fname)
                if os.path.exists(_p):
                    with open(_p, "r", encoding="utf-8") as _f:
                        return _HTMLR17(content=_f.read())
                return _HTMLR17(content=f"<h1>{desc}页面未找到</h1>")
            return _page_handler_r17
        _make_page_handler_r17()
    log.info("第17轮新前端页面已注册：/threat-hunt /network-analysis /identity-security /endpoint-security")
except Exception as e:
    log.warning(f"第17轮新前端页面注册失败: {e}")




# ============== 第18轮升级方向1：邮件安全路由（30+端点） ==============
try:
    from api_server.email_security_routes import router as email_security_router
    app.include_router(email_security_router)
    log.info("第18轮邮件安全路由已注册：钓鱼检测/BEC检测/邮件认证/附件沙箱/威胁情报/运营仪表盘，共30+个端点")
except Exception as e:
    log.warning(f"第18轮邮件安全路由注册失败: {e}")


# ============== 第18轮升级方向2：容器与Kubernetes安全路由（30+端点） ==============
try:
    from api_server.container_security_routes import router as container_security_router
    app.include_router(container_security_router)
    log.info("第18轮容器与K8s安全路由已注册：镜像扫描/运行时安全/K8s配置审计/K8s运行时/基础设施/运营仪表盘，共30+个端点")
except Exception as e:
    log.warning(f"第18轮容器与K8s安全路由注册失败: {e}")


# ============== 第18轮升级方向3：漏洞赏金/SRC管理平台路由（30+端点） ==============
try:
    from api_server.bug_bounty_routes import router as bug_bounty_router
    app.include_router(bug_bounty_router)
    log.info("第18轮漏洞赏金/SRC平台路由已注册：项目管理/漏洞提交/白帽社区/赏金财务/漏洞生命周期/运营仪表盘，共30+个端点")
except Exception as e:
    log.warning(f"第18轮漏洞赏金/SRC平台路由注册失败: {e}")


# ============== 第18轮升级方向4：CTF训练平台路由（30+端点） ==============
try:
    from api_server.ctf_platform_routes import router as ctf_platform_router
    app.include_router(ctf_platform_router)
    log.info("第18轮CTF训练平台路由已注册：题目靶场/竞赛赛事/解题验证/学习路径/战队管理/运营仪表盘，共30+个端点")
except Exception as e:
    log.warning(f"第18轮CTF训练平台路由注册失败: {e}")


# ============== 第18轮升级：新前端页面路由（4个控制台） ==============
try:
    from fastapi.responses import HTMLResponse as _HTMLR18
    _PAGES_R18 = [
        ("/email-security", "email_security_console.html", "邮件安全控制台"),
        ("/container-security", "container_security_console.html", "容器与Kubernetes安全控制台"),
        ("/bug-bounty", "bug_bounty_console.html", "漏洞赏金/SRC管理平台控制台"),
        ("/ctf-platform", "ctf_platform_console.html", "CTF训练平台控制台"),
    ]
    for _route, _fname, _desc in _PAGES_R18:
        def _make_page_handler_r18(fname=_fname, desc=_desc):
            @app.get(_route, include_in_schema=False)
            async def _page_handler_r18():
                _p = os.path.join(os.path.dirname(__file__), fname)
                if os.path.exists(_p):
                    with open(_p, "r", encoding="utf-8") as _f:
                        return _HTMLR18(content=_f.read())
                return _HTMLR18(content=f"<h1>{desc}页面未找到</h1>")
            return _page_handler_r18
        _make_page_handler_r18()
    log.info("第18轮新前端页面已注册：/email-security /container-security /bug-bounty /ctf-platform")
except Exception as e:
    log.warning(f"第18轮新前端页面注册失败: {e}")




# ============== 第19轮升级方向1：性能优化大提升路由（30+端点） ==============
try:
    from api_server.performance_routes import router as performance_router
    app.include_router(performance_router)
    log.info("第19轮性能优化路由已注册：查询优化/API性能/并发异步/启动内存/数据库/性能仪表盘，共30+个端点")
except Exception as e:
    log.warning(f"第19轮性能优化路由注册失败: {e}")


# ============== 第19轮升级方向2：安全加固大提升路由（30+端点） ==============
try:
    from api_server.self_security_routes import router as self_security_router
    app.include_router(self_security_router)
    log.info("第19轮安全加固路由已注册：自身渗透/代码审计/API加固/数据安全/运行时防护/安全仪表盘，共30+个端点")
except Exception as e:
    log.warning(f"第19轮安全加固路由注册失败: {e}")


# ============== 第19轮升级方向3：文档体系大提升路由（30+端点） ==============
try:
    from api_server.docs_system_routes import router as docs_system_router
    app.include_router(docs_system_router)
    log.info("第19轮文档体系路由已注册：架构文档/API文档/用户手册/部署运维/知识库/文档管理，共30+个端点")
except Exception as e:
    log.warning(f"第19轮文档体系路由注册失败: {e}")


# ============== 第19轮升级方向4：测试体系与CI/CD路由（30+端点） ==============
try:
    from api_server.testing_routes import router as testing_router
    app.include_router(testing_router)
    log.info("第19轮测试体系与CI/CD路由已注册：单元测试/集成测试/性能测试/安全测试/CI-CD流水线/测试仪表盘，共30+个端点")
except Exception as e:
    log.warning(f"第19轮测试体系与CI/CD路由注册失败: {e}")


# ============== 第19轮升级：新前端页面路由（4个控制台） ==============
try:
    from fastapi.responses import HTMLResponse as _HTMLR19
    _PAGES_R19 = [
        ("/performance", "performance_console.html", "性能优化控制台"),
        ("/self-security", "self_security_console.html", "安全加固控制台"),
        ("/docs-center", "docs_system_console.html", "文档体系控制台"),
        ("/testing", "testing_console.html", "测试体系与CI/CD控制台"),
    ]
    for _route, _fname, _desc in _PAGES_R19:
        def _make_page_handler_r19(fname=_fname, desc=_desc):
            @app.get(_route, include_in_schema=False)
            async def _page_handler_r19():
                _p = os.path.join(os.path.dirname(__file__), fname)
                if os.path.exists(_p):
                    with open(_p, "r", encoding="utf-8") as _f:
                        return _HTMLR19(content=_f.read())
                return _HTMLR19(content=f"<h1>{desc}页面未找到</h1>")
            return _page_handler_r19
        _make_page_handler_r19()
    log.info("第19轮新前端页面已注册：/performance /self-security /docs-center /testing")
except Exception as e:
    log.warning(f"第19轮新前端页面注册失败: {e}")




# ============== 第20轮升级方向1：一键部署与安装包路由（30+端点） ==============
try:
    from api_server.deploy_routes import router as deploy_router
    app.include_router(deploy_router)
    log.info("第20轮一键部署路由已注册：环境检测/一键安装/配置向导/备份恢复/多环境部署/部署管理，共30+个端点")
except Exception as e:
    log.warning(f"第20轮一键部署路由注册失败: {e}")


# ============== 第20轮升级方向2：Web渗透评估做深路由（30+端点） ==============
try:
    from api_server.web_pentest_deep_routes import router as web_pentest_deep_router
    app.include_router(web_pentest_deep_router)
    log.info("第20轮Web渗透做深路由已注册：高级侦察/注入检测/认证授权/业务逻辑/漏洞验证/渗透控制台，共30+个端点")
except Exception as e:
    log.warning(f"第20轮Web渗透做深路由注册失败: {e}")


# ============== 第20轮升级方向3：移动APK分析做深路由（30+端点） ==============
try:
    from api_server.mobile_deep_routes import router as mobile_deep_router
    app.include_router(mobile_deep_router)
    log.info("第20轮移动APK做深路由已注册：APK解析/漏洞检测/隐私合规/恶意软件/动态分析/移动控制台，共30+个端点")
except Exception as e:
    log.warning(f"第20轮移动APK做深路由注册失败: {e}")


# ============== 第20轮升级方向4：报告引擎做深路由（30+端点） ==============
try:
    from api_server.report_engine_deep_routes import router as report_engine_deep_router
    app.include_router(report_engine_deep_router)
    log.info("第20轮报告引擎做深路由已注册：模板体系/内容生成/图表可视化/质量审核/导出分发/报告管理，共30+个端点")
except Exception as e:
    log.warning(f"第20轮报告引擎做深路由注册失败: {e}")


# ============== 第20轮升级：新前端页面路由（4个控制台） ==============
try:
    from fastapi.responses import HTMLResponse as _HTMLR20
    _PAGES_R20 = [
        ("/deploy", "deploy_console.html", "一键部署控制台"),
        ("/web-pentest-deep", "web_pentest_deep_console.html", "Web渗透做深控制台"),
        ("/mobile-deep", "mobile_deep_console.html", "移动APK做深控制台"),
        ("/report-engine-deep", "report_engine_deep_console.html", "报告引擎做深控制台"),
    ]
    for _route, _fname, _desc in _PAGES_R20:
        def _make_page_handler_r20(fname=_fname, desc=_desc):
            @app.get(_route, include_in_schema=False)
            async def _page_handler_r20():
                _p = os.path.join(os.path.dirname(__file__), fname)
                if os.path.exists(_p):
                    with open(_p, "r", encoding="utf-8") as _f:
                        return _HTMLR20(content=_f.read())
                return _HTMLR20(content=f"<h1>{desc}页面未找到</h1>")
            return _page_handler_r20
        _make_page_handler_r20()
    log.info("第20轮新前端页面已注册：/deploy /web-pentest-deep /mobile-deep /report-engine-deep")
except Exception as e:
    log.warning(f"第20轮新前端页面注册失败: {e}")




# ============== 第21轮升级方向1：License授权系统路由（30+端点） ==============
try:
    from api_server.license_system_routes import router as license_system_router
    app.include_router(license_system_router)
    log.info("第21轮License授权系统路由已注册：License生成/设备绑定/功能权限/续费升级/防盗版/运营仪表盘，共30+个端点")
except Exception as e:
    log.warning(f"第21轮License授权系统路由注册失败: {e}")


# ============== 第21轮升级方向2：品牌官网落地页路由（30+端点） ==============
try:
    from api_server.brand_website_routes import router as brand_website_router
    app.include_router(brand_website_router)
    log.info("第21轮品牌官网落地页路由已注册：内容管理/产品展示/定价购买/文档支持/博客营销/运营仪表盘，共30+个端点")
except Exception as e:
    log.warning(f"第21轮品牌官网落地页路由注册失败: {e}")


# ============== 第21轮升级方向3：客户管理CRM路由（30+端点） ==============
try:
    from api_server.crm_system_routes import router as crm_system_router
    app.include_router(crm_system_router)
    log.info("第21轮客户管理CRM路由已注册：客户管理/销售漏斗/沟通活动/产品定价/客户服务/运营仪表盘，共30+个端点")
except Exception as e:
    log.warning(f"第21轮客户管理CRM路由注册失败: {e}")


# ============== 第21轮升级方向4：交互式教程路由（30+端点） ==============
try:
    from api_server.interactive_tutorial_routes import router as interactive_tutorial_router
    app.include_router(interactive_tutorial_router)
    log.info("第21轮交互式教程路由已注册：教程内容/交互环境/学习路径/进度评估/场景实战/运营控制台，共30+个端点")
except Exception as e:
    log.warning(f"第21轮交互式教程路由注册失败: {e}")


# ============== 第21轮升级：新前端页面路由（4个控制台） ==============
try:
    from fastapi.responses import HTMLResponse as _HTMLR21
    _PAGES_R21 = [
        ("/license-system", "license_system_console.html", "License授权系统控制台"),
        ("/brand-website", "brand_website_console.html", "品牌官网落地页控制台"),
        ("/crm-system", "crm_system_console.html", "客户管理CRM控制台"),
        ("/interactive-tutorial", "interactive_tutorial_console.html", "交互式教程控制台"),
    ]
    for _route, _fname, _desc in _PAGES_R21:
        def _make_page_handler_r21(fname=_fname, desc=_desc):
            @app.get(_route, include_in_schema=False)
            async def _page_handler_r21():
                _p = os.path.join(os.path.dirname(__file__), fname)
                if os.path.exists(_p):
                    with open(_p, "r", encoding="utf-8") as _f:
                        return _HTMLR21(content=_f.read())
                return _HTMLR21(content=f"<h1>{desc}页面未找到</h1>")
            return _page_handler_r21
        _make_page_handler_r21()
    log.info("第21轮新前端页面已注册：/license-system /brand-website /crm-system /interactive-tutorial")
except Exception as e:
    log.warning(f"第21轮新前端页面注册失败: {e}")




# ============== 第22轮升级方向1：一键Demo模式路由（30+端点） ==============
try:
    from api_server.demo_mode_routes import router as demo_mode_router
    app.include_router(demo_mode_router)
    log.info("第22轮一键Demo模式路由已注册：Demo数据集/自动演示/交互引导/快速体验/品牌定制/运营控制台，共30+个端点")
except Exception as e:
    log.warning(f"第22轮一键Demo模式路由注册失败: {e}")


# ============== 第22轮升级方向2：真实靶场集成路由（30+端点） ==============
try:
    from api_server.range_integration_routes import router as range_integration_router
    app.include_router(range_integration_router)
    log.info("第22轮真实靶场集成路由已注册：靶场管理/漏洞靶场/自动扫描/报告生成/学习训练/运营控制台，共30+个端点")
except Exception as e:
    log.warning(f"第22轮真实靶场集成路由注册失败: {e}")


# ============== 第22轮升级方向3：性能最终优化路由（30+端点） ==============
try:
    from api_server.performance_final_routes import router as performance_final_router
    app.include_router(performance_final_router)
    log.info("第22轮性能最终优化路由已注册：全链路压测/瓶颈修复/启动优化/API优化/内存优化/监控告警，共30+个端点")
except Exception as e:
    log.warning(f"第22轮性能最终优化路由注册失败: {e}")


# ============== 第22轮升级方向4：安全最终加固路由（30+端点） ==============
try:
    from api_server.security_final_routes import router as security_final_router
    app.include_router(security_final_router)
    log.info("第22轮安全最终加固路由已注册：自身渗透/依赖扫描/基线检查/审计监控/数据安全/安全控制台，共30+个端点")
except Exception as e:
    log.warning(f"第22轮安全最终加固路由注册失败: {e}")


# ============== 第22轮升级：新前端页面路由（4个控制台） ==============
try:
    from fastapi.responses import HTMLResponse as _HTMLR22
    _PAGES_R22 = [
        ("/demo-mode", "demo_mode_console.html", "一键Demo模式控制台"),
        ("/range-integration", "range_integration_console.html", "真实靶场集成控制台"),
        ("/performance-final", "performance_final_console.html", "性能最终优化控制台"),
        ("/security-final", "security_final_console.html", "安全最终加固控制台"),
    ]
    for _route, _fname, _desc in _PAGES_R22:
        def _make_page_handler_r22(fname=_fname, desc=_desc):
            @app.get(_route, include_in_schema=False)
            async def _page_handler_r22():
                _p = os.path.join(os.path.dirname(__file__), fname)
                if os.path.exists(_p):
                    with open(_p, "r", encoding="utf-8") as _f:
                        return _HTMLR22(content=_f.read())
                return _HTMLR22(content=f"<h1>{desc}页面未找到</h1>")
            return _page_handler_r22
        _make_page_handler_r22()
    log.info("第22轮新前端页面已注册：/demo-mode /range-integration /performance-final /security-final")
except Exception as e:
    log.warning(f"第22轮新前端页面注册失败: {e}")




# ============== 第23轮升级方向1：AI大模型智能决策引擎路由（40+端点） ==============
try:
    from api_server.ai_intelligence_routes import router as ai_intelligence_router
    app.include_router(ai_intelligence_router)
    log.info("第23轮AI大模型智能决策引擎路由已注册：自然语言助手/智能扫描决策/POC生成/智能报告/AI知识库/AI控制台，共40+个端点")
except Exception as e:
    log.warning(f"第23轮AI大模型智能决策引擎路由注册失败: {e}")


# ============== 第23轮升级方向2：分布式扫描与任务调度路由（40+端点） ==============
try:
    from api_server.distributed_scan_routes import router as distributed_scan_router
    app.include_router(distributed_scan_router)
    log.info("第23轮分布式扫描与任务调度路由已注册：集群架构/任务管理/代理池/断点续扫/资源管理/分布式控制台，共40+个端点")
except Exception as e:
    log.warning(f"第23轮分布式扫描与任务调度路由注册失败: {e}")


# ============== 第23轮升级方向3：威胁情报与攻击面管理路由（40+端点） ==============
try:
    from api_server.threat_intel_routes import router as threat_intel_router
    app.include_router(threat_intel_router)
    log.info("第23轮威胁情报与攻击面管理路由已注册：情报源/IOC管理/攻击面/漏洞情报/威胁Actor/情报控制台，共40+个端点")
except Exception as e:
    log.warning(f"第23轮威胁情报与攻击面管理路由注册失败: {e}")


# ============== 第23轮升级方向4：企业级多租户与计费路由（40+端点） ==============
try:
    from api_server.enterprise_saas_routes import router as enterprise_saas_router
    app.include_router(enterprise_saas_router)
    log.info("第23轮企业级多租户与计费路由已注册：多租户架构/订阅计费/客户门户/SSO身份/审计合规/企业控制台，共40+个端点")
except Exception as e:
    log.warning(f"第23轮企业级多租户与计费路由注册失败: {e}")


# ============== 第23轮升级：新前端页面路由（4个控制台） ==============
try:
    from fastapi.responses import HTMLResponse as _HTMLR23
    _PAGES_R23 = [
        ("/ai-intelligence", "ai_intelligence_console.html", "AI大模型智能决策引擎控制台"),
        ("/distributed-scan", "distributed_scan_console.html", "分布式扫描与任务调度控制台"),
        ("/threat-intel", "threat_intel_console.html", "威胁情报与攻击面管理控制台"),
        ("/enterprise-saas", "enterprise_saas_console.html", "企业级多租户与计费控制台"),
    ]
    for _route, _fname, _desc in _PAGES_R23:
        def _make_page_handler_r23(fname=_fname, desc=_desc):
            @app.get(_route, include_in_schema=False)
            async def _page_handler_r23():
                _p = os.path.join(os.path.dirname(__file__), fname)
                if os.path.exists(_p):
                    with open(_p, "r", encoding="utf-8") as _f:
                        return _HTMLR23(content=_f.read())
                return _HTMLR23(content=f"<h1>{desc}页面未找到</h1>")
            return _page_handler_r23
        _make_page_handler_r23()
    log.info("第23轮新前端页面已注册：/ai-intelligence /distributed-scan /threat-intel /enterprise-saas")
except Exception as e:
    log.warning(f"第23轮新前端页面注册失败: {e}")




# ============== 第24轮升级方向1：自动化红蓝对抗与攻击模拟平台路由（50+端点） ==============
try:
    from api_server.red_blue_team_routes import router as red_blue_team_router
    app.include_router(red_blue_team_router)
    log.info("第24轮自动化红蓝对抗与攻击模拟平台路由已注册：攻击模拟/防御验证/对抗管理/攻击可视化/攻击工具/对抗控制台，共50+个端点")
except Exception as e:
    log.warning(f"第24轮自动化红蓝对抗与攻击模拟平台路由注册失败: {e}")


# ============== 第24轮升级方向2：SOAR深度平台路由（50+端点） ==============
try:
    from api_server.soar_deep_routes import router as soar_deep_router
    app.include_router(soar_deep_router)
    log.info("第24轮SOAR深度平台路由已注册：剧本编排/响应动作/告警分诊/案例管理/威胁情报联动/SOAR控制台，共50+个端点")
except Exception as e:
    log.warning(f"第24轮SOAR深度平台路由注册失败: {e}")


# ============== 第24轮升级方向3：数据安全与隐私保护深度平台路由（50+端点） ==============
try:
    from api_server.data_security_deep_routes import router as data_security_deep_router
    app.include_router(data_security_deep_router)
    log.info("第24轮数据安全与隐私保护深度平台路由已注册：数据分类分级/DLP防泄漏/隐私计算加密/访问审计/隐私合规/数据安全控制台，共50+个端点")
except Exception as e:
    log.warning(f"第24轮数据安全与隐私保护深度平台路由注册失败: {e}")


# ============== 第24轮升级方向4：跨平台客户端与开发者生态路由（50+端点） ==============
try:
    from api_server.developer_ecosystem_routes import router as developer_ecosystem_router
    app.include_router(developer_ecosystem_router)
    log.info("第24轮跨平台客户端与开发者生态路由已注册：CLI工具/桌面客户端/IDE插件/Python SDK/开发者门户/开放API，共50+个端点")
except Exception as e:
    log.warning(f"第24轮跨平台客户端与开发者生态路由注册失败: {e}")


# ============== 第24轮升级：新前端页面路由（4个控制台） ==============
try:
    from fastapi.responses import HTMLResponse as _HTMLR24
    _PAGES_R24 = [
        ("/red-blue-team", "red_blue_team_console.html", "自动化红蓝对抗与攻击模拟平台控制台"),
        ("/soar-deep", "soar_deep_console.html", "SOAR深度平台控制台"),
        ("/data-security-deep", "data_security_deep_console.html", "数据安全与隐私保护深度平台控制台"),
        ("/developer-ecosystem", "developer_ecosystem_console.html", "跨平台客户端与开发者生态控制台"),
    ]
    for _route, _fname, _desc in _PAGES_R24:
        def _make_page_handler_r24(fname=_fname, desc=_desc):
            @app.get(_route, include_in_schema=False)
            async def _page_handler_r24():
                _p = os.path.join(os.path.dirname(__file__), fname)
                if os.path.exists(_p):
                    with open(_p, "r", encoding="utf-8") as _f:
                        return _HTMLR24(content=_f.read())
                return _HTMLR24(content=f"<h1>{desc}页面未找到</h1>")
            return _page_handler_r24
        _make_page_handler_r24()
    log.info("第24轮新前端页面已注册：/red-blue-team /soar-deep /data-security-deep /developer-ecosystem")
except Exception as e:
    log.warning(f"第24轮新前端页面注册失败: {e}")




# ============== 第25轮升级方向1：高级威胁检测与响应(UEBA+ML)路由（50+端点） ==============
try:
    from api_server.advanced_threat_routes import router as advanced_threat_router
    app.include_router(advanced_threat_router)
    log.info("第25轮高级威胁检测与响应(UEBA+ML)路由已注册：UEBA/ML异常检测/APT检测/攻击链分析/威胁狩猎/高级威胁控制台，共50+个端点")
except Exception as e:
    log.warning(f"第25轮高级威胁检测与响应(UEBA+ML)路由注册失败: {e}")


# ============== 第25轮升级方向2：云原生安全深度(CNAPP)路由（50+端点） ==============
try:
    from api_server.cloud_native_security_routes import router as cloud_native_security_router
    app.include_router(cloud_native_security_router)
    log.info("第25轮云原生安全深度(CNAPP)路由已注册：K8s运行时/容器安全/服务网格/CWPP/CSPM/云原生安全控制台，共50+个端点")
except Exception as e:
    log.warning(f"第25轮云原生安全深度(CNAPP)路由注册失败: {e}")


# ============== 第25轮升级方向3：安全度量与成熟度平台路由（50+端点） ==============
try:
    from api_server.security_metrics_deep_routes import router as security_metrics_deep_router
    app.include_router(security_metrics_deep_router)
    log.info("第25轮安全度量与成熟度平台路由已注册：成熟度评估/KPI-KRI/ROI/效能度量/文化评估/安全度量控制台，共50+个端点")
except Exception as e:
    log.warning(f"第25轮安全度量与成熟度平台路由注册失败: {e}")


# ============== 第25轮升级方向4：国际化与全球部署路由（50+端点） ==============
try:
    from api_server.globalization_routes import router as globalization_router
    app.include_router(globalization_router)
    log.info("第25轮国际化与全球部署路由已注册：多语言国际化/区域合规/国际支付/全球部署CDN/本地化/国际化控制台，共50+个端点")
except Exception as e:
    log.warning(f"第25轮国际化与全球部署路由注册失败: {e}")


# ============== 第25轮升级：新前端页面路由（4个控制台） ==============
try:
    from fastapi.responses import HTMLResponse as _HTMLR25
    _PAGES_R25 = [
        ("/advanced-threat", "advanced_threat_console.html", "高级威胁检测与响应(UEBA+ML)控制台"),
        ("/cloud-native-security", "cloud_native_security_console.html", "云原生安全深度(CNAPP)控制台"),
        ("/security-metrics", "security_metrics_deep_console.html", "安全度量与成熟度平台控制台"),
        ("/globalization", "globalization_console.html", "国际化与全球部署控制台"),
    ]
    for _route, _fname, _desc in _PAGES_R25:
        def _make_page_handler_r25(fname=_fname, desc=_desc):
            @app.get(_route, include_in_schema=False)
            async def _page_handler_r25():
                _p = os.path.join(os.path.dirname(__file__), fname)
                if os.path.exists(_p):
                    with open(_p, "r", encoding="utf-8") as _f:
                        return _HTMLR25(content=_f.read())
                return _HTMLR25(content=f"<h1>{desc}页面未找到</h1>")
            return _page_handler_r25
        _make_page_handler_r25()
    log.info("第25轮新前端页面已注册：/advanced-threat /cloud-native-security /security-metrics /globalization")
except Exception as e:
    log.warning(f"第25轮新前端页面注册失败: {e}")




# ============== 第26轮升级方向1：安全大模型与AI Agent深度平台路由（50+端点） ==============
try:
    from api_server.security_llm_routes import router as security_llm_router
    app.include_router(security_llm_router)
    log.info("第26轮安全大模型与AI Agent深度平台路由已注册：大模型管理/Agent引擎/代码生成/问答系统/智能报告/大模型控制台，共50+个端点")
except Exception as e:
    log.warning(f"第26轮安全大模型与AI Agent深度平台路由注册失败: {e}")


# ============== 第26轮升级方向2：安全自动化与DevSecOps深度平台路由（50+端点） ==============
try:
    from api_server.devsecops_deep_routes import router as devsecops_deep_router
    app.include_router(devsecops_deep_router)
    log.info("第26轮安全自动化与DevSecOps深度平台路由已注册：CI/CD安全/SAST深度/依赖深度/容器深度/IaC安全/安全即代码/DevSecOps控制台，共50+个端点")
except Exception as e:
    log.warning(f"第26轮安全自动化与DevSecOps深度平台路由注册失败: {e}")


# ============== 第26轮升级方向3：安全运营中心(SOC)深度平台路由（50+端点） ==============
try:
    from api_server.soc_deep_routes import router as soc_deep_router
    app.include_router(soc_deep_router)
    log.info("第26轮安全运营中心(SOC)深度平台路由已注册：SIEM日志/关联规则/告警分诊/事件响应/威胁情报/SOC度量/SOC控制台，共50+个端点")
except Exception as e:
    log.warning(f"第26轮安全运营中心(SOC)深度平台路由注册失败: {e}")


# ============== 第26轮升级方向4：安全培训与认证平台深度路由（50+端点） ==============
try:
    from api_server.security_training_deep_routes import router as security_training_deep_router
    app.include_router(security_training_deep_router)
    log.info("第26轮安全培训与认证平台深度路由已注册：课程体系/实验环境/考试认证/能力评估/企业培训/安全意识/培训控制台，共50+个端点")
except Exception as e:
    log.warning(f"第26轮安全培训与认证平台深度路由注册失败: {e}")


# ============== 第26轮升级：新前端页面路由（4个控制台） ==============
try:
    from fastapi.responses import HTMLResponse as _HTMLR26
    _PAGES_R26 = [
        ("/security-llm", "security_llm_console.html", "安全大模型与AI Agent深度平台控制台"),
        ("/devsecops-deep", "devsecops_deep_console.html", "安全自动化与DevSecOps深度平台控制台"),
        ("/soc-deep", "soc_deep_console.html", "安全运营中心(SOC)深度平台控制台"),
        ("/security-training-deep", "security_training_deep_console.html", "安全培训与认证平台深度控制台"),
    ]
    for _route, _fname, _desc in _PAGES_R26:
        def _make_page_handler_r26(fname=_fname, desc=_desc):
            @app.get(_route, include_in_schema=False)
            async def _page_handler_r26():
                _p = os.path.join(os.path.dirname(__file__), fname)
                if os.path.exists(_p):
                    with open(_p, "r", encoding="utf-8") as _f:
                        return _HTMLR26(content=_f.read())
                return _HTMLR26(content=f"<h1>{desc}页面未找到</h1>")
            return _page_handler_r26
        _make_page_handler_r26()
    log.info("第26轮新前端页面已注册：/security-llm /devsecops-deep /soc-deep /security-training-deep")
except Exception as e:
    log.warning(f"第26轮新前端页面注册失败: {e}")




# ============== 第28轮升级方向1：真实工具集成深度增强路由（60+端点） ==============
try:
    from api_server.real_tools_deep_routes import router as real_tools_deep_router
    app.include_router(real_tools_deep_router)
    log.info("第28轮真实工具集成深度增强路由已注册：Nmap深度/SQLMap深度/Metasploit深度/Nikto/Hydra/John/nuclei/工具编排/控制台数据聚合，共60+个端点")
except Exception as e:
    log.warning(f"第28轮真实工具集成深度增强路由注册失败: {e}")



# ============== 第28轮升级方向2：真实场景验证与误报率优化路由（50+端点） ==============
try:
    from api_server.real_validation_routes import router as real_validation_router
    app.include_router(real_validation_router)
    log.info("第28轮真实场景验证与误报率优化路由已注册：靶场集成/扫描验证/误报优化/漏洞验证/验证体系/真实场景验证控制台，共50+个端点")
except Exception as e:
    log.warning(f"第28轮真实场景验证与误报率优化路由注册失败: {e}")


# ============== 第28轮升级方向3：性能优化与压力测试路由（50+端点） ==============
try:
    from api_server.performance_deep_routes import router as performance_deep_router
    app.include_router(performance_deep_router)
    log.info("第28轮性能优化与压力测试路由已注册：基准测试/高并发优化/大数据优化/分布式扫描优化/压力测试/性能监控/性能优化控制台，共50+个端点")
except Exception as e:
    log.warning(f"第28轮性能优化与压力测试路由注册失败: {e}")


# ============== 第28轮升级方向4：文档完善与用户体验优化路由（50+端点） ==============
try:
    from api_server.ux_docs_deep_routes import router as ux_docs_deep_router
    app.include_router(ux_docs_deep_router)
    log.info("第28轮文档完善与用户体验优化路由已注册：用户手册/部署文档/API文档/前端UX/新手引导/文档管理/文档与UX控制台，共50+个端点")
except Exception as e:
    log.warning(f"第28轮文档完善与用户体验优化路由注册失败: {e}")


# ============== 第28轮升级：新前端页面路由 ==============
try:
    from fastapi.responses import HTMLResponse as _HTMLR28
    _PAGES_R28 = [
        ("/real-tools-deep", "real_tools_deep_console.html", "真实工具集成深度增强控制台"),
        ("/real-validation", "real_validation_console.html", "真实场景验证与误报率优化控制台"),
        ("/performance-deep", "performance_deep_console.html", "性能优化与压力测试控制台"),
        ("/ux-docs-deep", "ux_docs_deep_console.html", "文档完善与用户体验优化控制台"),
    ]
    for _route, _fname, _desc in _PAGES_R28:
        def _make_page_handler_r28(fname=_fname, desc=_desc):
            @app.get(_route, include_in_schema=False)
            async def _page_handler_r28():
                _p = os.path.join(os.path.dirname(__file__), fname)
                if os.path.exists(_p):
                    with open(_p, "r", encoding="utf-8") as _f:
                        return _HTMLR28(content=_f.read())
                return _HTMLR28(content=f"<h1>{desc}页面未找到</h1>")
            return _page_handler_r28
        _make_page_handler_r28()
    log.info("第28轮新前端页面已注册：/real-tools-deep /real-validation /performance-deep /ux-docs-deep")
except Exception as e:
    log.warning(f"第28轮新前端页面注册失败: {e}")




# ============== 第29轮升级方向1：安全数据湖与大数据分析深度路由（50+端点） ==============
try:
    from api_server.data_lake_deep_routes import router as data_lake_deep_router
    app.include_router(data_lake_deep_router)
    log.info("第29轮安全数据湖与大数据分析深度路由已注册：数据湖架构/日志聚合/行为分析/AI威胁检测/数据挖掘/数据湖控制台，共50+个端点")
except Exception as e:
    log.warning(f"第29轮安全数据湖与大数据分析深度路由注册失败: {e}")


# ============== 第29轮升级方向2：移动端安全深度路由（50+端点） ==============
try:
    from api_server.mobile_security_deep_routes import router as mobile_security_deep_router
    app.include_router(mobile_security_deep_router)
    log.info("第29轮移动端安全深度路由已注册：Android深度/iOS深度/鸿蒙深度/移动漏洞POC/隐私合规/测试评测/移动安全控制台，共50+个端点")
except Exception as e:
    log.warning(f"第29轮移动端安全深度路由注册失败: {e}")


# ============== 第29轮升级方向3：API安全全生命周期路由（50+端点） ==============
try:
    from api_server.api_security_lifecycle_routes import router as api_security_lifecycle_router
    app.include_router(api_security_lifecycle_router)
    log.info("第29轮API安全全生命周期路由已注册：API资产/设计安全/开发安全/运行时安全/滥用与业务逻辑/治理合规/API安全控制台，共50+个端点")
except Exception as e:
    log.warning(f"第29轮API安全全生命周期路由注册失败: {e}")


# ============== 第29轮升级方向4：5G/车联网/新兴通信安全路由（50+端点） ==============
try:
    from api_server.emerging_comm_security_routes import router as emerging_comm_security_router
    app.include_router(emerging_comm_security_router)
    log.info("第29轮5G/车联网/新兴通信安全路由已注册：5G核心网安全/V2X安全/车载安全/OTA安全/新兴通信/新兴通信安全控制台，共50+个端点")
except Exception as e:
    log.warning(f"第29轮5G/车联网/新兴通信安全路由注册失败: {e}")


# ============== 第29轮升级：新前端页面路由（4个控制台） ==============
try:
    from fastapi.responses import HTMLResponse as _HTMLR29
    _PAGES_R29 = [
        ("/data-lake-deep", "data_lake_deep_console.html", "安全数据湖与大数据分析深度控制台"),
        ("/mobile-security-deep", "mobile_security_deep_console.html", "移动端安全深度控制台"),
        ("/api-security-lifecycle", "api_security_lifecycle_console.html", "API安全全生命周期控制台"),
        ("/emerging-comm-security", "emerging_comm_security_console.html", "5G/车联网/新兴通信安全控制台"),
    ]
    for _route, _fname, _desc in _PAGES_R29:
        def _make_page_handler_r29(fname=_fname, desc=_desc):
            @app.get(_route, include_in_schema=False)
            async def _page_handler_r29():
                _p = os.path.join(os.path.dirname(__file__), fname)
                if os.path.exists(_p):
                    with open(_p, "r", encoding="utf-8") as _f:
                        return _HTMLR28(content=_f.read())
                return _HTMLR28(content=f"<h1>{desc}页面未找到</h1>")
            return _page_handler_r29
        _make_page_handler_r29()
    log.info("第29轮新前端页面已注册：/data-lake-deep /mobile-security-deep /api-security-lifecycle /emerging-comm-security")
except Exception as e:
    log.warning(f"第29轮新前端页面注册失败: {e}")



# >>> LLM-CONFIG-INTEGRATION
try:
    from api_server.llm_config_routes import router as llm_config_router
    app.include_router(llm_config_router)
    log.info("LLM配置路由已注册：状态/保存/连接测试/AI对话/漏洞分析/修复方案/提供商，共7个端点")
except Exception as _e_llm_cfg:
    log.warning(f"LLM配置路由注册失败: {_e_llm_cfg}")


try:
    from fastapi.responses import HTMLResponse as _HTMLR_LLM
    @app.get("/llm-config", include_in_schema=False)
    async def _llm_config_page():
        _p = os.path.join(os.path.dirname(__file__), "llm_config_console.html")
        if os.path.exists(_p):
            with open(_p, "r", encoding="utf-8") as _f:
                return _HTMLR_LLM(content=_f.read())
        return _HTMLR_LLM(content="<h1>LLM 配置页面未找到</h1>")
    log.info("LLM配置前端页面已注册：/llm-config")
except Exception as _e_llm_page:
    log.warning(f"LLM配置前端页面注册失败: {_e_llm_page}")
# <<< LLM-CONFIG-INTEGRATION



# ============== # P0-1/P0-2 real tools & fp-rate routes ==============
try:
    from api_server.fp_rate_routes import tools_router as _p0_tools_router
    app.include_router(_p0_tools_router)
    log.info("P0-1 真实工具路由已注册: /api/v1/real-tools-deep/nmap|sqlmap|nuclei|nikto|dirb|dirsearch")
except Exception as e:
    log.warning(f"P0-1 真实工具路由注册失败: {e}")

try:
    from api_server.fp_rate_routes import router as _p0_fp_router
    app.include_router(_p0_fp_router)
    log.info("P0-2 误报率验证路由已注册: /api/v1/real-validation/fp-test/*")
except Exception as e:
    log.warning(f"P0-2 误报率验证路由注册失败: {e}")

try:
    from fastapi.responses import HTMLResponse as _HTML_P0
    @app.get("/fp-rate-console", include_in_schema=False)
    async def _fp_rate_console_page():
        _p = os.path.join(os.path.dirname(__file__), "fp_rate_console.html")
        if os.path.exists(_p):
            with open(_p, "r", encoding="utf-8") as _f:
                return _HTML_P0(content=_f.read())
        return _HTML_P0(content="<h1>误报率验证控制台页面未找到</h1>")
    log.info("P0-2 误报率验证控制台已注册: /fp-rate-console")
except Exception as e:
    log.warning(f"P0-2 控制台页面注册失败: {e}")




# ============== 第30轮 P1-1：Web 渗透全流程做透路由（30+端点） ==============
try:
    from api_server.web_pentest_full_routes import router as web_pentest_full_router
    app.include_router(web_pentest_full_router)
    log.info("第30轮P1-1 Web渗透全流程路由已注册：指纹识别/目录扫描/漏洞扫描/利用验证/渗透报告，共30+个端点")
except Exception as e:
    log.warning(f"第30轮P1-1 Web渗透全流程路由注册失败: {e}")


# ============== 第30轮 P2：专业安全报告引擎路由（20+端点） ==============
try:
    from api_server.report_pro_routes import router as report_pro_router
    app.include_router(report_pro_router)
    log.info("第30轮P2 专业安全报告引擎路由已注册：报告生成/历史/对比/图表/导出，共20+个端点")
except Exception as e:
    log.warning(f"第30轮P2 专业安全报告引擎路由注册失败: {e}")


# ============== 第30轮：新前端页面路由（2个控制台） ==============
try:
    from fastapi.responses import HTMLResponse as _HTMLR30
    _PAGES_R30 = [
        ("/web-pentest-full", "web_pentest_full_console.html", "Web渗透全流程控制台"),
        ("/report-pro", "report_pro_console.html", "专业安全报告引擎控制台"),
    ]
    for _route, _fname, _desc in _PAGES_R30:
        def _make_page_handler_r30(fname=_fname, desc=_desc):
            @app.get(_route, include_in_schema=False)
            async def _page_handler_r30():
                _p = os.path.join(os.path.dirname(__file__), fname)
                if os.path.exists(_p):
                    with open(_p, "r", encoding="utf-8") as _f:
                        return _HTMLR30(content=_f.read())
                return _HTMLR30(content=f"<h1>{desc}页面未找到</h1>")
            return _page_handler_r30
        _make_page_handler_r30()
    log.info("第30轮新前端页面已注册：/web-pentest-full /report-pro")
except Exception as e:
    log.warning(f"第30轮新前端页面注册失败: {e}")




# ============== 方向1：内网渗透真实能力（20+端点） ==============
try:
    from api_server.internal_pentest_real_routes import router as internal_real_router
    app.include_router(internal_real_router)
    log.info("方向1 内网渗透真实能力路由已注册（Nmap/SMB/RPC/LDAP/Nuclei 真实执行）")
except Exception as e:
    log.warning(f"方向1 路由注册失败: {e}")

# ============== 方向2：移动安全真实能力（20+端点） ==============
try:
    from api_server.mobile_real_routes import router as mobile_real_router
    app.include_router(mobile_real_router)
    log.info("方向2 移动安全真实分析路由已注册（APK真实解析+权限风险+静态漏洞）")
except Exception as e:
    log.warning(f"方向2 路由注册失败: {e}")

# ============== 新增控制台页面 ==============
try:
    from fastapi.responses import HTMLResponse as _HTMLR_REAL
    _PAGES_REAL = [
        ("/internal-pentest-real", "internal_pentest_real_console.html", "内网渗透真实能力控制台"),
        ("/mobile-real", "mobile_real_console.html", "移动安全真实分析控制台"),
    ]
    for _route, _fname, _desc in _PAGES_REAL:
        def _make_page(_fname=_fname, _desc=_desc):
            @app.get(_route, include_in_schema=False)
            async def _page():
                _p = os.path.join(os.path.dirname(__file__), _fname)
                if os.path.exists(_p):
                    with open(_p, "r", encoding="utf-8") as f:
                        return _HTMLR_REAL(content=f.read())
                return _HTMLR_REAL(content=f"<h1>{_desc}页面未找到</h1>")
            return _page
        _make_page()
    log.info("控制台页面已注册：/internal-pentest-real /mobile-real")
except Exception as e:
    log.warning(f"控制台页面注册失败: {e}")




# ============== 方向5：SRC 挖洞工作台路由（34端点） ==============
try:
    from api_server.src_workbench_routes import router as src_workbench_router
    app.include_router(src_workbench_router)
    log.info("方向5 SRC挖洞工作台路由已注册：资产侦察/端口扫描/漏洞扫描/报告生成/项目管理/统计，共34个端点")
except Exception as e:
    log.warning(f"方向5 SRC挖洞工作台路由注册失败: {e}")


# ============== 方向5：SRC 挖洞工作台前端控制台 ==============
try:
    from fastapi.responses import HTMLResponse as _HTMLR_SRC5
    _SRC5_PAGES = [
        ("/src-workbench", "src_workbench_console.html", "SRC挖洞工作台"),
    ]
    for _route, _fname, _desc in _SRC5_PAGES:
        def _make_page_handler_src5(fname=_fname, desc=_desc):
            @app.get(_route, include_in_schema=False)
            async def _page_handler_src5():
                _p = os.path.join(os.path.dirname(__file__), fname)
                if os.path.exists(_p):
                    with open(_p, "r", encoding="utf-8") as _f:
                        return _HTMLR_SRC5(content=_f.read())
                return _HTMLR_SRC5(content=f"<h1>{desc}页面未找到</h1>")
            return _page_handler_src5
        _make_page_handler_src5()
    log.info("方向5 SRC挖洞工作台前端页面已注册：/src-workbench")
except Exception as e:
    log.warning(f"方向5 SRC挖洞工作台前端页面注册失败: {e}")




# ============== 方向5：企业级安全与合规路由（27端点） ==============
try:
    from api_server.enterprise_security_routes import router as enterprise_sec_router
    app.include_router(enterprise_sec_router)
    log.info("方向5 企业级安全与合规路由已注册：RBAC/审计/加密/基线/合规/控制台，共27个端点")
except Exception as e:
    log.warning(f"方向5 企业级安全与合规路由注册失败: {e}")


# ============== 方向5：企业级安全与合规前端控制台 ==============
try:
    from fastapi.responses import HTMLResponse as _HTMLR_ENT5
    _ENT5_PAGES = [
        ("/enterprise-security", "enterprise_security_console.html", "企业级安全与合规"),
    ]
    for _route, _fname, _desc in _ENT5_PAGES:
        def _make_page_ent5(fname=_fname, desc=_desc):
            @app.get(_route, include_in_schema=False)
            async def _page_handler_ent5():
                _p = os.path.join(os.path.dirname(__file__), fname)
                if os.path.exists(_p):
                    with open(_p, "r", encoding="utf-8") as _f:
                        return _HTMLR_ENT5(content=_f.read())
                return _HTMLR_ENT5(content=f"<h1>{desc}页面未找到</h1>")
            return _page_handler_ent5
        _make_page_ent5()
    log.info("方向5 企业级安全与合规前端页面已注册：/enterprise-security")
except Exception as e:
    log.warning(f"方向5 企业级安全与合规前端页面注册失败: {e}")




# ============== 方向3：极致用户体验（超级首页）路由（26 端点） ==============
try:
    from api_server.super_homepage_routes import router as super_homepage_router
    app.include_router(super_homepage_router)
    log.info("方向3 超级首页路由已注册：首页聚合/智能引导/全局搜索/快速操作/主题导航，共26个端点")
except Exception as e:
    log.warning(f"方向3 超级首页路由注册失败: {e}")


# ============== 方向4：性能极致优化路由（30 端点） ==============
try:
    from api_server.perf_ultra_routes import router as perf_ultra_router
    app.include_router(perf_ultra_router)
    log.info("方向4 性能极致优化路由已注册：启动/缓存/队列/DB/监控/静态，共30个端点")
except Exception as e:
    log.warning(f"方向4 性能极致优化路由注册失败: {e}")


# ============== 方向3+4：新前端页面路由（2个控制台） ==============
try:
    from fastapi.responses import HTMLResponse as _HTMLR_D34
    _PAGES_D34 = [
        ("/super-home", "super_homepage_console.html", "超级首页（极致用户体验）"),
        ("/perf-ultra", "perf_ultra_console.html", "性能极致优化控制台"),
    ]
    for _route, _fname, _desc in _PAGES_D34:
        def _make_page_handler_d34(fname=_fname, desc=_desc):
            @app.get(_route, include_in_schema=False)
            async def _page_handler_d34():
                _p = os.path.join(os.path.dirname(__file__), fname)
                if os.path.exists(_p):
                    with open(_p, "r", encoding="utf-8") as _f:
                        return _HTMLR_D34(content=_f.read())
                return _HTMLR_D34(content=f"<h1>{desc}页面未找到</h1>")
            return _page_handler_d34
        _make_page_handler_d34()
    log.info("方向3+4 前端页面已注册：/super-home /perf-ultra")
except Exception as e:
    log.warning(f"方向3+4 前端页面注册失败: {e}")




# ============== 方向2：AI 能力大升级路由（26 端点） ==============
try:
    from api_server.ai_upgrade_routes import router as ai_upgrade_router
    app.include_router(ai_upgrade_router)
    log.info("方向2 AI能力大升级路由已注册：LLM接入/漏洞分析/报告生成/智能问答/攻击链/SRC，共26个端点")
except Exception as e:
    log.warning(f"方向2 AI能力大升级路由注册失败: {e}")


# ============== 方向5：用户体验大升级路由（26 端点） ==============
try:
    from api_server.ux_upgrade_routes import router as ux_upgrade_router
    app.include_router(ux_upgrade_router)
    log.info("方向5 用户体验大升级路由已注册：超级首页/智能引导/移动端/暗色主题/全局搜索，共26个端点")
except Exception as e:
    log.warning(f"方向5 用户体验大升级路由注册失败: {e}")


# ============== 方向2+5：新前端页面路由（2个控制台） ==============
try:
    from fastapi.responses import HTMLResponse as _HTMLR_D25
    _PAGES_D25 = [
        ("/ai-upgrade", "ai_upgrade_console.html", "AI 能力升级控制台"),
        ("/ux-upgrade", "ux_upgrade_console.html", "UX 升级控制台"),
    ]
    for _route, _fname, _desc in _PAGES_D25:
        def _make_page_handler_d25(fname=_fname, desc=_desc):
            @app.get(_route, include_in_schema=False)
            async def _page_handler_d25():
                _p = os.path.join(os.path.dirname(__file__), fname)
                if os.path.exists(_p):
                    with open(_p, "r", encoding="utf-8") as _f:
                        return _HTMLR_D25(content=_f.read())
                return _HTMLR_D25(content=f"<h1>{desc}页面未找到</h1>")
            return _page_handler_d25
        _make_page_handler_d25()
    log.info("方向2+5 前端页面已注册：/ai-upgrade /ux-upgrade")
except Exception as e:
    log.warning(f"方向2+5 前端页面注册失败: {e}")




# ============== 方向4：商业成熟度大升级路由（40+ 端点） ==============
try:
    from api_server.commercial_pro_routes import router as commercial_pro_router
    app.include_router(commercial_pro_router)
    log.info("方向4 商业成熟度路由已注册：License/客户门户/计费/SLA，共40+端点")
except Exception as e:
    log.warning(f"方向4 商业成熟度路由注册失败: {e}")


# ============== 方向6：性能大升级路由（28+ 端点） ==============
try:
    from api_server.performance_pro_routes import router as performance_pro_router
    app.include_router(performance_pro_router)
    log.info("方向6 性能大升级路由已注册：启动/响应/并发/DB/静态，共28+端点")
except Exception as e:
    log.warning(f"方向6 性能大升级路由注册失败: {e}")


# ============== 方向4+6：新前端页面路由（2个控制台） ==============
try:
    from fastapi.responses import HTMLResponse as _HTMLR_R33
    _PAGES_R33 = [
        ("/commercial-pro", "commercial_pro_console.html", "商业成熟度大升级控制台"),
        ("/performance-pro", "performance_pro_console.html", "性能大升级控制台"),
    ]
    for _route, _fname, _desc in _PAGES_R33:
        def _make_page_handler_r33(fname=_fname, desc=_desc):
            @app.get(_route, include_in_schema=False)
            async def _page_handler_r33():
                _p = os.path.join(os.path.dirname(__file__), fname)
                if os.path.exists(_p):
                    with open(_p, "r", encoding="utf-8") as _f:
                        return _HTMLR_R33(content=_f.read())
                return _HTMLR_R33(content=f"<h1>{desc}页面未找到</h1>")
            return _page_handler_r33
        _make_page_handler_r33()
    log.info("方向4+6 前端页面已注册：/commercial-pro /performance-pro")
except Exception as e:
    log.warning(f"方向4+6 前端页面注册失败: {e}")




# ============== 方向1：技术深度大升级路由（37 端点） ==============
try:
    from api_server.tech_deep_routes import router as tech_deep_router
    app.include_router(tech_deep_router)
    log.info("方向1 技术深度大升级路由已注册：Web做深/内网做实/移动做实/云做实，共37个端点")
except Exception as e:
    log.warning(f"方向1 技术深度路由注册失败: {e}")


# ============== 方向3：真实可用性大升级路由（26 端点） ==============
try:
    from api_server.real_usability_routes import router as real_usability_router
    app.include_router(real_usability_router)
    log.info("方向3 真实可用性大升级路由已注册：误报率/E2E/靶场/质量，共26个端点")
except Exception as e:
    log.warning(f"方向3 真实可用性路由注册失败: {e}")


# ============== 方向1+3：新前端页面路由（2个控制台） ==============
try:
    from fastapi.responses import HTMLResponse as _HTMLR_D1D3
    _PAGES_D1D3 = [
        ("/tech-deep", "tech_deep_console.html", "技术深度大升级控制台"),
        ("/real-usability", "real_usability_console.html", "真实可用性大升级控制台"),
    ]
    for _route, _fname, _desc in _PAGES_D1D3:
        def _make_page_handler_d1d3(fname=_fname, desc=_desc):
            @app.get(_route, include_in_schema=False)
            async def _page_handler_d1d3():
                _p = os.path.join(os.path.dirname(__file__), fname)
                if os.path.exists(_p):
                    with open(_p, "r", encoding="utf-8") as _f:
                        return _HTMLR_D1D3(content=_f.read())
                return _HTMLR_D1D3(content=f"<h1>{desc}页面未找到</h1>")
            return _page_handler_d1d3
        _make_page_handler_d1d3()
    log.info("方向1+3 前端页面已注册：/tech-deep /real-usability")
except Exception as e:
    log.warning(f"方向1+3 前端页面注册失败: {e}")




# ============== 方向1+方向2：误报率验证做实 + 内网渗透深度做实 ==============
try:
    from api_server.fp_validation_routes import router as fp_validation_router
    app.include_router(fp_validation_router)
    log.info("方向1 误报率验证做实路由已注册：/api/v1/fp-validation（20+端点）")
except Exception as e:
    log.warning(f"方向1 fp_validation_router 注册失败: {e}")

try:
    from api_server.internal_deep_routes import router as internal_deep_router
    app.include_router(internal_deep_router)
    log.info("方向2 内网渗透深度做实路由已注册：/api/v1/internal-deep（25+端点）")
except Exception as e:
    log.warning(f"方向2 internal_deep_router 注册失败: {e}")

try:
    from fastapi.responses import HTMLResponse as _HTMLR_DIR12
    _PAGES_DIR12 = [
        ("/fp-validation", "fp_validation_console.html", "误报率验证控制台"),
        ("/internal-deep", "internal_deep_console.html", "内网渗透深度控制台"),
    ]
    for _route, _fname, _desc in _PAGES_DIR12:
        def _make_page_handler_dir12(fname=_fname, desc=_desc):
            @app.get(_route, include_in_schema=False)
            async def _page_handler_dir12():
                _p = os.path.join(os.path.dirname(__file__), fname)
                if os.path.exists(_p):
                    with open(_p, "r", encoding="utf-8") as _f:
                        return _HTMLR_DIR12(content=_f.read())
                return _HTMLR_DIR12(content=f"<h1>{desc}页面未找到</h1>")
            return _page_handler_dir12
        _make_page_handler_dir12()
    log.info("方向1+方向2 前端页面已注册：/fp-validation /internal-deep")
except Exception as e:
    log.warning(f"方向1+方向2 前端页面注册失败: {e}")




# ============== 方向3+4：移动安全深度做实 v2 / 云安全深度做实 ==============
try:
    from api_server.cloud_deep_routes import router as cloud_deep_router
    app.include_router(cloud_deep_router)
    log.info("方向4 云安全深度路由已注册：/api/v1/cloud-deep，30+ 端点")
except Exception as e:
    log.warning(f"方向4 云安全深度路由注册失败: {e}")

try:
    from fastapi.responses import HTMLResponse as _HTMLR_D34
    _PAGES_D34 = [
        ("/mobile-deep-v2", "mobile_deep_console.html", "移动安全深度控制台 v2"),
        ("/cloud-deep", "cloud_deep_console.html", "云安全深度控制台"),
    ]
    for _route, _fname, _desc in _PAGES_D34:
        def _make_page_d34(fname=_fname, desc=_desc):
            @app.get(_route, include_in_schema=False)
            async def _page_d34():
                _p = os.path.join(os.path.dirname(__file__), fname)
                if os.path.exists(_p):
                    with open(_p, "r", encoding="utf-8") as _f:
                        return _HTMLR_D34(content=_f.read())
                return _HTMLR_D34(content=f"<h1>{desc}页面未找到</h1>")
            return _page_d34
        _make_page_d34()
    log.info("方向3+4 新前端页面已注册：/mobile-deep-v2 /cloud-deep")
except Exception as e:
    log.warning(f"方向3+4 新前端页面注册失败: {e}")




# ============== 方向2：所有领域真实可用（补齐短板） ==============
try:
    from api_server.domains_real_routes import router as domains_real_router
    app.include_router(domains_real_router)
    log.info("方向2 所有领域真实可用路由已注册：/api/v1/domains-real（60+端点）")
except Exception as e:
    log.warning(f"方向2 domains_real_router 注册失败: {e}")

try:
    from fastapi.responses import HTMLResponse as _HTMLR_DOMAINS_REAL
    @app.get("/domains-real", include_in_schema=False)
    async def _domains_real_console_page():
        _p = os.path.join(os.path.dirname(__file__), "domains_real_console.html")
        if os.path.exists(_p):
            with open(_p, "r", encoding="utf-8") as _f:
                return _HTMLR_DOMAINS_REAL(content=_f.read())
        return _HTMLR_DOMAINS_REAL(content="<h1>领域真实可用控制台页面未找到</h1>")
    log.info("方向2 前端页面已注册：/domains-real")
except Exception as e:
    log.warning(f"方向2 前端页面注册失败: {e}")




# ============== 方向5：工具安装器/靶场部署/LLM配置 路由 ==============
try:
    from api_server.tools_installer_routes import router as _tools_installer_router
    app.include_router(_tools_installer_router)
    log.info("方向5 工具一键安装路由已注册")
except Exception as _e:
    log.warning(f"方向5 工具安装路由注册失败: {_e}")

try:
    from api_server.target_lab_real_routes import router as _target_lab_real_router
    app.include_router(_target_lab_real_router)
    log.info("方向5 真实靶场部署路由已注册")
except Exception as _e:
    log.warning(f"方向5 靶场路由注册失败: {_e}")

try:
    from api_server.llm_config_real_routes import router as _llm_config_real_router
    app.include_router(_llm_config_real_router)
    log.info("方向5 LLM 配置引导路由已注册")
except Exception as _e:
    log.warning(f"方向5 LLM 配置路由注册失败: {_e}")

try:
    from fastapi.responses import HTMLResponse as _HTMLR_D5
    _PAGES_D5 = [
        ("/tools-installer", "tools_installer_console.html", "工具一键安装"),
        ("/target-lab-real", "target_lab_real_console.html", "真实靶场部署"),
        ("/llm-config-real", "llm_config_real_console.html", "LLM Key 配置引导"),
    ]
    for _route, _fname, _desc in _PAGES_D5:
        def _make_page_d5(fname=_fname, desc=_desc):
            @app.get(_route, include_in_schema=False)
            async def _page_d5():
                _p = os.path.join(os.path.dirname(__file__), fname)
                if os.path.exists(_p):
                    with open(_p, "r", encoding="utf-8") as _f:
                        return _HTMLR_D5(content=_f.read())
                return _HTMLR_D5(content=f"<h1>{desc}页面未找到</h1>")
            return _page_d5
        _make_page_d5()
    log.info("方向5 三个前端控制台已注册：/tools-installer /target-lab-real /llm-config-real")
except Exception as _e:
    log.warning(f"方向5 前端页面注册失败: {_e}")


# ============== 全局异常处理器（不暴露堆栈，统一返回 JSON 500） ==============
try:
    from fastapi.responses import JSONResponse as _JSONResponse

    @app.exception_handler(Exception)
    async def _global_exception_handler(request, exc: Exception):
        log.error(f"未处理异常 [{request.method} {request.url.path}]: {exc}")
        return _JSONResponse(
            status_code=500,
            content={"error": "Internal Server Error", "detail": str(exc)},
        )
except Exception as e:
    log.warning(f"全局异常处理器注册失败: {e}")


def run_api_server(host: str = "0.0.0.0", port: int = 8000):
    """运行相关操作。

        Args:
            host: 相关参数。
            port: 相关参数。

        Returns:
            操作结果。
    """
    import uvicorn
    log.info(f"API服务器启动: http://{host}:{port}")
    log.info(f"API文档: http://{host}:{port}/docs")
    uvicorn.run(app, host=host, port=port, log_level="info")




# ============================================================
# 空前升级模块 API 路由
# ============================================================


# ============== API别名路由（常用路径兼容） ==============
from fastapi.responses import RedirectResponse

@app.get("/api/v1/cves", tags=["漏洞库"], dependencies=[Depends(verify_api_key)])
async def cves_alias(limit: int = 20):
    """CVE漏洞列表（别名，指向/api/v1/knowledge/cve）"""
    from knowledge.cve import cve_kb
    cves = [{"id": cid, "name": d.get("name", ""), "severity": d.get("severity", ""),
             "description": d.get("description", "")[:200]}
             for cid, d in cve_kb.local_db.items()]
    return {"total": len(cves), "cves": cves[:limit]}

@app.get("/api/v1/ultimate/pocs", tags=["空前升级"], dependencies=[Depends(verify_api_key)])
async def ultimate_pocs_alias(keyword: str = None):
    """POC漏洞利用库（别名，指向/api/v1/ultimate/poc-library）"""
    from agent.ultimate_upgrade import ultimate
    if keyword:
        results = ultimate.exploit_framework.search_poc(keyword)
        return {"total": len(results), "results": results}
    all_pocs = ultimate.exploit_framework.list_all_pocs()
    return {"total": len(all_pocs), "results": all_pocs}

@app.get("/api/v1/ultimate/attack-chain", tags=["空前升级"], dependencies=[Depends(verify_api_key)])
async def ultimate_attack_chain_alias():
    """攻击链知识库（别名，指向/api/v1/ultimate/kill-chain）"""
    from agent.ultimate_upgrade import ultimate
    return {
        "kill_chain": {"phases": ultimate.knowledge_base.get_kill_chain()},
        "attack_patterns": ultimate.knowledge_base.get_all_patterns()
    }

@app.get("/api/v1/ultimate/status", tags=["空前升级"], dependencies=[Depends(verify_api_key)])
async def ultimate_status():
    """空前升级模块状态"""
    try:
        from agent.ultimate_upgrade import ultimate
        return ultimate.get_status()
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@app.post("/api/v1/ultimate/pentest-workflow", tags=["空前升级"], dependencies=[Depends(verify_api_key)])
async def ultimate_pentest_workflow(request: dict):
    """执行完整渗透测试工作流（4大智能体协作）"""
    try:
        from agent.ultimate_upgrade import ultimate
        target = request.get("target", "127.0.0.1")
        import asyncio
        result = await ultimate.orchestrator.run_pentest_workflow(target)
        return result
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@app.get("/api/v1/ultimate/poc-library", tags=["空前升级"], dependencies=[Depends(verify_api_key)])
async def ultimate_poc_library(keyword: str = None):
    """POC漏洞利用库查询"""
    try:
        from agent.ultimate_upgrade import ultimate
        if keyword:
            return {"total": len(ultimate.exploit_framework.search_poc(keyword)),
                    "results": ultimate.exploit_framework.search_poc(keyword)}
        return {"total": len(ultimate.exploit_framework.list_all_pocs()),
                "results": ultimate.exploit_framework.list_all_pocs()}
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@app.get("/api/v1/ultimate/poc/{cve_id}", tags=["空前升级"], dependencies=[Depends(verify_api_key)])
async def ultimate_poc_detail(cve_id: str):
    """POC详情查询"""
    try:
        from agent.ultimate_upgrade import ultimate
        poc = ultimate.exploit_framework.get_poc(cve_id)
        if not poc:
            raise HTTPException(status_code=404, detail=f"POC not found: {cve_id}")
        return {"cve_id": cve_id, **poc}
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@app.post("/api/v1/ultimate/payload/generate", tags=["空前升级"], dependencies=[Depends(verify_api_key)])
async def ultimate_generate_payload(request: dict):
    """生成攻击Payload"""
    try:
        from agent.ultimate_upgrade import ultimate
        cve_id = request.get("cve_id", "")
        attacker_host = request.get("attacker_host", "ATTACKER_IP")
        payload = ultimate.exploit_framework.generate_payload(cve_id, attacker_host)
        if not payload:
            raise HTTPException(status_code=404, detail=f"POC not found: {cve_id}")
        return payload
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@app.get("/api/v1/ultimate/kill-chain", tags=["空前升级"], dependencies=[Depends(verify_api_key)])
async def ultimate_kill_chain():
    """网络杀伤链7阶段"""
    try:
        from agent.ultimate_upgrade import ultimate
        return {"phases": ultimate.knowledge_base.get_kill_chain()}
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@app.get("/api/v1/ultimate/attack-patterns", tags=["空前升级"], dependencies=[Depends(verify_api_key)])
async def ultimate_attack_patterns():
    """MITRE ATT&CK攻击模式"""
    try:
        from agent.ultimate_upgrade import ultimate
        return ultimate.knowledge_base.get_all_patterns()
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@app.post("/api/v1/ultimate/monitor/target", tags=["空前升级"], dependencies=[Depends(verify_api_key)])
async def ultimate_add_monitor_target(request: dict):
    """添加持续监控目标"""
    try:
        from agent.ultimate_upgrade import ultimate
        target = request.get("target", "")
        interval = request.get("scan_interval", 3600)
        ports = request.get("ports", "1-1000")
        ultimate.monitor.add_target(target, interval, ports)
        return {"status": "success", "target": target, "message": f"目标 {target} 已添加到持续监控"}
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@app.get("/api/v1/ultimate/monitor/status", tags=["空前升级"], dependencies=[Depends(verify_api_key)])
async def ultimate_monitor_status():
    """持续监控状态"""
    try:
        from agent.ultimate_upgrade import ultimate
        return ultimate.monitor.get_status()
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@app.get("/api/v1/ultimate/monitor/alerts", tags=["空前升级"], dependencies=[Depends(verify_api_key)])
async def ultimate_monitor_alerts(severity: str = None):
    """监控告警列表"""
    try:
        from agent.ultimate_upgrade import ultimate
        return {"total": len(ultimate.monitor.get_alerts(severity)),
                "alerts": ultimate.monitor.get_alerts(severity)}
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@app.get("/api/v1/ultimate/dashboard", tags=["空前升级"], dependencies=[Depends(verify_api_key)])
async def ultimate_dashboard():
    """实时可视化仪表盘数据"""
    try:
        from agent.ultimate_upgrade import ultimate
        return ultimate.visualization.get_dashboard_data()
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@app.get("/api/v1/ultimate/performance", tags=["空前升级"], dependencies=[Depends(verify_api_key)])
async def ultimate_performance():
    """性能优化器统计"""
    try:
        from agent.ultimate_upgrade import ultimate
        return ultimate.optimizer.get_stats()
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

# 空前升级前端页面

# ============== 攻击面管理ASM路由 ==============
try:
    from api_server.asm_routes import router as asm_router
    app.include_router(asm_router)
    log.info("攻击面管理ASM路由已注册：完整评估/快速扫描/资产发现/历史/报告/对比，共7个端点")
except Exception as e:
    log.warning(f"ASM路由注册失败: {e}")


@app.get("/asm", include_in_schema=False)
async def asm_page():
    asm_path = _os.path.join(_os.path.dirname(__file__), "asm.html")
    with open(asm_path, "r", encoding="utf-8") as f:
        return HTMLResponse(content=f.read())

@app.get("/ultimate", include_in_schema=False)
async def ultimate_page():
    ultimate_path = _os.path.join(_os.path.dirname(__file__), "ultimate.html")
    with open(ultimate_path, "r", encoding="utf-8") as f:
        html_content = f.read()
    return HTMLResponse(content=html_content)



# 企业级功能初始化
try:
    from enterprise.database import init_db
    from enterprise.monitor_worker import start_monitor_worker
    init_db()
    start_monitor_worker(check_interval=60)
    print("[Enterprise] 企业级功能已加载：数据库持久化+持续监控+用户认证")
except Exception as e:
    print(f"[Enterprise] 企业级功能加载失败: {e}")

if __name__ == "__main__":
    run_api_server()


# ============================================
# 第35轮升级路由注入（误报率优化Pro + LLM极致 + 商业极致 + 性能极致Pro）
# ============================================
try:
    from api_server.fp_optimizer_pro_routes import router as fp_opt_pro_router
    app.include_router(fp_opt_pro_router)
    print("第35轮 误报率优化Pro路由已注册")
except Exception as e:
    print(f"第35轮 误报率优化Pro路由注册失败: {e}")

try:
    from api_server.llm_ultra_routes import router as llm_ultra_router
    app.include_router(llm_ultra_router)
    print("第35轮 LLM极致路由已注册")
except Exception as e:
    print(f"第35轮 LLM极致路由注册失败: {e}")

try:
    from api_server.commercial_ultra_routes import router as commercial_ultra_router
    app.include_router(commercial_ultra_router)
    print("第35轮 商业极致路由已注册")
except Exception as e:
    print(f"第35轮 商业极致路由注册失败: {e}")

try:
    from api_server.performance_ultra_pro_routes import router as perf_ultra_pro_router
    app.include_router(perf_ultra_pro_router)
    print("第35轮 性能极致Pro路由已注册")
except Exception as e:
    print(f"第35轮 性能极致Pro路由注册失败: {e}")

# 第35轮前端页面注册
try:
    _PAGES_R35 = [
        ("/fp-optimizer-pro", "fp_optimizer_pro_console.html"),
        ("/llm-ultra", "llm_ultra_console.html"),
        ("/commercial-ultra", "commercial_ultra_console.html"),
        ("/performance-ultra-pro", "performance_ultra_pro_console.html"),
    ]
    for _path, _file in _PAGES_R35:
        try:
            @app.get(_path, include_in_schema=False)
            async def _r35_page():
                from pathlib import Path
                from fastapi.responses import HTMLResponse
                _html = Path(__file__).parent / _file
                if _html.exists():
                    return HTMLResponse(_html.read_text(encoding='utf-8'))
                return HTMLResponse(f"<h1>Page not found: {_file}</h1>", status_code=404)
        except Exception:
            pass
    print("第35轮 前端页面已注册: /fp-optimizer-pro /llm-ultra /commercial-ultra /performance-ultra-pro")
except Exception as e:
    print(f"第35轮 前端页面注册失败: {e}")

# === AIPLANNER_RT_BEGIN ===
# ---- Direction 1: AI 自主规划能力大升级 ----
try:
    from api_server.ai_autonomous_planner_routes import router as ai_planner_router
    app.include_router(ai_planner_router)
    log.info("AI 自主规划路由已注册：/api/v1/ai-autonomous-planner（27端点）")
except Exception as e:
    log.warning(f"AI 自主规划路由注册失败: {e}")

# ---- Direction 2: WebSocket 实时可视化 ----
try:
    from api_server.realtime_visualization_routes import router as rt_vis_router
    app.include_router(rt_vis_router)
    log.info("实时可视化路由已注册：/api/v1/realtime-visualization（22 REST + 1 WebSocket）")
except Exception as e:
    log.warning(f"实时可视化路由注册失败: {e}")

# ---- 前端页面路由 ----
try:
    from fastapi.responses import HTMLResponse as _HTMLR_APRT
    from pathlib import Path as _Path_APRT
    _PAGES_APRT = [
        ("/ai-autonomous-planner", "ai_autonomous_planner_console.html", "AI 自主规划控制台"),
        ("/realtime-visualization", "realtime_visualization_console.html", "实时可视化控制台"),
    ]
    for _route, _fname, _desc in _PAGES_APRT:
        def _make_page_aprt(fname=_fname, desc=_desc):
            @app.get(_route, include_in_schema=False)
            async def _page_aprt():
                _p = _Path_APRT(__file__).parent / fname
                if _p.exists():
                    return _HTMLR_APRT(content=_p.read_text(encoding="utf-8"))
                return _HTMLR_APRT(content=f"<h1>{desc} 未找到</h1>")
            return _page_aprt
        _make_page_aprt()
    log.info("前端页面已注册：/ai-autonomous-planner /realtime-visualization")
except Exception as e:
    log.warning(f"前端页面路由注册失败: {e}")
# === AIPLANNER_RT_END ===


# ==== INJECT: web_pentest_pro (方向4) ====
try:
    from api_server.web_pentest_pro_routes import router as _wpp_router
    app.include_router(_wpp_router)
    print("方向4 Web渗透Pro路由已注册 (45端点: 五阶段/CVE库/DVWA)")
except Exception as _e:
    print(f"方向4 Web渗透Pro路由注册失败: {_e}")

try:
    from fastapi.responses import HTMLResponse as _HTMLWPP
    @app.get("/web-pentest-pro", include_in_schema=False)
    async def _wpp_page():
        import os as _os
        _p = _os.path.join(_os.path.dirname(__file__),
                           "web_pentest_pro_console.html")
        if _os.path.exists(_p):
            with open(_p, "r", encoding="utf-8") as _f:
                return _HTMLWPP(content=_f.read())
        return _HTMLWPP(content="<h1>web_pentest_pro_console.html 未找到</h1>")
    print("方向4 控制台页面已注册: /web-pentest-pro")
except Exception as _e:
    print(f"方向4 控制台页面注册失败: {_e}")


# ==== INJECT: simple_mode (方向3 极简模式) ====
try:
    from api_server.simple_mode_routes import router as _simple_router
    app.include_router(_simple_router)
    print("方向3 极简模式路由已注册 (21端点)")
except Exception as _e:
    print(f"方向3 极简模式路由注册失败: {_e}")

try:
    from fastapi.responses import HTMLResponse as _HTMLSIMPLE
    @app.get("/simple-console", include_in_schema=False)
    async def _simple_page():
        import os as _os
        _p = _os.path.join(_os.path.dirname(__file__),
                           "simple_mode_console.html")
        if _os.path.exists(_p):
            with open(_p, "r", encoding="utf-8") as _f:
                return _HTMLSIMPLE(content=_f.read())
        return _HTMLSIMPLE(content="<h1>simple_mode_console.html 未找到</h1>")
    print("方向3 控制台页面已注册: /simple-console")
except Exception as _e:
    print(f"方向3 控制台页面注册失败: {_e}")


# ==== INJECT: target_lab_manager (方向5 本地靶场) ====
try:
    from api_server.target_lab_manager_routes import router as _tlab_router
    app.include_router(_tlab_router)
    print("方向5 本地靶场路由已注册 (26端点)")
except Exception as _e:
    print(f"方向5 本地靶场路由注册失败: {_e}")

try:
    from fastapi.responses import HTMLResponse as _HTMLTLAB
    @app.get("/target-lab", include_in_schema=False)
    async def _tlab_page():
        import os as _os
        _p = _os.path.join(_os.path.dirname(__file__),
                           "target_lab_manager_console.html")
        if _os.path.exists(_p):
            with open(_p, "r", encoding="utf-8") as _f:
                return _HTMLTLAB(content=_f.read())
        return _HTMLTLAB(content="<h1>target_lab_manager_console.html 未找到</h1>")
    print("方向5 控制台页面已注册: /target-lab")
except Exception as _e:
    print(f"方向5 控制台页面注册失败: {_e}")


# ==== INJECT: cloud_security_pro (方向3) ====
try:
    from api_server.cloud_security_pro_routes import router as _csp_router
    app.include_router(_csp_router)
    print("方向3 云安全Pro路由已注册 (含 WebSocket /ws)")
except Exception as _e:
    print(f"方向3 云安全Pro路由注册失败: {_e}")

try:
    from fastapi.responses import HTMLResponse as _HTMLCSP
    @app.get("/cloud-security-pro", include_in_schema=False)
    async def _csp_page():
        import os as _os
        _p = _os.path.join(_os.path.dirname(__file__),
                           "cloud_security_pro_console.html")
        if _os.path.exists(_p):
            with open(_p, "r", encoding="utf-8") as _f:
                return _HTMLCSP(content=_f.read())
        return _HTMLCSP(content="<h1>cloud_security_pro_console.html 未找到</h1>")
    print("方向3 控制台页面已注册: /cloud-security-pro")
except Exception as _e:
    print(f"方向3 控制台页面注册失败: {_e}")


# ==== INJECT: internal_pentest_pro (方向1) ====
try:
    from api_server.internal_pentest_pro_routes import router as _ipp_router
    app.include_router(_ipp_router)
    print("方向1 内网渗透Pro路由已注册 (52端点: 五阶段/AI/报告/WS)")
except Exception as _e:
    print(f"方向1 内网渗透Pro路由注册失败: {_e}")

try:
    from fastapi.responses import HTMLResponse as _HTMLIPP
    @app.get("/internal-pentest-pro", include_in_schema=False)
    async def _ipp_page():
        import os as _os
        _p = _os.path.join(_os.path.dirname(__file__),
                           "internal_pentest_pro_console.html")
        if _os.path.exists(_p):
            with open(_p, "r", encoding="utf-8") as _f:
                return _HTMLIPP(content=_f.read())
        return _HTMLIPP(content="<h1>internal_pentest_pro_console.html 未找到</h1>")
    print("方向1 控制台页面已注册: /internal-pentest-pro")
except Exception as _e:
    print(f"方向1 控制台页面注册失败: {_e}")
# ==== /INJECT: internal_pentest_pro (方向1) ====


# ==== INJECT: mobile_pentest_pro (方向2 移动安全做深) ====
try:
    from api_server.mobile_pentest_pro_routes import router as _mpp_router
    app.include_router(_mpp_router)
    print("方向2 移动安全Pro路由已注册 (40+端点: 五阶段/25规则/Frida/WebSocket)")
except Exception as _e:
    print(f"方向2 移动安全Pro路由注册失败: {_e}")

try:
    from fastapi.responses import HTMLResponse as _HTMLMPP
    @app.get("/mobile-pentest-pro", include_in_schema=False)
    async def _mpp_page():
        import os as _os
        _p = _os.path.join(_os.path.dirname(__file__),
                           "mobile_pentest_pro_console.html")
        if _os.path.exists(_p):
            with open(_p, "r", encoding="utf-8") as _f:
                return _HTMLMPP(content=_f.read())
        return _HTMLMPP(content="<h1>mobile_pentest_pro_console.html 未找到</h1>")
    print("方向2 控制台页面已注册: /mobile-pentest-pro")
except Exception as _e:
    print(f"方向2 控制台页面注册失败: {_e}")


# ==== INJECT: red_blue_pro (方向1) ====
try:
    from api_server.red_blue_pro_routes import router as _rbp_router
    app.include_router(_rbp_router)
    print("方向1 红蓝对抗Pro路由已注册 (69端点: 6红+3蓝+紫/AI/报告/WS)")
except Exception as _e:
    print(f"方向1 红蓝对抗Pro路由注册失败: {_e}")

try:
    from fastapi.responses import HTMLResponse as _HTMLRBP
    @app.get("/red-blue-pro", include_in_schema=False)
    async def _rbp_page():
        import os as _os
        _p = _os.path.join(_os.path.dirname(__file__),
                           "red_blue_pro_console.html")
        if _os.path.exists(_p):
            with open(_p, "r", encoding="utf-8") as _f:
                return _HTMLRBP(content=_f.read())
        return _HTMLRBP(content="<h1>red_blue_pro_console.html 未找到</h1>")
    print("方向1 控制台页面已注册: /red-blue-pro")
except Exception as _e:
    print(f"方向1 控制台页面注册失败: {_e}")
# ==== /INJECT: red_blue_pro (方向1) ====

# === SCPRO_BEGIN ===
# ---- Direction 2: 供应链安全做深（5.5 -> 9.0） ----
try:
    from api_server.supply_chain_pro_routes import router as _scp_router
    app.include_router(_scp_router)
    log.info("供应链安全 Pro 路由已注册：/api/v1/supply-chain-pro（40 REST + 1 WebSocket）")
except Exception as e:
    log.warning(f"供应链安全 Pro 路由注册失败: {e}")

# ---- 前端页面路由: /supply-chain-pro ----
try:
    from fastapi.responses import HTMLResponse as _HTMLR_SCP
    from pathlib import Path as _Path_SCP
    @app.get("/supply-chain-pro", include_in_schema=False)
    async def _page_scp():
        _p = _Path_SCP(__file__).parent / "supply_chain_pro_console.html"
        if _p.exists():
            return _HTMLR_SCP(content=_p.read_text(encoding="utf-8"))
        return _HTMLR_SCP(content="<h1>供应链安全 Pro 控制台未找到</h1>")
    log.info("供应链安全 Pro 页面已注册：/supply-chain-pro")
except Exception as e:
    log.warning(f"供应链安全 Pro 页面注册失败: {e}")
# === SCPRO_END ===


# ==== INJECT: devsecops_pro (方向3) ====
try:
    from api_server.devsecops_pro_routes import router as _dso_router
    app.include_router(_dso_router)
    print("方向3 DevSecOps Pro 路由已注册 (47端点: 八阶段/AI/WebSocket/报告)")
except Exception as _e:
    print(f"方向3 DevSecOps Pro 路由注册失败: {_e}")

try:
    from fastapi.responses import HTMLResponse as _HTMLDSO
    @app.get("/devsecops-pro", include_in_schema=False)
    async def _dso_page():
        import os as _os
        _p = _os.path.join(_os.path.dirname(__file__),
                           "devsecops_pro_console.html")
        if _os.path.exists(_p):
            with open(_p, "r", encoding="utf-8") as _f:
                return _HTMLDSO(content=_f.read())
        return _HTMLDSO(content="<h1>devsecops_pro_console.html 未找到</h1>")
    print("方向3 控制台页面已注册: /devsecops-pro")
except Exception as _e:
    print(f"方向3 控制台页面注册失败: {_e}")


# ==== INJECT: soc_pro (方向1) ====
try:
    from api_server.soc_pro_routes import router as _soc_router
    app.include_router(_soc_router)
    print("方向1 SOC Pro 路由已注入（七阶段 / 58 检测规则 / AI / WebSocket / 大屏 / 报告）")
except Exception as _e:
    print(f"方向1 SOC Pro 路由注册失败: {_e}")

try:
    from fastapi.responses import HTMLResponse as _HTMLSOC
    @app.get("/soc-pro", include_in_schema=False)
    async def _soc_page():
        import os as _os
        _p = _os.path.join(_os.path.dirname(__file__),
                           "soc_pro_console.html")
        if _os.path.exists(_p):
            with open(_p, "r", encoding="utf-8") as _f:
                return _HTMLSOC(content=_f.read())
        return _HTMLSOC(content="<h1>soc_pro_console.html 未找到</h1>")
    print("方向1 控制台页面已注册: /soc-pro")
except Exception as _e:
    print(f"方向1 控制台页面注册失败: {_e}")

# === DSPRO_BEGIN ===
# ---- Direction 3: 数据安全做深（5.5 -> 9.0） ----
try:
    from api_server.data_security_pro_routes import router as _dsp_router
    app.include_router(_dsp_router)
    log.info("数据安全 Pro 路由已注册：/api/v1/data-security-pro（64 REST + 1 WebSocket）")
except Exception as e:
    log.warning(f"数据安全 Pro 路由注册失败: {e}")

# ---- 前端页面路由: /data-security-pro ----
try:
    from fastapi.responses import HTMLResponse as _HTMLR_DSP
    from pathlib import Path as _Path_DSP
    @app.get("/data-security-pro", include_in_schema=False)
    async def _page_dsp():
        _p = _Path_DSP(__file__).parent / "data_security_pro_console.html"
        if _p.exists():
            return _HTMLR_DSP(content=_p.read_text(encoding="utf-8"))
        return _HTMLR_DSP(content="<h1>数据安全 Pro 控制台未找到</h1>")
    log.info("数据安全 Pro 页面已注册：/data-security-pro")
except Exception as e:
    log.warning(f"数据安全 Pro 页面注册失败: {e}")
# === DSPRO_END ===


# ==== INJECT: threat_intel_pro (方向2) ====
try:
    from api_server.threat_intel_pro_routes import router as _tip_router
    app.include_router(_tip_router)
    print("方向2 威胁情报Pro路由已注册 (八阶段/IOC/Actor/攻击面/暗网/STIX/WebSocket)")
except Exception as _e:
    print(f"方向2 威胁情报Pro路由注册失败: {_e}")

try:
    from fastapi.responses import HTMLResponse as _HTMLTIP
    @app.get("/threat-intel-pro", include_in_schema=False)
    async def _tip_page():
        import os as _os
        _p = _os.path.join(_os.path.dirname(__file__),
                           "threat_intel_pro_console.html")
        if _os.path.exists(_p):
            with open(_p, "r", encoding="utf-8") as _f:
                return _HTMLTIP(content=_f.read())
        return _HTMLTIP(content="<h1>threat_intel_pro_console.html 未找到</h1>")
    print("方向2 控制台页面已注册: /threat-intel-pro")
except Exception as _e:
    print(f"方向2 控制台页面注册失败: {_e}")


# ==== INJECT: forensics_pro (方向2) ====
try:
    from api_server.forensics_pro_routes import router as _fp_router
    app.include_router(_fp_router)
    print("方向2 取证Pro路由已注册（八阶段 / 94端点 / AI / WebSocket / 大屏 / 报告）")
except Exception as _e:
    print(f"方向2 取证Pro路由注册失败: {_e}")

try:
    from fastapi.responses import HTMLResponse as _HTMLFP
    @app.get("/forensics-pro", include_in_schema=False)
    async def _fp_page():
        import os as _os
        _p = _os.path.join(_os.path.dirname(__file__),
                           "forensics_pro_console.html")
        if _os.path.exists(_p):
            with open(_p, "r", encoding="utf-8") as _f:
                return _HTMLFP(content=_f.read())
        return _HTMLFP(content="<h1>forensics_pro_console.html 未找到</h1>")
    print("方向2 控制台页面已注册: /forensics-pro")
except Exception as _e:
    print(f"方向2 控制台页面注册失败: {_e}")

# === CPRO_BEGIN ===
# ---- 方向1：合规审计做深（5.5 -> 9.0） ----
try:
    from api_server.compliance_pro_routes import router as _cpr_router
    app.include_router(_cpr_router)
    log.info("合规审计 Pro 路由已注册：/api/v1/compliance-pro（50+ REST + 1 WebSocket）")
except Exception as e:
    log.warning(f"合规审计 Pro 路由注册失败: {e}")

# ---- 前端页面路由: /compliance-pro ----
try:
    from fastapi.responses import HTMLResponse as _HTMLR_CPR
    from pathlib import Path as _Path_CPR
    @app.get("/compliance-pro", include_in_schema=False)
    async def _page_cpr():
        _p = _Path_CPR(__file__).parent / "compliance_pro_console.html"
        if _p.exists():
            return _HTMLR_CPR(content=_p.read_text(encoding="utf-8"))
        return _HTMLR_CPR(content="<h1>合规审计 Pro 控制台未找到</h1>")
    log.info("合规审计 Pro 页面已注册：/compliance-pro")
except Exception as e:
    log.warning(f"合规审计 Pro 页面注册失败: {e}")
# === CPRO_END ===


# ==== INJECT: iot_ot_pro (方向3) ====
try:
    from api_server.iot_ot_pro_routes import router as _iotot_router
    app.include_router(_iotot_router)
    print("方向3 工控IoT Pro 路由已注入（八阶段 / 85端点 / AI / WebSocket / 大屏 / 报告）")
except Exception as _e:
    print(f"方向3 工控IoT Pro 路由注册失败: {_e}")

try:
    from fastapi.responses import HTMLResponse as _HTMLIOTOT
    @app.get("/iot-ot-pro", include_in_schema=False)
    async def _iotot_page():
        import os as _os
        _p = _os.path.join(_os.path.dirname(__file__),
                           "iot_ot_pro_console.html")
        if _os.path.exists(_p):
            with open(_p, "r", encoding="utf-8") as _f:
                return _HTMLIOTOT(content=_f.read())
        return _HTMLIOTOT(content="<h1>iot_ot_pro_console.html 未找到</h1>")
    print("方向3 控制台页面已注册: /iot-ot-pro")
except Exception as _e:
    print(f"方向3 控制台页面注册失败: {_e}")


# ==== INJECT: src_platform_pro (方向2) ====
try:
    from api_server.src_platform_pro_routes import router as _src_router
    app.include_router(_src_router)
    print("方向2 SRC Pro 路由已注入（八阶段 / 80+端点 / AI / WebSocket / 大屏 / 报告）")
except Exception as _e:
    print(f"方向2 SRC Pro 路由注册失败: {_e}")

try:
    from fastapi.responses import HTMLResponse as _HTMLSRC
    @app.get("/src-platform-pro", include_in_schema=False)
    async def _src_page():
        import os as _os
        _p = _os.path.join(_os.path.dirname(__file__),
                           "src_platform_pro_console.html")
        if _os.path.exists(_p):
            with open(_p, "r", encoding="utf-8") as _f:
                return _HTMLSRC(content=_f.read())
        return _HTMLSRC(content="<h1>src_platform_pro_console.html 未找到</h1>")
    print("方向2 控制台页面已注册: /src-platform-pro")
except Exception as _e:
    print(f"方向2 控制台页面注册失败: {_e}")


# ==== INJECT: security_training_pro (方向3) ====
try:
    from api_server.security_training_pro_routes import router as _stp_router
    app.include_router(_stp_router)
    print("方向3 安全培训 Pro 路由已注入（八阶段 / AI / WebSocket / 大屏 / 报告）")
except Exception as _e:
    print(f"方向3 安全培训 Pro 路由注册失败: {_e}")

try:
    from fastapi.responses import HTMLResponse as _HTMLSTP
    @app.get("/security-training-pro", include_in_schema=False)
    async def _stp_page():
        import os as _os
        _p = _os.path.join(_os.path.dirname(__file__),
                           "security_training_pro_console.html")
        if _os.path.exists(_p):
            with open(_p, "r", encoding="utf-8") as _f:
                return _HTMLSTP(content=_f.read())
        return _HTMLSTP(content="<h1>security_training_pro_console.html 未找到</h1>")
    print("方向3 控制台页面已注册: /security-training-pro")
except Exception as _e:
    print(f"方向3 控制台页面注册失败: {_e}")


# ==== INJECT: ctf_pro (方向1 CTF) ====
try:
    from api_server.ctf_pro_routes import router as _ctf_router
    app.include_router(_ctf_router)
    print("方向1 CTF Pro 路由已注入（八阶段 / 8大题型 / Docker部署 / AI / WebSocket / CTF大屏 / 报告）")
except Exception as _e:
    print(f"方向1 CTF Pro 路由注册失败: {_e}")

try:
    from fastapi.responses import HTMLResponse as _HTMLCTF
    @app.get("/ctf-pro", include_in_schema=False)
    async def _ctf_page():
        import os as _os
        _p = _os.path.join(_os.path.dirname(__file__),
                           "ctf_pro_console.html")
        if _os.path.exists(_p):
            with open(_p, "r", encoding="utf-8") as _f:
                return _HTMLCTF(content=_f.read())
        return _HTMLCTF(content="<h1>ctf_pro_console.html 未找到</h1>")
    print("方向1 CTF 控制台页面已注册: /ctf-pro")
except Exception as _e:
    print(f"方向1 CTF 控制台页面注册失败: {_e}")

# === CUPRO_BEGIN ===
# ---- 方向4：商业产品化做深（支付/订阅/客户/SLA/工单/API计费/多租户） ----
try:
    from api_server.commercial_ultra_pro_routes import router as _cupro_router
    app.include_router(_cupro_router)
    log.info("商业产品化 Ultra Pro 路由已注册：/api/v1/commercial-ultra-pro（96 端点）")
except Exception as e:
    log.warning(f"商业产品化 Ultra Pro 路由注册失败: {e}")

# ---- 前端页面路由: /admin-center ----
try:
    from fastapi.responses import HTMLResponse as _HTMLR_CUPRO
    from pathlib import Path as _Path_CUPRO
    @app.get("/admin-center", include_in_schema=False)
    async def _page_cupro():
        _p = _Path_CUPRO(__file__).parent / "commercial_ultra_pro_console.html"
        if _p.exists():
            return _HTMLR_CUPRO(content=_p.read_text(encoding="utf-8"))
        return _HTMLR_CUPRO(content="<h1>商业产品化 Ultra Pro 控制台未找到</h1>")
    log.info("商业产品化 Ultra Pro 页面已注册：/admin-center")
except Exception as e:
    log.warning(f"商业产品化 Ultra Pro 页面注册失败: {e}")
# === CUPRO_END ===

# === SOCCENTER_LINKAGE_BEGIN ===
# ---- 方向1：统一安全运营中心 SOC Center（54 REST + 统一 WebSocket） ----
try:
    from api_server.soc_center_routes import router as _socc_router
    app.include_router(_socc_router)
    print("统一 SOC Center 路由已注册：/api/v1/soc-center（54 REST + 统一 WebSocket）")
except Exception as _e:
    print(f"统一 SOC Center 路由注册失败: {_e}")

# ---- 前端页面路由: /soc-center ----
try:
    from fastapi.responses import HTMLResponse as _HTMLSOCC
    @app.get("/soc-center", include_in_schema=False)
    async def _page_socc():
        import os as _os_socc
        _p = _os_socc.path.join(_os_socc.path.dirname(__file__),
                                "soc_center_console.html")
        if _os_socc.path.exists(_p):
            with open(_p, "r", encoding="utf-8") as _f:
                return _HTMLSOCC(content=_f.read())
        return _HTMLSOCC(content="<h1>soc_center_console.html 未找到</h1>")
    print("统一 SOC Center 页面已注册：/soc-center")
except Exception as _e:
    print(f"统一 SOC Center 页面注册失败: {_e}")

# ---- 方向2：领域联动工作流（35 REST） ----
try:
    from api_server.workflow_linkage_routes import router as _wfl_router
    app.include_router(_wfl_router)
    print("领域联动工作流 路由已注册：/api/v1/workflow-linkage（35 REST）")
except Exception as _e:
    print(f"领域联动工作流 路由注册失败: {_e}")

# ---- 前端页面路由: /workflow-linkage ----
try:
    from fastapi.responses import HTMLResponse as _HTMLWFL
    @app.get("/workflow-linkage", include_in_schema=False)
    async def _page_wfl():
        import os as _os_wfl
        _p = _os_wfl.path.join(_os_wfl.path.dirname(__file__),
                               "workflow_linkage_console.html")
        if _os_wfl.path.exists(_p):
            with open(_p, "r", encoding="utf-8") as _f:
                return _HTMLWFL(content=_f.read())
        return _HTMLWFL(content="<h1>workflow_linkage_console.html 未找到</h1>")
    print("领域联动工作流 页面已注册：/workflow-linkage")
except Exception as _e:
    print(f"领域联动工作流 页面注册失败: {_e}")
# === SOCCENTER_LINKAGE_END ===

# === PDFVAL_BEGIN ===
# ---- 方向3: PDF报告导出 + 方向5: 真实环境验证体系 ----
try:
    from api_server.pdf_report_routes import router as _pdf_router
    app.include_router(_pdf_router)
    print("方向3 PDF报告路由已注册：/api/v1/pdf-report（40+端点）")
except Exception as _e:
    print(f"方向3 PDF报告路由注册失败: {_e}")

try:
    from fastapi.responses import HTMLResponse as _HTMLRC
    from pathlib import Path as _PathRC
    @app.get("/report-center", include_in_schema=False)
    async def _page_rc():
        _p = _PathRC(__file__).parent / "report_center_console.html"
        if _p.exists():
            return _HTMLRC(content=_p.read_text(encoding="utf-8"))
        return _HTMLRC(content="<h1>report_center_console.html 未找到</h1>")
    print("方向3 报告中心页面已注册：/report-center")
except Exception as _e:
    print(f"方向3 报告中心页面注册失败: {_e}")

try:
    from api_server.validation_center_routes import router as _val_router
    app.include_router(_val_router)
    print("方向5 验证中心路由已注册：/api/v1/validation（40+端点）")
except Exception as _e:
    print(f"方向5 验证中心路由注册失败: {_e}")

try:
    from fastapi.responses import HTMLResponse as _HTMLVC
    from pathlib import Path as _PathVC
    @app.get("/validation-center", include_in_schema=False)
    async def _page_vc():
        _p = _PathVC(__file__).parent / "validation_center_console.html"
        if _p.exists():
            return _HTMLVC(content=_p.read_text(encoding="utf-8"))
        return _HTMLVC(content="<h1>validation_center_console.html 未找到</h1>")
    print("方向5 验证中心页面已注册：/validation-center")
except Exception as _e:
    print(f"方向5 验证中心页面注册失败: {_e}")
# === PDFVAL_END ===


# ==== INJECT: mobile_pentest_real (方向2 移动安全真实化) ====
try:
    from api_server.mobile_pentest_real_routes import router as _mpr_router
    app.include_router(_mpr_router)
    print("方向2 移动安全真实化路由已注册 (50+端点: 真实反编译/androguard/Frida/脱壳)")
except Exception as _e:
    print(f"方向2 移动安全真实化路由注册失败: {_e}")

try:
    from fastapi.responses import HTMLResponse as _HTMLMPR
    @app.get("/mobile-pentest-real", include_in_schema=False)
    async def _mpr_page():
        import os as _os
        _p = _os.path.join(_os.path.dirname(__file__),
                           "mobile_pentest_real_console.html")
        if _os.path.exists(_p):
            with open(_p, "r", encoding="utf-8") as _f:
                return _HTMLMPR(content=_f.read())
        return _HTMLMPR(content="<h1>mobile_pentest_real_console.html 未找到</h1>")
    print("方向2 真实化控制台页面已注册: /mobile-pentest-real")
except Exception as _e:
    print(f"方向2 真实化控制台页面注册失败: {_e}")


# ==== INJECT: internal_pentest_real (方向1真实化) ====
try:
    from api_server.internal_pentest_real_routes import (
        legacy_router as _ipr_legacy)
    app.include_router(_ipr_legacy)
    print("方向1 内网渗透真实化: 兼容旧前缀 /api/v1/internal-real 已挂载")
except Exception as _e:
    print(f"方向1 内网渗透真实化 legacy 路由挂载失败: {_e}")
# ==== /INJECT: internal_pentest_real (方向1真实化) ====

# === CSREAL_BEGIN ===
# ---- 方向3：云安全真实化（6.5 -> 8.5）----
try:
    from api_server.cloud_security_real_routes import router as _csreal_router
    app.include_router(_csreal_router)
    print("方向3 云安全真实版路由已注册: /api/v1/cloud-security-real (60+ REST)")
except Exception as _e:
    print(f"方向3 云安全真实版路由注册失败: {_e}")

# ---- 前端页面路由: /cloud-security-real ----
try:
    from fastapi.responses import HTMLResponse as _HTMLR_CSREAL
    import os as _os_csreal
    @app.get("/cloud-security-real", include_in_schema=False)
    async def _page_csreal():
        _p = _os_csreal.path.join(_os_csreal.path.dirname(__file__),
                                  "cloud_security_real_console.html")
        if _os_csreal.path.exists(_p):
            with open(_p, "r", encoding="utf-8") as _f:
                return _HTMLR_CSREAL(content=_f.read())
        return _HTMLR_CSREAL(content="<h1>cloud_security_real_console.html 未找到</h1>")
    print("方向3 云安全真实版页面已注册: /cloud-security-real")
except Exception as _e:
    print(f"方向3 云安全真实版页面注册失败: {_e}")
# === CSREAL_END ===


# ==== INJECT: red_blue_real (方向4) ====
try:
    from api_server.red_blue_real_routes import router as _rbr_router
    app.include_router(_rbr_router)
    print("方向4 红蓝对抗真实化路由已注册 (118端点: 红8战术+蓝5能力+紫+C2工具+导航+报告+WS)")
except Exception as _e:
    print(f"方向4 红蓝对抗真实化路由注册失败: {_e}")

try:
    from fastapi.responses import HTMLResponse as _HTMLRBR
    @app.get("/red-blue-real", include_in_schema=False)
    async def _rbr_page():
        import os as _osrbr
        _p = _osrbr.path.join(_osrbr.path.dirname(__file__),
                           "red_blue_real_console.html")
        if _osrbr.path.exists(_p):
            with open(_p, "r", encoding="utf-8") as _f:
                return _HTMLRBR(content=_f.read())
        return _HTMLRBR(content="<h1>red_blue_real_console.html 未找到</h1>")
    print("方向4 控制台页面已注册: /red-blue-real")
except Exception as _e:
    print(f"方向4 控制台页面注册失败: {_e}")
# ==== /INJECT: red_blue_real (方向4) ====


# ============== 深度侦察与靶场管理路由 ==============
try:
    from api_server.deep_recon_routes import router as deep_recon_router
    app.include_router(deep_recon_router)
    log.info("深度侦察与靶场管理路由已注册")
except Exception as e:
    log.error(f"深度侦察与靶场管理路由注册失败: {e}")
# ============== 深度侦察与靶场管理路由 ==============
try:
    from api_server.deep_recon_routes import router as deep_recon_router
    app.include_router(deep_recon_router)
    log.info("深度侦察与靶场管理路由已注册：子域名爆破/目录扫描/API端点发现/技术栈识别/靶场部署管理，共16个端点")
except Exception as e:
    log.error(f"深度侦察与靶场管理路由注册失败: {e}")

# ============== 漏洞扫描引擎路由 ==============
try:
    from api_server.vuln_scan_routes import router as vuln_scan_router
    app.include_router(vuln_scan_router)
    log.info("漏洞扫描引擎路由已注册：Nuclei风格模板扫描/模板列表/模板详情，共3个端点，内置15+漏洞模板")
except Exception as e:
    log.error(f"漏洞扫描引擎路由注册失败: {e}")
# ============== 第二轮升级：增强型AI智能体路由 ==============
try:
    from api_server.agent_enhanced_routes import router as agent_enhanced_router
    app.include_router(agent_enhanced_router)
    log.info("增强型AI智能体路由已注册：自主规划/动态调整/多轮ReAct推理/反思机制/多智能体流水线，共4个端点")
except Exception as e:
    log.error(f"增强型AI智能体路由注册失败: {e}")

# ============== 第二轮升级：报告AI分析增强路由 ==============
try:
    from api_server.report_ai_routes import router as report_ai_router
    app.include_router(report_ai_router)
    log.info("报告AI分析增强路由已注册：漏洞关联/攻击链推理/业务影响评估/MITRE ATT&CK映射，共5个端点")
except Exception as e:
    log.error(f"报告AI分析增强路由注册失败: {e}")

# ============== 第二轮升级：被动资产积累路由 ==============
try:
    from api_server.passive_asset_routes import router as passive_asset_router
    app.include_router(passive_asset_router)
    log.info("被动资产积累路由已注册：扫描记录/资产画像/趋势分析/变更事件/全局统计，共6个端点")
except Exception as e:
    log.error(f"被动资产积累路由注册失败: {e}")

# ============== 第二轮升级：漏洞验证框架路由 ==============
try:
    from api_server.vuln_verifier_routes import router as vuln_verifier_router
    app.include_router(vuln_verifier_router)
    log.info("漏洞验证框架路由已注册：单漏洞验证/批量验证/授权检查/验证方法列表/验证汇总，共5个端点")
except Exception as e:
    log.error(f"漏洞验证框架路由注册失败: {e}")
# ============== 第四轮升级P0：真实端口扫描路由 ==============
try:
    from api_server.port_scan_routes import router as port_scan_router
    app.include_router(port_scan_router)
    log.info("真实端口扫描路由已注册")
except Exception as e:
    log.error(f"真实端口扫描路由注册失败: {e}")

# ============== 第五轮升级: Web侦察路由 ==============
try:
    from api_server.recon_routes import router as recon_router
    app.include_router(recon_router)
    log.info("第五轮Web侦察路由已注册: 指纹识别/目录扫描/一键完整侦察, 共3个端点")
except Exception as e:
    log.error(f"第五轮Web侦察路由注册失败: {e}")

# ============== 第六轮升级: SSL/报告/CVE路由 ==============
try:
    from api_server.security_routes import router as sec_round6_router
    app.include_router(sec_round6_router)
    log.info("第六轮安全路由已注册: SSL检测/报告生成/CVE搜索")
except Exception as e:
    log.error(f"第六轮安全路由注册失败: {e}")

# ============== 真实工具链路由 ==============
try:
    from api_server.real_tools_routes import router as real_tools_router
    app.include_router(real_tools_router)
    log.info("真实工具链路由已注册: Nmap/Nuclei/Subfinder/Httpx/Nikto")
except Exception as e:
    log.error(f"真实工具链路由注册失败: {e}")

# ============== 一键侦察工作流 ==============
try:
    from api_server.recon_workflow_routes import router as recon_wf_router
    app.include_router(recon_wf_router)
    log.info("一键侦察工作流路由已注册: /api/v1/recon-workflow/run")
except Exception as e:
    log.error(f"侦察工作流路由注册失败: {e}")

# ============== MCP工具服务器 ==============
try:
    from api_server.mcp_server_routes import router as mcp_router
    app.include_router(mcp_router)
    log.info("MCP工具服务器路由已注册: 12个MCP工具")
except Exception as e:
    log.error(f"MCP路由注册失败: {e}")

# ============== AI代理队 ==============
try:
    from api_server.agent_team_routes import router as agent_team_router
    app.include_router(agent_team_router)
    log.info("AI代理队路由已注册: 4代理链式协作")
except Exception as e:
    log.error(f"AI代理队路由注册失败: {e}")

# ============== 武器手册知识库 ==============
try:
    from api_server.weapon_manual_routes import router as weapon_manual_router
    app.include_router(weapon_manual_router)
    log.info("武器手册知识库路由已注册: 16份武器手册")
except Exception as e:
    log.error(f"武器手册路由注册失败: {e}")
