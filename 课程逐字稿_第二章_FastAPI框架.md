# AI安全渗透测试实战 — 逐字稿（第二章：FastAPI后端框架与项目结构）

---

## 第4节：FastAPI入门

大家好，这一节我们正式开始写代码。首先学FastAPI——我们整个平台的后端框架。

为什么选FastAPI而不是Flask或者Django？三个原因。第一，FastAPI性能非常好，基于Starlette和Pydantic，异步支持原生，速度接近Node.js和Go。第二，自动生成API文档，写好接口就自动有Swagger UI，前后端联调非常方便。第三，类型提示驱动，用Python的类型注解做数据校验，代码可读性高。

我们来写第一个FastAPI应用。

【屏幕录制：打开VS Code，创建main.py】

在项目目录下创建main.py，输入以下代码：

```python
from fastapi import FastAPI

app = FastAPI(title="AI Hacking Agent", version="1.0")

@app.get("/")
def root():
    return {"message": "AI Hacking Agent is running"}
```

就这么几行，一个Web服务就写好了。我们来运行它。在命令行执行uvicorn main:app --reload，--reload参数的意思是代码修改后自动重启，开发的时候很方便。

【屏幕录制：执行uvicorn main:app --reload】

服务启动后，打开浏览器访问http://127.0.0.1:8000，你会看到返回的JSON。然后访问http://127.0.0.1:8000/docs，这就是自动生成的Swagger文档页面，所有接口都列在这里，可以直接在页面上测试。

接下来我们看路由定义。FastAPI用装饰器定义路由，@app.get是GET请求，@app.post是POST请求，还有put、delete等等。路由路径可以带参数，比如：

```python
@app.get("/targets/{target_id}")
def get_target(target_id: int):
    return {"target_id": target_id}
```

这里target_id是路径参数，FastAPI会自动把它转换成int类型，如果传了非数字会自动返回422错误。

查询参数用函数参数定义，比如：

```python
@app.get("/targets")
def list_targets(page: int = 1, size: int = 20):
    return {"page": page, "size": size}
```

调用的时候用?page=2&size=10，FastAPI自动解析。默认值也在这里定义。

请求体用Pydantic模型。比如我们要创建一个扫描任务，定义一个模型：

```python
from pydantic import BaseModel

class ScanRequest(BaseModel):
    target: str
    scan_type: str = "full"
    ports: list[int] = [80, 443]
```

然后在路由里用这个模型作为参数：

```python
@app.post("/scan")
def start_scan(req: ScanRequest):
    return {"target": req.target, "type": req.scan_type}
```

FastAPI会自动校验请求体的字段类型，target是必填的字符串，scan_type有默认值，ports是整数列表。如果客户端传了错误的类型，自动返回422和详细的错误信息。

这就是FastAPI最核心的三个概念——路径参数、查询参数、请求体模型。掌握这三个，大部分接口都能写了。

我们再看几个实用功能。第一个是响应模型。你可以定义响应的结构，FastAPI会自动过滤掉多余字段：

```python
class TargetResponse(BaseModel):
    id: int
    url: str
    status: str

@app.post("/targets", response_model=TargetResponse)
def create_target(req: ScanRequest):
    # 创建逻辑
    return {"id": 1, "url": req.target, "status": "pending", "secret": "xxx"}
```

即使返回了secret字段，响应模型里没有定义，FastAPI会自动过滤掉，不会返回给客户端。

第二个是状态码。可以在装饰器里指定默认状态码：@app.post("/targets", status_code=201)。也可以在函数里用Response对象动态设置。

第三个是依赖注入。FastAPI有强大的依赖系统，比如我们要做认证，可以写一个依赖函数：

```python
from fastapi import Depends, HTTPException, Header

async def verify_api_key(x_api_key: str = Header(...)):
    if x_api_key != "your-secret-key":
        raise HTTPException(status_code=401, detail="Invalid API key")
    return x_api_key

@app.get("/secure", dependencies=[Depends(verify_api_key)])
def secure_endpoint():
    return {"message": "secure data"}
```

这样访问/secure接口的时候，FastAPI会自动执行verify_api_key，检查请求头里的X-API-Key，不对就返回401。这个我们后面做认证模块的时候会详细讲。

好，这一节讲了FastAPI的基础——创建应用、路由定义、三种参数、响应模型、状态码、依赖注入。这些是我们后面所有接口的基础。

下一节我们设计整个项目的目录结构，把代码组织成模块化的架构，而不是所有东西都写在一个文件里。我们下节课见。

---

## 第5节：项目结构设计

大家好，这一节我们设计项目的目录结构。一个好的项目结构能让代码可维护、可扩展，特别是我们这个项目有40多个路由模块，如果都堆在一个文件里根本没法维护。

我们采用模块化的设计，每个功能领域一个模块，每个模块有自己的路由、服务、数据模型。整体结构是这样的：

```
ai-hacking-agent/
├── main.py              # 入口文件
├── app_lite.py          # 轻量启动入口（快速启动，只加载核心模块）
├── requirements.txt     # 依赖清单
├── config.py            # 配置管理
├── api_server/          # API服务层
│   ├── app.py           # FastAPI应用创建
│   ├── routes/          # 路由模块（每个功能一个文件）
│   │   ├── recon_routes.py
│   │   ├── scan_routes.py
│   │   ├── ai_decision_routes.py
│   │   └── ...
│   └── models.py        # 请求/响应模型
├── core/                # 核心业务逻辑
│   ├── scanner.py       # 扫描引擎
│   ├── ai_engine.py     # AI决策引擎
│   ├── reporter.py      # 报告生成
│   └── ...
├── utils/               # 工具函数
│   ├── logger.py        # 日志
│   ├── database.py      # 数据库
│   └── ...
├── data/                # 数据文件
│   ├── hacking_agent.db # SQLite数据库
│   ├── vuln_database.json # CVE漏洞库
│   └── ...
├── templates/           # 前端页面
│   ├── console.html
│   └── ...
└── tests/               # 测试
```

我们一个一个说。

最顶层的main.py是完整启动入口，加载所有模块，启动比较慢，大概要几分钟。app_lite.py是轻量启动入口，只加载核心模块，1-2秒就能启动，开发调试的时候用这个。后面我们会讲怎么实现模块化加载。

config.py是配置管理。所有可配置的东西——端口、API Key、工具路径、数据库路径——都集中在这里，用环境变量覆盖。这样部署到不同环境不用改代码，只改环境变量。

```python
import os

class Config:
    HOST = os.getenv("HOST", "127.0.0.1")
    PORT = int(os.getenv("PORT", "8000"))
    API_KEY = os.getenv("API_KEY", "default-key")
    NMAP_PATH = os.getenv("NMAP_PATH", "nmap")
    NUCLEI_PATH = os.getenv("NUCLEI_PATH", "nuclei")
    DB_PATH = os.getenv("DB_PATH", "data/hacking_agent.db")
```

api_server目录是API服务层。app.py负责创建FastAPI应用实例，注册所有路由模块。routes目录下每个功能一个文件，比如侦察模块是recon_routes.py，扫描模块是scan_routes.py，AI决策模块是ai_decision_routes.py。每个路由文件里定义一个router，然后在app.py里统一注册。

```python
# recon_routes.py
from fastapi import APIRouter

router = APIRouter(prefix="/api/v1/recon", tags=["侦察"])

@router.get("/subdomains")
def enumerate_subdomains(domain: str):
    # 子域名枚举逻辑
    pass

# app.py
from fastapi import FastAPI
from api_server.routes import recon_routes, scan_routes

app = FastAPI()
app.include_router(recon_routes.router)
app.include_router(scan_routes.router)
```

这样每个路由模块独立，改一个不影响其他的。加新功能就是加一个新的路由文件，注册一下就行。

core目录是核心业务逻辑。路由层只负责接收请求、返回响应，真正的业务逻辑放在core里。比如scanner.py里封装Nmap、Nuclei的调用，ai_engine.py里是AI决策的核心逻辑，reporter.py是报告生成。这样路由层很薄，业务逻辑可以复用和测试。

utils目录是工具函数。logger.py统一配置日志格式，database.py封装数据库操作，还有一些通用的工具函数比如时间处理、字符串处理。

data目录存数据文件。SQLite数据库、CVE漏洞库JSON、扫描结果缓存都放这里。这个目录要加入.gitignore，不提交到版本控制。

templates目录是前端HTML页面。我们用服务端渲染的方式，FastAPI直接返回HTML文件，不用前后端分离，这样部署简单。

tests目录是单元测试和集成测试。每个核心模块对应一个测试文件。

这种结构的好处是：第一，关注点分离，路由、业务逻辑、工具函数分开；第二，模块化，每个功能独立，可以单独测试；第三，可扩展，加新功能加新文件就行；第四，团队协作，不同人可以并行开发不同模块。

接下来讲日志系统。日志是生产环境排查问题的关键，我们用Python标准库的logging模块，统一配置格式和输出。

```python
import logging
import sys

def setup_logger(name="ai_hacking"):
    logger = logging.getLogger(name)
    logger.setLevel(logging.INFO)
    
    handler = logging.StreamHandler(sys.stdout)
    formatter = logging.Formatter(
        "%(asctime)s | %(levelname)s | %(name)s | %(message)s",
        datefmt="%Y-%m-%d %H:%M:%S"
    )
    handler.setFormatter(formatter)
    logger.addHandler(handler)
    return logger
```

每个模块用自己的logger：logger = logging.getLogger("ai_hacking.recon")，这样日志里能看到是哪个模块输出的。

然后是数据库。我们用SQLite，因为它零配置、单文件、足够应付中小规模的使用。后面如果要迁移PostgreSQL，数据访问层做了抽象的话改动不大。

我们用Python标准库的sqlite3，封装一个Database类：

```python
import sqlite3
from contextlib import contextmanager

class Database:
    def __init__(self, db_path):
        self.db_path = db_path
        self._init_tables()
    
    @contextmanager
    def get_conn(self):
        conn = sqlite3.connect(self.db_path)
        conn.row_factory = sqlite3.Row
        try:
            yield conn
            conn.commit()
        finally:
            conn.close()
    
    def _init_tables(self):
        with self.get_conn() as conn:
            conn.execute("""
                CREATE TABLE IF NOT EXISTS targets (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    url TEXT NOT NULL,
                    status TEXT DEFAULT 'pending',
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                )
            """)
```

用contextmanager管理连接，自动提交和关闭，不会忘记关连接。

最后讲统一响应格式。我们所有接口返回统一的JSON结构：

```json
{
  "code": 0,
  "message": "success",
  "data": { ... }
}
```

code=0表示成功，非0表示错误，message是描述，data是实际数据。这样前端处理起来统一。错误用FastAPI的HTTPException，或者自定义异常处理器。

好，这一节讲了项目结构、配置管理、日志系统、数据库封装、统一响应格式。下一节我们实现认证与权限系统，给API加上API Key认证和RBAC角色权限。我们下节课见。

---

## 第6节：认证与权限

大家好，这一节我们给API加上认证和权限系统。一个安全产品自己的API不能没有认证，否则任何人都能调用你的扫描引擎去扫别人，那你的服务器就成了攻击跳板。

我们实现两层安全：第一层是API Key认证，所有接口都需要有效的API Key才能调用；第二层是RBAC角色权限，不同角色有不同的操作权限。

先讲API Key认证。思路很简单——客户端在请求头里带X-API-Key，服务端验证这个Key是否有效，无效返回401。

我们用FastAPI的依赖注入来实现，这样不用在每个接口里重复写认证逻辑。

```python
from fastapi import Depends, HTTPException, Header
from config import Config

API_KEYS = {
    Config.API_KEY: {"role": "admin", "name": "默认管理员"}
}

async def verify_api_key(x_api_key: str = Header(..., alias="X-API-Key")):
    if x_api_key not in API_KEYS:
        raise HTTPException(status_code=401, detail="无效的API Key")
    return API_KEYS[x_api_key]
```

然后在需要认证的路由上加上依赖：

```python
@router.post("/scan", dependencies=[Depends(verify_api_key)])
def start_scan(req: ScanRequest):
    return {"status": "started"}
```

这样访问这个接口的时候，FastAPI会自动执行verify_api_key，检查请求头里的X-API-Key。如果没带或者不对，自动返回401。

但每个路由都加dependencies太麻烦了，我们可以在创建router的时候统一加：

```python
router = APIRouter(
    prefix="/api/v1/recon",
    tags=["侦察"],
    dependencies=[Depends(verify_api_key)]
)
```

这样这个router下的所有接口自动都需要认证，不用每个都写。

API Key的存储要注意——不能明文写在代码里。我们用环境变量注入，生产环境从配置文件或环境变量读取。Key本身要足够长、足够随机，比如用secrets.token_urlsafe(48)生成。

接下来是RBAC角色权限。RBAC就是基于角色的访问控制，用户属于某个角色，角色有一组权限，用户通过角色获得权限。

我们设计四个预设角色：

| 角色 | 权限 |
|------|------|
| admin | 所有权限，包括用户管理、系统配置 |
| analyst | 扫描、侦察、漏洞管理、报告生成 |
| auditor | 只读权限，查看扫描结果和报告 |
| readonly | 只能看仪表盘 |

权限点我们定义成字符串，比如"scan:start"、"target:create"、"report:export"、"user:manage"。每个角色有一组允许的权限点。

```python
ROLES = {
    "admin": ["*"],  # 所有权限
    "analyst": [
        "target:read", "target:create", "target:delete",
        "scan:start", "scan:stop", "scan:read",
        "vuln:read", "vuln:update",
        "report:read", "report:export",
        "recon:run"
    ],
    "auditor": [
        "target:read", "scan:read", "vuln:read", "report:read"
    ],
    "readonly": ["dashboard:read"]
}
```

然后写一个权限检查的依赖：

```python
def require_permission(permission: str):
    async def checker(api_key_info = Depends(verify_api_key)):
        role = api_key_info["role"]
        allowed = ROLES.get(role, [])
        if "*" not in allowed and permission not in allowed:
            raise HTTPException(status_code=403, detail="权限不足")
        return api_key_info
    return checker
```

用的时候：

```python
@router.post("/scan", dependencies=[Depends(require_permission("scan:start"))])
def start_scan(req: ScanRequest):
    return {"status": "started"}
```

这个接口需要scan:start权限，analyst和admin可以调用，auditor和readonly会返回403。

接下来是接口限流。防止API Key泄露后被滥用，我们加一个简单的限流——每个Key每分钟最多60次请求。用一个内存字典记录每个Key的请求时间戳：

```python
from collections import defaultdict
import time

rate_limit_store = defaultdict(list)

async def rate_limit(api_key_info = Depends(verify_api_key)):
    key = api_key_info.get("key", "unknown")
    now = time.time()
    # 清理1分钟前的记录
    rate_limit_store[key] = [t for t in rate_limit_store[key] if now - t < 60]
    if len(rate_limit_store[key]) >= 60:
        raise HTTPException(status_code=429, detail="请求过于频繁，请稍后再试")
    rate_limit_store[key].append(now)
    return api_key_info
```

这个是内存版的限流，重启后清零，适合单实例部署。如果要多实例部署，需要用Redis做分布式限流。

然后是审计日志。所有敏感操作——启动扫描、删除目标、导出报告、修改配置——都要记录审计日志，包括谁、什么时间、做了什么、IP地址。

```python
import sqlite3
from fastapi import Request

async def audit_log(request: Request, action: str, detail: str = ""):
    api_key = request.headers.get("X-API-Key", "unknown")
    ip = request.client.host if request.client else "unknown"
    with db.get_conn() as conn:
        conn.execute(
            "INSERT INTO audit_logs (api_key, ip, action, detail, created_at) VALUES (?, ?, ?, ?, ?)",
            (api_key, ip, action, detail, datetime.now().isoformat())
        )
```

在关键操作的路由里调用audit_log记录。这样出了问题能追溯是谁做的。

最后讲安全注意事项。第一，API Key不要硬编码在代码里，用环境变量。第二，Key要定期轮换。第三，生产环境一定要用HTTPS，否则API Key在网络上明文传输。第四，错误信息不要泄露内部细节，比如数据库错误不要把SQL语句返回给客户端。第五，所有用户输入都要校验和转义，防止注入。

好，这一节讲了API Key认证、RBAC角色权限、接口限流、审计日志。到这里，我们的后端框架基础就搭好了——FastAPI服务、模块化结构、配置管理、日志、数据库、认证权限。

下一章我们进入第一个核心功能模块——侦察自动化，集成Nmap做端口扫描、Subfinder做子域名枚举、指纹识别、目录爆破。我们下节课见。
