# AI Hacking Agent - API 文档

> 版本：v6.0
> 基础URL：`http://127.0.0.1:8000`
> 认证方式：API Key（Header: `X-API-Key`）或 JWT Bearer Token
> 交互式文档：`http://127.0.0.1:8000/docs`（Swagger UI）

---

## 目录

1. [认证与授权](#1-认证与授权)
2. [系统接口](#2-系统接口)
3. [任务管理](#3-任务管理)
4. [工具调用](#4-工具调用)
5. [智能体](#5-智能体)
6. [知识库](#6-知识库)
7. [报告生成](#7-报告生成)
8. [PoC验证](#8-poc验证)
9. [超级智能体](#9-超级智能体)
10. [AI工具集](#10-ai工具集)
11. [数据库管理](#11-数据库管理)
12. [用户管理](#12-用户管理)
13. [插件系统](#13-插件系统)
14. [渗透测试](#14-渗透测试)
15. [企业级增强](#15-企业级增强)
16. [告警通知](#16-告警通知)
17. [数据备份](#17-数据备份)
18. [漏洞数据库](#18-漏洞数据库)
19. [工作流](#19-工作流)
20. [WebSocket](#20-websocket)

---

## 1. 认证与授权

### API Key 认证

在请求头中添加：
```
X-API-Key: your-api-key-here
```

### JWT Bearer Token 认证

在请求头中添加：
```
Authorization: Bearer your-jwt-token-here
```

### 登录获取Token

**POST** `/api/v1/auth/login`

请求体：
```json
{
  "username": "admin",
  "password": "Admin123456"
}
```

响应：
```json
{
  "access_token": "eyJhbGciOiJIUzI1NiIs...",
  "refresh_token": "eyJhbGciOiJIUzI1NiIs...",
  "token_type": "bearer",
  "expires_in": 3600
}
```

### 刷新Token

**POST** `/api/v1/auth/refresh`

请求体：
```json
{
  "refresh_token": "your-refresh-token"
}
```

### 获取当前用户信息

**GET** `/api/v1/auth/me`

需要认证。返回当前登录用户的详细信息。

---

## 2. 系统接口

### 健康检查

**GET** `/health`

无需认证。

响应：
```json
{
  "status": "healthy",
  "version": "6.0.0",
  "uptime": "1h 23m 45s",
  "timestamp": "2026-08-30T22:00:00Z"
}
```

### 系统统计

**GET** `/api/v1/system/stats`

响应：
```json
{
  "total_tools": 34,
  "total_agents": 4,
  "total_tasks": 128,
  "completed_tasks": 95,
  "running_tasks": 3,
  "total_findings": 256,
  "total_reports": 42,
  "uptime_seconds": 5025,
  "database_size": "15.2 MB"
}
```

### 系统配置

**GET** `/api/v1/system/config`

返回当前系统配置（隐藏敏感信息）。

---

## 3. 任务管理

### 创建任务

**POST** `/api/v1/tasks`

请求体：
```json
{
  "target": "https://example.com",
  "target_type": "url",
  "task_type": "scan",
  "description": "全面安全扫描",
  "options": {
    "rate_limit": 10,
    "max_concurrency": 5,
    "timeout": 300
  }
}
```

响应：
```json
{
  "task_id": "task-abc123",
  "status": "pending",
  "target": "https://example.com",
  "created_at": "2026-08-30T22:00:00Z"
}
```

### 获取任务列表

**GET** `/api/v1/tasks`

查询参数：
- `status`：按状态筛选（pending/running/completed/failed）
- `limit`：返回数量（默认20）
- `offset`：偏移量

### 获取单个任务

**GET** `/api/v1/tasks/{task_id}`

### 获取任务日志

**GET** `/api/v1/tasks/{task_id}/logs`

### 获取任务结果

**GET** `/api/v1/tasks/{task_id}/result`

### 取消任务

**POST** `/api/v1/tasks/{task_id}/cancel`

### 删除任务

**DELETE** `/api/v1/tasks/{task_id}`

---

## 4. 工具调用

### 获取可用工具列表

**GET** `/api/v1/tools`

响应：
```json
{
  "tools": [
    {"name": "nmap", "description": "端口扫描工具", "category": "recon"},
    {"name": "nuclei", "description": "漏洞扫描工具", "category": "scanner"},
    {"name": "sqlmap", "description": "SQL注入检测工具", "category": "exploit"}
  ],
  "total": 34
}
```

### 调用工具

**POST** `/api/v1/tools/call`

请求体：
```json
{
  "tool_name": "nmap",
  "target": "192.168.1.1",
  "args": ["-sV", "-p", "1-1000"],
  "timeout": 120
}
```

响应：
```json
{
  "execution_id": "exec-xyz789",
  "status": "running",
  "output": "",
  "started_at": "2026-08-30T22:00:00Z"
}
```

---

## 5. 智能体

### 获取智能体列表

**GET** `/api/v1/agents`

响应：
```json
{
  "agents": [
    {"id": "recon", "name": "侦察智能体", "description": "负责信息收集和侦察", "status": "idle"},
    {"id": "exploit", "name": "漏洞利用智能体", "description": "负责漏洞验证和利用", "status": "idle"},
    {"id": "verification", "name": "验证智能体", "description": "负责漏洞验证和误报排除", "status": "idle"},
    {"id": "report", "name": "报告智能体", "description": "负责生成安全报告", "status": "idle"}
  ],
  "total": 4
}
```

### 与智能体交互

**POST** `/api/v1/agents/react`

请求体：
```json
{
  "agent_id": "recon",
  "message": "扫描目标192.168.1.1的开放端口",
  "context": {}
}
```

---

## 6. 知识库

### CVE漏洞查询

**GET** `/api/v1/knowledge/cve`

查询参数：
- `keyword`：搜索关键词
- `severity`：严重程度（low/medium/high/critical）
- `limit`：返回数量

### CVE详情

**GET** `/api/v1/knowledge/cve/{cve_id}`

### RAG知识检索

**POST** `/api/v1/knowledge/rag`

请求体：
```json
{
  "query": "SQL注入的修复方法",
  "top_k": 5,
  "filters": {"category": "remediation"}
}
```

### 知识库统计

**GET** `/api/v1/knowledge/stats`

响应：
```json
{
  "total_cves": 6665,
  "total_pocs": 40,
  "total_attack_chains": 20,
  "total_fingerprints": 198,
  "total_remediations": 30
}
```

---

## 7. 报告生成

### 生成报告

**POST** `/api/v1/reports/generate`

请求体：
```json
{
  "task_id": "task-abc123",
  "report_type": "full",
  "format": "markdown",
  "include_remediation": true,
  "include_poc": true
}
```

响应：
```json
{
  "report_id": "report-def456",
  "status": "generating",
  "format": "markdown",
  "created_at": "2026-08-30T22:00:00Z"
}
```

### 获取报告

**GET** `/api/v1/reports/{report_id}`

### 下载报告

**GET** `/api/v1/reports/{report_id}/download`

---

## 8. PoC验证

### 提交PoC验证

**POST** `/api/v1/poc/verify`

请求体：
```json
{
  "target": "https://example.com/vulnerable.php",
  "poc_id": "poc-sqli-001",
  "poc_code": "...",
  "use_sandbox": true,
  "timeout": 60
}
```

响应：
```json
{
  "verification_id": "verify-ghi789",
  "status": "pending",
  "target": "https://example.com/vulnerable.php"
}
```

### 获取验证状态

**GET** `/api/v1/poc/status/{verification_id}`

---

## 9. 超级智能体

### 执行超级智能体任务

**POST** `/api/v1/super-agent/execute`

请求体：
```json
{
  "objective": "对目标进行全面渗透测试并生成报告",
  "target": "https://example.com",
  "max_iterations": 10,
  "use_sandbox": true,
  "ai_enabled": true
}
```

### 获取超级智能体能力

**GET** `/api/v1/super-agent/capabilities`

### 获取执行历史

**GET** `/api/v1/super-agent/history`

---

## 10. AI工具集

### 代码生成

**POST** `/api/v1/ai/code-generate`

请求体：
```json
{
  "prompt": "写一个Python端口扫描器",
  "language": "python",
  "max_tokens": 2048
}
```

### 代码审查

**POST** `/api/v1/ai/code-review`

请求体：
```json
{
  "code": "def login(username, password): ...",
  "language": "python",
  "focus": ["security", "performance"]
}
```

### 文档分析

**POST** `/api/v1/ai/document-analysis`

### 数据分析

**POST** `/api/v1/ai/data-analysis`

### 知识查询

**POST** `/api/v1/ai/knowledge-query`

### 任务规划

**POST** `/api/v1/ai/task-planning`

### 报告生成

**POST** `/api/v1/ai/report-generate`

---

## 11. 数据库管理

### 任务数据查询

**GET** `/api/v1/db/tasks`

### 发现数据查询

**GET** `/api/v1/db/findings`

### 报告数据查询

**GET** `/api/v1/db/reports`

### 统计数据

**GET** `/api/v1/db/stats`

---

## 12. 用户管理

### 用户列表

**GET** `/api/v1/users`

### 创建用户

**POST** `/api/v1/users`

请求体：
```json
{
  "username": "newuser",
  "email": "user@example.com",
  "password": "SecurePass123!",
  "role": "analyst",
  "full_name": "Test User"
}
```

### 更新用户

**PUT** `/api/v1/users/{user_id}`

### 删除用户

**DELETE** `/api/v1/users/{user_id}`

### 审计日志

**GET** `/api/v1/audit-logs`

查询参数：
- `username`：按用户筛选
- `action`：按操作筛选
- `severity`：按严重程度筛选
- `limit`：返回数量

---

## 13. 插件系统

### 插件列表

**GET** `/api/v1/plugins`

### 安装插件

**POST** `/api/v1/plugins/install`

请求体：
```json
{
  "plugin_name": "custom-scanner",
  "plugin_path": "/path/to/plugin",
  "config": {}
}
```

### 启用/禁用插件

**POST** `/api/v1/plugins/{plugin_id}/toggle`

### 卸载插件

**DELETE** `/api/v1/plugins/{plugin_id}`

---

## 14. 渗透测试

### 执行渗透测试

**POST** `/api/v1/pentest/execute`

请求体：
```json
{
  "target": "https://example.com",
  "target_type": "url",
  "scope": "full",
  "use_ai": true,
  "use_sandbox": false,
  "max_duration": 3600
}
```

### 渗透测试操作

**POST** `/api/v1/pentest/actions`

请求体：
```json
{
  "session_id": "pentest-abc123",
  "action": "next_step",
  "params": {}
}
```

---

## 15. 企业级增强

### 执行企业级任务

**POST** `/api/v1/enterprise/execute`

### 企业级操作

**POST** `/api/v1/enterprise/actions`

---

## 16. 告警通知

### 获取告警列表

**GET** `/api/v1/alerts`

查询参数：
- `severity`：严重程度
- `status`：状态（active/acknowledged/resolved）
- `limit`：返回数量

### 确认告警

**POST** `/api/v1/alerts/{alert_id}/acknowledge`

### 解决告警

**POST** `/api/v1/alerts/{alert_id}/resolve`

---

## 17. 数据备份

### 创建备份

**POST** `/api/v1/backup/create`

响应：
```json
{
  "backup_id": "backup-20260830-220000",
  "status": "creating",
  "size": 0,
  "created_at": "2026-08-30T22:00:00Z"
}
```

### 备份列表

**GET** `/api/v1/backup/list`

### 恢复备份

**POST** `/api/v1/backup/restore/{backup_id}`

### 删除备份

**DELETE** `/api/v1/backup/{backup_id}`

---

## 18. 漏洞数据库

### 漏洞列表

**GET** `/api/v1/vuln-database`

查询参数：
- `keyword`：搜索关键词
- `severity`：严重程度
- `vendor`：厂商
- `product`：产品
- `limit`：返回数量

### 漏洞详情

**GET** `/api/v1/vuln-database/{vuln_id}`

### 同步漏洞数据库

**POST** `/api/v1/vuln-database/sync`

### 漏洞数据库统计

**GET** `/api/v1/vuln-database/stats`

---

## 19. 工作流

### 创建工作流

**POST** `/api/v1/workflow/create`

请求体：
```json
{
  "name": "标准渗透测试流程",
  "target": "https://example.com",
  "target_type": "url",
  "use_sandbox": false,
  "ai_enabled": true,
  "auto_continue": true
}
```

### 工作流列表

**GET** `/api/v1/workflow/list`

### 工作流详情

**GET** `/api/v1/workflow/{workflow_id}`

### 运行工作流

**POST** `/api/v1/workflow/{workflow_id}/run`

### 取消工作流

**POST** `/api/v1/workflow/{workflow_id}/cancel`

### 审核步骤

**POST** `/api/v1/workflow/{workflow_id}/review`

请求体：
```json
{
  "step_id": "step-019",
  "decision": "approve",
  "comment": "确认在授权范围内，可以执行"
}
```

---

## 20. WebSocket

### 任务实时日志

**WS** `/ws/tasks/{task_id}`

连接后实时接收任务执行日志和状态更新。

消息格式：
```json
{
  "type": "log",
  "timestamp": "2026-08-30T22:00:00Z",
  "level": "INFO",
  "message": "开始端口扫描...",
  "task_id": "task-abc123"
}
```

状态更新消息：
```json
{
  "type": "status",
  "task_id": "task-abc123",
  "old_status": "running",
  "new_status": "completed",
  "timestamp": "2026-08-30T22:05:00Z"
}
```

---

## 错误响应格式

所有API错误响应统一格式：

```json
{
  "error": {
    "code": "VALIDATION_ERROR",
    "message": "参数验证失败",
    "details": {
      "field": "target",
      "reason": "target不能为空"
    },
    "timestamp": "2026-08-30T22:00:00Z"
  }
}
```

### 常见错误码

| HTTP状态码 | 错误码 | 说明 |
|-----------|--------|------|
| 400 | VALIDATION_ERROR | 参数验证失败 |
| 401 | UNAUTHORIZED | 未认证或认证失败 |
| 403 | FORBIDDEN | 无权限访问 |
| 404 | NOT_FOUND | 资源不存在 |
| 409 | CONFLICT | 资源冲突 |
| 429 | RATE_LIMITED | 请求频率超限 |
| 500 | INTERNAL_ERROR | 服务器内部错误 |

---

## 速率限制

- API Key认证：100请求/分钟
- JWT认证：60请求/分钟
- 未认证：10请求/分钟

超出限制返回429状态码。

---

## 版本历史

| 版本 | 日期 | 说明 |
|------|------|------|
| v6.0 | 2026-08-30 | 企业级增强，超级智能体，AI工具集，工作流引擎 |
| v5.0 | 2026-08-15 | 云安全，移动安全，企业审计，插件系统 |
| v4.0 | 2026-07-01 | 多智能体协作，知识库，PoC验证 |
| v3.0 | 2026-06-01 | Web界面，报告生成，用户管理 |
| v2.0 | 2026-05-01 | API服务，任务管理，工具调用 |
| v1.0 | 2026-04-01 | 初始版本，核心扫描功能 |

---

*文档生成时间：2026-08-30*
*交互式API文档：http://127.0.0.1:8000/docs*
