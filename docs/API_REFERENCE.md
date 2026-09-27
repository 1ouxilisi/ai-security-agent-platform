# AI Hacking Agent API 参考文档

> 自动生成时间：2026-09-12 17:32:33  
> 版本：4.0.0  
> 端点总数：**439**  

## 通用说明

- **基础 URL**：`http://<host>:<port>`（本地默认 `http://127.0.0.1:8000`）
- **认证方式**：在请求头中携带 `X-API-Key: <API_AUTH_KEY>`
- **请求格式**：JSON（`Content-Type: application/json`）
- **响应格式**：统一 JSON，错误时 `{"detail": "..."}`
- **错误码**：200 成功 / 400 参数错误 / 401 未认证 / 403 无权限 / 404 不存在 / 422 校验失败 / 500 服务器错误

## 目录

- [AI工具集](#ai工具集)（8 个端点）
- [POC验证](#poc验证)（2 个端点）
- [一键安全评估](#一键安全评估)（6 个端点）
- [任务管理](#任务管理)（6 个端点）
- [企业级增强](#企业级增强)（2 个端点）
- [全域安全评估](#全域安全评估)（10 个端点）
- [内网渗透](#内网渗透)（20 个端点）
- [分布式扫描](#分布式扫描)（20 个端点）
- [前端页面](#前端页面)（1 个端点）
- [协作](#协作)（15 个端点）
- [告警通知](#告警通知)（10 个端点）
- [商业化管理](#商业化管理)（23 个端点）
- [增强模块](#增强模块)（31 个端点）
- [实战能力](#实战能力)（22 个端点）
- [工作流](#工作流)（11 个端点）
- [工具调用](#工具调用)（2 个端点）
- [工具集成](#工具集成)（14 个端点）
- [扩展安全模块](#扩展安全模块)（22 个端点）
- [报告](#报告)（1 个端点）
- [报告管理](#报告管理)（7 个端点）
- [插件系统](#插件系统)（5 个端点）
- [数据分析](#数据分析)（9 个端点）
- [数据备份](#数据备份)（8 个端点）
- [数据库](#数据库)（5 个端点）
- [新手引导](#新手引导)（3 个端点）
- [新领域安全](#新领域安全)（13 个端点）
- [智能体](#智能体)（2 个端点）
- [渗透测试](#渗透测试)（2 个端点）
- [漏洞利用](#漏洞利用)（16 个端点）
- [漏洞数据库](#漏洞数据库)（18 个端点）
- [用户管理](#用户管理)（6 个端点）
- [用户认证](#用户认证)（8 个端点）
- [监控](#监控)（14 个端点）
- [知识库](#知识库)（3 个端点）
- [系统](#系统)（4 个端点）
- [统一平台控制台](#统一平台控制台)（6 个端点）
- [超级智能体](#超级智能体)（3 个端点）
- [防御中心](#防御中心)（10 个端点）
- [集成管理](#集成管理)（21 个端点）
- [高级安全](#高级安全)（22 个端点）
- [高级安全模块](#高级安全模块)（28 个端点）


## AI工具集

本模块共 8 个端点。

### 🟢 `GET /api/v1/ai/tools`

Ai Tools List

**请求参数：**

（无请求参数）

**调用示例：**

```bash
curl -X GET 'http://<host>/api/v1/ai/tools' \ \
  -H 'X-API-Key: $API_KEY' \ \
  -H 'Content-Type: application/json'
```

### 🔵 `POST /api/v1/ai/code-generate`

Ai Code Generate

**请求参数：**

（无请求参数）

**请求体示例：**

```json
{
  "requirement": "string",
  "language": "string",
  "framework": "string"
}
```

**调用示例：**

```bash
curl -X POST 'http://<host>/api/v1/ai/code-generate' \ \
  -H 'X-API-Key: $API_KEY' \ \
  -H 'Content-Type: application/json' \
  -d '{}'
```

### 🔵 `POST /api/v1/ai/code-review`

Ai Code Review

**请求参数：**

（无请求参数）

**请求体示例：**

```json
{
  "code": "string",
  "language": "string"
}
```

**调用示例：**

```bash
curl -X POST 'http://<host>/api/v1/ai/code-review' \ \
  -H 'X-API-Key: $API_KEY' \ \
  -H 'Content-Type: application/json' \
  -d '{}'
```

### 🔵 `POST /api/v1/ai/document-analyze`

Ai Document Analyze

**请求参数：**

（无请求参数）

**请求体示例：**

```json
{
  "content": "string",
  "doc_type": "string"
}
```

**调用示例：**

```bash
curl -X POST 'http://<host>/api/v1/ai/document-analyze' \ \
  -H 'X-API-Key: $API_KEY' \ \
  -H 'Content-Type: application/json' \
  -d '{}'
```

### 🔵 `POST /api/v1/ai/data-analyze`

Ai Data Analyze

**请求参数：**

（无请求参数）

**请求体示例：**

```json
{
  "data": "string",
  "analysis_type": "string"
}
```

**调用示例：**

```bash
curl -X POST 'http://<host>/api/v1/ai/data-analyze' \ \
  -H 'X-API-Key: $API_KEY' \ \
  -H 'Content-Type: application/json' \
  -d '{}'
```

### 🔵 `POST /api/v1/ai/knowledge-query`

Ai Knowledge Query

**请求参数：**

（无请求参数）

**请求体示例：**

```json
{
  "query": "string",
  "knowledge_type": "string"
}
```

**调用示例：**

```bash
curl -X POST 'http://<host>/api/v1/ai/knowledge-query' \ \
  -H 'X-API-Key: $API_KEY' \ \
  -H 'Content-Type: application/json' \
  -d '{}'
```

### 🔵 `POST /api/v1/ai/task-plan`

Ai Task Plan

**请求参数：**

（无请求参数）

**请求体示例：**

```json
{
  "goal": "string",
  "context": "string"
}
```

**调用示例：**

```bash
curl -X POST 'http://<host>/api/v1/ai/task-plan' \ \
  -H 'X-API-Key: $API_KEY' \ \
  -H 'Content-Type: application/json' \
  -d '{}'
```

### 🔵 `POST /api/v1/ai/report-generate`

Ai Report Generate

**请求参数：**

（无请求参数）

**请求体示例：**

```json
{
  "data": {},
  "report_type": "string"
}
```

**调用示例：**

```bash
curl -X POST 'http://<host>/api/v1/ai/report-generate' \ \
  -H 'X-API-Key: $API_KEY' \ \
  -H 'Content-Type: application/json' \
  -d '{}'
```


## POC验证

本模块共 2 个端点。

### 🔵 `POST /api/v1/poc/verify`

Poc Verify

**请求参数：**

（无请求参数）

**请求体示例：**

```json
{
  "findings": [],
  "task_id": "xxx-xxx"
}
```

**调用示例：**

```bash
curl -X POST 'http://<host>/api/v1/poc/verify' \ \
  -H 'X-API-Key: $API_KEY' \ \
  -H 'Content-Type: application/json' \
  -d '{}'
```

### 🟢 `GET /api/v1/poc/status`

Poc Status

**请求参数：**

（无请求参数）

**调用示例：**

```bash
curl -X GET 'http://<host>/api/v1/poc/status' \ \
  -H 'X-API-Key: $API_KEY' \ \
  -H 'Content-Type: application/json'
```


## 一键安全评估

本模块共 6 个端点。

### 🔵 `POST /api/v1/assessment/start`

Start Assessment

**请求参数：**

（无请求参数）

**请求体示例：**

```json
{
  "target": "example.com",
  "scan_type": "string",
  "async_mode": true
}
```

**调用示例：**

```bash
curl -X POST 'http://<host>/api/v1/assessment/start' \ \
  -H 'X-API-Key: $API_KEY' \ \
  -H 'Content-Type: application/json' \
  -d '{}'
```

### 🟢 `GET /api/v1/assessment/status/{task_id}`

Get Assessment Status

**请求参数：**

| 参数名 | 位置 | 类型 | 必填 | 说明 |
|---|---|---|---|---|
| `task_id` | path | string | ✅ |  |

**调用示例：**

```bash
curl -X GET 'http://<host>/api/v1/assessment/status/{task_id}' \ \
  -H 'X-API-Key: $API_KEY' \ \
  -H 'Content-Type: application/json'
```

### 🟢 `GET /api/v1/assessment/result/{task_id}`

Get Assessment Result

**请求参数：**

| 参数名 | 位置 | 类型 | 必填 | 说明 |
|---|---|---|---|---|
| `task_id` | path | string | ✅ |  |

**调用示例：**

```bash
curl -X GET 'http://<host>/api/v1/assessment/result/{task_id}' \ \
  -H 'X-API-Key: $API_KEY' \ \
  -H 'Content-Type: application/json'
```

### 🟢 `GET /api/v1/assessment/report/{task_id}`

Download Report

**请求参数：**

| 参数名 | 位置 | 类型 | 必填 | 说明 |
|---|---|---|---|---|
| `task_id` | path | string | ✅ |  |

**调用示例：**

```bash
curl -X GET 'http://<host>/api/v1/assessment/report/{task_id}' \ \
  -H 'X-API-Key: $API_KEY' \ \
  -H 'Content-Type: application/json'
```

### 🟢 `GET /api/v1/assessment/tasks`

List Tasks

**请求参数：**

（无请求参数）

**调用示例：**

```bash
curl -X GET 'http://<host>/api/v1/assessment/tasks' \ \
  -H 'X-API-Key: $API_KEY' \ \
  -H 'Content-Type: application/json'
```

### 🟢 `GET /api/v1/assessment/tools/status`

Get Tools Status

**请求参数：**

（无请求参数）

**调用示例：**

```bash
curl -X GET 'http://<host>/api/v1/assessment/tools/status' \ \
  -H 'X-API-Key: $API_KEY' \ \
  -H 'Content-Type: application/json'
```


## 任务管理

本模块共 6 个端点。

### 🔵 `POST /api/v1/tasks`

Create Task

**请求参数：**

（无请求参数）

**请求体示例：**

```json
{
  "target": "example.com",
  "task_type": "string",
  "description": "string",
  "options": {}
}
```

**调用示例：**

```bash
curl -X POST 'http://<host>/api/v1/tasks' \ \
  -H 'X-API-Key: $API_KEY' \ \
  -H 'Content-Type: application/json' \
  -d '{}'
```

### 🟢 `GET /api/v1/tasks`

List Tasks

**请求参数：**

| 参数名 | 位置 | 类型 | 必填 | 说明 |
|---|---|---|---|---|
| `status` | query | any | — |  |
| `limit` | query | integer | — |  |

**调用示例：**

```bash
curl -X GET 'http://<host>/api/v1/tasks' \ \
  -H 'X-API-Key: $API_KEY' \ \
  -H 'Content-Type: application/json'
```

### 🟢 `GET /api/v1/tasks/{task_id}`

Get Task

**请求参数：**

| 参数名 | 位置 | 类型 | 必填 | 说明 |
|---|---|---|---|---|
| `task_id` | path | string | ✅ |  |

**调用示例：**

```bash
curl -X GET 'http://<host>/api/v1/tasks/{task_id}' \ \
  -H 'X-API-Key: $API_KEY' \ \
  -H 'Content-Type: application/json'
```

### 🔴 `DELETE /api/v1/tasks/{task_id}`

Delete Task

**请求参数：**

| 参数名 | 位置 | 类型 | 必填 | 说明 |
|---|---|---|---|---|
| `task_id` | path | string | ✅ |  |

**调用示例：**

```bash
curl -X DELETE 'http://<host>/api/v1/tasks/{task_id}' \ \
  -H 'X-API-Key: $API_KEY' \ \
  -H 'Content-Type: application/json'
```

### 🟢 `GET /api/v1/tasks/{task_id}/logs`

Get Task Logs

**请求参数：**

| 参数名 | 位置 | 类型 | 必填 | 说明 |
|---|---|---|---|---|
| `task_id` | path | string | ✅ |  |

**调用示例：**

```bash
curl -X GET 'http://<host>/api/v1/tasks/{task_id}/logs' \ \
  -H 'X-API-Key: $API_KEY' \ \
  -H 'Content-Type: application/json'
```

### 🟢 `GET /api/v1/tasks/{task_id}/result`

Get Task Result

**请求参数：**

| 参数名 | 位置 | 类型 | 必填 | 说明 |
|---|---|---|---|---|
| `task_id` | path | string | ✅ |  |

**调用示例：**

```bash
curl -X GET 'http://<host>/api/v1/tasks/{task_id}/result' \ \
  -H 'X-API-Key: $API_KEY' \ \
  -H 'Content-Type: application/json'
```


## 企业级增强

本模块共 2 个端点。

### 🔵 `POST /api/v1/enterprise/execute`

Execute Enterprise

**请求参数：**

（无请求参数）

**请求体示例：**

```json
{
  "action": "string",
  "keyword": "string",
  "cve_id": "xxx-xxx",
  "severity": "string",
  "target": "example.com",
  "standard": "string",
  "limit": "string"
}
```

**调用示例：**

```bash
curl -X POST 'http://<host>/api/v1/enterprise/execute' \ \
  -H 'X-API-Key: $API_KEY' \ \
  -H 'Content-Type: application/json' \
  -d '{}'
```

### 🟢 `GET /api/v1/enterprise/actions`

List Enterprise Actions

**请求参数：**

（无请求参数）

**调用示例：**

```bash
curl -X GET 'http://<host>/api/v1/enterprise/actions' \ \
  -H 'X-API-Key: $API_KEY' \ \
  -H 'Content-Type: application/json'
```


## 全域安全评估

本模块共 10 个端点。

### 🔵 `POST /api/v1/unified/assessment`

创建并执行全域评估

**请求参数：**

（无请求参数）

**请求体示例：**

```json
{
  "target": "example.com",
  "assessment_type": "string",
  "domains": "string",
  "options": "string"
}
```

**调用示例：**

```bash
curl -X POST 'http://<host>/api/v1/unified/assessment' \ \
  -H 'X-API-Key: $API_KEY' \ \
  -H 'Content-Type: application/json' \
  -d '{}'
```

### 🟢 `GET /api/v1/unified/assessment/{assessment_id}`

获取评估结果

**请求参数：**

| 参数名 | 位置 | 类型 | 必填 | 说明 |
|---|---|---|---|---|
| `assessment_id` | path | string | ✅ |  |

**调用示例：**

```bash
curl -X GET 'http://<host>/api/v1/unified/assessment/{assessment_id}' \ \
  -H 'X-API-Key: $API_KEY' \ \
  -H 'Content-Type: application/json'
```

### 🟢 `GET /api/v1/unified/assessments`

获取评估历史列表

**请求参数：**

| 参数名 | 位置 | 类型 | 必填 | 说明 |
|---|---|---|---|---|
| `limit` | query | integer | — | 返回数量上限 |

**调用示例：**

```bash
curl -X GET 'http://<host>/api/v1/unified/assessments' \ \
  -H 'X-API-Key: $API_KEY' \ \
  -H 'Content-Type: application/json'
```

### 🟢 `GET /api/v1/unified/domains`

获取可用领域列表

**请求参数：**

（无请求参数）

**调用示例：**

```bash
curl -X GET 'http://<host>/api/v1/unified/domains' \ \
  -H 'X-API-Key: $API_KEY' \ \
  -H 'Content-Type: application/json'
```

### 🟢 `GET /api/v1/unified/knowledge/stats`

获取知识库统计

**请求参数：**

（无请求参数）

**调用示例：**

```bash
curl -X GET 'http://<host>/api/v1/unified/knowledge/stats' \ \
  -H 'X-API-Key: $API_KEY' \ \
  -H 'Content-Type: application/json'
```

### 🟢 `GET /api/v1/unified/knowledge/search`

搜索知识库

**请求参数：**

| 参数名 | 位置 | 类型 | 必填 | 说明 |
|---|---|---|---|---|
| `keyword` | query | string | ✅ | 搜索关键词 |

**调用示例：**

```bash
curl -X GET 'http://<host>/api/v1/unified/knowledge/search' \ \
  -H 'X-API-Key: $API_KEY' \ \
  -H 'Content-Type: application/json'
```

### 🟢 `GET /api/v1/unified/knowledge/{domain}`

获取指定领域Top漏洞知识库

**请求参数：**

| 参数名 | 位置 | 类型 | 必填 | 说明 |
|---|---|---|---|---|
| `domain` | path | string | ✅ |  |

**调用示例：**

```bash
curl -X GET 'http://<host>/api/v1/unified/knowledge/{domain}' \ \
  -H 'X-API-Key: $API_KEY' \ \
  -H 'Content-Type: application/json'
```

### 🔵 `POST /api/v1/unified/report/generate`

生成报告

**请求参数：**

（无请求参数）

**请求体示例：**

```json
{
  "assessment_id": "xxx-xxx",
  "format": "string",
  "title": "string"
}
```

**调用示例：**

```bash
curl -X POST 'http://<host>/api/v1/unified/report/generate' \ \
  -H 'X-API-Key: $API_KEY' \ \
  -H 'Content-Type: application/json' \
  -d '{}'
```

### 🟢 `GET /api/v1/unified/report/{assessment_id}`

下载报告

**请求参数：**

| 参数名 | 位置 | 类型 | 必填 | 说明 |
|---|---|---|---|---|
| `assessment_id` | path | string | ✅ |  |
| `format` | query | string | — | 报告格式: html/markdown/json |

**调用示例：**

```bash
curl -X GET 'http://<host>/api/v1/unified/report/{assessment_id}' \ \
  -H 'X-API-Key: $API_KEY' \ \
  -H 'Content-Type: application/json'
```

### 🟢 `GET /api/v1/unified/stats`

获取统一框架统计

**请求参数：**

（无请求参数）

**调用示例：**

```bash
curl -X GET 'http://<host>/api/v1/unified/stats' \ \
  -H 'X-API-Key: $API_KEY' \ \
  -H 'Content-Type: application/json'
```


## 内网渗透

本模块共 20 个端点。

### 🔵 `POST /api/v1/internal/smb/scan`

SMB端口扫描

**请求参数：**

（无请求参数）

**请求体示例：**

```json
{
  "target": "example.com",
  "ports": "string",
  "timeout": "string",
  "enumerate_shares": "string"
}
```

**调用示例：**

```bash
curl -X POST 'http://<host>/api/v1/internal/smb/scan' \ \
  -H 'X-API-Key: $API_KEY' \ \
  -H 'Content-Type: application/json' \
  -d '{}'
```

### 🔵 `POST /api/v1/internal/smb/enumerate`

SMB共享枚举

**请求参数：**

（无请求参数）

**请求体示例：**

```json
{
  "target": "example.com",
  "ports": "string",
  "timeout": "string",
  "enumerate_shares": "string"
}
```

**调用示例：**

```bash
curl -X POST 'http://<host>/api/v1/internal/smb/enumerate' \ \
  -H 'X-API-Key: $API_KEY' \ \
  -H 'Content-Type: application/json' \
  -d '{}'
```

### 🟢 `GET /api/v1/internal/smb/stats`

SMB扫描统计

**请求参数：**

（无请求参数）

**调用示例：**

```bash
curl -X GET 'http://<host>/api/v1/internal/smb/stats' \ \
  -H 'X-API-Key: $API_KEY' \ \
  -H 'Content-Type: application/json'
```

### 🔵 `POST /api/v1/internal/ldap/query`

LDAP查询

**请求参数：**

（无请求参数）

**请求体示例：**

```json
{
  "server": "string",
  "domain": "string",
  "username": "string",
  "password": "string",
  "filter": "string",
  "base_dn": "string"
}
```

**调用示例：**

```bash
curl -X POST 'http://<host>/api/v1/internal/ldap/query' \ \
  -H 'X-API-Key: $API_KEY' \ \
  -H 'Content-Type: application/json' \
  -d '{}'
```

### 🟢 `GET /api/v1/internal/ldap/filters`

获取LDAP过滤器列表

**请求参数：**

（无请求参数）

**调用示例：**

```bash
curl -X GET 'http://<host>/api/v1/internal/ldap/filters' \ \
  -H 'X-API-Key: $API_KEY' \ \
  -H 'Content-Type: application/json'
```

### 🔵 `POST /api/v1/internal/kerberos/kerberoast`

Kerberoasting攻击

**请求参数：**

（无请求参数）

**请求体示例：**

```json
{
  "domain": "string",
  "dc_ip": "string",
  "username": "string",
  "password": "string",
  "target_users": "string"
}
```

**调用示例：**

```bash
curl -X POST 'http://<host>/api/v1/internal/kerberos/kerberoast' \ \
  -H 'X-API-Key: $API_KEY' \ \
  -H 'Content-Type: application/json' \
  -d '{}'
```

### 🔵 `POST /api/v1/internal/kerberos/asrep-roast`

AS-REP Roasting攻击

**请求参数：**

（无请求参数）

**请求体示例：**

```json
{
  "domain": "string",
  "dc_ip": "string",
  "username": "string",
  "password": "string",
  "target_users": "string"
}
```

**调用示例：**

```bash
curl -X POST 'http://<host>/api/v1/internal/kerberos/asrep-roast' \ \
  -H 'X-API-Key: $API_KEY' \ \
  -H 'Content-Type: application/json' \
  -d '{}'
```

### 🔵 `POST /api/v1/internal/kerberos/golden-ticket`

创建黄金票据

**请求参数：**

（无请求参数）

**请求体示例：**

```json
{
  "domain": "string",
  "dc_ip": "string",
  "username": "string",
  "password": "string",
  "target_users": "string"
}
```

**调用示例：**

```bash
curl -X POST 'http://<host>/api/v1/internal/kerberos/golden-ticket' \ \
  -H 'X-API-Key: $API_KEY' \ \
  -H 'Content-Type: application/json' \
  -d '{}'
```

### 🔵 `POST /api/v1/internal/hash-pass`

哈希传递攻击

**请求参数：**

（无请求参数）

**请求体示例：**

```json
{
  "target": "example.com",
  "username": "string",
  "ntlm_hash": "string",
  "domain": "string",
  "protocol": "string",
  "command": "string"
}
```

**调用示例：**

```bash
curl -X POST 'http://<host>/api/v1/internal/hash-pass' \ \
  -H 'X-API-Key: $API_KEY' \ \
  -H 'Content-Type: application/json' \
  -d '{}'
```

### 🟢 `GET /api/v1/internal/hash-pass/protocols`

获取支持的哈希传递协议

**请求参数：**

（无请求参数）

**调用示例：**

```bash
curl -X GET 'http://<host>/api/v1/internal/hash-pass/protocols' \ \
  -H 'X-API-Key: $API_KEY' \ \
  -H 'Content-Type: application/json'
```

### 🔵 `POST /api/v1/internal/lateral-move`

横向移动

**请求参数：**

（无请求参数）

**请求体示例：**

```json
{
  "target": "example.com",
  "method": "string",
  "command": "string",
  "username": "string",
  "password": "string",
  "ntlm_hash": "string",
  "domain": "string"
}
```

**调用示例：**

```bash
curl -X POST 'http://<host>/api/v1/internal/lateral-move' \ \
  -H 'X-API-Key: $API_KEY' \ \
  -H 'Content-Type: application/json' \
  -d '{}'
```

### 🟢 `GET /api/v1/internal/lateral-move/methods`

获取支持的横向移动方法

**请求参数：**

（无请求参数）

**调用示例：**

```bash
curl -X GET 'http://<host>/api/v1/internal/lateral-move/methods' \ \
  -H 'X-API-Key: $API_KEY' \ \
  -H 'Content-Type: application/json'
```

### 🔵 `POST /api/v1/internal/port-forward/start`

启动端口转发

**请求参数：**

（无请求参数）

**请求体示例：**

```json
{
  "local_port": 1,
  "target_host": "string",
  "target_port": 1,
  "forward_type": "string",
  "local_host": "string"
}
```

**调用示例：**

```bash
curl -X POST 'http://<host>/api/v1/internal/port-forward/start' \ \
  -H 'X-API-Key: $API_KEY' \ \
  -H 'Content-Type: application/json' \
  -d '{}'
```

### 🔵 `POST /api/v1/internal/port-forward/stop/{session_id}`

停止端口转发

**请求参数：**

| 参数名 | 位置 | 类型 | 必填 | 说明 |
|---|---|---|---|---|
| `session_id` | path | string | ✅ |  |

**调用示例：**

```bash
curl -X POST 'http://<host>/api/v1/internal/port-forward/stop/{session_id}' \ \
  -H 'X-API-Key: $API_KEY' \ \
  -H 'Content-Type: application/json'
```

### 🟢 `GET /api/v1/internal/port-forward/sessions`

列出端口转发会话

**请求参数：**

（无请求参数）

**调用示例：**

```bash
curl -X GET 'http://<host>/api/v1/internal/port-forward/sessions' \ \
  -H 'X-API-Key: $API_KEY' \ \
  -H 'Content-Type: application/json'
```

### 🔵 `POST /api/v1/internal/dns/query`

DNS查询

**请求参数：**

（无请求参数）

**请求体示例：**

```json
{
  "domain": "string",
  "record_type": "string",
  "wordlist": "string"
}
```

**调用示例：**

```bash
curl -X POST 'http://<host>/api/v1/internal/dns/query' \ \
  -H 'X-API-Key: $API_KEY' \ \
  -H 'Content-Type: application/json' \
  -d '{}'
```

### 🔵 `POST /api/v1/internal/dns/subdomains`

子域名枚举

**请求参数：**

（无请求参数）

**请求体示例：**

```json
{
  "domain": "string",
  "record_type": "string",
  "wordlist": "string"
}
```

**调用示例：**

```bash
curl -X POST 'http://<host>/api/v1/internal/dns/subdomains' \ \
  -H 'X-API-Key: $API_KEY' \ \
  -H 'Content-Type: application/json' \
  -d '{}'
```

### 🔵 `POST /api/v1/internal/ad/assess`

AD域安全评估

**请求参数：**

（无请求参数）

**请求体示例：**

```json
{
  "domain": "string",
  "dc_ip": "string",
  "username": "string",
  "password": "string"
}
```

**调用示例：**

```bash
curl -X POST 'http://<host>/api/v1/internal/ad/assess' \ \
  -H 'X-API-Key: $API_KEY' \ \
  -H 'Content-Type: application/json' \
  -d '{}'
```

### 🟢 `GET /api/v1/internal/ad/vulnerabilities`

获取已知AD漏洞列表

**请求参数：**

（无请求参数）

**调用示例：**

```bash
curl -X GET 'http://<host>/api/v1/internal/ad/vulnerabilities' \ \
  -H 'X-API-Key: $API_KEY' \ \
  -H 'Content-Type: application/json'
```

### 🟢 `GET /api/v1/internal/overview`

内网渗透模块总览

**请求参数：**

（无请求参数）

**调用示例：**

```bash
curl -X GET 'http://<host>/api/v1/internal/overview' \ \
  -H 'X-API-Key: $API_KEY' \ \
  -H 'Content-Type: application/json'
```


## 分布式扫描

本模块共 20 个端点。

### 🔵 `POST /api/v1/distributed/tasks/submit`

提交分布式任务

**请求参数：**

（无请求参数）

**请求体示例：**

```json
{
  "task_type": "string",
  "payload": {},
  "priority": 0,
  "max_retries": 0,
  "timeout": 0,
  "dependencies": [],
  "tags": []
}
```

**调用示例：**

```bash
curl -X POST 'http://<host>/api/v1/distributed/tasks/submit' \ \
  -H 'X-API-Key: $API_KEY' \ \
  -H 'Content-Type: application/json' \
  -d '{}'
```

### 🟢 `GET /api/v1/distributed/tasks`

列出所有任务

**请求参数：**

| 参数名 | 位置 | 类型 | 必填 | 说明 |
|---|---|---|---|---|
| `status` | query | string | — |  |

**调用示例：**

```bash
curl -X GET 'http://<host>/api/v1/distributed/tasks' \ \
  -H 'X-API-Key: $API_KEY' \ \
  -H 'Content-Type: application/json'
```

### 🟢 `GET /api/v1/distributed/tasks/{task_id}`

获取任务详情

**请求参数：**

| 参数名 | 位置 | 类型 | 必填 | 说明 |
|---|---|---|---|---|
| `task_id` | path | string | ✅ |  |

**调用示例：**

```bash
curl -X GET 'http://<host>/api/v1/distributed/tasks/{task_id}' \ \
  -H 'X-API-Key: $API_KEY' \ \
  -H 'Content-Type: application/json'
```

### 🔵 `POST /api/v1/distributed/tasks/{task_id}/cancel`

取消任务

**请求参数：**

| 参数名 | 位置 | 类型 | 必填 | 说明 |
|---|---|---|---|---|
| `task_id` | path | string | ✅ |  |

**调用示例：**

```bash
curl -X POST 'http://<host>/api/v1/distributed/tasks/{task_id}/cancel' \ \
  -H 'X-API-Key: $API_KEY' \ \
  -H 'Content-Type: application/json'
```

### 🔵 `POST /api/v1/distributed/workers/register`

注册工作节点

**请求参数：**

（无请求参数）

**请求体示例：**

```json
{
  "hostname": "string",
  "ip": "example.com",
  "port": 1,
  "capabilities": [],
  "max_tasks": 0
}
```

**调用示例：**

```bash
curl -X POST 'http://<host>/api/v1/distributed/workers/register' \ \
  -H 'X-API-Key: $API_KEY' \ \
  -H 'Content-Type: application/json' \
  -d '{}'
```

### 🔵 `POST /api/v1/distributed/workers/heartbeat`

工作节点心跳

**请求参数：**

（无请求参数）

**请求体示例：**

```json
{
  "worker_id": "xxx-xxx",
  "cpu_usage": 0.0,
  "memory_usage": 0.0,
  "current_tasks": 0
}
```

**调用示例：**

```bash
curl -X POST 'http://<host>/api/v1/distributed/workers/heartbeat' \ \
  -H 'X-API-Key: $API_KEY' \ \
  -H 'Content-Type: application/json' \
  -d '{}'
```

### 🟢 `GET /api/v1/distributed/workers`

列出工作节点

**请求参数：**

| 参数名 | 位置 | 类型 | 必填 | 说明 |
|---|---|---|---|---|
| `status` | query | string | — |  |

**调用示例：**

```bash
curl -X GET 'http://<host>/api/v1/distributed/workers' \ \
  -H 'X-API-Key: $API_KEY' \ \
  -H 'Content-Type: application/json'
```

### 🟢 `GET /api/v1/distributed/workers/stats`

工作节点统计

**请求参数：**

（无请求参数）

**调用示例：**

```bash
curl -X GET 'http://<host>/api/v1/distributed/workers/stats' \ \
  -H 'X-API-Key: $API_KEY' \ \
  -H 'Content-Type: application/json'
```

### 🔴 `DELETE /api/v1/distributed/workers/{worker_id}`

注销工作节点

**请求参数：**

| 参数名 | 位置 | 类型 | 必填 | 说明 |
|---|---|---|---|---|
| `worker_id` | path | string | ✅ |  |

**调用示例：**

```bash
curl -X DELETE 'http://<host>/api/v1/distributed/workers/{worker_id}' \ \
  -H 'X-API-Key: $API_KEY' \ \
  -H 'Content-Type: application/json'
```

### 🔵 `POST /api/v1/distributed/results/aggregate`

汇总扫描结果

**请求参数：**

（无请求参数）

**请求体示例：**

```json
{
  "task_id": "xxx-xxx",
  "worker_id": "xxx-xxx",
  "scan_data": {}
}
```

**调用示例：**

```bash
curl -X POST 'http://<host>/api/v1/distributed/results/aggregate' \ \
  -H 'X-API-Key: $API_KEY' \ \
  -H 'Content-Type: application/json' \
  -d '{}'
```

### 🟢 `GET /api/v1/distributed/results/{task_id}`

获取汇总结果

**请求参数：**

| 参数名 | 位置 | 类型 | 必填 | 说明 |
|---|---|---|---|---|
| `task_id` | path | string | ✅ |  |

**调用示例：**

```bash
curl -X GET 'http://<host>/api/v1/distributed/results/{task_id}' \ \
  -H 'X-API-Key: $API_KEY' \ \
  -H 'Content-Type: application/json'
```

### 🟢 `GET /api/v1/distributed/results/{task_id}/summary`

获取漏洞摘要

**请求参数：**

| 参数名 | 位置 | 类型 | 必填 | 说明 |
|---|---|---|---|---|
| `task_id` | path | string | ✅ |  |

**调用示例：**

```bash
curl -X GET 'http://<host>/api/v1/distributed/results/{task_id}/summary' \ \
  -H 'X-API-Key: $API_KEY' \ \
  -H 'Content-Type: application/json'
```

### 🟢 `GET /api/v1/distributed/results/{task_id}/worker-contributions`

获取工作节点贡献

**请求参数：**

| 参数名 | 位置 | 类型 | 必填 | 说明 |
|---|---|---|---|---|
| `task_id` | path | string | ✅ |  |

**调用示例：**

```bash
curl -X GET 'http://<host>/api/v1/distributed/results/{task_id}/worker-contributions' \ \
  -H 'X-API-Key: $API_KEY' \ \
  -H 'Content-Type: application/json'
```

### 🟢 `GET /api/v1/distributed/results/stats`

汇总统计

**请求参数：**

（无请求参数）

**调用示例：**

```bash
curl -X GET 'http://<host>/api/v1/distributed/results/stats' \ \
  -H 'X-API-Key: $API_KEY' \ \
  -H 'Content-Type: application/json'
```

### 🔵 `POST /api/v1/distributed/proxies/add`

添加代理

**请求参数：**

（无请求参数）

**请求体示例：**

```json
{
  "host": "example.com",
  "port": 1,
  "proxy_type": "string",
  "username": "string",
  "password": "string",
  "country": "string"
}
```

**调用示例：**

```bash
curl -X POST 'http://<host>/api/v1/distributed/proxies/add' \ \
  -H 'X-API-Key: $API_KEY' \ \
  -H 'Content-Type: application/json' \
  -d '{}'
```

### 🟢 `GET /api/v1/distributed/proxies`

列出代理

**请求参数：**

| 参数名 | 位置 | 类型 | 必填 | 说明 |
|---|---|---|---|---|
| `proxy_type` | query | string | — |  |
| `country` | query | string | — |  |

**调用示例：**

```bash
curl -X GET 'http://<host>/api/v1/distributed/proxies' \ \
  -H 'X-API-Key: $API_KEY' \ \
  -H 'Content-Type: application/json'
```

### 🟢 `GET /api/v1/distributed/proxies/get`

获取可用代理

**请求参数：**

| 参数名 | 位置 | 类型 | 必填 | 说明 |
|---|---|---|---|---|
| `target` | query | string | — |  |
| `strategy` | query | string | — |  |

**调用示例：**

```bash
curl -X GET 'http://<host>/api/v1/distributed/proxies/get' \ \
  -H 'X-API-Key: $API_KEY' \ \
  -H 'Content-Type: application/json'
```

### 🟢 `GET /api/v1/distributed/proxies/stats`

代理池统计

**请求参数：**

（无请求参数）

**调用示例：**

```bash
curl -X GET 'http://<host>/api/v1/distributed/proxies/stats' \ \
  -H 'X-API-Key: $API_KEY' \ \
  -H 'Content-Type: application/json'
```

### 🔴 `DELETE /api/v1/distributed/proxies/{host}/{port}`

移除代理

**请求参数：**

| 参数名 | 位置 | 类型 | 必填 | 说明 |
|---|---|---|---|---|
| `host` | path | string | ✅ |  |
| `port` | path | integer | ✅ |  |

**调用示例：**

```bash
curl -X DELETE 'http://<host>/api/v1/distributed/proxies/{host}/{port}' \ \
  -H 'X-API-Key: $API_KEY' \ \
  -H 'Content-Type: application/json'
```

### 🟢 `GET /api/v1/distributed/overview`

分布式扫描模块总览

**请求参数：**

（无请求参数）

**调用示例：**

```bash
curl -X GET 'http://<host>/api/v1/distributed/overview' \ \
  -H 'X-API-Key: $API_KEY' \ \
  -H 'Content-Type: application/json'
```


## 前端页面

本模块共 1 个端点。

### 🟢 `GET /unified-console`

Unified Console Page

**请求参数：**

（无请求参数）

**调用示例：**

```bash
curl -X GET 'http://<host>/unified-console' \ \
  -H 'X-API-Key: $API_KEY' \ \
  -H 'Content-Type: application/json'
```


## 协作

本模块共 15 个端点。

### 🟢 `GET /api/collaboration/tasks`

List Tasks

**请求参数：**

| 参数名 | 位置 | 类型 | 必填 | 说明 |
|---|---|---|---|---|
| `status` | query | any | — |  |
| `assignee` | query | any | — |  |
| `priority` | query | any | — |  |
| `limit` | query | integer | — |  |

**调用示例：**

```bash
curl -X GET 'http://<host>/api/collaboration/tasks' \ \
  -H 'X-API-Key: $API_KEY' \ \
  -H 'Content-Type: application/json'
```

### 🔵 `POST /api/collaboration/tasks`

Create Task

**请求参数：**

（无请求参数）

**请求体示例：**

```json
{
  "title": "string",
  "description": "string",
  "assignee": "string",
  "priority": "string",
  "due_date": "string",
  "tags": "string",
  "related_assessment_id": "xxx-xxx"
}
```

**调用示例：**

```bash
curl -X POST 'http://<host>/api/collaboration/tasks' \ \
  -H 'X-API-Key: $API_KEY' \ \
  -H 'Content-Type: application/json' \
  -d '{}'
```

### 🟢 `GET /api/collaboration/tasks/stats`

Task Stats

**请求参数：**

| 参数名 | 位置 | 类型 | 必填 | 说明 |
|---|---|---|---|---|
| `user` | query | any | — |  |

**调用示例：**

```bash
curl -X GET 'http://<host>/api/collaboration/tasks/stats' \ \
  -H 'X-API-Key: $API_KEY' \ \
  -H 'Content-Type: application/json'
```

### 🟢 `GET /api/collaboration/tasks/{task_id}`

Get Task

**请求参数：**

| 参数名 | 位置 | 类型 | 必填 | 说明 |
|---|---|---|---|---|
| `task_id` | path | string | ✅ |  |

**调用示例：**

```bash
curl -X GET 'http://<host>/api/collaboration/tasks/{task_id}' \ \
  -H 'X-API-Key: $API_KEY' \ \
  -H 'Content-Type: application/json'
```

### 🟡 `PUT /api/collaboration/tasks/{task_id}`

Update Task

**请求参数：**

| 参数名 | 位置 | 类型 | 必填 | 说明 |
|---|---|---|---|---|
| `task_id` | path | string | ✅ |  |

**请求体示例：**

```json
{
  "title": "string",
  "description": "string",
  "priority": "string",
  "status": "string",
  "due_date": "string",
  "tags": "string",
  "assignee": "string"
}
```

**调用示例：**

```bash
curl -X PUT 'http://<host>/api/collaboration/tasks/{task_id}' \ \
  -H 'X-API-Key: $API_KEY' \ \
  -H 'Content-Type: application/json' \
  -d '{}'
```

### 🔴 `DELETE /api/collaboration/tasks/{task_id}`

Delete Task

**请求参数：**

| 参数名 | 位置 | 类型 | 必填 | 说明 |
|---|---|---|---|---|
| `task_id` | path | string | ✅ |  |

**调用示例：**

```bash
curl -X DELETE 'http://<host>/api/collaboration/tasks/{task_id}' \ \
  -H 'X-API-Key: $API_KEY' \ \
  -H 'Content-Type: application/json'
```

### 🔵 `POST /api/collaboration/tasks/{task_id}/assign`

Assign Task

**请求参数：**

| 参数名 | 位置 | 类型 | 必填 | 说明 |
|---|---|---|---|---|
| `task_id` | path | string | ✅ |  |

**请求体示例：**

```json
{
  "assignee": "string",
  "assigner": "string"
}
```

**调用示例：**

```bash
curl -X POST 'http://<host>/api/collaboration/tasks/{task_id}/assign' \ \
  -H 'X-API-Key: $API_KEY' \ \
  -H 'Content-Type: application/json' \
  -d '{}'
```

### 🟢 `GET /api/collaboration/tasks/{task_id}/comments`

Get Comments

**请求参数：**

| 参数名 | 位置 | 类型 | 必填 | 说明 |
|---|---|---|---|---|
| `task_id` | path | string | ✅ |  |

**调用示例：**

```bash
curl -X GET 'http://<host>/api/collaboration/tasks/{task_id}/comments' \ \
  -H 'X-API-Key: $API_KEY' \ \
  -H 'Content-Type: application/json'
```

### 🔵 `POST /api/collaboration/tasks/{task_id}/comments`

Add Comment

**请求参数：**

| 参数名 | 位置 | 类型 | 必填 | 说明 |
|---|---|---|---|---|
| `task_id` | path | string | ✅ |  |

**请求体示例：**

```json
{
  "user": "string",
  "content": "string"
}
```

**调用示例：**

```bash
curl -X POST 'http://<host>/api/collaboration/tasks/{task_id}/comments' \ \
  -H 'X-API-Key: $API_KEY' \ \
  -H 'Content-Type: application/json' \
  -d '{}'
```

### 🟢 `GET /api/collaboration/notifications`

List Notifications

**请求参数：**

| 参数名 | 位置 | 类型 | 必填 | 说明 |
|---|---|---|---|---|
| `user` | query | string | ✅ |  |
| `status` | query | any | — |  |
| `limit` | query | integer | — |  |

**调用示例：**

```bash
curl -X GET 'http://<host>/api/collaboration/notifications' \ \
  -H 'X-API-Key: $API_KEY' \ \
  -H 'Content-Type: application/json'
```

### 🟢 `GET /api/collaboration/notifications/unread-count`

Unread Count

**请求参数：**

| 参数名 | 位置 | 类型 | 必填 | 说明 |
|---|---|---|---|---|
| `user` | query | string | ✅ |  |

**调用示例：**

```bash
curl -X GET 'http://<host>/api/collaboration/notifications/unread-count' \ \
  -H 'X-API-Key: $API_KEY' \ \
  -H 'Content-Type: application/json'
```

### 🟢 `GET /api/collaboration/notifications/latest`

Latest Notifications

**请求参数：**

| 参数名 | 位置 | 类型 | 必填 | 说明 |
|---|---|---|---|---|
| `user` | query | string | ✅ |  |
| `since` | query | string | — |  |

**调用示例：**

```bash
curl -X GET 'http://<host>/api/collaboration/notifications/latest' \ \
  -H 'X-API-Key: $API_KEY' \ \
  -H 'Content-Type: application/json'
```

### 🔵 `POST /api/collaboration/notifications/{notification_id}/read`

Mark Read

**请求参数：**

| 参数名 | 位置 | 类型 | 必填 | 说明 |
|---|---|---|---|---|
| `notification_id` | path | string | ✅ |  |
| `user` | query | string | ✅ |  |

**调用示例：**

```bash
curl -X POST 'http://<host>/api/collaboration/notifications/{notification_id}/read' \ \
  -H 'X-API-Key: $API_KEY' \ \
  -H 'Content-Type: application/json'
```

### 🔵 `POST /api/collaboration/notifications/read-all`

Mark All Read

**请求参数：**

| 参数名 | 位置 | 类型 | 必填 | 说明 |
|---|---|---|---|---|
| `user` | query | string | ✅ |  |

**调用示例：**

```bash
curl -X POST 'http://<host>/api/collaboration/notifications/read-all' \ \
  -H 'X-API-Key: $API_KEY' \ \
  -H 'Content-Type: application/json'
```

### 🔴 `DELETE /api/collaboration/notifications/{notification_id}`

Delete Notification

**请求参数：**

| 参数名 | 位置 | 类型 | 必填 | 说明 |
|---|---|---|---|---|
| `notification_id` | path | string | ✅ |  |
| `user` | query | string | ✅ |  |

**调用示例：**

```bash
curl -X DELETE 'http://<host>/api/collaboration/notifications/{notification_id}' \ \
  -H 'X-API-Key: $API_KEY' \ \
  -H 'Content-Type: application/json'
```


## 告警通知

本模块共 10 个端点。

### 🔵 `POST /api/v1/alerts`

创建告警

**请求参数：**

（无请求参数）

**请求体示例：**

```json
{
  "title": "string",
  "message": "string",
  "severity": "string",
  "category": "string",
  "target": "example.com",
  "details": "string",
  "auto_notify": true
}
```

**调用示例：**

```bash
curl -X POST 'http://<host>/api/v1/alerts' \ \
  -H 'X-API-Key: $API_KEY' \ \
  -H 'Content-Type: application/json' \
  -d '{}'
```

### 🟢 `GET /api/v1/alerts`

获取告警列表

**请求参数：**

| 参数名 | 位置 | 类型 | 必填 | 说明 |
|---|---|---|---|---|
| `severity` | query | any | — |  |
| `status` | query | any | — |  |
| `category` | query | any | — |  |
| `limit` | query | integer | — |  |

**调用示例：**

```bash
curl -X GET 'http://<host>/api/v1/alerts' \ \
  -H 'X-API-Key: $API_KEY' \ \
  -H 'Content-Type: application/json'
```

### 🟢 `GET /api/v1/alerts/stats`

获取告警统计

**请求参数：**

（无请求参数）

**调用示例：**

```bash
curl -X GET 'http://<host>/api/v1/alerts/stats' \ \
  -H 'X-API-Key: $API_KEY' \ \
  -H 'Content-Type: application/json'
```

### 🔵 `POST /api/v1/alerts/{alert_id}/acknowledge`

确认告警

**请求参数：**

| 参数名 | 位置 | 类型 | 必填 | 说明 |
|---|---|---|---|---|
| `alert_id` | path | string | ✅ |  |

**调用示例：**

```bash
curl -X POST 'http://<host>/api/v1/alerts/{alert_id}/acknowledge' \ \
  -H 'X-API-Key: $API_KEY' \ \
  -H 'Content-Type: application/json'
```

### 🔵 `POST /api/v1/alerts/{alert_id}/notify`

重新发送告警通知

**请求参数：**

| 参数名 | 位置 | 类型 | 必填 | 说明 |
|---|---|---|---|---|
| `alert_id` | path | string | ✅ |  |

**调用示例：**

```bash
curl -X POST 'http://<host>/api/v1/alerts/{alert_id}/notify' \ \
  -H 'X-API-Key: $API_KEY' \ \
  -H 'Content-Type: application/json'
```

### 🟢 `GET /api/v1/alerts/channels`

获取通知渠道列表

**请求参数：**

（无请求参数）

**调用示例：**

```bash
curl -X GET 'http://<host>/api/v1/alerts/channels' \ \
  -H 'X-API-Key: $API_KEY' \ \
  -H 'Content-Type: application/json'
```

### 🔵 `POST /api/v1/alerts/channels`

添加通知渠道

**请求参数：**

（无请求参数）

**请求体示例：**

```json
{
  "name": "string",
  "type": "string",
  "config": {}
}
```

**调用示例：**

```bash
curl -X POST 'http://<host>/api/v1/alerts/channels' \ \
  -H 'X-API-Key: $API_KEY' \ \
  -H 'Content-Type: application/json' \
  -d '{}'
```

### 🔵 `POST /api/v1/alerts/channels/test`

测试通知渠道

**请求参数：**

（无请求参数）

**请求体示例：**

```json
{
  "channel_id": "xxx-xxx"
}
```

**调用示例：**

```bash
curl -X POST 'http://<host>/api/v1/alerts/channels/test' \ \
  -H 'X-API-Key: $API_KEY' \ \
  -H 'Content-Type: application/json' \
  -d '{}'
```

### 🔵 `POST /api/v1/alerts/vulnerability`

创建漏洞告警

**请求参数：**

| 参数名 | 位置 | 类型 | 必填 | 说明 |
|---|---|---|---|---|
| `title` | query | string | ✅ |  |
| `target` | query | string | ✅ |  |
| `severity` | query | string | — |  |

**请求体示例：**

（无请求体）

**调用示例：**

```bash
curl -X POST 'http://<host>/api/v1/alerts/vulnerability' \ \
  -H 'X-API-Key: $API_KEY' \ \
  -H 'Content-Type: application/json'
```

### 🔵 `POST /api/v1/alerts/system`

创建系统告警

**请求参数：**

| 参数名 | 位置 | 类型 | 必填 | 说明 |
|---|---|---|---|---|
| `title` | query | string | ✅ |  |
| `severity` | query | string | — |  |

**请求体示例：**

（无请求体）

**调用示例：**

```bash
curl -X POST 'http://<host>/api/v1/alerts/system' \ \
  -H 'X-API-Key: $API_KEY' \ \
  -H 'Content-Type: application/json'
```


## 商业化管理

本模块共 23 个端点。

### 🟢 `GET /api/v1/commercial/tenants`

租户列表

**请求参数：**

（无请求参数）

**调用示例：**

```bash
curl -X GET 'http://<host>/api/v1/commercial/tenants' \ \
  -H 'X-API-Key: $API_KEY' \ \
  -H 'Content-Type: application/json'
```

### 🔵 `POST /api/v1/commercial/tenants`

创建租户

**请求参数：**

（无请求参数）

**请求体示例：**

```json
{
  "tenant_id": "xxx-xxx",
  "name": "string",
  "plan": "string",
  "quotas": "string"
}
```

**调用示例：**

```bash
curl -X POST 'http://<host>/api/v1/commercial/tenants' \ \
  -H 'X-API-Key: $API_KEY' \ \
  -H 'Content-Type: application/json' \
  -d '{}'
```

### 🟢 `GET /api/v1/commercial/tenants/{tenant_id}`

租户详情

**请求参数：**

| 参数名 | 位置 | 类型 | 必填 | 说明 |
|---|---|---|---|---|
| `tenant_id` | path | string | ✅ |  |

**调用示例：**

```bash
curl -X GET 'http://<host>/api/v1/commercial/tenants/{tenant_id}' \ \
  -H 'X-API-Key: $API_KEY' \ \
  -H 'Content-Type: application/json'
```

### 🟡 `PUT /api/v1/commercial/tenants/{tenant_id}/quota`

更新租户配额

**请求参数：**

| 参数名 | 位置 | 类型 | 必填 | 说明 |
|---|---|---|---|---|
| `tenant_id` | path | string | ✅ |  |

**请求体示例：**

```json
{
  "quota_type": "string",
  "value": 1
}
```

**调用示例：**

```bash
curl -X PUT 'http://<host>/api/v1/commercial/tenants/{tenant_id}/quota' \ \
  -H 'X-API-Key: $API_KEY' \ \
  -H 'Content-Type: application/json' \
  -d '{}'
```

### 🔵 `POST /api/v1/commercial/tenants/{tenant_id}/disable`

禁用租户

**请求参数：**

| 参数名 | 位置 | 类型 | 必填 | 说明 |
|---|---|---|---|---|
| `tenant_id` | path | string | ✅ |  |

**调用示例：**

```bash
curl -X POST 'http://<host>/api/v1/commercial/tenants/{tenant_id}/disable' \ \
  -H 'X-API-Key: $API_KEY' \ \
  -H 'Content-Type: application/json'
```

### 🔵 `POST /api/v1/commercial/tenants/{tenant_id}/enable`

启用租户

**请求参数：**

| 参数名 | 位置 | 类型 | 必填 | 说明 |
|---|---|---|---|---|
| `tenant_id` | path | string | ✅ |  |

**调用示例：**

```bash
curl -X POST 'http://<host>/api/v1/commercial/tenants/{tenant_id}/enable' \ \
  -H 'X-API-Key: $API_KEY' \ \
  -H 'Content-Type: application/json'
```

### 🔵 `POST /api/v1/commercial/billing/subscribe`

订阅计划

**请求参数：**

| 参数名 | 位置 | 类型 | 必填 | 说明 |
|---|---|---|---|---|
| `tenant_id` | query | string | ✅ |  |

**请求体示例：**

```json
{
  "plan": "string",
  "cycle": "string"
}
```

**调用示例：**

```bash
curl -X POST 'http://<host>/api/v1/commercial/billing/subscribe' \ \
  -H 'X-API-Key: $API_KEY' \ \
  -H 'Content-Type: application/json' \
  -d '{}'
```

### 🟢 `GET /api/v1/commercial/billing/subscription/{tenant_id}`

获取订阅

**请求参数：**

| 参数名 | 位置 | 类型 | 必填 | 说明 |
|---|---|---|---|---|
| `tenant_id` | path | string | ✅ |  |

**调用示例：**

```bash
curl -X GET 'http://<host>/api/v1/commercial/billing/subscription/{tenant_id}' \ \
  -H 'X-API-Key: $API_KEY' \ \
  -H 'Content-Type: application/json'
```

### 🔵 `POST /api/v1/commercial/billing/order`

创建订单

**请求参数：**

（无请求参数）

**请求体示例：**

```json
{
  "tenant_id": "xxx-xxx",
  "plan": "string",
  "cycle": "string"
}
```

**调用示例：**

```bash
curl -X POST 'http://<host>/api/v1/commercial/billing/order' \ \
  -H 'X-API-Key: $API_KEY' \ \
  -H 'Content-Type: application/json' \
  -d '{}'
```

### 🔵 `POST /api/v1/commercial/billing/pay/{order_id}`

支付订单（模拟）

**请求参数：**

| 参数名 | 位置 | 类型 | 必填 | 说明 |
|---|---|---|---|---|
| `order_id` | path | string | ✅ |  |

**请求体示例：**

```json
{
  "payment_method": "string"
}
```

**调用示例：**

```bash
curl -X POST 'http://<host>/api/v1/commercial/billing/pay/{order_id}' \ \
  -H 'X-API-Key: $API_KEY' \ \
  -H 'Content-Type: application/json' \
  -d '{}'
```

### 🟢 `GET /api/v1/commercial/billing/usage/{tenant_id}`

获取用量

**请求参数：**

| 参数名 | 位置 | 类型 | 必填 | 说明 |
|---|---|---|---|---|
| `tenant_id` | path | string | ✅ |  |
| `period` | query | any | — |  |

**调用示例：**

```bash
curl -X GET 'http://<host>/api/v1/commercial/billing/usage/{tenant_id}' \ \
  -H 'X-API-Key: $API_KEY' \ \
  -H 'Content-Type: application/json'
```

### 🟢 `GET /api/v1/commercial/billing/invoice/{order_id}`

获取发票

**请求参数：**

| 参数名 | 位置 | 类型 | 必填 | 说明 |
|---|---|---|---|---|
| `order_id` | path | string | ✅ |  |

**调用示例：**

```bash
curl -X GET 'http://<host>/api/v1/commercial/billing/invoice/{order_id}' \ \
  -H 'X-API-Key: $API_KEY' \ \
  -H 'Content-Type: application/json'
```

### 🔵 `POST /api/v1/commercial/api-keys`

创建 API Key

**请求参数：**

（无请求参数）

**请求体示例：**

```json
{
  "tenant_id": "xxx-xxx",
  "username": "string",
  "name": "string",
  "permissions": "string",
  "rate_limit": "string"
}
```

**调用示例：**

```bash
curl -X POST 'http://<host>/api/v1/commercial/api-keys' \ \
  -H 'X-API-Key: $API_KEY' \ \
  -H 'Content-Type: application/json' \
  -d '{}'
```

### 🟢 `GET /api/v1/commercial/api-keys/{tenant_id}`

列出租户 API Key

**请求参数：**

| 参数名 | 位置 | 类型 | 必填 | 说明 |
|---|---|---|---|---|
| `tenant_id` | path | string | ✅ |  |

**调用示例：**

```bash
curl -X GET 'http://<host>/api/v1/commercial/api-keys/{tenant_id}' \ \
  -H 'X-API-Key: $API_KEY' \ \
  -H 'Content-Type: application/json'
```

### 🔴 `DELETE /api/v1/commercial/api-keys/{key_id}`

吊销 API Key

**请求参数：**

| 参数名 | 位置 | 类型 | 必填 | 说明 |
|---|---|---|---|---|
| `key_id` | path | string | ✅ |  |

**调用示例：**

```bash
curl -X DELETE 'http://<host>/api/v1/commercial/api-keys/{key_id}' \ \
  -H 'X-API-Key: $API_KEY' \ \
  -H 'Content-Type: application/json'
```

### 🟢 `GET /api/v1/commercial/api-keys/stats/{key_id}`

Key 调用统计

**请求参数：**

| 参数名 | 位置 | 类型 | 必填 | 说明 |
|---|---|---|---|---|
| `key_id` | path | string | ✅ |  |

**调用示例：**

```bash
curl -X GET 'http://<host>/api/v1/commercial/api-keys/stats/{key_id}' \ \
  -H 'X-API-Key: $API_KEY' \ \
  -H 'Content-Type: application/json'
```

### 🔵 `POST /api/v1/commercial/data/export/{tenant_id}`

导出租户数据

**请求参数：**

| 参数名 | 位置 | 类型 | 必填 | 说明 |
|---|---|---|---|---|
| `tenant_id` | path | string | ✅ |  |

**调用示例：**

```bash
curl -X POST 'http://<host>/api/v1/commercial/data/export/{tenant_id}' \ \
  -H 'X-API-Key: $API_KEY' \ \
  -H 'Content-Type: application/json'
```

### 🔵 `POST /api/v1/commercial/data/delete/{tenant_id}`

彻底删除租户数据

**请求参数：**

| 参数名 | 位置 | 类型 | 必填 | 说明 |
|---|---|---|---|---|
| `tenant_id` | path | string | ✅ |  |

**调用示例：**

```bash
curl -X POST 'http://<host>/api/v1/commercial/data/delete/{tenant_id}' \ \
  -H 'X-API-Key: $API_KEY' \ \
  -H 'Content-Type: application/json'
```

### 🟢 `GET /api/v1/commercial/data/audit/{tenant_id}`

查询审计日志

**请求参数：**

| 参数名 | 位置 | 类型 | 必填 | 说明 |
|---|---|---|---|---|
| `tenant_id` | path | string | ✅ |  |
| `limit` | query | integer | — |  |

**调用示例：**

```bash
curl -X GET 'http://<host>/api/v1/commercial/data/audit/{tenant_id}' \ \
  -H 'X-API-Key: $API_KEY' \ \
  -H 'Content-Type: application/json'
```

### 🔵 `POST /api/v1/commercial/users`

创建租户用户

**请求参数：**

（无请求参数）

**请求体示例：**

```json
{
  "username": "string",
  "password": "string",
  "tenant_id": "xxx-xxx",
  "role": "string",
  "email": "string"
}
```

**调用示例：**

```bash
curl -X POST 'http://<host>/api/v1/commercial/users' \ \
  -H 'X-API-Key: $API_KEY' \ \
  -H 'Content-Type: application/json' \
  -d '{}'
```

### 🟢 `GET /api/v1/commercial/users/{tenant_id}`

列出租户用户

**请求参数：**

| 参数名 | 位置 | 类型 | 必填 | 说明 |
|---|---|---|---|---|
| `tenant_id` | path | string | ✅ |  |

**调用示例：**

```bash
curl -X GET 'http://<host>/api/v1/commercial/users/{tenant_id}' \ \
  -H 'X-API-Key: $API_KEY' \ \
  -H 'Content-Type: application/json'
```

### 🔵 `POST /api/v1/commercial/auth/login`

登录

**请求参数：**

（无请求参数）

**请求体示例：**

```json
{
  "username": "string",
  "password": "string",
  "ip": "example.com",
  "user_agent": "string"
}
```

**调用示例：**

```bash
curl -X POST 'http://<host>/api/v1/commercial/auth/login' \ \
  -H 'X-API-Key: $API_KEY' \ \
  -H 'Content-Type: application/json' \
  -d '{}'
```

### 🔵 `POST /api/v1/commercial/auth/logout`

登出

**请求参数：**

| 参数名 | 位置 | 类型 | 必填 | 说明 |
|---|---|---|---|---|
| `session_token` | query | string | ✅ |  |

**调用示例：**

```bash
curl -X POST 'http://<host>/api/v1/commercial/auth/logout' \ \
  -H 'X-API-Key: $API_KEY' \ \
  -H 'Content-Type: application/json'
```


## 增强模块

本模块共 31 个端点。

### 🔵 `POST /api/v1/enhanced/tools/nmap/scan`

Nmap端口扫描

**请求参数：**

（无请求参数）

**请求体示例：**

```json
{
  "target": "example.com",
  "scan_type": "string",
  "ports": "string",
  "timeout": 0
}
```

**调用示例：**

```bash
curl -X POST 'http://<host>/api/v1/enhanced/tools/nmap/scan' \ \
  -H 'X-API-Key: $API_KEY' \ \
  -H 'Content-Type: application/json' \
  -d '{}'
```

### 🔵 `POST /api/v1/enhanced/tools/sqlmap/scan`

SQLMap注入扫描

**请求参数：**

（无请求参数）

**请求体示例：**

```json
{
  "url": "string",
  "data": "string",
  "cookie": "string",
  "level": 0,
  "risk": 0,
  "timeout": 0
}
```

**调用示例：**

```bash
curl -X POST 'http://<host>/api/v1/enhanced/tools/sqlmap/scan' \ \
  -H 'X-API-Key: $API_KEY' \ \
  -H 'Content-Type: application/json' \
  -d '{}'
```

### 🔵 `POST /api/v1/enhanced/tools/nuclei/scan`

Nuclei漏洞扫描

**请求参数：**

（无请求参数）

**请求体示例：**

```json
{
  "target": "example.com",
  "templates": "string",
  "severity": "string",
  "timeout": 0
}
```

**调用示例：**

```bash
curl -X POST 'http://<host>/api/v1/enhanced/tools/nuclei/scan' \ \
  -H 'X-API-Key: $API_KEY' \ \
  -H 'Content-Type: application/json' \
  -d '{}'
```

### 🟢 `GET /api/v1/enhanced/tools/status`

获取工具状态

**请求参数：**

（无请求参数）

**调用示例：**

```bash
curl -X GET 'http://<host>/api/v1/enhanced/tools/status' \ \
  -H 'X-API-Key: $API_KEY' \ \
  -H 'Content-Type: application/json'
```

### 🔵 `POST /api/v1/enhanced/internal/scan`

内网扫描

**请求参数：**

（无请求参数）

**请求体示例：**

```json
{
  "target": "example.com",
  "scan_type": "string",
  "ports": [],
  "max_workers": 0
}
```

**调用示例：**

```bash
curl -X POST 'http://<host>/api/v1/enhanced/internal/scan' \ \
  -H 'X-API-Key: $API_KEY' \ \
  -H 'Content-Type: application/json' \
  -d '{}'
```

### 🔵 `POST /api/v1/enhanced/internal/smb/enum`

SMB共享枚举

**请求参数：**

（无请求参数）

**请求体示例：**

```json
{
  "ip": "example.com",
  "username": "string",
  "password": "string",
  "domain": "string"
}
```

**调用示例：**

```bash
curl -X POST 'http://<host>/api/v1/enhanced/internal/smb/enum' \ \
  -H 'X-API-Key: $API_KEY' \ \
  -H 'Content-Type: application/json' \
  -d '{}'
```

### 🔵 `POST /api/v1/enhanced/internal/netbios/query`

NetBIOS名称查询

**请求参数：**

| 参数名 | 位置 | 类型 | 必填 | 说明 |
|---|---|---|---|---|
| `ip` | query | string | ✅ | 目标IP |

**调用示例：**

```bash
curl -X POST 'http://<host>/api/v1/enhanced/internal/netbios/query' \ \
  -H 'X-API-Key: $API_KEY' \ \
  -H 'Content-Type: application/json'
```

### 🔵 `POST /api/v1/enhanced/internal/ldap/query`

LDAP域查询

**请求参数：**

（无请求参数）

**请求体示例：**

```json
{
  "dc_ip": "string",
  "username": "string",
  "password": "string",
  "domain": "string",
  "query_type": "string"
}
```

**调用示例：**

```bash
curl -X POST 'http://<host>/api/v1/enhanced/internal/ldap/query' \ \
  -H 'X-API-Key: $API_KEY' \ \
  -H 'Content-Type: application/json' \
  -d '{}'
```

### 🔵 `POST /api/v1/enhanced/cloud/scan`

云安全扫描

**请求参数：**

（无请求参数）

**请求体示例：**

```json
{
  "provider": "xxx-xxx",
  "aws_access_key": "string",
  "aws_secret_key": "string",
  "aws_region": "string"
}
```

**调用示例：**

```bash
curl -X POST 'http://<host>/api/v1/enhanced/cloud/scan' \ \
  -H 'X-API-Key: $API_KEY' \ \
  -H 'Content-Type: application/json' \
  -d '{}'
```

### 🔵 `POST /api/v1/enhanced/cloud/dockerfile/check`

Dockerfile安全检查

**请求参数：**

（无请求参数）

**请求体示例：**

```json
{
  "path": "string"
}
```

**调用示例：**

```bash
curl -X POST 'http://<host>/api/v1/enhanced/cloud/dockerfile/check' \ \
  -H 'X-API-Key: $API_KEY' \ \
  -H 'Content-Type: application/json' \
  -d '{}'
```

### 🔵 `POST /api/v1/enhanced/cloud/k8s/check`

K8s清单安全检查

**请求参数：**

（无请求参数）

**请求体示例：**

```json
{
  "path": "string"
}
```

**调用示例：**

```bash
curl -X POST 'http://<host>/api/v1/enhanced/cloud/k8s/check' \ \
  -H 'X-API-Key: $API_KEY' \ \
  -H 'Content-Type: application/json' \
  -d '{}'
```

### 🟢 `GET /api/v1/enhanced/performance/stats`

获取性能统计

**请求参数：**

（无请求参数）

**调用示例：**

```bash
curl -X GET 'http://<host>/api/v1/enhanced/performance/stats' \ \
  -H 'X-API-Key: $API_KEY' \ \
  -H 'Content-Type: application/json'
```

### 🔵 `POST /api/v1/enhanced/performance/cache/clear`

清空缓存

**请求参数：**

（无请求参数）

**调用示例：**

```bash
curl -X POST 'http://<host>/api/v1/enhanced/performance/cache/clear' \ \
  -H 'X-API-Key: $API_KEY' \ \
  -H 'Content-Type: application/json'
```

### 🔵 `POST /api/v1/enhanced/users/create`

创建用户

**请求参数：**

（无请求参数）

**请求体示例：**

```json
{
  "username": "string",
  "password": "string",
  "email": "string",
  "role": "string",
  "tenant_id": "xxx-xxx"
}
```

**调用示例：**

```bash
curl -X POST 'http://<host>/api/v1/enhanced/users/create' \ \
  -H 'X-API-Key: $API_KEY' \ \
  -H 'Content-Type: application/json' \
  -d '{}'
```

### 🔵 `POST /api/v1/enhanced/users/login`

用户登录

**请求参数：**

（无请求参数）

**请求体示例：**

```json
{
  "username": "string",
  "password": "string"
}
```

**调用示例：**

```bash
curl -X POST 'http://<host>/api/v1/enhanced/users/login' \ \
  -H 'X-API-Key: $API_KEY' \ \
  -H 'Content-Type: application/json' \
  -d '{}'
```

### 🔵 `POST /api/v1/enhanced/users/logout`

用户登出

**请求参数：**

| 参数名 | 位置 | 类型 | 必填 | 说明 |
|---|---|---|---|---|
| `session_id` | query | string | ✅ | 会话ID |

**调用示例：**

```bash
curl -X POST 'http://<host>/api/v1/enhanced/users/logout' \ \
  -H 'X-API-Key: $API_KEY' \ \
  -H 'Content-Type: application/json'
```

### 🟢 `GET /api/v1/enhanced/users/list`

列出用户

**请求参数：**

（无请求参数）

**调用示例：**

```bash
curl -X GET 'http://<host>/api/v1/enhanced/users/list' \ \
  -H 'X-API-Key: $API_KEY' \ \
  -H 'Content-Type: application/json'
```

### 🟢 `GET /api/v1/enhanced/users/roles`

列出角色

**请求参数：**

（无请求参数）

**调用示例：**

```bash
curl -X GET 'http://<host>/api/v1/enhanced/users/roles' \ \
  -H 'X-API-Key: $API_KEY' \ \
  -H 'Content-Type: application/json'
```

### 🔵 `POST /api/v1/enhanced/users/api-key/create`

创建API密钥

**请求参数：**

（无请求参数）

**请求体示例：**

```json
{
  "username": "string",
  "name": "string",
  "expires_days": 0
}
```

**调用示例：**

```bash
curl -X POST 'http://<host>/api/v1/enhanced/users/api-key/create' \ \
  -H 'X-API-Key: $API_KEY' \ \
  -H 'Content-Type: application/json' \
  -d '{}'
```

### 🟢 `GET /api/v1/enhanced/users/audit-logs`

获取审计日志

**请求参数：**

| 参数名 | 位置 | 类型 | 必填 | 说明 |
|---|---|---|---|---|
| `username` | query | string | — | 用户名过滤 |
| `action` | query | string | — | 动作过滤 |
| `limit` | query | integer | — | 返回数量 |

**调用示例：**

```bash
curl -X GET 'http://<host>/api/v1/enhanced/users/audit-logs' \ \
  -H 'X-API-Key: $API_KEY' \ \
  -H 'Content-Type: application/json'
```

### 🟢 `GET /api/v1/enhanced/users/stats`

获取用户系统统计

**请求参数：**

（无请求参数）

**调用示例：**

```bash
curl -X GET 'http://<host>/api/v1/enhanced/users/stats' \ \
  -H 'X-API-Key: $API_KEY' \ \
  -H 'Content-Type: application/json'
```

### 🔵 `POST /api/v1/enhanced/distributed/scan`

提交分布式扫描任务

**请求参数：**

（无请求参数）

**请求体示例：**

```json
{
  "target": "example.com",
  "scan_type": "string",
  "parameters": {},
  "priority": 0
}
```

**调用示例：**

```bash
curl -X POST 'http://<host>/api/v1/enhanced/distributed/scan' \ \
  -H 'X-API-Key: $API_KEY' \ \
  -H 'Content-Type: application/json' \
  -d '{}'
```

### 🟢 `GET /api/v1/enhanced/distributed/scan/{task_id}`

获取扫描任务结果

**请求参数：**

| 参数名 | 位置 | 类型 | 必填 | 说明 |
|---|---|---|---|---|
| `task_id` | path | string | ✅ |  |

**调用示例：**

```bash
curl -X GET 'http://<host>/api/v1/enhanced/distributed/scan/{task_id}' \ \
  -H 'X-API-Key: $API_KEY' \ \
  -H 'Content-Type: application/json'
```

### 🔵 `POST /api/v1/enhanced/distributed/nodes/register`

注册扫描节点

**请求参数：**

（无请求参数）

**请求体示例：**

```json
{
  "name": "string",
  "address": "string",
  "capabilities": []
}
```

**调用示例：**

```bash
curl -X POST 'http://<host>/api/v1/enhanced/distributed/nodes/register' \ \
  -H 'X-API-Key: $API_KEY' \ \
  -H 'Content-Type: application/json' \
  -d '{}'
```

### 🟢 `GET /api/v1/enhanced/distributed/nodes/list`

列出扫描节点

**请求参数：**

（无请求参数）

**调用示例：**

```bash
curl -X GET 'http://<host>/api/v1/enhanced/distributed/nodes/list' \ \
  -H 'X-API-Key: $API_KEY' \ \
  -H 'Content-Type: application/json'
```

### 🔵 `POST /api/v1/enhanced/distributed/nodes/{node_id}/heartbeat`

节点心跳

**请求参数：**

| 参数名 | 位置 | 类型 | 必填 | 说明 |
|---|---|---|---|---|
| `node_id` | path | string | ✅ |  |
| `cpu_usage` | query | number | — |  |
| `memory_usage` | query | number | — |  |
| `current_tasks` | query | integer | — |  |

**调用示例：**

```bash
curl -X POST 'http://<host>/api/v1/enhanced/distributed/nodes/{node_id}/heartbeat' \ \
  -H 'X-API-Key: $API_KEY' \ \
  -H 'Content-Type: application/json'
```

### 🔵 `POST /api/v1/enhanced/distributed/proxies/add`

添加代理

**请求参数：**

（无请求参数）

**请求体示例：**

```json
{
  "address": "string",
  "protocol": "string",
  "username": "string",
  "password": "string"
}
```

**调用示例：**

```bash
curl -X POST 'http://<host>/api/v1/enhanced/distributed/proxies/add' \ \
  -H 'X-API-Key: $API_KEY' \ \
  -H 'Content-Type: application/json' \
  -d '{}'
```

### 🟢 `GET /api/v1/enhanced/distributed/proxies/list`

列出代理

**请求参数：**

（无请求参数）

**调用示例：**

```bash
curl -X GET 'http://<host>/api/v1/enhanced/distributed/proxies/list' \ \
  -H 'X-API-Key: $API_KEY' \ \
  -H 'Content-Type: application/json'
```

### 🟢 `GET /api/v1/enhanced/distributed/stats`

获取分布式系统统计

**请求参数：**

（无请求参数）

**调用示例：**

```bash
curl -X GET 'http://<host>/api/v1/enhanced/distributed/stats' \ \
  -H 'X-API-Key: $API_KEY' \ \
  -H 'Content-Type: application/json'
```

### 🟢 `GET /api/v1/enhanced/distributed/tasks/list`

列出分布式任务

**请求参数：**

| 参数名 | 位置 | 类型 | 必填 | 说明 |
|---|---|---|---|---|
| `status` | query | string | — | 状态过滤 |
| `limit` | query | integer | — | 返回数量 |

**调用示例：**

```bash
curl -X GET 'http://<host>/api/v1/enhanced/distributed/tasks/list' \ \
  -H 'X-API-Key: $API_KEY' \ \
  -H 'Content-Type: application/json'
```

### 🟢 `GET /api/v1/enhanced/status`

增强模块综合状态

**请求参数：**

（无请求参数）

**调用示例：**

```bash
curl -X GET 'http://<host>/api/v1/enhanced/status' \ \
  -H 'X-API-Key: $API_KEY' \ \
  -H 'Content-Type: application/json'
```


## 实战能力

本模块共 22 个端点。

### 🔵 `POST /api/v1/combat/sql/scan`

SQL注入扫描

**请求参数：**

（无请求参数）

**请求体示例：**

```json
{
  "url": "string",
  "parameters": "string",
  "level": 0,
  "risk": 0,
  "cookies": "string",
  "timeout": 0
}
```

**调用示例：**

```bash
curl -X POST 'http://<host>/api/v1/combat/sql/scan' \ \
  -H 'X-API-Key: $API_KEY' \ \
  -H 'Content-Type: application/json' \
  -d '{}'
```

### 🔵 `POST /api/v1/combat/sql/dump`

SQL数据库Dump

**请求参数：**

（无请求参数）

**请求体示例：**

```json
{
  "url": "string",
  "database": "string",
  "tables": "string",
  "level": 0,
  "risk": 0,
  "timeout": 0
}
```

**调用示例：**

```bash
curl -X POST 'http://<host>/api/v1/combat/sql/dump' \ \
  -H 'X-API-Key: $API_KEY' \ \
  -H 'Content-Type: application/json' \
  -d '{}'
```

### 🔵 `POST /api/v1/combat/sql/os-command`

SQL注入执行系统命令

**请求参数：**

（无请求参数）

**请求体示例：**

```json
{
  "url": "string",
  "command": "string",
  "level": 0,
  "risk": 0
}
```

**调用示例：**

```bash
curl -X POST 'http://<host>/api/v1/combat/sql/os-command' \ \
  -H 'X-API-Key: $API_KEY' \ \
  -H 'Content-Type: application/json' \
  -d '{}'
```

### 🔵 `POST /api/v1/combat/msf/exploit`

Metasploit漏洞利用

**请求参数：**

（无请求参数）

**请求体示例：**

```json
{
  "module": "string",
  "options": {},
  "payload": "string",
  "payload_options": "string",
  "wait_for_session": true,
  "timeout": 0
}
```

**调用示例：**

```bash
curl -X POST 'http://<host>/api/v1/combat/msf/exploit' \ \
  -H 'X-API-Key: $API_KEY' \ \
  -H 'Content-Type: application/json' \
  -d '{}'
```

### 🔵 `POST /api/v1/combat/msf/quick`

Metasploit快速利用

**请求参数：**

（无请求参数）

**请求体示例：**

```json
{
  "target": "example.com",
  "module": "string",
  "port": 0,
  "payload_lhost": "string",
  "payload_lport": 0
}
```

**调用示例：**

```bash
curl -X POST 'http://<host>/api/v1/combat/msf/quick' \ \
  -H 'X-API-Key: $API_KEY' \ \
  -H 'Content-Type: application/json' \
  -d '{}'
```

### 🟢 `GET /api/v1/combat/msf/sessions`

获取Metasploit会话列表

**请求参数：**

（无请求参数）

**调用示例：**

```bash
curl -X GET 'http://<host>/api/v1/combat/msf/sessions' \ \
  -H 'X-API-Key: $API_KEY' \ \
  -H 'Content-Type: application/json'
```

### 🔵 `POST /api/v1/combat/msf/session/{session_id}/execute`

在会话中执行命令

**请求参数：**

| 参数名 | 位置 | 类型 | 必填 | 说明 |
|---|---|---|---|---|
| `session_id` | path | integer | ✅ |  |

**请求体示例：**

```json
{
  "command": "string",
  "session_type": "string"
}
```

**调用示例：**

```bash
curl -X POST 'http://<host>/api/v1/combat/msf/session/{session_id}/execute' \ \
  -H 'X-API-Key: $API_KEY' \ \
  -H 'Content-Type: application/json' \
  -d '{}'
```

### 🟢 `GET /api/v1/combat/msf/search`

搜索Metasploit模块

**请求参数：**

| 参数名 | 位置 | 类型 | 必填 | 说明 |
|---|---|---|---|---|
| `keyword` | query | string | ✅ | 搜索关键词 |
| `module_type` | query | string | — | 模块类型过滤 |

**调用示例：**

```bash
curl -X GET 'http://<host>/api/v1/combat/msf/search' \ \
  -H 'X-API-Key: $API_KEY' \ \
  -H 'Content-Type: application/json'
```

### 🔵 `POST /api/v1/combat/ad/full-chain`

执行完整AD攻击链

**请求参数：**

（无请求参数）

**请求体示例：**

```json
{
  "dc_ip": "string",
  "domain": "string",
  "username": "string",
  "password": "string",
  "nt_hash": "string",
  "stages": "string"
}
```

**调用示例：**

```bash
curl -X POST 'http://<host>/api/v1/combat/ad/full-chain' \ \
  -H 'X-API-Key: $API_KEY' \ \
  -H 'Content-Type: application/json' \
  -d '{}'
```

### 🔵 `POST /api/v1/combat/ad/kerberoast`

Kerberoasting攻击

**请求参数：**

（无请求参数）

**请求体示例：**

```json
{
  "dc_ip": "string",
  "domain": "string",
  "username": "string",
  "password": "string",
  "nt_hash": "string",
  "stages": "string"
}
```

**调用示例：**

```bash
curl -X POST 'http://<host>/api/v1/combat/ad/kerberoast' \ \
  -H 'X-API-Key: $API_KEY' \ \
  -H 'Content-Type: application/json' \
  -d '{}'
```

### 🔵 `POST /api/v1/combat/ad/asrep-roast`

AS-REP Roasting攻击

**请求参数：**

（无请求参数）

**请求体示例：**

```json
{
  "dc_ip": "string",
  "domain": "string",
  "username": "string",
  "password": "string",
  "nt_hash": "string",
  "stages": "string"
}
```

**调用示例：**

```bash
curl -X POST 'http://<host>/api/v1/combat/ad/asrep-roast' \ \
  -H 'X-API-Key: $API_KEY' \ \
  -H 'Content-Type: application/json' \
  -d '{}'
```

### 🔵 `POST /api/v1/combat/ad/golden-ticket`

生成黄金票据

**请求参数：**

（无请求参数）

**请求体示例：**

```json
{
  "dc_ip": "string",
  "domain": "string",
  "krbtgt_hash": "string",
  "username": "string",
  "domain_sid": "xxx-xxx"
}
```

**调用示例：**

```bash
curl -X POST 'http://<host>/api/v1/combat/ad/golden-ticket' \ \
  -H 'X-API-Key: $API_KEY' \ \
  -H 'Content-Type: application/json' \
  -d '{}'
```

### 🔵 `POST /api/v1/combat/ad/dcsync`

DCSync域控同步

**请求参数：**

（无请求参数）

**请求体示例：**

```json
{
  "dc_ip": "string",
  "domain": "string",
  "username": "string",
  "password": "string",
  "nt_hash": "string",
  "stages": "string"
}
```

**调用示例：**

```bash
curl -X POST 'http://<host>/api/v1/combat/ad/dcsync' \ \
  -H 'X-API-Key: $API_KEY' \ \
  -H 'Content-Type: application/json' \
  -d '{}'
```

### 🔵 `POST /api/v1/combat/web/scan`

Web深度漏洞扫描

**请求参数：**

（无请求参数）

**请求体示例：**

```json
{
  "url": "string",
  "scan_types": "string",
  "cookies": "string",
  "timeout": 0
}
```

**调用示例：**

```bash
curl -X POST 'http://<host>/api/v1/combat/web/scan' \ \
  -H 'X-API-Key: $API_KEY' \ \
  -H 'Content-Type: application/json' \
  -d '{}'
```

### 🔵 `POST /api/v1/combat/web/scan/sql-injection`

SQL注入检测

**请求参数：**

（无请求参数）

**请求体示例：**

```json
{
  "url": "string",
  "parameter": "string",
  "method": "string"
}
```

**调用示例：**

```bash
curl -X POST 'http://<host>/api/v1/combat/web/scan/sql-injection' \ \
  -H 'X-API-Key: $API_KEY' \ \
  -H 'Content-Type: application/json' \
  -d '{}'
```

### 🔵 `POST /api/v1/combat/web/scan/xss`

XSS检测

**请求参数：**

（无请求参数）

**请求体示例：**

```json
{
  "url": "string",
  "parameter": "string",
  "method": "string"
}
```

**调用示例：**

```bash
curl -X POST 'http://<host>/api/v1/combat/web/scan/xss' \ \
  -H 'X-API-Key: $API_KEY' \ \
  -H 'Content-Type: application/json' \
  -d '{}'
```

### 🔵 `POST /api/v1/combat/web/scan/ssrf`

SSRF检测

**请求参数：**

（无请求参数）

**请求体示例：**

```json
{
  "url": "string",
  "parameter": "string",
  "method": "string"
}
```

**调用示例：**

```bash
curl -X POST 'http://<host>/api/v1/combat/web/scan/ssrf' \ \
  -H 'X-API-Key: $API_KEY' \ \
  -H 'Content-Type: application/json' \
  -d '{}'
```

### 🟢 `GET /api/v1/combat/templates`

列出所有攻击模板

**请求参数：**

| 参数名 | 位置 | 类型 | 必填 | 说明 |
|---|---|---|---|---|
| `category` | query | string | — | 按类别过滤 |

**调用示例：**

```bash
curl -X GET 'http://<host>/api/v1/combat/templates' \ \
  -H 'X-API-Key: $API_KEY' \ \
  -H 'Content-Type: application/json'
```

### 🟢 `GET /api/v1/combat/templates/{template_id}`

获取模板详情

**请求参数：**

| 参数名 | 位置 | 类型 | 必填 | 说明 |
|---|---|---|---|---|
| `template_id` | path | string | ✅ |  |

**调用示例：**

```bash
curl -X GET 'http://<host>/api/v1/combat/templates/{template_id}' \ \
  -H 'X-API-Key: $API_KEY' \ \
  -H 'Content-Type: application/json'
```

### 🔵 `POST /api/v1/combat/templates/execute`

执行攻击模板

**请求参数：**

（无请求参数）

**请求体示例：**

```json
{
  "template_id": "xxx-xxx",
  "target": "example.com",
  "variables": "string",
  "dry_run": true
}
```

**调用示例：**

```bash
curl -X POST 'http://<host>/api/v1/combat/templates/execute' \ \
  -H 'X-API-Key: $API_KEY' \ \
  -H 'Content-Type: application/json' \
  -d '{}'
```

### 🟢 `GET /api/v1/combat/executions`

列出执行记录

**请求参数：**

（无请求参数）

**调用示例：**

```bash
curl -X GET 'http://<host>/api/v1/combat/executions' \ \
  -H 'X-API-Key: $API_KEY' \ \
  -H 'Content-Type: application/json'
```

### 🟢 `GET /api/v1/combat/status`

实战能力状态

**请求参数：**

（无请求参数）

**调用示例：**

```bash
curl -X GET 'http://<host>/api/v1/combat/status' \ \
  -H 'X-API-Key: $API_KEY' \ \
  -H 'Content-Type: application/json'
```


## 工作流

本模块共 11 个端点。

### 🟢 `GET /api/v1/workflows/templates`

List Workflow Templates

**请求参数：**

（无请求参数）

**调用示例：**

```bash
curl -X GET 'http://<host>/api/v1/workflows/templates' \ \
  -H 'X-API-Key: $API_KEY' \ \
  -H 'Content-Type: application/json'
```

### 🔵 `POST /api/v1/workflows/start`

Start Workflow

**请求参数：**

（无请求参数）

**请求体示例：**

```json
{
  "workflow_id": "xxx-xxx",
  "target": "example.com",
  "name": "string",
  "description": "string",
  "config": "string"
}
```

**调用示例：**

```bash
curl -X POST 'http://<host>/api/v1/workflows/start' \ \
  -H 'X-API-Key: $API_KEY' \ \
  -H 'Content-Type: application/json' \
  -d '{}'
```

### 🟢 `GET /api/v1/workflows`

List Workflows

**请求参数：**

（无请求参数）

**调用示例：**

```bash
curl -X GET 'http://<host>/api/v1/workflows' \ \
  -H 'X-API-Key: $API_KEY' \ \
  -H 'Content-Type: application/json'
```

### 🟢 `GET /api/v1/workflows/{instance_id}`

Get Workflow Status

**请求参数：**

| 参数名 | 位置 | 类型 | 必填 | 说明 |
|---|---|---|---|---|
| `instance_id` | path | string | ✅ |  |
| `include_results` | query | boolean | — |  |

**调用示例：**

```bash
curl -X GET 'http://<host>/api/v1/workflows/{instance_id}' \ \
  -H 'X-API-Key: $API_KEY' \ \
  -H 'Content-Type: application/json'
```

### 🔵 `POST /api/v1/workflows/{instance_id}/cancel`

Cancel Workflow

**请求参数：**

| 参数名 | 位置 | 类型 | 必填 | 说明 |
|---|---|---|---|---|
| `instance_id` | path | string | ✅ |  |

**调用示例：**

```bash
curl -X POST 'http://<host>/api/v1/workflows/{instance_id}/cancel' \ \
  -H 'X-API-Key: $API_KEY' \ \
  -H 'Content-Type: application/json'
```

### 🟢 `GET /api/v1/workflows/{instance_id}/report`

Get Workflow Report

**请求参数：**

| 参数名 | 位置 | 类型 | 必填 | 说明 |
|---|---|---|---|---|
| `instance_id` | path | string | ✅ |  |

**调用示例：**

```bash
curl -X GET 'http://<host>/api/v1/workflows/{instance_id}/report' \ \
  -H 'X-API-Key: $API_KEY' \ \
  -H 'Content-Type: application/json'
```

### 🔵 `POST /api/v1/workflows/{instance_id}/pause`

Pause Workflow

**请求参数：**

| 参数名 | 位置 | 类型 | 必填 | 说明 |
|---|---|---|---|---|
| `instance_id` | path | string | ✅ |  |

**调用示例：**

```bash
curl -X POST 'http://<host>/api/v1/workflows/{instance_id}/pause' \ \
  -H 'X-API-Key: $API_KEY' \ \
  -H 'Content-Type: application/json'
```

### 🔵 `POST /api/v1/workflows/{instance_id}/resume`

Resume Workflow

**请求参数：**

| 参数名 | 位置 | 类型 | 必填 | 说明 |
|---|---|---|---|---|
| `instance_id` | path | string | ✅ |  |

**调用示例：**

```bash
curl -X POST 'http://<host>/api/v1/workflows/{instance_id}/resume' \ \
  -H 'X-API-Key: $API_KEY' \ \
  -H 'Content-Type: application/json'
```

### 🔵 `POST /api/v1/workflows/{instance_id}/approval`

Submit Approval

**请求参数：**

| 参数名 | 位置 | 类型 | 必填 | 说明 |
|---|---|---|---|---|
| `instance_id` | path | string | ✅ |  |

**请求体示例：**

```json
{
  "phase_id": "xxx-xxx",
  "action": "string",
  "reason": "string"
}
```

**调用示例：**

```bash
curl -X POST 'http://<host>/api/v1/workflows/{instance_id}/approval' \ \
  -H 'X-API-Key: $API_KEY' \ \
  -H 'Content-Type: application/json' \
  -d '{}'
```

### 🟢 `GET /api/v1/workflows/{instance_id}/logs`

Get Workflow Logs

**请求参数：**

| 参数名 | 位置 | 类型 | 必填 | 说明 |
|---|---|---|---|---|
| `instance_id` | path | string | ✅ |  |
| `limit` | query | integer | — |  |

**调用示例：**

```bash
curl -X GET 'http://<host>/api/v1/workflows/{instance_id}/logs' \ \
  -H 'X-API-Key: $API_KEY' \ \
  -H 'Content-Type: application/json'
```

### 🟢 `GET /api/v1/workflows/{instance_id}/context`

Get Workflow Context

**请求参数：**

| 参数名 | 位置 | 类型 | 必填 | 说明 |
|---|---|---|---|---|
| `instance_id` | path | string | ✅ |  |

**调用示例：**

```bash
curl -X GET 'http://<host>/api/v1/workflows/{instance_id}/context' \ \
  -H 'X-API-Key: $API_KEY' \ \
  -H 'Content-Type: application/json'
```


## 工具调用

本模块共 2 个端点。

### 🟢 `GET /api/v1/tools`

List Tools

**请求参数：**

（无请求参数）

**调用示例：**

```bash
curl -X GET 'http://<host>/api/v1/tools' \ \
  -H 'X-API-Key: $API_KEY' \ \
  -H 'Content-Type: application/json'
```

### 🔵 `POST /api/v1/tools/call`

Call Tool

**请求参数：**

（无请求参数）

**请求体示例：**

```json
{
  "tool_name": "string",
  "parameters": {}
}
```

**调用示例：**

```bash
curl -X POST 'http://<host>/api/v1/tools/call' \ \
  -H 'X-API-Key: $API_KEY' \ \
  -H 'Content-Type: application/json' \
  -d '{}'
```


## 工具集成

本模块共 14 个端点。

### 🔵 `POST /api/v1/tools/network/nmap/scan`

Nmap扫描

**请求参数：**

（无请求参数）

**请求体示例：**

```json
{
  "target": "example.com",
  "ports": "string",
  "scan_type": "string",
  "rate": 0
}
```

**调用示例：**

```bash
curl -X POST 'http://<host>/api/v1/tools/network/nmap/scan' \ \
  -H 'X-API-Key: $API_KEY' \ \
  -H 'Content-Type: application/json' \
  -d '{}'
```

### 🔵 `POST /api/v1/tools/network/masscan/scan`

Masscan高速扫描

**请求参数：**

（无请求参数）

**请求体示例：**

```json
{
  "target": "example.com",
  "ports": "string",
  "scan_type": "string",
  "rate": 0
}
```

**调用示例：**

```bash
curl -X POST 'http://<host>/api/v1/tools/network/masscan/scan' \ \
  -H 'X-API-Key: $API_KEY' \ \
  -H 'Content-Type: application/json' \
  -d '{}'
```

### 🔵 `POST /api/v1/tools/directory/brute`

目录爆破

**请求参数：**

（无请求参数）

**请求体示例：**

```json
{
  "url": "string",
  "tool": "string",
  "wordlist": "string",
  "extensions": []
}
```

**调用示例：**

```bash
curl -X POST 'http://<host>/api/v1/tools/directory/brute' \ \
  -H 'X-API-Key: $API_KEY' \ \
  -H 'Content-Type: application/json' \
  -d '{}'
```

### 🔵 `POST /api/v1/tools/password/brute-force`

在线暴力破解

**请求参数：**

（无请求参数）

**请求体示例：**

```json
{
  "target": "example.com",
  "service": "string",
  "username": "string",
  "wordlist": "string",
  "attack_type": "string"
}
```

**调用示例：**

```bash
curl -X POST 'http://<host>/api/v1/tools/password/brute-force' \ \
  -H 'X-API-Key: $API_KEY' \ \
  -H 'Content-Type: application/json' \
  -d '{}'
```

### 🔵 `POST /api/v1/tools/password/identify-hash`

哈希类型识别

**请求参数：**

（无请求参数）

**请求体示例：**

```json
{
  "hash_value": "string"
}
```

**调用示例：**

```bash
curl -X POST 'http://<host>/api/v1/tools/password/identify-hash' \ \
  -H 'X-API-Key: $API_KEY' \ \
  -H 'Content-Type: application/json' \
  -d '{}'
```

### 🟢 `GET /api/v1/tools/password/services`

获取支持的暴力破解服务

**请求参数：**

（无请求参数）

**调用示例：**

```bash
curl -X GET 'http://<host>/api/v1/tools/password/services' \ \
  -H 'X-API-Key: $API_KEY' \ \
  -H 'Content-Type: application/json'
```

### 🔵 `POST /api/v1/tools/web/scan`

Web扫描

**请求参数：**

（无请求参数）

**请求体示例：**

```json
{
  "url": "string",
  "scan_type": "string",
  "ssl": true
}
```

**调用示例：**

```bash
curl -X POST 'http://<host>/api/v1/tools/web/scan' \ \
  -H 'X-API-Key: $API_KEY' \ \
  -H 'Content-Type: application/json' \
  -d '{}'
```

### 🟢 `GET /api/v1/tools/manager/list`

列出所有工具

**请求参数：**

| 参数名 | 位置 | 类型 | 必填 | 说明 |
|---|---|---|---|---|
| `category` | query | string | — |  |

**调用示例：**

```bash
curl -X GET 'http://<host>/api/v1/tools/manager/list' \ \
  -H 'X-API-Key: $API_KEY' \ \
  -H 'Content-Type: application/json'
```

### 🟢 `GET /api/v1/tools/manager/stats`

工具管理统计

**请求参数：**

（无请求参数）

**调用示例：**

```bash
curl -X GET 'http://<host>/api/v1/tools/manager/stats' \ \
  -H 'X-API-Key: $API_KEY' \ \
  -H 'Content-Type: application/json'
```

### 🔵 `POST /api/v1/tools/manager/check`

检查工具安装状态

**请求参数：**

| 参数名 | 位置 | 类型 | 必填 | 说明 |
|---|---|---|---|---|
| `name` | query | string | ✅ |  |

**调用示例：**

```bash
curl -X POST 'http://<host>/api/v1/tools/manager/check' \ \
  -H 'X-API-Key: $API_KEY' \ \
  -H 'Content-Type: application/json'
```

### 🔵 `POST /api/v1/tools/manager/check-all`

检查所有工具安装状态

**请求参数：**

（无请求参数）

**调用示例：**

```bash
curl -X POST 'http://<host>/api/v1/tools/manager/check-all' \ \
  -H 'X-API-Key: $API_KEY' \ \
  -H 'Content-Type: application/json'
```

### 🟢 `GET /api/v1/tools/manager/search`

搜索工具

**请求参数：**

| 参数名 | 位置 | 类型 | 必填 | 说明 |
|---|---|---|---|---|
| `keyword` | query | string | ✅ |  |

**调用示例：**

```bash
curl -X GET 'http://<host>/api/v1/tools/manager/search' \ \
  -H 'X-API-Key: $API_KEY' \ \
  -H 'Content-Type: application/json'
```

### 🟢 `GET /api/v1/tools/manager/install-script`

生成工具安装脚本

**请求参数：**

| 参数名 | 位置 | 类型 | 必填 | 说明 |
|---|---|---|---|---|
| `os_type` | query | string | — |  |

**调用示例：**

```bash
curl -X GET 'http://<host>/api/v1/tools/manager/install-script' \ \
  -H 'X-API-Key: $API_KEY' \ \
  -H 'Content-Type: application/json'
```

### 🟢 `GET /api/v1/tools/overview`

工具集成模块总览

**请求参数：**

（无请求参数）

**调用示例：**

```bash
curl -X GET 'http://<host>/api/v1/tools/overview' \ \
  -H 'X-API-Key: $API_KEY' \ \
  -H 'Content-Type: application/json'
```


## 扩展安全模块

本模块共 22 个端点。

### 🔵 `POST /api/v1/extended/mobile/analyze`

APK静态分析

**请求参数：**

（无请求参数）

**请求体示例：**

（无请求体）

**调用示例：**

```bash
curl -X POST 'http://<host>/api/v1/extended/mobile/analyze' \ \
  -H 'X-API-Key: $API_KEY' \ \
  -H 'Content-Type: application/json'
```

### 🟢 `GET /api/v1/extended/mobile/vulnerabilities`

移动App漏洞扫描

**请求参数：**

| 参数名 | 位置 | 类型 | 必填 | 说明 |
|---|---|---|---|---|
| `apk_path` | query | string | ✅ | APK文件路径 |

**调用示例：**

```bash
curl -X GET 'http://<host>/api/v1/extended/mobile/vulnerabilities' \ \
  -H 'X-API-Key: $API_KEY' \ \
  -H 'Content-Type: application/json'
```

### 🟢 `GET /api/v1/extended/mobile/frida/scripts`

获取Frida脚本列表

**请求参数：**

（无请求参数）

**调用示例：**

```bash
curl -X GET 'http://<host>/api/v1/extended/mobile/frida/scripts' \ \
  -H 'X-API-Key: $API_KEY' \ \
  -H 'Content-Type: application/json'
```

### 🔵 `POST /api/v1/extended/mobile/frida/generate`

生成自定义Frida脚本

**请求参数：**

（无请求参数）

**请求体示例：**

（无请求体）

**调用示例：**

```bash
curl -X POST 'http://<host>/api/v1/extended/mobile/frida/generate' \ \
  -H 'X-API-Key: $API_KEY' \ \
  -H 'Content-Type: application/json'
```

### 🟢 `GET /api/v1/extended/mobile/devices`

获取连接的Android设备列表

**请求参数：**

（无请求参数）

**调用示例：**

```bash
curl -X GET 'http://<host>/api/v1/extended/mobile/devices' \ \
  -H 'X-API-Key: $API_KEY' \ \
  -H 'Content-Type: application/json'
```

### 🔵 `POST /api/v1/extended/internal/scan`

内网扫描

**请求参数：**

（无请求参数）

**请求体示例：**

（无请求体）

**调用示例：**

```bash
curl -X POST 'http://<host>/api/v1/extended/internal/scan' \ \
  -H 'X-API-Key: $API_KEY' \ \
  -H 'Content-Type: application/json'
```

### 🔵 `POST /api/v1/extended/internal/smb`

SMB共享枚举

**请求参数：**

（无请求参数）

**请求体示例：**

（无请求体）

**调用示例：**

```bash
curl -X POST 'http://<host>/api/v1/extended/internal/smb' \ \
  -H 'X-API-Key: $API_KEY' \ \
  -H 'Content-Type: application/json'
```

### 🔵 `POST /api/v1/extended/internal/domain`

域信息枚举

**请求参数：**

（无请求参数）

**请求体示例：**

（无请求体）

**调用示例：**

```bash
curl -X POST 'http://<host>/api/v1/extended/internal/domain' \ \
  -H 'X-API-Key: $API_KEY' \ \
  -H 'Content-Type: application/json'
```

### 🔵 `POST /api/v1/extended/internal/privesc`

本地提权漏洞检查

**请求参数：**

（无请求参数）

**调用示例：**

```bash
curl -X POST 'http://<host>/api/v1/extended/internal/privesc' \ \
  -H 'X-API-Key: $API_KEY' \ \
  -H 'Content-Type: application/json'
```

### 🔵 `POST /api/v1/extended/internal/kerberoasting`

Kerberoasting

**请求参数：**

（无请求参数）

**请求体示例：**

（无请求体）

**调用示例：**

```bash
curl -X POST 'http://<host>/api/v1/extended/internal/kerberoasting' \ \
  -H 'X-API-Key: $API_KEY' \ \
  -H 'Content-Type: application/json'
```

### 🔵 `POST /api/v1/extended/cloud/scan/aws`

AWS配置安全扫描

**请求参数：**

（无请求参数）

**请求体示例：**

（无请求体）

**调用示例：**

```bash
curl -X POST 'http://<host>/api/v1/extended/cloud/scan/aws' \ \
  -H 'X-API-Key: $API_KEY' \ \
  -H 'Content-Type: application/json'
```

### 🔵 `POST /api/v1/extended/cloud/scan/container`

容器镜像安全扫描

**请求参数：**

（无请求参数）

**请求体示例：**

（无请求体）

**调用示例：**

```bash
curl -X POST 'http://<host>/api/v1/extended/cloud/scan/container' \ \
  -H 'X-API-Key: $API_KEY' \ \
  -H 'Content-Type: application/json'
```

### 🔵 `POST /api/v1/extended/cloud/scan/k8s`

Kubernetes集群安全扫描

**请求参数：**

（无请求参数）

**请求体示例：**

（无请求体）

**调用示例：**

```bash
curl -X POST 'http://<host>/api/v1/extended/cloud/scan/k8s' \ \
  -H 'X-API-Key: $API_KEY' \ \
  -H 'Content-Type: application/json'
```

### 🔵 `POST /api/v1/extended/api-security/parse-openapi`

解析OpenAPI文档

**请求参数：**

（无请求参数）

**请求体示例：**

（无请求体）

**调用示例：**

```bash
curl -X POST 'http://<host>/api/v1/extended/api-security/parse-openapi' \ \
  -H 'X-API-Key: $API_KEY' \ \
  -H 'Content-Type: application/json'
```

### 🔵 `POST /api/v1/extended/api-security/test-auth`

API认证测试

**请求参数：**

（无请求参数）

**请求体示例：**

（无请求体）

**调用示例：**

```bash
curl -X POST 'http://<host>/api/v1/extended/api-security/test-auth' \ \
  -H 'X-API-Key: $API_KEY' \ \
  -H 'Content-Type: application/json'
```

### 🔵 `POST /api/v1/extended/api-security/test-business-logic`

API业务逻辑测试

**请求参数：**

（无请求参数）

**请求体示例：**

（无请求体）

**调用示例：**

```bash
curl -X POST 'http://<host>/api/v1/extended/api-security/test-business-logic' \ \
  -H 'X-API-Key: $API_KEY' \ \
  -H 'Content-Type: application/json'
```

### 🔵 `POST /api/v1/extended/client/analyze`

二进制文件安全分析

**请求参数：**

（无请求参数）

**请求体示例：**

（无请求体）

**调用示例：**

```bash
curl -X POST 'http://<host>/api/v1/extended/client/analyze' \ \
  -H 'X-API-Key: $API_KEY' \ \
  -H 'Content-Type: application/json'
```

### 🔵 `POST /api/v1/extended/code-audit/audit`

代码审计

**请求参数：**

（无请求参数）

**请求体示例：**

（无请求体）

**调用示例：**

```bash
curl -X POST 'http://<host>/api/v1/extended/code-audit/audit' \ \
  -H 'X-API-Key: $API_KEY' \ \
  -H 'Content-Type: application/json'
```

### 🔵 `POST /api/v1/extended/code-audit/dependencies`

依赖漏洞扫描

**请求参数：**

（无请求参数）

**请求体示例：**

（无请求体）

**调用示例：**

```bash
curl -X POST 'http://<host>/api/v1/extended/code-audit/dependencies' \ \
  -H 'X-API-Key: $API_KEY' \ \
  -H 'Content-Type: application/json'
```

### 🔵 `POST /api/v1/extended/wireless/scan`

WiFi扫描

**请求参数：**

（无请求参数）

**请求体示例：**

（无请求体）

**调用示例：**

```bash
curl -X POST 'http://<host>/api/v1/extended/wireless/scan' \ \
  -H 'X-API-Key: $API_KEY' \ \
  -H 'Content-Type: application/json'
```

### 🔵 `POST /api/v1/extended/wireless/audit`

无线网络安全审计

**请求参数：**

（无请求参数）

**调用示例：**

```bash
curl -X POST 'http://<host>/api/v1/extended/wireless/audit' \ \
  -H 'X-API-Key: $API_KEY' \ \
  -H 'Content-Type: application/json'
```

### 🟢 `GET /api/v1/extended/report/summary`

获取所有模块的综合报告摘要

**请求参数：**

（无请求参数）

**调用示例：**

```bash
curl -X GET 'http://<host>/api/v1/extended/report/summary' \ \
  -H 'X-API-Key: $API_KEY' \ \
  -H 'Content-Type: application/json'
```


## 报告

本模块共 1 个端点。

### 🔵 `POST /api/v1/reports/generate`

Generate Report

**请求参数：**

（无请求参数）

**请求体示例：**

```json
{
  "data": {},
  "report_type": "string"
}
```

**调用示例：**

```bash
curl -X POST 'http://<host>/api/v1/reports/generate' \ \
  -H 'X-API-Key: $API_KEY' \ \
  -H 'Content-Type: application/json' \
  -d '{}'
```


## 报告管理

本模块共 7 个端点。

### 🔵 `POST /api/v1/reporting/generate`

生成报告

**请求参数：**

（无请求参数）

**请求体示例：**

```json
{
  "assessment_data": {},
  "format": "string",
  "template_id": "xxx-xxx",
  "output_dir": "string"
}
```

**调用示例：**

```bash
curl -X POST 'http://<host>/api/v1/reporting/generate' \ \
  -H 'X-API-Key: $API_KEY' \ \
  -H 'Content-Type: application/json' \
  -d '{}'
```

### 🟢 `GET /api/v1/reporting/download/{report_id}`

下载报告

**请求参数：**

| 参数名 | 位置 | 类型 | 必填 | 说明 |
|---|---|---|---|---|
| `report_id` | path | string | ✅ |  |

**调用示例：**

```bash
curl -X GET 'http://<host>/api/v1/reporting/download/{report_id}' \ \
  -H 'X-API-Key: $API_KEY' \ \
  -H 'Content-Type: application/json'
```

### 🟢 `GET /api/v1/reporting/formats`

支持的报告格式

**请求参数：**

（无请求参数）

**调用示例：**

```bash
curl -X GET 'http://<host>/api/v1/reporting/formats' \ \
  -H 'X-API-Key: $API_KEY' \ \
  -H 'Content-Type: application/json'
```

### 🟢 `GET /api/v1/reporting/templates`

模板列表

**请求参数：**

（无请求参数）

**调用示例：**

```bash
curl -X GET 'http://<host>/api/v1/reporting/templates' \ \
  -H 'X-API-Key: $API_KEY' \ \
  -H 'Content-Type: application/json'
```

### 🔵 `POST /api/v1/reporting/templates`

保存新模板

**请求参数：**

（无请求参数）

**请求体示例：**

```json
{
  "id": "xxx-xxx",
  "name": "string",
  "company_name": "string",
  "logo_path": "string",
  "report_title": "string",
  "header_text": "string",
  "footer_text": "string",
  "contact_info": "string",
  "language": "string",
  "sections": "string",
  "is_default": "string"
}
```

**调用示例：**

```bash
curl -X POST 'http://<host>/api/v1/reporting/templates' \ \
  -H 'X-API-Key: $API_KEY' \ \
  -H 'Content-Type: application/json' \
  -d '{}'
```

### 🟡 `PUT /api/v1/reporting/templates/{template_id}`

更新模板

**请求参数：**

| 参数名 | 位置 | 类型 | 必填 | 说明 |
|---|---|---|---|---|
| `template_id` | path | string | ✅ |  |

**请求体示例：**

```json
{
  "id": "xxx-xxx",
  "name": "string",
  "company_name": "string",
  "logo_path": "string",
  "report_title": "string",
  "header_text": "string",
  "footer_text": "string",
  "contact_info": "string",
  "language": "string",
  "sections": "string",
  "is_default": "string"
}
```

**调用示例：**

```bash
curl -X PUT 'http://<host>/api/v1/reporting/templates/{template_id}' \ \
  -H 'X-API-Key: $API_KEY' \ \
  -H 'Content-Type: application/json' \
  -d '{}'
```

### 🔴 `DELETE /api/v1/reporting/templates/{template_id}`

删除模板

**请求参数：**

| 参数名 | 位置 | 类型 | 必填 | 说明 |
|---|---|---|---|---|
| `template_id` | path | string | ✅ |  |

**调用示例：**

```bash
curl -X DELETE 'http://<host>/api/v1/reporting/templates/{template_id}' \ \
  -H 'X-API-Key: $API_KEY' \ \
  -H 'Content-Type: application/json'
```


## 插件系统

本模块共 5 个端点。

### 🟢 `GET /api/v1/plugins`

List Plugins

**请求参数：**

（无请求参数）

**调用示例：**

```bash
curl -X GET 'http://<host>/api/v1/plugins' \ \
  -H 'X-API-Key: $API_KEY' \ \
  -H 'Content-Type: application/json'
```

### 🟢 `GET /api/v1/plugins/stats`

Plugin Stats

**请求参数：**

（无请求参数）

**调用示例：**

```bash
curl -X GET 'http://<host>/api/v1/plugins/stats' \ \
  -H 'X-API-Key: $API_KEY' \ \
  -H 'Content-Type: application/json'
```

### 🔵 `POST /api/v1/plugins/discover`

Discover Plugins

**请求参数：**

（无请求参数）

**调用示例：**

```bash
curl -X POST 'http://<host>/api/v1/plugins/discover' \ \
  -H 'X-API-Key: $API_KEY' \ \
  -H 'Content-Type: application/json'
```

### 🟢 `GET /api/v1/plugins/{plugin_name}/help`

Plugin Help

**请求参数：**

| 参数名 | 位置 | 类型 | 必填 | 说明 |
|---|---|---|---|---|
| `plugin_name` | path | string | ✅ |  |

**调用示例：**

```bash
curl -X GET 'http://<host>/api/v1/plugins/{plugin_name}/help' \ \
  -H 'X-API-Key: $API_KEY' \ \
  -H 'Content-Type: application/json'
```

### 🔵 `POST /api/v1/plugins/execute`

Execute Plugin

**请求参数：**

（无请求参数）

**请求体示例：**

```json
{
  "plugin_name": "string",
  "parameters": {}
}
```

**调用示例：**

```bash
curl -X POST 'http://<host>/api/v1/plugins/execute' \ \
  -H 'X-API-Key: $API_KEY' \ \
  -H 'Content-Type: application/json' \
  -d '{}'
```


## 数据分析

本模块共 9 个端点。

### 🟢 `GET /api/v1/analytics/trends/vulnerabilities`

Api Trend Vulnerabilities

**请求参数：**

| 参数名 | 位置 | 类型 | 必填 | 说明 |
|---|---|---|---|---|
| `days` | query | integer | — |  |
| `group_by` | query | string | — |  |

**调用示例：**

```bash
curl -X GET 'http://<host>/api/v1/analytics/trends/vulnerabilities' \ \
  -H 'X-API-Key: $API_KEY' \ \
  -H 'Content-Type: application/json'
```

### 🟢 `GET /api/v1/analytics/trends/risk`

Api Trend Risk

**请求参数：**

| 参数名 | 位置 | 类型 | 必填 | 说明 |
|---|---|---|---|---|
| `days` | query | integer | — |  |

**调用示例：**

```bash
curl -X GET 'http://<host>/api/v1/analytics/trends/risk' \ \
  -H 'X-API-Key: $API_KEY' \ \
  -H 'Content-Type: application/json'
```

### 🟢 `GET /api/v1/analytics/distribution/severity`

Api Distribution Severity

**请求参数：**

| 参数名 | 位置 | 类型 | 必填 | 说明 |
|---|---|---|---|---|
| `tenant_id` | query | any | — |  |

**调用示例：**

```bash
curl -X GET 'http://<host>/api/v1/analytics/distribution/severity' \ \
  -H 'X-API-Key: $API_KEY' \ \
  -H 'Content-Type: application/json'
```

### 🟢 `GET /api/v1/analytics/distribution/type`

Api Distribution Type

**请求参数：**

| 参数名 | 位置 | 类型 | 必填 | 说明 |
|---|---|---|---|---|
| `tenant_id` | query | any | — |  |
| `limit` | query | integer | — |  |

**调用示例：**

```bash
curl -X GET 'http://<host>/api/v1/analytics/distribution/type' \ \
  -H 'X-API-Key: $API_KEY' \ \
  -H 'Content-Type: application/json'
```

### 🟢 `GET /api/v1/analytics/top/vulnerabilities`

Api Top Vulnerabilities

**请求参数：**

| 参数名 | 位置 | 类型 | 必填 | 说明 |
|---|---|---|---|---|
| `n` | query | integer | — |  |
| `tenant_id` | query | any | — |  |

**调用示例：**

```bash
curl -X GET 'http://<host>/api/v1/analytics/top/vulnerabilities' \ \
  -H 'X-API-Key: $API_KEY' \ \
  -H 'Content-Type: application/json'
```

### 🟢 `GET /api/v1/analytics/top/targets`

Api Top Targets

**请求参数：**

| 参数名 | 位置 | 类型 | 必填 | 说明 |
|---|---|---|---|---|
| `n` | query | integer | — |  |
| `tenant_id` | query | any | — |  |

**调用示例：**

```bash
curl -X GET 'http://<host>/api/v1/analytics/top/targets' \ \
  -H 'X-API-Key: $API_KEY' \ \
  -H 'Content-Type: application/json'
```

### 🟢 `GET /api/v1/analytics/compare/{assessment_id1}/{assessment_id2}`

Api Compare

**请求参数：**

| 参数名 | 位置 | 类型 | 必填 | 说明 |
|---|---|---|---|---|
| `assessment_id1` | path | string | ✅ |  |
| `assessment_id2` | path | string | ✅ |  |

**调用示例：**

```bash
curl -X GET 'http://<host>/api/v1/analytics/compare/{assessment_id1}/{assessment_id2}' \ \
  -H 'X-API-Key: $API_KEY' \ \
  -H 'Content-Type: application/json'
```

### 🟢 `GET /api/v1/analytics/summary`

Api Summary

**请求参数：**

| 参数名 | 位置 | 类型 | 必填 | 说明 |
|---|---|---|---|---|
| `tenant_id` | query | any | — |  |

**调用示例：**

```bash
curl -X GET 'http://<host>/api/v1/analytics/summary' \ \
  -H 'X-API-Key: $API_KEY' \ \
  -H 'Content-Type: application/json'
```

### 🔵 `POST /api/v1/analytics/export`

Api Export

**请求参数：**

（无请求参数）

**请求体示例：**

```json
{
  "data": "string",
  "format": "string"
}
```

**调用示例：**

```bash
curl -X POST 'http://<host>/api/v1/analytics/export' \ \
  -H 'X-API-Key: $API_KEY' \ \
  -H 'Content-Type: application/json' \
  -d '{}'
```


## 数据备份

本模块共 8 个端点。

### 🟢 `GET /api/v1/backup`

获取备份列表

**请求参数：**

（无请求参数）

**调用示例：**

```bash
curl -X GET 'http://<host>/api/v1/backup' \ \
  -H 'X-API-Key: $API_KEY' \ \
  -H 'Content-Type: application/json'
```

### 🔵 `POST /api/v1/backup`

创建备份

**请求参数：**

（无请求参数）

**请求体示例：**

```json
{
  "backup_type": "string",
  "description": "string"
}
```

**调用示例：**

```bash
curl -X POST 'http://<host>/api/v1/backup' \ \
  -H 'X-API-Key: $API_KEY' \ \
  -H 'Content-Type: application/json' \
  -d '{}'
```

### 🟢 `GET /api/v1/backup/stats`

获取备份统计

**请求参数：**

（无请求参数）

**调用示例：**

```bash
curl -X GET 'http://<host>/api/v1/backup/stats' \ \
  -H 'X-API-Key: $API_KEY' \ \
  -H 'Content-Type: application/json'
```

### 🟢 `GET /api/v1/backup/{backup_name}`

获取备份详情

**请求参数：**

| 参数名 | 位置 | 类型 | 必填 | 说明 |
|---|---|---|---|---|
| `backup_name` | path | string | ✅ |  |

**调用示例：**

```bash
curl -X GET 'http://<host>/api/v1/backup/{backup_name}' \ \
  -H 'X-API-Key: $API_KEY' \ \
  -H 'Content-Type: application/json'
```

### 🔴 `DELETE /api/v1/backup/{backup_name}`

删除备份

**请求参数：**

| 参数名 | 位置 | 类型 | 必填 | 说明 |
|---|---|---|---|---|
| `backup_name` | path | string | ✅ |  |

**调用示例：**

```bash
curl -X DELETE 'http://<host>/api/v1/backup/{backup_name}' \ \
  -H 'X-API-Key: $API_KEY' \ \
  -H 'Content-Type: application/json'
```

### 🔵 `POST /api/v1/backup/restore`

恢复备份

**请求参数：**

（无请求参数）

**请求体示例：**

```json
{
  "backup_name": "string"
}
```

**调用示例：**

```bash
curl -X POST 'http://<host>/api/v1/backup/restore' \ \
  -H 'X-API-Key: $API_KEY' \ \
  -H 'Content-Type: application/json' \
  -d '{}'
```

### 🔵 `POST /api/v1/backup/quick`

快速创建完整备份

**请求参数：**

| 参数名 | 位置 | 类型 | 必填 | 说明 |
|---|---|---|---|---|
| `description` | query | any | — |  |

**调用示例：**

```bash
curl -X POST 'http://<host>/api/v1/backup/quick' \ \
  -H 'X-API-Key: $API_KEY' \ \
  -H 'Content-Type: application/json'
```

### 🔵 `POST /api/v1/backup/cleanup`

清理旧备份

**请求参数：**

| 参数名 | 位置 | 类型 | 必填 | 说明 |
|---|---|---|---|---|
| `keep` | query | integer | — |  |

**调用示例：**

```bash
curl -X POST 'http://<host>/api/v1/backup/cleanup' \ \
  -H 'X-API-Key: $API_KEY' \ \
  -H 'Content-Type: application/json'
```


## 数据库

本模块共 5 个端点。

### 🟢 `GET /api/v1/db/tasks`

Db List Tasks

**请求参数：**

| 参数名 | 位置 | 类型 | 必填 | 说明 |
|---|---|---|---|---|
| `status` | query | any | — |  |
| `limit` | query | integer | — |  |
| `offset` | query | integer | — |  |

**调用示例：**

```bash
curl -X GET 'http://<host>/api/v1/db/tasks' \ \
  -H 'X-API-Key: $API_KEY' \ \
  -H 'Content-Type: application/json'
```

### 🟢 `GET /api/v1/db/tasks/{task_id}`

Db Get Task

**请求参数：**

| 参数名 | 位置 | 类型 | 必填 | 说明 |
|---|---|---|---|---|
| `task_id` | path | string | ✅ |  |

**调用示例：**

```bash
curl -X GET 'http://<host>/api/v1/db/tasks/{task_id}' \ \
  -H 'X-API-Key: $API_KEY' \ \
  -H 'Content-Type: application/json'
```

### 🟢 `GET /api/v1/db/findings`

Db List Findings

**请求参数：**

| 参数名 | 位置 | 类型 | 必填 | 说明 |
|---|---|---|---|---|
| `task_id` | query | any | — |  |
| `severity` | query | any | — |  |
| `target` | query | any | — |  |
| `limit` | query | integer | — |  |

**调用示例：**

```bash
curl -X GET 'http://<host>/api/v1/db/findings' \ \
  -H 'X-API-Key: $API_KEY' \ \
  -H 'Content-Type: application/json'
```

### 🟢 `GET /api/v1/db/reports/{report_id}`

Db Get Report

**请求参数：**

| 参数名 | 位置 | 类型 | 必填 | 说明 |
|---|---|---|---|---|
| `report_id` | path | string | ✅ |  |

**调用示例：**

```bash
curl -X GET 'http://<host>/api/v1/db/reports/{report_id}' \ \
  -H 'X-API-Key: $API_KEY' \ \
  -H 'Content-Type: application/json'
```

### 🟢 `GET /api/v1/db/stats`

Db Stats

**请求参数：**

（无请求参数）

**调用示例：**

```bash
curl -X GET 'http://<host>/api/v1/db/stats' \ \
  -H 'X-API-Key: $API_KEY' \ \
  -H 'Content-Type: application/json'
```


## 新手引导

本模块共 3 个端点。

### 🟢 `GET /api/v1/onboarding/status`

获取引导完成状态

**请求参数：**

| 参数名 | 位置 | 类型 | 必填 | 说明 |
|---|---|---|---|---|
| `user_id` | query | string | — |  |

**调用示例：**

```bash
curl -X GET 'http://<host>/api/v1/onboarding/status' \ \
  -H 'X-API-Key: $API_KEY' \ \
  -H 'Content-Type: application/json'
```

### 🔵 `POST /api/v1/onboarding/complete`

标记引导完成

**请求参数：**

（无请求参数）

**请求体示例：**

```json
{
  "user_id": "xxx-xxx",
  "step": "string"
}
```

**调用示例：**

```bash
curl -X POST 'http://<host>/api/v1/onboarding/complete' \ \
  -H 'X-API-Key: $API_KEY' \ \
  -H 'Content-Type: application/json' \
  -d '{}'
```

### 🟢 `GET /api/v1/onboarding/steps`

获取引导步骤配置

**请求参数：**

（无请求参数）

**调用示例：**

```bash
curl -X GET 'http://<host>/api/v1/onboarding/steps' \ \
  -H 'X-API-Key: $API_KEY' \ \
  -H 'Content-Type: application/json'
```


## 新领域安全

本模块共 13 个端点。

### 🔵 `POST /api/v1/new-domains/mobile/apk/analyze`

分析APK文件

**请求参数：**

（无请求参数）

**请求体示例：**

```json
{
  "file_path": "string"
}
```

**调用示例：**

```bash
curl -X POST 'http://<host>/api/v1/new-domains/mobile/apk/analyze' \ \
  -H 'X-API-Key: $API_KEY' \ \
  -H 'Content-Type: application/json' \
  -d '{}'
```

### 🔵 `POST /api/v1/new-domains/mobile/api/scan`

扫描移动端API

**请求参数：**

（无请求参数）

**请求体示例：**

```json
{
  "api_url": "string",
  "method": "string",
  "headers": "string",
  "data": "string"
}
```

**调用示例：**

```bash
curl -X POST 'http://<host>/api/v1/new-domains/mobile/api/scan' \ \
  -H 'X-API-Key: $API_KEY' \ \
  -H 'Content-Type: application/json' \
  -d '{}'
```

### 🟢 `GET /api/v1/new-domains/mobile/status`

移动安全模块状态

**请求参数：**

（无请求参数）

**调用示例：**

```bash
curl -X GET 'http://<host>/api/v1/new-domains/mobile/status' \ \
  -H 'X-API-Key: $API_KEY' \ \
  -H 'Content-Type: application/json'
```

### 🔵 `POST /api/v1/new-domains/cloud/configuration/scan`

扫描云配置

**请求参数：**

（无请求参数）

**请求体示例：**

```json
{
  "provider": "xxx-xxx",
  "region": "string"
}
```

**调用示例：**

```bash
curl -X POST 'http://<host>/api/v1/new-domains/cloud/configuration/scan' \ \
  -H 'X-API-Key: $API_KEY' \ \
  -H 'Content-Type: application/json' \
  -d '{}'
```

### 🔵 `POST /api/v1/new-domains/cloud/container/scan`

扫描容器安全

**请求参数：**

（无请求参数）

**请求体示例：**

```json
{
  "target": "example.com",
  "scan_type": "string"
}
```

**调用示例：**

```bash
curl -X POST 'http://<host>/api/v1/new-domains/cloud/container/scan' \ \
  -H 'X-API-Key: $API_KEY' \ \
  -H 'Content-Type: application/json' \
  -d '{}'
```

### 🟢 `GET /api/v1/new-domains/cloud/status`

云安全模块状态

**请求参数：**

（无请求参数）

**调用示例：**

```bash
curl -X GET 'http://<host>/api/v1/new-domains/cloud/status' \ \
  -H 'X-API-Key: $API_KEY' \ \
  -H 'Content-Type: application/json'
```

### 🔵 `POST /api/v1/new-domains/client/binary/analyze`

分析二进制文件

**请求参数：**

（无请求参数）

**请求体示例：**

```json
{
  "file_path": "string"
}
```

**调用示例：**

```bash
curl -X POST 'http://<host>/api/v1/new-domains/client/binary/analyze' \ \
  -H 'X-API-Key: $API_KEY' \ \
  -H 'Content-Type: application/json' \
  -d '{}'
```

### 🔵 `POST /api/v1/new-domains/client/vulnerabilities/find`

发现二进制漏洞

**请求参数：**

（无请求参数）

**请求体示例：**

```json
{
  "file_path": "string",
  "source_code": "string"
}
```

**调用示例：**

```bash
curl -X POST 'http://<host>/api/v1/new-domains/client/vulnerabilities/find' \ \
  -H 'X-API-Key: $API_KEY' \ \
  -H 'Content-Type: application/json' \
  -d '{}'
```

### 🟢 `GET /api/v1/new-domains/client/status`

客户端安全模块状态

**请求参数：**

（无请求参数）

**调用示例：**

```bash
curl -X GET 'http://<host>/api/v1/new-domains/client/status' \ \
  -H 'X-API-Key: $API_KEY' \ \
  -H 'Content-Type: application/json'
```

### 🔵 `POST /api/v1/new-domains/ai/prompt-injection/detect`

检测Prompt注入

**请求参数：**

（无请求参数）

**请求体示例：**

```json
{
  "prompt": "string"
}
```

**调用示例：**

```bash
curl -X POST 'http://<host>/api/v1/new-domains/ai/prompt-injection/detect' \ \
  -H 'X-API-Key: $API_KEY' \ \
  -H 'Content-Type: application/json' \
  -d '{}'
```

### 🔵 `POST /api/v1/new-domains/ai/redteam/run`

运行AI红队测试

**请求参数：**

（无请求参数）

**请求体示例：**

```json
{
  "target": "example.com",
  "categories": "string"
}
```

**调用示例：**

```bash
curl -X POST 'http://<host>/api/v1/new-domains/ai/redteam/run' \ \
  -H 'X-API-Key: $API_KEY' \ \
  -H 'Content-Type: application/json' \
  -d '{}'
```

### 🟢 `GET /api/v1/new-domains/ai/status`

AI安全模块状态

**请求参数：**

（无请求参数）

**调用示例：**

```bash
curl -X GET 'http://<host>/api/v1/new-domains/ai/status' \ \
  -H 'X-API-Key: $API_KEY' \ \
  -H 'Content-Type: application/json'
```

### 🟢 `GET /api/v1/new-domains/status`

新领域安全模块综合状态

**请求参数：**

（无请求参数）

**调用示例：**

```bash
curl -X GET 'http://<host>/api/v1/new-domains/status' \ \
  -H 'X-API-Key: $API_KEY' \ \
  -H 'Content-Type: application/json'
```


## 智能体

本模块共 2 个端点。

### 🔵 `POST /api/v1/agents/react`

React Inference

**请求参数：**

（无请求参数）

**请求体示例：**

```json
{
  "task": "string",
  "max_iterations": 0
}
```

**调用示例：**

```bash
curl -X POST 'http://<host>/api/v1/agents/react' \ \
  -H 'X-API-Key: $API_KEY' \ \
  -H 'Content-Type: application/json' \
  -d '{}'
```

### 🟢 `GET /api/v1/agents`

List Agents

**请求参数：**

（无请求参数）

**调用示例：**

```bash
curl -X GET 'http://<host>/api/v1/agents' \ \
  -H 'X-API-Key: $API_KEY' \ \
  -H 'Content-Type: application/json'
```


## 渗透测试

本模块共 2 个端点。

### 🔵 `POST /api/v1/pentest/execute`

Execute Pentest

**请求参数：**

（无请求参数）

**请求体示例：**

```json
{
  "action": "string",
  "target": "example.com",
  "code": "string",
  "password": "string",
  "platform": "string"
}
```

**调用示例：**

```bash
curl -X POST 'http://<host>/api/v1/pentest/execute' \ \
  -H 'X-API-Key: $API_KEY' \ \
  -H 'Content-Type: application/json' \
  -d '{}'
```

### 🟢 `GET /api/v1/pentest/actions`

List Pentest Actions

**请求参数：**

（无请求参数）

**调用示例：**

```bash
curl -X GET 'http://<host>/api/v1/pentest/actions' \ \
  -H 'X-API-Key: $API_KEY' \ \
  -H 'Content-Type: application/json'
```


## 漏洞利用

本模块共 16 个端点。

### 🔵 `POST /api/v1/exploit/payload/reverse-shell`

生成反向Shell Payload

**请求参数：**

（无请求参数）

**请求体示例：**

```json
{
  "host": "example.com",
  "port": 1,
  "language": "string",
  "target_os": "string"
}
```

**调用示例：**

```bash
curl -X POST 'http://<host>/api/v1/exploit/payload/reverse-shell' \ \
  -H 'X-API-Key: $API_KEY' \ \
  -H 'Content-Type: application/json' \
  -d '{}'
```

### 🔵 `POST /api/v1/exploit/payload/bind-shell`

生成绑定Shell Payload

**请求参数：**

（无请求参数）

**请求体示例：**

```json
{
  "host": "example.com",
  "port": 1,
  "language": "string",
  "target_os": "string"
}
```

**调用示例：**

```bash
curl -X POST 'http://<host>/api/v1/exploit/payload/bind-shell' \ \
  -H 'X-API-Key: $API_KEY' \ \
  -H 'Content-Type: application/json' \
  -d '{}'
```

### 🔵 `POST /api/v1/exploit/payload/webshell`

生成WebShell

**请求参数：**

（无请求参数）

**请求体示例：**

```json
{
  "language": "string",
  "password": "string"
}
```

**调用示例：**

```bash
curl -X POST 'http://<host>/api/v1/exploit/payload/webshell' \ \
  -H 'X-API-Key: $API_KEY' \ \
  -H 'Content-Type: application/json' \
  -d '{}'
```

### 🔵 `POST /api/v1/exploit/payload/download-exec`

生成下载并执行Payload

**请求参数：**

（无请求参数）

**请求体示例：**

```json
{
  "url": "string",
  "filename": "string",
  "language": "string",
  "target_os": "string"
}
```

**调用示例：**

```bash
curl -X POST 'http://<host>/api/v1/exploit/payload/download-exec' \ \
  -H 'X-API-Key: $API_KEY' \ \
  -H 'Content-Type: application/json' \
  -d '{}'
```

### 🔵 `POST /api/v1/exploit/payload/persistence`

生成持久化Payload

**请求参数：**

（无请求参数）

**请求体示例：**

```json
{
  "method": "string",
  "target_os": "string",
  "command": "string"
}
```

**调用示例：**

```bash
curl -X POST 'http://<host>/api/v1/exploit/payload/persistence' \ \
  -H 'X-API-Key: $API_KEY' \ \
  -H 'Content-Type: application/json' \
  -d '{}'
```

### 🟢 `GET /api/v1/exploit/payload/templates`

获取Payload模板列表

**请求参数：**

（无请求参数）

**调用示例：**

```bash
curl -X GET 'http://<host>/api/v1/exploit/payload/templates' \ \
  -H 'X-API-Key: $API_KEY' \ \
  -H 'Content-Type: application/json'
```

### 🔵 `POST /api/v1/exploit/payload/encode`

编码Payload

**请求参数：**

（无请求参数）

**请求体示例：**

（无请求体）

**调用示例：**

```bash
curl -X POST 'http://<host>/api/v1/exploit/payload/encode' \ \
  -H 'X-API-Key: $API_KEY' \ \
  -H 'Content-Type: application/json'
```

### 🔵 `POST /api/v1/exploit/post-exploit/execute`

执行后渗透操作

**请求参数：**

（无请求参数）

**请求体示例：**

```json
{
  "target": "example.com",
  "action": "string",
  "os_type": "string",
  "method": "string"
}
```

**调用示例：**

```bash
curl -X POST 'http://<host>/api/v1/exploit/post-exploit/execute' \ \
  -H 'X-API-Key: $API_KEY' \ \
  -H 'Content-Type: application/json' \
  -d '{}'
```

### 🟢 `GET /api/v1/exploit/post-exploit/credentials`

获取已发现的凭证

**请求参数：**

（无请求参数）

**调用示例：**

```bash
curl -X GET 'http://<host>/api/v1/exploit/post-exploit/credentials' \ \
  -H 'X-API-Key: $API_KEY' \ \
  -H 'Content-Type: application/json'
```

### 🟢 `GET /api/v1/exploit/post-exploit/stats`

后渗透统计

**请求参数：**

（无请求参数）

**调用示例：**

```bash
curl -X GET 'http://<host>/api/v1/exploit/post-exploit/stats' \ \
  -H 'X-API-Key: $API_KEY' \ \
  -H 'Content-Type: application/json'
```

### 🔵 `POST /api/v1/exploit/msf/connect`

连接Metasploit RPC

**请求参数：**

（无请求参数）

**请求体示例：**

```json
{
  "host": "example.com",
  "port": 0,
  "username": "string",
  "password": "string",
  "module": "string",
  "target": "example.com",
  "payload": "string"
}
```

**调用示例：**

```bash
curl -X POST 'http://<host>/api/v1/exploit/msf/connect' \ \
  -H 'X-API-Key: $API_KEY' \ \
  -H 'Content-Type: application/json' \
  -d '{}'
```

### 🟢 `GET /api/v1/exploit/msf/modules`

列出Metasploit模块

**请求参数：**

| 参数名 | 位置 | 类型 | 必填 | 说明 |
|---|---|---|---|---|
| `module_type` | query | string | — |  |

**调用示例：**

```bash
curl -X GET 'http://<host>/api/v1/exploit/msf/modules' \ \
  -H 'X-API-Key: $API_KEY' \ \
  -H 'Content-Type: application/json'
```

### 🟢 `GET /api/v1/exploit/poc/list`

列出PoC库

**请求参数：**

| 参数名 | 位置 | 类型 | 必填 | 说明 |
|---|---|---|---|---|
| `category` | query | string | — |  |
| `severity` | query | string | — |  |

**调用示例：**

```bash
curl -X GET 'http://<host>/api/v1/exploit/poc/list' \ \
  -H 'X-API-Key: $API_KEY' \ \
  -H 'Content-Type: application/json'
```

### 🟢 `GET /api/v1/exploit/poc/stats`

PoC库统计

**请求参数：**

（无请求参数）

**调用示例：**

```bash
curl -X GET 'http://<host>/api/v1/exploit/poc/stats' \ \
  -H 'X-API-Key: $API_KEY' \ \
  -H 'Content-Type: application/json'
```

### 🟢 `GET /api/v1/exploit/poc/search`

搜索PoC

**请求参数：**

| 参数名 | 位置 | 类型 | 必填 | 说明 |
|---|---|---|---|---|
| `keyword` | query | string | ✅ |  |

**调用示例：**

```bash
curl -X GET 'http://<host>/api/v1/exploit/poc/search' \ \
  -H 'X-API-Key: $API_KEY' \ \
  -H 'Content-Type: application/json'
```

### 🟢 `GET /api/v1/exploit/overview`

漏洞利用模块总览

**请求参数：**

（无请求参数）

**调用示例：**

```bash
curl -X GET 'http://<host>/api/v1/exploit/overview' \ \
  -H 'X-API-Key: $API_KEY' \ \
  -H 'Content-Type: application/json'
```


## 漏洞数据库

本模块共 18 个端点。

### 🟢 `GET /api/v1/vuln/search`

Search Vulnerabilities

**请求参数：**

| 参数名 | 位置 | 类型 | 必填 | 说明 |
|---|---|---|---|---|
| `keyword` | query | string | — | 搜索关键词 |
| `severity` | query | string | — | 严重程度: critical/high/medium/low/info |
| `vendor` | query | string | — | 厂商名称 |
| `product` | query | string | — | 产品名称 |
| `cwe` | query | string | — | CWE编号，如 CWE-89 |
| `has_exploit` | query | boolean | — | 仅显示有利用代码的漏洞 |
| `has_poc` | query | boolean | — | 仅显示有POC的漏洞 |
| `kev_only` | query | boolean | — | 仅显示CISA KEV漏洞 |
| `limit` | query | integer | — | 返回数量 |
| `offset` | query | integer | — | 偏移量 |

**调用示例：**

```bash
curl -X GET 'http://<host>/api/v1/vuln/search' \ \
  -H 'X-API-Key: $API_KEY' \ \
  -H 'Content-Type: application/json'
```

### 🟢 `GET /api/v1/vuln/stats`

Get Vuln Stats

**请求参数：**

（无请求参数）

**调用示例：**

```bash
curl -X GET 'http://<host>/api/v1/vuln/stats' \ \
  -H 'X-API-Key: $API_KEY' \ \
  -H 'Content-Type: application/json'
```

### 🟢 `GET /api/v1/vuln/recent`

Get Recent Vulnerabilities

**请求参数：**

| 参数名 | 位置 | 类型 | 必填 | 说明 |
|---|---|---|---|---|
| `days` | query | integer | — | 最近N天 |
| `limit` | query | integer | — | 返回数量 |

**调用示例：**

```bash
curl -X GET 'http://<host>/api/v1/vuln/recent' \ \
  -H 'X-API-Key: $API_KEY' \ \
  -H 'Content-Type: application/json'
```

### 🟢 `GET /api/v1/vuln/top-exploitable`

Get Top Exploitable

**请求参数：**

| 参数名 | 位置 | 类型 | 必填 | 说明 |
|---|---|---|---|---|
| `limit` | query | integer | — | 返回数量 |

**调用示例：**

```bash
curl -X GET 'http://<host>/api/v1/vuln/top-exploitable' \ \
  -H 'X-API-Key: $API_KEY' \ \
  -H 'Content-Type: application/json'
```

### 🟢 `GET /api/v1/vuln/{cve_id}`

Get Vulnerability

**请求参数：**

| 参数名 | 位置 | 类型 | 必填 | 说明 |
|---|---|---|---|---|
| `cve_id` | path | string | ✅ |  |

**调用示例：**

```bash
curl -X GET 'http://<host>/api/v1/vuln/{cve_id}' \ \
  -H 'X-API-Key: $API_KEY' \ \
  -H 'Content-Type: application/json'
```

### 🔵 `POST /api/v1/vuln/match`

Match Vulnerabilities

**请求参数：**

（无请求参数）

**请求体示例：**

```json
{
  "service": "string",
  "version": "string"
}
```

**调用示例：**

```bash
curl -X POST 'http://<host>/api/v1/vuln/match' \ \
  -H 'X-API-Key: $API_KEY' \ \
  -H 'Content-Type: application/json' \
  -d '{}'
```

### 🔵 `POST /api/v1/vuln/sync/nvd`

Sync Nvd

**请求参数：**

（无请求参数）

**请求体示例：**

```json
{
  "days": 0,
  "max_results": 0
}
```

**调用示例：**

```bash
curl -X POST 'http://<host>/api/v1/vuln/sync/nvd' \ \
  -H 'X-API-Key: $API_KEY' \ \
  -H 'Content-Type: application/json' \
  -d '{}'
```

### 🔵 `POST /api/v1/vuln/sync/exploit-db`

Sync Exploit Db

**请求参数：**

| 参数名 | 位置 | 类型 | 必填 | 说明 |
|---|---|---|---|---|
| `max_cves` | query | integer | — | 最多处理的CVE数量 |

**调用示例：**

```bash
curl -X POST 'http://<host>/api/v1/vuln/sync/exploit-db' \ \
  -H 'X-API-Key: $API_KEY' \ \
  -H 'Content-Type: application/json'
```

### 🟢 `GET /api/v1/vuln/sync/status`

Get Sync Status

**请求参数：**

（无请求参数）

**调用示例：**

```bash
curl -X GET 'http://<host>/api/v1/vuln/sync/status' \ \
  -H 'X-API-Key: $API_KEY' \ \
  -H 'Content-Type: application/json'
```

### 🟢 `GET /api/v1/vuln/poc/{cve_id}`

Get Poc List

**请求参数：**

| 参数名 | 位置 | 类型 | 必填 | 说明 |
|---|---|---|---|---|
| `cve_id` | path | string | ✅ |  |

**调用示例：**

```bash
curl -X GET 'http://<host>/api/v1/vuln/poc/{cve_id}' \ \
  -H 'X-API-Key: $API_KEY' \ \
  -H 'Content-Type: application/json'
```

### 🟢 `GET /api/v1/vuln/alerts`

Get Alerts

**请求参数：**

| 参数名 | 位置 | 类型 | 必填 | 说明 |
|---|---|---|---|---|
| `status` | query | string | — | 告警状态: new/acknowledged/ignored |
| `severity` | query | string | — | 严重程度 |
| `limit` | query | integer | — | 返回数量 |
| `offset` | query | integer | — | 偏移量 |

**调用示例：**

```bash
curl -X GET 'http://<host>/api/v1/vuln/alerts' \ \
  -H 'X-API-Key: $API_KEY' \ \
  -H 'Content-Type: application/json'
```

### 🔵 `POST /api/v1/vuln/alerts/check`

Check New Alerts

**请求参数：**

| 参数名 | 位置 | 类型 | 必填 | 说明 |
|---|---|---|---|---|
| `hours` | query | integer | — | 检查最近N小时的新漏洞 |

**调用示例：**

```bash
curl -X POST 'http://<host>/api/v1/vuln/alerts/check' \ \
  -H 'X-API-Key: $API_KEY' \ \
  -H 'Content-Type: application/json'
```

### 🔵 `POST /api/v1/vuln/alerts/{alert_id}/acknowledge`

Acknowledge Alert

**请求参数：**

| 参数名 | 位置 | 类型 | 必填 | 说明 |
|---|---|---|---|---|
| `alert_id` | path | string | ✅ |  |

**调用示例：**

```bash
curl -X POST 'http://<host>/api/v1/vuln/alerts/{alert_id}/acknowledge' \ \
  -H 'X-API-Key: $API_KEY' \ \
  -H 'Content-Type: application/json'
```

### 🟢 `GET /api/v1/vuln/alerts/stats`

Get Alert Stats

**请求参数：**

（无请求参数）

**调用示例：**

```bash
curl -X GET 'http://<host>/api/v1/vuln/alerts/stats' \ \
  -H 'X-API-Key: $API_KEY' \ \
  -H 'Content-Type: application/json'
```

### 🟢 `GET /api/v1/vuln/vulners/search`

Vulners Search

**请求参数：**

| 参数名 | 位置 | 类型 | 必填 | 说明 |
|---|---|---|---|---|
| `query` | query | string | ✅ | Lucene搜索语法，如 type:cve AND severity:critical |
| `limit` | query | integer | — | 返回数量 |

**调用示例：**

```bash
curl -X GET 'http://<host>/api/v1/vuln/vulners/search' \ \
  -H 'X-API-Key: $API_KEY' \ \
  -H 'Content-Type: application/json'
```

### 🟢 `GET /api/v1/vuln/vulners/software`

Vulners Check Software

**请求参数：**

| 参数名 | 位置 | 类型 | 必填 | 说明 |
|---|---|---|---|---|
| `software` | query | string | ✅ | 软件名称，如 apache |
| `version` | query | string | ✅ | 版本号，如 2.4.49 |

**调用示例：**

```bash
curl -X GET 'http://<host>/api/v1/vuln/vulners/software' \ \
  -H 'X-API-Key: $API_KEY' \ \
  -H 'Content-Type: application/json'
```

### 🔵 `POST /api/v1/vuln/import`

Import Vulnerabilities

**请求参数：**

| 参数名 | 位置 | 类型 | 必填 | 说明 |
|---|---|---|---|---|
| `filepath` | query | string | ✅ | JSON文件路径 |

**调用示例：**

```bash
curl -X POST 'http://<host>/api/v1/vuln/import' \ \
  -H 'X-API-Key: $API_KEY' \ \
  -H 'Content-Type: application/json'
```

### 🟢 `GET /api/v1/vuln/export`

Export Vulnerabilities

**请求参数：**

| 参数名 | 位置 | 类型 | 必填 | 说明 |
|---|---|---|---|---|
| `filepath` | query | string | — | 导出文件路径 |

**调用示例：**

```bash
curl -X GET 'http://<host>/api/v1/vuln/export' \ \
  -H 'X-API-Key: $API_KEY' \ \
  -H 'Content-Type: application/json'
```


## 用户管理

本模块共 6 个端点。

### 🔵 `POST /api/v1/auth/register`

Auth Register

**请求参数：**

（无请求参数）

**请求体示例：**

```json
{
  "username": "string",
  "password": "string",
  "email": "string",
  "role": "string"
}
```

**调用示例：**

```bash
curl -X POST 'http://<host>/api/v1/auth/register' \ \
  -H 'X-API-Key: $API_KEY' \ \
  -H 'Content-Type: application/json' \
  -d '{}'
```

### 🔵 `POST /api/v1/auth/login`

Auth Login

**请求参数：**

（无请求参数）

**请求体示例：**

```json
{
  "username": "string",
  "password": "string"
}
```

**调用示例：**

```bash
curl -X POST 'http://<host>/api/v1/auth/login' \ \
  -H 'X-API-Key: $API_KEY' \ \
  -H 'Content-Type: application/json' \
  -d '{}'
```

### 🟢 `GET /api/v1/users`

List Users

**请求参数：**

| 参数名 | 位置 | 类型 | 必填 | 说明 |
|---|---|---|---|---|
| `limit` | query | integer | — |  |

**调用示例：**

```bash
curl -X GET 'http://<host>/api/v1/users' \ \
  -H 'X-API-Key: $API_KEY' \ \
  -H 'Content-Type: application/json'
```

### 🟢 `GET /api/v1/users/{user_id}`

Get User

**请求参数：**

| 参数名 | 位置 | 类型 | 必填 | 说明 |
|---|---|---|---|---|
| `user_id` | path | string | ✅ |  |

**调用示例：**

```bash
curl -X GET 'http://<host>/api/v1/users/{user_id}' \ \
  -H 'X-API-Key: $API_KEY' \ \
  -H 'Content-Type: application/json'
```

### 🔵 `POST /api/v1/users/{user_id}/regenerate-key`

Regenerate Api Key

**请求参数：**

| 参数名 | 位置 | 类型 | 必填 | 说明 |
|---|---|---|---|---|
| `user_id` | path | string | ✅ |  |

**调用示例：**

```bash
curl -X POST 'http://<host>/api/v1/users/{user_id}/regenerate-key' \ \
  -H 'X-API-Key: $API_KEY' \ \
  -H 'Content-Type: application/json'
```

### 🟢 `GET /api/v1/audit-logs`

Get Audit Logs

**请求参数：**

| 参数名 | 位置 | 类型 | 必填 | 说明 |
|---|---|---|---|---|
| `user_id` | query | any | — |  |
| `action` | query | any | — |  |
| `limit` | query | integer | — |  |

**调用示例：**

```bash
curl -X GET 'http://<host>/api/v1/audit-logs' \ \
  -H 'X-API-Key: $API_KEY' \ \
  -H 'Content-Type: application/json'
```


## 用户认证

本模块共 8 个端点。

### 🔵 `POST /api/v1/auth/logout`

用户登出

**请求参数：**

（无请求参数）

**调用示例：**

```bash
curl -X POST 'http://<host>/api/v1/auth/logout' \ \
  -H 'X-API-Key: $API_KEY' \ \
  -H 'Content-Type: application/json'
```

### 🟢 `GET /api/v1/auth/me`

获取当前用户信息

**请求参数：**

（无请求参数）

**调用示例：**

```bash
curl -X GET 'http://<host>/api/v1/auth/me' \ \
  -H 'X-API-Key: $API_KEY' \ \
  -H 'Content-Type: application/json'
```

### 🔵 `POST /api/v1/auth/change-password`

修改密码

**请求参数：**

（无请求参数）

**请求体示例：**

```json
{
  "old_password": "string",
  "new_password": "string"
}
```

**调用示例：**

```bash
curl -X POST 'http://<host>/api/v1/auth/change-password' \ \
  -H 'X-API-Key: $API_KEY' \ \
  -H 'Content-Type: application/json' \
  -d '{}'
```

### 🟢 `GET /api/v1/auth/api-keys`

获取用户API密钥列表

**请求参数：**

（无请求参数）

**调用示例：**

```bash
curl -X GET 'http://<host>/api/v1/auth/api-keys' \ \
  -H 'X-API-Key: $API_KEY' \ \
  -H 'Content-Type: application/json'
```

### 🔵 `POST /api/v1/auth/api-keys`

创建新的API密钥

**请求参数：**

（无请求参数）

**请求体示例：**

```json
{
  "name": "string",
  "expires_in_days": "string"
}
```

**调用示例：**

```bash
curl -X POST 'http://<host>/api/v1/auth/api-keys' \ \
  -H 'X-API-Key: $API_KEY' \ \
  -H 'Content-Type: application/json' \
  -d '{}'
```

### 🔴 `DELETE /api/v1/auth/api-keys/{key_id}`

删除API密钥

**请求参数：**

| 参数名 | 位置 | 类型 | 必填 | 说明 |
|---|---|---|---|---|
| `key_id` | path | string | ✅ |  |

**调用示例：**

```bash
curl -X DELETE 'http://<host>/api/v1/auth/api-keys/{key_id}' \ \
  -H 'X-API-Key: $API_KEY' \ \
  -H 'Content-Type: application/json'
```

### 🟢 `GET /api/v1/auth/users`

获取所有用户（管理员）

**请求参数：**

| 参数名 | 位置 | 类型 | 必填 | 说明 |
|---|---|---|---|---|
| `limit` | query | integer | — |  |
| `offset` | query | integer | — |  |

**调用示例：**

```bash
curl -X GET 'http://<host>/api/v1/auth/users' \ \
  -H 'X-API-Key: $API_KEY' \ \
  -H 'Content-Type: application/json'
```

### 🟢 `GET /api/v1/auth/stats`

获取认证系统统计

**请求参数：**

（无请求参数）

**调用示例：**

```bash
curl -X GET 'http://<host>/api/v1/auth/stats' \ \
  -H 'X-API-Key: $API_KEY' \ \
  -H 'Content-Type: application/json'
```


## 监控

本模块共 14 个端点。

### 🟢 `GET /api/monitoring/scheduled-tasks`

列出所有定时任务

**请求参数：**

| 参数名 | 位置 | 类型 | 必填 | 说明 |
|---|---|---|---|---|
| `enabled_only` | query | boolean | — |  |

**调用示例：**

```bash
curl -X GET 'http://<host>/api/monitoring/scheduled-tasks' \ \
  -H 'X-API-Key: $API_KEY' \ \
  -H 'Content-Type: application/json'
```

### 🔵 `POST /api/monitoring/scheduled-tasks`

创建定时任务

**请求参数：**

（无请求参数）

**请求体示例：**

```json
{
  "name": "string",
  "target": "example.com",
  "scan_type": "string",
  "schedule_type": "string",
  "cron_expression": "string",
  "interval_seconds": "string",
  "options": "string"
}
```

**调用示例：**

```bash
curl -X POST 'http://<host>/api/monitoring/scheduled-tasks' \ \
  -H 'X-API-Key: $API_KEY' \ \
  -H 'Content-Type: application/json' \
  -d '{}'
```

### 🟢 `GET /api/monitoring/scheduled-tasks/{task_id}`

获取定时任务详情

**请求参数：**

| 参数名 | 位置 | 类型 | 必填 | 说明 |
|---|---|---|---|---|
| `task_id` | path | string | ✅ |  |

**调用示例：**

```bash
curl -X GET 'http://<host>/api/monitoring/scheduled-tasks/{task_id}' \ \
  -H 'X-API-Key: $API_KEY' \ \
  -H 'Content-Type: application/json'
```

### 🟡 `PUT /api/monitoring/scheduled-tasks/{task_id}`

更新定时任务

**请求参数：**

| 参数名 | 位置 | 类型 | 必填 | 说明 |
|---|---|---|---|---|
| `task_id` | path | string | ✅ |  |

**请求体示例：**

```json
{
  "name": "string",
  "target": "example.com",
  "scan_type": "string",
  "schedule_type": "string",
  "cron_expression": "string",
  "interval_seconds": "string",
  "options": "string",
  "enabled": "string"
}
```

**调用示例：**

```bash
curl -X PUT 'http://<host>/api/monitoring/scheduled-tasks/{task_id}' \ \
  -H 'X-API-Key: $API_KEY' \ \
  -H 'Content-Type: application/json' \
  -d '{}'
```

### 🔴 `DELETE /api/monitoring/scheduled-tasks/{task_id}`

删除定时任务

**请求参数：**

| 参数名 | 位置 | 类型 | 必填 | 说明 |
|---|---|---|---|---|
| `task_id` | path | string | ✅ |  |

**调用示例：**

```bash
curl -X DELETE 'http://<host>/api/monitoring/scheduled-tasks/{task_id}' \ \
  -H 'X-API-Key: $API_KEY' \ \
  -H 'Content-Type: application/json'
```

### 🔵 `POST /api/monitoring/scheduled-tasks/{task_id}/run`

立即执行一次定时任务

**请求参数：**

| 参数名 | 位置 | 类型 | 必填 | 说明 |
|---|---|---|---|---|
| `task_id` | path | string | ✅ |  |

**调用示例：**

```bash
curl -X POST 'http://<host>/api/monitoring/scheduled-tasks/{task_id}/run' \ \
  -H 'X-API-Key: $API_KEY' \ \
  -H 'Content-Type: application/json'
```

### 🟢 `GET /api/monitoring/scheduled-tasks/{task_id}/history`

获取任务执行历史

**请求参数：**

| 参数名 | 位置 | 类型 | 必填 | 说明 |
|---|---|---|---|---|
| `task_id` | path | string | ✅ |  |
| `limit` | query | integer | — |  |

**调用示例：**

```bash
curl -X GET 'http://<host>/api/monitoring/scheduled-tasks/{task_id}/history' \ \
  -H 'X-API-Key: $API_KEY' \ \
  -H 'Content-Type: application/json'
```

### 🟢 `GET /api/monitoring/nodes`

列出分布式节点状态

**请求参数：**

| 参数名 | 位置 | 类型 | 必填 | 说明 |
|---|---|---|---|---|
| `status` | query | any | — |  |

**调用示例：**

```bash
curl -X GET 'http://<host>/api/monitoring/nodes' \ \
  -H 'X-API-Key: $API_KEY' \ \
  -H 'Content-Type: application/json'
```

### 🟢 `GET /api/monitoring/alerts`

列出告警

**请求参数：**

| 参数名 | 位置 | 类型 | 必填 | 说明 |
|---|---|---|---|---|
| `status` | query | any | — |  |
| `severity` | query | any | — |  |
| `limit` | query | integer | — |  |

**调用示例：**

```bash
curl -X GET 'http://<host>/api/monitoring/alerts' \ \
  -H 'X-API-Key: $API_KEY' \ \
  -H 'Content-Type: application/json'
```

### 🟢 `GET /api/monitoring/alerts/{alert_id}`

获取告警详情

**请求参数：**

| 参数名 | 位置 | 类型 | 必填 | 说明 |
|---|---|---|---|---|
| `alert_id` | path | string | ✅ |  |

**调用示例：**

```bash
curl -X GET 'http://<host>/api/monitoring/alerts/{alert_id}' \ \
  -H 'X-API-Key: $API_KEY' \ \
  -H 'Content-Type: application/json'
```

### 🔵 `POST /api/monitoring/alerts/{alert_id}/acknowledge`

确认告警

**请求参数：**

| 参数名 | 位置 | 类型 | 必填 | 说明 |
|---|---|---|---|---|
| `alert_id` | path | string | ✅ |  |

**请求体示例：**

```json
{
  "user": "string"
}
```

**调用示例：**

```bash
curl -X POST 'http://<host>/api/monitoring/alerts/{alert_id}/acknowledge' \ \
  -H 'X-API-Key: $API_KEY' \ \
  -H 'Content-Type: application/json' \
  -d '{}'
```

### 🔵 `POST /api/monitoring/alerts/{alert_id}/close`

关闭告警

**请求参数：**

| 参数名 | 位置 | 类型 | 必填 | 说明 |
|---|---|---|---|---|
| `alert_id` | path | string | ✅ |  |

**请求体示例：**

```json
{
  "user": "string"
}
```

**调用示例：**

```bash
curl -X POST 'http://<host>/api/monitoring/alerts/{alert_id}/close' \ \
  -H 'X-API-Key: $API_KEY' \ \
  -H 'Content-Type: application/json' \
  -d '{}'
```

### 🟢 `GET /api/monitoring/proxy-pool`

代理池状态

**请求参数：**

（无请求参数）

**调用示例：**

```bash
curl -X GET 'http://<host>/api/monitoring/proxy-pool' \ \
  -H 'X-API-Key: $API_KEY' \ \
  -H 'Content-Type: application/json'
```

### 🔵 `POST /api/monitoring/proxy-pool/check`

触发代理健康检查

**请求参数：**

（无请求参数）

**调用示例：**

```bash
curl -X POST 'http://<host>/api/monitoring/proxy-pool/check' \ \
  -H 'X-API-Key: $API_KEY' \ \
  -H 'Content-Type: application/json'
```


## 知识库

本模块共 3 个端点。

### 🔵 `POST /api/v1/knowledge/rag`

Rag Retrieve

**请求参数：**

（无请求参数）

**请求体示例：**

```json
{
  "query": "string",
  "top_k": 0,
  "category": "string"
}
```

**调用示例：**

```bash
curl -X POST 'http://<host>/api/v1/knowledge/rag' \ \
  -H 'X-API-Key: $API_KEY' \ \
  -H 'Content-Type: application/json' \
  -d '{}'
```

### 🟢 `GET /api/v1/knowledge/cve`

List Cves

**请求参数：**

| 参数名 | 位置 | 类型 | 必填 | 说明 |
|---|---|---|---|---|
| `limit` | query | integer | — |  |

**调用示例：**

```bash
curl -X GET 'http://<host>/api/v1/knowledge/cve' \ \
  -H 'X-API-Key: $API_KEY' \ \
  -H 'Content-Type: application/json'
```

### 🟢 `GET /api/v1/knowledge/stats`

Knowledge Stats

**请求参数：**

（无请求参数）

**调用示例：**

```bash
curl -X GET 'http://<host>/api/v1/knowledge/stats' \ \
  -H 'X-API-Key: $API_KEY' \ \
  -H 'Content-Type: application/json'
```


## 系统

本模块共 4 个端点。

### 🟢 `GET /`

Root

**请求参数：**

（无请求参数）

**调用示例：**

```bash
curl -X GET 'http://<host>/' \ \
  -H 'X-API-Key: $API_KEY' \ \
  -H 'Content-Type: application/json'
```

### 🟢 `GET /health`

Health Check

**请求参数：**

（无请求参数）

**调用示例：**

```bash
curl -X GET 'http://<host>/health' \ \
  -H 'X-API-Key: $API_KEY' \ \
  -H 'Content-Type: application/json'
```

### 🟢 `GET /api/v1/system/stats`

System Stats

**请求参数：**

（无请求参数）

**调用示例：**

```bash
curl -X GET 'http://<host>/api/v1/system/stats' \ \
  -H 'X-API-Key: $API_KEY' \ \
  -H 'Content-Type: application/json'
```

### 🟢 `GET /api/v1/system/config`

System Config

**请求参数：**

（无请求参数）

**调用示例：**

```bash
curl -X GET 'http://<host>/api/v1/system/config' \ \
  -H 'X-API-Key: $API_KEY' \ \
  -H 'Content-Type: application/json'
```


## 统一平台控制台

本模块共 6 个端点。

### 🟢 `GET /api/platform/overview`

Platform Overview

**请求参数：**

（无请求参数）

**调用示例：**

```bash
curl -X GET 'http://<host>/api/platform/overview' \ \
  -H 'X-API-Key: $API_KEY' \ \
  -H 'Content-Type: application/json'
```

### 🟢 `GET /api/platform/tools-status`

Tools Status

**请求参数：**

（无请求参数）

**调用示例：**

```bash
curl -X GET 'http://<host>/api/platform/tools-status' \ \
  -H 'X-API-Key: $API_KEY' \ \
  -H 'Content-Type: application/json'
```

### 🟢 `GET /api/platform/stats`

Platform Stats

**请求参数：**

（无请求参数）

**调用示例：**

```bash
curl -X GET 'http://<host>/api/platform/stats' \ \
  -H 'X-API-Key: $API_KEY' \ \
  -H 'Content-Type: application/json'
```

### 🟢 `GET /api/platform/recent-activity`

Recent Activity

**请求参数：**

| 参数名 | 位置 | 类型 | 必填 | 说明 |
|---|---|---|---|---|
| `limit` | query | integer | — |  |

**调用示例：**

```bash
curl -X GET 'http://<host>/api/platform/recent-activity' \ \
  -H 'X-API-Key: $API_KEY' \ \
  -H 'Content-Type: application/json'
```

### 🟢 `GET /api/platform/nav-config`

Nav Config

**请求参数：**

（无请求参数）

**调用示例：**

```bash
curl -X GET 'http://<host>/api/platform/nav-config' \ \
  -H 'X-API-Key: $API_KEY' \ \
  -H 'Content-Type: application/json'
```

### 🟢 `GET /api/platform/health`

Platform Health

**请求参数：**

（无请求参数）

**调用示例：**

```bash
curl -X GET 'http://<host>/api/platform/health' \ \
  -H 'X-API-Key: $API_KEY' \ \
  -H 'Content-Type: application/json'
```


## 超级智能体

本模块共 3 个端点。

### 🔵 `POST /api/v1/super-agent/execute`

Super Agent Execute

**请求参数：**

（无请求参数）

**请求体示例：**

```json
{
  "task": "string",
  "context": "string"
}
```

**调用示例：**

```bash
curl -X POST 'http://<host>/api/v1/super-agent/execute' \ \
  -H 'X-API-Key: $API_KEY' \ \
  -H 'Content-Type: application/json' \
  -d '{}'
```

### 🟢 `GET /api/v1/super-agent/capabilities`

Super Agent Capabilities

**请求参数：**

（无请求参数）

**调用示例：**

```bash
curl -X GET 'http://<host>/api/v1/super-agent/capabilities' \ \
  -H 'X-API-Key: $API_KEY' \ \
  -H 'Content-Type: application/json'
```

### 🟢 `GET /api/v1/super-agent/history`

Super Agent History

**请求参数：**

| 参数名 | 位置 | 类型 | 必填 | 说明 |
|---|---|---|---|---|
| `limit` | query | integer | — |  |

**调用示例：**

```bash
curl -X GET 'http://<host>/api/v1/super-agent/history' \ \
  -H 'X-API-Key: $API_KEY' \ \
  -H 'Content-Type: application/json'
```


## 防御中心

本模块共 10 个端点。

### 🔵 `POST /api/v1/defense/ids/analyze`

分析单条请求/日志

**请求参数：**

（无请求参数）

**请求体示例：**

```json
{
  "packet": "string",
  "log_line": "string"
}
```

**调用示例：**

```bash
curl -X POST 'http://<host>/api/v1/defense/ids/analyze' \ \
  -H 'X-API-Key: $API_KEY' \ \
  -H 'Content-Type: application/json' \
  -d '{}'
```

### 🔵 `POST /api/v1/defense/ids/analyze-file`

批量分析日志/流量文件

**请求参数：**

（无请求参数）

**请求体示例：**

```json
{
  "filepath": "string",
  "log_type": "string"
}
```

**调用示例：**

```bash
curl -X POST 'http://<host>/api/v1/defense/ids/analyze-file' \ \
  -H 'X-API-Key: $API_KEY' \ \
  -H 'Content-Type: application/json' \
  -d '{}'
```

### 🟢 `GET /api/v1/defense/ids/alerts`

获取告警列表

**请求参数：**

| 参数名 | 位置 | 类型 | 必填 | 说明 |
|---|---|---|---|---|
| `severity` | query | any | — | info/warning/critical |

**调用示例：**

```bash
curl -X GET 'http://<host>/api/v1/defense/ids/alerts' \ \
  -H 'X-API-Key: $API_KEY' \ \
  -H 'Content-Type: application/json'
```

### 🔵 `POST /api/v1/defense/log/analyze`

分析日志文件

**请求参数：**

（无请求参数）

**请求体示例：**

```json
{
  "filepath": "string",
  "log_type": "string"
}
```

**调用示例：**

```bash
curl -X POST 'http://<host>/api/v1/defense/log/analyze' \ \
  -H 'X-API-Key: $API_KEY' \ \
  -H 'Content-Type: application/json' \
  -d '{}'
```

### 🟢 `GET /api/v1/defense/log/statistics`

获取日志统计

**请求参数：**

（无请求参数）

**调用示例：**

```bash
curl -X GET 'http://<host>/api/v1/defense/log/statistics' \ \
  -H 'X-API-Key: $API_KEY' \ \
  -H 'Content-Type: application/json'
```

### 🔵 `POST /api/v1/defense/baseline/check`

执行基线检查

**请求参数：**

（无请求参数）

**请求体示例：**

```json
{
  "category": "string",
  "configs": "string"
}
```

**调用示例：**

```bash
curl -X POST 'http://<host>/api/v1/defense/baseline/check' \ \
  -H 'X-API-Key: $API_KEY' \ \
  -H 'Content-Type: application/json' \
  -d '{}'
```

### 🟢 `GET /api/v1/defense/baseline/report`

获取基线检查报告

**请求参数：**

（无请求参数）

**调用示例：**

```bash
curl -X GET 'http://<host>/api/v1/defense/baseline/report' \ \
  -H 'X-API-Key: $API_KEY' \ \
  -H 'Content-Type: application/json'
```

### 🔵 `POST /api/v1/defense/remediation/verify`

验证漏洞修复

**请求参数：**

（无请求参数）

**请求体示例：**

```json
{
  "vulns": []
}
```

**调用示例：**

```bash
curl -X POST 'http://<host>/api/v1/defense/remediation/verify' \ \
  -H 'X-API-Key: $API_KEY' \ \
  -H 'Content-Type: application/json' \
  -d '{}'
```

### 🔵 `POST /api/v1/defense/threat-hunt/run`

执行威胁狩猎

**请求参数：**

（无请求参数）

**请求体示例：**

```json
{
  "scenario": "string",
  "events": [],
  "iocs": "string"
}
```

**调用示例：**

```bash
curl -X POST 'http://<host>/api/v1/defense/threat-hunt/run' \ \
  -H 'X-API-Key: $API_KEY' \ \
  -H 'Content-Type: application/json' \
  -d '{}'
```

### 🟢 `GET /api/v1/defense/threat-hunt/findings`

获取狩猎发现

**请求参数：**

（无请求参数）

**调用示例：**

```bash
curl -X GET 'http://<host>/api/v1/defense/threat-hunt/findings' \ \
  -H 'X-API-Key: $API_KEY' \ \
  -H 'Content-Type: application/json'
```


## 集成管理

本模块共 21 个端点。

### 🟢 `GET /api/v1/integrations/siem/config`

获取 SIEM 配置

**请求参数：**

（无请求参数）

**调用示例：**

```bash
curl -X GET 'http://<host>/api/v1/integrations/siem/config' \ \
  -H 'X-API-Key: $API_KEY' \ \
  -H 'Content-Type: application/json'
```

### 🟡 `PUT /api/v1/integrations/siem/config`

更新 SIEM 配置

**请求参数：**

（无请求参数）

**请求体示例：**

```json
{
  "config": {}
}
```

**调用示例：**

```bash
curl -X PUT 'http://<host>/api/v1/integrations/siem/config' \ \
  -H 'X-API-Key: $API_KEY' \ \
  -H 'Content-Type: application/json' \
  -d '{}'
```

### 🔵 `POST /api/v1/integrations/siem/test`

测试 SIEM 连接

**请求参数：**

（无请求参数）

**调用示例：**

```bash
curl -X POST 'http://<host>/api/v1/integrations/siem/test' \ \
  -H 'X-API-Key: $API_KEY' \ \
  -H 'Content-Type: application/json'
```

### 🔵 `POST /api/v1/integrations/siem/push-test`

推送测试告警到 SIEM

**请求参数：**

（无请求参数）

**调用示例：**

```bash
curl -X POST 'http://<host>/api/v1/integrations/siem/push-test' \ \
  -H 'X-API-Key: $API_KEY' \ \
  -H 'Content-Type: application/json'
```

### 🟢 `GET /api/v1/integrations/ticket/config`

获取工单系统配置

**请求参数：**

（无请求参数）

**调用示例：**

```bash
curl -X GET 'http://<host>/api/v1/integrations/ticket/config' \ \
  -H 'X-API-Key: $API_KEY' \ \
  -H 'Content-Type: application/json'
```

### 🟡 `PUT /api/v1/integrations/ticket/config`

更新工单系统配置

**请求参数：**

（无请求参数）

**请求体示例：**

```json
{
  "config": {}
}
```

**调用示例：**

```bash
curl -X PUT 'http://<host>/api/v1/integrations/ticket/config' \ \
  -H 'X-API-Key: $API_KEY' \ \
  -H 'Content-Type: application/json' \
  -d '{}'
```

### 🔵 `POST /api/v1/integrations/ticket/test`

测试工单系统连接

**请求参数：**

（无请求参数）

**调用示例：**

```bash
curl -X POST 'http://<host>/api/v1/integrations/ticket/test' \ \
  -H 'X-API-Key: $API_KEY' \ \
  -H 'Content-Type: application/json'
```

### 🔵 `POST /api/v1/integrations/ticket/create`

自动创建漏洞工单

**请求参数：**

（无请求参数）

**请求体示例：**

```json
{
  "vuln_data": {},
  "summary": "string"
}
```

**调用示例：**

```bash
curl -X POST 'http://<host>/api/v1/integrations/ticket/create' \ \
  -H 'X-API-Key: $API_KEY' \ \
  -H 'Content-Type: application/json' \
  -d '{}'
```

### 🔵 `POST /api/v1/integrations/ticket/{ticket_id}/sync`

同步工单状态

**请求参数：**

| 参数名 | 位置 | 类型 | 必填 | 说明 |
|---|---|---|---|---|
| `ticket_id` | path | string | ✅ |  |

**调用示例：**

```bash
curl -X POST 'http://<host>/api/v1/integrations/ticket/{ticket_id}/sync' \ \
  -H 'X-API-Key: $API_KEY' \ \
  -H 'Content-Type: application/json'
```

### 🟢 `GET /api/v1/integrations/notification/channels`

获取通知渠道状态

**请求参数：**

（无请求参数）

**调用示例：**

```bash
curl -X GET 'http://<host>/api/v1/integrations/notification/channels' \ \
  -H 'X-API-Key: $API_KEY' \ \
  -H 'Content-Type: application/json'
```

### 🟡 `PUT /api/v1/integrations/notification/{channel}/config`

更新通知渠道配置

**请求参数：**

| 参数名 | 位置 | 类型 | 必填 | 说明 |
|---|---|---|---|---|
| `channel` | path | string | ✅ |  |

**请求体示例：**

```json
{
  "config": {}
}
```

**调用示例：**

```bash
curl -X PUT 'http://<host>/api/v1/integrations/notification/{channel}/config' \ \
  -H 'X-API-Key: $API_KEY' \ \
  -H 'Content-Type: application/json' \
  -d '{}'
```

### 🔵 `POST /api/v1/integrations/notification/{channel}/test`

发送渠道测试消息

**请求参数：**

| 参数名 | 位置 | 类型 | 必填 | 说明 |
|---|---|---|---|---|
| `channel` | path | string | ✅ |  |

**调用示例：**

```bash
curl -X POST 'http://<host>/api/v1/integrations/notification/{channel}/test' \ \
  -H 'X-API-Key: $API_KEY' \ \
  -H 'Content-Type: application/json'
```

### 🔵 `POST /api/v1/integrations/notification/send`

推送告警到通知渠道

**请求参数：**

（无请求参数）

**请求体示例：**

```json
{
  "alert": {},
  "channels": "string"
}
```

**调用示例：**

```bash
curl -X POST 'http://<host>/api/v1/integrations/notification/send' \ \
  -H 'X-API-Key: $API_KEY' \ \
  -H 'Content-Type: application/json' \
  -d '{}'
```

### 🟢 `GET /api/v1/integrations/ldap/config`

获取 LDAP 配置

**请求参数：**

（无请求参数）

**调用示例：**

```bash
curl -X GET 'http://<host>/api/v1/integrations/ldap/config' \ \
  -H 'X-API-Key: $API_KEY' \ \
  -H 'Content-Type: application/json'
```

### 🟡 `PUT /api/v1/integrations/ldap/config`

更新 LDAP 配置

**请求参数：**

（无请求参数）

**请求体示例：**

```json
{
  "config": {}
}
```

**调用示例：**

```bash
curl -X PUT 'http://<host>/api/v1/integrations/ldap/config' \ \
  -H 'X-API-Key: $API_KEY' \ \
  -H 'Content-Type: application/json' \
  -d '{}'
```

### 🔵 `POST /api/v1/integrations/ldap/test`

测试 LDAP 连接

**请求参数：**

（无请求参数）

**调用示例：**

```bash
curl -X POST 'http://<host>/api/v1/integrations/ldap/test' \ \
  -H 'X-API-Key: $API_KEY' \ \
  -H 'Content-Type: application/json'
```

### 🔵 `POST /api/v1/integrations/ldap/sync-users`

查看已同步的 LDAP 用户

**请求参数：**

（无请求参数）

**调用示例：**

```bash
curl -X POST 'http://<host>/api/v1/integrations/ldap/sync-users' \ \
  -H 'X-API-Key: $API_KEY' \ \
  -H 'Content-Type: application/json'
```

### 🔵 `POST /api/v1/integrations/vuln-db/sync`

触发漏洞库同步

**请求参数：**

（无请求参数）

**请求体示例：**

```json
{
  "source": "string",
  "keyword": "string",
  "cve_id": "xxx-xxx",
  "max_results": 0
}
```

**调用示例：**

```bash
curl -X POST 'http://<host>/api/v1/integrations/vuln-db/sync' \ \
  -H 'X-API-Key: $API_KEY' \ \
  -H 'Content-Type: application/json' \
  -d '{}'
```

### 🟢 `GET /api/v1/integrations/vuln-db/status`

获取漏洞库同步状态

**请求参数：**

（无请求参数）

**调用示例：**

```bash
curl -X GET 'http://<host>/api/v1/integrations/vuln-db/status' \ \
  -H 'X-API-Key: $API_KEY' \ \
  -H 'Content-Type: application/json'
```

### 🟢 `GET /api/v1/integrations/vuln-db/stats`

获取漏洞库统计

**请求参数：**

（无请求参数）

**调用示例：**

```bash
curl -X GET 'http://<host>/api/v1/integrations/vuln-db/stats' \ \
  -H 'X-API-Key: $API_KEY' \ \
  -H 'Content-Type: application/json'
```

### 🟢 `GET /api/v1/integrations/vuln-db/search`

本地漏洞库搜索

**请求参数：**

| 参数名 | 位置 | 类型 | 必填 | 说明 |
|---|---|---|---|---|
| `keyword` | query | string | — |  |
| `severity` | query | any | — |  |

**调用示例：**

```bash
curl -X GET 'http://<host>/api/v1/integrations/vuln-db/search' \ \
  -H 'X-API-Key: $API_KEY' \ \
  -H 'Content-Type: application/json'
```


## 高级安全

本模块共 22 个端点。

### 🟢 `GET /api/v1/security/vuln-lifecycle/list`

Vuln List

**请求参数：**

| 参数名 | 位置 | 类型 | 必填 | 说明 |
|---|---|---|---|---|
| `status` | query | any | — |  |

**调用示例：**

```bash
curl -X GET 'http://<host>/api/v1/security/vuln-lifecycle/list' \ \
  -H 'X-API-Key: $API_KEY' \ \
  -H 'Content-Type: application/json'
```

### 🔵 `POST /api/v1/security/vuln-lifecycle`

Vuln Create

**请求参数：**

（无请求参数）

**请求体示例：**

```json
{
  "title": "string",
  "severity": "string",
  "target": "example.com",
  "description": "string",
  "cve": "string"
}
```

**调用示例：**

```bash
curl -X POST 'http://<host>/api/v1/security/vuln-lifecycle' \ \
  -H 'X-API-Key: $API_KEY' \ \
  -H 'Content-Type: application/json' \
  -d '{}'
```

### 🔵 `POST /api/v1/security/vuln-lifecycle/{vuln_id}/transition`

Vuln Transition

**请求参数：**

| 参数名 | 位置 | 类型 | 必填 | 说明 |
|---|---|---|---|---|
| `vuln_id` | path | string | ✅ |  |

**请求体示例：**

```json
{
  "to_status": "string",
  "changed_by": "string",
  "note": "string"
}
```

**调用示例：**

```bash
curl -X POST 'http://<host>/api/v1/security/vuln-lifecycle/{vuln_id}/transition' \ \
  -H 'X-API-Key: $API_KEY' \ \
  -H 'Content-Type: application/json' \
  -d '{}'
```

### 🔵 `POST /api/v1/security/vuln-lifecycle/{vuln_id}/assign`

Vuln Assign

**请求参数：**

| 参数名 | 位置 | 类型 | 必填 | 说明 |
|---|---|---|---|---|
| `vuln_id` | path | string | ✅ |  |

**请求体示例：**

```json
{
  "assignee": "string",
  "note": "string"
}
```

**调用示例：**

```bash
curl -X POST 'http://<host>/api/v1/security/vuln-lifecycle/{vuln_id}/assign' \ \
  -H 'X-API-Key: $API_KEY' \ \
  -H 'Content-Type: application/json' \
  -d '{}'
```

### 🔵 `POST /api/v1/security/vuln-lifecycle/{vuln_id}/verify`

Vuln Verify

**请求参数：**

| 参数名 | 位置 | 类型 | 必填 | 说明 |
|---|---|---|---|---|
| `vuln_id` | path | string | ✅ |  |

**请求体示例：**

```json
{
  "result": true,
  "verified_by": "string"
}
```

**调用示例：**

```bash
curl -X POST 'http://<host>/api/v1/security/vuln-lifecycle/{vuln_id}/verify' \ \
  -H 'X-API-Key: $API_KEY' \ \
  -H 'Content-Type: application/json' \
  -d '{}'
```

### 🟢 `GET /api/v1/security/vuln-lifecycle/{vuln_id}/history`

Vuln History

**请求参数：**

| 参数名 | 位置 | 类型 | 必填 | 说明 |
|---|---|---|---|---|
| `vuln_id` | path | string | ✅ |  |

**调用示例：**

```bash
curl -X GET 'http://<host>/api/v1/security/vuln-lifecycle/{vuln_id}/history' \ \
  -H 'X-API-Key: $API_KEY' \ \
  -H 'Content-Type: application/json'
```

### 🟢 `GET /api/v1/security/vuln-lifecycle/overdue`

Vuln Overdue

**请求参数：**

（无请求参数）

**调用示例：**

```bash
curl -X GET 'http://<host>/api/v1/security/vuln-lifecycle/overdue' \ \
  -H 'X-API-Key: $API_KEY' \ \
  -H 'Content-Type: application/json'
```

### 🟢 `GET /api/v1/security/vuln-lifecycle/stats`

Vuln Stats

**请求参数：**

（无请求参数）

**调用示例：**

```bash
curl -X GET 'http://<host>/api/v1/security/vuln-lifecycle/stats' \ \
  -H 'X-API-Key: $API_KEY' \ \
  -H 'Content-Type: application/json'
```

### 🔵 `POST /api/v1/security/asset-discovery/scan`

Asset Scan

**请求参数：**

（无请求参数）

**请求体示例：**

```json
{
  "cidr": "xxx-xxx",
  "scan_type": "string"
}
```

**调用示例：**

```bash
curl -X POST 'http://<host>/api/v1/security/asset-discovery/scan' \ \
  -H 'X-API-Key: $API_KEY' \ \
  -H 'Content-Type: application/json' \
  -d '{}'
```

### 🟢 `GET /api/v1/security/asset-discovery/assets`

Asset List

**请求参数：**

（无请求参数）

**调用示例：**

```bash
curl -X GET 'http://<host>/api/v1/security/asset-discovery/assets' \ \
  -H 'X-API-Key: $API_KEY' \ \
  -H 'Content-Type: application/json'
```

### 🟢 `GET /api/v1/security/asset-discovery/{asset_id}`

Asset Get

**请求参数：**

| 参数名 | 位置 | 类型 | 必填 | 说明 |
|---|---|---|---|---|
| `asset_id` | path | string | ✅ |  |

**调用示例：**

```bash
curl -X GET 'http://<host>/api/v1/security/asset-discovery/{asset_id}' \ \
  -H 'X-API-Key: $API_KEY' \ \
  -H 'Content-Type: application/json'
```

### 🔵 `POST /api/v1/security/asset-discovery/{asset_id}/detect-changes`

Asset Detect Changes

**请求参数：**

| 参数名 | 位置 | 类型 | 必填 | 说明 |
|---|---|---|---|---|
| `asset_id` | path | string | ✅ |  |

**调用示例：**

```bash
curl -X POST 'http://<host>/api/v1/security/asset-discovery/{asset_id}/detect-changes' \ \
  -H 'X-API-Key: $API_KEY' \ \
  -H 'Content-Type: application/json'
```

### 🟢 `GET /api/v1/security/asset-discovery/{asset_id}/risk`

Asset Risk

**请求参数：**

| 参数名 | 位置 | 类型 | 必填 | 说明 |
|---|---|---|---|---|
| `asset_id` | path | string | ✅ |  |

**调用示例：**

```bash
curl -X GET 'http://<host>/api/v1/security/asset-discovery/{asset_id}/risk' \ \
  -H 'X-API-Key: $API_KEY' \ \
  -H 'Content-Type: application/json'
```

### 🔵 `POST /api/v1/security/compliance/audit`

Compliance Audit

**请求参数：**

（无请求参数）

**请求体示例：**

```json
{
  "framework": "string",
  "target_data": "string"
}
```

**调用示例：**

```bash
curl -X POST 'http://<host>/api/v1/security/compliance/audit' \ \
  -H 'X-API-Key: $API_KEY' \ \
  -H 'Content-Type: application/json' \
  -d '{}'
```

### 🟢 `GET /api/v1/security/compliance/audits`

Compliance List

**请求参数：**

| 参数名 | 位置 | 类型 | 必填 | 说明 |
|---|---|---|---|---|
| `framework` | query | any | — |  |

**调用示例：**

```bash
curl -X GET 'http://<host>/api/v1/security/compliance/audits' \ \
  -H 'X-API-Key: $API_KEY' \ \
  -H 'Content-Type: application/json'
```

### 🟢 `GET /api/v1/security/compliance/{audit_id}/report`

Compliance Report

**请求参数：**

| 参数名 | 位置 | 类型 | 必填 | 说明 |
|---|---|---|---|---|
| `audit_id` | path | string | ✅ |  |

**调用示例：**

```bash
curl -X GET 'http://<host>/api/v1/security/compliance/{audit_id}/report' \ \
  -H 'X-API-Key: $API_KEY' \ \
  -H 'Content-Type: application/json'
```

### 🟢 `GET /api/v1/security/compliance/checklists`

Compliance Checklists

**请求参数：**

| 参数名 | 位置 | 类型 | 必填 | 说明 |
|---|---|---|---|---|
| `framework` | query | string | — |  |

**调用示例：**

```bash
curl -X GET 'http://<host>/api/v1/security/compliance/checklists' \ \
  -H 'X-API-Key: $API_KEY' \ \
  -H 'Content-Type: application/json'
```

### 🟢 `GET /api/v1/security/compliance/trend`

Compliance Trend

**请求参数：**

| 参数名 | 位置 | 类型 | 必填 | 说明 |
|---|---|---|---|---|
| `audit_id1` | query | string | ✅ |  |
| `audit_id2` | query | string | ✅ |  |

**调用示例：**

```bash
curl -X GET 'http://<host>/api/v1/security/compliance/trend' \ \
  -H 'X-API-Key: $API_KEY' \ \
  -H 'Content-Type: application/json'
```

### 🔵 `POST /api/v1/security/attack-path/generate`

Attack Generate

**请求参数：**

（无请求参数）

**请求体示例：**

```json
{
  "assets": [],
  "vulnerabilities": []
}
```

**调用示例：**

```bash
curl -X POST 'http://<host>/api/v1/security/attack-path/generate' \ \
  -H 'X-API-Key: $API_KEY' \ \
  -H 'Content-Type: application/json' \
  -d '{}'
```

### 🟢 `GET /api/v1/security/attack-path/{graph_id}/critical-paths`

Attack Critical

**请求参数：**

| 参数名 | 位置 | 类型 | 必填 | 说明 |
|---|---|---|---|---|
| `graph_id` | path | string | ✅ |  |
| `n` | query | integer | — |  |

**调用示例：**

```bash
curl -X GET 'http://<host>/api/v1/security/attack-path/{graph_id}/critical-paths' \ \
  -H 'X-API-Key: $API_KEY' \ \
  -H 'Content-Type: application/json'
```

### 🟢 `GET /api/v1/security/attack-path/{graph_id}/mitigations`

Attack Mitigations

**请求参数：**

| 参数名 | 位置 | 类型 | 必填 | 说明 |
|---|---|---|---|---|
| `graph_id` | path | string | ✅ |  |

**调用示例：**

```bash
curl -X GET 'http://<host>/api/v1/security/attack-path/{graph_id}/mitigations' \ \
  -H 'X-API-Key: $API_KEY' \ \
  -H 'Content-Type: application/json'
```

### 🟢 `GET /api/v1/security/attack-path/{graph_id}/visualize`

Attack Visualize

**请求参数：**

| 参数名 | 位置 | 类型 | 必填 | 说明 |
|---|---|---|---|---|
| `graph_id` | path | string | ✅ |  |
| `format` | query | string | — |  |

**调用示例：**

```bash
curl -X GET 'http://<host>/api/v1/security/attack-path/{graph_id}/visualize' \ \
  -H 'X-API-Key: $API_KEY' \ \
  -H 'Content-Type: application/json'
```


## 高级安全模块

本模块共 28 个端点。

### 🔵 `POST /api/v1/advanced/ai-security/detect-prompt-injection`

检测提示注入

**请求参数：**

（无请求参数）

**请求体示例：**

（无请求体）

**调用示例：**

```bash
curl -X POST 'http://<host>/api/v1/advanced/ai-security/detect-prompt-injection' \ \
  -H 'X-API-Key: $API_KEY' \ \
  -H 'Content-Type: application/json'
```

### 🔵 `POST /api/v1/advanced/ai-security/assess-model`

评估AI模型安全性

**请求参数：**

（无请求参数）

**调用示例：**

```bash
curl -X POST 'http://<host>/api/v1/advanced/ai-security/assess-model' \ \
  -H 'X-API-Key: $API_KEY' \ \
  -H 'Content-Type: application/json'
```

### 🔵 `POST /api/v1/advanced/ai-security/detect-data-poisoning`

检测数据投毒

**请求参数：**

（无请求参数）

**请求体示例：**

（无请求体）

**调用示例：**

```bash
curl -X POST 'http://<host>/api/v1/advanced/ai-security/detect-data-poisoning' \ \
  -H 'X-API-Key: $API_KEY' \ \
  -H 'Content-Type: application/json'
```

### 🔵 `POST /api/v1/advanced/iot/scan`

扫描IoT网络

**请求参数：**

（无请求参数）

**请求体示例：**

（无请求体）

**调用示例：**

```bash
curl -X POST 'http://<host>/api/v1/advanced/iot/scan' \ \
  -H 'X-API-Key: $API_KEY' \ \
  -H 'Content-Type: application/json'
```

### 🟢 `GET /api/v1/advanced/iot/default-credentials`

获取默认密码

**请求参数：**

| 参数名 | 位置 | 类型 | 必填 | 说明 |
|---|---|---|---|---|
| `vendor` | query | string | — | 厂商名称 |

**调用示例：**

```bash
curl -X GET 'http://<host>/api/v1/advanced/iot/default-credentials' \ \
  -H 'X-API-Key: $API_KEY' \ \
  -H 'Content-Type: application/json'
```

### 🔵 `POST /api/v1/advanced/iot/analyze-firmware`

分析固件

**请求参数：**

（无请求参数）

**请求体示例：**

（无请求体）

**调用示例：**

```bash
curl -X POST 'http://<host>/api/v1/advanced/iot/analyze-firmware' \ \
  -H 'X-API-Key: $API_KEY' \ \
  -H 'Content-Type: application/json'
```

### 🔵 `POST /api/v1/advanced/ics/scan`

扫描ICS网络

**请求参数：**

（无请求参数）

**请求体示例：**

（无请求体）

**调用示例：**

```bash
curl -X POST 'http://<host>/api/v1/advanced/ics/scan' \ \
  -H 'X-API-Key: $API_KEY' \ \
  -H 'Content-Type: application/json'
```

### 🟢 `GET /api/v1/advanced/ics/vulnerabilities`

获取已知ICS漏洞

**请求参数：**

| 参数名 | 位置 | 类型 | 必填 | 说明 |
|---|---|---|---|---|
| `vendor` | query | string | — | 厂商 |

**调用示例：**

```bash
curl -X GET 'http://<host>/api/v1/advanced/ics/vulnerabilities' \ \
  -H 'X-API-Key: $API_KEY' \ \
  -H 'Content-Type: application/json'
```

### 🟢 `GET /api/v1/advanced/ics/security-assessment`

ICS安全评估

**请求参数：**

（无请求参数）

**调用示例：**

```bash
curl -X GET 'http://<host>/api/v1/advanced/ics/security-assessment' \ \
  -H 'X-API-Key: $API_KEY' \ \
  -H 'Content-Type: application/json'
```

### 🔵 `POST /api/v1/advanced/blockchain/audit-contract`

审计智能合约

**请求参数：**

（无请求参数）

**请求体示例：**

（无请求体）

**调用示例：**

```bash
curl -X POST 'http://<host>/api/v1/advanced/blockchain/audit-contract' \ \
  -H 'X-API-Key: $API_KEY' \ \
  -H 'Content-Type: application/json'
```

### 🔵 `POST /api/v1/advanced/blockchain/check-erc20`

检查ERC20合规性

**请求参数：**

（无请求参数）

**请求体示例：**

（无请求体）

**调用示例：**

```bash
curl -X POST 'http://<host>/api/v1/advanced/blockchain/check-erc20' \ \
  -H 'X-API-Key: $API_KEY' \ \
  -H 'Content-Type: application/json'
```

### 🔵 `POST /api/v1/advanced/forensics/analyze-windows-logs`

分析Windows日志

**请求参数：**

（无请求参数）

**请求体示例：**

（无请求体）

**调用示例：**

```bash
curl -X POST 'http://<host>/api/v1/advanced/forensics/analyze-windows-logs' \ \
  -H 'X-API-Key: $API_KEY' \ \
  -H 'Content-Type: application/json'
```

### 🔵 `POST /api/v1/advanced/forensics/calculate-hash`

计算文件哈希

**请求参数：**

（无请求参数）

**请求体示例：**

（无请求体）

**调用示例：**

```bash
curl -X POST 'http://<host>/api/v1/advanced/forensics/calculate-hash' \ \
  -H 'X-API-Key: $API_KEY' \ \
  -H 'Content-Type: application/json'
```

### 🟢 `GET /api/v1/advanced/forensics/report`

生成取证报告

**请求参数：**

（无请求参数）

**调用示例：**

```bash
curl -X GET 'http://<host>/api/v1/advanced/forensics/report' \ \
  -H 'X-API-Key: $API_KEY' \ \
  -H 'Content-Type: application/json'
```

### 🔵 `POST /api/v1/advanced/threat-intel/query-ioc`

查询IOC

**请求参数：**

（无请求参数）

**请求体示例：**

（无请求体）

**调用示例：**

```bash
curl -X POST 'http://<host>/api/v1/advanced/threat-intel/query-ioc' \ \
  -H 'X-API-Key: $API_KEY' \ \
  -H 'Content-Type: application/json'
```

### 🔵 `POST /api/v1/advanced/threat-intel/assess-ip`

评估IP信誉

**请求参数：**

（无请求参数）

**请求体示例：**

（无请求体）

**调用示例：**

```bash
curl -X POST 'http://<host>/api/v1/advanced/threat-intel/assess-ip' \ \
  -H 'X-API-Key: $API_KEY' \ \
  -H 'Content-Type: application/json'
```

### 🟢 `GET /api/v1/advanced/threat-intel/attack-tactics`

获取ATT&CK战术

**请求参数：**

（无请求参数）

**调用示例：**

```bash
curl -X GET 'http://<host>/api/v1/advanced/threat-intel/attack-tactics' \ \
  -H 'X-API-Key: $API_KEY' \ \
  -H 'Content-Type: application/json'
```

### 🟢 `GET /api/v1/advanced/threat-intel/threat-groups`

获取威胁组织

**请求参数：**

（无请求参数）

**调用示例：**

```bash
curl -X GET 'http://<host>/api/v1/advanced/threat-intel/threat-groups' \ \
  -H 'X-API-Key: $API_KEY' \ \
  -H 'Content-Type: application/json'
```

### 🔵 `POST /api/v1/advanced/social-engineering/generate-phishing`

生成钓鱼演练邮件

**请求参数：**

（无请求参数）

**请求体示例：**

（无请求体）

**调用示例：**

```bash
curl -X POST 'http://<host>/api/v1/advanced/social-engineering/generate-phishing' \ \
  -H 'X-API-Key: $API_KEY' \ \
  -H 'Content-Type: application/json'
```

### 🟢 `GET /api/v1/advanced/social-engineering/pretext-scenarios`

获取Pretext场景

**请求参数：**

（无请求参数）

**调用示例：**

```bash
curl -X GET 'http://<host>/api/v1/advanced/social-engineering/pretext-scenarios' \ \
  -H 'X-API-Key: $API_KEY' \ \
  -H 'Content-Type: application/json'
```

### 🟢 `GET /api/v1/advanced/social-engineering/training-topics`

获取安全培训主题

**请求参数：**

（无请求参数）

**调用示例：**

```bash
curl -X GET 'http://<host>/api/v1/advanced/social-engineering/training-topics' \ \
  -H 'X-API-Key: $API_KEY' \ \
  -H 'Content-Type: application/json'
```

### 🔵 `POST /api/v1/advanced/vuln-management/add`

添加漏洞

**请求参数：**

（无请求参数）

**请求体示例：**

（无请求体）

**调用示例：**

```bash
curl -X POST 'http://<host>/api/v1/advanced/vuln-management/add' \ \
  -H 'X-API-Key: $API_KEY' \ \
  -H 'Content-Type: application/json'
```

### 🔵 `POST /api/v1/advanced/vuln-management/update-status`

更新漏洞状态

**请求参数：**

（无请求参数）

**请求体示例：**

（无请求体）

**调用示例：**

```bash
curl -X POST 'http://<host>/api/v1/advanced/vuln-management/update-status' \ \
  -H 'X-API-Key: $API_KEY' \ \
  -H 'Content-Type: application/json'
```

### 🟢 `GET /api/v1/advanced/vuln-management/list`

列出漏洞

**请求参数：**

| 参数名 | 位置 | 类型 | 必填 | 说明 |
|---|---|---|---|---|
| `severity` | query | string | — | 按严重程度筛选 |
| `status` | query | string | — | 按状态筛选 |

**调用示例：**

```bash
curl -X GET 'http://<host>/api/v1/advanced/vuln-management/list' \ \
  -H 'X-API-Key: $API_KEY' \ \
  -H 'Content-Type: application/json'
```

### 🟢 `GET /api/v1/advanced/vuln-management/statistics`

漏洞统计

**请求参数：**

（无请求参数）

**调用示例：**

```bash
curl -X GET 'http://<host>/api/v1/advanced/vuln-management/statistics' \ \
  -H 'X-API-Key: $API_KEY' \ \
  -H 'Content-Type: application/json'
```

### 🟢 `GET /api/v1/advanced/vuln-management/sla-config`

获取SLA配置

**请求参数：**

（无请求参数）

**调用示例：**

```bash
curl -X GET 'http://<host>/api/v1/advanced/vuln-management/sla-config' \ \
  -H 'X-API-Key: $API_KEY' \ \
  -H 'Content-Type: application/json'
```

### 🟢 `GET /api/v1/advanced/vuln-management/report`

生成漏洞管理报告

**请求参数：**

（无请求参数）

**调用示例：**

```bash
curl -X GET 'http://<host>/api/v1/advanced/vuln-management/report' \ \
  -H 'X-API-Key: $API_KEY' \ \
  -H 'Content-Type: application/json'
```

### 🟢 `GET /api/v1/advanced/status`

高级安全模块综合状态

**请求参数：**

（无请求参数）

**调用示例：**

```bash
curl -X GET 'http://<host>/api/v1/advanced/status' \ \
  -H 'X-API-Key: $API_KEY' \ \
  -H 'Content-Type: application/json'
```
