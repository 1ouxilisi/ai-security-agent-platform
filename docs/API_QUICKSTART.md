# API 快速参考卡

> 自动生成时间：2026-09-12 17:32:33

## 常用端点速查


### AI工具集

- 🟢 `GET /api/v1/ai/tools` — Ai Tools List
  ```bash
  curl -X GET 'http://<host>/api/v1/ai/tools' -H 'X-API-Key: $API_KEY'
  ```
- 🔵 `POST /api/v1/ai/task-plan` — Ai Task Plan
  ```bash
  curl -X POST 'http://<host>/api/v1/ai/task-plan' -H 'X-API-Key: $API_KEY'
  ```
- 🔵 `POST /api/v1/ai/code-review` — Ai Code Review
  ```bash
  curl -X POST 'http://<host>/api/v1/ai/code-review' -H 'X-API-Key: $API_KEY'
  ```

### POC验证

- 🟢 `GET /api/v1/poc/status` — Poc Status
  ```bash
  curl -X GET 'http://<host>/api/v1/poc/status' -H 'X-API-Key: $API_KEY'
  ```
- 🔵 `POST /api/v1/poc/verify` — Poc Verify
  ```bash
  curl -X POST 'http://<host>/api/v1/poc/verify' -H 'X-API-Key: $API_KEY'
  ```

### 一键安全评估

- 🟢 `GET /api/v1/assessment/tasks` — List Tasks
  ```bash
  curl -X GET 'http://<host>/api/v1/assessment/tasks' -H 'X-API-Key: $API_KEY'
  ```
- 🟢 `GET /api/v1/assessment/tools/status` — Get Tools Status
  ```bash
  curl -X GET 'http://<host>/api/v1/assessment/tools/status' -H 'X-API-Key: $API_KEY'
  ```
- 🟢 `GET /api/v1/assessment/status/{task_id}` — Get Assessment Status
  ```bash
  curl -X GET 'http://<host>/api/v1/assessment/status/{task_id}' -H 'X-API-Key: $API_KEY'
  ```

### 任务管理

- 🟢 `GET /api/v1/tasks` — List Tasks
  ```bash
  curl -X GET 'http://<host>/api/v1/tasks' -H 'X-API-Key: $API_KEY'
  ```
- 🟢 `GET /api/v1/tasks/{task_id}` — Get Task
  ```bash
  curl -X GET 'http://<host>/api/v1/tasks/{task_id}' -H 'X-API-Key: $API_KEY'
  ```
- 🟢 `GET /api/v1/tasks/{task_id}/logs` — Get Task Logs
  ```bash
  curl -X GET 'http://<host>/api/v1/tasks/{task_id}/logs' -H 'X-API-Key: $API_KEY'
  ```

### 企业级增强

- 🟢 `GET /api/v1/enterprise/actions` — List Enterprise Actions
  ```bash
  curl -X GET 'http://<host>/api/v1/enterprise/actions' -H 'X-API-Key: $API_KEY'
  ```
- 🔵 `POST /api/v1/enterprise/execute` — Execute Enterprise
  ```bash
  curl -X POST 'http://<host>/api/v1/enterprise/execute' -H 'X-API-Key: $API_KEY'
  ```

### 全域安全评估

- 🟢 `GET /api/v1/unified/stats` — 获取统一框架统计
  ```bash
  curl -X GET 'http://<host>/api/v1/unified/stats' -H 'X-API-Key: $API_KEY'
  ```
- 🟢 `GET /api/v1/unified/domains` — 获取可用领域列表
  ```bash
  curl -X GET 'http://<host>/api/v1/unified/domains' -H 'X-API-Key: $API_KEY'
  ```
- 🟢 `GET /api/v1/unified/assessments` — 获取评估历史列表
  ```bash
  curl -X GET 'http://<host>/api/v1/unified/assessments' -H 'X-API-Key: $API_KEY'
  ```

### 内网渗透

- 🟢 `GET /api/v1/internal/overview` — 内网渗透模块总览
  ```bash
  curl -X GET 'http://<host>/api/v1/internal/overview' -H 'X-API-Key: $API_KEY'
  ```
- 🟢 `GET /api/v1/internal/smb/stats` — SMB扫描统计
  ```bash
  curl -X GET 'http://<host>/api/v1/internal/smb/stats' -H 'X-API-Key: $API_KEY'
  ```
- 🟢 `GET /api/v1/internal/ldap/filters` — 获取LDAP过滤器列表
  ```bash
  curl -X GET 'http://<host>/api/v1/internal/ldap/filters' -H 'X-API-Key: $API_KEY'
  ```

### 分布式扫描

- 🟢 `GET /api/v1/distributed/tasks` — 列出所有任务
  ```bash
  curl -X GET 'http://<host>/api/v1/distributed/tasks' -H 'X-API-Key: $API_KEY'
  ```
- 🟢 `GET /api/v1/distributed/workers` — 列出工作节点
  ```bash
  curl -X GET 'http://<host>/api/v1/distributed/workers' -H 'X-API-Key: $API_KEY'
  ```
- 🟢 `GET /api/v1/distributed/proxies` — 列出代理
  ```bash
  curl -X GET 'http://<host>/api/v1/distributed/proxies' -H 'X-API-Key: $API_KEY'
  ```

### 前端页面

- 🟢 `GET /unified-console` — Unified Console Page
  ```bash
  curl -X GET 'http://<host>/unified-console' -H 'X-API-Key: $API_KEY'
  ```

### 协作

- 🟢 `GET /api/collaboration/tasks` — List Tasks
  ```bash
  curl -X GET 'http://<host>/api/collaboration/tasks' -H 'X-API-Key: $API_KEY'
  ```
- 🟢 `GET /api/collaboration/tasks/stats` — Task Stats
  ```bash
  curl -X GET 'http://<host>/api/collaboration/tasks/stats' -H 'X-API-Key: $API_KEY'
  ```
- 🟢 `GET /api/collaboration/notifications` — List Notifications
  ```bash
  curl -X GET 'http://<host>/api/collaboration/notifications' -H 'X-API-Key: $API_KEY'
  ```

### 告警通知

- 🟢 `GET /api/v1/alerts` — 获取告警列表
  ```bash
  curl -X GET 'http://<host>/api/v1/alerts' -H 'X-API-Key: $API_KEY'
  ```
- 🟢 `GET /api/v1/alerts/stats` — 获取告警统计
  ```bash
  curl -X GET 'http://<host>/api/v1/alerts/stats' -H 'X-API-Key: $API_KEY'
  ```
- 🟢 `GET /api/v1/alerts/channels` — 获取通知渠道列表
  ```bash
  curl -X GET 'http://<host>/api/v1/alerts/channels' -H 'X-API-Key: $API_KEY'
  ```

### 商业化管理

- 🟢 `GET /api/v1/commercial/tenants` — 租户列表
  ```bash
  curl -X GET 'http://<host>/api/v1/commercial/tenants' -H 'X-API-Key: $API_KEY'
  ```
- 🟢 `GET /api/v1/commercial/users/{tenant_id}` — 列出租户用户
  ```bash
  curl -X GET 'http://<host>/api/v1/commercial/users/{tenant_id}' -H 'X-API-Key: $API_KEY'
  ```
- 🟢 `GET /api/v1/commercial/tenants/{tenant_id}` — 租户详情
  ```bash
  curl -X GET 'http://<host>/api/v1/commercial/tenants/{tenant_id}' -H 'X-API-Key: $API_KEY'
  ```

### 增强模块

- 🟢 `GET /api/v1/enhanced/status` — 增强模块综合状态
  ```bash
  curl -X GET 'http://<host>/api/v1/enhanced/status' -H 'X-API-Key: $API_KEY'
  ```
- 🟢 `GET /api/v1/enhanced/users/list` — 列出用户
  ```bash
  curl -X GET 'http://<host>/api/v1/enhanced/users/list' -H 'X-API-Key: $API_KEY'
  ```
- 🟢 `GET /api/v1/enhanced/users/roles` — 列出角色
  ```bash
  curl -X GET 'http://<host>/api/v1/enhanced/users/roles' -H 'X-API-Key: $API_KEY'
  ```

### 实战能力

- 🟢 `GET /api/v1/combat/status` — 实战能力状态
  ```bash
  curl -X GET 'http://<host>/api/v1/combat/status' -H 'X-API-Key: $API_KEY'
  ```
- 🟢 `GET /api/v1/combat/templates` — 列出所有攻击模板
  ```bash
  curl -X GET 'http://<host>/api/v1/combat/templates' -H 'X-API-Key: $API_KEY'
  ```
- 🟢 `GET /api/v1/combat/msf/search` — 搜索Metasploit模块
  ```bash
  curl -X GET 'http://<host>/api/v1/combat/msf/search' -H 'X-API-Key: $API_KEY'
  ```

### 工作流

- 🟢 `GET /api/v1/workflows` — List Workflows
  ```bash
  curl -X GET 'http://<host>/api/v1/workflows' -H 'X-API-Key: $API_KEY'
  ```
- 🟢 `GET /api/v1/workflows/templates` — List Workflow Templates
  ```bash
  curl -X GET 'http://<host>/api/v1/workflows/templates' -H 'X-API-Key: $API_KEY'
  ```
- 🟢 `GET /api/v1/workflows/{instance_id}` — Get Workflow Status
  ```bash
  curl -X GET 'http://<host>/api/v1/workflows/{instance_id}' -H 'X-API-Key: $API_KEY'
  ```

### 工具调用

- 🟢 `GET /api/v1/tools` — List Tools
  ```bash
  curl -X GET 'http://<host>/api/v1/tools' -H 'X-API-Key: $API_KEY'
  ```
- 🔵 `POST /api/v1/tools/call` — Call Tool
  ```bash
  curl -X POST 'http://<host>/api/v1/tools/call' -H 'X-API-Key: $API_KEY'
  ```

### 工具集成

- 🟢 `GET /api/v1/tools/overview` — 工具集成模块总览
  ```bash
  curl -X GET 'http://<host>/api/v1/tools/overview' -H 'X-API-Key: $API_KEY'
  ```
- 🟢 `GET /api/v1/tools/manager/list` — 列出所有工具
  ```bash
  curl -X GET 'http://<host>/api/v1/tools/manager/list' -H 'X-API-Key: $API_KEY'
  ```
- 🟢 `GET /api/v1/tools/manager/stats` — 工具管理统计
  ```bash
  curl -X GET 'http://<host>/api/v1/tools/manager/stats' -H 'X-API-Key: $API_KEY'
  ```

### 扩展安全模块

- 🟢 `GET /api/v1/extended/mobile/devices` — 获取连接的Android设备列表
  ```bash
  curl -X GET 'http://<host>/api/v1/extended/mobile/devices' -H 'X-API-Key: $API_KEY'
  ```
- 🟢 `GET /api/v1/extended/report/summary` — 获取所有模块的综合报告摘要
  ```bash
  curl -X GET 'http://<host>/api/v1/extended/report/summary' -H 'X-API-Key: $API_KEY'
  ```
- 🟢 `GET /api/v1/extended/mobile/frida/scripts` — 获取Frida脚本列表
  ```bash
  curl -X GET 'http://<host>/api/v1/extended/mobile/frida/scripts' -H 'X-API-Key: $API_KEY'
  ```

### 报告

- 🔵 `POST /api/v1/reports/generate` — Generate Report
  ```bash
  curl -X POST 'http://<host>/api/v1/reports/generate' -H 'X-API-Key: $API_KEY'
  ```

### 报告管理

- 🟢 `GET /api/v1/reporting/formats` — 支持的报告格式
  ```bash
  curl -X GET 'http://<host>/api/v1/reporting/formats' -H 'X-API-Key: $API_KEY'
  ```
- 🟢 `GET /api/v1/reporting/templates` — 模板列表
  ```bash
  curl -X GET 'http://<host>/api/v1/reporting/templates' -H 'X-API-Key: $API_KEY'
  ```
- 🟢 `GET /api/v1/reporting/download/{report_id}` — 下载报告
  ```bash
  curl -X GET 'http://<host>/api/v1/reporting/download/{report_id}' -H 'X-API-Key: $API_KEY'
  ```

### 插件系统

- 🟢 `GET /api/v1/plugins` — List Plugins
  ```bash
  curl -X GET 'http://<host>/api/v1/plugins' -H 'X-API-Key: $API_KEY'
  ```
- 🟢 `GET /api/v1/plugins/stats` — Plugin Stats
  ```bash
  curl -X GET 'http://<host>/api/v1/plugins/stats' -H 'X-API-Key: $API_KEY'
  ```
- 🟢 `GET /api/v1/plugins/{plugin_name}/help` — Plugin Help
  ```bash
  curl -X GET 'http://<host>/api/v1/plugins/{plugin_name}/help' -H 'X-API-Key: $API_KEY'
  ```

### 数据分析

- 🟢 `GET /api/v1/analytics/summary` — Api Summary
  ```bash
  curl -X GET 'http://<host>/api/v1/analytics/summary' -H 'X-API-Key: $API_KEY'
  ```
- 🟢 `GET /api/v1/analytics/trends/risk` — Api Trend Risk
  ```bash
  curl -X GET 'http://<host>/api/v1/analytics/trends/risk' -H 'X-API-Key: $API_KEY'
  ```
- 🟢 `GET /api/v1/analytics/top/targets` — Api Top Targets
  ```bash
  curl -X GET 'http://<host>/api/v1/analytics/top/targets' -H 'X-API-Key: $API_KEY'
  ```

### 数据备份

- 🟢 `GET /api/v1/backup` — 获取备份列表
  ```bash
  curl -X GET 'http://<host>/api/v1/backup' -H 'X-API-Key: $API_KEY'
  ```
- 🟢 `GET /api/v1/backup/stats` — 获取备份统计
  ```bash
  curl -X GET 'http://<host>/api/v1/backup/stats' -H 'X-API-Key: $API_KEY'
  ```
- 🟢 `GET /api/v1/backup/{backup_name}` — 获取备份详情
  ```bash
  curl -X GET 'http://<host>/api/v1/backup/{backup_name}' -H 'X-API-Key: $API_KEY'
  ```

### 数据库

- 🟢 `GET /api/v1/db/tasks` — Db List Tasks
  ```bash
  curl -X GET 'http://<host>/api/v1/db/tasks' -H 'X-API-Key: $API_KEY'
  ```
- 🟢 `GET /api/v1/db/stats` — Db Stats
  ```bash
  curl -X GET 'http://<host>/api/v1/db/stats' -H 'X-API-Key: $API_KEY'
  ```
- 🟢 `GET /api/v1/db/findings` — Db List Findings
  ```bash
  curl -X GET 'http://<host>/api/v1/db/findings' -H 'X-API-Key: $API_KEY'
  ```

### 新手引导

- 🟢 `GET /api/v1/onboarding/steps` — 获取引导步骤配置
  ```bash
  curl -X GET 'http://<host>/api/v1/onboarding/steps' -H 'X-API-Key: $API_KEY'
  ```
- 🟢 `GET /api/v1/onboarding/status` — 获取引导完成状态
  ```bash
  curl -X GET 'http://<host>/api/v1/onboarding/status' -H 'X-API-Key: $API_KEY'
  ```
- 🔵 `POST /api/v1/onboarding/complete` — 标记引导完成
  ```bash
  curl -X POST 'http://<host>/api/v1/onboarding/complete' -H 'X-API-Key: $API_KEY'
  ```

### 新领域安全

- 🟢 `GET /api/v1/new-domains/status` — 新领域安全模块综合状态
  ```bash
  curl -X GET 'http://<host>/api/v1/new-domains/status' -H 'X-API-Key: $API_KEY'
  ```
- 🟢 `GET /api/v1/new-domains/ai/status` — AI安全模块状态
  ```bash
  curl -X GET 'http://<host>/api/v1/new-domains/ai/status' -H 'X-API-Key: $API_KEY'
  ```
- 🟢 `GET /api/v1/new-domains/cloud/status` — 云安全模块状态
  ```bash
  curl -X GET 'http://<host>/api/v1/new-domains/cloud/status' -H 'X-API-Key: $API_KEY'
  ```

### 智能体

- 🟢 `GET /api/v1/agents` — List Agents
  ```bash
  curl -X GET 'http://<host>/api/v1/agents' -H 'X-API-Key: $API_KEY'
  ```
- 🔵 `POST /api/v1/agents/react` — React Inference
  ```bash
  curl -X POST 'http://<host>/api/v1/agents/react' -H 'X-API-Key: $API_KEY'
  ```

### 渗透测试

- 🟢 `GET /api/v1/pentest/actions` — List Pentest Actions
  ```bash
  curl -X GET 'http://<host>/api/v1/pentest/actions' -H 'X-API-Key: $API_KEY'
  ```
- 🔵 `POST /api/v1/pentest/execute` — Execute Pentest
  ```bash
  curl -X POST 'http://<host>/api/v1/pentest/execute' -H 'X-API-Key: $API_KEY'
  ```

### 漏洞利用

- 🟢 `GET /api/v1/exploit/poc/list` — 列出PoC库
  ```bash
  curl -X GET 'http://<host>/api/v1/exploit/poc/list' -H 'X-API-Key: $API_KEY'
  ```
- 🟢 `GET /api/v1/exploit/overview` — 漏洞利用模块总览
  ```bash
  curl -X GET 'http://<host>/api/v1/exploit/overview' -H 'X-API-Key: $API_KEY'
  ```
- 🟢 `GET /api/v1/exploit/poc/stats` — PoC库统计
  ```bash
  curl -X GET 'http://<host>/api/v1/exploit/poc/stats' -H 'X-API-Key: $API_KEY'
  ```

### 漏洞数据库

- 🟢 `GET /api/v1/vuln/stats` — Get Vuln Stats
  ```bash
  curl -X GET 'http://<host>/api/v1/vuln/stats' -H 'X-API-Key: $API_KEY'
  ```
- 🟢 `GET /api/v1/vuln/search` — Search Vulnerabilities
  ```bash
  curl -X GET 'http://<host>/api/v1/vuln/search' -H 'X-API-Key: $API_KEY'
  ```
- 🟢 `GET /api/v1/vuln/recent` — Get Recent Vulnerabilities
  ```bash
  curl -X GET 'http://<host>/api/v1/vuln/recent' -H 'X-API-Key: $API_KEY'
  ```

### 用户管理

- 🟢 `GET /api/v1/users` — List Users
  ```bash
  curl -X GET 'http://<host>/api/v1/users' -H 'X-API-Key: $API_KEY'
  ```
- 🟢 `GET /api/v1/audit-logs` — Get Audit Logs
  ```bash
  curl -X GET 'http://<host>/api/v1/audit-logs' -H 'X-API-Key: $API_KEY'
  ```
- 🟢 `GET /api/v1/users/{user_id}` — Get User
  ```bash
  curl -X GET 'http://<host>/api/v1/users/{user_id}' -H 'X-API-Key: $API_KEY'
  ```

### 用户认证

- 🟢 `GET /api/v1/auth/me` — 获取当前用户信息
  ```bash
  curl -X GET 'http://<host>/api/v1/auth/me' -H 'X-API-Key: $API_KEY'
  ```
- 🟢 `GET /api/v1/auth/users` — 获取所有用户（管理员）
  ```bash
  curl -X GET 'http://<host>/api/v1/auth/users' -H 'X-API-Key: $API_KEY'
  ```
- 🟢 `GET /api/v1/auth/stats` — 获取认证系统统计
  ```bash
  curl -X GET 'http://<host>/api/v1/auth/stats' -H 'X-API-Key: $API_KEY'
  ```

### 监控

- 🟢 `GET /api/monitoring/nodes` — 列出分布式节点状态
  ```bash
  curl -X GET 'http://<host>/api/monitoring/nodes' -H 'X-API-Key: $API_KEY'
  ```
- 🟢 `GET /api/monitoring/alerts` — 列出告警
  ```bash
  curl -X GET 'http://<host>/api/monitoring/alerts' -H 'X-API-Key: $API_KEY'
  ```
- 🟢 `GET /api/monitoring/proxy-pool` — 代理池状态
  ```bash
  curl -X GET 'http://<host>/api/monitoring/proxy-pool' -H 'X-API-Key: $API_KEY'
  ```

### 知识库

- 🟢 `GET /api/v1/knowledge/cve` — List Cves
  ```bash
  curl -X GET 'http://<host>/api/v1/knowledge/cve' -H 'X-API-Key: $API_KEY'
  ```
- 🟢 `GET /api/v1/knowledge/stats` — Knowledge Stats
  ```bash
  curl -X GET 'http://<host>/api/v1/knowledge/stats' -H 'X-API-Key: $API_KEY'
  ```
- 🔵 `POST /api/v1/knowledge/rag` — Rag Retrieve
  ```bash
  curl -X POST 'http://<host>/api/v1/knowledge/rag' -H 'X-API-Key: $API_KEY'
  ```

### 系统

- 🟢 `GET /` — Root
  ```bash
  curl -X GET 'http://<host>/' -H 'X-API-Key: $API_KEY'
  ```
- 🟢 `GET /health` — Health Check
  ```bash
  curl -X GET 'http://<host>/health' -H 'X-API-Key: $API_KEY'
  ```
- 🟢 `GET /api/v1/system/stats` — System Stats
  ```bash
  curl -X GET 'http://<host>/api/v1/system/stats' -H 'X-API-Key: $API_KEY'
  ```

### 统一平台控制台

- 🟢 `GET /api/platform/stats` — Platform Stats
  ```bash
  curl -X GET 'http://<host>/api/platform/stats' -H 'X-API-Key: $API_KEY'
  ```
- 🟢 `GET /api/platform/health` — Platform Health
  ```bash
  curl -X GET 'http://<host>/api/platform/health' -H 'X-API-Key: $API_KEY'
  ```
- 🟢 `GET /api/platform/overview` — Platform Overview
  ```bash
  curl -X GET 'http://<host>/api/platform/overview' -H 'X-API-Key: $API_KEY'
  ```

### 超级智能体

- 🟢 `GET /api/v1/super-agent/history` — Super Agent History
  ```bash
  curl -X GET 'http://<host>/api/v1/super-agent/history' -H 'X-API-Key: $API_KEY'
  ```
- 🟢 `GET /api/v1/super-agent/capabilities` — Super Agent Capabilities
  ```bash
  curl -X GET 'http://<host>/api/v1/super-agent/capabilities' -H 'X-API-Key: $API_KEY'
  ```
- 🔵 `POST /api/v1/super-agent/execute` — Super Agent Execute
  ```bash
  curl -X POST 'http://<host>/api/v1/super-agent/execute' -H 'X-API-Key: $API_KEY'
  ```

### 防御中心

- 🟢 `GET /api/v1/defense/ids/alerts` — 获取告警列表
  ```bash
  curl -X GET 'http://<host>/api/v1/defense/ids/alerts' -H 'X-API-Key: $API_KEY'
  ```
- 🟢 `GET /api/v1/defense/log/statistics` — 获取日志统计
  ```bash
  curl -X GET 'http://<host>/api/v1/defense/log/statistics' -H 'X-API-Key: $API_KEY'
  ```
- 🟢 `GET /api/v1/defense/baseline/report` — 获取基线检查报告
  ```bash
  curl -X GET 'http://<host>/api/v1/defense/baseline/report' -H 'X-API-Key: $API_KEY'
  ```

### 集成管理

- 🟢 `GET /api/v1/integrations/siem/config` — 获取 SIEM 配置
  ```bash
  curl -X GET 'http://<host>/api/v1/integrations/siem/config' -H 'X-API-Key: $API_KEY'
  ```
- 🟢 `GET /api/v1/integrations/ldap/config` — 获取 LDAP 配置
  ```bash
  curl -X GET 'http://<host>/api/v1/integrations/ldap/config' -H 'X-API-Key: $API_KEY'
  ```
- 🟢 `GET /api/v1/integrations/ticket/config` — 获取工单系统配置
  ```bash
  curl -X GET 'http://<host>/api/v1/integrations/ticket/config' -H 'X-API-Key: $API_KEY'
  ```

### 高级安全

- 🟢 `GET /api/v1/security/compliance/trend` — Compliance Trend
  ```bash
  curl -X GET 'http://<host>/api/v1/security/compliance/trend' -H 'X-API-Key: $API_KEY'
  ```
- 🟢 `GET /api/v1/security/compliance/audits` — Compliance List
  ```bash
  curl -X GET 'http://<host>/api/v1/security/compliance/audits' -H 'X-API-Key: $API_KEY'
  ```
- 🟢 `GET /api/v1/security/vuln-lifecycle/list` — Vuln List
  ```bash
  curl -X GET 'http://<host>/api/v1/security/vuln-lifecycle/list' -H 'X-API-Key: $API_KEY'
  ```

### 高级安全模块

- 🟢 `GET /api/v1/advanced/status` — 高级安全模块综合状态
  ```bash
  curl -X GET 'http://<host>/api/v1/advanced/status' -H 'X-API-Key: $API_KEY'
  ```
- 🟢 `GET /api/v1/advanced/forensics/report` — 生成取证报告
  ```bash
  curl -X GET 'http://<host>/api/v1/advanced/forensics/report' -H 'X-API-Key: $API_KEY'
  ```
- 🟢 `GET /api/v1/advanced/ics/vulnerabilities` — 获取已知ICS漏洞
  ```bash
  curl -X GET 'http://<host>/api/v1/advanced/ics/vulnerabilities' -H 'X-API-Key: $API_KEY'
  ```

## 常见任务

- **开始一次扫描**：`POST /api/v1/tasks`，body 传 `{"target": "example.com", "task_type": "scan"}`
- **查询任务状态**：`GET /api/v1/tasks/{task_id}`
- **查看任务结果**：`GET /api/v1/tasks/{task_id}/result`
- **调用工具**：`POST /api/v1/tools/call`，body 传 `{"tool_name": "nmap", "parameters": {}}`
- **生成报告**：`POST /api/v1/reports/generate`，body 传 `{"task_id": "..."}`
- **知识库 CVE 查询**：`GET /api/v1/knowledge/cve?keyword=openssl`
- **健康检查**：`GET /health`（无需认证）


> 共选取 114 个常用端点，完整参考见 [API_REFERENCE.md](./API_REFERENCE.md)