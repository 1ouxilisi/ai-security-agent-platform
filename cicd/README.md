# AI Hacking Agent CI/CD 集成指南

将 AI Hacking Agent 安全扫描能力无缝集成到 CI/CD 流水线中，实现"代码提交即安全检测"的 DevSecOps 实践。

> **免责声明**：本工具仅用于授权安全测试。集成到流水线时，请确保扫描目标为你拥有或已获得授权的系统。

## 概述

CI/CD 集成模块的核心价值：

- **安全左移**：在开发阶段早期发现安全问题，降低修复成本
- **自动化**：无需人工介入，每次提交自动扫描
- **质量门禁**：通过漏洞阈值自动阻断不安全的部署
- **报告留存**：自动生成并归档安全报告，满足审计要求
- **多平台支持**：GitLab CI / GitHub Actions / Jenkins / 通用CLI

## 支持的 CI/CD 平台

| 平台 | 模板文件 | 集成复杂度 | 推荐场景 |
|------|---------|-----------|---------|
| GitLab CI | `gitlab_ci.yml` | ★★☆☆☆ | GitLab 自建/云版 |
| GitHub Actions | `github_actions.yml` | ★★☆☆☆ | GitHub 仓库 |
| Jenkins | `jenkinsfile` | ★★★☆☆ | 企业自建Jenkins |
| 通用CLI | `cli.py` | ★☆☆☆☆ | 任意流水线 |

## CLI 工具使用指南

### 全局参数

| 参数 | 缩写 | 说明 | 默认值 |
|------|------|------|--------|
| `--config` | `-c` | 配置文件路径（YAML/JSON） | 无 |
| `--format` | `-f` | 输出格式：text / json | text |
| `--api-url` | | API服务地址 | http://localhost:8000 |
| `--api-key` | | API密钥 | 无 |
| `--verbose` | `-v` | 详细输出模式 | 关闭 |

### 命令清单

#### 1. `scan` - 执行安全扫描

```bash
python -m cicd.cli scan --target https://example.com --type comprehensive
```

| 参数 | 说明 | 默认值 |
|------|------|--------|
| `--target / -t` | 目标URL/IP（必填） | - |
| `--type / -y` | 扫描类型 | comprehensive |
| `--depth` | 扫描深度：quick/standard/deep | standard |
| `--timeout` | 超时秒数 | 300 |
| `--wait` | 是否等待完成 | true |

**扫描类型**：comprehensive / web / mobile / internal / domain / ai / blockchain / compliance

#### 2. `verify` - 漏洞真实验证

```bash
python -m cicd.cli verify --target https://example.com --vuln-type sql_injection
```

| 参数 | 说明 |
|------|------|
| `--target / -t` | 目标URL（必填） |
| `--vuln-type / -vt` | 漏洞类型：sql_injection/xss/csrf/ssrf等（必填） |
| `--param` | 测试参数名 |
| `--port` | 服务端口 |
| `--service` | 服务名 |

#### 3. `report` - 生成安全报告

```bash
python -m cicd.cli report --assessment-id assess_123 --format html --output report.html
```

| 参数 | 说明 |
|------|------|
| `--assessment-id / -id` | 评估任务ID（必填） |
| `--report-format / -f` | 报告格式：html/json/pdf/markdown |
| `--output / -o` | 输出文件路径 |

#### 4. `workflow` - 执行工作流

```bash
python -m cicd.cli workflow --template web_security --target https://example.com
```

| 参数 | 说明 |
|------|------|
| `--template / -tpl` | 工作流模板ID（必填） |
| `--target / -t` | 扫描目标（必填） |
| `--params` | 额外参数（JSON字符串） |
| `--wait` | 是否等待完成 |

**可用模板**：pentest_full / web_security / mobile_security / internal_assessment / domain_audit / ai_agent_security / blockchain_security / compliance_audit

#### 5. `check` - 漏洞阈值检查（CI/CD核心）

```bash
python -m cicd.cli check --target https://example.com --threshold high
```

| 参数 | 说明 | 默认值 |
|------|------|--------|
| `--target / -t` | 目标（必填） | - |
| `--threshold / -th` | 阈值等级：critical/high/medium/low | high |
| `--type / -y` | 扫描类型 | comprehensive |
| `--fail-on` | 失败条件 | any_high |
| `--max-count` | 最大允许漏洞数 | - |

**失败条件说明**：
- `any_high`：发现任一高危/严重漏洞即失败
- `any_critical`：仅发现严重漏洞才失败
- `count_gt_N`：高于阈值的漏洞数超过`--max-count`时失败

### 退出码

| 退出码 | 含义 | 处理方式 |
|--------|------|---------|
| 0 | 成功 / 检查通过 | 继续流水线 |
| 1 | 发现高危漏洞 | 阻断部署 |
| 2 | 扫描/执行失败 | 检查API服务状态 |
| 3 | 参数错误 | 修正命令参数 |

### 输出格式

**Text模式**（人类可读）：
- 带颜色的终端输出
- 进度条显示
- 漏洞统计表格

**JSON模式**（CI/CD解析）：
```json
{
  "exit_code": 0,
  "assessment_id": "assess_abc123",
  "status": "completed",
  "vulnerabilities": [...],
  "summary": {
    "total": 15,
    "critical": 0,
    "high": 2,
    "medium": 5,
    "low": 8
  }
}
```

### 配置文件

支持YAML/JSON配置文件，避免每次都输入相同参数：

```yaml
# cicd-config.yaml
api_url: http://your-ai-agent:8000
api_key: ""  # 建议通过环境变量传入
default:
  target: https://staging.your-app.com
  type: comprehensive
  depth: standard
  threshold: high
  format: text
  timeout: 300
notifications:
  email: security-team@example.com
  webhook: https://oapi.dingtalk.com/robot/send?access_token=xxx
```

使用：`python -m cicd.cli scan -c cicd-config.yaml --target https://staging.example.com`

## 平台集成步骤

### GitLab CI 集成（5步）

1. **复制模板**：将 `gitlab_ci.yml` 内容复制到 `.gitlab-ci.yml`
2. **配置变量**：在 GitLab Settings → CI/CD → Variables 中添加：
   - `AI_HACKING_API_URL`
   - `AI_HACKING_API_KEY`（标记为Masked）
   - `AI_HACKING_TARGET`
3. **调整阈值**：根据团队安全要求修改 `AI_HACKING_THRESHOLD`
4. **渐进启用**：先将 `allow_failure: true` 改为观察模式
5. **提交代码**：推送后自动触发安全扫描

### GitHub Actions 集成（5步）

1. **复制模板**：将 `github_actions.yml` 保存为 `.github/workflows/security-scan.yml`
2. **配置Secrets**：仓库 Settings → Secrets and variables → Actions：
   - Secrets: `AI_HACKING_API_URL`, `AI_HACKING_API_KEY`
   - Variables: `AI_HACKING_TARGET`
3. **调整触发**：根据需要修改 `on:` 部分的分支和定时规则
4. **PR评论**：模板已包含自动在PR上评论扫描结果的步骤
5. **启用阻断**：确认无误报后，保留"Fail build if vulnerabilities found"步骤

### Jenkins 集成（6步）

1. **安装插件**：Pipeline / HTML Publisher / Credentials Binding / Email Extension
2. **创建任务**：新建 Pipeline 类型任务
3. **粘贴脚本**：将 `jenkinsfile` 内容粘贴到 Pipeline 脚本区域
4. **配置环境**：在任务配置中设置环境变量，API密钥用Credentials绑定
5. **HTML报告**：确保 HTML Publisher 插件已安装
6. **首次运行**：手动触发构建，观察输出和报告

## 配置说明

### 扫描目标
- **Web应用**：完整URL，如 `https://staging.example.com`
- **服务器**：IP或域名，如 `192.168.1.100` 或 `internal.example.com`
- **移动应用**：APK/IPA文件路径

### 扫描类型选择
| 类型 | 适用场景 | 耗时参考 |
|------|---------|---------|
| comprehensive | 首次全面评估 | 10-30分钟 |
| web | Web应用专项 | 5-15分钟 |
| mobile | 移动应用分析 | 5-10分钟 |
| internal | 内网环境扫描 | 15-60分钟 |
| compliance | 合规审计 | 20-60分钟 |

### 阈值策略
| 阶段 | 阈值设置 | 说明 |
|------|---------|------|
| 观察期 | 仅报告不阻断 | `allow_failure: true` |
| 初期 | critical only | 仅阻断严重漏洞 |
| 中期 | high | 阻断高危及以上 |
| 成熟 | medium | 严格质量门禁 |

### 通知配置
支持多种通知渠道，在流水线中添加对应步骤：

- **邮件**：GitLab/GitHub/Jenkins 原生邮件功能
- **钉钉**：使用机器人Webhook发送Markdown消息
- **企业微信**：使用群机器人Webhook
- **Slack**： incoming webhook 或 GitHub/GitLab 官方Slack集成

## 最佳实践

### 1. 流水线阶段位置
安全扫描应放在 **build之后，deploy之前**：
```
Build → Test → Security Scan → Deploy
```
- 不要在build之前扫描（代码还没编译完成）
- 绝对不能在deploy之后扫描（失去意义）

### 2. 渐进式启用策略
不要一上来就阻断所有部署，建议：

```
第1周：仅收集数据，不阻断（观察模式）
第2周：仅阻断严重漏洞（critical）
第3周：阻断高危及以上（high）
第4周：严格门禁（medium及以上）
```

### 3. 误报处理
- 建立误报反馈机制：开发团队可标记误报
- 维护白名单：对已知误报类型添加排除规则
- 定期回顾：每周评审误报率，优化扫描规则

### 4. 扫描频率建议
| 触发时机 | 扫描深度 | 目的 |
|---------|---------|------|
| 每次PR | quick | 快速反馈 |
| 合入主分支 | standard | 合并前把关 |
| 每日定时 | deep | 持续监控 |
| 每周深度 | deep+全量 | 全面审计 |

### 5. 报告归档策略
- 安全报告保留至少 **90天**
- 关键版本的报告建议 **永久留存**
- 报告应包含：扫描时间、目标、漏洞列表、修复建议

### 6. 性能优化
- 使用增量扫描：只扫描变更部分
- 缓存工具状态：避免每次都重新安装工具
- 分布式扫描：大规模目标使用分布式模式

## 常见问题 FAQ

**Q1: 安全扫描会不会影响生产环境？**
A: 设计上采用非破坏性扫描方式（被动检测+低强度主动探测），但仍建议先在预发布环境验证。对生产环境扫描前请务必：1) 获得授权 2) 选择低峰时段 3) 限制扫描速率。

**Q2: 扫描时间太长，流水线超时了怎么办？**
A: 1) 调整 `--timeout` 参数增加超时时间 2) 使用 `--depth quick` 减少扫描深度 3) 改为异步模式（`--wait false`），提交任务后立即返回，结果异步获取。

**Q3: 如何处理误报？**
A: 1) 使用漏洞验证功能（`verify`命令）确认真实性 2) 在`check`命令中调整`--fail-on`策略 3) 建立内部白名单流程，对确认误报的漏洞类型添加排除规则。

**Q4: API服务部署在哪里？**
A: 推荐部署在与CI/CD runner同一网络环境中，避免跨网络延迟。Docker Compose一键部署：参考项目根目录的 `docker-compose.yml`。

**Q5: 支持哪些认证方式？**
A: 目前支持API密钥认证（X-API-Key请求头）。可通过 `--api-key` 参数或环境变量 `AI_HACKING_API_KEY` 传入。

**Q6: 扫描结果可以导入到Jira/Slack等工具吗？**
A: 可以。使用 `--format json` 输出结构化结果，再配合各工具的Webhook/API进行集成。JSON输出包含完整的漏洞列表和统计信息。

**Q7: 如何在 monorepo 中为不同服务配置不同扫描策略？**
A: 为每个服务目录配置独立的CI配置文件，指定不同的 `--target` 和 `--threshold`。GitHub Actions支持路径过滤（`paths:`），仅在对应服务变更时触发扫描。

**Q8: 安全扫描会拖慢开发流程吗？**
A: 快速模式（quick）通常在2-5分钟内完成，对PR流程影响很小。深度扫描建议放在每日定时任务中，不阻塞日常开发。

## 故障排查

### API连接失败
```
错误: 网络连接失败
排查:
1. 确认API服务已启动: curl http://your-api:8000/health
2. 检查网络连通性: ping/telnet API地址
3. 检查防火墙规则
4. 确认base_url和端口正确
```

### 认证失败 (401)
```
错误: 认证失败：API密钥无效
排查:
1. 确认API密钥是否正确
2. 检查密钥是否过期
3. 确认密钥是否有访问权限
```

### 扫描超时
```
错误: 任务超时
排查:
1. 增加 --timeout 参数值
2. 降低扫描深度 (quick替代deep)
3. 检查目标网络是否可达
4. 查看服务端日志是否有错误
```

### 报告生成失败
```
错误: 报告生成失败
排查:
1. 确认assessment_id有效
2. 检查报告模块是否正常工作
3. 查看是否有足够的磁盘空间
4. 尝试使用JSON格式报告
```

## 许可证与免责声明

本 CI/CD 集成工具仅用于授权安全测试和防御性安全研究。使用者必须：

1. 获得目标系统所有者的明确书面授权
2. 遵守《网络安全法》及相关法律法规
3. 不得将其用于任何非法或未授权的活动
4. 对因使用本工具产生的任何后果自行承担责任

**安全是每个人的责任**。让我们共同建设更安全的数字世界。
