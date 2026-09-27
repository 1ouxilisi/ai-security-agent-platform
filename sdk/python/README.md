# AI Hacking Agent Python SDK

官方 Python SDK，用于与 AI Hacking Agent 安全评估平台 API 交互。

> **免责声明**：本 SDK 仅供授权安全测试使用。未经授权，不得对任何第三方系统进行扫描、测试或攻击。使用者需自行承担因不当使用产生的法律责任。

## 安装

### 方式一：pip 安装依赖

```bash
pip install requests pydantic typing-extensions
```

### 方式二：本地开发安装

```bash
cd ai-hacking-agent
python setup.py develop
```

### 方式三：直接复制使用

直接将 `sdk/python/` 目录复制到你的项目中即可使用，无额外依赖（除 requests 外）。

## 快速开始

### 第1步：安装依赖

```bash
pip install requests>=2.28.0
```

### 第2步：初始化客户端

```python
from sdk.python.ai_hacking_sdk import AIAgentClient

# 基础用法
client = AIAgentClient(
    base_url="http://localhost:8000",  # API服务地址
    api_key="your-api-key-here",        # API密钥（如果开启了认证）
    timeout=30,
    max_retries=3,
)
```

### 第3步：调用API

```python
# 健康检查
health = client.health()
print(f"服务状态: {health['status']}")

# 创建Web安全评估
assessment = client.create_assessment(
    target="https://your-app.example.com",
    assessment_type="web",
)
print(f"评估ID: {assessment['assessment_id']}")

# 轮询等待完成
result = client.poll_until_done(
    lambda: client.get_assessment(assessment['assessment_id']),
    interval=10,
    timeout=600,
)
print(f"扫描完成，发现 {result['summary']['total_vulns']} 个漏洞")
```

## 配置说明

| 参数 | 类型 | 默认值 | 说明 |
|------|------|--------|------|
| `base_url` | str | `http://localhost:8000` | API服务基础URL |
| `api_key` | str | `""` | API密钥，通过 `X-API-Key` 请求头传递 |
| `timeout` | int | `30` | 请求超时时间（秒） |
| `max_retries` | int | `3` | 最大重试次数（网络错误和5xx） |
| `retry_delay` | float | `1.0` | 重试基础延迟（秒），指数退避 |
| `debug` | bool | `False` | 是否开启调试日志 |

## API 方法参考（35个）

### 健康与系统
| 方法 | HTTP | 路径 | 说明 |
|------|------|------|------|
| `health()` | GET | `/health` | 服务健康检查 |

### 安全评估
| 方法 | HTTP | 路径 | 说明 |
|------|------|------|------|
| `create_assessment(target, type, config)` | POST | `/api/v1/unified/assessment` | 创建全域评估 |
| `get_assessment(assessment_id)` | GET | `/api/v1/unified/assessment/{id}` | 获取评估详情 |
| `list_assessments(limit, offset)` | GET | `/api/v1/unified/assessments` | 评估历史列表 |

### 漏洞验证
| 方法 | HTTP | 路径 | 说明 |
|------|------|------|------|
| `verify_web_vuln(url, vuln_type, params)` | POST | `/api/v1/verify/web` | Web漏洞验证 |
| `verify_service_vuln(target, service, port, vuln_type)` | POST | `/api/v1/verify/service` | 服务漏洞验证 |
| `get_verify_result(task_id)` | GET | `/api/v1/verify/result/{task_id}` | 获取验证结果 |

### AI 智能
| 方法 | HTTP | 路径 | 说明 |
|------|------|------|------|
| `ai_chat(message, conversation_id)` | POST | `/api/v1/ai/chat` | AI对话 |
| `ai_verify_vuln(vuln_info)` | POST | `/api/v1/ai/verify` | AI验证漏洞 |
| `ai_generate_remediation(vuln_info)` | POST | `/api/v1/ai/remediation` | AI生成修复方案 |
| `ai_assistant(query, context)` | POST | `/api/v1/ai/assistant` | AI安全助手 |

### 工作流
| 方法 | HTTP | 路径 | 说明 |
|------|------|------|------|
| `execute_workflow(template_id, target, params)` | POST | `/api/v1/workflows/start` | 执行工作流 |
| `get_workflow_status(instance_id)` | GET | `/api/v1/workflows/{id}` | 工作流状态 |
| `get_workflow_result(instance_id)` | GET | `/api/v1/workflows/{id}/report` | 工作流结果 |
| `get_workflow_steps(instance_id)` | GET | `/api/v1/workflows/{id}/context` | 工作流步骤 |
| `get_workflow_logs(instance_id, limit)` | GET | `/api/v1/workflows/{id}/logs` | 工作流日志 |
| `cancel_workflow(instance_id)` | POST | `/api/v1/workflows/{id}/cancel` | 取消工作流 |
| `list_workflow_templates()` | GET | `/api/v1/workflows/templates` | 模板列表 |
| `get_workflow_template(template_id)` | GET | `/api/v1/workflows/templates/{id}` | 模板详情 |
| `create_custom_workflow(name, workflow_def)` | POST | `/api/v1/workflows/templates` | 创建自定义工作流 |
| `list_custom_workflows()` | GET | `/api/v1/workflows/templates` | 自定义工作流列表 |

### 报告
| 方法 | HTTP | 路径 | 说明 |
|------|------|------|------|
| `generate_report(assessment_id, format)` | POST | `/api/v1/reporting/generate` | 生成报告 |
| `download_report(report_id)` | GET | `/api/v1/reporting/download/{id}` | 下载报告 |
| `list_reports(limit)` | GET | `/api/v1/reporting/formats` | 报告列表 |

### 漏洞数据库
| 方法 | HTTP | 路径 | 说明 |
|------|------|------|------|
| `search_cve(keyword, product, severity, page)` | GET | `/api/v1/vuln/search` | 搜索CVE |
| `get_cve(cve_id)` | GET | `/api/v1/vuln/{cve_id}` | CVE详情 |
| `match_cve(service, version)` | POST | `/api/v1/vuln/match` | 服务版本匹配CVE |
| `get_remediation(cve_id)` | GET | `/api/v1/vuln/poc/{cve_id}` | 获取修复方案 |
| `list_vulnerabilities(assessment_id, severity, limit)` | GET | `/api/v1/vuln/recent` | 漏洞列表 |

### 工具与可视化
| 方法 | HTTP | 路径 | 说明 |
|------|------|------|------|
| `get_tool_status()` | GET | `/api/v1/tools/manager/stats` | 工具状态 |
| `install_tool(tool_name)` | POST | `/api/v1/tools/manager/check` | 安装工具 |
| `get_attack_path(assessment_id, scan_data)` | POST | `/api/v1/analytics/top/vulnerabilities` | 攻击路径图 |
| `get_network_topology(assessment_id, scan_data)` | POST | `/api/v1/analytics/export` | 网络拓扑 |
| `get_risk_heatmap(scan_data, dimension)` | POST | `/api/v1/analytics/export` | 风险热力图 |
| `get_analytics_trend(metric)` | GET | `/api/v1/analytics/trends/vulnerabilities` | 趋势分析 |

## 异常处理

SDK 定义了完整的异常类体系：

```
APIError (基础异常)
├── AuthenticationError  (401 - 认证失败)
├── ValidationError      (400 - 参数错误)
├── NotFoundError        (404 - 资源不存在)
├── RateLimitError       (429 - 频率限制)
└── ServerError          (5xx - 服务器错误)
```

### 捕获示例

```python
from sdk.python.ai_hacking_sdk import (
    AIAgentClient, APIError,
    AuthenticationError, NotFoundError,
    RateLimitError, ServerError, ValidationError
)

client = AIAgentClient(api_key="your-key")

try:
    result = client.create_assessment(target="https://example.com")
except AuthenticationError:
    print("API密钥无效，请检查认证配置")
except NotFoundError:
    print("请求的资源不存在")
except RateLimitError as e:
    print(f"请求太频繁，建议等待{e.retry_after}秒")
except ValidationError as e:
    print(f"参数错误: {e.message}")
except ServerError:
    print("服务器内部错误，请稍后重试")
except APIError as e:
    print(f"其他API错误: [{e.status_code}] {e.message}")
```

## 最佳实践

### 1. 重试配置
对于不稳定的网络环境，建议增加重试次数：
```python
client = AIAgentClient(max_retries=5, retry_delay=2.0)
```

### 2. 超时设置
根据任务耗时调整超时：
- 快速查询：`timeout=10`
- 扫描/验证：`timeout=60` 或更长

### 3. 使用上下文管理器
自动管理资源：
```python
with AIAgentClient(base_url="...") as client:
    health = client.health()
    # 自动关闭会话
```

### 4. 分页处理
对于列表类API，使用分页参数：
```python
all_vulns = []
offset = 0
while True:
    batch = client.list_vulnerabilities(limit=100, offset=offset)
    items = batch.get("items", [])
    if not items:
        break
    all_vulns.extend(items)
    offset += len(items)
```

### 5. 调试日志
排查问题时开启debug模式：
```python
client = AIAgentClient(debug=True)
```

## 完整示例

### 示例：一键安全扫描 + 报告生成

```python
from sdk.python.ai_hacking_sdk import AIAgentClient

def scan_and_report(target: str):
    with AIAgentClient(base_url="http://localhost:8000") as client:
        # 1. 健康检查
        assert client.health()["status"] == "healthy"

        # 2. 创建评估
        assess = client.create_assessment(target=target, assessment_type="web")
        aid = assess["assessment_id"]
        print(f"扫描已启动: {aid}")

        # 3. 等待完成
        result = client.poll_until_done(
            lambda: client.get_assessment(aid),
            interval=10,
            timeout=600,
        )
        print(f"扫描完成: {result['summary']}")

        # 4. 生成报告
        report = client.generate_report(aid, report_format="html")
        content = client.download_report(report["report_id"])
        with open("report.html", "wb") as f:
            f.write(content)
        print(f"报告已保存: report.html")

scan_and_report("https://your-app.example.com")
```

## 常见问题 FAQ

**Q1: SDK 连接不上服务怎么办？**
A: 检查以下几点：
1. API服务是否已启动（访问 `http://localhost:8000/docs` 验证）
2. `base_url` 是否正确
3. 防火墙/端口是否开放
4. 如果开启了认证，确认 `api_key` 是否正确

**Q2: 扫描任务执行很慢，SDK会超时吗？**
A: SDK的`timeout`参数只控制单次HTTP请求的超时，不是整个扫描任务的超时。对于异步扫描，请使用 `poll_until_done()` 方法轮询结果，配合合理的 `timeout`（如600秒）。

**Q3: 如何批量扫描多个目标？**
A: 参考 `examples.py` 中的 `example_batch_operations()`。建议依次提交任务后统一轮询，避免并发过高。

**Q4: API返回429 Too Many Requests怎么办？**
A: SDK会自动重试，但如果持续触发限流，建议：
1. 降低请求频率
2. 在请求间添加 `time.sleep()`
3. 联系管理员提升限流配额

**Q5: 如何处理二进制报告下载？**
A: `download_report()` 方法直接返回 `bytes` 类型，直接写入文件即可：
```python
content = client.download_report(report_id)
with open("report.pdf", "wb") as f:
    f.write(content)
```

## 许可证与免责声明

本 SDK 仅用于授权安全测试和防御性安全研究。使用者必须：
1. 获得目标系统所有者的书面授权
2. 遵守适用的法律法规
3. 不得将其用于任何非法或未授权的活动

因不当使用造成的任何后果，由使用者自行承担。
