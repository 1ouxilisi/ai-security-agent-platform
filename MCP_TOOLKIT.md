# AI Hacking Agent - MCP安全工具包

## 概述

AI Hacking Agent 提供完整的 MCP (Model Context Protocol) 安全工具包，可接入支持 MCP 协议的 AI Agent（如 Claude Desktop、豆包、Cursor 等），为 AI Agent 提供专业的安全测试能力。

## 工具列表

### 侦察类工具
| 工具名 | 描述 | 参数 |
|--------|------|------|
| `port_scan` | 端口扫描 | target, ports, scan_type |
| `service_detection` | 服务识别 | target, port |
| `subdomain_enum` | 子域名枚举 | domain, wordlist |
| `directory_bruteforce` | 目录爆破 | url, wordlist, extensions |

### 漏洞扫描类工具
| 工具名 | 描述 | 参数 |
|--------|------|------|
| `sql_injection_scan` | SQL注入扫描 | url, param, method |
| `xss_scan` | XSS扫描 | url, param |
| `ssrf_scan` | SSRF扫描 | url, param |
| `idor_scan` | IDOR扫描 | url, param |
| `vulnerability_scan` | 综合漏洞扫描 | target, scan_level, vuln_types |

### 认证测试类工具
| 工具名 | 描述 | 参数 |
|--------|------|------|
| `jwt_analysis` | JWT分析 | token |
| `oauth_analysis` | OAuth分析 | auth_url |
| `cookie_analysis` | Cookie安全分析 | cookies |

### API安全类工具
| 工具名 | 描述 | 参数 |
|--------|------|------|
| `openapi_analysis` | OpenAPI分析 | spec_url, spec_content |
| `graphql_test` | GraphQL测试 | endpoint, test_type |
| `api_fuzzing` | API模糊测试 | url, params |

### 情报类工具
| 工具名 | 描述 | 参数 |
|--------|------|------|
| `cve_lookup` | CVE查询 | cve_id |
| `vuln_search` | 漏洞搜索 | keyword, severity |
| `exploit_search` | 利用代码搜索 | query |

### 报告类工具
| 工具名 | 描述 | 参数 |
|--------|------|------|
| `generate_report` | 生成报告 | task_id, format |
| `get_task_status` | 获取任务状态 | task_id |

### 超级智能体
| 工具名 | 描述 | 参数 |
|--------|------|------|
| `super_agent_execute` | 超级智能体执行 | task (自然语言) |

## 接入方式

### 方式1: Claude Desktop

1. 打开 Claude Desktop 配置文件
   - macOS: `~/Library/Application Support/Claude/claude_desktop_config.json`
   - Windows: `%APPDATA%\Claude\claude_desktop_config.json`

2. 添加 MCP 服务器配置:
```json
{
  "mcpServers": {
    "ai-hacking-agent": {
      "command": "python",
      "args": ["-m", "mcp_server"],
      "cwd": "/path/to/ai-hacking-agent",
      "env": {
        "PYTHONPATH": "."
      }
    }
  }
}
```

3. 重启 Claude Desktop

### 方式2: 豆包 / 其他支持 MCP 的客户端

1. 在客户端设置中找到 MCP 配置
2. 导入 `mcp_config.json` 或手动添加服务器
3. 服务器地址: `http://127.0.0.1:8000/mcp`

### 方式3: 直接使用 HTTP API

```bash
# 端口扫描
curl -X POST http://127.0.0.1:8000/api/v1/tools/port_scan \
  -H "Content-Type: application/json" \
  -H "X-API-Key: your-api-key" \
  -d '{"target": "127.0.0.1", "ports": "1-1000"}'

# 超级智能体执行
curl -X POST http://127.0.0.1:8000/api/v1/super-agent/execute \
  -H "Content-Type: application/json" \
  -H "X-API-Key: your-api-key" \
  -d '{"task": "扫描127.0.0.1的端口和服务"}'
```

## 使用示例

### 示例1: 完整安全测试流程

```
用户: 帮我测试 http://example.com 的安全性

AI Agent (通过MCP):
1. 调用 port_scan 扫描端口
2. 调用 service_detection 识别服务
3. 调用 directory_bruteforce 爆破目录
4. 调用 sql_injection_scan 测试SQL注入
5. 调用 xss_scan 测试XSS
6. 调用 generate_report 生成报告
```

### 示例2: 使用超级智能体

```
用户: 扫描127.0.0.1的端口和服务，找出漏洞

AI Agent:
调用 super_agent_execute(task="扫描127.0.0.1的端口和服务，找出漏洞")

结果: 自动完成端口扫描→服务识别→漏洞检测→报告生成
```

### 示例3: CVE漏洞查询

```
用户: CVE-2021-44228 是什么漏洞？

AI Agent:
调用 cve_lookup(cve_id="CVE-2021-44228")

结果: 返回漏洞详情、CVSS评分、影响范围、修复建议
```

## 配置选项

### 环境变量

| 变量名 | 描述 | 默认值 |
|--------|------|--------|
| `MCP_SERVER_HOST` | MCP服务器监听地址 | `127.0.0.1` |
| `MCP_SERVER_PORT` | MCP服务器端口 | `8000` |
| `LLM_API_KEY` | LLM API密钥 | - |
| `LLM_BASE_URL` | LLM API地址 | - |
| `LLM_MODEL` | LLM模型名称 | - |
| `VULNERS_API_KEY` | Vulners API密钥（可选） | - |
| `GITHUB_TOKEN` | GitHub Token（可选） | - |

### API鉴权

默认API密钥: `hacking-agent-2026-secure-key`

在请求头中添加: `X-API-Key: your-api-key`

## 安全注意事项

1. **仅限授权测试**: 仅对您拥有或已获得授权的目标进行安全测试
2. **本地部署**: MCP服务器默认监听 `127.0.0.1`，不要暴露到公网
3. **API密钥**: 修改默认API密钥，使用强密码
4. **日志审计**: 所有操作记录在审计日志中，定期审查
5. **速率限制**: 扫描引擎内置速率限制，避免对目标造成压力

## 故障排查

### MCP服务器无法启动
```bash
# 检查端口占用
netstat -ano | findstr :8000

# 检查依赖
pip install -r requirements.txt

# 手动启动测试
python -m mcp_server
```

### 工具调用失败
1. 检查API密钥是否正确
2. 检查目标是否可达
3. 查看日志文件: `logs/hacking_agent.log`

### LLM连接失败
1. 检查 `.env` 文件中的API密钥
2. 检查网络连接
3. 测试API连通性: `python scripts/test_llm.py`

## 许可证

MIT License - 详见 LICENSE 文件

## 贡献

欢迎提交 Issue 和 Pull Request！

## 联系方式

- 项目地址: https://github.com/your-org/ai-hacking-agent
- 问题反馈: https://github.com/your-org/ai-hacking-agent/issues
