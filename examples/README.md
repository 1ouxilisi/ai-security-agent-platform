# AI Hacking Agent 示例

此目录包含 AI Hacking Agent 的使用示例和演示脚本。

## 目录结构

```
examples/
├── README.md                    # 本文件
├── basic_usage.py               # 基础使用示例
├── api_client.py                # API客户端示例
├── scan_workflow.py             # 扫描工作流示例
├── penetration_test.py          # 渗透测试完整流程示例
├── custom_agent.py              # 自定义智能体示例
├── plugin_example.py            # 插件开发示例
├── report_generation.py         # 报告生成示例
├── docker-compose.yml           # Docker部署示例
├── configs/                     # 配置文件示例
│   ├── .env.example             # 环境变量示例
│   └── config.example.yaml      # 配置文件示例
└── data/                        # 示例数据
    └── sample_targets.txt       # 示例目标列表
```

## 快速开始

### 1. 基础使用

```python
# examples/basic_usage.py
from ai_hacking_agent import AIAgent

# 创建智能体
agent = AIAgent(api_key="your-api-key")

# 执行扫描
result = agent.scan(target="192.168.1.1", scan_type="quick")
print(result)
```

### 2. API客户端

```python
# examples/api_client.py
import requests

# 调用API
response = requests.post(
    "http://127.0.0.1:8000/api/v1/tasks",
    json={
        "target": "192.168.1.1",
        "task_type": "scan",
        "description": "快速端口扫描"
    }
)
print(response.json())
```

### 3. 完整渗透测试流程

```python
# examples/penetration_test.py
from ai_hacking_agent import PenetrationTester

# 创建渗透测试器
tester = PenetrationTester(target="192.168.1.0/24")

# 执行完整流程
report = tester.execute_full_pentest(
    phases=["recon", "scan", "exploit", "post_exploit", "report"]
)
report.save("pentest_report.html")
```

## 运行示例

### 基础示例

```bash
# 确保API服务正在运行
python main.py api-server --host 127.0.0.1 --port 8000

# 运行示例
python examples/basic_usage.py
python examples/api_client.py
python examples/scan_workflow.py
```

### Docker示例

```bash
# 使用Docker Compose启动
cd examples
docker-compose up -d

# 查看日志
docker-compose logs -f
```

## 示例说明

### basic_usage.py
基础使用示例，展示如何创建智能体和执行基本扫描。

### api_client.py
API客户端示例，展示如何通过REST API与服务交互。

### scan_workflow.py
扫描工作流示例，展示如何编排多个扫描任务。

### penetration_test.py
完整渗透测试流程示例，展示从侦察到报告的完整流程。

### custom_agent.py
自定义智能体示例，展示如何扩展和定制智能体行为。

### plugin_example.py
插件开发示例，展示如何开发自定义插件。

### report_generation.py
报告生成示例，展示如何生成各种格式的安全报告。

## 配置示例

### 环境变量 (.env)

```bash
# API配置
API_KEY=your-api-key
API_BASE_URL=https://api.example.com/v1

# 数据库配置
DATABASE_URL=sqlite:///data/hacking_agent.db

# LLM配置
LLM_MODEL=gpt-4
LLM_TEMPERATURE=0.7
LLM_MAX_TOKENS=2048

# 扫描配置
SCAN_TIMEOUT=300
SCAN_RATE=1000
MAX_CONCURRENT_SCANS=5
```

### 配置文件 (config.yaml)

```yaml
# 项目配置
project:
  name: AI Hacking Agent
  version: 7.0.0
  environment: development

# API配置
api:
  host: 127.0.0.1
  port: 8000
  debug: true
  cors_origins:
    - http://localhost:3000
    - http://127.0.0.1:8000

# 数据库配置
database:
  url: sqlite:///data/hacking_agent.db
  echo: false
  pool_size: 10
  max_overflow: 20

# LLM配置
llm:
  provider: openai
  model: gpt-4
  temperature: 0.7
  max_tokens: 2048
  timeout: 60
  retry:
    max_attempts: 3
    delay: 1.0

# 扫描配置
scanning:
  timeout: 300
  rate_limit: 1000
  max_concurrent: 5
  tools:
    nmap:
      path: /usr/bin/nmap
      default_args: -T4 -F
    nuclei:
      path: /usr/bin/nuclei
      templates: /usr/share/nuclei-templates

# 报告配置
reporting:
  output_dir: reports
  formats:
    - html
    - pdf
    - json
    - markdown
  include_screenshots: true
  include_evidence: true

# 日志配置
logging:
  level: INFO
  format: "%(asctime)s | %(levelname)-8s | %(name)s:%(lineno)d | %(message)s"
  file: logs/ai_hacking_agent.log
  max_size: 10MB
  backup_count: 5
```

## 注意事项

1. **授权使用**：所有示例仅用于授权的安全测试和研究目的
2. **API密钥**：运行示例前请配置有效的API密钥
3. **目标授权**：确保你有权扫描和测试目标系统
4. **法律合规**：遵守当地法律法规，不要进行未授权的测试

## 贡献示例

欢迎贡献更多示例！请遵循以下步骤：

1. Fork 项目
2. 创建特性分支 (`git checkout -b feature/amazing-example`)
3. 提交更改 (`git commit -m 'Add amazing example'`)
4. 推送到分支 (`git push origin feature/amazing-example`)
5. 创建 Pull Request

## 相关资源

- [README.md](../README.md) - 项目主文档
- [QUICKSTART.md](../QUICKSTART.md) - 快速开始指南
- [API_DOCUMENTATION.md](../API_DOCUMENTATION.md) - API文档
- [ARCHITECTURE.md](../ARCHITECTURE.md) - 架构文档
- [CONTRIBUTING.md](../CONTRIBUTING.md) - 贡献指南

## 支持

如有问题或建议，请：

- 创建 [Issue](https://github.com/your-repo/ai-hacking-agent/issues)
- 参与 [Discussions](https://github.com/your-repo/ai-hacking-agent/discussions)
- 阅读 [文档](https://your-docs-url.com)

---

**最后更新**：2026-08-31
**版本**：v7.0.0
