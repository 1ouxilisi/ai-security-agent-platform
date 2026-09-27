# AI Hacking Agent - 快速开始指南

> 一个AI驱动的全栈网络安全平台，支持全自动渗透测试、漏洞扫描、威胁情报、安全运营等7大安全领域。

---

## 🚀 5分钟快速开始

### 1. 环境要求

- Python 3.10+
- Windows / Linux / macOS
- （可选）Docker 20.0+（用于沙箱隔离）
- （可选）Git

### 2. 下载项目

```bash
# 方式1：Git克隆
git clone https://github.com/your-repo/ai-hacking-agent.git
cd ai-hacking-agent

# 方式2：直接下载压缩包并解压
# 解压后进入项目目录
```

### 3. 安装依赖

```bash
# Windows
pip install -r requirements.txt

# Linux/macOS
pip3 install -r requirements.txt
```

### 4. 配置API密钥

复制 `.env.example` 为 `.env`，然后编辑配置：

```bash
# Windows
copy .env.example .env

# Linux/macOS
cp .env.example .env
```

编辑 `.env` 文件，填入你的API密钥：

```env
# LLM配置（必填，用于AI分析和报告生成）
LLM_API_KEY=sk-your-api-key-here
LLM_BASE_URL=https://api.deepseek.com/v1
LLM_MODEL=deepseek-chat

# 支持的LLM提供商：
# - DeepSeek: https://api.deepseek.com/v1
# - OpenAI: https://api.openai.com/v1
# - 硅基流动: https://api.siliconflow.cn/v1
# - 智谱AI: https://open.bigmodel.cn/api/paas/v4
# - 月之暗面: https://api.moonshot.cn/v1
# - 通义千问: https://dashscope.aliyuncs.com/compatible-mode/v1

# 安全配置
SECRET_KEY=your-secret-key-for-session
DEBUG=false
```

### 5. 启动服务

```bash
# 启动API服务（默认端口8000）
python main.py api-server --host 127.0.0.1 --port 8000

# 启动Web界面（另一个终端）
python main.py web-ui --host 127.0.0.1 --port 8501
```

### 6. 访问系统

打开浏览器访问：

- **API文档（Swagger UI）**: http://127.0.0.1:8000/docs
- **高级控制台**: http://127.0.0.1:8000/advanced-console
- **仪表盘**: http://127.0.0.1:8000/dashboard
- **漏洞数据库**: http://127.0.0.1:8000/vuln-database
- **Web UI（Streamlit）**: http://127.0.0.1:8501

---

## 🎯 第一次使用：全自动渗透测试

### 方式1：通过API（推荐）

```bash
# 1. 创建全自动渗透测试工作流
curl -X POST http://127.0.0.1:8000/api/v1/workflow/create \
  -H "Content-Type: application/json" \
  -d '{"target": "https://example.com", "target_type": "url", "use_sandbox": true}'

# 返回 workflow_id，例如：PT-1234567890-12345

# 2. 启动工作流（异步执行）
curl -X POST http://127.0.0.1:8000/api/v1/workflow/start \
  -H "Content-Type: application/json" \
  -d '{"workflow_id": "PT-1234567890-12345"}'

# 3. 查看工作流状态
curl http://127.0.0.1:8000/api/v1/workflow/status?workflow_id=PT-1234567890-12345

# 4. 获取最终报告
curl http://127.0.0.1:8000/api/v1/workflow/report?workflow_id=PT-1234567890-12345
```

### 方式2：通过Python脚本

```python
import requests
import json
import time

BASE_URL = "http://127.0.0.1:8000"

# 1. 创建工作流
resp = requests.post(f"{BASE_URL}/api/v1/workflow/create", json={
    "target": "https://example.com",
    "target_type": "url",
    "use_sandbox": True,  # 使用Docker沙箱隔离
    "ai_enabled": True    # 启用AI自主决策
})
workflow_id = resp.json()["workflow_id"]
print(f"工作流创建成功: {workflow_id}")

# 2. 启动工作流
requests.post(f"{BASE_URL}/api/v1/workflow/start", json={
    "workflow_id": workflow_id
})
print("工作流已启动，正在执行...")

# 3. 轮询状态
while True:
    status = requests.get(f"{BASE_URL}/api/v1/workflow/status",
                         params={"workflow_id": workflow_id}).json()
    print(f"进度: {status['completed_steps']}/{status['steps_count']} 步骤完成, "
          f"发现漏洞: {status['findings_count']}")

    if status["status"] in ["completed", "failed", "cancelled"]:
        break
    time.sleep(5)

# 4. 获取报告
report = requests.get(f"{BASE_URL}/api/v1/workflow/report",
                     params={"workflow_id": workflow_id}).json()
print(f"\n=== 渗透测试报告 ===")
print(f"目标: {report['target']}")
print(f"发现漏洞: {report['findings_summary']}")
print(f"风险评分: {report['risk_score']}/100")
print(f"\n执行摘要: {report['executive_summary']}")
```

### 方式3：通过Web界面

1. 打开 http://127.0.0.1:8000/advanced-console
2. 找到"全自动渗透测试"卡片
3. 输入目标URL，点击"开始扫描"
4. 实时查看进度和发现
5. 扫描完成后下载报告

---

## 📋 核心功能模块

### 1. 侦察模块（Recon）

```bash
# 子域名枚举
curl -X POST http://127.0.0.1:8000/api/v1/recon/subdomains \
  -H "Content-Type: application/json" \
  -d '{"domain": "example.com"}'

# 端口扫描
curl -X POST http://127.0.0.1:8000/api/v1/recon/port-scan \
  -H "Content-Type: application/json" \
  -d '{"target": "192.168.1.1", "ports": "1-1000"}'

# 服务指纹识别
curl -X POST http://127.0.0.1:8000/api/v1/recon/fingerprint \
  -H "Content-Type: application/json" \
  -d '{"url": "https://example.com"}'
```

### 2. 漏洞扫描模块（Scan）

```bash
# Nuclei漏洞扫描
curl -X POST http://127.0.0.1:8000/api/v1/scan/nuclei \
  -H "Content-Type: application/json" \
  -d '{"target": "https://example.com"}'

# Web漏洞扫描
curl -X POST http://127.0.0.1:8000/api/v1/scan/web \
  -H "Content-Type: application/json" \
  -d '{"url": "https://example.com", "scan_type": "full"}'

# CVE漏洞查询
curl http://127.0.0.1:8000/api/v1/knowledge/cve?keyword=log4j
```

### 3. 漏洞验证模块（Verify）

```bash
# 验证SQL注入
curl -X POST http://127.0.0.1:8000/api/v1/verify/sql-injection \
  -H "Content-Type: application/json" \
  -d '{"url": "https://example.com/page?id=1", "parameter": "id"}'

# 验证XSS
curl -X POST http://127.0.0.1:8000/api/v1/verify/xss \
  -H "Content-Type: application/json" \
  -d '{"url": "https://example.com/search?q=test", "parameter": "q"}'
```

### 4. 移动安全模块（Mobile）

```bash
# APK静态分析
curl -X POST http://127.0.0.1:8000/api/v1/mobile/analyze-apk \
  -H "Content-Type: application/json" \
  -d '{"apk_path": "/path/to/app.apk"}'

# 权限分析
curl http://127.0.0.1:8000/api/v1/mobile/permissions?apk_path=/path/to/app.apk
```

### 5. 云安全模块（Cloud）

```bash
# AWS S3存储桶检查
curl -X POST http://127.0.0.1:8000/api/v1/cloud/check-s3 \
  -H "Content-Type: application/json" \
  -d '{"bucket_name": "my-bucket", "public_access_block": {...}}'

# Dockerfile安全检查
curl -X POST http://127.0.0.1:8000/api/v1/cloud/check-dockerfile \
  -H "Content-Type: application/json" \
  -d '{"content": "FROM ubuntu:latest\nRUN apt-get install curl"}'

# K8s Pod安全检查
curl -X POST http://127.0.0.1:8000/api/v1/cloud/check-k8s-pod \
  -H "Content-Type: application/json" \
  -d '{"spec": {"containers": [{"name": "app", "image": "nginx:latest"}]}}'
```

### 6. 知识库模块（Knowledge）

```bash
# CVE漏洞查询
curl http://127.0.0.1:8000/api/v1/knowledge/cve?keyword=sql&limit=10

# PoC查询
curl http://127.0.0.1:8000/api/v1/knowledge/poc?vuln_type=sql_injection

# 攻击链查询
curl http://127.0.0.1:8000/api/v1/knowledge/attack-chain

# 指纹查询
curl http://127.0.0.1:8000/api/v1/knowledge/fingerprint?service=nginx

# 修复方案查询
curl http://127.0.0.1:8000/api/v1/knowledge/remediation?vuln_type=sql_injection
```

### 7. 安全运营模块（SOC）

```bash
# SIEM日志分析
curl -X POST http://127.0.0.1:8000/api/v1/soc/siem/analyze \
  -H "Content-Type: application/json" \
  -d '{"logs": [...]}'

# SOAR剧本执行
curl -X POST http://127.0.0.1:8000/api/v1/soc/soar/execute \
  -H "Content-Type: application/json" \
  -d '{"playbook_id": "phishing-response", "alert": {...}}'

# 威胁情报查询
curl http://127.0.0.1:8000/api/v1/soc/threat-intel?ioc=1.2.3.4
```

### 8. 企业审计模块（Audit）

```bash
# 查询审计日志
curl http://127.0.0.1:8000/api/v1/audit/logs?limit=50&severity=high

# 审计统计
curl http://127.0.0.1:8000/api/v1/audit/statistics?days=30

# 导出审计日志
curl -X POST http://127.0.0.1:8000/api/v1/audit/export \
  -H "Content-Type: application/json" \
  -d '{"format": "csv", "days": 30}'
```

---

## 🧠 AI功能使用

### 1. AI漏洞分析

```bash
curl -X POST http://127.0.0.1:8000/api/v1/ai/analyze-vulnerability \
  -H "Content-Type: application/json" \
  -d '{"vuln_type": "sql_injection", "url": "https://example.com/page?id=1", "evidence": "..."}'
```

### 2. AI报告生成

```bash
curl -X POST http://127.0.0.1:8000/api/v1/ai/generate-report \
  -H "Content-Type: application/json" \
  -d '{"findings": [...], "target": "https://example.com", "format": "professional"}'
```

### 3. AI修复建议

```bash
curl -X POST http://127.0.0.1:8000/api/v1/ai/remediation \
  -H "Content-Type: application/json" \
  -d '{"vuln_type": "xss", "language": "javascript", "framework": "react"}'
```

---

## 🐳 Docker沙箱使用

### 1. 检查Docker是否可用

```bash
curl http://127.0.0.1:8000/api/v1/sandbox/status
```

### 2. 创建沙箱容器

```bash
curl -X POST http://127.0.0.1:8000/api/v1/sandbox/create \
  -H "Content-Type: application/json" \
  -d '{"image": "kalilinux/kali-rolling:latest", "memory_limit": "512m", "cpu_limit": 1.0}'
```

### 3. 在沙箱中执行命令

```bash
curl -X POST http://127.0.0.1:8000/api/v1/sandbox/execute \
  -H "Content-Type: application/json" \
  -d '{"container_id": "abc123", "command": "nmap -sV example.com", "timeout": 60}'
```

### 4. 清理沙箱

```bash
curl -X POST http://127.0.0.1:8000/api/v1/sandbox/cleanup
```

---

## ❓ 常见问题

### Q1: 启动时提示"端口被占用"怎么办？

```bash
# Windows查看占用进程
netstat -ano | findstr :8000

# 杀掉进程（替换PID）
taskkill /PID <进程ID> /F

# 或换个端口启动
python main.py api-server --port 8001
```

### Q2: LLM连接失败怎么办？

1. 检查 `.env` 文件中的 `LLM_API_KEY` 是否正确
2. 检查网络是否能访问API地址
3. 确认API密钥有余额
4. 尝试更换LLM提供商（如DeepSeek换成硅基流动）

### Q3: Docker沙箱不可用怎么办？

1. 确认Docker已安装并启动
2. Windows需要启动Docker Desktop
3. 如果没有Docker，可以设置 `use_sandbox: false` 在本地执行
4. 注意：本地执行有安全风险，建议只测试授权目标

### Q4: 扫描速度慢怎么办？

1. 减少扫描范围（如只扫常用端口）
2. 使用更快的DNS服务器
3. 增加超时时间
4. 使用分布式扫描（需要额外配置）

### Q5: 如何更新漏洞库？

```bash
# 更新CVE漏洞库
python scripts/update_cve_database.py

# 更新Nuclei模板
python scripts/update_nuclei_templates.py
```

### Q6: 支持哪些LLM模型？

支持所有兼容OpenAI API格式的大模型：
- DeepSeek (deepseek-chat / deepseek-reasoner)
- OpenAI (gpt-4o / gpt-4o-mini / gpt-3.5-turbo)
- 硅基流动 (Qwen / Llama / Mistral等)
- 智谱AI (glm-4 / glm-3-turbo)
- 月之暗面 (moonshot-v1-8k / 32k / 128k)
- 通义千问 (qwen-plus / qwen-max)
- 本地模型 (Ollama / Llama.cpp)

---

## 📊 项目数据

| 维度 | 数量 |
|------|------|
| 模块总数 | 35+ |
| API端点 | 100+ |
| CVE漏洞库 | 6665条 |
| PoC利用代码 | 40个 |
| 攻击链 | 20个（133步骤） |
| 指纹规则 | 198个 |
| 修复方案 | 30个 |
| 安全工具 | 61个 |
| SIEM规则 | 10条 |
| SOAR动作/剧本 | 13动作/6剧本 |
| 威胁情报源 | 11个 |
| Web界面页面 | 8个 |
| 代码总行数 | ~42万行 |

---

## ⚠️ 免责声明

本工具仅供授权的安全测试和学习研究使用。使用本工具进行未授权的网络攻击是违法行为。使用者需自行承担使用本工具的一切法律责任。

**请确保：**
1. 你拥有目标系统的明确授权
2. 你遵守当地法律法规
3. 你不将本工具用于恶意目的
4. 你对测试造成的影响负责

---

## 📞 获取帮助

- API文档：http://127.0.0.1:8000/docs
- 项目文档：见 `docs/` 目录
- 示例脚本：见 `examples/` 目录
- 常见问题：见上文

---

**祝你使用愉快，安全测试顺利！🛡️**
