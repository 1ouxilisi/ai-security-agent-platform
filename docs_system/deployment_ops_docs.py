# -*- coding: utf-8 -*-
"""
deployment_ops_docs.py — 部署与运维文档模块。

提供安装部署文档、配置参考、运维操作手册、监控告警、故障排查指南。
"""

from __future__ import annotations

from typing import Any, Dict, List


# --------------------------------------------------------------------------- #
# 1. 安装部署文档
# --------------------------------------------------------------------------- #
def get_install_guide() -> Dict[str, Any]:
    """安装部署文档。"""
    return {
        "title": "安装部署文档",
        "platforms": [
            {
                "platform": "Windows",
                "steps": [
                    "1. 安装Python 3.14+（从python.org下载）",
                    "2. 安装Git（从git-scm.com下载）",
                    "3. 打开PowerShell，克隆仓库: git clone <repo>",
                    "4. cd ai-hacking-agent",
                    "5. python -m venv .venv",
                    "6. .venv\\Scripts\\activate",
                    "7. pip install -r requirements.txt",
                    "8. copy .env.example .env",
                    "9. 编辑.env配置",
                    "10. python -m uvicorn api_server.app:app --host 0.0.0.0 --port 8000",
                ],
                "requirements": ["Windows 10/11", "4GB+ RAM", "10GB+磁盘"],
            },
            {
                "platform": "Linux (Ubuntu/Debian)",
                "steps": [
                    "1. sudo apt update && sudo apt install python3.14 python3-pip git",
                    "2. git clone <repo> && cd ai-hacking-agent",
                    "3. python3 -m venv .venv",
                    "4. source .venv/bin/activate",
                    "5. pip install -r requirements.txt",
                    "6. cp .env.example .env",
                    "7. 编辑.env",
                    "8. uvicorn api_server.app:app --host 0.0.0.0 --port 8000",
                ],
                "requirements": ["Ubuntu 22.04+", "4GB+ RAM", "systemd"],
            },
            {
                "platform": "Docker",
                "steps": [
                    "1. 安装Docker和Docker Compose",
                    "2. git clone <repo> && cd ai-hacking-agent",
                    "3. docker build -t ai-hacking-agent .",
                    "4. docker run -d -p 8000:8000 --env-file .env ai-hacking-agent",
                    "5. 访问 http://localhost:8000/docs",
                ],
                "dockerfile": [
                    "FROM python:3.14-slim",
                    "WORKDIR /app",
                    "COPY requirements.txt .",
                    "RUN pip install --no-cache-dir -r requirements.txt",
                    "COPY . .",
                    "EXPOSE 8000",
                    'CMD ["uvicorn", "api_server.app:app", "--host", "0.0.0.0", "--port", "8000"]',
                ],
            },
            {
                "platform": "Kubernetes",
                "steps": [
                    "1. 构建Docker镜像并推送到仓库",
                    "2. 创建Deployment YAML",
                    "3. kubectl apply -f deployment.yaml",
                    "4. 创建Service暴露端口",
                    "5. 配置Ingress和TLS",
                ],
                "deployment_yaml_snippet": (
                    "apiVersion: apps/v1\n"
                    "kind: Deployment\n"
                    "metadata:\n  name: ai-hacking-agent\n"
                    "spec:\n  replicas: 2\n"
                    "  selector:\n    matchLabels:\n      app: ai-hacking-agent\n"
                    "  template:\n    metadata:\n      labels:\n        app: ai-hacking-agent\n"
                    "    spec:\n      containers:\n      - name: app\n"
                    "        image: ai-hacking-agent:latest\n"
                    "        ports:\n        - containerPort: 8000\n"
                    "        envFrom:\n        - configMapRef:\n            name: app-config"
                ),
            },
        ],
        "dependencies": [
            "fastapi", "uvicorn", "pydantic", "python-dotenv",
            "httpx", "aiofiles", "jinja2",
        ],
        "env_variables": [
            {"name": "APP_HOST", "default": "0.0.0.0", "desc": "监听地址"},
            {"name": "APP_PORT", "default": "8000", "desc": "监听端口"},
            {"name": "API_KEY", "default": "", "desc": "API认证密钥（必填）"},
            {"name": "DEBUG", "default": "false", "desc": "调试模式"},
            {"name": "LOG_LEVEL", "default": "INFO", "desc": "日志级别"},
            {"name": "MAX_WORKERS", "default": "4", "desc": "并发worker数"},
            {"name": "TASK_TIMEOUT", "default": "3600", "desc": "任务超时秒数"},
        ],
    }


# --------------------------------------------------------------------------- #
# 2. 配置参考
# --------------------------------------------------------------------------- #
def get_config_reference() -> Dict[str, Any]:
    """配置参考文档。"""
    return {
        "title": "配置参考手册",
        "config_sections": [
            {
                "section": "服务配置",
                "items": [
                    {"key": "APP_HOST", "type": "string", "default": "0.0.0.0",
                     "desc": "服务监听地址，0.0.0.0表示所有网卡", "example": "127.0.0.1"},
                    {"key": "APP_PORT", "type": "int", "default": "8000",
                     "desc": "服务监听端口", "example": "8080"},
                    {"key": "DEBUG", "type": "bool", "default": "false",
                     "desc": "调试模式，生产环境务必关闭", "example": "true"},
                ],
            },
            {
                "section": "安全配置",
                "items": [
                    {"key": "API_KEY", "type": "string", "default": "",
                     "desc": "API认证密钥，所有请求需携带X-API-Key头", "example": "sk-xxxxxx"},
                    {"key": "CORS_ORIGINS", "type": "string", "default": "*",
                     "desc": "允许的跨域来源，逗号分隔", "example": "https://app.example.com"},
                    {"key": "RATE_LIMIT", "type": "int", "default": "60",
                     "desc": "每用户每分钟请求限制", "example": "100"},
                ],
            },
            {
                "section": "任务配置",
                "items": [
                    {"key": "MAX_WORKERS", "type": "int", "default": "4",
                     "desc": "并发执行的最大任务数", "example": "8"},
                    {"key": "TASK_TIMEOUT", "type": "int", "default": "3600",
                     "desc": "单个任务超时时间（秒）", "example": "7200"},
                    {"key": "TASK_CLEANUP_DAYS", "type": "int", "default": "7",
                     "desc": "自动清理N天前的任务", "example": "30"},
                ],
            },
            {
                "section": "日志配置",
                "items": [
                    {"key": "LOG_LEVEL", "type": "enum", "default": "INFO",
                     "desc": "日志级别: DEBUG/INFO/WARNING/ERROR", "example": "DEBUG"},
                    {"key": "LOG_FILE", "type": "string", "default": "logs/app.log",
                     "desc": "日志文件路径", "example": "/var/log/agent.log"},
                    {"key": "LOG_MAX_SIZE", "type": "string", "default": "10MB",
                     "desc": "单个日志文件最大大小", "example": "50MB"},
                ],
            },
        ],
        "config_template": (
            "# .env 配置模板\n"
            "# 服务配置\n"
            "APP_HOST=0.0.0.0\n"
            "APP_PORT=8000\n"
            "DEBUG=false\n\n"
            "# 安全配置\n"
            "API_KEY=your-secret-api-key-here\n"
            "CORS_ORIGINS=*\n"
            "RATE_LIMIT=60\n\n"
            "# 任务配置\n"
            "MAX_WORKERS=4\n"
            "TASK_TIMEOUT=3600\n"
            "TASK_CLEANUP_DAYS=7\n\n"
            "# 日志配置\n"
            "LOG_LEVEL=INFO\n"
            "LOG_FILE=logs/app.log"
        ),
    }


# --------------------------------------------------------------------------- #
# 3. 运维操作手册
# --------------------------------------------------------------------------- #
def get_ops_manual() -> Dict[str, Any]:
    """运维操作手册。"""
    return {
        "title": "运维操作手册",
        "operations": [
            {
                "name": "启动服务",
                "commands": [
                    "# 开发模式",
                    "uvicorn api_server.app:app --reload --port 8000",
                    "# 生产模式",
                    "uvicorn api_server.app:app --host 0.0.0.0 --port 8000 --workers 4",
                ],
            },
            {
                "name": "停止服务",
                "commands": [
                    "# Ctrl+C 停止",
                    "# 或查找进程并杀死",
                    "ps aux | grep uvicorn",
                    "kill <PID>",
                ],
            },
            {
                "name": "重启服务",
                "commands": [
                    "1. 停止当前服务",
                    "2. 备份数据",
                    "3. 启动新服务",
                    "4. 验证: curl http://localhost:8000/health",
                ],
            },
            {
                "name": "升级操作",
                "commands": [
                    "1. git pull",
                    "2. pip install -r requirements.txt",
                    "3. 检查.env是否有新增配置项",
                    "4. 重启服务",
                    "5. 查看日志确认无报错",
                ],
            },
            {
                "name": "备份操作",
                "commands": [
                    "# 备份配置",
                    "cp .env .env.backup",
                    "# 备份数据目录",
                    "tar -czf backup_$(date +%Y%m%d).tar.gz data/ logs/",
                ],
            },
            {
                "name": "恢复操作",
                "commands": [
                    "1. 停止服务",
                    "2. tar -xzf backup_YYYYMMDD.tar.gz",
                    "3. 恢复.env",
                    "4. 启动服务",
                    "5. 验证数据完整性",
                ],
            },
            {
                "name": "日志查看",
                "commands": [
                    "# 实时日志",
                    "tail -f logs/app.log",
                    "# 错误日志",
                    "grep ERROR logs/app.log",
                    "# 最近100行",
                    "tail -100 logs/app.log",
                ],
            },
            {
                "name": "性能调优",
                "items": [
                    "增加workers: --workers 4（CPU核数*2+1）",
                    "启用GZip压缩",
                    "配置合理的TASK_TIMEOUT",
                    "定期清理旧TASKS数据",
                    "监控内存使用，必要时重启服务",
                ],
            },
        ],
        "daily_checklist": [
            "服务进程是否正常运行",
            "API健康检查 /health 返回200",
            "磁盘空间是否充足（>10%可用）",
            "内存使用是否正常（<80%）",
            "日志中是否有ERROR级别记录",
            "备份是否成功执行",
        ],
    }


# --------------------------------------------------------------------------- #
# 4. 监控与告警
# --------------------------------------------------------------------------- #
def get_monitoring_alerting() -> Dict[str, Any]:
    """监控与告警文档。"""
    return {
        "title": "监控与告警配置",
        "metrics": [
            {"name": "api_request_latency", "desc": "API请求延迟（P50/P95/P99）", "unit": "ms"},
            {"name": "api_request_count", "desc": "API请求总数", "unit": "次/分钟"},
            {"name": "api_error_rate", "desc": "API错误率", "unit": "%"},
            {"name": "task_queue_size", "desc": "任务队列长度", "unit": "个"},
            {"name": "task_duration", "desc": "任务执行时长", "unit": "秒"},
            {"name": "memory_usage", "desc": "内存使用率", "unit": "%"},
            {"name": "cpu_usage", "desc": "CPU使用率", "unit": "%"},
            {"name": "disk_usage", "desc": "磁盘使用率", "unit": "%"},
        ],
        "alert_rules": [
            {
                "name": "服务宕机告警",
                "condition": "连续3次/health返回失败",
                "severity": "critical",
                "action": "立即通知值班人员",
            },
            {
                "name": "高错误率告警",
                "condition": "api_error_rate > 5% 持续5分钟",
                "severity": "high",
                "action": "通知运维团队检查",
            },
            {
                "name": "内存告警",
                "condition": "memory_usage > 85% 持续10分钟",
                "severity": "medium",
                "action": "检查是否有内存泄漏",
            },
            {
                "name": "磁盘告警",
                "condition": "disk_usage > 90%",
                "severity": "high",
                "action": "清理日志和旧数据",
            },
            {
                "name": "任务超时告警",
                "condition": "单个任务执行超过TASK_TIMEOUT",
                "severity": "medium",
                "action": "终止任务并记录",
            },
        ],
        "alert_channels": [
            "邮件通知",
            "Webhook (钉钉/飞书/Slack)",
            "短信通知（P0级告警）",
        ],
        "oncall_process": [
            "1. 收到告警通知",
            "2. 登录系统查看监控仪表盘",
            "3. 根据故障排查指南定位问题",
            "4. 执行修复操作",
            "5. 验证服务恢复",
            "6. 记录事件并复盘",
        ],
        "dashboards": [
            {"name": "总览仪表盘", "content": "QPS、延迟、错误率、在线用户"},
            {"name": "任务仪表盘", "content": "任务队列、执行时长、成功率"},
            {"name": "系统仪表盘", "content": "CPU、内存、磁盘、网络"},
            {"name": "安全仪表盘", "content": "扫描任务数、发现漏洞数、告警数"},
        ],
    }


# --------------------------------------------------------------------------- #
# 5. 故障排查指南
# --------------------------------------------------------------------------- #
def get_troubleshooting() -> Dict[str, Any]:
    """故障排查指南。"""
    return {
        "title": "故障排查指南",
        "common_issues": [
            {
                "symptom": "服务启动失败",
                "causes": [
                    "Python版本不对（需3.14+）",
                    "依赖未安装",
                    "端口被占用",
                    ".env配置错误",
                ],
                "solutions": [
                    "python --version 检查版本",
                    "pip install -r requirements.txt",
                    "netstat -ano | findstr :8000 检查端口",
                    "检查.env文件格式",
                ],
            },
            {
                "symptom": "API返回401 Unauthorized",
                "causes": [
                    "请求未携带X-API-Key头",
                    "API Key不正确",
                    "API_KEY环境变量未设置",
                ],
                "solutions": [
                    "检查请求头是否包含X-API-Key",
                    "对比.env中的API_KEY",
                    "重启服务使配置生效",
                ],
            },
            {
                "symptom": "API返回503 Module Unavailable",
                "causes": [
                    "模块依赖缺失",
                    "模块加载失败",
                    "第三方库未安装",
                ],
                "solutions": [
                    "查看服务启动日志中的报错",
                    "pip install 缺失的依赖",
                    "模块有try-import回退，功能降级可用",
                ],
            },
            {
                "symptom": "任务一直pending",
                "causes": [
                    "任务worker未启动",
                    "任务队列堵塞",
                    "任务执行超时",
                ],
                "solutions": [
                    "检查任务是否被正确提交",
                    "查看日志中的任务执行记录",
                    "重启服务清理积压任务",
                ],
            },
            {
                "symptom": "内存持续增长",
                "causes": [
                    "TASKS字典未清理",
                    "扫描结果数据量过大",
                    "内存泄漏",
                ],
                "solutions": [
                    "定期清理旧任务: 设置TASK_CLEANUP_DAYS",
                    "重启服务释放内存",
                    "监控内存趋势，定位泄漏点",
                ],
            },
            {
                "symptom": "前端页面加载白屏",
                "causes": [
                    "HTML文件路径错误",
                    "静态文件未正确挂载",
                    "JS语法错误",
                ],
                "solutions": [
                    "检查浏览器控制台错误信息",
                    "确认HTML文件在api_server/目录下",
                    "检查是否有CORS问题",
                ],
            },
        ],
        "error_codes": [
            {"code": "400", "meaning": "请求参数错误", "action": "检查请求体格式和必填字段"},
            {"code": "401", "meaning": "未认证", "action": "检查X-API-Key请求头"},
            {"code": "403", "meaning": "无权限", "action": "检查用户角色权限"},
            {"code": "404", "meaning": "资源不存在", "action": "检查URL路径和资源ID"},
            {"code": "429", "meaning": "请求限流", "action": "降低请求频率"},
            {"code": "503", "meaning": "服务不可用", "action": "检查模块加载状态"},
        ],
        "troubleshooting_steps": [
            "1. 确认现象：错误信息、复现步骤",
            "2. 查看日志：tail -100 logs/app.log",
            "3. 检查配置：对比.env和默认配置",
            "4. 验证依赖：pip list | grep 相关包",
            "5. 测试API：curl直接调用验证",
            "6. 搜索FAQ和已知问题",
            "7. 如无法解决，记录详细信息并寻求社区支持",
        ],
        "faq": [
            {
                "q": "如何重置API Key？",
                "a": "修改.env中的API_KEY，重启服务即可。",
            },
            {
                "q": "任务结果保存在哪里？",
                "a": "当前版本使用内存字典TASKS存储，服务重启后丢失。生产环境建议持久化。",
            },
            {
                "q": "如何增加新的安全扫描模块？",
                "a": "参考现有_routes.py模板，创建新的路由文件并在app.py中注册。",
            },
            {
                "q": "支持多用户吗？",
                "a": "当前通过API Key区分用户，基础权限控制已实现。企业版支持完整RBAC。",
            },
        ],
        "fault_tree": (
            "服务不可用\n"
            "├── 进程未运行\n"
            "│   ├── 启动命令错误\n"
            "│   └── 端口被占用\n"
            "├── 依赖问题\n"
            "│   ├── Python版本不兼容\n"
            "│   └── 缺失第三方库\n"
            "├── 配置错误\n"
            "│   ├── .env格式错误\n"
            "│   └── 环境变量未设置\n"
            "└── 资源不足\n"
            "    ├── 内存不足\n"
            "    └── 磁盘已满"
        ),
    }
