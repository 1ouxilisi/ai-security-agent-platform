# -*- coding: utf-8 -*-
"""
user_guides.py — 用户手册与指南模块。

提供快速上手指南、功能使用手册、场景化教程、管理员指南、开发者指南，
基于项目32大安全方向生成完整用户手册体系。
"""

from __future__ import annotations

from typing import Any, Dict, List


# --------------------------------------------------------------------------- #
# 32大安全方向（与architecture_docs保持一致）
# --------------------------------------------------------------------------- #
_SECURITY_DOMAINS = [
    ("web_security", "Web安全测试", "Web应用漏洞扫描与安全评估"),
    ("api_security", "API安全测试", "REST API/GraphQL安全测试与治理"),
    ("network_security", "网络安全分析", "网络流量分析与网络架构安全"),
    ("cloud_security", "云安全", "云配置审计与云原生安全评估"),
    ("container_security", "容器安全", "Docker/K8s容器镜像与运行时安全"),
    ("endpoint_security", "终端安全", "终端设备安全基线检查与加固"),
    ("identity_security", "身份安全", "身份认证与访问管理安全评估"),
    ("iot_security", "物联网安全", "IoT设备与固件安全测试"),
    ("ics_security", "工控安全", "工业控制系统安全评估"),
    ("mobile_security", "移动安全", "移动应用安全测试"),
    ("code_audit", "代码审计", "源代码安全审计与漏洞挖掘"),
    ("forensics", "取证分析", "数字取证与证据收集分析"),
    ("incident_response", "应急响应", "安全事件应急响应流程"),
    ("threat_intel", "威胁情报", "威胁情报收集与分析"),
    ("vulnerability_mgmt", "漏洞管理", "漏洞全生命周期管理"),
    ("compliance", "合规检查", "等保/GDPR/ISO27001合规评估"),
    ("data_security", "数据安全", "数据分类分级与DLP策略"),
    ("privacy", "隐私保护", "隐私合规与个人信息保护"),
    ("encryption", "加密管理", "密钥管理与加密算法评估"),
    ("access_control", "访问控制", "权限矩阵与访问策略审计"),
    ("audit_logging", "审计日志", "安全审计日志分析"),
    ("monitoring", "安全监控", "安全监控平台与告警"),
    ("alerting", "告警管理", "安全告警规则与通知"),
    ("backup_recovery", "备份恢复", "数据备份与灾难恢复"),
    ("devsecops", "DevSecOps", "安全左移与CI/CD安全集成"),
    ("bug_bounty", "漏洞赏金", "漏洞赏金项目管理"),
    ("combat_training", "实战训练", "攻防实战演练训练"),
    ("ctf_platform", "CTF平台", "CTF比赛与技能训练平台"),
    ("darkweb", "暗网监测", "暗网信息泄露监测"),
    ("deception", "欺骗防御", "蜜罐/欺骗防御系统"),
    ("email_security", "邮件安全", "邮件安全网关与钓鱼检测"),
    ("performance", "性能安全", "安全性能与压力测试"),
]


# --------------------------------------------------------------------------- #
# 1. 快速上手指南
# --------------------------------------------------------------------------- #
def get_quickstart() -> Dict[str, Any]:
    """快速上手指南。"""
    return {
        "title": "快速上手指南",
        "version": "v19.0",
        "sections": [
            {
                "step": 1,
                "title": "环境要求",
                "content": (
                    "Python 3.14+\n"
                    "操作系统: Windows 10+/Linux/macOS\n"
                    "内存: 最低4GB，推荐8GB\n"
                    "磁盘: 10GB可用空间\n"
                    "网络: 需访问授权测试目标"
                ),
            },
            {
                "step": 2,
                "title": "安装依赖",
                "content": (
                    "git clone <repo>\n"
                    "cd ai-hacking-agent\n"
                    "python -m venv .venv\n"
                    "# Windows: .venv\\Scripts\\activate\n"
                    "# Linux: source .venv/bin/activate\n"
                    "pip install -r requirements.txt"
                ),
            },
            {
                "step": 3,
                "title": "配置环境变量",
                "content": (
                    "复制 .env.example 为 .env\n"
                    "编辑 .env 设置:\n"
                    "  APP_HOST=0.0.0.0\n"
                    "  APP_PORT=8000\n"
                    "  API_KEY=your-secret-key\n"
                    "  DEBUG=false"
                ),
            },
            {
                "step": 4,
                "title": "启动服务",
                "content": (
                    "python -m uvicorn api_server.app:app --host 0.0.0.0 --port 8000\n"
                    "访问 http://localhost:8000/docs 查看API文档"
                ),
            },
            {
                "step": 5,
                "title": "第一个任务",
                "content": (
                    "# 通过API启动一次Web安全扫描\n"
                    "curl -X POST http://localhost:8000/api/v1/web-security/scan \\\n"
                    "  -H 'X-API-Key: your-key' \\\n"
                    "  -H 'Content-Type: application/json' \\\n"
                    "  -d '{\"target\": \"https://your-authorized-target.com\"}'\n\n"
                    "# 返回任务ID后查询结果\n"
                    "curl http://localhost:8000/api/v1/web-security/scan/<task_id> \\\n"
                    "  -H 'X-API-Key: your-key'"
                ),
            },
            {
                "step": 6,
                "title": "打开控制台",
                "content": (
                    "访问 http://localhost:8000/docs_system_console.html\n"
                    "在控制台中可视化操作所有安全功能模块。"
                ),
            },
        ],
        "checklist": [
            "Python 3.14+ 已安装",
            "虚拟环境已创建并激活",
            "依赖包安装完成",
            ".env 配置文件已填写",
            "服务启动无报错",
            "API文档页面可访问",
            "控制台页面可访问",
            "第一个测试任务已成功运行",
        ],
        "faq": [
            {
                "q": "启动报错 ModuleNotFoundError",
                "a": "确保在虚拟环境中运行，且已执行 pip install -r requirements.txt",
            },
            {
                "q": "端口被占用",
                "a": "修改 .env 中的 APP_PORT，或停止占用8000端口的进程",
            },
            {
                "q": "API返回401",
                "a": "检查请求头 X-API-Key 是否与 .env 中的 API_KEY 一致",
            },
        ],
    }


# --------------------------------------------------------------------------- #
# 2. 功能使用手册
# --------------------------------------------------------------------------- #
def get_feature_manuals() -> Dict[str, Any]:
    """功能使用手册（32大安全方向）。"""
    manuals = []
    for key, name, desc in _SECURITY_DOMAINS:
        manuals.append({
            "id": key,
            "name": name,
            "description": desc,
            "api_prefix": f"/api/v1/{key.replace('_', '-')}",
            "common_endpoints": [
                {"method": "POST", "path": "/scan", "desc": f"启动{name}扫描任务"},
                {"method": "GET", "path": "/scan/{task_id}", "desc": "查询任务状态"},
                {"method": "GET", "path": "/results/{task_id}", "desc": "获取扫描结果"},
                {"method": "GET", "path": "/reports", "desc": "获取报告列表"},
                {"method": "GET", "path": "/reports/{report_id}", "desc": "下载报告"},
            ],
            "usage_steps": [
                f"1. 确认已获得对目标 {desc.split('，')[0] if '，' in desc else desc} 的授权",
                "2. 调用POST /scan 提交目标和参数",
                "3. 获取task_id，轮询GET /scan/{task_id}等待完成",
                "4. 调用GET /results/{task_id}查看详细结果",
                "5. 调用GET /reports下载PDF/HTML格式报告",
            ],
            "best_practices": [
                "扫描前务必确认授权范围",
                "建议先在测试环境验证扫描参数",
                "生产环境扫描需在业务低峰期执行",
                "结果需人工复核后再出报告",
            ],
        })

    return {
        "total_modules": len(manuals),
        "modules": manuals,
    }


# --------------------------------------------------------------------------- #
# 3. 场景化教程
# --------------------------------------------------------------------------- #
def get_scenario_tutorials() -> Dict[str, Any]:
    """场景化教程库。"""
    return {
        "title": "场景化教程库",
        "scenarios": [
            {
                "id": "scenario_001",
                "name": "企业Web应用安全评估全流程",
                "difficulty": "中级",
                "duration": "2-4小时",
                "prerequisites": ["目标授权书", "API Key", "基础网络知识"],
                "steps": [
                    "步骤1: 使用Web安全模块对目标URL进行完整漏洞扫描",
                    "步骤2: 使用API安全模块检查REST接口",
                    "步骤3: 使用代码审计模块审查前端源代码",
                    "步骤4: 使用合规检查模块对照OWASP Top 10",
                    "步骤5: 生成综合安全评估报告",
                ],
                "expected_results": [
                    "漏洞清单（按严重程度排序）",
                    "风险等级分布图",
                    "修复建议清单",
                    "合规差距分析",
                ],
                "sample_data": {
                    "target": "https://your-app.example.com",
                    "scan_depth": "full",
                    "include_api_testing": True,
                },
            },
            {
                "id": "scenario_002",
                "name": "云基础设施安全基线检查",
                "difficulty": "初级",
                "duration": "1-2小时",
                "prerequisites": ["云账号只读权限"],
                "steps": [
                    "步骤1: 使用云安全模块扫描云配置",
                    "步骤2: 使用容器安全检查K8s集群",
                    "步骤3: 使用身份安全检查IAM策略",
                    "步骤4: 生成云安全基线报告",
                ],
                "expected_results": [
                    "云配置违规项列表",
                    "安全基线合规率",
                    "风险项修复优先级",
                ],
            },
            {
                "id": "scenario_003",
                "name": "应急响应取证分析",
                "difficulty": "高级",
                "duration": "4-8小时",
                "prerequisites": ["受影响系统镜像", "取证工具环境"],
                "steps": [
                    "步骤1: 使用取证分析模块加载系统镜像",
                    "步骤2: 使用威胁情报模块匹配IOC",
                    "步骤3: 使用应急响应模块编排处置流程",
                    "步骤4: 生成取证分析报告",
                ],
                "expected_results": [
                    "入侵时间线",
                    "受影响资产清单",
                    "攻击者TTPs分析",
                    "根除与恢复建议",
                ],
            },
            {
                "id": "scenario_004",
                "name": "等保2.0合规评估",
                "difficulty": "中级",
                "duration": "1-2天",
                "prerequisites": ["系统架构文档", "运维记录"],
                "steps": [
                    "步骤1: 使用合规检查模块选择等保2.0标准",
                    "步骤2: 逐项检查安全控制措施",
                    "步骤3: 使用审计日志模块验证日志完整性",
                    "步骤4: 生成等保合规差距报告",
                ],
                "expected_results": [
                    "合规项达标率",
                    "不符合项清单",
                    "整改建议",
                    "等保测评准备清单",
                ],
            },
            {
                "id": "scenario_005",
                "name": "护网行动红蓝对抗",
                "difficulty": "高级",
                "duration": "持续",
                "prerequisites": ["红蓝两队人员", "靶场环境"],
                "steps": [
                    "步骤1: 防守方部署欺骗防御蜜罐",
                    "步骤2: 防守方配置安全监控告警规则",
                    "步骤3: 攻击方使用渗透测试模块发起攻击",
                    "步骤4: 使用实战训练模块记录攻击链",
                    "步骤5: 复盘分析与改进",
                ],
                "expected_results": [
                    "攻击链时间线",
                    "告警触发记录",
                    "防御有效性评估",
                    "改进建议清单",
                ],
            },
        ],
    }


# --------------------------------------------------------------------------- #
# 4. 管理员指南
# --------------------------------------------------------------------------- #
def get_admin_guide() -> Dict[str, Any]:
    """管理员指南。"""
    return {
        "title": "管理员指南",
        "sections": [
            {
                "name": "系统配置",
                "items": [
                    {"config": "APP_HOST", "default": "0.0.0.0", "desc": "监听地址"},
                    {"config": "APP_PORT", "default": "8000", "desc": "监听端口"},
                    {"config": "API_KEY", "default": "change-me", "desc": "API认证密钥"},
                    {"config": "DEBUG", "default": "false", "desc": "调试模式"},
                    {"config": "MAX_WORKERS", "default": "4", "desc": "最大并发worker数"},
                    {"config": "TASK_TIMEOUT", "default": "3600", "desc": "任务超时(秒)"},
                ],
            },
            {
                "name": "用户管理",
                "items": [
                    "通过API Key管理用户访问",
                    "每个用户分配独立API Key",
                    "支持admin/operator/viewer三级权限",
                    "定期轮换API Key",
                ],
            },
            {
                "name": "权限配置",
                "items": [
                    "admin: 全部权限",
                    "operator: 扫描/报告/查看",
                    "viewer: 只读查看",
                    "权限通过API Key前缀区分",
                ],
            },
            {
                "name": "备份恢复",
                "items": [
                    "备份: 每日导出TASKS字典和报告文件",
                    "恢复: 将备份文件放回data目录",
                    "建议保留最近30天备份",
                ],
            },
            {
                "name": "升级",
                "items": [
                    "1. 备份当前数据",
                    "2. git pull拉取最新代码",
                    "3. pip install -r requirements.txt",
                    "4. 重启服务",
                    "5. 检查日志确认无报错",
                ],
            },
            {
                "name": "监控",
                "items": [
                    "健康检查: GET /health",
                    "日志路径: logs/ 目录",
                    "关键指标: API延迟、任务队列长度、错误率",
                ],
            },
            {
                "name": "故障排查",
                "items": [
                    "服务无法启动 → 检查Python版本和依赖",
                    "API 401 → 检查API Key配置",
                    "任务一直pending → 检查任务worker是否运行",
                    "内存占用高 → 清理旧TASKS数据",
                ],
            },
        ],
    }


# --------------------------------------------------------------------------- #
# 5. 开发者指南
# --------------------------------------------------------------------------- #
def get_developer_guide() -> Dict[str, Any]:
    """开发者指南。"""
    return {
        "title": "开发者指南",
        "sections": [
            {
                "name": "开发环境搭建",
                "items": [
                    "Python 3.14+",
                    "VS Code + Python扩展",
                    "推荐: ruff代码检查 + black格式化",
                    "Git版本控制",
                    "pre-commit hooks（可选）",
                ],
            },
            {
                "name": "代码规范",
                "items": [
                    "PEP 8 Python代码风格",
                    "from __future__ import annotations",
                    "所有模块顶部docstring说明用途",
                    "类型标注使用typing模块",
                    "路由文件: APIRouter + try-except + ok()/fail()",
                    "第三方库try-import + 回退模拟数据",
                ],
            },
            {
                "name": "新增模块开发",
                "items": [
                    "1. 在对应领域目录创建新模块文件",
                    "2. 实现核心业务逻辑函数",
                    "3. 在api_server/下创建 xxx_routes.py",
                    "4. 路由模板: APIRouter(prefix, tags) + try-except",
                    "5. 响应统一用 ok(data) / fail(msg)",
                    "6. 在app.py中注册路由（如需）",
                    "7. 编写对应的HTML控制台页面",
                ],
            },
            {
                "name": "API开发规范",
                "items": [
                    "端点路径: /api/v1/{domain}/{action}",
                    "请求模型: Pydantic BaseModel",
                    "响应格式: {success, data, error}",
                    "每个端点try-except兜底",
                    "文档字符串说明用途和参数",
                ],
            },
            {
                "name": "前端开发规范",
                "items": [
                    "单HTML文件，内联CSS/JS",
                    "深色主题，响应式布局",
                    "UTF-8编码",
                    "Fetch API调用后端",
                    "Tab切换式布局",
                ],
            },
            {
                "name": "测试",
                "items": [
                    "单元测试: pytest",
                    "API测试: TestClient",
                    "手动测试: 启动服务后用curl验证",
                    "import验证: 每个.py文件独立import无报错",
                ],
            },
            {
                "name": "提交PR流程",
                "items": [
                    "1. Fork仓库",
                    "2. 创建特性分支",
                    "3. 开发并测试",
                    "4. 提交PR，描述变更内容",
                    "5. Code Review通过后合并",
                ],
            },
        ],
    }
