# 项目目录结构说明

## 目录概览

本项目包含77个顶级目录，部分目录存在功能重叠或历史遗留。以下是详细说明。

## 核心模块目录

| 目录 | 功能 | 状态 |
|------|------|------|
| `agent/` | 多智能体框架（ReAct/RAG/记忆/结果分析） | ✅ 活跃 |
| `scanner/` | 核心扫描引擎（端口/服务/漏洞） | ✅ 活跃 |
| `exploit/` | PoC利用框架和漏洞库 | ✅ 活跃 |
| `workflow/` | 工作流引擎 | ✅ 活跃 |
| `knowledge/` | 知识库（CVE/漏洞/攻击模式） | ✅ 活跃 |
| `nuclei_engine/` | Nuclei模板引擎 | ✅ 活跃 |
| `api_server/` | FastAPI API服务和前端页面 | ✅ 活跃 |
| `mcp_server/` | MCP协议服务端 | ✅ 活跃 |
| `config/` | 配置管理 | ✅ 活跃 |
| `utils/` | 工具函数库 | ✅ 活跃 |
| `database/` | 数据库模块 | ✅ 活跃 |
| `security/` | 安全模块（API鉴权等） | ✅ 活跃 |
| `cache/` | 缓存管理 | ✅ 活跃 |
| `plugins/` | 插件系统 | ✅ 活跃 |
| `reporting/` | 报告导出 | ✅ 活跃 |
| `scheduler/` | 任务调度器 | ✅ 活跃 |

## 扩展安全模块目录（7大领域）

| 目录 | 功能 | 状态 |
|------|------|------|
| `mobile_security/` | 移动安全（APK解析/漏洞扫描/动态分析/Frida） | ✅ 活跃 |
| `internal_pentest/` | 内网渗透（SMB枚举/域渗透/横向移动） | ✅ 活跃 |
| `cloud_security/` | 云安全（AWS/Azure/阿里云/容器/K8s） | ✅ 活跃 |
| `api_security/` | API安全（OpenAPI解析/认证测试/Fuzz） | ✅ 活跃 |
| `client_security/` | 客户端安全（二进制分析/加壳检测/反调试） | ✅ 活跃 |
| `code_audit/` | 代码审计（5种语言静态分析/依赖扫描） | ✅ 活跃 |
| `wireless_security/` | 无线网络（WiFi扫描/安全评估/弱密码） | ✅ 活跃 |

## 高级安全模块目录（8大领域）

| 目录 | 功能 | 状态 |
|------|------|------|
| `ai_security/` | AI安全（提示注入/模型评估/数据投毒） | ✅ 活跃 |
| `iot_security/` | IoT安全（IoT扫描/默认密码/固件分析） | ✅ 活跃 |
| `ics_security/` | 工控安全（ICS扫描/已知漏洞/IEC 62443） | ✅ 活跃 |
| `blockchain_security/` | 区块链安全（智能合约审计/ERC20合规） | ✅ 活跃 |
| `forensics/` | 取证分析（Windows日志/哈希/证据链） | ✅ 活跃 |
| `threat_intelligence/` | 威胁情报（IOC查询/IP信誉/ATT&CK/APT） | ✅ 活跃 |
| `social_engineering/` | 社会工程学（钓鱼演练/Pretext/安全培训） | ✅ 活跃 |
| `vulnerability_management/` | 漏洞管理（跟踪/状态/SLA/统计） | ✅ 活跃 |

## 功能重叠/历史遗留目录

以下目录存在功能重叠，建议后续整合：

| 目录 | 与哪个目录重叠 | 说明 |
|------|---------------|------|
| `mobile/` | `mobile_security/` | 早期移动安全模块，建议迁移到mobile_security |
| `cloud/` | `cloud_security/` | 早期云安全模块，建议迁移到cloud_security |
| `threat_intel/` | `threat_intelligence/` | 早期威胁情报模块，建议迁移到threat_intelligence |
| `internal/` | `internal_pentest/` | 早期内网模块，建议迁移到internal_pentest |
| `report/` | `reporting/` | 早期报告模块，建议迁移到reporting |
| `reports/` | `reporting/` | 报告输出目录，非代码 |
| `web/` | `api_server/` | 早期Web模块，功能已集成到api_server |
| `web_ui/` | `api_server/` | 早期Web UI，功能已集成到api_server |
| `desktop/` | - | 桌面端（未完成） |
| `portal/` | - | 客户门户（未完成） |
| `saas/` | - | SaaS化（未完成） |
| `enterprise/` | - | 企业级功能（部分通过插件实现） |
| `distributed/` | `api_server/distributed_routes.py` | 分布式扫描（部分实现） |
| `combat/` | `api_server/combat_routes.py` | 实战能力（部分实现） |
| `lab/` | - | 实验性功能 |
| `ml_engine/` | - | 机器学习引擎（未完成） |
| `osint/` | - | 开源情报（未完成） |
| `siem/` | - | SIEM集成（未完成） |
| `soar/` | - | SOAR集成（未完成） |
| `monitoring/` | - | 监控模块（未完成） |
| `notifications/` | - | 通知模块（未完成） |
| `gateway/` | - | API网关（未完成） |
| `auth/` | `utils/auth.py` | 认证模块（部分重复） |
| `browser/` | - | 浏览器自动化（未完成） |
| `integrations/` | - | 第三方集成（未完成） |
| `mcp_standalone/` | `mcp_server/` | MCP独立版本 |
| `src_platform/` | - | 源码平台（未完成） |
| `verifier/` | - | 验证器（未完成） |
| `validation_reports/` | - | 验证报告输出目录 |
| `tools/` | `api_server/tools_routes.py` | 工具集成（部分实现） |
| `tools_cli/` | - | 工具CLI（未完成） |
| `scan_results/` | - | 扫描结果输出目录 |
| `screenshots/` | - | 截图输出目录 |
| `logs/` | - | 日志输出目录 |
| `data/` | - | 数据存储目录 |
| `assets/` | - | 静态资源 |
| `docs/` | - | 文档目录 |
| `examples/` | - | 示例代码 |
| `scripts/` | - | 辅助脚本 |
| `docker/` | - | Docker相关文件 |
| `.github/` | - | GitHub CI/CD配置 |
| `tests/` | - | 单元测试 |

## 建议整合方案

### 第一阶段：标记和文档（已完成）
- 本文档已标记所有重叠目录

### 第二阶段：迁移活跃代码
- 将`mobile/`、`cloud/`、`threat_intel/`、`internal/`中的活跃代码迁移到对应的新模块
- 更新所有导入引用

### 第三阶段：归档历史目录
- 将已迁移完成的旧目录移动到`_archive/`目录
- 保留至少一个版本周期后删除

### 第四阶段：完成未完成模块
- 优先完成`desktop/`、`portal/`、`distributed/`、`combat/`等有API路由支持的模块
- 其他未完成模块根据需求优先级逐步实现

## 注意事项

1. **不要直接删除目录**：部分目录可能被其他模块引用，删除前需全局搜索引用
2. **保留输出目录**：`data/`、`logs/`、`scan_results/`、`reports/`等是运行时输出目录，需保留
3. **渐进式迁移**：建议按模块逐个迁移，每迁移一个模块后运行测试确保不破坏现有功能
