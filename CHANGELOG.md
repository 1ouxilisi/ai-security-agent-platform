# 更新日志

## [4.0.0] - 2026-09-10

### 新增
- 20大安全领域全覆盖（核心5+扩展7+高级8）
- 高级安全控制台（8个高级领域完整前端界面）
- 扩展安全控制台（7个扩展领域完整前端界面）
- 315个单元测试，通过率100%
- 13个前端页面
- 254+ API端点
- Docker和docker-compose部署支持
- API鉴权系统
- 多智能体协作框架
- 工作流引擎

### 修复
- 修复MCP Server API兼容性问题（add_request_handler → request_handlers）
- 修复TaskScheduler类名和方法名不匹配问题
- 修复API鉴权测试白名单逻辑
- 修复code_audit模块语法错误
- 修复console-v7页面中文乱码导致的JS失效问题
- 修复6个文件的asyncio.iscoroutinefunction废弃警告

### 改进
- 项目规模扩展到382个Python文件，11.4万行代码
- 添加Linux/Mac启动脚本start.sh
- 添加代码质量工具配置（flake8/black/isort/mypy）
- 添加GitHub Actions CI/CD流水线
- 完善项目文档（INSTALL.md/USAGE.md/CHANGELOG.md）

## [3.0.0] - 2026-08

### 新增
- 7个扩展安全模块（移动/内网/云/API/客户端/代码审计/无线网络）
- 扩展安全API（22个端点）
- 扩展安全控制台前端页面

## [2.0.0] - 2026-07

### 新增
- 核心安全功能（Web扫描/漏洞扫描/PoC利用）
- 多智能体框架
- 工作流引擎
- API服务和Swagger文档
- 主控制台前端页面

## [1.0.0] - 2026-06

### 新增
- 项目初始化
- 基础架构搭建
- 配置管理系统
- 日志系统
