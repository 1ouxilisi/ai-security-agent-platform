# 贡献指南

感谢你对 AI Hacking Agent 项目的关注！我们欢迎各种形式的贡献，包括但不限于代码提交、文档改进、Bug报告、功能建议和社区支持。

## 目录

- [行为准则](#行为准则)
- [如何贡献](#如何贡献)
- [开发环境搭建](#开发环境搭建)
- [代码规范](#代码规范)
- [提交规范](#提交规范)
- [Pull Request 流程](#pull-request-流程)
- [报告Bug](#报告bug)
- [功能建议](#功能建议)

## 行为准则

参与本项目即表示你同意遵守我们的 [行为准则](CODE_OF_CONDUCT.md)。请在所有交互中保持尊重和专业。

## 如何贡献

### 1. Fork 并克隆

```bash
# Fork 项目到你的GitHub账户
git clone https://github.com/your-username/ai-hacking-agent.git
cd ai-hacking-agent
git remote add upstream https://github.com/original/ai-hacking-agent.git
```

### 2. 创建分支

```bash
git checkout -b feature/your-feature-name
# 或
git checkout -b fix/your-bug-fix
```

### 3. 提交更改

```bash
git add .
git commit -m "feat: 添加新功能描述"
```

### 4. 推送并创建PR

```bash
git push origin feature/your-feature-name
```

然后在GitHub上创建Pull Request。

## 开发环境搭建

### 系统要求

- Python 3.10+
- Git
- （可选）Docker / Docker Compose

### 安装步骤

```bash
# 1. 克隆项目
git clone https://github.com/your-username/ai-hacking-agent.git
cd ai-hacking-agent

# 2. 创建虚拟环境
python -m venv venv
source venv/bin/activate  # Linux/Mac
# 或
venv\Scripts\activate     # Windows

# 3. 安装依赖
pip install -r requirements.txt
pip install -r requirements-dev.txt

# 4. 安装pre-commit钩子
pre-commit install

# 5. 配置环境变量
cp .env.example .env
# 编辑 .env 文件，填入你的API密钥

# 6. 运行测试
pytest tests/

# 7. 启动服务
python main.py api-server --host 127.0.0.1 --port 8000
```

### 使用Docker

```bash
# 构建镜像
docker build -t ai-hacking-agent .

# 启动服务
docker-compose up -d

# 查看日志
docker-compose logs -f
```

## 代码规范

### Python 代码

- 遵循 [PEP 8](https://www.python.org/dev/peps/pep-0008/) 风格指南
- 使用类型注解（Type Hints）
- 编写文档字符串（Docstrings），遵循 Google 风格
- 最大行长度：120字符
- 使用 4 空格缩进

### 代码检查

```bash
# 运行flake8
flake8 .

# 运行black格式化
black .

# 运行isort排序导入
isort .

# 运行mypy类型检查
mypy .
```

### 命名规范

- 模块名：小写+下划线（`snake_case`）
- 类名：大驼峰（`PascalCase`）
- 函数/方法名：小写+下划线（`snake_case`）
- 常量：全大写+下划线（`UPPER_CASE`）
- 私有方法/属性：单下划线前缀（`_private`）

### 文档字符串示例

```python
def scan_target(target: str, ports: str = "1-1000") -> ScanResult:
    """扫描目标主机的开放端口。

    Args:
        target: 目标IP地址或域名
        ports: 要扫描的端口范围，默认为"1-1000"

    Returns:
        ScanResult: 包含扫描结果的对象

    Raises:
        ValueError: 目标地址无效时抛出
        ConnectionError: 无法连接目标时抛出

    Example:
        >>> result = scan_target("192.168.1.1", "1-100")
        >>> print(result.open_ports)
        [22, 80, 443]
    """
    pass
```

## 提交规范

我们使用 [Conventional Commits](https://www.conventionalcommits.org/) 规范：

```
<type>(<scope>): <subject>

<body>

<footer>
```

### 类型（type）

- `feat`: 新功能
- `fix`: Bug修复
- `docs`: 文档更新
- `style`: 代码格式（不影响功能）
- `refactor`: 重构（既不是新功能也不是修复）
- `perf`: 性能优化
- `test`: 添加或修改测试
- `chore`: 构建过程或辅助工具的变动
- `ci`: CI/CD配置变更
- `security`: 安全相关修复

### 示例

```
feat(scan): 添加Nmap服务版本探测功能

- 添加-sV参数支持
- 实现服务指纹识别
- 更新扫描结果数据模型

Closes #123
```

```
fix(auth): 修复JWT令牌过期验证逻辑

- 修复exp字段解析错误
- 添加令牌刷新机制
- 更新单元测试

Fixes #456
```

## Pull Request 流程

### PR 要求

1. **标题清晰**：使用提交规范格式
2. **描述完整**：说明做了什么、为什么、怎么做的
3. **测试通过**：所有单元测试必须通过
4. **代码规范**：通过flake8、black、isort检查
5. **文档更新**：如有必要，更新相关文档
6. **关联Issue**：关联相关的Issue编号

### PR 模板

创建PR时请使用我们的 [PR模板](.github/PULL_REQUEST_TEMPLATE.md)，包含：

- 变更类型
- 变更描述
- 测试说明
- 截图（如适用）
- 关联Issue
- 检查清单

### 审核流程

1. 提交PR后，自动运行CI检查
2. 维护者审核代码
3. 根据反馈进行修改
4. 审核通过后合并到主分支

## 报告Bug

请使用我们的 [Bug报告模板](.github/ISSUE_TEMPLATE/bug_report.md)，包含：

- 清晰的标题
- 复现步骤
- 预期行为
- 实际行为
- 环境信息（OS、Python版本、依赖版本）
- 日志/截图
- 可能的原因

## 功能建议

请使用我们的 [功能请求模板](.github/ISSUE_TEMPLATE/feature_request.md)，包含：

- 功能描述
- 解决的问题
- 建议的实现方案
- 替代方案
- 附加说明

## 安全漏洞披露

如果你发现了安全漏洞，请**不要**公开创建Issue。请按照我们的 [安全政策](SECURITY.md) 进行负责任的披露。

## 社区

- GitHub Discussions：一般讨论和问答
- Issues：Bug报告和功能请求
- Pull Requests：代码贡献

## 致谢

感谢所有为这个项目做出贡献的人！你的努力使这个项目变得更好。

---

如有任何疑问，请通过GitHub Discussions联系维护者。
