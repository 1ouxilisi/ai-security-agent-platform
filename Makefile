# AI Hacking Agent Makefile
# 用法: make <target>

.PHONY: help install install-dev test lint format clean build run docker-build docker-up docker-down docs coverage security audit

# 变量
PYTHON := python
PIP := pip
PROJECT := ai-hacking-agent
VERSION := 7.0.0
DOCKER_IMAGE := $(PROJECT):$(VERSION)

# 默认目标
.DEFAULT_GOAL := help

## 帮助
help: ## 显示此帮助信息
	@echo "AI Hacking Agent v$(VERSION)"
	@echo ""
	@echo "可用目标:"
	@grep -E '^[a-zA-Z_-]+:.*?## .*$$' $(MAKEFILE_LIST) | awk 'BEGIN {FS = ":.*?## "}; {printf "  \033[36m%-20s\033[0m %s\n", $$1, $$2}'
	@echo ""
	@echo "示例:"
	@echo "  make install      # 安装依赖"
	@echo "  make test         # 运行测试"
	@echo "  make run          # 启动服务"
	@echo "  make docker-up    # Docker启动"

## 安装
install: ## 安装生产依赖
	$(PIP) install -r requirements.txt

install-dev: ## 安装开发依赖
	$(PIP) install -r requirements.txt -r requirements-dev.txt
	pre-commit install

install-editable: ## 以可编辑模式安装
	$(PIP) install -e .

## 测试
test: ## 运行所有测试
	$(PYTHON) -m pytest tests/ -v

test-unit: ## 运行单元测试
	$(PYTHON) -m pytest tests/ -v -m unit

test-integration: ## 运行集成测试
	$(PYTHON) -m pytest tests/ -v -m integration

test-api: ## 运行API测试
	$(PYTHON) -m pytest tests/ -v -m api

test-security: ## 运行安全测试
	$(PYTHON) -m pytest tests/ -v -m security

test-coverage: ## 运行测试并生成覆盖率报告
	$(PYTHON) -m pytest tests/ --cov=. --cov-report=term-missing --cov-report=html --cov-report=xml

test-watch: ## 监听文件变化自动运行测试
	$(PYTHON) -m pytest-watch

## 代码质量
lint: ## 运行所有代码检查
	$(PYTHON) -m flake8 .
	$(PYTHON) -m black --check .
	$(PYTHON) -m isort --check-only .
	$(PYTHON) -m mypy .

lint-flake8: ## 运行flake8检查
	$(PYTHON) -m flake8 .

lint-black: ## 运行black检查
	$(PYTHON) -m black --check .

lint-isort: ## 运行isort检查
	$(PYTHON) -m isort --check-only .

lint-mypy: ## 运行mypy类型检查
	$(PYTHON) -m mypy .

lint-bandit: ## 运行bandit安全检查
	$(PYTHON) -m bandit -r . -c pyproject.toml

format: ## 格式化代码
	$(PYTHON) -m black .
	$(PYTHON) -m isort .

format-black: ## 用black格式化
	$(PYTHON) -m black .

format-isort: ## 用isort排序导入
	$(PYTHON) -m isort .

## 安全
security: ## 运行所有安全检查
	$(PYTHON) -m bandit -r .
	$(PIP) audit

security-bandit: ## 运行bandit安全扫描
	$(PYTHON) -m bandit -r . -f html -o security-report.html

security-audit: ## 运行依赖安全审计
	$(PIP) audit

security-safety: ## 运行safety安全检查
	safety check

## 运行
run: ## 启动API服务
	$(PYTHON) main.py api-server --host 127.0.0.1 --port 8000

run-dev: ## 以开发模式启动（自动重载）
	$(PYTHON) main.py api-server --host 127.0.0.1 --port 8000 --reload

run-debug: ## 以调试模式启动
	$(PYTHON) -m debugpy --listen 5678 --wait-for-client main.py api-server --host 127.0.0.1 --port 8000

run-cli: ## 启动CLI界面
	$(PYTHON) main.py cli

run-workbench: ## 启动工作台
	$(PYTHON) main.py workbench

## Docker
docker-build: ## 构建Docker镜像
	docker build -t $(DOCKER_IMAGE) .

docker-up: ## 启动Docker容器
	docker-compose up -d

docker-down: ## 停止Docker容器
	docker-compose down

docker-logs: ## 查看Docker日志
	docker-compose logs -f

docker-shell: ## 进入Docker容器
	docker-compose exec app bash

docker-clean: ## 清理Docker镜像和容器
	docker-compose down --rmi all --volumes --remove-orphans

## 文档
docs: ## 生成文档
	$(PYTHON) -m pdoc --html --output-dir docs/html .

docs-serve: ## 启动文档服务器
	$(PYTHON) -m pdoc --http :8080 .

## 构建
build: ## 构建包
	$(PYTHON) setup.py sdist bdist_wheel

build-check: ## 检查构建包
	twine check dist/*

publish: ## 发布到PyPI
	twine upload dist/*

publish-test: ## 发布到TestPyPI
	twine upload --repository testpypi dist/*

## 清理
clean: ## 清理临时文件
	find . -type d -name __pycache__ -exec rm -rf {} + 2>/dev/null || true
	find . -type f -name "*.pyc" -delete 2>/dev/null || true
	find . -type f -name "*.pyo" -delete 2>/dev/null || true
	find . -type d -name "*.egg-info" -exec rm -rf {} + 2>/dev/null || true
	find . -type d -name ".pytest_cache" -exec rm -rf {} + 2>/dev/null || true
	find . -type d -name ".mypy_cache" -exec rm -rf {} + 2>/dev/null || true
	rm -rf build/ dist/ htmlcov/ .coverage coverage.xml 2>/dev/null || true

clean-all: clean ## 深度清理（包括虚拟环境）
	rm -rf venv/ .venv/ env/ .env 2>/dev/null || true

## 版本
version: ## 显示版本信息
	@echo "$(PROJECT) v$(VERSION)"
	@echo "Python: $(shell $(PYTHON) --version)"
	@echo "Pip: $(shell $(PIP) --version)"

## 健康检查
health: ## 运行项目健康检查
	$(PYTHON) scripts/health_check_v2.py

## 预提交
pre-commit: ## 运行所有预提交钩子
	pre-commit run --all-files

pre-commit-update: ## 更新预提交钩子
	pre-commit autoupdate

## 数据库
db-init: ## 初始化数据库
	$(PYTHON) -c "from utils.database import init_database; init_database()"

db-migrate: ## 数据库迁移
	$(PYTHON) -m alembic upgrade head

db-migrate-create: ## 创建迁移文件
	$(PYTHON) -m alembic revision --autogenerate -m "$(msg)"

## 工具安装
install-tools: ## 安装安全工具
	$(PYTHON) scripts/install_tools.py

install-tools-kali: ## 在Kali Linux上安装工具
	sudo apt-get update && sudo apt-get install -y nmap nuclei sqlmap gobuster ffuf dirsearch hydra john nikto whatweb wpscan masscan

## 示例
examples: ## 运行示例
	@echo "示例脚本:"
	@ls -la examples/

## 所有检查
all: lint test security ## 运行所有检查（lint + test + security）

## CI/CD
ci: install-dev lint test-coverage security ## CI/CD流水线
