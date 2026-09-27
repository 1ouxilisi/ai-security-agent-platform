# 🛡️ SecurityAI Platform

> **AI 驱动的攻防兼备安全评估平台**
> 一次部署，覆盖 20 大安全领域。AI 自动扫描、验证、评级、修复——安全团队只需审核结果。

[![Version](https://img.shields.io/badge/version-1.0.0-blue.svg)]()
[![Docker](https://img.shields.io/badge/docker-ready-blue.svg)]()
[![Kubernetes](https://img.shields.io/badge/kubernetes-ready-blue.svg)]()
[![License](https://img.shields.io/badge/license-Commercial-red.svg)]()

---

## ✨ 核心特性

- 🤖 **AI 多 Agent 协作** — 模拟渗透测试团队，自动完成侦察→扫描→验证→报告全流程
- 🌐 **20 大安全领域** — Web/网络/主机/移动/区块链/AI/云/IoT/ICS...一次全覆盖
- 🎯 **自动漏洞验证** — AI 二次验证消除 80% 误报，安全人员只看真问题
- 🔧 **代码级修复建议** — 不仅说"有漏洞"，直接给出修复后的代码
- 🛡️ **攻防一体** — 不仅发现问题，还实时监测入侵 (IDS) 和主动狩猎威胁
- 📊 **智能风险评级** — 结合业务上下文评估真实风险，而非机械套用 CVSS
- 📋 **合规一键达标** — 内置等保 2.0 / CIS Benchmarks / ISO 27001 基线检查
- 🏢 **企业级架构** — 多租户 / RBAC / SSO / 审计日志 / API 网关
- 🐳 **私有化部署** — Docker Compose / Kubernetes，数据不出内网
- 📈 **漏洞全生命周期** — 发现→验证→修复→复测闭环管理
- 🔔 **实时告警** — 钉钉/企业微信/邮件/Webhook 多渠道推送
- 📦 **极低 TCO** — 年付万元级，替代传统数十万的安全工具组合

---

## 🚀 快速开始 (3 步启动)

### 第 1 步: Docker Compose 启动

```bash
# 克隆项目
git clone https://github.com/your-org/security-ai-platform.git
cd security-ai-platform

# 配置环境变量
cp .env.example .env
# 编辑 .env，填入 LLM_API_KEY 等必要配置

# 启动全部服务
docker compose up -d
```

### 第 2 步: 访问控制台

打开浏览器访问: `https://your-server-ip`

- 默认管理员账号: `admin`
- 默认密码: 在 `.env` 中的 `DEFAULT_ADMIN_PASSWORD` (**首次登录后立即修改!**)

### 第 3 步: 创建首次安全评估

1. 登录控制台 → 「安全评估」→「新建扫描」
2. 输入目标域名或 IP (确保已获授权)
3. 选择「快速扫描」模板
4. 等待 AI 引擎完成分析 (通常 5-15 分钟)
5. 查看 AI 生成的安全报告

---

## 🖥️ 功能模块概览

> 以下为各模块界面描述 (截图待补充)

### 📊 Dashboard 总览
- 安全态势总览仪表盘: 漏洞统计 / 风险分布 / 最近活动 / 趋势图
- 资产健康度评分 / 待处理任务提醒

### 🎯 安全评估中心
- 资产清单管理 (自动发现 + 手动录入)
- 扫描任务创建 / 执行 / 历史记录
- AI 分析结果展示: 漏洞列表 + 风险评级 + 修复建议

### 🛡️ 防御监测中心
- IDS 实时告警面板
- 攻击事件时间线
- 威胁狩猎结果展示

### 📋 报告中心
- 自动生成 HTML/PDF 报告
- 管理层摘要 (非技术语言)
- 技术详细报告 (代码级)
- 合规报告 (等保/CIS/ISO)

### ⚙️ 系统管理
- 用户与角色管理 (RBAC)
- 扫描配置 / 策略模板
- 通知渠道配置
- 系统日志 / 审计日志

---

## 📦 部署方式对比

| 特性 | Docker Compose | Kubernetes | 源码部署 |
|------|---------------|------------|---------|
| 适用场景 | 单机/中小团队 | 大规模/高可用 | 开发/测试 |
| 部署难度 | ⭐ 极简 | ⭐⭐ 中等 | ⭐⭐⭐ 较高 |
| 高可用 | ✗ | ✓ (多副本) | 取决于部署 |
| 弹性伸缩 | ✗ | ✓ (HPA) | ✗ |
| 资源需求 | 8GB RAM | 16GB+ RAM | 4GB+ RAM |
| 推荐用户 | Pro 版 | Enterprise 版 | 开发者 |

**Docker Compose 部署:**
```bash
docker compose up -d --build
```

**Kubernetes 部署:**
```bash
kubectl apply -f deploy/kubernetes/
```

**源码部署:**
```bash
pip install -r requirements.txt
uvicorn api_server.app:app --host 0.0.0.0 --port 8000
```

---

## 💰 定价计划

| 版本 | 价格 | 适合 |
|------|------|------|
| **Free** | 0 元/月 | 个人测试 |
| **Pro** | 999 元/月 | 中小企业 |
| **Enterprise** | 9999 元/年起 | 大型企业/私有化 |

👉 [查看完整定价方案 →](docs/PRICING.md)

---

## 📚 文档导航

| 文档 | 说明 |
|------|------|
| [🏗️ 企业级部署手册](INSTALL_ENTERPRISE.md) | 完整私有化部署指南 (含 K8s/备份/灾备/监控) |
| [📖 产品白皮书](docs/WHITEPAPER.md) | 技术架构与核心能力详解 |
| [💳 定价方案](docs/PRICING.md) | 三版本功能对比与购买流程 |
| [📂 应用案例](docs/USE_CASES.md) | 5 个真实行业应用案例 |
| [⚖️ 竞品对比](docs/COMPARISON.md) | 与 Nessus/Burp/开源工具对比 |
| [🔧 API 文档](API_DOCUMENTATION.md) | REST API 接口文档 |
| [🏗️ 架构设计](ARCHITECTURE.md) | 系统架构与模块设计 |

---

## 🏢 应用案例

- 🏭 **制造业:** 500 人企业季度安全评估，发现 23 个漏洞，修复周期从月级缩短到周级
- 🏦 **金融行业:** 手机银行 APP 自动化安全审计，检测项 120+，审计周期从 3 周缩短到 2 天
- ₿ **区块链:** DeFi 智能合约审计，发现重入/权限漏洞，成本仅为传统审计的 5%
- 🤖 **AI 安全:** AI 客服系统安全评估，发现 Prompt 注入/数据泄露风险
- 🛡️ **护网行动:** 国企 HW 行动支撑，拦截 47000+ 次攻击，发现 1 起潜伏入侵

👉 [查看完整案例 →](docs/USE_CASES.md)

---

## 🛠️ 技术栈

| 层 | 技术 |
|----|------|
| 后端框架 | FastAPI (Python 3.12) |
| WSGI/ASGI | Gunicorn + Uvicorn Workers |
| 数据库 | PostgreSQL 16 |
| 缓存/队列 | Redis 7 |
| AI 引擎 | 多 Agent 架构 + 兼容 OpenAI API 的 LLM |
| 反向代理 | Nginx 1.25 (SSL/限流/安全头) |
| 容器化 | Docker + Docker Compose / Kubernetes |
| 前端 | HTML5 / JavaScript / Bootstrap |
| 安全扫描引擎 | Nmap / Nuclei / SQLMap / 自定义检测规则 |

---

## 💻 系统要求

| 资源 | 最低 | 推荐 |
|------|------|------|
| OS | Ubuntu 22.04 LTS | Ubuntu 22.04 LTS |
| CPU | 4 核 | 8 核+ |
| 内存 | 8 GB | 16 GB+ |
| 磁盘 | 100 GB SSD | 500 GB SSD |
| Docker | 20.10+ | 24.0+ |
| 网络 | 100 Mbps | 1 Gbps |

---

## ❓ 常见问题

**Q: 没有安全团队能使用吗?**

A: 完全可以。平台设计为"AI 安全助手"，AI 引擎自动分析结果并用通俗语言解释风险。你只需要告诉平台扫描什么目标，它会告诉你发现了什么问题、有多严重、怎么修。

**Q: 扫描会影响业务吗?**

A: 默认使用低速率模式 (5-20 请求/秒)，对业务影响极小。建议在低峰期执行完整扫描。Pro 版以上支持自定义扫描速率。

**Q: 支持私有化部署吗? 数据安全吗?**

A: Enterprise 版支持完全私有化部署，数据 100% 在内网。传输全程 TLS 1.3 加密，敏感数据 AES-256 存储。平台不收集任何扫描数据。

**Q: 需要自己有大模型 API Key 吗?**

A: Free 版和 Pro 版可使用平台内置 LLM 额度。私有化部署时建议接入企业自有大模型服务 (兼容 OpenAI API 格式即可)。

**Q: 如何升级到新版本?**

A: 私有化部署执行 `git pull && docker compose up -d --build`。SaaS 版自动更新，无需操作。详细步骤见 [部署手册](INSTALL_ENTERPRISE.md)。

---

## 📞 联系方式

- 📧 **销售咨询:** sales@securityai-platform.com
- 📧 **技术支持:** support@securityai-platform.com
- 🌐 **官网:** https://www.securityai-platform.com
- 📱 **微信公众号:** SecurityAI安全平台
- 📞 **电话:** 400-XXX-XXXX (工作日 9:00-18:00)

---

## 📄 许可证

本软件为商业软件，受版权法保护。未经授权不得复制、修改、分发。
详细许可证条款见 [LICENSE](LICENSE) 文件。

---

## 📝 更新日志

查看 [CHANGELOG.md](CHANGELOG.md) 获取完整版本历史。

当前版本: **v1.0.0** (2026-09)
- ✅ 20 大安全领域覆盖
- ✅ AI 多 Agent 协作评估引擎
- ✅ Docker Compose / Kubernetes 部署
- ✅ Nginx 反向代理 + SSL + 限流
- ✅ PostgreSQL + Redis 生产级数据层
- ✅ 完整企业级部署文档

---

<div align="center">

**SecurityAI Platform** — 让 AI 成为你的安全团队

</div>
