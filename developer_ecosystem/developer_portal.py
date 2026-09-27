# -*- coding: utf-8 -*-
"""
developer_portal.py — 开发者门户与插件市场（第24轮升级方向4 / 模块5）。

包含：
  - 开发者门户：首页 / 文档中心 / API参考 / SDK下载 / 示例代码 / 教程 / 最佳实践 / FAQ
  - 开发者注册：开发者账户 / API密钥 / 应用注册 / 权限申请 / 配额管理 / 用量统计 / 账单
  - 插件市场：插件列表 / 分类 / 搜索 / 详情 / 安装 / 评分 / 评论 / 版本
  - 插件开发SDK：插件框架 / API文档 / 示例插件 / 开发指南 / 调试工具 / 测试工具 / 发布流程
  - 插件审核：插件提交 / 审核 / 审核标准 / 安全扫描 / 质量检查 / 发布管理 / 下架管理
  - 开发者社区：论坛 / 问答 / 博客 / 教程 / 活动 / 比赛 / 贡献者 / 排行榜

全部内存字典模拟。
"""

from __future__ import annotations

import json
import uuid
from datetime import datetime
from typing import Any, Dict, List, Optional


# ==================== 开发者门户 ====================

class DeveloperPortal:
    """开发者门户主站"""

    def __init__(self):
        self.announcements: List[Dict[str, str]] = [
            {"title": "开发者生态 v24.4 正式发布", "date": "2026-09-15", "type": "release"},
            {"title": "API 限流策略调整公告", "date": "2026-09-10", "type": "notice"},
        ]
        self.featured_guides: List[Dict[str, str]] = [
            {"title": "快速入门：10分钟完成首次API调用", "category": "getting-started", "read_time": "5分钟"},
            {"title": "Webhook 事件订阅最佳实践", "category": "webhook", "read_time": "8分钟"},
            {"title": "插件开发实战：从零到上架", "category": "plugin-dev", "read_time": "20分钟"},
        ]

    def homepage(self) -> Dict[str, Any]:
        return {
            "title": "AI Hacking Agent 开发者门户",
            "subtitle": "构建安全生态，赋能开发者",
            "announcements": self.announcements,
            "featured_guides": self.featured_guides,
            "stats": {"developers": 12500, "apis": 50, "plugins": 89, "calls_per_day": 5000000},
            "quick_links": [
                {"label": "快速开始", "url": "/docs/quickstart"},
                {"label": "API 参考", "url": "/api-docs"},
                {"label": "SDK 下载", "url": "/sdk"},
                {"label": "插件市场", "url": "/marketplace"},
            ],
        }

    def docs_center(self, category: str = "") -> List[Dict[str, Any]]:
        docs = [
            {"id": "doc-001", "title": "快速开始指南", "category": "getting-started", "updated": "2026-09-01"},
            {"id": "doc-002", "title": "认证与授权", "category": "auth", "updated": "2026-08-20"},
            {"id": "doc-003", "title": "错误码参考", "category": "reference", "updated": "2026-09-10"},
            {"id": "doc-004", "title": "Webhook 配置", "category": "webhook", "updated": "2026-09-05"},
            {"id": "doc-005", "title": "插件开发指南", "category": "plugin-dev", "updated": "2026-09-12"},
        ]
        if category:
            docs = [d for d in docs if d["category"] == category]
        return docs

    def sdk_downloads(self) -> List[Dict[str, Any]]:
        return [
            {"language": "Python", "package": "aha-sdk", "version": "24.4.0", "install": "pip install aha-sdk"},
            {"language": "JavaScript", "package": "@aha/sdk", "version": "24.4.0", "install": "npm install @aha/sdk"},
            {"language": "Go", "package": "aha-go", "version": "24.4.0", "install": "go get github.com/aha/sdk-go"},
            {"language": "Java", "package": "com.aha:sdk", "version": "24.4.0", "install": "Maven/Gradle"},
            {"language": "CLI", "package": "aha-cli", "version": "24.4.0", "install": "下载二进制文件"},
        ]

    def faq(self) -> List[Dict[str, str]]:
        return [
            {"q": "如何注册开发者账户？", "a": "点击右上角注册，完成邮箱验证即可"},
            {"q": "API 调用限额是多少？", "a": "免费版 1000次/天，专业版 100万次/天"},
            {"q": "Webhook 签名验证失败？", "a": "检查密钥是否正确，时间戳偏差不超过5分钟"},
            {"q": "插件审核需要多久？", "a": "通常1-3个工作日"},
        ]


# ==================== 开发者注册与账户 ====================

class DeveloperAccount:
    """开发者账户管理"""

    def __init__(self):
        self.accounts: Dict[str, Dict[str, Any]] = {}
        self.api_keys: Dict[str, Dict[str, Any]] = {}
        self.applications: Dict[str, Dict[str, Any]] = {}
        self.usage_records: Dict[str, List[Dict[str, Any]]] = {}
        self.bills: Dict[str, List[Dict[str, Any]]] = {}

    def register(self, email: str, name: str, company: str = "") -> Dict[str, Any]:
        did = f"dev-{uuid.uuid4().hex[:8]}"
        self.accounts[did] = {
            "developer_id": did, "email": email, "name": name, "company": company,
            "plan": "free", "status": "active", "created_at": datetime.now().isoformat(timespec="seconds"),
            "permissions": ["read"],
        }
        # 自动生成默认 API Key
        key_id = f"key-{uuid.uuid4().hex[:8]}"
        self.api_keys[key_id] = {
            "key_id": key_id, "developer_id": did,
            "key": f"aha_{uuid.uuid4().hex}", "name": "default",
            "created_at": datetime.now().isoformat(timespec="seconds"),
            "last_used": "", "status": "active",
        }
        return {"developer": self.accounts[did], "api_key": self.api_keys[key_id]}

    def create_app(self, developer_id: str, app_name: str, description: str = "") -> Dict[str, Any]:
        app_id = f"app-{uuid.uuid4().hex[:8]}"
        self.applications[app_id] = {
            "app_id": app_id, "developer_id": developer_id,
            "name": app_name, "description": description,
            "status": "pending_review", "created_at": datetime.now().isoformat(timespec="seconds"),
            "permissions": ["api:read"],
        }
        return self.applications[app_id]

    def request_permission(self, developer_id: str, permission: str) -> Dict[str, Any]:
        if developer_id in self.accounts:
            perms = self.accounts[developer_id].get("permissions", [])
            if permission not in perms:
                perms.append(permission)
                self.accounts[developer_id]["permissions"] = perms
        return {"developer_id": developer_id, "granted": permission, "status": "approved"}

    def get_usage(self, developer_id: str, period: str = "30d") -> Dict[str, Any]:
        return {
            "developer_id": developer_id, "period": period,
            "total_calls": 12500, "successful": 12450, "failed": 50,
            "quota_limit": 30000, "quota_used_pct": 41.7,
            "by_endpoint": {"/api/v1/assets": 5000, "/api/v1/scans": 4500, "/api/v1/vulns": 3000},
        }

    def get_bill(self, developer_id: str, month: str = "") -> Dict[str, Any]:
        return {
            "developer_id": developer_id, "month": month or datetime.now().strftime("%Y-%m"),
            "amount": 0.0, "currency": "CNY",
            "items": [{"description": "API 调用费", "quantity": 12500, "unit_price": 0.0, "subtotal": 0.0}],
            "status": "unpaid",
        }

    def list_keys(self, developer_id: str) -> List[Dict[str, Any]]:
        return [k for k in self.api_keys.values() if k.get("developer_id") == developer_id]


# ==================== 插件市场 ====================

class MarketplacePlugin:
    """插件市场"""

    def __init__(self):
        self.plugins: Dict[str, Dict[str, Any]] = {
            "vuln-exporter": {
                "id": "vuln-exporter", "name": "漏洞报告导出器",
                "developer": "dev-001", "version": "2.3.0",
                "description": "一键导出漏洞报告为多种格式",
                "category": "productivity", "price": 0,
                "rating": 4.7, "downloads": 5600, "installs": 4200,
                "reviews": 128, "verified": True,
                "changelog": ["v2.3.0: 新增 CSV 导出", "v2.2.0: 修复 PDF 格式问题"],
                "created_at": "2026-03-01", "updated_at": "2026-09-10",
            },
            "auto-pentest": {
                "id": "auto-pentest", "name": "自动化渗透测试",
                "developer": "dev-002", "version": "1.0.0",
                "description": "AI 驱动的自动化渗透测试编排",
                "category": "security", "price": 99,
                "rating": 4.2, "downloads": 2300, "installs": 1800,
                "reviews": 45, "verified": True,
                "changelog": ["v1.0.0: 首个正式版本"],
                "created_at": "2026-08-01", "updated_at": "2026-09-01",
            },
            "asset-dashboard": {
                "id": "asset-dashboard", "name": "资产可视化面板",
                "developer": "dev-001", "version": "3.1.2",
                "description": "资产全景可视化与拓扑图",
                "category": "dashboard", "price": 0,
                "rating": 4.9, "downloads": 8900, "installs": 7200,
                "reviews": 256, "verified": True,
                "changelog": ["v3.1.2: 修复图表渲染", "v3.1.0: 新增拓扑视图"],
                "created_at": "2026-01-15", "updated_at": "2026-09-12",
            },
        }
        self.categories = ["security", "productivity", "dashboard", "reporting", "integration"]
        self.reviews: Dict[str, List[Dict[str, Any]]] = {}

    def list(self, category: str = "", search: str = "", sort: str = "downloads") -> List[Dict[str, Any]]:
        items = list(self.plugins.values())
        if category:
            items = [p for p in items if p["category"] == category]
        if search:
            s = search.lower()
            items = [p for p in items if s in p["name"].lower() or s in p["description"].lower()]
        reverse = sort in ("downloads", "rating")
        items.sort(key=lambda x: x.get(sort, 0), reverse=reverse)
        return items

    def detail(self, plugin_id: str) -> Dict[str, Any]:
        p = self.plugins.get(plugin_id)
        if p:
            return {**p, "reviews": self.reviews.get(plugin_id, [])}
        return {"error": "插件不存在", "id": plugin_id}

    def install(self, plugin_id: str) -> Dict[str, Any]:
        return {"installed": True, "plugin_id": plugin_id, "install_path": f"./plugins/{plugin_id}"}

    def rate(self, plugin_id: str, score: int, comment: str = "", user: str = "") -> Dict[str, Any]:
        review = {
            "user": user or "anonymous", "score": score, "comment": comment,
            "created_at": datetime.now().isoformat(timespec="seconds"),
        }
        if plugin_id not in self.reviews:
            self.reviews[plugin_id] = []
        self.reviews[plugin_id].insert(0, review)
        return {"rated": True, "plugin_id": plugin_id, "review": review}

    def versions(self, plugin_id: str) -> List[Dict[str, Any]]:
        return [
            {"version": "2.3.0", "date": "2026-09-10", "stable": True},
            {"version": "2.2.0", "date": "2026-08-01", "stable": True},
            {"version": "2.1.0", "date": "2026-07-01", "stable": False},
        ]


# ==================== 插件开发 SDK ====================

class PluginDevSDK:
    """插件开发 SDK"""

    def __init__(self):
        self.framework_docs = {
            "overview": "基于 AHA Plugin Framework v3 构建",
            "entry_point": "plugin.py:PluginMain",
            "manifest": "plugin.json (名称/版本/权限/入口)",
        }

    def get_framework(self) -> Dict[str, Any]:
        return {
            "name": "AHA Plugin Framework",
            "version": "3.0.0",
            "language": "Python 3.8+",
            "features": ["事件系统", "Hook 机制", "UI 扩展", "数据存储", "权限系统"],
            "entry_template": self._entry_template(),
        }

    def _entry_template(self) -> str:
        return '''# -*- coding: utf-8 -*-
"""示例插件入口"""
from aha_plugin import PluginBase, hook

class MyPlugin(PluginBase):
    name = "my-plugin"
    version = "1.0.0"

    @hook("scan.completed")
    def on_scan_complete(self, context):
        print(f"扫描完成: {context['scan_id']}")

    def on_enable(self):
        print("插件已启用")

    def on_disable(self):
        print("插件已禁用")
'''

    def get_examples(self) -> List[Dict[str, str]]:
        return [
            {"name": "Hello World", "description": "最简单的插件示例", "difficulty": "beginner"},
            {"name": "Webhook Receiver", "description": "接收平台事件推送", "difficulty": "intermediate"},
            {"name": "Custom Report Generator", "description": "自定义报告模板", "difficulty": "advanced"},
        ]

    def debug_tools(self) -> Dict[str, List[str]]:
        return {
            "dev_server": ["aha plugin dev", "--hot-reload", "--port=9000"],
            "debug_logs": ["aha plugin logs", "--follow"],
            "test_framework": ["aha plugin test", "--coverage"],
            "package": ["aha plugin package", "--output=./dist"],
        }

    def release_flow(self) -> List[Dict[str, str]]:
        return [
            {"step": "1", "name": "开发", "desc": "使用插件框架开发功能"},
            {"step": "2", "name": "测试", "desc": "运行单元测试和集成测试"},
            {"step": "3", "name": "打包", "desc": "构建插件包 plugin.aha-plugin"},
            {"step": "4", "name": "提交审核", "desc": "提交到插件市场审核"},
            {"step": "5", "name": "发布", "desc": "审核通过后自动发布"},
        ]


# ==================== 插件审核 ====================

class PluginReview:
    """插件审核流程"""

    STANDARDS: List[Dict[str, str]] = [
        {"id": "SEC-01", "category": "安全", "rule": "不得包含恶意代码", "severity": "block"},
        {"id": "SEC-02", "category": "安全", "rule": "不得收集用户敏感数据", "severity": "block"},
        {"id": "SEC-03", "category": "安全", "rule": "网络请求必须使用 HTTPS", "severity": "warn"},
        {"id": "QLT-01", "category": "质量", "rule": "必须包含 README", "severity": "warn"},
        {"id": "QLT-02", "category": "质量", "rule": "代码注释覆盖率 > 30%", "severity": "info"},
        {"id": "QLT-03", "category": "质量", "rule": "必须通过单元测试", "severity": "block"},
    ]

    def __init__(self):
        self.submissions: Dict[str, Dict[str, Any]] = {}

    def submit(self, developer_id: str, plugin_id: str, version: str, package_path: str) -> Dict[str, Any]:
        sid = f"rev-{uuid.uuid4().hex[:8]}"
        self.submissions[sid] = {
            "submission_id": sid, "developer_id": developer_id,
            "plugin_id": plugin_id, "version": version,
            "package_path": package_path, "status": "pending",
            "submitted_at": datetime.now().isoformat(timespec="seconds"),
            "reviewer": "", "report": None,
        }
        return self.submissions[sid]

    def review(self, submission_id: str, action: str = "approve") -> Dict[str, Any]:
        if submission_id in self.submissions:
            self.submissions[submission_id]["status"] = "approved" if action == "approve" else "rejected"
            self.submissions[submission_id]["reviewed_at"] = datetime.now().isoformat(timespec="seconds")
            self.submissions[submission_id]["report"] = {
                "security_scan": "passed", "quality_check": "passed",
                "issues_found": 0, "recommendation": "approve",
            }
        return self.submissions.get(submission_id, {"error": "审核单不存在"})

    def get_standards(self) -> List[Dict[str, str]]:
        return self.STANDARDS

    def list_submissions(self, status: str = "") -> List[Dict[str, Any]]:
        items = list(self.submissions.values())
        if status:
            items = [s for s in items if s["status"] == status]
        return items


# ==================== 开发者社区 ====================

class DeveloperCommunity:
    """开发者社区"""

    def __init__(self):
        self.posts: List[Dict[str, Any]] = [
            {"id": "p-001", "title": "如何优化扫描性能？", "author": "sec_master", "category": "qa",
             "replies": 12, "views": 456, "created_at": "2026-09-10"},
            {"id": "p-002", "title": "分享：我的自动化报告工作流", "author": "dev_ops", "category": "blog",
             "replies": 8, "views": 1200, "created_at": "2026-09-08"},
        ]
        self.events: List[Dict[str, str]] = [
            {"id": "e-001", "name": "AI 安全创新大赛 2026", "date": "2026-10-01", "prize": "10万元"},
            {"id": "e-002", "name": "线上分享：SDK 最佳实践", "date": "2026-09-20", "prize": ""},
        ]
        self.contributors: List[Dict[str, Any]] = [
            {"rank": 1, "name": "core_dev", "contributions": 1520, "badges": ["MVP", "Bug Hunter"]},
            {"rank": 2, "name": "plugin_author", "contributions": 890, "badges": ["Top Plugin Dev"]},
            {"rank": 3, "name": "docs_writer", "contributions": 560, "badges": ["Documentation"]},
        ]

    def forum_posts(self, category: str = "") -> List[Dict[str, Any]]:
        if category:
            return [p for p in self.posts if p["category"] == category]
        return self.posts

    def events_list(self) -> List[Dict[str, str]]:
        return self.events

    def leaderboard(self, period: str = "monthly") -> List[Dict[str, Any]]:
        return self.contributors

    def ask(self, title: str, content: str, author: str = "") -> Dict[str, Any]:
        post = {
            "id": f"p-{uuid.uuid4().hex[:8]}", "title": title, "content": content,
            "author": author or "anonymous", "category": "qa",
            "replies": 0, "views": 0, "created_at": datetime.now().isoformat(timespec="seconds"),
        }
        self.posts.insert(0, post)
        return post


# ==================== 单例 ====================

portal = DeveloperPortal()
dev_account = DeveloperAccount()
marketplace = MarketplacePlugin()
plugin_dev_sdk = PluginDevSDK()
plugin_review = PluginReview()
community = DeveloperCommunity()

__all__ = [
    "DeveloperPortal", "DeveloperAccount", "MarketplacePlugin",
    "PluginDevSDK", "PluginReview", "DeveloperCommunity",
    "portal", "dev_account", "marketplace",
    "plugin_dev_sdk", "plugin_review", "community",
]
