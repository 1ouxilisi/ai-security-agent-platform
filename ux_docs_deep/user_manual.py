#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
ux_docs_deep/user_manual.py — 用户手册管理。

覆盖六大分册：
    1. 快速开始：环境要求/快速安装/配置初始化/首次启动/验证安装/常见问题
    2. 基础教程：界面介绍/功能导航/基本操作/常用功能/快捷操作/最佳实践/新手引导
    3. 进阶教程：高级功能/自定义配置/工作流/自动化/集成/扩展/插件开发/API使用
    4. 场景教程：渗透测试/漏洞扫描/合规审计/红蓝对抗/SOC运营/DevSecOps/安全培训
    5. 故障排查：常见错误/错误代码/排查步骤/解决方案/日志分析/调试技巧/支持渠道
    6. 参考手册：功能参考/配置参考/API参考/命令参考/快捷键参考/术语表/更新日志
"""

from __future__ import annotations

import time
import uuid
from typing import Any, Dict, List, Optional


# --------------------------------------------------------------------------- #
# 手册分册定义
# --------------------------------------------------------------------------- #
MANUAL_SECTIONS: Dict[str, Dict[str, Any]] = {
    "quick_start": {
        "name": "快速开始",
        "order": 1,
        "chapters": [
            {"id": "qs_env", "title": "环境要求", "topics": ["硬件要求", "操作系统", "Python版本", "依赖软件"]},
            {"id": "qs_install", "title": "快速安装", "topics": ["Windows安装", "Linux安装", "macOS安装", "Docker一键部署"]},
            {"id": "qs_config", "title": "配置初始化", "topics": ["配置文件", "环境变量", "密钥配置", "数据库初始化"]},
            {"id": "qs_start", "title": "首次启动", "topics": ["启动服务", "登录控制台", "初始向导", "默认账号"]},
            {"id": "qs_verify", "title": "验证安装", "topics": ["健康检查", "功能自检", "冒烟测试", "日志确认"]},
            {"id": "qs_faq", "title": "常见问题", "topics": ["端口占用", "权限错误", "依赖缺失", "启动失败"]},
        ],
    },
    "basic_tutorial": {
        "name": "基础教程",
        "order": 2,
        "chapters": [
            {"id": "bt_ui", "title": "界面介绍", "topics": ["控制台布局", "导航菜单", "状态栏", "主题切换"]},
            {"id": "bt_nav", "title": "功能导航", "topics": ["模块入口", "搜索", "书签", "最近访问"]},
            {"id": "bt_ops", "title": "基本操作", "topics": ["创建任务", "查看结果", "导出报告", "删除记录"]},
            {"id": "bt_common", "title": "常用功能", "topics": ["资产录入", "扫描配置", "漏洞管理", "报告生成"]},
            {"id": "bt_shortcut", "title": "快捷操作", "topics": ["快捷键", "批量操作", "右键菜单", "拖拽"]},
            {"id": "bt_best", "title": "最佳实践", "topics": ["任务编排", "权限分配", "周期执行", "通知配置"]},
            {"id": "bt_onboard", "title": "新手引导", "topics": ["首次向导", "功能介绍", "示例数据", "操作演示"]},
        ],
    },
    "advanced_tutorial": {
        "name": "进阶教程",
        "order": 3,
        "chapters": [
            {"id": "at_advanced", "title": "高级功能", "topics": ["自动化编排", "自定义规则", "智能分析", "报告模板"]},
            {"id": "at_custom", "title": "自定义配置", "topics": ["配置文件", "环境变量", "主题定制", "白标"]},
            {"id": "at_workflow", "title": "工作流", "topics": ["流程设计", "节点配置", "条件分支", "错误处理"]},
            {"id": "at_auto", "title": "自动化", "topics": ["定时任务", "Webhook", "事件触发", "链式执行"]},
            {"id": "at_integration", "title": "集成", "topics": ["SIEM集成", "Jira集成", "钉钉/企业微信", "LDAP/SSO"]},
            {"id": "at_extend", "title": "扩展", "topics": ["插件机制", "模块扩展", "自定义工具", "市场"]},
            {"id": "at_plugin", "title": "插件开发", "topics": ["插件骨架", "钩子函数", "打包发布", "调试"]},
            {"id": "at_api", "title": "API使用", "topics": ["认证", "SDK", "限流", "错误码"]},
        ],
    },
    "scenario_tutorial": {
        "name": "场景教程",
        "order": 4,
        "chapters": [
            {"id": "sc_pentest", "title": "渗透测试场景", "topics": ["信息收集", "漏洞利用", "后渗透", "报告"]},
            {"id": "sc_scan", "title": "漏洞扫描场景", "topics": ["资产扫描", "Web扫描", "主机扫描", "移动扫描"]},
            {"id": "sc_audit", "title": "合规审计场景", "topics": ["等保2.0", "PCI-DSS", "ISO27001", "GDPR"]},
            {"id": "sc_blue_red", "title": "红蓝对抗场景", "topics": ["红队行动", "蓝队检测", "复盘报告", "改进项"]},
            {"id": "sc_soc", "title": "SOC运营场景", "topics": ["告警分诊", "事件响应", "威胁狩猎", "报表"]},
            {"id": "sc_devsecops", "title": "DevSecOps场景", "topics": ["CI/CD集成", "代码扫描", "镜像扫描", "门禁"]},
            {"id": "sc_training", "title": "安全培训场景", "topics": ["课程编排", "靶场练习", "考核认证", "培训报告"]},
        ],
    },
    "troubleshooting": {
        "name": "故障排查",
        "order": 5,
        "chapters": [
            {"id": "tr_common", "title": "常见错误", "topics": ["连接失败", "权限拒绝", "超时", "5xx错误"]},
            {"id": "tr_code", "title": "错误代码", "topics": ["HTTP错误码", "业务错误码", "工具错误码", "SDK错误码"]},
            {"id": "tr_steps", "title": "排查步骤", "topics": ["定位问题", "复现问题", "收集日志", "上报问题"]},
            {"id": "tr_solution", "title": "解决方案", "topics": ["配置修复", "依赖修复", "网络修复", "版本回滚"]},
            {"id": "tr_log", "title": "日志分析", "topics": ["日志级别", "关键日志", "过滤技巧", "日志归档"]},
            {"id": "tr_debug", "title": "调试技巧", "topics": ["调试模式", "断点", "抓包", "性能剖析"]},
            {"id": "tr_support", "title": "支持渠道", "topics": ["工单", "社区", "邮件", "电话", "在线客服"]},
        ],
    },
    "reference": {
        "name": "参考手册",
        "order": 6,
        "chapters": [
            {"id": "rf_func", "title": "功能参考", "topics": ["功能清单", "功能对比", "模块依赖", "版本差异"]},
            {"id": "rf_config", "title": "配置参考", "topics": ["配置项列表", "默认值", "取值范围", "示例"]},
            {"id": "rf_api", "title": "API参考", "topics": ["接口列表", "参数说明", "响应格式", "错误码"]},
            {"id": "rf_cmd", "title": "命令参考", "topics": ["CLI命令", "子命令", "参数", "示例"]},
            {"id": "rf_shortcut", "title": "快捷键参考", "topics": ["全局快捷键", "编辑器快捷键", "表格快捷键", "导航快捷键"]},
            {"id": "rf_glossary", "title": "术语表", "topics": ["安全术语", "产品术语", "行业术语", "缩写"]},
            {"id": "rf_changelog", "title": "更新日志", "topics": ["版本历史", "新增功能", "破坏性变更", "废弃项"]},
        ],
    },
}


# --------------------------------------------------------------------------- #
# 单篇文章对象
# --------------------------------------------------------------------------- #
class ManualArticle:
    """用户手册文章对象。"""

    def __init__(self, section: str, chapter: str, title: str, content: str = "",
                 author: str = "doc-bot", tags: Optional[List[str]] = None) -> None:
        self.id = f"ma_{uuid.uuid4().hex[:10]}"
        self.section = section
        self.chapter = chapter
        self.title = title
        self.content = content
        self.author = author
        self.tags: List[str] = tags or []
        self.created_at = time.strftime("%Y-%m-%d %H:%M:%S")
        self.updated_at = self.created_at
        self.version = 1
        self.status = "published"  # draft / published / archived
        self.views = 0
        self.likes = 0

    def to_dict(self) -> Dict[str, Any]:
        return {
            "id": self.id, "section": self.section, "chapter": self.chapter,
            "title": self.title, "content": self.content, "author": self.author,
            "tags": self.tags, "created_at": self.created_at,
            "updated_at": self.updated_at, "version": self.version,
            "status": self.status, "views": self.views, "likes": self.likes,
        }


# --------------------------------------------------------------------------- #
# 用户手册管理器
# --------------------------------------------------------------------------- #
class UserManualManager:
    """用户手册内容管理器（内存字典模拟）。"""

    def __init__(self) -> None:
        self.articles: Dict[str, ManualArticle] = {}
        self._seed_default_articles()

    def _seed_default_articles(self) -> None:
        """预置演示文章。"""
        seeds = [
            ("quick_start", "qs_install", "Windows一键安装指南",
             "下载安装包 -> 双击 setup.exe -> 按向导下一步 -> 启动服务 -> 浏览器访问 http://localhost:8000",
             ["安装", "Windows"]),
            ("quick_start", "qs_verify", "安装验证三步法",
             "1) 访问 /health 返回 200  2) 执行 cli doctor  3) 查看控制台登录页",
             ["验证", "健康检查"]),
            ("basic_tutorial", "bt_ui", "控制台界面导览",
             "顶部导航 / 左侧菜单 / 主内容区 / 右侧详情栏，四区布局，支持折叠。",
             ["界面", "入门"]),
            ("advanced_tutorial", "at_api", "API快速调用示例",
             "curl -H 'Authorization: Bearer <TOKEN>' https://host/api/v1/...",
             ["API", "开发者"]),
            ("scenario_tutorial", "sc_pentest", "一次完整渗透测试演练",
             "信息收集 -> 漏洞发现 -> 利用验证 -> 后渗透 -> 报告归档",
             ["渗透测试", "实战"]),
            ("troubleshooting", "tr_log", "如何读懂错误日志",
             "按 ERROR/WARN/INFO 级别过滤，定位 traceback 第一行，对照错误码表。",
             ["日志", "排错"]),
            ("reference", "rf_glossary", "常用安全术语速查",
             "CVE/EDR/XDR/SOAR/DevSecOps/零信任/纵深防御/最小权限",
             ["术语", "速查"]),
        ]
        for sec, chap, title, content, tags in seeds:
            a = ManualArticle(sec, chap, title, content, tags=tags)
            self.articles[a.id] = a

    # ---- CRUD ----
    def create_article(self, section: str, chapter: str, title: str,
                       content: str = "", author: str = "doc-bot",
                       tags: Optional[List[str]] = None) -> Dict[str, Any]:
        if section not in MANUAL_SECTIONS:
            raise ValueError(f"未知分册: {section}，可选: {list(MANUAL_SECTIONS.keys())}")
        a = ManualArticle(section, chapter, title, content, author, tags)
        self.articles[a.id] = a
        return a.to_dict()

    def get_article(self, article_id: str) -> Optional[Dict[str, Any]]:
        a = self.articles.get(article_id)
        if a is None:
            return None
        a.views += 1
        return a.to_dict()

    def update_article(self, article_id: str, **fields: Any) -> Optional[Dict[str, Any]]:
        a = self.articles.get(article_id)
        if a is None:
            return None
        for k in ("title", "content", "author", "status", "tags"):
            if k in fields and fields[k] is not None:
                setattr(a, k, fields[k])
        a.version += 1
        a.updated_at = time.strftime("%Y-%m-%d %H:%M:%S")
        return a.to_dict()

    def delete_article(self, article_id: str) -> bool:
        if article_id in self.articles:
            del self.articles[article_id]
            return True
        return False

    def list_articles(self, section: Optional[str] = None,
                      chapter: Optional[str] = None,
                      status: Optional[str] = None,
                      keyword: Optional[str] = None) -> List[Dict[str, Any]]:
        items = list(self.articles.values())
        if section:
            items = [a for a in items if a.section == section]
        if chapter:
            items = [a for a in items if a.chapter == chapter]
        if status:
            items = [a for a in items if a.status == status]
        if keyword:
            kw = keyword.lower()
            items = [a for a in items
                     if kw in a.title.lower() or kw in a.content.lower()]
        return [a.to_dict() for a in items]

    def like_article(self, article_id: str) -> Optional[Dict[str, Any]]:
        a = self.articles.get(article_id)
        if a is None:
            return None
        a.likes += 1
        return a.to_dict()

    # ---- 结构 ----
    def list_sections(self) -> List[Dict[str, Any]]:
        return [
            {"key": k, **v, "article_count": len([
                a for a in self.articles.values() if a.section == k])}
            for k, v in MANUAL_SECTIONS.items()
        ]

    def get_chapters(self, section: str) -> List[Dict[str, Any]]:
        sec = MANUAL_SECTIONS.get(section)
        if not sec:
            return []
        return sec.get("chapters", [])

    # ---- 统计 ----
    def stats(self) -> Dict[str, Any]:
        items = list(self.articles.values())
        by_section: Dict[str, int] = {}
        for a in items:
            by_section[a.section] = by_section.get(a.section, 0) + 1
        return {
            "total_articles": len(items),
            "by_section": by_section,
            "total_views": sum(a.views for a in items),
            "total_likes": sum(a.likes for a in items),
            "published": len([a for a in items if a.status == "published"]),
            "draft": len([a for a in items if a.status == "draft"]),
        }


# --------------------------------------------------------------------------- #
# 单例
# --------------------------------------------------------------------------- #
_manager: Optional[UserManualManager] = None


def get_user_manual_manager() -> UserManualManager:
    global _manager
    if _manager is None:
        _manager = UserManualManager()
    return _manager
