#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
ux_docs_deep — 第28轮升级方向4：文档完善与用户体验优化。

包含 7 大核心模块：
    - user_manual          用户手册管理（快速开始/基础教程/进阶教程/场景教程/故障排查/参考手册）
    - deployment_docs      部署文档管理（部署指南/安装部署/配置指南/升级指南/运维指南/高可用部署）
    - api_docs             API文档管理（接口文档/认证授权/SDK文档/最佳实践）
    - frontend_ux          前端交互优化（界面/交互/响应式/性能/可访问性/国际化）
    - onboarding_tutorials 新手引导与教程（引导流程/交互式教程/视频教程/实验环境/学习路径/帮助中心）
    - docs_management      文档管理系统（文档CRUD/版本/权限/协作/分析）
    - ux_docs_dashboard    文档与UX控制台数据聚合层

设计定位：全部内存字典模拟，不建数据库表，不依赖外部服务。
"""

from __future__ import annotations

__version__ = "28.4.0"
__all__ = [
    "user_manual",
    "deployment_docs",
    "api_docs",
    "frontend_ux",
    "onboarding_tutorials",
    "docs_management",
    "ux_docs_dashboard",
]
