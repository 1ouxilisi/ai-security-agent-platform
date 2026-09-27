# -*- coding: utf-8 -*-
"""portal_workflow.py — 开发者中心综合工作流。

串联：注册 → 创建应用 → 获取密钥 → 阅读文档 → 沙箱测试 → 正式调用 → 用量监控 → 社区支持。
"""

from __future__ import annotations

import time
from typing import Any, Dict, List, Optional

from .api_docs import get_docs_center
from .sdk_tools import get_sdk_manager
from .sandbox_manager import get_sandbox_manager
from .app_key_manager import get_app_key_manager
from .usage_billing import get_usage_billing
from .community_support import get_community


WORKFLOW_STEPS: List[Dict[str, Any]] = [
    {"step": 1, "key": "register", "name": "注册开发者账号",
     "desc": "使用邮箱/手机号注册，完成邮箱验证"},
    {"step": 2, "key": "create_app", "name": "创建应用",
     "desc": "填写应用名称、描述、所需权限范围"},
    {"step": 3, "key": "get_key", "name": "获取 API Key",
     "desc": "为应用生成 API Key，并妥善保管"},
    {"step": 4, "key": "read_docs", "name": "阅读文档",
     "desc": "浏览 OpenAPI 规范、错误码、示例代码"},
    {"step": 5, "key": "sandbox_test", "name": "沙箱测试",
     "desc": "在沙箱中使用测试 Key 调试接口"},
    {"step": 6, "key": "prod_call", "name": "正式调用",
     "desc": "切换生产 Key，开始真实调用"},
    {"step": 7, "key": "monitor_usage", "name": "用量监控",
     "desc": "关注配额、账单与告警"},
    {"step": 8, "key": "community", "name": "社区支持",
     "desc": "参与论坛、问答、贡献者计划"},
]


class DeveloperPortalWorkflow:
    """开发者中心综合工作流编排。"""

    def __init__(self) -> None:
        self.docs = get_docs_center()
        self.sdk = get_sdk_manager()
        self.sandbox = get_sandbox_manager()
        self.keys = get_app_key_manager()
        self.billing = get_usage_billing()
        self.community = get_community()
        # developer_id -> 进度
        self.progress: Dict[str, Dict[str, Any]] = {}

    def steps(self) -> List[Dict[str, Any]]:
        return WORKFLOW_STEPS

    # ------------------------------------------------------------------ #
    # 一站式：注册 -> 应用 -> Key -> 沙箱
    # ------------------------------------------------------------------ #
    def onboard(self, developer: str, app_name: str,
                scopes: Optional[List[str]] = None) -> Dict[str, Any]:
        # 1) 注册社区成员
        member = self.community.register_member(developer)
        # 2) 创建应用
        app = self.keys.register_app(
            name=app_name, owner=developer,
            description=f"onboarded via workflow by {developer}",
            scopes=scopes or ["scanner:read"],
        )
        # 3) 自动审核通过（演示）
        self.keys.review_app(app["app_id"], approved=True, note="auto-approved by workflow")
        # 4) 生成 Key
        key = self.keys.create_key(app["app_id"], name="default")
        # 5) 开通免费套餐
        self.billing.subscribe(app["app_id"], "free")
        # 6) 创建沙箱
        sb = self.sandbox.create(owner=developer, name=f"{app_name}-sandbox")
        # 7) 记录进度
        self.progress[developer] = {
            "developer": developer,
            "current_step": 5,
            "completed_steps": ["register", "create_app", "get_key", "read_docs"],
            "app_id": app["app_id"],
            "key_id": key["key_id"],
            "sandbox_id": sb["sandbox_id"],
            "updated_at": time.strftime("%Y-%m-%d %H:%M:%S"),
        }
        return {
            "developer": developer,
            "app": {k: v for k, v in app.items()},
            "key": {k: v for k, v in key.items() if k != "key_hash"},
            "sandbox": sb,
            "member": member,
            "next_step": "sandbox_test",
        }

    def advance(self, developer: str, step_key: str) -> Dict[str, Any]:
        p = self.progress.get(developer)
        if not p:
            return {"success": False, "error": "developer not onboarded"}
        if step_key not in p["completed_steps"]:
            p["completed_steps"].append(step_key)
        idx = next((i for i, s in enumerate(WORKFLOW_STEPS) if s["key"] == step_key), None)
        if idx is not None:
            p["current_step"] = idx + 1
        p["updated_at"] = time.strftime("%Y-%m-%d %H:%M:%S")
        return {"success": True, "progress": p}

    def get_progress(self, developer: str) -> Dict[str, Any]:
        p = self.progress.get(developer)
        if not p:
            return {"developer": developer, "current_step": 0,
                    "completed_steps": []}
        return p

    # ------------------------------------------------------------------ #
    # 总览仪表盘
    # ------------------------------------------------------------------ #
    def overview(self) -> Dict[str, Any]:
        return {
            "platform": "开放 API 平台",
            "version": "15.0.0",
            "docs_endpoints": len(self.docs.endpoints),
            "sdk_languages": len(self.sdk.languages),
            "active_sandboxes": len([s for s in self.sandbox.sandboxes.values()
                                     if s.get("status") == "running"]),
            "registered_apps": len(self.keys.apps),
            "active_keys": len([k for k in self.keys.keys.values()
                                if k.get("status") == "active"]),
            "monthly_billed_amount": round(
                sum(u.get("billed_amount", 0.0) for u in self.billing.usage.values()), 2),
            "community_members": len(self.community.members),
            "open_feedback": len([f for f in self.community.feedback.values()
                                 if f.get("status") == "open"]),
            "generated_at": time.strftime("%Y-%m-%d %H:%M:%S"),
        }


_workflow: Optional[DeveloperPortalWorkflow] = None


def get_portal_workflow() -> DeveloperPortalWorkflow:
    global _workflow
    if _workflow is None:
        _workflow = DeveloperPortalWorkflow()
    return _workflow
