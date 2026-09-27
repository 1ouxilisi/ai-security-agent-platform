# -*- coding: utf-8 -*-
"""新手引导 API 路由（V2 统一平台控制台配套）。

为前端 platform_console_v2.html 提供新手引导数据与状态持久化端点：

    - GET  /api/v1/onboarding/status?user_id=  查询某用户的引导完成状态
    - POST /api/v1/onboarding/complete           标记引导完成 / 记录当前步骤
    - GET  /api/v1/onboarding/steps             从 config/ui_config.json 读取引导步骤配置

设计原则（与 analytics_routes / platform_routes 保持一致）：
    - 所有端点均 try-except 包裹，任何异常都返回统一 JSON，不抛出 500；
    - 引导状态以 JSON 文件持久化到 data/onboarding_status.json，无需数据库依赖；
    - steps 配置缺失时回退到内置默认步骤，前端永远能拿到可用数据。

注意事项：
    - 本模块仅用于授权安全评估产品的前端引导流程
"""
import json
import os
import sys
from datetime import datetime
from typing import Any, Dict, Optional

from fastapi import APIRouter
from fastapi.responses import JSONResponse
from pydantic import BaseModel

# 保证项目根在 sys.path 中（与其它路由模块保持一致）
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

router = APIRouter(prefix="/api/v1/onboarding", tags=["新手引导"])

# 项目根目录（api_server 的上一级）
PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

# 引导状态持久化文件
STATUS_FILE = os.path.join(PROJECT_ROOT, "data", "onboarding_status.json")

# UI 配置文件（引导步骤配置来源）
UI_CONFIG_FILE = os.path.join(PROJECT_ROOT, "config", "ui_config.json")


# ==================== 请求模型 ====================

class CompleteRequest(BaseModel):
    """标记引导完成请求体。"""

    user_id: str = "default_user"
    step: Optional[str] = None  # 传入则记录"当前到达步骤"；不传/为空表示整段引导完成


# ==================== 内置默认引导步骤（配置文件缺失时兜底） ====================

_DEFAULT_STEPS = [
    {
        "id": "welcome",
        "title_zh": "欢迎使用统一安全平台 V2",
        "title_en": "Welcome to Unified Security Platform V2",
        "description_zh": "一站式安全运营控制台，1 分钟带您熟悉核心功能。",
        "description_en": "Your all-in-one security console. A 1-minute tour.",
        "target_selector": None,
        "position": "center",
    },
    {
        "id": "nav",
        "title_zh": "左侧导航菜单",
        "title_en": "Left Navigation",
        "description_zh": "所有功能模块都在这里，点击即可切换视图。",
        "description_en": "All modules live here. Click to switch views.",
        "target_selector": "#nav-sidebar",
        "position": "right",
    },
    {
        "id": "quick-assess",
        "title_zh": "快速评估入口",
        "title_en": "Quick Assessment",
        "description_zh": "在仪表盘输入目标地址即可发起快速安全评估。",
        "description_en": "Enter a target on the Dashboard to run a quick assessment.",
        "target_selector": "#view-dashboard .quick-assess-card",
        "position": "bottom",
    },
    {
        "id": "analytics",
        "title_zh": "数据分析仪表盘",
        "title_en": "Analytics Dashboard",
        "description_zh": "查看评估总量、漏洞趋势、严重程度分布与 Top 风险目标。",
        "description_en": "View totals, vulnerability trends, severity distribution and top targets.",
        "target_selector": "#nav-analytics",
        "position": "right",
    },
    {
        "id": "reporting",
        "title_zh": "报告生成",
        "title_en": "Report Generation",
        "description_zh": "在报告中心选择评估 ID、格式与模板，一键生成报告。",
        "description_en": "Pick an assessment, format and template to generate a report.",
        "target_selector": "#nav-reports",
        "position": "right",
    },
    {
        "id": "done",
        "title_zh": "开始使用",
        "title_en": "You Are All Set",
        "description_zh": "按 Ctrl+K 打开命令面板，按 Ctrl+/ 查看快捷键。",
        "description_en": "Press Ctrl+K for the command palette, Ctrl+/ for shortcuts.",
        "target_selector": None,
        "position": "center",
    },
]


# ==================== 状态文件读写 ====================

def _load_status() -> Dict[str, Any]:
    """读取全部用户引导状态；文件不存在或损坏时返回空字典。"""
    try:
        if os.path.exists(STATUS_FILE):
            with open(STATUS_FILE, "r", encoding="utf-8") as f:
                data = json.load(f)
            if isinstance(data, dict):
                return data
    except Exception:  # noqa: BLE001
        pass
    return {}


def _save_status(data: Dict[str, Any]) -> bool:
    """持久化引导状态，自动创建 data 目录。返回是否写入成功。"""
    try:
        os.makedirs(os.path.dirname(STATUS_FILE), exist_ok=True)
        with open(STATUS_FILE, "w", encoding="utf-8") as f:
            json.dump(data, f, ensure_ascii=False, indent=2)
        return True
    except Exception:  # noqa: BLE001
        return False


def _read_steps_from_config() -> list:
    """从 config/ui_config.json 读取 onboarding_steps；失败返回内置默认步骤。"""
    try:
        if os.path.exists(UI_CONFIG_FILE):
            with open(UI_CONFIG_FILE, "r", encoding="utf-8") as f:
                cfg = json.load(f)
            steps = cfg.get("onboarding_steps")
            if isinstance(steps, list) and steps:
                return steps
    except Exception:  # noqa: BLE001
        pass
    return _DEFAULT_STEPS


# ==================== 端点 ====================

@router.get("/status", summary="获取引导完成状态")
def get_onboarding_status(user_id: str = "default_user"):
    """返回某用户的引导完成状态：{completed, completed_at, current_step}。"""
    try:
        all_status = _load_status()
        rec = all_status.get(user_id) or {}
        return JSONResponse(content={
            "success": True,
            "user_id": user_id,
            "completed": bool(rec.get("completed", False)),
            "completed_at": rec.get("completed_at"),
            "current_step": rec.get("current_step"),
        })
    except Exception as e:  # noqa: BLE001
        return JSONResponse(status_code=200, content={
            "success": False,
            "error": f"引导状态查询失败: {e}",
            "completed": False,
            "completed_at": None,
            "current_step": None,
        })


@router.post("/complete", summary="标记引导完成")
def complete_onboarding(req: CompleteRequest):
    """标记某用户引导完成（或仅记录当前到达步骤）。"""
    try:
        all_status = _load_status()
        rec = all_status.get(req.user_id) or {}
        now = datetime.now().isoformat(timespec="seconds")

        if req.step:
            # 只记录进度步骤，不把整体置为完成
            rec["current_step"] = req.step
        else:
            # 整段引导完成
            rec["completed"] = True
            rec["completed_at"] = now
            rec["current_step"] = None

        rec["updated_at"] = now
        all_status[req.user_id] = rec
        saved = _save_status(all_status)

        return JSONResponse(content={
            "success": saved,
            "user_id": req.user_id,
            "completed": bool(rec.get("completed", False)),
            "completed_at": rec.get("completed_at"),
            "current_step": rec.get("current_step"),
        })
    except Exception as e:  # noqa: BLE001
        return JSONResponse(status_code=200, content={
            "success": False,
            "error": f"引导完成状态保存失败: {e}",
        })


@router.get("/steps", summary="获取引导步骤配置")
def get_onboarding_steps():
    """从 config/ui_config.json 读取引导步骤列表，失败回退内置默认配置。"""
    try:
        steps = _read_steps_from_config()
        return JSONResponse(content={
            "success": True,
            "count": len(steps),
            "steps": steps,
        })
    except Exception as e:  # noqa: BLE001
        return JSONResponse(status_code=200, content={
            "success": False,
            "error": f"引导步骤配置读取失败: {e}",
            "count": 0,
            "steps": _DEFAULT_STEPS,
        })
