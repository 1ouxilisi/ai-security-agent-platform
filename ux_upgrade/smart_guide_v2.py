# -*- coding: utf-8 -*-
"""
ux_upgrade/smart_guide_v2.py — 智能引导 V2

首次进入自动引导流程；每个功能带 tooltip；操作失败自动提示怎么修。
"""
from __future__ import annotations

import time
from typing import Any, Dict, List

# 用户引导状态（内存）
USER_STATE: Dict[str, Dict[str, Any]] = {}

# 引导步骤
GUIDE_STEPS = [
    {"step": 1, "title": "欢迎使用 AI Hacking Agent",
     "body": "这是你的一站式智能渗透平台，我用 30 秒带你熟悉核心功能。",
     "target": "body"},
    {"step": 2, "title": "一键扫描",
     "body": "点击大按钮即可对目标发起全量扫描，无需记住复杂命令。",
     "target": ".quick-scan"},
    {"step": 3, "title": "AI 智能分析",
     "body": "扫描结果会自动交由 AI 判断严重度并给出利用/修复建议。",
     "target": ".ai-panel"},
    {"step": 4, "title": "全局搜索 (Ctrl+K)",
     "body": "任何时候按 Ctrl+K，可一键搜索功能、漏洞、报告并直达。",
     "target": "body"},
    {"step": 5, "title": "完成 🎉",
     "body": "配置 LLM Key 可解锁全部 AI 能力；没有 Key 也能用规则模式。",
     "target": "body"},
]

# 功能 tooltip 库
TOOLTIPS: Dict[str, str] = {
    "quick_scan": "对目标域名/IP 发起全量被动+主动扫描，约 1-3 分钟出结果。",
    "quick_report": "调用 AI 将扫描结果整理成专业渗透报告，支持导出 Markdown。",
    "quick_dashboard": "汇总今日扫描数、漏洞分布、风险等级的可视化总览。",
    "llm_config": "配置 OpenAI 兼容接口的 API Key；不配置则使用内置规则引擎。",
    "global_search": "按 Ctrl+K 唤起。支持中文模糊搜索功能、漏洞、报告。",
    "dark_mode": "专业安全工具暗色风格，长时间盯屏更护眼。",
    "mobile": "已做响应式适配，手机浏览器也能查看仪表盘与报告。",
}

# 错误 -> 修复建议
ERROR_FIX: Dict[str, str] = {
    "timeout": "请求超时：检查目标是否可达，或在『设置』中调大超时时间。",
    "auth_error": "认证失败：API Key 不正确，请到 LLM 配置页重新填写。",
    "not_configured": "未配置 LLM Key：当前走规则模式；如需 AI 推理请先配置 Key。",
    "rate_limit": "触发限流：请稍后重试，或降低并发数。",
    "target_unreachable": "目标不可达：确认 URL 与网络，是否需要代理。",
}


class SmartGuideV2:
    """智能引导 + tooltip + 错误修复提示。"""

    def should_start(self, user_id: str) -> bool:
        st = USER_STATE.get(user_id)
        return st is None or not st.get("guide_done", False)

    def start(self, user_id: str) -> Dict[str, Any]:
        USER_STATE[user_id] = {"guide_done": False, "current_step": 1,
                               "started_at": time.strftime("%Y-%m-%d %H:%M:%S")}
        return {"user_id": user_id, "steps": GUIDE_STEPS,
                "total": len(GUIDE_STEPS), "current": 1}

    def next_step(self, user_id: str) -> Dict[str, Any]:
        st = USER_STATE.setdefault(user_id, {})
        st["current_step"] = st.get("current_step", 1) + 1
        done = st["current_step"] > len(GUIDE_STEPS)
        if done:
            st["guide_done"] = True
        return {"user_id": user_id, "current_step": st["current_step"],
                "done": done,
                "step": GUIDE_STEPS[st["current_step"] - 1]
                if not done and st["current_step"] <= len(GUIDE_STEPS) else None}

    def complete(self, user_id: str) -> Dict[str, Any]:
        USER_STATE[user_id] = {"guide_done": True,
                               "completed_at": time.strftime("%Y-%m-%d %H:%M:%S")}
        return {"user_id": user_id, "guide_done": True}

    def get_tooltips(self) -> Dict[str, str]:
        return TOOLTIPS

    def get_tooltip(self, key: str) -> Dict[str, Any]:
        return {"key": key, "tip": TOOLTIPS.get(key, "暂无说明")}

    def suggest_fix(self, error_code: str,
                    raw: str = "") -> Dict[str, Any]:
        tip = ERROR_FIX.get(error_code,
                            f"操作失败（{error_code or 'unknown'}）："
                            "请查看控制台日志，或联系支持。原始信息：" + raw[:200])
        return {"error_code": error_code, "suggestion": tip}


_smart_guide_singleton: SmartGuideV2 | None = None


def get_smart_guide_v2() -> SmartGuideV2:
    global _smart_guide_singleton
    if _smart_guide_singleton is None:
        _smart_guide_singleton = SmartGuideV2()
    return _smart_guide_singleton
