# -*- coding: utf-8 -*-
"""
commercial_ultra/brand_website.py — 品牌官网（商业产品体验极致）。

内存字典模拟：首页 / 功能页 / 定价页 / 文档页 / 联系页 五大站点内容。
"""

from __future__ import annotations

import threading
import time
from typing import Any, Dict, List


class BrandWebsite:
    """产品品牌官网内容（全内存模拟）。"""

    def __init__(self) -> None:
        self._lock = threading.RLock()
        self._views: Dict[str, int] = {"home": 0, "features": 0, "pricing": 0,
                                       "docs": 0, "contact": 0}
        self._leads: List[Dict[str, Any]] = []
        self._seq = 0

    def _incr(self, page: str) -> None:
        with self._lock:
            self._views[page] = self._views.get(page, 0) + 1

    # ------------------------------------------------------------------ #
    # 首页
    # ------------------------------------------------------------------ #
    def home(self) -> Dict[str, Any]:
        self._incr("home")
        return {
            "meta": {"title": "AI Hacking Agent — 智能化渗透测试平台",
                     "tagline": "AI 驱动的自动化安全攻防平台",
                     "version": "v4.0-ultra"},
            "hero": {
                "headline": "让安全测试像聊天一样简单",
                "sub": "一句话下达指令，AI 自动完成侦察、扫描、利用与报告",
                "cta_primary": "免费试用",
                "cta_secondary": "观看演示",
            },
            "core_features": [
                {"icon": "🤖", "name": "AI 渗透引擎",
                 "desc": "大模型自动规划攻击路径，覆盖 Web/API/内网/云"},
                {"icon": "⚡", "name": "分钟级出报告",
                 "desc": "从扫描到可执行修复建议，全链路自动化"},
                {"icon": "🛡️", "name": "合规与审计",
                 "desc": "全操作留痕，满足等保 / ISO27001 审计要求"},
                {"icon": "📊", "name": "可视化攻击链",
                 "desc": "3D 拓扑 + 攻击图谱，一眼看清风险面"},
            ],
            "stats": [
                {"label": "企业客户", "value": "1200+"},
                {"label": "日均扫描", "value": "50万+"},
                {"label": "漏洞库", "value": "20万+"},
                {"label": "SLA 可用性", "value": "99.95%"},
            ],
            "customers": [
                {"name": "某头部电商", "logo": "E-COMMERCE", "quote": "报告产出效率提升 10 倍"},
                {"name": "某金融集团", "logo": "FINANCE", "quote": "合规审计一次通过"},
                {"name": "某云服务商", "logo": "CLOUD", "quote": "多云资产统一纳管"},
            ],
        }

    # ------------------------------------------------------------------ #
    # 功能页
    # ------------------------------------------------------------------ #
    def features(self) -> Dict[str, Any]:
        self._incr("features")
        return {
            "title": "核心功能",
            "groups": [
                {"group": "自动化渗透", "items": [
                    {"name": "Web 渗透", "desc": "SQL 注入 / XSS / 越权 / 逻辑漏洞全自动"},
                    {"name": "API 安全", "desc": "OpenAPI 导入 + 未授权 / 鉴权绕过"},
                    {"name": "内网横向", "desc": "AD 攻击 / 横向移动 / 权限提升链"},
                    {"name": "云安全", "desc": "AWS/阿里云/腾讯云 配置审计与提权"},
                ]},
                {"group": "智能分析", "items": [
                    {"name": "AI 漏洞研判", "desc": "自动去误报、验证可利用性"},
                    {"name": "攻击链关联", "desc": "多漏洞自动串联成完整攻击路径"},
                    {"name": "修复建议", "desc": "按优先级给出代码级修复方案"},
                ]},
                {"group": "协作与交付", "items": [
                    {"name": "客户门户", "desc": "客户在线查看自己的项目与报告"},
                    {"name": "报告引擎", "desc": "多模板 PDF / Word / 在线报告"},
                    {"name": "工单流转", "desc": "漏洞指派、复测、闭环跟踪"},
                ]},
            ],
        }

    # ------------------------------------------------------------------ #
    # 定价页
    # ------------------------------------------------------------------ #
    def pricing(self) -> Dict[str, Any]:
        self._incr("pricing")
        return {
            "title": "定价方案",
            "plans": [
                {"id": "free", "name": "免费版", "price": 0, "unit": "/月",
                 "highlight": False, "features": [
                     "每月 50 次扫描", "基础 Web 扫描", "社区支持", "单项目"]},
                {"id": "pro", "name": "专业版", "price": 299, "unit": "/月",
                 "highlight": True, "features": [
                     "每月 5000 次扫描", "全模块渗透", "客户门户",
                     "PDF 报告导出", "邮件支持", "10 个项目"]},
                {"id": "enterprise", "name": "企业版", "price": "定制",
                 "unit": "", "highlight": False, "features": [
                     "无限扫描", "私有化部署", "SSO / 多租户",
                     "SLA 99.95%", "专属客户成功", "不限项目"]},
            ],
            "compare_note": "年付享 8 折，支持 Stripe / 支付宝 / 对公转账。",
        }

    # ------------------------------------------------------------------ #
    # 文档页
    # ------------------------------------------------------------------ #
    def docs(self) -> Dict[str, Any]:
        self._incr("docs")
        return {
            "title": "使用文档",
            "sections": [
                {"id": "quickstart", "name": "快速开始", "pages": [
                    "5 分钟完成首次扫描", "API Key 与鉴权", "目标授权范围说明"]},
                {"id": "scan", "name": "扫描指南", "pages": [
                    "Web 扫描配置", "API 扫描导入", "内网渗透模式"]},
                {"id": "report", "name": "报告与交付", "pages": [
                    "在线报告查看", "导出 PDF", "修复复测闭环"]},
                {"id": "integrate", "name": "集成", "pages": [
                    "REST API", "Webhook 回调", "CI/CD 集成"]},
            ],
        }

    # ------------------------------------------------------------------ #
    # 联系页
    # ------------------------------------------------------------------ #
    def contact(self) -> Dict[str, Any]:
        self._incr("contact")
        return {
            "title": "联系我们",
            "channels": [
                {"type": "sales", "label": "销售咨询", "value": "sales@hacking.ai"},
                {"type": "support", "label": "技术支持", "value": "support@hacking.ai"},
                {"type": "chat", "label": "在线客服", "value": "官网右下角悬浮窗"},
            ],
            "office": {"city": "深圳 / 上海 / 北京", "hours": "工作日 9:00-19:00"},
        }

    def submit_lead(self, name: str, email: str, message: str) -> Dict[str, Any]:
        with self._lock:
            self._seq += 1
            lead = {"lead_id": f"L-{int(time.time()) % 100000:05d}{self._seq:03d}",
                    "name": name, "email": email, "message": message,
                    "created_at": time.strftime("%Y-%m-%d %H:%M:%S"),
                    "status": "new"}
            self._leads.append(lead)
            return {"lead_id": lead["lead_id"], "received": True}

    def leads(self) -> List[Dict[str, Any]]:
        with self._lock:
            return list(self._leads)

    def analytics(self) -> Dict[str, Any]:
        with self._lock:
            return {"page_views": dict(self._views),
                    "total_leads": len(self._leads)}


_website: BrandWebsite | None = None


def get_brand_website() -> BrandWebsite:
    global _website
    if _website is None:
        _website = BrandWebsite()
    return _website
