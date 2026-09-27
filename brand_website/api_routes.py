# -*- coding: utf-8 -*-
"""
brand_website/api_routes.py — 品牌官网落地页 FastAPI 路由（30+ 端点）。

路由前缀: /api/v1/brand-website
统一响应: {"success": bool, "data": ..., "error": ...}
所有端点 try/except 兜底；任务用内存字典模拟异步。
"""

from __future__ import annotations

import logging
import time
import uuid
from typing import Any, Dict, List, Optional

from fastapi import APIRouter, Query
from fastapi.responses import JSONResponse
from pydantic import BaseModel, Field

from . import content_manager as cm
from . import product_showcase as ps
from . import pricing_purchase as pp
from . import docs_support as ds
from . import blog_marketing as bm
from . import brand_dashboard as bd

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/api/v1/brand-website", tags=["品牌官网落地页"])


# --------------------------------------------------------------------------- #
# 任务存储（内存字典模拟异步）
# --------------------------------------------------------------------------- #
_TASKS: Dict[str, Dict[str, Any]] = {}


def _new_task(kind: str) -> str:
    task_id = uuid.uuid4().hex[:16]
    _TASKS[task_id] = {
        "task_id": task_id, "kind": kind, "status": "pending",
        "created_at": time.strftime("%Y-%m-%d %H:%M:%S"),
        "finished_at": None, "result": None, "error": None,
    }
    return task_id


def _finish_task(task_id: str, result: Any, error: Optional[str] = None) -> None:
    if task_id in _TASKS:
        t = _TASKS[task_id]
        t["status"] = "error" if error else "done"
        t["result"] = result
        t["error"] = error
        t["finished_at"] = time.strftime("%Y-%m-%d %H:%M:%S")


def _get_task(task_id: str) -> Optional[Dict[str, Any]]:
    return _TASKS.get(task_id)


# --------------------------------------------------------------------------- #
# 统一响应 / 控制字符清理
# --------------------------------------------------------------------------- #
def _clean(obj: Any) -> Any:
    """递归清理控制字符与无效 Unicode，保证 JSON 可序列化。"""
    if isinstance(obj, str):
        return "".join(
            ch for ch in obj
            if ch in ("\n", "\t", "\r") or ord(ch) >= 32
        )
    if isinstance(obj, dict):
        return {k: _clean(v) for k, v in obj.items()}
    if isinstance(obj, list):
        return [_clean(v) for v in obj]
    if isinstance(obj, tuple):
        return [_clean(v) for v in obj]
    return obj


def ok(data: Any = None) -> JSONResponse:
    return JSONResponse({"success": True, "data": _clean(data), "error": None})


def fail(message: str, code: int = 400) -> JSONResponse:
    return JSONResponse({"success": False, "data": None,
                         "error": _clean(message)}, status_code=code)


# --------------------------------------------------------------------------- #
# 请求模型
# --------------------------------------------------------------------------- #
class PageCreate(BaseModel):
    title: str
    ptype: str = "page"
    content_md: str = ""
    author: str = "admin"


class PageEdit(BaseModel):
    title: Optional[str] = None
    content_md: Optional[str] = None
    seo_title: Optional[str] = None
    seo_description: Optional[str] = None
    seo_keywords: Optional[List[str]] = None
    language: Optional[str] = None


class MediaUpload(BaseModel):
    name: str
    mtype: str = "image"
    size: int = 0
    category: str = "general"
    tags: List[str] = Field(default_factory=list)


class NavItem(BaseModel):
    label: str
    url: str
    order: int = 0


class TranslateReq(BaseModel):
    lang: str
    key: str = ""
    value: str = ""


class OrderCreate(BaseModel):
    plan_id: str
    period: str = "yearly"
    users: int = 1
    coupon: str = ""
    contact: str = ""


class CouponCreate(BaseModel):
    code: str
    type: str = "fixed"
    value: float = 50
    min_amount: float = 0
    expire: str = ""
    max_uses: int = 100


class TrialApply(BaseModel):
    plan_id: str = "pro"
    contact: str = ""
    days: int = 14


class CustomReq(BaseModel):
    company: str
    requirements: str
    budget: str = ""
    contact: str = ""


class DocCreate(BaseModel):
    title: str
    category: str = "manual"
    body: str = ""


class TicketCreate(BaseModel):
    title: str
    category: str = "general"
    priority: str = "normal"
    requester: str = ""


class ReplyReq(BaseModel):
    author: str
    body: str


class ChatStart(BaseModel):
    user: str
    message: str


class PostCreate(BaseModel):
    title: str
    category: str = "tech"
    author: str = "editor"
    summary: str = ""
    body: str = ""
    tags: List[str] = Field(default_factory=list)


class CalendarPlan(BaseModel):
    title: str
    type: str = "article"
    owner: str = "editor"
    due: str = ""


# =========================================================================== #
# 1. 内容管理（页面/媒体/导航/多语言/SEO）
# =========================================================================== #
@router.get("/pages")
def list_pages(status: Optional[str] = Query(None)):
    try:
        return ok(cm.PageManager().list_pages(status))
    except Exception as e:  # pragma: no cover
        logger.exception("list_pages")
        return fail(f"页面列表失败: {e}", 500)


@router.post("/pages")
def create_page(req: PageCreate):
    try:
        return ok(cm.PageManager().create_page(req.title, req.ptype,
                                              req.content_md, req.author))
    except Exception as e:
        logger.exception("create_page")
        return fail(f"创建页面失败: {e}", 500)


@router.put("/pages/{slug}")
def edit_page(slug: str, req: PageEdit):
    try:
        fields = req.model_dump(exclude_none=True)
        p = cm.PageManager().edit_page(slug, **fields)
        if not p:
            return fail("页面不存在", 404)
        return ok(p)
    except Exception as e:
        logger.exception("edit_page")
        return fail(f"编辑页面失败: {e}", 500)


@router.post("/pages/{slug}/publish")
def publish_page(slug: str):
    try:
        p = cm.PageManager().publish(slug)
        if not p:
            return fail("页面不存在", 404)
        return ok(p)
    except Exception as e:
        logger.exception("publish_page")
        return fail(f"发布失败: {e}", 500)


@router.post("/pages/{slug}/unpublish")
def unpublish_page(slug: str):
    try:
        p = cm.PageManager().unpublish(slug)
        if not p:
            return fail("页面不存在", 404)
        return ok(p)
    except Exception as e:
        logger.exception("unpublish_page")
        return fail(f"下线失败: {e}", 500)


@router.get("/pages/{slug}/preview")
def preview_page(slug: str, language: str = "zh-CN"):
    try:
        return ok(cm.PageManager().preview(slug, language))
    except Exception as e:
        logger.exception("preview_page")
        return fail(f"预览失败: {e}", 500)


@router.post("/pages/{slug}/version")
def save_version(slug: str):
    try:
        v = cm.PageManager().save_version(slug)
        if not v:
            return fail("页面不存在", 404)
        return ok(v)
    except Exception as e:
        logger.exception("save_version")
        return fail(f"保存版本失败: {e}", 500)


@router.get("/media")
def list_media(mtype: Optional[str] = None,
               keyword: Optional[str] = None):
    try:
        return ok(cm.MediaLibrary().list_media(mtype, keyword))
    except Exception as e:
        logger.exception("list_media")
        return fail(f"媒体库失败: {e}", 500)


@router.post("/media/upload")
def upload_media(req: MediaUpload):
    try:
        return ok(cm.MediaLibrary().upload(req.name, req.mtype, req.size,
                                           req.category, req.tags))
    except Exception as e:
        logger.exception("upload_media")
        return fail(f"上传失败: {e}", 500)


@router.get("/nav")
def list_nav():
    try:
        return ok(cm.NavigationMenu().list_menus())
    except Exception as e:
        logger.exception("list_nav")
        return fail(f"导航菜单失败: {e}", 500)


@router.post("/nav/{key}/items")
def add_nav_item(key: str, req: NavItem):
    try:
        item = cm.NavigationMenu().add_item(key, req.label, req.url, req.order)
        if not item:
            return fail("菜单不存在", 404)
        return ok(item)
    except Exception as e:
        logger.exception("add_nav_item")
        return fail(f"添加菜单项失败: {e}", 500)


@router.get("/languages")
def list_languages():
    try:
        return ok(cm.I18nManager().list_languages())
    except Exception as e:
        logger.exception("list_languages")
        return fail(f"语言列表失败: {e}", 500)


@router.post("/i18n/translate")
def translate_page(req: TranslateReq):
    try:
        if req.key:
            return ok(cm.I18nManager().set_translation(req.lang, req.key, req.value))
        return ok(cm.I18nManager().translate_page(req.value, req.lang) or {})
    except Exception as e:
        logger.exception("translate_page")
        return fail(f"翻译失败: {e}", 500)


@router.get("/seo/global")
def seo_global():
    try:
        return ok(cm.SEOWizard().global_settings())
    except Exception as e:
        logger.exception("seo_global")
        return fail(f"SEO 全局失败: {e}", 500)


@router.put("/seo/global")
def update_seo_global(settings: Dict[str, Any]):
    try:
        return ok(cm.SEOWizard().update_global(**settings))
    except Exception as e:
        logger.exception("update_seo_global")
        return fail(f"更新 SEO 失败: {e}", 500)


@router.get("/sitemap")
def sitemap():
    try:
        return ok({"xml": cm.SEOWizard().generate_sitemap()})
    except Exception as e:
        logger.exception("sitemap")
        return fail(f"sitemap 生成失败: {e}", 500)


@router.get("/landing/{slug}")
def landing_page(slug: str, language: str = "zh-CN"):
    try:
        task_id = _new_task("landing")
        result = cm.render_landing_page(slug, language)
        _finish_task(task_id, result)
        return ok({"task_id": task_id, "result": result})
    except Exception as e:
        logger.exception("landing_page")
        return fail(f"落地页渲染失败: {e}", 500)


# =========================================================================== #
# 2. 产品展示
# =========================================================================== #
@router.get("/products")
def list_products():
    try:
        return ok(ps.ProductShowcase().list_products())
    except Exception as e:
        logger.exception("list_products")
        return fail(f"产品列表失败: {e}", 500)


@router.get("/features")
def list_features(category: Optional[str] = None):
    try:
        return ok(ps.ProductShowcase().list_features(category))
    except Exception as e:
        logger.exception("list_features")
        return fail(f"功能列表失败: {e}", 500)


@router.get("/versions/compare")
def compare_versions():
    try:
        return ok(ps.ProductShowcase().compare_versions())
    except Exception as e:
        logger.exception("compare_versions")
        return fail(f"版本对比失败: {e}", 500)


@router.get("/architecture")
def architecture():
    try:
        return ok(ps.ProductShowcase().architecture())
    except Exception as e:
        logger.exception("architecture")
        return fail(f"技术架构失败: {e}", 500)


@router.get("/cases")
def list_cases(industry: Optional[str] = None):
    try:
        return ok(ps.ProductShowcase().list_cases(industry))
    except Exception as e:
        logger.exception("list_cases")
        return fail(f"案例列表失败: {e}", 500)


@router.get("/partners")
def list_partners(ptype: Optional[str] = None):
    try:
        return ok(ps.ProductShowcase().list_partners(ptype))
    except Exception as e:
        logger.exception("list_partners")
        return fail(f"合作伙伴失败: {e}", 500)


@router.post("/partners/apply")
def apply_partner(req: Dict[str, str]):
    try:
        return ok(ps.ProductShowcase().apply_partner(
            req.get("name", ""), req.get("type", "集成商"),
            req.get("mode", "项目分成")))
    except Exception as e:
        logger.exception("apply_partner")
        return fail(f"申请失败: {e}", 500)


# =========================================================================== #
# 3. 定价购买
# =========================================================================== #
@router.get("/plans")
def list_plans():
    try:
        return ok(pp.PricingPurchase().list_plans())
    except Exception as e:
        logger.exception("list_plans")
        return fail(f"定价失败: {e}", 500)


@router.post("/orders")
def create_order(req: OrderCreate):
    try:
        return ok(pp.PricingPurchase().create_order(
            req.plan_id, req.period, req.users, req.coupon, req.contact))
    except Exception as e:
        logger.exception("create_order")
        return fail(f"下单失败: {e}", 500)


@router.post("/orders/{order_id}/pay")
def pay_order(order_id: str, channel: str = "alipay"):
    try:
        result = pp.PricingPurchase().confirm_pay(order_id, channel)
        if "error" in result:
            return fail(result["error"], 404)
        return ok(result)
    except Exception as e:
        logger.exception("pay_order")
        return fail(f"支付失败: {e}", 500)


@router.get("/orders")
def list_orders():
    try:
        return ok(pp.PricingPurchase().list_orders())
    except Exception as e:
        logger.exception("list_orders")
        return fail(f"订单列表失败: {e}", 500)


@router.get("/coupons")
def list_coupons():
    try:
        return ok(pp.PricingPurchase().list_coupons())
    except Exception as e:
        logger.exception("list_coupons")
        return fail(f"优惠券失败: {e}", 500)


@router.post("/coupons")
def create_coupon(req: CouponCreate):
    try:
        return ok(pp.PricingPurchase().create_coupon(
            req.code, req.type, req.value, req.min_amount,
            req.expire, req.max_uses))
    except Exception as e:
        logger.exception("create_coupon")
        return fail(f"创建优惠券失败: {e}", 500)


@router.post("/trials")
def apply_trial(req: TrialApply):
    try:
        return ok(pp.PricingPurchase().apply_trial(
            req.plan_id, req.contact, req.days))
    except Exception as e:
        logger.exception("apply_trial")
        return fail(f"试用申请失败: {e}", 500)


@router.get("/trials/stats")
def trial_stats():
    try:
        return ok(pp.PricingPurchase().trial_stats())
    except Exception as e:
        logger.exception("trial_stats")
        return fail(f"试用统计失败: {e}", 500)


@router.post("/custom")
def custom_request(req: CustomReq):
    try:
        return ok(pp.PricingPurchase().custom_request(
            req.company, req.requirements, req.budget, req.contact))
    except Exception as e:
        logger.exception("custom_request")
        return fail(f"定制请求失败: {e}", 500)


# =========================================================================== #
# 4. 文档与支持
# =========================================================================== #
@router.get("/docs")
def list_docs(category: Optional[str] = None):
    try:
        return ok(ds.DocsSupport().list_docs(category))
    except Exception as e:
        logger.exception("list_docs")
        return fail(f"文档列表失败: {e}", 500)


@router.post("/docs")
def create_doc(req: DocCreate):
    try:
        return ok(ds.DocsSupport().create_doc(req.title, req.category, req.body))
    except Exception as e:
        logger.exception("create_doc")
        return fail(f"创建文档失败: {e}", 500)


@router.get("/kb")
def list_kb(keyword: Optional[str] = None):
    try:
        return ok(ds.DocsSupport().list_kb(keyword))
    except Exception as e:
        logger.exception("list_kb")
        return fail(f"知识库失败: {e}", 500)


@router.get("/tickets")
def list_tickets(status: Optional[str] = None):
    try:
        return ok(ds.DocsSupport().list_tickets(status))
    except Exception as e:
        logger.exception("list_tickets")
        return fail(f"工单列表失败: {e}", 500)


@router.post("/tickets")
def create_ticket(req: TicketCreate):
    try:
        return ok(ds.DocsSupport().create_ticket(
            req.title, req.category, req.priority, req.requester))
    except Exception as e:
        logger.exception("create_ticket")
        return fail(f"创建工单失败: {e}", 500)


@router.post("/tickets/{tid}/reply")
def reply_ticket(tid: str, req: ReplyReq):
    try:
        t = ds.DocsSupport().reply_ticket(tid, req.author, req.body)
        if not t:
            return fail("工单不存在", 404)
        return ok(t)
    except Exception as e:
        logger.exception("reply_ticket")
        return fail(f"回复工单失败: {e}", 500)


@router.post("/chats")
def start_chat(req: ChatStart):
    try:
        return ok(ds.DocsSupport().start_chat(req.user, req.message))
    except Exception as e:
        logger.exception("start_chat")
        return fail(f"客服会话失败: {e}", 500)


@router.get("/videos")
def list_videos(category: Optional[str] = None):
    try:
        return ok(ds.DocsSupport().list_videos(category))
    except Exception as e:
        logger.exception("list_videos")
        return fail(f"视频教程失败: {e}", 500)


# =========================================================================== #
# 5. 博客与营销
# =========================================================================== #
@router.get("/posts")
def list_posts(status: Optional[str] = None,
               category: Optional[str] = None):
    try:
        return ok(bm.BlogMarketing().list_posts(status, category))
    except Exception as e:
        logger.exception("list_posts")
        return fail(f"博客列表失败: {e}", 500)


@router.post("/posts")
def create_post(req: PostCreate):
    try:
        return ok(bm.BlogMarketing().create_post(
            req.title, req.category, req.author, req.summary,
            req.body, req.tags))
    except Exception as e:
        logger.exception("create_post")
        return fail(f"创建博客失败: {e}", 500)


@router.post("/posts/{pid}/publish")
def publish_post(pid: str):
    try:
        p = bm.BlogMarketing().publish_post(pid)
        if not p:
            return fail("文章不存在", 404)
        return ok(p)
    except Exception as e:
        logger.exception("publish_post")
        return fail(f"发布文章失败: {e}", 500)


@router.get("/calendar")
def list_calendar():
    try:
        return ok(bm.BlogMarketing().list_calendar())
    except Exception as e:
        logger.exception("list_calendar")
        return fail(f"内容日历失败: {e}", 500)


@router.post("/calendar")
def plan_content(req: CalendarPlan):
    try:
        return ok(bm.BlogMarketing().plan_content(
            req.title, req.type, req.owner, req.due))
    except Exception as e:
        logger.exception("plan_content")
        return fail(f"排期失败: {e}", 500)


@router.get("/seo/report")
def seo_report():
    try:
        return ok(bm.BlogMarketing().seo_report())
    except Exception as e:
        logger.exception("seo_report")
        return fail(f"SEO 报告失败: {e}", 500)


@router.get("/social")
def list_social():
    try:
        return ok(bm.BlogMarketing().list_social())
    except Exception as e:
        logger.exception("list_social")
        return fail(f"社交媒体失败: {e}", 500)


@router.post("/social/{platform}/sync")
def sync_social(platform: str):
    try:
        return ok(bm.BlogMarketing().sync_social(platform))
    except Exception as e:
        logger.exception("sync_social")
        return fail(f"同步失败: {e}", 500)


@router.get("/campaigns")
def list_campaigns():
    try:
        return ok(bm.BlogMarketing().list_campaigns())
    except Exception as e:
        logger.exception("list_campaigns")
        return fail(f"邮件活动失败: {e}", 500)


@router.post("/campaigns/{eid}/send")
def send_campaign(eid: str):
    try:
        c = bm.BlogMarketing().send_campaign(eid)
        if not c:
            return fail("活动不存在", 404)
        return ok(c)
    except Exception as e:
        logger.exception("send_campaign")
        return fail(f"发送失败: {e}", 500)


@router.get("/analytics")
def analytics():
    try:
        return ok(bm.BlogMarketing().analytics())
    except Exception as e:
        logger.exception("analytics")
        return fail(f"数据分析失败: {e}", 500)


# =========================================================================== #
# 6. 运营仪表盘
# =========================================================================== #
@router.get("/dashboard/overview")
def dashboard_overview():
    try:
        return ok(bd.BrandDashboard().overview())
    except Exception as e:
        logger.exception("dashboard_overview")
        return fail(f"总览失败: {e}", 500)


@router.get("/dashboard/content")
def dashboard_content():
    try:
        return ok(bd.BrandDashboard().content_health())
    except Exception as e:
        logger.exception("dashboard_content")
        return fail(f"内容健康失败: {e}", 500)


@router.get("/dashboard/business")
def dashboard_business():
    try:
        return ok(bd.BrandDashboard().business_stats())
    except Exception as e:
        logger.exception("dashboard_business")
        return fail(f"商业统计失败: {e}", 500)


@router.get("/dashboard/support")
def dashboard_support():
    try:
        return ok(bd.BrandDashboard().support_satisfaction())
    except Exception as e:
        logger.exception("dashboard_support")
        return fail(f"支持统计失败: {e}", 500)


@router.get("/dashboard/marketing")
def dashboard_marketing():
    try:
        return ok(bd.BrandDashboard().marketing_roi())
    except Exception as e:
        logger.exception("dashboard_marketing")
        return fail(f"营销 ROI 失败: {e}", 500)


@router.get("/dashboard/traffic")
def dashboard_traffic(days: int = 30):
    try:
        return ok(bd.BrandDashboard().traffic_trend(days))
    except Exception as e:
        logger.exception("dashboard_traffic")
        return fail(f"流量趋势失败: {e}", 500)


@router.get("/tasks/{task_id}")
def get_task(task_id: str):
    try:
        t = _get_task(task_id)
        if not t:
            return fail("任务不存在", 404)
        return ok(t)
    except Exception as e:
        logger.exception("get_task")
        return fail(f"查询任务失败: {e}", 500)
