# -*- coding: utf-8 -*-
"""
globalization_routes.py — 国际化与全球部署 REST API（第25轮升级方向4）。

路由前缀：/api/v1/globalization
统一响应：{"success": bool, "data": ..., "error": ...}
所有端点 try-except 包裹，不返回 500 错误。
任务用内存字典 TASKS 模拟异步。
本模块仅用于授权的企业国际化运营场景。
"""

from __future__ import annotations

import os
import re
import sys
import uuid
from datetime import datetime
from typing import Any, Dict, List, Optional

from fastapi import APIRouter, Query
from fastapi.responses import JSONResponse
from pydantic import BaseModel, Field

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

# ---------- 模块 try-import ----------
try:
    from globalization.i18n_engine import i18n_engine, LANGUAGES, LOCALE_FORMATS
    from globalization.regional_compliance import regional_compliance, COMPLIANCE_FRAMEWORKS, REGION_FRAMEWORK_MAP
    from globalization.global_payment import global_payment, PAYMENT_METHODS, CURRENCIES, SUBSCRIPTION_PLANS
    from globalization.global_deployment import global_deployment, DEPLOYMENT_REGIONS, CDN_NODES
    from globalization.localization import localization, REGIONAL_SETTINGS, CULTURAL_PREFERENCES
    from globalization.globalization_dashboard import globalization_dashboard, SYSTEM_CONFIG
    _MODULES_OK = True
except Exception as _e:  # pragma: no cover
    import logging
    logging.getLogger("globalization_routes").warning("模块导入失败: %s", _e)
    i18n_engine = None  # type: ignore
    regional_compliance = None  # type: ignore
    global_payment = None  # type: ignore
    global_deployment = None  # type: ignore
    localization = None  # type: ignore
    globalization_dashboard = None  # type: ignore
    LANGUAGES = {}  # type: ignore
    LOCALE_FORMATS = {}  # type: ignore
    COMPLIANCE_FRAMEWORKS = {}  # type: ignore
    REGION_FRAMEWORK_MAP = {}  # type: ignore
    PAYMENT_METHODS = {}  # type: ignore
    CURRENCIES = {}  # type: ignore
    SUBSCRIPTION_PLANS = {}  # type: ignore
    DEPLOYMENT_REGIONS = {}  # type: ignore
    CDN_NODES = []  # type: ignore
    REGIONAL_SETTINGS = {}  # type: ignore
    CULTURAL_PREFERENCES = {}  # type: ignore
    SYSTEM_CONFIG = {}  # type: ignore
    _MODULES_OK = False


router = APIRouter(prefix="/api/v1/globalization", tags=["国际化与全球部署"])


# ==================== 响应工具 ====================

_CTRL_RE = re.compile(r"[\x00-\x08\x0b\x0c\x0e-\x1f\x7f]")


def _clean(obj: Any) -> Any:
    """递归清理无效控制字符"""
    if isinstance(obj, str):
        return _CTRL_RE.sub("", obj)
    if isinstance(obj, dict):
        return {k: _clean(v) for k, v in obj.items()}
    if isinstance(obj, (list, tuple)):
        return [_clean(x) for x in obj]
    return obj


def _ok(data: Any = None) -> JSONResponse:
    return JSONResponse({"success": True, "data": _clean(data), "error": None})


def _fail(err: str, data: Any = None) -> JSONResponse:
    return JSONResponse({"success": False, "data": _clean(data), "error": str(err)})


def _check() -> Optional[JSONResponse]:
    if not _MODULES_OK:
        return _fail("globalization 模块未正确加载")
    return None


# ==================== 内存任务存储 ====================

TASKS: Dict[str, Dict[str, Any]] = {}


def _new_task(task_type: str) -> str:
    tid = f"{task_type}-{uuid.uuid4().hex[:12]}"
    TASKS[tid] = {
        "task_id": tid, "type": task_type,
        "status": "pending", "result": None, "error": None,
        "created_at": datetime.now().isoformat(timespec="seconds"),
    }
    return tid


# ==================== 请求模型 ====================

class TranslateReq(BaseModel):
    text: str
    target_lang: str = "en"
    source_lang: str = "auto"


class DetectReq(BaseModel):
    text: str


class TMAddReq(BaseModel):
    key: str
    source: str
    translations: Dict[str, str] = Field(default_factory=dict)


class TerminologyAddReq(BaseModel):
    term_id: str
    translations: Dict[str, str] = Field(default_factory=dict)


class ReviewReq(BaseModel):
    reviewer: str = "reviewer"
    approved: bool = True
    score: float = 90.0
    comment: str = ""


class ContentRenderReq(BaseModel):
    template_key: str
    lang: str = "zh-CN"
    params: Dict[str, str] = Field(default_factory=dict)


class QACompareReq(BaseModel):
    source: str
    translated: str
    lang: str = "en"


class CrossBorderAssessReq(BaseModel):
    source_region: str
    dest_region: str
    data_type: str = "general"
    volume_gb: float = 1.0


class RightsSubmitReq(BaseModel):
    data_subject: str
    right_type: str = "access"
    region: str = "CN"
    details: str = ""


class RightsProcessReq(BaseModel):
    action: str = "verify"
    handler: str = ""


class InvoiceCreateReq(BaseModel):
    customer: str
    amount: float
    currency: str = "USD"
    items: List[Dict[str, Any]] = Field(default_factory=list)
    inv_type: str = "electronic"


class SubscribeReq(BaseModel):
    customer_email: str
    plan: str = "basic"
    billing_cycle: str = "monthly"
    coupon: str = ""


class PlanChangeReq(BaseModel):
    new_plan: str


class CurrencyConvertReq(BaseModel):
    amount: float
    from_currency: str = "USD"
    to_currency: str = "CNY"


class TaxCalcReq(BaseModel):
    amount: float
    region: str = "CN"


class SwitchRegionReq(BaseModel):
    region_id: str


class FailoverReq(BaseModel):
    from_region: str
    to_region: str


class PurgeReq(BaseModel):
    url: str = ""


class RouteReq(BaseModel):
    client_ip: str = "8.8.8.8"
    service: str = "api"


class ResolveConflictReq(BaseModel):
    strategy: str = "last_write_wins"


class DeployEdgeReq(BaseModel):
    name: str
    code: str = ""
    region: str = "global"


class TicketCreateReq(BaseModel):
    subject: str
    region: str = "CN"
    priority: str = "medium"


class UpdateSettingReq(BaseModel):
    value: Any = None


class PreferenceReq(BaseModel):
    user_id: str
    lang: str = "zh-CN"


class UIStrAddReq(BaseModel):
    key: str
    translations: Dict[str, str] = Field(default_factory=dict)


class DocCreateReq(BaseModel):
    doc_id: str
    title: str
    content: str
    lang: str = "zh-CN"


class ControlUpdateReq(BaseModel):
    status: str = ""
    evidence: str = ""
    owner: str = ""


# ==================== 概览与健康 ====================

@router.get("/overview")
def get_overview():
    """国际化总览"""
    try:
        c = _check()
        if c:
            return c
        return _ok(globalization_dashboard.overview())
    except Exception as e:
        return _fail(str(e))


@router.get("/health")
def health_check():
    """健康检查"""
    try:
        return _ok({"status": "healthy", "timestamp": datetime.now().isoformat(timespec="seconds"), "modules_loaded": _MODULES_OK})
    except Exception as e:
        return _fail(str(e))


# ==================== 1. 多语言国际化 (i18n_engine) ====================

@router.get("/i18n/languages")
def i18n_list_languages():
    """列出所有支持语言"""
    try:
        c = _check()
        if c:
            return c
        return _ok({"languages": [{"code": k, **v} for k, v in LANGUAGES.items()], "total": len(LANGUAGES)})
    except Exception as e:
        return _fail(str(e))


@router.get("/i18n/languages/{lang_code}")
def i18n_get_language(lang_code: str):
    """获取单个语言详情"""
    try:
        c = _check()
        if c:
            return c
        info = LANGUAGES.get(lang_code)
        if not info:
            return _fail(f"语言 {lang_code} 不存在")
        fmt = LOCALE_FORMATS.get(lang_code, {})
        return _ok({"code": lang_code, **info, "locale_format": fmt})
    except Exception as e:
        return _fail(str(e))


@router.post("/i18n/translate")
def i18n_translate(req: TranslateReq):
    """翻译文本"""
    try:
        c = _check()
        if c:
            return c
        result = i18n_engine.translate(req.text, req.target_lang, req.source_lang)
        return _ok(result)
    except Exception as e:
        return _fail(str(e))


@router.post("/i18n/detect")
def i18n_detect(req: DetectReq):
    """自动语言检测"""
    try:
        c = _check()
        if c:
            return c
        lang = i18n_engine.detector.detect(req.text)
        info = LANGUAGES.get(lang, {})
        return _ok({"detected_language": lang, "name": info.get("name", lang), "confidence": 0.9 if lang != "en" else 0.7})
    except Exception as e:
        return _fail(str(e))


@router.get("/i18n/tm/entries")
def i18n_tm_list():
    """翻译记忆库条目"""
    try:
        c = _check()
        if c:
            return c
        entries = list(i18n_engine.memory.entries.values())
        return _ok({"entries": entries, "total": len(entries)})
    except Exception as e:
        return _fail(str(e))


@router.get("/i18n/tm/search")
def i18n_tm_search(q: str = Query(..., description="搜索文本")):
    """搜索翻译记忆库"""
    try:
        c = _check()
        if c:
            return c
        results = i18n_engine.memory.search(q)
        return _ok({"query": q, "results": results, "total": len(results)})
    except Exception as e:
        return _fail(str(e))


@router.post("/i18n/tm/add")
def i18n_tm_add(req: TMAddReq):
    """添加翻译记忆条目"""
    try:
        c = _check()
        if c:
            return c
        entry = i18n_engine.memory.add(req.key, req.source, req.translations)
        return _ok(entry)
    except Exception as e:
        return _fail(str(e))


@router.get("/i18n/terminology")
def i18n_terminology_list():
    """术语库列表"""
    try:
        c = _check()
        if c:
            return c
        terms = [{"term_id": k, **v} for k, v in i18n_engine.terminology.terms.items()]
        return _ok({"terms": terms, "total": len(terms)})
    except Exception as e:
        return _fail(str(e))


@router.get("/i18n/terminology/search")
def i18n_terminology_search(q: str = Query(...)):
    """搜索术语库"""
    try:
        c = _check()
        if c:
            return c
        results = i18n_engine.terminology.search(q)
        return _ok({"query": q, "results": results, "total": len(results)})
    except Exception as e:
        return _fail(str(e))


@router.post("/i18n/terminology/add")
def i18n_terminology_add(req: TerminologyAddReq):
    """添加术语"""
    try:
        c = _check()
        if c:
            return c
        result = i18n_engine.terminology.add(req.term_id, req.translations)
        return _ok(result)
    except Exception as e:
        return _fail(str(e))


@router.get("/i18n/translations/progress")
def i18n_translation_progress():
    """翻译进度"""
    try:
        c = _check()
        if c:
            return c
        return _ok(i18n_engine.translations.progress())
    except Exception as e:
        return _fail(str(e))


@router.post("/i18n/translations/create")
def i18n_translation_create(lang: str, key: str, source: str, translated: str):
    """创建翻译版本"""
    try:
        c = _check()
        if c:
            return c
        result = i18n_engine.translations.create_version(lang, key, source, translated)
        return _ok(result)
    except Exception as e:
        return _fail(str(e))


@router.post("/i18n/translations/{version_id}/review")
def i18n_translation_review(version_id: str, req: ReviewReq):
    """审核翻译"""
    try:
        c = _check()
        if c:
            return c
        result = i18n_engine.translations.review(version_id, req.reviewer, req.approved, req.score, req.comment)
        return _ok(result)
    except Exception as e:
        return _fail(str(e))


@router.get("/i18n/ui/strings")
def i18n_ui_strings():
    """UI国际化文本"""
    try:
        c = _check()
        if c:
            return c
        return _ok({"strings": i18n_engine.ui.list_keys(), "total": len(i18n_engine.ui.ui_strings)})
    except Exception as e:
        return _fail(str(e))


@router.post("/i18n/ui/strings")
def i18n_ui_add_string(req: UIStrAddReq):
    """添加UI文本"""
    try:
        c = _check()
        if c:
            return c
        result = i18n_engine.ui.add_string(req.key, req.translations)
        return _ok(result)
    except Exception as e:
        return _fail(str(e))


@router.get("/i18n/ui/format")
def i18n_ui_format(dt: str, num: float = 0.0, currency: float = 0.0, lang: str = "zh-CN"):
    """格式化日期/数字/货币"""
    try:
        c = _check()
        if c:
            return c
        return _ok({
            "datetime": i18n_engine.ui.format_datetime(dt, lang),
            "number": i18n_engine.ui.format_number(num, lang),
            "currency": i18n_engine.ui.format_currency(currency, lang),
            "lang": lang,
        })
    except Exception as e:
        return _fail(str(e))


@router.get("/i18n/content/templates")
def i18n_content_templates():
    """内容模板列表"""
    try:
        c = _check()
        if c:
            return c
        return _ok({"templates": i18n_engine.content.list_templates()})
    except Exception as e:
        return _fail(str(e))


@router.post("/i18n/content/render")
def i18n_content_render(req: ContentRenderReq):
    """渲染内容模板"""
    try:
        c = _check()
        if c:
            return c
        rendered = i18n_engine.content.render(req.template_key, req.lang, **req.params)
        return _ok({"template": req.template_key, "lang": req.lang, "rendered": rendered})
    except Exception as e:
        return _fail(str(e))


@router.post("/i18n/content/documents")
def i18n_content_create_doc(req: DocCreateReq):
    """创建多语言文档"""
    try:
        c = _check()
        if c:
            return c
        result = i18n_engine.content.create_document(req.doc_id, req.title, req.content, req.lang)
        return _ok(result)
    except Exception as e:
        return _fail(str(e))


@router.post("/i18n/qa/score")
def i18n_qa_score(req: QACompareReq):
    """翻译质量评分"""
    try:
        c = _check()
        if c:
            return c
        result = i18n_engine.qa.score_translation(req.source, req.translated, req.lang)
        return _ok(result)
    except Exception as e:
        return _fail(str(e))


@router.post("/i18n/qa/check-format")
def i18n_qa_check_format(source: str, translated: str):
    """翻译格式检查"""
    try:
        c = _check()
        if c:
            return c
        result = i18n_engine.qa.check_format(source, translated)
        return _ok(result)
    except Exception as e:
        return _fail(str(e))


@router.post("/i18n/preference")
def i18n_set_preference(req: PreferenceReq):
    """设置语言偏好"""
    try:
        c = _check()
        if c:
            return c
        result = i18n_engine.lang_mgr.set_preference(req.user_id, req.lang)
        return _ok(result)
    except Exception as e:
        return _fail(str(e))


@router.get("/i18n/preference/{user_id}")
def i18n_get_preference(user_id: str):
    """获取语言偏好"""
    try:
        c = _check()
        if c:
            return c
        lang = i18n_engine.lang_mgr.get_preference(user_id)
        resolved = i18n_engine.lang_mgr.resolve(lang)
        return _ok({"user_id": user_id, "preferred": lang, "resolved": resolved})
    except Exception as e:
        return _fail(str(e))


# ==================== 2. 区域合规 (regional_compliance) ====================

@router.get("/compliance/frameworks")
def compliance_frameworks():
    """合规框架库"""
    try:
        c = _check()
        if c:
            return c
        frameworks = [{"code": k, **v} for k, v in COMPLIANCE_FRAMEWORKS.items()]
        return _ok({"frameworks": frameworks, "total": len(frameworks)})
    except Exception as e:
        return _fail(str(e))


@router.get("/compliance/frameworks/{fw_code}")
def compliance_framework_detail(fw_code: str):
    """单个合规框架详情"""
    try:
        c = _check()
        if c:
            return c
        fw = COMPLIANCE_FRAMEWORKS.get(fw_code)
        if not fw:
            return _fail(f"合规框架 {fw_code} 不存在")
        return _ok({"code": fw_code, **fw})
    except Exception as e:
        return _fail(str(e))


@router.get("/compliance/regions")
def compliance_regions():
    """区域→合规框架映射"""
    try:
        c = _check()
        if c:
            return c
        regions = [{"code": k, **v} for k, v in REGION_FRAMEWORK_MAP.items()]
        return _ok({"regions": regions, "total": len(regions)})
    except Exception as e:
        return _fail(str(e))


@router.get("/compliance/matrix")
def compliance_matrix():
    """合规控制矩阵"""
    try:
        c = _check()
        if c:
            return c
        controls = [{"control_id": k, "framework": v.framework, "requirement": v.requirement, "status": v.status, "owner": v.owner, "evidence_count": len(v.evidence)} for k, v in regional_compliance.matrix.controls.items()]
        return _ok({"controls": controls, "total": len(controls)})
    except Exception as e:
        return _fail(str(e))


@router.get("/compliance/gap-analysis")
def compliance_gap_analysis():
    """合规差距分析"""
    try:
        c = _check()
        if c:
            return c
        return _ok(regional_compliance.matrix.gap_analysis())
    except Exception as e:
        return _fail(str(e))


@router.put("/compliance/controls/{control_id}")
def compliance_update_control(control_id: str, req: ControlUpdateReq):
    """更新控制项状态"""
    try:
        c = _check()
        if c:
            return c
        result = regional_compliance.matrix.update_control(control_id, req.status, req.evidence, req.owner)
        return _ok(result)
    except Exception as e:
        return _fail(str(e))


@router.get("/compliance/cross-border/transfers")
def compliance_transfers():
    """跨境数据传输列表"""
    try:
        c = _check()
        if c:
            return c
        return _ok({"transfers": regional_compliance.cross_border.list_transfers(), "total": len(regional_compliance.cross_border.transfers)})
    except Exception as e:
        return _fail(str(e))


@router.post("/compliance/cross-border/assess")
def compliance_assess(req: CrossBorderAssessReq):
    """跨境传输评估"""
    try:
        c = _check()
        if c:
            return c
        result = regional_compliance.cross_border.assess(req.source_region, req.dest_region, req.data_type, req.volume_gb)
        return _ok(result)
    except Exception as e:
        return _fail(str(e))


@router.get("/compliance/rights/requests")
def compliance_rights_requests():
    """隐私权利请求列表"""
    try:
        c = _check()
        if c:
            return c
        return _ok({"requests": list(regional_compliance.rights.requests.values()), "total": len(regional_compliance.rights.requests)})
    except Exception as e:
        return _fail(str(e))


@router.post("/compliance/rights/submit")
def compliance_rights_submit(req: RightsSubmitReq):
    """提交数据主体权利请求"""
    try:
        c = _check()
        if c:
            return c
        result = regional_compliance.rights.submit(req.data_subject, req.right_type, req.region, req.details)
        return _ok(result)
    except Exception as e:
        return _fail(str(e))


@router.post("/compliance/rights/{request_id}/process")
def compliance_rights_process(request_id: str, req: RightsProcessReq):
    """处理权利请求"""
    try:
        c = _check()
        if c:
            return c
        result = regional_compliance.rights.process(request_id, req.action, req.handler)
        return _ok(result)
    except Exception as e:
        return _fail(str(e))


@router.get("/compliance/rights/stats")
def compliance_rights_stats():
    """隐私权利统计"""
    try:
        c = _check()
        if c:
            return c
        return _ok(regional_compliance.rights.stats())
    except Exception as e:
        return _fail(str(e))


@router.get("/compliance/report")
def compliance_report():
    """区域合规报告"""
    try:
        c = _check()
        if c:
            return c
        return _ok(regional_compliance.report.status_report(regional_compliance.matrix))
    except Exception as e:
        return _fail(str(e))


@router.get("/compliance/regulation-changes")
def compliance_regulation_changes():
    """法规变更监控"""
    try:
        c = _check()
        if c:
            return c
        return _ok({"changes": regional_compliance.report.regulation_changes, "total": len(regional_compliance.report.regulation_changes)})
    except Exception as e:
        return _fail(str(e))


# ==================== 3. 国际支付 (global_payment) ====================

@router.get("/payment/methods")
def payment_methods():
    """支付方式列表"""
    try:
        c = _check()
        if c:
            return c
        methods = [{"id": k, **v} for k, v in PAYMENT_METHODS.items()]
        return _ok({"methods": methods, "total": len(methods)})
    except Exception as e:
        return _fail(str(e))


@router.get("/payment/currencies")
def payment_currencies():
    """支持货币列表"""
    try:
        c = _check()
        if c:
            return c
        currencies = [{"code": k, **v} for k, v in CURRENCIES.items()]
        return _ok({"currencies": currencies, "total": len(currencies)})
    except Exception as e:
        return _fail(str(e))


@router.get("/payment/rates")
def payment_rates(base: str = "USD"):
    """实时汇率"""
    try:
        c = _check()
        if c:
            return c
        return _ok({"base": base, "rates": global_payment.exchange.get_rates(base), "timestamp": datetime.now().isoformat(timespec="seconds")})
    except Exception as e:
        return _fail(str(e))


@router.post("/payment/convert")
def payment_convert(req: CurrencyConvertReq):
    """货币兑换"""
    try:
        c = _check()
        if c:
            return c
        result = global_payment.exchange.convert(req.amount, req.from_currency, req.to_currency)
        return _ok(result)
    except Exception as e:
        return _fail(str(e))


@router.get("/payment/rates/history/{currency}")
def payment_rate_history(currency: str, days: int = 30):
    """汇率历史"""
    try:
        c = _check()
        if c:
            return c
        return _ok({"currency": currency, "history": global_payment.exchange.history(currency, days)})
    except Exception as e:
        return _fail(str(e))


@router.post("/payment/tax/calculate")
def payment_tax_calculate(req: TaxCalcReq):
    """税务计算"""
    try:
        c = _check()
        if c:
            return c
        result = global_payment.tax.calculate(req.amount, req.region)
        return _ok(result)
    except Exception as e:
        return _fail(str(e))


@router.get("/payment/tax/report")
def payment_tax_report(period: str = "2026-Q2"):
    """税务报告"""
    try:
        c = _check()
        if c:
            return c
        return _ok(global_payment.tax.tax_report(period))
    except Exception as e:
        return _fail(str(e))


@router.get("/payment/invoices")
def payment_invoices(status: Optional[str] = None):
    """发票列表"""
    try:
        c = _check()
        if c:
            return c
        return _ok({"invoices": global_payment.invoices.list_invoices(status), "total": len(global_payment.invoices.invoices)})
    except Exception as e:
        return _fail(str(e))


@router.post("/payment/invoices")
def payment_invoice_create(req: InvoiceCreateReq):
    """创建发票"""
    try:
        c = _check()
        if c:
            return c
        result = global_payment.invoices.create(req.customer, req.amount, req.currency, req.items, req.inv_type)
        return _ok(result)
    except Exception as e:
        return _fail(str(e))


@router.post("/payment/invoices/{invoice_id}/send")
def payment_invoice_send(invoice_id: str, method: str = "email"):
    """发送发票"""
    try:
        c = _check()
        if c:
            return c
        result = global_payment.invoices.send(invoice_id, method)
        return _ok(result)
    except Exception as e:
        return _fail(str(e))


@router.get("/payment/plans")
def payment_plans():
    """订阅套餐"""
    try:
        c = _check()
        if c:
            return c
        return _ok({"plans": SUBSCRIPTION_PLANS, "total": len(SUBSCRIPTION_PLANS)})
    except Exception as e:
        return _fail(str(e))


@router.get("/payment/subscriptions")
def payment_subscriptions():
    """订阅列表"""
    try:
        c = _check()
        if c:
            return c
        return _ok({"subscriptions": list(global_payment.subscriptions.subscriptions.values()), "stats": global_payment.subscriptions.stats()})
    except Exception as e:
        return _fail(str(e))


@router.post("/payment/subscribe")
def payment_subscribe(req: SubscribeReq):
    """创建订阅"""
    try:
        c = _check()
        if c:
            return c
        result = global_payment.subscriptions.subscribe(req.customer_email, req.plan, req.billing_cycle, req.coupon)
        return _ok(result)
    except Exception as e:
        return _fail(str(e))


@router.post("/payment/subscriptions/{subscription_id}/change")
def payment_change_plan(subscription_id: str, req: PlanChangeReq):
    """变更套餐"""
    try:
        c = _check()
        if c:
            return c
        result = global_payment.subscriptions.change_plan(subscription_id, req.new_plan)
        return _ok(result)
    except Exception as e:
        return _fail(str(e))


@router.post("/payment/subscriptions/{subscription_id}/cancel")
def payment_cancel_sub(subscription_id: str):
    """取消订阅"""
    try:
        c = _check()
        if c:
            return c
        result = global_payment.subscriptions.cancel(subscription_id)
        return _ok(result)
    except Exception as e:
        return _fail(str(e))


@router.get("/payment/financial/income")
def payment_income():
    """收入报告"""
    try:
        c = _check()
        if c:
            return c
        return _ok(global_payment.financial.income_statement())
    except Exception as e:
        return _fail(str(e))


@router.get("/payment/financial/cashflow")
def payment_cashflow():
    """现金流报告"""
    try:
        c = _check()
        if c:
            return c
        return _ok(global_payment.financial.cash_flow())
    except Exception as e:
        return _fail(str(e))


@router.get("/payment/financial/forecast")
def payment_forecast(months: int = 6):
    """财务预测"""
    try:
        c = _check()
        if c:
            return c
        return _ok(global_payment.financial.forecast(months))
    except Exception as e:
        return _fail(str(e))


# ==================== 4. 全球部署 (global_deployment) ====================

@router.get("/deployment/regions")
def deployment_regions():
    """部署区域列表"""
    try:
        c = _check()
        if c:
            return c
        return _ok({"regions": global_deployment.regions.list_regions(), "total": len(DEPLOYMENT_REGIONS)})
    except Exception as e:
        return _fail(str(e))


@router.post("/deployment/switch")
def deployment_switch(req: SwitchRegionReq):
    """切换部署区域"""
    try:
        c = _check()
        if c:
            return c
        result = global_deployment.regions.switch_region(req.region_id)
        return _ok(result)
    except Exception as e:
        return _fail(str(e))


@router.post("/deployment/failover")
def deployment_failover(req: FailoverReq):
    """区域故障转移"""
    try:
        c = _check()
        if c:
            return c
        result = global_deployment.regions.failover(req.from_region, req.to_region)
        return _ok(result)
    except Exception as e:
        return _fail(str(e))


@router.get("/deployment/cdn/nodes")
def cdn_nodes():
    """CDN节点列表"""
    try:
        c = _check()
        if c:
            return c
        return _ok({"nodes": CDN_NODES, "total": len(CDN_NODES)})
    except Exception as e:
        return _fail(str(e))


@router.get("/deployment/cdn/stats")
def cdn_stats():
    """CDN统计"""
    try:
        c = _check()
        if c:
            return c
        return _ok(global_deployment.cdn.stats())
    except Exception as e:
        return _fail(str(e))


@router.post("/deployment/cdn/purge")
def cdn_purge(req: PurgeReq):
    """清除CDN缓存"""
    try:
        c = _check()
        if c:
            return c
        result = global_deployment.cdn.purge_cache(req.url)
        return _ok(result)
    except Exception as e:
        return _fail(str(e))


@router.get("/deployment/loadbalancer/health")
def lb_health():
    """负载均衡健康检查"""
    try:
        c = _check()
        if c:
            return c
        return _ok(global_deployment.load_balancer.health_summary())
    except Exception as e:
        return _fail(str(e))


@router.post("/deployment/loadbalancer/route")
def lb_route(req: RouteReq):
    """智能路由"""
    try:
        c = _check()
        if c:
            return c
        result = global_deployment.load_balancer.route_traffic(req.client_ip, req.service)
        return _ok(result)
    except Exception as e:
        return _fail(str(e))


@router.get("/deployment/sync/status")
def sync_status():
    """数据同步状态"""
    try:
        c = _check()
        if c:
            return c
        return _ok(global_deployment.data_sync.status())
    except Exception as e:
        return _fail(str(e))


@router.post("/deployment/sync/{sync_id}/resolve")
def sync_resolve(sync_id: str, req: ResolveConflictReq):
    """解决数据冲突"""
    try:
        c = _check()
        if c:
            return c
        result = global_deployment.data_sync.resolve_conflict(sync_id, req.strategy)
        return _ok(result)
    except Exception as e:
        return _fail(str(e))


@router.get("/deployment/edge/functions")
def edge_functions():
    """边缘函数列表"""
    try:
        c = _check()
        if c:
            return c
        return _ok({"functions": global_deployment.edge.list_functions(), "stats": global_deployment.edge.stats()})
    except Exception as e:
        return _fail(str(e))


@router.post("/deployment/edge/deploy")
def edge_deploy(req: DeployEdgeReq):
    """部署边缘函数"""
    try:
        c = _check()
        if c:
            return c
        result = global_deployment.edge.deploy_function(req.name, req.code, req.region)
        return _ok(result)
    except Exception as e:
        return _fail(str(e))


@router.get("/deployment/performance")
def deployment_performance():
    """全球性能监控"""
    try:
        c = _check()
        if c:
            return c
        return _ok(global_deployment.performance.report())
    except Exception as e:
        return _fail(str(e))


# ==================== 5. 本地化 (localization) ====================

@router.get("/localization/settings")
def loc_settings():
    """区域设置"""
    try:
        c = _check()
        if c:
            return c
        return _ok({"settings": REGIONAL_SETTINGS, "total": len(REGIONAL_SETTINGS)})
    except Exception as e:
        return _fail(str(e))


@router.get("/localization/holidays")
def loc_holidays(region: Optional[str] = None):
    """节假日"""
    try:
        c = _check()
        if c:
            return c
        if region:
            return _ok({"region": region, "holidays": localization.content.news.get(region, [])})
        from globalization.localization import HOLIDAYS
        return _ok({"holidays": HOLIDAYS, "regions": list(HOLIDAYS.keys())})
    except Exception as e:
        return _fail(str(e))


@router.get("/localization/culture")
def loc_culture():
    """文化适配"""
    try:
        c = _check()
        if c:
            return c
        return _ok({"cultures": CULTURAL_PREFERENCES, "total": len(CULTURAL_PREFERENCES)})
    except Exception as e:
        return _fail(str(e))


@router.get("/localization/news")
def loc_news(region: Optional[str] = None):
    """区域新闻"""
    try:
        c = _check()
        if c:
            return c
        return _ok(localization.content.list_news(region or ""))
    except Exception as e:
        return _fail(str(e))


@router.get("/localization/cases")
def loc_cases():
    """区域案例"""
    try:
        c = _check()
        if c:
            return c
        return _ok({"cases": localization.content.cases, "total": len(localization.content.cases)})
    except Exception as e:
        return _fail(str(e))


@router.get("/localization/partners")
def loc_partners():
    """区域合作伙伴"""
    try:
        c = _check()
        if c:
            return c
        return _ok({"partners": localization.content.partners, "total": len(localization.content.partners)})
    except Exception as e:
        return _fail(str(e))


@router.get("/localization/marketing/campaigns")
def loc_marketing():
    """区域营销活动"""
    try:
        c = _check()
        if c:
            return c
        return _ok(localization.marketing.campaigns_summary())
    except Exception as e:
        return _fail(str(e))


@router.get("/localization/marketing/kol")
def loc_kol():
    """区域KOL"""
    try:
        c = _check()
        if c:
            return c
        return _ok({"kol_list": localization.marketing.kol_list, "total": len(localization.marketing.kol_list)})
    except Exception as e:
        return _fail(str(e))


@router.get("/localization/support/tickets")
def loc_tickets():
    """区域支持工单"""
    try:
        c = _check()
        if c:
            return c
        return _ok({"tickets": list(localization.support.tickets.values()), "stats": localization.support.stats()})
    except Exception as e:
        return _fail(str(e))


@router.post("/localization/support/tickets")
def loc_create_ticket(req: TicketCreateReq):
    """创建支持工单"""
    try:
        c = _check()
        if c:
            return c
        result = localization.support.create_ticket(req.subject, req.region, req.priority)
        return _ok(result)
    except Exception as e:
        return _fail(str(e))


@router.get("/localization/legal/documents")
def loc_legal():
    """区域法律文档"""
    try:
        c = _check()
        if c:
            return c
        return _ok(localization.legal.list_documents())
    except Exception as e:
        return _fail(str(e))


# ==================== 6. 控制台与系统设置 ====================

@router.get("/dashboard/summary")
def dashboard_summary():
    """控制台总览摘要"""
    try:
        c = _check()
        if c:
            return c
        return _ok(globalization_dashboard.overview())
    except Exception as e:
        return _fail(str(e))


@router.get("/dashboard/i18n")
def dashboard_i18n():
    """多语言管理面板"""
    try:
        c = _check()
        if c:
            return c
        return _ok(globalization_dashboard.i18n_summary())
    except Exception as e:
        return _fail(str(e))


@router.get("/dashboard/compliance")
def dashboard_compliance():
    """区域合规面板"""
    try:
        c = _check()
        if c:
            return c
        return _ok(globalization_dashboard.compliance_summary())
    except Exception as e:
        return _fail(str(e))


@router.get("/dashboard/payment")
def dashboard_payment():
    """国际支付面板"""
    try:
        c = _check()
        if c:
            return c
        return _ok(globalization_dashboard.payment_summary())
    except Exception as e:
        return _fail(str(e))


@router.get("/dashboard/deployment")
def dashboard_deployment():
    """全球部署面板"""
    try:
        c = _check()
        if c:
            return c
        return _ok(globalization_dashboard.deployment_summary())
    except Exception as e:
        return _fail(str(e))


@router.get("/dashboard/localization")
def dashboard_localization():
    """本地化面板"""
    try:
        c = _check()
        if c:
            return c
        return _ok(globalization_dashboard.localization_summary())
    except Exception as e:
        return _fail(str(e))


@router.get("/settings")
def get_settings():
    """系统设置"""
    try:
        c = _check()
        if c:
            return c
        return _ok(globalization_dashboard.system_settings())
    except Exception as e:
        return _fail(str(e))


@router.put("/settings/{category}/{key}")
def update_setting(category: str, key: str, req: UpdateSettingReq):
    """更新系统设置"""
    try:
        c = _check()
        if c:
            return c
        result = globalization_dashboard.update_setting(category, key, req.value)
        return _ok(result)
    except Exception as e:
        return _fail(str(e))


@router.get("/tasks/{task_id}")
def get_task(task_id: str):
    """查询异步任务状态"""
    try:
        t = TASKS.get(task_id)
        if not t:
            return _fail("任务不存在")
        return _ok(t)
    except Exception as e:
        return _fail(str(e))
