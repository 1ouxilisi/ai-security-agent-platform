# -*- coding: utf-8 -*-
"""
api_server/llm_config_real_routes.py — 真实 LLM Key 配置引导 API

路由前缀：/api/v1/llm-real-config
统一响应：{success, data, error}
"""
from __future__ import annotations

from typing import Any, Dict, List, Optional

from fastapi import APIRouter
from fastapi.responses import JSONResponse
from pydantic import BaseModel, Field

from llm_config import llm_providers
from llm_config import llm_tester
from llm_config import llm_usage
from llm_config import llm_model_comparison
from llm_config.llm_config_manager import get_config_manager
from llm_config.llm_dashboard import get_dashboard

router = APIRouter(prefix="/api/v1/llm-real-config", tags=["LLM配置引导"])


def _ok(data: Any = None) -> JSONResponse:
    return JSONResponse({"success": True, "data": data, "error": None})


def _err(status: int, message: str, data: Any = None) -> JSONResponse:
    return JSONResponse({"success": False, "data": data, "error": message},
                        status_code=status)


class SaveKeyBody(BaseModel):
    provider: str
    api_key: str
    base_url: Optional[str] = None
    model: Optional[str] = None
    temperature: float = Field(0.7, ge=0.0, le=2.0)
    max_tokens: int = Field(4096, ge=256, le=128000)
    timeout: int = Field(60, ge=1, le=300)
    retries: int = Field(3, ge=0, le=10)
    proxy: Optional[str] = None


class TestKeyBody(BaseModel):
    provider: str
    api_key: Optional[str] = None
    base_url: Optional[str] = None
    model: Optional[str] = None
    timeout: int = 60
    prompt: str = "Hello"


class DefaultBody(BaseModel):
    provider: str


class CompareCase(BaseModel):
    provider: str
    api_key: str
    model: Optional[str] = None
    base_url: Optional[str] = None


class CompareBody(BaseModel):
    cases: List[CompareCase]
    prompt: str = "用一句话解释 SQL 注入。"


# ---------------------------------------------------------------------------
# 仪表盘
# ---------------------------------------------------------------------------
@router.get("/dashboard", summary="LLM 仪表盘")
def dashboard():
    return _ok(get_dashboard())


@router.get("/notice", summary="安全提示")
def notice():
    return _ok({"notice": get_dashboard()["notice"]})


@router.get("/ping", summary="健康检查")
def ping():
    return _ok({"pong": True, "module": "llm-real-config"})


# ---------------------------------------------------------------------------
# 提供商 / 模型
# ---------------------------------------------------------------------------
@router.get("/providers", summary="支持的提供商清单")
def providers():
    return _ok({"providers": llm_providers.list_providers()})


@router.get("/providers/{pid}", summary="单个提供商详情")
def provider_detail(pid: str):
    p = llm_providers.get_provider(pid)
    if not p:
        return _err(404, f"未知提供商 {pid}")
    return _ok(p)


@router.get("/providers/{pid}/models", summary="提供商模型列表")
def provider_models(pid: str):
    p = llm_providers.get_provider(pid)
    if not p:
        return _err(404, f"未知提供商 {pid}")
    return _ok({"provider": pid, "models": p["models"]})


@router.get("/providers/{pid}/apply-hint", summary="申请 Key 引导")
def apply_hint(pid: str):
    p = llm_providers.get_provider(pid)
    if not p:
        return _err(404, f"未知提供商 {pid}")
    return _ok({"provider": pid, "apply_url": p["apply_url"],
                "free_quota": p.get("free_quota"), "docs": p.get("docs")})


# ---------------------------------------------------------------------------
# Key 管理
# ---------------------------------------------------------------------------
@router.get("/keys", summary="已配置 Key 列表（脱敏）")
def list_keys():
    return _ok({"keys": get_config_manager().list_keys_masked()})


@router.get("/keys/status", summary="Key 总状态")
def keys_status():
    return _ok(get_config_manager().status())


@router.post("/keys", summary="保存/更新 Key")
def save_key(body: SaveKeyBody):
    r = get_config_manager().save_key(
        body.provider, body.api_key, body.base_url, body.model,
        body.temperature, body.max_tokens, body.timeout, body.retries,
        body.proxy)
    return _ok(r)


@router.delete("/keys/{pid}", summary="删除 Key")
def delete_key(pid: str):
    ok = get_config_manager().delete_key(pid)
    if not ok:
        return _err(404, "Key 不存在")
    return _ok({"deleted": True})


@router.post("/keys/default", summary="设为默认 Key")
def set_default(body: DefaultBody):
    ok = get_config_manager().set_default(body.provider)
    if not ok:
        return _err(400, "请先保存该提供商的 Key")
    return _ok({"default": body.provider})


@router.get("/keys/default", summary="获取默认 Key 配置（脱敏）")
def get_default():
    cm = get_config_manager()
    st = cm.status()
    pid = st.get("default_provider")
    if not pid:
        return _ok({"configured": False})
    for k in cm.list_keys_masked():
        if k["provider"] == pid:
            return _ok({"configured": True, **k})
    return _ok({"configured": False})


@router.get("/keys/{pid}/clear", summary="获取明文 Key（本机用）")
def get_clear(pid: str):
    return _ok(get_config_manager().get_clear_key(pid))


# ---------------------------------------------------------------------------
# 测试
# ---------------------------------------------------------------------------
@router.post("/test", summary="测试 Key（真实 HTTP）")
def test_key(body: TestKeyBody):
    cm = get_config_manager()
    api_key = body.api_key
    base_url = body.base_url
    model = body.model
    timeout = body.timeout
    if not api_key:
        clear = cm.get_clear_key(body.provider)
        if not clear.get("configured"):
            return _err(400, "未提供 Key 且未保存该提供商配置")
        api_key = clear["api_key"]
        base_url = base_url or clear.get("base_url")
        model = model or clear.get("model")
        timeout = clear.get("timeout", timeout)
    r = llm_tester.test_key(body.provider, api_key, base_url, model,
                            timeout, prompt=body.prompt)
    if r.get("success"):
        llm_usage.record_call(body.provider, r.get("model", ""),
                              r.get("prompt_tokens") or 0,
                              r.get("completion_tokens") or 0,
                              r.get("elapsed_ms") or 0)
    return _ok(r)


@router.post("/test/{pid}", summary="测试已保存的 Key")
def test_saved(pid: str, prompt: str = "Hello"):
    clear = get_config_manager().get_clear_key(pid)
    if not clear.get("configured"):
        return _err(400, "未配置")
    r = llm_tester.test_key(pid, clear["api_key"], clear.get("base_url"),
                            clear.get("model"), clear.get("timeout", 60),
                            prompt=prompt)
    return _ok(r)


# ---------------------------------------------------------------------------
# 用量
# ---------------------------------------------------------------------------
@router.get("/usage/24h", summary="24 小时用量")
def usage_24h():
    return _ok(llm_usage.stats_range(86400))


@router.get("/usage/7d", summary="7 天用量")
def usage_7d():
    return _ok(llm_usage.stats_range(86400 * 7))


@router.get("/usage/30d", summary="30 天用量")
def usage_30d():
    return _ok(llm_usage.stats_range(86400 * 30))


@router.get("/usage/all", summary="全部用量")
def usage_all():
    return _ok(llm_usage.stats_range(10 ** 9))


@router.post("/usage/clear", summary="清空用量记录")
def usage_clear():
    return _ok({"cleared": llm_usage.clear()})


@router.get("/usage/prices", summary="单价表")
def prices():
    return _ok(llm_usage.PRICE_TABLE)


# ---------------------------------------------------------------------------
# 模型对比
# ---------------------------------------------------------------------------
@router.post("/compare", summary="多模型对比")
def compare(body: CompareBody):
    cases = [c.model_dump() for c in body.cases]
    r = llm_model_comparison.compare_models(cases, body.prompt)
    return _ok(r)


@router.get("/recommend/{scene}", summary="按场景推荐模型")
def recommend(scene: str):
    return _ok(llm_model_comparison.recommend_model(scene))


@router.get("/recommend", summary="场景推荐列表")
def recommend_all():
    scenes = ["code", "chat", "reasoning", "long", "local"]
    return _ok({s: llm_model_comparison.recommend_model(s) for s in scenes})


# ---------------------------------------------------------------------------
# 导入导出
# ---------------------------------------------------------------------------
@router.get("/export", summary="加密导出配置")
def export():
    return _ok(get_config_manager().export_encrypted())


@router.post("/import", summary="导入配置")
def import_cfg(data: Dict[str, Any]):
    n = get_config_manager().import_config(data)
    return _ok({"imported": n})


# ---------------------------------------------------------------------------
# 未配置引导
# ---------------------------------------------------------------------------
@router.get("/guide", summary="未配置引导")
def guide():
    cm = get_config_manager()
    st = cm.status()
    return _ok({
        "any_configured": st["any_configured"],
        "default_provider": st.get("default_provider"),
        "next_step": "请在 /llm-config 页面选择一个提供商并填入 API Key，"
                     "或先完成下方免费试用引导。" if not st["any_configured"]
                     else "已配置，可直接使用 AI 功能。",
        "free_trial": [p for p in llm_providers.list_providers()
                       if p.get("free_quota")],
    })


@router.get("/scaffold", summary="一页纸配置检查清单")
def scaffold():
    return _ok({
        "steps": [
            "1. 选择一个提供商（推荐 DeepSeek / 通义千问，性价比高）",
            "2. 打开 apply_url 注册并创建 API Key",
            "3. 粘贴 Key 到本页面并保存（自动加密存储）",
            "4. 点击「测试 Key」验证连通性",
            "5. 设为默认 Key，AI 功能自动生效",
        ],
        "encryption": "Fernet / XOR 兜底，本机机器密钥派生，不明文落盘",
    })


@router.get("/models-all", summary="所有提供商所有模型")
def models_all():
    return _ok({p["id"]: p["models"] for p in llm_providers.list_providers()})


@router.get("/count", summary="统计")
def count():
    st = get_config_manager().status()
    return _ok({"providers": len(llm_providers.list_providers()),
                "configured": st["total_configured"]})


@router.post("/rotate/{pid}", summary="轮换 Key（提示重新填写）")
def rotate(pid: str):
    return _ok({"provider": pid,
                "message": f"请重新调用 POST /keys 更新 {pid} 的 Key",
                "old_kept_until_overwrite": True})


@router.post("/record", summary="手动记录一次用量")
def record_usage(body: Dict[str, Any]):
    r = llm_usage.record_call(
        body.get("provider", "unknown"), body.get("model", "unknown"),
        int(body.get("prompt_tokens", 0)),
        int(body.get("completion_tokens", 0)),
        int(body.get("latency_ms", 0)),
        bool(body.get("success", True)))
    return _ok(r)


@router.get("/keys/{pid}/masked", summary="查看单个 Key（脱敏）")
def key_masked(pid: str):
    for k in get_config_manager().list_keys_masked():
        if k["provider"] == pid:
            return _ok(k)
    return _err(404, "未配置")


@router.delete("/keys-clear-all", summary="清空所有 Key")
def clear_all():
    st = get_config_manager().status()
    n = 0
    for k in st["keys"]:
        get_config_manager().delete_key(k["provider"])
        n += 1
    return _ok({"cleared": n})


@router.get("/usage/trend", summary="用量趋势（按天）")
def usage_trend(days: int = 7):
    data = llm_usage.stats_range(86400 * days)
    return _ok({"days": days, "summary": data})


@router.get("/usage/cost-summary", summary="费用汇总")
def cost_summary():
    data = llm_usage.stats_range(10 ** 9)
    return _ok({"total_cost_usd": data["total_cost_usd"],
                "by_provider": data["by_provider"]})


@router.get("/usage/by-model", summary="按模型聚合")
def usage_by_model():
    data = llm_usage.stats_range(10 ** 9)
    models: Dict[str, Dict[str, Any]] = {}
    for r in data["recent"]:
        m = r["model"]
        a = models.setdefault(m, {"calls": 0, "tokens": 0, "cost": 0.0})
        a["calls"] += 1
        a["tokens"] += r["total_tokens"]
        a["cost"] += r["cost_usd"]
    return _ok(models)


@router.post("/test-batch", summary="批量测试已保存的所有 Key")
def test_batch():
    results = []
    for k in get_config_manager().list_keys_masked():
        clear = get_config_manager().get_clear_key(k["provider"])
        if clear.get("configured"):
            r = llm_tester.test_key(
                k["provider"], clear["api_key"], clear.get("base_url"),
                clear.get("model"), clear.get("timeout", 60))
            results.append({"provider": k["provider"], "result": r})
    return _ok({"results": results})


@router.get("/providers/{pid}/docs", summary="提供商文档链接")
def provider_docs(pid: str):
    p = llm_providers.get_provider(pid)
    if not p:
        return _err(404, "未知提供商")
    return _ok({"docs": p.get("docs"), "apply_url": p.get("apply_url"),
                "free_quota": p.get("free_quota")})


@router.post("/compare/saved", summary="用已保存的 Key 做对比")
def compare_saved(prompt: str = "用一句话解释 SQL 注入。"):
    cases = []
    for k in get_config_manager().list_keys_masked():
        clear = get_config_manager().get_clear_key(k["provider"])
        if clear.get("configured"):
            cases.append({"provider": k["provider"],
                          "api_key": clear["api_key"],
                          "model": clear.get("model"),
                          "base_url": clear.get("base_url")})
    if not cases:
        return _err(400, "没有已配置的 Key")
    return _ok(llm_model_comparison.compare_models(cases, prompt))


@router.get("/health", summary="LLM 模块健康")
def health():
    st = get_config_manager().status()
    return _ok({"configured": st["any_configured"],
                "default": st.get("default_provider"),
                "encryption": st.get("encryption")})


@router.post("/quick-chat", summary="用默认 Key 发一次对话")
def quick_chat(message: str = "你好"):
    clear = get_config_manager().get_clear_key()
    if not clear.get("configured"):
        return _err(400, "未配置默认 Key")
    r = llm_tester.test_key(clear["provider"], clear["api_key"],
                             clear.get("base_url"), clear.get("model"),
                             clear.get("timeout", 60), prompt=message)
    return _ok(r)


@router.get("/keys/list-saved", summary="已保存 Key 完整列表")
def list_saved():
    return _ok({"keys": get_config_manager().list_keys_masked()})
