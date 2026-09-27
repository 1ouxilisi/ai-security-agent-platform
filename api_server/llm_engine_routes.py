#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
LLM智能引擎 API路由 v4.3

端点：
- POST /api/v1/llm/configure — 配置LLM
- GET  /api/v1/llm/stats — 获取使用统计
- POST /api/v1/llm/chat — 通用对话
- POST /api/v1/llm/parse-task — 自然语言任务解析
- POST /api/v1/llm/analyze-vulns — 漏洞智能分析
- POST /api/v1/llm/infer-params — API参数补全
- POST /api/v1/llm/generate-report — 智能报告生成
- POST /api/v1/llm/attack-chain — 攻击链推理
- POST /api/v1/llm/remediation — 修复建议
"""

from fastapi import APIRouter, HTTPException
from pydantic import BaseModel
from typing import Optional, Dict, Any, List

from llm_engine import get_llm_client, LLMConfig, LLMProvider

router = APIRouter(prefix="/api/v1/llm", tags=["LLM智能引擎 v4.3"])


class ConfigureRequest(BaseModel):
    api_key: str = ""
    base_url: str = "https://api.siliconflow.cn/v1"
    model: str = "Qwen/Qwen2.5-7B-Instruct"
    temperature: float = 0.3
    provider: str = "siliconflow"


class ChatRequest(BaseModel):
    message: str
    system_prompt: str = "你是一位网络安全专家助手。"
    temperature: Optional[float] = None


class ParseTaskRequest(BaseModel):
    user_input: str


class AnalyzeVulnsRequest(BaseModel):
    target: str
    findings: List[Dict] = []


class InferParamsRequest(BaseModel):
    url: str
    method: str = "GET"
    existing_params: List = []
    path: str = ""


class GenerateReportRequest(BaseModel):
    target: str
    findings: List[Dict] = []
    duration: float = 0
    tools: List[str] = []


class AttackChainRequest(BaseModel):
    target: str
    findings: List[Dict] = []
    services: List[Dict] = []


class RemediationRequest(BaseModel):
    vulnerabilities: List[Dict] = []


@router.post("/configure")
async def configure_llm(req: ConfigureRequest):
    """配置LLM参数"""
    try:
        client = get_llm_client()
        provider_map = {
            "siliconflow": LLMProvider.SILICONFLOW,
            "openai": LLMProvider.OPENAI,
            "ollama": LLMProvider.OLLAMA,
            "custom": LLMProvider.CUSTOM,
        }
        client.configure(
            api_key=req.api_key,
            model=req.model,
            base_url=req.base_url,
            provider=provider_map.get(req.provider, LLMProvider.SILICONFLOW),
        )
        client.config.temperature = req.temperature
        return {"success": True, "data": client.get_stats()}
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@router.get("/stats")
async def get_stats():
    """获取LLM使用统计"""
    try:
        client = get_llm_client()
        return {"success": True, "data": client.get_stats()}
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@router.post("/chat")
async def chat(req: ChatRequest):
    """通用对话"""
    try:
        client = get_llm_client()
        response = client.chat_with_system(
            req.system_prompt, req.message,
            temperature=req.temperature,
        )
        if not response.success:
            return {"success": False, "error": response.error, "data": None}
        return {
            "success": True,
            "data": {
                "content": response.content,
                "model": response.model,
                "usage": response.usage,
                "latency_ms": response.latency_ms,
            }
        }
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@router.post("/parse-task")
async def parse_task(req: ParseTaskRequest):
    """自然语言任务解析"""
    try:
        client = get_llm_client()
        if not client.config.api_key:
            # 无API Key时使用规则回退
            result = _rule_based_task_parse(req.user_input)
            return {"success": True, "data": result}
        result = client.parse_task(req.user_input)
        if result.get("error"):
            # LLM失败时回退规则
            result = _rule_based_task_parse(req.user_input)
        return {"success": True, "data": result}
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@router.post("/analyze-vulns")
async def analyze_vulnerabilities(req: AnalyzeVulnsRequest):
    """漏洞智能分析"""
    try:
        client = get_llm_client()
        if not client.config.api_key:
            return {"success": False, "error": "请先配置LLM API Key", "data": None}
        result = client.analyze_vulnerabilities(req.target, req.findings)
        return {"success": True, "data": result}
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@router.post("/infer-params")
async def infer_parameters(req: InferParamsRequest):
    """API参数智能补全"""
    try:
        client = get_llm_client()
        if not client.config.api_key:
            return {"success": False, "error": "请先配置LLM API Key", "data": None}
        result = client.infer_api_parameters(
            req.url, req.method, req.existing_params, req.path
        )
        return {"success": True, "data": result}
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@router.post("/generate-report")
async def generate_report(req: GenerateReportRequest):
    """智能报告生成"""
    try:
        client = get_llm_client()
        if not client.config.api_key:
            return {"success": False, "error": "请先配置LLM API Key", "data": None}
        report = client.generate_report(
            req.target, req.findings, req.duration, req.tools
        )
        return {"success": True, "data": {"report": report}}
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@router.post("/attack-chain")
async def attack_chain(req: AttackChainRequest):
    """攻击链推理"""
    try:
        client = get_llm_client()
        if not client.config.api_key:
            return {"success": False, "error": "请先配置LLM API Key", "data": None}
        result = client.reason_attack_chain(req.target, req.findings, req.services)
        return {"success": True, "data": {"analysis": result}}
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@router.post("/remediation")
async def get_remediation(req: RemediationRequest):
    """修复建议生成"""
    try:
        client = get_llm_client()
        if not client.config.api_key:
            return {"success": False, "error": "请先配置LLM API Key", "data": None}
        result = client.get_remediation(req.vulnerabilities)
        return {"success": True, "data": {"remediation": result}}
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


def _rule_based_task_parse(user_input: str) -> Dict:
    """基于规则的任务解析（LLM不可用时的回退）"""
    text = user_input.lower()
    result = {
        "task_type": "unknown",
        "target": "",
        "parameters": {},
        "aggressive": False,
        "description": user_input,
        "estimated_time": "未知",
    }

    # 提取URL/IP/域名
    import re
    url_match = re.search(r'https?://[^\s]+', user_input)
    ip_match = re.search(r'\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b', user_input)
    domain_match = re.search(r'\b([a-zA-Z0-9][-a-zA-Z0-9]*\.[a-zA-Z]{2,}(?:\.[a-zA-Z]{2,})?)\b', user_input)
    if url_match:
        result["target"] = url_match.group()
    elif ip_match:
        result["target"] = ip_match.group()
    elif domain_match:
        result["target"] = domain_match.group()

    # 任务类型判断
    if any(kw in text for kw in ['端口扫描', 'port scan', '扫描端口', 'nmap']):
        result["task_type"] = "port_scan"
        result["estimated_time"] = "1-3分钟"
    elif any(kw in text for kw in ['web漏洞', 'web扫描', 'web scan', '网站扫描', '渗透测试网站']):
        result["task_type"] = "web_scan"
        result["estimated_time"] = "3-5分钟"
    elif any(kw in text for kw in ['api', '接口测试', '接口安全']):
        result["task_type"] = "api_pentest"
        result["estimated_time"] = "5-10分钟"
    elif any(kw in text for kw in ['信息收集', 'recon', '侦察']):
        result["task_type"] = "recon"
        result["estimated_time"] = "2-5分钟"
    elif any(kw in text for kw in ['报告', 'report', '生成报告']):
        result["task_type"] = "report"
        result["estimated_time"] = "1分钟"
    elif any(kw in text for kw in ['攻击链', 'attack chain', '攻击路径']):
        result["task_type"] = "attack_chain"
        result["estimated_time"] = "1分钟"
    elif any(kw in text for kw in ['修复', 'remediation', '加固']):
        result["task_type"] = "remediation"
        result["estimated_time"] = "1分钟"
    elif any(kw in text for kw in ['完整渗透', 'full pentest', '全面测试']):
        result["task_type"] = "full_pentest"
        result["estimated_time"] = "10-30分钟"
    elif any(kw in text for kw in ['移动', 'mobile', 'apk', 'app']):
        result["task_type"] = "mobile_audit"
        result["estimated_time"] = "5-15分钟"
    else:
        result["task_type"] = "web_scan"
        result["estimated_time"] = "3-5分钟"

    # 激进模式
    if any(kw in text for kw in ['激进', 'aggressive', '深入', '全面']):
        result["aggressive"] = True

    return result
