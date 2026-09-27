"""
攻击面管理（ASM）API路由
提供资产发现、暴露面评估、攻击路径分析、风险优先级排序的REST API
"""
from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel
from typing import Optional, Dict, Any
import sys
import os

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

router = APIRouter(prefix="/api/v1/asm", tags=["攻击面管理ASM"])

# ASM管理器单例
_asm_manager = None

def get_asm_manager():
    global _asm_manager
    if _asm_manager is None:
        from asm.asm_manager import ASMManager
        _asm_manager = ASMManager()
    return _asm_manager


# 请求模型
class FullAssessmentRequest(BaseModel):
    target: str
    options: Optional[Dict[str, Any]] = None
    business_context: Optional[Dict[str, Any]] = None


class QuickScanRequest(BaseModel):
    target: str


class AssetDiscoveryRequest(BaseModel):
    target: str
    options: Optional[Dict[str, Any]] = None


class CompareReportsRequest(BaseModel):
    report_id1: str
    report_id2: str


@router.post("/full-assessment")
async def full_assessment(request: FullAssessmentRequest):
    """运行完整攻击面评估（资产发现→暴露面评估→攻击路径分析→风险排序）"""
    try:
        manager = get_asm_manager()
        result = manager.run_full_assessment(
            target=request.target,
            options=request.options,
            business_context=request.business_context
        )
        return {"status": "success", "report": result}
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"评估失败: {str(e)}")


@router.post("/quick-scan")
async def quick_scan(request: QuickScanRequest):
    """快速扫描（资产发现+端口评估）"""
    try:
        manager = get_asm_manager()
        result = manager.quick_scan(target=request.target)
        return {"status": "success", "result": result}
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"快速扫描失败: {str(e)}")


@router.post("/asset-discovery")
async def asset_discovery(request: AssetDiscoveryRequest):
    """资产发现（单独调用）"""
    try:
        from asm.asset_discovery import AssetDiscoveryEngine
        engine = AssetDiscoveryEngine()
        result = engine.discover_all(target=request.target, options=request.options)
        return {"status": "success", "result": result}
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"资产发现失败: {str(e)}")


@router.get("/history")
async def get_history(limit: int = 20):
    """获取扫描历史"""
    try:
        manager = get_asm_manager()
        history = manager.get_history(limit=limit)
        return {"status": "success", "total": len(history), "history": history}
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"获取历史失败: {str(e)}")


@router.get("/report/{report_id}")
async def get_report(report_id: str):
    """获取指定报告详情"""
    try:
        manager = get_asm_manager()
        report = manager.get_report(report_id)
        if not report:
            raise HTTPException(status_code=404, detail="报告不存在")
        return {"status": "success", "report": report}
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"获取报告失败: {str(e)}")


@router.post("/compare-reports")
async def compare_reports(request: CompareReportsRequest):
    """对比两次扫描结果"""
    try:
        manager = get_asm_manager()
        result = manager.compare_reports(request.report_id1, request.report_id2)
        if "error" in result:
            raise HTTPException(status_code=404, detail=result["error"])
        return {"status": "success", "comparison": result}
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"对比失败: {str(e)}")


@router.get("/status")
async def asm_status():
    """ASM模块状态"""
    return {
        "status": "running",
        "version": "1.0.0",
        "modules": {
            "asset_discovery": "available",
            "exposure_assessment": "available",
            "attack_path_analysis": "available",
            "risk_prioritization": "available"
        },
        "capabilities": [
            "资产自动发现（域名/子域名/IP/端口/服务/云存储桶）",
            "暴露面风险评估（端口风险/服务风险/证书风险/配置风险）",
            "攻击路径分析（ATT&CK战术映射/攻击链建模/入口点识别）",
            "风险优先级排序（CVSS/可利用性/业务影响/暴露程度多维度）",
            "扫描历史管理与结果对比",
            "执行摘要与修复计划生成"
        ]
    }
