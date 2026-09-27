"""
被动资产积累API路由（第二轮升级）
- /api/v1/passive-assets/record - 记录扫描结果
- /api/v1/passive-assets/profile/{target} - 获取资产画像
- /api/v1/passive-assets/trend/{target} - 获取趋势分析
- /api/v1/passive-assets/assets - 获取所有资产
- /api/v1/passive-assets/changes - 获取最近变更事件
- /api/v1/passive-assets/statistics - 获取全局统计
"""

from fastapi import APIRouter, HTTPException, Header, Query
from pydantic import BaseModel
from typing import Optional, Dict, Any, List
import sys
import os

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from asm.passive_asset_manager import PassiveAssetManager

router = APIRouter(prefix="/api/v1/passive-assets", tags=["被动资产积累"])

API_AUTH_KEY = os.getenv("API_AUTH_KEY", "cF_fK3wzzFd3sDU-WykQzDbAKNhn_Jjoyphbmh-adLtwx5ShhU8oLpt94aV_uECT")

DB_PATH = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "data", "passive_assets.db")


def verify_api_key(x_api_key: Optional[str] = Header(None)):
    if x_api_key != API_AUTH_KEY:
        raise HTTPException(status_code=401, detail="无效的API Key")
    return True


def get_manager():
    return PassiveAssetManager(db_path=DB_PATH)


class RecordScanRequest(BaseModel):
    target: str
    scan_type: str = "full_scan"
    result: Dict[str, Any]
    duration: float = 0


@router.post("/record")
async def record_scan(
    request: RecordScanRequest,
    x_api_key: Optional[str] = Header(None)
):
    """记录扫描结果（自动检测变更并生成变更事件）"""
    verify_api_key(x_api_key)
    try:
        manager = get_manager()
        scan_id = manager.record_scan(request.target, request.scan_type, request.result, request.duration)
        return {
            "status": "success",
            "scan_id": scan_id,
            "target": request.target,
            "message": "扫描结果已记录，变更检测已完成"
        }
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@router.get("/profile/{target}")
async def get_asset_profile(
    target: str,
    x_api_key: Optional[str] = Header(None)
):
    """获取资产画像（基本信息+扫描历史+变更历史+漏洞统计+端口趋势）"""
    verify_api_key(x_api_key)
    try:
        manager = get_manager()
        profile = manager.get_asset_profile(target)
        if not profile:
            raise HTTPException(status_code=404, detail="资产不存在")
        return {
            "status": "success",
            "target": target,
            "profile": profile
        }
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@router.get("/trend/{target}")
async def get_trend_analysis(
    target: str,
    days: int = Query(30, description="分析天数"),
    x_api_key: Optional[str] = Header(None)
):
    """获取趋势分析（扫描趋势/端口数量趋势/漏洞数量趋势/变更统计）"""
    verify_api_key(x_api_key)
    try:
        manager = get_manager()
        trend = manager.get_trend_analysis(target, days=days)
        return {
            "status": "success",
            "target": target,
            "days": days,
            "trend": trend
        }
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@router.get("/assets")
async def get_all_assets(x_api_key: Optional[str] = Header(None)):
    """获取所有资产列表"""
    verify_api_key(x_api_key)
    try:
        manager = get_manager()
        assets = manager.get_all_assets()
        return {
            "status": "success",
            "total": len(assets),
            "assets": assets
        }
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@router.get("/changes")
async def get_recent_changes(
    limit: int = Query(50, description="返回数量"),
    x_api_key: Optional[str] = Header(None)
):
    """获取最近变更事件（新资产/新端口/新漏洞/服务变化等8种类型）"""
    verify_api_key(x_api_key)
    try:
        manager = get_manager()
        changes = manager.get_recent_changes(limit=limit)
        return {
            "status": "success",
            "total": len(changes),
            "changes": changes
        }
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@router.get("/statistics")
async def get_statistics(x_api_key: Optional[str] = Header(None)):
    """获取全局统计（总资产/总扫描/总变更/漏洞分布）"""
    verify_api_key(x_api_key)
    try:
        manager = get_manager()
        stats = manager.get_statistics()
        return {
            "status": "success",
            "statistics": stats
        }
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))
