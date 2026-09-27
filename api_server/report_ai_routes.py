"""
报告AI分析增强API路由（第二轮升级）
- /api/v1/report-ai/analyze - 漏洞关联分析+攻击链推理+业务影响评估
- /api/v1/report-ai/relations - 仅漏洞关联分析
- /api/v1/report-ai/attack-paths - 仅攻击链推理
- /api/v1/report-ai/business-impact - 仅业务影响评估
- /api/v1/report-ai/mitre-mapping - MITRE ATT&CK映射
"""

from fastapi import APIRouter, HTTPException, Header
from pydantic import BaseModel
from typing import Optional, Dict, Any, List
import sys
import os

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from asm.report_ai_analyzer import ReportAIAnalyzer

router = APIRouter(prefix="/api/v1/report-ai", tags=["报告AI分析增强"])

API_AUTH_KEY = os.getenv("API_AUTH_KEY", "cF_fK3wzzFd3sDU-WykQzDbAKNhn_Jjoyphbmh-adLtwx5ShhU8oLpt94aV_uECT")


def verify_api_key(x_api_key: Optional[str] = Header(None)):
    if x_api_key != API_AUTH_KEY:
        raise HTTPException(status_code=401, detail="无效的API Key")
    return True


class VulnerabilityItem(BaseModel):
    id: str
    name: str
    severity: str  # critical/high/medium/low/info
    category: str
    url: Optional[str] = ""
    description: Optional[str] = ""


class AnalyzeRequest(BaseModel):
    vulnerabilities: List[VulnerabilityItem]


@router.post("/analyze")
async def analyze_all(
    request: AnalyzeRequest,
    x_api_key: Optional[str] = Header(None)
):
    """完整AI分析：漏洞关联+攻击链推理+业务影响+风险优先级+MITRE映射"""
    verify_api_key(x_api_key)
    try:
        analyzer = ReportAIAnalyzer()
        vuln_data = [v.model_dump() for v in request.vulnerabilities]
        analyzer.load_vulnerabilities(vuln_data)
        result = analyzer.analyze_all()
        return {
            "status": "success",
            "vulnerability_count": len(vuln_data),
            "result": result
        }
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@router.post("/relations")
async def analyze_relations(
    request: AnalyzeRequest,
    x_api_key: Optional[str] = Header(None)
):
    """仅漏洞关联分析（同组件/可链式/同URL/同类别）"""
    verify_api_key(x_api_key)
    try:
        analyzer = ReportAIAnalyzer()
        vuln_data = [v.model_dump() for v in request.vulnerabilities]
        analyzer.load_vulnerabilities(vuln_data)
        relations = analyzer._analyze_relations()
        return {
            "status": "success",
            "vulnerability_count": len(vuln_data),
            "relation_count": len(relations),
            "relations": relations
        }
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@router.post("/attack-paths")
async def analyze_attack_paths(
    request: AnalyzeRequest,
    x_api_key: Optional[str] = Header(None)
):
    """仅攻击链推理（经典Web攻击链/认证绕过/文件上传GetShell）"""
    verify_api_key(x_api_key)
    try:
        analyzer = ReportAIAnalyzer()
        vuln_data = [v.model_dump() for v in request.vulnerabilities]
        analyzer.load_vulnerabilities(vuln_data)
        paths = analyzer._infer_attack_paths()
        return {
            "status": "success",
            "vulnerability_count": len(vuln_data),
            "attack_path_count": len(paths),
            "attack_paths": paths
        }
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@router.post("/business-impact")
async def analyze_business_impact(
    request: AnalyzeRequest,
    x_api_key: Optional[str] = Header(None)
):
    """仅业务影响评估（影响领域/潜在损害/合规问题/恢复时间）"""
    verify_api_key(x_api_key)
    try:
        analyzer = ReportAIAnalyzer()
        vuln_data = [v.model_dump() for v in request.vulnerabilities]
        analyzer.load_vulnerabilities(vuln_data)
        impacts = analyzer._assess_business_impact()
        return {
            "status": "success",
            "vulnerability_count": len(vuln_data),
            "business_impacts": impacts
        }
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@router.post("/mitre-mapping")
async def mitre_mapping(
    request: AnalyzeRequest,
    x_api_key: Optional[str] = Header(None)
):
    """MITRE ATT&CK映射（20个漏洞类别到MITRE技术）"""
    verify_api_key(x_api_key)
    try:
        analyzer = ReportAIAnalyzer()
        vuln_data = [v.model_dump() for v in request.vulnerabilities]
        analyzer.load_vulnerabilities(vuln_data)
        mapping = analyzer._map_mitre_attack()
        return {
            "status": "success",
            "vulnerability_count": len(vuln_data),
            "mitre_mapping": mapping
        }
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))
