"""
专业报告引擎v2 API路由 - CVSS评分 + 修复建议库 + 多格式报告
- /api/v1/report-v2/generate - 生成报告
- /api/v1/report-v2/cvss/score - CVSS评分
- /api/v1/report-v2/cvss/parse - 解析CVSS向量
- /api/v1/report-v2/remediation/list - 修复建议列表
- /api/v1/report-v2/remediation/{type} - 获取修复方案
- /api/v1/report-v2/finding/add - 添加漏洞发现
"""
from fastapi import APIRouter, HTTPException, Header
from pydantic import BaseModel
from typing import Optional, Dict, Any, List
import sys
import os

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from report_engine_v2 import ReportGenerator, CVSSScorer, RemediationLibrary, CVSSMetrics

router = APIRouter(prefix="/api/v1/report-v2", tags=["报告引擎v2"])

API_AUTH_KEY = os.getenv("API_AUTH_KEY", "cF_fK3wzzFd3sDU-WykQzDbAKNhn_Jjoyphbmh-adLtwx5ShhU8oLpt94aV_uECT")

_generator = ReportGenerator()
_scorer = CVSSScorer()
_remediation = RemediationLibrary()

_reports = {}


def verify_api_key(x_api_key: Optional[str] = Header(None)):
    if x_api_key != API_AUTH_KEY:
        raise HTTPException(status_code=401, detail="无效的API Key")
    return True


class CVSSScoreRequest(BaseModel):
    attack_vector: str = "N"
    attack_complexity: str = "L"
    privileges_required: str = "N"
    user_interaction: str = "N"
    scope: str = "U"
    confidentiality: str = "N"
    integrity: str = "N"
    availability: str = "N"


class CVSSParseRequest(BaseModel):
    vector: str


class FindingAddRequest(BaseModel):
    report_id: str = ""
    title: str
    vulnerability_type: str
    description: str = ""
    affected_url: str = ""
    affected_parameter: str = ""
    proof_of_concept: str = ""
    impact: str = ""
    severity: str = ""


class ReportCreateRequest(BaseModel):
    title: str
    client_name: str = ""
    target: str = ""
    test_type: str = "web"
    tester: str = ""


@router.post("/cvss/score")
async def cvss_score(
    request: CVSSScoreRequest,
    x_api_key: Optional[str] = Header(None)
):
    """计算CVSS v3.1分数"""
    verify_api_key(x_api_key)
    try:
        metrics = CVSSMetrics(
            attack_vector=request.attack_vector,
            attack_complexity=request.attack_complexity,
            privileges_required=request.privileges_required,
            user_interaction=request.user_interaction,
            scope=request.scope,
            confidentiality_impact=request.confidentiality,
            integrity_impact=request.integrity,
            availability_impact=request.availability,
        )
        score = _scorer.calculate_base_score(metrics)
        severity = _scorer.get_severity(score)
        vector = _scorer.get_vector_string(metrics)
        return {
            "status": "success",
            "data": {
                "score": score,
                "severity": severity,
                "vector": vector,
            }
        }
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@router.post("/cvss/score-by-type")
async def cvss_score_by_type(
    vulnerability_type: str,
    x_api_key: Optional[str] = Header(None)
):
    """根据漏洞类型快速评分"""
    verify_api_key(x_api_key)
    try:
        score, severity, vector = _scorer.score_by_type(vulnerability_type)
        return {
            "status": "success",
            "data": {
                "vulnerability_type": vulnerability_type,
                "score": score,
                "severity": severity,
                "vector": vector,
            }
        }
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@router.post("/cvss/parse")
async def cvss_parse(
    request: CVSSParseRequest,
    x_api_key: Optional[str] = Header(None)
):
    """解析CVSS向量字符串"""
    verify_api_key(x_api_key)
    try:
        metrics = _scorer.parse_vector_string(request.vector)
        if not metrics:
            raise HTTPException(status_code=400, detail="无效的CVSS向量")
        score = _scorer.calculate_base_score(metrics)
        severity = _scorer.get_severity(score)
        return {
            "status": "success",
            "data": {
                "score": score,
                "severity": severity,
                "metrics": {
                    "attack_vector": metrics.attack_vector,
                    "attack_complexity": metrics.attack_complexity,
                    "privileges_required": metrics.privileges_required,
                    "user_interaction": metrics.user_interaction,
                    "scope": metrics.scope,
                    "confidentiality": metrics.confidentiality_impact,
                    "integrity": metrics.integrity_impact,
                    "availability": metrics.availability_impact,
                }
            }
        }
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@router.get("/remediation/list")
async def list_remediations(
    x_api_key: Optional[str] = Header(None)
):
    """列出所有修复建议"""
    verify_api_key(x_api_key)
    return {"status": "success", "data": _remediation.get_stats()}


@router.get("/remediation/{vulnerability_type}")
async def get_remediation(
    vulnerability_type: str,
    x_api_key: Optional[str] = Header(None)
):
    """获取指定漏洞类型的修复方案"""
    verify_api_key(x_api_key)
    rem = _remediation.get_remediation(vulnerability_type)
    if not rem:
        raise HTTPException(status_code=404, detail="未找到该漏洞类型的修复方案")
    return {
        "status": "success",
        "data": {
            "title": rem.title,
            "description": rem.description,
            "severity": rem.severity,
            "cwe_id": rem.cwe_id,
            "owasp_category": rem.owasp_category,
            "remediation_steps": rem.remediation_steps,
            "code_examples": rem.code_examples,
            "best_practices": rem.best_practices,
            "references": rem.references,
        }
    }


@router.get("/remediation/search/{keyword}")
async def search_remediation(
    keyword: str,
    x_api_key: Optional[str] = Header(None)
):
    """搜索修复建议"""
    verify_api_key(x_api_key)
    results = _remediation.search_remediation(keyword)
    return {
        "status": "success",
        "data": [
            {"vulnerability_type": r.vulnerability_type, "title": r.title, "severity": r.severity}
            for r in results
        ]
    }


@router.post("/report/create")
async def create_report(
    request: ReportCreateRequest,
    x_api_key: Optional[str] = Header(None)
):
    """创建新报告"""
    verify_api_key(x_api_key)
    try:
        report = _generator.create_report(
            title=request.title,
            client_name=request.client_name,
            target=request.target,
            test_type=request.test_type,
            tester=request.tester,
        )
        _reports[report.report_id] = report
        return {"status": "success", "data": {"report_id": report.report_id, "title": report.title}}
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@router.post("/report/finding/add")
async def add_finding(
    request: FindingAddRequest,
    x_api_key: Optional[str] = Header(None)
):
    """向报告添加漏洞发现"""
    verify_api_key(x_api_key)
    try:
        report = _reports.get(request.report_id)
        if not report:
            report = _generator.create_report(title="临时报告")
            _reports[report.report_id] = report

        finding = _generator.add_finding(
            report=report,
            title=request.title,
            vulnerability_type=request.vulnerability_type,
            description=request.description,
            affected_url=request.affected_url,
            affected_parameter=request.affected_parameter,
            proof_of_concept=request.proof_of_concept,
            impact=request.impact,
            severity=request.severity,
        )
        return {
            "status": "success",
            "data": {
                "report_id": report.report_id,
                "finding_id": finding.finding_id,
                "severity": finding.severity,
                "cvss_score": finding.cvss_score,
            }
        }
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@router.get("/report/{report_id}/markdown")
async def get_report_markdown(
    report_id: str,
    x_api_key: Optional[str] = Header(None)
):
    """获取Markdown格式报告"""
    verify_api_key(x_api_key)
    report = _reports.get(report_id)
    if not report:
        raise HTTPException(status_code=404, detail="报告不存在")
    md = _generator.generate_markdown(report)
    return {"status": "success", "data": {"report_id": report_id, "content": md}}


@router.get("/report/{report_id}/json")
async def get_report_json(
    report_id: str,
    x_api_key: Optional[str] = Header(None)
):
    """获取JSON格式报告"""
    verify_api_key(x_api_key)
    report = _reports.get(report_id)
    if not report:
        raise HTTPException(status_code=404, detail="报告不存在")
    return {"status": "success", "data": _generator.get_statistics(report)}


@router.get("/report/list")
async def list_reports(
    x_api_key: Optional[str] = Header(None)
):
    """列出所有报告"""
    verify_api_key(x_api_key)
    return {
        "status": "success",
        "data": [
            {"report_id": r.report_id, "title": r.title, "target": r.target, "findings": len(r.findings)}
            for r in _reports.values()
        ]
    }
