"""
第五轮升级API路由：Web指纹识别 + 目录扫描 + 一键完整扫描
"""
from fastapi import APIRouter, HTTPException, Header
from pydantic import BaseModel
from typing import Optional, Dict, Any
import sys
import os
import time

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from asm.web_fingerprint import WebFingerprinter, DirectoryScanner, COMMON_PATHS
from asm.real_port_scanner import RealPortScanner
from asm.nuclei_engine import NucleiEngine

router = APIRouter(prefix="/api/v1/recon", tags=["第五轮: Web侦察"])

API_AUTH_KEY = os.getenv("API_AUTH_KEY", "cF_fK3wzzFd3sDU-WykQzDbAKNhn_Jjoyphbmh-adLtwx5ShhU8oLpt94aV_uECT")


def verify_api_key(x_api_key: Optional[str] = Header(None)):
    if x_api_key != API_AUTH_KEY:
        raise HTTPException(status_code=401, detail="无效的API Key")
    return True


class FingerprintRequest(BaseModel):
    target: str
    timeout: int = 5


class DirScanRequest(BaseModel):
    target: str
    timeout: int = 3
    max_threads: int = 20
    custom_paths: Optional[list] = None


class FullReconRequest(BaseModel):
    target: str
    port_timeout: int = 2
    web_timeout: int = 5
    vuln_timeout: int = 5


@router.post("/fingerprint")
async def web_fingerprint(
    request: FingerprintRequest,
    x_api_key: Optional[str] = Header(None)
):
    """Web服务指纹识别：服务器/框架/CMS/技术栈/安全头"""
    verify_api_key(x_api_key)
    try:
        fp = WebFingerprinter(request.target, request.timeout)
        result = fp.fingerprint()
        return {"status": "success", "data": result}
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@router.post("/dir-scan")
async def directory_scan(
    request: DirScanRequest,
    x_api_key: Optional[str] = Header(None)
):
    """Web目录/路径枚举扫描"""
    verify_api_key(x_api_key)
    try:
        paths = request.custom_paths if request.custom_paths else COMMON_PATHS
        ds = DirectoryScanner(request.target, request.timeout, request.max_threads)
        result = ds.scan(paths)
        return {"status": "success", "data": result}
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@router.post("/full-scan")
async def full_recon(
    request: FullReconRequest,
    x_api_key: Optional[str] = Header(None)
):
    """
    一键完整侦察：端口扫描 + Web指纹 + 目录扫描 + 漏洞检测
    返回完整的安全评估报告
    """
    verify_api_key(x_api_key)
    try:
        start = time.time()
        report = {"target": request.target, "phases": {}}

        # Phase 1: 端口扫描
        print(f"[FullRecon] Phase 1: 端口扫描 {request.target}")
        ps = RealPortScanner(request.target, request.port_timeout, 50)
        port_result = ps.scan_common_ports()
        report["phases"]["port_scan"] = port_result

        # Phase 2: Web指纹识别（如果有HTTP/HTTPS端口开放）
        http_ports = [p for p in port_result["open_ports"] if p["service"] in ("http", "https", "http-alt", "https-alt", "nodejs")]
        if http_ports:
            print(f"[FullRecon] Phase 2: Web指纹识别")
            port = http_ports[0]["port"]
            scheme = "https" if port == 443 else "http"
            fp_url = f"{scheme}://{request.target}:{port}"
            fp = WebFingerprinter(fp_url, request.web_timeout)
            fp_result = fp.fingerprint()
            report["phases"]["web_fingerprint"] = fp_result

            # Phase 3: 目录扫描
            print(f"[FullRecon] Phase 3: 目录扫描")
            ds = DirectoryScanner(fp_url, request.web_timeout, 20)
            dir_result = ds.scan()
            report["phases"]["directory_scan"] = dir_result

            # Phase 4: 漏洞检测
            print(f"[FullRecon] Phase 4: 漏洞检测")
            engine = NucleiEngine(fp_url, request.vuln_timeout, 15)
            vuln_result = engine.scan_all()
            report["phases"]["vuln_scan"] = vuln_result

        # 综合风险评估
        total_time = round(time.time() - start, 2)
        risk_score = 0
        risk_factors = []

        port_count = port_result["open_ports_count"]
        if port_count > 10:
            risk_score += 20
            risk_factors.append(f"暴露{port_count}个端口")
        elif port_count > 5:
            risk_score += 10
            risk_factors.append(f"暴露{port_count}个端口")

        if "vuln_scan" in report["phases"]:
            v = report["phases"]["vuln_scan"]
            summary = v.get("summary", {})
            sev = summary.get("severity_distribution", {})
            risk_score += sev.get("critical", 0) * 10 + sev.get("high", 0) * 7 + sev.get("medium", 0) * 4

        if risk_score >= 50:
            overall_risk = "critical"
        elif risk_score >= 25:
            overall_risk = "high"
        elif risk_score >= 10:
            overall_risk = "medium"
        else:
            overall_risk = "low"

        report["summary"] = {
            "total_time_seconds": total_time,
            "risk_score": min(risk_score, 100),
            "overall_risk": overall_risk,
            "risk_factors": risk_factors,
            "phases_completed": list(report["phases"].keys())
        }

        print(f"[FullRecon] 完成: 风险={overall_risk}, 耗时={total_time}s")
        return {"status": "success", "data": report}

    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


# ============== 第七轮: DNS收集 + 资产基线 + 智能工作流 ==============
class DNSCollectRequest(BaseModel):
    target: str
    timeout: int = 5


class BaselineCompareRequest(BaseModel):
    target: str
    scan_data: Dict[str, Any]


class SmartStrategyRequest(BaseModel):
    target: str
    port_results: Dict[str, Any]


@router.post("/dns-collect")
async def dns_collect(request: DNSCollectRequest, x_api_key: Optional[str] = Header(None)):
    """DNS信息收集：A/MX/NS记录 + 子域名枚举"""
    verify_api_key(x_api_key)
    try:
        from asm.dns_workflow import DNSCollector
        return {"status": "success", "data": DNSCollector(request.target, request.timeout).collect()}
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@router.post("/baseline/compare")
async def baseline_compare(request: BaselineCompareRequest, x_api_key: Optional[str] = Header(None)):
    """资产基线对比：检测端口/漏洞变化"""
    verify_api_key(x_api_key)
    try:
        from asm.dns_workflow import AssetBaseline
        ab = AssetBaseline()
        result = ab.compare(request.target, request.scan_data)
        ab.save_baseline(request.target, request.scan_data)
        return {"status": "success", "data": result}
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@router.post("/smart-strategy")
async def smart_strategy(request: SmartStrategyRequest, x_api_key: Optional[str] = Header(None)):
    """智能工作流：根据端口扫描结果自动推荐扫描策略"""
    verify_api_key(x_api_key)
    try:
        from asm.dns_workflow import SmartWorkflow
        return {"status": "success", "data": SmartWorkflow.recommend_strategy(request.target, request.port_results)}
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))
