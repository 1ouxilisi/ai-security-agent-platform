#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
新领域安全API路由
New Domain Security API Routes

覆盖：移动安全、云安全、客户端安全、AI安全
"""

import os
import sys
from typing import Optional, Dict, Any, List
from fastapi import APIRouter, HTTPException, Query, Body
from pydantic import BaseModel, Field
from loguru import logger

router = APIRouter(prefix="/api/v1/new-domains", tags=["新领域安全"])

# ============================================
# 请求/响应模型
# ============================================

class APKAnalyzeRequest(BaseModel):
    """APK分析请求"""
    file_path: str = Field(..., description="APK文件路径")

class MobileAPIScanRequest(BaseModel):
    """移动端API扫描请求"""
    api_url: str = Field(..., description="API URL")
    method: str = Field("GET", description="HTTP方法")
    headers: Optional[Dict[str, str]] = None
    data: Optional[Dict[str, Any]] = None

class CloudScanRequest(BaseModel):
    """云安全扫描请求"""
    provider: str = Field("aws", description="云服务商: aws/azure/aliyun")
    region: str = Field("us-east-1", description="区域")

class ContainerScanRequest(BaseModel):
    """容器安全扫描请求"""
    target: str = Field(..., description="镜像名称或集群标识")
    scan_type: str = Field("image", description="扫描类型: image/k8s")

class BinaryAnalyzeRequest(BaseModel):
    """二进制分析请求"""
    file_path: str = Field(..., description="二进制文件路径")

class VulnFindRequest(BaseModel):
    """漏洞发现请求"""
    file_path: Optional[str] = Field(None, description="目标文件路径")
    source_code: Optional[str] = Field(None, description="源代码")

class PromptInjectionRequest(BaseModel):
    """Prompt注入检测请求"""
    prompt: str = Field(..., description="待检测的Prompt")

class AIRedTeamRequest(BaseModel):
    """AI红队测试请求"""
    target: Optional[str] = Field(None, description="目标AI系统标识")
    categories: Optional[List[str]] = Field(None, description="测试类别")

# ============================================
# 移动安全API
# ============================================

@router.post("/mobile/apk/analyze", summary="分析APK文件")
async def analyze_apk(request: APKAnalyzeRequest):
    """分析APK文件的结构、权限、组件、SDK和漏洞"""
    try:
        from mobile_security.apk_analyzer import APKAnalyzer
        analyzer = APKAnalyzer(request.file_path)
        result = analyzer.analyze()
        return {"status": "success", "data": result.to_dict()}
    except FileNotFoundError as e:
        raise HTTPException(status_code=404, detail=str(e))
    except Exception as e:
        logger.error(f"APK分析失败: {e}")
        raise HTTPException(status_code=500, detail=str(e))

@router.post("/mobile/api/scan", summary="扫描移动端API")
async def scan_mobile_api(request: MobileAPIScanRequest):
    """扫描移动端API的安全问题"""
    try:
        from mobile_security.mobile_scanner import MobileScanner
        scanner = MobileScanner(timeout=10)
        result = scanner.scan_api(
            api_url=request.api_url,
            method=request.method,
            headers=request.headers,
            data=request.data
        )
        return {"status": "success", "data": result.to_dict()}
    except Exception as e:
        logger.error(f"移动端API扫描失败: {e}")
        raise HTTPException(status_code=500, detail=str(e))

@router.get("/mobile/status", summary="移动安全模块状态")
async def mobile_status():
    """获取移动安全模块状态"""
    return {
        "status": "success",
        "data": {
            "module": "mobile_security",
            "version": "1.0.0",
            "features": ["APK静态分析", "移动端API扫描", "权限检测", "组件暴露检测", "第三方SDK识别"],
            "api_endpoints": 2,
        }
    }

# ============================================
# 云安全API
# ============================================

@router.post("/cloud/configuration/scan", summary="扫描云配置")
async def scan_cloud_config(request: CloudScanRequest):
    """扫描云服务商的配置安全问题"""
    try:
        from cloud_security.cloud_scanner import CloudScanner
        scanner = CloudScanner(provider=request.provider, region=request.region)
        result = scanner.scan()
        return {"status": "success", "data": result.to_dict()}
    except Exception as e:
        logger.error(f"云配置扫描失败: {e}")
        raise HTTPException(status_code=500, detail=str(e))

@router.post("/cloud/container/scan", summary="扫描容器安全")
async def scan_container(request: ContainerScanRequest):
    """扫描容器镜像或K8s集群的安全问题"""
    try:
        from cloud_security.container_scanner import ContainerScanner
        scanner = ContainerScanner(target=request.target)
        if request.scan_type == 'k8s':
            result = scanner.scan_k8s()
        else:
            result = scanner.scan_image()
        return {"status": "success", "data": result.to_dict()}
    except Exception as e:
        logger.error(f"容器安全扫描失败: {e}")
        raise HTTPException(status_code=500, detail=str(e))

@router.get("/cloud/status", summary="云安全模块状态")
async def cloud_status():
    """获取云安全模块状态"""
    return {
        "status": "success",
        "data": {
            "module": "cloud_security",
            "version": "1.0.0",
            "supported_providers": ["aws", "azure", "aliyun"],
            "features": ["云配置检查", "容器镜像扫描", "K8s安全扫描", "IaC安全检查"],
            "check_rules": 21,
            "api_endpoints": 2,
        }
    }

# ============================================
# 客户端安全API
# ============================================

@router.post("/client/binary/analyze", summary="分析二进制文件")
async def analyze_binary(request: BinaryAnalyzeRequest):
    """分析PE/ELF二进制文件的结构、导入导出、字符串和风险"""
    try:
        from client_security.binary_analyzer import BinaryAnalyzer
        analyzer = BinaryAnalyzer(request.file_path)
        result = analyzer.analyze()
        return {"status": "success", "data": result.to_dict()}
    except FileNotFoundError as e:
        raise HTTPException(status_code=404, detail=str(e))
    except Exception as e:
        logger.error(f"二进制分析失败: {e}")
        raise HTTPException(status_code=500, detail=str(e))

@router.post("/client/vulnerabilities/find", summary="发现二进制漏洞")
async def find_vulnerabilities(request: VulnFindRequest):
    """发现二进制文件或源代码中的漏洞和危险函数"""
    try:
        from client_security.vuln_finder import VulnerabilityFinder
        finder = VulnerabilityFinder(target=request.file_path)
        result = finder.scan(source_code=request.source_code)
        return {"status": "success", "data": result.to_dict()}
    except Exception as e:
        logger.error(f"漏洞发现失败: {e}")
        raise HTTPException(status_code=500, detail=str(e))

@router.get("/client/status", summary="客户端安全模块状态")
async def client_status():
    """获取客户端安全模块状态"""
    return {
        "status": "success",
        "data": {
            "module": "client_security",
            "version": "1.0.0",
            "supported_formats": ["pe", "elf"],
            "features": ["二进制结构分析", "危险函数检测", "漏洞模式匹配", "Fuzzing模板生成", "字符串提取"],
            "dangerous_functions": 30,
            "vulnerability_patterns": 8,
            "fuzzing_templates": 4,
            "api_endpoints": 2,
        }
    }

# ============================================
# AI安全API
# ============================================

@router.post("/ai/prompt-injection/detect", summary="检测Prompt注入")
async def detect_prompt_injection(request: PromptInjectionRequest):
    """检测Prompt中是否包含注入、越狱或恶意指令"""
    try:
        from ai_security.prompt_injection import PromptInjectionDetector
        detector = PromptInjectionDetector()
        result = detector.analyze(request.prompt)
        return {"status": "success", "data": result.to_dict()}
    except Exception as e:
        logger.error(f"Prompt注入检测失败: {e}")
        raise HTTPException(status_code=500, detail=str(e))

@router.post("/ai/redteam/run", summary="运行AI红队测试")
async def run_ai_redteam(request: AIRedTeamRequest):
    """运行AI系统红队测试，检测越狱、注入、数据泄露等漏洞"""
    try:
        from ai_security.ai_redteam import AIRedTeamTester
        tester = AIRedTeamTester(target=request.target)
        result = tester.run_tests(test_categories=request.categories)
        return {"status": "success", "data": result.to_dict()}
    except Exception as e:
        logger.error(f"AI红队测试失败: {e}")
        raise HTTPException(status_code=500, detail=str(e))

@router.get("/ai/status", summary="AI安全模块状态")
async def ai_status():
    """获取AI安全模块状态"""
    return {
        "status": "success",
        "data": {
            "module": "ai_security",
            "version": "1.0.0",
            "features": ["Prompt注入检测", "越狱检测", "AI红队测试", "对抗样本生成", "模型漏洞扫描"],
            "injection_patterns": 15,
            "redteam_test_cases": 12,
            "adversarial_techniques": 6,
            "model_vulnerabilities": 6,
            "api_endpoints": 2,
        }
    }

# ============================================
# 综合状态API
# ============================================

@router.get("/status", summary="新领域安全模块综合状态")
async def new_domains_status():
    """获取所有新领域安全模块的综合状态"""
    return {
        "status": "success",
        "data": {
            "total_modules": 4,
            "modules": [
                {
                    "name": "mobile_security",
                    "display_name": "移动安全",
                    "version": "1.0.0",
                    "status": "active",
                    "api_endpoints": 3,
                },
                {
                    "name": "cloud_security",
                    "display_name": "云安全",
                    "version": "1.0.0",
                    "status": "active",
                    "api_endpoints": 3,
                },
                {
                    "name": "client_security",
                    "display_name": "客户端安全",
                    "version": "1.0.0",
                    "status": "active",
                    "api_endpoints": 3,
                },
                {
                    "name": "ai_security",
                    "display_name": "AI安全",
                    "version": "1.0.0",
                    "status": "active",
                    "api_endpoints": 3,
                },
            ],
            "total_api_endpoints": 13,
            "coverage": ["移动安全", "云安全", "客户端安全", "AI安全"],
        }
    }


logger.info("新领域安全API路由已加载")
