#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
扩展安全模块API路由
提供移动安全、内网渗透、云安全、API安全、客户端安全、代码审计、无线网络的API端点
"""

import os
import json
from datetime import datetime
from typing import Optional
from fastapi import APIRouter, HTTPException, UploadFile, File, Form, Query
from pydantic import BaseModel

router = APIRouter(prefix="/api/v1/extended", tags=["扩展安全模块"])


# ==================== 移动安全API ====================

@router.post("/mobile/analyze", summary="APK静态分析")
async def mobile_analyze_apk(
    file: UploadFile = File(..., description="APK文件"),
):
    """上传并分析APK文件"""
    try:
        # 保存上传的文件
        upload_dir = os.path.join('data', 'mobile', 'uploads')
        os.makedirs(upload_dir, exist_ok=True)
        file_path = os.path.join(upload_dir, file.filename)

        with open(file_path, 'wb') as f:
            content = await file.read()
            f.write(content)

        # 解析APK
        from mobile_security.apk_parser import get_apk_parser
        parser = get_apk_parser()
        apk_info = parser.parse(file_path)

        return {
            "success": True,
            "message": "APK分析完成",
            "data": parser.to_dict(),
        }
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@router.get("/mobile/vulnerabilities", summary="移动App漏洞扫描")
async def mobile_scan_vulnerabilities(
    apk_path: str = Query(..., description="APK文件路径"),
):
    """扫描移动App漏洞"""
    try:
        from mobile_security.apk_parser import get_apk_parser
        from mobile_security.vulnerability_scanner import get_mobile_vulnerability_scanner

        # 解析APK
        parser = get_apk_parser()
        apk_info = parser.parse(apk_path)

        # 漏洞扫描
        scanner = get_mobile_vulnerability_scanner()
        vulnerabilities = scanner.scan_apk(apk_info)

        return {
            "success": True,
            "message": "漏洞扫描完成",
            "data": {
                "total": len(vulnerabilities),
                "statistics": scanner.get_statistics(),
                "vulnerabilities": [
                    {
                        "id": v.id,
                        "name": v.name,
                        "category": v.category,
                        "severity": v.severity,
                        "description": v.description,
                        "location": v.location,
                        "recommendation": v.recommendation,
                    }
                    for v in vulnerabilities
                ],
            },
        }
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@router.get("/mobile/frida/scripts", summary="获取Frida脚本列表")
async def mobile_get_frida_scripts():
    """获取可用的Frida脚本"""
    try:
        from mobile_security.frida_helper import get_frida_helper
        helper = get_frida_helper()
        scripts = helper.get_all_scripts()
        return {
            "success": True,
            "data": scripts,
        }
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@router.post("/mobile/frida/generate", summary="生成自定义Frida脚本")
async def mobile_generate_frida_script(
    class_name: str = Form(""),
    method_name: str = Form(""),
    hook_type: str = Form("trace"),
):
    """生成自定义Frida Hook脚本"""
    try:
        from mobile_security.frida_helper import get_frida_helper
        helper = get_frida_helper()
        script = helper.generate_custom_script(class_name, method_name, hook_type)
        return {
            "success": True,
            "data": {"script": script},
        }
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@router.get("/mobile/devices", summary="获取连接的Android设备列表")
async def mobile_get_devices():
    """获取ADB连接的设备列表"""
    try:
        from mobile_security.dynamic_analyzer import get_dynamic_analyzer
        analyzer = get_dynamic_analyzer()
        devices = analyzer.get_devices()
        return {
            "success": True,
            "data": {"devices": devices},
        }
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


# ==================== 内网渗透API ====================

@router.post("/internal/scan", summary="内网扫描")
async def internal_scan_network(
    target: str = Form(..., description="目标IP或网段"),
    ports: str = Form("1-1000", description="端口范围"),
):
    """扫描内网存活主机和开放端口"""
    try:
        from internal_pentest import get_internal_pentest
        pentest = get_internal_pentest()
        hosts = pentest.scan_network(target, ports)
        return {
            "success": True,
            "message": "内网扫描完成",
            "data": {
                "total": len(hosts),
                "hosts": [
                    {
                        "ip": h.ip,
                        "hostname": h.hostname,
                        "os": h.os,
                        "open_ports": h.open_ports,
                    }
                    for h in hosts
                ],
            },
        }
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@router.post("/internal/smb", summary="SMB共享枚举")
async def internal_enumerate_smb(
    target: str = Form(..., description="目标IP"),
):
    """枚举SMB共享"""
    try:
        from internal_pentest import get_internal_pentest
        pentest = get_internal_pentest()
        shares = pentest.enumerate_smb(target)
        return {
            "success": True,
            "data": {"shares": shares},
        }
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@router.post("/internal/domain", summary="域信息枚举")
async def internal_enumerate_domain(
    domain: str = Form("", description="域名"),
):
    """枚举域信息"""
    try:
        from internal_pentest import get_internal_pentest
        pentest = get_internal_pentest()
        domain_info = pentest.enumerate_domain(domain)
        return {
            "success": True,
            "data": {
                "domain_name": domain_info.domain_name,
                "domain_controllers": domain_info.domain_controllers,
                "domain_admins": domain_info.domain_admins,
            },
        }
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@router.post("/internal/privesc", summary="本地提权漏洞检查")
async def internal_check_privesc():
    """检查本地提权漏洞"""
    try:
        from internal_pentest import get_internal_pentest
        pentest = get_internal_pentest()
        vulnerabilities = pentest.check_local_privesc()
        return {
            "success": True,
            "data": {"vulnerabilities": vulnerabilities},
        }
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@router.post("/internal/kerberoasting", summary="Kerberoasting")
async def internal_kerberoasting(
    domain: str = Form("", description="域名"),
):
    """Kerberoasting攻击"""
    try:
        from internal_pentest import get_internal_pentest
        pentest = get_internal_pentest()
        tickets = pentest.kerberoasting(domain)
        return {
            "success": True,
            "data": {"tickets": tickets},
        }
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


# ==================== 云安全API ====================

@router.post("/cloud/scan/aws", summary="AWS配置安全扫描")
async def cloud_scan_aws(
    profile: str = Form("default", description="AWS配置文件"),
):
    """扫描AWS配置安全"""
    try:
        from cloud_security import get_cloud_security_scanner
        scanner = get_cloud_security_scanner()
        findings = scanner.scan_aws(profile)
        return {
            "success": True,
            "data": {
                "total": len(findings),
                "statistics": scanner.get_statistics(),
                "findings": [
                    {
                        "provider": f.provider,
                        "service": f.service,
                        "issue": f.issue,
                        "severity": f.severity,
                        "recommendation": f.recommendation,
                    }
                    for f in findings
                ],
            },
        }
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@router.post("/cloud/scan/container", summary="容器镜像安全扫描")
async def cloud_scan_container(
    image: str = Form("", description="镜像名称"),
):
    """扫描容器镜像安全"""
    try:
        from cloud_security import get_cloud_security_scanner
        scanner = get_cloud_security_scanner()
        findings = scanner.scan_container(image)
        return {
            "success": True,
            "data": {
                "total": len(findings),
                "findings": [
                    {
                        "issue": f.issue,
                        "severity": f.severity,
                        "recommendation": f.recommendation,
                    }
                    for f in findings
                ],
            },
        }
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@router.post("/cloud/scan/k8s", summary="Kubernetes集群安全扫描")
async def cloud_scan_k8s(
    context: str = Form("", description="K8s上下文"),
):
    """扫描Kubernetes集群安全"""
    try:
        from cloud_security import get_cloud_security_scanner
        scanner = get_cloud_security_scanner()
        findings = scanner.scan_kubernetes(context)
        return {
            "success": True,
            "data": {
                "total": len(findings),
                "findings": [
                    {
                        "issue": f.issue,
                        "severity": f.severity,
                        "recommendation": f.recommendation,
                    }
                    for f in findings
                ],
            },
        }
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


# ==================== API安全API ====================

@router.post("/api-security/parse-openapi", summary="解析OpenAPI文档")
async def api_security_parse_openapi(
    spec_url: str = Form("", description="OpenAPI文档URL"),
    spec_path: str = Form("", description="OpenAPI文件路径"),
):
    """解析OpenAPI/Swagger文档"""
    try:
        from api_security import get_api_security_tester
        tester = get_api_security_tester()
        endpoints = tester.parse_openapi(spec_path, spec_url)
        return {
            "success": True,
            "data": {
                "total": len(endpoints),
                "endpoints": [
                    {
                        "path": e.path,
                        "method": e.method,
                        "description": e.description,
                        "auth_required": e.auth_required,
                    }
                    for e in endpoints
                ],
            },
        }
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@router.post("/api-security/test-auth", summary="API认证测试")
async def api_security_test_auth(
    base_url: str = Form(..., description="API基础URL"),
):
    """测试API认证漏洞"""
    try:
        from api_security import get_api_security_tester
        tester = get_api_security_tester()
        vulns = tester.test_authentication(base_url)
        return {
            "success": True,
            "data": {"vulnerabilities": [v.__dict__ for v in vulns]},
        }
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@router.post("/api-security/test-business-logic", summary="API业务逻辑测试")
async def api_security_test_business_logic(
    base_url: str = Form(..., description="API基础URL"),
):
    """测试API业务逻辑漏洞"""
    try:
        from api_security import get_api_security_tester
        tester = get_api_security_tester()
        vulns = tester.test_business_logic(base_url)
        return {
            "success": True,
            "data": {"vulnerabilities": [v.__dict__ for v in vulns]},
        }
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


# ==================== 客户端安全API ====================

@router.post("/client/analyze", summary="二进制文件安全分析")
async def client_analyze_binary(
    file: UploadFile = File(..., description="二进制文件"),
):
    """分析二进制文件安全"""
    try:
        # 保存文件
        upload_dir = os.path.join('data', 'client', 'uploads')
        os.makedirs(upload_dir, exist_ok=True)
        file_path = os.path.join(upload_dir, file.filename)

        with open(file_path, 'wb') as f:
            content = await file.read()
            f.write(content)

        # 分析
        from client_security import get_client_security_analyzer
        analyzer = get_client_security_analyzer()
        binary_info = analyzer.analyze(file_path)
        assessment = analyzer.get_security_assessment()

        return {
            "success": True,
            "data": {
                "file_info": {
                    "file_name": binary_info.file_name,
                    "file_size": binary_info.file_size,
                    "file_type": binary_info.file_type,
                    "architecture": binary_info.architecture,
                    "md5": binary_info.md5,
                    "is_packed": binary_info.is_packed,
                    "packer_name": binary_info.packer_name,
                    "has_anti_debug": binary_info.has_anti_debug,
                    "has_anti_vm": binary_info.has_anti_vm,
                },
                "security_assessment": assessment,
            },
        }
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


# ==================== 代码审计API ====================

@router.post("/code-audit/audit", summary="代码审计")
async def code_audit_audit(
    directory: str = Form(..., description="代码目录路径"),
):
    """审计代码目录"""
    try:
        from code_audit import get_code_auditor
        auditor = get_code_auditor()
        issues = auditor.audit_directory(directory)
        stats = auditor.get_statistics()

        return {
            "success": True,
            "message": "代码审计完成",
            "data": {
                "scanned_files": stats['scanned_files'],
                "total_issues": stats['total_issues'],
                "statistics": stats,
                "issues": [
                    {
                        "file_path": issue.file_path,
                        "line_number": issue.line_number,
                        "issue_type": issue.issue_type,
                        "severity": issue.severity,
                        "description": issue.description,
                        "code_snippet": issue.code_snippet,
                        "recommendation": issue.recommendation,
                    }
                    for issue in issues[:100]  # 限制返回数量
                ],
            },
        }
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@router.post("/code-audit/dependencies", summary="依赖漏洞扫描")
async def code_audit_dependencies(
    directory: str = Form(..., description="项目目录路径"),
):
    """扫描项目依赖漏洞"""
    try:
        from code_audit import get_code_auditor
        auditor = get_code_auditor()
        vulnerabilities = auditor.scan_dependencies(directory)
        return {
            "success": True,
            "data": {"vulnerabilities": vulnerabilities},
        }
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


# ==================== 无线网络API ====================

@router.post("/wireless/scan", summary="WiFi扫描")
async def wireless_scan_wifi(
    interface: str = Form("wlan0", description="无线网卡接口"),
    duration: int = Form(10, description="扫描时长（秒）"),
):
    """扫描周围WiFi网络"""
    try:
        from wireless_security import get_wireless_security_scanner
        scanner = get_wireless_security_scanner()
        networks = scanner.scan_wifi(interface, duration)
        return {
            "success": True,
            "data": {
                "total": len(networks),
                "networks": [
                    {
                        "bssid": n.bssid,
                        "ssid": n.ssid or "(隐藏)",
                        "signal_strength": n.signal_strength,
                        "channel": n.channel,
                        "encryption": n.encryption,
                        "is_hidden": n.is_hidden,
                    }
                    for n in networks
                ],
            },
        }
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@router.post("/wireless/audit", summary="无线网络安全审计")
async def wireless_audit():
    """审计扫描到的所有WiFi网络安全"""
    try:
        from wireless_security import get_wireless_security_scanner
        scanner = get_wireless_security_scanner()
        vulnerabilities = scanner.audit_all_networks()
        stats = scanner.get_statistics()
        return {
            "success": True,
            "data": {
                "statistics": stats,
                "vulnerabilities": [
                    {
                        "ssid": v.ssid,
                        "vulnerability": v.vulnerability,
                        "severity": v.severity,
                        "description": v.description,
                        "recommendation": v.recommendation,
                    }
                    for v in vulnerabilities
                ],
            },
        }
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


# ==================== 综合报告API ====================

@router.get("/report/summary", summary="获取所有模块的综合报告摘要")
async def get_extended_report_summary():
    """获取所有扩展安全模块的综合报告摘要"""
    return {
        "success": True,
        "data": {
            "modules": [
                {"name": "移动安全", "status": "已集成", "features": ["APK静态分析", "动态分析", "漏洞扫描", "Frida集成"]},
                {"name": "内网渗透", "status": "已集成", "features": ["内网扫描", "SMB枚举", "域渗透", "横向移动", "Kerberoasting"]},
                {"name": "云安全", "status": "已集成", "features": ["AWS/Azure/阿里云", "容器扫描", "K8s安全"]},
                {"name": "API安全", "status": "已集成", "features": ["OpenAPI解析", "认证测试", "授权测试", "业务逻辑测试", "Fuzz"]},
                {"name": "客户端安全", "status": "已集成", "features": ["二进制分析", "加壳检测", "反调试检测", "敏感信息提取"]},
                {"name": "代码审计", "status": "已集成", "features": ["静态分析", "依赖扫描", "敏感信息检测"]},
                {"name": "无线网络", "status": "已集成", "features": ["WiFi扫描", "安全评估", "弱密码检测"]},
            ],
            "total_modules": 7,
            "total_features": 30,
        },
    }
