#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
高级安全模块API路由
提供AI安全、IoT安全、工控安全、区块链安全、取证分析、威胁情报、社会工程学、漏洞管理的API端点
"""

import os
import json
from datetime import datetime
from typing import Optional
from fastapi import APIRouter, HTTPException, UploadFile, File, Form, Query
from pydantic import BaseModel

router = APIRouter(prefix="/api/v1/advanced", tags=["高级安全模块"])


# ==================== AI安全API ====================

@router.post("/ai-security/detect-prompt-injection", summary="检测提示注入")
async def ai_detect_prompt_injection(
    prompt: str = Form(..., description="待检测的提示词"),
):
    """检测提示注入攻击"""
    try:
        from ai_security import get_ai_security_tester
        tester = get_ai_security_tester()
        detections = tester.detect_prompt_injection(prompt)
        return {
            "success": True,
            "data": {
                "total_detections": len(detections),
                "is_injection": len(detections) > 0,
                "detections": detections,
            },
        }
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@router.post("/ai-security/assess-model", summary="评估AI模型安全性")
async def ai_assess_model_security():
    """评估AI模型安全性"""
    try:
        from ai_security import get_ai_security_tester
        tester = get_ai_security_tester()
        assessment = tester.assess_model_security()
        return {"success": True, "data": assessment}
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@router.post("/ai-security/detect-data-poisoning", summary="检测数据投毒")
async def ai_detect_data_poisoning(
    dataset_info: str = Form("", description="数据集信息JSON"),
):
    """检测数据投毒"""
    try:
        from ai_security import get_ai_security_tester
        tester = get_ai_security_tester()
        info = json.loads(dataset_info) if dataset_info else None
        detections = tester.detect_data_poisoning(dataset_info=info)
        return {"success": True, "data": {"detections": detections}}
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


# ==================== IoT安全API ====================

@router.post("/iot/scan", summary="扫描IoT网络")
async def iot_scan_network(
    target: str = Form(..., description="目标IP或网段"),
):
    """扫描IoT网络设备"""
    try:
        from iot_security import get_iot_security_scanner
        scanner = get_iot_security_scanner()
        devices = scanner.scan_iot_network(target)
        return {
            "success": True,
            "data": {
                "total": len(devices),
                "devices": [
                    {"ip": d.ip, "open_ports": d.open_ports, "protocols": d.protocols}
                    for d in devices
                ],
            },
        }
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@router.get("/iot/default-credentials", summary="获取默认密码")
async def iot_default_credentials(
    vendor: str = Query("", description="厂商名称"),
):
    """获取IoT设备默认密码"""
    try:
        from iot_security import get_iot_security_scanner
        scanner = get_iot_security_scanner()
        creds = scanner.check_default_credentials(vendor)
        return {"success": True, "data": {"credentials": creds, "total": len(creds)}}
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@router.post("/iot/analyze-firmware", summary="分析固件")
async def iot_analyze_firmware(
    firmware_path: str = Form("", description="固件文件路径"),
):
    """分析IoT固件"""
    try:
        from iot_security import get_iot_security_scanner
        scanner = get_iot_security_scanner()
        result = scanner.analyze_firmware(firmware_path)
        return {"success": True, "data": result}
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


# ==================== 工控安全API ====================

@router.post("/ics/scan", summary="扫描ICS网络")
async def ics_scan_network(
    target: str = Form(..., description="目标IP"),
):
    """扫描工业控制系统"""
    try:
        from ics_security import get_ics_security_tester
        tester = get_ics_security_tester()
        devices = tester.scan_ics_network(target)
        return {
            "success": True,
            "data": {
                "total": len(devices),
                "devices": [{"ip": d.ip, "open_ports": d.open_ports} for d in devices],
            },
        }
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@router.get("/ics/vulnerabilities", summary="获取已知ICS漏洞")
async def ics_vulnerabilities(
    vendor: str = Query("", description="厂商"),
):
    """获取已知ICS漏洞"""
    try:
        from ics_security import get_ics_security_tester
        tester = get_ics_security_tester()
        vulns = tester.check_ics_vulnerabilities(vendor)
        return {"success": True, "data": {"vulnerabilities": vulns, "total": len(vulns)}}
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@router.get("/ics/security-assessment", summary="ICS安全评估")
async def ics_security_assessment():
    """获取ICS安全评估"""
    try:
        from ics_security import get_ics_security_tester
        tester = get_ics_security_tester()
        assessment = tester.assess_ics_security()
        return {"success": True, "data": assessment}
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


# ==================== 区块链安全API ====================

@router.post("/blockchain/audit-contract", summary="审计智能合约")
async def blockchain_audit_contract(
    contract_code: str = Form("", description="合约代码"),
    file_path: str = Form("", description="合约文件路径"),
):
    """审计Solidity智能合约"""
    try:
        from blockchain_security import get_blockchain_security_auditor
        auditor = get_blockchain_security_auditor()
        vulns = auditor.audit_solidity_contract(contract_code, file_path)
        report = auditor.generate_audit_report()
        return {"success": True, "data": report}
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@router.post("/blockchain/check-erc20", summary="检查ERC20合规性")
async def blockchain_check_erc20(
    contract_code: str = Form(..., description="合约代码"),
):
    """检查ERC20合规性"""
    try:
        from blockchain_security import get_blockchain_security_auditor
        auditor = get_blockchain_security_auditor()
        result = auditor.check_erc20_compliance(contract_code)
        return {"success": True, "data": result}
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


# ==================== 取证分析API ====================

@router.post("/forensics/analyze-windows-logs", summary="分析Windows日志")
async def forensics_analyze_logs(
    log_type: str = Form("Security", description="日志类型"),
):
    """分析Windows安全日志"""
    try:
        from forensics import get_forensic_analyzer
        analyzer = get_forensic_analyzer()
        events = analyzer.analyze_windows_logs(log_type=log_type)
        return {"success": True, "data": {"events": events, "total": len(events)}}
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@router.post("/forensics/calculate-hash", summary="计算文件哈希")
async def forensics_calculate_hash(
    file_path: str = Form(..., description="文件路径"),
):
    """计算文件哈希值"""
    try:
        from forensics import get_forensic_analyzer
        analyzer = get_forensic_analyzer()
        result = analyzer.calculate_file_hash(file_path)
        return {"success": True, "data": result}
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@router.get("/forensics/report", summary="生成取证报告")
async def forensics_report():
    """生成取证分析报告"""
    try:
        from forensics import get_forensic_analyzer
        analyzer = get_forensic_analyzer()
        report = analyzer.generate_forensic_report()
        return {"success": True, "data": report}
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


# ==================== 威胁情报API ====================

@router.post("/threat-intel/query-ioc", summary="查询IOC")
async def threat_intel_query_ioc(
    ioc_value: str = Form(..., description="IOC值（IP/域名/URL/哈希）"),
    ioc_type: str = Form("auto", description="IOC类型"),
):
    """查询失陷指标"""
    try:
        from threat_intelligence import get_threat_intelligence
        ti = get_threat_intelligence()
        results = ti.query_ioc(ioc_value, ioc_type)
        return {"success": True, "data": {"results": results, "total": len(results)}}
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@router.post("/threat-intel/assess-ip", summary="评估IP信誉")
async def threat_intel_assess_ip(
    ip: str = Form(..., description="IP地址"),
):
    """评估IP信誉"""
    try:
        from threat_intelligence import get_threat_intelligence
        ti = get_threat_intelligence()
        result = ti.assess_ip_reputation(ip)
        return {"success": True, "data": result}
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@router.get("/threat-intel/attack-tactics", summary="获取ATT&CK战术")
async def threat_intel_attack_tactics():
    """获取MITRE ATT&CK战术"""
    try:
        from threat_intelligence import get_threat_intelligence
        ti = get_threat_intelligence()
        tactics = ti.get_attack_tactics()
        return {"success": True, "data": {"tactics": tactics, "total": len(tactics)}}
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@router.get("/threat-intel/threat-groups", summary="获取威胁组织")
async def threat_intel_threat_groups():
    """获取知名威胁组织信息"""
    try:
        from threat_intelligence import get_threat_intelligence
        ti = get_threat_intelligence()
        groups = ti.get_threat_groups()
        return {"success": True, "data": {"groups": groups, "total": len(groups)}}
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


# ==================== 社会工程学API ====================

@router.post("/social-engineering/generate-phishing", summary="生成钓鱼演练邮件")
async def se_generate_phishing(
    scenario: str = Form("", description="场景"),
    target_name: str = Form("", description="目标姓名"),
    company_name: str = Form("", description="公司名称"),
    sender_name: str = Form("", description="发件人姓名"),
):
    """生成钓鱼演练邮件（仅用于授权培训）"""
    try:
        from social_engineering import get_social_engineering_tester
        tester = get_social_engineering_tester()
        result = tester.generate_phishing_email(scenario, target_name, company_name, sender_name)
        return {"success": True, "data": result}
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@router.get("/social-engineering/pretext-scenarios", summary="获取Pretext场景")
async def se_pretext_scenarios():
    """获取社会工程学pretext场景"""
    try:
        from social_engineering import get_social_engineering_tester
        tester = get_social_engineering_tester()
        scenarios = tester.get_pretext_scenarios()
        return {"success": True, "data": {"scenarios": scenarios, "total": len(scenarios)}}
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@router.get("/social-engineering/training-topics", summary="获取安全培训主题")
async def se_training_topics():
    """获取安全意识培训主题"""
    try:
        from social_engineering import get_social_engineering_tester
        tester = get_social_engineering_tester()
        topics = tester.get_training_topics()
        return {"success": True, "data": {"topics": topics, "total": len(topics)}}
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


# ==================== 漏洞管理API ====================

@router.post("/vuln-management/add", summary="添加漏洞")
async def vuln_mgmt_add(
    title: str = Form(..., description="漏洞标题"),
    severity: str = Form(..., description="严重程度"),
    description: str = Form("", description="漏洞描述"),
    affected_asset: str = Form("", description="受影响资产"),
    cve: str = Form("", description="CVE编号"),
):
    """添加漏洞到管理系统"""
    try:
        from vulnerability_management import get_vulnerability_manager
        manager = get_vulnerability_manager()
        vuln = manager.add_vulnerability(title, severity, description, affected_asset, cve)
        return {"success": True, "data": vuln.__dict__}
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@router.post("/vuln-management/update-status", summary="更新漏洞状态")
async def vuln_mgmt_update_status(
    vuln_id: str = Form(..., description="漏洞ID"),
    new_status: str = Form(..., description="新状态"),
    comment: str = Form("", description="备注"),
):
    """更新漏洞状态"""
    try:
        from vulnerability_management import get_vulnerability_manager
        manager = get_vulnerability_manager()
        vuln = manager.update_vulnerability_status(vuln_id, new_status, comment)
        if vuln:
            return {"success": True, "data": vuln.__dict__}
        return {"success": False, "error": "漏洞不存在"}
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@router.get("/vuln-management/list", summary="列出漏洞")
async def vuln_mgmt_list(
    severity: str = Query("", description="按严重程度筛选"),
    status: str = Query("", description="按状态筛选"),
):
    """列出漏洞"""
    try:
        from vulnerability_management import get_vulnerability_manager
        manager = get_vulnerability_manager()
        vulns = manager.list_vulnerabilities(severity, status)
        return {
            "success": True,
            "data": {
                "total": len(vulns),
                "vulnerabilities": [v.__dict__ for v in vulns],
            },
        }
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@router.get("/vuln-management/statistics", summary="漏洞统计")
async def vuln_mgmt_statistics():
    """获取漏洞统计信息"""
    try:
        from vulnerability_management import get_vulnerability_manager
        manager = get_vulnerability_manager()
        stats = manager.get_statistics()
        return {"success": True, "data": stats}
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@router.get("/vuln-management/sla-config", summary="获取SLA配置")
async def vuln_mgmt_sla_config():
    """获取漏洞修复SLA配置"""
    try:
        from vulnerability_management import get_vulnerability_manager
        manager = get_vulnerability_manager()
        config = manager.get_sla_config()
        return {"success": True, "data": config}
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@router.get("/vuln-management/report", summary="生成漏洞管理报告")
async def vuln_mgmt_report():
    """生成漏洞管理报告"""
    try:
        from vulnerability_management import get_vulnerability_manager
        manager = get_vulnerability_manager()
        report = manager.generate_vuln_report()
        return {"success": True, "data": report}
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


# ==================== 综合状态API ====================

@router.get("/status", summary="高级安全模块综合状态")
async def advanced_status():
    """获取所有高级安全模块状态"""
    return {
        "success": True,
        "data": {
            "modules": [
                {"name": "AI安全", "status": "已集成", "endpoints": 3, "features": ["提示注入检测", "模型安全评估", "数据投毒检测"]},
                {"name": "IoT安全", "status": "已集成", "endpoints": 3, "features": ["IoT扫描", "默认密码", "固件分析"]},
                {"name": "工控安全", "status": "已集成", "endpoints": 3, "features": ["ICS扫描", "已知漏洞", "安全评估"]},
                {"name": "区块链安全", "status": "已集成", "endpoints": 2, "features": ["合约审计", "ERC20合规"]},
                {"name": "取证分析", "status": "已集成", "endpoints": 3, "features": ["日志分析", "哈希计算", "取证报告"]},
                {"name": "威胁情报", "status": "已集成", "endpoints": 4, "features": ["IOC查询", "IP信誉", "ATT&CK", "威胁组织"]},
                {"name": "社会工程学", "status": "已集成", "endpoints": 3, "features": ["钓鱼演练", "Pretext场景", "安全培训"]},
                {"name": "漏洞管理", "status": "已集成", "endpoints": 6, "features": ["漏洞跟踪", "状态管理", "SLA管理", "统计报告"]},
            ],
            "total_modules": 8,
            "total_endpoints": 27,
            "total_features": 30,
        },
    }
