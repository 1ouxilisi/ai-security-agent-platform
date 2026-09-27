#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
hw_defense安全工具集成模块，提供相关安全工具的封装和调用。

模块功能：
    - 提供相关安全测试功能
    - 支持API调用和命令行使用
    - 与其他模块集成协作

注意事项：
    - 本模块仅用于授权的安全测试
    - 请勿用于非法用途
    - 使用前请确保已获得相关授权
"""

import asyncio
import json
import time
from datetime import datetime
from typing import Dict, List, Optional, Any
from dataclasses import dataclass, field
from loguru import logger


@dataclass
class HWCheckItem:
    """护网检查项"""
    id: str
    category: str
    name: str
    description: str
    risk_level: str  # high/medium/low
    check_method: str
    remediation: str
    status: str = "pending"  # pending/passed/failed/skipped
    evidence: str = ""
    checked_at: str = ""


@dataclass
class HWCheckResult:
    """护网检查结果"""
    target: str
    start_time: str
    end_time: str = ""
    total_checks: int = 0
    passed: int = 0
    failed: int = 0
    skipped: int = 0
    high_risk_count: int = 0
    medium_risk_count: int = 0
    low_risk_count: int = 0
    check_items: List[HWCheckItem] = field(default_factory=list)
    summary: str = ""
    recommendations: List[str] = field(default_factory=list)


class HWDefense:
    """护网专项防御"""

    def __init__(self, config: Optional[Dict] = None):
        """初始化HWDefense实例。

        Args:
            self: 类实例。
        """
        self.config = config or {}
        self.check_items = self._init_check_items()
        logger.info("护网专项模块初始化完成")

    def _init_check_items(self) -> List[HWCheckItem]:
        """初始化护网检查项"""
        items = [
            # 一、资产暴露面检查
            HWCheckItem(
                id="ASSET-001",
                category="资产暴露面",
                name="公网IP暴露检查",
                description="检查是否有未授权的公网IP暴露",
                risk_level="high",
                check_method="查询IP归属地、端口扫描、资产比对",
                remediation="关闭不必要的公网暴露，使用VPN/堡垒机访问"
            ),
            HWCheckItem(
                id="ASSET-002",
                category="资产暴露面",
                name="端口暴露检查",
                description="检查是否有高危端口暴露在公网（3389/22/445/3306等）",
                risk_level="high",
                check_method="端口扫描、服务识别",
                remediation="关闭高危端口，限制IP访问，使用强密码"
            ),
            HWCheckItem(
                id="ASSET-003",
                category="资产暴露面",
                name="子域名暴露检查",
                description="检查是否有未管理的子域名暴露",
                risk_level="medium",
                check_method="子域名枚举、DNS查询",
                remediation="下线未使用的子域名，统一管理DNS"
            ),
            HWCheckItem(
                id="ASSET-004",
                category="资产暴露面",
                name="管理后台暴露检查",
                description="检查管理后台是否暴露在公网",
                risk_level="high",
                check_method="目录扫描、指纹识别",
                remediation="管理后台限制IP访问，使用VPN，开启双因素认证"
            ),
            HWCheckItem(
                id="ASSET-005",
                category="资产暴露面",
                name="API接口暴露检查",
                description="检查API接口是否未授权访问",
                risk_level="high",
                check_method="API扫描、接口测试",
                remediation="API接口增加鉴权，限制访问频率，使用HTTPS"
            ),

            # 二、漏洞检查
            HWCheckItem(
                id="VULN-001",
                category="漏洞检查",
                name="已知CVE漏洞检查",
                description="检查是否存在已知高危CVE漏洞",
                risk_level="high",
                check_method="CVE漏洞扫描、版本比对",
                remediation="及时打补丁，升级到最新版本，使用WAF防护"
            ),
            HWCheckItem(
                id="VULN-002",
                category="漏洞检查",
                name="Web漏洞检查",
                description="检查SQL注入、XSS、SSRF、文件上传等Web漏洞",
                risk_level="high",
                check_method="Web漏洞扫描、手动测试",
                remediation="修复漏洞，使用WAF，输入验证，输出编码"
            ),
            HWCheckItem(
                id="VULN-003",
                category="漏洞检查",
                name="中间件漏洞检查",
                description="检查Nginx/Apache/Tomcat/Weblogic等中间件漏洞",
                risk_level="high",
                check_method="指纹识别、漏洞扫描",
                remediation="升级中间件版本，关闭不必要的功能，限制访问"
            ),
            HWCheckItem(
                id="VULN-004",
                category="漏洞检查",
                name="框架漏洞检查",
                description="检查Spring/Struts/ThinkPHP/Laravel等框架漏洞",
                risk_level="high",
                check_method="指纹识别、漏洞扫描",
                remediation="升级框架版本，使用安全配置，关闭调试模式"
            ),
            HWCheckItem(
                id="VULN-005",
                category="漏洞检查",
                name="弱口令检查",
                description="检查是否存在弱口令、默认口令",
                risk_level="high",
                check_method="弱口令爆破、口令策略检查",
                remediation="使用强密码，开启双因素认证，定期更换密码"
            ),

            # 三、安全配置检查
            HWCheckItem(
                id="CONFIG-001",
                category="安全配置",
                name="HTTPS配置检查",
                description="检查是否启用HTTPS，证书是否有效",
                risk_level="medium",
                check_method="SSL检查、证书验证",
                remediation="启用HTTPS，使用有效证书，禁用弱加密算法"
            ),
            HWCheckItem(
                id="CONFIG-002",
                category="安全配置",
                name="HTTP安全头检查",
                description="检查是否配置CSP/X-Frame-Options/X-Content-Type-Options等安全头",
                risk_level="medium",
                check_method="HTTP头检查",
                remediation="配置安全响应头，启用CSP，禁止MIME类型嗅探"
            ),
            HWCheckItem(
                id="CONFIG-003",
                category="安全配置",
                name="目录遍历检查",
                description="检查是否存在目录遍历、目录列出",
                risk_level="medium",
                check_method="目录扫描、配置检查",
                remediation="关闭目录列出，限制目录访问权限"
            ),
            HWCheckItem(
                id="CONFIG-004",
                category="安全配置",
                name="备份文件检查",
                description="检查是否存在备份文件、源码泄露",
                risk_level="high",
                check_method="目录扫描、文件枚举",
                remediation="删除备份文件，限制文件访问，使用.gitignore"
            ),
            HWCheckItem(
                id="CONFIG-005",
                category="安全配置",
                name="调试模式检查",
                description="检查是否开启调试模式、错误信息泄露",
                risk_level="medium",
                check_method="页面检查、错误触发",
                remediation="关闭调试模式，自定义错误页面，不泄露敏感信息"
            ),

            # 四、身份认证检查
            HWCheckItem(
                id="AUTH-001",
                category="身份认证",
                name="双因素认证检查",
                description="检查关键系统是否开启双因素认证",
                risk_level="high",
                check_method="登录测试、配置检查",
                remediation="关键系统开启双因素认证，使用硬件令牌或手机验证"
            ),
            HWCheckItem(
                id="AUTH-002",
                category="身份认证",
                name="会话管理检查",
                description="检查会话是否安全，是否存在会话固定、会话劫持",
                risk_level="medium",
                check_method="Cookie检查、会话测试",
                remediation="使用安全Cookie，设置HttpOnly/Secure/SameSite，定期失效会话"
            ),
            HWCheckItem(
                id="AUTH-003",
                category="身份认证",
                name="权限控制检查",
                description="检查是否存在越权访问、未授权访问",
                risk_level="high",
                check_method="权限测试、越权测试",
                remediation="严格权限控制，最小权限原则，垂直/水平越权防护"
            ),
            HWCheckItem(
                id="AUTH-004",
                category="身份认证",
                name="账号锁定检查",
                description="检查是否有登录失败锁定机制",
                risk_level="medium",
                check_method="暴力破解测试、配置检查",
                remediation="登录失败5次锁定账号，使用验证码，限制登录IP"
            ),

            # 五、日志监控检查
            HWCheckItem(
                id="LOG-001",
                category="日志监控",
                name="访问日志检查",
                description="检查是否开启访问日志，日志是否完整",
                risk_level="medium",
                check_method="日志检查、配置检查",
                remediation="开启访问日志，记录关键操作，日志保存6个月以上"
            ),
            HWCheckItem(
                id="LOG-002",
                category="日志监控",
                name="安全告警检查",
                description="检查是否有安全告警机制，是否能及时发现攻击",
                risk_level="high",
                check_method="告警测试、配置检查",
                remediation="部署WAF/IDS/IPS，配置安全告警，7x24小时监控"
            ),
            HWCheckItem(
                id="LOG-003",
                category="日志监控",
                name="异常行为检测检查",
                description="检查是否有异常行为检测机制",
                risk_level="medium",
                check_method="行为分析、配置检查",
                remediation="部署UEBA，检测异常登录、异常操作、异常流量"
            ),

            # 六、应急响应检查
            HWCheckItem(
                id="IR-001",
                category="应急响应",
                name="应急预案检查",
                description="检查是否有网络安全应急预案",
                risk_level="medium",
                check_method="文档检查、演练检查",
                remediation="制定应急预案，定期演练，明确责任人"
            ),
            HWCheckItem(
                id="IR-002",
                category="应急响应",
                name="备份恢复检查",
                description="检查是否有数据备份，能否快速恢复",
                risk_level="high",
                check_method="备份检查、恢复测试",
                remediation="定期备份数据，离线备份，定期测试恢复"
            ),
            HWCheckItem(
                id="IR-003",
                category="应急响应",
                name="漏洞响应检查",
                description="检查是否有漏洞响应机制，能否快速修复漏洞",
                risk_level="high",
                check_method="流程检查、响应时间测试",
                remediation="建立漏洞响应流程，高危漏洞24小时内修复，使用临时防护"
            ),
        ]
        return items

    async def run_check(self, target: str, categories: Optional[List[str]] = None) -> HWCheckResult:
        """运行护网检查"""
        result = HWCheckResult(
            target=target,
            start_time=datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        )

        logger.info(f"开始护网检查: {target}")

        # 筛选检查项
        check_items = self.check_items
        if categories:
            check_items = [item for item in check_items if item.category in categories]

        result.total_checks = len(check_items)

        # 执行检查（模拟，实际需要调用扫描引擎）
        for item in check_items:
            item.checked_at = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
            item.status = "pending"  # 实际需要调用扫描引擎
            item.evidence = f"待扫描: {item.check_method}"

            if item.risk_level == "high":
                result.high_risk_count += 1
            elif item.risk_level == "medium":
                result.medium_risk_count += 1
            else:
                result.low_risk_count += 1

            result.check_items.append(item)

        result.end_time = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

        # 生成摘要
        result.summary = self._generate_summary(result)
        result.recommendations = self._generate_recommendations(result)

        logger.info(f"护网检查完成: {result.total_checks}项, 高危{result.high_risk_count}项")

        return result

    def _generate_summary(self, result: HWCheckResult) -> str:
        """生成检查摘要"""
        return (
            f"护网自查完成，共检查{result.total_checks}项，"
            f"其中高危{result.high_risk_count}项，中危{result.medium_risk_count}项，"
            f"低危{result.low_risk_count}项。"
            f"建议优先修复高危项，护网前完成所有中危及以上漏洞修复。"
        )

    def _generate_recommendations(self, result: HWCheckResult) -> List[str]:
        """生成修复建议"""
        recommendations = [
            "护网前1个月完成全面自查，修复所有高危漏洞",
            "护网前1周完成二次扫描，确认漏洞已修复",
            "护网期间7x24小时监控，发现攻击及时响应",
            "关闭不必要的公网暴露，管理后台使用VPN访问",
            "所有系统开启双因素认证，使用强密码",
            "部署WAF/IDS/IPS，配置安全告警",
            "定期备份数据，测试恢复流程",
            "制定应急预案，明确责任人和响应流程",
        ]
        return recommendations

    def generate_report(self, result: HWCheckResult, output_path: str) -> str:
        """生成护网自查报告"""
        report = {
            "title": "护网行动安全自查报告",
            "target": result.target,
            "start_time": result.start_time,
            "end_time": result.end_time,
            "summary": result.summary,
            "statistics": {
                "total_checks": result.total_checks,
                "passed": result.passed,
                "failed": result.failed,
                "skipped": result.skipped,
                "high_risk": result.high_risk_count,
                "medium_risk": result.medium_risk_count,
                "low_risk": result.low_risk_count,
            },
            "check_items": [
                {
                    "id": item.id,
                    "category": item.category,
                    "name": item.name,
                    "description": item.description,
                    "risk_level": item.risk_level,
                    "status": item.status,
                    "check_method": item.check_method,
                    "remediation": item.remediation,
                    "evidence": item.evidence,
                    "checked_at": item.checked_at,
                }
                for item in result.check_items
            ],
            "recommendations": result.recommendations,
            "generated_at": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        }

        with open(output_path, "w", encoding="utf-8") as f:
            json.dump(report, f, ensure_ascii=False, indent=2)

        logger.info(f"护网自查报告已生成: {output_path}")
        return output_path

    def get_checklist(self) -> List[Dict]:
        """获取护网自查清单"""
        return [
            {
                "id": item.id,
                "category": item.category,
                "name": item.name,
                "risk_level": item.risk_level,
                "description": item.description,
                "check_method": item.check_method,
                "remediation": item.remediation,
            }
            for item in self.check_items
        ]

    def get_hw_timeline(self) -> List[Dict]:
        """获取护网时间线建议"""
        return [
            {
                "phase": "护网前1个月",
                "tasks": [
                    "全面资产梳理，发现未知资产和影子资产",
                    "全面漏洞扫描，发现所有高危和中危漏洞",
                    "制定修复计划，明确责任人和时间节点",
                    "开始修复高危漏洞",
                ],
            },
            {
                "phase": "护网前2周",
                "tasks": [
                    "完成所有高危漏洞修复",
                    "二次扫描，确认漏洞已修复",
                    "安全配置加固，关闭不必要的服务和端口",
                    "部署WAF/IDS/IPS，配置安全告警",
                    "开启双因素认证，使用强密码",
                ],
            },
            {
                "phase": "护网前1周",
                "tasks": [
                    "最终扫描，确认无高危漏洞",
                    "应急演练，测试应急预案",
                    "数据备份，测试恢复流程",
                    "7x24小时监控准备，明确值班人员",
                    "攻击面收敛，关闭不必要的公网暴露",
                ],
            },
            {
                "phase": "护网期间",
                "tasks": [
                    "7x24小时安全监控，发现攻击及时响应",
                    "每日安全报告，汇总攻击情况和处置情况",
                    "漏洞应急响应，新发现漏洞24小时内修复",
                    "攻击溯源，发现攻击源和攻击手段",
                    "配合监管单位，及时上报安全事件",
                ],
            },
            {
                "phase": "护网后",
                "tasks": [
                    "护网总结，汇总攻击情况和处置情况",
                    "漏洞复盘，分析漏洞成因和修复情况",
                    "安全加固，修复护网期间发现的问题",
                    "完善应急预案，优化安全流程",
                    "持续安全运营，定期扫描和监控",
                ],
            },
        ]


# 便捷函数
async def hw_check(target: str, output_path: Optional[str] = None) -> HWCheckResult:
    """护网自查便捷函数"""
    hw = HWDefense()
    result = await hw.run_check(target)

    if output_path:
        hw.generate_report(result, output_path)

    return result


def get_hw_checklist() -> List[Dict]:
    """获取护网自查清单"""
    hw = HWDefense()
    return hw.get_checklist()


def get_hw_timeline() -> List[Dict]:
    """获取护网时间线"""
    hw = HWDefense()
    return hw.get_hw_timeline()


if __name__ == "__main__":
    # 测试
    result = asyncio.run(hw_check("https://example.com"))
    print(f"检查完成: {result.total_checks}项")
    print(f"高危: {result.high_risk_count}项")
    print(f"中危: {result.medium_risk_count}项")
    print(f"低危: {result.low_risk_count}项")
    print(f"摘要: {result.summary}")
