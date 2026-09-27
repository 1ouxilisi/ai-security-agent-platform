#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
攻击链验证引擎（Attack Chain Validator）

自动验证12条跨领域攻击链的可行性，计算完成度、风险等级、利用难度，
生成攻击链验证报告。

12条攻击链：
1. Web→Cloud: Web漏洞获取服务器权限→云元数据服务攻击→云资源接管
2. Mobile→AI: 移动APP硬编码密钥→AI API滥用→模型攻击
3. Web→Internal: Web漏洞getshell→内网横向移动→域控攻陷
4. Social→Internal: 社工获取凭证→内网登录→权限提升
5. IoT→ICS: IoT设备入侵→工控网络渗透→PLC控制
6. Wireless→Internal: WiFi破解→内网接入→横向移动
7. Binary→IoT: 固件漏洞挖掘→IoT设备入侵→僵尸网络
8. Internal→Cloud: 内网云配置窃取→云控制台登录→云资源滥用
9. AI→Social: AI模型数据泄露→个人信息收集→精准钓鱼
10. Binary→Internal: 恶意软件分析→C2通信→内网入侵
11. Blockchain→AI: 合约漏洞→链上数据→AI训练数据污染
12. Forensics→全领域: 取证分析→攻击溯源→威胁狩猎
"""

import re
from typing import Dict, List, Optional, Any, Tuple
from dataclasses import dataclass, field
from enum import Enum


class ChainStatus(Enum):
    """攻击链状态"""
    NOT_APPLICABLE = "not_applicable"  # 不适用
    POTENTIAL = "potential"  # 潜在可能
    PARTIALLY_VERIFIED = "partially_verified"  # 部分验证
    VERIFIED = "verified"  # 已验证
    EXPLOITABLE = "exploitable"  # 可利用


class RiskLevel(Enum):
    """风险等级"""
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


@dataclass
class ChainStage:
    """攻击链阶段"""
    stage_id: str
    name: str
    description: str
    required_findings: List[str]  # 需要的发现类型
    verified: bool = False
    evidence: List[Dict] = field(default_factory=list)
    confidence: float = 0.0  # 0-1


@dataclass
class AttackChain:
    """攻击链"""
    chain_id: str
    name: str
    description: str
    stages: List[ChainStage]
    status: ChainStatus = ChainStatus.NOT_APPLICABLE
    completion_rate: float = 0.0  # 完成度 0-1
    risk_level: RiskLevel = RiskLevel.INFO
    exploit_difficulty: str = "unknown"  # easy/medium/hard/unknown
    overall_score: float = 0.0  # 综合评分 0-100
    recommendations: List[str] = field(default_factory=list)


class AttackChainValidator:
    """
    攻击链验证引擎

    接收多领域发现，自动验证12条攻击链的可行性。
    """

    def __init__(self):
        self.chains = self._init_chains()

    def _init_chains(self) -> List[AttackChain]:
        """初始化12条攻击链"""
        return [
            AttackChain(
                chain_id="web_to_cloud",
                name="Web→云攻击链",
                description="Web漏洞获取服务器权限→云元数据服务攻击→云资源接管",
                stages=[
                    ChainStage("s1", "Web漏洞利用", "通过Web漏洞获取服务器权限",
                              ["vulnerability", "open_port", "web_vuln"]),
                    ChainStage("s2", "云元数据访问", "访问云元数据服务获取临时凭证",
                              ["cloud_metadata", "iam_role", "cloud_config"]),
                    ChainStage("s3", "云资源接管", "使用临时凭证接管云资源",
                              ["cloud_resource", "storage_bucket", "cloud_permission"]),
                ]
            ),
            AttackChain(
                chain_id="mobile_to_ai",
                name="移动→AI攻击链",
                description="移动APP硬编码密钥→AI API滥用→模型攻击",
                stages=[
                    ChainStage("s1", "APP密钥泄露", "从移动APP提取硬编码API密钥",
                              ["hardcoded_key", "api_key", "secret"]),
                    ChainStage("s2", "AI API滥用", "使用泄露密钥调用AI API",
                              ["ai_api", "model_access", "api_endpoint"]),
                    ChainStage("s3", "模型攻击", "提示注入/数据污染/模型逃逸",
                              ["prompt_injection", "model_vuln", "ai_security"]),
                ]
            ),
            AttackChain(
                chain_id="web_to_internal",
                name="Web→内网攻击链",
                description="Web漏洞getshell→内网横向移动→域控攻陷",
                stages=[
                    ChainStage("s1", "Web getshell", "通过Web漏洞获取服务器权限",
                              ["vulnerability", "web_vuln", "rce"]),
                    ChainStage("s2", "内网侦察", "内网端口扫描和服务发现",
                              ["open_port", "internal_service", "smb", "ldap"]),
                    ChainStage("s3", "横向移动", "利用SMB/WinRM等协议横向移动",
                              ["smb_open", "credential", "lateral_movement"]),
                    ChainStage("s4", "域控攻陷", "获取域管理员权限",
                              ["domain_admin", "dc_access", "privilege_escalation"]),
                ]
            ),
            AttackChain(
                chain_id="social_to_internal",
                name="社工→内网攻击链",
                description="社工获取凭证→内网登录→权限提升",
                stages=[
                    ChainStage("s1", "信息收集", "OSINT收集目标信息",
                              ["osint", "email", "employee_info"]),
                    ChainStage("s2", "凭证获取", "钓鱼/ pretexting获取凭证",
                              ["credential", "phishing", "password"]),
                    ChainStage("s3", "内网登录", "使用凭证登录内网系统",
                              ["internal_access", "valid_credential"]),
                    ChainStage("s4", "权限提升", "利用配置错误提升权限",
                              ["privilege_escalation", "misconfiguration"]),
                ]
            ),
            AttackChain(
                chain_id="iot_to_ics",
                name="IoT→工控攻击链",
                description="IoT设备入侵→工控网络渗透→PLC控制",
                stages=[
                    ChainStage("s1", "IoT设备入侵", "利用IoT设备漏洞入侵",
                              ["iot_vuln", "firmware_vuln", "default_credential"]),
                    ChainStage("s2", "工控网络渗透", "从IoT网络渗透到工控网络",
                              ["ics_network", "network_segmentation_fail"]),
                    ChainStage("s3", "PLC控制", " Modbus/S7等协议控制PLC",
                              ["modbus_open", "plc_access", "ics_control"]),
                ]
            ),
            AttackChain(
                chain_id="wireless_to_internal",
                name="无线→内网攻击链",
                description="WiFi破解→内网接入→横向移动",
                stages=[
                    ChainStage("s1", "WiFi破解", "破解WiFi密码或WPS",
                              ["wifi_network", "weak_encryption", "wps"]),
                    ChainStage("s2", "内网接入", "接入无线网络",
                              ["network_access", "dhcp"]),
                    ChainStage("s3", "横向移动", "内网扫描和横向移动",
                              ["open_port", "internal_service", "lateral_movement"]),
                ]
            ),
            AttackChain(
                chain_id="binary_to_iot",
                name="二进制→IoT攻击链",
                description="固件漏洞挖掘→IoT设备入侵→僵尸网络",
                stages=[
                    ChainStage("s1", "固件分析", "逆向分析固件发现漏洞",
                              ["firmware_vuln", "buffer_overflow", "binary_vuln"]),
                    ChainStage("s2", "IoT入侵", "利用固件漏洞入侵设备",
                              ["iot_access", "rce", "device_compromise"]),
                    ChainStage("s3", "僵尸网络", "控制大量设备组成僵尸网络",
                              ["botnet", "c2", "device_control"]),
                ]
            ),
            AttackChain(
                chain_id="internal_to_cloud",
                name="内网→云攻击链",
                description="内网云配置窃取→云控制台登录→云资源滥用",
                stages=[
                    ChainStage("s1", "云配置窃取", "从内网服务器获取云配置",
                              ["cloud_config", "aws_keys", "cloud_credential"]),
                    ChainStage("s2", "云控制台登录", "使用窃取凭证登录云控制台",
                              ["cloud_access", "console_access"]),
                    ChainStage("s3", "云资源滥用", "创建/删除/修改云资源",
                              ["resource_abuse", "data_exfiltration", "mining"]),
                ]
            ),
            AttackChain(
                chain_id="ai_to_social",
                name="AI→社工攻击链",
                description="AI模型数据泄露→个人信息收集→精准钓鱼",
                stages=[
                    ChainStage("s1", "模型数据泄露", "从AI模型提取训练数据",
                              ["data_leakage", "model_extraction", "training_data"]),
                    ChainStage("s2", "个人信息收集", "从泄露数据中提取个人信息",
                              ["pii", "personal_info", "email"]),
                    ChainStage("s3", "精准钓鱼", "利用个人信息制作精准钓鱼",
                              ["spear_phishing", "social_engineering", "credential_theft"]),
                ]
            ),
            AttackChain(
                chain_id="binary_to_internal",
                name="二进制→内网攻击链",
                description="恶意软件分析→C2通信→内网入侵",
                stages=[
                    ChainStage("s1", "恶意软件分析", "逆向分析恶意软件",
                              ["malware", "binary_analysis", "payload"]),
                    ChainStage("s2", "C2通信", "分析C2通信协议",
                              ["c2", "command_control", "network_traffic"]),
                    ChainStage("s3", "内网入侵", "利用C2控制内网主机",
                              ["internal_compromise", "lateral_movement", "persistence"]),
                ]
            ),
            AttackChain(
                chain_id="blockchain_to_ai",
                name="区块链→AI攻击链",
                description="合约漏洞→链上数据→AI训练数据污染",
                stages=[
                    ChainStage("s1", "合约漏洞", "发现智能合约漏洞",
                              ["contract_vuln", "solidity_issue", "reentrancy"]),
                    ChainStage("s2", "链上数据获取", "获取链上交易和数据",
                              ["chain_data", "transaction", "onchain"]),
                    ChainStage("s3", "AI数据污染", "污染AI训练数据",
                              ["data_poisoning", "training_data", "model_attack"]),
                ]
            ),
            AttackChain(
                chain_id="forensics_to_all",
                name="取证→全领域攻击链",
                description="取证分析→攻击溯源→威胁狩猎",
                stages=[
                    ChainStage("s1", "证据收集", "收集系统和网络证据",
                              ["evidence", "log", "file_hash"]),
                    ChainStage("s2", "攻击溯源", "分析攻击来源和路径",
                              ["attack_trace", "ioc", "threat_intel"]),
                    ChainStage("s3", "威胁狩猎", "基于IOC进行威胁狩猎",
                              ["threat_hunt", "detection", "response"]),
                ]
            ),
        ]

    def validate_chains(self, findings: List[Dict],
                        domain_findings: Dict[str, List[Dict]] = None) -> List[AttackChain]:
        """
        验证所有攻击链

        Args:
            findings: 所有发现的合并列表
            domain_findings: 按领域分组的发现 {domain: [findings]}

        Returns:
            验证后的攻击链列表
        """
        if domain_findings is None:
            domain_findings = {}

        for chain in self.chains:
            self._validate_chain(chain, findings, domain_findings)

        # 按综合评分排序
        self.chains.sort(key=lambda c: c.overall_score, reverse=True)
        return self.chains

    def _validate_chain(self, chain: AttackChain, findings: List[Dict],
                        domain_findings: Dict[str, List[Dict]]):
        """验证单条攻击链"""
        verified_stages = 0
        total_evidence = []

        for stage in chain.stages:
            stage.verified = False
            stage.evidence = []
            stage.confidence = 0.0

            # 检查每个阶段需要的发现类型
            for req_type in stage.required_findings:
                matching = [f for f in findings
                           if self._finding_matches_type(f, req_type)]
                if matching:
                    stage.verified = True
                    stage.evidence.extend(matching[:3])
                    stage.confidence = min(1.0, len(matching) / 3.0)
                    break

            if stage.verified:
                verified_stages += 1
                total_evidence.extend(stage.evidence)

        # 计算完成度
        chain.completion_rate = verified_stages / len(chain.stages) if chain.stages else 0

        # 确定状态
        if chain.completion_rate == 0:
            chain.status = ChainStatus.NOT_APPLICABLE
        elif chain.completion_rate < 0.34:
            chain.status = ChainStatus.POTENTIAL
        elif chain.completion_rate < 0.67:
            chain.status = ChainStatus.PARTIALLY_VERIFIED
        elif chain.completion_rate < 1.0:
            chain.status = ChainStatus.VERIFIED
        else:
            chain.status = ChainStatus.EXPLOITABLE

        # 计算风险等级
        high_severity_count = sum(
            1 for f in total_evidence
            if f.get('severity', '').lower() in ['critical', 'high']
        )
        if chain.completion_rate >= 0.67 and high_severity_count >= 2:
            chain.risk_level = RiskLevel.CRITICAL
        elif chain.completion_rate >= 0.5 and high_severity_count >= 1:
            chain.risk_level = RiskLevel.HIGH
        elif chain.completion_rate >= 0.34:
            chain.risk_level = RiskLevel.MEDIUM
        elif chain.completion_rate > 0:
            chain.risk_level = RiskLevel.LOW
        else:
            chain.risk_level = RiskLevel.INFO

        # 利用难度评估
        if chain.completion_rate >= 0.67:
            chain.exploit_difficulty = "easy"
        elif chain.completion_rate >= 0.34:
            chain.exploit_difficulty = "medium"
        elif chain.completion_rate > 0:
            chain.exploit_difficulty = "hard"
        else:
            chain.exploit_difficulty = "unknown"

        # 综合评分 (0-100)
        chain.overall_score = int(
            chain.completion_rate * 60 +
            (high_severity_count * 10) +
            (len(total_evidence) * 2)
        )
        chain.overall_score = min(100, chain.overall_score)

        # 生成建议
        chain.recommendations = self._generate_recommendations(chain)

    def _finding_matches_type(self, finding: Dict, req_type: str) -> bool:
        """检查发现是否匹配指定类型"""
        finding_type = str(finding.get('type', '')).lower()
        finding_name = str(finding.get('name', '')).lower()
        finding_desc = str(finding.get('description', '')).lower()
        req_lower = req_type.lower()

        # 直接匹配type
        if req_lower in finding_type:
            return True

        # 匹配name或description中的关键词
        keywords = req_lower.split('_')
        text = f"{finding_type} {finding_name} {finding_desc}"
        if all(kw in text for kw in keywords):
            return True

        # 特殊映射
        type_mappings = {
            'vulnerability': ['vuln', 'cve', '漏洞'],
            'open_port': ['port', 'open', '端口'],
            'web_vuln': ['web', 'xss', 'sql', '注入'],
            'credential': ['password', 'credential', '凭证', '密码'],
            'smb': ['smb', '445', 'microsoft-ds'],
            'hardcoded_key': ['hardcoded', 'api_key', 'secret', '密钥'],
            'ai_api': ['ai', 'api', 'model', '模型'],
            'internal_service': ['internal', '内网', 'service'],
            'firmware_vuln': ['firmware', '固件', 'iot'],
            'modbus_open': ['modbus', '502', 'plc'],
            'wifi_network': ['wifi', 'wireless', 'ssid'],
            'malware': ['malware', '恶意软件', 'trojan'],
            'c2': ['c2', 'command', 'control'],
            'contract_vuln': ['contract', 'solidity', '合约'],
            'evidence': ['evidence', 'hash', '证据', '取证'],
            'cloud_config': ['cloud', 'aws', '配置'],
        }

        for mapped_type, keywords in type_mappings.items():
            if req_lower == mapped_type:
                if any(kw in text for kw in keywords):
                    return True

        return False

    def _generate_recommendations(self, chain: AttackChain) -> List[str]:
        """生成修复建议"""
        recs = []
        if chain.status == ChainStatus.EXPLOITABLE:
            recs.append(f"⚠️ 攻击链「{chain.name}」已完全验证，可被利用，需立即修复")
        elif chain.status == ChainStatus.VERIFIED:
            recs.append(f"攻击链「{chain.name}」大部分阶段已验证，建议优先修复")
        elif chain.status == ChainStatus.PARTIALLY_VERIFIED:
            recs.append(f"攻击链「{chain.name}」部分阶段已验证，存在潜在风险")

        for stage in chain.stages:
            if stage.verified:
                recs.append(f"  - 阶段「{stage.name}」已验证: {stage.description}")
            else:
                recs.append(f"  - 阶段「{stage.name}」未验证，需关注: {stage.description}")

        return recs

    def get_summary(self) -> Dict[str, Any]:
        """获取攻击链验证摘要"""
        total = len(self.chains)
        by_status = {}
        by_risk = {}
        exploitable = []
        high_risk = []

        for chain in self.chains:
            status = chain.status.value
            risk = chain.risk_level.value
            by_status[status] = by_status.get(status, 0) + 1
            by_risk[risk] = by_risk.get(risk, 0) + 1

            if chain.status == ChainStatus.EXPLOITABLE:
                exploitable.append(chain.name)
            if chain.risk_level in [RiskLevel.CRITICAL, RiskLevel.HIGH]:
                high_risk.append(chain.name)

        avg_completion = sum(c.completion_rate for c in self.chains) / total if total else 0
        avg_score = sum(c.overall_score for c in self.chains) / total if total else 0

        return {
            "total_chains": total,
            "by_status": by_status,
            "by_risk": by_risk,
            "exploitable_chains": exploitable,
            "high_risk_chains": high_risk,
            "average_completion_rate": round(avg_completion, 3),
            "average_score": round(avg_score, 1),
            "top_chains": [
                {"name": c.name, "score": c.overall_score,
                 "status": c.status.value, "risk": c.risk_level.value}
                for c in self.chains[:5]
            ],
        }

    def to_dict(self) -> Dict[str, Any]:
        """转换为字典"""
        return {
            "summary": self.get_summary(),
            "chains": [
                {
                    "chain_id": c.chain_id,
                    "name": c.name,
                    "description": c.description,
                    "status": c.status.value,
                    "completion_rate": c.completion_rate,
                    "risk_level": c.risk_level.value,
                    "exploit_difficulty": c.exploit_difficulty,
                    "overall_score": c.overall_score,
                    "stages": [
                        {
                            "stage_id": s.stage_id,
                            "name": s.name,
                            "description": s.description,
                            "verified": s.verified,
                            "confidence": s.confidence,
                            "evidence_count": len(s.evidence),
                        }
                        for s in c.stages
                    ],
                    "recommendations": c.recommendations,
                }
                for c in self.chains
            ],
        }


# 单例模式
_validator_instance: Optional[AttackChainValidator] = None

def get_validator() -> AttackChainValidator:
    """获取全局验证器实例"""
    global _validator_instance
    if _validator_instance is None:
        _validator_instance = AttackChainValidator()
    return _validator_instance
