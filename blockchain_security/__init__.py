#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
区块链安全模块
提供智能合约审计、重入攻击检测、整数溢出检测、权限漏洞检测功能
仅用于授权的安全测试
"""

import os
import re
import json
from datetime import datetime
from typing import Dict, List, Any, Optional
from dataclasses import dataclass, field


@dataclass
class ContractVulnerability:
    """智能合约漏洞"""
    vulnerability_type: str = ""
    severity: str = ""
    description: str = ""
    location: str = ""
    code_snippet: str = ""
    recommendation: str = ""
    cwe: str = ""


class BlockchainSecurityAuditor:
    """区块链安全审计器"""

    # Solidity漏洞模式
    SOLIDITY_PATTERNS = [
        {
            'type': '重入攻击',
            'pattern': r'\.(call|send|transfer)\s*\(',
            'severity': 'Critical',
            'description': '外部调用可能导致重入攻击',
            'recommendation': '使用检查-生效-交互模式，在外部调用前更新状态',
            'cwe': 'CWE-841'
        },
        {
            'type': '整数溢出',
            'pattern': r'(uint|int)[0-9]*\s+\w+\s*[+\-*/]=',
            'severity': 'High',
            'description': '整数运算可能溢出（Solidity 0.8以下版本）',
            'recommendation': '使用SafeMath库或升级到Solidity 0.8+',
            'cwe': 'CWE-190'
        },
        {
            'type': 'tx.origin钓鱼',
            'pattern': r'tx\.origin',
            'severity': 'High',
            'description': '使用tx.origin进行认证可能被钓鱼攻击利用',
            'recommendation': '使用msg.sender代替tx.origin进行认证',
            'cwe': 'CWE-477'
        },
        {
            'type': '未检查返回值',
            'pattern': r'\.(call|send)\s*\([^)]*\)\s*;',
            'severity': 'Medium',
            'description': '未检查外部调用的返回值',
            'recommendation': '检查所有外部调用的返回值',
            'cwe': 'CWE-252'
        },
        {
            'type': '时间戳依赖',
            'pattern': r'block\.timestamp',
            'severity': 'Medium',
            'description': '依赖区块时间戳可能被矿工操纵',
            'recommendation': '避免使用block.timestamp进行关键逻辑判断',
            'cwe': 'CWE-829'
        },
        {
            'type': '硬编码地址',
            'pattern': r'0x[a-fA-F0-9]{40}',
            'severity': 'Low',
            'description': '硬编码地址可能导致合约不可升级',
            'recommendation': '使用可配置的地址或代理模式',
            'cwe': 'CWE-798'
        },
        {
            'type': '缺少事件',
            'pattern': r'function\s+(transfer|mint|burn|pause)',
            'severity': 'Low',
            'description': '关键操作缺少事件日志',
            'recommendation': '为所有关键状态变更添加事件',
            'cwe': 'CWE-778'
        },
        {
            'type': '可见性问题',
            'pattern': r'function\s+\w+\s*\([^)]*\)\s*(public|external)?\s*(?!view|pure)',
            'severity': 'Medium',
            'description': '函数可见性可能设置不当',
            'recommendation': '明确设置函数可见性（public/external/internal/private）',
            'cwe': 'CWE-284'
        },
    ]

    def __init__(self):
        self.vulnerabilities: List[ContractVulnerability] = []

    def audit_solidity_contract(self, contract_code: str = "", file_path: str = "") -> List[ContractVulnerability]:
        """审计Solidity智能合约"""
        vulns = []

        if file_path and os.path.exists(file_path):
            with open(file_path, 'r', encoding='utf-8') as f:
                contract_code = f.read()

        if not contract_code:
            return vulns

        lines = contract_code.split('\n')

        for pattern_info in self.SOLIDITY_PATTERNS:
            for line_num, line in enumerate(lines, 1):
                if re.search(pattern_info['pattern'], line):
                    vuln = ContractVulnerability(
                        vulnerability_type=pattern_info['type'],
                        severity=pattern_info['severity'],
                        description=pattern_info['description'],
                        location=f'Line {line_num}',
                        code_snippet=line.strip()[:200],
                        recommendation=pattern_info['recommendation'],
                        cwe=pattern_info['cwe']
                    )
                    vulns.append(vuln)
                    break  # 每种漏洞类型只报告一次

        self.vulnerabilities = vulns
        return vulns

    def check_erc20_compliance(self, contract_code: str = "") -> Dict:
        """检查ERC20合规性"""
        required_functions = ['totalSupply', 'balanceOf', 'transfer', 'transferFrom', 'approve', 'allowance']
        required_events = ['Transfer', 'Approval']

        found_functions = [f for f in required_functions if f'function {f}' in contract_code]
        found_events = [e for e in required_events if f'event {e}' in contract_code]

        return {
            'is_compliant': len(found_functions) == len(required_functions) and len(found_events) == len(required_events),
            'missing_functions': [f for f in required_functions if f not in found_functions],
            'missing_events': [e for e in required_events if e not in found_events],
            'found_functions': found_functions,
            'found_events': found_events,
        }

    def generate_audit_report(self) -> Dict:
        """生成审计报告"""
        stats = {
            'total': len(self.vulnerabilities),
            'critical': len([v for v in self.vulnerabilities if v.severity == 'Critical']),
            'high': len([v for v in self.vulnerabilities if v.severity == 'High']),
            'medium': len([v for v in self.vulnerabilities if v.severity == 'Medium']),
            'low': len([v for v in self.vulnerabilities if v.severity == 'Low']),
        }

        return {
            'report_title': '智能合约安全审计报告',
            'generated_time': datetime.now().isoformat(),
            'statistics': stats,
            'overall_risk': 'Critical' if stats['critical'] > 0 else 'High' if stats['high'] > 0 else 'Medium' if stats['medium'] > 0 else 'Low',
            'vulnerabilities': [
                {
                    'type': v.vulnerability_type,
                    'severity': v.severity,
                    'description': v.description,
                    'location': v.location,
                    'code_snippet': v.code_snippet,
                    'recommendation': v.recommendation,
                    'cwe': v.cwe,
                }
                for v in self.vulnerabilities
            ],
            'recommendations': [
                '使用专业审计工具（Mythril、Slither、Securify）',
                '进行人工代码审查',
                '部署前进行测试网验证',
                '考虑使用形式化验证',
                '建立漏洞赏金计划',
            ],
        }


# 全局单例
_blockchain_auditor = None

def get_blockchain_security_auditor() -> BlockchainSecurityAuditor:
    global _blockchain_auditor
    if _blockchain_auditor is None:
        _blockchain_auditor = BlockchainSecurityAuditor()
    return _blockchain_auditor
