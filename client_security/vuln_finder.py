#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
二进制漏洞发现器
Binary Vulnerability Finder

功能：危险函数检测、漏洞模式匹配、Fuzzing模板生成、Shellcode检测
"""

import os
import re
from dataclasses import dataclass, field
from typing import List, Dict, Optional
from loguru import logger


@dataclass
class VulnerabilityFinding:
    """漏洞发现"""
    finding_id: str
    type: str  # buffer_overflow, format_string, command_injection, etc.
    name: str
    severity: str  # critical, high, medium, low, info
    description: str = ""
    location: str = ""
    evidence: str = ""
    recommendation: str = ""
    cwe: str = ""
    confidence: str = "medium"  # high, medium, low

    def to_dict(self) -> Dict:
        return {
            'finding_id': self.finding_id,
            'type': self.type,
            'name': self.name,
            'severity': self.severity,
            'description': self.description,
            'location': self.location,
            'evidence': self.evidence[:200],
            'recommendation': self.recommendation,
            'cwe': self.cwe,
            'confidence': self.confidence,
        }


@dataclass
class DangerousFunction:
    """危险函数"""
    function_name: str
    category: str  # string, memory, format, command, crypto, etc.
    risk_level: str  # critical, high, medium, low
    description: str = ""
    safe_alternative: str = ""
    cwe: str = ""
    count: int = 0
    locations: List[str] = field(default_factory=list)

    def to_dict(self) -> Dict:
        return {
            'function_name': self.function_name,
            'category': self.category,
            'risk_level': self.risk_level,
            'description': self.description,
            'safe_alternative': self.safe_alternative,
            'cwe': self.cwe,
            'count': self.count,
        }


@dataclass
class FuzzingTemplate:
    """Fuzzing模板"""
    template_id: str
    name: str
    target_function: str
    input_type: str  # file, network, stdin, argument
    description: str = ""
    payloads: List[str] = field(default_factory=list)
    mutators: List[str] = field(default_factory=list)

    def to_dict(self) -> Dict:
        return {
            'template_id': self.template_id,
            'name': self.name,
            'target_function': self.target_function,
            'input_type': self.input_type,
            'description': self.description,
            'payload_count': len(self.payloads),
        }


@dataclass
class VulnFinderResult:
    """漏洞发现结果"""
    target: str
    findings: List[VulnerabilityFinding] = field(default_factory=list)
    dangerous_functions: List[DangerousFunction] = field(default_factory=list)
    fuzzing_templates: List[FuzzingTemplate] = field(default_factory=list)
    total_findings: int = 0
    critical_count: int = 0
    high_count: int = 0
    medium_count: int = 0
    low_count: int = 0
    risk_score: float = 0.0
    risk_level: str = "low"
    summary: Dict = field(default_factory=dict)

    def to_dict(self) -> Dict:
        return {
            'target': self.target,
            'findings': [f.to_dict() for f in self.findings],
            'dangerous_functions': [d.to_dict() for d in self.dangerous_functions],
            'fuzzing_templates': [t.to_dict() for t in self.fuzzing_templates],
            'total_findings': self.total_findings,
            'critical_count': self.critical_count,
            'high_count': self.high_count,
            'medium_count': self.medium_count,
            'low_count': self.low_count,
            'risk_score': self.risk_score,
            'risk_level': self.risk_level,
            'summary': self.summary,
        }


# 危险函数库
DANGEROUS_FUNCTIONS = {
    # 字符串操作
    'strcpy': {'category': 'string', 'risk_level': 'critical', 'description': '字符串复制，无边界检查', 'safe_alternative': 'strncpy_s / strlcpy', 'cwe': 'CWE-120'},
    'strcat': {'category': 'string', 'risk_level': 'critical', 'description': '字符串拼接，无边界检查', 'safe_alternative': 'strncat_s / strlcat', 'cwe': 'CWE-120'},
    'sprintf': {'category': 'string', 'risk_level': 'high', 'description': '格式化字符串输出，无边界检查', 'safe_alternative': 'snprintf', 'cwe': 'CWE-120'},
    'vsprintf': {'category': 'string', 'risk_level': 'high', 'description': '可变参数格式化输出', 'safe_alternative': 'vsnprintf', 'cwe': 'CWE-120'},
    'gets': {'category': 'string', 'risk_level': 'critical', 'description': '读取一行输入，无边界检查', 'safe_alternative': 'fgets', 'cwe': 'CWE-120'},
    'scanf': {'category': 'string', 'risk_level': 'high', 'description': '格式化输入，可能缓冲区溢出', 'safe_alternative': 'fgets + sscanf', 'cwe': 'CWE-120'},
    # 内存操作
    'memcpy': {'category': 'memory', 'risk_level': 'high', 'description': '内存复制，需确保目标足够大', 'safe_alternative': 'memcpy_s', 'cwe': 'CWE-120'},
    'memmove': {'category': 'memory', 'risk_level': 'medium', 'description': '内存移动，需检查重叠', 'safe_alternative': 'memmove_s', 'cwe': 'CWE-120'},
    'alloca': {'category': 'memory', 'risk_level': 'high', 'description': '栈上分配内存，可能栈溢出', 'safe_alternative': 'malloc', 'cwe': 'CWE-770'},
    # 格式化字符串
    'printf': {'category': 'format', 'risk_level': 'medium', 'description': '格式化输出，用户可控格式串可导致漏洞', 'safe_alternative': '使用固定格式串', 'cwe': 'CWE-134'},
    'fprintf': {'category': 'format', 'risk_level': 'medium', 'description': '文件格式化输出', 'safe_alternative': '使用固定格式串', 'cwe': 'CWE-134'},
    'syslog': {'category': 'format', 'risk_level': 'medium', 'description': '系统日志格式化', 'safe_alternative': '使用固定格式串', 'cwe': 'CWE-134'},
    # 命令执行
    'system': {'category': 'command', 'risk_level': 'critical', 'description': '执行系统命令，可能命令注入', 'safe_alternative': 'execve / CreateProcess', 'cwe': 'CWE-78'},
    'popen': {'category': 'command', 'risk_level': 'critical', 'description': '执行命令并返回管道', 'safe_alternative': 'execve', 'cwe': 'CWE-78'},
    'WinExec': {'category': 'command', 'risk_level': 'critical', 'description': 'Windows执行命令', 'safe_alternative': 'CreateProcess', 'cwe': 'CWE-78'},
    'ShellExecute': {'category': 'command', 'risk_level': 'high', 'description': 'Windows Shell执行', 'safe_alternative': 'CreateProcess', 'cwe': 'CWE-78'},
    # 加密相关
    'MD5': {'category': 'crypto', 'risk_level': 'medium', 'description': 'MD5哈希，已被证明不安全', 'safe_alternative': 'SHA-256 / SHA-3', 'cwe': 'CWE-327'},
    'SHA1': {'category': 'crypto', 'risk_level': 'medium', 'description': 'SHA-1哈希，已被证明不安全', 'safe_alternative': 'SHA-256 / SHA-3', 'cwe': 'CWE-327'},
    'DES': {'category': 'crypto', 'risk_level': 'high', 'description': 'DES加密，已被破解', 'safe_alternative': 'AES-256', 'cwe': 'CWE-327'},
    'RC4': {'category': 'crypto', 'risk_level': 'high', 'description': 'RC4加密，存在已知攻击', 'safe_alternative': 'AES-GCM', 'cwe': 'CWE-327'},
    'rand': {'category': 'crypto', 'risk_level': 'medium', 'description': '伪随机数生成器，不适合加密', 'safe_alternative': 'CryptGenRandom / /dev/urandom', 'cwe': 'CWE-338'},
    # 路径遍历
    'fopen': {'category': 'file', 'risk_level': 'medium', 'description': '文件打开，用户可控路径可能路径遍历', 'safe_alternative': '路径规范化 + 白名单', 'cwe': 'CWE-22'},
    'open': {'category': 'file', 'risk_level': 'medium', 'description': '文件打开', 'safe_alternative': '路径规范化 + 白名单', 'cwe': 'CWE-22'},
    'CreateFile': {'category': 'file', 'risk_level': 'medium', 'description': 'Windows文件创建/打开', 'safe_alternative': '路径规范化 + 白名单', 'cwe': 'CWE-22'},
}

# 漏洞模式
VULNERABILITY_PATTERNS = [
    {
        'id': 'VULN-001',
        'type': 'buffer_overflow',
        'name': '栈缓冲区溢出',
        'severity': 'critical',
        'pattern': r'(strcpy|strcat|sprintf|gets)\s*\(',
        'description': '使用不安全的字符串函数，可能导致栈缓冲区溢出',
        'recommendation': '使用安全的替代函数，如strncpy_s、snprintf、fgets',
        'cwe': 'CWE-120',
    },
    {
        'id': 'VULN-002',
        'type': 'format_string',
        'name': '格式化字符串漏洞',
        'severity': 'high',
        'pattern': r'(printf|fprintf|sprintf|syslog)\s*\([^,)]*$',
        'description': '格式化字符串函数的格式串参数可能被用户控制',
        'recommendation': '使用固定的格式串，不要将用户输入作为格式串',
        'cwe': 'CWE-134',
    },
    {
        'id': 'VULN-003',
        'type': 'command_injection',
        'name': '命令注入',
        'severity': 'critical',
        'pattern': r'(system|popen|WinExec|ShellExecute)\s*\(',
        'description': '执行系统命令的函数，参数可能被用户控制导致命令注入',
        'recommendation': '使用execve或CreateProcess，避免使用shell解释器',
        'cwe': 'CWE-78',
    },
    {
        'id': 'VULN-004',
        'type': 'path_traversal',
        'name': '路径遍历',
        'severity': 'high',
        'pattern': r'(fopen|open|CreateFile)\s*\([^,)]*\.\.[^,)]*[,)]',
        'description': '文件操作函数的路径参数可能包含..导致路径遍历',
        'recommendation': '对路径进行规范化，使用白名单限制可访问目录',
        'cwe': 'CWE-22',
    },
    {
        'id': 'VULN-005',
        'type': 'weak_crypto',
        'name': '弱加密算法',
        'severity': 'medium',
        'pattern': r'(MD5|SHA1|DES|RC4)\s*\(',
        'description': '使用已知不安全的加密算法',
        'recommendation': '使用AES-256、SHA-256等现代安全算法',
        'cwe': 'CWE-327',
    },
    {
        'id': 'VULN-006',
        'type': 'integer_overflow',
        'name': '整数溢出',
        'severity': 'high',
        'pattern': r'malloc\s*\(\s*\w+\s*\*\s*\w+\s*\)',
        'description': 'malloc的大小参数可能整数溢出导致分配过小的缓冲区',
        'recommendation': '检查乘法溢出，使用calloc或安全的大小计算',
        'cwe': 'CWE-190',
    },
    {
        'id': 'VULN-007',
        'type': 'use_after_free',
        'name': '释放后使用',
        'severity': 'critical',
        'pattern': r'free\s*\([^)]+\)[^;]*;[^;]*(?:\1)',
        'description': '内存释放后可能继续使用',
        'recommendation': '释放后将指针置为NULL，使用智能指针',
        'cwe': 'CWE-416',
    },
    {
        'id': 'VULN-008',
        'type': 'sql_injection',
        'name': 'SQL注入',
        'severity': 'critical',
        'pattern': r'(?:sprintf|strcat|strcpy)[^;]*(?:SELECT|INSERT|UPDATE|DELETE)',
        'description': 'SQL查询字符串可能通过字符串拼接构造，存在SQL注入风险',
        'recommendation': '使用参数化查询或预编译语句',
        'cwe': 'CWE-89',
    },
]

# Fuzzing模板库
FUZZING_TEMPLATES = [
    FuzzingTemplate(
        template_id='FUZZ-001',
        name='文件解析器Fuzzing',
        target_function='parse_file',
        input_type='file',
        description='针对文件解析函数的Fuzzing模板，测试畸形文件处理',
        payloads=['A' * 100, 'A' * 1000, 'A' * 10000, '\x00' * 100, '%n' * 50, '%s' * 50],
        mutators=['bit_flip', 'byte_flip', 'arithmetic', 'interest', 'dictionary'],
    ),
    FuzzingTemplate(
        template_id='FUZZ-002',
        name='网络协议Fuzzing',
        target_function='handle_network',
        input_type='network',
        description='针对网络协议处理函数的Fuzzing模板',
        payloads=['GET /' + 'A' * 1000, 'POST /' + 'A' * 500, '\x00' * 200, 'AAAA%n%n%n'],
        mutators=['bit_flip', 'byte_flip', 'arithmetic', 'splice'],
    ),
    FuzzingTemplate(
        template_id='FUZZ-003',
        name='命令行参数Fuzzing',
        target_function='main',
        input_type='argument',
        description='针对命令行参数处理的Fuzzing模板',
        payloads=['-f ' + 'A' * 1000, '--input=' + 'A' * 2000, '-x ' + '%n' * 100, '-p ' + '\x00' * 50],
        mutators=['bit_flip', 'byte_flip', 'arithmetic', 'dictionary'],
    ),
    FuzzingTemplate(
        template_id='FUZZ-004',
        name='标准输入Fuzzing',
        target_function='read_input',
        input_type='stdin',
        description='针对标准输入处理的Fuzzing模板',
        payloads=['A' * 5000, '\x00' * 1000, '%s' * 200, 'A\nB\nC\n' * 100],
        mutators=['bit_flip', 'byte_flip', 'arithmetic', 'interest'],
    ),
]


class VulnerabilityFinder:
    """二进制漏洞发现器"""

    def __init__(self, target: str = None):
        self.target = target

    def scan(self, target: str = None, source_code: str = None) -> VulnFinderResult:
        """扫描漏洞"""
        if target:
            self.target = target

        logger.info(f"开始漏洞扫描: {self.target}")

        result = VulnFinderResult(target=self.target)

        # 1. 危险函数检测
        result.dangerous_functions = self._detect_dangerous_functions(source_code)

        # 2. 漏洞模式匹配
        result.findings = self._match_vulnerability_patterns(source_code)

        # 3. 生成Fuzzing模板
        result.fuzzing_templates = FUZZING_TEMPLATES

        # 4. 汇总
        result.total_findings = len(result.findings)
        result.critical_count = len([f for f in result.findings if f.severity == 'critical'])
        result.high_count = len([f for f in result.findings if f.severity == 'high'])
        result.medium_count = len([f for f in result.findings if f.severity == 'medium'])
        result.low_count = len([f for f in result.findings if f.severity == 'low'])

        # 危险函数风险
        critical_funcs = len([d for d in result.dangerous_functions if d.risk_level == 'critical' and d.count > 0])
        high_funcs = len([d for d in result.dangerous_functions if d.risk_level == 'high' and d.count > 0])

        # 风险评分
        result.risk_score = min(100, result.critical_count * 12 + result.high_count * 6 + result.medium_count * 2 + critical_funcs * 8 + high_funcs * 4)
        if result.risk_score >= 70:
            result.risk_level = 'critical'
        elif result.risk_score >= 50:
            result.risk_level = 'high'
        elif result.risk_score >= 30:
            result.risk_level = 'medium'
        else:
            result.risk_level = 'low'

        result.summary = {
            'total_findings': result.total_findings,
            'critical': result.critical_count,
            'high': result.high_count,
            'medium': result.medium_count,
            'low': result.low_count,
            'dangerous_functions': len(result.dangerous_functions),
            'critical_functions': critical_funcs,
            'high_functions': high_funcs,
            'fuzzing_templates': len(result.fuzzing_templates),
        }

        logger.info(f"漏洞扫描完成: {result.total_findings} 发现, 风险等级={result.risk_level}")
        return result

    def _detect_dangerous_functions(self, source_code: str = None) -> List[DangerousFunction]:
        """检测危险函数"""
        dangerous = []

        # 如果没有源代码，从二进制字符串中检测（简化）
        if not source_code and self.target and os.path.exists(self.target):
            try:
                with open(self.target, 'rb') as f:
                    data = f.read()
                source_code = data.decode('ascii', errors='ignore')
            except Exception:
                source_code = ""

        if not source_code:
            # 返回空列表但包含所有已知危险函数（count=0）
            for func_name, info in DANGEROUS_FUNCTIONS.items():
                dangerous.append(DangerousFunction(
                    function_name=func_name,
                    category=info['category'],
                    risk_level=info['risk_level'],
                    description=info['description'],
                    safe_alternative=info['safe_alternative'],
                    cwe=info['cwe'],
                    count=0,
                ))
            return dangerous

        # 检测危险函数
        for func_name, info in DANGEROUS_FUNCTIONS.items():
            pattern = re.compile(r'\b' + re.escape(func_name) + r'\s*\(', re.IGNORECASE)
            matches = list(pattern.finditer(source_code))

            df = DangerousFunction(
                function_name=func_name,
                category=info['category'],
                risk_level=info['risk_level'],
                description=info['description'],
                safe_alternative=info['safe_alternative'],
                cwe=info['cwe'],
                count=len(matches),
                locations=[f"offset:{m.start()}" for m in matches[:5]],
            )
            dangerous.append(df)

        # 只返回有检测到的或高风险的
        return [d for d in dangerous if d.count > 0 or d.risk_level in ['critical', 'high']]

    def _match_vulnerability_patterns(self, source_code: str = None) -> List[VulnerabilityFinding]:
        """匹配漏洞模式"""
        findings = []

        if not source_code and self.target and os.path.exists(self.target):
            try:
                with open(self.target, 'rb') as f:
                    data = f.read()
                source_code = data.decode('ascii', errors='ignore')
            except Exception:
                source_code = ""

        if not source_code:
            return findings

        for pattern_info in VULNERABILITY_PATTERNS:
            try:
                pattern = re.compile(pattern_info['pattern'], re.IGNORECASE | re.MULTILINE)
                matches = list(pattern.finditer(source_code))

                if matches:
                    for i, match in enumerate(matches[:3]):  # 限制每个模式最多3个发现
                        findings.append(VulnerabilityFinding(
                            finding_id=f"{pattern_info['id']}-{i+1}",
                            type=pattern_info['type'],
                            name=pattern_info['name'],
                            severity=pattern_info['severity'],
                            description=pattern_info['description'],
                            location=f"offset:{match.start()}",
                            evidence=match.group()[:100],
                            recommendation=pattern_info['recommendation'],
                            cwe=pattern_info['cwe'],
                            confidence='medium',
                        ))
            except re.error:
                continue

        return findings


def quick_find_vulnerabilities(target: str, source_code: str = None) -> Dict:
    """快速漏洞发现"""
    finder = VulnerabilityFinder(target=target)
    result = finder.scan(source_code=source_code)
    return result.to_dict()
