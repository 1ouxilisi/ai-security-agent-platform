#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Prompt注入检测器
Prompt Injection Detector

功能：Prompt注入检测、越狱检测、系统提示泄露检测、恶意指令识别
"""

import re
import json
from dataclasses import dataclass, field
from typing import List, Dict, Optional, Tuple
from loguru import logger


@dataclass
class InjectionFinding:
    """注入发现"""
    finding_id: str
    type: str  # prompt_injection, jailbreak, system_leak, malicious_instruction, etc.
    name: str
    severity: str  # critical, high, medium, low, info
    description: str = ""
    matched_pattern: str = ""
    matched_text: str = ""
    confidence: float = 0.0
    recommendation: str = ""
    cwe: str = ""

    def to_dict(self) -> Dict:
        return {
            'finding_id': self.finding_id,
            'type': self.type,
            'name': self.name,
            'severity': self.severity,
            'description': self.description,
            'matched_pattern': self.matched_pattern,
            'matched_text': self.matched_text[:200],
            'confidence': self.confidence,
            'recommendation': self.recommendation,
            'cwe': self.cwe,
        }


@dataclass
class PromptAnalysisResult:
    """Prompt分析结果"""
    prompt: str
    is_safe: bool = True
    risk_score: float = 0.0
    risk_level: str = "low"
    findings: List[InjectionFinding] = field(default_factory=list)
    prompt_length: int = 0
    word_count: int = 0
    has_system_instructions: bool = False
    has_jailbreak_attempt: bool = False
    has_malicious_instruction: bool = False
    summary: Dict = field(default_factory=dict)

    def to_dict(self) -> Dict:
        return {
            'is_safe': self.is_safe,
            'risk_score': self.risk_score,
            'risk_level': self.risk_level,
            'findings': [f.to_dict() for f in self.findings],
            'prompt_length': self.prompt_length,
            'word_count': self.word_count,
            'has_system_instructions': self.has_system_instructions,
            'has_jailbreak_attempt': self.has_jailbreak_attempt,
            'has_malicious_instruction': self.has_malicious_instruction,
            'summary': self.summary,
        }


# Prompt注入模式库
INJECTION_PATTERNS = [
    # 直接指令覆盖
    {
        'id': 'INJ-001',
        'type': 'prompt_injection',
        'name': '忽略之前的指令',
        'severity': 'critical',
        'pattern': r'(?i)(ignore|disregard|forget|skip)\s+(all\s+)?(previous|prior|above|earlier)\s+(instructions?|commands?|rules?|context)',
        'description': '尝试让模型忽略之前的系统指令',
        'recommendation': '对用户输入进行过滤，禁止包含指令覆盖关键词',
        'cwe': 'CWE-77',
        'confidence': 0.95,
    },
    {
        'id': 'INJ-002',
        'type': 'prompt_injection',
        'name': '系统指令重置',
        'severity': 'critical',
        'pattern': r'(?i)(you\s+are\s+now|from\s+now\s+on|your\s+new\s+(role|instructions?|system\s+prompt)\s+is)',
        'description': '尝试重新定义模型的角色或系统指令',
        'recommendation': '禁止用户输入包含角色定义关键词',
        'cwe': 'CWE-77',
        'confidence': 0.9,
    },
    {
        'id': 'INJ-003',
        'type': 'prompt_injection',
        'name': '显示系统提示',
        'severity': 'high',
        'pattern': r'(?i)(show|reveal|display|print|output|tell\s+me)\s+(your\s+)?(system\s+)?(prompt|instructions?|rules?|initial\s+message)',
        'description': '尝试让模型输出系统提示词',
        'recommendation': '系统提示词不应被输出，添加输出过滤',
        'cwe': 'CWE-200',
        'confidence': 0.85,
    },
    # 越狱模式
    {
        'id': 'JAIL-001',
        'type': 'jailbreak',
        'name': 'DAN模式',
        'severity': 'critical',
        'pattern': r'(?i)(DAN|do\s+anything\s+now|jailbreak|unrestricted\s+mode|developer\s+mode)',
        'description': '尝试激活DAN（Do Anything Now）越狱模式',
        'recommendation': '禁止包含越狱模式关键词',
        'cwe': 'CWE-77',
        'confidence': 0.95,
    },
    {
        'id': 'JAIL-002',
        'type': 'jailbreak',
        'name': '角色扮演绕过',
        'severity': 'high',
        'pattern': r'(?i)(act\s+as|pretend\s+to\s+be|roleplay|role\s+play)\s+(as\s+)?(a\s+)?(hack|criminal|evil|unethical|immoral|illegal)',
        'description': '通过角色扮演绕过安全限制',
        'recommendation': '限制角色扮演的范围，禁止危险角色',
        'cwe': 'CWE-77',
        'confidence': 0.85,
    },
    {
        'id': 'JAIL-003',
        'type': 'jailbreak',
        'name': '假设场景绕过',
        'severity': 'high',
        'pattern': r'(?i)(hypothetically|in\s+a\s+hypothetical\s+scenario|for\s+educational\s+purposes|for\s+research|just\s+asking|no\s+harm\s+will\s+come)',
        'description': '通过假设场景或教育目的绕过安全限制',
        'recommendation': '对假设性请求仍需进行安全检查',
        'cwe': 'CWE-77',
        'confidence': 0.7,
    },
    {
        'id': 'JAIL-004',
        'type': 'jailbreak',
        'name': '令牌耗尽攻击',
        'severity': 'medium',
        'pattern': r'(?i)(token|context)\s+(limit|window|length)\s+(is|has\s+been)\s+(reached|exceeded|full)',
        'description': '尝试通过声称令牌耗尽来绕过安全检查',
        'recommendation': '不依赖用户声称的状态，使用实际系统状态',
        'cwe': 'CWE-77',
        'confidence': 0.6,
    },
    # 恶意指令
    {
        'id': 'MAL-001',
        'type': 'malicious_instruction',
        'name': '生成恶意代码',
        'severity': 'critical',
        'pattern': r'(?i)(write|create|generate|produce)\s+(a\s+)?(virus|malware|ransomware|trojan|worm|exploit|payload|rootkit|keylogger)',
        'description': '请求生成恶意软件或攻击代码',
        'recommendation': '禁止生成恶意代码，提供安全替代方案',
        'cwe': 'CWE-94',
        'confidence': 0.9,
    },
    {
        'id': 'MAL-002',
        'type': 'malicious_instruction',
        'name': '攻击指导',
        'severity': 'critical',
        'pattern': r'(?i)(how\s+to|steps?\s+to|guide\s+to|tutorial\s+for)\s+(hack|crack|exploit|attack|breach|penetrate|bypass)\s+(a\s+)?(system|network|website|account|password|firewall)',
        'description': '请求攻击方法指导',
        'recommendation': '拒绝提供攻击指导，提供防御性安全建议',
        'cwe': 'CWE-94',
        'confidence': 0.85,
    },
    {
        'id': 'MAL-003',
        'type': 'malicious_instruction',
        'name': '社会工程学',
        'severity': 'high',
        'pattern': r'(?i)(phish|social\s+engineer|impersonat|pretend\s+to\s+be\s+(a\s+)?(bank|police|government|company))',
        'description': '请求社会工程学攻击方法',
        'recommendation': '拒绝提供社会工程学指导',
        'cwe': 'CWE-94',
        'confidence': 0.8,
    },
    {
        'id': 'MAL-004',
        'type': 'malicious_instruction',
        'name': '数据窃取',
        'severity': 'critical',
        'pattern': r'(?i)(steal|extract|exfiltrat|leak)\s+(data|information|credentials|passwords|personal\s+info)',
        'description': '请求数据窃取方法',
        'recommendation': '拒绝提供数据窃取指导',
        'cwe': 'CWE-94',
        'confidence': 0.9,
    },
    # 编码绕过
    {
        'id': 'ENC-001',
        'type': 'encoding_bypass',
        'name': 'Base64编码绕过',
        'severity': 'medium',
        'pattern': r'[A-Za-z0-9+/]{20,}={0,2}',
        'description': '可能包含Base64编码的恶意内容',
        'recommendation': '解码后进行安全检查',
        'cwe': 'CWE-77',
        'confidence': 0.5,
    },
    {
        'id': 'ENC-002',
        'type': 'encoding_bypass',
        'name': 'Unicode混淆',
        'severity': 'low',
        'pattern': r'[\u200b-\u200f\ufeff\u202a-\u202e]',
        'description': '包含零宽字符或双向控制字符，可能用于混淆',
        'recommendation': '移除不可见字符后进行检查',
        'cwe': 'CWE-77',
        'confidence': 0.6,
    },
    # 间接提示注入
    {
        'id': 'IND-001',
        'type': 'indirect_injection',
        'name': '外部内容指令',
        'severity': 'high',
        'pattern': r'(?i](the\s+)?(following|above|below|preceding)\s+(text|content|document|message|instructions?)\s+(says?|states?|contains?|instructs?)',
        'description': '尝试通过引用外部内容注入指令',
        'recommendation': '对外部内容进行隔离和过滤',
        'cwe': 'CWE-77',
        'confidence': 0.75,
    },
]


class PromptInjectionDetector:
    """Prompt注入检测器"""

    def __init__(self):
        self.patterns = INJECTION_PATTERNS
        logger.info("Prompt注入检测器初始化完成")

    def analyze(self, prompt: str) -> PromptAnalysisResult:
        """分析Prompt是否包含注入"""
        logger.info(f"开始分析Prompt: 长度={len(prompt)}")

        result = PromptAnalysisResult(
            prompt=prompt,
            prompt_length=len(prompt),
            word_count=len(prompt.split()),
        )

        # 1. 模式匹配
        findings = []
        for pattern_info in self.patterns:
            try:
                matches = list(re.finditer(pattern_info['pattern'], prompt, re.IGNORECASE | re.MULTILINE))
                for i, match in enumerate(matches[:3]):  # 每个模式最多3个匹配
                    finding = InjectionFinding(
                        finding_id=f"{pattern_info['id']}-{i+1}",
                        type=pattern_info['type'],
                        name=pattern_info['name'],
                        severity=pattern_info['severity'],
                        description=pattern_info['description'],
                        matched_pattern=pattern_info['pattern'],
                        matched_text=match.group(),
                        confidence=pattern_info['confidence'],
                        recommendation=pattern_info['recommendation'],
                        cwe=pattern_info['cwe'],
                    )
                    findings.append(finding)
            except re.error:
                continue

        result.findings = findings

        # 2. 风险评估
        critical = len([f for f in findings if f.severity == 'critical'])
        high = len([f for f in findings if f.severity == 'high'])
        medium = len([f for f in findings if f.severity == 'medium'])
        low = len([f for f in findings if f.severity == 'low'])

        result.risk_score = min(100, critical * 15 + high * 8 + medium * 3 + low * 1)
        if result.risk_score >= 70:
            result.risk_level = 'critical'
            result.is_safe = False
        elif result.risk_score >= 50:
            result.risk_level = 'high'
            result.is_safe = False
        elif result.risk_score >= 30:
            result.risk_level = 'medium'
        else:
            result.risk_level = 'low'

        # 3. 特征标记
        result.has_system_instructions = any(f.type == 'prompt_injection' for f in findings)
        result.has_jailbreak_attempt = any(f.type == 'jailbreak' for f in findings)
        result.has_malicious_instruction = any(f.type == 'malicious_instruction' for f in findings)

        # 4. 汇总
        result.summary = {
            'total_findings': len(findings),
            'critical': critical,
            'high': high,
            'medium': medium,
            'low': low,
            'is_safe': result.is_safe,
            'risk_level': result.risk_level,
            'risk_score': result.risk_score,
            'prompt_length': result.prompt_length,
            'word_count': result.word_count,
        }

        logger.info(f"Prompt分析完成: 安全={result.is_safe}, 风险等级={result.risk_level}, 发现={len(findings)}")
        return result

    def is_safe(self, prompt: str) -> bool:
        """快速检查Prompt是否安全"""
        result = self.analyze(prompt)
        return result.is_safe

    def sanitize(self, prompt: str) -> Tuple[str, List[str]]:
        """清理Prompt中的危险内容"""
        sanitized = prompt
        removed = []

        # 移除零宽字符
        zero_width = re.findall(r'[\u200b-\u200f\ufeff\u202a-\u202e]', prompt)
        if zero_width:
            sanitized = re.sub(r'[\u200b-\u200f\ufeff\u202a-\u202e]', '', sanitized)
            removed.append(f"移除了 {len(zero_width)} 个零宽字符")

        # 标记危险关键词（不删除，只标记）
        dangerous_keywords = ['ignore previous', 'system prompt', 'DAN', 'jailbreak',
                            'do anything now', 'you are now']
        for keyword in dangerous_keywords:
            if keyword.lower() in sanitized.lower():
                removed.append(f"检测到危险关键词: {keyword}")

        return sanitized, removed


def quick_detect_prompt_injection(prompt: str) -> Dict:
    """快速检测Prompt注入"""
    detector = PromptInjectionDetector()
    result = detector.analyze(prompt)
    return result.to_dict()
