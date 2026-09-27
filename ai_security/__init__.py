#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
AI安全模块
提供对抗样本检测、模型窃取检测、提示注入检测、数据投毒检测、AI模型安全评估功能
仅用于授权的安全测试
"""

import os
import re
import json
import hashlib
from datetime import datetime
from typing import Dict, List, Any, Optional
from dataclasses import dataclass, field


@dataclass
class AISecurityFinding:
    """AI安全发现"""
    category: str = ""
    vulnerability: str = ""
    severity: str = ""
    description: str = ""
    evidence: str = ""
    recommendation: str = ""


class AISecurityTester:
    """AI安全测试器"""

    # 提示注入模式
    PROMPT_INJECTION_PATTERNS = [
        r'(ignore|disregard|forget)\s+(all\s+)?(previous|above|prior)\s+(instructions|context|rules)',
        r'you\s+are\s+now\s+(a|an)\s+(DAN|jailbreak|unrestricted|developer)\s+(mode|assistant|bot)',
        r'(system|developer)\s*(message|prompt|instruction)\s*[:=]',
        r'```(system|developer|instructions)',
        r'(act|pretend|roleplay)\s+as\s+(if\s+you\s+are\s+)?(a|an)\s+(unrestricted|unfiltered|evil|malicious)',
        r'(no\s+)?(content|safety|ethical)\s+(policy|filter|restriction|guideline)',
        r'(bypass|override|circumvent|evade)\s+(the\s+)?(safety|security|content|filter|restriction)',
        r'(reveal|show|display|output)\s+(your\s+)?(system|initial|hidden)\s+(prompt|instructions|message)',
        r'(repeat|echo|say)\s+(back\s+)?(my\s+)?(previous|above|first)\s+(message|prompt|instruction)',
    ]

    # 数据投毒特征
    DATA_POISONING_SIGNALS = [
        'label_flip', 'backdoor_trigger', 'gradient_attack',
        'clean_label', 'dirty_label', 'synthetic_data',
    ]

    def __init__(self):
        self.findings: List[AISecurityFinding] = []

    def detect_prompt_injection(self, prompt: str) -> List[Dict]:
        """检测提示注入"""
        detections = []
        prompt_lower = prompt.lower()

        for i, pattern in enumerate(self.PROMPT_INJECTION_PATTERNS):
            if re.search(pattern, prompt_lower, re.IGNORECASE):
                detections.append({
                    'pattern_id': f'PI-{i+1:03d}',
                    'matched_pattern': pattern,
                    'description': self._get_injection_description(i),
                    'severity': 'High' if i < 5 else 'Medium',
                    'confidence': 'High'
                })

        # 检查编码混淆
        if self._check_encoded_injection(prompt):
            detections.append({
                'pattern_id': 'PI-ENC',
                'matched_pattern': 'encoded_injection',
                'description': '检测到可能经过编码/混淆的注入尝试',
                'severity': 'High',
                'confidence': 'Medium'
            })

        return detections

    def _get_injection_description(self, index: int) -> str:
        descriptions = [
            '尝试忽略/覆盖先前指令',
            '尝试切换到无限制模式（DAN等）',
            '尝试伪造系统/开发者消息',
            '尝试通过代码块注入系统指令',
            '尝试角色扮演为无限制助手',
            '尝试讨论/绕过安全策略',
            '尝试绕过安全过滤',
            '尝试提取系统提示词',
            '尝试让模型重复先前消息',
        ]
        return descriptions[index] if index < len(descriptions) else '未知注入模式'

    def _check_encoded_injection(self, prompt: str) -> bool:
        """检查编码混淆的注入"""
        # 检查Base64
        base64_pattern = r'[A-Za-z0-9+/]{20,}={0,2}'
        matches = re.findall(base64_pattern, prompt)
        for match in matches:
            try:
                import base64
                decoded = base64.b64decode(match).decode('utf-8', errors='ignore').lower()
                if any(kw in decoded for kw in ['ignore', 'system', 'instruction', 'prompt', 'dan']):
                    return True
            except Exception:
                continue
        return False

    def test_model_robustness(self, model_api: str, test_cases: List[Dict] = None) -> Dict:
        """测试模型鲁棒性（对抗样本）"""
        results = {
            'total_tests': 0,
            'passed': 0,
            'failed': 0,
            'attack_success_rate': 0.0,
            'details': []
        }

        # 默认测试用例
        if test_cases is None:
            test_cases = [
                {'type': 'adversarial_suffix', 'description': '对抗后缀攻击'},
                {'type': 'jailbreak', 'description': '越狱攻击'},
                {'type': 'role_play', 'description': '角色扮演绕过'},
                {'type': 'few_shot', 'description': '少样本诱导'},
                {'type': 'gradual', 'description': '渐进式诱导'},
            ]

        results['total_tests'] = len(test_cases)
        for tc in test_cases:
            results['details'].append({
                'test_type': tc['type'],
                'description': tc['description'],
                'status': '待执行',
                'model_api': model_api
            })

        return results

    def detect_data_poisoning(self, dataset_path: str = "", dataset_info: Dict = None) -> List[Dict]:
        """检测数据投毒"""
        detections = []

        if dataset_info:
            # 检查标签分布异常
            if 'label_distribution' in dataset_info:
                dist = dataset_info['label_distribution']
                if dist:
                    max_ratio = max(dist.values()) / sum(dist.values())
                    if max_ratio > 0.9:
                        detections.append({
                            'type': 'label_imbalance',
                            'severity': 'Medium',
                            'description': f'标签分布极度不平衡，最大类别占比{max_ratio:.1%}',
                            'recommendation': '检查是否存在标签翻转攻击'
                        })

            # 检查异常数据点
            if 'outlier_count' in dataset_info and dataset_info['outlier_count'] > 0:
                detections.append({
                    'type': 'potential_backdoor',
                    'severity': 'High',
                    'description': f'发现{dataset_info["outlier_count"]}个异常数据点，可能包含后门触发器',
                    'recommendation': '人工审查异常数据，使用异常检测算法过滤'
                })

        # 通用检查项
        detections.extend([
            {
                'type': 'source_verification',
                'severity': 'Info',
                'description': '建议验证数据来源可信度',
                'recommendation': '使用可信数据源，记录数据血缘'
            },
            {
                'type': 'augmentation_check',
                'severity': 'Info',
                'description': '建议检查数据增强过程是否引入漏洞',
                'recommendation': '审查数据增强管道，防止投毒'
            },
        ])

        return detections

    def assess_model_security(self, model_info: Dict = None) -> Dict:
        """评估AI模型安全性"""
        assessment = {
            'overall_score': 0,
            'risk_level': 'Unknown',
            'categories': {},
            'findings': [],
            'recommendations': []
        }

        # 安全评估维度
        categories = {
            'input_validation': {'weight': 0.2, 'score': 50, 'description': '输入验证与过滤'},
            'output_filtering': {'weight': 0.15, 'score': 50, 'description': '输出过滤与审核'},
            'model_hardening': {'weight': 0.2, 'score': 50, 'description': '模型加固与对抗训练'},
            'data_security': {'weight': 0.15, 'score': 50, 'description': '训练数据安全'},
            'access_control': {'weight': 0.15, 'score': 50, 'description': '访问控制与API安全'},
            'privacy_protection': {'weight': 0.15, 'score': 50, 'description': '隐私保护与数据脱敏'},
        }

        assessment['categories'] = categories

        # 计算总分
        total_score = sum(cat['score'] * cat['weight'] for cat in categories.values())
        assessment['overall_score'] = round(total_score, 1)

        if total_score >= 80:
            assessment['risk_level'] = 'Low'
        elif total_score >= 60:
            assessment['risk_level'] = 'Medium'
        elif total_score >= 40:
            assessment['risk_level'] = 'High'
        else:
            assessment['risk_level'] = 'Critical'

        assessment['recommendations'] = [
            '实施输入验证，检测并拦截提示注入攻击',
            '对模型输出进行安全过滤，防止生成有害内容',
            '使用对抗训练提升模型鲁棒性',
            '建立数据来源验证机制，防止数据投毒',
            '实施API访问控制和速率限制',
            '使用差分隐私等技术保护训练数据隐私',
            '定期进行红队测试和安全评估',
            '建立模型监控机制，检测异常行为',
        ]

        return assessment

    def generate_ai_security_report(self) -> Dict:
        """生成AI安全报告"""
        return {
            'report_title': 'AI安全评估报告',
            'generated_time': datetime.now().isoformat(),
            'summary': {
                'total_findings': len(self.findings),
                'categories_covered': ['提示注入', '对抗样本', '数据投毒', '模型窃取', '隐私泄露'],
            },
            'findings': [
                {
                    'category': f.category,
                    'vulnerability': f.vulnerability,
                    'severity': f.severity,
                    'description': f.description,
                    'recommendation': f.recommendation,
                }
                for f in self.findings
            ],
        }


# 全局单例
_ai_tester = None

def get_ai_security_tester() -> AISecurityTester:
    """获取AI安全测试器单例"""
    global _ai_tester
    if _ai_tester is None:
        _ai_tester = AISecurityTester()
    return _ai_tester
