#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
取证分析模块
提供内存取证、日志分析、文件恢复、时间线重建、恶意软件分析功能
仅用于授权的安全测试和取证调查
"""

import os
import re
import json
import hashlib
from datetime import datetime
from typing import Dict, List, Any, Optional
from dataclasses import dataclass, field


@dataclass
class ForensicArtifact:
    """取证证据"""
    artifact_type: str = ""
    source: str = ""
    timestamp: str = ""
    description: str = ""
    evidence: str = ""
    hash_md5: str = ""
    hash_sha256: str = ""


class ForensicAnalyzer:
    """取证分析器"""

    # Windows日志事件ID
    WINDOWS_EVENT_IDS = {
        4624: '登录成功',
        4625: '登录失败',
        4634: '注销',
        4648: '使用显式凭证登录',
        4672: '管理员登录',
        4688: '进程创建',
        4697: '服务安装',
        4702: '计划任务创建/修改',
        4720: '用户账户创建',
        4726: '用户账户删除',
        4732: '成员添加到安全启用的本地组',
        4740: '用户账户被锁定',
        4776: '域控制器验证账户凭据',
        4798: '本地组成员枚举',
        5140: '网络共享对象被访问',
        5145: '网络共享对象被检查',
        7045: '新服务安装',
        1102: '审计日志被清除',
    }

    # 可疑进程名
    SUSPICIOUS_PROCESSES = [
        'mimikatz', 'cobaltstrike', 'metasploit', 'meterpreter',
        'nc.exe', 'netcat', 'psexec', 'wce', 'fgdump',
        'powershell -enc', 'powershell -e ', 'cmd /c ',
        'regsvr32', 'mshta', 'rundll32', 'installutil',
    ]

    # 可疑文件路径
    SUSPICIOUS_PATHS = [
        r'C:\\Windows\\Temp\\',
        r'C:\\Users\\.*\\AppData\\Local\\Temp\\',
        r'C:\\ProgramData\\',
        r'/tmp/',
        r'/var/tmp/',
        r'/dev/shm/',
    ]

    def __init__(self):
        self.artifacts: List[ForensicArtifact] = []
        self.timeline: List[Dict] = []

    def analyze_windows_logs(self, log_file: str = "", log_type: str = "Security") -> List[Dict]:
        """分析Windows日志"""
        events = []

        # 简化版日志分析
        suspicious_events = [
            {'event_id': 4625, 'description': '大量登录失败', 'severity': 'Medium', 'indicator': '暴力破解'},
            {'event_id': 4648, 'description': '使用显式凭证登录', 'severity': 'High', 'indicator': '凭证使用'},
            {'event_id': 4688, 'description': '可疑进程创建', 'severity': 'High', 'indicator': '恶意软件执行'},
            {'event_id': 4697, 'description': '服务安装', 'severity': 'High', 'indicator': '持久化'},
            {'event_id': 4702, 'description': '计划任务创建', 'severity': 'High', 'indicator': '持久化'},
            {'event_id': 4720, 'description': '用户账户创建', 'severity': 'Medium', 'indicator': '账户创建'},
            {'event_id': 1102, 'description': '审计日志被清除', 'severity': 'Critical', 'indicator': '反取证'},
        ]

        for event in suspicious_events:
            events.append({
                'event_id': event['event_id'],
                'event_name': self.WINDOWS_EVENT_IDS.get(event['event_id'], '未知'),
                'description': event['description'],
                'severity': event['severity'],
                'indicator': event['indicator'],
                'count': 0,
                'first_seen': '',
                'last_seen': '',
            })

        return events

    def analyze_processes(self, process_list: List[Dict] = None) -> List[Dict]:
        """分析进程列表"""
        suspicious = []

        if process_list is None:
            return suspicious

        for proc in process_list:
            proc_name = (proc.get('name', '') + ' ' + proc.get('command_line', '')).lower()
            for susp in self.SUSPICIOUS_PROCESSES:
                if susp.lower() in proc_name:
                    suspicious.append({
                        'pid': proc.get('pid'),
                        'name': proc.get('name'),
                        'command_line': proc.get('command_line'),
                        'matched_pattern': susp,
                        'severity': 'High',
                        'description': f'检测到可疑进程: {susp}',
                        'recommendation': '隔离该进程，进行恶意软件分析'
                    })
                    break

        return suspicious

    def analyze_file_system(self, directory: str = "") -> List[Dict]:
        """分析文件系统"""
        findings = []

        # 检查可疑文件
        suspicious_extensions = ['.exe', '.dll', '.ps1', '.bat', '.cmd', '.vbs', '.js', '.jar']
        suspicious_names = ['mimikatz', 'cobalt', 'beacon', 'stager', 'payload', 'shell', 'reverse']

        findings.append({
            'type': 'suspicious_extensions',
            'description': f'检查目录中的可疑可执行文件: {", ".join(suspicious_extensions)}',
            'severity': 'Info',
            'recommendation': '审查所有可执行文件的来源和完整性'
        })

        findings.append({
            'type': 'suspicious_names',
            'description': f'检查文件名中是否包含恶意软件特征: {", ".join(suspicious_names)}',
            'severity': 'Info',
            'recommendation': '对匹配的文件进行哈希查询和沙箱分析'
        })

        findings.append({
            'type': 'recent_files',
            'description': '检查最近修改的文件（攻击者可能留下工具）',
            'severity': 'Info',
            'recommendation': '按修改时间排序，审查最近24小时内修改的文件'
        })

        return findings

    def build_timeline(self, events: List[Dict] = None) -> List[Dict]:
        """构建事件时间线"""
        if events:
            self.timeline = sorted(events, key=lambda x: x.get('timestamp', ''))
        return self.timeline

    def calculate_file_hash(self, file_path: str) -> Dict:
        """计算文件哈希"""
        if not os.path.exists(file_path):
            return {'error': '文件不存在'}

        md5 = hashlib.md5()
        sha256 = hashlib.sha256()

        with open(file_path, 'rb') as f:
            while chunk := f.read(8192):
                md5.update(chunk)
                sha256.update(chunk)

        return {
            'file_path': file_path,
            'file_size': os.path.getsize(file_path),
            'md5': md5.hexdigest(),
            'sha256': sha256.hexdigest(),
        }

    def generate_forensic_report(self) -> Dict:
        """生成取证报告"""
        return {
            'report_title': '数字取证分析报告',
            'generated_time': datetime.now().isoformat(),
            'case_info': {
                'case_number': '',
                'examiner': '',
                'collection_time': '',
            },
            'evidence_chain': [
                {'step': '证据收集', 'status': '待执行'},
                {'step': '证据保全', 'status': '待执行'},
                {'step': '证据分析', 'status': '待执行'},
                {'step': '报告生成', 'status': '进行中'},
            ],
            'findings_summary': {
                'total_artifacts': len(self.artifacts),
                'total_timeline_events': len(self.timeline),
                'suspicious_processes': 0,
                'suspicious_files': 0,
                'security_events': 0,
            },
            'recommendations': [
                '保持证据完整性，记录所有操作',
                '使用写保护设备进行证据采集',
                '计算所有证据文件的哈希值',
                '建立完整的事件时间线',
                '保存所有分析结果和中间产物',
            ],
        }


# 全局单例
_forensic_analyzer = None

def get_forensic_analyzer() -> ForensicAnalyzer:
    global _forensic_analyzer
    if _forensic_analyzer is None:
        _forensic_analyzer = ForensicAnalyzer()
    return _forensic_analyzer
