#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
客户端安全分析模块
提供二进制分析、反调试检测、加壳检测、敏感信息提取功能
"""

import os
import re
import json
import struct
from datetime import datetime
from typing import Dict, List, Any, Optional
from dataclasses import dataclass, field


@dataclass
class BinaryInfo:
    """二进制文件信息"""
    file_path: str = ""
    file_name: str = ""
    file_size: int = 0
    file_type: str = ""
    architecture: str = ""
    md5: str = ""
    sha1: str = ""
    sha256: str = ""
    compile_time: str = ""
    entry_point: str = ""
    sections: List[Dict] = field(default_factory=list)
    imports: List[str] = field(default_factory=list)
    exports: List[str] = field(default_factory=list)
    strings: List[str] = field(default_factory=list)
    is_packed: bool = False
    packer_name: str = ""
    has_anti_debug: bool = False
    has_anti_vm: bool = False
    has_anti_sandbox: bool = False
    suspicious_strings: List[Dict] = field(default_factory=list)


class ClientSecurityAnalyzer:
    """客户端安全分析器"""

    # 加壳特征
    PACKER_SIGNATURES = {
        'UPX': ['UPX!', 'UPX0', 'UPX1', 'This file is packed with the UPX executable packer'],
        'ASPack': ['ASPack', 'aspack'],
        'PECompact': ['PECompact', 'PEC2'],
        'Themida': ['Themida', 'WinLicense'],
        'VMProtect': ['VMProtect', 'vmp'],
        'Enigma Protector': ['Enigma', 'enigmaprotector'],
        'Obsidium': ['Obsidium'],
        'Armadillo': ['Armadillo'],
        'ASProtect': ['ASProtect'],
        'EXECryptor': ['EXECryptor'],
    }

    # 反调试API
    ANTI_DEBUG_APIS = [
        'IsDebuggerPresent', 'CheckRemoteDebuggerPresent', 'NtQueryInformationProcess',
        'NtSetInformationThread', 'OutputDebugString', 'GetTickCount',
        'QueryPerformanceCounter', 'timeGetTime', 'RDTSC', 'int 3',
        'SetUnhandledExceptionFilter', 'UnhandledExceptionFilter',
    ]

    # 反虚拟机特征
    ANTI_VM_STRINGS = [
        'VMware', 'VirtualBox', 'VBox', 'QEMU', 'Xen', 'Hyper-V',
        'vmxnet', 'vboxguest', 'VBoxMouse', 'VMwareVMware',
        'HKEY_LOCAL_MACHINE\\SOFTWARE\\VMware, Inc.\\VMware Tools',
        'HKEY_LOCAL_MACHINE\\HARDWARE\\DESCRIPTION\\System\\BIOS',
    ]

    # 敏感字符串模式
    SENSITIVE_PATTERNS = {
        'url': r'https?://[^\s"\'<>]+',
        'ip': r'\b(?:\d{1,3}\.){3}\d{1,3}\b',
        'email': r'[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}',
        'api_key': r'(api[_-]?key|apikey|secret[_-]?key|access[_-]?token)["\s:=]+["\']?([a-zA-Z0-9_\-]{16,})',
        'password': r'(password|passwd|pwd)["\s:=]+["\']?([a-zA-Z0-9_\-]{6,})',
    }

    def __init__(self):
        self.binary_info = BinaryInfo()

    def analyze(self, file_path: str) -> BinaryInfo:
        """分析二进制文件"""
        if not os.path.exists(file_path):
            raise FileNotFoundError(f"文件不存在: {file_path}")

        self.binary_info = BinaryInfo()
        self.binary_info.file_path = file_path
        self.binary_info.file_name = os.path.basename(file_path)
        self.binary_info.file_size = os.path.getsize(file_path)

        # 计算哈希
        self._calculate_hashes(file_path)

        # 检测文件类型
        self._detect_file_type(file_path)

        # 提取字符串
        self._extract_strings(file_path)

        # 检测加壳
        self._detect_packer(file_path)

        # 检测反调试
        self._detect_anti_debug(file_path)

        # 检测反虚拟机
        self._detect_anti_vm(file_path)

        # 提取敏感信息
        self._extract_sensitive_info(file_path)

        # PE文件分析
        if self.binary_info.file_type == 'PE':
            self._analyze_pe(file_path)

        return self.binary_info

    def _calculate_hashes(self, file_path: str):
        """计算文件哈希"""
        import hashlib
        md5 = hashlib.md5()
        sha1 = hashlib.sha1()
        sha256 = hashlib.sha256()

        with open(file_path, 'rb') as f:
            while chunk := f.read(8192):
                md5.update(chunk)
                sha1.update(chunk)
                sha256.update(chunk)

        self.binary_info.md5 = md5.hexdigest()
        self.binary_info.sha1 = sha1.hexdigest()
        self.binary_info.sha256 = sha256.hexdigest()

    def _detect_file_type(self, file_path: str):
        """检测文件类型"""
        with open(file_path, 'rb') as f:
            header = f.read(16)

        if header[:2] == b'MZ':
            self.binary_info.file_type = 'PE'
            # 检测架构
            if b'PE\x00\x00' in header:
                self.binary_info.architecture = 'x86'
        elif header[:4] == b'\x7fELF':
            self.binary_info.file_type = 'ELF'
            if header[4] == 1:
                self.binary_info.architecture = 'x86'
            elif header[4] == 2:
                self.binary_info.architecture = 'x64'
        elif header[:4] == b'\xcf\xfa\xed\xfe' or header[:4] == b'\xfe\xed\xfa\xcf':
            self.binary_info.file_type = 'Mach-O'
        elif header[:2] == b'PK':
            self.binary_info.file_type = 'ZIP/JAR'
        else:
            self.binary_info.file_type = 'Unknown'

    def _extract_strings(self, file_path: str, min_length: int = 4):
        """提取可打印字符串"""
        strings = []
        with open(file_path, 'rb') as f:
            data = f.read()

        current = []
        for byte in data:
            if 32 <= byte <= 126:
                current.append(chr(byte))
            else:
                if len(current) >= min_length:
                    strings.append(''.join(current))
                current = []

        if len(current) >= min_length:
            strings.append(''.join(current))

        self.binary_info.strings = strings[:5000]  # 限制数量

    def _detect_packer(self, file_path: str):
        """检测加壳"""
        with open(file_path, 'rb') as f:
            data = f.read()

        for packer_name, signatures in self.PACKER_SIGNATURES.items():
            for sig in signatures:
                if sig.encode() in data:
                    self.binary_info.is_packed = True
                    self.binary_info.packer_name = packer_name
                    return

    def _detect_anti_debug(self, file_path: str):
        """检测反调试"""
        with open(file_path, 'rb') as f:
            data = f.read()

        for api in self.ANTI_DEBUG_APIS:
            if api.encode() in data:
                self.binary_info.has_anti_debug = True
                return

    def _detect_anti_vm(self, file_path: str):
        """检测反虚拟机"""
        with open(file_path, 'rb') as f:
            data = f.read()

        for sig in self.ANTI_VM_STRINGS:
            if sig.encode() in data:
                self.binary_info.has_anti_vm = True
                return

    def _extract_sensitive_info(self, file_path: str):
        """提取敏感信息"""
        text = '\n'.join(self.binary_info.strings)

        for pattern_name, pattern in self.SENSITIVE_PATTERNS.items():
            matches = re.findall(pattern, text)
            for match in matches[:20]:
                if isinstance(match, tuple):
                    value = match[-1] if match[-1] else match[0]
                else:
                    value = match

                if len(str(value)) > 5:
                    self.binary_info.suspicious_strings.append({
                        'type': pattern_name,
                        'value': str(value)[:100],
                    })

    def _analyze_pe(self, file_path: str):
        """分析PE文件（简化版）"""
        try:
            with open(file_path, 'rb') as f:
                data = f.read()

            # 查找PE头
            pe_offset = struct.unpack_from('<I', data, 0x3C)[0]
            if pe_offset + 4 < len(data) and data[pe_offset:pe_offset+4] == b'PE\x00\x00':
                # COFF头
                machine = struct.unpack_from('<H', data, pe_offset + 4)[0]
                if machine == 0x14c:
                    self.binary_info.architecture = 'x86'
                elif machine == 0x8664:
                    self.binary_info.architecture = 'x64'

                # 节表
                num_sections = struct.unpack_from('<H', data, pe_offset + 6)[0]
                optional_header_size = struct.unpack_from('<H', data, pe_offset + 20)[0]
                section_offset = pe_offset + 24 + optional_header_size

                for i in range(min(num_sections, 20)):
                    offset = section_offset + i * 40
                    if offset + 40 < len(data):
                        name = data[offset:offset+8].rstrip(b'\x00').decode('ascii', errors='ignore')
                        virtual_size = struct.unpack_from('<I', data, offset + 8)[0]
                        raw_size = struct.unpack_from('<I', data, offset + 16)[0]
                        self.binary_info.sections.append({
                            'name': name,
                            'virtual_size': virtual_size,
                            'raw_size': raw_size,
                        })

        except Exception as e:
            print(f"PE分析错误: {e}")

    def get_security_assessment(self) -> Dict[str, Any]:
        """获取安全评估"""
        risks = []
        score = 100

        if self.binary_info.is_packed:
            risks.append({'risk': '加壳保护', 'detail': f'检测到{self.binary_info.packer_name}加壳', 'positive': True})
        else:
            risks.append({'risk': '未加壳', 'detail': '未检测到加壳，容易被反编译', 'positive': False})
            score -= 20

        if self.binary_info.has_anti_debug:
            risks.append({'risk': '反调试', 'detail': '检测到反调试机制', 'positive': True})
        else:
            risks.append({'risk': '无反调试', 'detail': '未检测到反调试机制', 'positive': False})
            score -= 15

        if self.binary_info.has_anti_vm:
            risks.append({'risk': '反虚拟机', 'detail': '检测到反虚拟机机制', 'positive': True})
        else:
            risks.append({'risk': '无反虚拟机', 'detail': '未检测到反虚拟机机制', 'positive': False})
            score -= 10

        if self.binary_info.suspicious_strings:
            sensitive_count = len([s for s in self.binary_info.suspicious_strings
                                  if s['type'] in ('password', 'api_key')])
            if sensitive_count > 0:
                risks.append({'risk': '敏感信息泄露', 'detail': f'发现{sensitive_count}个硬编码密码/密钥', 'positive': False})
                score -= 25

        return {
            'file_name': self.binary_info.file_name,
            'file_type': self.binary_info.file_type,
            'architecture': self.binary_info.architecture,
            'security_score': max(0, score),
            'risk_level': '高风险' if score < 50 else '中风险' if score < 70 else '低风险' if score < 90 else '安全',
            'risks': risks,
            'recommendations': [
                '使用专业加壳工具保护二进制文件',
                '实施反调试、反虚拟机、反沙箱检测',
                '不要在代码中硬编码密码和密钥',
                '使用代码混淆增加逆向难度',
                '实施完整性校验防止篡改',
            ]
        }


# 全局单例
_client_analyzer = None

def get_client_security_analyzer() -> ClientSecurityAnalyzer:
    """获取客户端安全分析器单例"""
    global _client_analyzer
    if _client_analyzer is None:
        _client_analyzer = ClientSecurityAnalyzer()
    return _client_analyzer
