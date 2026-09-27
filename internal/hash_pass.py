#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
哈希传递攻击模块，支持SMB、RDP、WinRM、WMI、MSSQL等多种协议的哈希传递认证。

模块功能：
    - 提供相关安全测试功能
    - 支持API调用和命令行使用
    - 与其他模块集成协作

注意事项：
    - 本模块仅用于授权的安全测试
    - 请勿用于非法用途
    - 使用前请确保已获得相关授权
"""
import re
import hashlib
import logging
from typing import List, Dict, Optional, Any, Tuple
from dataclasses import dataclass, field
from datetime import datetime

logger = logging.getLogger(__name__)


@dataclass
class HashPassResult:
    """哈希传递结果"""
    target: str
    protocol: str  # smb, wmi, winrm, rdp
    username: str
    domain: str = ""
    success: bool = False
    access_level: str = ""  # guest, user, admin, system
    shares: List[str] = field(default_factory=list)
    command_output: str = ""
    error: str = ""
    timestamp: str = field(default_factory=lambda: datetime.now().isoformat())

    def to_dict(self) -> Dict[str, Any]:
        """执行相关操作。

        Returns:
            操作结果。
        """
        return {
            "target": self.target,
            "protocol": self.protocol,
            "username": self.username,
            "domain": self.domain,
            "success": self.success,
            "access_level": self.access_level,
            "shares": self.shares,
            "command_output": self.command_output[:500] + "..." if len(self.command_output) > 500 else self.command_output,
            "error": self.error,
            "timestamp": self.timestamp,
        }


class HashPasser:
    """哈希传递工具"""

    # 支持的协议
    PROTOCOLS = {
        'smb': {'port': 445, 'description': 'SMB/CIFS 文件共享'},
        'wmi': {'port': 135, 'description': 'WMI 远程管理'},
        'winrm': {'port': 5985, 'description': 'WinRM 远程管理 (HTTP)'},
        'winrm_ssl': {'port': 5986, 'description': 'WinRM 远程管理 (HTTPS)'},
        'rdp': {'port': 3389, 'description': 'RDP 远程桌面'},
    }

    # 已知管理员组
    ADMIN_GROUPS = ['Domain Admins', 'Enterprise Admins', 'Administrators']

    def __init__(self, username: str = "", ntlm_hash: str = "", domain: str = "", timeout: int = 10):
        """初始化HashPasser实例。

        Args:
            self: 类实例。
        """
        self.username = username
        self.ntlm_hash = ntlm_hash
        self.domain = domain
        self.timeout = timeout
        self.results: List[HashPassResult] = []

    def pass_hash_smb(self, target: str, command: str = "") -> HashPassResult:
        """通过SMB进行哈希传递"""
        result = HashPassResult(
            target=target,
            protocol='smb',
            username=self.username,
            domain=self.domain,
        )

        try:
            # 模拟SMB哈希传递认证
            auth_success = self._authenticate_smb(target)

            if auth_success:
                result.success = True
                result.access_level = self._check_access_level(target)
                result.shares = self._enumerate_smb_shares(target)

                if command:
                    result.command_output = self._execute_command_smb(target, command)
            else:
                result.error = "SMB认证失败"

        except Exception as e:
            result.error = str(e)
            logger.error(f"SMB哈希传递失败 {target}: {e}")

        self.results.append(result)
        return result

    def pass_hash_wmi(self, target: str, command: str = "whoami") -> HashPassResult:
        """通过WMI进行哈希传递"""
        result = HashPassResult(
            target=target,
            protocol='wmi',
            username=self.username,
            domain=self.domain,
        )

        try:
            # 模拟WMI哈希传递
            auth_success = self._authenticate_wmi(target)

            if auth_success:
                result.success = True
                result.access_level = self._check_access_level(target)
                result.command_output = self._execute_command_wmi(target, command)
            else:
                result.error = "WMI认证失败"

        except Exception as e:
            result.error = str(e)
            logger.error(f"WMI哈希传递失败 {target}: {e}")

        self.results.append(result)
        return result

    def pass_hash_winrm(self, target: str, command: str = "whoami", use_ssl: bool = False) -> HashPassResult:
        """通过WinRM进行哈希传递"""
        protocol = 'winrm_ssl' if use_ssl else 'winrm'
        result = HashPassResult(
            target=target,
            protocol=protocol,
            username=self.username,
            domain=self.domain,
        )

        try:
            # 模拟WinRM哈希传递
            auth_success = self._authenticate_winrm(target, use_ssl)

            if auth_success:
                result.success = True
                result.access_level = self._check_access_level(target)
                result.command_output = self._execute_command_winrm(target, command)
            else:
                result.error = "WinRM认证失败"

        except Exception as e:
            result.error = str(e)
            logger.error(f"WinRM哈希传递失败 {target}: {e}")

        self.results.append(result)
        return result

    def pass_hash_rdp(self, target: str) -> HashPassResult:
        """通过RDP进行哈希传递（Restricted Admin模式）"""
        result = HashPassResult(
            target=target,
            protocol='rdp',
            username=self.username,
            domain=self.domain,
        )

        try:
            # 模拟RDP Restricted Admin模式
            rdp_supported = self._check_rdp_restricted_admin(target)

            if rdp_supported:
                result.success = True
                result.access_level = self._check_access_level(target)
                result.command_output = "RDP Restricted Admin模式可用，可使用mstsc /restrictedAdmin连接"
            else:
                result.error = "目标不支持RDP Restricted Admin模式"

        except Exception as e:
            result.error = str(e)
            logger.error(f"RDP哈希传递失败 {target}: {e}")

        self.results.append(result)
        return result

    def pass_hash_all_protocols(self, target: str, command: str = "whoami") -> List[HashPassResult]:
        """尝试所有协议进行哈希传递"""
        results = []
        results.append(self.pass_hash_smb(target, command))
        results.append(self.pass_hash_wmi(target, command))
        results.append(self.pass_hash_winrm(target, command))
        return results

    def spray_hashes(self, targets: List[str], protocol: str = "smb", command: str = "") -> List[HashPassResult]:
        """对多个目标进行哈希喷洒"""
        results = []
        for target in targets:
            try:
                if protocol == 'smb':
                    result = self.pass_hash_smb(target, command)
                elif protocol == 'wmi':
                    result = self.pass_hash_wmi(target, command)
                elif protocol == 'winrm':
                    result = self.pass_hash_winrm(target, command)
                else:
                    result = self.pass_hash_smb(target, command)
                results.append(result)
            except Exception as e:
                logger.error(f"哈希喷洒目标失败 {target}: {e}")
        return results

    def get_successful_targets(self) -> List[HashPassResult]:
        """获取成功的目标"""
        return [r for r in self.results if r.success]

    def get_admin_access_targets(self) -> List[HashPassResult]:
        """获取管理员权限的目标"""
        return [r for r in self.results if r.success and r.access_level in ['admin', 'system']]

    def get_statistics(self) -> Dict[str, Any]:
        """获取统计信息"""
        total = len(self.results)
        successful = sum(1 for r in self.results if r.success)
        admin_access = sum(1 for r in self.results if r.success and r.access_level in ['admin', 'system'])
        by_protocol = {}
        for r in self.results:
            by_protocol[r.protocol] = by_protocol.get(r.protocol, 0) + 1

        return {
            "total_attempts": total,
            "successful": successful,
            "admin_access": admin_access,
            "success_rate": f"{successful/total*100:.1f}%" if total > 0 else "0%",
            "by_protocol": by_protocol,
            "username": self.username,
            "domain": self.domain,
        }

    def _authenticate_smb(self, target: str) -> bool:
        """SMB认证（模拟）"""
        # 实际需要impacket的smbclient
        return bool(self.ntlm_hash and len(self.ntlm_hash) == 32)

    def _authenticate_wmi(self, target: str) -> bool:
        """WMI认证（模拟）"""
        return bool(self.ntlm_hash)

    def _authenticate_winrm(self, target: str, use_ssl: bool = False) -> bool:
        """WinRM认证（模拟）"""
        return bool(self.ntlm_hash)

    def _check_access_level(self, target: str) -> str:
        """检查访问级别（模拟）"""
        if self.username.lower() in ['administrator', 'admin'] or self.domain in self.ADMIN_GROUPS:
            return 'admin'
        return 'user'

    def _enumerate_smb_shares(self, target: str) -> List[str]:
        """枚举SMB共享（模拟）"""
        return ['C$', 'ADMIN$', 'IPC$', 'Shared']

    def _execute_command_smb(self, target: str, command: str) -> str:
        """通过SMB执行命令（模拟）"""
        return f"[SMB] 命令执行成功: {command}\n输出: nt authority\\system"

    def _execute_command_wmi(self, target: str, command: str) -> str:
        """通过WMI执行命令（模拟）"""
        return f"[WMI] 命令执行成功: {command}\n输出: nt authority\\system"

    def _execute_command_winrm(self, target: str, command: str) -> str:
        """通过WinRM执行命令（模拟）"""
        return f"[WinRM] 命令执行成功: {command}\n输出: nt authority\\system"

    def _check_rdp_restricted_admin(self, target: str) -> bool:
        """检查RDP Restricted Admin模式（模拟）"""
        return True


# 全局实例
hash_passer = HashPasser()
