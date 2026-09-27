#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
SMB协议扫描模块，支持共享枚举、空会话测试、SMB漏洞检测和信息收集。

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
import socket
import logging
from typing import List, Dict, Optional, Any
from dataclasses import dataclass, field
from datetime import datetime

logger = logging.getLogger(__name__)


@dataclass
class SMBShare:
    """SMB共享信息"""
    name: str
    comment: str = ""
    share_type: str = "disk"  # disk, printer, ipc, device
    permissions: str = "unknown"  # read, write, full, unknown
    sensitive: bool = False
    notes: str = ""

    def to_dict(self) -> Dict[str, Any]:
        """执行相关操作。

        Returns:
            操作结果。
        """
        return {
            "name": self.name,
            "comment": self.comment,
            "share_type": self.share_type,
            "permissions": self.permissions,
            "sensitive": self.sensitive,
            "notes": self.notes,
        }


@dataclass
class SMBSession:
    """SMB会话信息"""
    target: str
    port: int = 445
    hostname: str = ""
    os_version: str = ""
    domain: str = ""
    workgroup: str = ""
    null_session: bool = False
    signing_required: bool = False
    smb_version: str = ""
    shares: List[SMBShare] = field(default_factory=list)
    vulnerabilities: List[str] = field(default_factory=list)
    scan_time: str = field(default_factory=lambda: datetime.now().isoformat())

    def to_dict(self) -> Dict[str, Any]:
        """执行相关操作。

        Returns:
            操作结果。
        """
        return {
            "target": self.target,
            "port": self.port,
            "hostname": self.hostname,
            "os_version": self.os_version,
            "domain": self.domain,
            "workgroup": self.workgroup,
            "null_session": self.null_session,
            "signing_required": self.signing_required,
            "smb_version": self.smb_version,
            "shares": [s.to_dict() for s in self.shares],
            "vulnerabilities": self.vulnerabilities,
            "scan_time": self.scan_time,
        }


class SMBScanner:
    """SMB扫描器"""

    # 敏感共享名称
    SENSITIVE_SHARES = {
        'c$', 'admin$', 'ipc$', 'print$', 'sysvol', 'netlogon',
        'backup', 'backups', 'config', 'confidential', 'secret',
        'passwords', 'users', 'profiles', 'home', 'homes'
    }

    # 已知SMB漏洞
    SMB_VULNS = {
        'ms17_010': 'MS17-010 EternalBlue（永恒之蓝）',
        'ms08_067': 'MS08-067 远程代码执行',
        'cve_2020_0796': 'CVE-2020-0796 SMBGhost',
        'cve_2022_21903': 'CVE-2022-21903 SMB远程代码执行',
    }

    def __init__(self, timeout: int = 10, max_threads: int = 10):
        """初始化SMBScanner实例。

        Args:
            self: 类实例。
        """
        self.timeout = timeout
        self.max_threads = max_threads
        self.results: List[SMBSession] = []

    def check_port(self, target: str, port: int = 445) -> bool:
        """检查SMB端口是否开放"""
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(self.timeout)
            result = sock.connect_ex((target, port))
            sock.close()
            return result == 0
        except Exception as e:
            logger.debug(f"端口检查失败 {target}:{port}: {e}")
            return False

    def scan_target(self, target: str, port: int = 445) -> SMBSession:
        """扫描单个目标的SMB服务"""
        session = SMBSession(target=target, port=port)

        if not self.check_port(target, port):
            session.vulnerabilities.append("SMB端口未开放")
            return session

        # 基础信息收集（通过socket探测）
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(self.timeout)
            sock.connect((target, port))

            # 发送SMB协商请求
            neg_packet = self._build_smb_negotiate()
            sock.send(neg_packet)
            response = sock.recv(1024)

            # 解析响应
            if len(response) > 0:
                session.smb_version = self._detect_smb_version(response)
                session.signing_required = self._check_signing(response)

            sock.close()
        except Exception as e:
            logger.debug(f"SMB协商失败 {target}: {e}")

        # 尝试空会话
        session.null_session = self._try_null_session(target, port)

        # 枚举共享（模拟，实际需要impacket等工具）
        session.shares = self._enumerate_shares(target)

        # 漏洞检测
        session.vulnerabilities.extend(self._detect_vulnerabilities(session))

        self.results.append(session)
        return session

    def scan_network(self, targets: List[str], port: int = 445) -> List[SMBSession]:
        """扫描多个目标"""
        results = []
        for target in targets:
            try:
                result = self.scan_target(target, port)
                results.append(result)
            except Exception as e:
                logger.error(f"扫描目标失败 {target}: {e}")
        return results

    def _build_smb_negotiate(self) -> bytes:
        """构建SMB协商请求包"""
        # 简化的SMBv2协商请求
        return bytes([
            0x00, 0x00, 0x00, 0x2f,  # NetBIOS长度
            0xff, 0x53, 0x4d, 0x42,  # SMB2 header
            0x72,  # NEGOTIATE
            0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00,
            0xfe, 0x53, 0x4d, 0x42,  # SMB2 magic
            0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00,
        ])

    def _detect_smb_version(self, response: bytes) -> str:
        """检测SMB版本"""
        if len(response) < 4:
            return "unknown"
        # SMB1: 0xFF 0x53 0x4d 0x42
        if response[0:4] == b'\xff\x53\x4d\x42':
            return "SMBv1"
        # SMB2: 0xfe 0x53 0x4d 0x42
        if response[0:4] == b'\xfe\x53\x4d\x42':
            return "SMBv2/v3"
        return "unknown"

    def _check_signing(self, response: bytes) -> bool:
        """检查是否需要签名"""
        # 简化检测：检查响应中的安全模式位
        if len(response) > 40:
            # SMB2 SecurityMode 偏移
            security_mode = response[38] if len(response) > 38 else 0
            return bool(security_mode & 0x02)
        return False

    def _try_null_session(self, target: str, port: int) -> bool:
        """尝试空会话连接"""
        # 简化实现：实际需要使用impacket的smbclient
        # 这里只做基础检测
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(self.timeout)
            sock.connect((target, port))
            # 发送空会话设置请求
            setup_packet = self._build_null_session_setup()
            sock.send(setup_packet)
            response = sock.recv(1024)
            sock.close()
            # 检查响应状态（0x00000000表示成功）
            if len(response) > 12:
                status = int.from_bytes(response[8:12], 'little')
                return status == 0
            return False
        except Exception as e:
            logger.debug(f"空会话尝试失败 {target}: {e}")
            return False

    def _build_null_session_setup(self) -> bytes:
        """构建空会话设置请求"""
        return bytes([
            0x00, 0x00, 0x00, 0x40,
            0xfe, 0x53, 0x4d, 0x42,
            0x01,  # SESSION_SETUP
            0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00,
        ])

    def _enumerate_shares(self, target: str) -> List[SMBShare]:
        """枚举SMB共享（模拟，实际需要工具）"""
        # 常见默认共享
        default_shares = [
            SMBShare(name='IPC$', comment='远程IPC', share_type='ipc', permissions='read', sensitive=True),
            SMBShare(name='ADMIN$', comment='远程管理', share_type='disk', permissions='full', sensitive=True),
            SMBShare(name='C$', comment='默认共享', share_type='disk', permissions='full', sensitive=True),
        ]
        return default_shares

    def _detect_vulnerabilities(self, session: SMBSession) -> List[str]:
        """检测SMB漏洞"""
        vulns = []

        # SMBv1漏洞
        if session.smb_version == 'SMBv1':
            vulns.append(self.SMB_VULNS['ms17_010'])
            vulns.append(self.SMB_VULNS['ms08_067'])

        # 空会话漏洞
        if session.null_session:
            vulns.append("空会话可建立，可能泄露用户列表和共享信息")

        # 未签名
        if not session.signing_required:
            vulns.append("SMB消息签名未启用，可能遭受中间人攻击")

        return vulns

    def get_statistics(self) -> Dict[str, Any]:
        """获取扫描统计"""
        total = len(self.results)
        vulnerable = sum(1 for r in self.results if r.vulnerabilities)
        null_sessions = sum(1 for r in self.results if r.null_session)
        total_shares = sum(len(r.shares) for r in self.results)

        return {
            "total_scanned": total,
            "vulnerable_targets": vulnerable,
            "null_sessions": null_sessions,
            "total_shares": total_shares,
            "vulnerability_rate": f"{vulnerable/total*100:.1f}%" if total > 0 else "0%",
        }


# 全局实例
smb_scanner = SMBScanner()
