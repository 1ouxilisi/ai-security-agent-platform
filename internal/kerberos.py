#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Kerberos攻击工具模块，支持Kerberoasting、AS-REP Roasting、黄金票据、白银票据等攻击技术。

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
class KerberosTicket:
    """Kerberos票据"""
    ticket_type: str  # TGT, TGS, golden, silver
    username: str = ""
    domain: str = ""
    spn: str = ""
    ticket_hash: str = ""
    encryption_type: str = ""  # RC4, AES128, AES256
    valid_from: str = ""
    valid_until: str = ""
    renewable: bool = False
    notes: str = ""

    def to_dict(self) -> Dict[str, Any]:
        """执行相关操作。

        Returns:
            操作结果。
        """
        return {
            "ticket_type": self.ticket_type,
            "username": self.username,
            "domain": self.domain,
            "spn": self.spn,
            "ticket_hash": self.ticket_hash[:50] + "..." if len(self.ticket_hash) > 50 else self.ticket_hash,
            "encryption_type": self.encryption_type,
            "valid_from": self.valid_from,
            "valid_until": self.valid_until,
            "renewable": self.renewable,
            "notes": self.notes,
        }


@dataclass
class KerberoastResult:
    """Kerberoasting结果"""
    username: str
    spn: str
    domain: str
    ticket_hash: str
    encryption_type: str
    crackable: bool = True
    notes: str = ""

    def to_dict(self) -> Dict[str, Any]:
        """执行相关操作。

        Returns:
            操作结果。
        """
        return {
            "username": self.username,
            "spn": self.spn,
            "domain": self.domain,
            "ticket_hash": self.ticket_hash[:50] + "..." if len(self.ticket_hash) > 50 else self.ticket_hash,
            "encryption_type": self.encryption_type,
            "crackable": self.crackable,
            "notes": self.notes,
        }


class KerberosTools:
    """Kerberos攻击工具"""

    # 加密类型
    ENCRYPTION_TYPES = {
        0x17: "RC4-HMAC",
        0x11: "AES128-CTS-HMAC-SHA1-96",
        0x12: "AES256-CTS-HMAC-SHA1-96",
        0x01: "DES-CBC-CRC",
        0x03: "DES-CBC-MD5",
    }

    # 已知弱加密类型（容易破解）
    WEAK_ENCRYPTION = [0x17, 0x01, 0x03]

    def __init__(self, domain: str = "", dc_ip: str = "", username: str = "", password: str = "", timeout: int = 10):
        """初始化KerberosTools实例。

        Args:
            self: 类实例。
        """
        self.domain = domain
        self.dc_ip = dc_ip
        self.username = username
        self.password = password
        self.timeout = timeout
        self.tickets: List[KerberosTicket] = []
        self.kerberoast_results: List[KerberoastResult] = []

    def kerberoast(self, target_users: List[str] = None, spn_list: List[str] = None) -> List[KerberoastResult]:
        """
        Kerberoasting攻击
        请求指定用户的TGS票据，提取哈希用于离线破解
        """
        results = []

        if not target_users and not spn_list:
            # 默认攻击所有有SPN的用户
            target_users = self._get_spn_users()

        for user in target_users or []:
            try:
                # 模拟请求TGS票据
                spn = f"{user}@{self.domain.upper()}"
                ticket_hash = self._request_tgs(spn)
                enc_type = self._detect_encryption_type(ticket_hash)

                result = KerberoastResult(
                    username=user,
                    spn=spn,
                    domain=self.domain,
                    ticket_hash=ticket_hash,
                    encryption_type=self.ENCRYPTION_TYPES.get(enc_type, "Unknown"),
                    crackable=enc_type in self.WEAK_ENCRYPTION,
                )
                results.append(result)
                self.kerberoast_results.append(result)

            except Exception as e:
                logger.error(f"Kerberoasting用户 {user} 失败: {e}")

        return results

    def asrep_roast(self, target_users: List[str] = None) -> List[KerberoastResult]:
        """
        AS-REP Roasting攻击
        对不需要预认证的用户请求AS-REP，提取哈希用于离线破解
        """
        results = []

        if not target_users:
            # 默认攻击所有不需要预认证的用户
            target_users = self._get_asrep_users()

        for user in target_users:
            try:
                # 模拟请求AS-REP
                asrep_hash = self._request_asrep(user)
                enc_type = self._detect_encryption_type(asrep_hash)

                result = KerberoastResult(
                    username=user,
                    spn=f"krbtgt/{self.domain.upper()}",
                    domain=self.domain,
                    ticket_hash=asrep_hash,
                    encryption_type=self.ENCRYPTION_TYPES.get(enc_type, "Unknown"),
                    crackable=True,
                    notes="AS-REP Roasting",
                )
                results.append(result)

            except Exception as e:
                logger.error(f"AS-REP Roasting用户 {user} 失败: {e}")

        return results

    def create_golden_ticket(self, krbtgt_hash: str, domain_sid: str, target_user: str = "Administrator", groups: List[int] = None) -> KerberosTicket:
        """
        创建黄金票据（Golden Ticket）
        使用krbtgt账户的哈希创建任意用户的TGT票据
        """
        if groups is None:
            groups = [512, 513, 518, 519, 520]  # Domain Admins等

        # 模拟生成黄金票据
        ticket_data = f"{krbtgt_hash}:{domain_sid}:{target_user}:{self.domain}:{','.join(map(str, groups))}"
        ticket_hash = hashlib.sha256(ticket_data.encode()).hexdigest()

        ticket = KerberosTicket(
            ticket_type="golden",
            username=target_user,
            domain=self.domain,
            spn=f"krbtgt/{self.domain.upper()}",
            ticket_hash=ticket_hash,
            encryption_type="AES256",
            valid_from=datetime.now().isoformat(),
            valid_until="2030-01-01T00:00:00",
            renewable=True,
            notes=f"黄金票据，用户组: {groups}",
        )
        self.tickets.append(ticket)
        return ticket

    def create_silver_ticket(self, service_hash: str, target_spn: str, target_user: str = "Administrator", service: str = "cifs") -> KerberosTicket:
        """
        创建白银票据（Silver Ticket）
        使用服务账户的哈希创建指定服务的TGS票据
        """
        # 模拟生成白银票据
        ticket_data = f"{service_hash}:{target_spn}:{target_user}:{service}"
        ticket_hash = hashlib.sha256(ticket_data.encode()).hexdigest()

        ticket = KerberosTicket(
            ticket_type="silver",
            username=target_user,
            domain=self.domain,
            spn=target_spn,
            ticket_hash=ticket_hash,
            encryption_type="RC4-HMAC",
            valid_from=datetime.now().isoformat(),
            valid_until="2030-01-01T00:00:00",
            renewable=False,
            notes=f"白银票据，服务: {service}",
        )
        self.tickets.append(ticket)
        return ticket

    def pass_the_ticket(self, ticket: KerberosTicket, target_host: str) -> bool:
        """
        Pass-the-Ticket攻击
        使用票据访问目标主机
        """
        try:
            # 模拟注入票据并访问
            logger.info(f"注入票据到 {target_host}，用户: {ticket.username}")
            return True
        except Exception as e:
            logger.error(f"Pass-the-Ticket失败: {e}")
            return False

    def get_kerberoastable_users(self) -> List[str]:
        """获取可Kerberoasting的用户列表"""
        return self._get_spn_users()

    def get_asrep_roastable_users(self) -> List[str]:
        """获取可AS-REP Roasting的用户列表"""
        return self._get_asrep_users()

    def get_statistics(self) -> Dict[str, Any]:
        """获取攻击统计"""
        return {
            "total_tickets": len(self.tickets),
            "golden_tickets": sum(1 for t in self.tickets if t.ticket_type == "golden"),
            "silver_tickets": sum(1 for t in self.tickets if t.ticket_type == "silver"),
            "kerberoast_results": len(self.kerberoast_results),
            "crackable_hashes": sum(1 for r in self.kerberoast_results if r.crackable),
            "domain": self.domain,
            "dc_ip": self.dc_ip,
        }

    def export_hashes(self, output_file: str = "kerberoast_hashes.txt") -> str:
        """导出Kerberoasting哈希（Hashcat格式）"""
        lines = []
        for result in self.kerberoast_results:
            # Hashcat格式: $krb5tgs$23$*user$realm$spn*$hash
            line = f"$krb5tgs$23$*{result.username}${result.domain.upper()}${result.spn}*${result.ticket_hash}"
            lines.append(line)

        content = "\n".join(lines)
        if output_file:
            with open(output_file, 'w') as f:
                f.write(content)
        return content

    def _get_spn_users(self) -> List[str]:
        """获取有SPN的用户（模拟）"""
        return [
            "MSSQLSvc",
            "HTTP",
            "CIFS",
            "HOST",
            "TERMSRV",
        ]

    def _get_asrep_users(self) -> List[str]:
        """获取不需要预认证的用户（模拟）"""
        return [
            "svc_backup",
            "svc_scan",
        ]

    def _request_tgs(self, spn: str) -> str:
        """请求TGS票据（模拟）"""
        # 模拟生成TGS票据哈希
        data = f"TGS:{spn}:{datetime.now().timestamp()}"
        return hashlib.md5(data.encode()).hexdigest() * 4

    def _request_asrep(self, username: str) -> str:
        """请求AS-REP（模拟）"""
        data = f"ASREP:{username}:{datetime.now().timestamp()}"
        return hashlib.md5(data.encode()).hexdigest() * 4

    def _detect_encryption_type(self, ticket_hash: str) -> int:
        """检测加密类型（模拟）"""
        # 根据哈希长度和特征判断
        if len(ticket_hash) == 32:
            return 0x17  # RC4
        elif len(ticket_hash) == 64:
            return 0x12  # AES256
        return 0x17


# 全局实例
kerberos_tools = KerberosTools()
