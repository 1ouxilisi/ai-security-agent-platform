#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
__init__内网渗透功能模块，提供相关内网渗透测试功能。

模块功能：
    - 提供相关安全测试功能
    - 支持API调用和命令行使用
    - 与其他模块集成协作

注意事项：
    - 本模块仅用于授权的安全测试
    - 请勿用于非法用途
    - 使用前请确保已获得相关授权
"""

from .smb_scanner import smb_scanner, SMBScanner, SMBShare, SMBSession
from .ldap_query import ldap_query, LDAPQuerier, LDAPEntry
from .kerberos import kerberos_tools, KerberosTools, KerberosTicket
from .hash_pass import hash_passer, HashPasser, HashPassResult
from .lateral_movement import lateral_mover, LateralMover, LateralMoveResult
from .port_forward import port_forwarder, PortForwarder, PortForwardSession
from .dns_enum import dns_enumerator, DNSEnumerator, DNSRecord
from .ad_assessment import ad_assessor, ADAssessor, ADHealthReport

__version__ = "1.0.0"
__all__ = [
    # SMB
    'smb_scanner', 'SMBScanner', 'SMBShare', 'SMBSession',
    # LDAP
    'ldap_query', 'LDAPQuerier', 'LDAPEntry',
    # Kerberos
    'kerberos_tools', 'KerberosTools', 'KerberosTicket',
    # 哈希传递
    'hash_passer', 'HashPasser', 'HashPassResult',
    # 横向移动
    'lateral_mover', 'LateralMover', 'LateralMoveResult',
    # 端口转发
    'port_forwarder', 'PortForwarder', 'PortForwardSession',
    # DNS枚举
    'dns_enumerator', 'DNSEnumerator', 'DNSRecord',
    # AD评估
    'ad_assessor', 'ADAssessor', 'ADHealthReport',
]
