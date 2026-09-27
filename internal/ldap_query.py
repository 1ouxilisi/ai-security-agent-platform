#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
LDAP/Active Directory查询模块，支持用户、计算机、组、GPO、OU等多种对象查询和枚举。

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
class LDAPEntry:
    """LDAP条目"""
    dn: str
    object_class: List[str] = field(default_factory=list)
    attributes: Dict[str, Any] = field(default_factory=dict)
    sAMAccountName: str = ""
    displayName: str = ""
    mail: str = ""
    memberOf: List[str] = field(default_factory=list)
    lastLogon: str = ""
    pwdLastSet: str = ""
    userAccountControl: int = 0
    adminCount: int = 0
    servicePrincipalName: List[str] = field(default_factory=list)
    operatingSystem: str = ""
    operatingSystemVersion: str = ""
    dNSHostName: str = ""

    def to_dict(self) -> Dict[str, Any]:
        """执行相关操作。

        Returns:
            操作结果。
        """
        return {
            "dn": self.dn,
            "object_class": self.object_class,
            "sAMAccountName": self.sAMAccountName,
            "displayName": self.displayName,
            "mail": self.mail,
            "memberOf": self.memberOf,
            "lastLogon": self.lastLogon,
            "pwdLastSet": self.pwdLastSet,
            "userAccountControl": self.userAccountControl,
            "adminCount": self.adminCount,
            "servicePrincipalName": self.servicePrincipalName,
            "operatingSystem": self.operatingSystem,
            "operatingSystemVersion": self.operatingSystemVersion,
            "dNSHostName": self.dNSHostName,
            "attributes": self.attributes,
        }

    def is_disabled(self) -> bool:
        """检查账户是否禁用"""
        return bool(self.userAccountControl & 0x0002)

    def is_admin(self) -> bool:
        """检查是否为管理员"""
        return self.adminCount == 1

    def has_spn(self) -> bool:
        """检查是否有SPN（可Kerberoasting）"""
        return len(self.servicePrincipalName) > 0


class LDAPQuerier:
    """LDAP查询器"""

    # 默认LDAP端口
    LDAP_PORT = 389
    LDAPS_PORT = 636
    GC_PORT = 3268

    # 常用LDAP过滤器
    FILTERS = {
        'all_users': '(&(objectClass=user)(objectCategory=person))',
        'all_computers': '(objectClass=computer)',
        'all_groups': '(objectClass=group)',
        'all_ous': '(objectClass=organizationalUnit)',
        'all_gpos': '(objectClass=groupPolicyContainer)',
        'admin_users': '(&(objectClass=user)(adminCount=1))',
        'disabled_users': '(&(objectClass=user)(userAccountControl:1.2.840.113556.1.4.803:=2))',
        'spn_users': '(&(objectClass=user)(servicePrincipalName=*))',
        'kerberoastable': '(&(objectClass=user)(servicePrincipalName=*)(!userAccountControl:1.2.840.113556.1.4.803:=2))',
        'asrep_roastable': '(&(objectClass=user)(userAccountControl:1.2.840.113556.1.4.803:=4194304))',
        'domain_controllers': '(&(objectClass=computer)(userAccountControl:1.2.840.113556.1.4.803:=8192))',
        'password_never_expires': '(&(objectClass=user)(userAccountControl:1.2.840.113556.1.4.803:=65536))',
    }

    def __init__(self, server: str = "", domain: str = "", username: str = "", password: str = "", use_ssl: bool = False, timeout: int = 10):
        """初始化LDAPQuerier实例。

        Args:
            self: 类实例。
        """
        self.server = server
        self.domain = domain
        self.username = username
        self.password = password
        self.use_ssl = use_ssl
        self.timeout = timeout
        self.connected = False
        self.base_dn = ""
        self.entries: List[LDAPEntry] = []

    def connect(self) -> bool:
        """连接LDAP服务器"""
        if not self.server:
            # 尝试通过DNS查找域控制器
            self.server = self._find_domain_controller()

        if not self.server:
            logger.error("无法找到LDAP服务器")
            return False

        port = self.LDAPS_PORT if self.use_ssl else self.LDAP_PORT

        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(self.timeout)
            result = sock.connect_ex((self.server, port))
            sock.close()

            if result == 0:
                self.connected = True
                # 构建base DN
                if self.domain:
                    self.base_dn = ",".join([f"DC={part}" for part in self.domain.split(".")])
                return True
            else:
                logger.error(f"LDAP服务器连接失败 {self.server}:{port}")
                return False
        except Exception as e:
            logger.error(f"LDAP连接异常: {e}")
            return False

    def query(self, filter_str: str = "", attributes: List[str] = None, base_dn: str = "", scope: str = "subtree") -> List[LDAPEntry]:
        """执行LDAP查询"""
        if not filter_str:
            filter_str = self.FILTERS['all_users']

        if not base_dn:
            base_dn = self.base_dn

        # 模拟查询（实际需要ldap3库）
        entries = self._simulate_query(filter_str, base_dn)
        self.entries.extend(entries)
        return entries

    def get_all_users(self) -> List[LDAPEntry]:
        """获取所有用户"""
        return self.query(self.FILTERS['all_users'])

    def get_all_computers(self) -> List[LDAPEntry]:
        """获取所有计算机"""
        return self.query(self.FILTERS['all_computers'])

    def get_all_groups(self) -> List[LDAPEntry]:
        """获取所有组"""
        return self.query(self.FILTERS['all_groups'])

    def get_admin_users(self) -> List[LDAPEntry]:
        """获取管理员用户"""
        return self.query(self.FILTERS['admin_users'])

    def get_kerberoastable_users(self) -> List[LDAPEntry]:
        """获取可Kerberoasting的用户"""
        return self.query(self.FILTERS['kerberoastable'])

    def get_asrep_roastable_users(self) -> List[LDAPEntry]:
        """获取可AS-REP Roasting的用户"""
        return self.query(self.FILTERS['asrep_roastable'])

    def get_domain_controllers(self) -> List[LDAPEntry]:
        """获取域控制器"""
        return self.query(self.FILTERS['domain_controllers'])

    def get_disabled_users(self) -> List[LDAPEntry]:
        """获取禁用用户"""
        return self.query(self.FILTERS['disabled_users'])

    def get_password_never_expires(self) -> List[LDAPEntry]:
        """获取密码永不过期的用户"""
        return self.query(self.FILTERS['password_never_expires'])

    def get_group_members(self, group_name: str) -> List[LDAPEntry]:
        """获取组成员"""
        filter_str = f'(&(objectClass=user)(memberOf=CN={group_name},CN=Users,{self.base_dn}))'
        return self.query(filter_str)

    def get_user_groups(self, username: str) -> List[str]:
        """获取用户所属组"""
        filter_str = f'(&(objectClass=user)(sAMAccountName={username}))'
        entries = self.query(filter_str, ['memberOf'])
        if entries:
            return entries[0].memberOf
        return []

    def search(self, keyword: str) -> List[LDAPEntry]:
        """搜索包含关键词的条目"""
        filter_str = f'(|(sAMAccountName=*{keyword}*)(displayName=*{keyword}*)(mail=*{keyword}*)(name=*{keyword}*))'
        return self.query(filter_str)

    def get_domain_info(self) -> Dict[str, Any]:
        """获取域信息"""
        return {
            "domain": self.domain,
            "server": self.server,
            "base_dn": self.base_dn,
            "connected": self.connected,
            "use_ssl": self.use_ssl,
        }

    def get_statistics(self) -> Dict[str, Any]:
        """获取查询统计"""
        users = [e for e in self.entries if 'user' in e.object_class]
        computers = [e for e in self.entries if 'computer' in e.object_class]
        groups = [e for e in self.entries if 'group' in e.object_class]
        admins = [e for e in users if e.is_admin()]
        disabled = [e for e in users if e.is_disabled()]
        kerberoastable = [e for e in users if e.has_spn()]

        return {
            "total_entries": len(self.entries),
            "users": len(users),
            "computers": len(computers),
            "groups": len(groups),
            "admin_users": len(admins),
            "disabled_users": len(disabled),
            "kerberoastable_users": len(kerberoastable),
        }

    def _find_domain_controller(self) -> str:
        """通过DNS查找域控制器"""
        if not self.domain:
            return ""
        try:
            # 查询_ldap._tcp.dc._msdcs.domain.com SRV记录
            result = socket.getaddrinfo(f"_ldap._tcp.dc._msdcs.{self.domain}", 389, socket.AF_INET, socket.SOCK_STREAM)
            if result:
                return result[0][4][0]
        except Exception:
            pass
        return ""

    def _simulate_query(self, filter_str: str, base_dn: str) -> List[LDAPEntry]:
        """模拟LDAP查询（实际需要ldap3库）"""
        entries = []

        # 根据过滤器类型返回模拟数据
        if 'user' in filter_str.lower() and 'computer' not in filter_str.lower():
            entries = [
                LDAPEntry(
                    dn=f"CN=Administrator,CN=Users,{base_dn}",
                    object_class=['user', 'person', 'organizationalPerson', 'top'],
                    sAMAccountName="Administrator",
                    displayName="Administrator",
                    adminCount=1,
                    userAccountControl=512,
                ),
                LDAPEntry(
                    dn=f"CN=Guest,CN=Users,{base_dn}",
                    object_class=['user', 'person', 'organizationalPerson', 'top'],
                    sAMAccountName="Guest",
                    displayName="Guest",
                    userAccountControl=514,  # 禁用
                ),
                LDAPEntry(
                    dn=f"CN=krbtgt,CN=Users,{base_dn}",
                    object_class=['user', 'person', 'organizationalPerson', 'top'],
                    sAMAccountName="krbtgt",
                    displayName="krbtgt",
                    adminCount=1,
                    servicePrincipalName=["kadmin/changepw"],
                ),
            ]
        elif 'computer' in filter_str.lower():
            entries = [
                LDAPEntry(
                    dn=f"CN=DC01,OU=Domain Controllers,{base_dn}",
                    object_class=['computer', 'user', 'person', 'organizationalPerson', 'top'],
                    sAMAccountName="DC01$",
                    dNSHostName=f"dc01.{self.domain}",
                    operatingSystem="Windows Server 2022",
                    operatingSystemVersion="10.0 (20348)",
                    userAccountControl=532480,
                ),
            ]
        elif 'group' in filter_str.lower():
            entries = [
                LDAPEntry(
                    dn=f"CN=Domain Admins,CN=Users,{base_dn}",
                    object_class=['group', 'top'],
                    sAMAccountName="Domain Admins",
                    adminCount=1,
                ),
                LDAPEntry(
                    dn=f"CN=Enterprise Admins,CN=Users,{base_dn}",
                    object_class=['group', 'top'],
                    sAMAccountName="Enterprise Admins",
                    adminCount=1,
                ),
                LDAPEntry(
                    dn=f"CN=Domain Users,CN=Users,{base_dn}",
                    object_class=['group', 'top'],
                    sAMAccountName="Domain Users",
                ),
            ]

        return entries


# 全局实例
ldap_query = LDAPQuerier()
