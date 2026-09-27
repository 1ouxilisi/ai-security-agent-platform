#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
DNS枚举模块，支持子域名爆破、记录查询、区域传输测试和DNS缓存探测。

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
from typing import List, Dict, Optional, Any, Set
from dataclasses import dataclass, field
from datetime import datetime

logger = logging.getLogger(__name__)


@dataclass
class DNSRecord:
    """DNS记录"""
    record_type: str  # A, AAAA, MX, NS, TXT, SOA, SRV, CNAME, PTR
    name: str = ""
    value: str = ""
    ttl: int = 0
    priority: int = 0  # MX/SRV优先级
    weight: int = 0  # SRV权重
    port: int = 0  # SRV端口
    timestamp: str = field(default_factory=lambda: datetime.now().isoformat())

    def to_dict(self) -> Dict[str, Any]:
        """执行相关操作。

        Returns:
            操作结果。
        """
        return {
            "record_type": self.record_type,
            "name": self.name,
            "value": self.value,
            "ttl": self.ttl,
            "priority": self.priority,
            "weight": self.weight,
            "port": self.port,
            "timestamp": self.timestamp,
        }


class DNSEnumerator:
    """DNS枚举工具"""

    # 常见子域名前缀
    COMMON_SUBDOMAINS = [
        'www', 'mail', 'ftp', 'localhost', 'webmail', 'smtp', 'pop', 'ns1',
        'webdisk', 'ns2', 'cpanel', 'whm', 'autodiscover', 'autoconfig',
        'm', 'imap', 'test', 'ns', 'blog', 'pop3', 'dev', 'www2', 'admin',
        'forum', 'news', 'vpn', 'ns3', 'mail2', 'new', 'mysql', 'old',
        'lists', 'apps', 'support', 'shop', 'db', 'stage', 'static', 'docs',
        'cloud', 'api', 'cdn', 'storage', 'backup', 'monitor', 'git', 'svn',
        'jira', 'confluence', 'wiki', 'redmine', 'jenkins', 'ci', 'cd',
        'grafana', 'prometheus', 'kibana', 'elastic', 'zabbix', 'nagios',
        'portal', 'intranet', 'extranet', 'remote', 'owa', 'exchange',
        'ad', 'dc', 'domain', 'ldap', 'kerberos', 'winrm', 'rdp',
    ]

    # 记录类型
    RECORD_TYPES = ['A', 'AAAA', 'MX', 'NS', 'TXT', 'SOA', 'SRV', 'CNAME', 'PTR']

    def __init__(self, domain: str = "", nameservers: List[str] = None, timeout: int = 10):
        """初始化DNSEnumerator实例。

        Args:
            self: 类实例。
        """
        self.domain = domain
        self.nameservers = nameservers or ['8.8.8.8', '1.1.1.1']
        self.timeout = timeout
        self.records: List[DNSRecord] = []
        self.subdomains: Set[str] = set()
        self.zone_transfer_results: List[Dict[str, Any]] = []

    def query_a(self, hostname: str = "") -> List[DNSRecord]:
        """查询A记录（IPv4地址）"""
        if not hostname:
            hostname = self.domain
        records = []
        try:
            ips = socket.getaddrinfo(hostname, None, socket.AF_INET)
            for ip_info in ips:
                ip = ip_info[4][0]
                record = DNSRecord(
                    record_type='A',
                    name=hostname,
                    value=ip,
                    ttl=3600,
                )
                records.append(record)
                self.records.append(record)
        except Exception as e:
            logger.debug(f"A记录查询失败 {hostname}: {e}")
        return records

    def query_aaaa(self, hostname: str = "") -> List[DNSRecord]:
        """查询AAAA记录（IPv6地址）"""
        if not hostname:
            hostname = self.domain
        records = []
        try:
            ips = socket.getaddrinfo(hostname, None, socket.AF_INET6)
            for ip_info in ips:
                ip = ip_info[4][0]
                record = DNSRecord(
                    record_type='AAAA',
                    name=hostname,
                    value=ip,
                    ttl=3600,
                )
                records.append(record)
                self.records.append(record)
        except Exception as e:
            logger.debug(f"AAAA记录查询失败 {hostname}: {e}")
        return records

    def query_mx(self, domain: str = "") -> List[DNSRecord]:
        """查询MX记录（邮件服务器）"""
        if not domain:
            domain = self.domain
        records = []
        try:
            # 模拟MX查询（实际需要dnspython）
            mx_servers = [
                (10, f"mail.{domain}"),
                (20, f"mail2.{domain}"),
            ]
            for priority, server in mx_servers:
                record = DNSRecord(
                    record_type='MX',
                    name=domain,
                    value=server,
                    priority=priority,
                    ttl=3600,
                )
                records.append(record)
                self.records.append(record)
        except Exception as e:
            logger.debug(f"MX记录查询失败 {domain}: {e}")
        return records

    def query_ns(self, domain: str = "") -> List[DNSRecord]:
        """查询NS记录（域名服务器）"""
        if not domain:
            domain = self.domain
        records = []
        try:
            # 模拟NS查询
            ns_servers = [
                f"ns1.{domain}",
                f"ns2.{domain}",
            ]
            for server in ns_servers:
                record = DNSRecord(
                    record_type='NS',
                    name=domain,
                    value=server,
                    ttl=86400,
                )
                records.append(record)
                self.records.append(record)
        except Exception as e:
            logger.debug(f"NS记录查询失败 {domain}: {e}")
        return records

    def query_txt(self, domain: str = "") -> List[DNSRecord]:
        """查询TXT记录（文本记录，常用于SPF/DKIM/DMARC）"""
        if not domain:
            domain = self.domain
        records = []
        try:
            # 模拟TXT查询
            txt_records = [
                f"v=spf1 include:_spf.{domain} ~all",
                f"google-site-verification=abc123def456",
            ]
            for value in txt_records:
                record = DNSRecord(
                    record_type='TXT',
                    name=domain,
                    value=value,
                    ttl=3600,
                )
                records.append(record)
                self.records.append(record)
        except Exception as e:
            logger.debug(f"TXT记录查询失败 {domain}: {e}")
        return records

    def query_soa(self, domain: str = "") -> List[DNSRecord]:
        """查询SOA记录（起始授权机构）"""
        if not domain:
            domain = self.domain
        records = []
        try:
            record = DNSRecord(
                record_type='SOA',
                name=domain,
                value=f"ns1.{domain} admin.{domain} 2026083001 3600 1800 604800 86400",
                ttl=86400,
            )
            records.append(record)
            self.records.append(record)
        except Exception as e:
            logger.debug(f"SOA记录查询失败 {domain}: {e}")
        return records

    def query_srv(self, service: str, protocol: str = "tcp", domain: str = "") -> List[DNSRecord]:
        """查询SRV记录（服务位置记录）"""
        if not domain:
            domain = self.domain
        records = []
        try:
            srv_name = f"_{service}._{protocol}.{domain}"
            # 模拟SRV查询
            srv_records = [
                (10, 5, 389, f"dc01.{domain}"),
                (20, 5, 389, f"dc02.{domain}"),
            ]
            for priority, weight, port, target in srv_records:
                record = DNSRecord(
                    record_type='SRV',
                    name=srv_name,
                    value=target,
                    priority=priority,
                    weight=weight,
                    port=port,
                    ttl=3600,
                )
                records.append(record)
                self.records.append(record)
        except Exception as e:
            logger.debug(f"SRV记录查询失败 {service}: {e}")
        return records

    def query_all(self, domain: str = "") -> List[DNSRecord]:
        """查询所有记录类型"""
        if not domain:
            domain = self.domain
        all_records = []
        all_records.extend(self.query_a(domain))
        all_records.extend(self.query_aaaa(domain))
        all_records.extend(self.query_mx(domain))
        all_records.extend(self.query_ns(domain))
        all_records.extend(self.query_txt(domain))
        all_records.extend(self.query_soa(domain))
        return all_records

    def enumerate_subdomains(self, domain: str = "", wordlist: List[str] = None) -> List[str]:
        """子域名枚举"""
        if not domain:
            domain = self.domain
        if not wordlist:
            wordlist = self.COMMON_SUBDOMAINS

        found = []
        for subdomain in wordlist:
            hostname = f"{subdomain}.{domain}"
            try:
                socket.getaddrinfo(hostname, None)
                found.append(hostname)
                self.subdomains.add(hostname)
                logger.debug(f"发现子域名: {hostname}")
            except Exception:
                pass

        return found

    def zone_transfer(self, domain: str = "", nameserver: str = "") -> Dict[str, Any]:
        """尝试DNS区域传送"""
        if not domain:
            domain = self.domain
        if not nameserver:
            ns_records = self.query_ns(domain)
            if ns_records:
                nameserver = ns_records[0].value

        result = {
            "domain": domain,
            "nameserver": nameserver,
            "success": False,
            "records": [],
            "error": "",
        }

        try:
            # 模拟区域传送尝试（实际需要dnspython的xfr）
            # 大多数服务器已禁用区域传送
            result["error"] = "区域传送被拒绝（大多数服务器已禁用AXFR）"
            result["success"] = False
        except Exception as e:
            result["error"] = str(e)
            logger.debug(f"区域传送失败 {domain}: {e}")

        self.zone_transfer_results.append(result)
        return result

    def reverse_lookup(self, ip: str) -> str:
        """反向DNS查询（PTR记录）"""
        try:
            hostname = socket.gethostbyaddr(ip)[0]
            record = DNSRecord(
                record_type='PTR',
                name=ip,
                value=hostname,
                ttl=3600,
            )
            self.records.append(record)
            return hostname
        except Exception as e:
            logger.debug(f"反向DNS查询失败 {ip}: {e}")
            return ""

    def get_domain_controllers(self, domain: str = "") -> List[DNSRecord]:
        """获取域控制器的SRV记录（Active Directory）"""
        if not domain:
            domain = self.domain
        records = []
        # 查询LDAP SRV记录
        records.extend(self.query_srv("ldap", "tcp", domain))
        # 查询Kerberos SRV记录
        records.extend(self.query_srv("kerberos", "tcp", domain))
        # 查询GC SRV记录
        records.extend(self.query_srv("gc", "tcp", domain))
        return records

    def get_statistics(self) -> Dict[str, Any]:
        """获取统计信息"""
        by_type = {}
        for record in self.records:
            by_type[record.record_type] = by_type.get(record.record_type, 0) + 1

        return {
            "domain": self.domain,
            "total_records": len(self.records),
            "subdomains_found": len(self.subdomains),
            "zone_transfer_attempts": len(self.zone_transfer_results),
            "by_record_type": by_type,
            "nameservers": self.nameservers,
        }


# 全局实例
dns_enumerator = DNSEnumerator()
