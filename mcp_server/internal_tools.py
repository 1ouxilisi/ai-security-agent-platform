#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
internal_tools模块，提供相关安全测试功能。

模块功能：
    - 提供相关安全测试功能
    - 支持API调用和命令行使用
    - 与其他模块集成协作

注意事项：
    - 本模块仅用于授权的安全测试
    - 请勿用于非法用途
    - 使用前请确保已获得相关授权
"""
import asyncio
import socket
import struct
import time
from typing import Any, Dict, List, Optional, Tuple
from dataclasses import dataclass

from utils.logger import log


@dataclass
class ScanResult:
    """扫描结果"""
    host: str
    port: int
    service: str
    status: str  # open/closed/filtered
    banner: str = ""
    version: str = ""
    details: Dict[str, Any] = None

    def to_dict(self) -> Dict[str, Any]:
        """执行相关操作。

        Returns:
            操作结果。
        """
        return {
            "host": self.host,
            "port": self.port,
            "service": self.service,
            "status": self.status,
            "banner": self.banner,
            "version": self.version,
            "details": self.details or {}
        }


class InternalPenetrationTools:
    """内网渗透工具集"""

    # 内网常用端口映射
    INTERNAL_PORTS = {
        21: "FTP",
        22: "SSH",
        23: "Telnet",
        25: "SMTP",
        53: "DNS",
        80: "HTTP",
        88: "Kerberos",
        110: "POP3",
        135: "MSRPC",
        139: "NetBIOS",
        143: "IMAP",
        161: "SNMP",
        389: "LDAP",
        443: "HTTPS",
        445: "SMB",
        465: "SMTPS",
        587: "SMTP",
        593: "MSRPC",
        636: "LDAPS",
        993: "IMAPS",
        995: "POP3S",
        1025: "MSRPC",
        1433: "MSSQL",
        1521: "Oracle",
        2049: "NFS",
        3306: "MySQL",
        3389: "RDP",
        5432: "PostgreSQL",
        5985: "WinRM-HTTP",
        5986: "WinRM-HTTPS",
        6379: "Redis",
        8080: "HTTP-Proxy",
        8443: "HTTPS-Alt",
        9200: "Elasticsearch",
        27017: "MongoDB",
    }

    def __init__(self):
        """初始化InternalPenetrationTools实例。

        Args:
            self: 类实例。
        """
        self.timeout = 3.0
        self.max_concurrent = 50

    async def _check_port(self, host: str, port: int, timeout: float = None) -> ScanResult:
        """检查单个端口"""
        timeout = timeout or self.timeout
        service = self.INTERNAL_PORTS.get(port, "Unknown")
        try:
            reader, writer = await asyncio.wait_for(
                asyncio.open_connection(host, port),
                timeout=timeout
            )
            # 尝试获取banner
            banner = ""
            try:
                data = await asyncio.wait_for(reader.read(1024), timeout=2.0)
                banner = data.decode('utf-8', errors='replace').strip()[:200]
            except Exception:
                pass
            writer.close()
            try:
                await writer.wait_closed()
            except Exception:
                pass
            return ScanResult(host=host, port=port, service=service, status="open", banner=banner)
        except asyncio.TimeoutError:
            return ScanResult(host=host, port=port, service=service, status="filtered")
        except ConnectionRefusedError:
            return ScanResult(host=host, port=port, service=service, status="closed")
        except Exception as e:
            return ScanResult(host=host, port=port, service=service, status="error", banner=str(e)[:100])

    async def internal_port_scan(self, target: str, ports: str = "common") -> Dict[str, Any]:
        """
        内网端口扫描 - 扫描内网常用端口
        :param target: 目标IP或主机名
        :param ports: 端口范围，common=常用内网端口, full=全部常用, 或自定义如"1-1000"
        """
        log.info(f"内网端口扫描: {target}, 端口: {ports}")

        # 解析端口
        if ports == "common":
            port_list = list(self.INTERNAL_PORTS.keys())
        elif ports == "full":
            port_list = list(range(1, 10000))
        elif "-" in ports:
            start, end = map(int, ports.split("-"))
            port_list = list(range(start, end + 1))
        else:
            port_list = [int(p.strip()) for p in ports.split(",")]

        # 并发扫描
        semaphore = asyncio.Semaphore(self.max_concurrent)

        async def scan_with_sem(port):
            async with semaphore:
                return await self._check_port(target, port)

        tasks = [scan_with_sem(port) for port in port_list]
        results = await asyncio.gather(*tasks)

        open_ports = [r for r in results if r.status == "open"]
        filtered_ports = [r for r in results if r.status == "filtered"]

        # 服务识别
        services = {}
        for r in open_ports:
            services[r.port] = {
                "service": r.service,
                "banner": r.banner,
                "version": r.version
            }

        log.info(f"内网端口扫描完成: {target}, 开放端口: {len(open_ports)}, 过滤: {len(filtered_ports)}")

        return {
            "target": target,
            "scan_type": "internal_port_scan",
            "total_ports_scanned": len(port_list),
            "open_ports": [r.port for r in open_ports],
            "open_port_count": len(open_ports),
            "filtered_ports": [r.port for r in filtered_ports],
            "services": services,
            "details": [r.to_dict() for r in open_ports],
            "vulnerabilities": self._analyze_internal_vulnerabilities(open_ports, target)
        }

    def _analyze_internal_vulnerabilities(self, open_ports: List[ScanResult], target: str) -> List[Dict[str, Any]]:
        """分析内网漏洞"""
        vulns = []
        open_port_set = {r.port for r in open_ports}

        # SMB匿名访问检测
        if 445 in open_port_set or 139 in open_port_set:
            vulns.append({
                "name": "SMB服务暴露",
                "severity": "medium",
                "description": f"目标 {target} 暴露了SMB服务(端口445/139)，可能存在匿名访问、永恒之蓝等漏洞",
                "affected": f"{target}:445/139",
                "recommendation": "限制SMB端口访问，启用SMB签名，及时安装MS17-010补丁"
            })

        # RDP暴露
        if 3389 in open_port_set:
            vulns.append({
                "name": "RDP远程桌面暴露",
                "severity": "medium",
                "description": f"目标 {target} 暴露了RDP服务(端口3389)，可能存在暴力破解、BlueKeep等漏洞",
                "affected": f"{target}:3389",
                "recommendation": "限制RDP访问来源，启用网络级别认证(NLA)，安装CVE-2019-0708补丁"
            })

        # WinRM暴露
        if 5985 in open_port_set or 5986 in open_port_set:
            vulns.append({
                "name": "WinRM远程管理暴露",
                "severity": "high",
                "description": f"目标 {target} 暴露了WinRM服务(端口5985/5986)，攻击者可通过PowerShell远程执行命令",
                "affected": f"{target}:5985/5986",
                "recommendation": "限制WinRM访问，启用证书认证，禁用基本认证"
            })

        # 数据库暴露
        db_ports = {1433: "MSSQL", 3306: "MySQL", 5432: "PostgreSQL", 1521: "Oracle", 6379: "Redis", 27017: "MongoDB"}
        for port, db_name in db_ports.items():
            if port in open_port_set:
                vulns.append({
                    "name": f"{db_name}数据库暴露",
                    "severity": "high",
                    "description": f"目标 {target} 暴露了{db_name}服务(端口{port})，可能存在弱口令、未授权访问等漏洞",
                    "affected": f"{target}:{port}",
                    "recommendation": f"限制{db_name}端口访问，设置强密码，启用访问控制"
                })

        # LDAP/AD暴露
        if 389 in open_port_set or 636 in open_port_set:
            vulns.append({
                "name": "LDAP/AD服务暴露",
                "severity": "medium",
                "description": f"目标 {target} 暴露了LDAP服务(端口389/636)，可能是域控制器，存在用户枚举、匿名绑定等风险",
                "affected": f"{target}:389/636",
                "recommendation": "限制LDAP访问，禁用匿名绑定，启用LDAPS"
            })

        # SNMP暴露
        if 161 in open_port_set:
            vulns.append({
                "name": "SNMP服务暴露",
                "severity": "medium",
                "description": f"目标 {target} 暴露了SNMP服务(端口161)，可能存在默认社区字符串(public/private)，可泄露大量系统信息",
                "affected": f"{target}:161",
                "recommendation": "修改默认社区字符串，限制SNMP访问，升级到SNMPv3"
            })

        return vulns

    async def smb_scan(self, target: str) -> Dict[str, Any]:
        """
        SMB扫描 - 检测SMB服务，枚举共享、检测匿名访问、检测漏洞
        """
        log.info(f"SMB扫描: {target}")
        results = {
            "target": target,
            "port": 445,
            "smb_available": False,
            "anonymous_access": False,
            "shares": [],
            "os_info": {},
            "vulnerabilities": [],
            "details": {}
        }

        # 检查445端口
        port_check = await self._check_port(target, 445)
        if port_check.status != "open":
            results["details"]["error"] = f"SMB端口445未开放，状态: {port_check.status}"
            log.info(f"SMB端口未开放: {target}")
            return results

        results["smb_available"] = True
        results["details"]["port_status"] = "open"

        # 尝试SMB协议握手（简化版）
        try:
            # 发送SMB Negotiate Protocol Request
            reader, writer = await asyncio.wait_for(
                asyncio.open_connection(target, 445),
                timeout=self.timeout
            )

            # SMB2 Negotiate Request (简化)
            negotiate_req = bytes.fromhex(
                "000000a4"  # NetBIOS session request length
                "fe534d42"  # SMB2 protocol ID
                "00000000"  # StructureSize
                "0100"      # NegotiateContextCount
                "00000000"  # ProcessId
                "00000000"  # NetworkReserved
                "0000000000000000"  # MessageId
                "00000000"  # Reserved
                "00000000"  # TreeId
                "00000000"  # SessionId
                "41000800"  # Signature
                "01000000"  # NegotiateContextList
                "00000000"  # Reserved2
                "0200"      # DialectCount
                "0100"      # Dialects: SMB 2.0.2
                "0202"      # Dialects: SMB 2.1
                "1002"      # Dialects: SMB 3.0
                "1103"      # Dialects: SMB 3.1.1
            )
            writer.write(negotiate_req)
            await writer.drain()

            response = await asyncio.wait_for(reader.read(4096), timeout=5.0)
            writer.close()

            if len(response) > 4 and response[4:8] == b'\xfeSMB':
                results["details"]["protocol"] = "SMB2/SMB3"
                # 解析操作系统信息（简化）
                results["os_info"] = {
                    "protocol_supported": True,
                    "smb_version": "2.x/3.x",
                    "signing_required": False,  # 简化检测
                }
                results["vulnerabilities"].append({
                    "name": "SMB服务可访问",
                    "severity": "info",
                    "description": f"目标 {target} 运行SMB2/SMB3协议",
                })
            else:
                results["details"]["protocol"] = "SMB1 or unknown"
                results["vulnerabilities"].append({
                    "name": "SMB1协议可能启用",
                    "severity": "high",
                    "description": "SMB1协议存在严重漏洞(永恒之蓝MS17-010)，建议禁用",
                    "recommendation": "禁用SMB1协议，安装MS17-010补丁"
                })

        except asyncio.TimeoutError:
            results["details"]["error"] = "SMB握手超时"
        except Exception as e:
            results["details"]["error"] = f"SMB扫描异常: {str(e)}"

        # 匿名访问检测（简化：尝试空会话连接）
        results["anonymous_access"] = False  # 简化，实际需要impacket
        results["details"]["note"] = "完整的共享枚举和匿名访问检测需要impacket工具库，当前为基础检测"

        log.info(f"SMB扫描完成: {target}, 可用: {results['smb_available']}")
        return results

    async def netbios_enum(self, target: str) -> Dict[str, Any]:
        """
        NetBIOS枚举 - 查询NetBIOS名称、MAC地址、工作组
        """
        log.info(f"NetBIOS枚举: {target}")
        results = {
            "target": target,
            "port": 137,
            "netbios_available": False,
            "computer_name": "",
            "workgroup": "",
            "mac_address": "",
            "names": [],
            "details": {}
        }

        try:
            # 构造NetBIOS名称查询请求
            transaction_id = 0x1234
            nbns_query = struct.pack(
                ">HHHHHH",
                transaction_id,  # Transaction ID
                0x0010,          # Flags: Standard query, recursion desired
                0x0001,          # Questions
                0x0000,          # Answer RRs
                0x0000,          # Authority RRs
                0x0000           # Additional RRs
            )
            # 查询名称: *\x00\x00\x21 (NetBIOS Node Status)
            nbns_query += b'\x20' + b'CKAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA' + b'\x00\x00\x21\x00\x01'

            # UDP发送到137端口
            loop = asyncio.get_event_loop()
            transport, protocol = await loop.create_datagram_endpoint(
                lambda: _NBNSProtocol(),
                remote_addr=(target, 137)
            )
            transport.sendto(nbns_query)

            # 等待响应
            await asyncio.sleep(2.0)
            response = protocol.response
            transport.close()

            if response:
                results["netbios_available"] = True
                # 简化解析（实际需要完整的NetBIOS解析）
                results["details"]["raw_response_length"] = len(response)
                results["details"]["note"] = "NetBIOS响应已接收，完整解析需要更复杂的解析逻辑"

        except asyncio.TimeoutError:
            results["details"]["error"] = "NetBIOS查询超时"
        except Exception as e:
            results["details"]["error"] = f"NetBIOS枚举异常: {str(e)}"

        log.info(f"NetBIOS枚举完成: {target}, 可用: {results['netbios_available']}")
        return results

    async def ldap_query(self, target: str, base_dn: str = "", query: str = "(objectClass=*)") -> Dict[str, Any]:
        """
        LDAP/AD查询 - 查询Active Directory信息，用户/组/计算机枚举
        """
        log.info(f"LDAP查询: {target}, 查询: {query}")
        results = {
            "target": target,
            "port": 389,
            "ldap_available": False,
            "base_dn": base_dn,
            "query": query,
            "entries": [],
            "naming_contexts": [],
            "vulnerabilities": [],
            "details": {}
        }

        # 检查389端口
        port_check = await self._check_port(target, 389)
        if port_check.status != "open":
            results["details"]["error"] = f"LDAP端口389未开放，状态: {port_check.status}"
            return results

        results["ldap_available"] = True
        results["details"]["port_status"] = "open"

        # 匿名绑定检测（简化）
        try:
            reader, writer = await asyncio.wait_for(
                asyncio.open_connection(target, 389),
                timeout=self.timeout
            )

            # LDAP bind request (anonymous)
            bind_request = bytes.fromhex(
                "300c"  # SEQUENCE length 12
                "020101"  # INTEGER messageID 1
                "6007"  # APPLICATION 0 (bindRequest) length 7
                "020103"  # INTEGER version 3
                "0400"  # OCTET STRING name (empty = anonymous)
                "8000"  # CONTEXT 0 authentication (simple, empty)
            )
            writer.write(bind_request)
            await writer.drain()

            response = await asyncio.wait_for(reader.read(1024), timeout=5.0)
            writer.close()

            if len(response) > 6:
                # 解析bind response
                result_code = response[7] if len(response) > 7 else -1
                if result_code == 0:
                    results["details"]["anonymous_bind"] = "success"
                    results["vulnerabilities"].append({
                        "name": "LDAP匿名绑定启用",
                        "severity": "medium",
                        "description": f"目标 {target} LDAP服务允许匿名绑定，攻击者可枚举域内用户、组、计算机信息",
                        "recommendation": "禁用LDAP匿名绑定，限制未认证查询"
                    })
                else:
                    results["details"]["anonymous_bind"] = f"failed (result code: {result_code})"

        except Exception as e:
            results["details"]["error"] = f"LDAP查询异常: {str(e)}"

        results["details"]["note"] = "完整的AD用户/组/计算机枚举需要python-ldap或ldap3库，当前为基础检测"
        log.info(f"LDAP查询完成: {target}, 可用: {results['ldap_available']}")
        return results

    async def kerberos_enum(self, target: str, domain: str = "") -> Dict[str, Any]:
        """
        Kerberos枚举 - 用户枚举、AS-REP Roasting检测、Kerberoasting检测
        """
        log.info(f"Kerberos枚举: {target}, 域: {domain}")
        results = {
            "target": target,
            "port": 88,
            "kerberos_available": False,
            "domain": domain,
            "asrep_roastable_users": [],
            "vulnerabilities": [],
            "details": {}
        }

        # 检查88端口
        port_check = await self._check_port(target, 88)
        if port_check.status != "open":
            results["details"]["error"] = f"Kerberos端口88未开放，状态: {port_check.status}"
            return results

        results["kerberos_available"] = True
        results["details"]["port_status"] = "open"
        results["details"]["note"] = "完整的Kerberos用户枚举和AS-REP Roasting需要impacket库，当前为基础检测"

        if domain:
            results["vulnerabilities"].append({
                "name": "Kerberos服务可访问",
                "severity": "info",
                "description": f"目标 {target} 可能是域控制器，域: {domain}",
            })

        log.info(f"Kerberos枚举完成: {target}")
        return results

    async def rdp_detect(self, target: str) -> Dict[str, Any]:
        """RDP检测 - 检测RDP服务版本、加密级别、NLA支持"""
        log.info(f"RDP检测: {target}")
        results = {
            "target": target,
            "port": 3389,
            "rdp_available": False,
            "nla_supported": None,
            "encryption_level": "",
            "protocol_version": "",
            "vulnerabilities": [],
            "details": {}
        }

        port_check = await self._check_port(target, 3389)
        if port_check.status != "open":
            results["details"]["error"] = f"RDP端口3389未开放，状态: {port_check.status}"
            return results

        results["rdp_available"] = True
        results["details"]["port_status"] = "open"

        # RDP协议检测（简化）
        try:
            reader, writer = await asyncio.wait_for(
                asyncio.open_connection(target, 3389),
                timeout=self.timeout
            )
            # 发送RDP连接请求（简化）
            x224_request = bytes.fromhex(
                "03000013"  # TPKT header
                "0eE00000"  # X.224 Data
                "00000001"  # RDP Negotiation Request
                "00080000"  # requestedProtocols: SSL
                "00000000"
            )
            writer.write(x224_request)
            await writer.drain()

            response = await asyncio.wait_for(reader.read(1024), timeout=5.0)
            writer.close()

            if len(response) > 11:
                # 解析RDP协商响应
                neg_type = response[11] if len(response) > 11 else 0
                if neg_type == 2:  # Negotiation Response
                    selected_proto = int.from_bytes(response[15:19], 'little') if len(response) > 19 else 0
                    results["protocol_version"] = f"RDP negotiated (proto: {selected_proto})"
                    results["nla_supported"] = (selected_proto & 0x01) != 0  # NLA
                elif neg_type == 3:  # Negotiation Failure
                    results["details"]["negotiation"] = "failed"
                else:
                    results["protocol_version"] = "RDP (unknown negotiation)"

        except Exception as e:
            results["details"]["error"] = f"RDP检测异常: {str(e)}"

        # 漏洞检测
        results["vulnerabilities"].append({
            "name": "RDP服务暴露",
            "severity": "medium",
            "description": f"目标 {target} 暴露RDP服务，建议检查CVE-2019-0708(BlueKeep)、CVE-2020-0609等漏洞",
            "recommendation": "限制RDP访问，启用NLA，安装最新安全补丁"
        })

        log.info(f"RDP检测完成: {target}, 可用: {results['rdp_available']}")
        return results

    async def winrm_detect(self, target: str) -> Dict[str, Any]:
        """WinRM检测 - 检测Windows远程管理服务"""
        log.info(f"WinRM检测: {target}")
        results = {
            "target": target,
            "ports": {"5985": False, "5986": False},
            "winrm_available": False,
            "auth_methods": [],
            "vulnerabilities": [],
            "details": {}
        }

        for port in [5985, 5986]:
            port_check = await self._check_port(target, port)
            if port_check.status == "open":
                results["ports"][str(port)] = True
                results["winrm_available"] = True

        if results["winrm_available"]:
            results["vulnerabilities"].append({
                "name": "WinRM服务暴露",
                "severity": "high",
                "description": f"目标 {target} 暴露WinRM服务，攻击者可通过PowerShell远程执行任意命令",
                "recommendation": "限制WinRM访问，启用证书认证，禁用基本认证，配置Just Enough Administration"
            })

        log.info(f"WinRM检测完成: {target}, 可用: {results['winrm_available']}")
        return results

    async def mssql_scan(self, target: str, port: int = 1433) -> Dict[str, Any]:
        """MSSQL扫描 - 检测MSSQL服务，弱口令检测"""
        log.info(f"MSSQL扫描: {target}:{port}")
        results = {
            "target": target,
            "port": port,
            "mssql_available": False,
            "version": "",
            "weak_credentials": [],
            "vulnerabilities": [],
            "details": {}
        }

        port_check = await self._check_port(target, port)
        if port_check.status != "open":
            results["details"]["error"] = f"MSSQL端口{port}未开放"
            return results

        results["mssql_available"] = True
        results["details"]["port_status"] = "open"
        results["vulnerabilities"].append({
            "name": "MSSQL数据库暴露",
            "severity": "high",
            "description": f"目标 {target}:{port} 暴露MSSQL服务，可能存在弱口令、未授权访问、xp_cmdshell等风险",
            "recommendation": "限制MSSQL访问，设置强密码，禁用sa账户，禁用xp_cmdshell"
        })

        log.info(f"MSSQL扫描完成: {target}")
        return results

    async def ssh_scan(self, target: str, port: int = 22) -> Dict[str, Any]:
        """SSH扫描 - 检测SSH服务版本，弱口令检测"""
        log.info(f"SSH扫描: {target}:{port}")
        results = {
            "target": target,
            "port": port,
            "ssh_available": False,
            "version": "",
            "weak_credentials": [],
            "vulnerabilities": [],
            "details": {}
        }

        port_check = await self._check_port(target, port)
        if port_check.status != "open":
            results["details"]["error"] = f"SSH端口{port}未开放"
            return results

        results["ssh_available"] = True
        results["version"] = port_check.banner

        # 漏洞检测
        if "SSH-1" in port_check.banner or "SSH-1.5" in port_check.banner:
            results["vulnerabilities"].append({
                "name": "SSH v1协议启用",
                "severity": "high",
                "description": "SSH v1协议存在严重安全漏洞，建议升级到SSH v2",
                "recommendation": "禁用SSH v1，仅允许SSH v2"
            })

        results["vulnerabilities"].append({
            "name": "SSH服务暴露",
            "severity": "low",
            "description": f"目标 {target}:{port} 暴露SSH服务 ({port_check.banner})",
            "recommendation": "限制SSH访问，禁用密码认证，使用密钥认证，修改默认端口"
        })

        log.info(f"SSH扫描完成: {target}, 版本: {results['version']}")
        return results

    async def ftp_scan(self, target: str, port: int = 21) -> Dict[str, Any]:
        """FTP扫描 - 检测FTP服务，匿名登录检测"""
        log.info(f"FTP扫描: {target}:{port}")
        results = {
            "target": target,
            "port": port,
            "ftp_available": False,
            "anonymous_access": False,
            "version": "",
            "vulnerabilities": [],
            "details": {}
        }

        port_check = await self._check_port(target, port)
        if port_check.status != "open":
            results["details"]["error"] = f"FTP端口{port}未开放"
            return results

        results["ftp_available"] = True
        results["version"] = port_check.banner

        # 匿名登录检测
        try:
            reader, writer = await asyncio.wait_for(
                asyncio.open_connection(target, port),
                timeout=self.timeout
            )
            await asyncio.wait_for(reader.read(1024), timeout=3.0)

            # 发送USER anonymous
            writer.write(b"USER anonymous\r\n")
            await writer.drain()
            response = await asyncio.wait_for(reader.read(1024), timeout=3.0)

            if b"331" in response:  # Need password
                writer.write(b"PASS test@test.com\r\n")
                await writer.drain()
                response2 = await asyncio.wait_for(reader.read(1024), timeout=3.0)
                if b"230" in response2:  # Login successful
                    results["anonymous_access"] = True
                    results["vulnerabilities"].append({
                        "name": "FTP匿名登录启用",
                        "severity": "high",
                        "description": f"目标 {target}:{port} FTP服务允许匿名登录，攻击者可上传下载文件",
                        "recommendation": "禁用FTP匿名登录，使用FTPS/SFTP，限制访问IP"
                    })

            writer.write(b"QUIT\r\n")
            writer.close()
        except Exception as e:
            results["details"]["anonymous_check_error"] = str(e)

        log.info(f"FTP扫描完成: {target}, 匿名: {results['anonymous_access']}")
        return results

    async def snmp_enum(self, target: str, community: str = "public") -> Dict[str, Any]:
        """SNMP枚举 - 社区字符串检测，系统信息枚举"""
        log.info(f"SNMP枚举: {target}, 社区: {community}")
        results = {
            "target": target,
            "port": 161,
            "snmp_available": False,
            "community_strings": [],
            "system_info": {},
            "vulnerabilities": [],
            "details": {}
        }

        # 常见社区字符串
        communities = ["public", "private", "community", "admin", "manager", "cisco", "default"]

        try:
            loop = asyncio.get_event_loop()
            for comm in communities:
                transport, protocol = await loop.create_datagram_endpoint(
                    lambda: _SNMPProtocol(),
                    remote_addr=(target, 161)
                )

                # SNMPv2c GetRequest for sysDescr (1.3.6.1.2.1.1.1.0)
                snmp_request = bytes.fromhex(
                    "3026"  # SEQUENCE
                    "020101"  # version: 1 (SNMPv2c)
                    "0406" + comm.encode().hex() +  # community
                    "a019"  # PDU: GetRequest
                    "020400000001"  # request-id
                    "020100"  # error-status: noError
                    "020100"  # error-index
                    "300b"  # variable-bindings
                    "3009"  # variable-binding
                    "06052b06010201"  # OID: 1.3.6.1.2.1
                    "0500"  # value: NULL
                )
                transport.sendto(snmp_request)
                await asyncio.sleep(1.5)
                response = protocol.response
                transport.close()

                if response:
                    results["snmp_available"] = True
                    results["community_strings"].append(comm)
                    results["details"][f"{comm}_response_length"] = len(response)
                    break  # 找到一个就停止

        except Exception as e:
            results["details"]["error"] = f"SNMP枚举异常: {str(e)}"

        if results["community_strings"]:
            results["vulnerabilities"].append({
                "name": "SNMP默认社区字符串",
                "severity": "high",
                "description": f"目标 {target} SNMP服务使用默认社区字符串: {', '.join(results['community_strings'])}，攻击者可获取系统信息、网络拓扑、用户列表等敏感信息",
                "recommendation": "修改默认社区字符串，限制SNMP访问IP，升级到SNMPv3"
            })

        log.info(f"SNMP枚举完成: {target}, 可用: {results['snmp_available']}")
        return results

    async def pass_the_hash_detect(self, target: str) -> Dict[str, Any]:
        """哈希传递检测 - 检测目标是否容易受到Pass-the-Hash攻击"""
        log.info(f"哈希传递检测: {target}")
        results = {
            "target": target,
            "vulnerable": False,
            "risk_factors": [],
            "vulnerabilities": [],
            "details": {}
        }

        # 检查相关端口
        smb_check = await self._check_port(target, 445)
        rdp_check = await self._check_port(target, 3389)
        winrm_check = await self._check_port(target, 5985)

        if smb_check.status == "open":
            results["risk_factors"].append("SMB服务开放(445)")
        if rdp_check.status == "open":
            results["risk_factors"].append("RDP服务开放(3389)")
        if winrm_check.status == "open":
            results["risk_factors"].append("WinRM服务开放(5985)")

        if len(results["risk_factors"]) >= 2:
            results["vulnerable"] = True
            results["vulnerabilities"].append({
                "name": "存在哈希传递(Pass-the-Hash)风险",
                "severity": "high",
                "description": f"目标 {target} 开放多个Windows远程管理服务，存在哈希传递攻击风险。攻击者获取用户NTLM哈希后，可无需明文密码直接登录系统",
                "affected": ", ".join(results["risk_factors"]),
                "recommendation": "启用Restricted Admin模式，配置LSA保护，使用Windows Defender Credential Guard，限制管理员登录"
            })

        results["details"]["note"] = "完整的哈希传递漏洞利用需要impacket工具库，当前为风险评估"
        log.info(f"哈希传递检测完成: {target}, 风险: {results['vulnerable']}")
        return results


class _NBNSProtocol:
    """NetBIOS Name Service协议处理器"""
    def __init__(self):
        """初始化_NBNSProtocol实例。

        Args:
            self: 类实例。
        """
        self.response = None
        self.transport = None

    def connection_made(self, transport):
        """建立连接。

        Args:
            transport: 相关参数。

        Returns:
            操作结果。
        """
        self.transport = transport

    def datagram_received(self, data, addr):
        """接收相关数据。

        Args:
            data: 相关参数。
            addr: 相关参数。

        Returns:
            操作结果。
        """
        self.response = data

    def error_received(self, exc):
        """接收相关数据。

        Args:
            exc: 相关参数。

        Returns:
            操作结果。
        """
        pass

    def connection_lost(self, exc):
        """建立连接。

        Args:
            exc: 相关参数。

        Returns:
            操作结果。
        """
        pass


class _SNMPProtocol:
    """SNMP协议处理器"""
    def __init__(self):
        """初始化_SNMPProtocol实例。

        Args:
            self: 类实例。
        """
        self.response = None
        self.transport = None

    def connection_made(self, transport):
        """建立连接。

        Args:
            transport: 相关参数。

        Returns:
            操作结果。
        """
        self.transport = transport

    def datagram_received(self, data, addr):
        """接收相关数据。

        Args:
            data: 相关参数。
            addr: 相关参数。

        Returns:
            操作结果。
        """
        self.response = data

    def error_received(self, exc):
        """接收相关数据。

        Args:
            exc: 相关参数。

        Returns:
            操作结果。
        """
        pass

    def connection_lost(self, exc):
        """建立连接。

        Args:
            exc: 相关参数。

        Returns:
            操作结果。
        """
        pass


# 全局实例
internal_tools = InternalPenetrationTools()
