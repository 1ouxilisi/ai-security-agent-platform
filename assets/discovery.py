#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
discovery模块，提供相关安全测试功能。

模块功能：
    - 提供相关安全测试功能
    - 支持API调用和命令行使用
    - 与其他模块集成协作

注意事项：
    - 本模块仅用于授权的安全测试
    - 请勿用于非法用途
    - 使用前请确保已获得相关授权
"""
import json
import os
import re
import time
import uuid
from typing import Any, Dict, List, Optional, Set, Tuple
from dataclasses import dataclass, field
from collections import defaultdict, Counter
from urllib.parse import urlparse

import socket

from utils.logger import log


class AssetTypes:
    """资产类型"""
    SERVER = "server"
    WORKSTATION = "workstation"
    NETWORK_DEVICE = "network_device"
    SECURITY_DEVICE = "security_device"
    CLOUD_INSTANCE = "cloud_instance"
    CONTAINER = "container"
    DATABASE = "database"
    APPLICATION = "application"
    WEBSITE = "website"
    API = "api"
    STORAGE = "storage"
    PRINTER = "printer"
    IOT = "iot"
    UNKNOWN = "unknown"


class AssetStatus:
    """资产状态"""
    ACTIVE = "active"
    INACTIVE = "inactive"
    DECOMMISSIONED = "decommissioned"
    MAINTENANCE = "maintenance"
    QUARANTINED = "quarantined"
    UNKNOWN = "unknown"


class RiskLevels:
    """风险等级"""
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"
    UNKNOWN = "unknown"


@dataclass
class Asset:
    """资产"""
    asset_id: str
    name: str = ""
    type: str = "unknown"
    status: str = "unknown"
    ip_addresses: List[str] = field(default_factory=list)
    mac_addresses: List[str] = field(default_factory=list)
    hostnames: List[str] = field(default_factory=list)
    domains: List[str] = field(default_factory=list)
    open_ports: List[Dict[str, Any]] = field(default_factory=list)  # [{port, protocol, service, version}]
    operating_system: str = ""
    os_version: str = ""
    hardware: str = ""
    manufacturer: str = ""
    model: str = ""
    serial_number: str = ""
    applications: List[Dict[str, Any]] = field(default_factory=list)  # [{name, version, path, publisher}]
    services: List[Dict[str, Any]] = field(default_factory=list)  # [{name, port, protocol, version, status}]
    databases: List[Dict[str, Any]] = field(default_factory=list)  # [{type, version, port, instance}]
    certificates: List[Dict[str, Any]] = field(default_factory=list)  # [{subject, issuer, valid_from, valid_to, fingerprint}]
    tags: List[str] = field(default_factory=list)
    owner: str = ""
    department: str = ""
    location: str = ""
    environment: str = ""  # production/staging/development/test
    business_criticality: str = "medium"  # critical/high/medium/low
    risk_level: str = "unknown"
    risk_score: float = 0.0  # 0-100
    vulnerabilities: List[str] = field(default_factory=list)  # CVE IDs
    last_seen: float = field(default_factory=time.time)
    first_seen: float = field(default_factory=time.time)
    discovery_source: str = ""  # scan/manual/api/import
    metadata: Dict[str, Any] = field(default_factory=dict)
    created_at: float = field(default_factory=time.time)
    updated_at: float = field(default_factory=time.time)

    def to_dict(self) -> Dict[str, Any]:
        """执行相关操作。

        Returns:
            操作结果。
        """
        return {
            "asset_id": self.asset_id,
            "name": self.name,
            "type": self.type,
            "status": self.status,
            "ip_addresses": self.ip_addresses,
            "mac_addresses": self.mac_addresses,
            "hostnames": self.hostnames,
            "domains": self.domains,
            "open_ports": self.open_ports,
            "open_ports_count": len(self.open_ports),
            "operating_system": self.operating_system,
            "os_version": self.os_version,
            "hardware": self.hardware,
            "manufacturer": self.manufacturer,
            "model": self.model,
            "applications_count": len(self.applications),
            "services_count": len(self.services),
            "databases_count": len(self.databases),
            "certificates_count": len(self.certificates),
            "tags": self.tags,
            "owner": self.owner,
            "department": self.department,
            "location": self.location,
            "environment": self.environment,
            "business_criticality": self.business_criticality,
            "risk_level": self.risk_level,
            "risk_score": self.risk_score,
            "vulnerabilities_count": len(self.vulnerabilities),
            "vulnerabilities": self.vulnerabilities,
            "last_seen": self.last_seen,
            "first_seen": self.first_seen,
            "discovery_source": self.discovery_source,
            "metadata": self.metadata,
            "created_at": self.created_at,
            "updated_at": self.updated_at
        }


@dataclass
class DiscoveryScan:
    """发现扫描任务"""
    scan_id: str
    name: str = ""
    target: str = ""  # IP范围/CIDR/域名列表
    scan_type: str = "full"  # full/quick/port/service/os/application
    status: str = "pending"  # pending/running/completed/failed/cancelled
    started_at: float = 0
    completed_at: float = 0
    duration_seconds: float = 0
    total_targets: int = 0
    alive_targets: int = 0
    new_assets: int = 0
    updated_assets: int = 0
    open_ports_found: int = 0
    vulnerabilities_found: int = 0
    error_message: str = ""
    created_by: str = ""
    tags: List[str] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        """执行相关操作。

        Returns:
            操作结果。
        """
        return {
            "scan_id": self.scan_id,
            "name": self.name,
            "target": self.target,
            "scan_type": self.scan_type,
            "status": self.status,
            "started_at": self.started_at,
            "completed_at": self.completed_at,
            "duration_seconds": round(self.duration_seconds, 2),
            "total_targets": self.total_targets,
            "alive_targets": self.alive_targets,
            "new_assets": self.new_assets,
            "updated_assets": self.updated_assets,
            "open_ports_found": self.open_ports_found,
            "vulnerabilities_found": self.vulnerabilities_found,
            "error_message": self.error_message,
            "created_by": self.created_by,
            "tags": self.tags
        }


class AssetDiscovery:
    """资产自动发现"""

    def __init__(self, data_dir: str = "data/assets"):
        """初始化AssetDiscovery实例。

        Args:
            self: 类实例。
        """
        self.data_dir = data_dir
        self.assets: Dict[str, Asset] = {}
        self.scans: Dict[str, DiscoveryScan] = {}
        os.makedirs(data_dir, exist_ok=True)
        self._load_data()

        # 常见端口和服务映射
        self.port_service_map = {
            21: ("ftp", "File Transfer Protocol"),
            22: ("ssh", "Secure Shell"),
            23: ("telnet", "Telnet"),
            25: ("smtp", "Simple Mail Transfer Protocol"),
            53: ("dns", "Domain Name System"),
            80: ("http", "Hypertext Transfer Protocol"),
            110: ("pop3", "Post Office Protocol v3"),
            111: ("rpcbind", "RPC Port Mapper"),
            135: ("msrpc", "Microsoft RPC"),
            139: ("netbios-ssn", "NetBIOS Session Service"),
            143: ("imap", "Internet Message Access Protocol"),
            161: ("snmp", "Simple Network Management Protocol"),
            389: ("ldap", "Lightweight Directory Access Protocol"),
            443: ("https", "HTTP Secure"),
            445: ("microsoft-ds", "Microsoft Directory Services (SMB)"),
            465: ("smtps", "SMTP Secure"),
            587: ("submission", "SMTP Submission"),
            631: ("ipp", "Internet Printing Protocol"),
            636: ("ldaps", "LDAP Secure"),
            873: ("rsync", "Rsync"),
            993: ("imaps", "IMAP Secure"),
            995: ("pop3s", "POP3 Secure"),
            1080: ("socks", "SOCKS Proxy"),
            1433: ("mssql", "Microsoft SQL Server"),
            1521: ("oracle", "Oracle Database"),
            2049: ("nfs", "Network File System"),
            2375: ("docker", "Docker API (unencrypted)"),
            2376: ("docker", "Docker API (encrypted)"),
            3000: ("http-alt", "HTTP Alternate (Grafana/Node.js)"),
            3306: ("mysql", "MySQL Database"),
            3389: ("ms-wbt-server", "Remote Desktop Protocol"),
            5000: ("upnp", "UPnP / Flask"),
            5432: ("postgresql", "PostgreSQL Database"),
            5601: ("kibana", "Kibana"),
            5900: ("vnc", "Virtual Network Computing"),
            5985: ("wsman", "Windows Remote Management (HTTP)"),
            5986: ("wsmans", "Windows Remote Management (HTTPS)"),
            6379: ("redis", "Redis Database"),
            7001: ("weblogic", "WebLogic Server"),
            8000: ("http-alt", "HTTP Alternate"),
            8080: ("http-proxy", "HTTP Proxy / Tomcat"),
            8081: ("http-alt", "HTTP Alternate"),
            8443: ("https-alt", "HTTPS Alternate"),
            8888: ("http-alt", "HTTP Alternate (Jupyter)"),
            9000: ("http-alt", "HTTP Alternate (SonarQube)"),
            9090: ("http-alt", "HTTP Alternate (Prometheus)"),
            9200: ("elasticsearch", "Elasticsearch"),
            9300: ("elasticsearch", "Elasticsearch Transport"),
            11211: ("memcached", "Memcached"),
            27017: ("mongodb", "MongoDB Database"),
            50070: ("hadoop", "Hadoop NameNode"),
        }

        # 常见端口扫描列表（Top 100）
        self.top_ports = [
            21, 22, 23, 25, 53, 80, 110, 111, 135, 139, 143, 161, 389, 443, 445,
            465, 587, 631, 636, 873, 993, 995, 1080, 1433, 1521, 2049, 2375, 2376,
            3000, 3306, 3389, 5000, 5432, 5601, 5900, 5985, 5986, 6379, 7001, 8000,
            8080, 8081, 8443, 8888, 9000, 9090, 9200, 9300, 11211, 27017, 50070
        ]

        # 指纹识别规则
        self.fingerprint_rules = [
            {"pattern": "nginx", "type": "web_server", "name": "Nginx"},
            {"pattern": "apache", "type": "web_server", "name": "Apache"},
            {"pattern": "iis", "type": "web_server", "name": "Microsoft IIS"},
            {"pattern": "tomcat", "type": "app_server", "name": "Apache Tomcat"},
            {"pattern": "weblogic", "type": "app_server", "name": "Oracle WebLogic"},
            {"pattern": "jboss", "type": "app_server", "name": "JBoss"},
            {"pattern": "jetty", "type": "app_server", "name": "Eclipse Jetty"},
            {"pattern": "node", "type": "runtime", "name": "Node.js"},
            {"pattern": "express", "type": "framework", "name": "Express.js"},
            {"pattern": "django", "type": "framework", "name": "Django"},
            {"pattern": "flask", "type": "framework", "name": "Flask"},
            {"pattern": "spring", "type": "framework", "name": "Spring Framework"},
            {"pattern": "laravel", "type": "framework", "name": "Laravel"},
            {"pattern": "wordpress", "type": "cms", "name": "WordPress"},
            {"pattern": "drupal", "type": "cms", "name": "Drupal"},
            {"pattern": "joomla", "type": "cms", "name": "Joomla"},
            {"pattern": "phpmyadmin", "type": "tool", "name": "phpMyAdmin"},
            {"pattern": "grafana", "type": "tool", "name": "Grafana"},
            {"pattern": "kibana", "type": "tool", "name": "Kibana"},
            {"pattern": "prometheus", "type": "tool", "name": "Prometheus"},
            {"pattern": "elasticsearch", "type": "database", "name": "Elasticsearch"},
            {"pattern": "mysql", "type": "database", "name": "MySQL"},
            {"pattern": "postgresql", "type": "database", "name": "PostgreSQL"},
            {"pattern": "mongodb", "type": "database", "name": "MongoDB"},
            {"pattern": "redis", "type": "database", "name": "Redis"},
            {"pattern": "oracle", "type": "database", "name": "Oracle Database"},
            {"pattern": "mssql", "type": "database", "name": "Microsoft SQL Server"},
            {"pattern": "docker", "type": "platform", "name": "Docker"},
            {"pattern": "kubernetes", "type": "platform", "name": "Kubernetes"},
            {"pattern": "windows", "type": "os", "name": "Windows"},
            {"pattern": "linux", "type": "os", "name": "Linux"},
            {"pattern": "ubuntu", "type": "os", "name": "Ubuntu"},
            {"pattern": "centos", "type": "os", "name": "CentOS"},
            {"pattern": "debian", "type": "os", "name": "Debian"},
            {"pattern": "redhat", "type": "os", "name": "Red Hat Enterprise Linux"},
        ]

    def _load_data(self):
        """从文件加载数据"""
        # 加载资产
        assets_file = os.path.join(self.data_dir, "assets.json")
        if os.path.exists(assets_file):
            try:
                with open(assets_file, 'r', encoding='utf-8') as f:
                    data = json.load(f)
                for aid, adata in data.items():
                    self.assets[aid] = Asset(
                        asset_id=adata["asset_id"],
                        name=adata.get("name", ""),
                        type=adata.get("type", "unknown"),
                        status=adata.get("status", "unknown"),
                        ip_addresses=adata.get("ip_addresses", []),
                        mac_addresses=adata.get("mac_addresses", []),
                        hostnames=adata.get("hostnames", []),
                        domains=adata.get("domains", []),
                        open_ports=adata.get("open_ports", []),
                        operating_system=adata.get("operating_system", ""),
                        os_version=adata.get("os_version", ""),
                        hardware=adata.get("hardware", ""),
                        manufacturer=adata.get("manufacturer", ""),
                        model=adata.get("model", ""),
                        serial_number=adata.get("serial_number", ""),
                        applications=adata.get("applications", []),
                        services=adata.get("services", []),
                        databases=adata.get("databases", []),
                        certificates=adata.get("certificates", []),
                        tags=adata.get("tags", []),
                        owner=adata.get("owner", ""),
                        department=adata.get("department", ""),
                        location=adata.get("location", ""),
                        environment=adata.get("environment", ""),
                        business_criticality=adata.get("business_criticality", "medium"),
                        risk_level=adata.get("risk_level", "unknown"),
                        risk_score=adata.get("risk_score", 0),
                        vulnerabilities=adata.get("vulnerabilities", []),
                        last_seen=adata.get("last_seen", time.time()),
                        first_seen=adata.get("first_seen", time.time()),
                        discovery_source=adata.get("discovery_source", ""),
                        metadata=adata.get("metadata", {})
                    )
            except Exception as e:
                log.error(f"加载资产失败: {e}")

        # 加载扫描记录
        scans_file = os.path.join(self.data_dir, "scans.json")
        if os.path.exists(scans_file):
            try:
                with open(scans_file, 'r', encoding='utf-8') as f:
                    data = json.load(f)
                for sid, sdata in data.items():
                    self.scans[sid] = DiscoveryScan(
                        scan_id=sdata["scan_id"],
                        name=sdata.get("name", ""),
                        target=sdata.get("target", ""),
                        scan_type=sdata.get("scan_type", "full"),
                        status=sdata.get("status", "pending"),
                        started_at=sdata.get("started_at", 0),
                        completed_at=sdata.get("completed_at", 0),
                        duration_seconds=sdata.get("duration_seconds", 0),
                        total_targets=sdata.get("total_targets", 0),
                        alive_targets=sdata.get("alive_targets", 0),
                        new_assets=sdata.get("new_assets", 0),
                        updated_assets=sdata.get("updated_assets", 0),
                        open_ports_found=sdata.get("open_ports_found", 0),
                        vulnerabilities_found=sdata.get("vulnerabilities_found", 0),
                        error_message=sdata.get("error_message", ""),
                        created_by=sdata.get("created_by", ""),
                        tags=sdata.get("tags", [])
                    )
            except Exception as e:
                log.error(f"加载扫描记录失败: {e}")

    def _save_data(self):
        """保存数据到文件"""
        # 保存资产
        assets_file = os.path.join(self.data_dir, "assets.json")
        try:
            data = {aid: a.to_dict() for aid, a in self.assets.items()}
            with open(assets_file, 'w', encoding='utf-8') as f:
                json.dump(data, f, ensure_ascii=False, indent=2, default=str)
        except Exception as e:
            log.error(f"保存资产失败: {e}")

        # 保存扫描记录（只保存最近100条）
        scans_file = os.path.join(self.data_dir, "scans.json")
        try:
            sorted_scans = sorted(self.scans.values(), key=lambda x: x.started_at, reverse=True)[:100]
            data = {s.scan_id: s.to_dict() for s in sorted_scans}
            with open(scans_file, 'w', encoding='utf-8') as f:
                json.dump(data, f, ensure_ascii=False, indent=2, default=str)
        except Exception as e:
            log.error(f"保存扫描记录失败: {e}")

    # ===== 资产发现 =====
    def discover_assets(self, target: str, scan_type: str = "quick",
                        scan_name: str = "", created_by: str = "") -> Dict[str, Any]:
        """发现资产"""
        scan_id = f"scan-{uuid.uuid4().hex[:8]}"
        scan = DiscoveryScan(
            scan_id=scan_id,
            name=scan_name or f"资产发现扫描 - {target}",
            target=target,
            scan_type=scan_type,
            status="running",
            started_at=time.time(),
            created_by=created_by
        )
        self.scans[scan_id] = scan

        log.info(f"开始资产发现: {target} (扫描类型: {scan_type})")

        try:
            # 解析目标
            ip_list = self._parse_target(target)
            scan.total_targets = len(ip_list)

            new_assets = 0
            updated_assets = 0
            alive_targets = 0
            open_ports_found = 0

            for ip in ip_list:
                # 主机存活检测
                if not self._is_host_alive(ip):
                    continue

                alive_targets += 1

                # 端口扫描
                ports_to_scan = self.top_ports if scan_type in ["quick", "full"] else self.top_ports[:20]
                open_ports = self._scan_ports(ip, ports_to_scan)
                open_ports_found += len(open_ports)

                # 服务识别和指纹识别
                services = []
                fingerprints = []
                for port_info in open_ports:
                    port = port_info["port"]
                    service_info = self.port_service_map.get(port, ("unknown", "Unknown Service"))
                    port_info["service"] = service_info[0]
                    port_info["service_description"] = service_info[1]

                    # Web服务指纹识别
                    if port in [80, 443, 8080, 8443, 3000, 5000] or service_info[0] in ["http", "https"]:
                        fp = self._identify_web_fingerprint(ip, port)
                        if fp:
                            fingerprints.extend(fp)

                    services.append({
                        "name": service_info[0],
                        "port": port,
                        "protocol": port_info.get("protocol", "tcp"),
                        "version": "",
                        "status": "open"
                    })

                # 操作系统识别（简化）
                os_info = self._identify_os(ip, open_ports)

                # 资产类型判断
                asset_type = self._determine_asset_type(open_ports, fingerprints, os_info)

                # 检查是否已存在
                existing_asset = self._find_existing_asset(ip)

                if existing_asset:
                    # 更新已有资产
                    existing_asset.open_ports = open_ports
                    existing_asset.services = services
                    existing_asset.operating_system = os_info.get("os", existing_asset.operating_system)
                    existing_asset.os_version = os_info.get("version", existing_asset.os_version)
                    existing_asset.last_seen = time.time()
                    existing_asset.status = "active"
                    existing_asset.updated_at = time.time()
                    if fingerprints:
                        existing_asset.metadata["fingerprints"] = fingerprints
                    updated_assets += 1
                else:
                    # 创建新资产
                    asset_id = f"asset-{uuid.uuid4().hex[:8]}"
                    asset = Asset(
                        asset_id=asset_id,
                        name=ip,
                        type=asset_type,
                        status="active",
                        ip_addresses=[ip],
                        open_ports=open_ports,
                        services=services,
                        operating_system=os_info.get("os", ""),
                        os_version=os_info.get("version", ""),
                        discovery_source="scan",
                        metadata={"fingerprints": fingerprints, "scan_id": scan_id}
                    )
                    self.assets[asset_id] = asset
                    new_assets += 1

            scan.alive_targets = alive_targets
            scan.new_assets = new_assets
            scan.updated_assets = updated_assets
            scan.open_ports_found = open_ports_found
            scan.status = "completed"
            scan.completed_at = time.time()
            scan.duration_seconds = scan.completed_at - scan.started_at

            self._save_data()

            log.info(f"资产发现完成: 发现 {alive_targets} 个存活主机, {new_assets} 个新资产, {updated_assets} 个更新资产")

            return {
                "scan_id": scan_id,
                "status": "completed",
                "total_targets": scan.total_targets,
                "alive_targets": alive_targets,
                "new_assets": new_assets,
                "updated_assets": updated_assets,
                "open_ports_found": open_ports_found,
                "duration_seconds": round(scan.duration_seconds, 2)
            }

        except Exception as e:
            scan.status = "failed"
            scan.error_message = str(e)
            scan.completed_at = time.time()
            scan.duration_seconds = scan.completed_at - scan.started_at
            self._save_data()
            log.error(f"资产发现失败: {e}")
            return {"scan_id": scan_id, "status": "failed", "error": str(e)}

    def _parse_target(self, target: str) -> List[str]:
        """解析目标（支持单个IP、CIDR、IP范围、逗号分隔）"""
        ip_list = []

        # 逗号分隔的多个目标
        targets = [t.strip() for t in target.split(",")]

        for t in targets:
            if "/" in t:
                # CIDR格式
                try:
                    import ipaddress
                    network = ipaddress.ip_network(t, strict=False)
                    ip_list.extend([str(ip) for ip in network.hosts()])
                except:
                    pass
            elif "-" in t:
                # IP范围格式 (192.168.1.1-192.168.1.100)
                try:
                    start, end = t.split("-")
                    start_parts = list(map(int, start.strip().split(".")))
                    end_parts = list(map(int, end.strip().split(".")))
                    for i in range(start_parts[3], end_parts[3] + 1):
                        ip_list.append(f"{start_parts[0]}.{start_parts[1]}.{start_parts[2]}.{i}")
                except:
                    pass
            else:
                # 单个IP或域名
                try:
                    ip = socket.gethostbyname(t)
                    ip_list.append(ip)
                except:
                    ip_list.append(t)

        return list(set(ip_list))[:256]  # 限制最多256个目标

    def _is_host_alive(self, ip: str, timeout: float = 1.0) -> bool:
        """主机存活检测（简化版：尝试连接常见端口）"""
        common_ports = [22, 80, 443, 445, 3389, 8080]
        for port in common_ports:
            try:
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(timeout)
                result = sock.connect_ex((ip, port))
                sock.close()
                if result == 0:
                    return True
            except:
                continue
        return False

    def _scan_ports(self, ip: str, ports: List[int], timeout: float = 0.5) -> List[Dict[str, Any]]:
        """端口扫描"""
        open_ports = []
        for port in ports:
            try:
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(timeout)
                result = sock.connect_ex((ip, port))
                sock.close()
                if result == 0:
                    open_ports.append({
                        "port": port,
                        "protocol": "tcp",
                        "status": "open"
                    })
            except:
                continue
        return open_ports

    def _identify_web_fingerprint(self, ip: str, port: int) -> List[Dict[str, Any]]:
        """Web指纹识别（简化版）"""
        fingerprints = []
        try:
            import requests
            protocol = "https" if port in [443, 8443] else "http"
            url = f"{protocol}://{ip}:{port}"
            resp = requests.get(url, timeout=3, verify=False, allow_redirects=True)
            headers = str(resp.headers).lower()
            body = resp.text[:5000].lower()
            server = resp.headers.get("Server", "").lower()
            x_powered_by = resp.headers.get("X-Powered-By", "").lower()

            for rule in self.fingerprint_rules:
                pattern = rule["pattern"].lower()
                if pattern in server or pattern in x_powered_by or pattern in headers or pattern in body:
                    fingerprints.append({
                        "name": rule["name"],
                        "type": rule["type"],
                        "confidence": "high" if pattern in server or pattern in x_powered_by else "medium"
                    })

        except:
            pass

        return fingerprints

    def _identify_os(self, ip: str, open_ports: List[Dict[str, Any]]) -> Dict[str, str]:
        """操作系统识别（简化版，基于端口和服务）"""
        port_list = [p["port"] for p in open_ports]

        # Windows特征
        if 135 in port_list or 139 in port_list or 445 in port_list or 3389 in port_list or 5985 in port_list:
            return {"os": "Windows", "version": "Unknown"}

        # Linux特征
        if 22 in port_list and (80 in port_list or 443 in port_list):
            return {"os": "Linux", "version": "Unknown"}

        # 网络设备特征
        if 23 in port_list and 161 in port_list:
            return {"os": "Network Device OS", "version": "Unknown"}

        return {"os": "Unknown", "version": "Unknown"}

    def _determine_asset_type(self, open_ports: List[Dict[str, Any]],
                                fingerprints: List[Dict[str, Any]],
                                os_info: Dict[str, str]) -> str:
        """判断资产类型"""
        port_list = [p["port"] for p in open_ports]
        fp_names = [fp["name"].lower() for fp in fingerprints]

        # 数据库服务器
        if any(p in port_list for p in [1433, 1521, 3306, 5432, 6379, 27017, 9200]):
            return "database"

        # Web服务器
        if any(p in port_list for p in [80, 443, 8080, 8443]) or any("web" in fp or "nginx" in fp or "apache" in fp for fp in fp_names):
            return "server"

        # 应用服务器
        if any(p in port_list for p in [7001, 8080, 9000]) or any("tomcat" in fp or "weblogic" in fp or "jboss" in fp for fp in fp_names):
            return "application"

        # 远程访问服务器
        if any(p in port_list for p in [22, 23, 3389, 5900]):
            return "server"

        # 网络设备
        if os_info.get("os") == "Network Device OS" or (23 in port_list and 161 in port_list):
            return "network_device"

        # 安全设备
        if any(p in port_list for p in [443, 8443]) and any("firewall" in fp or "vpn" in fp for fp in fp_names):
            return "security_device"

        return "unknown"

    def _find_existing_asset(self, ip: str) -> Optional[Asset]:
        """查找已存在的资产"""
        for asset in self.assets.values():
            if ip in asset.ip_addresses:
                return asset
        return None

    # ===== 资产风险管理 =====
    def calculate_asset_risk(self, asset_id: str) -> Dict[str, Any]:
        """计算资产风险评分"""
        asset = self.assets.get(asset_id)
        if not asset:
            return {"error": "资产不存在"}

        score = 0
        factors = {}

        # 开放端口数量（最多20分）
        port_count = len(asset.open_ports)
        port_score = min(port_count * 2, 20)
        factors["open_ports"] = port_score
        score += port_score

        # 高危端口（最多20分）
        high_risk_ports = [21, 23, 135, 139, 445, 1433, 1521, 3306, 5432, 6379, 27017, 9200, 2375]
        high_risk_count = sum(1 for p in asset.open_ports if p["port"] in high_risk_ports)
        high_risk_score = min(high_risk_count * 3, 20)
        factors["high_risk_ports"] = high_risk_score
        score += high_risk_score

        # 漏洞数量（最多25分）
        vuln_count = len(asset.vulnerabilities)
        vuln_score = min(vuln_count * 5, 25)
        factors["vulnerabilities"] = vuln_score
        score += vuln_score

        # 业务关键性（最多15分）
        criticality_scores = {"critical": 15, "high": 10, "medium": 5, "low": 2}
        criticality_score = criticality_scores.get(asset.business_criticality, 5)
        factors["business_criticality"] = criticality_score
        score += criticality_score

        # 环境（最多10分）
        env_scores = {"production": 10, "staging": 5, "development": 2, "test": 1}
        env_score = env_scores.get(asset.environment, 2)
        factors["environment"] = env_score
        score += env_score

        # 过期证书（最多10分）
        cert_issues = 0
        for cert in asset.certificates:
            if cert.get("valid_to", 0) < time.time():
                cert_issues += 1
        cert_score = min(cert_issues * 5, 10)
        factors["certificate_issues"] = cert_score
        score += cert_score

        # 状态加分/减分
        if asset.status == "quarantined":
            score *= 0.5
        elif asset.status == "maintenance":
            score *= 0.8

        score = min(score, 100)

        # 风险等级
        if score >= 80:
            risk_level = "critical"
        elif score >= 60:
            risk_level = "high"
        elif score >= 40:
            risk_level = "medium"
        elif score >= 20:
            risk_level = "low"
        else:
            risk_level = "info"

        asset.risk_score = score
        asset.risk_level = risk_level
        asset.updated_at = time.time()
        self._save_data()

        return {
            "asset_id": asset_id,
            "name": asset.name,
            "risk_score": round(score, 2),
            "risk_level": risk_level,
            "factors": factors
        }

    def recalculate_all_risks(self) -> Dict[str, Any]:
        """重新计算所有资产风险"""
        results = []
        for asset_id in self.assets:
            result = self.calculate_asset_risk(asset_id)
            results.append(result)

        risk_distribution = Counter(r["risk_level"] for r in results)

        return {
            "total_assets": len(results),
            "risk_distribution": dict(risk_distribution),
            "average_risk_score": round(sum(r["risk_score"] for r in results) / len(results), 2) if results else 0,
            "high_risk_assets": [r for r in results if r["risk_level"] in ["critical", "high"]]
        }

    # ===== 影子IT发现 =====
    def detect_shadow_it(self) -> Dict[str, Any]:
        """发现影子IT（未登记的资产）"""
        shadow_assets = []
        known_departments = set()

        for asset in self.assets.values():
            # 未分配所有者或部门
            if not asset.owner or not asset.department:
                shadow_assets.append({
                    "asset_id": asset.asset_id,
                    "name": asset.name,
                    "ip_addresses": asset.ip_addresses,
                    "reason": "未分配所有者或部门",
                    "risk_level": asset.risk_level,
                    "open_ports_count": len(asset.open_ports)
                })
            # 非标准端口的服务
            elif any(p["port"] not in self.top_ports for p in asset.open_ports):
                non_standard = [p["port"] for p in asset.open_ports if p["port"] not in self.top_ports]
                shadow_assets.append({
                    "asset_id": asset.asset_id,
                    "name": asset.name,
                    "ip_addresses": asset.ip_addresses,
                    "reason": f"运行非标准端口服务: {non_standard}",
                    "risk_level": asset.risk_level,
                    "open_ports_count": len(asset.open_ports)
                })
            # 云存储/数据库暴露在公网
            elif any(p["port"] in [9200, 6379, 27017, 2375] for p in asset.open_ports):
                shadow_assets.append({
                    "asset_id": asset.asset_id,
                    "name": asset.name,
                    "ip_addresses": asset.ip_addresses,
                    "reason": "数据库/容器服务暴露在公网",
                    "risk_level": asset.risk_level,
                    "open_ports_count": len(asset.open_ports)
                })

        return {
            "total_shadow_it": len(shadow_assets),
            "shadow_assets": shadow_assets,
            "high_risk_shadow_it": sum(1 for a in shadow_assets if a["risk_level"] in ["critical", "high"])
        }

    # ===== 资产生命周期管理 =====
    def update_asset_status(self, asset_id: str, status: str,
                            reason: str = "") -> bool:
        """更新资产状态"""
        asset = self.assets.get(asset_id)
        if not asset:
            return False
        asset.status = status
        if reason:
            asset.metadata["status_change_reason"] = reason
            asset.metadata["status_change_time"] = time.time()
        asset.updated_at = time.time()
        self._save_data()
        return True

    def decommission_asset(self, asset_id: str, reason: str = "") -> bool:
        """退役资产"""
        return self.update_asset_status(asset_id, "decommissioned", reason)

    def quarantine_asset(self, asset_id: str, reason: str = "") -> bool:
        """隔离资产"""
        return self.update_asset_status(asset_id, "quarantined", reason)

    # ===== 查询和统计 =====
    def get_assets(self, type: str = None, status: str = None,
                   risk_level: str = None, environment: str = None,
                   owner: str = None, department: str = None,
                   min_risk_score: float = 0, limit: int = 100) -> List[Dict[str, Any]]:
        """获取资产列表"""
        results = []
        for asset in self.assets.values():
            if type and asset.type != type:
                continue
            if status and asset.status != status:
                continue
            if risk_level and asset.risk_level != risk_level:
                continue
            if environment and asset.environment != environment:
                continue
            if owner and asset.owner != owner:
                continue
            if department and asset.department != department:
                continue
            if asset.risk_score < min_risk_score:
                continue
            results.append(asset.to_dict())
        results.sort(key=lambda x: x["risk_score"], reverse=True)
        return results[:limit]

    def get_asset_detail(self, asset_id: str) -> Optional[Dict[str, Any]]:
        """获取资产详情"""
        asset = self.assets.get(asset_id)
        if not asset:
            return None
        data = asset.to_dict()
        # 关联漏洞
        data["related_vulnerabilities"] = asset.vulnerabilities
        return data

    def get_statistics(self) -> Dict[str, Any]:
        """获取统计信息"""
        total_assets = len(self.assets)
        active_assets = sum(1 for a in self.assets.values() if a.status == "active")

        by_type = Counter(a.type for a in self.assets.values())
        by_status = Counter(a.status for a in self.assets.values())
        by_risk_level = Counter(a.risk_level for a in self.assets.values())
        by_environment = Counter(a.environment for a in self.assets.values() if a.environment)
        by_department = Counter(a.department for a in self.assets.values() if a.department)

        total_open_ports = sum(len(a.open_ports) for a in self.assets.values())
        total_vulnerabilities = sum(len(a.vulnerabilities) for a in self.assets.values())
        high_risk_assets = sum(1 for a in self.assets.values() if a.risk_level in ["critical", "high"])

        # 最常见的开放端口
        all_ports = []
        for asset in self.assets.values():
            all_ports.extend([p["port"] for p in asset.open_ports])
        top_ports = Counter(all_ports).most_common(10)

        # 扫描统计
        total_scans = len(self.scans)
        completed_scans = sum(1 for s in self.scans.values() if s.status == "completed")
        failed_scans = sum(1 for s in self.scans.values() if s.status == "failed")

        return {
            "total_assets": total_assets,
            "active_assets": active_assets,
            "by_type": dict(by_type),
            "by_status": dict(by_status),
            "by_risk_level": dict(by_risk_level),
            "by_environment": dict(by_environment),
            "by_department": dict(by_department),
            "total_open_ports": total_open_ports,
            "total_vulnerabilities": total_vulnerabilities,
            "high_risk_assets": high_risk_assets,
            "average_risk_score": round(sum(a.risk_score for a in self.assets.values()) / total_assets, 2) if total_assets > 0 else 0,
            "top_open_ports": top_ports,
            "total_scans": total_scans,
            "completed_scans": completed_scans,
            "failed_scans": failed_scans
        }

    def get_scans(self, status: str = None, limit: int = 50) -> List[Dict[str, Any]]:
        """获取扫描记录"""
        results = []
        for scan in self.scans.values():
            if status and scan.status != status:
                continue
            results.append(scan.to_dict())
        results.sort(key=lambda x: x["started_at"], reverse=True)
        return results[:limit]

    # ===== 资产导入导出 =====
    def import_assets(self, assets_data: List[Dict[str, Any]],
                      source: str = "import") -> Dict[str, Any]:
        """批量导入资产"""
        imported = 0
        updated = 0
        for adata in assets_data:
            ip = adata.get("ip_addresses", [""])[0] if isinstance(adata.get("ip_addresses"), list) else adata.get("ip", "")
            existing = self._find_existing_asset(ip) if ip else None

            if existing:
                # 更新已有资产
                for key, value in adata.items():
                    if hasattr(existing, key) and value:
                        setattr(existing, key, value)
                existing.updated_at = time.time()
                updated += 1
            else:
                # 创建新资产
                asset_id = f"asset-{uuid.uuid4().hex[:8]}"
                asset = Asset(
                    asset_id=asset_id,
                    name=adata.get("name", ip or "Unknown"),
                    type=adata.get("type", "unknown"),
                    status=adata.get("status", "active"),
                    ip_addresses=adata.get("ip_addresses", [ip] if ip else []),
                    mac_addresses=adata.get("mac_addresses", []),
                    hostnames=adata.get("hostnames", []),
                    domains=adata.get("domains", []),
                    open_ports=adata.get("open_ports", []),
                    operating_system=adata.get("operating_system", ""),
                    os_version=adata.get("os_version", ""),
                    tags=adata.get("tags", []),
                    owner=adata.get("owner", ""),
                    department=adata.get("department", ""),
                    location=adata.get("location", ""),
                    environment=adata.get("environment", ""),
                    business_criticality=adata.get("business_criticality", "medium"),
                    discovery_source=source,
                    metadata=adata.get("metadata", {})
                )
                self.assets[asset_id] = asset
                imported += 1

        self._save_data()
        return {"total": len(assets_data), "imported": imported, "updated": updated}

    def export_assets(self, type: str = None, status: str = None,
                      format: str = "json") -> Any:
        """导出资产"""
        assets = self.get_assets(type=type, status=status, limit=10000)
        if format == "json":
            return json.dumps(assets, ensure_ascii=False, indent=2, default=str)
        elif format == "csv":
            # 简化的CSV导出
            import io
            output = io.StringIO()
            if assets:
                headers = list(assets[0].keys())[:20]  # 只导出前20个字段
                output.write(",".join(headers) + "\n")
                for asset in assets:
                    row = [str(asset.get(h, "")).replace(",", " ").replace("\n", " ") for h in headers]
                    output.write(",".join(row) + "\n")
            return output.getvalue()
        return assets


# 全局实例
asset_discovery = AssetDiscovery()
