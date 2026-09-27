#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
cloud_security_tools模块，提供相关安全测试功能。

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
import json
import re
import socket
import ssl
import urllib.request
import urllib.error
from typing import Any, Dict, List, Optional
from dataclasses import dataclass

from utils.logger import log


@dataclass
class CloudFinding:
    """云安全发现"""
    type: str
    severity: str
    description: str
    resource: str
    recommendation: str = ""

    def to_dict(self) -> Dict[str, Any]:
        """执行相关操作。

        Returns:
            操作结果。
        """
        return {
            "type": self.type,
            "severity": self.severity,
            "description": self.description,
            "resource": self.resource,
            "recommendation": self.recommendation
        }


class CloudSecurityTools:
    """云安全工具集"""

    # 常见云服务端口
    CLOUD_PORTS = {
        22: "SSH",
        80: "HTTP",
        443: "HTTPS",
        3306: "MySQL",
        5432: "PostgreSQL",
        1433: "MSSQL",
        6379: "Redis",
        27017: "MongoDB",
        9200: "Elasticsearch",
        5601: "Kibana",
        8080: "Tomcat/Jenkins",
        8443: "HTTPS-Alt",
        2375: "Docker API",
        2376: "Docker API TLS",
        5000: "Docker Registry",
        9000: "SonarQube/Portainer",
        15672: "RabbitMQ Management",
        15692: "RabbitMQ Prometheus",
    }

    # 常见云服务商标识
    CLOUD_PROVIDERS = {
        "amazonaws.com": "AWS",
        "azure.com": "Azure",
        "azurewebsites.net": "Azure App Service",
        "cloudapp.net": "Azure Cloud Service",
        "aliyuncs.com": "阿里云",
        "alibabacloud.com": "阿里云",
        "myqcloud.com": "腾讯云",
        "tencentcloudapi.com": "腾讯云",
        "huaweicloud.com": "华为云",
        "myhuaweicloud.com": "华为云",
        "googleapis.com": "GCP",
        "cloud.google.com": "GCP",
    }

    def __init__(self):
        """初始化CloudSecurityTools实例。

        Args:
            self: 类实例。
        """
        self.timeout = 10.0

    async def detect_cloud_provider(self, target: str) -> Dict[str, Any]:
        """
        检测云服务提供商
        """
        log.info(f"检测云服务提供商: {target}")
        results = {
            "target": target,
            "provider": "Unknown",
            "confidence": "low",
            "indicators": []
        }

        target_lower = target.lower()

        # 通过域名检测
        for domain, provider in self.CLOUD_PROVIDERS.items():
            if domain in target_lower:
                results["provider"] = provider
                results["confidence"] = "high"
                results["indicators"].append(f"域名包含 {domain}")
                break

        # 通过IP反查（简化版，只检测已知云IP段）
        try:
            ip = socket.gethostbyname(target)
            results["ip"] = ip

            # AWS IP段检测（简化版，实际需要查询AWS IP范围JSON）
            if ip.startswith(("3.", "52.", "54.", "35.", "13.", "18.", "53.", "34.", "3.8", "3.12", "3.16")):
                if results["provider"] == "Unknown":
                    results["provider"] = "AWS (可能)"
                    results["confidence"] = "medium"
                results["indicators"].append(f"IP {ip} 可能属于AWS IP段")

            # Azure IP段检测（简化版）
            elif ip.startswith(("20.", "40.", "51.", "52.", "104.", "137.", "138.", "168.", "191.", "207.")):
                if results["provider"] == "Unknown":
                    results["provider"] = "Azure (可能)"
                    results["confidence"] = "medium"
                results["indicators"].append(f"IP {ip} 可能属于Azure IP段")

        except socket.gaierror:
            results["indicators"].append("DNS解析失败")
        except Exception as e:
            results["indicators"].append(f"IP检测异常: {str(e)}")

        log.info(f"云服务商检测完成: {results['provider']} (置信度: {results['confidence']})")
        return results

    async def check_s3_public_bucket(self, bucket_name: str) -> Dict[str, Any]:
        """
        检测S3存储桶是否公开可访问
        """
        log.info(f"检测S3存储桶: {bucket_name}")
        results = {
            "bucket": bucket_name,
            "exists": False,
            "public_read": False,
            "public_write": False,
            "vulnerable": False,
            "findings": [],
            "details": {}
        }

        # 测试存储桶是否存在及权限
        urls_to_test = [
            f"https://{bucket_name}.s3.amazonaws.com",
            f"https://s3.amazonaws.com/{bucket_name}",
        ]

        for url in urls_to_test:
            try:
                req = urllib.request.Request(url, method="GET")
                with urllib.request.urlopen(req, timeout=self.timeout) as response:
                    if response.status == 200:
                        results["exists"] = True
                        results["public_read"] = True
                        results["vulnerable"] = True
                        body = response.read().decode("utf-8", errors="replace")
                        # 尝试解析XML获取文件列表
                        if "<ListBucketResult" in body:
                            files = re.findall(r"<Key>([^<]+)</Key>", body)
                            results["details"]["public_files"] = files[:20]
                            results["details"]["public_files_count"] = len(files)
                        results["findings"].append(
                            CloudFinding(
                                type="S3 Public Read",
                                severity="high",
                                description=f"S3存储桶 {bucket_name} 公开可读，任何人可访问存储桶内容",
                                resource=bucket_name,
                                recommendation="限制存储桶访问权限，启用S3 Block Public Access，配置Bucket Policy"
                            ).to_dict()
                        )
                        break
            except urllib.error.HTTPError as e:
                if e.code == 403:
                    results["exists"] = True
                    results["details"]["access_denied"] = True
                elif e.code == 404:
                    results["exists"] = False
                results["details"]["http_status"] = e.code
            except Exception as e:
                results["details"]["error"] = str(e)

        # 测试公开写入
        if results["exists"] and not results["public_read"]:
            try:
                test_url = f"https://{bucket_name}.s3.amazonaws.com/security-test-file.txt"
                req = urllib.request.Request(test_url, data=b"test", method="PUT")
                with urllib.request.urlopen(req, timeout=self.timeout) as response:
                    if response.status in (200, 204):
                        results["public_write"] = True
                        results["vulnerable"] = True
                        results["findings"].append(
                            CloudFinding(
                                type="S3 Public Write",
                                severity="critical",
                                description=f"S3存储桶 {bucket_name} 公开可写，攻击者可上传恶意文件",
                                resource=bucket_name,
                                recommendation="立即限制写入权限，启用S3 Block Public Access"
                            ).to_dict()
                        )
            except urllib.error.HTTPError:
                pass
            except Exception:
                pass

        log.info(f"S3检测完成: 存在={results['exists']}, 公开读={results['public_read']}, 公开写={results['public_write']}")
        return results

    async def container_security_scan(self, image_name: str = "") -> Dict[str, Any]:
        """
        容器安全扫描 - 检测Docker配置和镜像漏洞
        """
        log.info(f"容器安全扫描: {image_name or '本地Docker环境'}")
        results = {
            "image": image_name,
            "docker_available": False,
            "vulnerabilities": [],
            "misconfigurations": [],
            "findings": []
        }

        # 检测Docker是否可用
        try:
            import subprocess
            docker_check = subprocess.run(
                ["docker", "--version"],
                capture_output=True, text=True, timeout=5
            )
            if docker_check.returncode == 0:
                results["docker_available"] = True
                results["docker_version"] = docker_check.stdout.strip()
        except Exception:
            results["docker_available"] = False

        # 检测Docker API是否暴露
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(3)
            result = sock.connect_ex(("127.0.0.1", 2375))
            sock.close()
            if result == 0:
                results["findings"].append(
                    CloudFinding(
                        type="Docker API Exposed",
                        severity="critical",
                        description="Docker Remote API (端口2375) 未认证暴露，攻击者可远程控制Docker守护进程",
                        resource="127.0.0.1:2375",
                        recommendation="禁用Docker Remote API，或配置TLS认证和访问控制"
                    ).to_dict()
                )
        except Exception:
            pass

        # 检测Docker Registry是否暴露
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(3)
            result = sock.connect_ex(("127.0.0.1", 5000))
            sock.close()
            if result == 0:
                results["findings"].append(
                    CloudFinding(
                        type="Docker Registry Exposed",
                        severity="high",
                        description="Docker Registry (端口5000) 可能未认证暴露，攻击者可拉取/推送镜像",
                        resource="127.0.0.1:5000",
                        recommendation="配置Registry认证，启用TLS，限制访问IP"
                    ).to_dict()
                )
        except Exception:
            pass

        # 常见容器漏洞检测（基于镜像名的简化检测）
        if image_name:
            image_lower = image_name.lower()
            vulnerable_images = {
                "log4j": ("log4j2 RCE (CVE-2021-44228)", "critical"),
                "struts2": ("Struts2 远程代码执行", "critical"),
                "heartbleed": ("OpenSSL Heartbleed (CVE-2014-0160)", "high"),
                "ghost": ("glibc GHOST (CVE-2015-0235)", "medium"),
                "shellshock": ("Bash Shellshock (CVE-2014-6271)", "high"),
            }
            for keyword, (vuln_name, severity) in vulnerable_images.items():
                if keyword in image_lower:
                    results["vulnerabilities"].append({
                        "name": vuln_name,
                        "severity": severity,
                        "detected_by": f"镜像名包含 '{keyword}'"
                    })

        # 容器配置最佳实践检查
        results["misconfigurations"] = [
            {"check": "不要以root用户运行容器", "status": "需要检查", "severity": "medium"},
            {"check": "启用只读文件系统", "status": "需要检查", "severity": "low"},
            {"check": "限制容器资源(CPU/内存)", "status": "需要检查", "severity": "low"},
            {"check": "禁用特权模式(--privileged)", "status": "需要检查", "severity": "high"},
            {"check": "不要挂载Docker套接字(/var/run/docker.sock)", "status": "需要检查", "severity": "critical"},
            {"check": "使用特定版本标签而非latest", "status": "需要检查", "severity": "low"},
            {"check": "启用用户命名空间隔离", "status": "需要检查", "severity": "medium"},
        ]

        log.info(f"容器安全扫描完成: 发现={len(results['findings'])}个, 漏洞={len(results['vulnerabilities'])}个")
        return results

    async def cloud_service_exposure_scan(self, target: str) -> Dict[str, Any]:
        """
        云服务暴露扫描 - 检测目标是否暴露了常见的云管理服务和数据库
        """
        log.info(f"云服务暴露扫描: {target}")
        results = {
            "target": target,
            "open_services": [],
            "vulnerable_services": [],
            "findings": [],
            "risk_level": "low"
        }

        # 扫描常见云服务端口
        open_ports = []
        for port, service in self.CLOUD_PORTS.items():
            try:
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(2)
                result = sock.connect_ex((target, port))
                sock.close()
                if result == 0:
                    open_ports.append({"port": port, "service": service})
            except Exception:
                pass

        results["open_services"] = open_ports

        # 评估高风险服务
        high_risk_ports = {3306, 5432, 1433, 6379, 27017, 9200, 2375, 2376, 5000, 15672}
        medium_risk_ports = {22, 8080, 8443, 9000, 5601}

        for svc in open_ports:
            if svc["port"] in high_risk_ports:
                results["vulnerable_services"].append({**svc, "risk": "high"})
                results["findings"].append(
                    CloudFinding(
                        type=f"{svc['service']} Exposed",
                        severity="high",
                        description=f"{svc['service']}服务(端口{svc['port']})直接暴露在公网，可能存在未授权访问或弱口令风险",
                        resource=f"{target}:{svc['port']}",
                        recommendation=f"限制{svc['service']}端口访问，配置安全组/防火墙，启用认证和加密"
                    ).to_dict()
                )
            elif svc["port"] in medium_risk_ports:
                results["vulnerable_services"].append({**svc, "risk": "medium"})

        # 风险评级
        high_count = sum(1 for s in results["vulnerable_services"] if s.get("risk") == "high")
        if high_count >= 3:
            results["risk_level"] = "critical"
        elif high_count >= 1:
            results["risk_level"] = "high"
        elif len(open_ports) >= 5:
            results["risk_level"] = "medium"

        log.info(f"云服务暴露扫描完成: 开放服务={len(open_ports)}, 高风险={high_count}, 风险等级={results['risk_level']}")
        return results

    async def iam_config_audit(self, cloud_provider: str = "aws") -> Dict[str, Any]:
        """
        IAM配置审计 - 检查云IAM配置最佳实践
        """
        log.info(f"IAM配置审计: {cloud_provider}")
        results = {
            "cloud_provider": cloud_provider,
            "checks": [],
            "findings": [],
            "overall_score": 0
        }

        # IAM最佳实践检查清单
        iam_checks = {
            "aws": [
                {"check": "启用MFA for root账户", "severity": "critical", "weight": 10},
                {"check": "不使用root账户进行日常操作", "severity": "critical", "weight": 10},
                {"check": "为所有IAM用户启用MFA", "severity": "high", "weight": 8},
                {"check": "使用IAM角色而非长期访问密钥", "severity": "high", "weight": 8},
                {"check": "定期轮换访问密钥(90天内)", "severity": "medium", "weight": 5},
                {"check": "遵循最小权限原则", "severity": "high", "weight": 8},
                {"check": "启用IAM访问分析器", "severity": "medium", "weight": 4},
                {"check": "配置密码策略(最小长度/复杂度/过期)", "severity": "medium", "weight": 5},
                {"check": "监控CloudTrail中的IAM操作", "severity": "medium", "weight": 4},
                {"check": "删除未使用的IAM用户/角色/策略", "severity": "low", "weight": 2},
            ],
            "azure": [
                {"check": "启用MFA for all users", "severity": "critical", "weight": 10},
                {"check": "启用Conditional Access策略", "severity": "high", "weight": 8},
                {"check": "使用Managed Identities而非连接字符串", "severity": "high", "weight": 8},
                {"check": "遵循最小权限原则(RBAC)", "severity": "high", "weight": 8},
                {"check": "启用Privileged Identity Management", "severity": "high", "weight": 7},
                {"check": "监控Azure AD登录日志", "severity": "medium", "weight": 4},
            ],
            "aliyun": [
                {"check": "启用MFA for root账户", "severity": "critical", "weight": 10},
                {"check": "创建RAM子用户而非使用主账户", "severity": "high", "weight": 8},
                {"check": "为RAM用户启用MFA", "severity": "high", "weight": 8},
                {"check": "遵循最小权限原则", "severity": "high", "weight": 8},
                {"check": "定期轮换AccessKey", "severity": "medium", "weight": 5},
                {"check": "启用操作日志(ActionTrail)", "severity": "medium", "weight": 4},
            ]
        }

        checks = iam_checks.get(cloud_provider.lower(), iam_checks["aws"])
        results["checks"] = checks

        # 计算满分（实际需要调用云API进行真实检查，这里提供检查清单）
        total_weight = sum(c["weight"] for c in checks)
        results["max_score"] = total_weight
        results["note"] = "需要配置云服务商API密钥进行真实检查，当前为最佳实践检查清单"

        log.info(f"IAM配置审计完成: {cloud_provider}, 检查项={len(checks)}")
        return results


# 全局实例
cloud_security_tools = CloudSecurityTools()
