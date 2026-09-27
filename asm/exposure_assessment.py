"""
暴露面评估引擎
对发现的每个资产进行风险评级：开放端口风险、服务风险、配置风险、证书风险、已知漏洞
"""
from typing import List, Dict, Any, Optional
import time


class ExposureAssessmentEngine:
    """暴露面评估引擎"""

    # 高危端口列表（暴露在公网风险高）
    HIGH_RISK_PORTS = {
        21: {"name": "FTP", "risk": "high", "reason": "明文传输，弱口令常见"},
        23: {"name": "Telnet", "risk": "critical", "reason": "明文传输，极易被窃听"},
        25: {"name": "SMTP", "risk": "medium", "reason": "可能被用于发送垃圾邮件"},
        110: {"name": "POP3", "risk": "medium", "reason": "明文邮件传输"},
        143: {"name": "IMAP", "risk": "medium", "reason": "明文邮件传输"},
        445: {"name": "SMB", "risk": "critical", "reason": "EternalBlue等勒索软件利用入口"},
        3389: {"name": "RDP", "risk": "high", "reason": "远程桌面，暴力破解常见，BlueKeep漏洞"},
        5900: {"name": "VNC", "risk": "high", "reason": "远程控制，弱口令常见"},
        6379: {"name": "Redis", "risk": "critical", "reason": "未授权访问可导致RCE和数据泄露"},
        9200: {"name": "Elasticsearch", "risk": "high", "reason": "未授权访问可导致数据泄露"},
        11211: {"name": "Memcached", "risk": "high", "reason": "未授权访问可导致数据泄露和DDoS放大"},
        27017: {"name": "MongoDB", "risk": "critical", "reason": "未授权访问可导致数据泄露和勒索"},
        3306: {"name": "MySQL", "risk": "high", "reason": "数据库暴露，弱口令可导致数据泄露"},
        5432: {"name": "PostgreSQL", "risk": "high", "reason": "数据库暴露，弱口令可导致数据泄露"},
        1723: {"name": "PPTP", "risk": "high", "reason": "VPN协议，已知安全漏洞"},
        135: {"name": "MSRPC", "risk": "high", "reason": "Windows RPC，多种漏洞利用入口"},
        139: {"name": "NetBIOS", "risk": "medium", "reason": "信息泄露，SMB中继攻击"},
    }

    # 服务风险评级
    SERVICE_RISK = {
        "HTTP": {"risk": "low", "weight": 10},
        "HTTPS": {"risk": "low", "weight": 5},
        "SSH": {"risk": "medium", "weight": 30},
        "FTP": {"risk": "high", "weight": 60},
        "Telnet": {"risk": "critical", "weight": 100},
        "SMB": {"risk": "critical", "weight": 95},
        "RDP": {"risk": "high", "weight": 75},
        "Redis": {"risk": "critical", "weight": 95},
        "MongoDB": {"risk": "critical", "weight": 95},
        "Elasticsearch": {"risk": "high", "weight": 80},
        "MySQL": {"risk": "high", "weight": 70},
        "PostgreSQL": {"risk": "high", "weight": 70},
        "VNC": {"risk": "high", "weight": 75},
    }

    def __init__(self):
        self.assessment_results = []
        self.risk_distribution = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}

    def assess_all(self, assets: Dict[str, Any]) -> Dict[str, Any]:
        """
        全面暴露面评估
        :param assets: 资产发现引擎的输出
        :return: 评估结果
        """
        self.assessment_results = []
        self.risk_distribution = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}

        # 1. 评估每个IP的端口暴露风险
        self._assess_port_exposure(assets.get("open_ports", []))

        # 2. 评估服务风险
        self._assess_service_risk(assets.get("services", []))

        # 3. 评估证书风险
        self._assess_certificate_risk(assets.get("certificates", []))

        # 4. 评估云存储桶风险
        self._assess_cloud_bucket_risk(assets.get("cloud_buckets", []))

        # 5. 评估DNS记录风险
        self._assess_dns_risk(assets.get("dns_records", []))

        # 6. 计算每个资产的综合风险评分
        asset_risks = self._calculate_asset_risk_scores()

        # 7. 生成暴露面热力图
        heatmap = self._generate_heatmap(assets)

        overall_risk = self._calculate_overall_risk()
        return {
            "total_findings": len(self.assessment_results),
            "risk_distribution": self.risk_distribution,
            "findings": self.assessment_results,
            "asset_risks": asset_risks,
            "heatmap": heatmap,
            "overall_risk": overall_risk,
            "overall_risk_score": overall_risk,
            "assessment_time": time.strftime("%Y-%m-%d %H:%M:%S")
        }

    def _assess_port_exposure(self, open_ports: List[Dict]):
        """评估端口暴露风险"""
        for port_info in open_ports:
            port = port_info["port"]
            ip = port_info["ip"]

            if port in self.HIGH_RISK_PORTS:
                risk_info = self.HIGH_RISK_PORTS[port]
                finding = {
                    "type": "port_exposure",
                    "severity": risk_info["risk"],
                    "asset": ip,
                    "port": port,
                    "service": risk_info["name"],
                    "title": f"{risk_info['name']}服务暴露在公网",
                    "description": f"端口{port}({risk_info['name']})对外开放。{risk_info['reason']}",
                    "recommendation": f"限制{risk_info['name']}服务的访问来源，使用VPN或防火墙白名单，避免直接暴露在公网",
                    "cvss_score": self._port_to_cvss(port)
                }
                self.assessment_results.append(finding)
                self.risk_distribution[risk_info["risk"]] += 1
            else:
                # 普通端口，低风险
                finding = {
                    "type": "port_exposure",
                    "severity": "info",
                    "asset": ip,
                    "port": port,
                    "title": f"端口{port}开放",
                    "description": f"端口{port}对外开放，需确认是否为业务必需端口",
                    "recommendation": "确认该端口是否为业务必需，非必需端口建议关闭",
                    "cvss_score": 2.0
                }
                self.assessment_results.append(finding)
                self.risk_distribution["info"] += 1

    def _assess_service_risk(self, services: List[Dict]):
        """评估服务风险"""
        for svc in services:
            service_name = svc.get("service", "")
            banner = svc.get("banner", "")

            # 检测服务版本信息泄露
            if banner and any(kw in banner.lower() for kw in ["apache", "nginx", "openssh", "iis", "python", "php"]):
                finding = {
                    "type": "information_disclosure",
                    "severity": "low",
                    "asset": svc["ip"],
                    "port": svc["port"],
                    "title": "服务版本信息泄露",
                    "description": f"服务Banner中包含版本信息：{banner[:100]}",
                    "recommendation": "配置服务器隐藏版本号，减少攻击者信息收集",
                    "cvss_score": 3.5
                }
                self.assessment_results.append(finding)
                self.risk_distribution["low"] += 1

            # 检测明文传输服务
            if service_name in ["HTTP", "FTP", "Telnet", "POP3", "IMAP", "SMTP"]:
                finding = {
                    "type": "plaintext_transmission",
                    "severity": "medium",
                    "asset": svc["ip"],
                    "port": svc["port"],
                    "title": f"{service_name}明文传输",
                    "description": f"{service_name}服务使用明文传输，数据可被中间人窃听和篡改",
                    "recommendation": f"升级为加密版本（HTTPS/FTPS/SSH/SMTPS等）",
                    "cvss_score": 5.3
                }
                self.assessment_results.append(finding)
                self.risk_distribution["medium"] += 1

    def _assess_certificate_risk(self, certificates: List[Dict]):
        """评估证书风险"""
        for cert in certificates:
            not_after = cert.get("not_after", "")
            if not_after:
                try:
                    from datetime import datetime
                    expiry_date = datetime.strptime(not_after.split("T")[0], "%Y-%m-%d")
                    days_left = (expiry_date - datetime.now()).days

                    if days_left < 0:
                        finding = {
                            "type": "certificate_expired",
                            "severity": "high",
                            "asset": cert.get("domain", ""),
                            "title": "SSL证书已过期",
                            "description": f"证书已于{not_after}过期，过期{abs(days_left)}天",
                            "recommendation": "立即更新SSL证书",
                            "cvss_score": 7.5
                        }
                        self.assessment_results.append(finding)
                        self.risk_distribution["high"] += 1
                    elif days_left < 30:
                        finding = {
                            "type": "certificate_expiring",
                            "severity": "medium",
                            "asset": cert.get("domain", ""),
                            "title": "SSL证书即将过期",
                            "description": f"证书将于{not_after}过期，剩余{days_left}天",
                            "recommendation": "尽快更新SSL证书，避免服务中断",
                            "cvss_score": 4.0
                        }
                        self.assessment_results.append(finding)
                        self.risk_distribution["medium"] += 1
                except Exception:
                    pass

    def _assess_cloud_bucket_risk(self, buckets: List[Dict]):
        """评估云存储桶风险"""
        for bucket in buckets:
            if bucket.get("access") == "public":
                finding = {
                    "type": "cloud_bucket_public",
                    "severity": "critical",
                    "asset": bucket.get("name", ""),
                    "title": f"{bucket.get('provider')}存储桶公开访问",
                    "description": f"存储桶{bucket.get('name')}配置为公开访问，任何人都可以读取其中的数据",
                    "recommendation": "立即修改存储桶访问策略为私有，检查是否有敏感数据泄露",
                    "cvss_score": 9.1
                }
                self.assessment_results.append(finding)
                self.risk_distribution["critical"] += 1

    def _assess_dns_risk(self, dns_records: List[Dict]):
        """评估DNS记录风险"""
        for record in dns_records:
            if record.get("type") == "TXT":
                value = record.get("value", "")
                # 检测TXT记录中的敏感信息
                if any(kw in value.lower() for kw in ["password", "secret", "key", "token", "credential"]):
                    finding = {
                        "type": "dns_sensitive_info",
                        "severity": "high",
                        "asset": record.get("domain", ""),
                        "title": "DNS TXT记录包含敏感信息",
                        "description": f"TXT记录中可能包含敏感信息：{value[:100]}",
                        "recommendation": "从DNS记录中移除敏感信息，使用安全的密钥管理服务",
                        "cvss_score": 7.0
                    }
                    self.assessment_results.append(finding)
                    self.risk_distribution["high"] += 1

    def _calculate_asset_risk_scores(self) -> List[Dict]:
        """计算每个资产的综合风险评分"""
        asset_scores = {}

        for finding in self.assessment_results:
            asset = finding.get("asset", "unknown")
            cvss = finding.get("cvss_score", 0)

            if asset not in asset_scores:
                asset_scores[asset] = {
                    "asset": asset,
                    "total_findings": 0,
                    "critical": 0,
                    "high": 0,
                    "medium": 0,
                    "low": 0,
                    "info": 0,
                    "risk_score": 0,
                    "risk_level": "low"
                }

            asset_scores[asset]["total_findings"] += 1
            severity = finding.get("severity", "info")
            if severity in asset_scores[asset]:
                asset_scores[asset][severity] += 1
            asset_scores[asset]["risk_score"] += cvss

        # 计算风险等级
        result = []
        for asset, data in asset_scores.items():
            score = data["risk_score"]
            if score >= 50:
                data["risk_level"] = "critical"
            elif score >= 30:
                data["risk_level"] = "high"
            elif score >= 15:
                data["risk_level"] = "medium"
            else:
                data["risk_level"] = "low"
            data["risk_score"] = round(score, 1)
            result.append(data)

        # 按风险评分排序
        result.sort(key=lambda x: x["risk_score"], reverse=True)
        return result

    def _generate_heatmap(self, assets: Dict) -> Dict:
        """生成暴露面热力图数据"""
        ip_ports = {}
        for port_info in assets.get("open_ports", []):
            ip = port_info["ip"]
            port = port_info["port"]
            if ip not in ip_ports:
                ip_ports[ip] = []
            ip_ports[ip].append(port)

        heatmap_data = []
        for ip, ports in ip_ports.items():
            risk_count = sum(1 for p in ports if p in self.HIGH_RISK_PORTS)
            heatmap_data.append({
                "ip": ip,
                "ports": ports,
                "port_count": len(ports),
                "high_risk_port_count": risk_count,
                "risk_density": round(risk_count / len(ports) * 100, 1) if ports else 0
            })

        heatmap_data.sort(key=lambda x: x["high_risk_port_count"], reverse=True)
        return {
            "total_assets": len(heatmap_data),
            "assets_with_high_risk_ports": sum(1 for d in heatmap_data if d["high_risk_port_count"] > 0),
            "data": heatmap_data[:20]
        }

    def _calculate_overall_risk(self) -> Dict:
        """计算整体风险评分"""
        critical = self.risk_distribution["critical"]
        high = self.risk_distribution["high"]
        medium = self.risk_distribution["medium"]
        low = self.risk_distribution["low"]

        score = critical * 10 + high * 7 + medium * 4 + low * 1

        if score >= 100:
            level = "critical"
        elif score >= 50:
            level = "high"
        elif score >= 20:
            level = "medium"
        else:
            level = "low"

        return {
            "score": min(score, 100),
            "level": level,
            "description": f"发现{critical}个严重风险、{high}个高危风险、{medium}个中危风险、{low}个低危风险"
        }

    def _port_to_cvss(self, port: int) -> float:
        """端口到CVSS评分映射"""
        cvss_map = {
            23: 9.8, 445: 9.8, 6379: 9.8, 27017: 9.8,
            21: 7.5, 3389: 8.1, 5900: 7.5, 9200: 7.5,
            11211: 7.5, 3306: 7.5, 5432: 7.5, 1723: 7.5,
            135: 7.5, 25: 5.3, 110: 5.3, 143: 5.3, 139: 5.3
        }
        return cvss_map.get(port, 2.0)
