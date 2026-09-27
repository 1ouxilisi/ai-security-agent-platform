"""
DNS信息收集 + 资产变化检测 + 智能工作流编排 - 第七轮升级
"""
import socket
import json
import os
import time
import hashlib
from typing import Dict, List, Any, Optional
from datetime import datetime


class DNSCollector:
    """DNS信息收集器"""

    COMMON_SUBDOMAINS = [
        "www", "mail", "ftp", "admin", "api", "dev", "test", "staging",
        "blog", "shop", "portal", "vpn", "git", "jenkins", "docker",
        " grafana", "prometheus", "kibana", "elastic", "mongo", "redis",
        "db", "backup", "old", "new", "m", "mobile", "app", "cdn",
        "static", "img", "images", "media", "docs", "support",
        "auth", "sso", "login", "register", "pay", "payment",
        "status", "monitor", "log", "trace", "debug",
        "ns1", "ns2", "dns", "mx", "smtp", "pop", "imap",
        "webmail", "email", "crm", "erp", "oa", "hr"
    ]

    def __init__(self, target: str, timeout: int = 5):
        self.target = target.replace("http://", "").replace("https://", "").split("/")[0]
        if ":" in self.target:
            self.target = self.target.split(":")[0]
        self.timeout = timeout

    def collect(self) -> Dict[str, Any]:
        """收集完整DNS信息"""
        result = {
            "domain": self.target,
            "timestamp": datetime.now().isoformat(),
            "records": {},
            "subdomains": [],
            "reverse_dns": None,
            "summary": {}
        }

        # A记录
        try:
            ip = socket.gethostbyname(self.target)
            result["records"]["A"] = [ip]
            result["ip"] = ip
        except:
            result["records"]["A"] = []

        # 反向DNS
        if "ip" in result:
            try:
                hostname, _, _ = socket.gethostbyaddr(result["ip"])
                result["reverse_dns"] = hostname
            except:
                pass

        # MX记录（简单解析）
        try:
            mx_ip = socket.gethostbyname(f"mail.{self.target}")
            result["records"]["MX"] = [f"mail.{self.target} -> {mx_ip}"]
        except:
            pass

        # NS记录
        try:
            ns_ip = socket.gethostbyname(f"ns1.{self.target}")
            result["records"]["NS"] = [f"ns1.{self.target} -> {ns_ip}"]
        except:
            pass

        # 子域名枚举
        found_subdomains = []
        for sub in self.COMMON_SUBDOMAINS:
            sub = sub.strip()
            if not sub:
                continue
            try:
                full = f"{sub}.{self.target}"
                ip = socket.gethostbyname(full)
                found_subdomains.append({"subdomain": full, "ip": ip})
            except:
                pass
        result["subdomains"] = found_subdomains

        result["summary"] = {
            "a_records": len(result["records"].get("A", [])),
            "mx_records": len(result["records"].get("MX", [])),
            "subdomains_found": len(found_subdomains),
            "has_reverse_dns": bool(result["reverse_dns"])
        }
        return result


class AssetBaseline:
    """资产基线对比与变化检测"""

    def __init__(self, data_dir: str = "data/baselines"):
        self.data_dir = data_dir
        os.makedirs(data_dir, exist_ok=True)

    def _hash_data(self, data: Dict) -> str:
        return hashlib.md5(json.dumps(data, sort_keys=True, default=str).encode()).hexdigest()

    def save_baseline(self, target: str, scan_data: Dict) -> str:
        """保存扫描结果作为基线"""
        baseline = {
            "target": target,
            "timestamp": datetime.now().isoformat(),
            "hash": self._hash_data(scan_data),
            "data": scan_data
        }
        filename = os.path.join(self.data_dir, f"{target.replace('/', '_').replace(':', '_')}.json")
        with open(filename, "w", encoding="utf-8") as f:
            json.dump(baseline, f, ensure_ascii=False, indent=2, default=str)
        return filename

    def compare(self, target: str, current_data: Dict) -> Dict[str, Any]:
        """与上次基线对比，检测变化"""
        filename = os.path.join(self.data_dir, f"{target.replace('/', '_').replace(':', '_')}.json")
        if not os.path.exists(filename):
            return {"status": "new", "message": "无历史基线，本次为首次扫描", "changes": []}

        with open(filename, "r", encoding="utf-8") as f:
            baseline = json.load(f)

        old_hash = baseline.get("hash", "")
        new_hash = self._hash_data(current_data)

        changes = []
        if old_hash != new_hash:
            # 检测端口变化
            old_ports = set(p.get("port") for p in baseline.get("data", {}).get("port_scan", {}).get("open_ports", []))
            new_ports = set(p.get("port") for p in current_data.get("port_scan", {}).get("open_ports", []))
            if new_ports - old_ports:
                changes.append({"type": "new_ports", "ports": list(new_ports - old_ports)})
            if old_ports - new_ports:
                changes.append({"type": "closed_ports", "ports": list(old_ports - new_ports)})

            # 检测漏洞变化
            old_vulns = set(v.get("name") for v in baseline.get("data", {}).get("vuln_scan", {}).get("vulnerabilities", []))
            new_vulns = set(v.get("name") for v in current_data.get("vuln_scan", {}).get("vulnerabilities", []))
            if new_vulns - old_vulns:
                changes.append({"type": "new_vulnerabilities", "count": len(new_vulns - old_vulns)})

        return {
            "status": "changed" if changes else "unchanged",
            "baseline_time": baseline.get("timestamp"),
            "changes": changes,
            "change_count": len(changes)
        }


class SmartWorkflow:
    """智能工作流编排：根据目标特征自动选择扫描策略"""

    @staticmethod
    def recommend_strategy(target: str, port_results: Dict) -> Dict[str, Any]:
        """根据端口扫描结果推荐下一步扫描策略"""
        open_ports = port_results.get("open_ports", [])
        port_nums = [p["port"] for p in open_ports]

        recommendations = []
        scan_plan = []

        # HTTP/HTTPS
        if 80 in port_nums or 8080 in port_nums:
            scan_plan.append("web_fingerprint")
            scan_plan.append("directory_scan")
            scan_plan.append("vuln_scan")
            recommendations.append("检测到HTTP服务，建议执行Web指纹识别+目录扫描+漏洞检测")

        if 443 in port_nums or 8443 in port_nums:
            scan_plan.append("ssl_detect")
            recommendations.append("检测到HTTPS服务，建议执行SSL/TLS安全检测")

        # 数据库
        db_ports = {3306: "MySQL", 5432: "PostgreSQL", 6379: "Redis",
                    27017: "MongoDB", 1433: "SQL Server", 9200: "Elasticsearch"}
        found_dbs = [f"{p}({db_ports[p]})" for p in port_nums if p in db_ports]
        if found_dbs:
            recommendations.append(f"检测到数据库服务: {', '.join(found_dbs)}，建议检查未授权访问")
            scan_plan.append("db_security_check")

        # SMB/文件共享
        if 445 in port_nums or 139 in port_nums:
            recommendations.append("检测到SMB服务，建议检查匿名访问和已知漏洞(MS17-010)")
            scan_plan.append("smb_check")

        # SSH/FTP
        if 22 in port_nums:
            recommendations.append("检测到SSH服务，建议检查弱密码和密钥认证配置")
        if 21 in port_nums:
            recommendations.append("检测到FTP服务，建议检查匿名登录")

        # 风险评分
        risk = len(open_ports) * 5
        if found_dbs:
            risk += 20
        if 445 in port_nums:
            risk += 15

        return {
            "target": target,
            "open_ports": port_nums,
            "recommended_actions": recommendations,
            "scan_plan": list(dict.fromkeys(scan_plan)),
            "estimated_risk": risk,
            "strategy": "aggressive" if risk > 50 else ("moderate" if risk > 25 else "light")
        }
