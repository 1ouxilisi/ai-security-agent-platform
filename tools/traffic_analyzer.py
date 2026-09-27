"""
traffic_analyzer安全工具集成模块，提供相关安全工具的封装和调用。

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
from typing import Dict, Any, List, Optional, Tuple
from collections import defaultdict, Counter
from dataclasses import dataclass, field
from utils.logger import log


@dataclass
class NetworkFlow:
    """网络流"""
    src_ip: str
    src_port: int
    dst_ip: str
    dst_port: int
    protocol: str
    packets: int = 0
    bytes: int = 0
    first_seen: str = ""
    last_seen: str = ""
    flags: List[str] = field(default_factory=list)


@dataclass
class NetworkAlert:
    """网络告警"""
    type: str
    severity: str
    description: str
    src_ip: str = ""
    dst_ip: str = ""
    src_port: int = 0
    dst_port: int = 0
    protocol: str = ""
    evidence: str = ""
    recommendation: str = ""


class TrafficAnalyzer:
    """网络流量分析器"""

    # 常见端口和协议映射
    COMMON_PORTS = {
        20: "ftp-data", 21: "ftp", 22: "ssh", 23: "telnet", 25: "smtp",
        53: "dns", 67: "dhcp", 68: "dhcp", 69: "tftp", 80: "http",
        110: "pop3", 111: "rpcbind", 119: "nntp", 123: "ntp", 135: "msrpc",
        137: "netbios-ns", 138: "netbios-dgm", 139: "netbios-ssn", 143: "imap",
        161: "snmp", 162: "snmptrap", 179: "bgp", 194: "irc", 389: "ldap",
        443: "https", 445: "smb", 465: "smtps", 500: "isakmp", 514: "syslog",
        515: "printer", 520: "rip", 554: "rtsp", 587: "submission", 631: "ipp",
        636: "ldaps", 873: "rsync", 990: "ftps", 993: "imaps", 995: "pop3s",
        1080: "socks", 1194: "openvpn", 1433: "mssql", 1521: "oracle", 1701: "l2tp",
        1723: "pptp", 1812: "radius", 1813: "radius-acct", 2049: "nfs", 2082: "cpanel",
        2083: "cpanel-ssl", 2086: "whm", 2087: "whm-ssl", 2095: "webmail", 2096: "webmail-ssl",
        3128: "http-proxy", 3268: "global-catalog", 3269: "global-catalog-ssl", 3306: "mysql",
        3389: "rdp", 3690: "svn", 4040: "tomcat", 4444: "metasploit", 4848: "glassfish",
        5000: "upnp", 5060: "sip", 5222: "xmpp-client", 5269: "xmpp-server", 5432: "postgresql",
        5500: "vnc", 5666: "nrpe", 5800: "vnc-http", 5900: "vnc", 5985: "winrm",
        5986: "winrm-ssl", 6379: "redis", 6443: "kubernetes", 6660: "irc", 6667: "irc",
        6697: "irc-ssl", 7001: "weblogic", 7002: "weblogic-ssl", 7077: "activemq", 7199: "cassandra-jmx",
        7474: "neo4j", 7687: "neo4j-bolt", 8000: "http-alt", 8008: "http-alt", 8080: "http-proxy",
        8081: "http-proxy", 8088: "hadoop", 8089: "splunk", 8161: "activemq", 8443: "https-alt",
        8500: "coldfusion", 8761: "eureka", 8888: "jupyter", 9000: "sonarqube", 9042: "cassandra",
        9090: "prometheus", 9092: "kafka", 9200: "elasticsearch", 9300: "elasticsearch", 9418: "git",
        9999: "distcc", 10000: "webmin", 11211: "memcached", 15672: "rabbitmq", 27017: "mongodb",
        27018: "mongodb", 50000: "sap", 50070: "hadoop-nn", 50090: "hadoop-2nn", 61616: "activemq",
    }

    # 可疑端口（通常与恶意活动相关）
    SUSPICIOUS_PORTS = {
        4444: "Metasploit默认监听端口",
        5555: "常见后门端口",
        6666: "常见IRC/后门端口",
        7777: "常见后门端口",
        8888: "常见后门端口",
        9999: "常见后门端口",
        12345: "NetBus木马端口",
        12346: "NetBus木马端口",
        31337: "Elite/Back Orifice端口",
        54321: "常见后门端口",
        65535: "可疑高端口",
    }

    # IDS规则（简化版）
    IDS_RULES = {
        "port_scan": {
            "description": "端口扫描检测 - 单个源IP连接大量目标端口",
            "severity": "high",
            "threshold": 20,
            "window": 60,
        },
        "brute_force": {
            "description": "暴力破解检测 - 单个源IP对同一服务大量失败登录",
            "severity": "high",
            "threshold": 10,
            "window": 60,
        },
        "ddos": {
            "description": "DDoS检测 - 大量流量指向单个目标",
            "severity": "critical",
            "threshold": 1000,
            "window": 10,
        },
        "suspicious_connection": {
            "description": "可疑连接 - 连接到已知恶意端口",
            "severity": "medium",
        },
        "data_exfiltration": {
            "description": "数据外泄 - 大量出站数据到外部IP",
            "severity": "high",
            "threshold": 1000000,  # 1MB
        },
        "dns_tunneling": {
            "description": "DNS隧道 - 异常大的DNS查询或大量DNS流量",
            "severity": "high",
            "threshold": 512,  # 512字节
        },
    }

    def __init__(self):
        """初始化TrafficAnalyzer实例。

        Args:
            self: 类实例。
        """
        self.flows: Dict[str, NetworkFlow] = {}
        self.alerts: List[NetworkAlert] = []
        self.protocol_stats: Counter = Counter()
        self.ip_stats: Counter = Counter()
        self.port_stats: Counter = Counter()

    def parse_packet(self, packet_data: Dict[str, Any]) -> Optional[NetworkFlow]:
        """解析单个数据包"""
        try:
            src_ip = packet_data.get("src_ip", "")
            dst_ip = packet_data.get("dst_ip", "")
            src_port = packet_data.get("src_port", 0)
            dst_port = packet_data.get("dst_port", 0)
            protocol = packet_data.get("protocol", "tcp").lower()
            size = packet_data.get("size", 0)
            flags = packet_data.get("flags", [])

            if not src_ip or not dst_ip:
                return None

            # 创建流标识
            flow_key = f"{src_ip}:{src_port}-{dst_ip}:{dst_port}-{protocol}"

            if flow_key not in self.flows:
                self.flows[flow_key] = NetworkFlow(
                    src_ip=src_ip, src_port=src_port,
                    dst_ip=dst_ip, dst_port=dst_port,
                    protocol=protocol,
                )

            flow = self.flows[flow_key]
            flow.packets += 1
            flow.bytes += size
            if flags:
                flow.flags.extend(flags)

            # 更新统计
            self.protocol_stats[protocol] += 1
            self.ip_stats[src_ip] += 1
            self.ip_stats[dst_ip] += 1
            self.port_stats[dst_port] += 1

            # 检测可疑端口
            if dst_port in self.SUSPICIOUS_PORTS:
                self.alerts.append(NetworkAlert(
                    type="suspicious_port",
                    severity="medium",
                    description=f"连接到可疑端口 {dst_port}: {self.SUSPICIOUS_PORTS[dst_port]}",
                    src_ip=src_ip, dst_ip=dst_ip,
                    src_port=src_port, dst_port=dst_port,
                    protocol=protocol,
                    recommendation="调查该连接是否为恶意活动",
                ))

            return flow

        except Exception as e:
            log.debug(f"数据包解析错误: {e}")
            return None

    def detect_anomalies(self) -> List[NetworkAlert]:
        """检测异常流量"""
        anomalies = []

        # 检测端口扫描
        src_ports = defaultdict(set)
        for flow in self.flows.values():
            src_ports[flow.src_ip].add(flow.dst_port)

        for src_ip, ports in src_ports.items():
            if len(ports) >= self.IDS_RULES["port_scan"]["threshold"]:
                anomalies.append(NetworkAlert(
                    type="port_scan",
                    severity="high",
                    description=f"检测到端口扫描: {src_ip} 扫描了 {len(ports)} 个端口",
                    src_ip=src_ip,
                    evidence=f"扫描的端口: {sorted(list(ports))[:20]}...",
                    recommendation="阻止该IP并调查扫描来源",
                ))

        # 检测DDoS
        dst_traffic = defaultdict(int)
        for flow in self.flows.values():
            dst_traffic[flow.dst_ip] += flow.packets

        for dst_ip, packets in dst_traffic.items():
            if packets >= self.IDS_RULES["ddos"]["threshold"]:
                anomalies.append(NetworkAlert(
                    type="ddos",
                    severity="critical",
                    description=f"检测到DDoS攻击: {dst_ip} 收到 {packets} 个数据包",
                    dst_ip=dst_ip,
                    recommendation="启用DDoS防护，限制流量速率",
                ))

        # 检测数据外泄
        for flow in self.flows.values():
            if flow.bytes >= self.IDS_RULES["data_exfiltration"]["threshold"]:
                # 检查是否为出站流量（假设内网为10.x/172.16-31.x/192.168.x）
                if self._is_internal_ip(flow.src_ip) and not self._is_internal_ip(flow.dst_ip):
                    anomalies.append(NetworkAlert(
                        type="data_exfiltration",
                        severity="high",
                        description=f"检测到潜在数据外泄: {flow.src_ip} -> {flow.dst_ip} 传输 {flow.bytes} 字节",
                        src_ip=flow.src_ip, dst_ip=flow.dst_ip,
                        src_port=flow.src_port, dst_port=flow.dst_port,
                        protocol=flow.protocol,
                        recommendation="调查该流量是否为未授权数据传输",
                    ))

        self.alerts.extend(anomalies)
        return anomalies

    def _is_internal_ip(self, ip: str) -> bool:
        """检查是否为内网IP"""
        try:
            parts = list(map(int, ip.split('.')))
            if len(parts) != 4:
                return False
            if parts[0] == 10:
                return True
            if parts[0] == 172 and 16 <= parts[1] <= 31:
                return True
            if parts[0] == 192 and parts[1] == 168:
                return True
            if parts[0] == 127:
                return True
            return False
        except Exception:
            return False

    def generate_traffic_report(self) -> Dict[str, Any]:
        """生成流量分析报告"""
        # 检测异常
        self.detect_anomalies()

        # 统计
        total_packets = sum(f.packets for f in self.flows.values())
        total_bytes = sum(f.bytes for f in self.flows.values())
        unique_src_ips = len(set(f.src_ip for f in self.flows.values()))
        unique_dst_ips = len(set(f.dst_ip for f in self.flows.values()))

        # Top统计
        top_protocols = self.protocol_stats.most_common(10)
        top_src_ips = self.ip_stats.most_common(10)
        top_dst_ports = self.port_stats.most_common(10)

        # 告警统计
        alert_severity = Counter(a.severity for a in self.alerts)
        alert_types = Counter(a.type for a in self.alerts)

        # 风险评分
        severity_scores = {"critical": 10, "high": 7, "medium": 5, "low": 2, "info": 1}
        total_risk = sum(severity_scores.get(a.severity, 1) for a in self.alerts)
        max_risk = len(self.alerts) * 10 if self.alerts else 1
        risk_score = min(100, int((total_risk / max_risk) * 100)) if max_risk > 0 else 0

        if risk_score >= 70:
            risk_level = "critical"
        elif risk_score >= 50:
            risk_level = "high"
        elif risk_score >= 30:
            risk_level = "medium"
        else:
            risk_level = "low"

        return {
            "summary": {
                "total_flows": len(self.flows),
                "total_packets": total_packets,
                "total_bytes": total_bytes,
                "unique_src_ips": unique_src_ips,
                "unique_dst_ips": unique_dst_ips,
                "alerts_count": len(self.alerts),
            },
            "top_protocols": [{"protocol": p, "count": c} for p, c in top_protocols],
            "top_src_ips": [{"ip": ip, "count": c} for ip, c in top_src_ips],
            "top_dst_ports": [
                {"port": p, "service": self.COMMON_PORTS.get(p, "unknown"), "count": c}
                for p, c in top_dst_ports
            ],
            "alerts": [
                {
                    "type": a.type, "severity": a.severity, "description": a.description,
                    "src_ip": a.src_ip, "dst_ip": a.dst_ip,
                    "src_port": a.src_port, "dst_port": a.dst_port,
                    "protocol": a.protocol, "evidence": a.evidence,
                    "recommendation": a.recommendation,
                }
                for a in self.alerts
            ],
            "alert_summary": {
                "by_severity": dict(alert_severity),
                "by_type": dict(alert_types),
            },
            "risk_assessment": {
                "risk_score": risk_score,
                "risk_level": risk_level,
            },
            "recommendations": [
                "调查所有严重和高危告警",
                "实施网络分段和访问控制",
                "部署入侵检测/防御系统（IDS/IPS）",
                "启用网络流量监控和日志记录",
                "实施异常流量检测和告警",
                "定期审查网络安全策略",
                "对关键服务实施速率限制",
            ],
        }


# 全局流量分析器实例
traffic_analyzer = TrafficAnalyzer()
