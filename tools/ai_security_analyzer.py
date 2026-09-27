"""
ai_security_analyzer安全工具集成模块，提供相关安全工具的封装和调用。

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
import hashlib
from typing import Dict, Any, List, Optional, Tuple
from dataclasses import dataclass, field
from utils.logger import log


@dataclass
class CodeVulnerability:
    """代码漏洞"""
    type: str
    severity: str
    line: int
    column: int
    snippet: str
    description: str
    cwe: str
    recommendation: str
    confidence: float = 0.0


@dataclass
class MalwareIndicator:
    """恶意代码指标"""
    type: str
    severity: str
    description: str
    pattern: str
    line: int = 0
    confidence: float = 0.0


@dataclass
class ThreatIntel:
    """威胁情报"""
    ioc_type: str
    ioc_value: str
    threat_type: str
    severity: str
    description: str
    source: str
    first_seen: str = ""
    last_seen: str = ""
    references: List[str] = field(default_factory=list)


class AISecurityAnalyzer:
    """AI安全分析器"""

    # 代码漏洞模式（简化版规则引擎）
    CODE_VULNERABILITY_PATTERNS = {
        "sql_injection": {
            "patterns": [
                r'exec\s*\(\s*["\'].*%s.*["\']\s*%',
                r'cursor\.execute\s*\(\s*f["\']',
                r'query\s*=\s*["\'].*\$\{.*\}.*["\']',
                r'SELECT.*FROM.*\+\s*\w+',
                r'format\s*\(.*SELECT.*FROM',
            ],
            "severity": "critical",
            "cwe": "CWE-89",
            "description": "SQL注入漏洞 - 用户输入直接拼接到SQL查询中",
            "recommendation": "使用参数化查询或预编译语句，避免字符串拼接",
        },
        "xss": {
            "patterns": [
                r'document\.write\s*\(\s*[^)]*request',
                r'innerHTML\s*=\s*[^;]*request',
                r'response\.write\s*\(\s*[^)]*request',
                r'echo\s+\$_(GET|POST|REQUEST)',
                r'print\s*\(.*request\.(args|form|values)',
            ],
            "severity": "high",
            "cwe": "CWE-79",
            "description": "跨站脚本漏洞 - 用户输入未经过滤直接输出到HTML",
            "recommendation": "对输出进行HTML编码，使用CSP策略，使用模板引擎的自动转义",
        },
        "command_injection": {
            "patterns": [
                r'os\.system\s*\(\s*[^)]*request',
                r'subprocess\.(call|run|Popen)\s*\(\s*[^)]*request',
                r'exec\s*\(\s*[^)]*request',
                r'eval\s*\(\s*[^)]*request',
                r'`[^`]*\$\{?request',
                r'shell=True.*request',
            ],
            "severity": "critical",
            "cwe": "CWE-78",
            "description": "命令注入漏洞 - 用户输入直接传递给系统命令",
            "recommendation": "避免使用shell=True，使用参数列表，验证和过滤用户输入",
        },
        "path_traversal": {
            "patterns": [
                r'open\s*\(\s*[^)]*request',
                r'file_get_contents\s*\(\s*\$_(GET|POST)',
                r'readFile\s*\(\s*[^)]*request',
                r'send_file\s*\(\s*[^)]*request',
            ],
            "severity": "high",
            "cwe": "CWE-22",
            "description": "路径遍历漏洞 - 用户输入直接用于文件路径",
            "recommendation": "使用白名单验证文件名，规范化路径，限制在指定目录内",
        },
        "insecure_deserialization": {
            "patterns": [
                r'pickle\.loads?\s*\(\s*[^)]*request',
                r'yaml\.load\s*\(\s*[^)]*request',
                r'marshal\.loads?\s*\(\s*[^)]*request',
                r'java\.io\.ObjectInputStream',
                r'JSON\.parse\s*\(\s*[^)]*request',
            ],
            "severity": "critical",
            "cwe": "CWE-502",
            "description": "不安全的反序列化 - 不可信数据直接反序列化",
            "recommendation": "使用安全的序列化格式，验证反序列化数据，使用沙箱环境",
        },
        "hardcoded_credentials": {
            "patterns": [
                r'password\s*=\s*["\'][^"\']+["\']',
                r'secret\s*=\s*["\'][^"\']+["\']',
                r'api_key\s*=\s*["\'][^"\']+["\']',
                r'private_key\s*=\s*["\'][^"\']+["\']',
                r'token\s*=\s*["\'][^"\']+["\']',
                r'AKIA[0-9A-Z]{16}',
                r'sk-[a-zA-Z0-9]{32,}',
            ],
            "severity": "high",
            "cwe": "CWE-798",
            "description": "硬编码凭证 - 密码/密钥/Token直接写在代码中",
            "recommendation": "使用环境变量或密钥管理服务，不要在代码中硬编码凭证",
        },
        "weak_crypto": {
            "patterns": [
                r'MD5|SHA1|DES|RC4|3DES',
                r'random\.(random|randint|choice)\s*\(',
                r'math\.random\s*\(\s*\)',
                r'cipher\s*=\s*["\']AES-ECB["\']',
                r'createCipher\s*\(\s*["\']aes-128-ecb["\']',
            ],
            "severity": "medium",
            "cwe": "CWE-327",
            "description": "弱加密算法 - 使用已知不安全的加密算法或随机数生成器",
            "recommendation": "使用AES-256-GCM、SHA-256、bcrypt/argon2，使用secrets模块",
        },
        "ssrf": {
            "patterns": [
                r'requests\.(get|post|put|delete)\s*\(\s*[^)]*request',
                r'urllib\.request\.urlopen\s*\(\s*[^)]*request',
                r'fetch\s*\(\s*[^)]*request',
                r'axios\.(get|post)\s*\(\s*[^)]*request',
            ],
            "severity": "high",
            "cwe": "CWE-918",
            "description": "服务器端请求伪造 - 用户输入控制请求目标",
            "recommendation": "验证目标URL，禁止访问内网地址，使用白名单",
        },
    }

    # 恶意代码指标模式
    MALWARE_PATTERNS = {
        "reverse_shell": {
            "patterns": [
                r'socket\.socket.*connect.*\(.*\).*subprocess',
                r'Runtime\.getRuntime\(\)\.exec\s*\(\s*["\']/bin/sh["\']',
                r'ProcessBuilder\s*\(\s*["\']/bin/sh["\']',
                r'powershell.*-c.*IEX',
                r'cmd\.exe.*\/c.*powershell',
            ],
            "severity": "critical",
            "description": "反向Shell - 建立到攻击者的反向连接",
        },
        "credential_theft": {
            "patterns": [
                r'laZagne|mimikatz|sekurlsa',
                r'Get-.*Password|Dump.*Credential',
                r'\/etc\/shadow|\/etc\/passwd',
                r'Windows\\\\System32\\\\config\\\\SAM',
                r'lsass\.exe',
            ],
            "severity": "critical",
            "description": "凭证窃取 - 尝试提取系统或应用凭证",
        },
        "persistence": {
            "patterns": [
                r'reg.*add.*HKLM\\\\Software\\\\Microsoft\\\\Windows\\\\CurrentVersion\\\\Run',
                r'New-ItemProperty.*Run',
                r'crontab.*-e|@reboot',
                r'systemctl.*enable',
                r'WMI.*EventFilter',
            ],
            "severity": "high",
            "description": "持久化机制 - 在系统中建立持久化访问",
        },
        "evasion": {
            "patterns": [
                r'VirtualAlloc.*PAGE_EXECUTE_READWRITE',
                r'CreateRemoteThread',
                r'process.*inject|dll.*inject',
                r'Obfuscator|encode.*base64.*decode',
                r'anti.*debug|IsDebuggerPresent',
                r'NtQueryInformationProcess',
            ],
            "severity": "high",
            "description": "规避技术 - 尝试规避检测或调试",
        },
        "data_exfiltration": {
            "patterns": [
                r'curl.*--upload-file',
                r'scp.*@.*:',
                r'ftp.*put',
                r'Invoke-WebRequest.*-OutFile',
                r'base64.*\|\s*curl',
            ],
            "severity": "high",
            "description": "数据外泄 - 尝试将数据发送到外部服务器",
        },
        "ransomware": {
            "patterns": [
                r'encrypt.*file|crypt.*file',
                r'\.encrypted$|\.locked$|\.ransom$',
                r'Bitcoin|bitcoin|BTC',
                r'readme.*decrypt|README.*DECRYPT',
                r'AES.*encrypt.*RSA',
            ],
            "severity": "critical",
            "description": "勒索软件特征 - 加密文件并索要赎金",
        },
    }

    # 常见IOC类型
    IOC_TYPES = ["ip", "domain", "url", "hash_md5", "hash_sha1", "hash_sha256", "email", "mutex"]

    def analyze_code(self, code: str, language: str = "python") -> Dict[str, Any]:
        """代码漏洞分析"""
        vulnerabilities = []
        lines = code.split("\n")

        for vuln_type, vuln_info in self.CODE_VULNERABILITY_PATTERNS.items():
            for pattern in vuln_info["patterns"]:
                for i, line in enumerate(lines, 1):
                    try:
                        if re.search(pattern, line, re.IGNORECASE):
                            # 计算置信度
                            confidence = min(0.95, 0.5 + 0.1 * len(re.findall(pattern, line, re.IGNORECASE)))

                            vulnerabilities.append(CodeVulnerability(
                                type=vuln_type,
                                severity=vuln_info["severity"],
                                line=i,
                                column=line.find(line.strip()),
                                snippet=line.strip()[:200],
                                description=vuln_info["description"],
                                cwe=vuln_info["cwe"],
                                recommendation=vuln_info["recommendation"],
                                confidence=confidence,
                            ))
                    except re.error:
                        continue

        # 去重（同一行同一类型只保留一个）
        seen = set()
        unique_vulns = []
        for v in vulnerabilities:
            key = (v.type, v.line)
            if key not in seen:
                seen.add(key)
                unique_vulns.append(v)

        # 风险评分
        severity_scores = {"critical": 10, "high": 7, "medium": 5, "low": 2, "info": 1}
        total_risk = sum(severity_scores.get(v.severity, 1) for v in unique_vulns)
        max_risk = len(unique_vulns) * 10 if unique_vulns else 1
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
            "language": language,
            "lines_of_code": len(lines),
            "vulnerabilities_found": len(unique_vulns),
            "vulnerability_summary": {
                "critical": sum(1 for v in unique_vulns if v.severity == "critical"),
                "high": sum(1 for v in unique_vulns if v.severity == "high"),
                "medium": sum(1 for v in unique_vulns if v.severity == "medium"),
                "low": sum(1 for v in unique_vulns if v.severity == "low"),
            },
            "vulnerabilities": [
                {
                    "type": v.type, "severity": v.severity, "line": v.line,
                    "snippet": v.snippet, "description": v.description,
                    "cwe": v.cwe, "recommendation": v.recommendation,
                    "confidence": v.confidence,
                }
                for v in unique_vulns
            ],
            "risk_assessment": {
                "risk_score": risk_score,
                "risk_level": risk_level,
            },
            "recommendations": [
                "修复所有严重和高危漏洞",
                "实施安全编码规范培训",
                "使用静态代码分析工具（SAST）",
                "实施代码审查流程",
                "使用依赖检查工具检测已知漏洞",
            ],
        }

    def detect_malware(self, code: str) -> Dict[str, Any]:
        """恶意代码检测"""
        indicators = []
        lines = code.split("\n")

        for indicator_type, indicator_info in self.MALWARE_PATTERNS.items():
            for pattern in indicator_info["patterns"]:
                for i, line in enumerate(lines, 1):
                    try:
                        if re.search(pattern, line, re.IGNORECASE):
                            confidence = min(0.95, 0.6 + 0.1 * len(re.findall(pattern, line, re.IGNORECASE)))
                            indicators.append(MalwareIndicator(
                                type=indicator_type,
                                severity=indicator_info["severity"],
                                description=indicator_info["description"],
                                pattern=pattern,
                                line=i,
                                confidence=confidence,
                            ))
                    except re.error:
                        continue

        # 去重
        seen = set()
        unique_indicators = []
        for ind in indicators:
            key = (ind.type, ind.line)
            if key not in seen:
                seen.add(key)
                unique_indicators.append(ind)

        # 威胁评分
        severity_scores = {"critical": 10, "high": 7, "medium": 5, "low": 2}
        total_score = sum(severity_scores.get(i.severity, 1) for i in unique_indicators)
        max_score = len(unique_indicators) * 10 if unique_indicators else 1
        threat_score = min(100, int((total_score / max_score) * 100)) if max_score > 0 else 0

        if threat_score >= 70:
            threat_level = "critical"
        elif threat_score >= 50:
            threat_level = "high"
        elif threat_score >= 30:
            threat_level = "medium"
        else:
            threat_level = "low"

        return {
            "indicators_found": len(unique_indicators),
            "indicator_summary": {
                "critical": sum(1 for i in unique_indicators if i.severity == "critical"),
                "high": sum(1 for i in unique_indicators if i.severity == "high"),
                "medium": sum(1 for i in unique_indicators if i.severity == "medium"),
            },
            "indicators": [
                {
                    "type": i.type, "severity": i.severity, "line": i.line,
                    "description": i.description, "confidence": i.confidence,
                }
                for i in unique_indicators
            ],
            "threat_assessment": {
                "threat_score": threat_score,
                "threat_level": threat_level,
                "is_malware": threat_score >= 50,
            },
            "recommendations": [
                "在隔离环境中分析可疑代码",
                "使用多引擎杀毒软件扫描",
                "检查网络连接和文件操作",
                "监控系统行为和资源使用",
                "如有必要，进行逆向工程分析",
            ],
        }

    def extract_iocs(self, text: str) -> Dict[str, Any]:
        """提取IOC（入侵指标）"""
        iocs = {ioc_type: [] for ioc_type in self.IOC_TYPES}

        # IP地址
        ip_pattern = r'\b(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\b'
        iocs["ip"] = list(set(re.findall(ip_pattern, text)))

        # 域名
        domain_pattern = r'\b(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}\b'
        iocs["domain"] = list(set(re.findall(domain_pattern, text)))

        # URL
        url_pattern = r'https?://[^\s<>"\']+'
        iocs["url"] = list(set(re.findall(url_pattern, text)))

        # MD5
        md5_pattern = r'\b[a-fA-F0-9]{32}\b'
        iocs["hash_md5"] = list(set(re.findall(md5_pattern, text)))

        # SHA1
        sha1_pattern = r'\b[a-fA-F0-9]{40}\b'
        iocs["hash_sha1"] = list(set(re.findall(sha1_pattern, text)))

        # SHA256
        sha256_pattern = r'\b[a-fA-F0-9]{64}\b'
        iocs["hash_sha256"] = list(set(re.findall(sha256_pattern, text)))

        # Email
        email_pattern = r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b'
        iocs["email"] = list(set(re.findall(email_pattern, text)))

        # 过滤掉误报
        iocs["ip"] = [ip for ip in iocs["ip"] if not ip.startswith("0.") and ip != "0.0.0.0"]
        iocs["domain"] = [d for d in iocs["domain"] if "." in d and not d.endswith(".txt") and not d.endswith(".py")]

        total_iocs = sum(len(v) for v in iocs.values())

        return {
            "total_iocs": total_iocs,
            "iocs_by_type": {k: len(v) for k, v in iocs.items()},
            "iocs": iocs,
        }

    def calculate_file_hash(self, content: bytes, algorithm: str = "sha256") -> str:
        """计算文件哈希"""
        if algorithm == "md5":
            return hashlib.md5(content).hexdigest()
        elif algorithm == "sha1":
            return hashlib.sha1(content).hexdigest()
        elif algorithm == "sha256":
            return hashlib.sha256(content).hexdigest()
        else:
            return hashlib.sha256(content).hexdigest()


# 全局AI安全分析器实例
ai_security_analyzer = AISecurityAnalyzer()
