#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
本地规则引擎 - 基于HTTP响应数据的离线漏洞检测

规则类型:
regex_match / keyword_match / status_code /
response_header / response_time / content_length

response_data 格式:
{status_code:int, headers:dict, body:str, response_time:float, content_length:int}
"""
import re
from typing import Any, Dict, List, Optional


# ==================== 规则库（15条，覆盖10+种漏洞类型） ====================
_rules: Dict[str, Dict[str, Any]] = {
    "sql_error_detection": {
        "rule_id": "sql_error_detection",
        "name": "SQL错误信息检测",
        "description": "匹配MySQL/PostgreSQL/Oracle/MSSQL数据库错误信息",
        "rule_type": "regex_match",
        "pattern": r"(SQL syntax.*MySQL|Warning.*mysql_|MySQLDriver|PostgreSQL.*ERROR|"
                   r"Oracle.*ORA-\d{5}|ORA-\d{5}|Microsoft SQL Server.*Driver|unclosed quotation mark|"
                   r"quoted string is not properly terminated|SQLite.Exception)",
        "severity": "high",
        "category": "sql_injection",
        "enabled": True,
        "hit_count": 0,
        "false_positive_count": 0,
    },
    "xss_reflection": {
        "rule_id": "xss_reflection",
        "name": "XSS反射检测",
        "description": "检测响应中反射的<script>或事件处理器",
        "rule_type": "keyword_match",
        "pattern": "<script>|javascript:|onerror=|onload=|<img src=x",
        "severity": "high",
        "category": "xss",
        "enabled": True,
        "hit_count": 0,
        "false_positive_count": 0,
    },
    "command_injection": {
        "rule_id": "command_injection",
        "name": "命令执行检测",
        "description": "匹配命令执行结果特征（uid=、root@、Windows路径）",
        "rule_type": "keyword_match",
        "pattern": "uid=|gid=|groups=|root@|Linux version|Microsoft Windows [Version|C:\\Windows\\system32",
        "severity": "critical",
        "category": "command_injection",
        "enabled": True,
        "hit_count": 0,
        "false_positive_count": 0,
    },
    "path_traversal": {
        "rule_id": "path_traversal",
        "name": "路径穿越检测",
        "description": "匹配/etc/passwd或boot.ini等穿越目标内容",
        "rule_type": "keyword_match",
        "pattern": "root:.*:0:0:|/bin/bash|/bin/sh|boot.ini|\\[boot loader\\]",
        "severity": "high",
        "category": "path_traversal",
        "enabled": True,
        "hit_count": 0,
        "false_positive_count": 0,
    },
    "ssrf_indication": {
        "rule_id": "ssrf_indication",
        "name": "SSRF指示检测",
        "description": "检测响应中包含内部IP元数据地址",
        "rule_type": "keyword_match",
        "pattern": "169.254.169.254|10.0.2.100|192.168.|metadata.google|instance-data",
        "severity": "medium",
        "category": "ssrf",
        "enabled": True,
        "hit_count": 0,
        "false_positive_count": 0,
    },
    "sensitive_file_exposure": {
        "rule_id": "sensitive_file_exposure",
        "name": "敏感文件泄露检测",
        "description": "匹配.env/config.php/web.config/id_rsa等敏感文件内容",
        "rule_type": "regex_match",
        "pattern": r"(DB_PASSWORD|APP_KEY|AWS_SECRET|private key|-----BEGIN|web.config|<configuration>|<?php /etc/environment)",
        "severity": "high",
        "category": "sensitive_exposure",
        "enabled": True,
        "hit_count": 0,
        "false_positive_count": 0,
    },
    "directory_listing": {
        "rule_id": "directory_listing",
        "name": "目录列表检测",
        "description": "检测目录浏览特征",
        "rule_type": "keyword_match",
        "pattern": "Index of /|Parent Directory|<title>Index of",
        "severity": "low",
        "category": "info_disclosure",
        "enabled": True,
        "hit_count": 0,
        "false_positive_count": 0,
    },
    "server_info_leak": {
        "rule_id": "server_info_leak",
        "name": "服务器版本信息泄露",
        "description": "检测Server响应头中的具体版本号",
        "rule_type": "response_header",
        "pattern": r"Server:.*(Apache/|nginx/|Microsoft-IIS/)",
        "severity": "info",
        "category": "info_disclosure",
        "header_name": "server",
        "enabled": True,
        "hit_count": 0,
        "false_positive_count": 0,
    },
    "missing_security_header": {
        "rule_id": "missing_security_header",
        "name": "缺失安全响应头",
        "description": "检测缺失X-Frame-Options/X-Content-Type-Options/CSP",
        "rule_type": "response_header",
        "pattern": "missing",
        "severity": "low",
        "category": "misconfiguration",
        "required_headers": ["x-frame-options", "x-content-type-options", "content-security-policy"],
        "enabled": True,
        "hit_count": 0,
        "false_positive_count": 0,
    },
    "slow_response_dos": {
        "rule_id": "slow_response_dos",
        "name": "慢响应DoS指示",
        "description": "响应时间>10秒可能存在DoS或慢查询",
        "rule_type": "response_time",
        "pattern": "10",
        "severity": "medium",
        "category": "dos",
        "threshold_seconds": 10.0,
        "enabled": True,
        "hit_count": 0,
        "false_positive_count": 0,
    },
    "xxe_indication": {
        "rule_id": "xxe_indication",
        "name": "XXE指示检测",
        "description": "匹配XML外部实体解析错误",
        "rule_type": "keyword_match",
        "pattern": "XML Parsing Error|DOCTYPE|entity reference|xmlParseInternalSubset|javax.xml",
        "severity": "high",
        "category": "xxe",
        "enabled": True,
        "hit_count": 0,
        "false_positive_count": 0,
    },
    "insecure_deserialization": {
        "rule_id": "insecure_deserialization",
        "name": "不安全反序列化检测",
        "description": "匹配Java序列化/pickle反序列化错误",
        "rule_type": "keyword_match",
        "pattern": "java.io.InvalidClassException|ObjectInputStream|pickle.loads|__pyclassreduce|unpickling|Failed to deserialize",
        "severity": "critical",
        "category": "deserialization",
        "enabled": True,
        "hit_count": 0,
        "false_positive_count": 0,
    },
    "open_redirect": {
        "rule_id": "open_redirect",
        "name": "开放重定向检测",
        "description": "Location头跳转到外部域名",
        "rule_type": "response_header",
        "pattern": r"Location: https?://(?!.*(?:target|localhost)).+",
        "severity": "medium",
        "category": "open_redirect",
        "header_name": "location",
        "enabled": True,
        "hit_count": 0,
        "false_positive_count": 0,
    },
    "cve_in_banner": {
        "rule_id": "cve_in_banner",
        "name": "Banner已知CVE版本检测",
        "description": "匹配服务banner中的已知脆弱版本",
        "rule_type": "regex_match",
        "pattern": r"(OpenSSH[_-]?[0-7]\.|Apache/2\.2\.(8|1[0-3])|OpenSSL/0\.9\.[8-9]|OpenSSL/1\.0\.1[a-f])",
        "severity": "high",
        "category": "known_cve",
        "enabled": True,
        "hit_count": 0,
        "false_positive_count": 0,
    },
    "weak_crypto": {
        "rule_id": "weak_crypto",
        "name": "弱加密算法检测",
        "description": "匹配MD5/SHA1/DES/RC4等弱算法标识",
        "rule_type": "keyword_match",
        "pattern": "MD5|SHA1|DES-CBC|RC4|ECB mode|SSLv3|TLSv1.0",
        "severity": "medium",
        "category": "weak_crypto",
        "enabled": True,
        "hit_count": 0,
        "false_positive_count": 0,
    },
}


class RuleEngine:
    """本地规则引擎"""

    def __init__(self):
        self.rules = _rules

    def _normalize_headers(self, headers: Dict[str, str]) -> Dict[str, str]:
        try:
            return {str(k).lower(): str(v) for k, v in (headers or {}).items()}
        except Exception:
            return {}

    def _match_rule(self, rule: Dict[str, Any], data: Dict[str, Any]) -> bool:
        """判断单条规则是否命中"""
        try:
            rtype = rule.get("rule_type")
            body = str(data.get("body", "") or "")
            headers = self._normalize_headers(data.get("headers", {}))

            if rtype == "regex_match":
                pat = rule.get("pattern", "")
                return re.search(pat, body, re.IGNORECASE) is not None

            if rtype == "keyword_match":
                kws = [k.strip() for k in str(rule.get("pattern", "")).split("|") if k.strip()]
                body_lower = body.lower()
                return any(k.lower() in body_lower for k in kws)

            if rtype == "status_code":
                try:
                    return int(data.get("status_code", 0)) in [int(x) for x in str(rule.get("pattern", "")).split(",") if x.strip()]
                except Exception:
                    return False

            if rtype == "response_header":
                pat = rule.get("pattern", "")
                if pat == "missing":
                    required = rule.get("required_headers", [])
                    return any(h not in headers for h in required)
                hname = rule.get("header_name", "")
                val = headers.get(hname, "")
                if not val:
                    return False
                if pat.startswith("regex:") or ".*" in pat:
                    return re.search(pat, hname + ": " + val, re.IGNORECASE) is not None
                return pat.lower().split(":")[0] in val.lower()

            if rtype == "response_time":
                threshold = float(rule.get("threshold_seconds", rule.get("pattern", 10)))
                rt = float(data.get("response_time", 0) or 0)
                return rt >= threshold

            if rtype == "content_length":
                try:
                    return int(data.get("content_length", 0)) >= int(rule.get("pattern", 0))
                except Exception:
                    return False
            return False
        except Exception:
            return False

    def apply_rules(self, response_data: Dict[str, Any]) -> List[Dict[str, Any]]:
        """对HTTP响应数据应用所有启用规则，返回命中列表"""
        hits = []
        try:
            for rid, rule in self.rules.items():
                if not rule.get("enabled", True):
                    continue
                if self._match_rule(rule, response_data):
                    rule["hit_count"] = rule.get("hit_count", 0) + 1
                    hits.append({
                        "rule_id": rid,
                        "name": rule.get("name"),
                        "severity": rule.get("severity"),
                        "category": rule.get("category"),
                        "description": rule.get("description"),
                    })
        except Exception:
            pass
        return hits

    def apply_rule(self, rule_id: str, response_data: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        try:
            rule = self.rules.get(rule_id)
            if not rule:
                return None
            if not rule.get("enabled", True):
                return None
            if self._match_rule(rule, response_data):
                rule["hit_count"] = rule.get("hit_count", 0) + 1
                return {
                    "rule_id": rule_id, "name": rule.get("name"),
                    "severity": rule.get("severity"), "category": rule.get("category"),
                }
            return None
        except Exception:
            return None

    def list_rules(self) -> List[Dict[str, Any]]:
        try:
            return [dict(r) for r in self.rules.values()]
        except Exception:
            return []

    def update_rule(self, rule_id: str, updates: Dict[str, Any]) -> bool:
        try:
            rule = self.rules.get(rule_id)
            if not rule:
                return False
            for k in ("enabled", "severity", "pattern"):
                if k in updates:
                    rule[k] = updates[k]
            return True
        except Exception:
            return False

    def test_rule(self, rule_id: str, test_data: Dict[str, Any]) -> Dict[str, Any]:
        try:
            rule = self.rules.get(rule_id)
            if not rule:
                return {"hit": False, "error": "规则不存在"}
            hit = self._match_rule(rule, test_data)
            return {"hit": hit, "rule_id": rule_id, "name": rule.get("name")}
        except Exception as e:
            return {"hit": False, "error": str(e)}

    def get_stats(self) -> Dict[str, Any]:
        try:
            total_hits = sum(r.get("hit_count", 0) for r in self.rules.values())
            total_fp = sum(r.get("false_positive_count", 0) for r in self.rules.values())
            by_category: Dict[str, int] = {}
            for r in self.rules.values():
                cat = r.get("category", "other")
                by_category[cat] = by_category.get(cat, 0) + r.get("hit_count", 0)
            return {
                "total_rules": len(self.rules),
                "enabled_rules": sum(1 for r in self.rules.values() if r.get("enabled")),
                "total_hits": total_hits,
                "by_category": by_category,
                "false_positive_rate": round(total_fp / total_hits, 4) if total_hits else 0.0,
            }
        except Exception:
            return {"total_rules": 0}
