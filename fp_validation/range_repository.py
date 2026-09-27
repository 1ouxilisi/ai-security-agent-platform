# -*- coding: utf-8 -*-
"""range_repository.py — 10 个真实靶场知识库（已知漏洞清单）。

每个靶场登记：ID、名称、URL、类型、难度、已知漏洞清单（漏洞类型+CVE/编号+
严重级别+检测特征）、负对照标记。扫描结果将与本清单比对以计算误报/漏报。
"""
from __future__ import annotations

from typing import Any, Dict, List


# 已知漏洞条目结构：{id, type, name, severity, evidence}
# evidence 用于和扫描输出做特征匹配，避免把版本指纹误判成漏洞。
KNOWN_RANGES: List[Dict[str, Any]] = [
    {
        "id": "dvwa",
        "name": "DVWA",
        "url": "http://127.0.0.1/dvwa/",
        "category": "web",
        "difficulty": "low",
        "is_negative_control": False,
        "known_vulns": [
            {"id": "dvwa-sqli", "type": "sql_injection", "name": "SQL Injection",
             "severity": "high", "evidence": ["id="]},
            {"id": "dvwa-xss-reflected", "type": "xss_reflected", "name": "Reflected XSS",
             "severity": "medium", "evidence": ["name=", "<script>"]},
            {"id": "dvwa-xss-stored", "type": "xss_stored", "name": "Stored XSS",
             "severity": "high", "evidence": ["guestbook"]},
            {"id": "dvwa-csrf", "type": "csrf", "name": "CSRF",
             "severity": "medium", "evidence": ["password_new="]},
            {"id": "dvwa-file-upload", "type": "file_upload", "name": "Unrestricted File Upload",
             "severity": "high", "evidence": ["upload.php"]},
            {"id": "dvwa-file-include", "type": "lfi", "name": "Local File Inclusion",
             "severity": "high", "evidence": ["page=include.php"]},
            {"id": "dvwa-brute", "type": "brute_force", "name": "Weak Credentials",
             "severity": "medium", "evidence": ["login.php"]},
            {"id": "dvwa-cmd", "type": "command_injection", "name": "Command Injection",
             "severity": "high", "evidence": ["ip=", ";", "&&"]},
        ],
    },
    {
        "id": "juice-shop",
        "name": "OWASP Juice Shop",
        "url": "http://127.0.0.1:3000/",
        "category": "web",
        "difficulty": "medium",
        "is_negative_control": False,
        "known_vulns": [
            {"id": "juice-sqli", "type": "sql_injection", "name": "SQL Injection (Login)",
             "severity": "high", "evidence": ["rest/user/login"]},
            {"id": "juice-xss", "type": "xss_stored", "name": "Stored XSS (Feedback)",
             "severity": "high", "evidence": ["rest/feedbacks"]},
            {"id": "juice-xxe", "type": "xxe", "name": "XXE (B2B Order)",
             "severity": "high", "evidence": ["b2b", "xml"]},
            {"id": "juice-ssrf", "type": "ssrf", "name": "SSRF (Change Basket)",
             "severity": "high", "evidence": ["redirectTo"]},
            {"id": "juice-dir-traversal", "type": "path_traversal", "name": "Path Traversal",
             "severity": "high", "evidence": ["ftp", "../../"]},
            {"id": "juice-jwt", "type": "jwt_none", "name": "JWT none algorithm",
             "severity": "high", "evidence": ["authorization", "jwt"]},
            {"id": "juice-weak-login", "type": "brute_force", "name": "Admin Weak Login",
             "severity": "medium", "evidence": ["admin@juice-sh.op"]},
            {"id": "juice-sensi-info", "type": "sensitive_info", "name": "Sensitive Info Exposure",
             "severity": "medium", "evidence": ["sitemap.xml", "*.map", ".git"]},
        ],
    },
    {
        "id": "webgoat",
        "name": "OWASP WebGoat",
        "url": "http://127.0.0.1:8080/WebGoat/",
        "category": "web",
        "difficulty": "medium",
        "is_negative_control": False,
        "known_vulns": [
            {"id": "webgoat-sqli", "type": "sql_injection", "name": "SQL Injection",
             "severity": "high", "evidence": ["SQLInjection"]},
            {"id": "webgoat-xss", "type": "xss_reflected", "name": "XSS",
             "severity": "medium", "evidence": ["XSS"]},
            {"id": "webgoat-csrf", "type": "csrf", "name": "CSRF",
             "severity": "medium", "evidence": ["csrf"]},
            {"id": "webgoat-insecure-deser", "type": "insecure_deserialization",
             "name": "Insecure Deserialization", "severity": "high",
             "evidence": ["Serialization"]},
            {"id": "webgoat-idor", "type": "idor", "name": "IDOR",
             "severity": "high", "evidence": ["access-control", "users/"]},
            {"id": "webgoat-missing-ac", "type": "broken_access_control",
             "name": "Missing Access Control", "severity": "high",
             "evidence": ["access-control"]},
        ],
    },
    {
        "id": "bwapp",
        "name": "bWAPP",
        "url": "http://127.0.0.1/bwapp/",
        "category": "web",
        "difficulty": "low",
        "is_negative_control": False,
        "known_vulns": [
            {"id": "bwapp-sqli", "type": "sql_injection", "name": "SQL Injection",
             "severity": "high", "evidence": ["sqli_", "id="]},
            {"id": "bwapp-xss", "type": "xss_reflected", "name": "XSS Reflected/Stored",
             "severity": "medium", "evidence": ["xss_", "search="]},
            {"id": "bwapp-lfi", "type": "lfi", "name": "Local File Inclusion",
             "severity": "high", "evidence": ["page="]},
            {"id": "bwapp-rfi", "type": "rfi", "name": "Remote File Inclusion",
             "severity": "high", "evidence": ["page=http"]},
            {"id": "bwapp-cmd", "type": "command_injection", "name": "OS Command Injection",
             "severity": "high", "evidence": ["ping", ";"]},
            {"id": "bwapp-upload", "type": "file_upload", "name": "File Upload Bypass",
             "severity": "high", "evidence": ["upload"]},
            {"id": "bwapp-webshell", "type": "webshell", "name": "Webshell Upload",
             "severity": "critical", "evidence": ["shell"]},
        ],
    },
    {
        "id": "mutillidae",
        "name": "Mutillidae II",
        "url": "http://127.0.0.1/mutillidae/",
        "category": "web",
        "difficulty": "low",
        "is_negative_control": False,
        "known_vulns": [
            {"id": "mut-sqli", "type": "sql_injection", "name": "SQL Injection",
             "severity": "high", "evidence": ["sqli", "login.php"]},
            {"id": "mut-xss", "type": "xss_reflected", "name": "XSS",
             "severity": "medium", "evidence": ["xss", "pen-test"]},
            {"id": "mut-lfi", "type": "lfi", "name": "LFI",
             "severity": "high", "evidence": ["page=", "etc/passwd"]},
            {"id": "mut-capture", "type": "cleartext_creds", "name": "Cleartext Credentials",
             "severity": "medium", "evidence": ["proxy-capture"]},
        ],
    },
    {
        "id": "pikachu",
        "name": "Pikachu",
        "url": "http://127.0.0.1/pikachu/",
        "category": "web",
        "difficulty": "low",
        "is_negative_control": False,
        "known_vulns": [
            {"id": "pikachu-sqli", "type": "sql_injection", "name": "SQL Injection (字符型/数字型)",
             "severity": "high", "evidence": ["sqli"]},
            {"id": "pikachu-xss", "type": "xss_stored", "name": "Stored/Reflected XSS",
             "severity": "medium", "evidence": ["xss"]},
            {"id": "pikachu-rce", "type": "command_injection", "name": "RCE",
             "severity": "high", "evidence": ["exec", "ping"]},
            {"id": "pikachu-upload", "type": "file_upload", "name": "Unrestricted Upload",
             "severity": "high", "evidence": ["upload"]},
            {"id": "pikachu-include", "type": "lfi", "name": "File Inclusion",
             "severity": "high", "evidence": ["include"]},
            {"id": "pikachu-brute", "type": "brute_force", "name": "Weak Password",
             "severity": "medium", "evidence": ["brute"]},
        ],
    },
    {
        "id": "vulhub",
        "name": "Vulhub (CVE 复现环境)",
        "url": "http://127.0.0.1:8081/",
        "category": "docker",
        "difficulty": "hard",
        "is_negative_control": False,
        "known_vulns": [
            {"id": "vulhub-log4j", "type": "rce", "name": "Log4j JNDI (CVE-2021-44228)",
             "severity": "critical", "evidence": ["jndi:ldap", "${"]},
            {"id": "vulhub-fastjson", "type": "rce", "name": "Fastjson Autotype RCE",
             "severity": "critical", "evidence": ["@type"]},
            {"id": "vulhub-shiro", "type": "rce", "name": "Shiro-550 Deserialization",
             "severity": "critical", "evidence": ["rememberMe", "deleteMe"]},
            {"id": "vulhub-struts2", "type": "rce", "name": "Struts2 OGNL (S2-045)",
             "severity": "critical", "evidence": ["Content-Type", "%{"]},
            {"id": "vulhub-redis", "type": "unauth_access", "name": "Redis Unauthorized",
             "severity": "high", "evidence": ["redis_version", "6379"]},
        ],
    },
    {
        "id": "metasploitable",
        "name": "Metasploitable2",
        "url": "http://192.168.56.103/",
        "category": "network",
        "difficulty": "medium",
        "is_negative_control": False,
        "known_vulns": [
            {"id": "msf-vsftpd", "type": "backdoor", "name": "vsftpd 2.3.4 Backdoor",
             "severity": "critical", "evidence": ["vsftpd", ":6200"]},
            {"id": "msf-samba", "type": "rce", "name": "Samba usermap RCE (CVE-2007-2442)",
             "severity": "critical", "evidence": ["samba", "139", "445"]},
            {"id": "msf-dvwa", "type": "sql_injection", "name": "DVWA on Metasploitable",
             "severity": "high", "evidence": ["dvwa"]},
            {"id": "msf-unauth-nfs", "type": "unauth_access", "name": "NFS Export No Root Squash",
             "severity": "high", "evidence": ["/home", "nfs"]},
            {"id": "msf-mysql", "type": "weak_credential", "name": "MySQL Empty Root",
             "severity": "high", "evidence": ["mysql", "3306"]},
            {"id": "msf-telnet", "type": "cleartext_service", "name": "Telnet Enabled",
             "severity": "medium", "evidence": ["telnet", "23"]},
        ],
    },
    {
        "id": "testphp",
        "name": "testphp.vulnweb.com (公开靶场)",
        "url": "http://testphp.vulnweb.com/",
        "category": "web",
        "difficulty": "easy",
        "is_negative_control": False,
        "known_vulns": [
            {"id": "testphp-sqli", "type": "sql_injection", "name": "SQL Injection (artists.php)",
             "severity": "high", "evidence": ["artists.php", "id="]},
            {"id": "testphp-xss", "type": "xss_reflected", "name": "Reflected XSS",
             "severity": "medium", "evidence": ["guestbook.php", "test%3C"]},
            {"id": "testphp-path", "type": "path_traversal", "name": "Path Traversal",
             "severity": "high", "evidence": ["file=", "../../"]},
            {"id": "testphp-dirlist", "type": "directory_listing", "name": "Directory Listing",
             "severity": "low", "evidence": ["index of /"]},
        ],
    },
    {
        "id": "google-negative",
        "name": "Google.com（负对照）",
        "url": "https://www.google.com/",
        "category": "negative",
        "difficulty": "n/a",
        "is_negative_control": True,
        "known_vulns": [],
    },
]


class RangeRepository:
    """靶场知识库：CRUD + 按 ID 查询 + 特征匹配。"""

    def __init__(self) -> None:
        self._ranges: Dict[str, Dict[str, Any]] = {
            r["id"]: dict(r) for r in KNOWN_RANGES
        }

    def list_ranges(self) -> List[Dict[str, Any]]:
        out = []
        for r in self._ranges.values():
            item = {k: v for k, v in r.items() if k != "known_vulns"}
            item["known_vuln_count"] = len(r.get("known_vulns", []))
            out.append(item)
        return out

    def get(self, range_id: str) -> Dict[str, Any] | None:
        return self._ranges.get(range_id)

    def get_known_vulns(self, range_id: str) -> List[Dict[str, Any]]:
        r = self._ranges.get(range_id)
        if not r:
            return []
        return list(r.get("known_vulns", []))

    def is_negative_control(self, range_id: str) -> bool:
        r = self._ranges.get(range_id)
        return bool(r and r.get("is_negative_control"))

    def all_ids(self) -> List[str]:
        return list(self._ranges.keys())

    def match_scan_to_known(self, range_id: str, findings: List[Dict[str, Any]]) -> Dict[str, Any]:
        """把扫描发现和已知漏洞清单做特征匹配。

        返回:
            {
              "true_positives": [...],   # 命中已知
              "false_positives": [...],  # 不在清单里的发现
              "false_negatives": [...],  # 已知但未被扫到
              "known_total": N,
              "detected_total": M,
            }
        """
        known = self.get_known_vulns(range_id)
        remaining_known = {k["id"]: k for k in known}
        tps: List[Dict[str, Any]] = []
        fps: List[Dict[str, Any]] = []

        for f in findings:
            f_type = (f.get("type") or "").lower()
            f_text = " ".join(
                str(x) for x in (
                    f.get("name"), f.get("detail"), f.get("evidence"),
                    f.get("url"), f.get("title"),
                ) if x
            ).lower()
            matched_id = None
            for k in known:
                if k["type"].lower() != f_type:
                    continue
                # 类型对上，再看证据关键词
                evs = [e.lower() for e in k.get("evidence", [])]
                if not evs or any(e in f_text for e in evs):
                    matched_id = k["id"]
                    break
            if matched_id and matched_id in remaining_known:
                tps.append({"known_id": matched_id, "finding": f})
                remaining_known.pop(matched_id, None)
            else:
                # 负对照上出现任何 finding 都算 FP
                if self.is_negative_control(range_id):
                    fps.append(f)
                else:
                    # 正靶场上类型对不上清单的也算 FP（保守口径）
                    fps.append(f)

        fns = list(remaining_known.values())
        return {
            "true_positives": tps,
            "false_positives": fps,
            "false_negatives": fns,
            "known_total": len(known),
            "detected_total": len(findings),
        }


_singleton: RangeRepository | None = None


def get_repository() -> RangeRepository:
    global _singleton
    if _singleton is None:
        _singleton = RangeRepository()
    return _singleton
