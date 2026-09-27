"""
Nuclei风格漏洞扫描模板引擎
- 内置常见漏洞模板（SQL注入/XSS/SSRF/路径遍历/命令执行等）
- HTTP请求匹配和响应检测
- 模板执行引擎
- 结果解析与报告
"""

import urllib.request
import urllib.error
import time
import re
import json
from typing import Dict, List, Any, Optional
from concurrent.futures import ThreadPoolExecutor, as_completed


class NucleiEngine:
    """Nuclei风格漏洞扫描引擎"""

    def __init__(self, target: str, timeout: int = 5, max_threads: int = 10):
        self.target = target if target.startswith("http") else f"http://{target}"
        self.timeout = timeout
        self.max_threads = max_threads
        self.results = []
        self.templates = self._load_builtin_templates()

    def _load_builtin_templates(self) -> List[Dict]:
        """加载内置漏洞模板"""
        templates = [
            # ========== SQL注入 ==========
            {
                "id": "sqli-error-based",
                "name": "SQL注入（错误型）",
                "severity": "high",
                "category": "SQL注入",
                "description": "通过单引号触发SQL错误，检测基于错误的SQL注入",
                "requests": [
                    {
                        "method": "GET",
                        "path": "/?id=1'",
                        "matchers": [
                            {"type": "word", "words": ["SQL syntax", "mysql_fetch", "ORA-", "PostgreSQL", "SQLite", "unclosed quotation"], "condition": "or"},
                            {"type": "status", "status": [500]}
                        ]
                    }
                ]
            },
            {
                "id": "sqli-union-based",
                "name": "SQL注入（联合查询型）",
                "severity": "high",
                "category": "SQL注入",
                "description": "通过ORDER BY和UNION SELECT检测联合查询注入",
                "requests": [
                    {
                        "method": "GET",
                        "path": "/?id=1 ORDER BY 10--",
                        "matchers": [{"type": "status", "status": [200, 500]}]
                    },
                    {
                        "method": "GET",
                        "path": "/?id=1 UNION SELECT 1,2,3--",
                        "matchers": [
                            {"type": "word", "words": ["1", "2", "3"], "condition": "and"},
                            {"type": "status", "status": [200]}
                        ]
                    }
                ]
            },
            # ========== XSS ==========
            {
                "id": "xss-reflected",
                "name": "反射型XSS",
                "severity": "medium",
                "category": "XSS",
                "description": "检测反射型跨站脚本攻击",
                "requests": [
                    {
                        "method": "GET",
                        "path": "/?q=<script>alert(1)</script>",
                        "matchers": [
                            {"type": "word", "words": ["<script>alert(1)</script>"], "condition": "or"}
                        ]
                    },
                    {
                        "method": "GET",
                        "path": "/?search=<img src=x onerror=alert(1)>",
                        "matchers": [
                            {"type": "word", "words": ["<img src=x onerror=alert(1)>"], "condition": "or"}
                        ]
                    }
                ]
            },
            {
                "id": "xss-dom",
                "name": "DOM型XSS",
                "severity": "medium",
                "category": "XSS",
                "description": "检测DOM型跨站脚本攻击（通过URL hash）",
                "requests": [
                    {
                        "method": "GET",
                        "path": "/#<script>alert(1)</script>",
                        "matchers": [
                            {"type": "word", "words": ["document.write", "innerHTML", "eval(", "document.location"], "condition": "or"}
                        ]
                    }
                ]
            },
            # ========== 路径遍历 ==========
            {
                "id": "path-traversal",
                "name": "路径遍历漏洞",
                "severity": "high",
                "category": "路径遍历",
                "description": "检测目录遍历/文件包含漏洞",
                "requests": [
                    {
                        "method": "GET",
                        "path": "/?file=../../../../etc/passwd",
                        "matchers": [
                            {"type": "word", "words": ["root:x:", "bin:x:", "daemon:"], "condition": "or"}
                        ]
                    },
                    {
                        "method": "GET",
                        "path": "/?page=../../../../etc/passwd",
                        "matchers": [
                            {"type": "word", "words": ["root:x:", "bin:x:"], "condition": "or"}
                        ]
                    },
                    {
                        "method": "GET",
                        "path": "/?file=..\\..\\..\\..\\windows\\win.ini",
                        "matchers": [
                            {"type": "word", "words": ["[fonts]", "[extensions]", "drivers"], "condition": "or"}
                        ]
                    }
                ]
            },
            # ========== 命令执行 ==========
            {
                "id": "command-injection",
                "name": "操作系统命令注入",
                "severity": "critical",
                "category": "命令执行",
                "description": "检测操作系统命令注入漏洞",
                "requests": [
                    {
                        "method": "GET",
                        "path": "/?ip=127.0.0.1;id",
                        "matchers": [
                            {"type": "word", "words": ["uid=", "gid=", "groups="], "condition": "or"}
                        ]
                    },
                    {
                        "method": "GET",
                        "path": "/?host=127.0.0.1|whoami",
                        "matchers": [
                            {"type": "word", "words": ["root", "admin", "www-data", "nobody"], "condition": "or"}
                        ]
                    },
                    {
                        "method": "GET",
                        "path": "/?cmd=echo%20VULNERABLE",
                        "matchers": [
                            {"type": "word", "words": ["VULNERABLE"], "condition": "or"}
                        ]
                    }
                ]
            },
            # ========== SSRF ==========
            {
                "id": "ssrf",
                "name": "服务端请求伪造（SSRF）",
                "severity": "high",
                "category": "SSRF",
                "description": "检测服务端请求伪造漏洞",
                "requests": [
                    {
                        "method": "GET",
                        "path": "/?url=http://127.0.0.1:22",
                        "matchers": [
                            {"type": "word", "words": ["SSH-", "OpenSSH"], "condition": "or"}
                        ]
                    },
                    {
                        "method": "GET",
                        "path": "/?url=http://169.254.169.254/latest/meta-data/",
                        "matchers": [
                            {"type": "word", "words": ["ami-id", "instance-id", "local-hostname"], "condition": "or"}
                        ]
                    }
                ]
            },
            # ========== XXE ==========
            {
                "id": "xxe",
                "name": "XML外部实体注入（XXE）",
                "severity": "high",
                "category": "XXE",
                "description": "检测XML外部实体注入漏洞",
                "requests": [
                    {
                        "method": "POST",
                        "path": "/",
                        "headers": {"Content-Type": "application/xml"},
                        "body": "<?xml version=\"1.0\"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM \"file:///etc/passwd\">]><foo>&xxe;</foo>",
                        "matchers": [
                            {"type": "word", "words": ["root:x:", "bin:x:"], "condition": "or"}
                        ]
                    }
                ]
            },
            # ========== 开放重定向 ==========
            {
                "id": "open-redirect",
                "name": "开放重定向",
                "severity": "low",
                "category": "重定向",
                "description": "检测开放重定向漏洞",
                "requests": [
                    {
                        "method": "GET",
                        "path": "/?redirect=https://evil.com",
                        "matchers": [
                            {"type": "header", "header": "Location", "value": "evil.com"}
                        ]
                    },
                    {
                        "method": "GET",
                        "path": "/?url=https://evil.com",
                        "matchers": [
                            {"type": "header", "header": "Location", "value": "evil.com"}
                        ]
                    }
                ]
            },
            # ========== 敏感文件泄露 ==========
            {
                "id": "sensitive-files",
                "name": "敏感文件泄露",
                "severity": "medium",
                "category": "信息泄露",
                "description": "检测常见敏感文件是否可直接访问",
                "requests": [
                    {"method": "GET", "path": "/.env", "matchers": [{"type": "word", "words": ["DB_PASSWORD", "API_KEY", "SECRET_KEY", "PASSWORD="], "condition": "or"}]},
                    {"method": "GET", "path": "/.git/config", "matchers": [{"type": "word", "words": ["[core]", "repositoryformatversion"], "condition": "or"}]},
                    {"method": "GET", "path": "/config.php", "matchers": [{"type": "word", "words": ["DB_PASSWORD", "mysql_connect", "database"], "condition": "or"}]},
                    {"method": "GET", "path": "/backup.sql", "matchers": [{"type": "word", "words": ["CREATE TABLE", "INSERT INTO", "DROP TABLE"], "condition": "or"}]},
                    {"method": "GET", "path": "/phpinfo.php", "matchers": [{"type": "word", "words": ["phpinfo()", "PHP Version", "php.ini"], "condition": "or"}]},
                    {"method": "GET", "path": "/web.config", "matchers": [{"type": "word", "words": ["<configuration>", "<system.web>", "connectionString"], "condition": "or"}]},
                    {"method": "GET", "path": "/.htaccess", "matchers": [{"type": "word", "words": ["RewriteEngine", "Options", "AuthType"], "condition": "or"}]},
                    {"method": "GET", "path": "/robots.txt", "matchers": [{"type": "word", "words": ["Disallow:", "User-agent:"], "condition": "or"}]}
                ]
            },
            # ========== 弱口令/默认凭证 ==========
            {
                "id": "default-credentials",
                "name": "默认凭证/弱口令",
                "severity": "high",
                "category": "认证",
                "description": "检测常见默认凭证和弱口令",
                "requests": [
                    {
                        "method": "POST",
                        "path": "/login",
                        "headers": {"Content-Type": "application/x-www-form-urlencoded"},
                        "body": "username=admin&password=admin",
                        "matchers": [
                            {"type": "status", "status": [302, 200]},
                            {"type": "word", "words": ["dashboard", "welcome", "admin panel"], "condition": "or"}
                        ]
                    },
                    {
                        "method": "POST",
                        "path": "/login",
                        "headers": {"Content-Type": "application/x-www-form-urlencoded"},
                        "body": "username=admin&password=password",
                        "matchers": [
                            {"type": "status", "status": [302, 200]}
                        ]
                    },
                    {
                        "method": "POST",
                        "path": "/login",
                        "headers": {"Content-Type": "application/x-www-form-urlencoded"},
                        "body": "username=root&password=root",
                        "matchers": [
                            {"type": "status", "status": [302, 200]}
                        ]
                    }
                ]
            },
            # ========== CORS配置错误 ==========
            {
                "id": "cors-misconfiguration",
                "name": "CORS配置错误",
                "severity": "medium",
                "category": "CORS",
                "description": "检测跨域资源共享配置错误",
                "requests": [
                    {
                        "method": "GET",
                        "path": "/",
                        "headers": {"Origin": "https://evil.com"},
                        "matchers": [
                            {"type": "header", "header": "Access-Control-Allow-Origin", "value": "evil.com"}
                        ]
                    },
                    {
                        "method": "GET",
                        "path": "/",
                        "headers": {"Origin": "https://evil.com"},
                        "matchers": [
                            {"type": "header", "header": "Access-Control-Allow-Credentials", "value": "true"}
                        ]
                    }
                ]
            },
            # ========== 点击劫持 ==========
            {
                "id": "clickjacking",
                "name": "点击劫持",
                "severity": "low",
                "category": "点击劫持",
                "description": "检测点击劫持漏洞（缺少X-Frame-Options和CSP frame-ancestors）",
                "requests": [
                    {
                        "method": "GET",
                        "path": "/",
                        "matchers": [
                            {"type": "no-header", "header": "X-Frame-Options"},
                            {"type": "no-header", "header": "Content-Security-Policy"}
                        ],
                        "condition": "and"
                    }
                ]
            },
            # ========== 缺失安全头 ==========
            {
                "id": "missing-security-headers",
                "name": "缺失安全响应头",
                "severity": "low",
                "category": "安全头",
                "description": "检测常见安全响应头是否缺失",
                "requests": [
                    {
                        "method": "GET",
                        "path": "/",
                        "matchers": [
                            {"type": "no-header", "header": "X-Content-Type-Options"},
                            {"type": "no-header", "header": "X-XSS-Protection"},
                            {"type": "no-header", "header": "Strict-Transport-Security"},
                            {"type": "no-header", "header": "Referrer-Policy"}
                        ]

                    }
                ]
            }
        ]

        # 加载扩展模板库
        try:
            from asm.extended_templates import EXTENDED_TEMPLATES
            templates.extend(EXTENDED_TEMPLATES)
        except Exception:
            pass

        # 加载大规模模板库（第三轮升级：219个新模板）
        try:
            from asm.massive_templates import MASSIVE_TEMPLATES
            templates.extend(MASSIVE_TEMPLATES)
        except Exception:
            pass

        return templates

    def scan_all(self) -> Dict[str, Any]:
        """执行全部模板扫描"""
        start_time = time.time()
        self.results = []

        def run_template(template):
            template_results = []
            for req in template.get("requests", []):
                try:
                    result = self._execute_request(req)
                    if result.get("vulnerable"):
                        template_results.append({
                            "template_id": template["id"],
                            "template_name": template["name"],
                            "severity": template["severity"],
                            "category": template["category"],
                            "description": template["description"],
                            "request": result["request"],
                            "evidence": result["evidence"],
                            "matched_matcher": result["matched_matcher"]
                        })
                except Exception as e:
                    pass
            return template_results

        with ThreadPoolExecutor(max_workers=self.max_threads) as executor:
            futures = [executor.submit(run_template, t) for t in self.templates]
            for future in as_completed(futures):
                try:
                    results = future.result()
                    self.results.extend(results)
                except Exception:
                    pass

        # 按严重程度排序
        severity_order = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
        self.results.sort(key=lambda x: severity_order.get(x["severity"], 5))

        return {
            "target": self.target,
            "total_templates": len(self.templates),
            "vulnerabilities_found": len(self.results),
            "scan_duration_seconds": round(time.time() - start_time, 2),
            "vulnerabilities": self.results,
            "summary": self._generate_summary()
        }

    def _execute_request(self, req: Dict) -> Dict[str, Any]:
        """执行单个HTTP请求并匹配"""
        method = req.get("method", "GET")
        path = req.get("path", "/")
        headers = req.get("headers", {})
        body = req.get("body", None)

        url = f"{self.target}{path}"
        request_headers = {"User-Agent": "Mozilla/5.0 (compatible; NucleiEngine/1.0)"}
        request_headers.update(headers)

        try:
            req_obj = urllib.request.Request(url, headers=request_headers, method=method)
            if body and method in ("POST", "PUT", "PATCH"):
                req_obj.data = body.encode() if isinstance(body, str) else body

            with urllib.request.urlopen(req_obj, timeout=self.timeout) as resp:
                status_code = resp.status
                resp_headers = {k.lower(): v for k, v in dict(resp.headers).items()}
                resp_body = resp.read().decode("utf-8", errors="ignore")[:10000]
        except urllib.error.HTTPError as e:
            status_code = e.code
            resp_headers = {k.lower(): v for k, v in dict(e.headers).items()} if e.headers else {}
            try:
                resp_body = e.read().decode("utf-8", errors="ignore")[:10000]
            except Exception:
                resp_body = ""
        except Exception as e:
            return {"vulnerable": False, "error": str(e)}

        # 匹配检测
        matchers = req.get("matchers", [])
        condition = req.get("condition", "or")
        matched = []
        vulnerable = False

        for matcher in matchers:
            matcher_type = matcher.get("type", "word")
            is_matched = False

            if matcher_type == "word":
                words = matcher.get("words", [])
                word_condition = matcher.get("condition", "or")
                if word_condition == "and":
                    is_matched = all(w in resp_body for w in words)
                else:
                    is_matched = any(w in resp_body for w in words)
                if is_matched:
                    matched.append(f"word匹配: {[w for w in words if w in resp_body]}")

            elif matcher_type == "status":
                statuses = matcher.get("status", [])
                is_matched = status_code in statuses
                if is_matched:
                    matched.append(f"状态码匹配: {status_code}")

            elif matcher_type == "header":
                header_name = matcher.get("header", "").lower()
                header_value = matcher.get("value", "")
                actual_value = resp_headers.get(header_name, "")
                is_matched = header_value in actual_value if actual_value else False
                if is_matched:
                    matched.append(f"响应头匹配: {header_name}={actual_value}")

            elif matcher_type == "no-header":
                header_name = matcher.get("header", "").lower()
                is_matched = header_name not in resp_headers
                if is_matched:
                    matched.append(f"缺失响应头: {header_name}")

            if condition == "and":
                if not is_matched:
                    vulnerable = False
                    break
                vulnerable = True
            else:
                if is_matched:
                    vulnerable = True
                    break

        return {
            "vulnerable": vulnerable,
            "request": {"method": method, "path": path, "url": url},
            "response": {"status": status_code, "length": len(resp_body)},
            "evidence": matched,
            "matched_matcher": matched[0] if matched else None
        }

    def _generate_summary(self) -> Dict[str, Any]:
        """生成扫描摘要"""
        severity_counts = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
        category_counts = {}

        for vuln in self.results:
            sev = vuln.get("severity", "info")
            severity_counts[sev] = severity_counts.get(sev, 0) + 1
            cat = vuln.get("category", "其他")
            category_counts[cat] = category_counts.get(cat, 0) + 1

        risk_score = (
            severity_counts["critical"] * 10 +
            severity_counts["high"] * 7 +
            severity_counts["medium"] * 4 +
            severity_counts["low"] * 1
        )

        if risk_score >= 30:
            overall_risk = "critical"
        elif risk_score >= 15:
            overall_risk = "high"
        elif risk_score >= 5:
            overall_risk = "medium"
        else:
            overall_risk = "low"

        return {
            "severity_distribution": severity_counts,
            "category_distribution": category_counts,
            "risk_score": min(risk_score, 100),
            "overall_risk": overall_risk
        }

    def list_templates(self) -> List[Dict]:
        """列出所有可用模板"""
        return [
            {
                "id": t["id"],
                "name": t["name"],
                "severity": t["severity"],
                "category": t["category"],
                "description": t["description"],
                "request_count": len(t.get("requests", []))
            }
            for t in self.templates
        ]
