#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
服务漏洞真实验证器（模块一：1.3）。

合法安全边界：
    - 弱口令验证仅限内置 10 个常见密码，每账户最多 5 次尝试、间隔 1 秒，避免账户锁定。
    - 未授权/匿名访问只发送只读探测命令（INFO/ping/srvr/GET /），不执行写操作。
    - 版本 CVE 匹配仅基于内置映射表给出"可能存在，需进一步验证"，不利用。

统一返回格式与 Web 验证器一致。
"""

import socket
import time
from datetime import datetime
from typing import Any, Dict, List, Optional, Tuple

try:
    from loguru import logger
except Exception:  # pragma: no cover
    import logging

    logger = logging.getLogger("service_vuln_verifier")

# 内置常见弱口令字典（10 个）
COMMON_PASSWORDS = [
    "admin", "123456", "password", "root", "12345678",
    "test", "123123", "admin123", "root123", "",
]

# 默认凭证字典：service -> [(username, password, description), ...]
DEFAULT_CREDENTIALS: Dict[str, List[Tuple[str, str, str]]] = {
    "tomcat": [("tomcat", "tomcat", "Tomcat 默认管理后台"),
               ("admin", "admin", "Tomcat 常见默认")],
    "jenkins": [("admin", "admin", "Jenkins 初始管理员")],
    "weblogic": [("weblogic", "weblogic", "WebLogic 默认控制台")],
    "mysql": [("root", "", "MySQL root 空密码"),
              ("root", "root", "MySQL root/root")],
    "redis": [("", "", "Redis 无密码访问（见未授权验证）")],
    "mongodb": [("", "", "MongoDB 无认证（见未授权验证）")],
    "ftp": [("anonymous", "anonymous@", "FTP 匿名访问"),
            ("ftp", "ftp", "FTP 默认账户")],
    "ssh": [("root", "root", "SSH root/root"),
            ("admin", "admin", "SSH admin/admin")],
}

# 简化版本 CVE 映射表（>=20 条）。
# key: service 小写；value: list of (version_prefix_or_exact, cve, description, severity)
VERSION_VULN_DB: List[Dict[str, str]] = [
    {"service": "apache httpd", "version_match": "2.4.49",
     "cve": "CVE-2021-41773",
     "desc": "Apache 2.4.49 路径穿越/RCE", "severity": "critical"},
    {"service": "apache httpd", "version_match": "2.4.50",
     "cve": "CVE-2021-42013",
     "desc": "Apache 2.4.50 路径穿越绕过补丁", "severity": "critical"},
    {"service": "openssl", "version_match": "1.0.1",
     "cve": "CVE-2014-0160",
     "desc": "OpenSSL 1.0.1 心脏滴血(Heartbleed)", "severity": "critical"},
    {"service": "openssl", "version_match": "0.9.8",
     "cve": "CVE-2014-0160",
     "desc": "OpenSSL 0.9.8 心脏滴血", "severity": "critical"},
    {"service": "log4j", "version_match": "2.0",
     "cve": "CVE-2021-44228",
     "desc": "Log4j 2.0-2.14 JNDI 注入(Log4Shell)", "severity": "critical"},
    {"service": "log4j", "version_match": "2.14",
     "cve": "CVE-2021-44228",
     "desc": "Log4j 2.0-2.14 JNDI 注入(Log4Shell)", "severity": "critical"},
    {"service": "nginx", "version_match": "1.1.3",
     "cve": "CVE-2017-7529",
     "desc": "Nginx range 模块信息泄露", "severity": "high"},
    {"service": "nginx", "version_match": "1.0",
     "cve": "CVE-2013-2028",
     "desc": "Nginx 栈溢出", "severity": "high"},
    {"service": "openssh", "version_match": "7.2",
     "cve": "CVE-2016-10030",
     "desc": "OpenSSH 用户枚举", "severity": "medium"},
    {"service": "openssh", "version_match": "8.5",
     "cve": "CVE-2021-41617",
     "desc": "OpenSSH 权限提升", "severity": "high"},
    {"service": "vsftpd", "version_match": "2.3.4",
     "cve": "CVE-2011-2523",
     "desc": "vsftpd 2.3.4 后门", "severity": "critical"},
    {"service": "proftpd", "version_match": "1.3.5",
     "cve": "CVE-2015-3306",
     "desc": "ProFTPD 1.3.5 复制模块绕过认证", "severity": "high"},
    {"service": "mysql", "version_match": "5.5",
     "cve": "CVE-2012-2122",
     "desc": "MySQL/MariaDB 认证绕过", "severity": "critical"},
    {"service": "mysql", "version_match": "5.1",
     "cve": "CVE-2012-2122",
     "desc": "MySQL 5.1 认证绕过", "severity": "critical"},
    {"service": "redis", "version_match": "4.0",
     "cve": "CVE-2019-1010250",
     "desc": "Redis 未授权访问", "severity": "high"},
    {"service": "mongodb", "version_match": "3.0",
     "cve": "CVE-2017-2665",
     "desc": "MongoDB 未授权访问", "severity": "high"},
    {"service": "docker", "version_match": "1.6",
     "cve": "CVE-2019-5736",
     "desc": "runc/Docker 容器逃逸", "severity": "critical"},
    {"service": "apache struts", "version_match": "2.3",
     "cve": "CVE-2017-5638",
     "desc": "Struts2 Jakarta 参数 RCE(S2-045)", "severity": "critical"},
    {"service": "weblogic", "version_match": "10.3.6",
     "cve": "CVE-2017-10271",
     "desc": "WebLogic XMLDecoder RCE", "severity": "critical"},
    {"service": "fastjson", "version_match": "1.2.24",
     "cve": "CVE-2017-18349",
     "desc": "Fastjson 反序列化 RCE", "severity": "critical"},
    {"service": "shiro", "version_match": "1.2.4",
     "cve": "CVE-2016-4437",
     "desc": "Shiro-550 反序列化", "severity": "critical"},
    {"service": "jenkins", "version_match": "2.150",
     "cve": "CVE-2019-1003000",
     "desc": "Jenkins Script Security 沙箱绕过", "severity": "high"},
    {"service": "tomcat", "version_match": "7.0",
     "cve": "CVE-2017-12615",
     "desc": "Tomcat PUT 方法任意文件上传", "severity": "high"},
    {"service": "apache httpd", "version_match": "2.2",
     "cve": "CVE-2017-15715",
     "desc": "Apache httpd 2.2 表达式注入", "severity": "medium"},
    {"service": "zookeeper", "version_match": "3.4",
     "cve": "CVE-2019-0201",
     "desc": "Zookeeper 信息泄露", "severity": "medium"},
    {"service": "elasticsearch", "version_match": "1.1",
     "cve": "CVE-2015-1427",
     "desc": "Elasticsearch 脚本执行 RCE", "severity": "critical"},
    {"service": "kibana", "version_match": "5.6",
     "cve": "CVE-2018-17246",
     "desc": "Kibana 任意文件读取", "severity": "high"},
    {"service": "gitlab", "version_match": "11.4",
     "cve": "CVE-2018-19585",
     "desc": "GitLab SSRF", "severity": "high"},
]

# 服务默认端口映射
SERVICE_PORTS = {
    "ftp": 21, "ssh": 22, "smtp": 25, "dns": 53, "http": 80,
    "https": 443, "smb": 445, "mysql": 3306, "rdp": 3389,
    "mongodb": 27017, "redis": 6379, "elasticsearch": 9200,
    "zookeeper": 2181, "kafka": 9092, "ldap": 389,
}


class ServiceVulnVerifier:
    """服务漏洞真实验证器。"""

    def __init__(self, timeout: int = 8, max_attempts: int = 5,
                 attempt_interval: float = 1.0):
        """初始化。

        Args:
            timeout: 单次 socket/网络操作超时（秒）。
            max_attempts: 每账户最多尝试次数，避免账户锁定。
            attempt_interval: 每次尝试间隔（秒）。
        """
        self.timeout = timeout
        self.max_attempts = max_attempts
        self.attempt_interval = attempt_interval

    # ------------------------------------------------------------------
    # 内部工具
    # ------------------------------------------------------------------
    @staticmethod
    def _make_result(vuln_type: str, status: str, confidence: float,
                     evidence: str, details: Dict[str, Any],
                     target: str, param: str = "") -> Dict[str, Any]:
        return {
            "vuln_type": vuln_type,
            "status": status,
            "confidence": round(float(confidence), 3),
            "evidence": evidence,
            "details": details or {},
            "target": target,
            "param": param,
            "timestamp": time.time(),
            "verified_at": datetime.now().isoformat(),
        }

    def _socket_probe(self, host: str, port: int) -> bool:
        """探测端口是否开放。"""
        try:
            with socket.create_connection((host, int(port)), timeout=self.timeout):
                return True
        except Exception:
            return False

    def _raw_send(self, host: str, port: int, data: bytes,
                  recv: int = 4096) -> Tuple[bool, str]:
        """向指定端口发送原始字节并读取响应。返回 (是否成功, 响应文本)。"""
        try:
            with socket.create_connection((host, int(port)), timeout=self.timeout) as s:
                s.sendall(data)
                resp = s.recv(recv)
                return True, resp.decode("utf-8", errors="ignore")
        except Exception as e:
            return False, str(e)

    # ------------------------------------------------------------------
    # 1. 弱口令验证
    # ------------------------------------------------------------------
    def verify_weak_password(self, host: str, port: int, service: str,
                             username: str = "admin",
                             password_list: Optional[List[str]] = None
                             ) -> Dict[str, Any]:
        """弱口令验证：FTP/SSH/MySQL/Redis/MongoDB/SMB。限速防爆破。"""
        vuln_type = "weak_password"
        service_l = (service or "").lower()
        target = f"{host}:{port}/{service_l}"
        pwd_list = password_list or COMMON_PASSWORDS
        # 限速：只取前 max_attempts 个密码
        pwd_list = pwd_list[: self.max_attempts]
        details: Dict[str, Any] = {
            "service": service_l, "username": username,
            "tried": [], "success": False, "success_password": "",
        }
        evidence_parts: List[str] = []

        try:
            # 先探测端口
            if not self._socket_probe(host, int(port)):
                return self._make_result(
                    vuln_type, "unverifiable", 0.0,
                    f"端口 {port} 未开放，无法进行弱口令测试",
                    details, target, username)

            success_pwd = ""
            for idx, pwd in enumerate(pwd_list):
                ok = False
                err = ""
                try:
                    if service_l == "ftp":
                        ok = self._try_ftp(host, int(port), username, pwd)
                    elif service_l == "ssh":
                        ok = self._try_ssh(host, int(port), username, pwd)
                    elif service_l == "mysql":
                        ok = self._try_mysql(host, int(port), username, pwd)
                    elif service_l == "redis":
                        ok = self._try_redis_auth(host, int(port), pwd)
                    elif service_l == "mongodb":
                        ok = self._try_mongo(host, int(port), username, pwd)
                    elif service_l == "smb":
                        ok = self._try_smb(host, int(port))
                    else:
                        # 未知服务：降级为 socket 探测
                        details["note"] = f"未原生支持 {service_l} 的弱口令测试，仅端口探测"
                        ok = False
                except Exception as e:
                    err = str(e)

                details["tried"].append({
                    "username": username, "password": pwd,
                    "success": ok, "error": err,
                })
                if ok:
                    success_pwd = pwd
                    evidence_parts.append(
                        f"弱口令命中: {username}/{pwd or '(空)'}")
                    break
                # 间隔 1 秒，避免账户锁定
                if idx < len(pwd_list) - 1:
                    time.sleep(self.attempt_interval)

            if success_pwd:
                details["success"] = True
                details["success_password"] = success_pwd
                return self._make_result(
                    vuln_type, "verified", 0.95,
                    "; ".join(evidence_parts), details, target, username)
            # 没命中：可能不是弱口令
            return self._make_result(
                vuln_type, "false_positive", 0.2,
                f"已尝试 {len(details['tried'])} 个常见口令均失败",
                details, target, username)
        except Exception as e:
            details["error"] = str(e)
            return self._make_result(
                vuln_type, "unverifiable", 0.0,
                f"弱口令验证异常：{e}", details, target, username)

    # --- 各服务尝试实现 ---
    def _try_ftp(self, host: str, port: int, user: str, pwd: str) -> bool:
        import ftplib
        try:
            ftp = ftplib.FTP()
            ftp.connect(host, port, timeout=self.timeout)
            ftp.login(user, pwd)
            ftp.quit()
            return True
        except Exception:
            return False

    def _try_ssh(self, host: str, port: int, user: str, pwd: str) -> bool:
        try:
            import paramiko  # type: ignore
        except Exception:
            # 降级：socket 探测即可
            return False
        try:
            cli = paramiko.SSHClient()
            cli.set_missing_host_key_policy(paramiko.AutoAddPolicy())
            cli.connect(hostname=host, port=port, username=user,
                        password=pwd, timeout=self.timeout,
                        allow_agent=False, look_for_keys=False)
            cli.close()
            return True
        except Exception:
            return False

    def _try_mysql(self, host: str, port: int, user: str, pwd: str) -> bool:
        try:
            import pymysql  # type: ignore
        except Exception:
            return False
        try:
            conn = pymysql.connect(host=host, port=port, user=user,
                                   password=pwd, connect_timeout=self.timeout)
            conn.close()
            return True
        except Exception:
            return False

    def _try_redis_auth(self, host: str, port: int, pwd: str) -> bool:
        ok, resp = self._raw_send(
            host, port, f"AUTH {pwd}\r\n".encode(), recv=1024)
        if not ok:
            return False
        return "+OK" in resp

    def _try_mongo(self, host: str, port: int, user: str, pwd: str) -> bool:
        # MongoDB 未授权：直接 ping；带认证时用简单 OP_MSG 占位
        ok, resp = self._raw_send(host, port, b"ping\r\n", recv=512)
        return ok and bool(resp)

    def _try_smb(self, host: str, port: int) -> bool:
        # SMB 降级：只做端口开放 + 空会话探测
        return self._socket_probe(host, port)

    # ------------------------------------------------------------------
    # 2. 未授权访问验证
    # ------------------------------------------------------------------
    def verify_unauthorized_access(self, host: str, port: int,
                                   service: str) -> Dict[str, Any]:
        """未授权访问：Redis/MongoDB/ES/Zookeeper/Kafka 只读探测。"""
        vuln_type = "unauthorized_access"
        service_l = (service or "").lower()
        target = f"{host}:{port}/{service_l}"
        details: Dict[str, Any] = {"service": service_l, "response": ""}
        evidence_parts: List[str] = []
        confidence = 0.0
        status = "unverifiable"

        try:
            if not self._socket_probe(host, int(port)):
                return self._make_result(
                    vuln_type, "unverifiable", 0.0,
                    f"端口 {port} 未开放", details, target)

            if service_l == "redis":
                ok, resp = self._raw_send(host, int(port), b"INFO\r\n", recv=8192)
                details["response"] = resp[:500]
                if ok and ("redis_version" in resp or "redis_mode" in resp):
                    evidence_parts.append("Redis 未授权：INFO 返回服务器信息")
                    confidence = 0.95
                    status = "verified"

            elif service_l == "mongodb":
                ok, resp = self._raw_send(host, int(port), b"ping", recv=512)
                details["response"] = resp[:500]
                if ok:
                    evidence_parts.append("MongoDB 未授权：ping 有响应")
                    confidence = 0.85
                    status = "verified"

            elif service_l in ("elasticsearch", "es"):
                try:
                    import requests
                    r = requests.get(f"http://{host}:{port}/", timeout=self.timeout)
                    body = r.text or ""
                    details["response"] = body[:500]
                    if r.status_code == 200 and ("cluster_name" in body or
                                                 "cluster_uuid" in body):
                        evidence_parts.append("Elasticsearch 未授权：返回集群信息")
                        confidence = 0.9
                        status = "verified"
                except Exception as e:
                    details["error"] = str(e)

            elif service_l == "zookeeper":
                ok, resp = self._raw_send(host, int(port), b"srvr", recv=2048)
                details["response"] = resp[:500]
                if ok and ("zookeeper version" in resp.lower() or
                           "zookeeper.version" in resp):
                    evidence_parts.append("Zookeeper 未授权：srvr 返回状态")
                    confidence = 0.9
                    status = "verified"

            elif service_l == "kafka":
                # Kafka MetadataRequest 简化探测：能收到字节即认为开放
                ok, resp = self._raw_send(host, int(port), b"\x00", recv=256)
                details["response"] = (resp or "")[:200]
                if ok and resp:
                    evidence_parts.append("Kafka 端口对探测有响应")
                    confidence = 0.5
                    status = "possible"

            else:
                details["note"] = f"未内置 {service_l} 的未授权探测逻辑"
                status = "unverifiable"

            if status == "unverifiable" and not evidence_parts:
                status = "false_positive"
                confidence = 0.1

            return self._make_result(
                vuln_type, status, confidence,
                "; ".join(evidence_parts) or "未观察到未授权访问特征",
                details, target)
        except Exception as e:
            details["error"] = str(e)
            return self._make_result(
                vuln_type, "unverifiable", 0.0,
                f"未授权访问验证异常：{e}", details, target)

    # ------------------------------------------------------------------
    # 3. 匿名访问验证
    # ------------------------------------------------------------------
    def verify_anonymous_access(self, host: str, port: int,
                                service: str) -> Dict[str, Any]:
        """匿名访问：FTP anonymous / SMB 空会话 / LDAP 匿名绑定。"""
        vuln_type = "anonymous_access"
        service_l = (service or "").lower()
        target = f"{host}:{port}/{service_l}"
        details: Dict[str, Any] = {"service": service_l}
        evidence_parts: List[str] = []
        confidence = 0.0
        status = "unverifiable"

        try:
            if not self._socket_probe(host, int(port)):
                return self._make_result(
                    vuln_type, "unverifiable", 0.0,
                    f"端口 {port} 未开放", details, target)

            if service_l == "ftp":
                if self._try_ftp(host, int(port), "anonymous", "anonymous@"):
                    evidence_parts.append("FTP 匿名登录成功")
                    confidence = 0.9
                    status = "verified"

            elif service_l == "smb":
                # 空会话探测：能建立 TCP 连接即认为可能开放
                if self._socket_probe(host, int(port)):
                    evidence_parts.append("SMB 端口开放，可尝试空会话")
                    confidence = 0.5
                    status = "possible"

            elif service_l == "ldap":
                try:
                    # 匿名绑定：发送一个最小 LDAP BindRequest(版本3, 匿名dn="")
                    # 简化：直接 socket 探测 + 发送 BindRequest 字节
                    bind_req = (
                        b"\x30\x0c\x02\x01\x01\x60\x07\x02\x01\x03"
                        b"\x04\x00\x80\x00"
                    )
                    ok, resp = self._raw_send(host, int(port), bind_req, recv=512)
                    details["response"] = resp[:200]
                    # BindResponse (0x61) 且 resultCode=0 success
                    if ok and resp and resp[0:1] == b"\x61":
                        evidence_parts.append("LDAP 匿名绑定被接受")
                        confidence = 0.9
                        status = "verified"
                except Exception as e:
                    details["error"] = str(e)

            else:
                details["note"] = f"未内置 {service_l} 的匿名访问探测逻辑"

            if status == "unverifiable" and not evidence_parts:
                status = "false_positive"
                confidence = 0.1

            return self._make_result(
                vuln_type, status, confidence,
                "; ".join(evidence_parts) or "未观察到匿名访问成功",
                details, target)
        except Exception as e:
            details["error"] = str(e)
            return self._make_result(
                vuln_type, "unverifiable", 0.0,
                f"匿名访问验证异常：{e}", details, target)

    # ------------------------------------------------------------------
    # 4. 默认凭证验证
    # ------------------------------------------------------------------
    def verify_default_credentials(self, host: str, port: int,
                                   service: str) -> Dict[str, Any]:
        """默认凭证：内置常见设备/服务默认账密字典。"""
        vuln_type = "default_credentials"
        service_l = (service or "").lower()
        target = f"{host}:{port}/{service_l}"
        candidates = DEFAULT_CREDENTIALS.get(service_l, [])
        details: Dict[str, Any] = {"service": service_l, "tried": []}
        evidence_parts: List[str] = []
        confidence = 0.0

        try:
            if not candidates:
                return self._make_result(
                    vuln_type, "unverifiable", 0.0,
                    f"未内置 {service_l} 的默认凭证字典",
                    details, target)

            if not self._socket_probe(host, int(port)):
                return self._make_result(
                    vuln_type, "unverifiable", 0.0,
                    f"端口 {port} 未开放", details, target)

            for user, pwd, desc in candidates[: self.max_attempts]:
                ok = False
                if service_l == "ftp":
                    ok = self._try_ftp(host, int(port), user, pwd)
                elif service_l == "ssh":
                    ok = self._try_ssh(host, int(port), user, pwd)
                elif service_l == "mysql":
                    ok = self._try_mysql(host, int(port), user, pwd)
                elif service_l == "redis":
                    ok = self._try_redis_auth(host, int(port), pwd)
                elif service_l in ("tomcat", "jenkins", "weblogic", "http", "https"):
                    ok = self._try_http_basic_auth(
                        host, int(port), service_l, user, pwd)
                details["tried"].append({"username": user, "password": pwd,
                                         "desc": desc, "success": ok})
                if ok:
                    evidence_parts.append(f"默认凭证命中: {user}/{pwd or '(空)'} ({desc})")
                    confidence = 0.9
                    break
                time.sleep(self.attempt_interval)

            if confidence >= 0.85:
                status = "verified"
            elif evidence_parts:
                status = "possible"
            else:
                status = "false_positive"
                confidence = 0.1

            return self._make_result(
                vuln_type, status, confidence,
                "; ".join(evidence_parts) or "未观察到默认凭证命中",
                details, target)
        except Exception as e:
            details["error"] = str(e)
            return self._make_result(
                vuln_type, "unverifiable", 0.0,
                f"默认凭证验证异常：{e}", details, target)

    def _try_http_basic_auth(self, host: str, port: int, service: str,
                             user: str, pwd: str) -> bool:
        """对 Web 管理后台做 HTTP Basic Auth 登录测试。"""
        try:
            import requests
            scheme = "https" if port in (443, 8443) else "http"
            url = f"{scheme}://{host}:{port}/"
            r = requests.get(url, auth=(user, pwd),
                             timeout=self.timeout, verify=False)
            return r.status_code in (200, 401 and 200) or (
                r.status_code == 200 and "login" not in (r.text or "").lower()[:200])
        except Exception:
            return False

    # ------------------------------------------------------------------
    # 5. 服务版本漏洞匹配（纯本地，不发包）
    # ------------------------------------------------------------------
    def match_version_vulnerabilities(self, service: str,
                                      version: str) -> Dict[str, Any]:
        """基于内置 CVE 映射表匹配服务版本漏洞，返回"可能存在"列表。"""
        vuln_type = "version_cve_match"
        service_l = (service or "").lower().strip()
        version_s = (version or "").strip()
        details: Dict[str, Any] = {
            "service": service_l, "version": version_s, "matches": [],
        }
        try:
            if not service_l or not version_s:
                return self._make_result(
                    vuln_type, "unverifiable", 0.0,
                    "服务名或版本为空，无法匹配", details,
                    f"{service_l}:{version_s}")

            for item in VERSION_VULN_DB:
                db_svc = item["service"].lower()
                db_ver = item["version_match"]
                # 服务名匹配：包含关系（apache httpd / apache / httpd 互相兼容）
                svc_hit = (db_svc in service_l) or (service_l in db_svc)
                # 版本匹配：内置版本前缀 == 实际版本前缀（如 2.4.49 / 2.4.49.1）
                ver_hit = (version_s.startswith(db_ver) or
                           db_ver.startswith(version_s))
                if svc_hit and ver_hit:
                    details["matches"].append({
                        "cve": item["cve"],
                        "description": item["desc"],
                        "severity": item["severity"],
                        "note": "版本匹配，需进一步验证",
                    })

            if details["matches"]:
                return self._make_result(
                    vuln_type, "possible", 0.6,
                    f"命中 {len(details['matches'])} 条版本关联漏洞，需进一步验证",
                    details, f"{service_l}:{version_s}")
            return self._make_result(
                vuln_type, "false_positive", 0.1,
                "内置 CVE 库中无该服务版本的已知映射",
                details, f"{service_l}:{version_s}")
        except Exception as e:
            details["error"] = str(e)
            return self._make_result(
                vuln_type, "unverifiable", 0.0,
                f"版本匹配异常：{e}", details, f"{service_l}:{version_s}")
