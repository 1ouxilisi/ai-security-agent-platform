"""
cve知识库模块，存储和管理相关安全知识、漏洞信息和攻击链数据。

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
import time
from typing import Any, Dict, List, Optional
from pathlib import Path
from utils.logger import log
from config.settings import settings


class CVEKnowledgeBase:
    """CVE漏洞知识库"""

    def __init__(self, db_path: Optional[str] = None):
        """初始化CVEKnowledgeBase实例。

        Args:
            self: 类实例。
        """
        self.db_path = db_path or str(Path(settings.project_root) / "data" / "cve_knowledge.json")
        self.local_db: Dict[str, Any] = {}
        self._load_local_db()
        log.info(f"CVE知识库初始化: {self.db_path}")

    def _load_local_db(self):
        """加载本地漏洞库"""
        try:
            if Path(self.db_path).exists():
                with open(self.db_path, "r", encoding="utf-8") as f:
                    self.local_db = json.load(f)
                log.info(f"本地漏洞库加载: {len(self.local_db)} 条记录")
            else:
                # 初始化内置常见漏洞
                self.local_db = self._get_builtin_cves()
                self._save_local_db()
        except Exception as e:
            log.error(f"本地漏洞库加载失败: {e}")
            self.local_db = self._get_builtin_cves()

    def _save_local_db(self):
        """保存本地漏洞库"""
        try:
            Path(self.db_path).parent.mkdir(parents=True, exist_ok=True)
            with open(self.db_path, "w", encoding="utf-8") as f:
                json.dump(self.local_db, f, ensure_ascii=False, indent=2)
        except Exception as e:
            log.error(f"本地漏洞库保存失败: {e}")

    def _get_builtin_cves(self) -> Dict[str, Any]:
        """获取内置常见漏洞信息"""
        return {
            "CVE-2021-44228": {
                "id": "CVE-2021-44228",
                "name": "Log4Shell",
                "severity": "critical",
                "cvss_score": 10.0,
                "description": "Apache Log4j2 中存在远程代码执行漏洞，攻击者可通过构造特殊的日志消息触发JNDI注入，执行任意代码。",
                "affected": "Apache Log4j 2.0-beta9 到 2.14.1",
                "exploit_available": True,
                "fix": "升级到 Log4j 2.15.0 或更高版本；或设置 log4j2.formatMsgNoLookups=true",
                "references": [
                    "https://nvd.nist.gov/vuln/detail/CVE-2021-44228",
                    "https://logging.apache.org/log4j/2.x/security.html"
                ],
                "added_at": time.time()
            },
            "CVE-2017-5638": {
                "id": "CVE-2017-5638",
                "name": "Struts2 S2-045",
                "severity": "critical",
                "cvss_score": 10.0,
                "description": "Apache Struts2 中存在远程代码执行漏洞，攻击者可通过构造恶意的Content-Type头触发OGNL表达式执行。",
                "affected": "Apache Struts 2.3.5 - 2.3.31, 2.5 - 2.5.10",
                "exploit_available": True,
                "fix": "升级到 Struts 2.3.32 或 2.5.10.1",
                "references": ["https://nvd.nist.gov/vuln/detail/CVE-2017-5638"],
                "added_at": time.time()
            },
            "CVE-2014-0160": {
                "id": "CVE-2014-0160",
                "name": "Heartbleed",
                "severity": "high",
                "cvss_score": 7.5,
                "description": "OpenSSL 心跳扩展中存在信息泄露漏洞，攻击者可读取服务器内存中的敏感信息，包括私钥、会话cookie等。",
                "affected": "OpenSSL 1.0.1 - 1.0.1f",
                "exploit_available": True,
                "fix": "升级到 OpenSSL 1.0.1g 或更高版本",
                "references": ["https://heartbleed.com/", "https://nvd.nist.gov/vuln/detail/CVE-2014-0160"],
                "added_at": time.time()
            },
            "CVE-2021-41773": {
                "id": "CVE-2021-41773",
                "name": "Apache HTTP Server Path Traversal",
                "severity": "high",
                "cvss_score": 7.5,
                "description": "Apache HTTP Server 2.4.49 中存在路径穿越漏洞，攻击者可通过构造特殊URL读取服务器上的任意文件。",
                "affected": "Apache HTTP Server 2.4.49",
                "exploit_available": True,
                "fix": "升级到 Apache HTTP Server 2.4.50 或更高版本",
                "references": ["https://nvd.nist.gov/vuln/detail/CVE-2021-41773"],
                "added_at": time.time()
            },
            "CVE-2019-0708": {
                "id": "CVE-2019-0708",
                "name": "BlueKeep",
                "severity": "critical",
                "cvss_score": 9.8,
                "description": "Windows 远程桌面服务(RDP)中存在远程代码执行漏洞，攻击者可通过发送特制请求在目标系统上执行任意代码，无需身份验证。",
                "affected": "Windows 7, Windows Server 2008, Windows Server 2008 R2",
                "exploit_available": True,
                "fix": "安装微软安全更新 KB4499175 或更高版本",
                "references": ["https://nvd.nist.gov/vuln/detail/CVE-2019-0708"],
                "added_at": time.time()
            },
        }

    def query_cve(self, cve_id: str) -> Optional[Dict]:
        """查询CVE漏洞详情"""
        cve_id = cve_id.upper().strip()
        if cve_id in self.local_db:
            log.info(f"CVE查询命中本地库: {cve_id}")
            return self.local_db[cve_id]

        log.info(f"CVE未在本地库: {cve_id}，可尝试在线查询")
        return {
            "id": cve_id,
            "status": "not_found_local",
            "message": f"未在本地漏洞库中找到 {cve_id}，建议访问 NVD 官网查询",
            "nvd_url": f"https://nvd.nist.gov/vuln/detail/{cve_id}"
        }

    def search_by_keyword(self, keyword: str) -> List[Dict]:
        """按关键词搜索漏洞"""
        keyword = keyword.lower()
        results = []
        for cve_id, cve_data in self.local_db.items():
            search_text = (
                cve_data.get("name", "") + " " +
                cve_data.get("description", "") + " " +
                cve_data.get("affected", "")
            ).lower()
            if keyword in search_text:
                results.append(cve_data)
        log.info(f"关键词搜索 '{keyword}': 找到 {len(results)} 条")
        return results

    def get_by_severity(self, severity: str) -> List[Dict]:
        """按严重程度获取漏洞列表"""
        severity = severity.lower()
        results = [
            cve for cve in self.local_db.values()
            if cve.get("severity", "").lower() == severity
        ]
        log.info(f"按严重程度 '{severity}': 找到 {len(results)} 条")
        return results

    def get_statistics(self) -> Dict:
        """获取漏洞库统计"""
        severity_counts = {"critical": 0, "high": 0, "medium": 0, "low": 0}
        for cve in self.local_db.values():
            sev = cve.get("severity", "low").lower()
            if sev in severity_counts:
                severity_counts[sev] += 1

        return {
            "total": len(self.local_db),
            "by_severity": severity_counts,
            "exploit_available": sum(1 for c in self.local_db.values() if c.get("exploit_available")),
        }

    def add_cve(self, cve_data: Dict) -> bool:
        """添加漏洞到本地库"""
        cve_id = cve_data.get("id", "").upper()
        if not cve_id:
            return False
        cve_data["added_at"] = time.time()
        self.local_db[cve_id] = cve_data
        self._save_local_db()
        log.info(f"漏洞已添加到本地库: {cve_id}")
        return True

    def get_repair_suggestions(self, vulnerability_type: str) -> List[str]:
        """根据漏洞类型获取修复建议"""
        suggestions_map = {
            "sql_injection": [
                "使用参数化查询/预编译语句",
                "对用户输入进行严格验证和转义",
                "使用ORM框架",
                "最小化数据库账户权限",
                "部署WAF进行防护"
            ],
            "xss": [
                "对用户输入进行HTML实体编码",
                "使用Content Security Policy (CSP)",
                "设置HttpOnly Cookie标志",
                "使用现代前端框架的自动转义功能",
                "输入验证和输出编码"
            ],
            "ssrf": [
                "禁用不必要的协议（file://, gopher://, dict://）",
                "限制可访问的IP范围（禁止内网IP）",
                "使用URL白名单",
                "禁用HTTP重定向跟随",
                "部署在隔离网络环境"
            ],
            "command_injection": [
                "避免直接调用系统命令",
                "使用安全的API替代系统调用",
                "对输入进行严格验证（白名单）",
                "使用参数化的命令执行接口",
                "以最小权限运行应用"
            ],
            "file_upload": [
                "限制允许上传的文件类型（白名单）",
                "重命名上传文件，避免路径遍历",
                "将上传文件存储在Web根目录之外",
                "设置上传目录不可执行",
                "对上传文件进行病毒扫描"
            ],
            "idor": [
                "实施适当的访问控制检查",
                "使用不可预测的对象标识符",
                "验证用户对请求资源的所有权",
                "实施基于角色的访问控制(RBAC)",
                "审计所有对象访问请求"
            ],
        }
        return suggestions_map.get(vulnerability_type.lower(), ["建议参考OWASP指南进行修复"])


# 全局CVE知识库实例
cve_kb = CVEKnowledgeBase()
