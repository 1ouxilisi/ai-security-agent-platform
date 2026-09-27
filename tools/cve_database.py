"""
cve_database安全工具集成模块，提供相关安全工具的封装和调用。

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
import sqlite3
import os
from typing import Dict, Any, List, Optional, Tuple
from datetime import datetime, timedelta
from dataclasses import dataclass, field
from utils.logger import log


@dataclass
class CVERecord:
    """CVE漏洞记录"""
    cve_id: str
    description: str = ""
    severity: str = "unknown"  # critical/high/medium/low/unknown
    cvss_v2_score: float = 0.0
    cvss_v3_score: float = 0.0
    cvss_v31_score: float = 0.0
    cwe_ids: List[str] = field(default_factory=list)
    cpe_list: List[str] = field(default_factory=list)
    published_date: str = ""
    last_modified: str = ""
    references: List[str] = field(default_factory=list)
    exploitability: str = "unknown"  # high/medium/low/unknown
    patch_available: bool = False
    source: str = "local"  # nvd/local/manual


class CVEDatabase:
    """CVE漏洞数据库"""

    def __init__(self, db_path: str = None):
        """初始化CVEDatabase实例。

        Args:
            self: 类实例。
        """
        if db_path is None:
            db_path = os.path.join(
                os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
                "data", "cve_database.db"
            )
        self.db_path = db_path
        self.nvd_api_url = "https://services.nvd.nist.gov/rest/json/cves/2.0"
        self.cache_ttl = 86400 * 7  # 7天缓存
        self._init_db()
        self._load_builtin_cves()

    def _init_db(self):
        """初始化数据库"""
        os.makedirs(os.path.dirname(self.db_path), exist_ok=True)
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()

        cursor.execute("""
            CREATE TABLE IF NOT EXISTS cves (
                cve_id TEXT PRIMARY KEY,
                description TEXT,
                severity TEXT,
                cvss_v2_score REAL,
                cvss_v3_score REAL,
                cvss_v31_score REAL,
                cwe_ids TEXT,
                cpe_list TEXT,
                published_date TEXT,
                last_modified TEXT,
                refs TEXT,
                exploitability TEXT,
                patch_available INTEGER,
                source TEXT,
                cached_at TEXT
            )
        """)

        cursor.execute("""
            CREATE TABLE IF NOT EXISTS cpe_mappings (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                vendor TEXT,
                product TEXT,
                version TEXT,
                cve_id TEXT,
                FOREIGN KEY (cve_id) REFERENCES cves(cve_id)
            )
        """)

        cursor.execute("CREATE INDEX IF NOT EXISTS idx_severity ON cves(severity)")
        cursor.execute("CREATE INDEX IF NOT EXISTS idx_cwe ON cves(cwe_ids)")
        cursor.execute("CREATE INDEX IF NOT EXISTS idx_cpe ON cpe_mappings(vendor, product)")

        conn.commit()
        conn.close()

    def _load_builtin_cves(self):
        """加载内置常见CVE漏洞库"""
        builtin_cves = [
            # 高危漏洞精选
            CVERecord(
                cve_id="CVE-2021-44228",
                description="Apache Log4j2 远程代码执行漏洞（Log4Shell），攻击者可通过构造特殊的JNDI lookup实现远程代码执行",
                severity="critical",
                cvss_v31_score=10.0,
                cwe_ids=["CWE-502", "CWE-917"],
                cpe_list=["cpe:2.3:a:apache:log4j:*:*:*:*:*:*:*:*"],
                published_date="2021-12-10",
                exploitability="high",
                patch_available=True,
                source="builtin",
            ),
            CVERecord(
                cve_id="CVE-2017-0144",
                description="Microsoft Windows SMBv1 远程代码执行漏洞（EternalBlue），攻击者可通过发送特制的SMB数据包实现远程代码执行",
                severity="critical",
                cvss_v3_score=8.1,
                cwe_ids=["CWE-119"],
                cpe_list=["cpe:2.3:o:microsoft:windows:*:*:*:*:*:*:*:*"],
                published_date="2017-03-17",
                exploitability="high",
                patch_available=True,
                source="builtin",
            ),
            CVERecord(
                cve_id="CVE-2014-0160",
                description="OpenSSL 心脏滴血漏洞（Heartbleed），攻击者可通过特制的TLS心跳请求读取服务器内存中的敏感信息",
                severity="high",
                cvss_v2_score=5.0,
                cwe_ids=["CWE-119", "CWE-125"],
                cpe_list=["cpe:2.3:a:openssl:openssl:*:*:*:*:*:*:*:*"],
                published_date="2014-04-07",
                exploitability="high",
                patch_available=True,
                source="builtin",
            ),
            CVERecord(
                cve_id="CVE-2021-26855",
                description="Microsoft Exchange Server 远程代码执行漏洞（ProxyLogon），攻击者可通过SSRF和反序列化实现未授权远程代码执行",
                severity="critical",
                cvss_v31_score=9.8,
                cwe_ids=["CWE-918", "CWE-502"],
                cpe_list=["cpe:2.3:a:microsoft:exchange_server:*:*:*:*:*:*:*:*"],
                published_date="2021-03-02",
                exploitability="high",
                patch_available=True,
                source="builtin",
            ),
            CVERecord(
                cve_id="CVE-2019-0708",
                description="Microsoft Windows 远程桌面服务远程代码执行漏洞（BlueKeep），攻击者可通过发送特制的RDP数据包实现远程代码执行",
                severity="critical",
                cvss_v3_score=9.8,
                cwe_ids=["CWE-119"],
                cpe_list=["cpe:2.3:o:microsoft:windows:*:*:*:*:*:*:*:*"],
                published_date="2019-05-14",
                exploitability="high",
                patch_available=True,
                source="builtin",
            ),
            CVERecord(
                cve_id="CVE-2020-1472",
                description="Microsoft Netlogon 特权提升漏洞（Zerologon），攻击者可通过特制的Netlogon协议数据包重置域控制器密码",
                severity="critical",
                cvss_v31_score=10.0,
                cwe_ids=["CWE-330"],
                cpe_list=["cpe:2.3:o:microsoft:windows_server:*:*:*:*:*:*:*:*"],
                published_date="2020-08-11",
                exploitability="high",
                patch_available=True,
                source="builtin",
            ),
            CVERecord(
                cve_id="CVE-2022-22965",
                description="Spring Framework 远程代码执行漏洞（Spring4Shell），攻击者可通过数据绑定实现远程代码执行",
                severity="critical",
                cvss_v31_score=9.8,
                cwe_ids=["CWE-94"],
                cpe_list=["cpe:2.3:a:vmware:spring_framework:*:*:*:*:*:*:*:*"],
                published_date="2022-03-31",
                exploitability="high",
                patch_available=True,
                source="builtin",
            ),
            CVERecord(
                cve_id="CVE-2023-23397",
                description="Microsoft Outlook 远程代码执行漏洞，攻击者可通过特制的会议邀请触发NTLM凭证泄露",
                severity="critical",
                cvss_v31_score=9.8,
                cwe_ids=["CWE-294"],
                cpe_list=["cpe:2.3:a:microsoft:outlook:*:*:*:*:*:*:*:*"],
                published_date="2023-03-14",
                exploitability="high",
                patch_available=True,
                source="builtin",
            ),
            CVERecord(
                cve_id="CVE-2021-34527",
                description="Microsoft Windows Print Spooler 远程代码执行漏洞（PrintNightmare），攻击者可通过特制的打印请求实现远程代码执行",
                severity="critical",
                cvss_v31_score=8.8,
                cwe_ids=["CWE-269"],
                cpe_list=["cpe:2.3:o:microsoft:windows:*:*:*:*:*:*:*:*"],
                published_date="2021-07-01",
                exploitability="high",
                patch_available=True,
                source="builtin",
            ),
            CVERecord(
                cve_id="CVE-2018-13379",
                description="Fortinet FortiOS 路径遍历漏洞，攻击者可通过特制的HTTP请求读取系统文件（包含用户名和密码）",
                severity="critical",
                cvss_v3_score=9.8,
                cwe_ids=["CWE-22"],
                cpe_list=["cpe:2.3:o:fortinet:fortios:*:*:*:*:*:*:*:*"],
                published_date="2019-05-24",
                exploitability="high",
                patch_available=True,
                source="builtin",
            ),
            CVERecord(
                cve_id="CVE-2019-19781",
                description="Citrix ADC / Gateway 目录遍历漏洞，攻击者可通过特制的HTTP请求实现未授权代码执行",
                severity="critical",
                cvss_v3_score=9.8,
                cwe_ids=["CWE-22", "CWE-94"],
                cpe_list=["cpe:2.3:a:citrix:netscaler_gateway:*:*:*:*:*:*:*:*"],
                published_date="2019-12-17",
                exploitability="high",
                patch_available=True,
                source="builtin",
            ),
            CVERecord(
                cve_id="CVE-2020-5902",
                description="F5 BIG-IP 远程代码执行漏洞，攻击者可通过特制的HTTP请求实现未授权远程代码执行",
                severity="critical",
                cvss_v3_score=9.8,
                cwe_ids=["CWE-22", "CWE-78"],
                cpe_list=["cpe:2.3:a:f5:big-ip:*:*:*:*:*:*:*:*"],
                published_date="2020-07-01",
                exploitability="high",
                patch_available=True,
                source="builtin",
            ),
            CVERecord(
                cve_id="CVE-2022-1388",
                description="F5 BIG-IP iControl REST 身份认证绕过漏洞，攻击者可通过特制的HTTP请求实现未授权远程代码执行",
                severity="critical",
                cvss_v31_score=9.8,
                cwe_ids=["CWE-287", "CWE-306"],
                cpe_list=["cpe:2.3:a:f5:big-ip:*:*:*:*:*:*:*:*"],
                published_date="2022-05-04",
                exploitability="high",
                patch_available=True,
                source="builtin",
            ),
            CVERecord(
                cve_id="CVE-2023-27997",
                description="Fortinet FortiOS / FortiProxy SSL VPN 堆溢出漏洞（XORat），攻击者可通过特制的请求实现远程代码执行",
                severity="critical",
                cvss_v31_score=9.8,
                cwe_ids=["CWE-122"],
                cpe_list=["cpe:2.3:o:fortinet:fortios:*:*:*:*:*:*:*:*"],
                published_date="2023-06-12",
                exploitability="high",
                patch_available=True,
                source="builtin",
            ),
            CVERecord(
                cve_id="CVE-2023-34362",
                description="MOVEit Transfer SQL注入漏洞，攻击者可通过特制的HTTP请求实现未授权数据访问",
                severity="critical",
                cvss_v31_score=9.8,
                cwe_ids=["CWE-89"],
                cpe_list=["cpe:2.3:a:progress:moveit_transfer:*:*:*:*:*:*:*:*"],
                published_date="2023-05-31",
                exploitability="high",
                patch_available=True,
                source="builtin",
            ),
            CVERecord(
                cve_id="CVE-2024-3400",
                description="Palo Alto Networks GlobalProtect 命令注入漏洞，攻击者可通过特制的请求实现未授权远程代码执行",
                severity="critical",
                cvss_v31_score=10.0,
                cwe_ids=["CWE-77"],
                cpe_list=["cpe:2.3:a:paloaltonetworks:globalprotect:*:*:*:*:*:*:*:*"],
                published_date="2024-04-12",
                exploitability="high",
                patch_available=True,
                source="builtin",
            ),
            CVERecord(
                cve_id="CVE-2024-21762",
                description="Fortinet FortiOS SSL VPN 越界写入漏洞，攻击者可通过特制的请求实现未授权远程代码执行",
                severity="critical",
                cvss_v31_score=9.6,
                cwe_ids=["CWE-787"],
                cpe_list=["cpe:2.3:o:fortinet:fortios:*:*:*:*:*:*:*:*"],
                published_date="2024-02-08",
                exploitability="high",
                patch_available=True,
                source="builtin",
            ),
            CVERecord(
                cve_id="CVE-2023-4966",
                description="Citrix NetScaler ADC / Gateway 敏感信息泄露漏洞，攻击者可通过特制的请求读取会话令牌",
                severity="high",
                cvss_v31_score=9.4,
                cwe_ids=["CWE-119", "CWE-200"],
                cpe_list=["cpe:2.3:a:citrix:netscaler_gateway:*:*:*:*:*:*:*:*"],
                published_date="2023-10-10",
                exploitability="high",
                patch_available=True,
                source="builtin",
            ),
            CVERecord(
                cve_id="CVE-2022-30190",
                description="Microsoft Windows 支持诊断工具（MSDT）远程代码执行漏洞（Follina），攻击者可通过特制的Office文档触发代码执行",
                severity="high",
                cvss_v31_score=7.8,
                cwe_ids=["CWE-94"],
                cpe_list=["cpe:2.3:o:microsoft:windows:*:*:*:*:*:*:*:*"],
                published_date="2022-05-30",
                exploitability="high",
                patch_available=True,
                source="builtin",
            ),
            CVERecord(
                cve_id="CVE-2021-1675",
                description="Microsoft Windows Print Spooler 远程代码执行漏洞（PrintNightmare），攻击者可通过特制的打印请求实现远程代码执行",
                severity="critical",
                cvss_v31_score=8.8,
                cwe_ids=["CWE-269"],
                cpe_list=["cpe:2.3:o:microsoft:windows:*:*:*:*:*:*:*:*"],
                published_date="2021-07-01",
                exploitability="high",
                patch_available=True,
                source="builtin",
            ),
        ]

        for cve in builtin_cves:
            self._save_cve(cve)

        # 加载扩展CVE库（80个更多高危CVE）
        try:
            from tools.cve_extended import EXTENDED_CVES
            for ext in EXTENDED_CVES:
                cve = CVERecord(
                    cve_id=ext["cve_id"],
                    description=ext.get("desc", ext.get("name", "")),
                    severity=ext.get("severity", "high"),
                    cvss_v31_score=ext.get("cvss_v31", 0.0),
                    cwe_ids=ext.get("cwe", []),
                    cpe_list=[f"cpe:2.3:*:*:{ext.get('product', 'unknown')}:*:*:*:*:*:*:*:*"],
                    exploitability="high" if ext.get("severity") == "critical" else "medium",
                    patch_available=True,
                    source="builtin_extended",
                )
                self._save_cve(cve)
        except Exception as e:
            log.debug(f"加载扩展CVE库失败: {e}")

    def _save_cve(self, cve: CVERecord):
        """保存CVE记录到数据库"""
        try:
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()

            cursor.execute("""
                INSERT OR REPLACE INTO cves 
                (cve_id, description, severity, cvss_v2_score, cvss_v3_score, 
                 cvss_v31_score, cwe_ids, cpe_list, published_date, last_modified,
                 refs, exploitability, patch_available, source, cached_at)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """, (
                cve.cve_id, cve.description, cve.severity,
                cve.cvss_v2_score, cve.cvss_v3_score, cve.cvss_v31_score,
                json.dumps(cve.cwe_ids), json.dumps(cve.cpe_list),
                cve.published_date, cve.last_modified,
                json.dumps(cve.references), cve.exploitability,
                1 if cve.patch_available else 0,
                cve.source, datetime.now().isoformat()
            ))

            # 保存CPE映射
            for cpe in cve.cpe_list:
                parts = cpe.split(":")
                if len(parts) >= 5:
                    vendor = parts[3] if len(parts) > 3 else ""
                    product = parts[4] if len(parts) > 4 else ""
                    version = parts[5] if len(parts) > 5 else "*"
                    cursor.execute("""
                        INSERT OR REPLACE INTO cpe_mappings (vendor, product, version, cve_id)
                        VALUES (?, ?, ?, ?)
                    """, (vendor, product, version, cve.cve_id))

            conn.commit()
            conn.close()
        except Exception as e:
            log.debug(f"保存CVE失败: {e}")

    def get_cve(self, cve_id: str) -> Optional[CVERecord]:
        """查询CVE详情"""
        try:
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()
            cursor.execute("SELECT * FROM cves WHERE cve_id = ?", (cve_id,))
            row = cursor.fetchone()
            conn.close()

            if row:
                return self._row_to_cve(row)
            return None
        except Exception as e:
            log.debug(f"查询CVE失败: {e}")
            return None

    def _row_to_cve(self, row) -> CVERecord:
        """将数据库行转换为CVERecord"""
        return CVERecord(
            cve_id=row[0],
            description=row[1] or "",
            severity=row[2] or "unknown",
            cvss_v2_score=row[3] or 0.0,
            cvss_v3_score=row[4] or 0.0,
            cvss_v31_score=row[5] or 0.0,
            cwe_ids=json.loads(row[6]) if row[6] else [],
            cpe_list=json.loads(row[7]) if row[7] else [],
            published_date=row[8] or "",
            last_modified=row[9] or "",
            references=json.loads(row[10]) if row[10] else [],
            exploitability=row[11] or "unknown",
            patch_available=bool(row[12]),
            source=row[13] or "local",
        )

    def search_cves(self, keyword: str = "", severity: str = "",
                     cwe_id: str = "", limit: int = 20) -> List[CVERecord]:
        """搜索CVE漏洞"""
        try:
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()

            query = "SELECT * FROM cves WHERE 1=1"
            params = []

            if keyword:
                query += " AND (description LIKE ? OR cve_id LIKE ?)"
                params.extend([f"%{keyword}%", f"%{keyword}%"])

            if severity and severity != "all":
                query += " AND severity = ?"
                params.append(severity)

            if cwe_id:
                query += " AND cwe_ids LIKE ?"
                params.append(f"%{cwe_id}%")

            query += " ORDER BY cvss_v31_score DESC LIMIT ?"
            params.append(limit)

            cursor.execute(query, params)
            rows = cursor.fetchall()
            conn.close()

            return [self._row_to_cve(row) for row in rows]
        except Exception as e:
            log.debug(f"搜索CVE失败: {e}")
            return []

    def match_vulnerabilities(self, service: str = "", version: str = "",
                                vendor: str = "", product: str = "") -> List[CVERecord]:
        """根据服务/版本智能匹配CVE漏洞"""
        try:
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()

            # 通过CPE匹配
            if vendor and product:
                cursor.execute("""
                    SELECT DISTINCT c.* FROM cves c
                    JOIN cpe_mappings m ON c.cve_id = m.cve_id
                    WHERE m.vendor LIKE ? AND m.product LIKE ?
                    ORDER BY c.cvss_v31_score DESC LIMIT 20
                """, (f"%{vendor}%", f"%{product}%"))
            elif service:
                # 通过描述匹配
                cursor.execute("""
                    SELECT * FROM cves 
                    WHERE description LIKE ? OR cpe_list LIKE ?
                    ORDER BY cvss_v31_score DESC LIMIT 20
                """, (f"%{service}%", f"%{service}%"))
            else:
                return []

            rows = cursor.fetchall()
            conn.close()

            return [self._row_to_cve(row) for row in rows]
        except Exception as e:
            log.debug(f"匹配漏洞失败: {e}")
            return []

    def get_statistics(self) -> Dict[str, Any]:
        """获取漏洞库统计"""
        try:
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()

            cursor.execute("SELECT COUNT(*) FROM cves")
            total = cursor.fetchone()[0]

            cursor.execute("SELECT severity, COUNT(*) FROM cves GROUP BY severity")
            by_severity = dict(cursor.fetchall())

            cursor.execute("SELECT COUNT(*) FROM cves WHERE exploitability = 'high'")
            high_exploit = cursor.fetchone()[0]

            cursor.execute("SELECT COUNT(*) FROM cves WHERE patch_available = 1")
            patched = cursor.fetchone()[0]

            conn.close()

            return {
                "total_cves": total,
                "by_severity": by_severity,
                "high_exploitability": high_exploit,
                "patch_available": patched,
                "database_path": self.db_path,
                "cache_ttl_days": self.cache_ttl // 86400,
            }
        except Exception as e:
            log.debug(f"获取统计失败: {e}")
            return {"error": str(e)}

    def fetch_from_nvd(self, cve_id: str = "", keyword: str = "",
                        results_per_page: int = 20) -> Dict[str, Any]:
        """从NVD API获取最新漏洞数据"""
        try:
            import requests

            params = {"resultsPerPage": results_per_page}

            if cve_id:
                params["cveId"] = cve_id
            if keyword:
                params["keywordSearch"] = keyword

            headers = {"User-Agent": "AI-Hacking-Agent/1.0"}

            response = requests.get(
                self.nvd_api_url,
                params=params,
                headers=headers,
                timeout=30
            )

            if response.status_code == 200:
                data = response.json()
                vulnerabilities = data.get("vulnerabilities", [])
                total = data.get("totalResults", 0)

                # 保存到本地缓存
                for vuln in vulnerabilities:
                    cve_data = vuln.get("cve", {})
                    cve_id = cve_data.get("id", "")
                    if cve_id:
                        descriptions = cve_data.get("descriptions", [])
                        desc = next((d["value"] for d in descriptions
                                    if d.get("lang") == "en"), "")

                        metrics = cve_data.get("metrics", {})
                        cvss_v31 = metrics.get("cvssMetricV31", [{}])
                        cvss_v3 = metrics.get("cvssMetricV30", [{}])
                        cvss_v2 = metrics.get("cvssMetricV2", [{}])

                        v31_score = cvss_v31[0].get("cvssData", {}).get("baseScore", 0) if cvss_v31 else 0
                        v3_score = cvss_v3[0].get("cvssData", {}).get("baseScore", 0) if cvss_v3 else 0
                        v2_score = cvss_v2[0].get("cvssData", {}).get("baseScore", 0) if cvss_v2 else 0

                        severity = "unknown"
                        if v31_score >= 9.0:
                            severity = "critical"
                        elif v31_score >= 7.0:
                            severity = "high"
                        elif v31_score >= 4.0:
                            severity = "medium"
                        elif v31_score > 0:
                            severity = "low"

                        weaknesses = cve_data.get("weaknesses", [])
                        cwe_ids = []
                        for w in weaknesses:
                            for desc in w.get("description", []):
                                if desc.get("value", "").startswith("CWE-"):
                                    cwe_ids.append(desc["value"])

                        configurations = cve_data.get("configurations", [])
                        cpe_list = []
                        for config in configurations:
                            for node in config.get("nodes", []):
                                for cpe in node.get("cpeMatch", []):
                                    if cpe.get("criteria"):
                                        cpe_list.append(cpe["criteria"])

                        references = [r.get("url", "") for r in cve_data.get("references", [])]

                        cve_record = CVERecord(
                            cve_id=cve_id,
                            description=desc,
                            severity=severity,
                            cvss_v2_score=v2_score,
                            cvss_v3_score=v3_score,
                            cvss_v31_score=v31_score,
                            cwe_ids=cwe_ids,
                            cpe_list=cpe_list,
                            published_date=cve_data.get("published", ""),
                            last_modified=cve_data.get("lastModified", ""),
                            references=references,
                            exploitability="high" if v31_score >= 9.0 else "medium",
                            patch_available=any("patch" in r.lower() for r in references),
                            source="nvd",
                        )
                        self._save_cve(cve_record)

                return {
                    "success": True,
                    "total_results": total,
                    "returned": len(vulnerabilities),
                    "cached": True,
                    "message": f"从NVD获取{len(vulnerabilities)}条漏洞数据，已缓存到本地",
                }
            else:
                return {
                    "success": False,
                    "error": f"NVD API返回错误: HTTP {response.status_code}",
                }
        except Exception as e:
            return {
                "success": False,
                "error": f"从NVD获取数据失败: {e}",
            }


# 全局CVE数据库实例
cve_database = CVEDatabase()
