"""
vuln_intel安全工具集成模块，提供相关安全工具的封装和调用。

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
import time
from typing import Any, Dict, List, Optional, Tuple
from datetime import datetime, timedelta

from utils.logger import log


class VulnIntel:
    """漏洞情报收集器 - NVD/Exploit-DB/漏洞利用代码检索"""

    NVD_API_BASE = "https://services.nvd.nist.gov/rest/json/cves/2.0"
    NVD_CVE_API = "https://services.nvd.nist.gov/rest/json/cve/2.0"
    EXPLOIT_DB_API = "https://www.exploit-db.com/search"
    CVE_DETAILS_CACHE = {}
    CVE_SEARCH_CACHE = {}
    CACHE_TTL = 3600  # 1小时缓存

    def __init__(self, cache_dir: str = "data/vuln_cache"):
        """初始化VulnIntel实例。

        Args:
            self: 类实例。
        """
        self.cache_dir = cache_dir
        self._ensure_cache_dir()
        self._local_cve_db = self._load_local_cve_db()
        log.info(f"✅ 漏洞情报模块初始化成功，本地CVE库: {len(self._local_cve_db)}条")

    def _ensure_cache_dir(self):
        """确保缓存目录存在"""
        try:
            os.makedirs(self.cache_dir, exist_ok=True)
        except Exception as e:
            log.warning(f"创建缓存目录失败: {e}")

    def _load_local_cve_db(self) -> Dict:
        """加载本地CVE数据库"""
        try:
            db_path = os.path.join(os.path.dirname(os.path.dirname(__file__)), "data", "cve_knowledge.json")
            if os.path.exists(db_path):
                with open(db_path, "r", encoding="utf-8") as f:
                    return json.load(f)
        except Exception as e:
            log.warning(f"加载本地CVE库失败: {e}")
        return {}

    # ========== NVD CVE查询 ==========

    async def get_cve_details(self, cve_id: str, use_cache: bool = True) -> Dict:
        """
        获取CVE详情
        :param cve_id: CVE编号，如 CVE-2021-44228
        :param use_cache: 是否使用缓存
        :return: CVE详情字典
        """
        cve_id = cve_id.upper().strip()

        # 检查缓存
        if use_cache and cve_id in self.CVE_DETAILS_CACHE:
            cached = self.CVE_DETAILS_CACHE[cve_id]
            if time.time() - cached["timestamp"] < self.CACHE_TTL:
                log.info(f"使用缓存的CVE详情: {cve_id}")
                return cached["data"]

        # 先查本地库
        local_result = self._search_local_cve(cve_id)
        if local_result:
            self.CVE_DETAILS_CACHE[cve_id] = {"timestamp": time.time(), "data": local_result}
            return local_result

        # 从NVD API查询
        try:
            import aiohttp
            url = f"{self.NVD_CVE_API}/{cve_id}"

            async with aiohttp.ClientSession() as session:
                async with session.get(url, timeout=30) as resp:
                    if resp.status == 200:
                        data = await resp.json()
                        parsed = self._parse_nvd_cve_response(data)
                        if parsed:
                            self.CVE_DETAILS_CACHE[cve_id] = {"timestamp": time.time(), "data": parsed}
                            self._save_cve_to_cache(cve_id, parsed)
                            return parsed
                    elif resp.status == 404:
                        return {"error": f"CVE {cve_id} 不存在", "cve_id": cve_id}
                    else:
                        return {"error": f"NVD API返回错误: {resp.status}", "cve_id": cve_id}

        except ImportError:
            return {"error": "aiohttp未安装，无法查询NVD API", "cve_id": cve_id, "local_data": local_result}
        except Exception as e:
            log.error(f"查询CVE详情失败: {e}")
            return {"error": f"查询失败: {e}", "cve_id": cve_id, "local_data": local_result}

    async def search_cves(self, keyword: str, severity: Optional[str] = None,
                           year: Optional[int] = None, limit: int = 20) -> Dict:
        """
        搜索CVE
        :param keyword: 搜索关键词
        :param severity: 严重度过滤 (LOW/MEDIUM/HIGH/CRITICAL)
        :param year: 年份过滤
        :param limit: 结果数量限制
        :return: 搜索结果
        """
        cache_key = f"{keyword}_{severity}_{year}_{limit}"
        if cache_key in self.CVE_SEARCH_CACHE:
            cached = self.CVE_SEARCH_CACHE[cache_key]
            if time.time() - cached["timestamp"] < self.CACHE_TTL:
                return cached["data"]

        try:
            import aiohttp

            params = {"keywordSearch": keyword, "resultsPerPage": limit}
            if severity:
                params["cvssV3Severity"] = severity.upper()
            if year:
                params["pubStartDate"] = f"{year}-01-01T00:00:00.000"
                params["pubEndDate"] = f"{year}-12-31T23:59:59.999"

            async with aiohttp.ClientSession() as session:
                async with session.get(self.NVD_API_BASE, params=params, timeout=30) as resp:
                    if resp.status == 200:
                        data = await resp.json()
                        parsed = self._parse_nvd_search_response(data)
                        self.CVE_SEARCH_CACHE[cache_key] = {"timestamp": time.time(), "data": parsed}
                        return parsed
                    else:
                        return {"error": f"NVD API返回错误: {resp.status}", "keyword": keyword}

        except ImportError:
            # 回退到本地搜索
            return self._search_local_cves(keyword, severity, year, limit)
        except Exception as e:
            log.error(f"搜索CVE失败: {e}")
            return {"error": f"搜索失败: {e}", "keyword": keyword}

    async def get_cves_by_cwe(self, cwe_id: str, limit: int = 20) -> Dict:
        """根据CWE ID搜索相关CVE"""
        return await self.search_cves(keyword=cwe_id, limit=limit)

    async def get_recent_cves(self, days: int = 7, severity: Optional[str] = None, limit: int = 20) -> Dict:
        """获取最近的CVE"""
        end_date = datetime.now()
        start_date = end_date - timedelta(days=days)

        try:
            import aiohttp

            params = {
                "pubStartDate": start_date.strftime("%Y-%m-%dT00:00:00.000"),
                "pubEndDate": end_date.strftime("%Y-%m-%dT23:59:59.999"),
                "resultsPerPage": limit,
            }
            if severity:
                params["cvssV3Severity"] = severity.upper()

            async with aiohttp.ClientSession() as session:
                async with session.get(self.NVD_API_BASE, params=params, timeout=30) as resp:
                    if resp.status == 200:
                        data = await resp.json()
                        return self._parse_nvd_search_response(data)
                    else:
                        return {"error": f"NVD API返回错误: {resp.status}"}

        except ImportError:
            return {"error": "aiohttp未安装"}
        except Exception as e:
            return {"error": f"查询失败: {e}"}

    # ========== NVD响应解析 ==========

    def _parse_nvd_cve_response(self, data: Dict) -> Optional[Dict]:
        """解析NVD CVE详情响应"""
        try:
            vulnerabilities = data.get("vulnerabilities", [])
            if not vulnerabilities:
                return None

            cve_data = vulnerabilities[0].get("cve", {})
            return self._extract_cve_info(cve_data)
        except Exception as e:
            log.error(f"解析NVD CVE响应失败: {e}")
            return None

    def _parse_nvd_search_response(self, data: Dict) -> Dict:
        """解析NVD搜索响应"""
        result = {
            "total_results": data.get("totalResults", 0),
            "results_per_page": data.get("resultsPerPage", 0),
            "start_index": data.get("startIndex", 0),
            "cves": [],
        }

        vulnerabilities = data.get("vulnerabilities", [])
        for vuln in vulnerabilities:
            cve_data = vuln.get("cve", {})
            cve_info = self._extract_cve_info(cve_data)
            if cve_info:
                result["cves"].append(cve_info)

        return result

    def _extract_cve_info(self, cve_data: Dict) -> Optional[Dict]:
        """从CVE数据中提取关键信息"""
        try:
            cve_id = cve_data.get("id", "")
            published = cve_data.get("published", "")
            last_modified = cve_data.get("lastModified", "")
            status = cve_data.get("vulnStatus", "")

            # 描述
            descriptions = cve_data.get("descriptions", [])
            description = ""
            for desc in descriptions:
                if desc.get("lang") == "en":
                    description = desc.get("value", "")
                    break

            # CVSS评分
            cvss_metrics = cve_data.get("metrics", {})
            cvss_v3 = cvss_metrics.get("cvssMetricV31", []) or cvss_metrics.get("cvssMetricV30", [])
            cvss_v2 = cvss_metrics.get("cvssMetricV2", [])

            cvss_score = None
            cvss_severity = None
            cvss_vector = None
            cvss_version = None

            if cvss_v3:
                cvss_data = cvss_v3[0].get("cvssData", {})
                cvss_score = cvss_data.get("baseScore")
                cvss_severity = cvss_data.get("baseSeverity")
                cvss_vector = cvss_data.get("vectorString")
                cvss_version = cvss_data.get("version", "3.1")
            elif cvss_v2:
                cvss_data = cvss_v2[0].get("cvssData", {})
                cvss_score = cvss_data.get("baseScore")
                cvss_severity = cvss_v2[0].get("baseSeverity", "MEDIUM")
                cvss_vector = cvss_data.get("vectorString")
                cvss_version = "2.0"

            # 弱点类型（CWE）
            weaknesses = cve_data.get("weaknesses", [])
            cwe_ids = []
            for weak in weaknesses:
                for desc in weak.get("description", []):
                    if desc.get("value", "").startswith("CWE-"):
                        cwe_ids.append(desc["value"])

            # 参考链接
            references = cve_data.get("references", [])
            ref_urls = [ref.get("url", "") for ref in references[:10]]

            # 受影响产品
            configurations = cve_data.get("configurations", [])
            affected_products = []
            for config in configurations:
                for node in config.get("nodes", []):
                    for cpe in node.get("cpeMatch", []):
                        if cpe.get("vulnerable"):
                            affected_products.append(cpe.get("criteria", ""))

            return {
                "cve_id": cve_id,
                "description": description,
                "published": published,
                "last_modified": last_modified,
                "status": status,
                "cvss_score": cvss_score,
                "cvss_severity": cvss_severity,
                "cvss_vector": cvss_vector,
                "cvss_version": cvss_version,
                "cwe_ids": cwe_ids,
                "references": ref_urls,
                "affected_products": affected_products[:20],
                "source": "NVD",
            }
        except Exception as e:
            log.error(f"提取CVE信息失败: {e}")
            return None

    # ========== 本地CVE库 ==========

    def _search_local_cve(self, cve_id: str) -> Optional[Dict]:
        """搜索本地CVE库"""
        if isinstance(self._local_cve_db, list):
            for cve in self._local_cve_db:
                if cve.get("cve_id", "").upper() == cve_id.upper():
                    return cve
        elif isinstance(self._local_cve_db, dict):
            return self._local_cve_db.get(cve_id.upper())
        return None

    def _search_local_cves(self, keyword: str, severity: Optional[str] = None,
                            year: Optional[int] = None, limit: int = 20) -> Dict:
        """搜索本地CVE库"""
        results = []
        cve_list = self._local_cve_db if isinstance(self._local_cve_db, list) else list(self._local_cve_db.values())

        for cve in cve_list:
            cve_id = cve.get("cve_id", "").upper()
            desc = cve.get("description", "").lower()

            # 关键词匹配
            if keyword.lower() not in cve_id.lower() and keyword.lower() not in desc:
                continue

            # 严重度过滤
            if severity and cve.get("severity", "").upper() != severity.upper():
                continue

            # 年份过滤
            if year:
                if f"CVE-{year}" not in cve_id:
                    continue

            results.append(cve)
            if len(results) >= limit:
                break

        return {
            "total_results": len(results),
            "cves": results,
            "source": "local_cache",
        }

    def _save_cve_to_cache(self, cve_id: str, data: Dict):
        """保存CVE到本地缓存"""
        try:
            cache_file = os.path.join(self.cache_dir, f"{cve_id}.json")
            with open(cache_file, "w", encoding="utf-8") as f:
                json.dump(data, f, ensure_ascii=False, indent=2)
        except Exception as e:
            log.warning(f"保存CVE缓存失败: {e}")

    # ========== Exploit-DB查询 ==========

    async def search_exploits(self, keyword: str, limit: int = 10) -> Dict:
        """
        搜索Exploit-DB利用代码
        注意：Exploit-DB没有公开API，这里使用模拟数据
        实际使用时建议安装searchsploit工具
        """
        # 检查searchsploit是否可用
        try:
            import shutil
            if shutil.which("searchsploit"):
                return await self._search_with_searchsploit(keyword, limit)
        except:
            pass

        # 返回模拟结果（实际使用时需要真实API或工具）
        return {
            "keyword": keyword,
            "results": [],
            "note": "Exploit-DB搜索需要安装searchsploit工具或使用官方API",
            "install_hint": "apt install exploitdb 或 git clone https://github.com/offensive-security/exploitdb.git",
        }

    async def _search_with_searchsploit(self, keyword: str, limit: int) -> Dict:
        """使用searchsploit工具搜索"""
        try:
            import subprocess
            result = subprocess.run(
                ["searchsploit", keyword, "--json"],
                capture_output=True, text=True, timeout=30
            )
            if result.returncode == 0:
                data = json.loads(result.stdout)
                return {
                    "keyword": keyword,
                    "total": len(data.get("RESULTS_EXPLOIT", [])),
                    "exploits": data.get("RESULTS_EXPLOIT", [])[:limit],
                    "source": "searchsploit",
                }
        except Exception as e:
            log.error(f"searchsploit搜索失败: {e}")

        return {"keyword": keyword, "error": "searchsploit执行失败", "results": []}

    # ========== 漏洞分析 ==========

    def analyze_vulnerability_impact(self, cve_data: Dict) -> Dict:
        """分析漏洞影响"""
        result = {
            "cve_id": cve_data.get("cve_id", ""),
            "severity": cve_data.get("cvss_severity", "UNKNOWN"),
            "cvss_score": cve_data.get("cvss_score"),
            "impact_level": "unknown",
            "exploitability": "unknown",
            "affected_scope": [],
            "remediation_priority": "medium",
        }

        # 影响等级
        score = cve_data.get("cvss_score", 0) or 0
        if score >= 9.0:
            result["impact_level"] = "critical"
            result["remediation_priority"] = "immediate"
        elif score >= 7.0:
            result["impact_level"] = "high"
            result["remediation_priority"] = "high"
        elif score >= 4.0:
            result["impact_level"] = "medium"
            result["remediation_priority"] = "medium"
        else:
            result["impact_level"] = "low"
            result["remediation_priority"] = "low"

        # 可利用性
        description = cve_data.get("description", "").lower()
        if any(kw in description for kw in ["remote code execution", "rce", "arbitrary code"]):
            result["exploitability"] = "critical"
        elif any(kw in description for kw in ["privilege escalation", "authentication bypass"]):
            result["exploitability"] = "high"
        elif any(kw in description for kw in ["denial of service", "dos"]):
            result["exploitability"] = "medium"
        else:
            result["exploitability"] = "low"

        # 受影响范围
        result["affected_scope"] = cve_data.get("affected_products", [])[:10]

        return result

    def generate_remediation_advice(self, cve_data: Dict) -> Dict:
        """生成修复建议"""
        cve_id = cve_data.get("cve_id", "")
        cwe_ids = cve_data.get("cwe_ids", [])
        description = cve_data.get("description", "").lower()

        advice = {
            "cve_id": cve_id,
            "general_advice": [],
            "specific_remediation": [],
            "references": cve_data.get("references", [])[:5],
        }

        # 通用建议
        advice["general_advice"] = [
            "及时更新受影响的软件到最新版本",
            "监控厂商安全公告，获取补丁信息",
            "限制受影响系统的网络访问，减少攻击面",
            "部署WAF/IPS规则，拦截相关攻击",
            "定期进行漏洞扫描，确认修复效果",
        ]

        # 特定CWE的修复建议
        cwe_remediation = {
            "CWE-89": "使用参数化查询/预编译语句，避免拼接SQL",
            "CWE-79": "对用户输入进行HTML转义，使用CSP策略",
            "CWE-22": "规范化路径，限制在允许的目录范围内",
            "CWE-78": "避免使用系统命令，使用安全的API替代",
            "CWE-352": "使用CSRF Token，验证Referer/Origin头",
            "CWE-287": "实施强认证机制，使用多因素认证",
            "CWE-862": "实施严格的访问控制，验证用户权限",
            "CWE-200": "最小化信息泄露，错误信息不暴露内部细节",
            "CWE-400": "实施资源限制，防止资源耗尽攻击",
            "CWE-918": "限制出站请求，使用白名单，禁止访问内网",
        }

        for cwe in cwe_ids:
            if cwe in cwe_remediation:
                advice["specific_remediation"].append({
                    "cwe": cwe,
                    "advice": cwe_remediation[cwe],
                })

        # 根据描述添加特定建议
        if "sql injection" in description:
            advice["specific_remediation"].append({"type": "sql_injection", "advice": "使用ORM或参数化查询，输入验证和转义"})
        if "cross-site scripting" in description or "xss" in description:
            advice["specific_remediation"].append({"type": "xss", "advice": "输出编码，CSP策略，HttpOnly Cookie"})
        if "buffer overflow" in description:
            advice["specific_remediation"].append({"type": "buffer_overflow", "advice": "使用安全函数，边界检查，ASLR/DEP保护"})

        return advice

    # ========== 统计和状态 ==========

    def get_stats(self) -> Dict:
        """获取漏洞情报模块统计"""
        return {
            "local_cve_count": len(self._local_cve_db) if isinstance(self._local_cve_db, list) else len(self._local_cve_db),
            "cached_cve_details": len(self.CVE_DETAILS_CACHE),
            "cached_searches": len(self.CVE_SEARCH_CACHE),
            "cache_ttl": self.CACHE_TTL,
            "cache_dir": self.cache_dir,
            "sources": ["NVD API", "本地CVE库", "Exploit-DB (searchsploit)"],
        }


# 全局单例
vuln_intel = VulnIntel()
