"""
vuln_intel_enhanced安全工具集成模块，提供相关安全工具的封装和调用。

模块功能：
    - 提供相关安全测试功能
    - 支持API调用和命令行使用
    - 与其他模块集成协作

注意事项：
    - 本模块仅用于授权的安全测试
    - 请勿用于非法用途
    - 使用前请确保已获得相关授权
"""
import asyncio
import json
from typing import Optional, List, Dict, Any
from datetime import datetime, timedelta
import aiohttp
from utils.logger import log


class VulnIntelEnhanced:
    """增强漏洞情报管理器"""

    # API端点配置
    VULNERS_API = "https://vulners.com/api/v3"
    GITHUB_ADVISORIES_API = "https://api.github.com/advisories"
    OSS_FUCH_API = "https://oss-fuzz.com/api/v1"
    EXPLOIT_DB_API = "https://www.exploit-db.com/api"

    def __init__(self, vulners_api_key: str = None, github_token: str = None):
        """初始化VulnIntelEnhanced实例。

        Args:
            self: 类实例。
        """
        self.vulners_api_key = vulners_api_key
        self.github_token = github_token
        self._cache = {}
        self._cache_ttl = 3600  # 1小时缓存

    async def _make_request(self, url: str, headers: dict = None,
                            params: dict = None, timeout: int = 30) -> Optional[dict]:
        """异步HTTP请求"""
        try:
            async with aiohttp.ClientSession() as session:
                async with session.get(url, headers=headers, params=params, timeout=timeout) as resp:
                    if resp.status == 200:
                        return await resp.json()
                    else:
                        log.warning(f"API请求失败 {url}: {resp.status}")
                        return None
        except Exception as e:
            log.error(f"API请求异常 {url}: {e}")
            return None

    # ==================== Vulners API ====================

    async def search_vulners(self, query: str, limit: int = 20) -> List[dict]:
        """通过Vulners API搜索漏洞"""
        if not self.vulners_api_key:
            log.warning("Vulners API密钥未配置")
            return []

        cache_key = f"vulners:{query}:{limit}"
        if cache_key in self._cache:
            cached = self._cache[cache_key]
            if (datetime.now() - cached['time']).seconds < self._cache_ttl:
                return cached['data']

        url = f"{self.VULNERS_API}/search/lucene"
        headers = {"Content-Type": "application/json"}
        data = {
            "query": query,
            "size": limit,
            "apiKey": self.vulners_api_key,
        }

        try:
            async with aiohttp.ClientSession() as session:
                async with session.post(url, headers=headers, json=data, timeout=30) as resp:
                    if resp.status == 200:
                        result = await resp.json()
                        vulnerabilities = []
                        if result.get("result") == "OK":
                            for item in result.get("data", {}).get("search", []):
                                vuln = {
                                    "id": item.get("_id"),
                                    "title": item.get("_source", {}).get("title"),
                                    "description": item.get("_source", {}).get("description"),
                                    "severity": item.get("_source", {}).get("cvss", {}).get("severity", "unknown"),
                                    "cvss_score": item.get("_source", {}).get("cvss", {}).get("score"),
                                    "published": item.get("_source", {}).get("published"),
                                    "type": item.get("_type"),
                                    "source": "vulners",
                                }
                                vulnerabilities.append(vuln)

                        self._cache[cache_key] = {"data": vulnerabilities, "time": datetime.now()}
                        return vulnerabilities
                    return []
        except Exception as e:
            log.error(f"Vulners搜索失败: {e}")
            return []

    async def get_vulners_cve(self, cve_id: str) -> Optional[dict]:
        """通过Vulners获取CVE详情"""
        results = await self.search_vulners(cve_id, limit=1)
        return results[0] if results else None

    # ==================== GitHub Security Advisories ====================

    async def get_github_advisories(self, ecosystem: str = None,
                                      severity: str = None,
                                      limit: int = 20) -> List[dict]:
        """获取GitHub安全公告"""
        params = {"per_page": limit}
        if ecosystem:
            params["ecosystem"] = ecosystem
        if severity:
            params["severity"] = severity

        headers = {"Accept": "application/vnd.github+json"}
        if self.github_token:
            headers["Authorization"] = f"Bearer {self.github_token}"

        result = await self._make_request(self.GITHUB_ADVISORIES_API, headers=headers, params=params)
        if not result:
            return []

        advisories = []
        for item in result:
            advisory = {
                "id": item.get("ghsa_id"),
                "cve_id": item.get("cve_id"),
                "title": item.get("summary"),
                "description": item.get("description"),
                "severity": item.get("severity"),
                "ecosystem": item.get("ecosystem"),
                "published_at": item.get("published_at"),
                "updated_at": item.get("updated_at"),
                "references": [r.get("url") for r in item.get("references", [])],
                "source": "github_advisories",
            }
            advisories.append(advisory)

        return advisories

    # ==================== 多数据源聚合搜索 ====================

    async def search_all_sources(self, query: str, limit: int = 20) -> Dict[str, Any]:
        """多数据源聚合搜索"""
        log.info(f"多数据源搜索: {query}")

        results = {
            "query": query,
            "timestamp": datetime.now().isoformat(),
            "sources": {},
            "total_results": 0,
            "all_results": [],
        }

        # 并行搜索多个数据源
        tasks = []
        if self.vulners_api_key:
            tasks.append(("vulners", self.search_vulners(query, limit)))

        tasks.append(("github_advisories", self.get_github_advisories(limit=limit)))

        # 执行并行搜索
        task_results = await asyncio.gather(*[t[1] for t in tasks], return_exceptions=True)

        for (source_name, _), result in zip(tasks, task_results):
            if isinstance(result, Exception):
                log.error(f"数据源 {source_name} 搜索失败: {result}")
                results["sources"][source_name] = {"count": 0, "error": str(result)}
            else:
                results["sources"][source_name] = {"count": len(result)}
                results["all_results"].extend(result)

        results["total_results"] = len(results["all_results"])

        # 按严重度排序
        severity_order = {"critical": 0, "high": 1, "medium": 2, "low": 3, "unknown": 4}
        results["all_results"].sort(key=lambda x: severity_order.get(x.get("severity", "unknown"), 4))

        return results

    # ==================== 漏洞利用代码搜索 ====================

    async def search_exploits(self, query: str, limit: int = 10) -> List[dict]:
        """搜索漏洞利用代码"""
        # 通过Vulners搜索exploit类型
        if self.vulners_api_key:
            exploit_query = f"type:exploit AND {query}"
            return await self.search_vulners(exploit_query, limit)
        return []

    # ==================== 统计和报告 ====================

    def get_config_status(self) -> dict:
        """获取配置状态"""
        return {
            "vulners_api_configured": bool(self.vulners_api_key),
            "github_token_configured": bool(self.github_token),
            "cache_size": len(self._cache),
            "cache_ttl": self._cache_ttl,
            "supported_sources": ["vulners", "github_advisories", "exploit_db"],
        }


# 全局增强情报实例（需要配置API密钥后使用）
vuln_intel_enhanced = VulnIntelEnhanced()
