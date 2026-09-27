#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
vulners_api知识库模块，存储和管理相关安全知识、漏洞信息和攻击链数据。

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
import asyncio
import aiohttp
from datetime import datetime, timedelta
from typing import Any, Dict, List, Optional, Tuple
from loguru import logger
from .vuln_database import VulnDatabase, Vulnerability, get_vuln_db


class VulnersAPI:
    """Vulners API客户端"""

    API_BASE = "https://vulners.com/api/v3"
    SEARCH_ENDPOINT = "/search/lucene"
    BULLETIN_ENDPOINT = "/search/id"
    SOFTWARE_ENDPOINT = "/audit/software"
    REQUEST_DELAY = 1.0

    def __init__(self, api_key: str = "", db: Optional[VulnDatabase] = None):
        """初始化VulnersAPI实例。

        Args:
            self: 类实例。
        """
        self.api_key = api_key
        self.db = db or get_vuln_db()
        self.session: Optional[aiohttp.ClientSession] = None
        self.stats = {"queries": 0, "found": 0, "errors": 0}

    def _get_headers(self) -> Dict[str, str]:
        """获取相关数据。

        Returns:
            操作结果。
        """
        return {
            "Content-Type": "application/json",
            "User-Agent": "AI-Hacking-Agent/1.0",
        }

    async def _get_session(self) -> aiohttp.ClientSession:
        if not self.session:
            timeout = aiohttp.ClientTimeout(total=30)
            self.session = aiohttp.ClientSession(timeout=timeout)
        return self.session

    async def search(self, query: str, limit: int = 20,
                     offset: int = 0) -> List[Dict[str, Any]]:
        """
        Lucene语法搜索漏洞
        示例查询:
          - "type:cve AND severity:critical"
          - "affectedSoftware.name:apache AND affectedSoftware.version:2.4.49"
          - "cve:CVE-2021-44228"
        """
        results = []
        try:
            session = await self._get_session()
            payload = {
                "query": query,
                "size": limit,
                "offset": offset,
            }
            if self.api_key:
                payload["apiKey"] = self.api_key

            async with session.post(
                f"{self.API_BASE}{self.SEARCH_ENDPOINT}",
                json=payload,
                headers=self._get_headers()
            ) as resp:
                self.stats["queries"] += 1
                if resp.status == 200:
                    data = await resp.json()
                    if data.get("result") == "OK":
                        for item in data.get("data", {}).get("search", []):
                            results.append(item.get("_source", item))
                        self.stats["found"] += len(results)
                    else:
                        logger.error(f"Vulners搜索错误: {data.get('data', {}).get('error', 'unknown')}")
                        self.stats["errors"] += 1
                else:
                    logger.error(f"Vulners API HTTP错误: {resp.status}")
                    self.stats["errors"] += 1

        except Exception as e:
            logger.error(f"Vulners搜索失败: {e}")
            self.stats["errors"] += 1

        return results

    async def get_bulletin(self, vuln_id: str) -> Optional[Dict[str, Any]]:
        """获取单个漏洞公告详情（CVE/KB/安全公告等）"""
        try:
            session = await self._get_session()
            payload = {"id": vuln_id}
            if self.api_key:
                payload["apiKey"] = self.api_key

            async with session.post(
                f"{self.API_BASE}{self.BULLETIN_ENDPOINT}",
                json=payload,
                headers=self._get_headers()
            ) as resp:
                self.stats["queries"] += 1
                if resp.status == 200:
                    data = await resp.json()
                    if data.get("result") == "OK":
                        return data.get("data", {}).get("document", {})
        except Exception as e:
            logger.error(f"获取漏洞公告失败: {e}")
            self.stats["errors"] += 1
        return None

    async def check_software(self, software: str, version: str,
                               os_type: str = "") -> List[Dict[str, Any]]:
        """检查软件版本是否存在已知漏洞"""
        query = f"affectedSoftware.name:\"{software}\" AND affectedSoftware.version:\"{version}\""
        if os_type:
            query += f" AND affectedSoftware.OS:\"{os_type}\""
        return await self.search(query, limit=50)

    async def get_cve_details(self, cve_id: str) -> Optional[Dict[str, Any]]:
        """获取CVE详细信息（整合多源数据）"""
        bulletin = await self.get_bulletin(cve_id)
        if bulletin:
            return bulletin

        # 如果直接查询失败，用搜索
        results = await self.search(f"id:{cve_id} OR cve:{cve_id}", limit=1)
        if results:
            return results[0]
        return None

    def _parse_vulners_to_vuln(self, data: Dict[str, Any]) -> Optional[Vulnerability]:
        """将Vulners数据解析为Vulnerability对象"""
        try:
            cve_id = data.get("id", "")
            if not cve_id.startswith("CVE-"):
                # 尝试从cvelist中提取
                cve_list = data.get("cvelist", [])
                if cve_list:
                    cve_id = cve_list[0]
                else:
                    return None

            title = data.get("title", data.get("description", "")[:100])
            description = data.get("description", "")

            # 严重程度
            severity = data.get("cvss2", {}).get("severity",
                        data.get("cvss3", {}).get("severity", "medium")).lower()
            cvss_score = data.get("cvss3", {}).get("score",
                         data.get("cvss2", {}).get("score", 0.0))

            # 参考链接
            references = data.get("references", [])
            if isinstance(references, dict):
                references = list(references.values())

            # 受影响软件
            affected = data.get("affectedSoftware", [])
            vendor = ""
            product = ""
            versions = []
            if affected:
                first = affected[0] if isinstance(affected, list) else list(affected.values())[0]
                vendor = first.get("vendor", "")
                product = first.get("name", "")
                versions = [first.get("version", "")]

            # 标签
            tags = data.get("tags", [])
            if isinstance(tags, str):
                tags = [tags]

            return Vulnerability(
                cve_id=cve_id,
                title=title,
                description=description,
                severity=severity,
                cvss_score=float(cvss_score) if cvss_score else 0.0,
                published_date=data.get("published", "")[:10],
                last_modified=data.get("modified", "")[:10],
                vendor=vendor,
                product=product,
                references=references[:20] if isinstance(references, list) else [],
                affected_versions=versions,
                tags=tags if isinstance(tags, list) else [],
                source="vulners",
            )
        except Exception as e:
            logger.error(f"解析Vulners数据失败: {e}")
            return None

    async def sync_to_db(self, query: str = "type:cve",
                           max_results: int = 1000) -> Dict[str, Any]:
        """同步Vulners数据到本地漏洞库"""
        stats = {"queried": 0, "parsed": 0, "added": 0, "errors": 0}
        offset = 0
        batch_size = 100

        while stats["queried"] < max_results:
            results = await self.search(query, limit=batch_size, offset=offset)
            if not results:
                break

            for item in results:
                stats["queried"] += 1
                vuln = self._parse_vulners_to_vuln(item)
                if vuln:
                    stats["parsed"] += 1
                    if self.db.add(vuln):
                        stats["added"] += 1

            logger.info(f"Vulners同步进度: {stats['queried']} 查询, {stats['added']} 新增")
            offset += batch_size

            if len(results) < batch_size:
                break

            await asyncio.sleep(self.REQUEST_DELAY)

        self.db._save()
        self.db.last_sync["vulners"] = datetime.now().isoformat()
        logger.info(f"Vulners同步完成: {stats}")
        return stats

    async def enrich_cve(self, cve_id: str) -> bool:
        """用Vulners数据丰富单个CVE的信息"""
        try:
            details = await self.get_cve_details(cve_id)
            if details:
                vuln = self._parse_vulners_to_vuln(details)
                if vuln:
                    self.db.add(vuln)
                    self.db._save()
                    return True
        except Exception as e:
            logger.error(f"丰富CVE {cve_id} 失败: {e}")
        return False

    def get_stats(self) -> Dict[str, Any]:
        """获取相关数据。

        Returns:
            操作结果。
        """
        return {
            **self.stats,
            "api_key_configured": bool(self.api_key),
            "api_base": self.API_BASE,
        }

    async def close(self):
        if self.session:
            await self.session.close()
            self.session = None


def run_vulners_sync(query: str = "type:cve AND severity:critical",
                      max_results: int = 500, api_key: str = "") -> Dict[str, Any]:
    """运行Vulners同步"""
    vulners = VulnersAPI(api_key=api_key)
    try:
        return asyncio.run(vulners.sync_to_db(query=query, max_results=max_results))
    finally:
        asyncio.run(vulners.close())


if __name__ == "__main__":
    import sys
    query = sys.argv[1] if len(sys.argv) > 1 else "type:cve AND severity:critical"
    max_results = int(sys.argv[2]) if len(sys.argv) > 2 else 500
    print(f"开始同步Vulners: query={query}, max={max_results}")
    result = run_vulners_sync(query, max_results)
    print(f"同步完成: {result}")
