#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
nvd_sync知识库模块，存储和管理相关安全知识、漏洞信息和攻击链数据。

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
from typing import Any, Dict, List, Optional
from loguru import logger
from .vuln_database import VulnDatabase, Vulnerability, get_vuln_db


class NVDSync:
    """NVD漏洞数据同步器"""

    NVD_API_BASE = "https://services.nvd.nist.gov/rest/json/cves/2.0"
    NVD_CPE_API = "https://services.nvd.nist.gov/rest/json/cpes/2.0"
    REQUEST_DELAY = 6.0  # NVD API限制: 无密钥5次/30秒，有密钥50次/30秒
    RESULTS_PER_PAGE = 2000

    def __init__(self, db: Optional[VulnDatabase] = None, api_key: str = ""):
        """初始化NVDSync实例。

        Args:
            self: 类实例。
        """
        self.db = db or get_vuln_db()
        self.api_key = api_key
        self.session: Optional[aiohttp.ClientSession] = None
        self.stats = {"synced": 0, "added": 0, "updated": 0, "errors": 0}

    def _get_headers(self) -> Dict[str, str]:
        """获取相关数据。

        Returns:
            操作结果。
        """
        headers = {"Content-Type": "application/json"}
        if self.api_key:
            headers["apiKey"] = self.api_key
        return headers

    def _parse_severity(self, cvss_data: Dict[str, Any]) -> tuple:
        """解析CVSS数据，返回(severity, score, vector)"""
        if not cvss_data:
            return "medium", 0.0, ""

        # 优先使用CVSS v3.1，然后v3.0，最后v2
        for version in ["cvssMetricV31", "cvssMetricV30", "cvssMetricV2"]:
            if version in cvss_data and cvss_data[version]:
                metric = cvss_data[version][0]
                cvss = metric.get("cvssData", {})
                score = cvss.get("baseScore", 0.0)
                vector = cvss.get("vectorString", "")
                severity = metric.get("baseSeverity", cvss.get("baseSeverity", "medium")).lower()
                return severity, score, vector

        return "medium", 0.0, ""

    def _parse_cve_item(self, item: Dict[str, Any]) -> Optional[Vulnerability]:
        """解析NVD CVE数据项"""
        try:
            cve = item.get("cve", item)
            cve_id = cve.get("id", "")
            if not cve_id:
                return None

            # 描述（优先英文）
            descriptions = cve.get("descriptions", [])
            en_desc = next((d for d in descriptions if d.get("lang") == "en"), None)
            description = en_desc.get("value", "") if en_desc else (descriptions[0].get("value", "") if descriptions else "")

            # 标题（取描述前100字符作为标题）
            title = description[:100] + "..." if len(description) > 100 else description

            # CVSS
            metrics = cve.get("metrics", {})
            severity, cvss_score, cvss_vector = self._parse_severity(metrics)

            # CWE
            weaknesses = cve.get("weaknesses", [])
            cwe_ids = []
            for w in weaknesses:
                for desc in w.get("description", []):
                    cwe_id = desc.get("value", "")
                    if cwe_id.startswith("CWE-"):
                        cwe_ids.append(cwe_id)

            # 参考链接
            references = cve.get("references", [])
            ref_urls = [r.get("url", "") for r in references if r.get("url")]

            # 厂商/产品（从CPE配置中提取）
            vendor = ""
            product = ""
            configurations = cve.get("configurations", [])
            for config in configurations:
                for node in config.get("nodes", []):
                    for cpe_match in node.get("cpeMatch", []):
                        criteria = cpe_match.get("criteria", "")
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
            published = cve.get("published", "")[:10]
            last_modified = cve.get("lastModified", "")[:10]

            # 标签
            tags = []
            if cvss_score >= 9.0:
                tags.append("critical")
            elif cvss_score >= 7.0:
                tags.append("high")
            if "rce" in description.lower() or "remote code" in description.lower():
                tags.append("rce")
            if "sql" in description.lower():
                tags.append("sql-injection")
            if "xss" in description.lower() or "cross-site" in description.lower():
                tags.append("xss")

            return Vulnerability(
                cve_id=cve_id,
                title=title,
                description=description,
                severity=severity,
                cvss_score=cvss_score,
                cvss_vector=cvss_vector,
                published_date=published,
                last_modified=last_modified,
                vendor=vendor,
                product=product,
                cwe_ids=cwe_ids,
                references=ref_urls[:20],  # 限制参考链接数量
                tags=list(set(tags)),
                source="nvd",
            )
        except Exception as e:
            logger.error(f"解析CVE项失败: {e}")
            return None

    async def _fetch_page(self, params: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        """获取单页数据"""
        try:
            if not self.session:
                timeout = aiohttp.ClientTimeout(total=60)
                self.session = aiohttp.ClientSession(timeout=timeout)

            async with self.session.get(
                self.NVD_API_BASE,
                params=params,
                headers=self._get_headers()
            ) as response:
                if response.status == 200:
                    return await response.json()
                elif response.status == 403:
                    logger.warning("NVD API限流，等待后重试...")
                    await asyncio.sleep(self.REQUEST_DELAY * 2)
                    return await self._fetch_page(params)
                else:
                    logger.error(f"NVD API错误: {response.status}")
                    self.stats["errors"] += 1
                    return None
        except Exception as e:
            logger.error(f"获取NVD数据失败: {e}")
            self.stats["errors"] += 1
            return None

    async def sync_by_date_range(self, start_date: str, end_date: str,
                                   max_results: int = 10000) -> Dict[str, Any]:
        """按日期范围同步漏洞"""
        logger.info(f"开始同步NVD数据: {start_date} 至 {end_date}")
        self.stats = {"synced": 0, "added": 0, "updated": 0, "errors": 0}

        start_index = 0
        while True:
            params = {
                "pubStartDate": f"{start_date}T00:00:00.000",
                "pubEndDate": f"{end_date}T23:59:59.999",
                "resultsPerPage": self.RESULTS_PER_PAGE,
                "startIndex": start_index,
            }

            data = await self._fetch_page(params)
            if not data:
                break

            total = data.get("totalResults", 0)
            vulnerabilities = data.get("vulnerabilities", [])

            if not vulnerabilities:
                break

            for item in vulnerabilities:
                vuln = self._parse_cve_item(item)
                if vuln:
                    is_new = self.db.add(vuln)
                    if is_new:
                        self.stats["added"] += 1
                    else:
                        self.stats["updated"] += 1
                    self.stats["synced"] += 1

            logger.info(f"同步进度: {self.stats['synced']}/{total} (新增{self.stats['added']})")

            start_index += len(vulnerabilities)
            if start_index >= total or self.stats["synced"] >= max_results:
                break

            # NVD API限流
            await asyncio.sleep(self.REQUEST_DELAY)

        # 保存
        self.db._save()
        self.db.last_sync["nvd"] = datetime.now().isoformat()

        logger.info(f"NVD同步完成: {self.stats}")
        return self.stats

    async def sync_recent(self, days: int = 30, max_results: int = 5000) -> Dict[str, Any]:
        """同步最近N天的漏洞"""
        end_date = datetime.now().strftime("%Y-%m-%d")
        start_date = (datetime.now() - timedelta(days=days)).strftime("%Y-%m-%d")
        return await self.sync_by_date_range(start_date, end_date, max_results)

    async def sync_full(self, max_results: int = 50000) -> Dict[str, Any]:
        """全量同步（从2000年开始）"""
        logger.info("开始NVD全量同步（这可能需要较长时间）")
        # 按年份分批同步
        all_stats = {"synced": 0, "added": 0, "updated": 0, "errors": 0}
        current_year = datetime.now().year

        for year in range(2000, current_year + 1):
            start_date = f"{year}-01-01"
            end_date = f"{year}-12-31"
            logger.info(f"同步年份: {year}")

            year_stats = await self.sync_by_date_range(start_date, end_date, max_results)
            for k in all_stats:
                all_stats[k] += year_stats.get(k, 0)

            if all_stats["synced"] >= max_results:
                break

        if self.session:
            await self.session.close()
            self.session = None

        return all_stats

    async def sync_incremental(self) -> Dict[str, Any]:
        """增量同步（自上次同步以来）"""
        last_sync = self.db.last_sync.get("nvd", "")
        if last_sync:
            start_date = last_sync[:10]
        else:
            start_date = (datetime.now() - timedelta(days=7)).strftime("%Y-%m-%d")

        end_date = datetime.now().strftime("%Y-%m-%d")
        return await self.sync_by_date_range(start_date, end_date)

    async def close(self):
        """关闭会话"""
        if self.session:
            await self.session.close()
            self.session = None


def run_nvd_sync(days: int = 30, api_key: str = "") -> Dict[str, Any]:
    """运行NVD同步（同步入口）"""
    sync = NVDSync(api_key=api_key)
    try:
        result = asyncio.run(sync.sync_recent(days=days))
        return result
    finally:
        asyncio.run(sync.close())


if __name__ == "__main__":
    import sys
    days = int(sys.argv[1]) if len(sys.argv) > 1 else 30
    print(f"开始同步最近 {days} 天的NVD漏洞数据...")
    result = run_nvd_sync(days)
    print(f"同步完成: {result}")
