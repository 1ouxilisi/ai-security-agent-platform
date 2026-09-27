#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
vuln_db_sync 模块，提供漏洞库实时同步。

模块功能：
    - 从 NVD API 2.0 同步 CVE（描述/CVSS/CWE/参考链接）
    - 从 CNVD RSS 同步国内漏洞通告
    - 本地漏洞库按年份分文件存储 + 索引
    - 支持增量同步、本地搜索、统计
    - NVD 无 API Key 时遵守 6 秒/请求的速率限制

注意事项：
    - 本模块仅用于授权的安全运营场景
    - 请勿用于非法用途
    - 使用前请确保已获得相关授权
"""

import json
import os
import time
import xml.etree.ElementTree as ET
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

import requests

try:
    from loguru import logger
except ImportError:
    import logging
    logger = logging.getLogger(__name__)


PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
VULN_DB_DIR = os.path.join(PROJECT_ROOT, "data", "vuln_db")
INDEX_PATH = os.path.join(VULN_DB_DIR, "index.json")

NVD_API = "https://services.nvd.nist.gov/rest/json/cves/2.0"
CNVD_RSS = "https://www.cnvd.org.cn/rss.xml"
NVD_RATE_LIMIT_SEC = 6.0  # 无 API Key 时 NVD 要求 6 秒/请求


def _now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def _year_of(cve_id: str) -> str:
    """从 CVE ID 提取年份，如 CVE-2024-1234 -> 2024。"""
    parts = (cve_id or "").split("-")
    if len(parts) >= 2 and parts[1].isdigit():
        return parts[1]
    return "unknown"


class VulnDBSync:
    """漏洞库同步器。"""

    def __init__(self, db_dir: str = VULN_DB_DIR):
        """初始化，创建目录并加载索引。"""
        self.db_dir = db_dir
        os.makedirs(self.db_dir, exist_ok=True)
        self.index: Dict[str, Any] = self._load_index()

    # ==================== 本地存储 ====================

    def _load_index(self) -> Dict[str, Any]:
        """加载索引文件。"""
        default = {"last_sync": None, "total": 0, "by_year": {}, "by_severity": {}}
        try:
            if os.path.exists(INDEX_PATH):
                with open(INDEX_PATH, "r", encoding="utf-8") as f:
                    return json.load(f)
        except Exception as e:
            logger.warning("漏洞库索引加载失败: %s", e)
        return default

    def _save_index(self) -> None:
        try:
            with open(INDEX_PATH, "w", encoding="utf-8") as f:
                json.dump(self.index, f, ensure_ascii=False, indent=2)
        except Exception as e:
            logger.error("漏洞库索引保存失败: %s", e)

    def _year_path(self, year: str) -> str:
        return os.path.join(self.db_dir, f"{year}.json")

    def _load_year(self, year: str) -> Dict[str, Dict[str, Any]]:
        """加载某一年的 CVE 字典。"""
        path = self._year_path(year)
        try:
            if os.path.exists(path):
                with open(path, "r", encoding="utf-8") as f:
                    return json.load(f).get("cves", {})
        except Exception as e:
            logger.warning("年度库加载失败 %s: %s", path, e)
        return {}

    def _save_year(self, year: str, cves: Dict[str, Dict[str, Any]]) -> None:
        path = self._year_path(year)
        with open(path, "w", encoding="utf-8") as f:
            json.dump({"year": year, "cves": cves}, f, ensure_ascii=False, indent=2)

    def _upsert(self, cve_id: str, record: Dict[str, Any]) -> None:
        """把一条 CVE 写入对应年份文件并更新索引。"""
        year = _year_of(cve_id)
        bucket = self._load_year(year)
        is_new = cve_id not in bucket
        record["last_updated"] = _now_iso()
        bucket[cve_id] = record
        self._save_year(year, bucket)
        if is_new:
            self.index["total"] = int(self.index.get("total", 0)) + 1
            self.index.setdefault("by_year", {})[year] = \
                int(self.index.get("by_year", {}).get(year, 0)) + 1
        sev = (record.get("severity") or "unknown").lower()
        self.index.setdefault("by_severity", {})
        self.index["by_severity"][sev] = int(self.index["by_severity"].get(sev, 0))

    # ==================== NVD 同步 ====================

    @staticmethod
    def _parse_nvd_item(item: Dict[str, Any]) -> Dict[str, Any]:
        """把 NVD CVE item 归一化为本地记录结构。"""
        cve_id = item.get("id", "")
        descriptions = item.get("descriptions", [])
        desc = next((d["value"] for d in descriptions if d.get("lang") == "en"), "")
        # CVSS 指标
        metrics = item.get("metrics", {})
        severity = "unknown"
        cvss_score = None
        for key in ("cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
            if metrics.get(key):
                md = metrics[key][0]
                cvss_data = md.get("cvssData", {})
                severity = cvss_data.get("baseSeverity") or md.get("baseSeverity") or "unknown"
                cvss_score = cvss_data.get("baseScore")
                break
        # CWE
        cwes = []
        for node in item.get("weaknesses", []):
            for desc_item in node.get("description", []):
                if desc_item.get("value"):
                    cwes.append(desc_item["value"])
        refs = [r.get("url") for r in item.get("references", []) if r.get("url")]
        return {
            "cve_id": cve_id,
            "description": desc,
            "severity": severity.lower(),
            "cvss_score": cvss_score,
            "cwe": cwes,
            "references": refs,
            "published": item.get("published"),
            "source": "nvd",
        }

    def sync_nvd(self, keyword: Optional[str] = None, cve_id: Optional[str] = None,
                 start_date: Optional[str] = None, max_results: int = 100,
                 sleep_between: bool = True) -> Dict[str, Any]:
        """从 NVD API 2.0 同步 CVE。

        Args:
            keyword: 关键字搜索
            cve_id: 指定单个 CVE
            start_date: ISO 时间，增量同步起始时间
            max_results: 最多拉取条数
            sleep_between: 是否在请求间 sleep 6 秒（遵守速率限制）
        """
        params: Dict[str, Any] = {"resultsPerPage": min(max_results, 2000)}
        if cve_id:
            params["cveId"] = cve_id
        elif keyword:
            params["keywordSearch"] = keyword
        if start_date:
            params["pubStartDate"] = start_date
            params["pubEndDate"] = _now_iso()
        try:
            if sleep_between:
                time.sleep(NVD_RATE_LIMIT_SEC)
            resp = requests.get(NVD_API, params=params, timeout=20,
                                headers={"User-Agent": "AIHackingAgent/1.0"})
            data = resp.json()
        except Exception as e:
            logger.error("NVD 同步请求失败: %s", e)
            return {"success": False, "message": f"NVD 请求失败: {e}", "synced": 0}

        vulns = data.get("vulnerabilities", [])
        synced = 0
        for v in vulns:
            rec = self._parse_nvd_item(v.get("cve", {}))
            if rec.get("cve_id"):
                self._upsert(rec["cve_id"], rec)
                synced += 1
        self.index["last_sync"] = _now_iso()
        self._save_index()
        return {"success": True, "synced": synced,
                "total_results": data.get("totalResults", synced),
                "last_sync": self.index["last_sync"]}

    # ==================== CNVD 同步 ====================

    def sync_cnvd(self, max_results: int = 50) -> Dict[str, Any]:
        """解析 CNVD RSS 获取国内漏洞通告。"""
        try:
            resp = requests.get(CNVD_RSS, timeout=20,
                                headers={"User-Agent": "AIHackingAgent/1.0"})
            root = ET.fromstring(resp.content)
        except Exception as e:
            logger.error("CNVD RSS 拉取失败: %s", e)
            return {"success": False, "message": f"CNVD 拉取失败: {e}", "synced": 0}

        synced = 0
        for item in root.iter("item"):
            if synced >= max_results:
                break
            title = (item.findtext("title") or "").strip()
            link = (item.findtext("link") or "").strip()
            pub = (item.findtext("pubDate") or "").strip()
            desc = (item.findtext("description") or "").strip()
            # 从标题中提取 CNVD-ID（如 CNVD-2024-12345）
            cve_like = title.split(" ")[0] if title else f"CNVD-{synced}"
            cve_like = cve_like if cve_like.upper().startswith("CNVD") else f"CNVD-{synced}"
            record = {
                "cve_id": cve_like,
                "title": title,
                "description": desc,
                "severity": "medium",
                "references": [link],
                "published": pub,
                "source": "cnvd",
            }
            # CNVD 记录归入 cnvd.json
            year = "cnvd"
            bucket = self._load_year(year)
            bucket[cve_like] = record
            self._save_year(year, bucket)
            synced += 1
        self.index["last_sync"] = _now_iso()
        self._save_index()
        return {"success": True, "synced": synced, "last_sync": self.index["last_sync"]}

    # ==================== 查询 ====================

    def get_cve_detail(self, cve_id: str) -> Dict[str, Any]:
        """根据 CVE ID 查询本地详情。"""
        year = _year_of(cve_id)
        bucket = self._load_year(year)
        rec = bucket.get(cve_id)
        if rec:
            return {"found": True, "cve": rec}
        # 兜底：扫描全部年份文件
        for fname in os.listdir(self.db_dir):
            if fname.endswith(".json") and fname != "index.json":
                bucket = self._load_year(fname[:-5])
                if cve_id in bucket:
                    return {"found": True, "cve": bucket[cve_id]}
        return {"found": False, "cve_id": cve_id, "message": "本地库未收录"}

    def search_local(self, keyword: str,
                     severity: Optional[str] = None) -> Dict[str, Any]:
        """在本地库按关键字搜索（空库不报错）。"""
        results: List[Dict[str, Any]] = []
        kw = (keyword or "").lower()
        for fname in os.listdir(self.db_dir):
            if not fname.endswith(".json") or fname == "index.json":
                continue
            try:
                bucket = self._load_year(fname[:-5])
            except Exception:
                continue
            for cve_id, rec in bucket.items():
                if severity and (rec.get("severity") or "").lower() != severity.lower():
                    continue
                haystack = " ".join([
                    cve_id, rec.get("description", ""), rec.get("title", ""),
                    " ".join(rec.get("cwe", [])),
                ]).lower()
                if not kw or kw in haystack:
                    results.append({
                        "cve_id": cve_id,
                        "title": rec.get("title") or rec.get("description", "")[:80],
                        "severity": rec.get("severity", "unknown"),
                        "cvss_score": rec.get("cvss_score"),
                        "source": rec.get("source", "nvd"),
                    })
        results.sort(key=lambda x: (x.get("cvss_score") or 0), reverse=True)
        return {"keyword": keyword, "total": len(results), "results": results[:100]}

    # ==================== 同步状态 / 增量 / 统计 ====================

    def get_sync_status(self) -> Dict[str, Any]:
        """返回同步状态。"""
        return {
            "last_sync": self.index.get("last_sync"),
            "total_cves": self.index.get("total", 0),
            "by_year": self.index.get("by_year", {}),
        }

    def get_stats(self) -> Dict[str, Any]:
        """返回本地库统计。"""
        # 实时扫描年度文件以保证准确
        by_year: Dict[str, int] = {}
        by_severity: Dict[str, int] = {}
        total = 0
        for fname in os.listdir(self.db_dir):
            if not fname.endswith(".json") or fname == "index.json":
                continue
            bucket = self._load_year(fname[:-5])
            year = fname[:-5]
            by_year[year] = len(bucket)
            for rec in bucket.values():
                total += 1
                sev = (rec.get("severity") or "unknown").lower()
                by_severity[sev] = by_severity.get(sev, 0) + 1
        return {
            "total_cves": total,
            "by_year": by_year,
            "by_severity": by_severity,
            "last_sync": self.index.get("last_sync"),
        }

    def incremental_sync(self) -> Dict[str, Any]:
        """增量同步：以上次同步时间为起点拉取 NVD 更新。"""
        last = self.index.get("last_sync")
        if not last:
            # 首次全量拉取少量
            return self.sync_nvd(max_results=50)
        # NVD 要求日期格式 YYYY-MM-DDTHH:MM:SS.000
        start = last.replace("+00:00", ".000")
        return self.sync_nvd(start_date=start, max_results=50)


# 模块级单例
vuln_db_sync = VulnDBSync()
