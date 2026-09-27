#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
vuln_database知识库模块，存储和管理相关安全知识、漏洞信息和攻击链数据。

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
import hashlib
import asyncio
import aiohttp
from datetime import datetime, timedelta
from typing import Any, Dict, List, Optional, Tuple
from pathlib import Path
from dataclasses import dataclass, field, asdict
from loguru import logger


@dataclass
class Vulnerability:
    """漏洞数据结构"""
    cve_id: str
    title: str = ""
    description: str = ""
    severity: str = "medium"  # critical/high/medium/low/info
    cvss_score: float = 0.0
    cvss_vector: str = ""
    published_date: str = ""
    last_modified: str = ""
    vendor: str = ""
    product: str = ""
    cwe_ids: List[str] = field(default_factory=list)
    references: List[str] = field(default_factory=list)
    exploits: List[Dict[str, Any]] = field(default_factory=list)
    poc_urls: List[str] = field(default_factory=list)
    patches: List[str] = field(default_factory=list)
    affected_versions: List[str] = field(default_factory=list)
    tags: List[str] = field(default_factory=list)
    source: str = "local"  # local/nvd/exploit_db/vulners
    is_0day: bool = False
    in_the_wild: bool = False
    epss_score: float = 0.0
    kev: bool = False  # CISA Known Exploited Vulnerabilities

    def to_dict(self) -> Dict[str, Any]:
        """执行相关操作。

        Returns:
            操作结果。
        """
        return asdict(self)

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "Vulnerability":
        """从...导入。

        Args:
            data: 相关参数。

        Returns:
            操作结果。
        """
        return cls(**{k: v for k, v in data.items() if k in cls.__dataclass_fields__})


class VulnDatabase:
    """统一漏洞数据库"""

    def __init__(self, db_path: Optional[str] = None):
        """初始化VulnDatabase实例。

        Args:
            self: 类实例。
        """
        self.project_root = Path(__file__).parent.parent
        self.db_path = db_path or str(self.project_root / "data" / "vuln_database.json")
        self.db: Dict[str, Vulnerability] = {}
        self.last_sync: Dict[str, str] = {}
        self.stats: Dict[str, Any] = {
            "total": 0,
            "by_severity": {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0},
            "by_source": {"local": 0, "nvd": 0, "exploit_db": 0, "vulners": 0},
            "with_exploit": 0,
            "with_poc": 0,
            "kev_count": 0,
        }
        self._load()

    def _load(self):
        """加载本地数据库"""
        try:
            if Path(self.db_path).exists():
                with open(self.db_path, "r", encoding="utf-8") as f:
                    data = json.load(f)
                for cve_id, vuln_data in data.get("vulnerabilities", {}).items():
                    self.db[cve_id] = Vulnerability.from_dict(vuln_data)
                self.last_sync = data.get("last_sync", {})
                self._recalculate_stats()
                logger.info(f"漏洞数据库加载: {len(self.db)} 条记录")
            else:
                self._init_builtin()
        except Exception as e:
            logger.error(f"漏洞数据库加载失败: {e}")
            self._init_builtin()

    def _save(self):
        """保存到本地"""
        try:
            Path(self.db_path).parent.mkdir(parents=True, exist_ok=True)
            data = {
                "vulnerabilities": {k: v.to_dict() for k, v in self.db.items()},
                "last_sync": self.last_sync,
                "stats": self.stats,
                "updated_at": datetime.now().isoformat(),
            }
            with open(self.db_path, "w", encoding="utf-8") as f:
                json.dump(data, f, ensure_ascii=False, indent=2)
        except Exception as e:
            logger.error(f"漏洞数据库保存失败: {e}")

    def _init_builtin(self):
        """初始化内置常见漏洞"""
        builtin = {
            "CVE-2021-44228": Vulnerability(
                cve_id="CVE-2021-44228",
                title="Log4j2 远程代码执行漏洞 (Log4Shell)",
                description="Apache Log4j2 中存在JNDI注入漏洞，攻击者可通过构造特殊请求触发远程代码执行。",
                severity="critical",
                cvss_score=10.0,
                cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H",
                published_date="2021-12-10",
                vendor="Apache",
                product="Log4j2",
                cwe_ids=["CWE-502", "CWE-20"],
                tags=["rce", "jndi", "log4shell", "kev"],
                source="local",
                kev=True,
                in_the_wild=True,
            ),
            "CVE-2017-0144": Vulnerability(
                cve_id="CVE-2017-0144",
                title="SMBv1 远程代码执行漏洞 (EternalBlue)",
                description="Windows SMBv1协议中存在远程代码执行漏洞，可被用于传播勒索软件（WannaCry）。",
                severity="critical",
                cvss_score=8.1,
                cvss_vector="CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:H",
                published_date="2017-03-14",
                vendor="Microsoft",
                product="Windows SMBv1",
                cwe_ids=["CWE-119"],
                tags=["rce", "smb", "eternalblue", "ransomware", "kev"],
                source="local",
                kev=True,
                in_the_wild=True,
            ),
            "CVE-2014-0160": Vulnerability(
                cve_id="CVE-2014-0160",
                title="OpenSSL 心脏滴血漏洞 (Heartbleed)",
                description="OpenSSL TLS心跳扩展中存在信息泄露漏洞，可读取服务器内存中的敏感数据。",
                severity="high",
                cvss_score=7.5,
                cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N",
                published_date="2014-04-07",
                vendor="OpenSSL",
                product="OpenSSL",
                cwe_ids=["CWE-126"],
                tags=["info-disclosure", "tls", "heartbleed"],
                source="local",
            ),
            "CVE-2019-0708": Vulnerability(
                cve_id="CVE-2019-0708",
                title="Windows RDP 远程代码执行漏洞 (BlueKeep)",
                description="Windows远程桌面服务中存在预认证远程代码执行漏洞，可被蠕虫级利用。",
                severity="critical",
                cvss_score=9.8,
                cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
                published_date="2019-05-14",
                vendor="Microsoft",
                product="Windows RDP",
                cwe_ids=["CWE-416"],
                tags=["rce", "rdp", "bluekeep", "wormable", "kev"],
                source="local",
                kev=True,
            ),
            "CVE-2020-1472": Vulnerability(
                cve_id="CVE-2020-1472",
                title="Netlogon 特权提升漏洞 (Zerologon)",
                description="Windows Netlogon协议中存在特权提升漏洞，攻击者可将域控制器计算机账户密码置空。",
                severity="critical",
                cvss_score=10.0,
                cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H",
                published_date="2020-08-11",
                vendor="Microsoft",
                product="Windows Netlogon",
                cwe_ids=["CWE-330"],
                tags=["privilege-escalation", "ad", "zerologon", "domain-controller", "kev"],
                source="local",
                kev=True,
                in_the_wild=True,
            ),
        }
        self.db = builtin
        self._recalculate_stats()
        self._save()
        logger.info(f"内置漏洞库初始化: {len(self.db)} 条")

    def _recalculate_stats(self):
        """重新计算统计信息"""
        self.stats = {
            "total": len(self.db),
            "by_severity": {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0},
            "by_source": {"local": 0, "nvd": 0, "exploit_db": 0, "vulners": 0},
            "with_exploit": 0,
            "with_poc": 0,
            "kev_count": 0,
        }
        for vuln in self.db.values():
            self.stats["by_severity"][vuln.severity] = self.stats["by_severity"].get(vuln.severity, 0) + 1
            self.stats["by_source"][vuln.source] = self.stats["by_source"].get(vuln.source, 0) + 1
            if vuln.exploits:
                self.stats["with_exploit"] += 1
            if vuln.poc_urls:
                self.stats["with_poc"] += 1
            if vuln.kev:
                self.stats["kev_count"] += 1

    def add(self, vuln: Vulnerability) -> bool:
        """添加漏洞，返回是否新增"""
        is_new = vuln.cve_id not in self.db
        if is_new:
            self.db[vuln.cve_id] = vuln
        else:
            # 合并信息，保留更丰富的数据
            existing = self.db[vuln.cve_id]
            for field_name in vuln.__dataclass_fields__:
                new_val = getattr(vuln, field_name)
                old_val = getattr(existing, field_name)
                if new_val and not old_val:
                    setattr(existing, field_name, new_val)
                elif isinstance(new_val, list) and isinstance(old_val, list):
                    merged = list(set(old_val + new_val))
                    setattr(existing, field_name, merged)
                elif isinstance(new_val, dict) and isinstance(old_val, dict):
                    merged = {**old_val, **new_val}
                    setattr(existing, field_name, merged)
        self._recalculate_stats()
        return is_new

    def get(self, cve_id: str) -> Optional[Vulnerability]:
        """查询单个漏洞"""
        return self.db.get(cve_id)

    def search(self, keyword: str = "", severity: str = "",
               vendor: str = "", product: str = "", cwe: str = "",
               has_exploit: bool = False, has_poc: bool = False,
               kev_only: bool = False, limit: int = 50,
               offset: int = 0) -> Tuple[List[Vulnerability], int]:
        """高级搜索"""
        results = []
        keyword_lower = keyword.lower() if keyword else ""

        for vuln in self.db.values():
            if severity and vuln.severity != severity:
                continue
            if vendor and vendor.lower() not in vuln.vendor.lower():
                continue
            if product and product.lower() not in vuln.product.lower():
                continue
            if cwe and cwe not in vuln.cwe_ids:
                continue
            if has_exploit and not vuln.exploits:
                continue
            if has_poc and not vuln.poc_urls:
                continue
            if kev_only and not vuln.kev:
                continue
            if keyword_lower:
                search_text = f"{vuln.cve_id} {vuln.title} {vuln.description} {vuln.vendor} {vuln.product}".lower()
                if keyword_lower not in search_text:
                    continue
            results.append(vuln)

        # 按CVSS分数排序
        results.sort(key=lambda x: x.cvss_score, reverse=True)
        total = len(results)
        return results[offset:offset + limit], total

    def get_recent(self, days: int = 30, limit: int = 50) -> List[Vulnerability]:
        """获取最近N天的漏洞"""
        cutoff = (datetime.now() - timedelta(days=days)).isoformat()
        results = [v for v in self.db.values() if v.published_date >= cutoff]
        results.sort(key=lambda x: x.published_date, reverse=True)
        return results[:limit]

    def get_top_exploitable(self, limit: int = 20) -> List[Vulnerability]:
        """获取最可能被利用的漏洞（KEV + 有EXP + 高CVSS）"""
        results = [v for v in self.db.values() if v.kev or v.exploits or v.in_the_wild]
        results.sort(key=lambda x: (x.kev, bool(x.exploits), x.cvss_score), reverse=True)
        return results[:limit]

    def match_by_service(self, service: str, version: str = "") -> List[Vulnerability]:
        """根据服务/版本匹配漏洞"""
        results = []
        service_lower = service.lower()
        for vuln in self.db.values():
            if service_lower in vuln.product.lower() or service_lower in vuln.vendor.lower():
                if version:
                    if version in vuln.affected_versions or not vuln.affected_versions:
                        results.append(vuln)
                else:
                    results.append(vuln)
        results.sort(key=lambda x: x.cvss_score, reverse=True)
        return results

    def get_stats(self) -> Dict[str, Any]:
        """获取统计信息"""
        return {
            **self.stats,
            "last_sync": self.last_sync,
            "db_path": self.db_path,
            "db_size_kb": round(Path(self.db_path).stat().st_size / 1024, 2) if Path(self.db_path).exists() else 0,
        }

    def export_json(self, filepath: str) -> bool:
        """导出为JSON"""
        try:
            data = {
                "vulnerabilities": {k: v.to_dict() for k, v in self.db.items()},
                "exported_at": datetime.now().isoformat(),
                "total": len(self.db),
            }
            with open(filepath, "w", encoding="utf-8") as f:
                json.dump(data, f, ensure_ascii=False, indent=2)
            return True
        except Exception as e:
            logger.error(f"导出失败: {e}")
            return False

    def import_json(self, filepath: str) -> int:
        """从JSON导入，返回新增数量"""
        try:
            with open(filepath, "r", encoding="utf-8") as f:
                data = json.load(f)
            vulns = data.get("vulnerabilities", data) if isinstance(data, dict) else data
            added = 0
            for item in vulns if isinstance(vulns, list) else vulns.values():
                vuln = Vulnerability.from_dict(item) if isinstance(item, dict) else item
                if self.add(vuln):
                    added += 1
            self._save()
            return added
        except Exception as e:
            logger.error(f"导入失败: {e}")
            return 0


# 全局单例
_vuln_db: Optional[VulnDatabase] = None

def get_vuln_db() -> VulnDatabase:
    """获取全局漏洞数据库实例"""
    global _vuln_db
    if _vuln_db is None:
        _vuln_db = VulnDatabase()
    return _vuln_db
