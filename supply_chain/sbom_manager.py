#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
sbom_manager.py — SBOM 软件物料清单管理器。

覆盖：
    - SBOM 生成（SPDX 2.3 / CycloneDX 1.5 两种格式）
    - 组件清单、依赖树、版本追踪、许可证识别
    - SBOM 导入导出、SBOM 对比、变更检测
    - 内置示例 SBOM 数据集（20+ 常见开源组件）

设计定位：仅做 SBOM 生成、管理与对比分析，输出物料清单与变更报告。
"""

from __future__ import annotations

import hashlib
import json
import time
import uuid
from typing import Any, Dict, List, Optional, Tuple


# --------------------------------------------------------------------------- #
# SBOM 格式定义
# --------------------------------------------------------------------------- #
SBOM_FORMATS: Dict[str, Dict[str, Any]] = {
    "spdx": {
        "name": "SPDX 2.3",
        "full_name": "Software Package Data Exchange 2.3",
        "spec_version": "SPDX-2.3",
        "vendor": "Linux Foundation / ISO/IEC 5962",
        "file_ext": ".spdx.json",
        "mime_type": "application/spdx+json",
        "description": "ISO 标准 SBOM 格式，广泛用于合规审计与供应链认证",
        "pros": ["国际标准", "合规认可度高", "许可证信息完善"],
        "cons": ["结构较复杂", "工具链相对少"],
    },
    "cyclonedx": {
        "name": "CycloneDX 1.5",
        "full_name": "CycloneDX 1.5 Software Bill of Materials",
        "spec_version": "CycloneDX-1.5",
        "vendor": "OWASP Foundation",
        "file_ext": ".cdx.json",
        "mime_type": "application/vnd.cyclonedx+json",
        "description": "OWASP 主导的轻量级 SBOM 格式，面向安全与漏洞管理",
        "pros": ["安全导向", "漏洞集成原生", "结构简洁"],
        "cons": ["国际标准认可度待提升"],
    },
}


# --------------------------------------------------------------------------- #
# 内置示例组件库（20+ 常见开源组件）
# --------------------------------------------------------------------------- #
SAMPLE_COMPONENTS: List[Dict[str, Any]] = [
    {"name": "lodash", "version": "4.17.21", "type": "library", "ecosystem": "npm",
     "supplier": "OpenJS Foundation", "license": "MIT", "purl": "pkg:npm/lodash@4.17.21",
     "description": "JavaScript 实用工具库", "homepage": "https://lodash.com",
     "dep_count": 0, "is_direct": True},
    {"name": "axios", "version": "1.6.0", "type": "library", "ecosystem": "npm",
     "supplier": "OpenJS Foundation", "license": "MIT", "purl": "pkg:npm/axios@1.6.0",
     "description": "Promise-based HTTP 客户端", "homepage": "https://axios-http.com",
     "dep_count": 4, "is_direct": True},
    {"name": "react", "version": "18.2.0", "type": "framework", "ecosystem": "npm",
     "supplier": "Meta Platforms", "license": "MIT", "purl": "pkg:npm/react@18.2.0",
     "description": "用于构建用户界面的 JavaScript 库", "homepage": "https://reactjs.org",
     "dep_count": 3, "is_direct": True},
    {"name": "django", "version": "4.2.7", "type": "framework", "ecosystem": "pypi",
     "supplier": "Django Software Foundation", "license": "BSD-3-Clause",
     "purl": "pkg:pypi/django@4.2.7",
     "description": "Python Web 框架", "homepage": "https://www.djangoproject.com",
     "dep_count": 5, "is_direct": True},
    {"name": "flask", "version": "3.0.0", "type": "framework", "ecosystem": "pypi",
     "supplier": "Pallets Projects", "license": "BSD-3-Clause",
     "purl": "pkg:pypi/flask@3.0.0",
     "description": "Python 微 Web 框架", "homepage": "https://flask.palletsprojects.com",
     "dep_count": 4, "is_direct": True},
    {"name": "requests", "version": "2.31.0", "type": "library", "ecosystem": "pypi",
     "supplier": "PSF / Kenneth Reitz", "license": "Apache-2.0",
     "purl": "pkg:pypi/requests@2.31.0",
     "description": "HTTP 请求库", "homepage": "https://docs.python-requests.org",
     "dep_count": 6, "is_direct": True},
    {"name": "urllib3", "version": "1.26.18", "type": "library", "ecosystem": "pypi",
     "supplier": "PSF", "license": "MIT", "purl": "pkg:pypi/urllib3@1.26.18",
     "description": "HTTP 客户端底层库", "homepage": "https://urllib3.readthedocs.io",
     "dep_count": 2, "is_direct": False},
    {"name": "numpy", "version": "1.26.2", "type": "library", "ecosystem": "pypi",
     "supplier": "NumFOCUS", "license": "BSD-3-Clause",
     "purl": "pkg:pypi/numpy@1.26.2",
     "description": "科学计算基础库", "homepage": "https://numpy.org",
     "dep_count": 0, "is_direct": True},
    {"name": "pandas", "version": "2.1.4", "type": "library", "ecosystem": "pypi",
     "supplier": "NumFOCUS", "license": "BSD-3-Clause",
     "purl": "pkg:pypi/pandas@2.1.4",
     "description": "数据处理与分析库", "homepage": "https://pandas.pydata.org",
     "dep_count": 3, "is_direct": True},
    {"name": "fastapi", "version": "0.104.1", "type": "framework", "ecosystem": "pypi",
     "supplier": "Sebastian Ramirez", "license": "MIT",
     "purl": "pkg:pypi/fastapi@0.104.1",
     "description": "现代高性能 Python Web API 框架", "homepage": "https://fastapi.tiangolo.com",
     "dep_count": 5, "is_direct": True},
    {"name": "uvicorn", "version": "0.24.0", "type": "server", "ecosystem": "pypi",
     "supplier": "Encode OSS", "license": "BSD-3-Clause",
     "purl": "pkg:pypi/uvicorn@0.24.0",
     "description": "ASGI 服务器实现", "homepage": "https://www.uvicorn.org",
     "dep_count": 3, "is_direct": True},
    {"name": "sqlalchemy", "version": "2.0.23", "type": "library", "ecosystem": "pypi",
     "supplier": "SQLAlchemy Projects", "license": "MIT",
     "purl": "pkg:pypi/sqlalchemy@2.0.23",
     "description": "Python SQL 工具包和对象关系映射器", "homepage": "https://www.sqlalchemy.org",
     "dep_count": 0, "is_direct": True},
    {"name": "redis", "version": "5.0.1", "type": "library", "ecosystem": "pypi",
     "supplier": "Redis Ltd.", "license": "MIT",
     "purl": "pkg:pypi/redis@5.0.1",
     "description": "Redis Python 客户端", "homepage": "https://redis.readthedocs.io",
     "dep_count": 0, "is_direct": True},
    {"name": "celery", "version": "5.3.4", "type": "library", "ecosystem": "pypi",
     "supplier": "Celery Project", "license": "BSD-3-Clause",
     "purl": "pkg:pypi/celery@5.3.4",
     "description": "分布式任务队列", "homepage": "https://docs.celeryq.dev",
     "dep_count": 5, "is_direct": True},
    {"name": "log4j-core", "version": "2.14.1", "type": "library", "ecosystem": "maven",
     "supplier": "Apache Software Foundation", "license": "Apache-2.0",
     "purl": "pkg:maven/org.apache.logging.log4j/log4j-core@2.14.1",
     "description": "Java 日志框架核心", "homepage": "https://logging.apache.org/log4j/2.x/",
     "dep_count": 0, "is_direct": True},
    {"name": "spring-core", "version": "5.3.20", "type": "framework", "ecosystem": "maven",
     "supplier": "VMware / Spring Team", "license": "Apache-2.0",
     "purl": "pkg:maven/org.springframework/spring-core@5.3.20",
     "description": "Spring 框架核心容器", "homepage": "https://spring.io/projects/spring-framework",
     "dep_count": 2, "is_direct": True},
    {"name": "logback-classic", "version": "1.2.11", "type": "library", "ecosystem": "maven",
     "supplier": "QOS.ch", "license": "EPL-1.0",
     "purl": "pkg:maven/ch.qos.logback/logback-classic@1.2.11",
     "description": "Logback 日志经典模块", "homepage": "https://logback.qos.ch",
     "dep_count": 2, "is_direct": False},
    {"name": "jackson-databind", "version": "2.13.0", "type": "library", "ecosystem": "maven",
     "supplier": "FasterXML", "license": "Apache-2.0",
     "purl": "pkg:maven/com.fasterxml.jackson.core/jackson-databind@2.13.0",
     "description": "Jackson 数据绑定库", "homepage": "https://github.com/FasterXML/jackson",
     "dep_count": 1, "is_direct": False},
    {"name": "openssl", "version": "1.1.1k", "type": "crypto", "ecosystem": "system",
     "supplier": "OpenSSL Project", "license": "Apache-2.0",
     "purl": "pkg:generic/openssl@1.1.1k",
     "description": "开源 TLS/SSL 工具包", "homepage": "https://www.openssl.org",
     "dep_count": 0, "is_direct": True},
    {"name": "openssl", "version": "3.0.8", "type": "crypto", "ecosystem": "system",
     "supplier": "OpenSSL Project", "license": "Apache-2.0",
     "purl": "pkg:generic/openssl@3.0.8",
     "description": "开源 TLS/SSL 工具包", "homepage": "https://www.openssl.org",
     "dep_count": 0, "is_direct": True},
    {"name": "nginx", "version": "1.21.6", "type": "server", "ecosystem": "system",
     "supplier": "F5 Networks", "license": "BSD-2-Clause",
     "purl": "pkg:generic/nginx@1.21.6",
     "description": "高性能 HTTP 服务器与反向代理", "homepage": "https://nginx.org",
     "dep_count": 0, "is_direct": True},
    {"name": "mysql", "version": "8.0.33", "type": "database", "ecosystem": "system",
     "supplier": "Oracle Corporation", "license": "GPL-2.0",
     "purl": "pkg:generic/mysql@8.0.33",
     "description": "开源关系型数据库", "homepage": "https://www.mysql.com",
     "dep_count": 0, "is_direct": True},
    {"name": "postgresql", "version": "14.8", "type": "database", "ecosystem": "system",
     "supplier": "PostgreSQL Global Development Group", "license": "PostgreSQL",
     "purl": "pkg:generic/postgresql@14.8",
     "description": "开源对象关系型数据库", "homepage": "https://www.postgresql.org",
     "dep_count": 0, "is_direct": True},
    {"name": "jquery", "version": "3.6.0", "type": "library", "ecosystem": "npm",
     "supplier": "OpenJS Foundation", "license": "MIT",
     "purl": "pkg:npm/jquery@3.6.0",
     "description": "JavaScript DOM 操作库", "homepage": "https://jquery.com",
     "dep_count": 0, "is_direct": True},
    {"name": "webpack", "version": "5.89.0", "type": "toolchain", "ecosystem": "npm",
     "supplier": "OpenJS Foundation / Vercel", "license": "MIT",
     "purl": "pkg:npm/webpack@5.89.0",
     "description": "前端模块打包器", "homepage": "https://webpack.js.org",
     "dep_count": 30, "is_direct": True},
]

SAMPLE_SBOMS: Dict[str, Dict[str, Any]] = {
    "webapp-frontend": {
        "name": "前端 Web 应用 SBOM",
        "description": "React + Vite 前端项目示例物料清单",
        "components": ["react@18.2.0", "axios@1.6.0", "lodash@4.17.21",
                        "jquery@3.6.0", "webpack@5.89.0"],
    },
    "backend-api": {
        "name": "后端 API 服务 SBOM",
        "description": "FastAPI + PostgreSQL 后端服务示例物料清单",
        "components": ["fastapi@0.104.1", "uvicorn@0.24.0", "sqlalchemy@2.0.23",
                      "redis@5.0.1", "celery@5.3.4", "requests@2.31.0",
                      "urllib3@1.26.18", "pandas@2.1.4", "numpy@1.26.2"],
    },
    "java-enterprise": {
        "name": "Java 企业级应用 SBOM",
        "description": "Spring Boot 企业级应用示例物料清单",
        "components": ["spring-core@5.3.20", "log4j-core@2.14.1",
                        "logback-classic@1.2.11", "jackson-databind@2.13.0"],
    },
}


# --------------------------------------------------------------------------- #
# SBOM 管理器
# --------------------------------------------------------------------------- #
class SBOMManager:
    """SBOM 软件物料清单管理器。"""

    def __init__(self) -> None:
        self._sboms: Dict[str, Dict[str, Any]] = {}
        self._history: List[Dict[str, Any]] = []
        self._load_sample_sboms()

    # ---------------- 初始化 ---------------- #
    def _load_sample_sboms(self) -> None:
        """加载示例 SBOM 到内存。"""
        for sbom_id, info in SAMPLE_SBOMS.items():
            comps = self._resolve_components(info["components"])
            sbom = {
                "sbom_id": sbom_id,
                "name": info["name"],
                "description": info["description"],
                "format": "spdx",
                "spec_version": "SPDX-2.3",
                "created_at": time.strftime("%Y-%m-%d %H:%M:%S"),
                "created_by": "SBOMManager",
                "components": comps,
                "component_count": len(comps),
                "licenses": sorted({c.get("license", "Unknown") for c in comps}),
                "suppliers": sorted({c.get("supplier", "Unknown") for c in comps}),
                "ecosystems": sorted({c.get("ecosystem", "unknown") for c in comps}),
            }
            self._sboms[sbom_id] = sbom

    @staticmethod
    def _resolve_components(specs: List[str]) -> List[Dict[str, Any]]:
        """从组件规格列表解析出完整组件信息。"""
        comp_map = {f"{c['name']}@{c['version']}": c for c in SAMPLE_COMPONENTS}
        result = []
        for spec in specs:
            c = comp_map.get(spec)
            if c:
                entry = dict(c)
                entry["fingerprint"] = hashlib.sha256(
                    f"{c['name']}:{c['version']}:{c['ecosystem']}".encode()
                ).hexdigest()[:16]
                result.append(entry)
        return result

    # ---------------- SBOM 生成 ---------------- #
    def generate_sbom(self, name: str, components: List[Dict[str, Any]],
                      fmt: str = "spdx") -> Dict[str, Any]:
        """生成 SBOM 文档。"""
        sbom_id = uuid.uuid4().hex[:12]
        timestamp = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())

        if fmt == "spdx":
            doc = self._build_spdx(sbom_id, name, components, timestamp)
        else:
            doc = self._build_cyclonedx(sbom_id, name, components, timestamp)

        doc["sbom_id"] = sbom_id
        doc["format"] = fmt
        doc["created_at"] = time.strftime("%Y-%m-%d %H:%M:%S")
        doc["component_count"] = len(components)
        doc["licenses"] = sorted({c.get("license", "Unknown") for c in components})
        doc["suppliers"] = sorted({c.get("supplier", "Unknown") for c in components})
        doc["ecosystems"] = sorted({c.get("ecosystem", "unknown") for c in components})

        self._sboms[sbom_id] = doc
        self._history.append({"sbom_id": sbom_id, "action": "generated",
                              "time": doc["created_at"], "format": fmt})
        return doc

    @staticmethod
    def _build_spsbx(sbom_id: str, name: str, components: List[Dict[str, Any]],
                     timestamp: str) -> Dict[str, Any]:
        """构建 SPDX 2.3 格式 SBOM（兼容方法名）。"""
        return SBOMManager._build_spdx(sbom_id, name, components, timestamp)

    @staticmethod
    def _build_spdx(sbom_id: str, name: str, components: List[Dict[str, Any]],
                    timestamp: str) -> Dict[str, Any]:
        """构建 SPDX 2.3 格式 SBOM。"""
        return {
            "spdxVersion": "SPDX-2.3",
            "dataLicense": "CC0-1.0",
            "SPDXID": f"SPDXRef-DOCUMENT-{sbom_id}",
            "name": name,
            "documentNamespace": f"https://company.com/spdxdocs/{sbom_id}",
            "creationInfo": {
                "created": timestamp,
                "creators": ["Tool: SBOMManager-1.0", "Organization: Acme Corp"],
                "licenseListVersion": "3.20",
            },
            "packages": [
                {
                    "SPDXID": f"SPDXRef-Package-{i}",
                    "name": c.get("name", ""),
                    "versionInfo": c.get("version", ""),
                    "supplier": f"Organization: {c.get('supplier', 'NOASSERTION')}",
                    "licenseConcluded": c.get("license", "NOASSERTION"),
                    "licenseDeclared": c.get("license", "NOASSERTION"),
                    "copyrightText": "NOASSERTION",
                    "downloadLocation": "NOASSERTION",
                    "externalRefs": [
                        {
                            "referenceCategory": "PACKAGE-MANAGER",
                            "referenceType": c.get("ecosystem", "purl"),
                            "referenceLocator": c.get("purl", ""),
                        }
                    ],
                }
                for i, c in enumerate(components)
            ],
            "documentDescribes": [f"SPDXRef-Package-{i}" for i in range(len(components))],
        }

    @staticmethod
    def _build_cyclonedx(sbom_id: str, name: str, components: List[Dict[str, Any]],
                         timestamp: str) -> Dict[str, Any]:
        """构建 CycloneDX 1.5 格式 SBOM。"""
        return {
            "bomFormat": "CycloneDX",
            "specVersion": "1.5",
            "serialNumber": f"urn:uuid:{sbom_id}",
            "version": 1,
            "metadata": {
                "timestamp": timestamp,
                "tools": {"components": [{
                    "type": "application", "name": "SBOMManager", "version": "1.0"
                }]},
                "component": {"type": "application", "name": name},
            },
            "components": [
                {
                    "type": c.get("type", "library"),
                    "bom-ref": f"pkg-{i}",
                    "name": c.get("name", ""),
                    "version": c.get("version", ""),
                    "supplier": {"name": c.get("supplier", "Unknown")},
                    "licenses": [{"license": {"id": c.get("license", "NOASSERTION")}}],
                    "purl": c.get("purl", ""),
                    "description": c.get("description", ""),
                    "externalReferences": [
                        {"type": "website", "url": c.get("homepage", "")}
                    ],
                }
                for i, c in enumerate(components)
            ],
        }

    # ---------------- SBOM 查询 ---------------- #
    def list_sboms(self) -> List[Dict[str, Any]]:
        """列出所有 SBOM 摘要。"""
        return [
            {"sbom_id": s["sbom_id"], "name": s["name"], "format": s.get("format", "spdx"),
             "component_count": s.get("component_count", len(s.get("components", []))),
             "created_at": s.get("created_at", ""),
             "license_count": len(s.get("licenses", [])),
             "supplier_count": len(s.get("suppliers", []))}
            for s in self._sboms.values()
        ]

    def get_sbom(self, sbom_id: str) -> Optional[Dict[str, Any]]:
        return self._sboms.get(sbom_id)

    def get_components(self, sbom_id: str) -> List[Dict[str, Any]]:
        sbom = self._sboms.get(sbom_id)
        if not sbom:
            return []
        return sbom.get("components", [])

    def get_dependency_tree(self, sbom_id: str) -> Dict[str, Any]:
        """构建依赖树。"""
        sbom = self._sboms.get(sbom_id)
        if not sbom:
            return {"error": "SBOM not found"}
        comps = sbom.get("components", [])
        direct = [c for c in comps if c.get("is_direct")]
        transitive = [c for c in comps if not c.get("is_direct")]
        return {
            "sbom_id": sbom_id,
            "total_components": len(comps),
            "direct_deps": len(direct),
            "transitive_deps": len(transitive),
            "tree": [
                {"name": c["name"], "version": c["version"], "type": c.get("type"),
                 "ecosystem": c.get("ecosystem"), "license": c.get("license"),
                 "is_direct": c.get("is_direct", True),
                 "transitive_deps_count": c.get("dep_count", 0)}
                for c in comps
            ],
        }

    # ---------------- SBOM 对比与变更检测 ---------------- #
    def compare_sboms(self, sbom_id_a: str, sbom_id_b: str) -> Dict[str, Any]:
        """对比两个 SBOM，检测变更。"""
        a = self._sboms.get(sbom_id_a)
        b = self._sboms.get(sbom_id_b)
        if not a or not b:
            return {"error": "One or both SBOMs not found"}

        comps_a = {c["name"]: c for c in a.get("components", [])}
        comps_b = {c["name"]: c for c in b.get("components", [])}

        added = [comps_b[k] for k in comps_b if k not in comps_a]
        removed = [comps_a[k] for k in comps_a if k not in comps_b]
        upgraded = []
        downgraded = []
        unchanged = []
        for k in comps_a:
            if k in comps_b:
                va = comps_a[k].get("version", "")
                vb = comps_b[k].get("version", "")
                if va != vb:
                    entry = {"name": k, "old_version": va, "new_version": vb}
                    if self._version_tuple(vb) > self._version_tuple(va):
                        upgraded.append(entry)
                    else:
                        downgraded.append(entry)
                else:
                    unchanged.append(k)

        return {
            "sbom_a": sbom_id_a, "sbom_b": sbom_id_b,
            "summary": {
                "total_a": len(comps_a), "total_b": len(comps_b),
                "added": len(added), "removed": len(removed),
                "upgraded": len(upgraded), "downgraded": len(downgraded),
                "unchanged": len(unchanged),
            },
            "added": added, "removed": removed,
            "upgraded": upgraded, "downgraded": downgraded,
            "change_detected": bool(added or removed or upgraded or downgraded),
            "compared_at": time.strftime("%Y-%m-%d %H:%M:%S"),
        }

    @staticmethod
    def _version_tuple(v: str) -> Tuple:
        """简单版本号比较，返回元组。"""
        parts = []
        for p in v.replace("-", ".").split("."):
            try:
                parts.append(int("".join(ch for ch in p if ch.isdigit()) or "0"))
            except ValueError:
                parts.append(0)
        return tuple(parts)

    # ---------------- SBOM 导入导出 ---------------- #
    def export_sbom(self, sbom_id: str, fmt: Optional[str] = None) -> Dict[str, Any]:
        """导出 SBOM 为指定格式。"""
        sbom = self._sboms.get(sbom_id)
        if not sbom:
            return {"error": "SBOM not found"}
        target_fmt = fmt or sbom.get("format", "spdx")
        if target_fmt == sbom.get("format"):
            return {"sbom_id": sbom_id, "format": target_fmt, "data": sbom,
                    "exported_at": time.strftime("%Y-%m-%d %H:%M:%S")}
        # 重新格式转换
        comps = sbom.get("components", [])
        converted = self.generate_sbom(
            sbom.get("name", "export"), comps, target_fmt
        )
        return {"sbom_id": sbom_id, "format": target_fmt, "data": converted,
                "exported_at": time.strftime("%Y-%m-%d %H:%M:%S"),
                "converted_from": sbom.get("format")}

    def import_sbom(self, data: Dict[str, Any], fmt: str = "spdx") -> Dict[str, Any]:
        """导入外部 SBOM 数据。"""
        sbom_id = uuid.uuid4().hex[:12]
        components = self._extract_components(data, fmt)
        doc = {
            "sbom_id": sbom_id,
            "name": data.get("name", "Imported SBOM"),
            "description": f"Imported from {fmt} format",
            "format": fmt,
            "spec_version": SBOM_FORMATS.get(fmt, {}).get("spec_version", ""),
            "created_at": time.strftime("%Y-%m-%d %H:%M:%S"),
            "created_by": "SBOMManager.import",
            "components": components,
            "component_count": len(components),
            "licenses": sorted({c.get("license", "Unknown") for c in components}),
            "suppliers": sorted({c.get("supplier", "Unknown") for c in components}),
            "ecosystems": sorted({c.get("ecosystem", "unknown") for c in components}),
            "imported": True,
        }
        self._sboms[sbom_id] = doc
        self._history.append({"sbom_id": sbom_id, "action": "imported",
                              "time": doc["created_at"], "format": fmt})
        return doc

    @staticmethod
    def _extract_components(data: Dict[str, Any], fmt: str) -> List[Dict[str, Any]]:
        """从 SBOM 数据中提取组件列表。"""
        result = []
        if fmt == "spdx":
            for pkg in data.get("packages", []):
                result.append({
                    "name": pkg.get("name", ""),
                    "version": pkg.get("versionInfo", ""),
                    "license": pkg.get("licenseConcluded", "Unknown"),
                    "supplier": pkg.get("supplier", "Unknown").replace("Organization: ", ""),
                    "ecosystem": "unknown",
                    "type": "library",
                    "description": "",
                    "homepage": "",
                    "purl": "",
                    "dep_count": 0,
                    "is_direct": True,
                })
        else:
            for comp in data.get("components", []):
                licenses = comp.get("licenses", [])
                lic = licenses[0].get("license", {}).get("id", "Unknown") if licenses else "Unknown"
                supplier = comp.get("supplier", {}).get("name", "Unknown")
                result.append({
                    "name": comp.get("name", ""),
                    "version": comp.get("version", ""),
                    "license": lic,
                    "supplier": supplier,
                    "ecosystem": "unknown",
                    "type": comp.get("type", "library"),
                    "description": comp.get("description", ""),
                    "homepage": "",
                    "purl": comp.get("purl", ""),
                    "dep_count": 0,
                    "is_direct": True,
                })
        return result

    # ---------------- 统计与报告 ---------------- #
    def get_statistics(self) -> Dict[str, Any]:
        """获取 SBOM 统计信息。"""
        total = len(self._sboms)
        all_comps = []
        all_licenses = set()
        all_suppliers = set()
        all_ecosystems = set()
        for s in self._sboms.values():
            comps = s.get("components", [])
            all_comps.extend(comps)
            for c in comps:
                all_licenses.add(c.get("license", "Unknown"))
                all_suppliers.add(c.get("supplier", "Unknown"))
                all_ecosystems.add(c.get("ecosystem", "unknown"))

        # 生态系统分布
        eco_dist: Dict[str, int] = {}
        for c in all_comps:
            eco = c.get("ecosystem", "unknown")
            eco_dist[eco] = eco_dist.get(eco, 0) + 1

        return {
            "total_sboms": total,
            "total_components": len(all_comps),
            "unique_components": len({c["name"] for c in all_comps}),
            "total_licenses": len(all_licenses),
            "total_suppliers": len(all_suppliers),
            "ecosystem_distribution": eco_dist,
            "formats_supported": list(SBOM_FORMATS.keys()),
            "history_count": len(self._history),
        }

    def get_history(self) -> List[Dict[str, Any]]:
        return self._history

    def list_formats(self) -> Dict[str, Any]:
        return SBOM_FORMATS

    def get_report_markdown(self, sbom_id: str) -> str:
        """生成 SBOM Markdown 报告。"""
        sbom = self._sboms.get(sbom_id)
        if not sbom:
            return "# SBOM 未找到"
        lines = [
            f"# SBOM 报告：{sbom.get('name', sbom_id)}", "",
            f"- SBOM ID: {sbom_id}",
            f"- 格式: {sbom.get('format', 'spdx')}",
            f"- 创建时间: {sbom.get('created_at', '')}",
            f"- 组件总数: {sbom.get('component_count', 0)}", "",
            "## 组件清单",
        ]
        for c in sbom.get("components", []):
            lines.append(f"- **{c.get('name')}** `{c.get('version')}` "
                         f"| 许可证: {c.get('license')} | 供应商: {c.get('supplier')}")
        lines += ["", "## 许可证分布"]
        for lic in sbom.get("licenses", []):
            lines.append(f"- {lic}")
        return "\n".join(lines)
