#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
ux_docs_deep/deployment_docs.py — 部署文档管理。

覆盖六大分册：
    1. 部署指南：系统要求/硬件要求/软件要求/网络要求/安全要求/部署前检查
    2. 安装部署：Windows/Linux/macOS/Docker/K8s/云/离线/一键部署
    3. 配置指南：基础/高级/安全/性能/数据库/缓存/日志/备份配置
    4. 升级指南：版本升级/增量/全量/回滚/数据迁移/配置迁移/兼容性/验证
    5. 运维指南：启动/停止/重启/状态/日志/监控/告警/备份/恢复/扩缩容/故障处理
    6. 高可用部署：集群/负载均衡/主从复制/读写分离/故障转移/数据同步/容灾/多活
"""

from __future__ import annotations

import time
import uuid
from typing import Any, Dict, List, Optional


# --------------------------------------------------------------------------- #
# 部署方案定义
# --------------------------------------------------------------------------- #
DEPLOYMENT_PLATFORMS: Dict[str, Dict[str, Any]] = {
    "windows": {"name": "Windows", "min_os": "Windows 10 1809 / Server 2019",
                "package": ".exe / .msi", "difficulty": "低"},
    "linux":   {"name": "Linux", "min_os": "Ubuntu 20.04 / CentOS 8 / Debian 11",
                "package": ".deb / .rpm / shell", "difficulty": "低"},
    "macos":   {"name": "macOS", "min_os": "macOS 11 Big Sur",
                "package": ".dmg / brew", "difficulty": "低"},
    "docker":  {"name": "Docker", "min_os": "Docker 20.10+",
                "package": "docker-compose", "difficulty": "中"},
    "k8s":     {"name": "Kubernetes", "min_os": "K8s 1.24+ / Helm 3",
                "package": "helm chart", "difficulty": "高"},
    "cloud":   {"name": "云部署", "vendors": ["阿里云", "腾讯云", "AWS", "Azure"],
                "package": "Terraform / 云市场镜像", "difficulty": "高"},
    "offline": {"name": "离线部署", "min_os": "内网环境",
                "package": "离线包", "difficulty": "中"},
    "oneclick": {"name": "一键部署", "min_os": "主流OS",
                 "package": "install.sh / install.bat", "difficulty": "极低"},
}

HARDWARE_REQUIREMENTS: Dict[str, Dict[str, Any]] = {
    "min":  {"cpu": "2核", "memory": "4GB", "disk": "50GB SSD", "network": "100Mbps"},
    "std":  {"cpu": "4核", "memory": "8GB", "disk": "200GB SSD", "network": "1Gbps"},
    "pro":  {"cpu": "8核", "memory": "32GB", "disk": "1TB NVMe", "network": "10Gbps"},
    "ha":   {"cpu": "16核x3", "memory": "64GBx3", "disk": "2TB SSDx3", "network": "10Gbps"},
}

CONFIG_CATEGORIES: Dict[str, List[str]] = {
    "basic":  ["服务端口", "绑定地址", "工作目录", "日志级别", "时区"],
    "advanced": ["工作进程数", "连接池", "超时", "限流", "灰度发布"],
    "security": ["TLS证书", "访问控制", "密码策略", "审计开关", "数据加密"],
    "performance": ["缓存策略", "数据库索引", "异步队列", "资源上限", "JVM/GC"],
    "database": ["DB类型", "连接串", "连接池", "字符集", "慢查询阈值"],
    "cache": ["缓存类型", "地址", "密码", "TTL", "最大内存"],
    "logging": ["日志路径", "轮转策略", "保留天数", "远程上报", "脱敏"],
    "backup": ["备份策略", "备份周期", "保留份数", "备份存储", "加密"],
}


# --------------------------------------------------------------------------- #
# 部署文档对象
# --------------------------------------------------------------------------- #
class DeploymentDoc:
    """部署文档条目。"""

    def __init__(self, category: str, title: str, content: str = "",
                 platform: str = "all", owner: str = "devops") -> None:
        self.id = f"dd_{uuid.uuid4().hex[:10]}"
        self.category = category  # guide/install/config/upgrade/ops/ha
        self.title = title
        self.content = content
        self.platform = platform
        self.owner = owner
        self.created_at = time.strftime("%Y-%m-%d %H:%M:%S")
        self.updated_at = self.created_at
        self.version = "1.0.0"
        self.applicable_versions: List[str] = [">=28.0.0"]

    def to_dict(self) -> Dict[str, Any]:
        return {
            "id": self.id, "category": self.category, "title": self.title,
            "content": self.content, "platform": self.platform, "owner": self.owner,
            "created_at": self.created_at, "updated_at": self.updated_at,
            "version": self.version, "applicable_versions": self.applicable_versions,
        }


# --------------------------------------------------------------------------- #
# 部署文档管理器
# --------------------------------------------------------------------------- #
class DeploymentDocsManager:
    """部署文档管理器（内存字典模拟）。"""

    def __init__(self) -> None:
        self.docs: Dict[str, DeploymentDoc] = {}
        self.deploy_records: List[Dict[str, Any]] = []
        self._seed_defaults()

    def _seed_defaults(self) -> None:
        seeds = [
            ("guide", "生产环境硬件配置建议", "CPU 8核 / 内存32GB / SSD 1TB / 万兆网络", "all", "devops"),
            ("guide", "部署前安全检查清单", "确认端口开放/防火墙规则/证书有效期/密钥轮换", "all", "security"),
            ("install", "Docker Compose 部署", "docker compose up -d，访问 http://localhost:8080", "docker", "devops"),
            ("install", "K8s Helm 部署", "helm repo add xxx && helm install xxx ./chart", "k8s", "sre"),
            ("config", "生产环境性能配置", "workers=8, max_connections=200, cache_ttl=300", "all", "perf"),
            ("upgrade", "v28 增量升级步骤", "备份DB -> 拉镜像 -> helm upgrade -> 验证健康", "k8s", "release"),
            ("upgrade", "升级回滚方案", "helm rollback xxx N -> 恢复DB快照 -> 验证", "k8s", "release"),
            ("ops", "日常运维巡检清单", "CPU/内存/磁盘/连接数/错误率/证书/备份", "all", "ops"),
            ("ha", "三节点高可用集群部署", "3 master + 3 worker, PodAntiAffinity, LB", "k8s", "sre"),
            ("ha", "主从复制与读写分离", "PostgreSQL流复制, 读写分离中间件", "linux", "dba"),
        ]
        for cat, title, content, plat, owner in seeds:
            d = DeploymentDoc(cat, title, content, plat, owner)
            self.docs[d.id] = d

    # ---- CRUD ----
    def create_doc(self, category: str, title: str, content: str = "",
                   platform: str = "all", owner: str = "devops") -> Dict[str, Any]:
        d = DeploymentDoc(category, title, content, platform, owner)
        self.docs[d.id] = d
        return d.to_dict()

    def get_doc(self, doc_id: str) -> Optional[Dict[str, Any]]:
        d = self.docs.get(doc_id)
        return d.to_dict() if d else None

    def update_doc(self, doc_id: str, **fields: Any) -> Optional[Dict[str, Any]]:
        d = self.docs.get(doc_id)
        if d is None:
            return None
        for k in ("title", "content", "platform", "owner", "version"):
            if k in fields and fields[k] is not None:
                setattr(d, k, fields[k])
        d.updated_at = time.strftime("%Y-%m-%d %H:%M:%S")
        return d.to_dict()

    def delete_doc(self, doc_id: str) -> bool:
        if doc_id in self.docs:
            del self.docs[doc_id]
            return True
        return False

    def list_docs(self, category: Optional[str] = None,
                  platform: Optional[str] = None,
                  keyword: Optional[str] = None) -> List[Dict[str, Any]]:
        items = list(self.docs.values())
        if category:
            items = [d for d in items if d.category == category]
        if platform:
            items = [d for d in items if d.platform in (platform, "all")]
        if keyword:
            kw = keyword.lower()
            items = [d for d in items if kw in d.title.lower() or kw in d.content.lower()]
        return [d.to_dict() for d in items]

    # ---- 部署记录 ----
    def record_deploy(self, env: str, platform: str, version: str,
                      operator: str, result: str = "success",
                      notes: str = "") -> Dict[str, Any]:
        rec = {
            "id": f"dr_{uuid.uuid4().hex[:10]}",
            "env": env, "platform": platform, "version": version,
            "operator": operator, "result": result, "notes": notes,
            "time": time.strftime("%Y-%m-%d %H:%M:%S"),
        }
        self.deploy_records.append(rec)
        return rec

    def list_deploy_records(self, limit: int = 50) -> List[Dict[str, Any]]:
        return list(reversed(self.deploy_records[-limit:]))

    # ---- 参考数据 ----
    def list_platforms(self) -> Dict[str, Any]:
        return DEPLOYMENT_PLATFORMS

    def list_hardware(self) -> Dict[str, Any]:
        return HARDWARE_REQUIREMENTS

    def list_config_categories(self) -> Dict[str, List[str]]:
        return CONFIG_CATEGORIES

    # ---- 统计 ----
    def stats(self) -> Dict[str, Any]:
        items = list(self.docs.values())
        by_cat: Dict[str, int] = {}
        for d in items:
            by_cat[d.category] = by_cat.get(d.category, 0) + 1
        return {
            "total_docs": len(items),
            "by_category": by_cat,
            "deploy_records": len(self.deploy_records),
            "success_deploys": len([r for r in self.deploy_records
                                   if r["result"] == "success"]),
        }


# --------------------------------------------------------------------------- #
# 单例
# --------------------------------------------------------------------------- #
_manager: Optional[DeploymentDocsManager] = None


def get_deployment_docs_manager() -> DeploymentDocsManager:
    global _manager
    if _manager is None:
        _manager = DeploymentDocsManager()
    return _manager
