#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
target_manager模块，提供相关安全测试功能。

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
import uuid
import re
from typing import Any, Dict, List, Optional, Set
from dataclasses import dataclass, field
from enum import Enum

from utils.logger import log


class SRCPlatform(str, Enum):
    """SRC平台"""
    HACKERONE = "hackerone"
    BUGCROWD = "bugcrowd"
    INTIGRITI = "intigriti"
    YESWEHACK = "yeswehack"
    OTHER = "other"


class ScopeType(str, Enum):
    """范围类型"""
    URL = "url"  # 单个URL
    DOMAIN = "domain"  # 域名（含子域名）
    WILDCARD = "wildcard"  # 通配符 *.example.com
    IP = "ip"  # IP地址
    IP_RANGE = "ip_range"  # IP段
    MOBILE_APP = "mobile_app"  # 移动应用
    API = "api"  # API端点


class ScopeStatus(str, Enum):
    """范围状态"""
    IN_SCOPE = "in_scope"  # 在范围内
    OUT_OF_SCOPE = "out_of_scope"  # 不在范围内
    ELIGIBLE = "eligible"  # 有资格获奖
    NOT_ELIGIBLE = "not_eligible"  # 无资格获奖


@dataclass
class ScopeItem:
    """范围项"""
    scope_id: str
    type: ScopeType
    value: str  # 具体值（域名/IP/URL等）
    status: ScopeStatus = ScopeStatus.IN_SCOPE
    eligible_for_bounty: bool = True
    severity_restriction: str = ""  # 严重程度限制（如：仅critical/high）
    notes: str = ""
    discovered_assets: List[str] = field(default_factory=list)  # 从该范围发现的资产
    last_scanned: Optional[float] = None

    def to_dict(self) -> Dict[str, Any]:
        """执行相关操作。

        Returns:
            操作结果。
        """
        return {
            "scope_id": self.scope_id,
            "type": self.type.value,
            "value": self.value,
            "status": self.status.value,
            "eligible_for_bounty": self.eligible_for_bounty,
            "severity_restriction": self.severity_restriction,
            "notes": self.notes,
            "discovered_assets_count": len(self.discovered_assets),
            "last_scanned": self.last_scanned
        }


@dataclass
class SRCTarget:
    """SRC目标项目"""
    target_id: str
    name: str  # 项目名称
    platform: SRCPlatform
    platform_url: str = ""  # 项目在平台上的URL
    description: str = ""
    bounty_range: str = ""  # 奖励范围（如：$100-$10000）
    currency: str = "USD"
    scope: List[ScopeItem] = field(default_factory=list)
    out_of_scope: List[str] = field(default_factory=list)  # 明确不在范围内的
    rules_of_engagement: str = ""  # 参与规则
    allowed_testing_methods: List[str] = field(default_factory=list)
    prohibited_testing_methods: List[str] = field(default_factory=list)
    priority: int = 5  # 优先级 1-10，10最高
    status: str = "active"  # active/paused/completed
    tags: List[str] = field(default_factory=list)
    created_at: float = field(default_factory=time.time)
    last_updated: float = field(default_factory=time.time)
    total_submissions: int = 0
    total_bounty_earned: float = 0.0
    notes: str = ""

    def to_dict(self) -> Dict[str, Any]:
        """执行相关操作。

        Returns:
            操作结果。
        """
        return {
            "target_id": self.target_id,
            "name": self.name,
            "platform": self.platform.value,
            "platform_url": self.platform_url,
            "description": self.description,
            "bounty_range": self.bounty_range,
            "currency": self.currency,
            "scope_count": len(self.scope),
            "scope": [s.to_dict() for s in self.scope],
            "out_of_scope": self.out_of_scope,
            "priority": self.priority,
            "status": self.status,
            "tags": self.tags,
            "created_at": self.created_at,
            "last_updated": self.last_updated,
            "total_submissions": self.total_submissions,
            "total_bounty_earned": self.total_bounty_earned,
            "notes": self.notes
        }


@dataclass
class DiscoveredAsset:
    """发现的资产"""
    asset_id: str
    target_id: str  # 所属目标项目
    type: str  # subdomain/url/ip/port/endpoint/api
    value: str
    source: str = ""  # 发现来源（subfinder/httpx/manual等）
    status: str = "active"  # active/inactive/unknown
    http_status: int = 0
    title: str = ""
    technologies: List[str] = field(default_factory=list)
    first_seen: float = field(default_factory=time.time)
    last_seen: float = field(default_factory=time.time)
    vulnerabilities: List[Dict[str, Any]] = field(default_factory=list)
    tags: List[str] = field(default_factory=list)
    notes: str = ""

    def to_dict(self) -> Dict[str, Any]:
        """执行相关操作。

        Returns:
            操作结果。
        """
        return {
            "asset_id": self.asset_id,
            "target_id": self.target_id,
            "type": self.type,
            "value": self.value,
            "source": self.source,
            "status": self.status,
            "http_status": self.http_status,
            "title": self.title,
            "technologies": self.technologies,
            "first_seen": self.first_seen,
            "last_seen": self.last_seen,
            "vulnerability_count": len(self.vulnerabilities),
            "tags": self.tags,
            "notes": self.notes
        }


class SRCTargetManager:
    """SRC目标管理器"""

    def __init__(self, data_dir: str = "data/src_platform"):
        """初始化SRCTargetManager实例。

        Args:
            self: 类实例。
        """
        self.data_dir = data_dir
        self.targets: Dict[str, SRCTarget] = {}
        self.assets: Dict[str, DiscoveredAsset] = {}

        os.makedirs(data_dir, exist_ok=True)
        self._load_data()
        self._init_sample_targets()

    def _init_sample_targets(self):
        """初始化示例目标"""
        if self.targets:
            return

        # 示例：HackerOne项目
        sample = SRCTarget(
            target_id="target-001",
            name="示例公司 - 主程序",
            platform=SRCPlatform.HACKERONE,
            platform_url="https://hackerone.com/example",
            description="示例公司的漏洞赏金计划，覆盖所有在线资产",
            bounty_range="$100 - $10000",
            priority=8,
            tags=["web", "api", "high_bounty"]
        )

        # 添加范围
        sample.scope.append(ScopeItem(
            scope_id="scope-001",
            type=ScopeType.WILDCARD,
            value="*.example.com",
            status=ScopeStatus.IN_SCOPE,
            eligible_for_bounty=True
        ))
        sample.scope.append(ScopeItem(
            scope_id="scope-002",
            type=ScopeType.URL,
            value="https://api.example.com",
            status=ScopeStatus.IN_SCOPE,
            eligible_for_bounty=True
        ))
        sample.scope.append(ScopeItem(
            scope_id="scope-003",
            type=ScopeType.DOMAIN,
            value="admin.example.com",
            status=ScopeStatus.OUT_OF_SCOPE,
            eligible_for_bounty=False,
            notes="管理后台明确不在范围内"
        ))

        sample.out_of_scope = [
            "admin.example.com",
            "*.staging.example.com",
            "物理安全测试",
            "社会工程学攻击"
        ]

        sample.allowed_testing_methods = [
            "自动化扫描（速率限制）",
            "手动渗透测试",
            "API测试",
            "子域名枚举"
        ]

        sample.prohibited_testing_methods = [
            "DDoS攻击",
            "数据泄露（超过最小必要）",
            "修改/删除数据",
            "访问其他用户数据"
        ]

        self.targets[sample.target_id] = sample
        self._save_data()

    def _load_data(self):
        """从文件加载数据"""
        targets_file = os.path.join(self.data_dir, "targets.json")
        if os.path.exists(targets_file):
            try:
                with open(targets_file, 'r', encoding='utf-8') as f:
                    targets_data = json.load(f)
                for target_id, data in targets_data.items():
                    target = SRCTarget(
                        target_id=data["target_id"],
                        name=data.get("name", ""),
                        platform=SRCPlatform(data.get("platform", "other")),
                        platform_url=data.get("platform_url", ""),
                        description=data.get("description", ""),
                        bounty_range=data.get("bounty_range", ""),
                        priority=data.get("priority", 5),
                        status=data.get("status", "active"),
                        tags=data.get("tags", []),
                        total_submissions=data.get("total_submissions", 0),
                        total_bounty_earned=data.get("total_bounty_earned", 0),
                        notes=data.get("notes", "")
                    )
                    for s_data in data.get("scope", []):
                        target.scope.append(ScopeItem(
                            scope_id=s_data["scope_id"],
                            type=ScopeType(s_data.get("type", "url")),
                            value=s_data.get("value", ""),
                            status=ScopeStatus(s_data.get("status", "in_scope")),
                            eligible_for_bounty=s_data.get("eligible_for_bounty", True),
                            notes=s_data.get("notes", "")
                        ))
                    target.out_of_scope = data.get("out_of_scope", [])
                    self.targets[target_id] = target
            except Exception as e:
                log.error(f"加载SRC目标失败: {e}")

        assets_file = os.path.join(self.data_dir, "assets.json")
        if os.path.exists(assets_file):
            try:
                with open(assets_file, 'r', encoding='utf-8') as f:
                    assets_data = json.load(f)
                for asset_id, data in assets_data.items():
                    self.assets[asset_id] = DiscoveredAsset(
                        asset_id=data["asset_id"],
                        target_id=data.get("target_id", ""),
                        type=data.get("type", ""),
                        value=data.get("value", ""),
                        source=data.get("source", ""),
                        status=data.get("status", "active"),
                        http_status=data.get("http_status", 0),
                        title=data.get("title", ""),
                        technologies=data.get("technologies", []),
                        tags=data.get("tags", []),
                        notes=data.get("notes", "")
                    )
            except Exception as e:
                log.error(f"加载发现资产失败: {e}")

    def _save_data(self):
        """保存数据到文件"""
        targets_file = os.path.join(self.data_dir, "targets.json")
        try:
            targets_data = {tid: t.to_dict() for tid, t in self.targets.items()}
            with open(targets_file, 'w', encoding='utf-8') as f:
                json.dump(targets_data, f, ensure_ascii=False, indent=2, default=str)
        except Exception as e:
            log.error(f"保存SRC目标失败: {e}")

        assets_file = os.path.join(self.data_dir, "assets.json")
        try:
            assets_data = {aid: a.to_dict() for aid, a in self.assets.items()}
            with open(assets_file, 'w', encoding='utf-8') as f:
                json.dump(assets_data, f, ensure_ascii=False, indent=2, default=str)
        except Exception as e:
            log.error(f"保存发现资产失败: {e}")

    # ===== 目标管理 =====
    def add_target(self, name: str, platform: str = "hackerone",
                   platform_url: str = "", description: str = "",
                   bounty_range: str = "", priority: int = 5,
                   tags: List[str] = None) -> str:
        """添加SRC目标"""
        target_id = f"target-{uuid.uuid4().hex[:8]}"
        target = SRCTarget(
            target_id=target_id,
            name=name,
            platform=SRCPlatform(platform),
            platform_url=platform_url,
            description=description,
            bounty_range=bounty_range,
            priority=priority,
            tags=tags or []
        )
        self.targets[target_id] = target
        self._save_data()
        log.info(f"添加SRC目标: {name} ({target_id})")
        return target_id

    def add_scope(self, target_id: str, scope_type: str, value: str,
                  status: str = "in_scope", eligible: bool = True,
                  notes: str = "") -> Optional[str]:
        """添加范围"""
        target = self.targets.get(target_id)
        if not target:
            return None

        scope_id = f"scope-{uuid.uuid4().hex[:6]}"
        scope = ScopeItem(
            scope_id=scope_id,
            type=ScopeType(scope_type),
            value=value,
            status=ScopeStatus(status),
            eligible_for_bounty=eligible,
            notes=notes
        )
        target.scope.append(scope)
        target.last_updated = time.time()
        self._save_data()
        return scope_id

    def get_targets(self, status: str = None, platform: str = None,
                    priority_min: int = 0) -> List[Dict[str, Any]]:
        """获取目标列表"""
        results = []
        for target in self.targets.values():
            if status and target.status != status:
                continue
            if platform and target.platform.value != platform:
                continue
            if target.priority < priority_min:
                continue
            results.append(target.to_dict())
        results.sort(key=lambda x: x["priority"], reverse=True)
        return results

    def get_target_detail(self, target_id: str) -> Optional[Dict[str, Any]]:
        """获取目标详情"""
        target = self.targets.get(target_id)
        if not target:
            return None
        return target.to_dict()

    def get_in_scope_domains(self, target_id: str) -> List[str]:
        """获取在范围内的域名（用于扫描）"""
        target = self.targets.get(target_id)
        if not target:
            return []

        domains = []
        for scope in target.scope:
            if scope.status == ScopeStatus.IN_SCOPE and scope.eligible_for_bounty:
                if scope.type in [ScopeType.DOMAIN, ScopeType.WILDCARD, ScopeType.URL]:
                    domains.append(scope.value)
        return domains

    def is_in_scope(self, target_id: str, value: str) -> bool:
        """检查资产是否在范围内"""
        target = self.targets.get(target_id)
        if not target:
            return False

        # 检查不在范围内的
        for oos in target.out_of_scope:
            if oos.startswith("*."):
                domain = oos[2:]
                if value.endswith(domain) or value == domain:
                    return False
            elif value == oos or value.endswith("." + oos):
                return False

        # 检查在范围内的
        for scope in target.scope:
            if scope.status != ScopeStatus.IN_SCOPE:
                continue
            if scope.type == ScopeType.WILDCARD:
                domain = scope.value.replace("*.", "")
                if value.endswith(domain) or value == domain:
                    return True
            elif scope.type == ScopeType.DOMAIN:
                if value == scope.value or value.endswith("." + scope.value):
                    return True
            elif scope.type == ScopeType.URL:
                if value.startswith(scope.value):
                    return True
        return False

    # ===== 资产管理 =====
    def add_asset(self, target_id: str, asset_type: str, value: str,
                  source: str = "", http_status: int = 0, title: str = "",
                  technologies: List[str] = None) -> str:
        """添加发现的资产"""
        asset_id = f"asset-{uuid.uuid4().hex[:8]}"
        asset = DiscoveredAsset(
            asset_id=asset_id,
            target_id=target_id,
            type=asset_type,
            value=value,
            source=source,
            http_status=http_status,
            title=title,
            technologies=technologies or []
        )
        self.assets[asset_id] = asset

        # 更新目标的范围发现资产
        target = self.targets.get(target_id)
        if target:
            for scope in target.scope:
                if self._value_matches_scope(value, scope):
                    if value not in scope.discovered_assets:
                        scope.discovered_assets.append(value)
                    break

        self._save_data()
        return asset_id

    def _value_matches_scope(self, value: str, scope: ScopeItem) -> bool:
        """检查值是否匹配范围"""
        if scope.type == ScopeType.WILDCARD:
            domain = scope.value.replace("*.", "")
            return value.endswith(domain) or value == domain
        elif scope.type == ScopeType.DOMAIN:
            return value == scope.value or value.endswith("." + scope.value)
        return False

    def get_assets(self, target_id: str = None, asset_type: str = None,
                   status: str = None, has_vulns: bool = None) -> List[Dict[str, Any]]:
        """获取资产列表"""
        results = []
        for asset in self.assets.values():
            if target_id and asset.target_id != target_id:
                continue
            if asset_type and asset.type != asset_type:
                continue
            if status and asset.status != status:
                continue
            if has_vulns is not None:
                if has_vulns and not asset.vulnerabilities:
                    continue
                if not has_vulns and asset.vulnerabilities:
                    continue
            results.append(asset.to_dict())
        results.sort(key=lambda x: x["last_seen"], reverse=True)
        return results

    def batch_add_assets(self, target_id: str, assets: List[Dict[str, Any]]) -> int:
        """批量添加资产"""
        count = 0
        for asset_data in assets:
            # 检查是否已存在
            exists = any(a.value == asset_data.get("value") and a.target_id == target_id
                        for a in self.assets.values())
            if not exists:
                self.add_asset(
                    target_id=target_id,
                    asset_type=asset_data.get("type", "url"),
                    value=asset_data.get("value", ""),
                    source=asset_data.get("source", ""),
                    http_status=asset_data.get("http_status", 0),
                    title=asset_data.get("title", ""),
                    technologies=asset_data.get("technologies", [])
                )
                count += 1
        return count

    # ===== 统计 =====
    def get_statistics(self) -> Dict[str, Any]:
        """获取统计信息"""
        total_targets = len(self.targets)
        active_targets = sum(1 for t in self.targets.values() if t.status == "active")
        total_assets = len(self.assets)
        assets_with_vulns = sum(1 for a in self.assets.values() if a.vulnerabilities)
        total_scope = sum(len(t.scope) for t in self.targets.values())
        total_bounty = sum(t.total_bounty_earned for t in self.targets.values())

        # 按平台统计
        by_platform = {}
        for target in self.targets.values():
            p = target.platform.value
            by_platform[p] = by_platform.get(p, 0) + 1

        # 按资产类型统计
        by_asset_type = {}
        for asset in self.assets.values():
            t = asset.type
            by_asset_type[t] = by_asset_type.get(t, 0) + 1

        return {
            "total_targets": total_targets,
            "active_targets": active_targets,
            "total_assets": total_assets,
            "assets_with_vulnerabilities": assets_with_vulns,
            "total_scope_items": total_scope,
            "total_bounty_earned": total_bounty,
            "targets_by_platform": by_platform,
            "assets_by_type": by_asset_type,
            "platforms": [p.value for p in SRCPlatform]
        }


# 全局实例
src_target_manager = SRCTargetManager()
