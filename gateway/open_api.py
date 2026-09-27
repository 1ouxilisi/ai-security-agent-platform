#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
open_api模块，提供相关安全测试功能。

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
import hashlib
import secrets
from typing import Any, Dict, List, Optional
from dataclasses import dataclass, field
from enum import Enum

from utils.logger import log


class APIKeyStatus(str, Enum):
    """API密钥状态"""
    ACTIVE = "active"
    SUSPENDED = "suspended"
    REVOKED = "revoked"
    EXPIRED = "expired"


class APICallStatus(str, Enum):
    """API调用状态"""
    SUCCESS = "success"
    FAILED = "failed"
    RATE_LIMITED = "rate_limited"
    UNAUTHORIZED = "unauthorized"


@dataclass
class APIKey:
    """API密钥"""
    key_id: str
    api_key: str
    name: str
    description: str = ""
    status: APIKeyStatus = APIKeyStatus.ACTIVE
    created_at: float = field(default_factory=time.time)
    expires_at: Optional[float] = None
    last_used_at: Optional[float] = None
    rate_limit_per_minute: int = 60
    daily_quota: int = 10000
    total_calls: int = 0
    today_calls: int = 0
    last_reset_date: str = ""
    allowed_ips: List[str] = field(default_factory=list)
    scopes: List[str] = field(default_factory=list)  # 允许调用的API范围

    def to_dict(self, include_key: bool = False) -> Dict[str, Any]:
        """执行相关操作。

        Args:
            include_key: 相关参数。

        Returns:
            操作结果。
        """
        data = {
            "key_id": self.key_id,
            "name": self.name,
            "description": self.description,
            "status": self.status.value,
            "created_at": self.created_at,
            "expires_at": self.expires_at,
            "last_used_at": self.last_used_at,
            "rate_limit_per_minute": self.rate_limit_per_minute,
            "daily_quota": self.daily_quota,
            "total_calls": self.total_calls,
            "today_calls": self.today_calls,
            "allowed_ips": self.allowed_ips,
            "scopes": self.scopes
        }
        if include_key:
            data["api_key"] = self.api_key
        return data


@dataclass
class APICallLog:
    """API调用日志"""
    log_id: str
    api_key_id: str
    endpoint: str
    method: str
    status: APICallStatus
    status_code: int = 0
    response_time_ms: float = 0
    client_ip: str = ""
    user_agent: str = ""
    request_params: Dict[str, Any] = field(default_factory=dict)
    error_message: str = ""
    timestamp: float = field(default_factory=time.time)

    def to_dict(self) -> Dict[str, Any]:
        """执行相关操作。

        Returns:
            操作结果。
        """
        return {
            "log_id": self.log_id,
            "api_key_id": self.api_key_id,
            "endpoint": self.endpoint,
            "method": self.method,
            "status": self.status.value,
            "status_code": self.status_code,
            "response_time_ms": self.response_time_ms,
            "client_ip": self.client_ip,
            "user_agent": self.user_agent,
            "error_message": self.error_message,
            "timestamp": self.timestamp
        }


@dataclass
class APIEndpoint:
    """API端点定义"""
    endpoint_id: str
    path: str
    method: str
    name: str
    description: str
    category: str  # scan/recon/exploit/report/knowledge
    required_scopes: List[str] = field(default_factory=list)
    rate_limit_weight: int = 1  # 调用权重，消耗的配额倍数
    enabled: bool = True

    def to_dict(self) -> Dict[str, Any]:
        """执行相关操作。

        Returns:
            操作结果。
        """
        return {
            "endpoint_id": self.endpoint_id,
            "path": self.path,
            "method": self.method,
            "name": self.name,
            "description": self.description,
            "category": self.category,
            "required_scopes": self.required_scopes,
            "rate_limit_weight": self.rate_limit_weight,
            "enabled": self.enabled
        }


class OpenAPIPlatform:
    """API开放平台"""

    def __init__(self, data_dir: str = "data/open_api"):
        """初始化OpenAPIPlatform实例。

        Args:
            self: 类实例。
        """
        self.data_dir = data_dir
        self.api_keys: Dict[str, APIKey] = {}  # key_id -> APIKey
        self.api_key_index: Dict[str, str] = {}  # api_key -> key_id
        self.call_logs: List[APICallLog] = []
        self.endpoints: Dict[str, APIEndpoint] = {}
        self.rate_limit_cache: Dict[str, List[float]] = {}  # key_id -> 调用时间戳列表

        os.makedirs(data_dir, exist_ok=True)
        self._init_endpoints()
        self._load_data()

    def _init_endpoints(self):
        """初始化API端点"""
        endpoints = [
            APIEndpoint("ep-001", "/api/v1/scan/port", "POST", "端口扫描", "扫描目标主机的开放端口和服务", "scan", ["scan:port"], 1),
            APIEndpoint("ep-002", "/api/v1/scan/vulnerability", "POST", "漏洞扫描", "对目标进行漏洞扫描", "scan", ["scan:vuln"], 3),
            APIEndpoint("ep-003", "/api/v1/recon/dns", "POST", "DNS解析", "解析域名的DNS记录", "recon", ["recon:dns"], 1),
            APIEndpoint("ep-004", "/api/v1/recon/subdomain", "POST", "子域名枚举", "枚举目标的子域名", "recon", ["recon:subdomain"], 2),
            APIEndpoint("ep-005", "/api/v1/exploit/sql_injection", "POST", "SQL注入利用", "利用SQL注入漏洞提取数据", "exploit", ["exploit:sql"], 5),
            APIEndpoint("ep-006", "/api/v1/exploit/xss", "POST", "XSS利用", "验证和利用XSS漏洞", "exploit", ["exploit:xss"], 3),
            APIEndpoint("ep-007", "/api/v1/knowledge/cve", "GET", "CVE查询", "查询CVE漏洞详情", "knowledge", ["knowledge:cve"], 1),
            APIEndpoint("ep-008", "/api/v1/knowledge/poc", "GET", "PoC查询", "查询漏洞利用代码", "knowledge", ["knowledge:poc"], 1),
            APIEndpoint("ep-009", "/api/v1/report/generate", "POST", "生成报告", "生成渗透测试报告", "report", ["report:generate"], 5),
            APIEndpoint("ep-010", "/api/v1/workflow/start", "POST", "启动工作流", "启动自动化渗透测试工作流", "workflow", ["workflow:start"], 10),
            APIEndpoint("ep-011", "/api/v1/workflow/status", "GET", "工作流状态", "查询工作流执行状态", "workflow", ["workflow:status"], 1),
            APIEndpoint("ep-012", "/api/v1/system/stats", "GET", "系统统计", "获取系统统计信息", "system", ["system:stats"], 1),
        ]
        for ep in endpoints:
            self.endpoints[ep.endpoint_id] = ep

    def _load_data(self):
        """从文件加载数据"""
        # 加载API密钥
        keys_file = os.path.join(self.data_dir, "api_keys.json")
        if os.path.exists(keys_file):
            try:
                with open(keys_file, 'r', encoding='utf-8') as f:
                    keys_data = json.load(f)
                for key_id, key_data in keys_data.items():
                    key = APIKey(
                        key_id=key_data["key_id"],
                        api_key=key_data["api_key"],
                        name=key_data["name"],
                        description=key_data.get("description", ""),
                        status=APIKeyStatus(key_data.get("status", "active")),
                        created_at=key_data.get("created_at", time.time()),
                        expires_at=key_data.get("expires_at"),
                        last_used_at=key_data.get("last_used_at"),
                        rate_limit_per_minute=key_data.get("rate_limit_per_minute", 60),
                        daily_quota=key_data.get("daily_quota", 10000),
                        total_calls=key_data.get("total_calls", 0),
                        today_calls=key_data.get("today_calls", 0),
                        allowed_ips=key_data.get("allowed_ips", []),
                        scopes=key_data.get("scopes", [])
                    )
                    self.api_keys[key_id] = key
                    self.api_key_index[key.api_key] = key_id
            except Exception as e:
                log.error(f"加载API密钥失败: {e}")

        # 加载调用日志
        logs_file = os.path.join(self.data_dir, "call_logs.json")
        if os.path.exists(logs_file):
            try:
                with open(logs_file, 'r', encoding='utf-8') as f:
                    logs_data = json.load(f)
                for log_data in logs_data[-1000:]:  # 只保留最近1000条
                    self.call_logs.append(APICallLog(
                        log_id=log_data["log_id"],
                        api_key_id=log_data["api_key_id"],
                        endpoint=log_data["endpoint"],
                        method=log_data["method"],
                        status=APICallStatus(log_data.get("status", "success")),
                        status_code=log_data.get("status_code", 0),
                        response_time_ms=log_data.get("response_time_ms", 0),
                        client_ip=log_data.get("client_ip", ""),
                        user_agent=log_data.get("user_agent", ""),
                        error_message=log_data.get("error_message", ""),
                        timestamp=log_data.get("timestamp", time.time())
                    ))
            except Exception as e:
                log.error(f"加载调用日志失败: {e}")

    def _save_data(self):
        """保存数据到文件"""
        # 保存API密钥
        keys_file = os.path.join(self.data_dir, "api_keys.json")
        try:
            keys_data = {k_id: k.to_dict(include_key=True) for k_id, k in self.api_keys.items()}
            with open(keys_file, 'w', encoding='utf-8') as f:
                json.dump(keys_data, f, ensure_ascii=False, indent=2, default=str)
        except Exception as e:
            log.error(f"保存API密钥失败: {e}")

        # 保存调用日志（只保留最近1000条）
        logs_file = os.path.join(self.data_dir, "call_logs.json")
        try:
            logs_data = [log.to_dict() for log in self.call_logs[-1000:]]
            with open(logs_file, 'w', encoding='utf-8') as f:
                json.dump(logs_data, f, ensure_ascii=False, indent=2, default=str)
        except Exception as e:
            log.error(f"保存调用日志失败: {e}")

    # ===== API密钥管理 =====
    def create_api_key(self, name: str, description: str = "",
                       rate_limit_per_minute: int = 60,
                       daily_quota: int = 10000,
                       scopes: List[str] = None,
                       expires_in_days: int = 365) -> Dict[str, Any]:
        """创建API密钥"""
        key_id = f"key-{uuid.uuid4().hex[:8]}"
        api_key = f"sk-{secrets.token_hex(32)}"

        key = APIKey(
            key_id=key_id,
            api_key=api_key,
            name=name,
            description=description,
            rate_limit_per_minute=rate_limit_per_minute,
            daily_quota=daily_quota,
            scopes=scopes or ["scan:port", "recon:dns", "knowledge:cve"],
            expires_at=time.time() + expires_in_days * 86400 if expires_in_days else None
        )

        self.api_keys[key_id] = key
        self.api_key_index[api_key] = key_id
        self._save_data()

        log.info(f"创建API密钥: {name} ({key_id})")
        return key.to_dict(include_key=True)

    def validate_api_key(self, api_key: str, client_ip: str = "") -> Optional[APIKey]:
        """验证API密钥"""
        key_id = self.api_key_index.get(api_key)
        if not key_id:
            return None

        key = self.api_keys.get(key_id)
        if not key:
            return None

        # 检查状态
        if key.status != APIKeyStatus.ACTIVE:
            return None

        # 检查过期
        if key.expires_at and key.expires_at < time.time():
            key.status = APIKeyStatus.EXPIRED
            self._save_data()
            return None

        # 检查IP白名单
        if key.allowed_ips and client_ip not in key.allowed_ips:
            return None

        # 检查每日配额
        today = time.strftime("%Y-%m-%d")
        if key.last_reset_date != today:
            key.today_calls = 0
            key.last_reset_date = today

        if key.today_calls >= key.daily_quota:
            return None

        # 检查速率限制
        now = time.time()
        if key_id not in self.rate_limit_cache:
            self.rate_limit_cache[key_id] = []
        self.rate_limit_cache[key_id] = [t for t in self.rate_limit_cache[key_id] if now - t < 60]
        if len(self.rate_limit_cache[key_id]) >= key.rate_limit_per_minute:
            return None

        return key

    def record_call(self, api_key: APIKey, endpoint: str, method: str,
                    status: APICallStatus, status_code: int = 0,
                    response_time_ms: float = 0, client_ip: str = "",
                    user_agent: str = "", error_message: str = ""):
        """记录API调用"""
        log_entry = APICallLog(
            log_id=f"log-{uuid.uuid4().hex[:8]}",
            api_key_id=api_key.key_id,
            endpoint=endpoint,
            method=method,
            status=status,
            status_code=status_code,
            response_time_ms=response_time_ms,
            client_ip=client_ip,
            user_agent=user_agent,
            error_message=error_message
        )
        self.call_logs.append(log_entry)

        # 更新密钥统计
        api_key.last_used_at = time.time()
        api_key.total_calls += 1
        api_key.today_calls += 1
        if api_key.key_id not in self.rate_limit_cache:
            self.rate_limit_cache[api_key.key_id] = []
        self.rate_limit_cache[api_key.key_id].append(time.time())

        self._save_data()

    def revoke_api_key(self, key_id: str) -> bool:
        """撤销API密钥"""
        key = self.api_keys.get(key_id)
        if not key:
            return False
        key.status = APIKeyStatus.REVOKED
        self._save_data()
        log.info(f"撤销API密钥: {key.name} ({key_id})")
        return True

    def list_api_keys(self, status: str = None) -> List[Dict[str, Any]]:
        """列出API密钥"""
        results = []
        for key in self.api_keys.values():
            if status and key.status.value != status:
                continue
            results.append(key.to_dict())
        return results

    # ===== 端点管理 =====
    def list_endpoints(self, category: str = None) -> List[Dict[str, Any]]:
        """列出API端点"""
        results = []
        for ep in self.endpoints.values():
            if category and ep.category != category:
                continue
            if ep.enabled:
                results.append(ep.to_dict())
        return results

    # ===== 统计 =====
    def get_statistics(self) -> Dict[str, Any]:
        """获取平台统计"""
        total_calls = len(self.call_logs)
        success_calls = sum(1 for l in self.call_logs if l.status == APICallStatus.SUCCESS)
        failed_calls = sum(1 for l in self.call_logs if l.status == APICallStatus.FAILED)

        # 按端点统计
        endpoint_stats = {}
        for log in self.call_logs:
            if log.endpoint not in endpoint_stats:
                endpoint_stats[log.endpoint] = {"calls": 0, "success": 0, "failed": 0}
            endpoint_stats[log.endpoint]["calls"] += 1
            if log.status == APICallStatus.SUCCESS:
                endpoint_stats[log.endpoint]["success"] += 1
            else:
                endpoint_stats[log.endpoint]["failed"] += 1

        # 平均响应时间
        avg_response_time = 0
        if self.call_logs:
            avg_response_time = sum(l.response_time_ms for l in self.call_logs) / len(self.call_logs)

        return {
            "total_api_keys": len(self.api_keys),
            "active_api_keys": sum(1 for k in self.api_keys.values() if k.status == APIKeyStatus.ACTIVE),
            "total_endpoints": len(self.endpoints),
            "total_calls": total_calls,
            "success_calls": success_calls,
            "failed_calls": failed_calls,
            "success_rate": round(success_calls / total_calls * 100, 2) if total_calls > 0 else 0,
            "avg_response_time_ms": round(avg_response_time, 2),
            "endpoint_stats": endpoint_stats,
            "today_calls": sum(k.today_calls for k in self.api_keys.values())
        }

    def get_call_logs(self, key_id: str = None, limit: int = 50) -> List[Dict[str, Any]]:
        """获取调用日志"""
        logs = self.call_logs
        if key_id:
            logs = [l for l in logs if l.api_key_id == key_id]
        logs.sort(key=lambda l: l.timestamp, reverse=True)
        return [l.to_dict() for l in logs[:limit]]


# 全局实例
open_api_platform = OpenAPIPlatform()
