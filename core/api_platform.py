#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
API开放平台
API Open Platform

功能：API密钥管理、调用统计、限流计费、SDK生成、开发者文档、应用管理
"""

import os
import json
import time
import uuid
import hashlib
import secrets
from dataclasses import dataclass, field, asdict
from typing import Optional, Dict, Any, List, Tuple
from enum import Enum
from collections import defaultdict, deque
from loguru import logger


class APIKeyStatus(str, Enum):
    """API密钥状态"""
    ACTIVE = "active"
    SUSPENDED = "suspended"
    REVOKED = "revoked"
    EXPIRED = "expired"


class PlanTier(str, Enum):
    """套餐等级"""
    FREE = "free"           # 免费版
    BASIC = "basic"         # 基础版
    PRO = "pro"             # 专业版
    ENTERPRISE = "enterprise"  # 企业版


class ApplicationStatus(str, Enum):
    """应用状态"""
    DEVELOPMENT = "development"
    REVIEW = "review"
    APPROVED = "approved"
    REJECTED = "rejected"
    SUSPENDED = "suspended"


@dataclass
class Plan:
    """套餐"""
    plan_id: str
    name: str
    tier: PlanTier
    description: str = ""
    price_monthly: float = 0.0
    price_yearly: float = 0.0
    rate_limit_per_minute: int = 60
    rate_limit_per_day: int = 10000
    rate_limit_per_month: int = 100000
    max_concurrent_requests: int = 10
    max_api_keys: int = 5
    features: List[str] = field(default_factory=list)
    is_active: bool = True

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


@dataclass
class Application:
    """应用"""
    app_id: str
    name: str
    description: str = ""
    owner_id: str = ""
    status: ApplicationStatus = ApplicationStatus.DEVELOPMENT
    plan_id: str = "free"
    website: str = ""
    callback_url: str = ""
    logo_url: str = ""
    created_at: float = field(default_factory=time.time)
    updated_at: float = field(default_factory=time.time)
    approved_at: Optional[float] = None
    settings: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        return {
            'app_id': self.app_id,
            'name': self.name,
            'description': self.description,
            'owner_id': self.owner_id,
            'status': self.status.value,
            'plan_id': self.plan_id,
            'website': self.website,
            'callback_url': self.callback_url,
            'logo_url': self.logo_url,
            'created_at': self.created_at,
            'updated_at': self.updated_at,
            'approved_at': self.approved_at,
            'settings': self.settings,
        }


@dataclass
class APIKey:
    """API密钥"""
    key_id: str
    app_id: str
    name: str
    key: str
    secret: str = ""
    status: APIKeyStatus = APIKeyStatus.ACTIVE
    created_at: float = field(default_factory=time.time)
    expires_at: Optional[float] = None
    last_used_at: Optional[float] = None
    ip_whitelist: List[str] = field(default_factory=list)
    referer_whitelist: List[str] = field(default_factory=list)
    scopes: List[str] = field(default_factory=list)  # 权限范围
    usage_today: int = 0
    usage_month: int = 0
    usage_total: int = 0

    def to_dict(self) -> Dict[str, Any]:
        return {
            'key_id': self.key_id,
            'app_id': self.app_id,
            'name': self.name,
            'key': self.key[:8] + '...' + self.key[-4:],  # 脱敏
            'status': self.status.value,
            'created_at': self.created_at,
            'expires_at': self.expires_at,
            'last_used_at': self.last_used_at,
            'ip_whitelist': self.ip_whitelist,
            'referer_whitelist': self.referer_whitelist,
            'scopes': self.scopes,
            'usage_today': self.usage_today,
            'usage_month': self.usage_month,
            'usage_total': self.usage_total,
        }


@dataclass
class APICallLog:
    """API调用日志"""
    log_id: str
    api_key: str
    app_id: str
    endpoint: str
    method: str
    status_code: int
    response_time_ms: float
    ip_address: str = ""
    user_agent: str = ""
    request_size: int = 0
    response_size: int = 0
    error_message: str = ""
    timestamp: float = field(default_factory=time.time)

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


@dataclass
class APIEndpoint:
    """API端点信息"""
    path: str
    method: str
    description: str = ""
    category: str = ""
    auth_required: bool = True
    rate_limited: bool = True
    cost_per_call: float = 0.0  # 每次调用费用
    parameters: List[Dict[str, Any]] = field(default_factory=list)
    response_example: Dict[str, Any] = field(default_factory=dict)
    is_deprecated: bool = False

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


class RateLimiter:
    """限流器"""

    def __init__(self):
        self._requests: Dict[str, deque] = defaultdict(deque)
        self._daily_usage: Dict[str, int] = defaultdict(int)
        self._monthly_usage: Dict[str, int] = defaultdict(int)
        self._last_reset_day: str = time.strftime("%Y-%m-%d")
        self._last_reset_month: str = time.strftime("%Y-%m")

    def _check_reset(self):
        """检查是否需要重置计数"""
        today = time.strftime("%Y-%m-%d")
        month = time.strftime("%Y-%m")

        if today != self._last_reset_day:
            self._daily_usage.clear()
            self._last_reset_day = today

        if month != self._last_reset_month:
            self._monthly_usage.clear()
            self._last_reset_month = month

    def check_rate_limit(self, api_key: str, plan: Plan) -> Tuple[bool, str]:
        """检查限流"""
        self._check_reset()

        now = time.time()
        key_requests = self._requests[api_key]

        # 清理1分钟前的请求
        while key_requests and now - key_requests[0] > 60:
            key_requests.popleft()

        # 检查每分钟限流
        if len(key_requests) >= plan.rate_limit_per_minute:
            return False, f"每分钟请求数超过限制 ({plan.rate_limit_per_minute})"

        # 检查每日限流
        daily_usage = self._daily_usage[api_key]
        if daily_usage >= plan.rate_limit_per_day:
            return False, f"每日请求数超过限制 ({plan.rate_limit_per_day})"

        # 检查每月限流
        monthly_usage = self._monthly_usage[api_key]
        if monthly_usage >= plan.rate_limit_per_month:
            return False, f"每月请求数超过限制 ({plan.rate_limit_per_month})"

        return True, ""

    def record_request(self, api_key: str):
        """记录请求"""
        now = time.time()
        self._requests[api_key].append(now)
        self._daily_usage[api_key] += 1
        self._monthly_usage[api_key] += 1

    def get_usage(self, api_key: str) -> Dict[str, Any]:
        """获取使用情况"""
        self._check_reset()
        return {
            'requests_per_minute': len(self._requests[api_key]),
            'daily_usage': self._daily_usage[api_key],
            'monthly_usage': self._monthly_usage[api_key],
        }


class APIPlatformManager:
    """API开放平台管理器"""

    def __init__(self, data_dir: str = "data/api_platform"):
        self.data_dir = data_dir
        self.apps_file = os.path.join(data_dir, "apps.json")
        self.keys_file = os.path.join(data_dir, "api_keys.json")
        self.logs_file = os.path.join(data_dir, "call_logs.json")

        self._plans: Dict[str, Plan] = {}
        self._apps: Dict[str, Application] = {}
        self._api_keys: Dict[str, APIKey] = {}  # key_id -> APIKey
        self._key_index: Dict[str, str] = {}  # key string -> key_id
        self._call_logs: deque = deque(maxlen=10000)
        self._endpoints: Dict[str, APIEndpoint] = {}

        self._rate_limiter = RateLimiter()

        os.makedirs(data_dir, exist_ok=True)

        self._init_plans()
        self._init_endpoints()
        self._load_all()

        logger.info("API开放平台管理器初始化完成")

    def _init_plans(self):
        """初始化套餐"""
        self._plans = {
            'free': Plan(
                plan_id='free',
                name='免费版',
                tier=PlanTier.FREE,
                description='适合个人开发者和试用',
                price_monthly=0.0,
                price_yearly=0.0,
                rate_limit_per_minute=30,
                rate_limit_per_day=1000,
                rate_limit_per_month=10000,
                max_concurrent_requests=5,
                max_api_keys=2,
                features=['基础扫描', '漏洞查询', '报告生成'],
            ),
            'basic': Plan(
                plan_id='basic',
                name='基础版',
                tier=PlanTier.BASIC,
                description='适合小型团队',
                price_monthly=99.0,
                price_yearly=999.0,
                rate_limit_per_minute=120,
                rate_limit_per_day=10000,
                rate_limit_per_month=100000,
                max_concurrent_requests=20,
                max_api_keys=10,
                features=['全部免费功能', '高级扫描', '实战能力', 'API优先支持'],
            ),
            'pro': Plan(
                plan_id='pro',
                name='专业版',
                tier=PlanTier.PRO,
                description='适合专业安全团队',
                price_monthly=499.0,
                price_yearly=4999.0,
                rate_limit_per_minute=600,
                rate_limit_per_day=50000,
                rate_limit_per_month=500000,
                max_concurrent_requests=100,
                max_api_keys=50,
                features=['全部基础功能', '分布式扫描', '团队协作', '实时监控', '专属客服'],
            ),
            'enterprise': Plan(
                plan_id='enterprise',
                name='企业版',
                tier=PlanTier.ENTERPRISE,
                description='适合大型企业',
                price_monthly=1999.0,
                price_yearly=19999.0,
                rate_limit_per_minute=3000,
                rate_limit_per_day=500000,
                rate_limit_per_month=5000000,
                max_concurrent_requests=500,
                max_api_keys=500,
                features=['全部专业功能', '私有化部署', '定制开发', 'SLA保障', '专属技术团队'],
            ),
        }

    def _init_endpoints(self):
        """初始化API端点信息"""
        endpoints = [
            # 扫描相关
            APIEndpoint(path='/api/v1/scan/port', method='POST', description='端口扫描',
                        category='scan', parameters=[{'name': 'target', 'type': 'string', 'required': True}]),
            APIEndpoint(path='/api/v1/scan/directory', method='POST', description='目录扫描',
                        category='scan', parameters=[{'name': 'target', 'type': 'string', 'required': True}]),
            APIEndpoint(path='/api/v1/scan/subdomain', method='POST', description='子域名扫描',
                        category='scan', parameters=[{'name': 'target', 'type': 'string', 'required': True}]),
            APIEndpoint(path='/api/v1/scan/vulnerability', method='POST', description='漏洞扫描',
                        category='scan', parameters=[{'name': 'target', 'type': 'string', 'required': True}]),
            # 漏洞相关
            APIEndpoint(path='/api/v1/vulnerabilities', method='GET', description='获取漏洞列表',
                        category='vulnerability'),
            APIEndpoint(path='/api/v1/vulnerabilities/{id}', method='GET', description='获取漏洞详情',
                        category='vulnerability'),
            APIEndpoint(path='/api/v1/vulnerabilities/search', method='POST', description='搜索漏洞',
                        category='vulnerability'),
            # 报告相关
            APIEndpoint(path='/api/v1/reports', method='POST', description='生成报告',
                        category='report', parameters=[{'name': 'type', 'type': 'string', 'required': True}]),
            APIEndpoint(path='/api/v1/reports/{id}', method='GET', description='获取报告',
                        category='report'),
            APIEndpoint(path='/api/v1/reports/{id}/download', method='GET', description='下载报告',
                        category='report'),
            # 知识库
            APIEndpoint(path='/api/v1/knowledge/cve', method='GET', description='CVE知识库',
                        category='knowledge'),
            APIEndpoint(path='/api/v1/knowledge/exploits', method='GET', description='利用库',
                        category='knowledge'),
            # 系统
            APIEndpoint(path='/api/v1/system/stats', method='GET', description='系统统计',
                        category='system', auth_required=False),
            APIEndpoint(path='/api/v1/system/health', method='GET', description='健康检查',
                        category='system', auth_required=False, rate_limited=False),
        ]

        for ep in endpoints:
            self._endpoints[f"{ep.method}:{ep.path}"] = ep

    # ============== 应用管理 ==============

    def create_application(self, name: str, owner_id: str, description: str = "",
                           website: str = "", callback_url: str = "") -> Application:
        """创建应用"""
        app_id = str(uuid.uuid4())
        app = Application(
            app_id=app_id,
            name=name,
            description=description,
            owner_id=owner_id,
            website=website,
            callback_url=callback_url,
        )
        self._apps[app_id] = app
        self._save_apps()
        logger.info(f"创建应用: {name} ({app_id})")
        return app

    def get_application(self, app_id: str) -> Optional[Application]:
        """获取应用"""
        return self._apps.get(app_id)

    def list_applications(self, owner_id: str = None, status: ApplicationStatus = None) -> List[Application]:
        """列出应用"""
        apps = list(self._apps.values())
        if owner_id:
            apps = [a for a in apps if a.owner_id == owner_id]
        if status:
            apps = [a for a in apps if a.status == status]
        return sorted(apps, key=lambda a: a.created_at, reverse=True)

    def update_application_plan(self, app_id: str, plan_id: str) -> Optional[Application]:
        """更新应用套餐"""
        app = self._apps.get(app_id)
        if app and plan_id in self._plans:
            app.plan_id = plan_id
            app.updated_at = time.time()
            self._save_apps()
            return app
        return None

    # ============== API密钥管理 ==============

    def generate_api_key(self, app_id: str, name: str, scopes: List[str] = None,
                         expires_at: float = None, ip_whitelist: List[str] = None) -> Optional[APIKey]:
        """生成API密钥"""
        app = self._apps.get(app_id)
        if not app:
            return None

        plan = self._plans.get(app.plan_id, self._plans['free'])

        # 检查API密钥数量限制
        app_keys = [k for k in self._api_keys.values() if k.app_id == app_id and k.status == APIKeyStatus.ACTIVE]
        if len(app_keys) >= plan.max_api_keys:
            logger.warning(f"API密钥数量超过限制: {app_id}")
            return None

        key_id = str(uuid.uuid4())
        api_key = f"sk-{secrets.token_hex(24)}"
        api_secret = secrets.token_hex(32)

        key = APIKey(
            key_id=key_id,
            app_id=app_id,
            name=name,
            key=api_key,
            secret=api_secret,
            expires_at=expires_at,
            ip_whitelist=ip_whitelist or [],
            scopes=scopes or ['read', 'write'],
        )

        self._api_keys[key_id] = key
        self._key_index[api_key] = key_id
        self._save_keys()

        logger.info(f"生成API密钥: {name} ({key_id})")
        return key

    def validate_api_key(self, api_key: str, endpoint: str = "", method: str = "",
                          ip_address: str = "") -> Tuple[bool, str, Optional[APIKey]]:
        """验证API密钥"""
        key_id = self._key_index.get(api_key)
        if not key_id:
            return False, "无效的API密钥", None

        key = self._api_keys.get(key_id)
        if not key:
            return False, "API密钥不存在", None

        # 检查状态
        if key.status != APIKeyStatus.ACTIVE:
            return False, f"API密钥状态异常: {key.status.value}", None

        # 检查过期
        if key.expires_at and time.time() > key.expires_at:
            key.status = APIKeyStatus.EXPIRED
            self._save_keys()
            return False, "API密钥已过期", None

        # 检查IP白名单
        if key.ip_whitelist and ip_address not in key.ip_whitelist:
            return False, "IP地址不在白名单中", None

        # 检查限流
        app = self._apps.get(key.app_id)
        if app:
            plan = self._plans.get(app.plan_id, self._plans['free'])
            allowed, message = self._rate_limiter.check_rate_limit(api_key, plan)
            if not allowed:
                return False, message, key

        # 更新使用统计
        key.last_used_at = time.time()
        key.usage_today += 1
        key.usage_month += 1
        key.usage_total += 1
        self._save_keys()

        # 记录请求
        self._rate_limiter.record_request(api_key)

        return True, "", key

    def revoke_api_key(self, key_id: str) -> bool:
        """吊销API密钥"""
        key = self._api_keys.get(key_id)
        if key:
            key.status = APIKeyStatus.REVOKED
            if key.key in self._key_index:
                del self._key_index[key.key]
            self._save_keys()
            return True
        return False

    def list_api_keys(self, app_id: str = None) -> List[APIKey]:
        """列出API密钥"""
        keys = list(self._api_keys.values())
        if app_id:
            keys = [k for k in keys if k.app_id == app_id]
        return sorted(keys, key=lambda k: k.created_at, reverse=True)

    # ============== 调用日志 ==============

    def log_call(self, api_key: str, app_id: str, endpoint: str, method: str,
                 status_code: int, response_time_ms: float, ip_address: str = "",
                 user_agent: str = "", error_message: str = "") -> APICallLog:
        """记录API调用"""
        log = APICallLog(
            log_id=str(uuid.uuid4()),
            api_key=api_key[:8] + '...',
            app_id=app_id,
            endpoint=endpoint,
            method=method,
            status_code=status_code,
            response_time_ms=response_time_ms,
            ip_address=ip_address,
            user_agent=user_agent,
            error_message=error_message,
        )
        self._call_logs.append(log)
        return log

    def get_call_logs(self, app_id: str = None, api_key: str = None,
                      endpoint: str = None, limit: int = 100) -> List[APICallLog]:
        """获取调用日志"""
        logs = list(self._call_logs)
        if app_id:
            logs = [l for l in logs if l.app_id == app_id]
        if api_key:
            logs = [l for l in logs if l.api_key == api_key]
        if endpoint:
            logs = [l for l in logs if l.endpoint == endpoint]
        logs.sort(key=lambda l: l.timestamp, reverse=True)
        return logs[:limit]

    # ============== 统计 ==============

    def get_usage_stats(self, app_id: str) -> Dict[str, Any]:
        """获取使用统计"""
        app = self._apps.get(app_id)
        if not app:
            return {}

        plan = self._plans.get(app.plan_id, self._plans['free'])
        app_keys = [k for k in self._api_keys.values() if k.app_id == app_id]
        app_logs = [l for l in self._call_logs if l.app_id == app_id]

        # 计算成功率
        success_count = len([l for l in app_logs if 200 <= l.status_code < 300])
        error_count = len([l for l in app_logs if l.status_code >= 400])

        # 计算平均响应时间
        avg_response_time = (sum(l.response_time_ms for l in app_logs) / len(app_logs)) if app_logs else 0

        # 按端点统计
        endpoint_stats = defaultdict(lambda: {'count': 0, 'success': 0, 'error': 0, 'avg_time': 0.0})
        for log in app_logs:
            ep = endpoint_stats[log.endpoint]
            ep['count'] += 1
            if 200 <= log.status_code < 300:
                ep['success'] += 1
            else:
                ep['error'] += 1
            ep['avg_time'] += log.response_time_ms

        for ep in endpoint_stats.values():
            if ep['count'] > 0:
                ep['avg_time'] = round(ep['avg_time'] / ep['count'], 2)

        return {
            'app_id': app_id,
            'plan': plan.to_dict(),
            'total_api_keys': len(app_keys),
            'active_api_keys': len([k for k in app_keys if k.status == APIKeyStatus.ACTIVE]),
            'total_calls': len(app_logs),
            'success_calls': success_count,
            'error_calls': error_count,
            'success_rate': round(success_count / len(app_logs) * 100, 1) if app_logs else 0,
            'avg_response_time_ms': round(avg_response_time, 2),
            'endpoint_stats': dict(endpoint_stats),
            'daily_usage': sum(k.usage_today for k in app_keys),
            'monthly_usage': sum(k.usage_month for k in app_keys),
            'total_usage': sum(k.usage_total for k in app_keys),
        }

    def get_platform_stats(self) -> Dict[str, Any]:
        """获取平台统计"""
        return {
            'total_apps': len(self._apps),
            'active_apps': len([a for a in self._apps.values() if a.status == ApplicationStatus.APPROVED]),
            'total_api_keys': len(self._api_keys),
            'active_api_keys': len([k for k in self._api_keys.values() if k.status == APIKeyStatus.ACTIVE]),
            'total_calls': len(self._call_logs),
            'plans': {pid: p.to_dict() for pid, p in self._plans.items()},
            'endpoints_count': len(self._endpoints),
        }

    def list_plans(self) -> List[Plan]:
        """列出套餐"""
        return [p for p in self._plans.values() if p.is_active]

    def list_endpoints(self, category: str = None) -> List[APIEndpoint]:
        """列出API端点"""
        endpoints = list(self._endpoints.values())
        if category:
            endpoints = [e for e in endpoints if e.category == category]
        return sorted(endpoints, key=lambda e: e.path)

    # ============== SDK生成 ==============

    def generate_python_sdk(self, app_id: str) -> str:
        """生成Python SDK代码"""
        app = self._apps.get(app_id)
        if not app:
            return ""

        endpoints = self.list_endpoints()
        sdk_code = f'''#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
AI Hacking Agent Python SDK
应用: {app.name}
生成时间: {time.strftime("%Y-%m-%d %H:%M:%S")}
"""

import requests
from typing import Dict, Any, Optional, List


class AIHackingAgentClient:
    """AI Hacking Agent API客户端"""

    def __init__(self, api_key: str, base_url: str = "http://127.0.0.1:8000"):
        self.api_key = api_key
        self.base_url = base_url.rstrip("/")
        self.session = requests.Session()
        self.session.headers.update({{
            "Authorization": f"Bearer {{api_key}}",
            "Content-Type": "application/json",
        }})

    def _request(self, method: str, endpoint: str, data: Dict = None, params: Dict = None) -> Dict[str, Any]:
        """发送请求"""
        url = f"{{self.base_url}}{{endpoint}}"
        response = self.session.request(method, url, json=data, params=params, timeout=30)
        response.raise_for_status()
        return response.json()

'''

        # 为每个端点生成方法
        for ep in endpoints:
            if ep.auth_required:
                method_name = ep.path.split('/')[-1].replace('-', '_').replace('{', '').replace('}', '')
                if ep.method == 'GET':
                    sdk_code += f'''    def {method_name}(self, **kwargs) -> Dict[str, Any]:
        """{ep.description}"""
        return self._request("GET", "{ep.path}", params=kwargs)

'''
                elif ep.method == 'POST':
                    sdk_code += f'''    def {method_name}(self, data: Dict = None) -> Dict[str, Any]:
        """{ep.description}"""
        return self._request("POST", "{ep.path}", data=data or {{}})

'''

        sdk_code += '''
# 使用示例
if __name__ == "__main__":
    client = AIHackingAgentClient(api_key="your-api-key")

    # 健康检查
    # health = client.health()

    # 端口扫描
    # result = client.port(data={"target": "192.168.1.1", "ports": [22, 80, 443]})
    # print(result)
'''

        return sdk_code

    # ============== 持久化 ==============

    def _load_all(self):
        """加载所有数据"""
        self._load_apps()
        self._load_keys()
        self._load_logs()

    def _load_apps(self):
        if os.path.exists(self.apps_file):
            try:
                with open(self.apps_file, 'r', encoding='utf-8') as f:
                    for data in json.load(f):
                        app = Application(**{k: v for k, v in data.items() if k in Application.__dataclass_fields__})
                        if isinstance(app.status, str):
                            app.status = ApplicationStatus(app.status)
                        self._apps[app.app_id] = app
            except Exception as e:
                logger.warning(f"加载应用数据失败: {e}")

    def _load_keys(self):
        if os.path.exists(self.keys_file):
            try:
                with open(self.keys_file, 'r', encoding='utf-8') as f:
                    for data in json.load(f):
                        key = APIKey(**{k: v for k, v in data.items() if k in APIKey.__dataclass_fields__})
                        if isinstance(key.status, str):
                            key.status = APIKeyStatus(key.status)
                        self._api_keys[key.key_id] = key
                        self._key_index[key.key] = key.key_id
            except Exception as e:
                logger.warning(f"加载API密钥失败: {e}")

    def _load_logs(self):
        if os.path.exists(self.logs_file):
            try:
                with open(self.logs_file, 'r', encoding='utf-8') as f:
                    for data in json.load(f):
                        log = APICallLog(**{k: v for k, v in data.items() if k in APICallLog.__dataclass_fields__})
                        self._call_logs.append(log)
            except Exception as e:
                logger.warning(f"加载调用日志失败: {e}")

    def _save_apps(self):
        try:
            with open(self.apps_file, 'w', encoding='utf-8') as f:
                json.dump([a.to_dict() for a in self._apps.values()], f, ensure_ascii=False, indent=2)
        except Exception as e:
            logger.error(f"保存应用数据失败: {e}")

    def _save_keys(self):
        try:
            with open(self.keys_file, 'w', encoding='utf-8') as f:
                json.dump([k.to_dict() for k in self._api_keys.values()], f, ensure_ascii=False, indent=2)
        except Exception as e:
            logger.error(f"保存API密钥失败: {e}")

    def _save_logs(self):
        try:
            with open(self.logs_file, 'w', encoding='utf-8') as f:
                json.dump([l.to_dict() for l in list(self._call_logs)[-1000:]], f, ensure_ascii=False, indent=2)
        except Exception as e:
            logger.error(f"保存调用日志失败: {e}")


# 全局API开放平台管理器实例
_global_api_platform: Optional[APIPlatformManager] = None


def get_api_platform() -> APIPlatformManager:
    """获取全局API开放平台管理器实例"""
    global _global_api_platform
    if _global_api_platform is None:
        _global_api_platform = APIPlatformManager()
    return _global_api_platform
