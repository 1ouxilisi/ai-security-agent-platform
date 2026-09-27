# -*- coding: utf-8 -*-
"""商业化核心模块。

将单用户安全工具升级为多租户商业级 SaaS 产品，包含：

- multi_tenant  : 多租户管理引擎（租户隔离、配额、配置）
- billing       : 计费与订阅系统（订阅、订单、模拟支付、用量、超额告警）
- api_gateway   : API 网关（API Key、令牌桶限流、调用计量）
- data_security : 数据安全与合规（AES 加密、脱敏、保留策略、导出/删除、审计）

所有数据持久化到 ``data/tenants/`` 目录下，元数据集中在
``data/tenants/_meta/``，租户工作空间在 ``data/tenants/{tenant_id}/``。
"""

__version__ = "1.0.0"
__all__ = [
    "multi_tenant",
    "billing",
    "api_gateway",
    "data_security",
]
