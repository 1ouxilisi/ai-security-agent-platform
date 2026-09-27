#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
service_delivery — 安全服务交付平台（第 14 轮升级 · 方向 4）。

支撑安全服务公司项目交付全流程，可作为 SaaS 产品售卖：
    - project_manager       项目管理（8 种项目类型 / 5 阶段 / WBS / 甘特 / 风险登记册）
    - customer_portal       客户门户（合同/发票/工单/SLA/满意度/资产）
    - time_billing          工时与计费（5 级人员费率 / 预算 / 发票 / 利润率）
    - sla_manager           SLA 与服务级别（模板/监控/违约告警/仪表盘）
    - deliverable_manager   交付物管理（清单/版本/审核/签收/归档）
    - team_resource         团队与资源（20+ 安全技能矩阵/利用率/知识库）
    - delivery_workflow     综合交付工作流（启动→资源→执行→审核→验收→归档结算）

设计定位：
    - 全部为管理/运营视角，合法安全服务边界，不提供攻击/窃密工具。
    - 全部数据用内存字典模拟，不建数据库表。
    - 第三方库一律 try-import，缺失时回退内嵌模拟数据。
    - Python 3.14 兼容。
"""

from __future__ import annotations

__version__ = "14.4.0"
__round__ = 14
__direction__ = 4

try:
    from service_delivery.project_manager import (
        ProjectManager, PROJECT_TYPES, PROJECT_STAGES, RISK_REGISTER,
    )
except Exception:  # pragma: no cover
    ProjectManager = None  # type: ignore
    PROJECT_TYPES = {}
    PROJECT_STAGES = []
    RISK_REGISTER = {}

try:
    from service_delivery.customer_portal import (
        CustomerPortal, CUSTOMER_TIERS, TICKET_STATUSES,
    )
except Exception:  # pragma: no cover
    CustomerPortal = None  # type: ignore
    CUSTOMER_TIERS = {}
    TICKET_STATUSES = []

try:
    from service_delivery.time_billing import (
        TimeBillingEngine, STAFF_RATES, BUDGET_STATUS,
    )
except Exception:  # pragma: no cover
    TimeBillingEngine = None  # type: ignore
    STAFF_RATES = {}
    BUDGET_STATUS = {}

try:
    from service_delivery.sla_manager import (
        SLAManager, SLA_TEMPLATES, SLA_BREACH_LEVELS,
    )
except Exception:  # pragma: no cover
    SLAManager = None  # type: ignore
    SLA_TEMPLATES = {}
    SLA_BREACH_LEVELS = {}

try:
    from service_delivery.deliverable_manager import (
        DeliverableManager, DELIVERABLE_TEMPLATES, REVIEW_STATUS,
    )
except Exception:  # pragma: no cover
    DeliverableManager = None  # type: ignore
    DELIVERABLE_TEMPLATES = {}
    REVIEW_STATUS = {}

try:
    from service_delivery.team_resource import (
        TeamResourceManager, SECURITY_SKILLS, ROLE_PERMISSIONS,
    )
except Exception:  # pragma: no cover
    TeamResourceManager = None  # type: ignore
    SECURITY_SKILLS = {}
    ROLE_PERMISSIONS = {}

try:
    from service_delivery.delivery_workflow import (
        DeliveryWorkflow, get_delivery_workflow, DELIVERY_STAGES,
    )
except Exception:  # pragma: no cover
    DeliveryWorkflow = None  # type: ignore
    get_delivery_workflow = None  # type: ignore
    DELIVERY_STAGES = []

__all__ = [
    "__version__", "__round__", "__direction__",
    "ProjectManager", "PROJECT_TYPES", "PROJECT_STAGES", "RISK_REGISTER",
    "CustomerPortal", "CUSTOMER_TIERS", "TICKET_STATUSES",
    "TimeBillingEngine", "STAFF_RATES", "BUDGET_STATUS",
    "SLAManager", "SLA_TEMPLATES", "SLA_BREACH_LEVELS",
    "DeliverableManager", "DELIVERABLE_TEMPLATES", "REVIEW_STATUS",
    "TeamResourceManager", "SECURITY_SKILLS", "ROLE_PERMISSIONS",
    "DeliveryWorkflow", "get_delivery_workflow", "DELIVERY_STAGES",
]
