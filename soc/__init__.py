"""
SOC安全运营中心(Security Operations Center)模块

模块功能：
    - 安全事件管理（Incident）
    - 告警管理（Alert）与告警规则
    - 工单管理（Ticket）与SLA跟踪
    - 应急响应（Incident Response，遵循NIST SP 800-61）
    - SOC仪表盘数据生成

合法定位：
    本模块仅用于企业内部防御性安全运营、合规评估与检测响应视角，
    不提供任何攻击、渗透绕过或入侵实施能力。

注意事项：
    - 本模块仅用于授权的安全运营
    - 请勿用于非法用途
    - 使用前请确保已获得相关授权
"""

from soc.incident_manager import IncidentManager, incident_manager
from soc.alert_manager import AlertManager, alert_manager
from soc.ticket_manager import TicketManager, ticket_manager
from soc.incident_response import IncidentResponse, incident_response
from soc.soc_dashboard import SOCDashboard, soc_dashboard

__all__ = [
    "IncidentManager",
    "incident_manager",
    "AlertManager",
    "alert_manager",
    "TicketManager",
    "ticket_manager",
    "IncidentResponse",
    "incident_response",
    "SOCDashboard",
    "soc_dashboard",
]
