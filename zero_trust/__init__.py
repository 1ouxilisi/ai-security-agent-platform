# -*- coding: utf-8 -*-
"""
zero_trust — 零信任安全架构模块（第13轮升级）。

提供：
- 身份与访问管理（identity_access）：身份生命周期、MFA、SSO、PAM、身份风险评分
- 持续验证与动态授权（continuous_verification）：实时风险、设备信任、位置异常、
  行为基线、自适应访问策略、会话监控、步长认证
- 微隔离与网络分段（microsegmentation）：拓扑分析、东西向流量、应用依赖、
  ZTNA、SDP
- 设备安全与终端信任（device_trust）：合规检查、EDR、越狱/Root、设备指纹、
  BYOD、设备准入
- 应用与API安全（application_api_security）：应用访问控制、API网关、mTLS、
  服务网格、服务账户最小权限
- 零信任成熟度评估（zero_trust_maturity）：5阶段成熟度模型、8维差距分析、
  路线图规划、综合评分

所有功能均为防御 / 评估 / 检测视角，仅对授权环境进行零信任成熟度与
控制有效性评估，不主动绕过认证、不横向渗透、不窃取凭据。
"""

from __future__ import annotations

__version__ = "13.0.0"
__all__ = [
    "identity_access",
    "continuous_verification",
    "microsegmentation",
    "device_trust",
    "application_api_security",
    "zero_trust_maturity",
]
