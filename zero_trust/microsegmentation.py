# -*- coding: utf-8 -*-
"""
microsegmentation.py — 微隔离与网络分段器（第13轮升级 · 零信任模块）。

功能：
- 网络拓扑分析：网络资产发现 / 网络拓扑映射 / 网段划分 / VLAN 配置 / 路由分析
- 微隔离策略：应用级隔离 / 工作负载隔离 / 环境隔离（开发/测试/生产）/
  最小权限网络策略
- 东西向流量监控：内部流量分析 / 异常连接 / 未授权通信 / 横向移动检测 / 流量基线
- 应用依赖映射：应用间依赖关系 / 服务调用链 / 数据流向 / 依赖风险评估
- 零信任网络访问(ZTNA)：ZTNA 架构评估 / 应用级访问 / 身份感知代理 /
  隐藏应用 / 无 VPN 访问
- 软件定义边界(SDP)评估：SDP 架构 / 单包授权(SPA) / 控制器 / 网关 / 客户端 /
  部署评估
- 微隔离报告与策略建议

说明：仅基于模拟拓扑与流量元数据做评估，不主动扫描、不抓包、不发起连接。
"""

from __future__ import annotations

import random
from datetime import datetime
from typing import Any, Dict, List, Optional


# ==================== 内嵌拓扑与策略库 ====================

# 典型网段划分（模拟）
NETWORK_ZONES: List[Dict[str, Any]] = [
    {"zone": "prod_web",      "cidr": "10.10.0.0/24",  "env": "生产", "trust": "高"},
    {"zone": "prod_app",      "cidr": "10.10.1.0/24",  "env": "生产", "trust": "高"},
    {"zone": "prod_db",       "cidr": "10.10.2.0/24",  "env": "生产", "trust": "极高"},
    {"zone": "dmz",           "cidr": "10.20.0.0/24",  "env": "DMZ",  "trust": "中"},
    {"zone": "office",        "cidr": "10.30.0.0/16",  "env": "办公", "trust": "中"},
    {"zone": "dev",           "cidr": "10.40.0.0/24",  "env": "开发", "trust": "低"},
    {"zone": "test",          "cidr": "10.41.0.0/24",  "env": "测试", "trust": "低"},
    {"zone": "iot",           "cidr": "10.50.0.0/24",  "env": "IoT",  "trust": "低"},
    {"zone": "mgmt",          "cidr": "10.99.0.0/24",  "env": "管理", "trust": "极高"},
]

# 应用间依赖（模拟调用链）
APP_DEPENDENCIES: List[Dict[str, Any]] = [
    {"app": "web-frontend",  "depends_on": "api-gateway", "protocol": "HTTPS", "port": 443,  "critical": False},
    {"app": "api-gateway",   "depends_on": "auth-service", "protocol": "gRPC", "port": 8443, "critical": True},
    {"app": "api-gateway",   "depends_on": "order-service", "protocol": "gRPC", "port": 8443, "critical": True},
    {"app": "order-service", "depends_on": "mysql-prod",  "protocol": "MySQL", "port": 3306, "critical": True},
    {"app": "order-service", "depends_on": "redis-cache","protocol": "Redis",  "port": 6379, "critical": True},
    {"app": "report-job",    "depends_on": "mysql-prod",  "protocol": "MySQL", "port": 3306, "critical": False},
    {"app": "dev-shell",     "depends_on": "mysql-prod",  "protocol": "MySQL", "port": 3306, "critical": True},
]

# ZTNA 能力评估项
ZTNA_CAPABILITIES = [
    {"id": "app_level_access",  "name": "应用级访问",   "implemented": True,  "maturity": 80,
     "desc": "按应用而非网络位置授权"},
    {"id": "id_aware_proxy",   "name": "身份感知代理", "implemented": True,  "maturity": 75,
     "desc": "访问前先验证身份与设备"},
    {"id": "hidden_app",       "name": "应用隐身",     "implemented": False, "maturity": 20,
     "desc": "未授权探测时网络不可见"},
    {"id": "no_vpn",            "name": "无VPN替代",    "implemented": False, "maturity": 30,
     "desc": "尚未完全替代传统 VPN"},
    {"id": "adaptive",          "name": "动态授权",     "implemented": True,  "maturity": 60,
     "desc": "结合风险动态调整访问权限"},
]

# SDP 组件评估
SDP_COMPONENTS = [
    {"id": "controller",  "name": "SDP 控制器", "deployed": True,  "note": "集中策略下发"},
    {"id": "gateway",     "name": "SDP 网关",   "deployed": True,  "note": "隐藏服务入口"},
    {"id": "client",      "name": "SDP 客户端", "deployed": False, "note": "仅覆盖 40% 终端"},
    {"id": "spa",         "name": "单包授权SPA","deployed": True,  "note": "先认证后开放端口"},
]


# ==================== 主评估器 ====================

class MicrosegmentationManager:
    """微隔离与网络分段器（评估视角）。"""

    def __init__(self) -> None:
        self.zones = NETWORK_ZONES
        self.dependencies = APP_DEPENDENCIES
        self.ztna_caps = ZTNA_CAPABILITIES
        self.sdp_comps = SDP_COMPONENTS
        self._seed_flows()

    def _seed_flows(self) -> None:
        rng = random.Random(1304)
        self.flows: List[Dict[str, Any]] = []
        zones = [z["zone"] for z in self.zones]
        for _ in range(80):
            src = rng.choice(zones)
            dst = rng.choice(zones)
            self.flows.append({
                "src_zone": src, "dst_zone": dst,
                "bytes": rng.randint(1000, 10_000_000),
                "conn_count": rng.randint(1, 500),
                "approved": rng.random() > 0.15,
            })

    # ---------- 拓扑分析 ----------

    def analyze_topology(self) -> Dict[str, Any]:
        """网络拓扑与 VLAN/网段划分评估。"""
        return {
            "zones": self.zones,
            "zone_count": len(self.zones),
            "vlan_configuration": {
                "vlan_count": len(self.zones) + 2,
                "trusted_interfaces": 6,
                "untrusted_interfaces": 3,
                "voice_vlan_separated": True,
                "mgmt_vlan_separated": True,
            },
            "findings": [
                {"severity": "high", "desc": "办公网(10.30.0.0/16) 掩码过大，建议按部门再细分"},
                {"severity": "medium", "desc": "IoT 区未与办公网二层隔离，存在 ARP 欺骗风险"},
                {"severity": "low", "desc": "管理网段仅做 VLAN 隔离，未限制运维来源 IP"},
            ],
            "route_recommendations": [
                "办公网按部门拆分为 /24",
                "IoT 区独立 VRF 并仅放行必要管理端口",
                "管理平面启用 jump host + MFA 双因素",
            ],
        }

    # ---------- 微隔离策略 ----------

    def assess_policies(self) -> Dict[str, Any]:
        """应用/工作负载/环境级隔离策略有效性。"""
        policies = [
            {"name": "prod_web->prod_app", "scope": "应用级", "action": "allow",
             "ports": ["443", "8443"], "least_privilege": True},
            {"name": "prod_app->prod_db", "scope": "工作负载", "action": "allow",
             "ports": ["3306"], "least_privilege": True},
            {"name": "office->prod_db",   "scope": "环境",   "action": "deny",
             "ports": ["any"], "least_privilege": True},
            {"name": "dev->prod_db",      "scope": "环境",   "action": "allow",
             "ports": ["3306"], "least_privilege": False},
            {"name": "dmz->office",       "scope": "环境",   "action": "allow",
             "ports": ["any"], "least_privilege": False},
        ]
        over_perm = [p for p in policies if not p["least_privilege"]]
        return {
            "policies": policies,
            "total_policies": len(policies),
            "over_permissive_policies": over_perm,
            "over_permissive_count": len(over_perm),
            "environment_isolation": {
                "prod_isolated_from_dev_test": False,
                "dmz_isolated_from_office": False,
                "mgmt_isolated": True,
            },
            "recommendations": [
                "立即阻断 dev->prod_db 的放行规则，开发库与生产库物理隔离",
                "DMZ 到办公网仅放行堡垒机所需端口，禁止 any-any",
                "推行应用级白名单，默认拒绝所有东西向流量",
            ],
        }

    # ---------- 东西向流量 ----------

    def east_west_traffic(self) -> Dict[str, Any]:
        """内部流量基线与横向移动检测。"""
        total = len(self.flows)
        unapproved = [f for f in self.flows if not f["approved"]]
        cross_env: Dict[str, int] = {}
        for f in self.flows:
            if f["src_zone"] != f["dst_zone"]:
                key = f"{f['src_zone']}->{f['dst_zone']}"
                cross_env[key] = cross_env.get(key, 0) + f["conn_count"]
        # 横向移动可疑：办公区->生产区大量连接
        lateral_suspects = [f for f in self.flows
                            if f["src_zone"] == "office"
                            and f["dst_zone"].startswith("prod")
                            and f["conn_count"] > 100]
        return {
            "total_flows": total,
            "unapproved_flows": unapproved,
            "unapproved_count": len(unapproved),
            "cross_env_top": sorted(cross_env.items(), key=lambda x: x[1], reverse=True)[:10],
            "lateral_movement_suspects": lateral_suspects,
            "lateral_suspect_count": len(lateral_suspects),
            "baseline_status": "已建立 7 天流量基线，2 条新连接偏离基线",
            "recommendations": [
                "未审批流量默认阻断并告警",
                "办公区到生产区任何连接均视为横向移动嫌疑",
                "对偏离基线的新连接自动生成微隔离策略草案",
            ],
        }

    # ---------- 应用依赖映射 ----------

    def app_dependency_map(self) -> Dict[str, Any]:
        """应用调用链与依赖风险。"""
        risky = [d for d in self.dependencies
                 if d["app"].startswith(("dev", "report")) and d["depends_on"].startswith("mysql-prod")]
        return {
            "dependencies": self.dependencies,
            "total_edges": len(self.dependencies),
            "critical_edges": [d for d in self.dependencies if d["critical"]],
            "risky_dependencies": risky,
            "risky_count": len(risky),
            "data_flows": [
                {"from": "user", "to": "web-frontend", "desc": "HTTPS 访问"},
                {"from": "web-frontend", "to": "api-gateway", "desc": "API 调用"},
                {"from": "order-service", "to": "mysql-prod", "desc": "订单读写"},
            ],
            "recommendations": [
                "断开 dev-shell -> mysql-prod 的依赖，开发库用独立实例",
                "为 report-job 限定只读账号与脱敏视图",
            ],
        }

    # ---------- ZTNA ----------

    def assess_ztna(self) -> Dict[str, Any]:
        """ZTNA 架构成熟度。"""
        avg = int(sum(c["maturity"] for c in self.ztna_caps) / len(self.ztna_caps))
        return {
            "capabilities": self.ztna_caps,
            "overall_maturity": avg,
            "architecture": {
                "model": "代理式 ZTNA（反向代理应用入口）",
                "identity_integration": True,
                "device_check_inline": True,
                "tls_encryption": True,
            },
            "gaps": [c for c in self.ztna_caps if not c["implemented"]],
            "recommendations": [
                "实现应用隐身：未认证探测时端口/服务不响应",
                "用 ZTNA 逐步替代全流量 VPN 接入",
                "按应用粒度授权，而非网段授权",
            ],
        }

    # ---------- SDP ----------

    def assess_sdp(self) -> Dict[str, Any]:
        """SDP 架构与部署评估。"""
        deployed = [c for c in self.sdp_comps if c["deployed"]]
        return {
            "components": self.sdp_comps,
            "deployed_count": len(deployed),
            "total_components": len(self.sdp_comps),
            "spa_enabled": any(c["id"] == "spa" and c["deployed"] for c in self.sdp_comps),
            "coverage_pct": round(len(deployed) / len(self.sdp_comps) * 100),
            "recommendations": [
                "完成 SDP 客户端在剩余 60% 终端的部署",
                "控制器启用多因素认证与高可用",
                "网关侧关闭所有非 SPA 端口，实现端口敲门",
            ],
        }

    # ---------- 综合报告 ----------

    def full_report(self) -> Dict[str, Any]:
        topo = self.analyze_topology()
        pol = self.assess_policies()
        ew = self.east_west_traffic()
        dep = self.app_dependency_map()
        ztna = self.assess_ztna()
        sdp = self.assess_sdp()
        score = int(round(
            (100 - pol["over_permissive_count"] * 10) * 0.3
            + ztna["overall_maturity"] * 0.35
            + sdp["coverage_pct"] * 0.2
            + (100 - ew["lateral_suspect_count"] * 15) * 0.15
        ))
        return {
            "report_title": "微隔离与网络分段评估报告",
            "generated_at": datetime.now().isoformat(),
            "overall_score": score,
            "topology": topo,
            "policies": pol,
            "east_west": ew,
            "dependencies": dep,
            "ztna": ztna,
            "sdp": sdp,
            "summary": (
                f"共 {topo['zone_count']} 个网络分区；"
                f"{pol['over_permissive_count']} 条过宽策略；"
                f"未审批东西向流量 {ew['unapproved_count']} 条；"
                f"ZTNA 成熟度 {ztna['overall_maturity']}/100；"
                f"SDP 组件覆盖 {sdp['coverage_pct']}%。"
            ),
        }


# ==================== 工厂函数 ====================

_ms_singleton: Optional[MicrosegmentationManager] = None


def get_microsegmentation_manager() -> MicrosegmentationManager:
    global _ms_singleton
    if _ms_singleton is None:
        _ms_singleton = MicrosegmentationManager()
    return _ms_singleton
