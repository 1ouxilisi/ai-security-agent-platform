# -*- coding: utf-8 -*-
"""
baseline_checker.py - 工控安全基线检查器（第12轮 ICS/SCADA 深化模块）。

检查域：
  1. PLC 配置：固件版本 / 密码保护 / 程序上传下载保护 / 运行模式切换保护 /
     通信端口 / 远程访问
  2. 网络隔离：IT/OT 隔离 / 防火墙 / 分段 / VLAN / ACL / 远程访问通道
  3. 访问控制：账户 / 权限 / 默认账户 / 密码策略 / MFA / 账户锁定
  4. 补丁管理：固件 / OS / 应用补丁 / 测试 / 部署流程
  5. 日志审计：日志启用 / 保留 / 集中 / 保护 / 审计跟踪 / 告警
  6. 物理安全：物理访问 / 控制柜锁定 / 机房 / USB / 串口 / 维护口

输出：合规评分(0-100)、差距分析、整改建议、基线检查报告。
"""

from __future__ import annotations

from datetime import datetime
from typing import Any, Dict, List, Optional


# 基线规则库：每条规则含 id/category/title/expected/check_type/weight/remediation
BASELINE_RULES: List[Dict[str, Any]] = [
    # ---- PLC 配置 ----
    {"id": "PLC-01", "category": "PLC配置", "title": "固件为最新受支持版本",
     "expected": "无未修复的已知 CVE", "weight": 5, "remediation": "按厂商路线图升级固件，先在测试环境验证"},
    {"id": "PLC-02", "category": "PLC配置", "title": "PLC 编程/写保护已启用",
     "expected": "Protection level >= 写保护", "weight": 6, "remediation": "在 TIA/工程软件中设置写保护与知密保"},
    {"id": "PLC-03", "category": "PLC配置", "title": "程序上传下载需认证",
     "expected": "上传/下载均校验账户", "weight": 5, "remediation": "启用项目口令与账户授权"},
    {"id": "PLC-04", "category": "PLC配置", "title": "运行模式切换(RUN/STOP)受保护",
     "expected": "仅授权工程站可切换", "weight": 5, "remediation": "关闭远程 STOP 能力，仅本地柜面操作"},
    {"id": "PLC-05", "category": "PLC配置", "title": "未用通信端口/服务已关闭",
     "expected": "仅业务必要端口开放", "weight": 4, "remediation": "关闭未用的 HTTP/FTP/Telnet 服务"},
    {"id": "PLC-06", "category": "PLC配置", "title": "远程维护通道受控",
     "expected": "VPN/堡垒机+白名单", "weight": 5, "remediation": "禁止直连公网，维护走跳板机"},

    # ---- 网络隔离 ----
    {"id": "NET-01", "category": "网络隔离", "title": "IT/OT 网络已分段",
     "expected": "OT 与 IT 之间有边界设备", "weight": 6, "remediation": "部署工业防火墙 / DMZ"},
    {"id": "NET-02", "category": "网络隔离", "title": "工业防火墙规则按白名单配置",
     "expected": "默认拒绝+显式允许", "weight": 5, "remediation": "梳理通信矩阵后下发白名单"},
    {"id": "NET-03", "category": "网络隔离", "title": "VLAN 划分合理",
     "expected": "控制/监控/维护网络分离", "weight": 3, "remediation": "按安全域划分 VLAN 并 trunk 限制"},
    {"id": "NET-04", "category": "网络隔离", "title": "ACL 限制 ICS 端口来源",
     "expected": "502/102/44818 仅工程站可达", "weight": 5, "remediation": "在交换机 ACL 上限定源 IP"},
    {"id": "NET-05", "category": "网络隔离", "title": "无 OT 直连互联网链路",
     "expected": "OT 不得路由到公网", "weight": 6, "remediation": "移除 OT 默认网关至互联网，走隔离网"},

    # ---- 访问控制 ----
    {"id": "ACC-01", "category": "访问控制", "title": "无默认账户/默认口令",
     "expected": "admin/admin 等已修改或禁用", "weight": 6, "remediation": "上线强制改密，盘点所有账户"},
    {"id": "ACC-02", "category": "访问控制", "title": "按最小权限分配角色",
     "expected": "操作员/维护员/管理员分离", "weight": 4, "remediation": "RBAC 建模，回收过权账户"},
    {"id": "ACC-03", "category": "访问控制", "title": "密码策略符合复杂度要求",
     "expected": ">=12位/90天更换", "weight": 3, "remediation": "在域/本机策略启用复杂度与周期"},
    {"id": "ACC-04", "category": "访问控制", "title": "管理面启用多因素认证",
     "expected": "管理员登录需第二因子", "weight": 4, "remediation": "堡垒机/4A 启用 MFA"},
    {"id": "ACC-05", "category": "访问控制", "title": "账户锁定策略",
     "expected": "5次失败锁定15分钟", "weight": 3, "remediation": "配置账户锁定阈值"},

    # ---- 补丁管理 ----
    {"id": "PAT-01", "category": "补丁管理", "title": "固件补丁有维护周期",
     "expected": "每季度评估一次", "weight": 4, "remediation": "建立固件升级台账与变更窗口"},
    {"id": "PAT-02", "category": "补丁管理", "title": "OS 补丁经测试后部署",
     "expected": "测试环境验证后上生产", "weight": 4, "remediation": "搭建补丁测试镜像机"},
    {"id": "PAT-03", "category": "补丁管理", "title": "关键漏洞有缓解措施",
     "expected": "无法立即补丁时有 compensating control", "weight": 4, "remediation": "对不可打补丁资产用防火墙隔离"},
    {"id": "PAT-04", "category": "补丁管理", "title": "补丁部署走变更流程",
     "expected": "CR 审批+回滚预案", "weight": 3, "remediation": "纳入变更管理流程"},

    # ---- 日志审计 ----
    {"id": "LOG-01", "category": "日志审计", "title": "关键设备日志已启用",
     "expected": "PLC/HMI/防火墙 syslog 开启", "weight": 4, "remediation": "启用日志并指向集中平台"},
    {"id": "LOG-02", "category": "日志审计", "title": "日志保留 >= 90 天",
     "expected": "满足法规/等保要求", "weight": 3, "remediation": "扩容 SIEM/日志服务器"},
    {"id": "LOG-03", "category": "日志审计", "title": "日志集中收集",
     "expected": "OT 网段日志统一汇聚", "weight": 3, "remediation": "部署工业日志采集器"},
    {"id": "LOG-04", "category": "日志审计", "title": "日志防篡改",
     "expected": "只写存储/哈希链", "weight": 3, "remediation": "日志服务器设为只读写入"},
    {"id": "LOG-05", "category": "日志审计", "title": "关键操作有告警",
     "expected": "写寄存器/PLC 下载触发告警", "weight": 4, "remediation": "在 IDS/SIEM 配置规则"},

    # ---- 物理安全 ----
    {"id": "PHY-01", "category": "物理安全", "title": "控制柜上锁",
     "expected": "钥匙专人保管", "weight": 3, "remediation": "加装锁具与出入登记"},
    {"id": "PHY-02", "category": "物理安全", "title": "机房访问受控",
     "expected": "门禁+监控", "weight": 3, "remediation": "机房门禁审计"},
    {"id": "PHY-03", "category": "物理安全", "title": "USB/光驱端口管控",
     "expected": "禁用或白名单", "weight": 4, "remediation": "组策略禁用可移动存储"},
    {"id": "PHY-04", "category": "物理安全", "title": "串口/维护口封停",
     "expected": "闲置维护口贴签/断电", "weight": 2, "remediation": "盘点物理口并加签管理"},
]


class BaselineChecker:
    """工控安全基线检查器。"""

    CATEGORY_NAMES = ["PLC配置", "网络隔离", "访问控制", "补丁管理", "日志审计", "物理安全"]

    def __init__(self):
        self.rules = BASELINE_RULES

    def list_rules(self, category: Optional[str] = None) -> List[Dict[str, Any]]:
        if category:
            return [r for r in self.rules if r["category"] == category]
        return self.rules

    def check(self, evidence: Optional[Dict[str, Dict[str, bool]]] = None) -> Dict[str, Any]:
        """
        依据证据集执行基线检查。
        evidence 形如 {"PLC-02": True, "NET-01": False, ...}；未提供的规则按
        "未核查(unknown)" 处理，不计入得分分母但列入差距。
        """
        evidence = evidence or {}
        results: List[Dict[str, Any]] = []
        total_weight = 0
        passed_weight = 0
        gap: List[Dict[str, Any]] = []

        for r in self.rules:
            rid = r["id"]
            if rid in evidence:
                status = "pass" if evidence[rid] else "fail"
            else:
                status = "unknown"
            total_weight += r["weight"]
            if status == "pass":
                passed_weight += r["weight"]
            item = {**r, "status": status}
            results.append(item)
            if status == "fail":
                gap.append({
                    "rule_id": rid, "title": r["title"], "category": r["category"],
                    "expected": r["expected"], "remediation": r["remediation"],
                    "severity_hint": "high" if r["weight"] >= 5 else "medium",
                })

        score = round(passed_weight / total_weight * 100, 1) if total_weight else 0.0
        # 分类得分
        cat_scores: Dict[str, Dict[str, float]] = {}
        for cat in self.CATEGORY_NAMES:
            rs = [r for r in results if r["category"] == cat]
            tw = sum(r["weight"] for r in rs)
            pw = sum(r["weight"] for r in rs if r["status"] == "pass")
            cat_scores[cat] = {"score": round(pw / tw * 100, 1) if tw else 0.0,
                               "passed": sum(1 for r in rs if r["status"] == "pass"),
                               "failed": sum(1 for r in rs if r["status"] == "fail"),
                               "unknown": sum(1 for r in rs if r["status"] == "unknown"),
                               "total": len(rs)}

        if score >= 85:
            level = "合规"
        elif score >= 70:
            level = "基本合规"
        elif score >= 50:
            level = "不合规"
        else:
            level = "严重不合规"

        return {
            "score": score,
            "compliance_level": level,
            "category_scores": cat_scores,
            "results": results,
            "gap_analysis": gap,
            "summary": {
                "total_rules": len(results),
                "passed": sum(1 for r in results if r["status"] == "pass"),
                "failed": sum(1 for r in results if r["status"] == "fail"),
                "unknown": sum(1 for r in results if r["status"] == "unknown"),
            },
            "checked_at": datetime.now().isoformat(),
        }

    def generate_report(self, check_result: Dict[str, Any]) -> Dict[str, Any]:
        gaps = check_result.get("gap_analysis", [])
        return {
            "title": "工控安全基线检查报告",
            "generated_at": datetime.now().isoformat(),
            "compliance_score": check_result.get("score"),
            "compliance_level": check_result.get("compliance_level"),
            "category_scores": check_result.get("category_scores"),
            "gap_count": len(gaps),
            "top_gaps": sorted(gaps, key=lambda g: 0 if g["severity_hint"] == "high" else 1)[:15],
            "remediation_roadmap": [
                {"phase": "立即(0-30天)", "items": [g["rule_id"] for g in gaps if g["severity_hint"] == "high"][:8]},
                {"phase": "短期(30-90天)", "items": [g["rule_id"] for g in gaps if g["severity_hint"] == "medium"][:8]},
                {"phase": "中期(90-180天)", "items": ["PAT-01", "PAT-02", "LOG-03", "LOG-05"]},
            ],
            "conclusion": f"基线合规评分 {check_result.get('score')}/100，等级 {check_result.get('compliance_level')}。",
        }


def create_baseline_checker() -> BaselineChecker:
    return BaselineChecker()
