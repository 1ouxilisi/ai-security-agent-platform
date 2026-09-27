# -*- coding: utf-8 -*-
"""
seed_data/initialization_wizard.py — 一键初始化向导与示例数据生成器。

功能：
  - 首次启动自动检测数据库/种子状态（已初始化/未初始化/部分初始化）
  - 未初始化时：导入核心种子数据 → 创建默认管理员 → 生成示例项目 → 创建默认配置 → 输出初始化报告
  - 示例数据生成器：示例资产(10)/示例漏洞(20)/示例任务(5)/示例报告(3)/示例告警(10)/示例用户(5)
  - 一键生成/清除示例数据
  - 初始化报告：时间/各模块条数/总记录数/数据库大小/示例数据状态/耗时/结果

示例数据存放于内存字典（不写数据库）。
"""

from __future__ import annotations

import os
import time
from typing import Any, Dict, List, Optional

from seed_data.seed_manager import get_manager, MODULES
from seed_data import vulnerability_seeds as vs
from seed_data import knowledge_seeds as ks
from seed_data import tool_template_seeds as ts
from seed_data import report_kpi_compliance_seeds as rkcs

# 数据库文件路径（相对项目根）
_PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
DB_FILES = [
    os.path.join(_PROJECT_ROOT, "data", "hacking_agent.db"),
    os.path.join(_PROJECT_ROOT, "data", "platform.db"),
]


class InitializationWizard:
    """一键初始化向导。"""

    def __init__(self) -> None:
        self.manager = get_manager()
        self.sample_data: Dict[str, List[Dict[str, Any]]] = {
            "assets": [], "vulnerabilities": [], "tasks": [],
            "reports": [], "alerts": [], "users": [],
        }
        self.last_report: Optional[Dict[str, Any]] = None

    # ------------------------------------------------------------------ #
    # 状态检测
    # ------------------------------------------------------------------ #
    def detect_state(self) -> Dict[str, Any]:
        """检测初始化状态。"""
        db_exists = any(os.path.exists(p) for p in DB_FILES)
        mod_status = self.manager.module_status()
        imported = [m for m in mod_status if m["status"] == "imported"]
        total_mods = len(mod_status)
        if not db_exists and not imported:
            state = "not_initialized"
        elif len(imported) == total_mods:
            state = "initialized"
        else:
            state = "partial"
        return {
            "state": state,
            "db_files_exist": db_exists,
            "db_files": [
                {"path": p, "exists": os.path.exists(p),
                 "size": os.path.getsize(p) if os.path.exists(p) else 0}
                for p in DB_FILES
            ],
            "modules_imported": len(imported),
            "modules_total": total_mods,
            "sample_generated": bool(self.sample_data["assets"]),
        }

    # ------------------------------------------------------------------ #
    # 一键初始化
    # ------------------------------------------------------------------ #
    def run(self, with_sample: bool = True) -> Dict[str, Any]:
        start = time.time()
        started_at = time.strftime("%Y-%m-%d %H:%M:%S")
        steps: List[Dict[str, Any]] = []

        # 1. 检测状态
        state = self.detect_state()
        steps.append({"step": "detect", "result": state["state"]})

        # 2. 导入核心种子数据
        imp = self.manager.import_all()
        steps.append({"step": "import_seeds", "result": imp["success"],
                      "errors": imp["errors"]})

        # 3. 创建默认管理员账户
        admin = {
            "user_id": "u-admin-001", "username": "admin",
            "role": "administrator", "email": "admin@example.local",
            "status": "active", "created_at": time.strftime("%Y-%m-%d %H:%M:%S"),
        }
        steps.append({"step": "create_admin", "result": "OK"})

        # 4. 默认配置
        default_config = {
            "platform_name": "AI Hacking Agent 安全评估平台",
            "default_language": "zh-CN",
            "session_timeout_minutes": 30,
            "password_policy": "min_length=12;mfa_required=true",
            "log_retention_days": 180,
        }
        steps.append({"step": "default_config", "result": "OK"})

        # 5. 示例数据
        sample_status = "skipped"
        if with_sample:
            self.generate_sample_data()
            sample_status = "generated"
        steps.append({"step": "sample_data", "result": sample_status})

        elapsed = round(time.time() - start, 2)
        summary = self.manager.overall_status()
        db_size = sum(
            os.path.getsize(p) for p in DB_FILES if os.path.exists(p)
        )
        report = {
            "started_at": started_at,
            "finished_at": time.strftime("%Y-%m-%d %H:%M:%S"),
            "duration_seconds": elapsed,
            "result": "PASS" if imp["success"] else "FAIL",
            "modules_imported": summary["modules_imported"],
            "modules_total": summary["modules_total"],
            "total_records": summary["total_records"],
            "db_size_bytes": db_size,
            "sample_data_status": sample_status,
            "steps": steps,
            "module_counts": {
                m: len(meta["loader"]()) for m, meta in MODULES.items()
            },
        }
        self.last_report = report
        return {"success": imp["success"], "report": report}

    # ------------------------------------------------------------------ #
    # 示例数据生成器
    # ------------------------------------------------------------------ #
    def generate_sample_data(self) -> Dict[str, Any]:
        """生成示例资产/漏洞/任务/报告/告警/用户。"""
        now = time.strftime("%Y-%m-%d %H:%M:%S")

        # 10 个示例资产
        self.sample_data["assets"] = [
            {"asset_id": "AST-001", "name": "Web 前端服务器", "type": "web_server",
             "ip": "10.0.1.10", "os": "Ubuntu 22.04", "owner": "平台组", "criticality": "高"},
            {"asset_id": "AST-002", "name": "业务数据库", "type": "database",
             "ip": "10.0.2.20", "os": "CentOS 7", "owner": "DBA 组", "criticality": "高"},
            {"asset_id": "AST-003", "name": "核心交换机", "type": "network_device",
             "ip": "10.0.0.1", "os": "Cisco IOS XE", "owner": "网络组", "criticality": "高"},
            {"asset_id": "AST-004", "name": "云应用实例", "type": "cloud_instance",
             "ip": "公网弹性IP", "os": "Amazon Linux 2", "owner": "云平台组", "criticality": "中"},
            {"asset_id": "AST-005", "name": "移动 App 后端", "type": "mobile_app",
             "ip": "10.0.3.30", "os": "K8s Pod", "owner": "移动组", "criticality": "中"},
            {"asset_id": "AST-006", "name": "IoT 网关", "type": "iot_device",
             "ip": "10.0.9.40", "os": "Embedded Linux", "owner": "运维组", "criticality": "中"},
            {"asset_id": "AST-007", "name": "边界防火墙", "type": "firewall",
             "ip": "10.0.0.254", "os": "PAN-OS", "owner": "网络组", "criticality": "高"},
            {"asset_id": "AST-008", "name": "员工办公终端", "type": "endpoint",
             "ip": "DHCP", "os": "Windows 11", "owner": "IT 支持", "criticality": "低"},
            {"asset_id": "AST-009", "name": "文件共享服务器", "type": "file_server",
             "ip": "10.0.4.50", "os": "Windows Server 2019", "owner": "文档组", "criticality": "中"},
            {"asset_id": "AST-010", "name": "API 网关", "type": "api_gateway",
             "ip": "10.0.1.5", "os": "Kong/APISIX", "owner": "平台组", "criticality": "高"},
        ]

        # 20 个示例漏洞（关联示例资产），取真实 CVE
        sample_cves = vs.VULNERABILITY_SEEDS[:20]
        self.sample_data["vulnerabilities"] = [
            {
                "vuln_id": f"SV-{i+1:03d}",
                "asset_id": self.sample_data["assets"][i % 10]["asset_id"],
                "cve_id": v["cve_id"], "title": v["title"],
                "severity": v["severity"], "cvss": v["cvss"],
                "status": "open" if i % 3 else "in_progress",
                "discovered_at": now,
            }
            for i, v in enumerate(sample_cves)
        ]

        # 5 个示例任务（不同状态）
        self.sample_data["tasks"] = [
            {"task_id": "TASK-001", "name": "Web 服务器漏洞修复", "status": "pending",
             "assignee": "张三", "priority": "high", "created_at": now},
            {"task_id": "TASK-002", "name": "数据库基线检查", "status": "running",
             "assignee": "李四", "priority": "medium", "created_at": now},
            {"task_id": "TASK-003", "name": "季度渗透测试", "status": "done",
             "assignee": "王五", "priority": "high", "created_at": now},
            {"task_id": "TASK-004", "name": "IoT 固件更新", "status": "failed",
             "assignee": "赵六", "priority": "low", "created_at": now},
            {"task_id": "TASK-005", "name": "移动 App 加固", "status": "cancelled",
             "assignee": "钱七", "priority": "medium", "created_at": now},
        ]

        # 3 个示例报告
        self.sample_data["reports"] = [
            {"report_id": "RPT-001", "type": "渗透测试报告", "status": "published",
             "author": "安全团队", "created_at": now, "scope": "Web 业务系统"},
            {"report_id": "RPT-002", "type": "漏洞评估报告", "status": "draft",
             "author": "扫描平台", "created_at": now, "scope": "全资产"},
            {"report_id": "RPT-003", "type": "合规审计报告", "status": "review",
             "author": "合规组", "created_at": now, "scope": "等保三级"},
        ]

        # 10 个示例告警（不同级别）
        levels = ["critical", "high", "medium", "low", "info"]
        self.sample_data["alerts"] = [
            {
                "alert_id": f"ALT-{i+1:03d}",
                "title": f"示例告警 {i+1}",
                "level": levels[i % len(levels)],
                "source": "SIEM", "status": "open" if i % 2 else "acknowledged",
                "created_at": now, "message": f"示例告警描述 #{i+1}",
            }
            for i in range(10)
        ]

        # 5 个示例用户（不同角色）
        self.sample_data["users"] = [
            {"user_id": "U-001", "username": "admin", "role": "administrator",
             "email": "admin@example.local", "status": "active"},
            {"user_id": "U-002", "username": "analyst1", "role": "analyst",
             "email": "analyst1@example.local", "status": "active"},
            {"user_id": "U-003", "username": "auditor1", "role": "auditor",
             "email": "auditor1@example.local", "status": "active"},
            {"user_id": "U-004", "username": "guest1", "role": "guest",
             "email": "guest1@example.local", "status": "inactive"},
            {"user_id": "U-005", "username": "api_user", "role": "api_user",
             "email": "api@example.local", "status": "active"},
        ]

        return {"success": True,
                "counts": {k: len(v) for k, v in self.sample_data.items()}}

    def clear_sample_data(self) -> Dict[str, Any]:
        for k in self.sample_data:
            self.sample_data[k].clear()
        return {"success": True, "cleared": list(self.sample_data.keys())}

    def get_sample_data(self) -> Dict[str, Any]:
        return self.sample_data

    def get_report(self) -> Optional[Dict[str, Any]]:
        return self.last_report


# 单例
_wizard: Optional[InitializationWizard] = None


def get_wizard() -> InitializationWizard:
    global _wizard
    if _wizard is None:
        _wizard = InitializationWizard()
    return _wizard
