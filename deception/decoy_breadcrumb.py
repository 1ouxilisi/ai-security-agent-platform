# -*- coding: utf-8 -*-
"""
decoy_breadcrumb.py — 诱饵与面包屑设计器（第13轮升级）。

功能：
- 虚假文件：诱饵文档/源代码/配置/备份/密钥文件
- 虚假数据库记录：用户表/订单表/财务数据/客户数据/员工数据
- 虚假API端点：未文档化API/管理API/调试API/内部API/Webhook
- 虚假用户账户：管理员/服务账户/测试账户/离职员工
- 虚假网络共享：SMB/NFS/FTP/云存储
- 敏感数据诱饵：密码文件/SSH密钥/API密钥/数据库凭证/证书/Token
- 面包屑路径设计：入口到诱饵的路径/线索/检测点/引导
- 检测规则：诱饵访问/文件打开/数据复制/账户使用/API调用检测
- 诱饵与面包屑报告

合法边界：仅用于防御检测与研究。
"""

from __future__ import annotations

import hashlib
import random
import uuid
from dataclasses import asdict, dataclass, field
from datetime import datetime
from typing import Any, Dict, List, Optional

# ==================== 常量库：诱饵类型 ====================

DECOY_TYPES: Dict[str, Dict[str, Any]] = {
    "fake_document_word": {
        "name": "诱饵Word文档",
        "category": "file",
        "file_ext": ".docx",
        "desc": "看似敏感的Word文档（财务/合同/战略）",
        "detection_sensitivity": "high",
    },
    "fake_document_excel": {
        "name": "诱饵Excel表格",
        "category": "file",
        "file_ext": ".xlsx",
        "desc": "看似含敏感数据的Excel表格",
        "detection_sensitivity": "high",
    },
    "fake_document_pdf": {
        "name": "诱饵PDF",
        "category": "file",
        "file_ext": ".pdf",
        "desc": "看似敏感的PDF文档",
        "detection_sensitivity": "high",
    },
    "fake_source_code": {
        "name": "虚假源代码",
        "category": "file",
        "file_ext": ".py/.js/.java",
        "desc": "看似核心业务代码",
        "detection_sensitivity": "medium",
    },
    "fake_config": {
        "name": "虚假配置文件",
        "category": "file",
        "file_ext": ".yaml/.env/.conf",
        "desc": "含虚假凭证的配置文件",
        "detection_sensitivity": "critical",
    },
    "fake_backup": {
        "name": "虚假备份文件",
        "category": "file",
        "file_ext": ".tar.gz/.zip",
        "desc": "看似数据库备份",
        "detection_sensitivity": "critical",
    },
    "fake_key_file": {
        "name": "虚假密钥文件",
        "category": "file",
        "file_ext": ".pem/.key/.ppk",
        "desc": "看似SSH/API密钥",
        "detection_sensitivity": "critical",
    },
    "fake_db_users": {
        "name": "虚假用户表",
        "category": "database",
        "desc": "含虚假用户数据的数据库表",
        "detection_sensitivity": "high",
    },
    "fake_db_orders": {
        "name": "虚假订单表",
        "category": "database",
        "desc": "含虚假交易数据",
        "detection_sensitivity": "high",
    },
    "fake_db_finance": {
        "name": "虚假财务数据",
        "category": "database",
        "desc": "看似财务报表数据",
        "detection_sensitivity": "critical",
    },
    "fake_api_admin": {
        "name": "虚假管理API",
        "category": "api",
        "desc": "看似未文档化的管理接口",
        "detection_sensitivity": "critical",
    },
    "fake_api_debug": {
        "name": "虚假调试API",
        "category": "api",
        "desc": "看似调试接口",
        "detection_sensitivity": "high",
    },
    "fake_api_webhook": {
        "name": "诱饵Webhook",
        "category": "api",
        "desc": "看似回调Webhook",
        "detection_sensitivity": "high",
    },
    "fake_account_admin": {
        "name": "虚假管理员账户",
        "category": "account",
        "desc": "看似域管理员账户",
        "detection_sensitivity": "critical",
    },
    "fake_account_service": {
        "name": "虚假服务账户",
        "category": "account",
        "desc": "看似服务运行账户",
        "detection_sensitivity": "high",
    },
    "fake_account_test": {
        "name": "虚假测试账户",
        "category": "account",
        "desc": "看似遗留测试账户",
        "detection_sensitivity": "medium",
    },
    "fake_smb_share": {
        "name": "虚假SMB共享",
        "category": "network_share",
        "desc": "看似内部文件共享",
        "detection_sensitivity": "high",
    },
    "fake_ftp_dir": {
        "name": "虚假FTP目录",
        "category": "network_share",
        "desc": "看似FTP下载目录",
        "detection_sensitivity": "high",
    },
    "fake_cloud_bucket": {
        "name": "虚假云存储桶",
        "category": "network_share",
        "desc": "看似S3兼容存储桶",
        "detection_sensitivity": "critical",
    },
}

# 诱饵内容模板
DECOY_DOCS = {
    "financial_report": {
        "title": "2024年度财务报表_机密.docx",
        "content_summary": "营收数据/利润/成本分析（虚假）",
        "sensitivity": "critical",
    },
    "employee_list": {
        "title": "员工花名册_2024.xlsx",
        "content_summary": "姓名/职位/薪资/联系方式（虚假）",
        "sensitivity": "high",
    },
    "strategy_doc": {
        "title": "产品战略规划_机密.pdf",
        "content_summary": "新产品路线图/市场计划（虚假）",
        "sensitivity": "critical",
    },
    "db_backup": {
        "title": "appdb_backup_20240101.sql.gz",
        "content_summary": "完整数据库备份（虚假）",
        "sensitivity": "critical",
    },
    "env_file": {
        "title": ".env.production",
        "content_summary": "数据库密码/API密钥（虚假）",
        "sensitivity": "critical",
    },
}

# 虚假账户模板
FAKE_ACCOUNTS = [
    {"username": "svc_backup", "role": "Backup Service", "group": "Backup Operators", "fake": True},
    {"username": "admin_john", "role": "System Admin", "group": "Domain Admins", "fake": True},
    {"username": "test_deploy", "role": "Test Deploy", "group": "Developers", "fake": True},
    {"username": "svc_sql", "role": "SQL Server Service", "group": "SQL Admins", "fake": True},
    {"username": "temp_contractor", "role": "Contractor", "group": "Temp Staff", "fake": True},
]

# 虚假API端点
FAKE_API_ENDPOINTS = [
    {"path": "/api/v1/admin/users", "method": "GET", "desc": "管理-用户列表", "sensitive": True},
    {"path": "/api/v1/debug/config", "method": "GET", "desc": "调试-配置导出", "sensitive": True},
    {"path": "/api/v1/internal/db/query", "method": "POST", "desc": "内部-数据库查询", "sensitive": True},
    {"path": "/api/v1/webhook/order", "method": "POST", "desc": "订单Webhook", "sensitive": False},
    {"path": "/api/v1/admin/export", "method": "GET", "desc": "管理-数据导出", "sensitive": True},
]


# ==================== 数据类 ====================

@dataclass
class DecoyInstance:
    decoy_id: str = ""
    name: str = ""
    decoy_type: str = ""
    category: str = ""
    path: str = ""
    content_summary: str = ""
    sensitivity: str = "medium"
    created_at: str = ""
    accessed_count: int = 0
    last_accessed: str = ""
    detection_rules: List[str] = field(default_factory=list)
    breadcrumb_path: List[str] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


# ==================== 诱饵设计器 ====================

class DecoyBreadcrumbDesigner:
    """诱饵与面包屑设计器"""

    def __init__(self) -> None:
        self.decoys: Dict[str, DecoyInstance] = {}
        self.detection_events: List[Dict[str, Any]] = []
        self.paths: List[Dict[str, Any]] = []
        self._counter: int = 0

    # ---------- 类型库 ----------

    def list_types(self) -> List[Dict[str, Any]]:
        return [{"type_id": k, **v} for k, v in DECOY_TYPES.items()]

    # ---------- 创建诱饵 ----------

    def create_decoy(self, decoy_type: str, name: str = "",
                     path: str = "") -> Dict[str, Any]:
        info = DECOY_TYPES.get(decoy_type)
        if not info:
            return {"success": False, "error": f"未知诱饵类型: {decoy_type}"}

        self._counter += 1
        decoy_id = f"decoy-{uuid.uuid4().hex[:8]}"
        auto_path = path or self._default_path(decoy_type, self._counter)

        decoy = DecoyInstance(
            decoy_id=decoy_id,
            name=name or f"{info['name']}-{self._counter}",
            decoy_type=decoy_type,
            category=info["category"],
            path=auto_path,
            content_summary=self._decoy_content(decoy_type),
            sensitivity=info["detection_sensitivity"],
            created_at=datetime.now().isoformat(),
            detection_rules=self._build_detection_rules(decoy_type),
        )
        self.decoys[decoy_id] = decoy
        return {"success": True, "decoy_id": decoy_id, "decoy": decoy.to_dict()}

    @staticmethod
    def _default_path(decoy_type: str, n: int) -> str:
        paths = {
            "fake_document_word": f"/home/user/Documents/机密文档_{n}.docx",
            "fake_document_excel": f"/home/user/Documents/员工表_{n}.xlsx",
            "fake_document_pdf": f"/var/www/docs/战略规划_{n}.pdf",
            "fake_source_code": f"/opt/app/src/internal_{n}.py",
            "fake_config": f"/opt/app/.env.production",
            "fake_backup": f"/var/backups/appdb_{n}.sql.gz",
            "fake_key_file": f"/root/.ssh/id_rsa",
            "fake_db_users": "mysql://db/appdb?table=users",
            "fake_db_finance": "mysql://db/finance?table=quarterly",
            "fake_api_admin": "https://app.internal/api/v1/admin/users",
            "fake_smb_share": "\\\\fileserver\\confidential\\",
        }
        return paths.get(decoy_type, f"/decoy/{decoy_type}_{n}")

    @staticmethod
    def _decoy_content(decoy_type: str) -> str:
        contents = {
            "fake_config": "DB_PASSWORD=decoy_pwd_2024\nAPI_KEY=sk_fake_xxx",
            "fake_key_file": "-----BEGIN RSA PRIVATE KEY-----\nfake_content",
            "fake_db_finance": "Q1营收: 9,800,000 | Q1利润: 2,300,000 (虚假)",
            "fake_api_admin": "GET /api/v1/admin/users 返回200（虚假）",
        }
        return contents.get(decoy_type, "诱饵内容（模拟）")

    @staticmethod
    def _build_detection_rules(decoy_type: str) -> List[str]:
        rules = {
            "fake_config": ["file_open", "file_read", "file_copy"],
            "fake_key_file": ["file_open", "ssh_key_use"],
            "fake_db_finance": ["db_query", "db_export", "table_select"],
            "fake_api_admin": ["api_call", "api_auth", "http_request"],
            "fake_smb_share": ["smb_access", "file_list", "file_download"],
        }
        return rules.get(decoy_type, ["access"])

    # ---------- 面包屑路径设计 ----------

    def design_breadcrumb_path(self, entry_point: str,
                               decoy_ids: List[str]) -> Dict[str, Any]:
        """设计从入口到诱饵的面包屑路径"""
        steps = [
            {"step": 1, "action": "initial_access", "desc": entry_point},
            {"step": 2, "action": "reconnaissance", "desc": "攻击者进行文件枚举"},
            {"step": 3, "action": "lure_discovery", "desc": "发现诱饵文件/目录"},
            {"step": 4, "action": "decoy_access", "desc": "访问诱饵资源"},
        ]
        for i, did in enumerate(decoy_ids):
            decoy = self.decoys.get(did)
            if decoy:
                steps.append({
                    "step": 5 + i, "action": "decoy_" + str(i + 1),
                    "desc": f"访问诱饵: {decoy.name} ({decoy.path})",
                    "decoy_id": did,
                })
        path = {
            "path_id": f"path-{uuid.uuid4().hex[:8]}",
            "entry_point": entry_point,
            "steps": steps,
            "total_steps": len(steps),
            "detection_points": [s["action"] for s in steps if "decoy" in s["action"]],
            "created_at": datetime.now().isoformat(),
        }
        self.paths.append(path)
        return path

    # ---------- 访问检测 ----------

    def simulate_access(self, decoy_id: str, source_ip: str,
                        action: str = "open") -> Dict[str, Any]:
        """模拟诱饵访问事件并触发检测"""
        decoy = self.decoys.get(decoy_id)
        if not decoy:
            return {"success": False, "error": "诱饵不存在"}

        decoy.accessed_count += 1
        decoy.last_accessed = datetime.now().isoformat()

        event = {
            "event_id": f"evt-{uuid.uuid4().hex[:8]}",
            "decoy_id": decoy_id,
            "decoy_name": decoy.name,
            "source_ip": source_ip,
            "action": action,
            "sensitivity": decoy.sensitivity,
            "timestamp": datetime.now().isoformat(),
            "alert_level": decoy.sensitivity,
        }
        self.detection_events.append(event)
        return {"success": True, "event": event}

    def list_detections(self, limit: int = 100) -> List[Dict[str, Any]]:
        return self.detection_events[-limit:]

    # ---------- 查询 ----------

    def list_decoys(self) -> List[Dict[str, Any]]:
        return [d.to_dict() for d in self.decoys.values()]

    def get_decoy(self, decoy_id: str) -> Optional[Dict[str, Any]]:
        d = self.decoys.get(decoy_id)
        return d.to_dict() if d else None

    def delete_decoy(self, decoy_id: str) -> Dict[str, Any]:
        d = self.decoys.pop(decoy_id, None)
        if not d:
            return {"success": False, "error": "诱饵不存在"}
        return {"success": True, "message": f"诱饵 {d.name} 已删除"}

    def get_statistics(self) -> Dict[str, Any]:
        decoys = list(self.decoys.values())
        cat_count: Dict[str, int] = {}
        sens_count: Dict[str, int] = {}
        accessed = 0
        for d in decoys:
            cat_count[d.category] = cat_count.get(d.category, 0) + 1
            sens_count[d.sensitivity] = sens_count.get(d.sensitivity, 0) + 1
            if d.accessed_count > 0:
                accessed += 1
        return {
            "total_decoys": len(decoys),
            "by_category": cat_count,
            "by_sensitivity": sens_count,
            "decoys_accessed": accessed,
            "total_detection_events": len(self.detection_events),
            "breadcrumb_paths": len(self.paths),
        }

    # ---------- 报告 ----------

    def generate_report(self) -> Dict[str, Any]:
        stats = self.get_statistics()
        return {
            "report_title": "诱饵与面包屑设计报告",
            "generated_at": datetime.now().isoformat(),
            **stats,
            "recent_detections": self.detection_events[-10:],
            "decoys": [d.to_dict() for d in self.decoys.values()],
            "recommendations": [
                "高敏感诱饵应放置在攻击者自然会探索的位置",
                "诱饵内容应逼真且与真实业务数据一致",
                "结合面包屑路径引导攻击者进入监控区域",
            ],
        }


# ==================== 工厂函数 ====================

_designer_singleton: Optional[DecoyBreadcrumbDesigner] = None


def get_decoy_designer() -> DecoyBreadcrumbDesigner:
    global _designer_singleton
    if _designer_singleton is None:
        _designer_singleton = DecoyBreadcrumbDesigner()
    return _designer_singleton
