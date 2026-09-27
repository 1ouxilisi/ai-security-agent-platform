#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
client_portal模块，提供相关安全测试功能。

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


class UserRole(str, Enum):
    """用户角色"""
    ADMIN = "admin"
    ANALYST = "analyst"
    CLIENT = "client"


class ProjectStatus(str, Enum):
    """项目状态"""
    PENDING = "pending"
    IN_PROGRESS = "in_progress"
    COMPLETED = "completed"
    ON_HOLD = "on_hold"
    CANCELLED = "cancelled"


@dataclass
class User:
    """用户"""
    user_id: str
    username: str
    email: str
    role: UserRole
    password_hash: str = ""
    api_token: str = ""
    created_at: float = field(default_factory=time.time)
    last_login: Optional[float] = None
    active: bool = True
    client_id: Optional[str] = None  # 关联的客户ID（client角色）

    def to_dict(self, include_sensitive: bool = False) -> Dict[str, Any]:
        """执行相关操作。

        Args:
            include_sensitive: 相关参数。

        Returns:
            操作结果。
        """
        data = {
            "user_id": self.user_id,
            "username": self.username,
            "email": self.email,
            "role": self.role.value,
            "created_at": self.created_at,
            "last_login": self.last_login,
            "active": self.active,
            "client_id": self.client_id
        }
        if include_sensitive:
            data["password_hash"] = self.password_hash
            data["api_token"] = self.api_token
        return data


@dataclass
class Client:
    """客户"""
    client_id: str
    name: str
    contact_person: str = ""
    email: str = ""
    phone: str = ""
    company: str = ""
    address: str = ""
    notes: str = ""
    created_at: float = field(default_factory=time.time)
    status: str = "active"
    custom_fields: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        """执行相关操作。

        Returns:
            操作结果。
        """
        return {
            "client_id": self.client_id,
            "name": self.name,
            "contact_person": self.contact_person,
            "email": self.email,
            "phone": self.phone,
            "company": self.company,
            "address": self.address,
            "notes": self.notes,
            "created_at": self.created_at,
            "status": self.status,
            "custom_fields": self.custom_fields
        }


@dataclass
class Project:
    """项目"""
    project_id: str
    name: str
    description: str
    client_id: str
    status: ProjectStatus = ProjectStatus.PENDING
    assigned_to: List[str] = field(default_factory=list)
    targets: List[str] = field(default_factory=list)
    start_date: Optional[float] = None
    end_date: Optional[float] = None
    budget: float = 0.0
    priority: str = "medium"  # low/medium/high/critical
    created_at: float = field(default_factory=time.time)
    updated_at: float = field(default_factory=time.time)
    tags: List[str] = field(default_factory=list)
    findings_count: int = 0
    critical_count: int = 0
    high_count: int = 0
    medium_count: int = 0
    low_count: int = 0

    def to_dict(self) -> Dict[str, Any]:
        """执行相关操作。

        Returns:
            操作结果。
        """
        return {
            "project_id": self.project_id,
            "name": self.name,
            "description": self.description,
            "client_id": self.client_id,
            "status": self.status.value,
            "assigned_to": self.assigned_to,
            "targets": self.targets,
            "start_date": self.start_date,
            "end_date": self.end_date,
            "budget": self.budget,
            "priority": self.priority,
            "created_at": self.created_at,
            "updated_at": self.updated_at,
            "tags": self.tags,
            "findings_count": self.findings_count,
            "critical_count": self.critical_count,
            "high_count": self.high_count,
            "medium_count": self.medium_count,
            "low_count": self.low_count
        }


@dataclass
class Report:
    """报告"""
    report_id: str
    project_id: str
    client_id: str
    title: str
    report_type: str = "pentest"  # pentest/vulnerability_assessment/compliance
    status: str = "draft"  # draft/review/final/delivered
    content: str = ""
    file_path: str = ""
    created_by: str = ""
    created_at: float = field(default_factory=time.time)
    updated_at: float = field(default_factory=time.time)
    version: str = "1.0"
    findings: List[Dict[str, Any]] = field(default_factory=list)
    summary: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self, include_content: bool = True) -> Dict[str, Any]:
        """执行相关操作。

        Args:
            include_content: 相关参数。

        Returns:
            操作结果。
        """
        data = {
            "report_id": self.report_id,
            "project_id": self.project_id,
            "client_id": self.client_id,
            "title": self.title,
            "report_type": self.report_type,
            "status": self.status,
            "file_path": self.file_path,
            "created_by": self.created_by,
            "created_at": self.created_at,
            "updated_at": self.updated_at,
            "version": self.version,
            "findings_count": len(self.findings),
            "summary": self.summary
        }
        if include_content:
            data["content"] = self.content
            data["findings"] = self.findings
        return data


class ClientPortal:
    """客户门户系统"""

    def __init__(self, data_dir: str = "data/portal"):
        """初始化ClientPortal实例。

        Args:
            self: 类实例。
        """
        self.data_dir = data_dir
        self.users: Dict[str, User] = {}
        self.clients: Dict[str, Client] = {}
        self.projects: Dict[str, Project] = {}
        self.reports: Dict[str, Report] = {}
        self.tokens: Dict[str, str] = {}  # token -> user_id

        os.makedirs(data_dir, exist_ok=True)
        self._load_data()
        self._init_default_admin()

    def _hash_password(self, password: str) -> str:
        """密码哈希"""
        return hashlib.sha256(password.encode()).hexdigest()

    def _generate_token(self) -> str:
        """生成API Token"""
        return secrets.token_hex(32)

    def _init_default_admin(self):
        """初始化默认管理员"""
        if not self.users:
            admin = User(
                user_id="admin-001",
                username="admin",
                email="admin@aihacking.local",
                role=UserRole.ADMIN,
                password_hash=self._hash_password("admin123"),
                api_token=self._generate_token()
            )
            self.users[admin.user_id] = admin
            log.info("已创建默认管理员: admin/admin123")
            self._save_data()

    def _load_data(self):
        """从文件加载数据"""
        for data_type, data_dict, cls in [
            ("users", self.users, User),
            ("clients", self.clients, Client),
            ("projects", self.projects, Project),
            ("reports", self.reports, Report)
        ]:
            filepath = os.path.join(self.data_dir, f"{data_type}.json")
            if os.path.exists(filepath):
                try:
                    with open(filepath, 'r', encoding='utf-8') as f:
                        data = json.load(f)
                    for item_id, item_data in data.items():
                        # 简化：直接存储字典，不重建对象
                        data_dict[item_id] = item_data
                    log.info(f"加载 {data_type}: {len(data)} 条")
                except Exception as e:
                    log.error(f"加载 {data_type} 失败: {e}")

    def _save_data(self):
        """保存数据到文件"""
        for data_type, data_dict in [
            ("users", self.users),
            ("clients", self.clients),
            ("projects", self.projects),
            ("reports", self.reports)
        ]:
            filepath = os.path.join(self.data_dir, f"{data_type}.json")
            try:
                # 转换对象为字典
                serializable = {}
                for k, v in data_dict.items():
                    if hasattr(v, 'to_dict'):
                        serializable[k] = v.to_dict(include_sensitive=True) if data_type == "users" else v.to_dict()
                    else:
                        serializable[k] = v
                with open(filepath, 'w', encoding='utf-8') as f:
                    json.dump(serializable, f, ensure_ascii=False, indent=2, default=str)
            except Exception as e:
                log.error(f"保存 {data_type} 失败: {e}")

    # ===== 用户管理 =====
    def create_user(self, username: str, email: str, password: str, role: str = "client",
                    client_id: str = None) -> Dict[str, Any]:
        """创建用户"""
        user_id = f"user-{uuid.uuid4().hex[:8]}"
        user = User(
            user_id=user_id,
            username=username,
            email=email,
            role=UserRole(role),
            password_hash=self._hash_password(password),
            api_token=self._generate_token(),
            client_id=client_id
        )
        self.users[user_id] = user
        self._save_data()
        log.info(f"创建用户: {username} ({role})")
        return user.to_dict()

    def authenticate(self, username: str, password: str) -> Optional[Dict[str, Any]]:
        """用户认证"""
        password_hash = self._hash_password(password)
        for user in self.users.values():
            user_data = user if isinstance(user, dict) else user.to_dict(include_sensitive=True)
            if user_data.get("username") == username and user_data.get("password_hash") == password_hash:
                token = self._generate_token()
                self.tokens[token] = user_data["user_id"]
                if not isinstance(user, dict):
                    user.last_login = time.time()
                self._save_data()
                log.info(f"用户登录: {username}")
                return {
                    "token": token,
                    "user": {k: v for k, v in user_data.items() if k not in ("password_hash",)}
                }
        return None

    def verify_token(self, token: str) -> Optional[Dict[str, Any]]:
        """验证Token"""
        user_id = self.tokens.get(token)
        if not user_id:
            return None
        user = self.users.get(user_id)
        if user:
            return user if isinstance(user, dict) else user.to_dict()
        return None

    # ===== 客户管理 =====
    def create_client(self, name: str, contact_person: str = "", email: str = "",
                      phone: str = "", company: str = "", notes: str = "") -> Dict[str, Any]:
        """创建客户"""
        client_id = f"client-{uuid.uuid4().hex[:8]}"
        client = Client(
            client_id=client_id,
            name=name,
            contact_person=contact_person,
            email=email,
            phone=phone,
            company=company,
            notes=notes
        )
        self.clients[client_id] = client
        self._save_data()
        log.info(f"创建客户: {name}")
        return client.to_dict()

    def list_clients(self) -> List[Dict[str, Any]]:
        """列出客户"""
        return [c if isinstance(c, dict) else c.to_dict() for c in self.clients.values()]

    # ===== 项目管理 =====
    def create_project(self, name: str, description: str, client_id: str,
                       targets: List[str] = None, priority: str = "medium",
                       budget: float = 0.0) -> Dict[str, Any]:
        """创建项目"""
        project_id = f"proj-{uuid.uuid4().hex[:8]}"
        project = Project(
            project_id=project_id,
            name=name,
            description=description,
            client_id=client_id,
            targets=targets or [],
            priority=priority,
            budget=budget,
            start_date=time.time()
        )
        self.projects[project_id] = project
        self._save_data()
        log.info(f"创建项目: {name} ({project_id})")
        return project.to_dict()

    def list_projects(self, client_id: str = None, status: str = None) -> List[Dict[str, Any]]:
        """列出项目"""
        projects = []
        for p in self.projects.values():
            p_data = p if isinstance(p, dict) else p.to_dict()
            if client_id and p_data.get("client_id") != client_id:
                continue
            if status and p_data.get("status") != status:
                continue
            projects.append(p_data)
        return projects

    def update_project_status(self, project_id: str, status: str) -> Optional[Dict[str, Any]]:
        """更新项目状态"""
        project = self.projects.get(project_id)
        if not project:
            return None
        if isinstance(project, dict):
            project["status"] = status
            project["updated_at"] = time.time()
        else:
            project.status = ProjectStatus(status)
            project.updated_at = time.time()
        self._save_data()
        return project if isinstance(project, dict) else project.to_dict()

    # ===== 报告管理 =====
    def create_report(self, project_id: str, title: str, content: str = "",
                      report_type: str = "pentest", findings: List[Dict] = None) -> Dict[str, Any]:
        """创建报告"""
        project = self.projects.get(project_id)
        if not project:
            return {"error": "项目不存在"}
        client_id = project["client_id"] if isinstance(project, dict) else project.client_id

        report_id = f"report-{uuid.uuid4().hex[:8]}"
        report = Report(
            report_id=report_id,
            project_id=project_id,
            client_id=client_id,
            title=title,
            content=content,
            report_type=report_type,
            findings=findings or []
        )
        self.reports[report_id] = report
        self._save_data()
        log.info(f"创建报告: {title} ({report_id})")
        return report.to_dict()

    def list_reports(self, project_id: str = None, client_id: str = None) -> List[Dict[str, Any]]:
        """列出报告"""
        reports = []
        for r in self.reports.values():
            r_data = r if isinstance(r, dict) else r.to_dict(include_content=False)
            if project_id and r_data.get("project_id") != project_id:
                continue
            if client_id and r_data.get("client_id") != client_id:
                continue
            reports.append(r_data)
        return reports

    def get_report(self, report_id: str) -> Optional[Dict[str, Any]]:
        """获取报告详情"""
        report = self.reports.get(report_id)
        if report:
            return report if isinstance(report, dict) else report.to_dict()
        return None

    # ===== 统计 =====
    def get_dashboard_stats(self) -> Dict[str, Any]:
        """获取仪表盘统计"""
        total_clients = len(self.clients)
        total_projects = len(self.projects)
        total_reports = len(self.reports)
        total_users = len(self.users)

        active_projects = sum(
            1 for p in self.projects.values()
            if (p if isinstance(p, dict) else p.to_dict()).get("status") == "in_progress"
        )
        completed_projects = sum(
            1 for p in self.projects.values()
            if (p if isinstance(p, dict) else p.to_dict()).get("status") == "completed"
        )

        total_findings = sum(
            (r if isinstance(r, dict) else r.to_dict()).get("findings_count", 0)
            for r in self.reports.values()
        )

        return {
            "total_clients": total_clients,
            "total_projects": total_projects,
            "total_reports": total_reports,
            "total_users": total_users,
            "active_projects": active_projects,
            "completed_projects": completed_projects,
            "total_findings": total_findings,
            "recent_projects": self.list_projects()[:5],
            "recent_reports": self.list_reports()[:5]
        }


# 全局实例
client_portal = ClientPortal()
