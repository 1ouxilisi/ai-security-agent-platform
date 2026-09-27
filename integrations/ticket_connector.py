#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
ticket_connector 模块，提供工单系统连接器。

模块功能：
    - 支持 Jira / 禅道 / 飞书任务 / 通用 Webhook 四种后端
    - 创建 / 更新 / 评论 / 查询工单
    - 根据漏洞严重程度自动创建工单并设置优先级
    - 工单状态同步与连接测试

注意事项：
    - 本模块仅用于授权的安全运营场景
    - 请勿用于非法用途
    - 使用前请确保已获得相关授权
"""

import json
import os
from datetime import datetime, timezone
from typing import Any, Dict, Optional

import requests

try:
    from loguru import logger
except ImportError:
    import logging
    logger = logging.getLogger(__name__)


PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
CONFIG_DIR = os.path.join(PROJECT_ROOT, "config")
CONFIG_PATH = os.path.join(CONFIG_DIR, "ticket_config.json")

DEFAULT_CONFIG: Dict[str, Any] = {
    "type": "webhook",          # jira / zentao / feishu / webhook
    "timeout": 10,
    # Jira 配置
    "jira": {
        "base_url": "https://your-jira.example.com",
        "api_token": "",
        "username": "",
        "project_key": "SEC",
    },
    # 禅道配置
    "zentao": {
        "base_url": "https://your-zentao.example.com",
        "token": "",
        "product_id": "1",
    },
    # 飞书任务配置
    "feishu": {
        "app_id": "",
        "app_secret": "",
    },
    # 通用 Webhook 配置
    "webhook": {
        "url": "",
    },
}

# 严重程度 -> 工单优先级
SEVERITY_PRIORITY = {
    "critical": "Highest",
    "high": "High",
    "medium": "Medium",
    "low": "Low",
    "info": "Lowest",
}


class TicketConnector:
    """工单系统连接器（多后端）。"""

    def __init__(self, config_path: str = CONFIG_PATH):
        """初始化连接器并加载配置。"""
        self.config_path = config_path
        self.config: Dict[str, Any] = json.loads(json.dumps(DEFAULT_CONFIG))
        self.load_config()

    # ==================== 配置读写 ====================

    def load_config(self) -> Dict[str, Any]:
        """加载工单配置。"""
        try:
            os.makedirs(os.path.dirname(self.config_path), exist_ok=True)
            if os.path.exists(self.config_path):
                with open(self.config_path, "r", encoding="utf-8") as f:
                    saved = json.load(f)
                # 深合并
                for k, v in saved.items():
                    if isinstance(v, dict) and isinstance(self.config.get(k), dict):
                        self.config[k].update(v)
                    else:
                        self.config[k] = v
            else:
                self.save_config()
        except Exception as e:
            logger.warning("工单配置加载失败，使用默认配置: %s", e)
            self.config = json.loads(json.dumps(DEFAULT_CONFIG))
        return self.config

    def save_config(self) -> bool:
        """保存工单配置。"""
        try:
            os.makedirs(os.path.dirname(self.config_path), exist_ok=True)
            with open(self.config_path, "w", encoding="utf-8") as f:
                json.dump(self.config, f, ensure_ascii=False, indent=2)
            return True
        except Exception as e:
            logger.error("工单配置保存失败: %s", e)
            return False

    def update_config(self, new_config: Dict[str, Any]) -> Dict[str, Any]:
        """合并更新配置。"""
        self.config.update(new_config or {})
        self.save_config()
        return self.config

    # ==================== HTTP 工具 ====================

    def _timeout(self) -> float:
        return float(self.config.get("timeout", 10))

    @staticmethod
    def _headers(token: str = "", extra: Optional[Dict[str, str]] = None) -> Dict[str, str]:
        h = {"Content-Type": "application/json", "Accept": "application/json"}
        if token:
            h["Authorization"] = f"Bearer {token}"
        if extra:
            h.update(extra)
        return h

    # ==================== Jira 后端 ====================

    def _jira_creds(self) -> Dict[str, str]:
        return self.config.get("jira", {})

    def create_issue(self, project_key: str, summary: str, description: str,
                     priority: str = "Medium",
                     labels: Optional[list] = None) -> Dict[str, Any]:
        """在 Jira 中创建工单。"""
        j = self._jira_creds()
        base = j.get("base_url", "").rstrip("/")
        if not base:
            return {"success": False, "message": "Jira base_url 未配置"}
        url = f"{base}/rest/api/2/issue"
        fields = {
            "project": {"key": project_key},
            "summary": summary,
            "description": description,
            "issuetype": {"name": "Bug"},
            "priority": {"name": priority},
        }
        if labels:
            fields["labels"] = labels
        try:
            resp = requests.post(
                url,
                headers=self._headers(j.get("api_token", "")),
                json={"fields": fields},
                auth=(j.get("username", ""), j.get("api_token", "")) if j.get("username") else None,
                timeout=self._timeout(),
            )
            return {"success": resp.ok, "status_code": resp.status_code,
                    "data": resp.json() if resp.content else {},
                    "issue_key": (resp.json() or {}).get("key")}
        except Exception as e:
            return {"success": False, "message": f"Jira 创建工单失败: {e}"}

    def update_status(self, issue_key: str, transition_id: str) -> Dict[str, Any]:
        """更新 Jira 工单状态（执行 transition）。"""
        j = self._jira_creds()
        base = j.get("base_url", "").rstrip("/")
        url = f"{base}/rest/api/2/issue/{issue_key}/transitions"
        try:
            resp = requests.post(
                url,
                headers=self._headers(j.get("api_token", "")),
                json={"transition": {"id": transition_id}},
                auth=(j.get("username", ""), j.get("api_token", "")) if j.get("username") else None,
                timeout=self._timeout(),
            )
            return {"success": resp.ok, "status_code": resp.status_code}
        except Exception as e:
            return {"success": False, "message": f"Jira 更新状态失败: {e}"}

    def add_comment(self, issue_key: str, comment: str) -> Dict[str, Any]:
        """给 Jira 工单添加评论。"""
        j = self._jira_creds()
        base = j.get("base_url", "").rstrip("/")
        url = f"{base}/rest/api/2/issue/{issue_key}/comment"
        try:
            resp = requests.post(
                url,
                headers=self._headers(j.get("api_token", "")),
                json={"body": comment},
                auth=(j.get("username", ""), j.get("api_token", "")) if j.get("username") else None,
                timeout=self._timeout(),
            )
            return {"success": resp.ok, "status_code": resp.status_code}
        except Exception as e:
            return {"success": False, "message": f"Jira 添加评论失败: {e}"}

    def get_issue(self, issue_key: str) -> Dict[str, Any]:
        """查询 Jira 工单详情。"""
        j = self._jira_creds()
        base = j.get("base_url", "").rstrip("/")
        url = f"{base}/rest/api/2/issue/{issue_key}"
        try:
            resp = requests.get(
                url,
                headers=self._headers(j.get("api_token", "")),
                auth=(j.get("username", ""), j.get("api_token", "")) if j.get("username") else None,
                timeout=self._timeout(),
            )
            data = resp.json() if resp.content else {}
            return {
                "success": resp.ok,
                "issue_key": issue_key,
                "status": (data.get("fields", {}) or {}).get("status", {}).get("name"),
                "summary": (data.get("fields", {}) or {}).get("summary"),
                "data": data,
            }
        except Exception as e:
            return {"success": False, "issue_key": issue_key, "message": f"查询工单失败: {e}"}

    # ==================== 禅道后端 ====================

    def _zentao_creds(self) -> Dict[str, str]:
        return self.config.get("zentao", {})

    def create_bug(self, title: str, severity: int = 3, steps: str = "",
                   product_id: Optional[str] = None) -> Dict[str, Any]:
        """在禅道创建 Bug。

        Args:
            severity: 禅道严重程度 1-4（1 最严重）。
        """
        z = self._zentao_creds()
        base = z.get("base_url", "").rstrip("/")
        pid = product_id or z.get("product_id", "1")
        if not base:
            return {"success": False, "message": "禅道 base_url 未配置"}
        url = f"{base}/api/v1/products/{pid}/bugs"
        payload = {
            "title": title,
            "severity": severity,
            "steps": steps,
            "type": "codebug",
        }
        try:
            resp = requests.post(url, headers=self._headers(z.get("token", "")),
                                 json=payload, timeout=self._timeout())
            return {"success": resp.ok, "status_code": resp.status_code,
                    "data": resp.json() if resp.content else {}}
        except Exception as e:
            return {"success": False, "message": f"禅道创建 Bug 失败: {e}"}

    def update_bug(self, bug_id: str, payload: Dict[str, Any]) -> Dict[str, Any]:
        """更新禅道 Bug。"""
        z = self._zentao_creds()
        base = z.get("base_url", "").rstrip("/")
        url = f"{base}/api/v1/bugs/{bug_id}"
        try:
            resp = requests.post(url, headers=self._headers(z.get("token", "")),
                                 json=payload, timeout=self._timeout())
            return {"success": resp.ok, "status_code": resp.status_code}
        except Exception as e:
            return {"success": False, "message": f"禅道更新 Bug 失败: {e}"}

    # ==================== 飞书任务后端 ====================

    def create_feishu_task(self, summary: str, description: str = "") -> Dict[str, Any]:
        """通过飞书开放平台创建任务（基础实现，需 tenant_access_token）。"""
        f = self.config.get("feishu", {})
        if not f.get("app_id") or not f.get("app_secret"):
            return {"success": False, "message": "飞书 app_id/app_secret 未配置"}
        # 真实环境应先调用 /open-apis/auth/v3/tenant_access_token/internal 获取 token
        url = "https://open.feishu.cn/open-apis/task/v1/tasks"
        payload = {
            "summary": summary,
            "description": description,
        }
        try:
            resp = requests.post(url, headers=self._headers(""), json=payload,
                                 timeout=self._timeout())
            return {"success": resp.ok, "status_code": resp.status_code,
                    "data": resp.json() if resp.content else {}}
        except Exception as e:
            return {"success": False, "message": f"飞书创建任务失败: {e}"}

    # ==================== 通用 Webhook 后端 ====================

    def send_webhook(self, payload: Dict[str, Any]) -> Dict[str, Any]:
        """向配置的 Webhook URL 发送自定义 JSON。"""
        w = self.config.get("webhook", {})
        url = w.get("url", "")
        if not url:
            return {"success": False, "message": "Webhook URL 未配置"}
        try:
            resp = requests.post(url, json=payload, timeout=self._timeout())
            return {"success": resp.ok, "status_code": resp.status_code,
                    "data": resp.json() if resp.content else {}}
        except Exception as e:
            return {"success": False, "message": f"Webhook 推送失败: {e}"}

    # ==================== 业务编排 ====================

    def create_vulnerability_ticket(self, vuln_data: Dict[str, Any]) -> Dict[str, Any]:
        """根据漏洞数据自动创建工单，按严重程度设置优先级与标题。"""
        severity = (vuln_data.get("severity") or "medium").lower()
        priority = SEVERITY_PRIORITY.get(severity, "Medium")
        cve = vuln_data.get("cve_id") or vuln_data.get("vuln_id", "")
        target = vuln_data.get("target") or vuln_data.get("asset", "未知资产")
        title = f"[漏洞][{severity.upper()}] {cve} {vuln_data.get('title', '发现安全漏洞')} @ {target}"
        desc = (
            f"漏洞编号: {cve}\n"
            f"严重程度: {severity}\n"
            f"目标资产: {target}\n"
            f"描述: {vuln_data.get('description', '')}\n"
            f"发现时间: {datetime.now(timezone.utc).isoformat()}\n"
            f"修复建议: {vuln_data.get('remediation', '请人工评估')}"
        )
        backend = (self.config.get("type") or "webhook").lower()
        if backend == "jira":
            return self.create_issue(
                project_key=self._jira_creds().get("project_key", "SEC"),
                summary=title, description=desc, priority=priority,
                labels=["security", "vulnerability", severity],
            )
        if backend == "zentao":
            sev_num = {"critical": 1, "high": 2, "medium": 3, "low": 4}.get(severity, 3)
            return self.create_bug(title=title, severity=sev_num, steps=desc)
        if backend == "feishu":
            return self.create_feishu_task(summary=title, description=desc)
        # webhook / 未知后端
        return self.send_webhook({
            "event": "vulnerability_ticket",
            "title": title, "priority": priority, "severity": severity,
            "vuln": vuln_data,
        })

    def sync_ticket_status(self, ticket_id: str) -> Dict[str, Any]:
        """获取工单当前状态。"""
        backend = (self.config.get("type") or "webhook").lower()
        if backend == "jira":
            return self.get_issue(ticket_id)
        if backend == "zentao":
            z = self._zentao_creds()
            url = f"{z.get('base_url','').rstrip('/')}/api/v1/bugs/{ticket_id}"
            try:
                resp = requests.get(url, headers=self._headers(z.get("token", "")),
                                    timeout=self._timeout())
                return {"success": resp.ok, "ticket_id": ticket_id,
                        "data": resp.json() if resp.content else {}}
            except Exception as e:
                return {"success": False, "ticket_id": ticket_id,
                        "message": f"禅道状态同步失败: {e}"}
        if backend == "feishu":
            url = f"https://open.feishu.cn/open-apis/task/v1/tasks/{ticket_id}"
            try:
                resp = requests.get(url, timeout=self._timeout())
                return {"success": resp.ok, "ticket_id": ticket_id,
                        "data": resp.json() if resp.content else {}}
            except Exception as e:
                return {"success": False, "ticket_id": ticket_id,
                        "message": f"飞书任务状态同步失败: {e}"}
        return {"success": False, "ticket_id": ticket_id,
                "message": "Webhook 后端不支持状态查询，请传入工单系统链接"}

    def test_connection(self) -> Dict[str, Any]:
        """测试当前配置后端的连通性。"""
        backend = (self.config.get("type") or "webhook").lower()
        try:
            if backend == "jira":
                j = self._jira_creds()
                url = f"{j.get('base_url','').rstrip('/')}/rest/api/2/myself"
                resp = requests.get(
                    url, headers=self._headers(j.get("api_token", "")),
                    auth=(j.get("username", ""), j.get("api_token", "")) if j.get("username") else None,
                    timeout=self._timeout())
                return {"success": resp.ok, "message": f"Jira 返回 HTTP {resp.status_code}"}
            if backend == "zentao":
                z = self._zentao_creds()
                url = f"{z.get('base_url','').rstrip('/')}/api/v1/tokens"
                resp = requests.get(url, headers=self._headers(z.get("token", "")),
                                    timeout=self._timeout())
                return {"success": resp.ok, "message": f"禅道返回 HTTP {resp.status_code}"}
            if backend == "feishu":
                f = self.config.get("feishu", {})
                if not f.get("app_id"):
                    return {"success": False, "message": "飞书 app_id 未配置"}
                return {"success": True,
                        "message": "飞书应用配置已加载（未实际请求 open-api）"}
            w = self.config.get("webhook", {})
            if not w.get("url"):
                return {"success": False, "message": "Webhook URL 未配置"}
            resp = requests.post(w["url"], json={"event": "connection_test"},
                                timeout=self._timeout())
            return {"success": resp.ok, "message": f"Webhook 返回 HTTP {resp.status_code}"}
        except Exception as e:
            return {"success": False, "message": f"连接测试失败: {e}"}


# 模块级单例
ticket_connector = TicketConnector()
