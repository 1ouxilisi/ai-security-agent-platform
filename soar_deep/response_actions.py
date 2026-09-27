#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
soar_deep/response_actions.py — 深度响应动作库。

覆盖 6 大类响应动作：
    1. 网络响应动作：IP封禁/域名封禁/URL封禁/端口封禁/流量阻断/流量镜像/流量限速/路由黑洞
    2. 终端响应动作：进程终止/文件隔离/文件删除/注册表修改/服务停止/账户锁定/磁盘加密/系统重启
    3. 账户响应动作：密码重置/账户锁定/账户禁用/权限撤销/会话终止/MFA强制/登录位置限制
    4. 云响应动作：安全组修改/网络ACL/路由表修改/快照创建/实例隔离/存储加密/权限策略修改
    5. 应用响应动作：WAF规则更新/API限流/用户封禁/功能禁用/数据回滚/配置回滚/紧急补丁
    6. 通知协作动作：邮件/短信/电话/即时消息/工单创建/会议创建/文档共享/审批流程

全部 dry-run 模拟执行，记录执行历史与审计日志。
"""

from __future__ import annotations

import time
import uuid
from typing import Any, Dict, List, Optional


# --------------------------------------------------------------------------- #
# 动作定义注册表
# --------------------------------------------------------------------------- #
ACTION_REGISTRY: Dict[str, Dict[str, Any]] = {}


def _reg(action_id: str, category: str, name: str,
         description: str, params: List[Dict[str, str]],
         risk_level: str = "medium") -> None:
    ACTION_REGISTRY[action_id] = {
        "action_id": action_id,
        "category": category,
        "name": name,
        "description": description,
        "params": params,
        "risk_level": risk_level,
    }


# ---- 1. 网络响应动作 ----
_reg("network.block_ip", "network", "IP封禁",
     "在防火墙/边界设备封禁指定IP地址",
     [{"name": "ip", "type": "string", "required": True, "desc": "目标IP地址"},
      {"name": "duration", "type": "int", "required": False, "desc": "封禁时长(秒)，0=永久"}],
     risk_level="high")
_reg("network.unblock_ip", "network", "IP解封",
     "解除已封禁的IP地址",
     [{"name": "ip", "type": "string", "required": True, "desc": "目标IP地址"}],
     risk_level="low")
_reg("network.block_domain", "network", "域名封禁",
     "在DNS层封禁指定恶意域名",
     [{"name": "domain", "type": "string", "required": True, "desc": "恶意域名"}],
     risk_level="high")
_reg("network.block_url", "network", "URL封禁",
     "在代理/WAF层封禁指定URL",
     [{"name": "url", "type": "string", "required": True, "desc": "恶意URL"},
      {"name": "method", "type": "string", "required": False, "desc": "HTTP方法"}],
     risk_level="high")
_reg("network.block_port", "network", "端口封禁",
     "在防火墙封禁指定端口",
     [{"name": "port", "type": "int", "required": True, "desc": "端口号"},
      {"name": "protocol", "type": "string", "required": False, "desc": "tcp/udp/all"}],
     risk_level="high")
_reg("network.traffic_block", "network", "流量阻断",
     "阻断指定五元组的全部流量",
     [{"name": "src_ip", "type": "string", "required": True, "desc": "源IP"},
      {"name": "dst_ip", "type": "string", "required": True, "desc": "目的IP"},
      {"name": "dst_port", "type": "int", "required": True, "desc": "目的端口"}],
     risk_level="critical")
_reg("network.traffic_mirror", "network", "流量镜像",
     "将可疑流量镜像到分析平台",
     [{"name": "filter", "type": "string", "required": True, "desc": "BPF过滤表达式"},
      {"name": "mirror_port", "type": "int", "required": True, "desc": "镜像目标端口"}],
     risk_level="medium")
_reg("network.traffic_shaping", "network", "流量限速",
     "对指定源IP进行流量限速",
     [{"name": "ip", "type": "string", "required": True, "desc": "源IP"},
      {"name": "rate_kbps", "type": "int", "required": True, "desc": "限速值(kbps)"}],
     risk_level="medium")
_reg("network.route_blackhole", "network", "路由黑洞",
     "将指定前缀路由到黑洞路由",
     [{"name": "prefix", "type": "string", "required": True, "desc": "目标CIDR前缀"}],
     risk_level="critical")

# ---- 2. 终端响应动作 ----
_reg("endpoint.kill_process", "endpoint", "进程终止",
     "在终端上终止指定进程",
     [{"name": "host", "type": "string", "required": True, "desc": "目标主机"},
      {"name": "pid", "type": "int", "required": False, "desc": "进程ID"},
      {"name": "process_name", "type": "string", "required": False, "desc": "进程名"}],
     risk_level="high")
_reg("endpoint.quarantine_file", "endpoint", "文件隔离",
     "将可疑文件移动到隔离区",
     [{"name": "host", "type": "string", "required": True, "desc": "目标主机"},
      {"name": "file_path", "type": "string", "required": True, "desc": "文件路径"},
      {"name": "hash", "type": "string", "required": False, "desc": "文件SHA256"}],
     risk_level="high")
_reg("endpoint.delete_file", "endpoint", "文件删除",
     "删除恶意文件",
     [{"name": "host", "type": "string", "required": True, "desc": "目标主机"},
      {"name": "file_path", "type": "string", "required": True, "desc": "文件路径"}],
     risk_level="critical")
_reg("endpoint.modify_registry", "endpoint", "注册表修改",
     "修改Windows注册表项",
     [{"name": "host", "type": "string", "required": True, "desc": "目标主机"},
      {"name": "reg_path", "type": "string", "required": True, "desc": "注册表路径"},
      {"name": "value", "type": "string", "required": True, "desc": "设置值"}],
     risk_level="high")
_reg("endpoint.stop_service", "endpoint", "服务停止",
     "停止Windows/Linux服务",
     [{"name": "host", "type": "string", "required": True, "desc": "目标主机"},
      {"name": "service_name", "type": "string", "required": True, "desc": "服务名"}],
     risk_level="high")
_reg("endpoint.lock_account", "endpoint", "本地账户锁定",
     "锁定终端本地账户",
     [{"name": "host", "type": "string", "required": True, "desc": "目标主机"},
      {"name": "username", "type": "string", "required": True, "desc": "用户名"}],
     risk_level="high")
_reg("endpoint.encrypt_disk", "endpoint", "磁盘加密",
     "对受影响磁盘启用加密",
     [{"name": "host", "type": "string", "required": True, "desc": "目标主机"},
      {"name": "disk", "type": "string", "required": True, "desc": "磁盘标识符"}],
     risk_level="critical")
_reg("endpoint.reboot", "endpoint", "系统重启",
     "重启目标终端",
     [{"name": "host", "type": "string", "required": True, "desc": "目标主机"},
      {"name": "delay", "type": "int", "required": False, "desc": "延时(秒)"}],
     risk_level="critical")

# ---- 3. 账户响应动作 ----
_reg("account.reset_password", "account", "密码重置",
     "强制重置用户密码",
     [{"name": "username", "type": "string", "required": True, "desc": "目标用户"},
      {"name": "notify", "type": "bool", "required": False, "desc": "是否通知用户"}],
     risk_level="high")
_reg("account.lock", "account", "账户锁定",
     "锁定AD/本地账户",
     [{"name": "username", "type": "string", "required": True, "desc": "目标用户"},
      {"name": "duration", "type": "int", "required": False, "desc": "锁定时长(秒)"}],
     risk_level="high")
_reg("account.disable", "account", "账户禁用",
     "禁用账户（永久）",
     [{"name": "username", "type": "string", "required": True, "desc": "目标用户"}],
     risk_level="critical")
_reg("account.revoke_permission", "account", "权限撤销",
     "撤销用户的指定权限/角色",
     [{"name": "username", "type": "string", "required": True, "desc": "目标用户"},
      {"name": "role", "type": "string", "required": True, "desc": "角色/权限名"}],
     risk_level="high")
_reg("account.terminate_session", "account", "会话终止",
     "终止用户所有活跃会话",
     [{"name": "username", "type": "string", "required": True, "desc": "目标用户"}],
     risk_level="high")
_reg("account.force_mfa", "account", "MFA强制启用",
     "强制用户启用多因素认证",
     [{"name": "username", "type": "string", "required": True, "desc": "目标用户"}],
     risk_level="medium")
_reg("account.restrict_login_location", "account", "登录位置限制",
     "限制用户仅能从指定IP段登录",
     [{"name": "username", "type": "string", "required": True, "desc": "目标用户"},
      {"name": "allowed_cidrs", "type": "list", "required": True, "desc": "允许的CIDR列表"}],
     risk_level="high")

# ---- 4. 云响应动作 ----
_reg("cloud.modify_security_group", "cloud", "安全组修改",
     "修改云安全组规则",
     [{"name": "sg_id", "type": "string", "required": True, "desc": "安全组ID"},
      {"name": "action", "type": "string", "required": True, "desc": "add/remove"},
      {"name": "rule", "type": "object", "required": True, "desc": "规则定义"}],
     risk_level="high")
_reg("cloud.modify_network_acl", "cloud", "网络ACL修改",
     "修改子网网络ACL",
     [{"name": "acl_id", "type": "string", "required": True, "desc": "ACL ID"},
      {"name": "rule", "type": "object", "required": True, "desc": "规则定义"}],
     risk_level="high")
_reg("cloud.modify_route_table", "cloud", "路由表修改",
     "修改VPC路由表",
     [{"name": "rt_id", "type": "string", "required": True, "desc": "路由表ID"},
      {"name": "destination", "type": "string", "required": True, "desc": "目标网段"},
      {"name": "target", "type": "string", "required": True, "desc": "下一跳"}],
     risk_level="critical")
_reg("cloud.create_snapshot", "cloud", "快照创建",
     "创建磁盘/数据库快照用于取证",
     [{"name": "resource_id", "type": "string", "required": True, "desc": "资源ID"},
      {"name": "snapshot_name", "type": "string", "required": True, "desc": "快照名"}],
     risk_level="medium")
_reg("cloud.isolate_instance", "cloud", "实例隔离",
     "将云实例隔离到隔离VPC",
     [{"name": "instance_id", "type": "string", "required": True, "desc": "实例ID"}],
     risk_level="critical")
_reg("cloud.encrypt_storage", "cloud", "存储加密",
     "启用存储加密",
     [{"name": "storage_id", "type": "string", "required": True, "desc": "存储ID"},
      {"name": "kms_key", "type": "string", "required": False, "desc": "KMS密钥ID"}],
     risk_level="high")
_reg("cloud.modify_policy", "cloud", "权限策略修改",
     "修改IAM权限策略",
     [{"name": "policy_arn", "type": "string", "required": True, "desc": "策略ARN"},
      {"name": "statement", "type": "object", "required": True, "desc": "策略语句"}],
     risk_level="critical")

# ---- 5. 应用响应动作 ----
_reg("app.waf_update", "application", "WAF规则更新",
     "在WAF上添加/更新防护规则",
     [{"name": "rule_name", "type": "string", "required": True, "desc": "规则名"},
      {"name": "pattern", "type": "string", "required": True, "desc": "匹配模式"},
      {"name": "action", "type": "string", "required": True, "desc": "block/challenge"}],
     risk_level="high")
_reg("app.api_rate_limit", "application", "API限流",
     "对API端点配置限流策略",
     [{"name": "endpoint", "type": "string", "required": True, "desc": "API路径"},
      {"name": "rpm", "type": "int", "required": True, "desc": "每分钟请求数"}],
     risk_level="medium")
_reg("app.ban_user", "application", "用户封禁",
     "封禁应用用户",
     [{"name": "user_id", "type": "string", "required": True, "desc": "用户ID"},
      {"name": "duration", "type": "int", "required": False, "desc": "封禁时长"}],
     risk_level="high")
_reg("app.disable_feature", "application", "功能禁用",
     "禁用应用特定功能模块",
     [{"name": "feature", "type": "string", "required": True, "desc": "功能标识"}],
     risk_level="high")
_reg("app.data_rollback", "application", "数据回滚",
     "将应用数据回滚到快照",
     [{"name": "snapshot_id", "type": "string", "required": True, "desc": "快照ID"}],
     risk_level="critical")
_reg("app.config_rollback", "application", "配置回滚",
     "回滚应用配置到上一版本",
     [{"name": "app_name", "type": "string", "required": True, "desc": "应用名"}],
     risk_level="high")
_reg("app.emergency_patch", "application", "紧急补丁",
     "紧急部署安全补丁",
     [{"name": "app_name", "type": "string", "required": True, "desc": "应用名"},
      {"name": "patch_id", "type": "string", "required": True, "desc": "补丁ID"}],
     risk_level="critical")

# ---- 6. 通知协作动作 ----
_reg("notify.email", "notification", "邮件通知",
     "发送邮件通知",
     [{"name": "to", "type": "list", "required": True, "desc": "收件人列表"},
      {"name": "subject", "type": "string", "required": True, "desc": "主题"},
      {"name": "body", "type": "string", "required": True, "desc": "正文"}],
     risk_level="low")
_reg("notify.sms", "notification", "短信通知",
     "发送短信通知",
     [{"name": "phone", "type": "string", "required": True, "desc": "手机号"},
      {"name": "message", "type": "string", "required": True, "desc": "短信内容"}],
     risk_level="low")
_reg("notify.phone", "notification", "电话通知",
     "自动语音电话通知",
     [{"name": "phone", "type": "string", "required": True, "desc": "手机号"},
      {"name": "script", "type": "string", "required": True, "desc": "语音脚本"}],
     risk_level="medium")
_reg("notify.im", "notification", "即时消息通知",
     "发送IM消息（Slack/钉钉/企业微信）",
     [{"name": "channel", "type": "string", "required": True, "desc": "渠道"},
      {"name": "text", "type": "string", "required": True, "desc": "消息内容"}],
     risk_level="low")
_reg("notify.create_ticket", "notification", "工单创建",
     "在ITSM系统创建工单",
     [{"name": "title", "type": "string", "required": True, "desc": "工单标题"},
      {"name": "priority", "type": "string", "required": True, "desc": "优先级"},
      {"name": "assignee", "type": "string", "required": False, "desc": "处理人"}],
     risk_level="low")
_reg("notify.create_meeting", "notification", "会议创建",
     "自动创建应急响应会议",
     [{"name": "topic", "type": "string", "required": True, "desc": "会议主题"},
      {"name": "attendees", "type": "list", "required": True, "desc": "参会人列表"}],
     risk_level="low")
_reg("notify.share_doc", "notification", "文档共享",
     "共享事件文档给相关人员",
     [{"name": "doc_url", "type": "string", "required": True, "desc": "文档链接"},
      {"name": "recipients", "type": "list", "required": True, "desc": "接收人"}],
     risk_level="low")
_reg("notify.start_approval", "notification", "审批流程",
     "启动多级审批流程",
     [{"name": "title", "type": "string", "required": True, "desc": "审批标题"},
      {"name": "approvers", "type": "list", "required": True, "desc": "审批人列表"},
      {"name": "timeout", "type": "int", "required": False, "desc": "超时(秒)"}],
     risk_level="medium")


# 动作分类
ACTION_CATEGORIES: Dict[str, Dict[str, Any]] = {
    "network":      {"name": "网络响应", "icon": "🌐", "desc": "防火墙/WAF/DNS/路由层动作"},
    "endpoint":     {"name": "终端响应", "icon": "💻", "desc": "EDR/主机层动作"},
    "account":      {"name": "账户响应", "icon": "👤", "desc": "AD/IAM/身份层动作"},
    "cloud":        {"name": "云响应", "icon": "☁", "desc": "AWS/Azure/阿里云层动作"},
    "application":  {"name": "应用响应", "icon": "📱", "desc": "应用/WAF/数据层动作"},
    "notification": {"name": "通知协作", "icon": "📢", "desc": "通知/工单/审批动作"},
}


# --------------------------------------------------------------------------- #
# 动作执行器
# --------------------------------------------------------------------------- #
class ActionExecutor:
    """响应动作执行器（全部 dry-run 模拟）。"""

    def __init__(self) -> None:
        self.history: List[Dict[str, Any]] = []
        self.executed_count = 0
        self.failed_count = 0

    def execute(self, action_id: str, params: Optional[Dict[str, Any]] = None,
                operator: str = "soar-bot", dry_run: bool = True) -> Dict[str, Any]:
        """执行单个动作（模拟）。"""
        params = params or {}
        definition = ACTION_REGISTRY.get(action_id)
        exec_id = f"act_{uuid.uuid4().hex[:12]}"
        timestamp = time.strftime("%Y-%m-%d %H:%M:%S")

        result: Dict[str, Any] = {
            "execution_id": exec_id,
            "action_id": action_id,
            "action_name": definition["name"] if definition else action_id,
            "category": definition["category"] if definition else "unknown",
            "risk_level": definition["risk_level"] if definition else "medium",
            "params": params,
            "operator": operator,
            "dry_run": dry_run,
            "executed_at": timestamp,
            "status": "success",
            "message": "",
        }

        if not definition:
            result["status"] = "error"
            result["message"] = f"动作 {action_id} 未注册"
            self.failed_count += 1
        else:
            # 验证必填参数
            missing = []
            for p in definition["params"]:
                if p.get("required") and p["name"] not in params:
                    missing.append(p["name"])
            if missing:
                result["status"] = "error"
                result["message"] = f"缺少必填参数: {', '.join(missing)}"
                self.failed_count += 1
            else:
                if dry_run:
                    result["message"] = f"[DRY-RUN] 模拟执行: {definition['name']} -> {params}"
                else:
                    result["message"] = f"[SIMULATED] {definition['name']} 执行成功(模拟)"
                self.executed_count += 1

        self.history.append(result)
        return result

    def batch_execute(self, actions: List[Dict[str, Any]],
                      operator: str = "soar-bot",
                      dry_run: bool = True) -> List[Dict[str, Any]]:
        """批量执行动作。"""
        results = []
        for a in actions:
            r = self.execute(
                action_id=a.get("action_id", ""),
                params=a.get("params", {}),
                operator=operator,
                dry_run=dry_run,
            )
            results.append(r)
        return results

    def list_actions(self, category: Optional[str] = None) -> List[Dict[str, Any]]:
        items = list(ACTION_REGISTRY.values())
        if category:
            items = [a for a in items if a["category"] == category]
        return items

    def get_action(self, action_id: str) -> Optional[Dict[str, Any]]:
        return ACTION_REGISTRY.get(action_id)

    def list_categories(self) -> Dict[str, Dict[str, Any]]:
        return ACTION_CATEGORIES

    def get_history(self, limit: int = 50,
                    status: Optional[str] = None) -> List[Dict[str, Any]]:
        items = list(reversed(self.history))
        if status:
            items = [h for h in items if h["status"] == status]
        return items[:limit]

    def stats(self) -> Dict[str, Any]:
        by_cat: Dict[str, int] = {}
        for h in self.history:
            by_cat[h["category"]] = by_cat.get(h["category"], 0) + 1
        return {
            "total_actions_defined": len(ACTION_REGISTRY),
            "total_categories": len(ACTION_CATEGORIES),
            "total_executed": self.executed_count,
            "total_failed": self.failed_count,
            "success_rate": round(self.executed_count / max(1, self.executed_count + self.failed_count) * 100, 1),
            "by_category": by_cat,
        }


# --------------------------------------------------------------------------- #
# 单例
# --------------------------------------------------------------------------- #
_executor: Optional[ActionExecutor] = None


def get_action_executor() -> ActionExecutor:
    global _executor
    if _executor is None:
        _executor = ActionExecutor()
    return _executor
