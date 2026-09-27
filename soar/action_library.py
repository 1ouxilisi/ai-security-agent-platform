#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
soar/action_library.py — SOAR 响应动作库（100+ 响应动作）。

覆盖动作分类：
    - 主机隔离/网络控制：隔离主机、封禁 IP、防火墙联动、EDR 联动、端口封禁
    - 账户与身份：禁用账户、启用账户、重置密码、强制登出、MFA 重置、锁定账户
    - 取证与证据：收集内存、收集磁盘镜像、进程转储、网络包捕获、注册表导出、文件哈希
    - 工单与通知：创建工单、更新工单、邮件通知、IM 通知、短信通知、Webhook 通知
    - 扫描与检测：启动漏洞扫描、启动恶意软件扫描、沙箱分析、威胁情报查询、IOC 匹配
    - 邮件与内容：隔离邮件、撤销邮件、附件隔离、内容打捞
    - 云与容器：禁用云实例、隔离容器、撤销访问密钥、安全组变更
    - 数据库与应用：封禁数据库会话、撤销 API Key、禁用服务账号
    - 反制与欺骗：部署蜜标、重定向流量、诱饵文件下发

设计定位：仅为编排/管理视角的动作定义与模拟执行器，
所有 execute_* 均为 dry-run 模拟，不实际操作任何生产系统。
"""

from __future__ import annotations

import hashlib
import time
import uuid
from typing import Any, Dict, List, Optional


# --------------------------------------------------------------------------- #
# 动作分类
# --------------------------------------------------------------------------- #
ACTION_CATEGORIES: Dict[str, Dict[str, Any]] = {
    "host_isolation": {"name": "主机与网络控制", "icon": "🖥", "color": "#ff4d4f"},
    "identity":       {"name": "账户与身份治理", "icon": "🪪", "color": "#1890ff"},
    "forensics":      {"name": "取证与证据收集", "icon": "🔬", "color": "#722ed1"},
    "ticket":         {"name": "工单与流程", "icon": "🎫", "color": "#13c2c2"},
    "notification":   {"name": "通知与协作", "icon": "📣", "color": "#fa8c16"},
    "scan_detect":    {"name": "扫描与威胁检测", "icon": "🔍", "color": "#52c41a"},
    "email":          {"name": "邮件与内容处置", "icon": "✉", "color": "#eb2f96"},
    "cloud":          {"name": "云与容器处置", "icon": "☁", "color": "#2f54eb"},
    "database_app":   {"name": "数据库与应用处置", "icon": "🗄", "color": "#a0d911"},
    "counter":        {"name": "反制与欺骗", "icon": "🎭", "color": "#f5222d"},
}


# --------------------------------------------------------------------------- #
# 动作注册表：100+ 动作定义
# 每个动作: id, name, category, description, params(list), risk(低/中/高),
#          requires_approval(bool), platforms(list), revertible(bool)
# --------------------------------------------------------------------------- #
def _a(aid: str, name: str, cat: str, desc: str, params: List[str],
       risk: str = "低", approval: bool = False,
       platforms: Optional[List[str]] = None, revert: bool = True) -> Dict[str, Any]:
    return {
        "action_id": aid, "name": name, "category": cat, "description": desc,
        "params": params, "risk": risk, "requires_approval": approval,
        "platforms": platforms or ["edr", "firewall", "iam", "ticketing"],
        "revertible": revert,
    }


ACTION_LIBRARY: List[Dict[str, Any]] = [
    # ---- 主机与网络控制 (host_isolation) ----
    _a("host.isolate", "隔离主机", "host_isolation", "通过 EDR/NAC 将主机从生产网络隔离到 VLAN 隔离区",
       ["host_id", "isolate_vlan", "duration"], "高", True, ["edr", "nac"]),
    _a("host.release", "解除主机隔离", "host_isolation", "将主机从隔离区恢复到生产网络",
       ["host_id"], "中", True, ["edr", "nac"]),
    _a("host.shutdown", "强制关机", "host_isolation", "对失陷主机下发强制关机指令",
       ["host_id", "reason"], "高", True, ["edr"]),
    _a("host.reboot", "远程重启", "host_isolation", "远程重启目标主机",
       ["host_id"], "中", False, ["edr"]),
    _a("host.process_kill", "终止恶意进程", "host_isolation", "按 PID/进程名终止恶意进程",
       ["host_id", "pid", "process_name"], "中", False, ["edr"]),
    _a("host.service_stop", "停止恶意服务", "host_isolation", "停止并禁用指定服务",
       ["host_id", "service_name"], "中", False, ["edr"]),
    _a("host.quarantine_file", "隔离恶意文件", "host_isolation", "将可疑文件移动到隔离区并加锁",
       ["host_id", "file_path", "sha256"], "中", False, ["edr"]),
    _a("host.usb_block", "阻断 USB 外设", "host_isolation", "禁用目标主机 USB 存储设备",
       ["host_id"], "中", False, ["edr"]),
    _a("network.block_ip", "封禁 IP 地址", "host_isolation", "在防火墙/IPS 上封禁源/目的 IP",
       ["ip", "direction", "duration", "comment"], "高", True, ["firewall", "ips"]),
    _a("network.unblock_ip", "解除 IP 封禁", "host_isolation", "移除防火墙 IP 封禁规则",
       ["ip"], "低", False, ["firewall"]),
    _a("network.block_domain", "封禁域名", "host_isolation", "在 DNS/代理层封禁恶意域名",
       ["domain", "duration"], "中", False, ["dns", "proxy"]),
    _a("network.block_url", "封禁 URL", "host_isolation", "在 Web 代理层封禁指定 URL",
       ["url"], "中", False, ["proxy"]),
    _a("network.block_port", "封禁端口", "host_isolation", "在边界防火墙封禁端口",
       ["port", "protocol", "direction"], "中", True, ["firewall"]),
    _a("network.blacklist_hash", "黑名单文件哈希", "host_isolation", "将文件哈希加入威胁情报黑名单",
       ["sha256", "source"], "低", False, ["ti", "edr"]),
    _a("network.threat_feed_push", "推送威胁情报到防火墙", "host_isolation", "将 IOC 批量下发到防火墙情报订阅",
       ["ioc_list"], "中", False, ["firewall", "ti"]),
    _a("network.sinkhole", "流量黑洞重定向", "host_isolation", "将 C2 流量重定向到 sinkhole",
       ["c2_domain", "c2_ip"], "高", True, ["dns", "firewall"]),

    # ---- 账户与身份 (identity) ----
    _a("user.disable", "禁用账户", "identity", "在 IAM/AD 中禁用用户账户",
       ["username", "reason"], "高", True, ["iam", "ad"]),
    _a("user.enable", "启用账户", "identity", "重新启用已禁用账户",
       ["username"], "低", False, ["iam", "ad"]),
    _a("user.lock", "锁定账户", "identity", "因暴力破解风险临时锁定账户",
       ["username", "duration"], "中", False, ["iam", "ad"]),
    _a("user.unlock", "解锁账户", "identity", "解除账户锁定状态",
       ["username"], "低", False, ["iam"]),
    _a("user.reset_password", "重置密码", "identity", "为账户生成随机强密码并通知用户",
       ["username", "notify_user"], "高", True, ["iam"]),
    _a("user.force_logout", "强制登出会话", "identity", "吊销用户所有活动会话与 Token",
       ["username"], "中", False, ["iam", "sso"]),
    _a("user.revoke_token", "吊销访问令牌", "identity", "吊销 API/OAuth 访问令牌",
       ["token_id", "user_id"], "中", False, ["iam", "sso"]),
    _a("user.mfa_reset", "重置 MFA", "identity", "重置用户多因子认证设备",
       ["username"], "中", True, ["iam"]),
    _a("user.group_remove", "移出敏感用户组", "identity", "将用户从管理员/特权组移出",
       ["username", "group_name"], "高", True, ["ad", "iam"]),
    _a("user.group_add", "加入应急响应组", "identity", "将用户加入应急响应权限组",
       ["username", "group_name"], "中", False, ["ad"]),
    _a("service_account.disable", "禁用服务账户", "identity", "停用可疑服务账户",
       ["svc_account"], "高", True, ["iam", "cloud"]),
    _a("user.risk_score", "更新用户风险评分", "identity", "基于行为信号更新 UEBA 风险评分",
       ["username", "signals"], "低", False, ["ueba"]),
    _a("user.vpn_revoke", "吊销 VPN 权限", "identity", "撤销用户 VPN 接入权限",
       ["username"], "中", False, ["vpn", "iam"]),

    # ---- 取证与证据 (forensics) ----
    _a("evidence.collect_memory", "收集内存镜像", "forensics", "对目标主机生成内存快照并上传取证服务器",
       ["host_id", "memory_dump"], "中", False, ["edr", "forensics"], False),
    _a("evidence.collect_disk", "收集磁盘镜像", "forensics", "对目标卷做取证级磁盘镜像",
       ["host_id", "volume", "hash_verify"], "高", True, ["edr", "forensics"], False),
    _a("evidence.collect_process", "进程快照采集", "forensics", "采集进程/线程/模块树快照",
       ["host_id"], "低", False, ["edr"], False),
    _a("evidence.collect_network", "网络连接快照", "forensics", "采集当前 TCP/UDP 连接与监听端口",
       ["host_id"], "低", False, ["edr"], False),
    _a("evidence.pcap_capture", "网络包捕获", "forensics", "在镜像端口抓包并保存 pcap",
       ["host_id", "duration", "filter"], "中", False, ["network", "forensics"], False),
    _a("evidence.registry_export", "注册表导出", "forensics", "导出可疑注册表 hive",
       ["host_id", "reg_path"], "低", False, ["edr"], False),
    _a("evidence.prefetch_collect", "Prefetch/预读取收集", "forensics", "收集执行痕迹文件",
       ["host_id"], "低", False, ["edr"], False),
    _a("evidence.powershell_log", "PowerShell 日志导出", "forensics", "导出 4104 等脚本块日志",
       ["host_id", "time_window"], "低", False, ["edr"], False),
    _a("evidence.file_hash", "计算文件哈希", "forensics", "对可疑文件计算 MD5/SHA256",
       ["file_path"], "低", False, ["edr"], False),
    _a("evidence.upload", "证据上传", "forensics", "将取证文件上传到证据管理系统并哈希校验",
       ["artifact_id", "path"], "低", False, ["forensics"], False),
    _a("evidence.chain_of_custody", "生成证据链记录", "forensics", "登记证据保管链 (chain of custody)",
       ["artifact_id", "collector"], "低", False, ["forensics"], False),

    # ---- 工单与流程 (ticket) ----
    _a("ticket.create", "创建工单", "ticket", "在 ITSM 中创建应急响应工单",
       ["title", "severity", "assignee", "description"], "低", False, ["itsm"]),
    _a("ticket.update", "更新工单状态", "ticket", "更新工单字段/状态/备注",
       ["ticket_id", "fields"], "低", False, ["itsm"]),
    _a("ticket.assign", "分配工单", "ticket", "将工单分配给分析师或群组",
       ["ticket_id", "assignee"], "低", False, ["itsm"]),
    _a("ticket.priority", "调整工单优先级", "ticket", "调整工单 SLA 优先级",
       ["ticket_id", "priority"], "低", False, ["itsm"]),
    _a("ticket.link_alert", "关联告警", "ticket", "将工单与告警/事件关联",
       ["ticket_id", "alert_id"], "低", False, ["itsm", "soc"]),
    _a("ticket.close", "关闭工单", "ticket", "以解决状态关闭工单",
       ["ticket_id", "resolution"], "低", False, ["itsm"]),
    _a("ticket.sla_escalate", "SLA 升级", "ticket", "SLA 临近/超时时升级到二线",
       ["ticket_id", "escalation_level"], "中", False, ["itsm"]),
    _a("ticket.create_change", "创建变更单", "ticket", "针对处置动作创建 CAB 变更单",
       ["change_type", "risk", "plan"], "中", True, ["itsm", "change"]),

    # ---- 通知与协作 (notification) ----
    _a("notify.email", "发送邮件通知", "notification", "向相关人发送结构化告警邮件",
       ["to", "subject", "body", "severity"], "低", False, ["email"]),
    _a("notify.im", "发送 IM 通知", "notification", "向企业微信/钉钉/Slack 群推送",
       ["channel", "text", "mention"], "低", False, ["im"]),
    _a("notify.sms", "发送短信通知", "notification", "向值班人员发送短信告警",
       ["phone", "text"], "低", False, ["sms"]),
    _a("notify.webhook", "触发 Webhook", "notification", "向外部系统推送 JSON 事件",
       ["url", "payload", "headers"], "低", False, ["webhook"]),
    _a("notify.callout", "电话语音呼叫", "notification", "对值班经理发起电话呼叫升级",
       ["phone", "script"], "中", True, ["voice"]),
    _a("notify.dashboard_pin", "仪表盘置顶事件", "notification", "将事件置顶到 SOC 大屏",
       ["incident_id"], "低", False, ["dashboard"]),
    _a("notify.briefing", "生成早报摘要", "notification", "生成并发送每日安全简报",
       ["recipients", "window"], "低", False, ["report"]),

    # ---- 扫描与威胁检测 (scan_detect) ----
    _a("scan.vuln", "启动漏洞扫描", "scan_detect", "对受影响资产启动漏洞扫描",
       ["targets", "scan_profile"], "中", False, ["scanner"]),
    _a("scan.antivirus", "启动杀毒全盘扫描", "scan_detect", "在失陷主机触发全盘查杀",
       ["host_id", "quick"], "低", False, ["edr", "av"]),
    _a("scan.sandbox", "提交沙箱分析", "scan_detect", "将可疑样本提交沙箱动态分析",
       ["sample_ref", "timeout"], "低", False, ["sandbox"]),
    _a("scan.malware_ioc", "IOC 全网络检索", "scan_detect", "用 IOC 在全网日志中检索",
       ["ioc_type", "ioc_value", "time_window"], "低", False, ["siem"]),
    _a("ti.lookup_ip", "查询 IP 威胁情报", "scan_detect", "富化 IP 归属/ASN/恶意评分",
       ["ip"], "低", False, ["ti"]),
    _a("ti.lookup_domain", "查询域名情报", "scan_detect", "富化域名注册/DNS/恶意评分",
       ["domain"], "低", False, ["ti"]),
    _a("ti.lookup_hash", "查询文件哈希情报", "scan_detect", "查询沙箱/AV 多引擎检出",
       ["sha256"], "低", False, ["ti", "sandbox"]),
    _a("ti.geoip", "IP 归属地查询", "scan_detect", "查询 IP 地理位置与 ISP",
       ["ip"], "低", False, ["ti"]),
    _a("ti.whois", "域名 Whois 反查", "scan_detect", "查询域名注册信息",
       ["domain"], "低", False, ["ti"]),
    _a("ti.cve_lookup", "查询 CVE 情报", "scan_detect", "查询 CVE 详情与 EXP 可用性",
       ["cve_id"], "低", False, ["ti", "vulndb"]),
    _a("detect.hunting", "启动威胁狩猎", "scan_detect", "基于假设启动狩猎任务",
       ["hypothesis", "query"], "低", False, ["siem", "hunting"]),
    _a("detect.correlate", "运行关联规则", "scan_detect", "触发自定义关联分析规则",
       ["rule_id", "alert_id"], "低", False, ["siem"]),

    # ---- 邮件与内容 (email) ----
    _a("email.quarantine", "隔离邮件", "email", "将钓鱼/恶意邮件从邮箱隔离",
       ["message_id", "mailbox"], "中", False, ["email_security"]),
    _a("email.recall", "撤销已发送邮件", "email", "在邮件系统中撤回已投递邮件",
       ["message_id"], "中", False, ["email_security"]),
    _a("email.fix", "修复并再投递", "email", "清除恶意链接/附件后再投递",
       ["message_id", "safe_url_rewrite"], "低", False, ["email_security"]),
    _a("email.dlp_scan", "邮件 DLP 重扫", "email", "对邮件链路执行 DLP 二次扫描",
       ["message_id"], "低", False, ["dlp", "email_security"]),
    _a("attachment.quarantine", "隔离附件", "email", "将恶意附件单独隔离",
       ["attachment_id"], "低", False, ["email_security"]),
    _a("attachment.sandbox", "附件沙箱分析", "email", "对附件提交沙箱动态执行",
       ["attachment_id"], "低", False, ["sandbox"]),

    # ---- 云与容器 (cloud) ----
    _a("cloud.instance_stop", "停止云实例", "cloud", "停止可疑云主机实例",
       ["instance_id", "cloud_provider"], "高", True, ["cspm"]),
    _a("cloud.instance_isolate", "云实例网络隔离", "cloud", "将实例安全组改为仅取证通道",
       ["instance_id", "forensic_sg"], "高", True, ["cspm"]),
    _a("cloud.keypair_disable", "禁用访问密钥", "cloud", "禁用可疑 AK/SK 访问密钥",
       ["access_key_id"], "高", True, ["cspm", "iam"]),
    _a("cloud.securitygroup_lock", "锁定安全组", "cloud", "将开放 0.0.0.0 安全组改为最小化",
       ["sg_id", "restrict_cidr"], "中", True, ["cspm"]),
    _a("cloud.bucket_private", "对象存储改私有", "cloud", "将公开 Bucket 改为私有",
       ["bucket_name"], "中", False, ["cspm"]),
    _a("cloud.snapshot_create", "创建取证快照", "cloud", "对云盘创建只读取证快照",
       ["volume_id"], "中", False, ["cspm", "forensics"], False),
    _a("container.pause", "暂停恶意容器", "cloud", "pause 异常容器",
       ["namespace", "pod"], "中", False, ["cwpp", "k8s"]),
    _a("container.kill", "终止恶意容器", "cloud", "删除异常 Pod/容器",
       ["namespace", "pod"], "高", True, ["cwpp", "k8s"]),
    _a("container.image_block", "镜像拉黑", "cloud", "将恶意镜像加入仓库黑名单",
       ["image_digest"], "中", False, ["cwpp"]),

    # ---- 数据库与应用 (database_app) ----
    _a("db.kill_session", "终止数据库会话", "database_app", "KILL 可疑数据库连接会话",
       ["db_session_id", "instance"], "中", True, ["db"]),
    _a("db.block_user", "封禁数据库账户", "database_app", "撤销可疑 DB 账户权限",
       ["db_user", "instance"], "高", True, ["db"]),
    _a("app.revoke_api_key", "撤销应用 API Key", "database_app", "吊销泄露/被盗 API Key",
       ["api_key_id"], "高", True, ["api_gw"]),
    _a("app.rotate_secret", "轮换应用密钥", "database_app", "轮换泄露的密钥/Token 并重启服务",
       ["secret_name", "service"], "高", True, ["secrets", "cicd"]),
    _a("app.waf_block", "WAF 封禁", "database_app", "在 WAF 上封禁攻击者 IP/会话",
       ["src_ip", "rule_name"], "中", False, ["waf"]),
    _a("app.waf_challenge", "WAF 人机验证", "database_app", "对可疑流量开启验证码挑战",
       ["src_ip", "uri"], "低", False, ["waf"]),
    _a("app.feature_toggle_off", "关闭受影响功能", "database_app", "通过特性开关关闭受影响功能",
       ["feature_flag"], "中", False, ["feature_flag"]),

    # ---- 反制与欺骗 (counter) ----
    _a("decoy.file_deploy", "下发诱饵文件", "counter", "在蜜标路径部署诱饵文档",
       ["host_id", "decoy_type"], "低", False, ["deception"]),
    _a("decoy.credential_honeypot", "部署蜜罐凭证", "counter", "在主机放置伪造高权限凭证",
       ["host_id"], "中", False, ["deception"]),
    _a("decoy.service_listen", "开启欺骗服务端口", "counter", "在隔离 VLAN 开启蜜罐服务",
       ["port", "service_type"], "低", False, ["deception"]),
    _a("counter.fake_data_leak", "投放虚假数据", "counter", "向攻击者返回伪造数据库记录",
       ["target_profile"], "高", True, ["deception"], False),
    _a("counter.fingerprint", "指纹重定向", "counter", "向攻击者返回虚假系统指纹",
       ["src_ip"], "低", False, ["deception"]),

    # ---- 网络与边界补充 ----
    _a("network.quarantine_session", "隔离网络会话", "host_isolation", "断开主机与 C2 的当前会话",
       ["src_ip", "dst_ip", "dst_port"], "中", False, ["firewall", "edr"]),
    _a("traffic.mirror_start", "启动流量镜像", "host_isolation", "在交换机端口镜像流量到分析口",
       ["switch", "mirror_port", "target_port"], "中", False, ["network"], False),
    _a("network.dns_sinkhole_block", "DNS Sinkhole 封禁", "host_isolation", "在 DNS 层将恶意域名解析到 sinkhole",
       ["domain"], "中", False, ["dns"]),

    # ---- 身份治理补充 ----
    _a("user.privilege_escalation_block", "阻断提权路径", "identity", "临时移除可疑 sudo/sudoers 权限",
       ["username"], "高", True, ["iam"]),
    _a("service_account.rotate", "轮换服务账户密码", "identity", "自动轮换服务账户密码并通知应用",
       ["svc_account"], "高", True, ["iam", "secrets"]),
    _a("user.session_review", "在线会话审查", "identity", "列出用户全部在线会话供审查",
       ["username"], "低", False, ["iam"]),

    # ---- 取证补充 ----
    _a("evidence.mft_collect", "MFT 文件表收集", "forensics", "收集 NTFS MFT 记录",
       ["host_id"], "低", False, ["edr"], False),
    _a("evidence.usn_journal", "USN 日志收集", "forensics", "收集更新序列日志",
       ["host_id"], "低", False, ["edr"], False),
    _a("evidence.wevt_export", "Windows 事件导出", "forensics", "导出 Security/System 事件日志",
       ["host_id", "log_names"], "低", False, ["edr"], False),

    # ---- 通知补充 ----
    _a("notify.opsgenie", "触发值班 on-call", "notification", "在 Opsgenie/PagerDuty 拉起 on-call",
       ["schedule", "severity"], "中", True, ["itsm"]),
    _a("notify.slack_thread", "开启协作线程", "notification", "在指定频道开处置线程",
       ["channel", "incident_id"], "低", False, ["im"]),

    # ---- 扫描补充 ----
    _a("scan.config_audit", "安全配置基线检查", "scan_detect", "对主机跑 CIS 基线检查",
       ["host_id", "profile"], "低", False, ["scanner"]),
    _a("ti.c2_check", "C2 连通性主动探测", "scan_detect", "主动探测可疑 C2 心跳行为",
       ["host_id", "c2_endpoint"], "中", False, ["sandbox"]),

    # ---- 云/容器补充 ----
    _a("cloud.log4shell", "云运行时内存扫描", "cloud", "CWPP 扫描可疑内存反射载荷",
       ["workload_id"], "中", False, ["cwpp"]),
    _a("container.network_policy", "下发 K8s 网络策略", "cloud", "为 Namespace 下发最小化网络策略",
       ["namespace", "policy"], "高", True, ["k8s"]),
]


# --------------------------------------------------------------------------- #
# 执行器（全部为 dry-run 模拟）
# --------------------------------------------------------------------------- #
class ActionExecutor:
    """响应动作执行器：根据 action_id 查找动作定义并模拟执行。"""

    def __init__(self) -> None:
        self.library: Dict[str, Dict[str, Any]] = {a["action_id"]: a for a in ACTION_LIBRARY}
        self.execution_logs: List[Dict[str, Any]] = []

    # ---- 查询 ----
    def list_actions(self, category: Optional[str] = None,
                     risk: Optional[str] = None,
                     keyword: Optional[str] = None) -> List[Dict[str, Any]]:
        out = ACTION_LIBRARY
        if category:
            out = [a for a in out if a["category"] == category]
        if risk:
            out = [a for a in out if a["risk"] == risk]
        if keyword:
            kw = keyword.lower()
            out = [a for a in out if kw in a["name"].lower()
                   or kw in a["description"].lower() or kw in a["action_id"].lower()]
        return out

    def get_action(self, action_id: str) -> Optional[Dict[str, Any]]:
        return self.library.get(action_id)

    def categories(self) -> Dict[str, Dict[str, Any]]:
        return ACTION_CATEGORIES

    def stats(self) -> Dict[str, Any]:
        by_cat: Dict[str, int] = {}
        by_risk: Dict[str, int] = {}
        needs_approval = 0
        for a in ACTION_LIBRARY:
            by_cat[a["category"]] = by_cat.get(a["category"], 0) + 1
            by_risk[a["risk"]] = by_risk.get(a["risk"], 0) + 1
            if a["requires_approval"]:
                needs_approval += 1
        return {
            "total_actions": len(ACTION_LIBRARY),
            "categories": len(ACTION_CATEGORIES),
            "by_category": by_cat, "by_risk": by_risk,
            "needs_approval": needs_approval,
        }

    # ---- 模拟执行 ----
    def execute(self, action_id: str, params: Optional[Dict[str, Any]] = None,
                operator: str = "soar-bot", dry_run: bool = True) -> Dict[str, Any]:
        """模拟执行单个动作。dry_run=True 时只生成执行记录不实际下发。"""
        params = params or {}
        action = self.library.get(action_id)
        if not action:
            return {"success": False, "error": f"未知动作: {action_id}", "execution_id": None}

        exec_id = uuid.uuid4().hex[:12]
        required = action["params"]
        missing = [p for p in required if p not in params and p.split("|")[0] not in params]

        approval_required = action["requires_approval"] and not params.get("approved")
        ts = time.strftime("%Y-%m-%d %H:%M:%S")

        record = {
            "execution_id": exec_id, "action_id": action_id,
            "action_name": action["name"], "category": action["category"],
            "risk": action["risk"], "operator": operator,
            "params_used": {k: v for k, v in params.items() if not k.startswith("_")},
            "missing_params": missing, "dry_run": dry_run,
            "approval_required": approval_required,
            "status": "pending_approval" if approval_required else (
                "failed" if missing else "simulated_success"),
            "started_at": ts, "finished_at": None,
            "message": ("等待人工审批" if approval_required else
                        (f"缺少必要参数: {missing}" if missing else
                         f"[模拟] 已执行 {action['name']}（未实际操作生产系统）")),
        }
        if not approval_required and not missing:
            record["finished_at"] = time.strftime("%Y-%m-%d %H:%M:%S")
            record["artifact"] = self._synthesize_artifact(action, params)
        self.execution_logs.append(record)
        return record

    def approve(self, execution_id: str, approver: str) -> Dict[str, Any]:
        for rec in self.execution_logs:
            if rec["execution_id"] == execution_id and rec["status"] == "pending_approval":
                rec["status"] = "simulated_success"
                rec["approved_by"] = approver
                rec["finished_at"] = time.strftime("%Y-%m-%d %H:%M:%S")
                rec["message"] = f"[模拟] 审批通过并执行: {rec['action_name']}"
                return {"success": True, "record": rec}
        return {"success": False, "error": "未找到待审批执行记录"}

    def history(self, limit: int = 50) -> List[Dict[str, Any]]:
        return list(reversed(self.execution_logs[-limit:]))

    # ---- 内部：合成一个证据/结果产物 ----
    @staticmethod
    def _synthesize_artifact(action: Dict[str, Any], params: Dict[str, Any]) -> Dict[str, Any]:
        seed = f"{action['action_id']}:{sorted(params.items())}"
        digest = hashlib.sha256(seed.encode("utf-8")).hexdigest()[:16]
        return {
            "artifact_id": f"ART-{digest}",
            "hash_sha256": hashlib.sha256(seed.encode()).hexdigest(),
            "size_bytes": 1024 * (7 + len(seed) % 40),
            "note": "该产物为 SOAR 模拟执行生成，仅用于编排流程演示",
        }


_SINGLETON: Optional[ActionExecutor] = None


def get_action_executor() -> ActionExecutor:
    global _SINGLETON
    if _SINGLETON is None:
        _SINGLETON = ActionExecutor()
    return _SINGLETON


if __name__ == "__main__":  # pragma: no cover
    ex = get_action_executor()
    print("动作总数:", ex.stats()["total_actions"])
    print(ex.execute("host.isolate", {"host_id": "PC-001", "isolate_vlan": "QUAR", "duration": "4h"}))
