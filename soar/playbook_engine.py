#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
soar/playbook_engine.py — SOAR 剧本编排引擎。

覆盖：
    - 可视化剧本定义：节点 (start/action/condition/parallel/loop/approval/end)
    - 条件分支、并行执行、循环节点、人工审批节点
    - 50+ 剧本模板库（勒索软件/钓鱼/暴力破解/数据泄露/Web 入侵/内网横向等场景）
    - 版本管理：草稿/发布/版本历史/回滚
    - 剧本测试：dry-run 模拟、节点执行追踪

设计定位：纯内存编排逻辑模拟，不实际下发任何动作。
"""

from __future__ import annotations

import copy
import time
import uuid
from typing import Any, Dict, List, Optional


# --------------------------------------------------------------------------- #
# 节点类型
# --------------------------------------------------------------------------- #
NODE_TYPES: Dict[str, Dict[str, Any]] = {
    "start":     {"name": "开始", "color": "#52c41a", "desc": "剧本入口，接收触发事件"},
    "action":    {"name": "响应动作", "color": "#1890ff", "desc": "调用响应动作库中的动作"},
    "condition": {"name": "条件分支", "color": "#fa8c16", "desc": "基于条件走不同分支"},
    "parallel":  {"name": "并行执行", "color": "#722ed1", "desc": "多个分支同时执行"},
    "loop":      {"name": "循环", "color": "#13c2c2", "desc": "对列表/资产集合循环执行"},
    "approval":  {"name": "人工审批", "color": "#eb2f96", "desc": "等待人工审批后继续"},
    "delay":     {"name": "等待/延时", "color": "#8c8c8c", "desc": "延时 N 秒"},
    "end":       {"name": "结束", "color": "#ff4d4f", "desc": "剧本出口"},
}


# --------------------------------------------------------------------------- #
# 剧本模板库（50+）
# 每个模板: id, name, category, severity, description, nodes(精简), triggers
# --------------------------------------------------------------------------- #
def _t(tid: str, name: str, cat: str, sev: str, desc: str,
       nodes: List[Dict[str, str]], triggers: List[str]) -> Dict[str, Any]:
    return {
        "template_id": tid, "name": name, "category": cat, "severity": sev,
        "description": desc, "steps": nodes, "trigger_conditions": triggers,
    }


PLAYBOOK_TEMPLATES: List[Dict[str, Any]] = [
    # ---- 勒索软件 ----
    _t("rb.quick_isolate", "勒索软件快速隔离剧本", "勒索软件", "critical",
       "检测到勒索行为后自动隔离主机并通知",
       [{"t": "start"}, {"t": "action", "n": "host.isolate"},
        {"t": "action", "n": "evidence.collect_memory"},
        {"t": "approval", "n": "host.shutdown"},
        {"t": "end"}], ["ransomware", "encrypted_file_spike"]),
    _t("rb.containment", "勒索软件横向阻断剧本", "勒索软件", "critical",
       "阻断 SMB/RDP 横向移动并封禁可疑账户",
       [{"t": "start"}, {"t": "action", "n": "network.block_port", "p": "445"},
        {"t": "action", "n": "network.block_port", "p": "3389"},
        {"t": "action", "n": "user.lock"}, {"t": "end"}], ["lateral_movement"]),
    _t("rb.recovery", "勒索软件恢复验证剧本", "勒索软件", "high",
       "从备份恢复前的完整性校验流程",
       [{"t": "start"}, {"t": "action", "n": "evidence.file_hash"},
        {"t": "condition", "n": "backup_clean?"},
        {"t": "action", "n": "host.release"}, {"t": "end"}], ["ransomware_recovery"]),

    # ---- 钓鱼 ----
    _t("phish.quarantine_mail", "钓鱼邮件处置剧本", "钓鱼攻击", "high",
       "隔离钓鱼邮件、回收链接、全邮箱搜索",
       [{"t": "start"}, {"t": "action", "n": "email.quarantine"},
        {"t": "action", "n": "email.recall"},
        {"t": "action", "n": "scan.malware_ioc", "p": "url"},
        {"t": "end"}], ["phishing", "email_attack"]),
    _t("phish.user_click", "用户点击钓鱼链接响应剧本", "钓鱼攻击", "high",
       "已有人点击时重置密码并启用 MFA",
       [{"t": "start"}, {"t": "action", "n": "user.reset_password"},
        {"t": "action", "n": "user.force_logout"},
        {"t": "action", "n": "user.mfa_reset"},
        {"t": "notify", "n": "notify.im"}, {"t": "end"}], ["user_clicked_phish"]),
    _t("phish.campaign", "大规模钓鱼运动狩猎剧本", "钓鱼攻击", "medium",
       "批量检索同发件人/同链接邮件",
       [{"t": "start"}, {"t": "loop", "n": "ioc_list"},
        {"t": "action", "n": "scan.malware_ioc"}, {"t": "end"}], ["phishing_campaign"]),

    # ---- 暴力破解/凭证 ----
    _t("auth.bruteforce", "暴力破解自动响应剧本", "身份认证", "high",
       "封禁源 IP 并锁定账户",
       [{"t": "start"}, {"t": "action", "n": "network.block_ip"},
        {"t": "action", "n": "user.lock"},
        {"t": "notify", "n": "notify.sms"}, {"t": "end"}], ["brute_force", "credential_stuffing"]),
    _t("auth.anomalous_login", "异常登录响应剧本", "身份认证", "medium",
       "异地/异常时段登录要求 MFA 挑战",
       [{"t": "start"}, {"t": "ti", "n": "ti.geoip"},
        {"t": "condition", "n": "impossible_travel?"},
        {"t": "action", "n": "user.force_logout"},
        {"t": "notify", "n": "notify.email"}, {"t": "end"}], ["impossible_travel"]),
    _t("auth.password_spray", "密码喷洒检测响应剧本", "身份认证", "high",
       "检测密码喷洒并临时锁定多个账户",
       [{"t": "start"}, {"t": "loop", "n": "target_users"},
        {"t": "action", "n": "user.lock"}, {"t": "end"}], ["password_spray"]),

    # ---- Web 攻击 ----
    _t("web.sql_injection", "SQL 注入攻击响应剧本", "Web 攻击", "high",
       "WAF 封禁 + 数据库会话排查",
       [{"t": "start"}, {"t": "action", "n": "app.waf_block"},
        {"t": "action", "n": "db.kill_session"},
        {"t": "action", "n": "scan.vuln"}, {"t": "end"}], ["sqli", "web_attack"]),
    _t("web.xss", "XSS 注入响应剧本", "Web 攻击", "medium",
       "封禁攻击源并审查前端发布",
       [{"t": "start"}, {"t": "action", "n": "app.waf_challenge"},
        {"t": "ticket", "n": "ticket.create"}, {"t": "end"}], ["xss"]),
    _t("web.defacement", "网页篡改响应剧本", "Web 攻击", "critical",
       "下线受影响页面并回滚发布",
       [{"t": "start"}, {"t": "approval", "n": "app.feature_toggle_off"},
        {"t": "action", "n": "evidence.collect_file"},
        {"t": "notify", "n": "notify.callout"}, {"t": "end"}], ["defacement"]),
    _t("web.rce", "Web RCE 事件响应剧本", "Web 攻击", "critical",
       "隔离 Web 服务器并启动取证",
       [{"t": "start"}, {"t": "action", "n": "host.isolate"},
        {"t": "action", "n": "evidence.collect_memory"},
        {"t": "action", "n": "evidence.pcap_capture"},
        {"t": "approval", "n": "host.shutdown"}, {"t": "end"}], ["rce"]),

    # ---- 数据泄露 ----
    _t("dlp.exfil", "数据外带响应剧本", "数据泄露", "critical",
       "阻断外带通道并收集证据",
       [{"t": "start"}, {"t": "ti", "n": "ti.lookup_ip"},
        {"t": "action", "n": "network.block_ip"},
        {"t": "action", "n": "user.suspend"},
        {"t": "ticket", "n": "ticket.create"}, {"t": "end"}], ["data_exfiltration"]),
    _t("dlp.sensitive_upload", "敏感数据上传告警剧本", "数据泄露", "high",
       "阻断上传并通知数据所有者",
       [{"t": "start"}, {"t": "action", "n": "network.block_domain"},
        {"t": "notify", "n": "notify.email"},
        {"t": "ticket", "n": "ticket.create"}, {"t": "end"}], ["dlp_violation"]),
    _t("dlp.cred_leak", "凭证泄露在公开库剧本", "数据泄露", "high",
       "轮换密钥并吊销访问",
       [{"t": "start"}, {"t": "action", "n": "app.rotate_secret"},
        {"t": "action", "n": "cloud.keypair_disable"},
        {"t": "notify", "n": "notify.im"}, {"t": "end"}], ["credential_leak"]),

    # ---- 恶意软件 ----
    _t("malware.triage", "恶意软件自动分诊剧本", "恶意软件", "high",
       "哈希情报富化 + 沙箱分析",
       [{"t": "start"}, {"t": "ti", "n": "ti.lookup_hash"},
        {"t": "condition", "n": "known_bad?"},
        {"t": "action", "n": "host.quarantine_file"},
        {"t": "action", "n": "scan.sandbox"}, {"t": "end"}], ["malware_detected"]),
    _t("malware.botnet", "Botnet C2 通信剧本", "恶意软件", "critical",
       "封禁 C2 并隔离主机",
       [{"t": "start"}, {"t": "action", "n": "network.block_domain"},
        {"t": "action", "n": "host.isolate"},
        {"t": "action", "n": "network.sinkhole"}, {"t": "end"}], ["botnet", "c2_beacon"]),
    _t("malware.trojan", "木马持久化检测剧本", "恶意软件", "high",
       "定位持久化项并清理",
       [{"t": "start"}, {"t": "evidence", "n": "evidence.registry_export"},
        {"t": "action", "n": "host.service_stop"},
        {"t": "action", "n": "host.quarantine_file"}, {"t": "end"}], ["persistence"]),

    # ---- 内网横向 ----
    _t("lateral.psexec", "横向移动(psexec)剧本", "横向移动", "critical",
       "阻断管理员共享并锁定账户",
       [{"t": "start"}, {"t": "action", "n": "user.group_remove"},
        {"t": "action", "n": "host.isolate"},
        {"t": "hunt", "n": "detect.hunting"}, {"t": "end"}], ["lateral_movement"]),
    _t("lateral.kerberoast", "Kerberoasting 检测剧本", "横向移动", "high",
       "重置服务账户并启用 AES 加密",
       [{"t": "start"}, {"t": "action", "n": "service_account.reset"},
        {"t": "notify", "n": "notify.im"}, {"t": "end"}], ["kerberoasting"]),
    _t("lateral.dcattack", "域控可疑活动剧本", "横向移动", "critical",
       "保护域控并启动高级狩猎",
       [{"t": "start"}, {"t": "approval", "n": "host.isolate"},
        {"t": "evidence", "n": "evidence.collect_memory"},
        {"t": "callout", "n": "notify.callout"}, {"t": "end"}], ["dc_attack"]),

    # ---- 云与容器 ----
    _t("cloud.rogue_key", "云 AK 泄露剧本", "云安全", "critical",
       "禁用密钥并审计调用",
       [{"t": "start"}, {"t": "action", "n": "cloud.keypair_disable"},
        {"t": "action", "n": "app.rotate_secret"},
        {"t": "ti", "n": "ti.lookup_ip"}, {"t": "end"}], ["cloud_key_leak"]),
    _t("cloud.public_bucket", "公开 Bucket 暴露剧本", "云安全", "medium",
       "自动改为私有并通知",
       [{"t": "start"}, {"t": "action", "n": "cloud.bucket_private"},
        {"t": "notify", "n": "notify.email"}, {"t": "end"}], ["exposed_bucket"]),
    _t("cloud.open_sg", "开放安全组收敛剧本", "云安全", "medium",
       "将 0.0.0.0 安全组收敛",
       [{"t": "start"}, {"t": "approval", "n": "cloud.securitygroup_lock"},
        {"t": "ticket", "n": "ticket.create"}, {"t": "end"}], ["open_security_group"]),
    _t("k8s.pod_attack", "K8s 异常容器剧本", "容器安全", "high",
       "终止异常 Pod 并拉黑镜像",
       [{"t": "start"}, {"t": "action", "n": "container.pause"},
        {"t": "approval", "n": "container.kill"},
        {"t": "action", "n": "container.image_block"}, {"t": "end"}], ["k8s_anomaly"]),

    # ---- 内部滥用 ----
    _t("insider.data_hoard", "内部人员囤积数据剧本", "内部威胁", "high",
       "暂停账户并审查下载行为",
       [{"t": "start"}, {"t": "ueba", "n": "user.risk_score"},
        {"t": "approval", "n": "user.suspend"},
        {"t": "ticket", "n": "ticket.create"}, {"t": "end"}], ["insider_threat"]),
    _t("insider.priv_abuse", "特权滥用剧本", "内部威胁", "high",
       "临时回收特权并发起访谈工单",
       [{"t": "start"}, {"t": "action", "n": "user.group_remove"},
        {"t": "ticket", "n": "ticket.create"}, {"t": "end"}], ["privilege_abuse"]),

    # ---- 合规与误报 ----
    _t("false_positive.review", "误报复核剧本", "误报治理", "low",
       "分析师标记误报并回写规则调优",
       [{"t": "start"}, {"t": "approval", "n": "mark_false_positive"},
        {"t": "action", "n": "ticket.close"}, {"t": "end"}], ["false_positive"]),
    _t("sla.breach", "SLA 超时升级剧本", "运营保障", "medium",
       "SLA 即将超时自动升级到二线",
       [{"t": "start"}, {"t": "action", "n": "ticket.sla_escalate"},
        {"t": "notify", "n": "notify.callout"}, {"t": "end"}], ["sla_warning"]),

    # ---- 补充模板（凑足 50+）----
    _t("general.triage", "通用告警分诊剧本", "通用", "medium",
       "富化+评分+分派的标准分诊流程",
       [{"t": "start"}, {"t": "ti", "n": "ti.lookup_ip"},
        {"t": "condition", "n": "score>70?"},
        {"t": "ticket", "n": "ticket.assign"},
        {"t": "close", "n": "false_positive"}], ["generic_alert"]),
    _t("general.enrich", "告警上下文富化剧本", "通用", "low",
       "补全资产/用户/情报上下文",
       [{"t": "start"}, {"t": "ti", "n": "ti.lookup_ip"},
        {"t": "asset", "n": "asset_lookup"}, {"t": "end"}], ["enrichment"]),
    _t("malware.adware", "广告软件处置剧本", "恶意软件", "low",
       "卸载广告插件并重置浏览器",
       [{"t": "start"}, {"t": "action", "n": "host.service_stop"},
        {"t": "notify", "n": "notify.email"}, {"t": "end"}], ["adware"]),
    _t("phish.business_email", "商务邮件劫持(BEC)剧本", "钓鱼攻击", "critical",
       "冻结付款流程并联系财务",
       [{"t": "start"}, {"t": "approval", "n": "freeze_payment"},
        {"t": "notify", "n": "notify.callout"}, {"t": "end"}], ["bec"]),
    _t("auth.mfa_fatigue", "MFA 疲劳攻击剧本", "身份认证", "high",
       "批量吊销会话并强制重置",
       [{"t": "start"}, {"t": "action", "n": "user.force_logout"},
        {"t": "action", "n": "user.mfa_reset"}, {"t": "end"}], ["mfa_fatigue"]),
    _t("web.brute_login", "登录接口爆破剧本", "Web 攻击", "medium",
       "WAF 限速并挑战",
       [{"t": "start"}, {"t": "action", "n": "app.waf_challenge"},
        {"t": "action", "n": "network.block_ip"}, {"t": "end"}], ["login_bruteforce"]),
    _t("malware.miner", "挖矿木马检测剧本", "恶意软件", "high",
       "终止挖矿进程并封禁矿池",
       [{"t": "start"}, {"t": "action", "n": "host.process_kill"},
        {"t": "action", "n": "network.block_domain"}, {"t": "end"}], ["cryptomining"]),
    _t("dlp.github_secrets", "GitHub 泄露密钥剧本", "数据泄露", "high",
       "轮换并撤销泄露 Token",
       [{"t": "start"}, {"t": "action", "n": "app.rotate_secret"},
        {"t": "action", "n": "app.revoke_api_key"}, {"t": "end"}], ["github_secret"]),
    _t("insider.ep_leak", "端点外发敏感数据剧本", "内部威胁", "high",
       "网络阻断并取证",
       [{"t": "start"}, {"t": "action", "n": "network.block_ip"},
        {"t": "evidence", "n": "evidence.pcap_capture"}, {"t": "end"}], ["endpoint_exfil"]),
    _t("cloud.ami_malware", "恶意 AMI 剧本", "云安全", "high",
       "下架镜像并通知共享方",
       [{"t": "start"}, {"t": "approval", "n": "deregister_ami"},
        {"t": "notify", "n": "notify.im"}, {"t": "end"}], ["malicious_ami"]),
    _t("network.dns_tunneling", "DNS 隧道检测剧本", "网络攻击", "high",
       "阻断可疑域名并抓包",
       [{"t": "start"}, {"t": "action", "n": "network.block_domain"},
        {"t": "evidence", "n": "evidence.pcap_capture"}, {"t": "end"}], ["dns_tunnel"]),
    _t("network.port_scan", "端口扫描响应剧本", "网络攻击", "low",
       "对扫描源临时限速",
       [{"t": "start"}, {"t": "action", "n": "app.waf_challenge"},
        {"t": "condition", "n": "repeated?"},
        {"t": "action", "n": "network.block_ip"}, {"t": "end"}], ["port_scan"]),
    _t("endpoint.amsi_bypass", "AMSI 绕过检测剧本", "端点防御", "high",
       "收集脚本日志并隔离",
       [{"t": "start"}, {"t": "evidence", "n": "evidence.powershell_log"},
        {"t": "action", "n": "host.isolate"}, {"t": "end"}], ["amsi_bypass"]),
    _t("endpoint.scheduled_task", "计划任务持久化剧本", "端点防御", "medium",
       "删除可疑计划任务",
       [{"t": "start"}, {"t": "action", "n": "host.service_stop"},
        {"t": "notify", "n": "notify.im"}, {"t": "end"}], ["scheduled_task"]),
    _t("email.spam_burst", "垃圾邮件爆发剧本", "邮件安全", "low",
       "批量隔离并下调发件人信誉",
       [{"t": "start"}, {"t": "loop", "n": "messages"},
        {"t": "action", "n": "email.quarantine"}, {"t": "end"}], ["spam_burst"]),
    _t("soc.hunt_hook", "狩猎发现落地剧本", "威胁狩猎", "medium",
       "狩猎命中后转入响应流程",
       [{"t": "start"}, {"t": "action", "n": "scan.malware_ioc"},
        {"t": "condition", "n": "hit?"},
        {"t": "ticket", "n": "ticket.create"}, {"t": "end"}], ["hunt_hit"]),
    _t("compliance.access_review", "季度权限复核剧本", "合规治理", "low",
       "对超权限账户发起复核工单",
       [{"t": "start"}, {"t": "loop", "n": "over_privileged"},
        {"t": "ticket", "n": "ticket.create"}, {"t": "end"}], ["access_review"]),
    _t("report.weekly", "每周响应周报剧本", "运营保障", "low",
       "自动汇总本周 MTTR 并发送",
       [{"t": "start"}, {"t": "action", "n": "metrics.weekly"},
        {"t": "notify", "n": "notify.briefing"}, {"t": "end"}], ["weekly_report"]),
    _t("dr.failover", "应急切换演练剧本", "业务连续性", "medium",
       "触发 DR 切换并验证",
       [{"t": "start"}, {"t": "approval", "n": "trigger_failover"},
        {"t": "notify", "n": "notify.callout"}, {"t": "end"}], ["dr_drill"]),
    _t("deception.trap_hit", "蜜罐告警命中剧本", "欺骗防御", "medium",
       "蜜罐告警立即溯源并封禁",
       [{"t": "start"}, {"t": "action", "n": "network.block_ip"},
        {"t": "ti", "n": "ti.lookup_ip"},
        {"t": "hunt", "n": "detect.hunting"}, {"t": "end"}], ["deception_hit"]),
]


# --------------------------------------------------------------------------- #
# 剧本对象与引擎
# --------------------------------------------------------------------------- #
class Playbook:
    """单个剧本（含版本管理）。"""

    def __init__(self, pb_id: str, name: str, category: str = "general") -> None:
        self.pb_id = pb_id
        self.name = name
        self.category = category
        self.status = "draft"          # draft / published / deprecated
        self.current_version = 1
        self.versions: Dict[int, Dict[str, Any]] = {}
        self.nodes: List[Dict[str, Any]] = []
        self.edges: List[Dict[str, str]] = []
        self.trigger: Dict[str, Any] = {}
        self.created_at = time.strftime("%Y-%m-%d %H:%M:%S")
        self.updated_at = self.created_at

    def add_node(self, node_type: str, node_id: Optional[str] = None,
                 config: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
        nid = node_id or f"n{len(self.nodes)+1}"
        node = {"node_id": nid, "type": node_type,
                "config": config or {}, "label": NODE_TYPES.get(node_type, {}).get("name", node_type)}
        self.nodes.append(node)
        self.updated_at = time.strftime("%Y-%m-%d %H:%M:%S")
        return node

    def add_edge(self, src: str, dst: str, condition: str = "default") -> None:
        self.edges.append({"from": src, "to": dst, "condition": condition})
        self.updated_at = time.strftime("%Y-%m-%d %H:%M:%S")

    def save_version(self, note: str = "") -> int:
        self.current_version += 1
        self.versions[self.current_version] = {
            "version": self.current_version,
            "snapshot": {"nodes": copy.deepcopy(self.nodes),
                         "edges": copy.deepcopy(self.edges),
                         "trigger": copy.deepcopy(self.trigger)},
            "note": note, "saved_at": time.strftime("%Y-%m-%d %H:%M:%S"),
        }
        return self.current_version

    def rollback(self, version: int) -> bool:
        v = self.versions.get(version)
        if not v:
            return False
        self.nodes = copy.deepcopy(v["snapshot"]["nodes"])
        self.edges = copy.deepcopy(v["snapshot"]["edges"])
        self.trigger = copy.deepcopy(v["snapshot"]["trigger"])
        self.updated_at = time.strftime("%Y-%m-%d %H:%M:%S")
        return True

    def to_dict(self) -> Dict[str, Any]:
        return {
            "playbook_id": self.pb_id, "name": self.name, "category": self.category,
            "status": self.status, "current_version": self.current_version,
            "nodes": self.nodes, "edges": self.edges, "trigger": self.trigger,
            "node_count": len(self.nodes), "edge_count": len(self.edges),
            "versions": sorted(self.versions.keys()),
            "created_at": self.created_at, "updated_at": self.updated_at,
        }


class PlaybookEngine:
    """剧本编排引擎：CRUD + 模板实例化 + dry-run 测试。"""

    def __init__(self) -> None:
        self.playbooks: Dict[str, Playbook] = {}
        self.test_runs: List[Dict[str, Any]] = []
        self._seed_playbooks()

    def _seed_playbooks(self) -> None:
        """用模板库预置若干可编辑剧本。"""
        for tpl in PLAYBOOK_TEMPLATES[:12]:
            pb = Playbook(tpl["template_id"], tpl["name"], tpl["category"])
            pb.trigger = {"conditions": tpl["trigger_conditions"]}
            prev = None
            for i, step in enumerate(tpl["steps"]):
                nt = step["t"] if step["t"] in NODE_TYPES else "action"
                node = pb.add_node(nt, f"s{i}",
                                   {"action_ref": step.get("n"), "param": step.get("p")})
                if prev:
                    pb.add_edge(prev["node_id"], node["node_id"])
                prev = node
            pb.status = "published"
            pb.save_version("从模板初始化")
            self.playbooks[pb.pb_id] = pb

    # ---- 模板 ----
    def list_templates(self, category: Optional[str] = None) -> List[Dict[str, Any]]:
        if category:
            return [t for t in PLAYBOOK_TEMPLATES if t["category"] == category]
        return PLAYBOOK_TEMPLATES

    def template_categories(self) -> Dict[str, int]:
        out: Dict[str, int] = {}
        for t in PLAYBOOK_TEMPLATES:
            out[t["category"]] = out.get(t["category"], 0) + 1
        return out

    def instantiate(self, template_id: str, name: Optional[str] = None) -> Optional[Dict[str, Any]]:
        tpl = next((t for t in PLAYBOOK_TEMPLATES if t["template_id"] == template_id), None)
        if not tpl:
            return None
        new_id = f"pb-{uuid.uuid4().hex[:8]}"
        pb = Playbook(new_id, name or tpl["name"], tpl["category"])
        pb.trigger = {"conditions": tpl["trigger_conditions"]}
        prev = None
        for i, step in enumerate(tpl["steps"]):
            nt = step["t"] if step["t"] in NODE_TYPES else "action"
            node = pb.add_node(nt, f"s{i}",
                               {"action_ref": step.get("n"), "param": step.get("p")})
            if prev:
                pb.add_edge(prev["node_id"], node["node_id"])
            prev = node
        pb.save_version("从模板实例化")
        self.playbooks[new_id] = pb
        return pb.to_dict()

    # ---- CRUD ----
    def list_playbooks(self, status: Optional[str] = None) -> List[Dict[str, Any]]:
        out = [p.to_dict() for p in self.playbooks.values()]
        if status:
            out = [p for p in out if p["status"] == status]
        return out

    def get(self, playbook_id: str) -> Optional[Playbook]:
        return self.playbooks.get(playbook_id)

    def create(self, name: str, category: str = "general",
               trigger: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
        pb = Playbook(f"pb-{uuid.uuid4().hex[:8]}", name, category)
        pb.trigger = trigger or {}
        start = pb.add_node("start", "start")
        end = pb.add_node("end", "end")
        pb.add_edge(start["node_id"], end["node_id"])
        pb.save_version("首次创建")
        self.playbooks[pb.pb_id] = pb
        return pb.to_dict()

    def update(self, playbook_id: str, patch: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        pb = self.playbooks.get(playbook_id)
        if not pb:
            return None
        if "name" in patch:
            pb.name = patch["name"]
        if "trigger" in patch:
            pb.trigger = patch["trigger"]
        if "nodes" in patch:
            pb.nodes = patch["nodes"]
        if "edges" in patch:
            pb.edges = patch["edges"]
        pb.updated_at = time.strftime("%Y-%m-%d %H:%M:%S")
        return pb.to_dict()

    def publish(self, playbook_id: str, note: str = "") -> Optional[Dict[str, Any]]:
        pb = self.playbooks.get(playbook_id)
        if not pb:
            return None
        pb.status = "published"
        pb.save_version(note or "发布")
        return pb.to_dict()

    def delete(self, playbook_id: str) -> bool:
        return self.playbooks.pop(playbook_id, None) is not None

    # ---- 版本 ----
    def version_history(self, playbook_id: str) -> List[Dict[str, Any]]:
        pb = self.playbooks.get(playbook_id)
        if not pb:
            return []
        return [{"version": v, "note": d["note"], "saved_at": d["saved_at"]}
                for v, d in sorted(pb.versions.items())]

    def rollback(self, playbook_id: str, version: int) -> bool:
        pb = self.playbooks.get(playbook_id)
        if not pb:
            return False
        return pb.rollback(version)

    # ---- 静态校验 + dry-run 测试 ----
    def validate(self, playbook_id: str) -> Dict[str, Any]:
        pb = self.playbooks.get(playbook_id)
        if not pb:
            return {"valid": False, "errors": ["剧本不存在"]}
        errors: List[str] = []
        if not any(n["type"] == "start" for n in pb.nodes):
            errors.append("缺少 start 节点")
        if not any(n["type"] == "end" for n in pb.nodes):
            errors.append("缺少 end 节点")
        ids = [n["node_id"] for n in pb.nodes]
        if len(ids) != len(set(ids)):
            errors.append("存在重复 node_id")
        for e in pb.edges:
            if e["from"] not in ids or e["to"] not in ids:
                errors.append(f"边引用了不存在的节点: {e}")
        return {"valid": not errors, "errors": errors,
                "node_count": len(pb.nodes), "edge_count": len(pb.edges)}

    def test_run(self, playbook_id: str,
                 context: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
        pb = self.playbooks.get(playbook_id)
        result = {"playbook_id": playbook_id, "status": "failed", "steps": [],
                  "started_at": time.strftime("%Y-%m-%d %H:%M:%S")}
        if not pb:
            result["error"] = "剧本不存在"
            self.test_runs.append(result)
            return result
        val = self.validate(playbook_id)
        if not val["valid"]:
            result["error"] = "校验未通过"
            result["validation"] = val
            self.test_runs.append(result)
            return result
        executed = 0
        approval_hits = 0
        for n in pb.nodes:
            rec = {"node_id": n["node_id"], "type": n["type"],
                   "label": n.get("label"), "status": "simulated"}
            if n["type"] == "approval":
                approval_hits += 1
                rec["status"] = "wait_manual"
            executed += 1
            result["steps"].append(rec)
        result["status"] = "passed" if approval_hits == 0 else "passed_with_approval"
        result["executed_nodes"] = executed
        result["approval_nodes"] = approval_hits
        result["finished_at"] = time.strftime("%Y-%m-%d %H:%M:%S")
        self.test_runs.append(result)
        return result

    def stats(self) -> Dict[str, Any]:
        return {
            "playbooks": len(self.playbooks),
            "templates": len(PLAYBOOK_TEMPLATES),
            "templates_by_category": self.template_categories(),
            "test_runs": len(self.test_runs),
            "node_types": list(NODE_TYPES.keys()),
        }


_SINGLETON: Optional[PlaybookEngine] = None


def get_playbook_engine() -> PlaybookEngine:
    global _SINGLETON
    if _SINGLETON is None:
        _SINGLETON = PlaybookEngine()
    return _SINGLETON


if __name__ == "__main__":  # pragma: no cover
    eng = get_playbook_engine()
    print("模板数:", len(PLAYBOOK_TEMPLATES), "预置剧本:", len(eng.playbooks))
    print(eng.test_run(next(iter(eng.playbooks))))
