# -*- coding: utf-8 -*-
"""
dlp_phase.py — 阶段4：DLP 防泄漏（50+ 策略）。

策略覆盖:
    外发检测 / 上传检测 / 打印检测 / 拷贝检测 / 截屏检测 /
    邮件内容检测 / 网络传输检测 / 端点操作检测 /
    云存储公开访问检测 / 代码仓库敏感信息检测 等。

策略动作: 告警 / 阻断 / 加密 / 审批 / 记录。
内存字典存储策略与告警。
"""

from __future__ import annotations

import time
import uuid
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional


# --------------------------------------------------------------------------- #
# 50+ DLP 策略定义
# --------------------------------------------------------------------------- #
# 每条: (policy_id, 名称, 类别, 通道, 动作, 级别, 触发描述)
_DLP_POLICIES_RAW = [
    # ---- 外发检测 ----
    ("DLP-001", "邮件正文含身份证号外发检测", "外发", "email_out",
     "block", "critical", "SMTP 外发正文出现 18 位身份证号"),
    ("DLP-002", "邮件附件含银行卡号检测", "外发", "email_attach",
     "block", "critical", "外发附件中检出 Luhn 校验通过的银行卡"),
    ("DLP-003", "邮件正文含手机号批量外发", "外发", "email_out",
     "alert", "high", "单封邮件手机号 >= 20 个"),
    ("DLP-004", "云盘同步含密钥文件", "外发", "cloud_sync",
     "block", "critical", "同步目录出现 id_rsa / *.pem"),
    ("DLP-005", "即时通讯发送敏感文件", "外发", "im_upload",
     "alert", "high", "企业微信/钉钉发送 *.docx 含手机号"),
    ("DLP-006", "邮件外发超大附件", "外发", "email_attach",
     "alert", "medium", "附件 > 50MB"),
    ("DLP-007", "外发至个人邮箱", "外发", "email_out",
     "alert", "medium", "收件域不在企业白名单"),
    # ---- 上传检测 ----
    ("DLP-010", "Web 上传含身份证", "上传", "web_upload",
     "block", "critical", "HTTP 上传文件内容含身份证号"),
    ("DLP-011", "FTP 上传敏感目录", "上传", "ftp_upload",
     "alert", "high", "FTP 上传到 /incoming 含个人数据"),
    ("DLP-012", "API 批量导出用户数据", "上传", "api_upload",
     "block", "high", "单次 API 导出行数 >= 10000"),
    ("DLP-013", "表单提交含密码明文", "上传", "web_upload",
     "block", "critical", "POST body 中 password= 明文"),
    ("DLP-014", "拖拽上传敏感文件", "上传", "web_upload",
     "alert", "medium", "拖拽 *.csv 含手机号"),
    ("DLP-015", "上传至未审核第三方 SaaS", "上传", "web_upload",
     "alert", "high", "上传域不在审批 SaaS 清单"),
    # ---- 打印检测 ----
    ("DLP-020", "敏感文件打印", "打印", "print",
     "alert", "high", "打印标记机密的文档"),
    ("DLP-021", "批量打印客户名单", "打印", "print",
     "block", "high", "单次打印 > 50 页含客户信息"),
    ("DLP-022", "非工作时间打印", "打印", "print",
     "alert", "medium", "22:00-06:00 打印敏感文档"),
    # ---- 拷贝检测 ----
    ("DLP-030", "USB 拷贝敏感目录", "拷贝", "usb_copy",
     "block", "critical", "复制到 U 盘 命中机密标签"),
    ("DLP-031", "网络共享拷贝", "拷贝", "net_share",
     "alert", "high", "从 D 盘敏感目录复制到 \\10.* 共享"),
    ("DLP-032", "剪切板大段复制", "拷贝", "clipboard",
     "alert", "medium", "单次复制 > 2000 字符含手机号"),
    # ---- 截屏检测 ----
    ("DLP-040", "敏感页面截屏", "截屏", "screen_capture",
     "alert", "high", "财务/客户详情页触发 PrintScreen"),
    ("DLP-041", "截屏敏感弹窗", "截屏", "screen_capture",
     "alert", "medium", "含密钥弹窗截屏"),
    # ---- 邮件内容检测 ----
    ("DLP-050", "邮件正文含口令", "邮件内容", "email_body",
     "block", "critical", "正文出现 password= 模式"),
    ("DLP-051", "邮件附件为加密压缩包", "邮件内容", "email_attach",
     "alert", "medium", "*.zip 带密码"),
    ("DLP-052", "邮件正文含未加密信用卡号", "邮件内容", "email_body",
     "block", "critical", "正文出现 16 位 Luhn 通过卡号"),
    ("DLP-053", "邮件正文含病历描述", "邮件内容", "email_body",
     "alert", "high", "正文含诊断/处方关键词"),
    # ---- 网络传输检测 ----
    ("DLP-060", "HTTP 明文传输身份证", "网络传输", "http",
     "block", "critical", "HTTP URL/body 含身份证号"),
    ("DLP-061", "FTP 明文传输敏感文件", "网络传输", "ftp",
     "block", "high", "FTP 协议传输 *.csv 含个人数据"),
    ("DLP-062", "SMTP 明文外发", "网络传输", "smtp",
     "alert", "medium", "25 端口明文 SMTP"),
    ("DLP-063", "非加密 API 传输令牌", "网络传输", "http",
     "alert", "high", "Authorization 头走 HTTP 明文"),
    ("DLP-064", "异常境外 IP 出站", "网络传输", "egress",
     "alert", "high", "敏感主机连接境外 IP"),
    # ---- 端点操作检测 ----
    ("DLP-070", "端点复制粘贴敏感串", "端点", "endpoint_copy",
     "alert", "medium", "复制 > 15 位数字串"),
    ("DLP-071", "端点拖拽导出", "端点", "endpoint_drag",
     "alert", "medium", "拖拽表格到本地 CSV"),
    ("DLP-072", "端点批量重命名导出", "端点", "endpoint_bulk",
     "alert", "high", "短时间批量导出 100+ 文件"),
    # ---- 云存储检测 ----
    ("DLP-080", "AWS S3 桶公开访问", "云存储", "aws_s3",
     "block", "critical", "S3 bucket ACL = public-read"),
    ("DLP-081", "阿里云 OSS 公共读", "云存储", "ali_oss",
     "block", "critical", "OSS bucket 设为公共读"),
    ("DLP-082", "腾讯云 COS 公开访问", "云存储", "tencent_cos",
     "block", "critical", "COS bucket 允许匿名下载"),
    ("DLP-083", "云存储上传未加密备份", "云存储", "cloud_upload",
     "alert", "high", "上传 *.sql 备份未加密"),
    ("DLP-084", "云存储分享链接过期过长", "云存储", "cloud_share",
     "alert", "medium", "分享链接有效期 > 30 天"),
    # ---- 代码仓库检测 ----
    ("DLP-090", "GitHub 提交私钥", "代码仓库", "github",
     "block", "critical", "git push 含 BEGIN PRIVATE KEY"),
    ("DLP-091", "GitLab 提交 AccessKey", "代码仓库", "gitlab",
     "block", "critical", "代码含 AKIA[0-9A-Z]{16}"),
    ("DLP-092", "仓库中硬编码密码", "代码仓库", "repo_scan",
     "alert", "high", "代码含 password = '...'"),
    ("DLP-093", ".env 文件提交仓库", "代码仓库", "repo_scan",
     "alert", "high", ".env 被 git add"),
    ("DLP-094", "仓库中数据库连接串", "代码仓库", "repo_scan",
     "alert", "high", "mysql://user:pass@host"),
    # ---- 数据库导出 ----
    ("DLP-100", "数据库全表导出", "数据库", "db_export",
     "block", "critical", "mysqldump 全库导出"),
    ("DLP-101", "SELECT * 大结果集", "数据库", "db_query",
     "alert", "high", "查询返回 > 10w 行"),
    ("DLP-102", "DBA 非工作时间访问", "数据库", "db_query",
     "alert", "high", "DBA 账号 02:00 登录"),
    # ---- 其他 ----
    ("DLP-110", "敏感数据贴入公开 Wiki", "协作", "wiki",
     "alert", "high", "Confluence 页面含手机号"),
    ("DLP-111", "客户资料贴入工单", "协作", "ticket",
     "alert", "medium", "工单正文含身份证"),
    ("DLP-112", "外部访客下载敏感文档", "协作", "guest_download",
     "block", "high", "外部协作者下载机密文档"),
    ("DLP-113", "视频会议共享敏感屏幕", "协作", "screen_share",
     "alert", "medium", "共享窗口含密钥弹窗"),
    ("DLP-114", "备份磁带离线外借", "备份", "tape",
     "alert", "high", "LTO 磁带借出登记缺失"),
    ("DLP-115", "日志含敏感参数", "日志", "log",
     "alert", "medium", "应用日志打印 token"),
    ("DLP-116", "CRM 批量导出客户", "业务", "crm_export",
     "block", "high", "单次导出客户 >= 5000"),
    ("DLP-117", "HR 系统导出薪资表", "业务", "hr_export",
     "block", "critical", "导出 salary 字段全表"),
    ("DLP-118", "BI 看板未授权访问", "业务", "bi_dashboard",
     "alert", "medium", "未登录访问 BI 看板"),
    ("DLP-119", "移动端拍照敏感屏幕", "端点", "phone_capture",
     "alert", "high", "手机拍摄敏感显示屏"),
    ("DLP-120", "CDN 缓存敏感文件", "网络传输", "cdn",
     "alert", "high", "CDN 节点缓存 *.pii 文件"),
]

DLP_ACTIONS = ["alert", "block", "encrypt", "approve", "log"]
DLP_LEVELS = ["critical", "high", "medium", "low"]


@dataclass
class DLPPolicy:
    policy_id: str
    name: str
    category: str
    channel: str
    action: str
    level: str
    description: str
    enabled: bool = True
    threshold: int = 1

    def to_dict(self) -> Dict[str, Any]:
        return {
            "policy_id": self.policy_id, "name": self.name,
            "category": self.category, "channel": self.channel,
            "action": self.action, "level": self.level,
            "description": self.description,
            "enabled": self.enabled, "threshold": self.threshold,
        }


@dataclass
class DLPAlert:
    alert_id: str
    ts: str
    policy_id: str
    policy_name: str
    level: str
    action: str
    user: str
    channel: str
    detail: str
    status: str = "open"     # open/ack/closed

    def to_dict(self) -> Dict[str, Any]:
        return {
            "alert_id": self.alert_id, "ts": self.ts,
            "policy_id": self.policy_id, "policy_name": self.policy_name,
            "level": self.level, "action": self.action,
            "user": self.user, "channel": self.channel,
            "detail": self.detail, "status": self.status,
        }


class DLPPhase:
    """阶段4：DLP 防泄漏。"""

    def __init__(self) -> None:
        self.policies: Dict[str, DLPPolicy] = {}
        for raw in _DLP_POLICIES_RAW:
            p = DLPPolicy(*raw)
            self.policies[p.policy_id] = p
        self._alerts: List[DLPAlert] = []

    # ------------------------------------------------------------------ #
    def list_policies(self, category: Optional[str] = None,
                      enabled_only: bool = False) -> List[Dict[str, Any]]:
        items = list(self.policies.values())
        if category:
            items = [p for p in items if p.category == category]
        if enabled_only:
            items = [p for p in items if p.enabled]
        return [p.to_dict() for p in items]

    def policy_detail(self, policy_id: str) -> Optional[Dict[str, Any]]:
        p = self.policies.get(policy_id)
        return p.to_dict() if p else None

    def enable_policy(self, policy_id: str, enabled: bool = True
                      ) -> Dict[str, Any]:
        p = self.policies.get(policy_id)
        if not p:
            return {"error": "policy not found"}
        p.enabled = enabled
        return p.to_dict()

    def set_threshold(self, policy_id: str, threshold: int) -> Dict[str, Any]:
        p = self.policies.get(policy_id)
        if not p:
            return {"error": "policy not found"}
        p.threshold = max(1, threshold)
        return p.to_dict()

    def set_action(self, policy_id: str, action: str) -> Dict[str, Any]:
        p = self.policies.get(policy_id)
        if not p:
            return {"error": "policy not found"}
        if action not in DLP_ACTIONS:
            return {"error": f"action must be one of {DLP_ACTIONS}"}
        p.action = action
        return p.to_dict()

    def add_policy(self, name: str, category: str, channel: str,
                   action: str = "alert", level: str = "medium",
                   description: str = "", threshold: int = 1,
                   ) -> Dict[str, Any]:
        pid = f"DLP-C{len(self.policies):03d}"
        p = DLPPolicy(
            policy_id=pid, name=name, category=category, channel=channel,
            action=action, level=level, description=description,
            threshold=threshold)
        self.policies[pid] = p
        return p.to_dict()

    # ------------------------------------------------------------------ #
    def simulate_event(self, channel: str, content: str,
                      user: str = "demo-user",
                      ) -> Dict[str, Any]:
        """模拟一次 DLP 事件：按通道+内容匹配策略并产生告警。"""
        hits: List[DLPAlert] = []
        content_l = content.lower()
        for p in self.policies.values():
            if not p.enabled:
                continue
            if p.channel != channel:
                continue
            # 简单命中规则：critical 策略一律触发（演示引擎）
            a = DLPAlert(
                alert_id="A" + uuid.uuid4().hex[:10],
                ts=time.strftime("%Y-%m-%d %H:%M:%S"),
                policy_id=p.policy_id, policy_name=p.name,
                level=p.level, action=p.action,
                user=user, channel=channel,
                detail=f"通道={channel} 内容={content_l[:80]}")
            hits.append(a)
            self._alerts.append(a)
        return {
            "channel": channel, "user": user,
            "triggered": [h.to_dict() for h in hits],
            "hit_count": len(hits),
        }

    # ------------------------------------------------------------------ #
    def list_alerts(self, level: Optional[str] = None,
                    status: Optional[str] = None,
                    limit: int = 50) -> List[Dict[str, Any]]:
        items = list(self._alerts)
        if level:
            items = [a for a in items if a.level == level]
        if status:
            items = [a for a in items if a.status == status]
        items.sort(key=lambda a: a.ts, reverse=True)
        return [a.to_dict() for a in items[:limit]]

    def ack_alert(self, alert_id: str, status: str = "closed"
                  ) -> Dict[str, Any]:
        for a in self._alerts:
            if a.alert_id == alert_id:
                a.status = status
                return a.to_dict()
        return {"error": "alert not found"}

    # ------------------------------------------------------------------ #
    def stats(self) -> Dict[str, Any]:
        by_level: Dict[str, int] = {lv: 0 for lv in DLP_LEVELS}
        by_action: Dict[str, int] = {}
        by_category: Dict[str, int] = {}
        for a in self._alerts:
            by_level[a.level] = by_level.get(a.level, 0) + 1
            by_action[a.action] = by_action.get(a.action, 0) + 1
        for p in self.policies.values():
            if p.enabled:
                by_category[p.category] = by_category.get(p.category, 0) + 1
        # 24h 趋势（演示：按小时分桶，空数据）
        return {
            "policy_total": len(self.policies),
            "policy_enabled": sum(1 for p in self.policies.values()
                                  if p.enabled),
            "alert_total": len(self._alerts),
            "alerts_by_level": by_level,
            "alerts_by_action": by_action,
            "policies_by_category": by_category,
        }


_default_phase: Optional[DLPPhase] = None


def get_dlp_phase() -> DLPPhase:
    global _default_phase
    if _default_phase is None:
        _default_phase = DLPPhase()
    return _default_phase


__all__ = [
    "DLPPhase", "DLPPolicy", "DLPAlert", "get_dlp_phase",
    "DLP_ACTIONS", "DLP_LEVELS",
]
