#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
dlp_engine.py — 数据泄露防护(DLP)引擎。

覆盖：
    - 内容检测：基于规则/正则/字典/指纹/机器学习的敏感内容检测
    - 上下文感知：数据来源/用户角色/设备/位置/时间/操作类型
    - 通道监控：邮件/IM/USB/云盘/打印/网页上传/FTP/SMB/API 通道风险评估
    - 策略引擎：策略定义(条件/动作/严重级别)、策略匹配、优先级、策略模拟
    - 告警与阻断：风险事件、告警分级、阻断建议、事件关联
    - 水印追踪：可见/隐形数字水印、溯源追踪
    - DLP 事件报告

设计定位：仅做泄露风险评估与防护建议，不进行真实拦截或窃听。
"""

from __future__ import annotations

import hashlib
import re
import time
import uuid
from typing import Any, Dict, List, Optional


# --------------------------------------------------------------------------- #
# DLP 策略库
# --------------------------------------------------------------------------- #
DLP_POLICY_LIBRARY: Dict[str, Dict[str, Any]] = {
    "pii_exfil_email": {
        "id": "pii_exfil_email", "name": "个人信息邮件外发",
        "category": "PII", "severity": "high",
        "channels": ["email", "web_upload"],
        "conditions": {"content_contains": ["pii_cn_id", "pii_cn_mobile", "pii_email"],
                       "external_recipient": True},
        "actions": ["alert", "block", "watermark"],
        "description": "检测含身份证/手机号的邮件外发至外部收件人",
    },
    "credit_card_file": {
        "id": "credit_card_file", "name": "信用卡卡号文件外泄",
        "category": "PCI", "severity": "critical",
        "channels": ["usb", "ftp", "smb", "cloud"],
        "conditions": {"content_contains": ["pci_visa", "pci_mastercard", "pci_cn_unionpay"],
                       "count_threshold": 3},
        "actions": ["block", "quarantine", "alert_admin"],
        "description": "文件中包含多张信用卡号经USB/共享/云盘外传",
    },
    "code_repo_leak": {
        "id": "code_repo_leak", "name": "源代码/密钥外泄",
        "category": "商业机密", "severity": "critical",
        "channels": ["web_upload", "git", "api", "cloud"],
        "conditions": {"content_contains": ["biz_source_code", "biz_private_key", "biz_api_key"],
                       "after_hours": True},
        "actions": ["block", "alert_admin", "revoke_session"],
        "description": "非工作时间上传源代码或私钥到外部仓库",
    },
    "phi_print": {
        "id": "phi_print", "name": "病历/处方打印",
        "category": "PHI", "severity": "medium",
        "channels": ["print"],
        "conditions": {"content_contains": ["phi_medical_record", "phi_diagnosis", "phi_prescription"]},
        "actions": ["alert", "watermark_visible"],
        "description": "打印含病历/诊断/处方的文档",
    },
    "large_download": {
        "id": "large_download", "name": "异常大批量下载",
        "category": "行为", "severity": "high",
        "channels": ["web_upload", "api", "ftp"],
        "conditions": {"volume_mb_gt": 500, "new_device": True},
        "actions": ["alert", "step_up_auth", "rate_limit"],
        "description": "新设备短时间大批量下载数据",
    },
    "usb_unauthorized": {
        "id": "usb_unauthorized", "name": "未授权USB拷贝",
        "category": "终端", "severity": "medium",
        "channels": ["usb"],
        "conditions": {"device_authorized": False, "sensitive_read": True},
        "actions": ["block", "alert"],
        "description": "未授权USB设备读取敏感文件",
    },
    "cloud_personal": {
        "id": "cloud_personal", "name": "上传个人云盘",
        "category": "云", "severity": "high",
        "channels": ["cloud", "web_upload"],
        "conditions": {"destination_type": "personal_cloud", "content_sensitive": True},
        "actions": ["block", "alert", "notify_owner"],
        "description": "将敏感文件上传至个人网盘",
    },
    "im_clipboard": {
        "id": "im_clipboard", "name": "IM粘贴敏感信息",
        "category": "即时通讯", "severity": "medium",
        "channels": ["im"],
        "conditions": {"content_contains": ["pii_cn_id", "pci_cvv", "cred_password"],
                       "external_contact": True},
        "actions": ["warn", "watermark", "log"],
        "description": "即时通讯粘贴身份证/CVV/密码给外部联系人",
    },
}

# 通道风险基线
_CHANNEL_RISK: Dict[str, Dict[str, Any]] = {
    "email": {"name": "邮件", "base_risk": "medium", "encryption_expected": "TLS"},
    "im": {"name": "即时通讯", "base_risk": "medium", "encryption_expected": "E2EE可选"},
    "usb": {"name": "USB存储", "base_risk": "high", "encryption_expected": "设备加密"},
    "cloud": {"name": "云盘", "base_risk": "high", "encryption_expected": "传输+静态"},
    "print": {"name": "打印", "base_risk": "low", "encryption_expected": "纸质管控"},
    "web_upload": {"name": "网页上传", "base_risk": "high", "encryption_expected": "HTTPS"},
    "ftp": {"name": "FTP", "base_risk": "critical", "encryption_expected": "SFTP/FTPS"},
    "smb": {"name": "SMB共享", "base_risk": "medium", "encryption_expected": "SMB3加密"},
    "api": {"name": "API接口", "base_risk": "medium", "encryption_expected": "mTLS"},
    "git": {"name": "Git仓库", "base_risk": "high", "encryption_expected": "HTTPS/SSH"},
}


class DLPEngine:
    """数据泄露防护引擎。"""

    def __init__(self) -> None:
        self.policies: Dict[str, Dict[str, Any]] = DLP_POLICY_LIBRARY
        self.events: List[Dict[str, Any]] = []
        self._rx_cache: Dict[str, re.Pattern] = {}

    # ------------------------------------------------------------------ #
    # 内容检测
    # ------------------------------------------------------------------ #
    def detect_content(self, content: str) -> Dict[str, Any]:
        """基于规则/字典/指纹的敏感内容检测。"""
        found: List[Dict[str, Any]] = []
        checks = {
            "身份证": (r"\b\d{17}[\dXx]\b", "pii", "critical"),
            "手机号": (r"\b1[3-9]\d{9}\b", "pii", "high"),
            "邮箱": (r"[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}", "pii", "medium"),
            "银行卡": (r"\b(?:\d[ -]*?){13,19}\b", "pci", "critical"),
            "CVV": (r"(?i)cvv[:：\s]?\d{3,4}", "pci", "critical"),
            "私钥": (r"-----BEGIN [A-Z ]*PRIVATE KEY-----", "secret", "critical"),
            "API Key": (r"(?i)(sk|pk|api[_-]?key)['\"=:\s]+[A-Za-z0-9]{16,}", "secret", "critical"),
            "JWT": (r"eyJ[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]{10,}", "secret", "high"),
            "密码": (r"(?i)(password|passwd|pwd)['\"=:\s]+[^\s'\"]{6,}", "cred", "critical"),
            "病历号": (r"(?i)(病历号|病案号|medical_record)[:：=]?\w{4,15}", "phi", "high"),
        }
        for label, (pat, cat, risk) in checks.items():
            try:
                n = len(re.findall(pat, content or ""))
            except re.error:
                n = 0
            if n:
                found.append({"label": label, "category": cat,
                              "risk": risk, "count": n,
                              "fingerprint": hashlib.sha1((label + str(n)).encode()).hexdigest()[:12]})
        return {
            "detected": found,
            "total_findings": len(found),
            "max_risk": self._max_risk(found),
            "content_hash": hashlib.sha1((content or "").encode()).hexdigest()[:16],
        }

    @staticmethod
    def _max_risk(found: List[Dict[str, Any]]) -> str:
        order = {"info": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}
        if not found:
            return "info"
        return max(found, key=lambda f: order.get(f["risk"], 0))["risk"]

    # ------------------------------------------------------------------ #
    # 上下文感知检测
    # ------------------------------------------------------------------ #
    def context_assess(self, context: Dict[str, Any]) -> Dict[str, Any]:
        """评估上下文风险：来源/角色/设备/位置/时间/操作。"""
        factors: List[Dict[str, Any]] = []
        role = context.get("user_role", "employee")
        if role in ("extern", "contractor", "outsider"):
            factors.append({"factor": "外部角色", "risk": "high",
                            "detail": f"用户角色={role}，数据访问权限应收紧"})
        if context.get("new_device"):
            factors.append({"factor": "新设备", "risk": "high", "detail": "首次出现的设备"})
        if context.get("off_network"):
            factors.append({"factor": "外部网络", "risk": "medium", "detail": "非办公网/VPN外"})
        hour = context.get("hour")
        if isinstance(hour, int) and (hour < 7 or hour > 21):
            factors.append({"factor": "非工作时间", "risk": "medium",
                            "detail": f"操作时间 {hour}:00"})
        if context.get("unusual_location"):
            factors.append({"factor": "异常位置", "risk": "high", "detail": "非常用地理位置"})
        op = context.get("operation", "read")
        if op in ("download", "export", "copy", "share"):
            factors.append({"factor": f"高风险操作-{op}", "risk": "medium",
                            "detail": f"操作类型={op}"})
        return {
            "context_risk": self._max_risk(factors) if factors else "info",
            "factors": factors,
            "factor_count": len(factors),
        }

    # ------------------------------------------------------------------ #
    # 通道监控
    # ------------------------------------------------------------------ #
    def channel_monitor(self, channels: Optional[List[str]] = None) -> Dict[str, Any]:
        """评估各数据通道的泄露风险。"""
        channels = channels or list(_CHANNEL_RISK.keys())
        rows = []
        for ch in channels:
            base = _CHANNEL_RISK.get(ch, {"name": ch, "base_risk": "medium",
                                         "encryption_expected": "未知"})
            rows.append({
                "channel": ch, "name": base["name"],
                "base_risk": base["base_risk"],
                "encryption_expected": base["encryption_expected"],
                "monitoring_status": "已接入DLP" if ch in ("email", "web_upload", "api") else "未完全覆盖",
                "risk_note": self._channel_note(ch, base["base_risk"]),
            })
        uncovered = [r["channel"] for r in rows if r["monitoring_status"] != "已接入DLP"]
        return {
            "channels": rows, "total": len(rows),
            "uncovered_channels": uncovered,
            "recommendation": "优先对 ftp/usb/cloud 通道补齐 DLP 代理与审计",
        }

    @staticmethod
    def _channel_note(ch: str, risk: str) -> str:
        notes = {
            "ftp": "FTP明文传输敏感数据，应迁移SFTP/FTPS",
            "usb": "需USB端口管控+外设加密+写入审计",
            "cloud": "区分企业网盘与个人网盘，禁止个人网盘外传",
            "print": "纸质输出需水印+回收管理",
            "email": "外发邮件需DLP网关扫描+自动加密",
            "im": "禁止在IM粘贴密钥/身份证/银行卡",
            "web_upload": "浏览器扩展/代理拦截高危网页上传",
            "smb": "共享权限最小化+SMB签名加密",
            "api": "API出站流量审计+数据脱敏",
            "git": "仓库pre-commit扫描密钥泄露",
        }
        return notes.get(ch, f"{risk} 风险通道，需持续监控")

    # ------------------------------------------------------------------ #
    # 策略引擎
    # ------------------------------------------------------------------ #
    def match_policy(self, event: Dict[str, Any]) -> List[Dict[str, Any]]:
        """根据事件匹配策略。"""
        matched = []
        channels = set(event.get("channels", []))
        content_risk = event.get("content_risk", "info")
        ext = event.get("external_recipient", False)
        for p in self.policies.values():
            score = 0
            if channels & set(p["channels"]):
                score += 2
            cond = p["conditions"]
            if cond.get("external_recipient") and ext:
                score += 2
            if cond.get("after_hours") and event.get("after_hours"):
                score += 1
            if cond.get("new_device") and event.get("new_device"):
                score += 1
            if cond.get("content_sensitive") and content_risk in ("high", "critical"):
                score += 2
            if score >= 2:
                matched.append({
                    "policy_id": p["id"], "policy_name": p["name"],
                    "severity": p["severity"], "score": score,
                    "actions": p["actions"],
                    "priority": self._priority(p["severity"]),
                })
        matched.sort(key=lambda x: x["priority"], reverse=True)
        return matched

    @staticmethod
    def _priority(sev: str) -> int:
        return {"critical": 4, "high": 3, "medium": 2, "low": 1}.get(sev, 0)

    def simulate_policy(self, content: str, channel: str,
                        context: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
        """策略模拟：评估一次模拟外发会命中哪些策略。"""
        ctx = context or {}
        det = self.detect_content(content)
        event = {
            "channels": [channel],
            "content_risk": det["max_risk"],
            "external_recipient": ctx.get("external_recipient", True),
            "after_hours": ctx.get("after_hours", False),
            "new_device": ctx.get("new_device", False),
        }
        matched = self.match_policy(event)
        return {
            "content": det,
            "context": self.context_assess(ctx),
            "matched_policies": matched,
            "would_block": any("block" in m["actions"] for m in matched),
            "would_watermark": any("watermark" in a for m in matched for a in m["actions"]),
            "simulated_at": time.strftime("%Y-%m-%d %H:%M:%S"),
        }

    # ------------------------------------------------------------------ #
    # 告警与阻断
    # ------------------------------------------------------------------ #
    def generate_events(self, scan_result: Dict[str, Any],
                        channel: str = "email") -> List[Dict[str, Any]]:
        """根据检测结果生成DLP风险事件。"""
        self.events = []
        for det in scan_result.get("detected", []):
            sev = det["risk"]
            self.events.append({
                "event_id": uuid.uuid4().hex[:10],
                "timestamp": time.strftime("%Y-%m-%d %H:%M:%S"),
                "channel": channel,
                "type": det["label"], "category": det["category"],
                "severity": sev, "count": det["count"],
                "alert_level": self._alert_level(sev),
                "block_suggestion": sev in ("critical", "high"),
                "watermark_suggested": True,
                "status": "open",
            })
        # 事件关联
        if len(self.events) >= 3:
            self.events.append({
                "event_id": uuid.uuid4().hex[:10],
                "timestamp": time.strftime("%Y-%m-%d %H:%M:%S"),
                "channel": channel, "type": "关联事件",
                "category": "correlation", "severity": "high",
                "count": len(self.events),
                "alert_level": "P1",
                "block_suggestion": True,
                "watermark_suggested": True,
                "status": "open",
                "note": f"短时间内 {len(self.events)} 类敏感数据命中，疑似批量泄露",
            })
        return self.events

    @staticmethod
    def _alert_level(sev: str) -> str:
        return {"critical": "P1", "high": "P2", "medium": "P3",
                "low": "P4", "info": "P5"}.get(sev, "P5")

    # ------------------------------------------------------------------ #
    # 水印追踪
    # ------------------------------------------------------------------ #
    def watermark_plan(self, doc_name: str, user: str,
                       visible: bool = True) -> Dict[str, Any]:
        """生成水印/溯源方案（仅方案，不实际加水印）。"""
        trace_id = uuid.uuid4().hex[:12]
        return {
            "trace_id": trace_id,
            "visible_watermark": {
                "enabled": visible,
                "text": f"{user} | {trace_id}",
                "position": "对角线斜铺",
                "opacity": 0.08,
            },
            "invisible_watermark": {
                "enabled": True,
                "algorithm": "LSB空域+频域混合",
                "payload": f"uid={user};tid={trace_id};ts={int(time.time())}",
                "robustness": "抗截屏/压缩/裁剪",
            },
            "traceability": {
                "log_channel": "DLP审计日志",
                "linked_user": user,
                "linked_device_hash": hashlib.sha1(user.encode()).hexdigest()[:10],
            },
            "note": "水印方案用于泄露后溯源，不影响正常阅读",
        }

    # ------------------------------------------------------------------ #
    # 报告
    # ------------------------------------------------------------------ #
    def get_report_markdown(self, result: Dict[str, Any]) -> str:
        lines = [
            "# DLP 数据泄露防护报告", "",
            f"- 生成时间: {result.get('generated_at')}",
            f"- 策略数: {len(self.policies)}",
            f"- 事件数: {len(result.get('events', []))}", "",
            "## 事件清单",
        ]
        for e in result.get("events", []):
            lines.append(f"- [{e['severity']}/{e['alert_level']}] {e['channel']} "
                         f"{e['type']} x{e['count']} -> 阻断建议:{e['block_suggestion']}")
        lines += ["", "## 通道覆盖",
                  f"- 未完全覆盖通道: {', '.join(result.get('uncovered', [])) or '无'}",
                  "", "## 建议",
                  "- 对 critical 通道(ftp/usb/cloud)启用阻断型策略",
                  "- 外发敏感文档强制水印并记录溯源",
                  "- 定期演练策略误报/漏报"]
        return "\n".join(lines)

    def list_policies(self) -> Dict[str, Any]:
        by_sev: Dict[str, int] = {}
        for p in self.policies.values():
            by_sev[p["severity"]] = by_sev.get(p["severity"], 0) + 1
        return {"total": len(self.policies), "by_severity": by_sev,
                "policies": list(self.policies.values())}
