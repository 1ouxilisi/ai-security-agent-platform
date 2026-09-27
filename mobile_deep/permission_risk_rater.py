# -*- coding: utf-8 -*-
"""
permission_risk_rater.py — 权限风险评级（方向3）。

基于 CVSS v3.1 向量思想，对 Android 权限做风险打分：
    - 每个权限一个基础向量（AV/AC/PR/UI + 影响项）
    - 分数 0~10；>=9.0 Critical / >=7.0 High / >=4.0 Medium / 其余 Low
    - 给出修复建议
"""
from __future__ import annotations

from typing import Any, Dict, List


# 权限风险库：(base_score, reason, remediation)
PERMISSION_RISK_DB: Dict[str, Dict[str, Any]] = {
    "android.permission.READ_CALL_LOG": {
        "score": 7.5, "level": "high",
        "reason": "通话记录属于敏感个人信息，泄露可还原社交关系",
        "remediation": "若非电话功能必需，移除并改用运行时申请最小子集",
    },
    "android.permission.CALL_PHONE": {
        "score": 7.0, "level": "high",
        "reason": "可直接拨打电话，可能被劫持用于付费拨打",
        "remediation": "使用 ACTION_DIAL 让用户确认，避免直接 call",
    },
    "android.permission.CAMERA": {
        "score": 6.5, "level": "medium",
        "reason": "相机隐私风险，后台偷拍",
        "remediation": "仅在用户主动触发拍摄时申请",
    },
    "android.permission.RECORD_AUDIO": {
        "score": 7.5, "level": "high",
        "reason": "麦克风录音可窃听",
        "remediation": "前台服务 + 显眼通知，用完立即释放",
    },
    "android.permission.ACCESS_FINE_LOCATION": {
        "score": 7.0, "level": "high",
        "reason": "精确定位可还原行踪",
        "remediation": "使用 COARSE 或仅前台申请",
    },
    "android.permission.ACCESS_COARSE_LOCATION": {
        "score": 4.0, "level": "medium",
        "reason": "粗略定位",
        "remediation": "按需申请，避免后台持续定位",
    },
    "android.permission.READ_CONTACTS": {
        "score": 7.0, "level": "high",
        "reason": "通讯录读取",
        "remediation": "共享联系人走系统分享而非批量读取",
    },
    "android.permission.WRITE_CONTACTS": {
        "score": 8.0, "level": "high",
        "reason": "可篡改通讯录",
        "remediation": "若非必需禁止",
    },
    "android.permission.READ_SMS": {
        "score": 9.0, "level": "critical",
        "reason": "短信可读取验证码，是账户接管高频入口",
        "remediation": "默认移除；自动填充改走 SMS Retriever API",
    },
    "android.permission.SEND_SMS": {
        "score": 9.5, "level": "critical",
        "reason": "可静默发送扣费短信",
        "remediation": "禁止；使用系统短信 App 发送",
    },
    "android.permission.READ_EXTERNAL_STORAGE": {
        "score": 5.5, "level": "medium",
        "reason": "可读取外部存储任意文件",
        "remediation": "Scoped Storage / MediaStore",
    },
    "android.permission.WRITE_EXTERNAL_STORAGE": {
        "score": 6.5, "level": "medium",
        "reason": "可写外部存储，覆盖其他应用文件",
        "remediation": "Scoped Storage",
    },
    "android.permission.SYSTEM_ALERT_WINDOW": {
        "score": 8.5, "level": "high",
        "reason": "悬浮窗可做 overlay 钓鱼",
        "remediation": "非必需移除",
    },
    "android.permission.GET_ACCOUNTS": {
        "score": 5.0, "level": "medium",
        "reason": "可枚举设备账户",
        "remediation": "按业务最小化",
    },
    "android.permission.PROCESS_OUTGOING_CALLS": {
        "score": 8.0, "level": "high",
        "reason": "拦截外拨电话",
        "remediation": "非电话审计场景移除",
    },
    "android.permission.BODY_SENSORS": {
        "score": 6.0, "level": "medium",
        "reason": "传感器隐私",
        "remediation": "仅在前台运动时申请",
    },
    "android.permission.READ_PHONE_STATE": {
        "score": 5.5, "level": "medium",
        "reason": "读取 IMEI/IMSI 等硬件标识",
        "remediation": "改用 ANDROID_ID / 广告 ID",
    },
}

# 普通权限默认分
DEFAULT_SCORE = 2.0
DEFAULT_LEVEL = "low"


def _level(score: float) -> str:
    if score >= 9.0:
        return "critical"
    if score >= 7.0:
        return "high"
    if score >= 4.0:
        return "medium"
    return "low"


class PermissionRiskRater:
    """权限风险评级器。"""

    def rate(self, permissions: List[str]) -> Dict[str, Any]:
        details: List[Dict[str, Any]] = []
        score_sum = 0.0
        weighted_max = 0.0
        for p in permissions:
            entry = PERMISSION_RISK_DB.get(p, {})
            score = float(entry.get("score", DEFAULT_SCORE))
            level = entry.get("level", _level(score))
            details.append({
                "permission": p,
                "score": score,
                "level": level,
                "reason": entry.get("reason", "普通/三方权限，未入库"),
                "remediation": entry.get("remediation", "按业务最小化"),
            })
            score_sum += score
            weighted_max = max(weighted_max, score)

        # 综合分：取 0.6*最高 + 0.4*均值
        avg = score_sum / max(len(permissions), 1)
        overall = round(0.6 * weighted_max + 0.4 * avg, 2)
        return {
            "permissions": details,
            "overall_score": overall,
            "overall_level": _level(overall),
            "max_score": weighted_max,
            "dangerous_count": sum(1 for d in details
                                   if d["level"] in ("high", "critical")),
            "medium_count": sum(1 for d in details if d["level"] == "medium"),
            "low_count": sum(1 for d in details if d["level"] == "low"),
            "cvss_vector_example": (
                "CVSS:3.1/AV:L/AC:L/PR:N/UI:R/"
                "S:U/C:H/I:N/A:N"
            ),
            "note": "评分为启发式，仅供风险排序，不替代人工渗透测试。",
        }

    def list_database(self) -> Dict[str, Any]:
        return {
            "db_size": len(PERMISSION_RISK_DB),
            "entries": [{"permission": k, **v} for k, v in
                        sorted(PERMISSION_RISK_DB.items())],
        }
