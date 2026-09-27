# -*- coding: utf-8 -*-
"""Android 危险权限识别与风险评分。"""
from __future__ import annotations

from typing import Any, Dict, List, Tuple

# 内置危险/高危权限表（分组 + 分值）
DANGEROUS_PERMS: Dict[str, Dict[str, Any]] = {
    "android.permission.READ_CONTACTS": {"group": "contacts", "score": 8, "label": "读取联系人"},
    "android.permission.WRITE_CONTACTS": {"group": "contacts", "score": 8, "label": "写入联系人"},
    "android.permission.GET_ACCOUNTS": {"group": "accounts", "score": 6, "label": "获取账户"},
    "android.permission.CAMERA": {"group": "camera", "score": 9, "label": "相机"},
    "android.permission.RECORD_AUDIO": {"group": "mic", "score": 9, "label": "麦克风"},
    "android.permission.ACCESS_FINE_LOCATION": {"group": "location", "score": 9, "label": "精确定位"},
    "android.permission.ACCESS_COARSE_LOCATION": {"group": "location", "score": 6, "label": "粗略定位"},
    "android.permission.ACCESS_BACKGROUND_LOCATION": {"group": "location", "score": 10, "label": "后台定位"},
    "android.permission.READ_PHONE_STATE": {"group": "phone", "score": 7, "label": "读取手机状态"},
    "android.permission.CALL_PHONE": {"group": "phone", "score": 8, "label": "直接拨号"},
    "android.permission.READ_CALL_LOG": {"group": "phone", "score": 8, "label": "读取通话记录"},
    "android.permission.SEND_SMS": {"group": "sms", "score": 9, "label": "发送短信"},
    "android.permission.READ_SMS": {"group": "sms", "score": 9, "label": "读取短信"},
    "android.permission.RECEIVE_SMS": {"group": "sms", "score": 9, "label": "接收短信"},
    "android.permission.WRITE_EXTERNAL_STORAGE": {"group": "storage", "score": 6, "label": "写外部存储"},
    "android.permission.READ_EXTERNAL_STORAGE": {"group": "storage", "score": 5, "label": "读外部存储"},
    "android.permission.READ_CALENDAR": {"group": "calendar", "score": 6, "label": "读取日历"},
    "android.permission.WRITE_CALENDAR": {"group": "calendar", "score": 6, "label": "写入日历"},
    "android.permission.BODY_SENSORS": {"group": "sensors", "score": 7, "label": "身体传感器"},
    "android.permission.READ_CALL_LOG": {"group": "phone", "score": 8, "label": "通话记录"},
    "android.permission.SYSTEM_ALERT_WINDOW": {"group": "system", "score": 7, "label": "悬浮窗"},
    "android.permission.WRITE_SECURE_SETTINGS": {"group": "system", "score": 10, "label": "写安全设置"},
    "android.permission.INSTALL_PACKAGES": {"group": "system", "score": 10, "label": "安装应用"},
}


class PermissionRiskAnalyzer:
    def analyze(self, permissions: List[str]) -> Dict[str, Any]:
        hits: List[Dict[str, Any]] = []
        total = 0
        for p in permissions:
            info = DANGEROUS_PERMS.get(p)
            if info:
                hits.append({"permission": p, **info})
                total += info["score"]
        # 评级
        if total >= 40:
            level = "高危"
        elif total >= 20:
            level = "中危"
        elif total > 0:
            level = "低危"
        else:
            level = "安全"
        return {
            "total_perms": len(permissions),
            "dangerous_count": len(hits),
            "dangerous_perms": hits,
            "risk_score": total,
            "risk_level": level,
        }
