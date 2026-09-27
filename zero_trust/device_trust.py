# -*- coding: utf-8 -*-
"""
device_trust.py — 设备安全与终端信任评估器（第13轮升级 · 零信任模块）。

功能：
- 设备合规检查：操作系统版本 / 补丁级别 / 安全配置 / 密码策略 / 屏幕锁定 /
  磁盘加密 / 防火墙
- 终端防护(EDR)：EDR 覆盖率 / 防护状态 / 威胁检测 / 响应能力 / 离线设备 /
  未受管设备
- 越狱/Root 检测：移动设备越狱 / Root 检测 / 调试模式 / 开发者选项 / 侧载应用
- 设备指纹：硬件指纹 / 软件指纹 / 浏览器指纹 / 设备唯一性 / 设备克隆检测
- 信任级别评估：基于合规性 / 防护状态 / 风险历史的设备信任级别
  （可信 / 受限 / 不可信）
- BYOD 安全：个人设备访问 / 容器化 / 数据隔离 / MDM 管理 / 远程擦除 /
  个人隐私保护
- 设备准入控制：设备准入策略 / 不合规设备隔离 / 访客设备 / 物联网设备
- 设备信任报告

说明：仅基于模拟设备清单做合规评估，不实际安装 agent、不读取终端数据。
"""

from __future__ import annotations

import hashlib
import random
from datetime import datetime
from typing import Any, Dict, List, Optional


# ==================== 设备类型与合规基线 ====================

OS_COMPLIANCE_BASELINE: Dict[str, Dict[str, Any]] = {
    "Windows 11":  {"latest_build": "23H2", "patch_critical_days": 7,  "encryption": "BitLocker"},
    "Windows 10":  {"latest_build": "22H2", "patch_critical_days": 7,  "encryption": "BitLocker"},
    "macOS":       {"latest_build": "Sonoma", "patch_critical_days": 14, "encryption": "FileVault"},
    "Ubuntu":      {"latest_build": "24.04 LTS", "patch_critical_days": 14, "encryption": "LUKS"},
    "iOS":         {"latest_build": "17.x", "patch_critical_days": 7,  "encryption": "APFS"},
    "Android":     {"latest_build": "14",   "patch_critical_days": 30, "encryption": "File-Based"},
}

TRUST_LEVEL_RULES = {
    "trusted":   {"min_score": 80, "color": "green",  "desc": "全量访问企业资源"},
    "restricted": {"min_score": 50, "color": "yellow", "desc": "仅允许 Web 访问，禁止本地缓存"},
    "untrusted": {"min_score": 0,  "color": "red",    "desc": "隔离至访客网络"},
}

# 设备类型分类
DEVICE_TYPES = ["laptop", "desktop", "mobile", "tablet", "iot", "server"]


# ==================== 主评估器 ====================

class DeviceTrustManager:
    """设备安全与终端信任评估器（评估视角）。"""

    def __init__(self) -> None:
        self.inventory: List[Dict[str, Any]] = []
        self._seed_inventory()

    def _seed_inventory(self) -> None:
        rng = random.Random(1305)
        oses = list(OS_COMPLIANCE_BASELINE.keys())
        for i in range(1, 51):
            os_name = rng.choice(oses)
            self.inventory.append({
                "device_id": f"dev-{i:04d}",
                "hostname": f"host-{i:04d}",
                "owner": f"user{rng.randint(1, 40):04d}",
                "type": rng.choice(DEVICE_TYPES),
                "os": os_name,
                "os_version": OS_COMPLIANCE_BASELINE[os_name]["latest_build"],
                "patched": rng.random() > 0.15,
                "patch_age_days": rng.randint(0, 120),
                "edr_installed": rng.random() > 0.2,
                "edr_running": rng.random() > 0.1,
                "disk_encrypted": rng.random() > 0.2,
                "firewall_on": rng.random() > 0.1,
                "screen_lock": rng.random() > 0.15,
                "jailbroken": False if os_name not in ("iOS", "Android") else rng.random() < 0.08,
                "rooted": False if os_name != "Android" else rng.random() < 0.08,
                "debug_mode": rng.random() < 0.1,
                "sideloaded": rng.random() < 0.15,
                "managed": rng.random() > 0.2,
                "byod": rng.random() < 0.3,
                "online": rng.random() > 0.1,
            })

    # ---------- 合规检查 ----------

    def compliance_check(self, device_id: Optional[str] = None) -> Dict[str, Any]:
        """单设备或全量合规检查。"""
        targets = [d for d in self.inventory if (not device_id or d["device_id"] == device_id)]
        results: List[Dict[str, Any]] = []
        for d in targets:
            fails: List[str] = []
            if not d["patched"]:
                fails.append("关键补丁缺失")
            if d["patch_age_days"] > 60:
                fails.append(f"补丁 {d['patch_age_days']} 天未更新")
            if not d["disk_encrypted"]:
                fails.append("磁盘未加密")
            if not d["firewall_on"]:
                fails.append("防火墙关闭")
            if not d["screen_lock"]:
                fails.append("无屏幕锁")
            if d["jailbroken"] or d["rooted"]:
                fails.append("设备已越狱/Root")
            results.append({
                "device_id": d["device_id"], "hostname": d["hostname"],
                "os": d["os"], "compliant": len(fails) == 0,
                "fails": fails, "owner": d["owner"],
            })
        compliant = sum(1 for r in results if r["compliant"])
        return {
            "checked": len(results),
            "compliant": compliant,
            "non_compliant": len(results) - compliant,
            "compliance_pct": round(compliant / len(results) * 100, 1) if results else 0,
            "devices": results,
            "baseline": OS_COMPLIANCE_BASELINE,
        }

    # ---------- EDR ----------

    def edr_status(self) -> Dict[str, Any]:
        total = len(self.inventory)
        installed = [d for d in self.inventory if d["edr_installed"]]
        running = [d for d in installed if d["edr_running"]]
        unmanaged = [d for d in self.inventory if not d["managed"]]
        offline = [d for d in self.inventory if not d["online"]]
        return {
            "total_devices": total,
            "edr_installed": len(installed),
            "edr_running": len(running),
            "edr_coverage_pct": round(len(installed) / total * 100, 1),
            "edr_healthy_pct": round(len(running) / total * 100, 1),
            "unmanaged_devices": len(unmanaged),
            "offline_devices": len(offline),
            "threat_detections_30d": 14,
            "response_capability": {
                "isolation": True, "quarantine": True,
                "root_cause_analysis": True, "edr_soar": False,
            },
            "recommendations": [
                f"为 {len(unmanaged)} 台未受管设备安装 EDR/MDM agent",
                f"{len(offline)} 台离线设备超过 7 天未连接，应隔离",
                "将 EDR 告警接入 SOAR 实现自动响应",
            ],
        }

    # ---------- 越狱/Root ----------

    def jailbreak_root_detect(self) -> Dict[str, Any]:
        mobile = [d for d in self.inventory if d["os"] in ("iOS", "Android")]
        flagged = [d for d in self.inventory if d["jailbroken"] or d["rooted"]
                   or d["debug_mode"] or d["sideloaded"]]
        return {
            "mobile_devices": len(mobile),
            "flagged": [
                {"device_id": d["device_id"], "os": d["os"],
                 "jailbroken": d["jailbroken"], "rooted": d["rooted"],
                 "debug_mode": d["debug_mode"], "sideloaded": d["sideloaded"],
                 "owner": d["owner"]}
                for d in flagged
            ],
            "flagged_count": len(flagged),
            "policy": {
                "block_jailbreak": True,
                "block_debug_mode": True,
                "block_sideload_outside_enterprise_store": True,
            },
        }

    # ---------- 设备指纹 ----------

    def device_fingerprint(self, device_id: str = "dev-0001") -> Dict[str, Any]:
        d = next((x for x in self.inventory if x["device_id"] == device_id), None)
        seed = hashlib.sha256(device_id.encode()).hexdigest()
        return {
            "device_id": device_id,
            "hardware_fingerprint": seed[:16],
            "software_fingerprint": hashlib.sha256((seed + "sw").encode()).hexdigest()[:16],
            "browser_fingerprint": hashlib.sha256((seed + "br").encode()).hexdigest()[:16],
            "uniqueness": 98.5,
            "clone_detected": False,
            "hostname": d["hostname"] if d else "unknown",
            "os": d["os"] if d else "unknown",
        }

    # ---------- 信任级别 ----------

    def trust_level(self, device_id: str) -> Dict[str, Any]:
        d = next((x for x in self.inventory if x["device_id"] == device_id), None)
        if not d:
            return {"error": "设备不存在"}
        score = 100
        if not d["patched"]:
            score -= 15
        if not d["edr_installed"]:
            score -= 20
        elif not d["edr_running"]:
            score -= 10
        if not d["disk_encrypted"]:
            score -= 10
        if not d["firewall_on"]:
            score -= 8
        if not d["screen_lock"]:
            score -= 5
        if d["jailbroken"] or d["rooted"]:
            score -= 40
        if not d["managed"]:
            score -= 10
        score = max(0, min(100, score))
        level = "trusted" if score >= 80 else ("restricted" if score >= 50 else "untrusted")
        return {
            "device_id": device_id, "hostname": d["hostname"],
            "trust_score": score, "trust_level": level,
            "policy": TRUST_LEVEL_RULES[level],
        }

    # ---------- BYOD ----------

    def byod_assessment(self) -> Dict[str, Any]:
        byod = [d for d in self.inventory if d["byod"]]
        return {
            "byod_devices": len(byod),
            "total_devices": len(self.inventory),
            "byod_ratio_pct": round(len(byod) / len(self.inventory) * 100, 1),
            "capabilities": {
                "work_profile_container": True,
                "data_isolation": True,
                "remote_wipe": True,
                "personal_app_exclusion": True,
                "privacy_presence": True,
            },
            "findings": [
                {"severity": "medium", "desc": "BYOD 设备未强制工作资料区隔离，存在数据泄露风险"},
                {"severity": "low", "desc": "个人应用列表未采集，隐私策略已声明但技术上未隔离"},
            ],
            "recommendations": [
                "BYOD 强制 Android Work Profile / iOS User Enrollment",
                "远程擦除仅擦工作区，保留个人数据",
                "禁止 BYOD 访问高敏感数据库",
            ],
        }

    # ---------- 准入控制 ----------

    def admission_control(self) -> Dict[str, Any]:
        non_compliant = self.compliance_check()["non_compliant"]
        return {
            "policy": {
                "pre_admission_check": True,
                "continuous_check": True,
                "quarantine_vlan": True,
                "guest_network": True,
                "iot_isolated": True,
            },
            "non_compliant_blocked": non_compliant,
            "guest_devices": 12,
            "iot_devices": 8,
            "recommendations": [
                "不合规设备自动划入隔离 VLAN",
                "访客设备限制互联网访问，禁止内网路由",
                "IoT 设备按类型做指纹白名单准入",
            ],
        }

    # ---------- 清单 ----------

    def list_inventory(self) -> List[Dict[str, Any]]:
        return [
            {"device_id": d["device_id"], "hostname": d["hostname"], "owner": d["owner"],
             "type": d["type"], "os": d["os"], "managed": d["managed"],
             "online": d["online"], "byod": d["byod"]}
            for d in self.inventory
        ]

    # ---------- 综合报告 ----------

    def full_report(self) -> Dict[str, Any]:
        comp = self.compliance_check()
        edr = self.edr_status()
        jb = self.jailbreak_root_detect()
        byod = self.byod_assessment()
        adm = self.admission_control()
        score = int(round(
            comp["compliance_pct"] * 0.35
            + edr["edr_healthy_pct"] * 0.25
            + max(0, 100 - jb["flagged_count"] * 20) * 0.2
            + 80 * 0.2
        ))
        score = max(0, min(100, score))
        return {
            "report_title": "设备安全与终端信任报告",
            "generated_at": datetime.now().isoformat(),
            "overall_score": score,
            "compliance": comp,
            "edr": edr,
            "jailbreak_root": jb,
            "byod": byod,
            "admission": adm,
            "summary": (
                f"共 {len(self.inventory)} 台设备；合规率 {comp['compliance_pct']}%；"
                f"EDR 健康率 {edr['edr_healthy_pct']}%；"
                f"越狱/Root 标记 {jb['flagged_count']} 台；"
                f"BYOD 占比 {byod['byod_ratio_pct']}%。"
            ),
        }


# ==================== 工厂函数 ====================

_dt_singleton: Optional[DeviceTrustManager] = None


def get_device_trust_manager() -> DeviceTrustManager:
    global _dt_singleton
    if _dt_singleton is None:
        _dt_singleton = DeviceTrustManager()
    return _dt_singleton
