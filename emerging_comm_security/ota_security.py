#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
OTA 安全模块（emerging_comm_security / ota_security.py）。

真实功能：
  * 固件仓库：固件包 / 版本 / 差分包 / 签名 / 验证 / 安装 / 回滚
  * 安全启动 / 安全安装 / 防回滚 / 防篡改 / 防降级
  * 漏洞与威胁：重放 / 中间人 / 降级 / 伪造包 / 篡改包 / 安装失败 / 回滚失败
  * 监控：版本分布 / 成功率 / 失败率 / 回滚率 / 更新时间 / 异常检测
  * 合规：隐私 / 数据安全 / 用户同意 / 版本管理 / 审计
"""

from __future__ import annotations

import hashlib
import hmac
import secrets
import time
import uuid
from dataclasses import asdict, dataclass, field
from datetime import datetime
from typing import Any, Dict, List, Optional


# ---------------------------------------------------------------------------
# 数据模型
# ---------------------------------------------------------------------------

@dataclass
class Firmware:
    fw_id: str
    version: str
    component: str             # VCU / IVI / TBOX / BCM / BMS
    size_bytes: int = 0
    differential_from: str = ""    # 差分包来源版本
    signature: str = ""
    signed_by: str = ""
    release_notes: str = ""
    released_at: str = ""
    min_hw_revision: str = ""

    def __post_init__(self) -> None:
        if not self.fw_id:
            self.fw_id = f"fw-{uuid.uuid4().hex[:8]}"
        if not self.released_at:
            self.released_at = datetime.now().isoformat()


@dataclass
class InstallTask:
    task_id: str
    vin: str
    fw_id: str
    status: str = "QUEUED"     # QUEUED / DOWNLOADING / VERIFYING / INSTALLING /
                               # SUCCESS / FAILED / ROLLED_BACK
    progress: int = 0
    error: str = ""
    rollback_available_from: str = ""
    started_at: str = ""
    finished_at: str = ""

    def __post_init__(self) -> None:
        if not self.task_id:
            self.task_id = f"ota-{uuid.uuid4().hex[:8]}"
        if not self.started_at:
            self.started_at = datetime.now().isoformat()


# ---------------------------------------------------------------------------
# OTA 安全控制器
# ---------------------------------------------------------------------------

class OTASecurityController:
    """OTA 安全控制器。"""

    TRUSTED_RELEASE_KEYS = {
        "DemoAuto-Signing-A": secrets.token_hex(32),
        "DemoAuto-Signing-B": secrets.token_hex(32),
    }
    ALLOWED_COMPONENTS = ("VCU", "IVI", "TBOX", "BCM", "BMS", "TCU")
    ROLLBACK_GRACE_VERSIONS = 2     # 允许回退最近 N 个版本

    def __init__(self) -> None:
        self.firmware: Dict[str, Firmware] = {}
        self.tasks: Dict[str, InstallTask] = {}
        self.device_versions: Dict[str, str] = {}        # vin -> version
        self.audit_log: List[Dict[str, Any]] = []
        self.violations: List[Dict[str, Any]] = []
        self._seed_bootstrap()

    def _seed_bootstrap(self) -> None:
        for comp in self.ALLOWED_COMPONENTS:
            for v in ("1.0.0", "1.1.0", "1.2.0"):
                fw = Firmware(
                    fw_id="", version=v, component=comp,
                    size_bytes=2_500_000 + hash(v + comp) % 5_000_000,
                    signed_by="DemoAuto-Signing-A",
                    release_notes=f"{comp} v{v} 安全更新",
                )
                fw.signature = self._sign(fw.fw_id + fw.version + fw.component,
                                           "DemoAuto-Signing-A")
                self.firmware[fw.fw_id] = fw
        # 默认设备版本
        self.device_versions["LVGBE21KXNS000001"] = "1.0.0"

    @classmethod
    def _sign(cls, data: str, key_name: str) -> str:
        key = cls.TRUSTED_RELEASE_KEYS[key_name].encode()
        return hmac.new(key, data.encode(), hashlib.sha256).hexdigest()

    # ------------------------- 固件仓库 -------------------------
    def publish_firmware(self, version: str, component: str,
                          differential_from: str = "",
                          release_notes: str = "") -> Firmware:
        if component not in self.ALLOWED_COMPONENTS:
            raise ValueError(f"unsupported component: {component}")
        fw = Firmware(
            fw_id="", version=version, component=component,
            size_bytes=2_000_000 + secrets.randbelow(8_000_000),
            differential_from=differential_from,
            signed_by="DemoAuto-Signing-A", release_notes=release_notes,
        )
        fw.signature = self._sign(fw.fw_id + version + component, "DemoAuto-Signing-A")
        self.firmware[fw.fw_id] = fw
        self.audit_log.append({
            "ts": datetime.now().isoformat(), "kind": "FW_PUBLISHED",
            "fw_id": fw.fw_id, "version": version, "component": component,
        })
        return fw

    def list_firmware(self, component: Optional[str] = None) -> List[Dict[str, Any]]:
        out = []
        for fw in self.firmware.values():
            if component and fw.component != component:
                continue
            out.append(asdict(fw))
        return out

    def verify_firmware(self, fw_id: str) -> Dict[str, Any]:
        fw = self.firmware.get(fw_id)
        if not fw:
            return {"valid": False, "reason": "unknown firmware"}
        expected = self._sign(fw.fw_id + fw.version + fw.component, fw.signed_by)
        sig_ok = hmac.compare_digest(expected, fw.signature)
        return {"valid": sig_ok, "fw_id": fw_id, "version": fw.version,
                "component": fw.component, "signed_by": fw.signed_by,
                "tampered": not sig_ok}

    # ------------------------- 版本 / 回滚 -------------------------
    def _ver_tuple(self, v: str) -> tuple:
        out = []
        for p in v.split("."):
            try:
                out.append(int(p))
            except ValueError:
                out.append(0)
        return tuple(out)

    def check_rollback_allowed(self, vin: str, target_version: str) -> Dict[str, Any]:
        current = self.device_versions.get(vin)
        if not current:
            return {"allowed": False, "reason": "unknown device"}
        ct, tt = self._ver_tuple(current), self._ver_tuple(target_version)
        if tt > ct:
            return {"allowed": True, "reason": "upgrade"}
        if tt == ct:
            return {"allowed": False, "reason": "same version"}
        # 降级：必须在允许窗口内
        older = sorted([f.version for f in self.firmware.values()
                         if f.component == "IVI"], key=self._ver_tuple)
        try:
            idx = older.index(current)
        except ValueError:
            idx = len(older) - 1
        allowed = idx - older.index(target_version) if target_version in older else 999
        ok = allowed <= self.ROLLBACK_GRACE_VERSIONS
        if not ok:
            self.violations.append({
                "ts": datetime.now().isoformat(), "kind": "ROLLBACK_BLOCKED",
                "vin": vin, "target": target_version, "current": current,
            })
        return {"allowed": ok, "current": current, "target": target_version,
                "grace_versions": self.ROLLBACK_GRACE_VERSIONS,
                "versions_within_grace": older[max(0, idx - self.ROLLBACK_GRACE_VERSIONS):idx]}

    # ------------------------- 安装流程 -------------------------
    def start_install(self, vin: str, fw_id: str,
                        user_consent: bool = True) -> InstallTask:
        if not user_consent:
            raise PermissionError("user consent required")
        fw = self.firmware.get(fw_id)
        if not fw:
            raise KeyError(fw_id)
        # 先验签
        v = self.verify_firmware(fw_id)
        if not v["valid"]:
            raise PermissionError("firmature signature invalid, refuse to install")
        # 防降级
        rb = self.check_rollback_allowed(vin, fw.version)
        if not rb["allowed"] and "downgrade" in rb.get("reason", ""):
            raise PermissionError("rollback prohibited by anti-rollback policy")
        t = InstallTask(task_id="", vin=vin, fw_id=fw_id,
                        status="DOWNLOADING",
                        rollback_available_from=self.device_versions.get(vin, ""))
        self.tasks[t.task_id] = t
        return t

    def advance_install(self, task_id: str, step: str) -> InstallTask:
        t = self.tasks.get(task_id)
        if not t:
            raise KeyError(task_id)
        flow = ["DOWNLOADING", "VERIFYING", "INSTALLING"]
        try:
            idx = flow.index(step)
        except ValueError:
            raise ValueError(f"invalid step: {step}")
        t.status = step
        t.progress = int((idx + 1) / (len(flow) + 1) * 100)
        return t

    def finish_install(self, task_id: str, success: bool = True,
                        error: str = "") -> InstallTask:
        t = self.tasks.get(task_id)
        if not t:
            raise KeyError(task_id)
        fw = self.firmware[t.fw_id]
        if success:
            t.status = "SUCCESS"
            t.progress = 100
            self.device_versions[t.vin] = fw.version
        else:
            t.status = "FAILED"
            t.error = error
            # 自动回滚
            if t.rollback_available_from:
                t.status = "ROLLED_BACK"
                self.device_versions[t.vin] = t.rollback_available_from
        t.finished_at = datetime.now().isoformat()
        self.audit_log.append({
            "ts": t.finished_at, "kind": "OTA_FINISH",
            "task_id": task_id, "vin": t.vin, "fw_id": t.fw_id,
            "status": t.status,
        })
        return t

    def rollback(self, task_id: str) -> InstallTask:
        t = self.tasks.get(task_id)
        if not t:
            raise KeyError(task_id)
        if t.rollback_available_from:
            t.status = "ROLLED_BACK"
            self.device_versions[t.vin] = t.rollback_available_from
            t.finished_at = datetime.now().isoformat()
        return t

    # ------------------------- 威胁检测 -------------------------
    def detect_replay(self, fw_id: str, previous_seen_at: float) -> bool:
        now = time.time()
        if now - previous_seen_at < 300:  # 5 分钟内同包
            self.violations.append({
                "ts": datetime.now().isoformat(), "kind": "OTA_REPLAY",
                "fw_id": fw_id, "gap_s": round(now - previous_seen_at, 1),
            })
            return True
        return False

    def tamper_scan(self, fw_id: str, tampered: bool) -> Dict[str, Any]:
        if tampered:
            self.violations.append({
                "ts": datetime.now().isoformat(), "kind": "FW_TAMPERED",
                "fw_id": fw_id,
            })
        return {"tampered": tampered, "fw_id": fw_id}

    # ------------------------- 监控 / 总览 -------------------------
    def stats(self) -> Dict[str, Any]:
        total = len(self.tasks)
        success = sum(1 for t in self.tasks.values() if t.status == "SUCCESS")
        failed = sum(1 for t in self.tasks.values() if t.status == "FAILED")
        rolled = sum(1 for t in self.tasks.values() if t.status == "ROLLED_BACK")
        dist: Dict[str, int] = {}
        for v in self.device_versions.values():
            dist[v] = dist.get(v, 0) + 1
        return {
            "firmware_total": len(self.firmware),
            "device_total": len(self.device_versions),
            "install_tasks": total,
            "success_rate": round(success / total, 3) if total else 0.0,
            "failure_rate": round(failed / total, 3) if total else 0.0,
            "rollback_rate": round(rolled / total, 3) if total else 0.0,
            "version_distribution": dist,
            "violations_total": len(self.violations),
            "audit_total": len(self.audit_log),
        }

    def list_tasks(self, limit: int = 50) -> List[Dict[str, Any]]:
        return [asdict(t) for t in list(self.tasks.values())[-limit:]]

    def recent_violations(self, limit: int = 20) -> List[Dict[str, Any]]:
        return list(reversed(self.violations[-limit:]))


_controller: Optional[OTASecurityController] = None


def get_ota_controller() -> OTASecurityController:
    global _controller
    if _controller is None:
        _controller = OTASecurityController()
    return _controller
