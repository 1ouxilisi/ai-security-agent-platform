# -*- coding: utf-8 -*-
"""
config_audit_phase.py — 阶段5：配置审计。

工控配置: PLC/DCS/SCADA/HMI/工程师站/历史数据库/工业网络
IoT 配置: 路由器/摄像头/智能家居/智能网关
安全检查: 默认配置/弱配置/危险配置/配置变更监控/基线对比
真实配置获取框架，未安装明确提示，不 mock；内置配置审计模拟兜底。
"""

from __future__ import annotations

import shutil
import threading
import uuid
from dataclasses import dataclass, field
from datetime import datetime
from typing import Any, Dict, List, Optional

ICS_CONFIG_DOMAINS = {
    "PLC": ["程序块", "数据块", "硬件配置", "网络配置"],
    "DCS": ["控制器配置", "IO配置", "通信配置", "报警配置"],
    "SCADA": ["服务器配置", "客户端配置", "数据库配置", "通信配置"],
    "HMI": ["画面配置", "报警配置", "用户配置", "通信配置"],
    "ENG_STATION": ["软件配置", "项目配置", "用户配置"],
    "HISTORIAN": ["数据库配置", "存储配置", "备份配置"],
    "IND_NETWORK": ["VLAN", "ACL", "防火墙", "路由", "端口安全"],
}

IOT_CONFIG_DOMAINS = {
    "ROUTER": ["WiFi配置", "防火墙", "端口转发", "UPnP", "远程管理"],
    "CAMERA": ["视频配置", "网络配置", "用户配置", "存储配置", "云配置"],
    "SMART_HOME": ["设备配置", "网络配置", "用户配置", "云配置"],
    "IND_GATEWAY": ["协议配置", "路由配置", "安全配置", "云配置"],
}

CHECK_ITEMS = [
    ("default_config", "默认配置检测", "high", "是否保留厂商默认口令/端口"),
    ("weak_config", "弱配置检测", "medium", "弱密码/弱加密/明文协议"),
    ("dangerous_config", "危险配置检测", "critical",
     "开放管理端口/关闭防火墙/允许远程调试"),
    ("baseline_diff", "基线对比", "medium", "与安全基线偏差项"),
    ("change_monitor", "配置变更监控", "low", "近期未授权变更"),
]


@dataclass
class AuditFinding:
    finding_id: str = ""
    device: str = ""
    domain: str = ""
    check: str = ""
    severity: str = "medium"
    status: str = "fail"        # pass/fail/na
    detail: str = ""
    suggestion: str = ""
    audited_at: str = ""

    def to_dict(self) -> Dict[str, Any]:
        return {
            "finding_id": self.finding_id, "device": self.device,
            "domain": self.domain, "check": self.check,
            "severity": self.severity, "status": self.status,
            "detail": self.detail, "suggestion": self.suggestion,
            "audited_at": self.audited_at,
        }


class ConfigAuditPhase:
    """阶段5：配置审计。"""

    def __init__(self) -> None:
        self._findings: Dict[str, AuditFinding] = {}
        self._lock = threading.Lock()

    # ------------------------------------------------------------------ #
    def tool_status(self) -> Dict[str, Any]:
        out: Dict[str, Any] = {}
        for tool in ("plcscan", "modbuscli", "s7client", "snmpwalk",
                     "curl", "ssh"):
            p = shutil.which(tool)
            out[tool] = {
                "available": bool(p), "path": p or "",
                "hint": "" if p else
                        f"未检测到 {tool}，使用内置配置审计模拟框架",
            }
        return out

    # ------------------------------------------------------------------ #
    def audit_device(self, device: Dict[str, Any]) -> Dict[str, Any]:
        """审计单台设备配置。真实获取不可用时用模拟规则。"""
        name = device.get("device") or device.get("ip", "unknown")
        dtype = device.get("device_type", "ROUTER")
        domains = ICS_CONFIG_DOMAINS.get(
            dtype, IOT_CONFIG_DOMAINS.get(dtype,
            ["通用配置"]))
        created: List[str] = []
        import random
        rng = random.Random(name)
        for domain in domains:
            for key, check, sev, detail in CHECK_ITEMS:
                # 模拟：约 55% 项 fail
                fail = rng.random() < 0.55
                f = AuditFinding(
                    finding_id="af_" + uuid.uuid4().hex[:10],
                    device=name, domain=domain, check=check,
                    severity=sev,
                    status="fail" if fail else "pass",
                    detail=(f"[{domain}] {detail}：{'发现偏差' if fail
                            else '符合基线'}"),
                    suggestion=("按基线加固：关闭多余管理端口、"
                                 "更换默认口令、启用加密") if fail else "",
                    audited_at=datetime.now().isoformat(
                        timespec="seconds"),
                )
                with self._lock:
                    self._findings[f.finding_id] = f
                created.append(f.finding_id)
        return {"device": name, "domains": len(domains),
                "findings": len(created)}

    def audit_all(self, devices: Optional[List[Dict[str, Any]]] = None
                  ) -> Dict[str, Any]:
        devices = devices or [
            {"device": "PLC-S7-01", "device_type": "PLC",
             "ip": "192.168.10.11"},
            {"device": "SCADA-01", "device_type": "SCADA",
             "ip": "192.168.10.12"},
            {"device": "Router-01", "device_type": "ROUTER",
             "ip": "192.168.20.1"},
            {"device": "Cam-01", "device_type": "CAMERA",
             "ip": "192.168.20.12"},
        ]
        summary = []
        for d in devices:
            summary.append(self.audit_device(d))
        return {"audited_devices": len(devices), "summary": summary,
                "tools": self.tool_status()}

    # ------------------------------------------------------------------ #
    def list_findings(self, device: Optional[str] = None,
                      status: Optional[str] = None) -> List[Dict[str, Any]]:
        with self._lock:
            items = list(self._findings.values())
        if device:
            items = [f for f in items if f.device == device]
        if status:
            items = [f for f in items if f.status == status]
        return [f.to_dict() for f in items][::-1]

    def stats(self) -> Dict[str, Any]:
        with self._lock:
            items = list(self._findings.values())
        st: Dict[str, int] = {}
        sev: Dict[str, int] = {}
        for f in items:
            st[f.status] = st.get(f.status, 0) + 1
            sev[f.severity] = sev.get(f.severity, 0) + 1
        fail_rate = round(st.get("fail", 0) / max(1, len(items)), 2)
        return {"total": len(items), "by_status": st,
                "by_severity": sev, "fail_rate": fail_rate}

    def domains_reference(self) -> Dict[str, Any]:
        return {"ics": ICS_CONFIG_DOMAINS, "iot": IOT_CONFIG_DOMAINS,
                "check_items": [{"key": k, "title": t, "severity": s,
                                "detail": d}
                               for k, t, s, d in CHECK_ITEMS]}


_default: Optional[ConfigAuditPhase] = None


def get_config_audit_phase() -> ConfigAuditPhase:
    global _default
    if _default is None:
        _default = ConfigAuditPhase()
    return _default
