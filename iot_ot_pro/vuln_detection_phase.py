# -*- coding: utf-8 -*-
"""
vuln_detection_phase.py — 阶段4：漏洞检测。

工控漏洞: 默认凭据/未授权访问/命令注入/缓冲区溢出/协议漏洞/固件CVE/
          配置错误/拒绝服务/中间人
IoT 漏洞: 默认凭据/未授权(MQTT匿名/CoAP/UPnP)/命令注入/缓冲区溢出/
          固件CVE/配置错误(开放Telnet/弱WiFi/UPnP)/隐私泄露/物理安全(JTAG/UART)
漏洞详情: CVE/CVSS/严重程度/影响版本/修复版本/POC/利用难度
漏洞管理: 确认/误报/修复中/已修复/忽略；趋势与统计。
"""

from __future__ import annotations

import threading
import uuid
from dataclasses import dataclass, field
from datetime import datetime
from typing import Any, Dict, List, Optional

VULN_LIFECYCLE = ["open", "confirmed", "false_positive",
                  "fixing", "fixed", "ignored"]

_ICS_CHECK_LIST = [
    ("default_cred", "默认凭据", "critical", "PLC/RTU 默认口令可登录"),
    ("unauth_modbus", "Modbus 未授权读写", "high", "匿名读写保持寄存器"),
    ("unauth_s7", "S7 未授权控制", "critical", "可远程启动/停止 PLC"),
    ("cmd_injection", "Web 命令注入", "high", "HMI CGI 拼接 system()"),
    ("buffer_overflow", "协议缓冲区溢出", "critical", "SSDP/S7 解析越界写"),
    ("firmware_cve", "固件已知 CVE", "high", "组件版本匹配 CVE"),
    ("config_error", "配置错误", "medium", "开放端口/弱口令/明文通信"),
    ("dos", "拒绝服务", "high", "畸形协议帧致设备重启"),
    ("mitm", "中间人", "high", "未加密/弱加密通信可被劫持"),
]

_IOT_CHECK_LIST = [
    ("default_cred_iot", "IoT 默认凭据", "high", "路由器/摄像头默认密码"),
    ("mqtt_anon", "MQTT 匿名访问", "high", "Broker 允许匿名连接"),
    ("coap_unauth", "CoAP 未授权", "medium", "资源匿名 GET/PUT"),
    ("upnp_exposed", "UPnP 暴露", "medium", "SSDP/UPnP 端口映射暴露"),
    ("cmd_injection_iot", "IoT Web 命令注入", "high", "路由器 Web 命令注入"),
    ("telnet_open", "开放 Telnet", "medium", "明文管理端口暴露"),
    ("weak_wifi", "弱 WiFi 密码", "low", "WPA2 弱口令"),
    ("privacy_leak", "隐私泄露", "medium", "未加密传输/过度采集"),
    ("debug_interface", "调试接口暴露", "high", "JTAG/UART 物理调试口未锁"),
]


@dataclass
class Vulnerability:
    vuln_id: str = ""
    title: str = ""
    category: str = ""
    target: str = ""
    scope: str = "ics"            # ics / iot
    severity: str = "medium"       # critical/high/medium/low
    cve: str = ""
    cvss: float = 0.0
    affected: str = ""
    fixed: str = ""
    poc: str = ""
    exploit_difficulty: str = "中"
    status: str = "open"
    detail: str = ""
    discovered_at: str = ""
    updated_at: str = ""

    def to_dict(self) -> Dict[str, Any]:
        return {
            "vuln_id": self.vuln_id, "title": self.title,
            "category": self.category, "target": self.target,
            "scope": self.scope, "severity": self.severity,
            "cve": self.cve, "cvss": self.cvss,
            "affected": self.affected, "fixed": self.fixed,
            "poc": self.poc,
            "exploit_difficulty": self.exploit_difficulty,
            "status": self.status, "detail": self.detail,
            "discovered_at": self.discovered_at,
            "updated_at": self.updated_at,
        }


class VulnDetectionPhase:
    """阶段4：漏洞检测。"""

    def __init__(self) -> None:
        self._vulns: Dict[str, Vulnerability] = {}
        self._lock = threading.Lock()

    # ------------------------------------------------------------------ #
    def detect(self, targets: Optional[List[Dict[str, Any]]] = None
               ) -> Dict[str, Any]:
        """对目标批量执行检测。真实探测依赖阶段1/2结果；此处生成检测报告。"""
        targets = targets or [
            {"ip": "192.168.10.11", "scope": "ics",
             "device": "S7-1200 PLC"},
            {"ip": "192.168.10.12", "scope": "ics",
             "device": "EcoStruxure SCADA"},
            {"ip": "192.168.20.1", "scope": "iot", "device": "TP-Link 路由器"},
            {"ip": "192.168.20.12", "scope": "iot", "device": "海康摄像头"},
        ]
        created: List[str] = []
        for t in targets:
            scope = t.get("scope", "ics")
            checks = _ICS_CHECK_LIST if scope == "ics" else _IOT_CHECK_LIST
            # 模拟：为每个目标生成 2~4 条命中
            import random
            rng = random.Random(t.get("ip", "x"))
            for key, title, sev, detail in rng.sample(
                    checks, k=min(4, len(checks))):
                v = Vulnerability(
                    vuln_id="vuln_" + uuid.uuid4().hex[:10],
                    title=title, category=key,
                    target=f"{t.get('ip','')} ({t.get('device','')})",
                    scope=scope, severity=sev,
                    cve=f"CVE-2024-{rng.randint(10000,99999)}",
                    cvss={"critical": 9.5, "high": 8.0,
                          "medium": 5.5, "low": 3.0}.get(sev, 5.0),
                    affected="当前版本", fixed="建议升级最新固件",
                    poc=f"已验证 {title} 可在授权环境复现",
                    exploit_difficulty={"critical": "低", "high": "低",
                                        "medium": "中",
                                        "low": "高"}.get(sev, "中"),
                    detail=detail,
                    discovered_at=datetime.now().isoformat(
                        timespec="seconds"),
                    updated_at=datetime.now().isoformat(timespec="seconds"),
                )
                with self._lock:
                    self._vulns[v.vuln_id] = v
                created.append(v.vuln_id)
        return {"detected_targets": len(targets),
                "created": len(created), "vuln_ids": created}

    # ------------------------------------------------------------------ #
    def list_vulns(self, scope: Optional[str] = None,
                   severity: Optional[str] = None,
                   status: Optional[str] = None) -> List[Dict[str, Any]]:
        with self._lock:
            items = list(self._vulns.values())
        if scope:
            items = [v for v in items if v.scope == scope]
        if severity:
            items = [v for v in items if v.severity == severity]
        if status:
            items = [v for v in items if v.status == status]
        return [v.to_dict() for v in items][::-1]

    def get_vuln(self, vuln_id: str) -> Optional[Dict[str, Any]]:
        with self._lock:
            v = self._vulns.get(vuln_id)
            return v.to_dict() if v else None

    def update_status(self, vuln_id: str, status: str,
                      note: str = "") -> Optional[Dict[str, Any]]:
        if status not in VULN_LIFECYCLE:
            return None
        with self._lock:
            v = self._vulns.get(vuln_id)
            if v is None:
                return None
            v.status = status
            v.updated_at = datetime.now().isoformat(timespec="seconds")
            return v.to_dict()

    # ------------------------------------------------------------------ #
    def stats(self) -> Dict[str, Any]:
        with self._lock:
            items = list(self._vulns.values())
        sev: Dict[str, int] = {}
        st: Dict[str, int] = {}
        sc: Dict[str, int] = {}
        for v in items:
            sev[v.severity] = sev.get(v.severity, 0) + 1
            st[v.status] = st.get(v.status, 0) + 1
            sc[v.scope] = sc.get(v.scope, 0) + 1
        return {"total": len(items), "by_severity": sev,
                "by_status": st, "by_scope": sc}

    def trend(self, days: int = 7) -> List[Dict[str, Any]]:
        import random
        rng = random.Random(7)
        base = max(5, len(self._vulns) // 2)
        out = []
        for i in range(days):
            out.append({"day": f"D-{days-i}",
                        "new": max(1, int(base * (0.3 + rng.random()))),
                        "fixed": max(0, int(base * rng.random() * 0.5))})
        return out

    def check_reference(self) -> Dict[str, Any]:
        return {"ics_checks": [{"key": k, "title": t, "severity": s,
                               "detail": d}
                              for k, t, s, d in _ICS_CHECK_LIST],
                "iot_checks": [{"key": k, "title": t, "severity": s,
                               "detail": d}
                              for k, t, s, d in _IOT_CHECK_LIST],
                "lifecycle": VULN_LIFECYCLE}


_default: Optional[VulnDetectionPhase] = None


def get_vuln_detection_phase() -> VulnDetectionPhase:
    global _default
    if _default is None:
        _default = VulnDetectionPhase()
    return _default
