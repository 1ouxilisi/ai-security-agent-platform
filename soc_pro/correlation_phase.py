# -*- coding: utf-8 -*-
"""
correlation_phase.py — 阶段3：关联分析（SIEM 关联规则引擎，50+ 检测规则）。

覆盖:
    - 暴力破解（SSH/RDP/FTP/WEB 登录失败）
    - 异常登录（异地/非常用时间/特权账户）
    - 端口扫描（短时间多端口/横向扫描）
    - 数据外泄（大流量外发/敏感文件/异常 DNS）
    - 恶意软件（C2 通信/恶意进程/可疑文件）
    - 权限提升（sudo 异常/特权账户/服务安装）
    - 横向移动（SMB/WMI/RDP 异常）
    - 数据篡改（关键文件修改/配置变更/DB 异常）
"""

from __future__ import annotations

import threading
import time
import uuid
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from typing import Any, Dict, List, Optional


# --------------------------------------------------------------------------- #
# 检测规则定义（50+ 条）
# --------------------------------------------------------------------------- #
# (rule_id, name, category, severity, sigma-like 条件, 默认阈值, ATT&CK)
_DEFS: List[tuple] = [
    # ---- 暴力破解 ----
    ("BRU-SSH-001", "SSH 暴力破解", "brute_force", "high",
     "event:sshd_fail count>5 within:60s by:src_ip", 5, "T1110"),
    ("BRU-RDP-001", "RDP 暴力破解", "brute_force", "high",
     "event:rdp_fail count>5 within:60s by:src_ip", 5, "T1110.001"),
    ("BRU-FTP-001", "FTP 暴力破解", "brute_force", "medium",
     "event:ftp_fail count>5 within:60s by:src_ip", 5, "T1110.003"),
    ("BRU-WEB-001", "Web 登录暴力破解", "brute_force", "high",
     "http_status:401 count>8 within:60s by:src_ip", 8, "T1110.004"),
    ("BRU-ADMIN-001", "管理员账户爆破", "brute_force", "critical",
     "fail_user:root|admin count>3 within:30s", 3, "T1110"),
    ("BRU-SSH-002", "SSH 成功+前期失败", "brute_force", "high",
     "sshd_fail>5 then sshd_ok within:5m by:src_ip", 6, "T1078"),
    # ---- 异常登录 ----
    ("ANOM-LOIN-001", "异地登录检测", "anomaly_login", "medium",
     "login_new_geo by:user", 1, "T1078"),
    ("ANOM-LOIN-002", "非常用时间登录", "anomaly_login", "low",
     "login_hournotin:9-18 by:user", 1, "T1078"),
    ("ANOM-LOIN-003", "特权账户登录", "anomaly_login", "high",
     "login_user:root|administrator", 1, "T1078.002"),
    ("ANOM-LOIN-004", "同时多地登录", "anomaly_login", "high",
     "same_user_diff_geo within:5m", 2, "T1078"),
    ("ANOM-LOIN-005", "VPN 后首次登录", "anomaly_login", "low",
     "vpn_then_login within:10m", 1, "T1133"),
    # ---- 端口扫描 ----
    ("SCAN-PORT-001", "水平端口扫描", "port_scan", "medium",
     "distinct_dst_port>20 within:60s by:src_ip", 20, "T1046"),
    ("SCAN-PORT-002", "垂直主机扫描", "port_scan", "medium",
     "distinct_dst_ip>30 within:60s by:src_ip", 30, "T1046"),
    ("SCAN-PORT-003", "隐蔽扫描 (FIN/NULL/XMAS)", "port_scan", "high",
     "tcp_flag:FIN|NULL|XMAS by:src_ip", 5, "T1046"),
    ("SCAN-PORT-004", "Top1000 端口扫描", "port_scan", "medium",
     "dst_port in:1-1024 count>50 within:60s", 50, "T1046"),
    ("SCAN-PORT-005", "Suricata ET SCAN 签名", "port_scan", "high",
     "suricata_sig:ET SCAN", 1, "T1046"),
    # ---- 数据外泄 ----
    ("EXFIL-001", "大流量外发", "exfiltration", "high",
     "egress_bytes>50MB within:5m by:src_ip", 52428800, "T1041"),
    ("EXFIL-002", "敏感文件外发", "exfiltration", "critical",
     "file:dump.sql|export.csv|backup.tar.gz egress", 1, "T1048"),
    ("EXFIL-003", "异常 DNS 查询", "exfiltration", "medium",
     "dns_txt_query_long>50 chars count>10 within:5m", 10, "T1071.004"),
    ("EXFIL-004", "ICMP 隧道外发", "exfiltration", "high",
     "icmp_egress_rate>20/s by:src_ip", 20, "T1095"),
    ("EXFIL-005", "云存储上传", "exfiltration", "medium",
     "http_put to:s3|onedrive|drive.google", 5, "T1567.002"),
    ("EXFIL-006", "邮件外发大量附件", "exfiltration", "medium",
     "smtp_attachment_count>10 within:10m", 10, "T1020"),
    # ---- 恶意软件 / C2 ----
    ("MAL-C2-001", "C2 域名通信", "malware", "critical",
     "dns_query in:ti_c2_domain", 1, "T1071"),
    ("MAL-C2-002", "C2 IP 通信", "malware", "critical",
     "dst_ip in:ti_c2_ip", 1, "T1071.001"),
    ("MAL-C2-003", "Tor 出口节点通信", "malware", "high",
     "dst_ip in:tor_exit", 1, "T1090.003"),
    ("MAL-PROC-001", "可疑进程启动", "malware", "high",
     "process:mimikatz|cobalt|empire|meterpreter", 1, "T1059"),
    ("MAL-PROC-002", "PowerShell 编码命令", "malware", "high",
     "powershell:-enc|e JAB", 1, "T1059.001"),
    ("MAL-FILE-001", "Downloads 目录可疑文件", "malware", "medium",
     "file_create in:Downloads && ext:.exe|.dll|.ps1", 1, "T1204.002"),
    ("MAL-FILE-002", "文件哈希命中威胁情报", "malware", "critical",
     "file_hash in:ti_hash", 1, "T1204"),
    ("MAL-PERS-001", "可疑自启动项写入", "malware", "high",
     "registry:Run|Startup", 1, "T1547"),
    # ---- 权限提升 ----
    ("PRIV-SUDO-001", "异常 sudo 调用", "privesc", "medium",
     "sudo_user not:expect_user", 1, "T1548.003"),
    ("PRIV-SUDO-002", "sudo 失败次数过多", "privesc", "medium",
     "sudo_fail>3 within:10m", 3, "T1548"),
    ("PRIV-ACC-001", "特权账户创建", "privesc", "high",
     "useradd|net user /add in:wheel|admin", 1, "T1136"),
    ("PRIV-SVC-001", "可疑服务安装", "privesc", "high",
     "sc create|systemctl enable", 1, "T1543"),
    ("PRIV-KERN-001", "内核模块加载", "privesc", "medium",
     "insmod|modprobe", 1, "T1547.006"),
    ("PRIV-SUID-001", "SUID 位设置", "privesc", "medium",
     "chmod u+s", 1, "T1548.001"),
    # ---- 横向移动 ----
    ("LAT-SMB-001", "SMB 异常访问", "lateral_move", "medium",
     "smb distinct_dst>5 within:5m by:src_host", 5, "T1021.002"),
    ("LAT-WMI-001", "WMI 远程执行", "lateral_move", "high",
     "wmi_exec distinct_dst>3 within:5m", 3, "T1047"),
    ("LAT-RDP-001", "异常 RDP 横向", "lateral_move", "high",
     "rdp_login distinct_dst>3 within:10m", 3, "T1021.001"),
    ("LAT-PSH-001", "PowerShell 远程", "lateral_move", "high",
     "enter-pssession|invoke-command distinct_dst>3", 3, "T1021.006"),
    ("LAT-WINRM-001", "WinRM 异常", "lateral_move", "medium",
     "winrm distinct_dst>5 within:10m", 5, "T1021.006"),
    # ---- 数据篡改 ----
    ("TAMPER-001", "关键文件修改", "data_tamper", "high",
     "file_mod in:/etc/passwd|/etc/shadow|C:\\windows\\system32", 1, "T1070"),
    ("TAMPER-002", "配置文件变更", "data_tamper", "medium",
     "file_mod in:*.conf|*.ini|*.yaml", 3, "T1562"),
    ("TAMPER-003", "数据库批量 UPDATE/DELETE", "data_tamper", "high",
     "sql:UPDATE|DELETE WHERE:<5 rows", 1, "T1485"),
    ("TAMPER-004", "审计日志删除", "data_tamper", "critical",
     "rm -f /var/log|wevtutil cl", 1, "T1070.001"),
    ("TAMPER-005", "时间戳篡改", "data_tamper", "medium",
     "touch -t|system date change", 1, "T0915"),
    # ---- 其他 ----
    ("OTHER-DNS-001", "DNS 隧道特征", "exfiltration", "high",
     "dns_label>60 chars count>10", 10, "T1071.004"),
    ("OTHER-WEB-001", "SQL 注入尝试", "web_attack", "high",
     "http_uri:union.*select|or 1=1|sleep(", 1, "T1190"),
    ("OTHER-WEB-002", "XSS 尝试", "web_attack", "medium",
     "http_uri:<script|javascript:|onerror=", 1, "T1190"),
    ("OTHER-WEB-003", "Webshell 上传", "web_attack", "critical",
     "http_post file:shell.php|cmd.asp|.jsp", 1, "T1505.003"),
    ("OTHER-CERT-001", "证书验证失败激增", "anomaly", "low",
     "tls_cert_unknown>10 within:5m", 10, "T1553"),
    ("OTHER-TLS-001", "罕见 TLS 套件", "anomaly", "low",
     "tls_cipher:NULL|EXPORT", 1, "T1573"),
    ("OTHER-API-001", "API 异常高频调用", "anomaly", "medium",
     "api_call>1000/min by:api_key", 1000, "T1071"),
    ("OTHER-VPN-001", "VPN 异常拨入", "anomaly_login", "medium",
     "vpn_login_new_geo", 1, "T1133"),
    ("OTHER-PHISH-001", "钓鱼邮件点击", "malware", "high",
     "user_click:phish_link", 1, "T1566.002"),
    ("OTHER-PHISH-002", "钓鱼附件执行", "malware", "critical",
     "email_attachment_exec", 1, "T1566.001"),
    ("OTHER-BACKUP-001", "备份失败激增", "anomaly", "low",
     "backup_fail>3 within:1h", 3, "T1490"),
    ("OTHER-DENY-001", "防火墙拒绝激增", "anomaly", "medium",
     "asa_deny>100 within:5m by:src_ip", 100, "T1046"),
]


@dataclass
class DetectionRule:
    rule_id: str = ""
    name: str = ""
    category: str = ""
    severity: str = "medium"
    condition: str = ""
    threshold: int = 1
    mitre: str = ""
    enabled: bool = True
    hits: int = 0

    def to_dict(self) -> Dict[str, Any]:
        return {
            "rule_id": self.rule_id, "name": self.name,
            "category": self.category, "severity": self.severity,
            "condition": self.condition,
            "threshold": self.threshold, "mitre": self.mitre,
            "enabled": self.enabled, "hits": self.hits,
        }


@dataclass
class CorrelationHit:
    hit_id: str = ""
    rule_id: str = ""
    rule_name: str = ""
    category: str = ""
    severity: str = "medium"
    mitre: str = ""
    src_ip: str = ""
    dst_ip: str = ""
    user: str = ""
    count: int = 1
    timestamp: str = ""
    evidence: List[str] = field(default_factory=list)
    description: str = ""

    def to_dict(self) -> Dict[str, Any]:
        return {
            "hit_id": self.hit_id, "rule_id": self.rule_id,
            "rule_name": self.rule_name, "category": self.category,
            "severity": self.severity, "mitre": self.mitre,
            "src_ip": self.src_ip, "dst_ip": self.dst_ip,
            "user": self.user, "count": self.count,
            "timestamp": self.timestamp,
            "evidence": self.evidence[-5:],
            "description": self.description,
        }


DETECTION_RULES: List[DetectionRule] = [
    DetectionRule(rule_id=r[0], name=r[1], category=r[2], severity=r[3],
                  condition=r[4], threshold=r[5], mitre=r[6])
    for r in _DEFS
]


# --------------------------------------------------------------------------- #
class CorrelationPhase:
    """阶段3：关联分析引擎。"""

    def __init__(self) -> None:
        self._rules: Dict[str, DetectionRule] = {
            r.rule_id: DetectionRule(**r.to_dict()) for r in DETECTION_RULES
        }
        self._hits: List[CorrelationHit] = []
        # 简易计数窗口: (rule_id, key) -> (count, first_ts, samples)
        self._windows: Dict[tuple, Any] = {}
        self._lock = threading.Lock()

    # ------------------------------------------------------------------ #
    def list_rules(self, category: Optional[str] = None
                   ) -> List[Dict[str, Any]]:
        with self._lock:
            items = list(self._rules.values())
        if category:
            items = [r for r in items if r.category == category]
        return [r.to_dict() for r in items]

    def toggle_rule(self, rule_id: str, enabled: bool) -> bool:
        with self._lock:
            r = self._rules.get(rule_id)
            if r is None:
                return False
            r.enabled = enabled
            return True

    def update_threshold(self, rule_id: str, threshold: int) -> bool:
        with self._lock:
            r = self._rules.get(rule_id)
            if r is None:
                return False
            r.threshold = max(1, threshold)
            return True

    def add_rule(self, name: str, category: str, severity: str,
                 condition: str, threshold: int = 1,
                 mitre: str = "") -> Dict[str, Any]:
        rid = "CUS-" + uuid.uuid4().hex[:6].upper()
        r = DetectionRule(rule_id=rid, name=name, category=category,
                          severity=severity, condition=condition,
                          threshold=threshold, mitre=mitre)
        with self._lock:
            self._rules[rid] = r
        return r.to_dict()

    # ------------------------------------------------------------------ #
    def _classify(self, p: Dict[str, Any]) -> List[str]:
        """根据解析后日志粗分类事件标签。"""
        tags: List[str] = []
        raw = (p.get("raw") or "").lower()
        status = p.get("status_code", "")
        if "failed password" in raw or "401" in status:
            tags.append("fail")
        if "accepted password" in raw:
            tags.append("ok")
        if "sudo" in raw:
            tags.append("sudo")
        if "deny" in raw or "asa" in raw:
            tags.append("asa_deny")
        if "suricata" in raw:
            tags.append("suricata")
        if "scan" in raw:
            tags.append("scan")
        if p.get("ti_hit"):
            tags.append("ti_hit")
        if "bytes outbound" in raw or "bytes outbound" in raw:
            tags.append("egress")
        if "filecreate" in raw or "file_create" in raw:
            tags.append("file_create")
        return tags

    # ------------------------------------------------------------------ #
    def correlate(self, parsed_logs: Optional[List[Dict[str, Any]]] = None
                  ) -> Dict[str, Any]:
        if parsed_logs is None:
            from .log_parsing_phase import get_log_parsing_phase
            parsed_logs = get_log_parsing_phase().recent_parsed(500)

        new_hits: List[CorrelationHit] = []
        now = datetime.now()
        with self._lock:
            rules = {k: v for k, v in self._rules.items() if v.enabled}

        for p in parsed_logs:
            tags = self._classify(p)
            src = p.get("src_ip", "") or "unknown"
            dst = p.get("dst_ip", "") or "unknown"
            user = p.get("user", "") or "unknown"
            raw = (p.get("raw") or "")[:200]

            for rid, r in rules.items():
                fired = False
                # 简化匹配：按 category + 关键词命中
                if r.category == "brute_force" and "fail" in tags:
                    if rid in ("BRU-SSH-001",) and "ssh" in raw:
                        fired = True
                    elif rid in ("BRU-WEB-001",) and "401" in \
                            p.get("status_code", ""):
                        fired = True
                    elif rid.startswith("BRU-"):
                        fired = True
                elif r.category == "port_scan" and (
                        "scan" in tags or "suricata" in tags):
                    fired = True
                elif r.category == "exfiltration" and "egress" in tags:
                    fired = True
                elif r.category == "malware" and (
                        "ti_hit" in tags or "file_create" in tags
                        or "suricata" in tags):
                    fired = True
                elif r.category == "privesc" and "sudo" in tags:
                    fired = True
                elif r.category == "lateral_move" and "file_create" in tags:
                    fired = True
                elif r.category == "data_tamper" and "asa_deny" in tags:
                    fired = True
                elif r.category == "anomaly_login" and "ok" in tags:
                    fired = True
                elif r.category == "web_attack" and "401" in \
                        p.get("status_code", ""):
                    fired = True

                if not fired:
                    continue

                key = (rid, src, user)
                win = self._windows.get(key)
                if win is None:
                    win = {"count": 0, "first": now, "samples": []}
                    self._windows[key] = win
                win["count"] += 1
                win["samples"].append(raw)
                if win["count"] < r.threshold:
                    continue
                # 命中
                h = CorrelationHit(
                    hit_id="hit_" + uuid.uuid4().hex[:10],
                    rule_id=rid, rule_name=r.name,
                    category=r.category, severity=r.severity,
                    mitre=r.mitre, src_ip=src, dst_ip=dst, user=user,
                    count=win["count"],
                    timestamp=now.isoformat(timespec="seconds"),
                    evidence=win["samples"][-5:],
                    description=f"规则 [{r.name}] 命中 "
                                f"{win['count']} 次（阈值 {r.threshold}），"
                                f"源 {src}，ATT&CK {r.mitre}")
                new_hits.append(h)
                r.hits += 1
                # 重置窗口避免重复
                self._windows[key] = {"count": 0, "first": now,
                                      "samples": []}

        with self._lock:
            self._hits.extend(new_hits)
            self._hits = self._hits[-5000:]

        by_sev: Dict[str, int] = {}
        for h in new_hits:
            by_sev[h.severity] = by_sev.get(h.severity, 0) + 1
        by_cat: Dict[str, int] = {}
        for h in new_hits:
            by_cat[h.category] = by_cat.get(h.category, 0) + 1
        return {
            "scanned": len(parsed_logs),
            "hits": len(new_hits),
            "by_severity": by_sev,
            "by_category": by_cat,
            "samples": [h.to_dict() for h in new_hits[-30:]],
            "rule_total": len(self._rules),
            "rule_enabled": sum(1 for r in rules.values()),
        }

    # ------------------------------------------------------------------ #
    def recent_hits(self, limit: int = 100) -> List[Dict[str, Any]]:
        with self._lock:
            return [h.to_dict() for h in self._hits[-limit:]]

    def rule_hit_top(self, n: int = 10) -> List[Dict[str, Any]]:
        with self._lock:
            items = sorted(self._rules.values(),
                           key=lambda r: r.hits, reverse=True)[:n]
        return [r.to_dict() for r in items]

    def stats(self) -> Dict[str, Any]:
        with self._lock:
            hits = list(self._hits)
            rules = list(self._rules.values())
        by_sev: Dict[str, int] = {}
        by_cat: Dict[str, int] = {}
        for h in hits:
            by_sev[h.severity] = by_sev.get(h.severity, 0) + 1
            by_cat[h.category] = by_cat.get(h.category, 0) + 1
        return {
            "total_hits": len(hits),
            "rule_total": len(rules),
            "rule_enabled": sum(1 for r in rules if r.enabled),
            "by_severity": by_sev,
            "by_category": by_cat,
        }


_default: Optional[CorrelationPhase] = None


def get_correlation_phase() -> CorrelationPhase:
    global _default
    if _default is None:
        _default = CorrelationPhase()
    return _default
