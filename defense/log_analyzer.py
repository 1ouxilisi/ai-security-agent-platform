# -*- coding: utf-8 -*-
"""
日志分析与异常检测（Log Analyzer）—— 纯解析实现

支持：
    - Nginx / Apache 访问日志（combined / common 格式）
    - Windows 安全日志（事件 ID 基础解析：4624 登录成功 / 4625 登录失败 / 4672 特权登录）
    - Linux auth.log（SSH 登录成功 / 失败解析）
    - 通用认证日志

异常检测：
    - 暴力破解（同 IP 失败次数阈值）
    - 异常登录时间（非工作时段 08:00-20:00 之外）
    - 异常 IP 位置（内网 / 公网 / 已知恶意 IP 段）
    - 异常用户行为（首次登录、特权使用）

统计分析：
    - Top 攻击源 IP / Top 攻击类型 / 按小时时间分布 / 受攻击 URL / 状态码分布

仅做防御侧分析，不发起任何网络行为。
"""
from __future__ import annotations

import os
import re
from collections import Counter, defaultdict
from datetime import datetime
from typing import Any, Dict, List, Optional

try:
    from utils.logger import log  # type: ignore
except Exception:  # pragma: no cover
    import logging

    logging.basicConfig(level=logging.INFO)
    log = logging.getLogger("log_analyzer")


# Apache/Nginx combined:
# 1.2.3.4 - - [10/Oct/2000:14:55:36 +0000] "GET /a HTTP/1.1" 200 123 "ref" "ua"
_COMBINED_RE = re.compile(
    r'(?P<ip>\S+)\s+\S+\s+\S+\s+\[(?P<time>[^\]]+)\]\s+'
    r'"(?P<method>\S+)\s+(?P<path>\S+)\s+(?P<proto>[^"]*)"\s+'
    r'(?P<status>\d{3})\s+(?P<size>\S+)'
    r'(?:\s+"(?P<referer>[^"]*)"\s+"(?P<ua>[^"]*)")?'
)

# Linux auth.log:
# Sep 12 03:14:15 host sshd[1234]: Failed password for root from 1.2.3.4 port 22 ssh2
# Sep 12 03:14:15 host sshd[1234]: Accepted password for alice from 1.2.3.4 port 22 ssh2
_AUTH_FAIL_RE = re.compile(
    r'(?P<time>\w+\s+\d+\s+[\d:]+).*?(?P<action>Failed|Accepted) (?P<method>\S+) '
    r'for (?:invalid user )?(?P<user>\S+) from (?P<ip>\d+\.\d+\.\d+\.\d+)'
)

# Windows 安全日志行（简化）: EventID=4624 ... AccountName=... SourceNetworkAddress=...
_WIN_RE = re.compile(
    r'EventID[=:]\s*(?P<event>\d+).*?(?:AccountName|TargetUserName)[=:]\s*(?P<user>\S+).*?'
    r'(?:SourceNetworkAddress|Address)[=:]\s*(?P<ip>[\d\.a-fA-F:]+)',
    re.IGNORECASE,
)

# 已知恶意 IP 段（示例：仅供演示，可扩展）
_KNOWN_BAD_PREFIXES = ("185.220.", "45.155.", "91.219.", "103.75.")

# 攻击类型关键词 -> 标签
_ATTACK_PATTERNS = {
    "sql_injection": re.compile(r"union\s+select|or\s+1=1|'\s*or\s*'|information_schema|sleep\(", re.I),
    "xss": re.compile(r"<script|onerror=|javascript:|onload=", re.I),
    "directory_traversal": re.compile(r"\.\./|\.\.\\|%2e%2e", re.I),
    "file_inclusion": re.compile(r"php://filter|/etc/passwd|expect://", re.I),
    "webshell": re.compile(r"eval\(|base64_decode|shell\.php|c99", re.I),
    "sensitive_probe": re.compile(r"\.env|\.git|web\.config|\.ssh|backup", re.I),
    "scanner": re.compile(r"sqlmap|nikto|nmap|nessus|masscan|zgrab", re.I),
}


def _is_internal_ip(ip: str) -> bool:
    if not ip or ip in ("-", "::1"):
        return True
    if ip.startswith(("10.", "192.168.", "127.")):
        return True
    if ip.startswith("172."):
        try:
            second = int(ip.split(".")[1])
            if 16 <= second <= 31:
                return True
        except (ValueError, IndexError):
            pass
    return False


def _is_known_bad(ip: str) -> bool:
    return any(ip.startswith(p) for p in _KNOWN_BAD_PREFIXES)


class LogAnalyzer:
    """多格式日志解析与异常检测。"""

    def __init__(self):
        self.records: List[Dict[str, Any]] = []
        self.anomalies: List[Dict[str, Any]] = []
        self._seen_users: set = set()

    # ------------------------------------------------------------------ #
    # 解析
    # ------------------------------------------------------------------ #
    def parse_access_log(self, line: str) -> Optional[Dict[str, Any]]:
        """解析单行 Nginx/Apache combined/common 访问日志。"""
        line = line.strip()
        if not line:
            return None
        m = _COMBINED_RE.match(line)
        if not m:
            return None
        rec = m.groupdict()
        rec["type"] = "access"
        # 解析时间
        try:
            rec["dt"] = datetime.strptime(rec["time"].split()[0], "%d/%b/%Y:%H:%M:%S")
            rec["hour"] = rec["dt"].hour
        except Exception:
            rec["dt"] = None
            rec["hour"] = None
        rec["status"] = int(rec.get("status") or 0)
        return rec

    def _parse_auth_log(self, line: str) -> Optional[Dict[str, Any]]:
        m = _AUTH_FAIL_RE.search(line)
        if not m:
            return None
        g = m.groupdict()
        ok = g["action"] == "Accepted"
        return {
            "type": "auth",
            "ip": g["ip"],
            "user": g["user"],
            "success": ok,
            "method": g["method"],
            "raw_time": g["time"],
            "status": 200 if ok else 401,
            "hour": None,
        }

    def _parse_windows_log(self, line: str) -> Optional[Dict[str, Any]]:
        m = _WIN_RE.search(line)
        if not m:
            return None
        g = m.groupdict()
        event = int(g["event"])
        # 4624 登录成功 / 4625 登录失败 / 4672 特权使用
        success = event == 4624
        return {
            "type": "windows",
            "event_id": event,
            "ip": g["ip"],
            "user": g["user"],
            "success": success,
            "hour": None,
            "status": 200 if success else 401,
            "privilege": event == 4672,
        }

    def parse_line(self, line: str, log_type: str = "auto") -> Optional[Dict[str, Any]]:
        """按指定/自动类型解析单行。"""
        lt = log_type.lower()
        if lt in ("access", "nginx", "apache", "combined", "common"):
            return self.parse_access_log(line)
        if lt in ("auth", "authlog", "sshd", "linux"):
            return self._parse_auth_log(line)
        if lt in ("windows", "win", "event"):
            return self._parse_windows_log(line)
        # auto
        rec = self.parse_access_log(line)
        if rec:
            return rec
        rec = self._parse_auth_log(line)
        if rec:
            return rec
        return self._parse_windows_log(line)

    # ------------------------------------------------------------------ #
    # 攻击类型识别
    # ------------------------------------------------------------------ #
    @staticmethod
    def classify_attack(record: Dict[str, Any]) -> Optional[str]:
        text = record.get("path") or record.get("raw", "")
        if isinstance(text, str):
            text = text.lower()
        for label, pat in _ATTACK_PATTERNS.items():
            if pat.search(text):
                return label
        return None

    # ------------------------------------------------------------------ #
    # 分析
    # ------------------------------------------------------------------ #
    def analyze_file(self, filepath: str, log_type: str = "auto") -> Dict[str, Any]:
        """分析整个日志文件，返回记录数与初步异常。"""
        if not os.path.exists(filepath):
            log.warning(f"[LogAnalyzer] 文件不存在: {filepath}")
            return {"records": 0, "anomalies": []}
        with open(filepath, "r", encoding="utf-8", errors="ignore") as fh:
            for line in fh:
                rec = self.parse_line(line, log_type)
                if rec:
                    self.records.append(rec)
        self._run_anomaly_detection()
        return {
            "records": len(self.records),
            "anomalies": self.anomalies,
            "statistics": self.get_statistics(),
        }

    def _run_anomaly_detection(self) -> None:
        self.detect_brute_force()
        self._detect_abnormal_time()
        self._detect_abnormal_ip()
        self._detect_first_login()

    def detect_brute_force(self, threshold: int = 5) -> List[Dict[str, Any]]:
        """检测同 IP 登录失败次数超阈值。"""
        fail_by_ip: Dict[str, List[str]] = defaultdict(list)
        for rec in self.records:
            if rec.get("success") is False:
                fail_by_ip[rec.get("ip", "-")].append(rec.get("user", "?"))
        findings: List[Dict[str, Any]] = []
        for ip, users in fail_by_ip.items():
            if len(users) >= threshold:
                finding = {
                    "type": "brute_force",
                    "severity": "critical" if len(users) >= threshold * 2 else "warning",
                    "source_ip": ip,
                    "failed_count": len(users),
                    "usernames_tried": sorted(set(users))[:20],
                    "message": f"IP {ip} 登录失败 {len(users)} 次（阈值 {threshold}），疑似暴力破解",
                }
                self.anomalies.append(finding)
                findings.append(finding)
        return findings

    def _detect_abnormal_time(self) -> None:
        for rec in self.records:
            hour = rec.get("hour")
            if hour is None:
                continue
            if not (8 <= hour < 20):
                self.anomalies.append({
                    "type": "abnormal_login_time",
                    "severity": "warning",
                    "source_ip": rec.get("ip"),
                    "user": rec.get("user"),
                    "hour": hour,
                    "message": f"非工作时段({hour:02d}:00)登录: {rec.get('user')}@{rec.get('ip')}",
                })

    def _detect_abnormal_ip(self) -> None:
        seen = set()
        for rec in self.records:
            ip = rec.get("ip") or "-"
            key = (ip, rec.get("user"))
            if key in seen:
                continue
            seen.add(key)
            if _is_known_bad(ip):
                self.anomalies.append({
                    "type": "known_bad_ip",
                    "severity": "critical",
                    "source_ip": ip,
                    "message": f"来自已知恶意 IP 段的访问: {ip}",
                })
            elif not _is_internal_ip and rec.get("type") in ("auth", "windows"):
                self.anomalies.append({
                    "type": "external_auth",
                    "severity": "warning",
                    "source_ip": ip,
                    "message": f"公网 IP {ip} 发起认证登录（需关注）",
                })

    def _detect_first_login(self) -> None:
        for rec in self.records:
            user = rec.get("user")
            if not user:
                continue
            if rec.get("success") and user not in self._seen_users:
                self._seen_users.add(user)
                self.anomalies.append({
                    "type": "first_login",
                    "severity": "info",
                    "user": user,
                    "source_ip": rec.get("ip"),
                    "message": f"用户 {user} 首次登录记录（来自 {rec.get('ip')}）",
                })
            if rec.get("privilege"):
                self.anomalies.append({
                    "type": "privilege_use",
                    "severity": "warning",
                    "user": user,
                    "message": f"用户 {user} 使用特权凭证登录(EventID 4672)",
                })

    # ------------------------------------------------------------------ #
    # 统计
    # ------------------------------------------------------------------ #
    def get_statistics(self) -> Dict[str, Any]:
        # 攻击源 IP（失败认证 + 含攻击特征访问）
        attacker_ips = Counter()
        attack_types = Counter()
        attacked_urls = Counter()
        status_codes = Counter()
        hour_dist = Counter()

        for rec in self.records:
            ip = rec.get("ip") or "-"
            status_codes[rec.get("status", 0)] += 1
            if rec.get("hour") is not None:
                hour_dist[rec["hour"]] += 1
            if rec.get("success") is False:
                attacker_ips[ip] += 1
            atk = self.classify_attack(rec)
            if atk:
                attack_types[atk] += 1
                attacker_ips[ip] += 1
                if rec.get("path"):
                    attacked_urls[rec["path"]] += 1

        return {
            "total_records": len(self.records),
            "top_attack_ips": attacker_ips.most_common(10),
            "top_attack_types": attack_types.most_common(10),
            "top_attacked_urls": attacked_urls.most_common(10),
            "status_code_distribution": dict(status_codes),
            "attack_hour_distribution": dict(sorted(hour_dist.items())),
            "anomaly_count": len(self.anomalies),
        }

    def export_report(self) -> Dict[str, Any]:
        """导出完整分析报告。"""
        return {
            "generated_at": datetime.now().isoformat(),
            "statistics": self.get_statistics(),
            "anomalies": self.anomalies,
        }

    def reset(self) -> None:
        self.records.clear()
        self.anomalies.clear()
        self._seen_users.clear()


if __name__ == "__main__":
    la = LogAnalyzer()
    sample = [
        '203.0.113.66 - - [12/Sep/2026:03:14:15 +0800] "GET /search?q=1\' OR 1=1-- HTTP/1.1" 200 123 "-" "sqlmap/1.7"',
        '203.0.113.66 - - [12/Sep/2026:03:14:16 +0800] "GET /etc/passwd HTTP/1.1" 404 0 "-" "sqlmap/1.7"',
    ]
    for s in sample:
        la.records.append(la.parse_access_log(s))
    print(la.get_statistics())
