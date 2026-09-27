# -*- coding: utf-8 -*-
"""
入侵检测引擎（IDS Engine）—— 纯规则实现

基于规则的网络请求 / 日志检测引擎，仅做防御侧检测，不包含任何攻击工具。

能力：
    - 解析基础 Suricata/Snort 规则语法（action/protocol/[src port]->[dst port] 头，
      以及 sid / msg / content / pcre / classtype / severity 等选项）
    - 内置 20+ 条常见攻击规则，覆盖 SQL注入 / XSS / 目录遍历 / 暴力破解 / 端口扫描 /
      CC攻击 / 命令注入 / 文件包含 / WebShell / 敏感文件探测 / LFI/RFI / SSRF / XXE /
      反序列化 / CRLF注入 / 开放重定向 / 弱口令 / 扫描器指纹 / DDoS / 异常UA
    - 告警分级 info / warning / critical，字段：rule_id, msg, severity, source_ip,
      dest_ip, timestamp, evidence

注意：本模块只做模式匹配与告警，不发起任何网络请求。
"""
from __future__ import annotations

import os
import re
from datetime import datetime
from typing import Any, Dict, List, Optional

try:
    from utils.logger import log  # type: ignore
except Exception:  # pragma: no cover - 独立运行时退化
    import logging

    logging.basicConfig(level=logging.INFO)
    log = logging.getLogger("ids_engine")


SEVERITY_LEVELS = ("info", "warning", "critical")


class IDSEngine:
    """基于规则的入侵检测引擎。轻量、无外部依赖。"""

    def __init__(self, rules: Optional[List[Dict[str, Any]]] = None):
        self.rules: List[Dict[str, Any]] = []
        self.alerts: List[Dict[str, Any]] = []
        if rules:
            self.rules = list(rules)
        else:
            self.rules = self._builtin_rules()

    # ------------------------------------------------------------------ #
    # 规则解析
    # ------------------------------------------------------------------ #
    @staticmethod
    def parse_rule(line: str) -> Optional[Dict[str, Any]]:
        """
        解析一条基础 Suricata/Snort 规则。

        形如:
            alert tcp any any -> any any (msg:"SQL Injection Attempt"; content:"UNION SELECT"; sid:1000001; classtype:web-attack; rev:1;)
        返回结构化规则字典；非规则行返回 None。
        """
        line = line.strip()
        if not line or line.startswith("#"):
            return None
        # 必须以 alert/log/pass 等 action 开头，且包含括号选项段
        if "(" not in line or ")" not in line:
            return None
        try:
            head, options_part = line.split("(", 1)
            options_part = options_part.rsplit(")", 1)[0]
            head_parts = head.split()
            if len(head_parts) < 5:
                return None
            action = head_parts[0]
            protocol = head_parts[1]

            rule: Dict[str, Any] = {
                "action": action,
                "protocol": protocol,
                "raw": line,
                "sid": None,
                "msg": "",
                "contents": [],
                "pcre": None,
                "classtype": None,
                "severity": "warning",
                "category": "unknown",
            }

            # 拆分选项 key:value;
            for opt in re.split(r";\s*", options_part):
                opt = opt.strip()
                if not opt or ":" not in opt:
                    continue
                key, _, value = opt.partition(":")
                key = key.strip()
                value = value.strip()
                # 去掉引号
                clean = value.strip('"').strip("'")
                if key == "msg":
                    rule["msg"] = clean
                elif key == "sid":
                    try:
                        rule["sid"] = int(clean)
                    except ValueError:
                        rule["sid"] = clean
                elif key == "content":
                    # content:"xxx"; nocase;  等修饰在 value 内已无分号
                    needle = clean.strip()
                    if needle.startswith('"') and needle.endswith('"'):
                        needle = needle[1:-1]
                    rule["contents"].append(needle)
                elif key == "pcre":
                    rule["pcre"] = clean
                elif key == "classtype":
                    rule["classtype"] = clean
                    rule["category"] = clean
                elif key == "severity":
                    if clean in SEVERITY_LEVELS:
                        rule["severity"] = clean
            return rule
        except Exception:
            return None

    def load_rules(self, filepath: str) -> int:
        """从规则文件加载规则，返回加载条数。"""
        count = 0
        if not os.path.exists(filepath):
            log.warning(f"[IDS] 规则文件不存在: {filepath}")
            return 0
        with open(filepath, "r", encoding="utf-8", errors="ignore") as fh:
            for line in fh:
                rule = self.parse_rule(line)
                if rule:
                    self.rules.append(rule)
                    count += 1
        log.info(f"[IDS] 从 {filepath} 加载 {count} 条规则")
        return count

    # ------------------------------------------------------------------ #
    # 内置规则
    # ------------------------------------------------------------------ #
    def _builtin_rules(self) -> List[Dict[str, Any]]:
        """20+ 条常见攻击检测规则（纯模式匹配，防御视角）。"""
        def R(sid: int, msg: str, contents: List[str], category: str,
              severity: str = "critical", pcre: Optional[str] = None) -> Dict[str, Any]:
            return {
                "action": "alert",
                "protocol": "http",
                "raw": "",
                "sid": sid,
                "msg": msg,
                "contents": contents,
                "pcre": pcre,
                "classtype": category,
                "category": category,
                "severity": severity,
            }

        rules = [
            # 1 SQL 注入
            R(1000001, "SQL注入攻击 - UNION SELECT", ["union select"], "sqli", "critical"),
            R(1000002, "SQL注入攻击 - 布尔盲注关键词", ["' or '1'='1", "or 1=1--", "'--"], "sqli", "critical"),
            R(1000003, "SQL注入攻击 - 堆叠查询/注释符", ["; drop table", "/*", "--"], "sqli", "warning"),
            # 2 XSS
            R(1000004, "跨站脚本 XSS - script 标签", ["<script", "</script>"], "xss", "critical"),
            R(1000005, "跨站脚本 XSS - 事件处理器/伪协议", ["onerror=", "onload=", "javascript:"], "xss", "critical"),
            # 3 目录遍历
            R(1000006, "目录遍历攻击", ["../", "..\\", "....//"], "directory_traversal", "critical"),
            # 4 暴力破解
            R(1000007, "暴力破解 - 登录失败特征", ["failed password", "authentication failure", "login failed"],
              "bruteforce", "warning"),
            # 5 端口扫描（由 analyzer 基于行为判定，这里保留指纹规则）
            R(1000008, "扫描器指纹 - Nmap", ["nmap scripting engine", "nmap port"], "portscan", "warning"),
            # 6 CC 攻击（行为类，保留关键词特征）
            R(1000009, "CC/压测工具特征", ["sqlmap/", "python-requests", "scrapy", "curl/"], "cc_attack", "warning"),
            # 7 命令注入
            R(1000010, "命令注入 - shell 元字符", [";", "|", "`$(", "${"], "cmd_injection", "critical"),
            R(1000011, "命令注入 - 系统命令", ["; cat /etc/passwd", "| whoami", "&& id", "/bin/sh", "cmd.exe"],
              "cmd_injection", "critical"),
            # 8 文件包含 / 9 WebShell
            R(1000012, "本地文件包含 LFI", ["php://filter", "expect://", "/etc/passwd"], "lfi", "critical"),
            R(1000013, "远程文件包含 RFI", ["http://", "ftp://"], "rfi", "critical"),
            R(1000014, "WebShell 访问特征", ["c99shell", "r57shell", "eval(", "base64_decode(", "shell.php"],
              "webshell", "critical"),
            # 10 敏感文件探测
            R(1000015, "敏感文件探测", [".env", ".git/", "web.config", "/proc/self", ".ssh/id_rsa", "backup.sql"],
              "sensitive_probe", "critical"),
            # 11 SSRF
            R(1000016, "SSRF 服务端请求伪造", ["169.254.169.254", "localhost:", "127.0.0.1:", "0.0.0.0:"],
              "ssrf", "critical"),
            # 12 XXE
            R(1000017, "XXE 外部实体注入", ["<!entity", "system \"file:", "PUBLIC \"-//", "% entities"],
              "xxe", "critical"),
            # 13 反序列化
            R(1000018, "反序列化攻击特征", ["rO0ab", "java serialized", "commons.collections", "ysoserial"],
              "deserialization", "critical"),
            # 14 CRLF 注入
            R(1000019, "CRLF / HTTP 响应拆分注入", ["%0d%0a", "%0a%0d", "\\r\\nset-cookie", "header:"],
              "crlf_injection", "warning"),
            # 15 开放重定向
            R(1000020, "开放重定向攻击", ["?url=http", "?redirect=http", "?next=http", "goto=http"],
              "open_redirect", "warning"),
            # 16 弱口令尝试
            R(1000021, "弱口令尝试特征", ["password=123", "admin'--", "root/root", "passwd=admin"],
              "weak_cred", "warning"),
            # 17 扫描器指纹
            R(1000022, "扫描器指纹 - 自动化工具 UA", ["masscan", "zgrab", "nikto", "acunetix", "nessus", "burpsuite"],
              "scanner_fingerprint", "info"),
            # 18 DDoS 特征（关键词层面）
            R(1000023, "DDoS/反射攻击特征", ["amplification", "memcached", "ntp monlist"], "ddos", "warning"),
            # 19 异常 User-Agent
            R(1000024, "异常/空 User-Agent", ["", "-", "bad-ua", "anonymous"], "abnormal_ua", "info"),
            # 20 额外：路径穿越编码
            R(1000025, "编码绕过 - 路径穿越", ["%2e%2e%2f", "%2e%2e/", "%252e%252e%252f", "..%255c"],
              "directory_traversal", "critical"),
        ]
        return rules

    # ------------------------------------------------------------------ #
    # 匹配核心
    # ------------------------------------------------------------------ #
    def _haystack_from_packet(self, packet: Dict[str, Any]) -> str:
        """把一条网络请求记录归一化为可匹配文本（小写）。"""
        parts: List[str] = []
        for key in ("method", "path", "uri", "url", "query", "body", "payload",
                    "user_agent", "ua", "referer", "host", "raw", "request"):
            val = packet.get(key)
            if val is not None:
                parts.append(str(val))
        headers = packet.get("headers") or {}
        if isinstance(headers, dict):
            for hk, hv in headers.items():
                parts.append(f"{hk}:{hv}")
        return " ".join(parts).lower()

    def _match_rule(self, rule: Dict[str, Any], haystack: str) -> Optional[str]:
        """判断规则是否命中，命中返回证据片段，否则 None。"""
        # content 匹配：全部 content 都要出现（AND），任一为空 content 视为恒真
        needles = [c for c in rule.get("contents", []) if c != ""]
        if needles:
            found = None
            for needle in needles:
                n = needle.lower()
                if n and n in haystack:
                    found = needle
                    break  # 同一条规则内多个 content 任一命中即告警（OR，宽松防御）
            if found is None:
                return None
            evidence = found
        else:
            evidence = rule.get("msg", "")

        # pcre 额外匹配（可选）
        pcre = rule.get("pcre")
        if pcre:
            try:
                pat = re.sub(r"^[a-zA-Z]+", "", pcre).strip("/")
                if pat and not re.search(pat, haystack):
                    return None
            except re.error:
                pass
        return evidence

    def _make_alert(self, rule: Dict[str, Any], packet: Dict[str, Any],
                    evidence: str) -> Dict[str, Any]:
        return {
            "rule_id": rule.get("sid"),
            "msg": rule.get("msg"),
            "category": rule.get("category"),
            "severity": rule.get("severity", "warning"),
            "source_ip": packet.get("source_ip") or packet.get("src_ip") or packet.get("src", "-"),
            "dest_ip": packet.get("dest_ip") or packet.get("dst_ip") or packet.get("dst", "-"),
            "timestamp": packet.get("timestamp") or datetime.now().isoformat(),
            "evidence": evidence,
        }

    # ------------------------------------------------------------------ #
    # 公开方法
    # ------------------------------------------------------------------ #
    def analyze_packet(self, packet_dict: Dict[str, Any]) -> List[Dict[str, Any]]:
        """分析单条网络请求记录，返回命中的告警列表。"""
        hay = self._haystack_from_packet(packet_dict)
        hits: List[Dict[str, Any]] = []
        for rule in self.rules:
            evidence = self._match_rule(rule, hay)
            if evidence is not None:
                alert = self._make_alert(rule, packet_dict, evidence)
                self.alerts.append(alert)
                hits.append(alert)
        return hits

    def analyze_log_line(self, line: str) -> List[Dict[str, Any]]:
        """分析单行日志文本，返回命中告警。"""
        # 尝试从日志行中提取 source ip（第一个 token）
        src_ip = line.split()[0] if line else "-"
        packet = {"raw": line, "source_ip": src_ip, "timestamp": datetime.now().isoformat()}
        return self.analyze_packet(packet)

    def analyze_pcap_file(self, filepath: str) -> Dict[str, Any]:
        """
        基础版 PCAP 文本分析：解析导出为文本/行格式的流量记录。
        每行视为一条记录，依次调用 analyze_log_line。
        返回 {lines_scanned, alerts_count, alerts}。
        """
        if not os.path.exists(filepath):
            log.warning(f"[IDS] 文件不存在: {filepath}")
            return {"lines_scanned": 0, "alerts_count": 0, "alerts": []}
        scanned = 0
        with open(filepath, "r", encoding="utf-8", errors="ignore") as fh:
            for line in fh:
                line = line.strip()
                if not line:
                    continue
                scanned += 1
                self.analyze_log_line(line)
        result = {
            "lines_scanned": scanned,
            "alerts_count": len(self.alerts),
            "alerts": self.alerts[-scanned:] if scanned else [],
        }
        return result

    def get_alerts(self, severity: Optional[str] = None) -> List[Dict[str, Any]]:
        """获取告警，可按严重级别过滤。"""
        if severity:
            return [a for a in self.alerts if a.get("severity") == severity]
        return list(self.alerts)

    def clear_alerts(self) -> None:
        self.alerts = []


# 便于命令行 / 简单测试
if __name__ == "__main__":
    eng = IDSEngine()
    print(f"[*] 已加载内置规则 {len(eng.rules)} 条")
    demo = {
        "method": "GET",
        "path": "/search?q=1' OR '1'='1 UNION SELECT password--",
        "source_ip": "203.0.113.66",
        "dest_ip": "10.0.0.5",
        "user_agent": "sqlmap/1.7",
    }
    print("[*] SQL注入测试:", len(eng.analyze_packet(demo)), "条告警")
