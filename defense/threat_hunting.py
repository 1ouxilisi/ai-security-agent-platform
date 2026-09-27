# -*- coding: utf-8 -*-
"""
威胁狩猎引擎（Threat Hunter）—— 基于检测逻辑的假设狩猎

内置狩猎场景：
    - lateral_movement  横向移动（SMB/RDP 异常、PtH 登录类型3+5、多主机快速登录）
    - data_exfiltration 数据外泄（异常大出站流量、DNS 隧道特征、敏感文件访问）
    - persistence       持久化（计划任务、注册表 Run/RunOnce、新服务、WMI 订阅）
    - credential_theft  凭据窃取（Mimikatz 特征、LSASS 异常访问、Kerberoasting）

IOC 匹配：支持 IP / 域名 / SHA256 / MD5 / URL 的 IOC 列表。

所有判定基于传入的事件字典列表，纯离线分析，不发起任何活动。
"""
from __future__ import annotations

import hashlib
import re
from collections import defaultdict
from datetime import datetime
from typing import Any, Dict, List, Optional, Tuple

try:
    from utils.logger import log  # type: ignore
except Exception:  # pragma: no cover
    import logging

    logging.basicConfig(level=logging.INFO)
    log = logging.getLogger("threat_hunter")


class ThreatHunter:
    """威胁狩猎引擎。每个场景是一个对事件列表的检测函数。"""

    def __init__(self):
        self.findings: List[Dict[str, Any]] = []
        self.iocs: Dict[str, set] = {"ip": set(), "domain": set(),
                                      "sha256": set(), "md5": set(), "url": set()}
        self._scenarios = {
            "lateral_movement": self._hunt_lateral_movement,
            "data_exfiltration": self._hunt_data_exfiltration,
            "persistence": self._hunt_persistence,
            "credential_theft": self._hunt_credential_theft,
        }

    # ------------------------------------------------------------------ #
    # IOC
    # ------------------------------------------------------------------ #
    def load_iocs(self, ioc_list: List[Dict[str, str]]) -> int:
        """
        加载 IOC 列表。每项 {type: ip|domain|sha256|md5|url, value: ...}。
        """
        count = 0
        for item in ioc_list:
            t = (item.get("type") or "").lower()
            v = (item.get("value") or "").lower()
            if t in self.iocs and v:
                self.iocs[t].add(v)
                count += 1
        log.info(f"[ThreatHunter] 加载 {count} 条 IOC")
        return count

    def match_iocs(self, data: Dict[str, Any]) -> List[Dict[str, Any]]:
        """在一个事件数据字典中匹配已加载 IOC，返回命中项。"""
        hits: List[Dict[str, Any]] = []
        blobs = {
            "ip": [data.get("src_ip"), data.get("dest_ip"), data.get("ip"),
                   data.get("source_ip")],
            "domain": [data.get("domain"), data.get("host"), data.get("queried_domain")],
            "sha256": [data.get("sha256"), data.get("hash")],
            "md5": [data.get("md5")],
            "url": [data.get("url"), data.get("http_url")],
        }
        for itype, values in blobs.items():
            for v in values:
                if v and str(v).lower() in self.iocs[itype]:
                    hits.append({"ioc_type": itype, "value": v})
        return hits

    # ------------------------------------------------------------------ #
    # 场景检测
    # ------------------------------------------------------------------ #
    def _finding(self, scenario, name, severity, evidence, **extra):
        f = {
            "scenario": scenario,
            "name": name,
            "severity": severity,
            "evidence": evidence,
            "timestamp": datetime.now().isoformat(),
        }
        f.update(extra)
        self.findings.append(f)
        return f

    def _hunt_lateral_movement(self, events: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        out = []
        # PtH / 登录类型 3(网络) + 5(批处理) 组合 + NTLM
        by_user_host: Dict[Tuple[str, str], List[Dict[str, Any]]] = defaultdict(list)
        for e in events:
            lt = e.get("logon_type")
            proto = (e.get("protocol") or e.get("service") or "").lower()
            user = e.get("user", "?")
            host = e.get("dest_host") or e.get("computer", "?")
            by_user_host[(user, host)].append(e)

            # SMB/RDP 异常：同一账号短时间多主机 RDP/445
            if proto in ("rdp", "smb", "445", "3389"):
                # 登录类型 3 + 5 组合 PtH 特征
                if e.get("auth_package") == "NTLM" and e.get("ntlm_nt_hash_used"):
                    out.append(self._finding(
                        "lateral_movement", "疑似 Pass-the-Hash（NTLM 哈希登录）",
                        "critical",
                        f"用户 {user} 通过 NTLM 哈希登录 {host}", user=user, host=host))

        # 多主机快速登录（横向移动）：同一用户在短时间登录 >=3 台主机
        user_hosts: Dict[str, set] = defaultdict(set)
        for (user, host), evs in by_user_host.items():
            if user != "?":
                user_hosts[user].add(host)
        for user, hosts in user_hosts.items():
            if len(hosts) >= 3:
                out.append(self._finding(
                    "lateral_movement", "同一用户短时间登录多台主机",
                    "high",
                    f"用户 {user} 登录 {len(hosts)} 台主机: {sorted(hosts)[:10]}",
                    user=user, host_count=len(hosts)))
        return out

    def _hunt_data_exfiltration(self, events: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        out = []
        BIG = 50 * 1024 * 1024  # 50MB 出站阈值
        dns_long: Dict[str, int] = defaultdict(int)
        dns_txt: Dict[str, int] = defaultdict(int)
        for e in events:
            # 异常大出站
            bytes_out = e.get("bytes_out") or e.get("out_bytes") or 0
            if bytes_out and bytes_out >= BIG and e.get("direction") == "outbound":
                out.append(self._finding(
                    "data_exfiltration", "异常大流量出站",
                    "critical",
                    f"{e.get('src_ip','?')} -> {e.get('dest_ip','?')} "
                    f"出站 {bytes_out/1024/1024:.1f}MB",
                    src_ip=e.get("src_ip"), dest_ip=e.get("dest_ip"), bytes_out=bytes_out))
            # DNS 隧道：长域名
            q = e.get("queried_domain") or e.get("domain")
            if q and (e.get("query_type") or e.get("dns_type")) in ("TXT", "txt"):
                dns_txt[e.get("src_ip", "?")] += 1
            if q and len(q) > 40 and "-" in q:
                dns_long[e.get("src_ip", "?")] += 1
        for ip, cnt in dns_txt.items():
            if cnt >= 10:
                out.append(self._finding(
                    "data_exfiltration", "高频 DNS TXT 查询（疑似 DNS 隧道）",
                    "high", f"{ip} 发起 {cnt} 次 TXT 查询", src_ip=ip, count=cnt))
        for ip, cnt in dns_long.items():
            if cnt >= 5:
                out.append(self._finding(
                    "data_exfiltration", "超长随机域名查询（疑似 DNS 隧道）",
                    "high", f"{ip} 发起 {cnt} 次长域名查询", src_ip=ip, count=cnt))
        return out

    def _hunt_persistence(self, events: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        out = []
        susp_paths = [
            "schedule", "schtasks", "/create", "reg add",
            "runonce", "hklm\\software\\microsoft\\windows\\currentversion\\run",
            "wmic", "eventcreate", "sc create", "new service",
        ]
        for e in events:
            cmd = (e.get("command") or e.get("path") or e.get("target") or "").lower()
            ev_type = (e.get("event_type") or e.get("action") or "").lower()
            hit = [p for p in susp_paths if p in cmd]
            if hit or ev_type in ("service_create", "persistence"):
                out.append(self._finding(
                    "persistence", "可疑持久化机制创建",
                    "high",
                    f"进程 {e.get('process','?')} 执行: {cmd[:120]}",
                    process=e.get("process"), matched_trigger=hit))
        return out

    def _hunt_credential_theft(self, events: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        out = []
        for e in events:
            proc = (e.get("process") or e.get("source_process") or "").lower()
            target = (e.get("target_process") or e.get("access_target") or "").lower()
            # Mimikatz / LSASS 访问
            if "lsass.exe" in target and e.get("access_granted", 0) >= 0x1000:
                out.append(self._finding(
                    "credential_theft", "异常进程访问 LSASS（疑似凭据转储）",
                    "critical",
                    f"{proc} 以高权限访问 lsass.exe", process=proc))
            if any(k in proc for k in ("mimikatz", "sekurlsa", "procdump", "dump")):
                out.append(self._finding(
                    "credential_theft", "检测到凭据窃取工具进程",
                    "critical", f"进程名命中特征: {proc}", process=proc))
            # Kerberoasting：RC4(hmac-md5) 降级 + SPN 请求
            if e.get("event_type") == "kerberoast" or (
                    e.get("spn_requested") and e.get("encryption_type") in ("rc4-hmac", 23)):
                out.append(self._finding(
                    "credential_theft", "疑似 Kerberoasting（SPN 请求+RC4降级）",
                    "high",
                    f"用户 {e.get('user','?')} 请求 SPN {e.get('spn','?')} 且使用 RC4",
                    user=e.get("user"), spn=e.get("spn")))
        return out

    # ------------------------------------------------------------------ #
    # 调度
    # ------------------------------------------------------------------ #
    def hunt(self, scenario_name: str, data: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """执行单个狩猎场景。data 为事件字典列表。"""
        fn = self._scenarios.get(scenario_name)
        if fn is None:
            log.warning(f"[ThreatHunter] 未知场景: {scenario_name}")
            return []
        findings_before = len(self.findings)
        # IOC 交叉匹配
        for e in data:
            for hit in self.match_iocs(e):
                self._finding("ioc_match", "IOC 命中", "critical",
                              f"事件命中 {hit['ioc_type']}={hit['value']}",
                              ioc=hit)
        result = fn(data)
        return result

    def hunt_all(self, data: List[Dict[str, Any]]) -> Dict[str, Any]:
        """执行全部狩猎场景。"""
        self.findings = []
        for name in self._scenarios:
            self.hunt(name, data)
        return self.get_findings()

    def get_findings(self, severity: Optional[str] = None) -> List[Dict[str, Any]]:
        if severity:
            return [f for f in self.findings if f.get("severity") == severity]
        return list(self.findings)

    def export_hunt_report(self) -> Dict[str, Any]:
        by_scenario: Dict[str, int] = defaultdict(int)
        by_severity: Dict[str, int] = defaultdict(int)
        for f in self.findings:
            by_scenario[f["scenario"]] += 1
            by_severity[f["severity"]] += 1
        return {
            "generated_at": datetime.now().isoformat(),
            "total_findings": len(self.findings),
            "by_scenario": dict(by_scenario),
            "by_severity": dict(by_severity),
            "findings": self.findings,
        }


if __name__ == "__main__":
    th = ThreatHunter()
    sample = [
        {"user": "admin", "dest_host": "PC-01", "logon_type": 3,
         "auth_package": "NTLM", "ntlm_nt_hash_used": True, "protocol": "smb"},
        {"user": "admin", "dest_host": "PC-02", "logon_type": 5,
         "auth_package": "NTLM", "protocol": "rdp"},
        {"user": "admin", "dest_host": "PC-03", "logon_type": 3,
         "auth_package": "NTLM", "protocol": "smb"},
        {"process": "mimikatz.exe", "target_process": "lsass.exe", "access_granted": 0x1010},
        {"event_type": "kerberoast", "user": "admin", "spn": "cifs/srv01",
         "encryption_type": "rc4-hmac"},
        {"src_ip": "10.0.0.9", "direction": "outbound", "dest_ip": "203.0.113.9",
         "bytes_out": 80 * 1024 * 1024},
    ]
    print("findings:", len(th.hunt_all(sample)))
