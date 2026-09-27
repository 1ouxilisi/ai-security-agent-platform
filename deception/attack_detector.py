# -*- coding: utf-8 -*-
"""
attack_detector.py — 攻击检测与告警器（第13轮升级）。

功能：
- 攻击者行为捕获：连接记录/IP/端口/协议/时间戳/会话时长/包数
- 命令记录：执行命令/参数/输出/时间/序列
- 文件上传：文件名/大小/类型/哈希/内容分析/恶意软件检测
- 横向移动检测：内网扫描/端口探测/凭据尝试/远程执行
- 凭据窃取检测：密码抓取/哈希转储/令牌窃取/密钥提取
- 权限提升检测：提权尝试/漏洞利用/内核漏洞/SUID/计划任务
- 实时告警：事件生成/分级(critical/high/medium/low)/通知/关联
- 攻击链重建：阶段映射/ATT&CK映射/时间线/路径图
- 攻击检测报告

合法边界：仅用于防御检测与研究。
"""

from __future__ import annotations

import hashlib
import random
import re
import time
import uuid
from collections import defaultdict
from dataclasses import asdict, dataclass, field
from datetime import datetime
from typing import Any, Dict, List, Optional

# ==================== 常量：ATT&CK 映射库 ====================

ATTACK_TECHNIQUES: Dict[str, Dict[str, str]] = {
    "T1046": {"name": "网络服务扫描", "tactic": "发现", "kill_chain": "侦察"},
    "T1082": {"name": "系统信息发现", "tactic": "发现", "kill_chain": "武器化"},
    "T1110": {"name": "暴力破解", "tactic": "凭证访问", "kill_chain": "利用"},
    "T1078": {"name": "有效账户", "tactic": "防御规避", "kill_chain": "安装"},
    "T1059": {"name": "命令与脚本解释器", "tactic": "执行", "kill_chain": "利用"},
    "T1021": {"name": "远程服务", "tactic": "横向移动", "kill_chain": "横向移动"},
    "T1003": {"name": "操作系统凭证转储", "tactic": "凭证访问", "kill_chain": "利用"},
    "T1555": {"name": "凭证存储", "tactic": "凭证访问", "kill_chain": "利用"},
    "T1068": {"name": "利用漏洞提权", "tactic": "权限提升", "kill_chain": "权限提升"},
    "T1548": {"name": "滥用提权机制", "tactic": "权限提升", "kill_chain": "权限提升"},
    "T1053": {"name": "计划任务/作业", "tactic": "持久化", "kill_chain": "持久化"},
    "T1105": {"name": "入站工具传输", "tactic": "命令与控制", "kill_chain": "C2"},
    "T1071": {"name": "应用层协议", "tactic": "命令与控制", "kill_chain": "C2"},
    "T1041": {"name": "数据渗漏通道", "tactic": "数据渗漏", "kill_chain": "行动目标"},
    "T1203": {"name": "利用客户端执行", "tactic": "执行", "kill_chain": "交付"},
}

# 攻击阶段（杀伤链）
KILL_CHAIN_PHASES = ["侦察", "武器化", "交付", "利用", "安装",
                     "命令与控制", "横向移动", "权限提升", "数据渗漏"]

# 恶意命令特征库
MALICIOUS_COMMAND_PATTERNS: List[Dict[str, Any]] = [
    {"pattern": r"wget|curl.*\|\s*(ba)?sh", "technique": "T1105", "severity": "high", "desc": "下载并执行远程脚本"},
    {"pattern": r"chmod\s*\+x", "technique": "T1059", "severity": "medium", "desc": "赋予执行权限"},
    {"pattern": r"/etc/passwd|/etc/shadow", "technique": "T1003", "severity": "critical", "desc": "读取密码文件"},
    {"pattern": r"cat\s+.*\.ssh/id_", "technique": "T1555", "severity": "critical", "desc": "窃取SSH密钥"},
    {"pattern": r"nc\s+-|ncat\s+-|netcat", "technique": "T1071", "severity": "high", "desc": "反向Shell"},
    {"pattern": r"python3?\s+-c\s+['\"].*import", "technique": "T1059", "severity": "high", "desc": "Python内联执行"},
    {"pattern": r"sudo\s+su|sudo\s+-i", "technique": "T1548", "severity": "high", "desc": "尝试提权"},
    {"pattern": r"crontab|systemctl.*enable", "technique": "T1053", "severity": "medium", "desc": "持久化计划任务"},
    {"pattern": r"nmap|masscan|zmap", "technique": "T1046", "severity": "medium", "desc": "端口扫描工具"},
    {"pattern": r"hydra|medusa|ncrack", "technique": "T1110", "severity": "high", "desc": "暴力破解工具"},
    {"pattern": r"/bin/bash\s+-i|/bin/sh\s+-i", "technique": "T1059", "severity": "critical", "desc": "交互式Shell"},
    {"pattern": r"rm\s+-rf|dd\s+if=/dev/zero", "technique": "T1485", "severity": "critical", "desc": "数据破坏"},
]

# 文件类型 -> 风险
FILE_TYPE_RISK: Dict[str, str] = {
    "application/x-executable": "critical",
    "application/x-dosexec": "critical",
    "application/x-elf": "critical",
    "application/x-sharedlib": "critical",
    "text/x-shellscript": "high",
    "text/x-python": "medium",
    "application/pdf": "medium",
    "application/zip": "medium",
}

# 告警分级
ALERT_SEVERITY = {"critical": 4, "high": 3, "medium": 2, "low": 1}


# ==================== 数据类 ====================

@dataclass
class AttackAlert:
    alert_id: str = ""
    timestamp: str = ""
    severity: str = "medium"
    category: str = ""
    source_ip: str = ""
    target_port: int = 0
    description: str = ""
    technique: str = ""
    mitre_id: str = ""
    details: Dict[str, Any] = field(default_factory=dict)
    acknowledged: bool = False

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


# ==================== 攻击检测器 ====================

class AttackDetector:
    """攻击检测与告警器"""

    def __init__(self) -> None:
        self.connections: List[Dict[str, Any]] = []
        self.commands: List[Dict[str, Any]] = []
        self.uploads: List[Dict[str, Any]] = []
        self.alerts: List[AttackAlert] = []
        self.attack_chains: List[Dict[str, Any]] = []
        self._chain_counter: int = 0

    # ---------- 行为捕获 ----------

    def record_connection(self, source_ip: str, source_port: int,
                          target_port: int, protocol: str,
                          bytes_in: int = 0, bytes_out: int = 0,
                          duration: float = 0.0) -> Dict[str, Any]:
        """记录连接事件"""
        conn = {
            "conn_id": f"c-{uuid.uuid4().hex[:8]}",
            "source_ip": source_ip,
            "source_port": source_port,
            "target_port": target_port,
            "protocol": protocol,
            "timestamp": datetime.now().isoformat(),
            "bytes_in": bytes_in,
            "bytes_out": bytes_out,
            "duration_seconds": duration,
        }
        self.connections.append(conn)
        # 检测：扫描行为（短时间内多端口连接）
        self._detect_scan(source_ip)
        return conn

    def record_command(self, source_ip: str, command: str,
                       output: str = "", cmd_args: str = "") -> Dict[str, Any]:
        """记录执行命令并检测恶意行为"""
        cmd_record = {
            "cmd_id": f"cmd-{uuid.uuid4().hex[:8]}",
            "source_ip": source_ip,
            "command": command,
            "args": cmd_args,
            "output": output,
            "timestamp": datetime.now().isoformat(),
            "matched_techniques": [],
        }
        # 匹配恶意命令特征
        for pat in MALICIOUS_COMMAND_PATTERNS:
            if re.search(pat["pattern"], command, re.IGNORECASE):
                tech = ATTACK_TECHNIQUES.get(pat["technique"], {})
                cmd_record["matched_techniques"].append({
                    "pattern": pat["pattern"],
                    "mitre_id": pat["technique"],
                    "technique_name": tech.get("name", pat["technique"]),
                    "severity": pat["severity"],
                    "desc": pat["desc"],
                })
                self._raise_alert(
                    severity=pat["severity"],
                    category="command_execution",
                    source_ip=source_ip,
                    description=f"检测到可疑命令: {pat['desc']}",
                    mitre_id=pat["technique"],
                    details={"command": command, "pattern": pat["pattern"]},
                )
        self.commands.append(cmd_record)
        # 检测横向移动与提权
        self._detect_lateral_movement(source_ip, command)
        self._detect_privilege_escalation(source_ip, command)
        self._detect_credential_theft(source_ip, command)
        return cmd_record

    def record_upload(self, source_ip: str, filename: str,
                      file_size: int, file_content: bytes = b"") -> Dict[str, Any]:
        """记录文件上传并分析"""
        file_hash = hashlib.sha256(file_content).hexdigest() if file_content else \
            hashlib.sha256(filename.encode()).hexdigest()
        # 推断文件类型
        ftype = self._guess_file_type(filename, file_content)
        risk = FILE_TYPE_RISK.get(ftype, "low")
        upload = {
            "upload_id": f"up-{uuid.uuid4().hex[:8]}",
            "source_ip": source_ip,
            "filename": filename,
            "file_size": file_size,
            "file_type": ftype,
            "sha256": file_hash,
            "risk": risk,
            "timestamp": datetime.now().isoformat(),
            "malware_detected": risk == "critical",
        }
        self.uploads.append(upload)
        if risk in ("critical", "high"):
            self._raise_alert(
                severity=risk,
                category="malware_upload",
                source_ip=source_ip,
                description=f"检测到高风险文件上传: {filename} ({ftype})",
                mitre_id="T1105",
                details={"filename": filename, "sha256": file_hash, "type": ftype},
            )
        return upload

    # ---------- 检测规则 ----------

    def _detect_scan(self, source_ip: str) -> None:
        """检测端口扫描行为"""
        recent = [c for c in self.connections
                  if c["source_ip"] == source_ip and
                  (datetime.now() - datetime.fromisoformat(c["timestamp"])).seconds < 60]
        ports = set(c["target_port"] for c in recent)
        if len(ports) >= 10:
            self._raise_alert(
                severity="medium",
                category="port_scan",
                source_ip=source_ip,
                description=f"检测到端口扫描: {len(ports)}个端口",
                mitre_id="T1046",
                details={"ports": list(ports)[:20], "port_count": len(ports)},
            )

    def _detect_lateral_movement(self, source_ip: str, command: str) -> None:
        """检测横向移动"""
        lateral_patterns = [
            (r"ssh\s+.*@|scp\s+.*@", "SSH远程连接", "T1021"),
            (r"smbclient|net\s+use|rpcclient", "SMB横向移动", "T1021"),
            (r"psexec|wmic.*process.*call", "远程执行", "T1021"),
            (r"crackmapexec|impacket", "横向移动工具", "T1021"),
        ]
        for pat, desc, mitre in lateral_patterns:
            if re.search(pat, command, re.IGNORECASE):
                self._raise_alert(
                    severity="high", category="lateral_movement",
                    source_ip=source_ip,
                    description=f"横向移动行为: {desc}",
                    mitre_id=mitre,
                    details={"command": command, "pattern": pat},
                )

    def _detect_credential_theft(self, source_ip: str, command: str) -> None:
        """检测凭据窃取"""
        cred_patterns = [
            (r"/etc/shadow|/etc/passwd", "读取密码文件", "T1003"),
            (r"\.ssh/id_rsa|\.ssh/authorized_keys", "窃取SSH密钥", "T1555"),
            (r"mimikatz|secretsdump|dump.hashes", "哈希转储工具", "T1003"),
            (r"token|kinit|klist", "令牌窃取", "T1550"),
            (r"api[_-]?key|secret|password.*=", "提取密钥", "T1555"),
        ]
        for pat, desc, mitre in cred_patterns:
            if re.search(pat, command, re.IGNORECASE):
                self._raise_alert(
                    severity="critical", category="credential_theft",
                    source_ip=source_ip,
                    description=f"凭据窃取行为: {desc}",
                    mitre_id=mitre,
                    details={"command": command, "pattern": pat},
                )

    def _detect_privilege_escalation(self, source_ip: str, command: str) -> None:
        """检测权限提升"""
        priv_patterns = [
            (r"sudo\s+-i|sudo\s+su|su\s+-", "SU提权", "T1548"),
            (r"setuid|chmod\s+u\+s|suid", "SUID滥用", "T1548"),
            (r"expolit|cve-\d{4}-\d{4,5}|kernel", "漏洞利用提权", "T1068"),
            (r"crontab\s+-e|systemctl.*timers", "计划任务持久化", "T1053"),
        ]
        for pat, desc, mitre in priv_patterns:
            if re.search(pat, command, re.IGNORECASE):
                self._raise_alert(
                    severity="high", category="privilege_escalation",
                    source_ip=source_ip,
                    description=f"权限提升尝试: {desc}",
                    mitre_id=mitre,
                    details={"command": command, "pattern": pat},
                )

    @staticmethod
    def _guess_file_type(filename: str, content: bytes) -> str:
        ext = filename.lower().rsplit(".", 1)[-1] if "." in filename else ""
        mapping = {
            "exe": "application/x-dosexec",
            "dll": "application/x-dosexec",
            "elf": "application/x-elf",
            "so": "application/x-sharedlib",
            "sh": "text/x-shellscript",
            "py": "text/x-python",
            "pdf": "application/pdf",
            "zip": "application/zip",
        }
        return mapping.get(ext, "application/octet-stream")

    # ---------- 告警 ----------

    def _raise_alert(self, severity: str, category: str,
                     source_ip: str, description: str,
                     mitre_id: str = "",
                     details: Optional[Dict[str, Any]] = None,
                     target_port: int = 0) -> None:
        alert = AttackAlert(
            alert_id=f"al-{uuid.uuid4().hex[:10]}",
            timestamp=datetime.now().isoformat(),
            severity=severity,
            category=category,
            source_ip=source_ip,
            target_port=target_port,
            description=description,
            technique=ATTACK_TECHNIQUES.get(mitre_id, {}).get("name", ""),
            mitre_id=mitre_id,
            details=details or {},
        )
        self.alerts.append(alert)
        # 关联分析
        self._correlate_alert(alert)

    def _correlate_alert(self, alert: AttackAlert) -> None:
        """简单告警关联：同一IP的告警聚合"""
        related = [a for a in self.alerts
                   if a.source_ip == alert.source_ip and
                   (datetime.now() - datetime.fromisoformat(a.timestamp)).seconds < 300]
        if len(related) >= 3:
            self._raise_alert(
                severity="high",
                category="alert_correlation",
                source_ip=alert.source_ip,
                description=f"攻击者 {alert.source_ip} 触发 {len(related)} 条关联告警",
                mitre_id="",
                details={"related_alerts": [a.alert_id for a in related]},
            )

    def list_alerts(self, severity: Optional[str] = None,
                    source_ip: Optional[str] = None,
                    limit: int = 100) -> List[Dict[str, Any]]:
        result = self.alerts
        if severity:
            result = [a for a in result if a.severity == severity]
        if source_ip:
            result = [a for a in result if a.source_ip == source_ip]
        return [a.to_dict() for a in result[-limit:]]

    def acknowledge_alert(self, alert_id: str) -> Dict[str, Any]:
        for a in self.alerts:
            if a.alert_id == alert_id:
                a.acknowledged = True
                return {"success": True, "message": "告警已确认"}
        return {"success": False, "error": "告警不存在"}

    # ---------- 攻击链重建 ----------

    def rebuild_attack_chain(self, source_ip: str) -> Dict[str, Any]:
        """基于捕获数据重建攻击链"""
        conns = [c for c in self.connections if c["source_ip"] == source_ip]
        cmds = [c for c in self.commands if c["source_ip"] == source_ip]
        alrs = [a for a in self.alerts if a.source_ip == source_ip]
        ups = [u for u in self.uploads if u["source_ip"] == source_ip]

        # 阶段映射
        phases: List[Dict[str, Any]] = []
        if conns:
            phases.append({"phase": "侦察", "events": len(conns),
                           "techniques": ["T1046"], "timestamp": conns[0]["timestamp"]})
        if cmds:
            techs = set()
            for c in cmds:
                for t in c.get("matched_techniques", []):
                    techs.add(t["mitre_id"])
            phases.append({"phase": "执行/利用", "events": len(cmds),
                           "techniques": list(techs),
                           "timestamp": cmds[0]["timestamp"]})
        if ups:
            phases.append({"phase": "工具传输", "events": len(ups),
                           "techniques": ["T1105"],
                           "timestamp": ups[0]["timestamp"]})

        chain = {
            "chain_id": f"chain-{uuid.uuid4().hex[:8]}",
            "source_ip": source_ip,
            "rebuilt_at": datetime.now().isoformat(),
            "total_connections": len(conns),
            "total_commands": len(cmds),
            "total_alerts": len(alrs),
            "total_uploads": len(ups),
            "attack_phases": phases,
            "kill_chain": [p["phase"] for p in phases],
            "mitre_techniques": list(set(
                [t for p in phases for t in p["techniques"]]
            )),
            "timeline": sorted(
                [{"time": c["timestamp"], "event": "connection", "detail": c.get("target_port")}
                 for c in conns] +
                [{"time": c["timestamp"], "event": "command", "detail": c.get("command", "")[:80]}
                 for c in cmds],
                key=lambda x: x["time"]
            ),
        }
        self.attack_chains.append(chain)
        return chain

    # ---------- 报告 ----------

    def generate_report(self) -> Dict[str, Any]:
        sev_count = {"critical": 0, "high": 0, "medium": 0, "low": 0}
        for a in self.alerts:
            sev_count[a.severity] = sev_count.get(a.severity, 0) + 1
        ip_count: Dict[str, int] = defaultdict(int)
        for a in self.alerts:
            ip_count[a.source_ip] += 1
        top_attackers = sorted(ip_count.items(), key=lambda x: x[1], reverse=True)[:10]
        return {
            "report_title": "攻击检测报告",
            "generated_at": datetime.now().isoformat(),
            "total_connections": len(self.connections),
            "total_commands": len(self.commands),
            "total_uploads": len(self.uploads),
            "total_alerts": len(self.alerts),
            "alerts_by_severity": sev_count,
            "top_attackers": [{"ip": ip, "alert_count": cnt} for ip, cnt in top_attackers],
            "attack_chains_rebuilt": len(self.attack_chains),
            "recent_alerts": [a.to_dict() for a in self.alerts[-20:]],
            "recommendations": [
                "对critical级别告警立即进行事件响应",
                "关联分析同一攻击者的多阶段行为",
                "定期审查检测规则，降低误报率",
            ],
        }


# ==================== 工厂函数 ====================

_detector_singleton: Optional[AttackDetector] = None


def get_attack_detector() -> AttackDetector:
    global _detector_singleton
    if _detector_singleton is None:
        _detector_singleton = AttackDetector()
    return _detector_singleton
