# -*- coding: utf-8 -*-
"""
honeypot_manager.py 鈥?铚滅綈閮ㄧ讲绠＄悊鍣紙绗?3杞崌绾э級銆?

鍔熻兘锛?
- 铚滅綈绫诲瀷搴擄細Web/SSH/SMB/鏁版嵁搴?閭欢/DNS/IoT/宸ユ帶/FTP/Telnet/RDP/VNC
- 閮ㄧ讲閰嶇疆锛氱洃鍚鍙?鍗忚妯℃嫙/鏈嶅姟妯箙/鍝嶅簲琛屼负/浜や簰绾у埆/璧勬簮闄愬埗
- 璇遍サ鏈嶅姟锛氳櫄鍋囨湇鍔℃弿杩?鐗堟湰鍙?閿欒淇℃伅/鏂囦欢绯荤粺/鏁版嵁搴?
- 铏氬亣鍑瘉锛氱敤鎴峰悕/瀵嗙爜鍝堝笇/SSH瀵嗛挜/API瀵嗛挜/Token
- 浜や簰绾у埆锛氫綆浜や簰锛堣褰曡繛鎺ワ級/涓氦浜掞紙妯℃嫙鍗忚鍝嶅簲锛?楂樹氦浜掞紙瀹屾暣绯荤粺妯℃嫙锛?
- 鐢熷懡鍛ㄦ湡绠＄悊锛氬垱寤?鍚姩/鍋滄/閲嶅惎/鍒犻櫎/鐘舵€佺洃鎺?鍋ュ悍妫€鏌?
- 铚滅綈閮ㄧ讲鎶ュ憡

鍚堟硶杈圭晫锛氫粎鐢ㄤ簬闃插尽妫€娴嬩笌鐮旂┒锛屼笉涓诲姩鏀诲嚮銆?
"""

from __future__ import annotations

import hashlib
import os
import random
import string
import time
import uuid
from dataclasses import asdict, dataclass, field
from datetime import datetime
from typing import Any, Dict, List, Optional

# ==================== 甯搁噺搴擄細铚滅綈绫诲瀷 ====================

HONEYPOT_TYPES: Dict[str, Dict[str, Any]] = {
    "web_http": {
        "name": "Web铚滅綈(HTTP)",
        "category": "web",
        "default_port": 80,
        "protocol": "HTTP/TCP",
        "banner": "Apache/2.4.41 (Ubuntu)",
        "interactive_levels": ["low", "medium", "high"],
        "desc": "妯℃嫙HTTP Web鏈嶅姟锛屾崟鑾锋壂鎻忎笌婕忔礊鎺㈡祴",
    },
    "web_https": {
        "name": "Web铚滅綈(HTTPS)",
        "category": "web",
        "default_port": 443,
        "protocol": "HTTPS/TCP",
        "banner": "nginx/1.18.0",
        "interactive_levels": ["low", "medium", "high"],
        "desc": "妯℃嫙HTTPS鍔犲瘑Web鏈嶅姟",
    },
    "ssh": {
        "name": "SSH铚滅綈",
        "category": "remote",
        "default_port": 22,
        "protocol": "SSH/TCP",
        "banner": "SSH-2.0-OpenSSH_8.2p1 Ubuntu-4ubuntu0.5",
        "interactive_levels": ["low", "medium", "high"],
        "desc": "妯℃嫙SSH鏈嶅姟锛屾崟鑾锋毚鍔涚牬瑙ｄ笌鍛戒护鎵ц",
    },
    "smb": {
        "name": "SMB铚滅綈",
        "category": "file",
        "default_port": 445,
        "protocol": "SMB/TCP",
        "banner": "Samba 4.11.6-Ubuntu",
        "interactive_levels": ["low", "medium"],
        "desc": "妯℃嫙SMB鏂囦欢鍏变韩锛屾崟鑾?EternalBlue 绛夋帰娴?,
    },
    "mysql": {
        "name": "鏁版嵁搴撹湝缃?MySQL)",
        "category": "database",
        "default_port": 3306,
        "protocol": "MySQL/TCP",
        "banner": "5.7.36 MySQL Community Server",
        "interactive_levels": ["low", "medium"],
        "desc": "妯℃嫙MySQL鏁版嵁搴擄紝鎹曡幏寮卞彛浠や笌娉ㄥ叆鎺㈡祴",
    },
    "postgresql": {
        "name": "鏁版嵁搴撹湝缃?PostgreSQL)",
        "category": "database",
        "default_port": 5432,
        "protocol": "PostgreSQL/TCP",
        "banner": "PostgreSQL 12.9 on x86_64",
        "interactive_levels": ["low", "medium"],
        "desc": "妯℃嫙PostgreSQL鏁版嵁搴撴湇鍔?,
    },
    "mssql": {
        "name": "鏁版嵁搴撹湝缃?MSSQL)",
        "category": "database",
        "default_port": 1433,
        "protocol": "TDS/TCP",
        "banner": "Microsoft SQL Server 2019",
        "interactive_levels": ["low", "medium"],
        "desc": "妯℃嫙MSSQL鏁版嵁搴擄紝鎹曡幏xp_cmdshell鎺㈡祴",
    },
    "redis": {
        "name": "鏁版嵁搴撹湝缃?Redis)",
        "category": "database",
        "default_port": 6379,
        "protocol": "Redis/TCP",
        "banner": "redis_version:6.2.6",
        "interactive_levels": ["low", "medium", "high"],
        "desc": "妯℃嫙Redis鏈嶅姟锛屾崟鑾锋湭鎺堟潈璁块棶涓庡啓鏂囦欢鏀诲嚮",
    },
    "mongodb": {
        "name": "鏁版嵁搴撹湝缃?MongoDB)",
        "category": "database",
        "default_port": 27017,
        "protocol": "MongoDB/TCP",
        "banner": "MongoDB 4.4.10",
        "interactive_levels": ["low", "medium"],
        "desc": "妯℃嫙MongoDB鏈嶅姟锛屾崟鑾锋湭鎺堟潈璁块棶",
    },
    "smtp": {
        "name": "閭欢铚滅綈(SMTP)",
        "category": "mail",
        "default_port": 25,
        "protocol": "SMTP/TCP",
        "banner": "220 mail.example.com ESMTP Postfix",
        "interactive_levels": ["low", "medium"],
        "desc": "妯℃嫙SMTP閭欢鏈嶅姟锛屾崟鑾峰瀮鍦鹃偖浠朵笌涓户鎺㈡祴",
    },
    "pop3": {
        "name": "閭欢铚滅綈(POP3)",
        "category": "mail",
        "default_port": 110,
        "protocol": "POP3/TCP",
        "banner": "+OK POP3 mail.example.com ready",
        "interactive_levels": ["low", "medium"],
        "desc": "妯℃嫙POP3閭欢鏀跺彇鏈嶅姟",
    },
    "imap": {
        "name": "閭欢铚滅綈(IMAP)",
        "category": "mail",
        "default_port": 143,
        "protocol": "IMAP/TCP",
        "banner": "* OK IMAP4rev1 service ready",
        "interactive_levels": ["low", "medium"],
        "desc": "妯℃嫙IMAP閭欢璁块棶鏈嶅姟",
    },
    "dns": {
        "name": "DNS铚滅綈",
        "category": "network",
        "default_port": 53,
        "protocol": "DNS/UDP",
        "banner": "BIND 9.11.3-Ubuntu",
        "interactive_levels": ["low", "medium"],
        "desc": "妯℃嫙DNS鏈嶅姟锛屾崟鑾稤NS鏀惧ぇ涓庨毀閬?,
    },
    "mqtt": {
        "name": "IoT铚滅綈(MQTT)",
        "category": "iot",
        "default_port": 1883,
        "protocol": "MQTT/TCP",
        "banner": "MQTT v3.1.1 (Mosquitto 1.6.9)",
        "interactive_levels": ["low", "medium", "high"],
        "desc": "妯℃嫙MQTT Broker锛屾崟鑾稩oT鏀诲嚮",
    },
    "modbus": {
        "name": "宸ユ帶铚滅綈(Modbus)",
        "category": "ics",
        "default_port": 502,
        "protocol": "Modbus-TCP",
        "banner": "Modbus Gateway v2.1",
        "interactive_levels": ["low", "medium", "high"],
        "desc": "妯℃嫙宸ヤ笟Modbus鍗忚锛屾崟鑾峰伐鎺ф敾鍑?,
    },
    "s7": {
        "name": "宸ユ帶铚滅綈(S7)",
        "category": "ics",
        "default_port": 102,
        "protocol": "S7comm/TCP",
        "banner": "Siemens S7-1200 CPU 1214C",
        "interactive_levels": ["low", "medium"],
        "desc": "妯℃嫙瑗块棬瀛怱7 PLC閫氫俊",
    },
    "ftp": {
        "name": "FTP铚滅綈",
        "category": "file",
        "default_port": 21,
        "protocol": "FTP/TCP",
        "banner": "220 (vsFTPd 3.0.3)",
        "interactive_levels": ["low", "medium", "high"],
        "desc": "妯℃嫙FTP鏂囦欢浼犺緭锛屾崟鑾峰尶鍚嶈闂笌鏆村姏鐮磋В",
    },
    "telnet": {
        "name": "Telnet铚滅綈",
        "category": "remote",
        "default_port": 23,
        "protocol": "Telnet/TCP",
        "banner": "Ubuntu 20.04 LTS\r\nlogin:",
        "interactive_levels": ["low", "medium", "high"],
        "desc": "妯℃嫙Telnet鏄庢枃缁堢锛屾崟鑾稩oT鏆村姏鐮磋В",
    },
    "rdp": {
        "name": "RDP铚滅綈",
        "category": "remote",
        "default_port": 3389,
        "protocol": "RDP/TCP",
        "banner": "Microsoft Terminal Services",
        "interactive_levels": ["low", "medium"],
        "desc": "妯℃嫙杩滅▼妗岄潰锛屾崟鑾稡lueKeep绛夋帰娴?,
    },
    "vnc": {
        "name": "VNC铚滅綈",
        "category": "remote",
        "default_port": 5900,
        "protocol": "RFB/TCP",
        "banner": "RFB 003.008",
        "interactive_levels": ["low", "medium"],
        "desc": "妯℃嫙VNC杩滅▼妗岄潰锛屾崟鑾峰急鍙ｄ护鎺㈡祴",
    },
}

# 浜や簰绾у埆瀹氫箟
INTERACTION_LEVELS: Dict[str, Dict[str, str]] = {
    "low": {
        "name": "浣庝氦浜?,
        "desc": "浠呰褰曡繛鎺ュ厓鏁版嵁锛圛P/绔彛/鏃堕棿锛夛紝涓嶆ā鎷熷崗璁?,
        "resource_cost": "鏋佷綆",
        "attack_capture": "浣?,
    },
    "medium": {
        "name": "涓氦浜?,
        "desc": "妯℃嫙鍗忚鎻℃墜涓庢爣鍑嗗搷搴旓紝璁板綍鍛戒护涓庤涓?,
        "resource_cost": "涓?,
        "attack_capture": "涓?,
    },
    "high": {
        "name": "楂樹氦浜?,
        "desc": "瀹屾暣绯荤粺妯℃嫙锛岃櫄鍋囨枃浠剁郴缁?鏁版嵁搴?Shell",
        "resource_cost": "楂?,
        "attack_capture": "楂?,
    },
}

# 铏氬亣鍑瘉妯℃澘
DECOY_USERS: List[str] = [
    "admin", "root", "administrator", "sysadmin", "operator",
    "backup", "oracle", "mysql", "postgres", "appuser",
    "svc_web", "svc_db", "test", "dev", "guest",
]

DECOY_PASSWORDS: List[str] = [
    "P@ssw0rd2023", "Admin@123", "Welcome1", "Qwerty123",
    "Honeypot#2024", "S3cr3t!", "ChangeMe1", "TempPass99",
]

DECOY_API_KEYS: List[str] = [
    "stripe_api_key_here",
    "AKIAIOSFODNN7EXAMPLE",
    "ghp_AbCdEf123456GhIjKlMnOpQrStUvWxYz",
    "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6ImFkbWluIn0",
]

# 铏氬亣鏂囦欢绯荤粺妯℃澘
DECOY_FILESYSTEM: Dict[str, List[Dict[str, Any]]] = {
    "/etc": [
        {"name": "passwd", "size": 2841, "perms": "644"},
        {"name": "shadow", "size": 1234, "perms": "640"},
        {"name": "hosts", "size": 212, "perms": "644"},
        {"name": "ssh/sshd_config", "size": 3245, "perms": "644"},
    ],
    "/var/www/html": [
        {"name": "index.html", "size": 1024, "perms": "644"},
        {"name": "config.php", "size": 512, "perms": "644"},
        {"name": "admin/", "size": 0, "perms": "755", "is_dir": True},
    ],
    "/root": [
        {"name": ".bash_history", "size": 842, "perms": "600"},
        {"name": ".ssh/id_rsa", "size": 1675, "perms": "600"},
    ],
    "/opt/app": [
        {"name": "config.yaml", "size": 4096, "perms": "644"},
        {"name": ".env", "size": 256, "perms": "600"},
        {"name": "data.db", "size": 20480, "perms": "644"},
    ],
}


# ==================== 鏁版嵁绫?====================

@dataclass
class HoneypotInstance:
    """鍗曚釜铚滅綈瀹炰緥"""
    instance_id: str = ""
    name: str = ""
    honeypot_type: str = ""
    listen_port: int = 80
    listen_host: str = "0.0.0.0"
    protocol: str = "TCP"
    banner: str = ""
    interaction_level: str = "medium"
    status: str = "created"  # created/starting/running/stopping/stopped/error
    created_at: str = ""
    started_at: str = ""
    stopped_at: str = ""
    uptime_seconds: int = 0
    connection_count: int = 0
    bytes_in: int = 0
    bytes_out: int = 0
    error_message: str = ""
    max_connections: int = 100
    resource_limit_cpu: float = 1.0
    resource_limit_mem_mb: int = 256
    decoy_config: Dict[str, Any] = field(default_factory=dict)
    health_status: str = "unknown"

    def to_dict(self) -> Dict[str, Any]:
        d = asdict(self)
        return {k: v for k, v in d.items() if v is not None}


# ==================== 铚滅綈绠＄悊鍣?====================

class HoneypotManager:
    """铚滅綈閮ㄧ讲绠＄悊鍣?""

    def __init__(self) -> None:
        self.instances: Dict[str, HoneypotInstance] = {}
        self.deploy_history: List[Dict[str, Any]] = []
        self._counter: int = 0

    # ---------- 鏌ヨ绫诲瀷搴?----------

    def list_types(self) -> List[Dict[str, Any]]:
        """鍒楀嚭鎵€鏈夋敮鎸佺殑铚滅綈绫诲瀷"""
        result = []
        for tid, info in HONEYPOT_TYPES.items():
            result.append({
                "type_id": tid,
                "name": info["name"],
                "category": info["category"],
                "default_port": info["default_port"],
                "protocol": info["protocol"],
                "banner": info["banner"],
                "interactive_levels": info["interactive_levels"],
                "desc": info["desc"],
            })
        return result

    def get_type_info(self, type_id: str) -> Optional[Dict[str, Any]]:
        return HONEYPOT_TYPES.get(type_id)

    # ---------- 鐢熷懡鍛ㄦ湡 ----------

    def deploy(self, honeypot_type: str, name: str = "",
               listen_port: Optional[int] = None,
               listen_host: str = "0.0.0.0",
               interaction_level: str = "medium",
               custom_banner: str = "",
               max_connections: int = 100,
               resource_limit_cpu: float = 1.0,
               resource_limit_mem_mb: int = 256) -> Dict[str, Any]:
        """閮ㄧ讲锛堝垱寤猴級涓€涓湝缃愬疄渚?""
        type_info = HONEYPOT_TYPES.get(honeypot_type)
        if not type_info:
            return {"success": False, "error": f"鏈煡铚滅綈绫诲瀷: {honeypot_type}"}

        self._counter += 1
        inst_id = f"hp-{uuid.uuid4().hex[:10]}"
        port = listen_port or type_info["default_port"]
        banner = custom_banner or type_info["banner"]

        # 鏋勫缓璇遍サ閰嶇疆
        decoy_config = self._build_decoy_config(honeypot_type)

        inst = HoneypotInstance(
            instance_id=inst_id,
            name=name or f"{type_info['name']}-{self._counter}",
            honeypot_type=honeypot_type,
            listen_port=port,
            listen_host=listen_host,
            protocol=type_info["protocol"],
            banner=banner,
            interaction_level=interaction_level,
            status="created",
            created_at=datetime.now().isoformat(),
            max_connections=max_connections,
            resource_limit_cpu=resource_limit_cpu,
            resource_limit_mem_mb=resource_limit_mem_mb,
            decoy_config=decoy_config,
        )
        self.instances[inst_id] = inst
        self.deploy_history.append({
            "instance_id": inst_id,
            "name": inst.name,
            "type": honeypot_type,
            "action": "deploy",
            "timestamp": datetime.now().isoformat(),
        })
        return {"success": True, "instance_id": inst_id, "instance": inst.to_dict()}

    def start(self, instance_id: str) -> Dict[str, Any]:
        """鍚姩铚滅綈瀹炰緥"""
        inst = self.instances.get(instance_id)
        if not inst:
            return {"success": False, "error": "瀹炰緥涓嶅瓨鍦?}
        inst.status = "running"
        inst.started_at = datetime.now().isoformat()
        inst.health_status = "healthy"
        self.deploy_history.append({
            "instance_id": instance_id, "action": "start",
            "timestamp": datetime.now().isoformat(),
        })
        return {"success": True, "message": f"铚滅綈 {inst.name} 宸插惎鍔?}

    def stop(self, instance_id: str) -> Dict[str, Any]:
        """鍋滄铚滅綈瀹炰緥"""
        inst = self.instances.get(instance_id)
        if not inst:
            return {"success": False, "error": "瀹炰緥涓嶅瓨鍦?}
        inst.status = "stopped"
        inst.stopped_at = datetime.now().isoformat()
        inst.health_status = "stopped"
        self.deploy_history.append({
            "instance_id": instance_id, "action": "stop",
            "timestamp": datetime.now().isoformat(),
        })
        return {"success": True, "message": f"铚滅綈 {inst.name} 宸插仠姝?}

    def restart(self, instance_id: str) -> Dict[str, Any]:
        """閲嶅惎铚滅綈瀹炰緥"""
        self.stop(instance_id)
        return self.start(instance_id)

    def delete(self, instance_id: str) -> Dict[str, Any]:
        """鍒犻櫎铚滅綈瀹炰緥"""
        inst = self.instances.pop(instance_id, None)
        if not inst:
            return {"success": False, "error": "瀹炰緥涓嶅瓨鍦?}
        self.deploy_history.append({
            "instance_id": instance_id, "action": "delete",
            "timestamp": datetime.now().isoformat(),
        })
        return {"success": True, "message": f"铚滅綈 {inst.name} 宸插垹闄?}

    # ---------- 鐘舵€佺洃鎺?----------

    def list_instances(self) -> List[Dict[str, Any]]:
        """鍒楀嚭鎵€鏈夎湝缃愬疄渚?""
        return [inst.to_dict() for inst in self.instances.values()]

    def get_instance(self, instance_id: str) -> Optional[Dict[str, Any]]:
        inst = self.instances.get(instance_id)
        return inst.to_dict() if inst else None

    def health_check(self, instance_id: str) -> Dict[str, Any]:
        """鍋ュ悍妫€鏌?""
        inst = self.instances.get(instance_id)
        if not inst:
            return {"success": False, "error": "瀹炰緥涓嶅瓨鍦?}
        if inst.status != "running":
            inst.health_status = "stopped"
        else:
            # 妯℃嫙鍋ュ悍妫€鏌?
            inst.health_status = "healthy" if inst.connection_count < inst.max_connections else "degraded"
        return {
            "instance_id": instance_id,
            "status": inst.status,
            "health": inst.health_status,
            "uptime_seconds": inst.uptime_seconds,
            "connections": inst.connection_count,
            "max_connections": inst.max_connections,
            "cpu_limit": inst.resource_limit_cpu,
            "mem_limit_mb": inst.resource_limit_mem_mb,
        }

    def get_statistics(self) -> Dict[str, Any]:
        """鍏ㄥ眬缁熻"""
        insts = list(self.instances.values())
        by_status: Dict[str, int] = {}
        by_type: Dict[str, int] = {}
        total_conns = 0
        for i in insts:
            by_status[i.status] = by_status.get(i.status, 0) + 1
            by_type[i.honeypot_type] = by_type.get(i.honeypot_type, 0) + 1
            total_conns += i.connection_count
        return {
            "total_instances": len(insts),
            "by_status": by_status,
            "by_type": by_type,
            "total_connections": total_conns,
            "deploy_history_count": len(self.deploy_history),
        }

    # ---------- 璇遍サ閰嶇疆 ----------

    def _build_decoy_config(self, honeypot_type: str) -> Dict[str, Any]:
        """鏍规嵁铚滅綈绫诲瀷鏋勫缓璇遍サ閰嶇疆"""
        users = random.sample(DECOY_USERS, k=min(5, len(DECOY_USERS)))
        passwords = random.sample(DECOY_PASSWORDS, k=min(4, len(DECOY_PASSWORDS)))
        api_keys = random.sample(DECOY_API_KEYS, k=2)

        # 鐢熸垚铏氬亣瀵嗙爜鍝堝笇
        fake_hashes = []
        for u, p in zip(users, passwords):
            h = hashlib.sha256(f"{u}:{p}".encode()).hexdigest()
            fake_hashes.append({"username": u, "hash_sha256": h})

        config: Dict[str, Any] = {
            "decoy_users": users,
            "decoy_password_hashes": fake_hashes,
            "decoy_api_keys": api_keys,
            "fake_filesystem": DECOY_FILESYSTEM if honeypot_type in (
                "ssh", "ftp", "telnet", "web_http", "web_https", "redis"
            ) else {},
            "fake_database": {} if honeypot_type not in (
                "mysql", "postgresql", "mssql", "mongodb", "redis"
            ) else {
                "databases": ["appdb", "logdb", "metrics"],
                "tables": ["users", "orders", "sessions"],
                "fake_rows": 500,
            },
            "fake_error_messages": {
                "403": "Forbidden: You don't have permission to access this resource.",
                "404": "Not Found: The requested URL was not found on this server.",
                "500": "Internal Server Error: The server encountered an error.",
            },
            "fake_ssh_key": self._generate_fake_ssh_key(),
            "fake_token": self._generate_fake_token(),
        }
        return config

    @staticmethod
    def _generate_fake_ssh_key() -> str:
        key_body = "".join(random.choices(
            "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/", k=200))
        return f"ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQ{key_body} admin@honeypot"

    @staticmethod
    def _generate_fake_token() -> str:
        chars = string.ascii_letters + string.digits + "-_"
        return "".join(random.choices(chars, k=64))

    # ---------- 鎶ュ憡 ----------

    def generate_report(self) -> Dict[str, Any]:
        """鐢熸垚铚滅綈閮ㄧ讲鎶ュ憡"""
        insts = list(self.instances.values())
        running = [i for i in insts if i.status == "running"]
        return {
            "report_title": "铚滅綈閮ㄧ讲鎶ュ憡",
            "generated_at": datetime.now().isoformat(),
            "total_instances": len(insts),
            "running_instances": len(running),
            "by_type": self.get_statistics()["by_type"],
            "by_status": self.get_statistics()["by_status"],
            "total_connections_captured": sum(i.connection_count for i in insts),
            "instances": [i.to_dict() for i in insts],
            "deploy_history": self.deploy_history[-20:],
            "recommendations": [
                "寤鸿鎸夋敾鍑婚潰閮ㄧ讲澶氭牱鍖栬湝缃愮被鍨嬶紝瑕嗙洊鏆撮湶绔彛",
                "楂樹氦浜掕湝缃愯祫婧愭秷鑰楀ぇ锛屽缓璁粎鍦ㄥ叧閿祫浜ф梺閮ㄧ讲",
                "瀹氭湡瀹℃煡铚滅綈鏃ュ織锛岄伩鍏嶈鎶ュ共鎵板垎鏋?,
            ],
        }


# ==================== 宸ュ巶鍑芥暟 ====================

_manager_singleton: Optional[HoneypotManager] = None


def get_honeypot_manager() -> HoneypotManager:
    global _manager_singleton
    if _manager_singleton is None:
        _manager_singleton = HoneypotManager()
    return _manager_singleton
