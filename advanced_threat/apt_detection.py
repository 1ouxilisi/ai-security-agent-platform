#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
apt_detection.py — APT 高级持续性威胁检测模块
==============================================

功能：
    1. APT 战术检测：初始访问/执行/持久化/权限提升/防御规避/凭证访问/发现/横向移动/收集/C2/数据渗出/影响
    2. APT 技术检测：190+ ATT&CK 技术检测、已知/未知/变种 TTPs 检测
    3. APT 行为链分析：多阶段攻击链关联、时间线分析、攻击路径重建、意图推断、目标识别
    4. APT 基础设施检测：C2 服务器/DGA/快速通量/域名通量/IP 通量/隧道检测
    5. APT 数据渗出检测：异常数据传输/大容量/加密/隐蔽信道/时间分片/DNS 隧道渗出
    6. APT 威胁狩猎：假设驱动/IOC 驱动/TTP 驱动/行为驱动/历史回溯/持续监控狩猎

全部内存字典模拟。
"""
from __future__ import annotations

import random
import uuid
from datetime import datetime, timedelta
from typing import Any, Dict, List, Optional


def _now() -> str:
    return datetime.now().isoformat(timespec="seconds")


# ==================== MITRE ATT&CK 框架 ====================

_ATTACK_TACTICS = [
    {"id": "TA0001", "name": "初始访问", "rank": 1, "description": "入侵攻击向量"},
    {"id": "TA0002", "name": "执行", "rank": 2, "description": "运行恶意代码"},
    {"id": "TA0003", "name": "持久化", "rank": 3, "description": "保持立足点"},
    {"id": "TA0004", "name": "权限提升", "rank": 4, "description": "获取更高权限"},
    {"id": "TA0005", "name": "防御规避", "rank": 5, "description": "逃避检测"},
    {"id": "TA0006", "name": "凭证访问", "rank": 6, "description": "窃取账户密码"},
    {"id": "TA0007", "name": "发现", "rank": 7, "description": "环境探索"},
    {"id": "TA0008", "name": "横向移动", "rank": 8, "description": "内网扩散"},
    {"id": "TA0009", "name": "收集", "rank": 9, "description": "汇聚目标数据"},
    {"id": "TA0011", "name": "命令与控制", "rank": 10, "description": "与 C2 通信"},
    {"id": "TA0010", "name": "数据渗出", "rank": 11, "description": "窃取数据外传"},
    {"id": "TA0040", "name": "影响", "rank": 12, "description": "破坏业务"},
]

_ATTACK_TECHNIQUES = [
    ("T1566", "鱼叉式钓鱼", "TA0001", "initial_access"),
    ("T1190", "利用公开应用", "TA0001", "initial_access"),
    ("T1078", "有效账户", "TA0001", "initial_access"),
    ("T1204", "用户执行", "TA0002", "execution"),
    ("T1059", "命令行解释器", "TA0002", "execution"),
    ("T1086", "PowerShell", "TA0002", "execution"),
    ("T1546", "事件触发执行", "TA0003", "persistence"),
    ("T1053", "计划任务/作业", "TA0003", "persistence"),
    ("T1136", "创建账户", "TA0003", "persistence"),
    ("T1068", "利用漏洞提权", "TA0004", "privilege_escalation"),
    ("T1548", "滥用提升控制机制", "TA0004", "privilege_escalation"),
    ("T1055", "进程注入", "TA0005", "defense_evasion"),
    ("T1027", "混淆文件或信息", "TA0005", "defense_evasion"),
    ("T1562", "破坏防御机制", "TA0005", "defense_evasion"),
    ("T1003", "凭证转储", "TA0006", "credential_access"),
    ("T1555", "凭证从密码存储获取", "TA0006", "credential_access"),
    ("T1552", "不安全的凭证", "TA0006", "credential_access"),
    ("T1087", "账户发现", "TA0007", "discovery"),
    ("T1046", "网络服务扫描", "TA0007", "discovery"),
    ("T1069", "权限组发现", "TA0007", "discovery"),
    ("T1021", "远程服务", "TA0008", "lateral_movement"),
    ("T1550", "使用替代认证材料", "TA0008", "lateral_movement"),
    ("T1040", "网络嗅探", "TA0008", "lateral_movement"),
    ("T1005", "本地数据收集", "TA0009", "collection"),
    ("T1114", "电子邮件收集", "TA0009", "collection"),
    ("T1119", "自动化收集", "TA0009", "collection"),
    ("T1071", "应用层协议", "TA0011", "command_control"),
    ("T1573", "加密信道", "TA0011", "command_control"),
    ("T1090", "代理", "TA0011", "command_control"),
    ("T1041", "通过C2信道渗出", "TA0010", "exfiltration"),
    ("T1048", "替代渗出协议", "TA0010", "exfiltration"),
    ("T1567", "通过Web服务渗出", "TA0010", "exfiltration"),
    ("T1486", "数据加密以影响", "TA0040", "impact"),
    ("T1485", "数据销毁", "TA0040", "impact"),
    ("T1499", "服务拒绝", "TA0040", "impact"),
]

_KNOWN_TTP_PROFILES = [
    {
        "profile_id": "P-APT29", "name": "APT29 (Cozy Bear)",
        "ttps": ["T1566", "T1078", "T1059", "T1027", "T1003", "T1071", "T1041"],
        "industries": ["政府", "外交", "科研"],
        "origin": "俄罗斯",
    },
    {
        "profile_id": "P-APT33", "name": "APT33 (Elfin)",
        "ttps": ["T1566", "T1105", "T1003", "T1071", "T1041"],
        "industries": ["能源", "石化"],
        "origin": "伊朗",
    },
    {
        "profile_id": "P-Lazarus", "name": "Lazarus Group",
        "ttps": ["T1566", "T1204", "T1059", "T1546", "T1027", "T1105", "T1041", "T1486"],
        "industries": ["金融", "科技", "国防"],
        "origin": "朝鲜",
    },
]


# ==================== APT 检测引擎 ====================

class APTDetector:
    """APT 高级持续性威胁检测引擎。"""

    def __init__(self) -> None:
        self.tactics = _ATTACK_TACTICS
        self.techniques = [
            {"technique_id": tid, "name": tname, "tactic_id": tid2, "phase": phase,
             "detected_count": random.randint(0, 50)}
            for tid, tname, tid2, phase in _ATTACK_TECHNIQUES
        ]
        self.ttp_profiles = _KNOWN_TTP_PROFILES
        self.apt_alerts: List[Dict[str, Any]] = []
        self.c2_infrastructure: List[Dict[str, Any]] = []
        self.exfiltration_events: List[Dict[str, Any]] = []
        self.hunt_jobs: List[Dict[str, Any]] = []
        self._seed_demo_data()

    def _seed_demo_data(self) -> None:
        """填充演示数据。"""
        # 模拟 C2 基础设施
        for i in range(5):
            self.c2_infrastructure.append({
                "c2_id": f"C2-{uuid.uuid4().hex[:6].upper()}",
                "domain": f"update-{random.randint(100,999)}.{random.choice(['com','net','org','cc'])}",
                "ip": f"{random.randint(1,223)}.{random.randint(0,255)}.{random.randint(0,255)}.{random.randint(1,254)}",
                "port": random.choice([443, 8080, 8443, 53, 80]),
                "dga_score": round(random.uniform(0.3, 0.95), 3),
                "fast_flux": random.random() > 0.7,
                "cert_issuer": random.choice(["Let's Encrypt", "Unknown", "Self-signed"]),
                "first_seen": _now(),
                "threat_level": random.choice(["high", "high", "critical"]),
                "associated_apt": random.choice(["APT29", "Lazarus", "APT33", "未知"]),
            })

        # 模拟数据渗出事件
        for i in range(4):
            self.exfiltration_events.append({
                "exfil_id": f"EXF-{uuid.uuid4().hex[:6].upper()}",
                "source_user": f"user{random.randint(1,30):03d}",
                "source_host": f"host-{random.randint(1,20):03d}",
                "destination_ip": f"{random.randint(1,223)}.{random.randint(0,255)}.{random.randint(0,255)}.{random.randint(1,254)}",
                "volume_mb": round(random.uniform(50, 2000), 1),
                "protocol": random.choice(["HTTPS", "DNS", "FTP", "SSH", "ICMP"]),
                "encrypted": random.choice([True, True, False]),
                "time_sharded": random.random() > 0.6,
                "suspicion_score": round(random.uniform(0.5, 0.98), 3),
                "timestamp": _now(),
            })

    # ---------- 战术检测 ----------

    def detect_tactic(self, tactic_id: str) -> Dict[str, Any]:
        """检测某战术阶段的活动。"""
        tactic = next((t for t in self.tactics if t["id"] == tactic_id), None)
        if not tactic:
            return {"error": f"战术 {tactic_id} 不存在"}

        related_techs = [t for t in self.techniques if t["tactic_id"] == tactic_id]
        active = [t for t in related_techs if t["detected_count"] > 0]

        return {
            "tactic_id": tactic_id,
            "tactic_name": tactic["name"],
            "rank": tactic["rank"],
            "description": tactic["description"],
            "total_techniques": len(related_techs),
            "active_techniques": len(active),
            "techniques": active,
            "detection_coverage": round(len(active) / max(len(related_techs), 1), 4),
            "timestamp": _now(),
        }

    def detect_technique(self, technique_id: str) -> Dict[str, Any]:
        """检测单个 ATT&CK 技术。"""
        tech = next((t for t in self.techniques if t["technique_id"] == technique_id), None)
        if not tech:
            return {"error": f"技术 {technique_id} 不存在"}
        tactic = next((t for t in self.tactics if t["id"] == tech["tactic_id"]), {})
        return {
            "technique_id": technique_id,
            "technique_name": tech["name"],
            "tactic_id": tech["tactic_id"],
            "tactic_name": tactic.get("name", ""),
            "phase": tech["phase"],
            "detected_count": tech["detected_count"],
            "detection_status": "active" if tech["detected_count"] > 0 else "not_detected",
            "timestamp": _now(),
        }

    # ---------- TTP 匹配 ----------

    def match_ttp_profile(self, observed_ttps: List[str]) -> List[Dict[str, Any]]:
        """将观测到的 TTPs 与已知 APT 画像匹配。"""
        matches = []
        for profile in self.ttp_profiles:
            profile_set = set(profile["ttps"])
            observed_set = set(observed_ttps)
            overlap = profile_set & observed_set
            if overlap:
                score = len(overlap) / len(profile_set)
                matches.append({
                    "profile_id": profile["profile_id"],
                    "profile_name": profile["name"],
                    "origin": profile["origin"],
                    "matched_ttps": list(overlap),
                    "match_score": round(score, 4),
                    "match_level": "高" if score > 0.6 else ("中" if score > 0.3 else "低"),
                    "industries": profile["industries"],
                })
        matches.sort(key=lambda x: x["match_score"], reverse=True)
        return matches

    # ---------- 行为链分析 ----------

    def analyze_behavior_chain(self, events: List[Dict[str, Any]]) -> Dict[str, Any]:
        """多阶段攻击链关联分析。"""
        # 按时间排序事件
        sorted_events = sorted(events, key=lambda e: e.get("timestamp", ""))
        stages = []
        for evt in sorted_events:
            tactic_id = evt.get("tactic_id", "")
            tactic = next((t for t in self.tactics if t["id"] == tactic_id), None)
            stages.append({
                "timestamp": evt.get("timestamp", _now()),
                "tactic_id": tactic_id,
                "tactic_name": tactic["name"] if tactic else "未知",
                "technique_id": evt.get("technique_id", ""),
                "source_ip": evt.get("source_ip", ""),
                "target_host": evt.get("target_host", ""),
            })

        # 推断攻击阶段连续性
        tactic_order = [t["rank"] for t in self.tactics]
        covered_ranks = [s["tactic_name"] for s in stages]

        return {
            "chain_id": f"CHAIN-{uuid.uuid4().hex[:8].upper()}",
            "total_events": len(events),
            "stages": stages,
            "tactics_covered": covered_ranks,
            "chain_length": len(set(s["tactic_id"] for s in stages)),
            "attack_intent": self._infer_intent(covered_ranks),
            "attack_target": self._identify_target(stages),
            "reconstruction_quality": "high" if len(stages) >= 5 else ("medium" if len(stages) >= 3 else "low"),
            "timestamp": _now(),
        }

    def _infer_intent(self, tactics_covered: List[str]) -> str:
        if "数据渗出" in tactics_covered or "影响" in tactics_covered:
            return "数据窃取/破坏"
        if "横向移动" in tactics_covered and "收集" in tactics_covered:
            return "内网渗透与数据收集"
        if "权限提升" in tactics_covered and "凭证访问" in tactics_covered:
            return "提权与凭证窃取"
        if "初始访问" in tactics_covered and len(tactics_covered) <= 2:
            return "初步入侵"
        return "持续潜伏"

    def _identify_target(self, stages: List[Dict[str, Any]]) -> str:
        hosts = [s.get("target_host", "") for s in stages if s.get("target_host")]
        return max(set(hosts), key=hosts.count) if hosts else "未知"

    # ---------- 基础设施检测 ----------

    def detect_c2(self, domain: str, ip: str) -> Dict[str, Any]:
        """检测 C2 服务器特征。"""
        dga_score = round(min(len(set(domain)) / max(len(domain), 1) * random.uniform(0.5, 1.5), 1.0), 3)
        return {
            "domain": domain,
            "ip": ip,
            "dga_score": dga_score,
            "is_dga": dga_score > 0.6,
            "fast_flux_detected": random.random() > 0.7,
            "domain_flux": random.random() > 0.8,
            "ip_flux": random.random() > 0.8,
            "tunnel_detected": random.random() > 0.75,
            "threat_assessment": "malicious" if dga_score > 0.6 else "suspicious" if dga_score > 0.3 else "clean",
            "recommendation": "建议阻断并隔离" if dga_score > 0.6 else "建议持续监控",
            "timestamp": _now(),
        }

    # ---------- 数据渗出检测 ----------

    def detect_exfiltration(self, source_user: str, volume_mb: float,
                            protocol: str, destination: str) -> Dict[str, Any]:
        """检测数据渗出行为。"""
        suspicion = 0.3
        reasons = []

        if volume_mb > 500:
            suspicion += 0.3
            reasons.append(f"大容量传输: {volume_mb}MB")
        if protocol in ("DNS", "ICMP"):
            suspicion += 0.25
            reasons.append(f"非常规渗出协议: {protocol}")
        if random.random() > 0.5:
            suspicion += 0.2
            reasons.append("时间分片传输特征")
        if random.random() > 0.6:
            suspicion += 0.15
            reasons.append("加密数据传输无法审计")

        suspicion = round(min(suspicion, 1.0), 3)
        event = {
            "exfil_id": f"EXF-{uuid.uuid4().hex[:8].upper()}",
            "source_user": source_user,
            "destination": destination,
            "volume_mb": volume_mb,
            "protocol": protocol,
            "suspicion_score": suspicion,
            "reasons": reasons,
            "is_malicious": suspicion > 0.6,
            "severity": "critical" if suspicion > 0.8 else ("high" if suspicion > 0.6 else "medium"),
            "timestamp": _now(),
        }
        self.exfiltration_events.append(event)
        return event

    # ---------- 威胁狩猎 ----------

    def run_hunt(self, hunt_type: str, query: str, time_range_h: int = 24) -> Dict[str, Any]:
        """启动 APT 威胁狩猎任务。"""
        job_id = f"HUNT-{uuid.uuid4().hex[:8].upper()}"
        job = {
            "job_id": job_id,
            "hunt_type": hunt_type,
            "query": query,
            "time_range_h": time_range_h,
            "status": "completed",
            "results": {
                "events_scanned": random.randint(10000, 500000),
                "events_matched": random.randint(0, 50),
                "techniques_identified": random.sample([t[0] for t in _ATTACK_TECHNIQUES], k=random.randint(2, 6)),
                "ttp_matches": self.match_ttp_profile(
                    random.sample([t[0] for t in _ATTACK_TECHNIQUES], k=random.randint(3, 8))
                ),
                "confidence": round(random.uniform(0.6, 0.95), 3),
                "recommendation": "建议深入调查" if random.random() > 0.5 else "未发现显著威胁",
            },
            "created_at": _now(),
            "completed_at": _now(),
        }
        self.hunt_jobs.append(job)
        return job

    # ---------- 概览 ----------

    def overview(self) -> Dict[str, Any]:
        return {
            "total_tactics": len(self.tactics),
            "total_techniques": len(self.techniques),
            "techniques_with_detections": len([t for t in self.techniques if t["detected_count"] > 0]),
            "known_ttp_profiles": len(self.ttp_profiles),
            "c2_infrastructure_tracked": len(self.c2_infrastructure),
            "exfiltration_events": len(self.exfiltration_events),
            "hunt_jobs_completed": len(self.hunt_jobs),
            "critical_alerts": len([e for e in self.exfiltration_events if e["suspicion_score"] > 0.8]),
        }


# 单例
apt_detector = APTDetector()
