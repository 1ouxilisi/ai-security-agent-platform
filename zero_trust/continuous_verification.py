# -*- coding: utf-8 -*-
"""
continuous_verification.py — 持续验证与动态授权器（第13轮升级 · 零信任模块）。

功能：
- 实时风险评估：登录风险 / 访问风险 / 操作风险 / 数据风险的实时计算
- 设备信任评分：设备合规性 / 安全状态 / 补丁级别 / 终端防护 / 越狱Root /
  设备指纹的信任评分（0-100）
- 位置异常：异常地理位置 / 不可能旅行 / 新位置 / 高危国家 / IP信誉
- 行为基线：用户正常行为基线学习 / 行为偏离检测 / 异常操作序列 / 异常访问时间
- 自适应访问策略：基于风险/设备/位置/行为的动态授权策略
  （允许 / 拒绝 / 步长认证 / 限制访问）
- 会话持续监控：会话风险实时更新 / 异常会话检测 / 会话超时 / 会话终止 /
  会话并发限制
- 步长认证(Step-up Auth)：高风险操作触发额外认证 / 认证方式升级 / 认证频率
- 持续验证报告

说明：仅做风险评估与策略建议，不实际拦截用户会话、不读取真实网络流量。
"""

from __future__ import annotations

import hashlib
import random
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from typing import Any, Dict, List, Optional


# ==================== 内嵌风险因子库 ====================

# 高危国家/地区（示例，用于位置异常评估）
HIGH_RISK_COUNTRIES = [
    "XX-制裁名单A", "XX-制裁名单B", "XX-高风险地区C",
]

# IP 信誉评分基线（模拟）
IP_REPUTATION_BASE = {
    "known_bad": 10, "proxy_vpn": 30, "residential": 75,
    "corporate": 90, "datacenter": 55, "unknown": 50,
}

# 自适应策略决策矩阵
ADAPTIVE_ACTIONS = {
    "allow":  {"name": "允许访问",       "color": "green",  "desc": "风险低，放行当前访问"},
    "step_up": {"name": "步长认证",     "color": "yellow", "desc": "要求额外MFA验证后继续"},
    "restrict": {"name": "限制访问",    "color": "orange", "desc": "限制数据下载/操作范围"},
    "deny":   {"name": "拒绝访问",       "color": "red",    "desc": "阻断访问并触发告警"},
}

# 步长认证触发阈值
STEP_UP_THRESHOLDS = {
    "low": 0, "medium": 40, "high": 65, "critical": 85,
}


# ==================== 数据结构 ====================

@dataclass
class SessionRecord:
    """模拟会话记录"""
    session_id: str
    username: str
    device_id: str
    ip: str = ""
    country: str = ""
    login_time: str = ""
    risk_score: int = 0
    status: str = "active"
    concurrent: int = 1


# ==================== 主评估器 ====================

class ContinuousVerifier:
    """持续验证与动态授权器（评估视角）。"""

    def __init__(self) -> None:
        self.risk_weights: Dict[str, float] = {
            "login": 0.25, "access": 0.25,
            "operation": 0.25, "data": 0.25,
        }
        self.baselines: Dict[str, Dict[str, Any]] = {}
        self.sessions: Dict[str, SessionRecord] = {}
        self._seed_baselines()
        self._seed_sessions()

    # ---------- 模拟基线与会话 ----------

    def _seed_baselines(self) -> None:
        rng = random.Random(1302)
        for i in range(1, 21):
            uname = f"user{i:04d}"
            self.baselines[uname] = {
                "typical_hours": sorted(rng.sample(range(6, 22), 8)),
                "typical_countries": ["CN"],
                "typical_apps": [f"app_{rng.randint(1, 10)}" for _ in range(3)],
                "typical_data_mb": rng.randint(5, 80),
                "typical_ops_per_day": rng.randint(20, 200),
            }

    def _seed_sessions(self) -> None:
        rng = random.Random(1303)
        now = datetime.now()
        for i in range(1, 31):
            sid = f"sess_{i:04d}"
            self.sessions[sid] = SessionRecord(
                session_id=sid,
                username=f"user{rng.randint(1, 20):04d}",
                device_id=f"dev_{rng.randint(1, 50):04d}",
                ip=f"10.0.{rng.randint(0, 255)}.{rng.randint(1, 254)}",
                country="CN",
                login_time=(now - timedelta(minutes=rng.randint(1, 600))).isoformat(),
                risk_score=rng.randint(5, 90),
                status="active",
                concurrent=rng.choice([1, 1, 1, 2, 3]),
            )

    # ---------- 实时风险评估 ----------

    def realtime_risk(self, username: str = "user0001",
                      device_id: str = "dev_0001",
                      ip: str = "10.0.0.1",
                      country: str = "CN",
                      hour: Optional[int] = None,
                      app: str = "app_1") -> Dict[str, Any]:
        """实时计算登录/访问/操作/数据四维风险。"""
        if hour is None:
            hour = datetime.now().hour
        # 登录风险：位置/时间/IP
        login_risk = 10
        if country not in ("CN",) and country not in self.baselines.get(username, {}).get("typical_countries", ["CN"]):
            login_risk += 40
        if country in HIGH_RISK_COUNTRIES:
            login_risk += 30
        if hour not in self.baselines.get(username, {}).get("typical_hours", range(6, 22)):
            login_risk += 20
        # 访问风险：应用偏离基线
        access_risk = 10
        if app not in self.baselines.get(username, {}).get("typical_apps", []):
            access_risk += 35
        # 操作风险：模拟操作序列异常
        operation_risk = random.Random(hash(username) & 0xffff).randint(5, 60)
        # 数据风险：下载量异常
        baseline_mb = self.baselines.get(username, {}).get("typical_data_mb", 30)
        data_risk = min(80, int(baseline_mb * 1.5))
        # 综合
        overall = int(round(
            login_risk * self.risk_weights["login"]
            + access_risk * self.risk_weights["access"]
            + operation_risk * self.risk_weights["operation"]
            + data_risk * self.risk_weights["data"]
        ))
        return {
            "username": username, "device_id": device_id, "ip": ip,
            "country": country, "hour": hour, "app": app,
            "dimensions": {
                "login": {"score": login_risk, "level": self._level(login_risk)},
                "access": {"score": access_risk, "level": self._level(access_risk)},
                "operation": {"score": operation_risk, "level": self._level(operation_risk)},
                "data": {"score": data_risk, "level": self._level(data_risk)},
            },
            "overall_risk": overall,
            "level": self._level(overall),
            "recommended_action": self._action(overall),
            "evaluated_at": datetime.now().isoformat(),
        }

    # ---------- 设备信任评分 ----------

    def device_trust_score(self, device_id: str = "dev_0001",
                           os_name: str = "Windows 11",
                           os_version: str = "23H2",
                           patched: bool = True,
                           edr_installed: bool = True,
                           edr_running: bool = True,
                           disk_encrypted: bool = True,
                           firewall_on: bool = True,
                           screen_lock: bool = True,
                           jailbroken: bool = False,
                           rooted: bool = False,
                           debug_mode: bool = False) -> Dict[str, Any]:
        """计算设备信任评分（0-100，越高越可信）。"""
        score = 100
        deductions: List[Dict[str, Any]] = []
        if not patched:
            score -= 15
            deductions.append({"factor": "未打补丁", "penalty": 15, "severity": "high"})
        if not edr_installed:
            score -= 20
            deductions.append({"factor": "未安装EDR", "penalty": 20, "severity": "critical"})
        elif not edr_running:
            score -= 10
            deductions.append({"factor": "EDR已停止运行", "penalty": 10, "severity": "high"})
        if not disk_encrypted:
            score -= 10
            deductions.append({"factor": "磁盘未加密", "penalty": 10, "severity": "high"})
        if not firewall_on:
            score -= 8
            deductions.append({"factor": "防火墙关闭", "penalty": 8, "severity": "medium"})
        if not screen_lock:
            score -= 5
            deductions.append({"factor": "无屏幕锁", "penalty": 5, "severity": "medium"})
        if jailbroken or rooted:
            score -= 40
            deductions.append({"factor": "设备越狱/Root", "penalty": 40, "severity": "critical"})
        if debug_mode:
            score -= 10
            deductions.append({"factor": "调试模式开启", "penalty": 10, "severity": "high"})
        score = max(0, min(100, score))
        level = "trusted" if score >= 80 else ("restricted" if score >= 50 else "untrusted")
        return {
            "device_id": device_id,
            "os": f"{os_name} {os_version}".strip(),
            "trust_score": score,
            "trust_level": level,
            "deductions": deductions,
            "policy_advice": {
                "trusted": "允许全量访问，持续监控",
                "restricted": "仅允许访问非敏感应用，禁止下载数据",
                "untrusted": "隔离至访客网络，禁止访问企业资源",
            }[level],
            "evaluated_at": datetime.now().isoformat(),
        }

    # ---------- 位置异常 ----------

    def location_anomaly(self, username: str = "user0001",
                         current_country: str = "US",
                         prev_country: str = "CN",
                         hours_between: float = 2.0,
                         is_new_location: bool = False,
                         ip_reputation: str = "corporate") -> Dict[str, Any]:
        """检测不可能旅行 / 新位置 / 高危国家 / IP信誉。"""
        findings: List[Dict[str, Any]] = []
        risk = 0
        # 不可能旅行：2 小时内跨洲际
        if current_country != prev_country and hours_between < 6:
            findings.append({
                "type": "impossible_travel",
                "severity": "critical",
                "desc": f"{hours_between} 小时内从 {prev_country} 到 {current_country}，物理上不可能",
            })
            risk += 60
        if is_new_location:
            findings.append({
                "type": "new_location", "severity": "medium",
                "desc": f"{username} 首次从 {current_country} 登录",
            })
            risk += 20
        if current_country in HIGH_RISK_COUNTRIES:
            findings.append({
                "type": "high_risk_country", "severity": "high",
                "desc": f"登录地为高风险地区 {current_country}",
            })
            risk += 30
        ip_rep_score = IP_REPUTATION_BASE.get(ip_reputation, 50)
        if ip_rep_score < 40:
            findings.append({
                "type": "ip_reputation_bad", "severity": "high",
                "desc": f"IP 信誉差（{ip_reputation}），疑似代理/VPN/恶意节点",
            })
            risk += 25
        risk = min(100, risk)
        return {
            "username": username,
            "current_country": current_country,
            "previous_country": prev_country,
            "hours_between": hours_between,
            "is_new_location": is_new_location,
            "ip_reputation": ip_reputation,
            "ip_reputation_score": ip_rep_score,
            "anomalies": findings,
            "anomaly_count": len(findings),
            "location_risk": risk,
            "action": self._action(risk),
        }

    # ---------- 行为基线与偏离 ----------

    def behavior_deviation(self, username: str = "user0001",
                           hour: Optional[int] = None,
                           ops_today: int = 500,
                           data_mb: float = 500.0,
                           new_apps: Optional[List[str]] = None) -> Dict[str, Any]:
        """与用户行为基线对比，检测偏离。"""
        if hour is None:
            hour = datetime.now().hour
        base = self.baselines.get(username, {})
        deviations: List[Dict[str, Any]] = []
        risk = 0
        if hour not in base.get("typical_hours", range(6, 22)):
            deviations.append({"type": "off_hours", "severity": "medium",
                               "desc": f"当前 {hour} 时不在正常活跃时段"})
            risk += 15
        if ops_today > base.get("typical_ops_per_day", 100) * 3:
            deviations.append({"type": "ops_spike", "severity": "high",
                               "desc": f"今日操作 {ops_today} 次，远超基线 {base.get('typical_ops_per_day')}"})
            risk += 30
        if data_mb > base.get("typical_data_mb", 30) * 5:
            deviations.append({"type": "data_bulk_download", "severity": "critical",
                               "desc": f"下载 {data_mb}MB，超基线 {base.get('typical_data_mb')}MB 的 5 倍，疑似数据泄露"})
            risk += 45
        for app in (new_apps or []):
            if app not in base.get("typical_apps", []):
                deviations.append({"type": "new_app_access", "severity": "medium",
                                   "desc": f"首次访问应用 {app}"})
                risk += 10
        risk = min(100, risk)
        return {
            "username": username,
            "baseline": base,
            "current": {"hour": hour, "ops_today": ops_today,
                        "data_mb": data_mb, "new_apps": new_apps or []},
            "deviations": deviations,
            "deviation_count": len(deviations),
            "behavior_risk": risk,
            "level": self._level(risk),
        }

    # ---------- 自适应访问策略 ----------

    def adaptive_policy(self, overall_risk: int,
                        device_trust: int,
                        location_risk: int,
                        behavior_risk: int) -> Dict[str, Any]:
        """综合四维信号，输出动态授权决策。"""
        combined = int(round(overall_risk * 0.35 + (100 - device_trust) * 0.25
                            + location_risk * 0.2 + behavior_risk * 0.2))
        if combined >= STEP_UP_THRESHOLDS["critical"]:
            action = "deny"
        elif combined >= STEP_UP_THRESHOLDS["high"]:
            action = "step_up"
        elif combined >= STEP_UP_THRESHOLDS["medium"]:
            action = "restrict"
        else:
            action = "allow"
        policy = ADAPTIVE_ACTIONS[action]
        steps: List[str] = []
        if action == "step_up":
            steps.append("要求硬件密钥/生物识别二次验证")
            steps.append("会话有效期缩短至 15 分钟")
        if action == "restrict":
            steps.append("禁用数据导出与批量下载")
            steps.append("只读访问，禁止权限变更")
        if action == "deny":
            steps.append("立即终止会话并锁定账户")
            steps.append("触发安全运营告警与人工复核")
        return {
            "signals": {"overall_risk": overall_risk, "device_trust": device_trust,
                        "location_risk": location_risk, "behavior_risk": behavior_risk},
            "combined_score": combined,
            "decision": action,
            "decision_name": policy["name"],
            "desc": policy["desc"],
            "enforcement_steps": steps,
            "evaluated_at": datetime.now().isoformat(),
        }

    # ---------- 会话监控 ----------

    def session_monitor(self) -> Dict[str, Any]:
        """当前会话池健康度与异常会话检测。"""
        active = [s for s in self.sessions.values() if s.status == "active"]
        anomalies: List[Dict[str, Any]] = []
        for s in active:
            flags = []
            if s.risk_score >= 70:
                flags.append("高风险会话")
            if s.concurrent >= 2:
                flags.append(f"并发登录 {s.concurrent} 处")
            if flags:
                anomalies.append({
                    "session_id": s.session_id, "username": s.username,
                    "device_id": s.device_id, "ip": s.ip,
                    "risk_score": s.risk_score, "flags": flags,
                })
        return {
            "total_sessions": len(self.sessions),
            "active_sessions": len(active),
            "anomalous_sessions": anomalies,
            "anomaly_count": len(anomalies),
            "policy": {
                "idle_timeout_minutes": 30,
                "max_concurrent_sessions": 2,
                "absolute_timeout_hours": 12,
            },
            "recommendations": [
                "高风险会话立即触发步长认证或强制下线",
                "限制单用户并发会话数",
                "配置空闲超时 30 分钟、绝对超时 12 小时",
            ],
        }

    # ---------- 步长认证 ----------

    def step_up_auth(self, username: str, risk_score: int,
                     current_method: str = "password") -> Dict[str, Any]:
        """根据风险决定是否升级认证。"""
        required = risk_score >= STEP_UP_THRESHOLDS["medium"]
        upgraded_method = current_method
        if risk_score >= STEP_UP_THRESHOLDS["critical"]:
            upgraded_method = "hardware_key"
        elif risk_score >= STEP_UP_THRESHOLDS["high"]:
            upgraded_method = "biometric"
        elif risk_score >= STEP_UP_THRESHOLDS["medium"]:
            upgraded_method = "totp_or_push"
        return {
            "username": username,
            "risk_score": risk_score,
            "step_up_required": required,
            "current_method": current_method,
            "required_method": upgraded_method if required else current_method,
            "frequency_policy": "高风险操作每次触发；常规访问每 12 小时一次",
            "message": ("已触发步长认证，请使用 " + upgraded_method
                       if required else "风险较低，无需步长认证"),
        }

    # ---------- 综合报告 ----------

    def full_report(self) -> Dict[str, Any]:
        rt = self.realtime_risk()
        dt = self.device_trust_score()
        loc = self.location_anomaly()
        beh = self.behavior_deviation()
        pol = self.adaptive_policy(rt["overall_risk"], dt["trust_score"],
                                   loc["location_risk"], beh["behavior_risk"])
        sess = self.session_monitor()
        return {
            "report_title": "持续验证与动态授权报告",
            "generated_at": datetime.now().isoformat(),
            "realtime_risk": rt,
            "device_trust": dt,
            "location_anomaly": loc,
            "behavior_deviation": beh,
            "adaptive_decision": pol,
            "sessions": sess,
            "summary": (
                f"综合决策：{pol['decision_name']}（{pol['combined_score']} 分）；"
                f"异常位置事件 {loc['anomaly_count']} 起；"
                f"行为偏离 {beh['deviation_count']} 项；"
                f"异常会话 {sess['anomaly_count']} 个。"
            ),
        }

    # ---------- 工具 ----------

    @staticmethod
    def _level(score: int) -> str:
        if score >= 80:
            return "critical"
        if score >= 60:
            return "high"
        if score >= 40:
            return "medium"
        return "low"

    def _action(self, score: int) -> str:
        if score >= STEP_UP_THRESHOLDS["critical"]:
            return "deny"
        if score >= STEP_UP_THRESHOLDS["high"]:
            return "step_up"
        if score >= STEP_UP_THRESHOLDS["medium"]:
            return "restrict"
        return "allow"


# ==================== 工厂函数 ====================

_cv_singleton: Optional[ContinuousVerifier] = None


def get_continuous_verifier() -> ContinuousVerifier:
    global _cv_singleton
    if _cv_singleton is None:
        _cv_singleton = ContinuousVerifier()
    return _cv_singleton
