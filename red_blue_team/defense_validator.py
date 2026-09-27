# -*- coding: utf-8 -*-
"""
defense_validator.py — 防御检测验证（第24轮升级方向1）。

职责：
    1. 防御规则库（IDS/IPS/WAF/EDR/SIEM / Suricata / Snort / YARA / Sigma）
    2. 检测覆盖率分析（ATT&CK 技术检测覆盖率 / 盲区 / 检测强度 / 改进建议）
    3. 告警验证（攻击触发告警 / 准确性 / 误报率 / 漏报率 / 质量评估）
    4. 防御有效性评估（拦截率 / 检测率 / 响应率 / 恢复率 / 综合评分）
    5. 紫队协作（攻击方与防御方协作 / 信息共享 / 联合演练 / 改进闭环）
    6. 防御改进建议（规则优化 / 配置加固 / 流程改进 / 培训建议）

全部内存字典模拟。
"""

from __future__ import annotations

import random
import uuid
from datetime import datetime
from typing import Any, Dict, List, Optional

from red_blue_team.attack_simulator import ATTACK_TECHNIQUES, ATTACK_TACTICS


# ============================================================
# 1. 防御规则库
# ============================================================

DEFENSE_RULES: Dict[str, Dict[str, Any]] = {}


def _build_rules() -> None:
    """构建 IDS/IPS/WAF/EDR/SIEM/YARA/Sigma 规则库。"""
    raw = [
        # ---- Suricata / Snort IDS 规则 ----
        ("rule-suricata-log4j", "Suricata", "ids", "T1190",
         "alert http any any -> any any (msg:\"ATT&CK T1190 Log4Shell 探测\"; content:\"jndi:ldap\"; http_request_body; sid:2024001; rev:1;)",
         "Log4Shell JNDI 注入检测", 90, "suricata"),
        ("rule-suricata-sqlmap", "Suricata", "ids", "T1190",
         "alert http any any -> any any (msg:\"SQLMap 自动注入特征\"; content:\"sqlmap/\"; http_header; sid:2024002; rev:2;)",
         "SQLMap User-Agent 检测", 85, "suricata"),
        ("rule-snort-rdp-brute", "Snort", "ips", "T1110.001",
         "alert tcp any any -> $HOME_NET 3389 (msg:\"RDP 暴力破解\"; threshold: type both, track by_src, count 5, seconds 60; sid:3024001;)",
         "RDP 暴力破解阈值阻断", 88, "snort"),
        # ---- WAF 规则 ----
        ("rule-waf-xss", "ModSecurity", "waf", "T1190",
         "SecRule REQUEST_URI|REQUEST_BODY \"@rx <script\" \"id:1001,deny,status:403,msg:'XSS 探测'\"",
         "XSS 跨站脚本拦截", 92, "waf"),
        ("rule-waf-sqli", "ModSecurity", "waf", "T1190",
         "SecRule ARGS \"@rx union.*select\" \"id:1002,deny,msg:'SQL 注入特征'\"",
         "SQL 注入联合查询拦截", 95, "waf"),
        ("rule-waf-rce", "ModSecurity", "waf", "T1190",
         "SecRule REQUEST_BODY \"@exec|/bin/sh|cmd.exe\" \"id:1003,deny,msg:'命令执行特征'\"",
         "远程命令执行拦截", 90, "waf"),
        # ---- EDR 规则 ----
        ("rule-edr-mimikatz", "CrowdStrike", "edr", "T1003.001",
         "Detect LSASS memory access by unsigned non-system process",
         "Mimikatz LSASS 凭证转储检测", 96, "edr"),
        ("rule-edr-powershell-enc", "CrowdStrike", "edr", "T1059.001",
         "Detect PowerShell -enc / -EncodedCommand with AMSI bypass",
         "PowerShell 编码执行检测", 93, "edr"),
        ("rule-edr-injection", "SentinelOne", "edr", "T1055",
         "Detect remote thread creation into LSASS/explorer by unsigned binary",
         "进程注入检测", 94, "edr"),
        ("rule-edr-ransomware", "SentinelOne", "edr", "T1486",
         "Detect bulk file encryption with extension change pattern",
         "勒索软件批量加密行为检测", 97, "edr"),
        ("rule-edr-uac-bypass", "CrowdStrike", "edr", "T1548.002",
         "Detect fodhelper/eventvwr UAC bypass pattern",
         "UAC 绕过检测", 89, "edr"),
        # ---- SIEM / Sigma 规则 ----
        ("rule-sigma-rdp-login", "Sigma", "siem", "T1021.001",
         "title: RDP 异常登录 | logsource: product=windows, service=security | detection: EventID=4624 AND LogonType=10 AND src_ip not in allowlist",
         "RDP 异常登录关联分析", 87, "sigma"),
        ("rule-sigma-kerberoast", "Sigma", "siem", "T1558.003",
         "title: Kerberoasting | detection: many TGS requests for different SPNs in 5min",
         "Kerberoasting 票据请求异常", 86, "sigma"),
        ("rule-sigma-service-create", "Sigma", "siem", "T1543.003",
         "title: 可疑服务创建 | detection: EventID=4697 AND ImagePath not in system path",
         "可疑服务创建关联", 88, "sigma"),
        ("rule-sigma-admin-share", "Sigma", "siem", "T1021.002",
         "title: 管理共享访问 | detection: SMB admin$ write from non-admin host",
         "SMB 管理共享横向检测", 85, "sigma"),
        # ---- YARA 规则 ----
        ("rule-yarak-emotet", "YARA", "edr", "T1059.005",
         "rule Emotet { strings: $a = { 4D 5A 90 00 } $b = \"Emotet\" nocase condition: $a and $b }",
         "Emotet 恶意软件特征", 80, "yara"),
        ("rule-yarak-cobalt", "YARA", "edr", "T1071.001",
         "rule CobaltStrike { strings: $a = \"beacon.x64.dll\" $b = { FF 53 55 } condition: all of them }",
         "Cobalt Strike Beacon 特征", 84, "yara"),
    ]
    for rid, product, layer, tech_id, sig, desc, strength, engine in raw:
        DEFENSE_RULES[rid] = {
            "rule_id": rid,
            "product": product,
            "layer": layer,          # ids/ips/waf/edr/siem
            "engine": engine,
            "technique_id": tech_id,
            "signature": sig,
            "description": desc,
            "detection_strength": strength,
            "enabled": True,
            "created_at": datetime.now().isoformat(),
        }


_build_rules()


# ============================================================
# 2. 检测覆盖率分析
# ============================================================

class CoverageAnalyzer:
    """ATT&CK 技术检测覆盖率分析。"""

    def analyze(self) -> Dict[str, Any]:
        """分析当前防御规则库对 ATT&CK 技术的覆盖率。"""
        covered_techs = {r["technique_id"] for r in DEFENSE_RULES.values() if r["enabled"]}
        all_techs = set(ATTACK_TECHNIQUES.keys())
        total = len(all_techs)
        covered = len(covered_techs & all_techs)
        blind_spots = sorted(all_techs - covered_techs)

        # 按战术统计覆盖率
        by_tactic: Dict[str, Dict[str, Any]] = {}
        for tid, tech in ATTACK_TECHNIQUES.items():
            tac = tech["tactic"]
            by_tactic.setdefault(tac, {"covered": 0, "total": 0})
            by_tactic[tac]["total"] += 1
            if tid in covered_techs:
                by_tactic[tac]["covered"] += 1

        for tac, info in by_tactic.items():
            info["coverage_pct"] = round(info["covered"] / max(info["total"], 1) * 100, 1)
            info["tactic_cn"] = ATTACK_TACTICS.get(tac, {}).get("cn", tac)

        overall = round(covered / max(total, 1) * 100, 1)

        # 盲区技术详情
        blind_details = []
        for tid in blind_spots[:25]:
            t = ATTACK_TECHNIQUES.get(tid, {})
            blind_details.append({
                "tid": tid, "name": t.get("name"), "cn": t.get("cn"),
                "tactic": t.get("tactic"), "impact": t.get("impact"),
            })

        return {
            "total_techniques": total,
            "covered_techniques": covered,
            "coverage_pct": overall,
            "blind_spot_count": len(blind_spots),
            "by_tactic": by_tactic,
            "blind_spots": blind_details,
            "assessment": self._assess(overall),
            "recommendations": self._recommend(by_tactic, blind_details),
        }

    def _assess(self, pct: float) -> str:
        if pct >= 70:
            return "检测覆盖率良好，建议持续优化盲区"
        if pct >= 40:
            return "检测覆盖率中等，存在明显盲区需补齐"
        return "检测覆盖率严重不足，大量攻击技术无法发现"

    def _recommend(self, by_tactic: Dict[str, Any],
                   blind_details: List[Dict[str, Any]]) -> List[str]:
        recs: List[str] = []
        # 找出覆盖率最低的战术
        weak = sorted(by_tactic.items(), key=lambda x: x[1]["coverage_pct"])[:3]
        for tac, info in weak:
            if info["coverage_pct"] < 50:
                recs.append(f"战术「{info['tactic_cn']}」覆盖率仅 {info['coverage_pct']}%，"
                            f"建议新增 {info['total'] - info['covered']} 条检测规则")
        # 高影响盲区优先
        high_impact_blind = [b for b in blind_details if b.get("impact", 0) >= 4]
        if high_impact_blind:
            recs.append(f"存在 {len(high_impact_blind)} 个高影响盲区技术"
                        f"（如 {high_impact_blind[0]['cn']}），建议优先部署检测规则")
        recs.append("建议引入 MITRE CALDERA 自动化验证规则有效性")
        recs.append("建议建立规则定期演练与误报回流机制")
        return recs


# ============================================================
# 3. 告警验证
# ============================================================

ALERTS: Dict[str, Dict[str, Any]] = {}


class AlertValidator:
    """告警验证：攻击触发告警验证 / 准确性 / 误报率 / 漏报率。"""

    def trigger_alerts(self, attack_run: Dict[str, Any]) -> List[Dict[str, Any]]:
        """模拟攻击执行后触发的防御告警。"""
        tech_id = attack_run.get("technique_id", "")
        rule = next((r for r in DEFENSE_RULES.values()
                     if r["technique_id"] == tech_id and r["enabled"]), None)

        alerts: List[Dict[str, Any]] = []
        if rule:
            # 规则强度决定是否告警
            triggered = random.random() < (rule["detection_strength"] / 100.0)
            if triggered:
                aid = f"alert-{uuid.uuid4().hex[:10]}"
                alert = {
                    "alert_id": aid,
                    "rule_id": rule["rule_id"],
                    "product": rule["product"],
                    "layer": rule["layer"],
                    "technique_id": tech_id,
                    "technique_cn": ATTACK_TECHNIQUES.get(tech_id, {}).get("cn", tech_id),
                    "severity": "high" if rule["detection_strength"] >= 90 else "medium",
                    "message": f"[{rule['product']}] {rule['description']} 触发",
                    "attack_run_id": attack_run.get("run_id"),
                    "is_true_positive": True,
                    "triggered_at": datetime.now().isoformat(),
                }
                ALERTS[aid] = alert
                alerts.append(alert)
        return alerts

    def evaluate_alert_quality(self, exercise_id: str = "default") -> Dict[str, Any]:
        """评估告警质量：误报率/漏报率/准确性。"""
        total_alerts = len(ALERTS)
        true_pos = sum(1 for a in ALERTS.values() if a.get("is_true_positive"))
        false_pos = total_alerts - true_pos

        # 模拟漏报：基于未被任何告警覆盖的攻击运行
        false_neg = random.randint(0, max(1, total_alerts // 3))

        accuracy = round(true_pos / max(total_alerts, 1) * 100, 1)
        false_pos_rate = round(false_pos / max(total_alerts, 1) * 100, 1)
        false_neg_rate = round(false_neg / max(false_neg + true_pos, 1) * 100, 1)

        return {
            "exercise_id": exercise_id,
            "total_alerts": total_alerts,
            "true_positives": true_pos,
            "false_positives": false_pos,
            "false_negatives": false_neg,
            "alert_accuracy_pct": accuracy,
            "false_positive_rate_pct": false_pos_rate,
            "false_negative_rate_pct": false_neg_rate,
            "quality_grade": self._grade(accuracy, false_pos_rate),
        }

    def _grade(self, acc: float, fpr: float) -> str:
        if acc >= 90 and fpr <= 10:
            return "A 优秀"
        if acc >= 75:
            return "B 良好"
        if acc >= 60:
            return "C 一般"
        return "D 较差"


# ============================================================
# 4. 防御有效性评估
# ============================================================

class DefenseEffectiveness:
    """防御有效性：拦截率/检测率/响应率/恢复率/综合评分。"""

    def evaluate(self, attack_success_rate: float,
                  detection_rate: float,
                  response_time_min: float = 30.0) -> Dict[str, Any]:
        """综合防御评分。"""
        intercept_rate = round(1 - attack_success_rate, 2)
        # 响应时间越短响应率越高
        response_rate = round(max(0.3, 1 - response_time_min / 120.0), 2)
        recovery_rate = round(random.uniform(0.7, 0.98), 2)

        # 加权综合评分
        score = round(
            intercept_rate * 30 +
            detection_rate * 35 +
            response_rate * 20 +
            recovery_rate * 15, 1)

        if score >= 85:
            grade = "A 级防御体系"
        elif score >= 70:
            grade = "B 级防御体系"
        elif score >= 55:
            grade = "C 级防御体系"
        else:
            grade = "D 级防御体系（薄弱）"

        return {
            "intercept_rate": intercept_rate,
            "detection_rate": detection_rate,
            "response_rate": response_rate,
            "recovery_rate": recovery_rate,
            "defense_score": score,
            "defense_grade": grade,
            "benchmark": "对照 MITRE Engenuity 评估框架",
        }


# ============================================================
# 5. 紫队协作
# ============================================================

class PurpleTeam:
    """紫队协作：攻击方与防御方联合演练 / 信息共享 / 改进闭环。"""

    def __init__(self) -> None:
        self.sessions: Dict[str, Dict[str, Any]] = {}

    def start_session(self, name: str, red_team: List[str],
                      blue_team: List[str]) -> Dict[str, Any]:
        sid = f"purple-{uuid.uuid4().hex[:8]}"
        session = {
            "session_id": sid, "name": name,
            "red_team": red_team, "blue_team": blue_team,
            "shared_intel": [], "action_items": [],
            "status": "active",
            "started_at": datetime.now().isoformat(),
        }
        self.sessions[sid] = session
        return session

    def share_intel(self, session_id: str, intel: str,
                     from_team: str) -> Dict[str, Any]:
        """攻击方向防御方共享攻击情报。"""
        s = self.sessions.get(session_id)
        if not s:
            raise ValueError(f"未知紫队会话: {session_id}")
        entry = {"from": from_team, "intel": intel,
                 "shared_at": datetime.now().isoformat()}
        s["shared_intel"].append(entry)
        return entry

    def add_action_item(self, session_id: str, item: str,
                        owner: str) -> Dict[str, Any]:
        """生成改进闭环行动项。"""
        s = self.sessions.get(session_id)
        if not s:
            raise ValueError(f"未知紫队会话: {session_id}")
        ai = {"item": item, "owner": owner, "status": "open",
              "created_at": datetime.now().isoformat()}
        s["action_items"].append(ai)
        return ai

    def close_session(self, session_id: str) -> Dict[str, Any]:
        s = self.sessions.get(session_id)
        if not s:
            raise ValueError(f"未知紫队会话: {session_id}")
        s["status"] = "closed"
        s["closed_at"] = datetime.now().isoformat()
        return {
            "session_id": session_id,
            "shared_intel_count": len(s["shared_intel"]),
            "action_items_count": len(s["action_items"]),
            "open_items": sum(1 for i in s["action_items"] if i["status"] == "open"),
        }


# ============================================================
# 6. 防御改进建议引擎
# ============================================================

class DefenseImprover:
    """基于攻击结果生成防御改进建议。"""

    def generate(self, attack_results: List[Dict[str, Any]],
                 coverage: Dict[str, Any]) -> Dict[str, Any]:
        """综合攻击结果与覆盖率生成改进建议。"""
        rules_opt: List[str] = []
        hardening: List[str] = []
        process: List[str] = []
        training: List[str] = []

        # 基于成功攻击的技术
        for r in attack_results:
            if r.get("success"):
                tid = r.get("technique_id", "")
                tech = ATTACK_TECHNIQUES.get(tid, {})
                if tech:
                    rules_opt.append(f"为技术 {tid}({tech.get('cn')}) 优化"
                                     f"「{tech.get('mitigation')}」检测规则")
                if tech.get("tactic") in ("ta0001", "ta0006"):
                    hardening.append(f"针对 {tid} 加固: {tech.get('mitigation')}")

        # 基于覆盖率盲区
        for b in coverage.get("blind_spots", [])[:8]:
            if b.get("impact", 0) >= 4:
                rules_opt.append(f"新增高影响盲区 {b['tid']}({b.get('cn')}) 的检测规则")

        # 流程改进
        process.append("建立攻击演练-检测-响应的闭环验证流程")
        process.append("定期（季度）开展红蓝对抗以验证规则有效性")
        process.append("建立告警误报/漏报回流机制")

        # 培训建议
        if any(r.get("technique_id", "").startswith("T1566") for r in attack_results):
            training.append("开展钓鱼邮件识别专项培训")
        if any(r.get("technique_id", "") in ("T1003.001",) for r in attack_results):
            training.append("开展管理员凭证安全意识培训")

        return {
            "rule_optimizations": rules_opt[:10],
            "hardening_actions": hardening[:10],
            "process_improvements": process,
            "training_recommendations": training,
            "priority": "P1 紧急" if coverage.get("coverage_pct", 0) < 40 else "P2 高",
            "estimated_effort": "2-4 周",
        }


# ============================================================
# 7. 单例导出
# ============================================================

_analyzer = CoverageAnalyzer()
_validator = AlertValidator()
_effectiveness = DefenseEffectiveness()
_purple = PurpleTeam()
_improver = DefenseImprover()


def get_defense_validator() -> Dict[str, Any]:
    return {
        "rules": DEFENSE_RULES,
        "analyzer": _analyzer,
        "validator": _validator,
        "effectiveness": _effectiveness,
        "purple": _purple,
        "improver": _improver,
    }


def stats() -> Dict[str, Any]:
    return {
        "rules_count": len(DEFENSE_RULES),
        "alerts_count": len(ALERTS),
        "purple_sessions": len(_purple.sessions),
    }
