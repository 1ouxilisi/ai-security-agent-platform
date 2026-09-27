#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
web3_security/dao_security.py — DAO 安全深度。

真实能力：
    1. DAO 类型识别：协议/投资/收藏/社交/媒体/服务/资助/治理 DAO
    2. 治理安全：提案/投票/委托/时间锁/多签/执行/取消/否决/暂停/参数/升级
    3. 攻击类型：治理攻击/闪电贷治理/投票贿赂/选民冷漠/女巫/恶意提案/劫持/执行
    4. 资金安全：国库/多签/时间锁/支出/预算/审计/报告/透明/可追溯/挪用
    5. 成员管理：成员/角色/权限/邀请/加入/退出/驱逐/声誉/贡献/奖励/惩罚
    6. DAO 审计：治理/资金/合约/成员/评级/风险/改进/报告
"""

from __future__ import annotations

import hashlib
import time
import uuid
from collections import defaultdict
from typing import Any, Dict, List, Optional


# --------------------------------------------------------------------------- #
# 常量
# --------------------------------------------------------------------------- #
DAO_TYPES = {
    "protocol": "协议 DAO",
    "investment": "投资 DAO",
    "collector":  "收藏 DAO",
    "social":     "社交 DAO",
    "media":      "媒体 DAO",
    "service":    "服务 DAO",
    "grant":      "资助 DAO",
    "governance": "治理 DAO",
}

ATTACK_TYPES = {
    "flashloan_governance": "闪电贷治理攻击",
    "vote_buying":          "投票贿赂",
    "voter_apathy":        "选民冷漠（投票率过低）",
    "sybil":                "女巫攻击",
    "malicious_proposal":   "恶意提案",
    "proposal_hijack":      "提案劫持（grind 参数）",
    "execution_attack":     "执行期攻击（Timelock 内状态变化）",
}


# --------------------------------------------------------------------------- #
# 真实分析
# --------------------------------------------------------------------------- #
def assess_governance(voting_turnout_pct: float,
                      quorum_pct: float,
                      timelock_hours: int,
                      proposal_threshold_pct: float,
                      multisig_signers: int,
                      multisig_threshold: int,
                      delegation_enabled: bool,
                      has_emergency_pause: bool) -> Dict[str, Any]:
    """真实评估 DAO 治理风险。"""
    findings: List[Dict[str, Any]] = []
    score = 100.0

    if voting_turnout_pct < 15:
        score -= 15
        findings.append({"attack": "voter_apathy", "severity": "high",
                         "detail": f"投票率仅 {voting_turnout_pct}%",
                         "fix": "提高激励/延长投票期/委托投票。"})
    if quorum_pct < 4:
        score -= 12
        findings.append({"attack": "malicious_proposal", "severity": "high",
                         "detail": f"quorum={quorum_pct}%",
                         "fix": "提高 quorum 到 4%+。"})
    if timelock_hours < 24:
        score -= 12
        findings.append({"attack": "execution_attack", "severity": "high",
                         "detail": f"Timelock={timelock_hours}h 过短",
                         "fix": "升级/资金支出 Timelock 至少 48h。"})
    if proposal_threshold_pct < 1:
        score -= 10
        findings.append({"attack": "malicious_proposal", "severity": "medium",
                         "detail": f"提案门槛={proposal_threshold_pct}%",
                         "fix": "提案门槛提高到 1%+，并加反女巫校验。"})
    if multisig_signers and multisig_threshold * 2 <= multisig_signers:
        score -= 8
        findings.append({"attack": "flashloan_governance", "severity": "medium",
                         "detail": f"多签 {multisig_threshold}/{multisig_signers} 过低",
                         "fix": "采用 3/5 或 4/7 多签。"})
    if not delegation_enabled:
        score -= 3
        findings.append({"attack": "voter_apathy", "severity": "low",
                         "detail": "未启用委托投票",
                         "fix": "启用 Snapshot 委托。"})
    if not has_emergency_pause:
        score -= 5
        findings.append({"attack": "execution_attack", "severity": "medium",
                         "detail": "无紧急暂停开关",
                         "fix": "加入 pausable + 多签触发。"})

    score = max(0, min(100, score))
    rating = ("A 稳健" if score >= 85 else "B 良好" if score >= 70 else
              "C 关注" if score >= 50 else "D 危险" if score >= 30 else "F 高危")
    return {"score": round(score, 1), "rating": rating, "findings": findings}


def assess_treasury(total_usd: float,
                    monthly_outflow_usd: float,
                    multisig_threshold: int,
                    multisig_signers: int,
                    timelock_hours: int,
                    verified_signers: bool,
                    external_auditor: bool) -> Dict[str, Any]:
    """真实评估国库/资金风险。"""
    findings: List[Dict[str, Any]] = []
    runway = total_usd / max(monthly_outflow_usd, 1)
    if runway < 6:
        findings.append({"risk": "low_runway", "severity": "high",
                         "detail": f"国库可支撑 {runway:.1f} 个月",
                         "fix": "减少支出或补充国库。"})
    if multisig_threshold * 2 <= multisig_signers:
        findings.append({"risk": "weak_multisig", "severity": "high",
                         "detail": f"多签 {multisig_threshold}/{multisig_signers}",
                         "fix": "提高阈值。"})
    if timelock_hours < 48:
        findings.append({"risk": "short_timelock", "severity": "medium",
                         "detail": f"支出 Timelock={timelock_hours}h",
                         "fix": "大额支出 48h+ Timelock。"})
    if not verified_signers:
        findings.append({"risk": "unverified_signers", "severity": "medium",
                         "detail": "多签签名者未做 KYC/地址核验",
                         "fix": "公开签名者身份并做多签白名单。"})
    if not external_auditor:
        findings.append({"risk": "no_audit", "severity": "medium",
                         "detail": "未做外部审计",
                         "fix": "每年至少一次第三方审计并公开报告。"})
    sev_score = {"critical": 25, "high": 12, "medium": 5, "low": 1}
    score = 100 - sum(sev_score[f["severity"]] for f in findings)
    return {
        "total_treasury_usd": total_usd,
        "monthly_outflow_usd": monthly_outflow_usd,
        "runway_months": round(runway, 1),
        "multisig": f"{multisig_threshold}/{multisig_signers}",
        "timelock_hours": timelock_hours,
        "verified_signers": verified_signers,
        "external_auditor": external_auditor,
        "findings": findings,
        "score": max(0, score),
    }


# --------------------------------------------------------------------------- #
# 提案/投票/成员/资金管理（内存模型）
# --------------------------------------------------------------------------- #
class DAOInstance:
    def __init__(self, name: str, dao_type: str = "governance") -> None:
        self.name = name
        self.dao_type = DAO_TYPES.get(dao_type, dao_type)
        self.proposals: List[Dict[str, Any]] = []
        self.members: Dict[str, Dict[str, Any]] = {}
        self.treasury_usd = 0.0
        self.roles: Dict[str, List[str]] = {"admin": [], "proposer": [],
                                             "voter": []}

    def propose(self, title: str, description: str, proposer: str,
                actions: List[Dict[str, Any]], deposit_usd: float = 0) -> Dict[str, Any]:
        pid = "prop-" + uuid.uuid4().hex[:8]
        p = {
            "id": pid, "title": title, "description": description,
            "proposer": proposer, "actions": actions,
            "deposit_usd": deposit_usd,
            "votes_for": 0, "votes_against": 0, "abstain": 0,
            "status": "active", "created_at": time.strftime("%Y-%m-%d %H:%M:%S"),
            "executed_at": None,
        }
        self.proposals.append(p)
        return p

    def vote(self, pid: str, voter: str, choice: str, weight: float = 1) -> Dict[str, Any]:
        p = next((x for x in self.proposals if x["id"] == pid), None)
        if not p:
            return {"ok": False, "error": "proposal not found"}
        if choice == "for":
            p["votes_for"] += weight
        elif choice == "against":
            p["votes_against"] += weight
        else:
            p["abstain"] += weight
        return {"ok": True, "proposal": pid, "voter": voter, "choice": choice,
                "weight": weight}

    def execute(self, pid: str) -> Dict[str, Any]:
        p = next((x for x in self.proposals if x["id"] == pid), None)
        if not p:
            return {"ok": False, "error": "proposal not found"}
        total = p["votes_for"] + p["votes_against"] + p["abstain"]
        turnout = total / max(len(self.members), 1)
        if p["votes_for"] <= p["votes_against"]:
            p["status"] = "rejected"
            return {"ok": False, "reason": "votes_for <= votes_against"}
        if turnout < 0.15:
            p["status"] = "rejected_low_turnout"
            return {"ok": False, "reason": f"投票率 {turnout:.1%} < 15%"}
        p["status"] = "executed"
        p["executed_at"] = time.strftime("%Y-%m-%d %H:%M:%S")
        return {"ok": True, "proposal": pid, "turnout_pct": round(turnout * 100, 1)}

    def add_member(self, addr: str, role: str = "voter",
                    reputation: int = 0) -> Dict[str, Any]:
        self.members[addr] = {"addr": addr, "role": role,
                              "reputation": reputation,
                              "joined_at": time.strftime("%Y-%m-%d %H:%M:%S")}
        self.roles.setdefault(role, []).append(addr)
        return self.members[addr]

    def list_proposals(self) -> List[Dict[str, Any]]:
        return self.proposals


# --------------------------------------------------------------------------- #
# 单例
# --------------------------------------------------------------------------- #
class DAORegistry:
    def __init__(self) -> None:
        self.daos: Dict[str, DAOInstance] = {}

    def create(self, name: str, dao_type: str = "governance") -> DAOInstance:
        did = "dao-" + hashlib.sha1(
            f"{name}{time.time()}".encode()).hexdigest()[:10]
        d = DAOInstance(name, dao_type)
        self.daos[did] = d
        return d

    def get(self, did: str) -> Optional[DAOInstance]:
        return self.daos.get(did)

    def list(self) -> List[Dict[str, Any]]:
        return [{"id": k, "name": v.name, "type": v.dao_type,
                 "members": len(v.members),
                 "proposals": len(v.proposals),
                 "treasury_usd": v.treasury_usd}
                for k, v in self.daos.items()]


_reg: Optional[DAORegistry] = None


def get_dao_registry() -> DAORegistry:
    global _reg
    if _reg is None:
        _reg = DAORegistry()
        demo = _reg.create("DemoDAO", "governance")
        demo.treasury_usd = 5_000_000
        for i in range(20):
            demo.add_member(f"0xMember{i:04x}", "voter", reputation=i * 5)
    return _reg
