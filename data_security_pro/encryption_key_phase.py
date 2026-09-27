# -*- coding: utf-8 -*-
"""
encryption_key_phase.py — 阶段6：加密与密钥。

- 加密强度评估：算法/弱算法/密钥长度/加密模式（ECB）
- 密钥管理审计：轮换/存储/访问控制/备份恢复
- 未加密数据检测：字段/文件/传输/备份
- 加密覆盖率统计 + 风险评分
"""

from __future__ import annotations

import time
import uuid
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional


# 算法强度分级
ALGO_STRENGTH = {
    "AES-256": {"level": "strong", "risk": 5},
    "AES-128": {"level": "good", "risk": 15},
    "RSA-2048": {"level": "good", "risk": 15},
    "RSA-4096": {"level": "strong", "risk": 5},
    "ECC-256": {"level": "strong", "risk": 5},
    "SHA-256": {"level": "good", "risk": 10},
    "SHA-512": {"level": "strong", "risk": 5},
    "HMAC-SHA256": {"level": "good", "risk": 10},
    # 弱算法
    "DES": {"level": "weak", "risk": 90},
    "3DES": {"level": "weak", "risk": 70},
    "MD5": {"level": "weak", "risk": 80},
    "SHA1": {"level": "weak", "risk": 75},
    "RC4": {"level": "weak", "risk": 85},
    "Blowfish": {"level": "weak", "risk": 50},
}

WEAK_ALGOS = ["DES", "3DES", "MD5", "SHA1", "RC4"]


@dataclass
class EncryptionFinding:
    finding_id: str
    scope: str           # database_field/file/transport/backup/key
    target: str
    algorithm: str
    mode: str = ""
    key_length: int = 0
    risk_score: int = 0
    detail: str = ""

    def to_dict(self) -> Dict[str, Any]:
        return {
            "finding_id": self.finding_id, "scope": self.scope,
            "target": self.target, "algorithm": self.algorithm,
            "mode": self.mode, "key_length": self.key_length,
            "risk_score": self.risk_score, "detail": self.detail,
        }


@dataclass
class KeyRecord:
    key_id: str
    name: str
    storage: str          # HSM/KMS/明文配置/代码仓库
    rotated_days_ago: int = 0
    rotation_interval_days: int = 90
    access: str = "restricted"
    backed_up: bool = True

    def to_dict(self) -> Dict[str, Any]:
        overdue = self.rotated_days_ago > self.rotation_interval_days
        return {
            "key_id": self.key_id, "name": self.name,
            "storage": self.storage,
            "rotated_days_ago": self.rotated_days_ago,
            "rotation_interval_days": self.rotation_interval_days,
            "overdue": overdue,
            "access": self.access, "backed_up": self.backed_up,
        }


class EncryptionKeyPhase:
    """阶段6：加密与密钥。"""

    def __init__(self) -> None:
        self._findings: List[EncryptionFinding] = []
        self._keys: List[KeyRecord] = []
        self._seed_mock()

    def _fid(self) -> str:
        return "E" + uuid.uuid4().hex[:8]

    def _seed_mock(self) -> None:
        seeds = [
            ("database_field", "crm.users.id_card", "AES-256",
             "GCM", 256, 5, "字段已加密，模式安全"),
            ("database_field", "crm.users.mobile", "AES-128",
             "ECB", 128, 65, "ECB 模式不安全，建议改 GCM"),
            ("database_field", "crm.users.password_hash", "MD5",
             "", 128, 85, "MD5 已被破解，建议 bcrypt/argon2"),
            ("file", "nas://finance/2026Q2.xlsx", "none",
             "", 0, 90, "财务文件未加密"),
            ("transport", "http://legacy-erp.internal", "none",
             "plaintext", 0, 80, "HTTP 明文传输敏感字段"),
            ("backup", "oss://prod-backup-01/db.sql.gz", "none",
             "", 0, 75, "数据库备份未加密"),
            ("database_field", "crm.orders.bank_card", "RSA-2048",
             "OAEP", 2048, 15, "RSA-2048 可接受但建议升级 4096"),
            ("transport", "ftp://fileserver/shared", "none",
             "plaintext", 0, 85, "FTP 明文"),
        ]
        for scope, target, algo, mode, kl, risk, detail in seeds:
            self._findings.append(EncryptionFinding(
                finding_id=self._fid(), scope=scope, target=target,
                algorithm=algo, mode=mode, key_length=kl,
                risk_score=risk, detail=detail))
        key_seeds = [
            ("K1", "用户字段主密钥", "KMS", 30, 90, "restricted", True),
            ("K2", "数据库备份密钥", "KMS", 120, 90, "restricted", True),
            ("K3", "FTP 加密密钥", "明文配置文件", 400, 90,
             "full", False),
            ("K4", "API 签名密钥", "代码仓库", 700, 180,
             "full", False),
        ]
        for k in key_seeds:
            self._keys.append(KeyRecord(*k))

    # ------------------------------------------------------------------ #
    def list_findings(self, scope: Optional[str] = None,
                      min_risk: int = 0) -> List[Dict[str, Any]]:
        items = self._findings
        if scope:
            items = [f for f in items if f.scope == scope]
        items = [f for f in items if f.risk_score >= min_risk]
        return [f.to_dict() for f in
                sorted(items, key=lambda x: x.risk_score, reverse=True)]

    def list_keys(self) -> List[Dict[str, Any]]:
        return [k.to_dict() for k in self._keys]

    # ------------------------------------------------------------------ #
    def check_algorithm(self, algorithm: str, key_length: int = 0,
                        mode: str = "") -> Dict[str, Any]:
        """评估某个算法/长度/模式。"""
        algo = algorithm.strip().upper()
        info = ALGO_STRENGTH.get(algo, {"level": "unknown", "risk": 50})
        issues: List[str] = []
        risk = info["risk"]
        if algo in WEAK_ALGOS:
            issues.append(f"{algo} 为已知弱算法")
        if mode.upper() == "ECB":
            issues.append("ECB 模式泄露明文模式")
            risk += 20
        if key_length and algo.startswith("RSA") and key_length < 2048:
            issues.append("RSA 密钥长度 < 2048")
            risk += 30
        if key_length and algo.startswith("AES") and key_length < 128:
            issues.append("AES 密钥长度 < 128")
            risk += 25
        return {
            "algorithm": algo, "level": info["level"],
            "risk_score": min(100, risk),
            "issues": issues,
            "suggestion": "; ".join(issues) or "算法强度可接受",
        }

    # ------------------------------------------------------------------ #
    def coverage(self) -> Dict[str, Any]:
        total = len(self._findings) or 1
        encrypted = sum(1 for f in self._findings
                        if f.algorithm not in ("none", ""))
        weak = sum(1 for f in self._findings
                   if f.algorithm in WEAK_ALGOS or f.mode.upper() == "ECB")
        unencrypted = total - encrypted
        key_overdue = sum(1 for k in self._keys if k.to_dict()["overdue"])
        key_plain = sum(1 for k in self._keys
                        if k.storage in ("明文配置文件", "代码仓库"))
        return {
            "encryption_coverage_pct": round(encrypted / total * 100, 1),
            "weak_algo_count": weak,
            "unencrypted_count": unencrypted,
            "key_overdue_count": key_overdue,
            "key_plain_storage_count": key_plain,
            "total_findings": total,
            "avg_risk": round(
                sum(f.risk_score for f in self._findings) / total, 1),
        }

    # ------------------------------------------------------------------ #
    def risk_summary(self) -> Dict[str, Any]:
        cov = self.coverage()
        score = 100 - cov["avg_risk"]
        return {
            "encryption_risk_score": max(0, round(score, 1)),
            "coverage": cov,
            "top_findings": [f.to_dict() for f in
                             sorted(self._findings,
                                    key=lambda x: x.risk_score,
                                    reverse=True)[:5]],
        }


_default_phase: Optional[EncryptionKeyPhase] = None


def get_encryption_key_phase() -> EncryptionKeyPhase:
    global _default_phase
    if _default_phase is None:
        _default_phase = EncryptionKeyPhase()
    return _default_phase


__all__ = [
    "EncryptionKeyPhase", "EncryptionFinding", "KeyRecord",
    "get_encryption_key_phase", "ALGO_STRENGTH", "WEAK_ALGOS",
]
