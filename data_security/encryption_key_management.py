#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
encryption_key_management.py — 加密与密钥管理器。

覆盖：
    - 加密算法评估：对称(AES/DES/3DES/RC4)、非对称(RSA/ECC/DSA)、
      哈希(MD5/SHA1/SHA256/SHA512)、弱算法检测
    - 密钥强度：密钥长度/熵值/弱密钥/生成质量
    - 密钥轮换：策略/周期/历史密钥/轮换执行
    - 证书管理：有效期/证书链/密钥强度/签名算法/过期预警/自签名
    - TLS配置：版本/cipher suite/证书验证/HSTS/前向保密/弱配置
    - HSM 集成评估
    - 数据加密状态：静态/传输/使用中/数据库/磁盘/备份
    - 加密管理报告与加固建议

设计定位：仅做加密配置评估与密钥治理建议，不生成或托管真实密钥。
"""

from __future__ import annotations

import math
import re
import time
import uuid
from typing import Any, Dict, List, Optional


# --------------------------------------------------------------------------- #
# 加密算法库
# --------------------------------------------------------------------------- #
CRYPTO_ALGORITHM_LIBRARY: Dict[str, Dict[str, Any]] = {
    # 对称加密
    "AES": {"type": "对称", "standard": True, "min_key_bits": 128,
            "recommended": "AES-256-GCM", "weak": False, "note": "推荐GCM模式，避免ECB"},
    "DES": {"type": "对称", "standard": False, "min_key_bits": 56,
            "recommended": "已淘汰", "weak": True, "note": "56位可被暴力破解，必须迁移AES"},
    "3DES": {"type": "对称", "standard": False, "min_key_bits": 112,
             "recommended": "已淘汰(2023年NIST弃用)", "weak": True,
             "note": "Sweet32攻击，迁移AES"},
    "RC4": {"type": "对称", "standard": False, "min_key_bits": 128,
            "recommended": "已淘汰", "weak": True, "note": "偏差偏差，禁用"},
    "ChaCha20": {"type": "对称", "standard": True, "min_key_bits": 256,
                 "recommended": "ChaCha20-Poly1305", "weak": False,
                 "note": "无AES-NI设备的高性能替代"},
    # 非对称
    "RSA": {"type": "非对称", "standard": True, "min_key_bits": 2048,
            "recommended": "RSA-3072+", "weak": False,
            "note": "<2048位视为弱；签名用RSASSA-PSS"},
    "ECC": {"type": "非对称", "standard": True, "min_key_bits": 256,
            "recommended": "ECDSA P-256/384", "weak": False,
            "note": "密钥短性能好，选NIST曲线"},
    "DSA": {"type": "非对称", "standard": False, "min_key_bits": 2048,
            "recommended": "不推荐新系统", "weak": True, "note": "已逐渐弃用"},
    "Ed25519": {"type": "非对称", "standard": True, "min_key_bits": 256,
                "recommended": "Ed25519", "weak": False, "note": "现代签名，推荐"},
    # 哈希
    "MD5": {"type": "哈希", "standard": False, "min_key_bits": 128,
            "recommended": "已淘汰", "weak": True, "note": "碰撞攻击，禁止用于安全"},
    "SHA1": {"type": "哈希", "standard": False, "min_key_bits": 160,
             "recommended": "已淘汰", "weak": True, "note": "SHAttered碰撞，迁移SHA-256"},
    "SHA256": {"type": "哈希", "standard": True, "min_key_bits": 256,
               "recommended": "SHA-256", "weak": False, "note": "通用安全"},
    "SHA512": {"type": "哈希", "standard": True, "min_key_bits": 512,
               "recommended": "SHA-512/256", "weak": False, "note": "高安全场景"},
    "bcrypt": {"type": "口令哈希", "standard": True, "min_key_bits": 256,
               "recommended": "bcrypt/crypt", "weak": False, "note": "自适应口令哈希，推荐"},
    "PBKDF2": {"type": "口令哈希", "standard": True, "min_key_bits": 256,
               "recommended": "PBKDF2-HMAC-SHA256 (≥10万迭代)", "weak": False,
               "note": "需足够迭代次数+随机salt"},
    "Argon2": {"type": "口令哈希", "standard": True, "min_key_bits": 256,
               "recommended": "Argon2id", "weak": False, "note": "密码哈希竞赛冠军，首选"},
}

_WEAK_ALGOS = {k for k, v in CRYPTO_ALGORITHM_LIBRARY.items() if v["weak"]}


class EncryptionKeyManager:
    """加密与密钥管理器。"""

    def __init__(self) -> None:
        self.algo_lib = CRYPTO_ALGORITHM_LIBRARY
        self.findings: List[Dict[str, Any]] = []

    # ------------------------------------------------------------------ #
    # 算法使用检测
    # ------------------------------------------------------------------ #
    def scan_algorithms(self, text: str) -> Dict[str, Any]:
        """扫描配置/代码中使用的算法，识别弱算法。"""
        used: List[Dict[str, Any]] = []
        for name, meta in self.algo_lib.items():
            if re.search(r"\b" + re.escape(name) + r"\b", text or "", re.IGNORECASE):
                used.append({
                    "algorithm": name, "type": meta["type"],
                    "weak": meta["weak"], "recommended": meta["recommended"],
                    "note": meta["note"],
                })
        weak = [u for u in used if u["weak"]]
        return {
            "detected": used,
            "weak_algorithms": weak,
            "weak_count": len(weak),
            "recommendation": "立即替换 " + ", ".join(u["algorithm"] for u in weak) if weak else "未发现弱算法",
        }

    # ------------------------------------------------------------------ #
    # 密钥强度评估
    # ------------------------------------------------------------------ #
    def assess_key_strength(self, key_material: str = "",
                            declared_bits: int = 0,
                            algorithm: str = "") -> Dict[str, Any]:
        """评估密钥长度/熵/弱密钥/生成质量（不回显密钥本体）。"""
        entropy = 0.0
        if key_material:
            # 简易熵估算
            n = len(key_material)
            if n:
                freq: Dict[str, int] = {}
                for ch in key_material:
                    freq[ch] = freq.get(ch, 0) + 1
                for c in freq.values():
                    p = c / n
                    entropy -= p * math.log2(p)
                entropy = round(entropy * n, 1)
        algo = self.algo_lib.get(algorithm.upper(), {})
        min_bits = algo.get("min_key_bits", 128)
        actual = declared_bits or int(entropy)
        weak_length = actual < min_bits
        # 常见弱密钥模式
        weak_patterns = [
            (r"^(0123456789|password|123456|secret|qwerty|0{8,})$", "常见弱密钥"),
            (r"^(.)\1{7,}$", "重复字符"),
        ]
        weak_reason = ""
        for pat, reason in weak_patterns:
            if key_material and re.search(pat, key_material, re.IGNORECASE):
                weak_reason = reason
                break
        quality = "weak" if (weak_length or weak_reason or entropy < 64) else "strong"
        return {
            "algorithm": algorithm or "unknown",
            "declared_bits": declared_bits,
            "estimated_entropy_bits": round(entropy, 1),
            "required_min_bits": min_bits,
            "meets_length": not weak_length,
            "weak_reason": weak_reason or ("长度不足" if weak_length else ""),
            "generation_quality": quality,
            "recommendation": "使用 CSPRNG(os.urandom/secrets) 生成并存储于KMS/HSM" if quality == "weak"
                               else "密钥强度可接受，落实轮换与分离职责",
        }

    # ------------------------------------------------------------------ #
    # 密钥轮换
    # ------------------------------------------------------------------ #
    def assess_rotation(self, keys: Optional[List[Dict[str, Any]]] = None) -> Dict[str, Any]:
        keys = keys or [
            {"name": "数据库主密钥(DEK)", "age_days": 90, "max_lifecycle_days": 365,
             "rotatable": True, "wrapped_by": "KEK"},
            {"name": "TLS证书私钥", "age_days": 400, "max_lifecycle_days": 398,
             "rotatable": True, "wrapped_by": "HSM"},
            {"name": "API签名密钥", "age_days": 720, "max_lifecycle_days": 90,
             "rotatable": False, "wrapped_by": "配置文件"},
            {"name": "备份加密密钥", "age_days": 30, "max_lifecycle_days": 365,
             "rotatable": True, "wrapped_by": "KMS"},
            {"name": "旧版会话密钥", "age_days": 2000, "max_lifecycle_days": 90,
             "rotatable": False, "wrapped_by": "未知"},
        ]
        rows = []
        overdue = 0
        for k in keys:
            expired = k["age_days"] > k["max_lifecycle_days"]
            if expired:
                overdue += 1
            rows.append({**k,
                         "overdue": expired,
                         "risk": "high" if expired and not k["rotatable"] else
                                 ("medium" if expired else "low"),
                         "note": "已超期且无法轮换，立即迁移" if expired and not k["rotatable"]
                                 else ("建议尽快轮换" if expired else "在周期内")})
        return {
            "keys": rows, "total": len(rows), "overdue_count": overdue,
            "policy": {"max_lifecycle_days": 90, "grace_days": 15,
                       "history_retention": "保留旧密钥用于解密历史数据,到期销毁"},
            "recommendation": "API密钥/TLS私钥≤90-398天轮换;使用KMS自动轮换",
        }

    # ------------------------------------------------------------------ #
    # 证书管理
    # ------------------------------------------------------------------ #
    def assess_certificates(self, certs: Optional[List[Dict[str, Any]]] = None) -> Dict[str, Any]:
        today = time.strftime("%Y-%m-%d")
        certs = certs or [
            {"subject": "*.example.com", "issuer": "DigiCert", "not_after": "2026-06-01",
             "key_bits": 2048, "sig_alg": "SHA256withRSA", "self_signed": False, "chain_valid": True},
            {"subject": "internal.example.com", "issuer": "InternalCA", "not_after": "2025-01-01",
             "key_bits": 1024, "sig_alg": "SHA1withRSA", "self_signed": True, "chain_valid": False},
            {"subject": "api.example.com", "issuer": "Let's Encrypt", "not_after": "2027-09-01",
             "key_bits": 4096, "sig_alg": "SHA384withRSA", "self_signed": False, "chain_valid": True},
        ]
        rows = []
        issues = 0
        for c in certs:
            probs = []
            if c["key_bits"] < 2048:
                probs.append("密钥过短(<2048)")
            if "SHA1" in c["sig_alg"] or "MD5" in c["sig_alg"]:
                probs.append("弱签名算法")
            if c["self_signed"]:
                probs.append("自签名证书")
            if not c["chain_valid"]:
                probs.append("证书链不完整")
            if c["not_after"] < today:
                probs.append("已过期")
            elif c["not_after"] < "2026-12-31":
                probs.append("即将过期")
            rows.append({**c, "issues": probs, "healthy": not probs})
            if probs:
                issues += 1
        return {
            "today": today, "certificates": rows, "total": len(rows),
            "issue_count": issues,
            "recommendation": "替换1024位/SHA1/自签名证书;接入证书自动续期(ACME)",
        }

    # ------------------------------------------------------------------ #
    # TLS 配置
    # ------------------------------------------------------------------ #
    def assess_tls(self, config: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
        c = config or {}
        findings = []
        versions = c.get("versions", ["TLSv1.2", "TLSv1.3"])
        for v in versions:
            if v in ("SSLv2", "SSLv3", "TLSv1.0", "TLSv1.1"):
                findings.append({"item": f"协议版本 {v}", "risk": "high",
                                 "note": "已废弃协议，必须禁用"})
        ciphers = c.get("ciphers", ["TLS_AES_256_GCM_SHA384", "ECDHE-RSA-AES128-GCM-SHA256"])
        weak_ciphers = [x for x in ciphers if any(w in x for w in
                       ("RC4", "3DES", "DES", "MD5", "NULL", "EXPORT", "CBC"))]
        for wc in weak_ciphers:
            findings.append({"item": f"弱 cipher {wc}", "risk": "high", "note": "禁用"})
        if not c.get("hsts", True):
            findings.append({"item": "HSTS 未启用", "risk": "medium", "note": "加 Strict-Transport-Security"})
        if not c.get("forward_secrecy", True):
            findings.append({"item": "前向保密(PFS)未配置", "risk": "medium", "note": "用ECDHE"})
        if not c.get("cert_verify", True):
            findings.append({"item": "证书校验被关闭(verify=False)", "risk": "critical",
                             "note": "中间人风险，必须开启校验"})
        score = 100 - 15 * len(findings)
        return {
            "versions": versions, "ciphers": ciphers,
            "findings": findings,
            "tls_score": max(score, 0),
            "grade": "A" if score >= 90 else ("B" if score >= 75 else "C"),
            "recommendation": "仅启用 TLS1.2/1.3 + AEAD cipher + HSTS + PFS + 强证书校验",
        }

    # ------------------------------------------------------------------ #
    # HSM 集成评估
    # ------------------------------------------------------------------ #
    def assess_hsm(self, signals: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
        s = signals or {}
        checks = {
            "使用HSM/KMS保护主密钥(KEK)": s.get("hsm_kek", "部分满足"),
            "密钥不出硬件边界(不可导出)": s.get("non_exportable", "不满足"),
            "硬件随机数生成器(TRNG)": s.get("trng", "部分满足"),
            "多因素访问控制(M-of-N)": s.get("mofn", "不满足"),
            "操作审计日志(密钥使用)": s.get("audit", "部分满足"),
            "高可用/备份HSM": s.get("ha", "不满足"),
        }
        rows = [{"item": k, "status": v} for k, v in checks.items()]
        ok = sum(1 for v in checks.values() if v == "满足")
        return {"items": rows, "met": ok, "total": len(checks),
                "score": round(ok / len(checks) * 100, 1),
                "recommendation": "根密钥/KEK必须落入HSM,应用只持有数据密钥并禁止导出"}

    # ------------------------------------------------------------------ #
    # 数据加密状态
    # ------------------------------------------------------------------ #
    def assess_data_encryption(self, assets: Optional[List[Dict[str, Any]]] = None) -> Dict[str, Any]:
        assets = assets or [
            {"asset": "用户数据库", "at_rest": True, "in_transit": True, "in_use": False,
             "note": "TDE透明加密"},
            {"asset": "备份磁带", "at_rest": False, "in_transit": True, "in_use": False,
             "note": "备份未加密"},
            {"asset": "对象存储桶", "at_rest": True, "in_transit": True, "in_use": False,
             "note": "SSE-KMS"},
            {"asset": "笔记本磁盘", "at_rest": False, "in_transit": True, "in_use": False,
             "note": "未启用BitLocker"},
            {"asset": "API传输", "at_rest": False, "in_transit": True, "in_use": False,
             "note": "HTTPS"},
        ]
        rows = []
        unencrypted = 0
        for a in assets:
            missing = []
            if not a["at_rest"]:
                missing.append("静态未加密")
            if not a["in_transit"]:
                missing.append("传输未加密")
            if not a["in_use"]:
                missing.append("使用中未加密(内存明文)")
            if missing:
                unencrypted += 1
            rows.append({**a, "missing": missing, "healthy": not missing})
        return {
            "assets": rows, "total": len(rows), "unencrypted_assets": unencrypted,
            "encryption_coverage": round((len(rows) - unencrypted) / len(rows) * 100, 1),
            "recommendation": "静态AES-256/TDE;传输TLS1.3;敏感字段应用层字段级加密",
        }

    # ------------------------------------------------------------------ #
    # 综合
    # ------------------------------------------------------------------ #
    def assess(self, signals: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
        s = signals or {}
        algo = self.scan_algorithms(s.get("code_sample", ""))
        keys = self.assess_key_strength(
            s.get("key_material", ""), s.get("declared_bits", 256), s.get("algorithm", "AES"))
        rotation = self.assess_rotation(s.get("keys"))
        certs = self.assess_certificates(s.get("certificates"))
        tls = self.assess_tls(s.get("tls"))
        hsm = self.assess_hsm(s.get("hsm"))
        enc = self.assess_data_encryption(s.get("assets"))
        score = round((100 - algo["weak_count"] * 15 - rotation["overdue_count"] * 10
                       - certs["issue_count"] * 8 - (100 - tls["tls_score"]) * 0.3
                       + hsm["score"] * 0.2 + enc["encryption_coverage"] * 0.2), 1)
        score = max(0, min(100, score))
        return {
            "assessment_id": uuid.uuid4().hex[:10],
            "algorithms": algo, "key_strength": keys, "rotation": rotation,
            "certificates": certs, "tls": tls, "hsm": hsm,
            "data_encryption": enc,
            "overall_score": score,
            "grade": "A" if score >= 85 else ("B" if score >= 70 else ("C" if score >= 55 else "D")),
            "hardening": [
                "淘汰 DES/3DES/RC4/MD5/SHA1",
                "RSA≥3072 / ECC≥256,使用PSS",
                "密钥≤90-398天轮换,根密钥入HSM",
                "TLS仅1.2/1.3 + AEAD + HSTS + PFS",
                "备份/笔记本磁盘强制静态加密",
                "口令存储用 Argon2id/bcrypt",
            ],
            "generated_at": time.strftime("%Y-%m-%d %H:%M:%S"),
        }

    def get_report_markdown(self, result: Dict[str, Any]) -> str:
        lines = [
            "# 加密与密钥管理报告", "",
            f"- 评估ID: {result.get('assessment_id')}",
            f"- 综合得分: {result.get('overall_score')} ({result.get('grade')})",
            f"- 弱算法: {result.get('algorithms', {}).get('weak_count')}",
            f"- 超期密钥: {result.get('rotation', {}).get('overdue_count')}",
            f"- 问题证书: {result.get('certificates', {}).get('issue_count')}",
            f"- TLS评分: {result.get('tls', {}).get('tls_score')}",
            f"- 加密覆盖率: {result.get('data_encryption', {}).get('encryption_coverage')}%", "",
            "## 加固建议",
        ]
        for h in result.get("hardening", []):
            lines.append(f"- {h}")
        return "\n".join(lines)

    def list_algorithms(self) -> Dict[str, Any]:
        by_type: Dict[str, int] = {}
        weak = []
        for k, v in self.algo_lib.items():
            by_type[v["type"]] = by_type.get(v["type"], 0) + 1
            if v["weak"]:
                weak.append(k)
        return {"total": len(self.algo_lib), "by_type": by_type,
                "weak_algorithms": weak, "algorithms": self.algo_lib}
