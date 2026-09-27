#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
privacy_compute.py — 隐私计算与数据加密深度引擎（Round24 方向3）。

覆盖：
    1. 数据加密：静态/传输/字段级/应用层/数据库/文件/对象存储加密
    2. 密钥管理：生成/存储/轮换/销毁/备份/恢复/审计/HSM/KMS集成
    3. 数据脱敏：静态/动态/掩码/替换/加密/哈希/范围脱敏/数据合成
    4. 隐私计算：联邦学习/安全多方计算/同态加密/差分隐私/TEE/零知识证明
    5. 数据匿名化：k-匿名/l-多样性/t-接近/泛化/抑制/扰动/合成
    6. 数据水印：可见/不可见/指纹/溯源/鲁棒/脆弱水印/检测

设计定位：仅做加密/脱敏/隐私计算的方案设计与模拟执行，不做真实密钥管理。
第三方库 try-import，缺失时回退模拟。
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import os
import secrets
import uuid
from datetime import datetime
from typing import Any, Dict, List, Optional

# 尝试导入加密库
try:
    from cryptography.fernet import Fernet  # type: ignore
    from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes  # type: ignore
    from cryptography.hazmat.primitives import padding  # type: ignore
    _CRYPTO_OK = True
except Exception:  # pragma: no cover
    Fernet = None  # type: ignore
    Cipher = None  # type: ignore
    algorithms = None  # type: ignore
    modes = None  # type: ignore
    padding = None  # type: ignore
    _CRYPTO_OK = False


# 加密算法库
ENCRYPTION_ALGORITHMS: Dict[str, Dict[str, Any]] = {
    "aes-256-gcm": {
        "name": "AES-256-GCM", "type": "symmetric", "key_size": 256,
        "desc": "推荐：认证加密，同时保证机密性和完整性",
        "performance": "high",
    },
    "aes-256-cbc": {
        "name": "AES-256-CBC", "type": "symmetric", "key_size": 256,
        "desc": "经典对称加密，需配合HMAC", "performance": "medium",
    },
    "rsa-4096": {
        "name": "RSA-4096", "type": "asymmetric", "key_size": 4096,
        "desc": "非对称加密，用于密钥交换/数字签名", "performance": "low",
    },
    "chacha20-poly1305": {
        "name": "ChaCha20-Poly1305", "type": "stream", "key_size": 256,
        "desc": "流加密，移动端性能优异", "performance": "very_high",
    },
    "sm4": {
        "name": "SM4国密算法", "type": "symmetric", "key_size": 128,
        "desc": "中国国密标准对称加密", "performance": "medium",
    },
}

# 隐私计算技术
PRIVACY_COMPUTE_TECHS: Dict[str, Dict[str, Any]] = {
    "federated_learning": {
        "name": "联邦学习", "desc": "数据不出域，模型共同训练",
        "privacy_level": "high", "performance_overhead": "medium",
        "use_cases": ["跨机构联合建模", "金融风控", "医疗联合研究"],
    },
    "mpc": {
        "name": "安全多方计算(MPC)", "desc": "多方协同计算，互不知晓原始数据",
        "privacy_level": "very_high", "performance_overhead": "high",
        "use_cases": ["联合统计", "隐私集合求交", "联合查询"],
    },
    "homomorphic_encryption": {
        "name": "同态加密", "desc": "密文上直接计算，结果加密",
        "privacy_level": "very_high", "performance_overhead": "very_high",
        "use_cases": ["加密云计算", "隐私数据库查询"],
    },
    "differential_privacy": {
        "name": "差分隐私", "desc": "添加噪声保证单条记录不可识别",
        "privacy_level": "high", "performance_overhead": "low",
        "use_cases": ["统计发布", "数据分析", "机器学习"],
    },
    "tee": {
        "name": "可信执行环境(TEE)", "desc": "硬件级隔离的安全飞地",
        "privacy_level": "high", "performance_overhead": "low",
        "use_cases": ["敏感数据处理", "密钥托管", "机密计算"],
    },
    "zkp": {
        "name": "零知识证明(ZKP)", "desc": "证明事实成立而不泄露任何信息",
        "privacy_level": "very_high", "performance_overhead": "high",
        "use_cases": ["身份认证", "区块链隐私", "隐私凭证"],
    },
}

# 匿名化方法
ANONYMIZATION_METHODS: Dict[str, Dict[str, Any]] = {
    "k_anonymity": {"name": "k-匿名", "k": 5, "desc": "每条记录至少与k-1条记录不可区分"},
    "l_diversity": {"name": "l-多样性", "l": 3, "desc": "敏感属性至少有l个不同值"},
    "t_closeness": {"name": "t-接近", "t": 0.2, "desc": "敏感属性分布与全局分布距离≤t"},
    "generalization": {"name": "数据泛化", "desc": "将具体值替换为更宽泛的范围"},
    "suppression": {"name": "数据抑制", "desc": "直接移除敏感属性或记录"},
    "perturbation": {"name": "数据扰动", "desc": "添加随机噪声改变原始值"},
    "synthesis": {"name": "数据合成", "desc": "生成统计相似但无真实个体的合成数据"},
}

# 脱敏方法
MASKING_METHODS: Dict[str, Dict[str, Any]] = {
    "mask": {"name": "掩码脱敏", "desc": "用*替换中间字符", "example": "138****5678"},
    "replace": {"name": "替换脱敏", "desc": "替换为虚构但格式一致的值"},
    "hash": {"name": "哈希脱敏", "desc": "SHA-256不可逆哈希"},
    "encrypt_mask": {"name": "加密脱敏", "desc": "可逆加密，授权后可还原"},
    "range": {"name": "范围脱敏", "desc": "数值替换为区间", "example": "年龄: 25-35"},
    "null_out": {"name": "置空脱敏", "desc": "直接置空敏感字段"},
}


class PrivacyComputeEngine:
    """隐私计算与数据加密引擎"""

    def __init__(self) -> None:
        self.keys: Dict[str, Dict[str, Any]] = {}
        self.encryption_policies: Dict[str, Dict[str, Any]] = {}
        self.masking_tasks: Dict[str, Dict[str, Any]] = {}
        self.watermarks: Dict[str, Dict[str, Any]] = {}
        self.anonymization_jobs: Dict[str, Dict[str, Any]] = {}
        self._init_default_policies()
        self._generate_demo_keys()

    def _init_default_policies(self) -> None:
        self.encryption_policies = {
            "ep-001": {
                "policy_id": "ep-001", "name": "数据库字段级加密",
                "scope": "database_field", "algorithm": "aes-256-gcm",
                "fields": ["id_card", "mobile", "bank_card"], "enabled": True,
            },
            "ep-002": {
                "policy_id": "ep-002", "name": "静态文件加密",
                "scope": "file_at_rest", "algorithm": "aes-256-cbc",
                "directories": ["/data/sensitive/", "/backups/"], "enabled": True,
            },
            "ep-003": {
                "policy_id": "ep-003", "name": "传输TLS加密",
                "scope": "transport", "algorithm": "tls-1.3",
                "ports": [443, 8443], "enabled": True,
            },
        }

    def _generate_demo_keys(self) -> None:
        for kid in ["key-prod-001", "key-prod-002", "key-backup-001"]:
            self.keys[kid] = {
                "key_id": kid, "algorithm": "AES-256",
                "created_at": datetime.now().isoformat(timespec="seconds"),
                "status": "active", "version": 1,
                "rotation_days": 90, "last_rotated": datetime.now().isoformat(timespec="seconds"),
            }

    # ---------- 1. 数据加密 ----------
    def encrypt_data(self, plaintext: str, algorithm: str = "aes-256-gcm",
                    key_id: Optional[str] = None) -> Dict[str, Any]:
        """加密数据（模拟）"""
        try:
            kid = key_id or list(self.keys.keys())[0] if self.keys else "key-demo"
            # 真实加密路径
            if _CRYPTO_OK and Fernet is not None:
                fernet_key = Fernet.generate_key()
                f = Fernet(fernet_key)
                ciphertext = f.encrypt(plaintext.encode()).decode()
            else:
                # 回退：Base64 + 简单混淆
                raw = plaintext.encode()
                obfuscated = bytes([b ^ 0x5A for b in raw])
                ciphertext = base64.b64encode(obfuscated).decode()
            return {
                "encrypted": True, "ciphertext_preview": ciphertext[:32] + "...",
                "algorithm": algorithm, "key_id": kid,
                "original_length": len(plaintext),
                "encrypted_length": len(ciphertext),
                "encrypted_at": datetime.now().isoformat(timespec="seconds"),
            }
        except Exception as e:
            return {"error": str(e)}

    def decrypt_data(self, ciphertext: str, key_id: str = "") -> Dict[str, Any]:
        """解密数据（模拟，仅用于演示）"""
        try:
            # 回退解密
            try:
                decoded = base64.b64decode(ciphertext)
                raw = bytes([b ^ 0x5A for b in decoded])
                plaintext = raw.decode("utf-8", errors="replace")
            except Exception:
                plaintext = "[解密失败-模拟环境]"
            return {
                "decrypted": True, "plaintext_preview": plaintext[:20] + "..." if len(plaintext) > 20 else plaintext,
                "key_id": key_id, "algorithm": "aes-256-gcm",
                "decrypted_at": datetime.now().isoformat(timespec="seconds"),
            }
        except Exception as e:
            return {"error": str(e)}

    def get_encryption_status(self) -> Dict[str, Any]:
        """加密状态总览"""
        return {
            "at_rest_encrypted": True, "in_transit_encrypted": True,
            "field_level_encrypted": True,
            "algorithms_supported": list(ENCRYPTION_ALGORITHMS.keys()),
            "crypto_library_available": _CRYPTO_OK,
            "policies": len(self.encryption_policies),
        }

    # ---------- 2. 密钥管理 ----------
    def list_keys(self) -> List[Dict[str, Any]]:
        return list(self.keys.values())

    def generate_key(self, algorithm: str = "AES-256",
                     owner: str = "", rotation_days: int = 90) -> Dict[str, Any]:
        kid = f"key-{uuid.uuid4().hex[:10]}"
        self.keys[kid] = {
            "key_id": kid, "algorithm": algorithm,
            "created_at": datetime.now().isoformat(timespec="seconds"),
            "status": "active", "version": 1, "owner": owner,
            "rotation_days": rotation_days,
            "last_rotated": datetime.now().isoformat(timespec="seconds"),
        }
        return {"key_id": kid, "generated": True, "algorithm": algorithm}

    def rotate_key(self, key_id: str) -> Dict[str, Any]:
        if key_id not in self.keys:
            return {"error": "密钥不存在"}
        self.keys[key_id]["version"] += 1
        self.keys[key_id]["last_rotated"] = datetime.now().isoformat(timespec="seconds")
        return {"key_id": key_id, "new_version": self.keys[key_id]["version"]}

    def destroy_key(self, key_id: str) -> Dict[str, Any]:
        if key_id not in self.keys:
            return {"error": "密钥不存在"}
        self.keys[key_id]["status"] = "destroyed"
        return {"key_id": key_id, "status": "destroyed"}

    def key_audit(self, key_id: str) -> Dict[str, Any]:
        if key_id not in self.keys:
            return {"error": "密钥不存在"}
        k = self.keys[key_id]
        return {
            "key_id": key_id, "algorithm": k["algorithm"],
            "status": k["status"], "version": k["version"],
            "created_at": k["created_at"],
            "last_rotated": k.get("last_rotated"),
            "owner": k.get("owner", "未分配"),
            "compliance": "OK" if k["status"] == "active" else "异常",
        }

    # ---------- 3. 数据脱敏 ----------
    def mask_data(self, data: str, method: str = "mask",
                 field_type: str = "auto") -> Dict[str, Any]:
        """对数据执行脱敏"""
        try:
            if method == "mask":
                if len(data) <= 4:
                    masked = "*" * len(data)
                else:
                    masked = data[:2] + "*" * (len(data) - 4) + data[-2:]
            elif method == "hash":
                masked = hashlib.sha256(data.encode()).hexdigest()[:16]
            elif method == "range":
                # 数值范围脱敏
                try:
                    num = float(data)
                    low = int(num // 10 * 10)
                    masked = f"{low}-{low + 10}"
                except ValueError:
                    masked = "[范围脱敏]"
            elif method == "null_out":
                masked = ""
            elif method == "replace":
                masked = "***REDACTED***"
            else:
                masked = "***" + data[-2:]
            task_id = f"mask-{uuid.uuid4().hex[:8]}"
            self.masking_tasks[task_id] = {
                "task_id": task_id, "method": method,
                "original_length": len(data), "masked_length": len(masked),
                "field_type": field_type,
                "created_at": datetime.now().isoformat(timespec="seconds"),
            }
            return {
                "task_id": task_id, "original_preview": data[:3] + "***",
                "masked_result": masked, "method": method,
            }
        except Exception as e:
            return {"error": str(e)}

    def batch_mask(self, records: List[Dict[str, str]],
                  sensitive_fields: List[str]) -> Dict[str, Any]:
        """批量脱敏"""
        masked_count = 0
        for rec in records:
            for f in sensitive_fields:
                if f in rec and rec[f]:
                    rec[f] = "***MASKED***"
                    masked_count += 1
        return {"processed": len(records), "masked_fields": masked_count, "records": records}

    def get_masking_methods(self) -> Dict[str, Any]:
        return MASKING_METHODS

    # ---------- 4. 隐私计算 ----------
    def privacy_compute_demo(self, tech: str, data_size: int = 10000) -> Dict[str, Any]:
        """隐私计算模拟"""
        if tech not in PRIVACY_COMPUTE_TECHS:
            return {"error": f"不支持的技术: {tech}"}
        info = PRIVACY_COMPUTE_TECHS[tech]
        job_id = f"pc-{uuid.uuid4().hex[:8]}"
        self.anonymization_jobs[job_id] = {
            "job_id": job_id, "tech": tech,
            "data_size": data_size, "status": "completed",
            "created_at": datetime.now().isoformat(timespec="seconds"),
            "result": {"epsilon": 1.0, "noise_added": True} if tech == "differential_privacy" else {},
        }
        return {
            "job_id": job_id, "tech": tech,
            "tech_name": info["name"],
            "privacy_level": info["privacy_level"],
            "performance_overhead": info["performance_overhead"],
            "data_size": data_size, "status": "completed",
            "use_cases": info["use_cases"],
        }

    def list_privacy_techs(self) -> Dict[str, Any]:
        return PRIVACY_COMPUTE_TECHS

    # ---------- 5. 数据匿名化 ----------
    def anonymize(self, data: List[Dict[str, Any]],
                 method: str = "k_anonymity",
                 quasi_identifiers: Optional[List[str]] = None,
                 sensitive_attr: str = "") -> Dict[str, Any]:
        """数据匿名化处理"""
        try:
            qis = quasi_identifiers or ["age", "gender", "zipcode"]
            job_id = f"anon-{uuid.uuid4().hex[:8]}"
            if method == "k_anonymity":
                k = 5
                result_size = max(len(data) // k, 1)
                note = f"执行k={k}匿名化，{len(data)}条记录泛化为{result_size}组等价类"
            elif method == "l_diversity":
                l = 3
                note = f"执行l={l}多样性，确保每组敏感属性至少{l}个不同值"
                result_size = len(data)
            elif method == "generalization":
                note = "对准标识符进行泛化：年龄→十年区间，邮编→前3位"
                result_size = len(data)
            elif method == "perturbation":
                note = "对数值属性添加高斯噪声(μ=0,σ=0.1)"
                result_size = len(data)
            elif method == "synthesis":
                note = "生成与原始数据分布一致的合成数据集"
                result_size = len(data)
            else:
                note = f"执行{method}匿名化"
                result_size = len(data)
            self.anonymization_jobs[job_id] = {
                "job_id": job_id, "method": method,
                "input_size": len(data), "output_size": result_size,
                "quasi_identifiers": qis, "sensitive_attr": sensitive_attr,
                "status": "completed",
                "created_at": datetime.now().isoformat(timespec="seconds"),
            }
            return {
                "job_id": job_id, "method": method,
                "method_name": ANONYMIZATION_METHODS.get(method, {}).get("name", method),
                "input_records": len(data), "output_records": result_size,
                "note": note, "status": "completed",
            }
        except Exception as e:
            return {"error": str(e)}

    def list_anonymization_methods(self) -> Dict[str, Any]:
        return ANONYMIZATION_METHODS

    # ---------- 6. 数据水印 ----------
    def add_watermark(self, content: str, watermark_text: str = "",
                    wm_type: str = "invisible",
                    user_id: str = "system") -> Dict[str, Any]:
        """为数据添加水印"""
        wm_id = f"wm-{uuid.uuid4().hex[:10]}"
        wm_text = watermark_text or f"trace-{user_id}-{datetime.now().strftime('%Y%m%d%H%M')}"
        # 模拟水印嵌入：在文本末尾附加不可见标记
        marked_content = content + f"\n<!--WM:{wm_text}-->"
        self.watermarks[wm_id] = {
            "wm_id": wm_id, "wm_text": wm_text, "wm_type": wm_type,
            "user_id": user_id, "content_hash": hashlib.sha256(content.encode()).hexdigest()[:16],
            "added_at": datetime.now().isoformat(timespec="seconds"),
        }
        return {
            "wm_id": wm_id, "wm_text": wm_text,
            "wm_type": wm_type, "marked_length": len(marked_content),
            "user_id": user_id,
        }

    def detect_watermark(self, content: str) -> Dict[str, Any]:
        """检测数据中的水印"""
        detected = []
        for wm in self.watermarks.values():
            if f"WM:{wm['wm_text']}" in content:
                detected.append({
                    "wm_id": wm["wm_id"], "wm_text": wm["wm_text"],
                    "user_id": wm["user_id"], "wm_type": wm["wm_type"],
                })
        return {
            "content_length": len(content),
            "watermarks_found": len(detected),
            "detected": detected,
        }

    def list_watermarks(self) -> List[Dict[str, Any]]:
        return list(self.watermarks.values())

    # ---------- 统计 ----------
    def stats(self) -> Dict[str, Any]:
        return {
            "keys_total": len(self.keys),
            "active_keys": sum(1 for k in self.keys.values() if k["status"] == "active"),
            "encryption_policies": len(self.encryption_policies),
            "masking_tasks": len(self.masking_tasks),
            "watermarks": len(self.watermarks),
            "anonymization_jobs": len(self.anonymization_jobs),
            "crypto_lib_available": _CRYPTO_OK,
            "algorithms": len(ENCRYPTION_ALGORITHMS),
            "privacy_techs": len(PRIVACY_COMPUTE_TECHS),
            "anonymization_methods": len(ANONYMIZATION_METHODS),
            "masking_methods": len(MASKING_METHODS),
        }


_instance: Optional[PrivacyComputeEngine] = None


def get_privacy_compute_engine() -> PrivacyComputeEngine:
    global _instance
    if _instance is None:
        _instance = PrivacyComputeEngine()
    return _instance
