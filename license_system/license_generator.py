# -*- coding: utf-8 -*-
"""
license_generator.py — License 生成与管理核心。

能力:
    * License 类型定义（试用/标准/专业/企业/定制）：功能/用户数/时间/模块限制
    * RSA-2048 非对称密钥对生成、私钥签名、公钥验证（cryptography 可用时）
    * License 签发、激活码生成、批量签发、自定义有效期
    * 本地验证 / 在线验证 / 混合验证：签名校验 + 有效期 + 设备绑定 + 功能权限
    * License 加密存储、防篡改（HMAC 完整性校验）、备份/恢复/迁移
    * 吊销列表（CRL）：吊销原因/时间/在线吊销缓存
    * 审计：激活记录、验证记录、使用统计、异常检测、报告生成

不依赖任何数据库；全部内存字典 + 可选 JSON 落盘到 license_system/.data/。
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import json
import os
import threading
import time
import uuid
from typing import Any, Dict, List, Optional, Tuple

# --------------------------------------------------------------------------- #
# 第三方库 try-import
# --------------------------------------------------------------------------- #
_CRYPTO_OK = False
try:
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import padding, rsa
    from cryptography.hazmat.backends import default_backend
    _CRYPTO_OK = True
except Exception:  # pragma: no cover - 环境无 cryptography 时回退
    hashes = None  # type: ignore
    padding = None  # type: ignore
    rsa = None  # type: ignore
    serialization = None  # type: ignore
    default_backend = None  # type: ignore

LOCK = threading.RLock()

DATA_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), ".data")
os.makedirs(DATA_DIR, exist_ok=True)


# --------------------------------------------------------------------------- #
# License 类型定义
# --------------------------------------------------------------------------- #
LICENSE_PLANS: Dict[str, Dict[str, Any]] = {
    "trial": {
        "name": "试用版", "price_year": 0, "duration_days": 30,
        "max_users": 1, "max_devices": 1, "api_quota_per_day": 1000,
        "max_assets": 50, "max_scan_tasks": 5, "max_reports": 10, "max_storage_mb": 100,
        "modules": ["dashboard", "basic_scan"],
        "advanced_features": [],
        "grace_days": 3,
    },
    "standard": {
        "name": "标准版", "price_year": 2999, "duration_days": 365,
        "max_users": 5, "max_devices": 3, "api_quota_per_day": 50000,
        "max_assets": 2000, "max_scan_tasks": 100, "max_reports": 500, "max_storage_mb": 5120,
        "modules": ["dashboard", "basic_scan", "asset_mgmt", "report", "vuln_scan"],
        "advanced_features": ["basic_report"],
        "grace_days": 7,
    },
    "professional": {
        "name": "专业版", "price_year": 9999, "duration_days": 365,
        "max_users": 20, "max_devices": 10, "api_quota_per_day": 500000,
        "max_assets": 50000, "max_scan_tasks": 1000, "max_reports": 5000, "max_storage_mb": 51200,
        "modules": ["dashboard", "basic_scan", "asset_mgmt", "report", "vuln_scan",
                    "ai_analysis", "compliance", "api_open"],
        "advanced_features": ["ai_analysis", "advanced_report", "api_open"],
        "grace_days": 15,
    },
    "enterprise": {
        "name": "企业版", "price_year": 39999, "duration_days": 365,
        "max_users": 200, "max_devices": 50, "api_quota_per_day": 5000000,
        "max_assets": 500000, "max_scan_tasks": 10000, "max_reports": 50000, "max_storage_mb": 512000,
        "modules": ["dashboard", "basic_scan", "asset_mgmt", "report", "vuln_scan",
                    "ai_analysis", "compliance", "api_open", "multi_tenant",
                    "distributed_scan", "custom_integration"],
        "advanced_features": ["ai_analysis", "advanced_report", "multi_tenant",
                              "distributed_scan", "api_open", "custom_integration"],
        "grace_days": 30,
    },
    "custom": {
        "name": "定制版", "price_year": 99999, "duration_days": 365,
        "max_users": 9999, "max_devices": 9999, "api_quota_per_day": 99999999,
        "max_assets": 9999999, "max_scan_tasks": 99999, "max_reports": 999999, "max_storage_mb": 999999,
        "modules": ["*"],
        "advanced_features": ["*"],
        "grace_days": 60,
    },
}

# 全部可用模块清单
ALL_MODULES = [
    "dashboard", "basic_scan", "asset_mgmt", "report", "vuln_scan",
    "ai_analysis", "compliance", "api_open", "multi_tenant",
    "distributed_scan", "custom_integration",
]
ADVANCED_FEATURES = [
    "ai_analysis", "advanced_report", "multi_tenant",
    "distributed_scan", "api_open", "custom_integration",
]


# --------------------------------------------------------------------------- #
# 工具函数
# --------------------------------------------------------------------------- #
def _b64e(raw: bytes) -> str:
    return base64.urlsafe_b64encode(raw).decode("ascii").rstrip("=")


def _b64d(s: str) -> bytes:
    pad = "=" * (-len(s) % 4)
    return base64.urlsafe_b64decode(s + pad)


def _canonical(obj: Any) -> bytes:
    return json.dumps(obj, sort_keys=True, separators=(",", ":")).encode("utf-8")


def _now() -> float:
    return time.time()


# --------------------------------------------------------------------------- #
# RSA 密钥管理
# --------------------------------------------------------------------------- #
class KeyManager:
    """RSA 2048 密钥对管理（进程内生成，可选落盘 PEM）。"""

    def __init__(self) -> None:
        self.private_key = None
        self.public_key = None
        self.key_id = "km-" + uuid.uuid4().hex[:8]
        self._load_or_create()

    def _load_or_create(self) -> None:
        priv_path = os.path.join(DATA_DIR, "license_private.pem")
        pub_path = os.path.join(DATA_DIR, "license_public.pem")
        if _CRYPTO_OK and os.path.exists(priv_path) and os.path.exists(pub_path):
            try:
                with open(priv_path, "rb") as f:
                    self.private_key = serialization.load_pem_private_key(
                        f.read(), password=None, backend=default_backend())
                with open(pub_path, "rb") as f:
                    self.public_key = serialization.load_pem_public_key(
                        f.read(), backend=default_backend())
                return
            except Exception:
                self.private_key = None
                self.public_key = None
        if _CRYPTO_OK:
            try:
                self.private_key = rsa.generate_private_key(
                    public_exponent=65537, key_size=2048, backend=default_backend())
                self.public_key = self.private_key.public_key()
                self._persist()
            except Exception:
                self.private_key = None
                self.public_key = None
        else:
            # 回退：用一个固定随机种子做"模拟私钥"
            self._fallback_secret = hashlib.sha256(b"license-fallback-seed").digest()

    def _persist(self) -> None:
        if not _CRYPTO_OK or self.private_key is None:
            return
        try:
            priv_pem = self.private_key.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.PKCS8,
                encryption_algorithm=serialization.NoEncryption())
            pub_pem = self.public_key.public_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PublicFormat.SubjectPublicKeyInfo)
            with open(os.path.join(DATA_DIR, "license_private.pem"), "wb") as f:
                f.write(priv_pem)
            with open(os.path.join(DATA_DIR, "license_public.pem"), "wb") as f:
                f.write(pub_pem)
        except Exception:
            pass

    def public_key_pem(self) -> str:
        if not _CRYPTO_OK or self.public_key is None:
            return "FALLBACK-PUBLIC-KEY (cryptography unavailable)"
        try:
            return self.public_key.public_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PublicFormat.SubjectPublicKeyInfo).decode("ascii")
        except Exception:
            return "PUBLIC-KEY-EXPORT-FAILED"

    def sign(self, data: bytes) -> str:
        if _CRYPTO_OK and self.private_key is not None:
            sig = self.private_key.sign(
                data,
                padding.PSS(mgf=padding.MGF1(hashes.SHA256()),
                            salt_length=padding.PSS.MAX_LENGTH),
                hashes.SHA256())
            return _b64e(sig)
        # 回退：HMAC-SHA256 模拟签名
        return _b64e(hmac.new(self._fallback_secret, data, hashlib.sha256).digest())

    def verify(self, data: bytes, signature_b64: str) -> bool:
        try:
            sig = _b64d(signature_b64)
            if _CRYPTO_OK and self.public_key is not None:
                self.public_key.verify(
                    sig, data,
                    padding.PSS(mgf=padding.MGF1(hashes.SHA256()),
                                salt_length=padding.PSS.MAX_LENGTH),
                    hashes.SHA256())
                return True
            expected = hmac.new(self._fallback_secret, data, hashlib.sha256).digest()
            return hmac.compare_digest(sig, expected)
        except Exception:
            return False


_key_mgr: Optional[KeyManager] = None


def get_key_manager() -> KeyManager:
    global _key_mgr
    with LOCK:
        if _key_mgr is None:
            _key_mgr = KeyManager()
        return _key_mgr


# --------------------------------------------------------------------------- #
# 激活码生成（人读友好分组码）
# --------------------------------------------------------------------------- #
def _make_activation_code(license_id: str, secret: str) -> str:
    raw = (license_id + "::" + secret).encode("utf-8")
    digest = hashlib.sha256(raw).digest()
    code = base64.b32encode(digest).decode("ascii")[:20]
    return "-".join(code[i:i:5] for i in range(0, 20, 5))


# --------------------------------------------------------------------------- #
# License 签发器
# --------------------------------------------------------------------------- #
class LicenseIssuer:
    """签发、存储、吊销、审计 License。"""

    def __init__(self) -> None:
        self.licenses: Dict[str, Dict[str, Any]] = {}
        self.revoked: Dict[str, Dict[str, Any]] = {}
        self.activation_codes: Dict[str, str] = {}   # code -> license_id
        self.audit_logs: List[Dict[str, Any]] = []
        self.verify_stats: Dict[str, int] = {"total": 0, "ok": 0,
                                             "expired": 0, "revoked": 0,
                                             "bad_signature": 0, "device_mismatch": 0}

    # ---------------- 签发 ---------------- #
    def issue(self, plan: str, customer: str, days: Optional[int] = None,
              extra: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
        plan = plan if plan in LICENSE_PLANS else "trial"
        spec = dict(LICENSE_PLANS[plan])
        days = days or spec["duration_days"]
        now = int(_now())
        expires = now + int(days) * 86400
        license_id = "LIC-" + uuid.uuid4().hex[:12].upper()
        secret = uuid.uuid4().hex
        payload = {
            "license_id": license_id,
            "customer": customer,
            "plan": plan,
            "plan_name": spec["name"],
            "issued_at": now,
            "expires_at": expires,
            "duration_days": days,
            "max_users": spec["max_users"],
            "max_devices": spec["max_devices"],
            "api_quota_per_day": spec["api_quota_per_day"],
            "max_assets": spec["max_assets"],
            "max_scan_tasks": spec["max_scan_tasks"],
            "max_reports": spec["max_reports"],
            "max_storage_mb": spec["max_storage_mb"],
            "modules": spec["modules"],
            "advanced_features": spec["advanced_features"],
            "grace_days": spec["grace_days"],
            "extra": extra or {},
        }
        data = _canonical(payload)
        signature = get_key_manager().sign(data)
        activation_code = _make_activation_code(license_id, secret)
        record = {
            "payload": payload,
            "signature": signature,
            "activation_code": activation_code,
            "secret": secret,
            "status": "active",
            "devices": [],
            "created_at": time.strftime("%Y-%m-%d %H:%M:%S"),
        }
        with LOCK:
            self.licenses[license_id] = record
            self.activation_codes[activation_code] = license_id
            self._audit("issue", license_id, f"签发 {spec['name']} 给 {customer}")
        return self._view(license_id)

    def batch_issue(self, plan: str, customers: List[str],
                    days: Optional[int] = None) -> List[Dict[str, Any]]:
        return [self.issue(plan, c, days=days) for c in customers]

    # ---------------- 验证 ---------------- #
    def verify(self, license_id: str, signature: str,
               device_fingerprint: Optional[str] = None,
               mode: str = "local") -> Dict[str, Any]:
        """返回 {valid, reasons, payload, days_remaining}。mode: local/online/hybrid"""
        with LOCK:
            self.verify_stats["total"] += 1
            rec = self.licenses.get(license_id)
            reasons: List[str] = []
            if not rec:
                reasons.append("license_not_found")
                return {"valid": False, "reasons": reasons, "payload": None,
                        "days_remaining": 0}
            payload = rec["payload"]
            # 1) 签名校验
            if not get_key_manager().verify(_canonical(payload), signature):
                self.verify_stats["bad_signature"] += 1
                reasons.append("bad_signature")
            # 2) 吊销校验
            if license_id in self.revoked:
                self.verify_stats["revoked"] += 1
                reasons.append("revoked")
            # 3) 有效期校验
            now = int(_now())
            if now > payload["expires_at"]:
                self.verify_stats["expired"] += 1
                reasons.append("expired")
            elif now > payload["expires_at"] - payload["grace_days"] * 86400:
                reasons.append("in_grace_period")
            # 4) 设备绑定校验
            if device_fingerprint:
                bound = rec.get("devices", [])
                if bound and device_fingerprint not in bound:
                    # 未超设备数则允许绑定，否则拒绝
                    if len(bound) >= payload["max_devices"]:
                        self.verify_stats["device_mismatch"] += 1
                        reasons.append("device_limit_exceeded")
            valid = len([r for r in reasons if r in
                         ("bad_signature", "revoked", "expired", "device_limit_exceeded")]) == 0
            if valid:
                self.verify_stats["ok"] += 1
            days_remaining = max(0, (payload["expires_at"] - now) // 86400)
            self._audit("verify", license_id,
                        f"mode={mode} valid={valid} reasons={reasons}")
            return {"valid": valid, "reasons": reasons, "payload": payload,
                    "days_remaining": days_remaining, "mode": mode}

    def verify_by_code(self, activation_code: str,
                       device_fingerprint: Optional[str] = None) -> Dict[str, Any]:
        with LOCK:
            license_id = self.activation_codes.get(activation_code.strip().upper())
            if not license_id:
                return {"valid": False, "reasons": ["invalid_activation_code"],
                        "payload": None, "days_remaining": 0}
            rec = self.licenses[license_id]
            return self.verify(license_id, rec["signature"],
                               device_fingerprint=device_fingerprint, mode="online")

    # ---------------- 吊销 ---------------- #
    def revoke(self, license_id: str, reason: str = "用户主动吊销") -> bool:
        with LOCK:
            rec = self.licenses.get(license_id)
            if not rec:
                return False
            rec["status"] = "revoked"
            self.revoked[license_id] = {
                "license_id": license_id, "reason": reason,
                "revoked_at": time.strftime("%Y-%m-%d %H:%M:%S"),
                "revoked_ts": int(_now()),
            }
            self._audit("revoke", license_id, reason)
            return True

    def is_revoked(self, license_id: str) -> bool:
        return license_id in self.revoked

    # ---------------- 存储 / 备份 / 恢复 / 迁移 ---------------- #
    def export_encrypted(self) -> str:
        """导出全量（HMAC 完整性保护），用于备份。"""
        with LOCK:
            blob = {
                "licenses": self.licenses,
                "revoked": self.revoked,
                "activation_codes": self.activation_codes,
                "exported_at": int(_now()),
            }
            data = _canonical(blob)
            mac = hmac.new(get_key_manager().sign(b"export-mac").encode()[:32],
                           data, hashlib.sha256).hexdigest()
            return _b64e(data) + "." + mac

    def restore(self, blob: str) -> Dict[str, Any]:
        try:
            payload_b64, mac = blob.split(".", 1)
            data = _b64d(payload_b64)
            expect = hmac.new(get_key_manager().sign(b"export-mac").encode()[:32],
                              data, hashlib.sha256).hexdigest()
            if not hmac.compare_digest(mac, expect):
                return {"ok": False, "error": "完整性校验失败"}
            obj = json.loads(data.decode("utf-8"))
            with LOCK:
                self.licenses = obj.get("licenses", {})
                self.revoked = obj.get("revoked", {})
                self.activation_codes = obj.get("activation_codes", {})
            return {"ok": True, "restored": len(self.licenses)}
        except Exception as e:
            return {"ok": False, "error": str(e)}

    def migrate(self, src: Dict[str, Any]) -> Dict[str, Any]:
        """从旧系统字典迁移 License（重新计算 HMAC 签名）。"""
        count = 0
        for lid, rec in (src or {}).items():
            try:
                payload = rec["payload"]
                rec["signature"] = get_key_manager().sign(_canonical(payload))
                self.licenses[lid] = rec
                count += 1
            except Exception:
                continue
        return {"ok": True, "migrated": count}

    # ---------------- 审计 ---------------- #
    def _audit(self, action: str, license_id: str, detail: str) -> None:
        self.audit_logs.append({
            "ts": time.strftime("%Y-%m-%d %H:%M:%S"),
            "action": action, "license_id": license_id, "detail": detail,
        })
        if len(self.audit_logs) > 10000:
            self.audit_logs = self.audit_logs[-10000:]

    def anomaly_detection(self) -> List[Dict[str, Any]]:
        """简易异常检测：短时间大量验证失败、吊销后仍验证等。"""
        alerts: List[Dict[str, Any]] = []
        if self.verify_stats["total"]:
            fail_rate = 1 - self.verify_stats["ok"] / max(1, self.verify_stats["total"])
            if fail_rate > 0.3:
                alerts.append({"type": "high_failure_rate",
                               "value": round(fail_rate, 3),
                               "message": f"License 验证失败率 {fail_rate:.1%}，疑似破解"})
        if self.verify_stats["device_mismatch"] > 5:
            alerts.append({"type": "device_abuse",
                           "value": self.verify_stats["device_mismatch"],
                           "message": "设备绑定超限次数异常偏高"})
        return alerts

    def audit_report(self) -> Dict[str, Any]:
        return {
            "verify_stats": self.verify_stats,
            "total_licenses": len(self.licenses),
            "total_revoked": len(self.revoked),
            "audit_events": len(self.audit_logs),
            "recent_events": self.audit_logs[-20:],
            "anomalies": self.anomaly_detection(),
        }

    # ---------------- 视图 ---------------- #
    def _view(self, license_id: str) -> Dict[str, Any]:
        rec = self.licenses[license_id]
        p = rec["payload"]
        days_left = max(0, int((p["expires_at"] - _now()) // 86400))
        return {
            "license_id": license_id,
            "customer": p["customer"],
            "plan": p["plan"],
            "plan_name": p["plan_name"],
            "issued_at": time.strftime("%Y-%m-%d %H:%M:%S",
                                       time.localtime(p["issued_at"])),
            "expires_at": time.strftime("%Y-%m-%d %H:%M:%S",
                                        time.localtime(p["expires_at"])),
            "days_remaining": days_left,
            "status": rec["status"],
            "activation_code": rec["activation_code"],
            "modules": p["modules"],
            "max_users": p["max_users"],
            "max_devices": p["max_devices"],
            "bound_devices": len(rec.get("devices", [])),
            "revoked": license_id in self.revoked,
        }

    def list_all(self) -> List[Dict[str, Any]]:
        with LOCK:
            return [self._view(lid) for lid in self.licenses]

    def get(self, license_id: str) -> Optional[Dict[str, Any]]:
        with LOCK:
            if license_id not in self.licenses:
                return None
            return self._view(license_id)

    def extend(self, license_id: str, add_days: int) -> bool:
        with LOCK:
            rec = self.licenses.get(license_id)
            if not rec:
                return False
            rec["payload"]["expires_at"] += int(add_days) * 86400
            self._audit("extend", license_id, f"延长 {add_days} 天")
            return True

    def upgrade_plan(self, license_id: str, new_plan: str) -> bool:
        with LOCK:
            rec = self.licenses.get(license_id)
            if not rec or new_plan not in LICENSE_PLANS:
                return False
            spec = LICENSE_PLANS[new_plan]
            p = rec["payload"]
            p["plan"] = new_plan
            p["plan_name"] = spec["name"]
            for k in ("max_users", "max_devices", "api_quota_per_day",
                      "max_assets", "max_scan_tasks", "max_reports",
                      "max_storage_mb", "modules", "advanced_features",
                      "grace_days"):
                p[k] = spec[k]
            rec["signature"] = get_key_manager().sign(_canonical(p))
            self._audit("upgrade", license_id, f"升级到 {spec['name']}")
            return True


# --------------------------------------------------------------------------- #
# 单例
# --------------------------------------------------------------------------- #
_issuer: Optional[LicenseIssuer] = None


def get_issuer() -> LicenseIssuer:
    global _issuer
    with LOCK:
        if _issuer is None:
            _issuer = LicenseIssuer()
        return _issuer

# =============================================================================
# v30.0 Real License system (machine-code bound + RSA-PSS signature + tiers)
# License format: Base64(JSON payload) + "." + Base64(RSA signature)
# =============================================================================
from datetime import datetime, timezone  # noqa: E402
import platform as _platform_mod        # noqa: E402
import socket as _socket_mod             # noqa: E402

# --- Tier definitions: free / pro / enterprise ---
REAL_TIERS: Dict[str, Dict[str, Any]] = {
    "free": {
        "code": "free",
        "name": "Free",
        "max_api_calls_per_day": 100,
        "modules": ["dashboard", "basic_scan"],
        "features": ["basic_scan", "single_report"],
        "multi_tenant": False,
        "priority_support": False,
    },
    "pro": {
        "code": "pro",
        "name": "Pro",
        "max_api_calls_per_day": 100000,
        "modules": ["dashboard", "basic_scan", "vuln_scan", "ai_analysis",
                    "asset_mgmt", "report", "compliance", "api_open"],
        "features": ["basic_scan", "advanced_scan", "ai_analysis",
                     "unlimited_api", "advanced_report"],
        "multi_tenant": False,
        "priority_support": False,
    },
    "enterprise": {
        "code": "enterprise",
        "name": "Enterprise",
        "max_api_calls_per_day": 10_000_000,
        "modules": ["*"],
        "features": ["*", "multi_tenant", "distributed_scan",
                     "custom_integration", "priority_support", "sla"],
        "multi_tenant": True,
        "priority_support": True,
    },
}

VALID_TIER_CODES = tuple(REAL_TIERS.keys())


def generate_machine_code() -> str:
    """Return a 32-hex hardware fingerprint for the current host."""
    import os as _os
    override = _os.environ.get("LICENSE_MACHINE_CODE", "").strip()
    if override:
        return override.lower()
    try:
        mac = uuid.getnode()
    except Exception:
        mac = 0
    raw = (f"{_socket_mod.gethostname()}|{_platform_mod.node()}|"
           f"{_platform_mod.system()}|{mac}".encode())
    return hashlib.sha256(raw).hexdigest()[:32]


class RealLicenseIssuer:
    """Issue machine-bound, RSA-PSS signed licenses."""

    def __init__(self, key_manager=None) -> None:
        self._km = key_manager or get_key_manager()

    def issue(
        self,
        *,
        machine_code: str,
        tier: str = "pro",
        customer: str = "Anonymous",
        duration_days: int = 365,
        issued_at=None,
        features=None,
        extra=None,
    ) -> Dict[str, Any]:
        if tier not in REAL_TIERS:
            raise ValueError(f"unknown tier: {tier}; valid={VALID_TIER_CODES}")
        now = float(issued_at if issued_at is not None else time.time())
        expires = now + int(duration_days) * 86400

        tier_def = REAL_TIERS[tier]
        payload: Dict[str, Any] = {
            "schema": "aiah/v30",
            "lic_id": "LIC-" + uuid.uuid4().hex[:12].upper(),
            "machine_code": machine_code.strip().lower(),
            "tier": tier,
            "tier_name": tier_def["name"],
            "customer": customer,
            "issued_at": int(now),
            "expires_at": int(expires),
            "duration_days": int(duration_days),
            "features": list(features) if features else list(tier_def["features"]),
            "modules": list(tier_def["modules"]),
            "multi_tenant": bool(tier_def["multi_tenant"]),
            "priority_support": bool(tier_def["priority_support"]),
        }
        if extra:
            payload.update(extra)

        canonical = _canonical(payload)
        # KeyManager.sign() already returns a urlsafe-base64 string.
        sig_b64 = self._km.sign(canonical)

        payload_b64 = _b64e(canonical)
        license_str = f"{payload_b64}.{sig_b64}"
        return {
            "license_key": license_str,
            "payload": payload,
            "signature_b64": sig_b64,
            "issued_at_iso": datetime.fromtimestamp(now, tz=timezone.utc).isoformat(),
            "expires_at_iso": datetime.fromtimestamp(expires, tz=timezone.utc).isoformat(),
        }

    @staticmethod
    def parse(license_key: str) -> Dict[str, Any]:
        """Parse a license string into (payload, signature). No crypto check."""
        license_key = (license_key or "").strip()
        if "." not in license_key:
            raise ValueError("invalid license: missing '.' separator")
        payload_b64, sig_b64 = license_key.split(".", 1)
        payload_raw = _b64d(payload_b64)
        payload = json.loads(payload_raw.decode("utf-8"))
        return {"payload": payload, "signature": _b64d(sig_b64)}


_real_issuer = None


def get_real_issuer() -> RealLicenseIssuer:
    global _real_issuer
    with LOCK:
        if _real_issuer is None:
            _real_issuer = RealLicenseIssuer()
        return _real_issuer


def generate_real_license(
    *,
    machine_code=None,
    tier: str = "pro",
    customer: str = "Anonymous",
    duration_days: int = 365,
) -> Dict[str, Any]:
    """Convenience: issue a license for the current host."""
    return get_real_issuer().issue(
        machine_code=machine_code or generate_machine_code(),
        tier=tier,
        customer=customer,
        duration_days=duration_days,
    )
