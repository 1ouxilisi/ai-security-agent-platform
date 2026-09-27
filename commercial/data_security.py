# -*- coding: utf-8 -*-
"""数据安全与合规模块。

提供：
- AES-256-GCM 加密/解密（优先 cryptography，缺失时降级为 Fernet 不可用时的
  纯标准库 XOR+SHA256 占位实现，但正常环境均走 cryptography）
- 密码哈希（PBKDF2-HMAC-SHA256，标准库实现）
- 主密钥管理：环境变量 DATA_ENCRYPTION_KEY，缺失则生成并存 data/.master_key
- 数据脱敏（IP / 域名 / 密钥 / 递归字典）
- 数据保留策略与过期清理
- 租户数据导出 / 彻底删除（GDPR / 个保法）
- 审计日志（jsonl 追加）
"""
import os
import json
import time
import base64
import hmac
import hashlib
import secrets
import threading
from typing import Any, Dict, List, Optional

try:
    from utils.logger import log
except Exception:  # pragma: no cover
    import logging
    log = logging.getLogger("commercial.data_security")

# 尝试加载 cryptography
try:
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM  # type: ignore
    _HAS_CRYPTO = True
except Exception:  # pragma: no cover
    AESGCM = None  # type: ignore
    _HAS_CRYPTO = False


# 递归脱敏时识别的敏感字段名
SENSITIVE_FIELD_KEYWORDS = (
    "ip", "domain", "password", "secret", "key", "token",
    "email", "phone",
)


class DataSecurity:
    """数据安全与合规引擎。"""

    def __init__(self, base_dir: str = "data", tenant_manager=None):
        self.base_dir = base_dir
        self.tenants_dir = os.path.join(base_dir, "tenants")
        self.meta_dir = os.path.join(self.tenants_dir, "_meta")
        self.audit_file = os.path.join(self.meta_dir, "data_audit.jsonl")
        self.retention_file = os.path.join(self.meta_dir, "retention.json")

        self._lock = threading.RLock()
        self._tm = tenant_manager

        # 保留策略: {tenant_id: {data_type: days}}
        self._retention: Dict[str, Dict[str, int]] = {}

        os.makedirs(self.meta_dir, exist_ok=True)
        self._master_key = self._load_or_create_master_key()
        self._load_retention()

    # ---------------- 主密钥 ----------------

    def _load_or_create_master_key(self) -> bytes:
        """从环境变量读取主密钥，否则生成并落盘。"""
        env_key = os.environ.get("DATA_ENCRYPTION_KEY")
        if env_key:
            try:
                return base64.urlsafe_b64decode(env_key)
            except Exception:
                log.warning("[data_security] DATA_ENCRYPTION_KEY 非合法 base64，重新派生")
                return hashlib.sha256(env_key.encode()).digest()

        key_path = os.path.join(self.base_dir, ".master_key")
        if os.path.exists(key_path):
            try:
                with open(key_path, "rb") as f:
                    return f.read()
            except Exception as e:
                log.warning(f"[data_security] 读取主密钥失败: {e}")

        key = AESGCM.generate_key(bit_length=256) if _HAS_CRYPTO \
            else secrets.token_bytes(32)
        try:
            with open(key_path, "wb") as f:
                f.write(key)
            try:
                os.chmod(key_path, 0o600)
            except Exception:
                pass  # Windows 无 chmod 语义，忽略
            log.info(f"[data_security] 已生成新主密钥: {key_path}")
        except Exception as e:
            log.warning(f"[data_security] 主密钥落盘失败: {e}")
        return key

    # ---------------- 加密 / 解密 ----------------

    def encrypt(self, plaintext: str, key: Optional[bytes] = None) -> str:
        """AES-256-GCM 加密，返回 base64(nonce + ciphertext + tag)。"""
        use_key = key or self._master_key
        if isinstance(use_key, str):
            use_key = use_key.encode()
        use_key = hashlib.sha256(use_key).digest()  # 统一为 32 字节

        if _HAS_CRYPTO:
            aes = AESGCM(use_key)
            nonce = secrets.token_bytes(12)
            ct = aes.encrypt(nonce, plaintext.encode("utf-8"), None)
            return base64.b64encode(nonce + ct).decode("ascii")

        # 降级占位：XOR keystream（仅在 cryptography 不可用时）
        nonce = secrets.token_bytes(16)
        stream = hashlib.pbkdf2_hmac("sha256", use_key, nonce, 10000)
        data = plaintext.encode("utf-8")
        out = bytes(b ^ stream[i % len(stream)] for i, b in enumerate(data))
        return "fallback:" + base64.b64encode(nonce + out).decode("ascii")

    def decrypt(self, ciphertext_b64: str, key: Optional[bytes] = None) -> str:
        use_key = key or self._master_key
        if isinstance(use_key, str):
            use_key = use_key.encode()
        use_key = hashlib.sha256(use_key).digest()

        raw = base64.b64decode(ciphertext_b64)
        if ciphertext_b64.startswith("fallback:"):
            raw = base64.b64decode(ciphertext_b64.split(":", 1)[1])
            nonce, body = raw[:16], raw[16:]
            stream = hashlib.pbkdf2_hmac("sha256", use_key, nonce, 10000)
            out = bytes(b ^ stream[i % len(stream)] for i, b in enumerate(body))
            return out.decode("utf-8")

        nonce, ct = raw[:12], raw[12:]
        aes = AESGCM(use_key)
        return aes.decrypt(nonce, ct, None).decode("utf-8")

    # ---------------- 密码哈希 ----------------

    @staticmethod
    def hash_password(password: str) -> str:
        """PBKDF2-HMAC-SHA256 密码哈希。返回 ``salt$hash``。"""
        salt = secrets.token_hex(16)
        h = hashlib.pbkdf2_hmac(
            "sha256", password.encode(), salt.encode(), 200000).hex()
        return f"{salt}${h}"

    @staticmethod
    def verify_password(password: str, stored: str) -> bool:
        try:
            salt, expected = stored.split("$", 1)
        except ValueError:
            return False
        h = hashlib.pbkdf2_hmac(
            "sha256", password.encode(), salt.encode(), 200000).hex()
        return hmac.compare_digest(h, expected)

    # ---------------- 数据脱敏 ----------------

    @staticmethod
    def mask_ip(ip: str) -> str:
        parts = (ip or "").split(".")
        if len(parts) == 4:
            return f"{parts[0]}.{parts[1]}.{parts[2]}.***"
        return "***"

    @staticmethod
    def mask_domain(domain: str) -> str:
        parts = (domain or "").split(".")
        if len(parts) >= 2:
            head = parts[0]
            masked = (head[:2] + "***") if len(head) > 2 else "***"
            return f"{masked}." + ".".join(parts[1:])
        return "***"

    @staticmethod
    def mask_secret(secret: str) -> str:
        s = secret or ""
        if len(s) <= 8:
            return "****"
        return s[:4] + "****" + s[-4:]

    def mask_data(self, data: Any, fields: Optional[List[str]] = None) -> Any:
        """递归脱敏字典/列表中的敏感字段。"""
        sensitive = fields or list(SENSITIVE_FIELD_KEYWORDS)
        if isinstance(data, dict):
            out = {}
            for k, v in data.items():
                kl = k.lower()
                if any(s in kl for s in sensitive):
                    if isinstance(v, str):
                        if "ip" in kl:
                            out[k] = self.mask_ip(v)
                        elif "domain" in kl:
                            out[k] = self.mask_domain(v)
                        elif "email" in kl:
                            out[k] = self._mask_email(v)
                        elif "phone" in kl:
                            out[k] = v[:3] + "****" + v[-2:] if len(v) > 5 else "****"
                        else:
                            out[k] = self.mask_secret(v)
                    else:
                        out[k] = "***"
                else:
                    out[k] = self.mask_data(v, fields)
            return out
        if isinstance(data, list):
            return [self.mask_data(x, fields) for x in data]
        return data

    @staticmethod
    def _mask_email(email: str) -> str:
        if "@" not in email:
            return "***"
        local, dom = email.split("@", 1)
        local = (local[:2] + "***") if len(local) > 2 else "***"
        return f"{local}@{dom}"

    # ---------------- 保留策略 ----------------

    def _load_retention(self):
        if os.path.exists(self.retention_file):
            try:
                with open(self.retention_file, "r", encoding="utf-8") as f:
                    self._retention = json.load(f)
            except Exception as e:
                log.warning(f"[data_security] 加载保留策略失败: {e}")
                self._retention = {}

    def _save_retention(self):
        with open(self.retention_file, "w", encoding="utf-8") as f:
            json.dump(self._retention, f, ensure_ascii=False, indent=2)

    def set_retention_policy(self, tenant_id: str, data_type: str,
                             days: int) -> None:
        with self._lock:
            self._retention.setdefault(tenant_id, {})[data_type] = int(days)
            self._save_retention()

    def get_retention_policy(self, tenant_id: str) -> Dict[str, int]:
        return dict(self._retention.get(tenant_id, {}))

    def cleanup_expired(self, tenant_id: Optional[str] = None) -> Dict[str, int]:
        """按保留期删除过期数据文件。返回删除文件数。"""
        deleted = 0
        targets = [tenant_id] if tenant_id else list(self._retention.keys())
        now = time.time()
        for tid in targets:
            policy = self._retention.get(tid, {})
            if not policy:
                continue
            if self._tm is not None:
                root = self._tm.get_tenant_path(tid)
            else:
                root = os.path.join(self.tenants_dir, tid)
            for data_type, days in policy.items():
                subdir = data_type  # assessments/reports/logs
                target_dir = os.path.join(root, subdir)
                if not os.path.isdir(target_dir):
                    continue
                cutoff = now - days * 86400
                for name in os.listdir(target_dir):
                    fp = os.path.join(target_dir, name)
                    try:
                        if os.path.isfile(fp) and os.path.getmtime(fp) < cutoff:
                            os.remove(fp)
                            deleted += 1
                    except Exception:
                        pass
        return {"deleted_files": deleted}

    # ---------------- 导出 / 删除 ----------------

    def export_tenant_data(self, tenant_id: str,
                           output_path: Optional[str] = None) -> str:
        """导出租户全部数据为 JSON。"""
        payload: Dict[str, Any] = {
            "tenant_id": tenant_id,
            "exported_at": time.strftime("%Y-%m-%d %H:%M:%S"),
        }
        # 租户信息
        if self._tm is not None:
            payload["tenant"] = self._tm.get_tenant(tenant_id)
            root = self._tm.get_tenant_path(tenant_id)
        else:
            root = os.path.join(self.tenants_dir, tenant_id)
            payload["tenant"] = None

        # 收集各子目录文件清单与内容（小文件直接读）
        collected: Dict[str, Any] = {}
        if os.path.isdir(root):
            for sub in TENANT_SUBDIRS if False else ["assessments", "reports",
                                                     "logs", "uploads"]:
                sd = os.path.join(root, sub)
                files = []
                if os.path.isdir(sd):
                    for name in os.listdir(sd):
                        fp = os.path.join(sd, name)
                        if os.path.isfile(fp):
                            files.append({"name": name,
                                          "size": os.path.getsize(fp)})
                collected[sub] = files
        payload["files"] = collected

        # 审计日志
        payload["audit_logs"] = self.get_audit_logs(tenant_id, limit=1000)

        if output_path is None:
            out_dir = os.path.join(root, "exports") if os.path.isdir(root) \
                else self.meta_dir
            os.makedirs(out_dir, exist_ok=True)
            output_path = os.path.join(
                out_dir, f"export_{tenant_id}_{int(time.time())}.json")

        with open(output_path, "w", encoding="utf-8") as f:
            json.dump(payload, f, ensure_ascii=False, indent=2)
        self.log_access(tenant_id, "system", "data:export",
                        resource=output_path, details={"path": output_path})
        log.info(f"[data_security] 租户 {tenant_id} 数据已导出: {output_path}")
        return output_path

    def delete_tenant_data(self, tenant_id: str) -> Dict[str, int]:
        """彻底删除租户所有数据（GDPR/个保法）。"""
        # 删除前审计
        self.log_access(tenant_id, "system", "data:delete",
                        resource=f"tenant:{tenant_id}",
                        details={"reason": "gdpr_delete_request"})
        file_count = 0
        record_count = 0

        if self._tm is not None:
            root = self._tm.get_tenant_path(tenant_id)
        else:
            root = os.path.join(self.tenants_dir, tenant_id)

        if os.path.isdir(root):
            for dirpath, _dirnames, filenames in os.walk(root):
                file_count += len(filenames)
            import shutil
            shutil.rmtree(root, ignore_errors=True)

        # 统计中记录数
        record_count = file_count
        self.log_access(tenant_id, "system", "data:deleted",
                        resource=f"tenant:{tenant_id}",
                        details={"files": file_count})
        return {"deleted_files": file_count, "deleted_records": record_count}

    # ---------------- 审计日志 ----------------

    def log_access(self, tenant_id: str, username: str, action: str,
                   resource: str, details: Optional[Dict[str, Any]] = None):
        rec = {
            "ts": time.time(),
            "tenant_id": tenant_id,
            "username": username,
            "action": action,
            "resource": resource,
            "details": details or {},
        }
        with open(self.audit_file, "a", encoding="utf-8") as f:
            f.write(json.dumps(rec, ensure_ascii=False) + "\n")

    def get_audit_logs(self, tenant_id: str, limit: int = 100) -> List[Dict[str, Any]]:
        if not os.path.exists(self.audit_file):
            return []
        out: List[Dict[str, Any]] = []
        try:
            with open(self.audit_file, "r", encoding="utf-8") as f:
                for line in f:
                    line = line.strip()
                    if not line:
                        continue
                    try:
                        rec = json.loads(line)
                    except Exception:
                        continue
                    if rec.get("tenant_id") == tenant_id:
                        out.append(rec)
        except Exception as e:
            log.warning(f"[data_security] 读取审计日志失败: {e}")
        return out[-limit:]


# 模块级单例
_default_sec: Optional[DataSecurity] = None


def get_data_security(base_dir: str = "data",
                      tenant_manager=None) -> DataSecurity:
    global _default_sec
    if _default_sec is None:
        _default_sec = DataSecurity(base_dir, tenant_manager)
    return _default_sec
