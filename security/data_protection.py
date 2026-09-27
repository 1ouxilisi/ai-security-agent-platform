# -*- coding: utf-8 -*-
"""
data_protection模块，提供数据保护功能。

模块功能：
    - AES-256-GCM敏感数据加密/解密
    - 数据脱敏（IP/域名/密钥/邮箱等）
    - 数据备份与恢复
    - 安全删除（覆写删除）

注意事项：
    - 本模块仅用于授权的安全测试
    - 请勿用于非法用途
    - 使用前请确保已获得相关授权
"""
import os
import json
import time
import base64
import random
import shutil
import zipfile
import hashlib
from datetime import datetime, timedelta
from typing import Any, Dict, List, Optional, Union

# 项目根目录
_PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
_DATA_DIR = os.path.join(_PROJECT_ROOT, "data")
_CONFIG_DIR = os.path.join(_PROJECT_ROOT, "config")

# 尝试导入cryptography库
try:
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM
    _CRYPTOGRAPHY_AVAILABLE = True
except ImportError:
    _CRYPTOGRAPHY_AVAILABLE = False


class DataProtection:
    """数据保护类。

    提供加密存储、数据脱敏、备份恢复和安全删除功能。
    """

    # 备份保留天数
    BACKUP_RETENTION_DAYS = 7

    def __init__(self, encryption_key: Optional[bytes] = None):
        """初始化DataProtection实例。

        加密密钥从环境变量DATA_ENCRYPTION_KEY读取（32字节，AES-256），
        如果不存在则生成一个保存到data/.encryption_key。

        Args:
            encryption_key: 可选的加密密钥（32字节）。
        """
        os.makedirs(_DATA_DIR, exist_ok=True)

        self._degraded_mode = False
        self._key_file = os.path.join(_DATA_DIR, ".encryption_key")

        if encryption_key is not None:
            self._key = encryption_key
        else:
            env_key = os.environ.get("DATA_ENCRYPTION_KEY", "")
            if env_key:
                # 尝试从base64解码
                try:
                    self._key = base64.b64decode(env_key)
                except Exception:
                    self._key = env_key.encode("utf-8")[:32]
            else:
                self._key = self._load_or_create_key()

            # 确保密钥长度为32字节
            if len(self._key) < 32:
                self._key = self._key.ljust(32, b"\0")
            elif len(self._key) > 32:
                self._key = self._key[:32]

        # 如果cryptography不可用，降级模式
        if not _CRYPTOGRAPHY_AVAILABLE:
            self._degraded_mode = True

    def _load_or_create_key(self) -> bytes:
        """从文件加载或生成新加密密钥。"""
        if os.path.exists(self._key_file):
            try:
                with open(self._key_file, "rb") as f:
                    return f.read()
            except IOError:
                pass

        # 生成新密钥
        new_key = os.urandom(32)
        try:
            with open(self._key_file, "wb") as f:
                f.write(new_key)
            # 设置文件权限（仅所有者可读）
            try:
                os.chmod(self._key_file, 0o600)
            except OSError:
                pass  # Windows上可能不支持
        except IOError:
            pass
        return new_key

    # ------------------------------------------------------------------ #
    # 加密/解密
    # ------------------------------------------------------------------ #
    def encrypt(self, data: str) -> str:
        """加密敏感数据。

        Args:
            data: 明文字符串。

        Returns:
            base64编码的密文（含nonce和tag）。
        """
        if self._degraded_mode:
            # 降级加密：base64混淆 + XOR
            return self._degraded_encrypt(data)

        try:
            aesgcm = AESGCM(self._key)
            nonce = os.urandom(12)
            plaintext = data.encode("utf-8")
            ciphertext = aesgcm.encrypt(nonce, plaintext, None)
            # 组合nonce + ciphertext
            combined = nonce + ciphertext
            return base64.b64encode(combined).decode("ascii")
        except Exception:
            # 加密失败时降级
            return self._degraded_encrypt(data)

    def decrypt(self, encrypted_data: str) -> str:
        """解密数据。

        Args:
            encrypted_data: base64编码的密文。

        Returns:
            明文字符串。
        """
        if self._degraded_mode:
            return self._degraded_decrypt(encrypted_data)

        try:
            combined = base64.b64decode(encrypted_data)
            nonce = combined[:12]
            ciphertext = combined[12:]
            aesgcm = AESGCM(self._key)
            plaintext = aesgcm.decrypt(nonce, ciphertext, None)
            return plaintext.decode("utf-8")
        except Exception:
            # 解密失败时尝试降级解密
            try:
                return self._degraded_decrypt(encrypted_data)
            except Exception:
                return ""

    def _degraded_encrypt(self, data: str) -> str:
        """降级加密（安全性较低）：base64 + 简单XOR。"""
        plaintext = data.encode("utf-8")
        # 简单XOR混淆
        xor_key = self._key[:len(plaintext)] if len(plaintext) > 0 else self._key
        # 确保key长度匹配
        if len(xor_key) < len(plaintext):
            xor_key = (xor_key * (len(plaintext) // len(xor_key) + 1))[:len(plaintext)]
        encrypted = bytes(a ^ b for a, b in zip(plaintext, xor_key))
        return "DEGRADED:" + base64.b64encode(encrypted).decode("ascii")

    def _degraded_decrypt(self, encrypted_data: str) -> str:
        """降级解密。"""
        if encrypted_data.startswith("DEGRADED:"):
            encrypted_data = encrypted_data[len("DEGRADED:"):]
        encrypted = base64.b64decode(encrypted_data)
        xor_key = self._key[:len(encrypted)] if len(encrypted) > 0 else self._key
        if len(xor_key) < len(encrypted):
            xor_key = (xor_key * (len(encrypted) // len(xor_key) + 1))[:len(encrypted)]
        decrypted = bytes(a ^ b for a, b in zip(encrypted, xor_key))
        return decrypted.decode("utf-8")

    # ------------------------------------------------------------------ #
    # 数据脱敏
    # ------------------------------------------------------------------ #
    # 敏感字段名（字典key匹配，命中则强制脱敏值）
    SENSITIVE_KEY_PATTERNS = ("password", "passwd", "secret", "token", "api_key", "apikey",
                               "private_key", "access_key", "credential", "auth")

    def mask_sensitive(self, data: Any, level: str = "medium") -> Any:
        """数据脱敏。

        支持IP地址、域名、密钥/密码、邮箱的脱敏，
        支持字典/列表/字符串递归脱敏。
        字典key命中敏感词（password/secret/token等）时强制脱敏值。

        Args:
            data: 待脱敏的数据（字符串/字典/列表）。
            level: 脱敏级别（medium/high）。

        Returns:
            脱敏后的数据。
        """
        if isinstance(data, dict):
            result = {}
            for k, v in data.items():
                k_lower = str(k).lower()
                if any(p in k_lower for p in self.SENSITIVE_KEY_PATTERNS):
                    # key命中敏感词，强制将值按密钥规则脱敏
                    if isinstance(v, str):
                        result[k] = self._mask_secret(v)
                    else:
                        result[k] = self.mask_sensitive(v, level)
                else:
                    result[k] = self.mask_sensitive(v, level)
            return result
        elif isinstance(data, list):
            return [self.mask_sensitive(item, level) for item in data]
        elif isinstance(data, str):
            return self._mask_string(data, level)
        else:
            return data

    def _mask_string(self, s: str, level: str) -> str:
        """对单个字符串进行脱敏判断和处理。"""
        # 检查是否为IP地址
        if self._is_ip(s):
            return self._mask_ip(s, level)
        # 检查是否为邮箱
        if "@" in s and "." in s and " " not in s:
            return self._mask_email(s, level)
        # 检查是否像密钥/密码（以sk-、token、key等开头或长度>16的连续字母数字）
        if self._is_secret_like(s):
            return self._mask_secret(s)
        # 检查是否像域名
        if self._is_domain(s):
            return self._mask_domain(s, level)
        return s

    @staticmethod
    def _is_ip(s: str) -> bool:
        """简单判断是否为IP地址。"""
        parts = s.split(".")
        if len(parts) != 4:
            return False
        try:
            return all(p.isdigit() and 0 <= int(p) <= 255 for p in parts)
        except ValueError:
            return False

    @staticmethod
    def _is_domain(s: str) -> bool:
        """简单判断是否为域名。"""
        if " " in s or "/" in s or ":" in s:
            return False
        parts = s.split(".")
        if len(parts) < 2:
            return False
        return all(p.replace("-", "").isalnum() for p in parts if p)

    @staticmethod
    def _is_secret_like(s: str) -> bool:
        """判断是否像密钥/密码。"""
        prefixes = ("sk-", "api-", "token", "secret", "key-", "AKIA")
        if any(s.lower().startswith(p) for p in prefixes):
            return True
        # 长度>=16且包含字母和数字的连续字符串可能是密钥
        if len(s) >= 16 and s.replace("-", "").replace("_", "").isalnum():
            has_alpha = any(c.isalpha() for c in s)
            has_digit = any(c.isdigit() for c in s)
            if has_alpha and has_digit:
                return True
        return False

    def _mask_ip(self, ip: str, level: str) -> str:
        """IP地址脱敏。"""
        parts = ip.split(".")
        if level == "high":
            return "*.*.*.*"
        # medium：保留前两段
        return f"{parts[0]}.{parts[1]}.*.*"

    def _mask_email(self, email: str, level: str) -> str:
        """邮箱脱敏。"""
        if "@" not in email:
            return email
        username, domain = email.split("@", 1)
        if level == "high":
            return f"***@{domain}"
        # medium：用户名部分脱敏
        if len(username) <= 1:
            masked_user = "*"
        else:
            masked_user = username[0] + "*" * (len(username) - 1)
        return f"{masked_user}@{domain}"

    @staticmethod
    def _mask_secret(secret: str) -> str:
        """密钥/密码脱敏：始终显示前4位+****。"""
        if len(secret) <= 4:
            return "****"
        return secret[:4] + "****"

    def _mask_domain(self, domain: str, level: str) -> str:
        """域名脱敏。"""
        parts = domain.split(".")
        if len(parts) < 2:
            return domain
        if level == "high":
            return "*." + ".".join(parts[-2:])
        # medium：保留顶级域
        return "*." + ".".join(parts[-2:])

    # ------------------------------------------------------------------ #
    # 数据备份
    # ------------------------------------------------------------------ #
    def backup_data(self, backup_dir: str = "data/backups") -> str:
        """备份数据。

        备份SQLite数据库、配置文件和API密钥。
        Windows上使用zipfile格式。

        Args:
            backup_dir: 备份目录。

        Returns:
            备份文件路径。
        """
        # 处理相对路径
        if not os.path.isabs(backup_dir):
            backup_dir = os.path.join(_PROJECT_ROOT, backup_dir)
        os.makedirs(backup_dir, exist_ok=True)

        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        backup_name = f"backup_{timestamp}.zip"
        backup_path = os.path.join(backup_dir, backup_name)

        with zipfile.ZipFile(backup_path, "w", zipfile.ZIP_DEFLATED) as zf:
            # 备份SQLite数据库
            db_files = [
                os.path.join(_DATA_DIR, "platform.db"),
                os.path.join(_DATA_DIR, "hacking_agent.db"),
            ]
            for db_file in db_files:
                if os.path.exists(db_file):
                    arcname = os.path.join("db", os.path.basename(db_file))
                    zf.write(db_file, arcname)

            # 备份配置文件
            if os.path.isdir(_CONFIG_DIR):
                for fname in os.listdir(_CONFIG_DIR):
                    if fname.endswith(".json"):
                        fpath = os.path.join(_CONFIG_DIR, fname)
                        if os.path.isfile(fpath):
                            zf.write(fpath, os.path.join("config", fname))

            # 备份API密钥
            keys_file = os.path.join(_DATA_DIR, "api_keys.json")
            if os.path.exists(keys_file):
                zf.write(keys_file, "api_keys.json")

        # 清理旧备份
        self._cleanup_old_backups(backup_dir)

        return backup_path

    def _cleanup_old_backups(self, backup_dir: str):
        """删除超过保留天数的旧备份。"""
        cutoff = time.time() - self.BACKUP_RETENTION_DAYS * 86400
        try:
            for fname in os.listdir(backup_dir):
                if fname.startswith("backup_") and fname.endswith(".zip"):
                    fpath = os.path.join(backup_dir, fname)
                    if os.path.getmtime(fpath) < cutoff:
                        os.remove(fpath)
        except IOError:
            pass

    def restore_data(self, backup_path: str) -> bool:
        """从备份恢复数据。

        恢复前自动备份当前数据。

        Args:
            backup_path: 备份文件路径。

        Returns:
            是否恢复成功。
        """
        if not os.path.exists(backup_path):
            return False

        # 恢复前自动备份当前数据
        try:
            self.backup_data()
        except Exception:
            pass

        try:
            with zipfile.ZipFile(backup_path, "r") as zf:
                for member in zf.namelist():
                    # 安全检查：防止路径遍历
                    if ".." in member:
                        continue
                    # 恢复到对应位置
                    if member.startswith("db/"):
                        target = os.path.join(_DATA_DIR, os.path.basename(member))
                    elif member.startswith("config/"):
                        target = os.path.join(_CONFIG_DIR, os.path.basename(member))
                    elif member == "api_keys.json":
                        target = os.path.join(_DATA_DIR, "api_keys.json")
                    else:
                        continue

                    # 解压文件
                    with zf.open(member) as src, open(target, "wb") as dst:
                        dst.write(src.read())
            return True
        except (zipfile.BadZipFile, IOError, KeyError):
            return False

    # ------------------------------------------------------------------ #
    # 安全删除
    # ------------------------------------------------------------------ #
    def secure_delete(self, file_path: str, passes: int = 3) -> bool:
        """安全删除文件（覆写删除，不可恢复）。

        安全限制：只允许删除data/目录下的文件。

        Args:
            file_path: 待删除文件路径。
            passes: 覆写次数。

        Returns:
            是否删除成功。
        """
        # 安全检查：只允许删除data/目录下的文件
        abs_path = os.path.abspath(file_path)
        data_abs = os.path.abspath(_DATA_DIR)
        if not abs_path.startswith(data_abs):
            return False

        if not os.path.exists(abs_path) or not os.path.isfile(abs_path):
            return False

        try:
            file_size = os.path.getsize(abs_path)
            with open(abs_path, "wb") as f:
                for _ in range(passes):
                    f.seek(0)
                    f.write(os.urandom(file_size))
                    f.flush()
                os.fsync(f.fileno())
            os.remove(abs_path)
            return True
        except (IOError, OSError):
            return False


# 全局实例
_data_protection_instance: Optional[DataProtection] = None


def get_data_protection() -> DataProtection:
    """获取全局DataProtection实例（单例模式）。"""
    global _data_protection_instance
    if _data_protection_instance is None:
        _data_protection_instance = DataProtection()
    return _data_protection_instance
