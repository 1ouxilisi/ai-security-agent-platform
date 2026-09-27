#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
ldap_auth 模块，提供 LDAP/SSO 认证集成。

模块功能：
    - 支持 Active Directory / OpenLDAP
    - 用户绑定认证、用户搜索、组 -> 本地角色映射
    - 首次登录成功自动创建/更新本地用户
    - python-ldap 不可用时自动降级：纯 socket 实现简单 Bind（RFC 4511），
      并提供配置接口与模拟认证用于测试

注意事项：
    - 本模块仅用于授权的身份认证场景
    - 请勿用于非法用途
    - 使用前请确保已获得相关授权
"""

import json
import os
import socket
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

try:
    from loguru import logger
except ImportError:
    import logging
    logger = logging.getLogger(__name__)

try:
    import ldap  # type: ignore
    LDAP_AVAILABLE = True
except Exception:
    ldap = None  # type: ignore
    LDAP_AVAILABLE = False


PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
CONFIG_DIR = os.path.join(PROJECT_ROOT, "config")
CONFIG_PATH = os.path.join(CONFIG_DIR, "ldap_config.json")
LOCAL_USERS_PATH = os.path.join(CONFIG_DIR, "ldap_users.json")

DEFAULT_CONFIG: Dict[str, Any] = {
    "enabled": False,
    "server": "ldap://127.0.0.1",
    "port": 389,
    "use_ssl": False,
    "base_dn": "dc=example,dc=com",
    "bind_dn": "cn=admin,dc=example,dc=com",
    "bind_password": "",
    "user_filter": "(uid={username})",          # OpenLDAP 示例；AD 可用 (sAMAccountName={username})
    "group_filter": "(member={user_dn})",
    "role_mapping": {
        "CN=admins,OU=groups,DC=example,DC=com": "admin",
        "CN=analysts,OU=groups,DC=example,DC=com": "analyst",
    },
    "default_role": "viewer",
    "mock_mode": False,   # 无真实 LDAP 时开启模拟认证
}


# ==================== 纯 socket 极简 LDAP Bind（BER 编码） ====================

def _ber_len(n: int) -> bytes:
    """BER 长度编码。"""
    if n < 0x80:
        return bytes([n])
    out = []
    while n > 0:
        out.insert(0, n & 0xFF)
        n >>= 8
    return bytes([0x80 | len(out)]) + bytes(out)


def _ber_int(n: int) -> bytes:
    body = n.to_bytes(max(1, (n.bit_length() + 7) // 8), "big")
    return b"\x02" + _ber_len(len(body)) + body


def _ber_str(s: str) -> bytes:
    body = s.encode("utf-8")
    return b"\x04" + _ber_len(len(body)) + body


def _ber_seq(*parts: bytes) -> bytes:
    body = b"".join(parts)
    return b"\x30" + _ber_len(len(body)) + body


def build_simple_bind_request(message_id: int, username: str, password: str) -> bytes:
    """构造 LDAP Simple BindRequest（RFC 4511）。

    BindRequest ::= [APPLICATION 0] SEQUENCE {
        version INTEGER (3), name LDAPString, authentication [CHOICE] }
    simple 认证 = context-specific [0] 包裹的 OCTET STRING。
    """
    bind_content = _ber_int(3) + _ber_str(username) + b"\x80" + _ber_len(len(password.encode())) + password.encode("utf-8")
    bind_req = b"\x60" + _ber_len(len(bind_content)) + bind_content
    return _ber_seq(_ber_int(message_id), bind_req)


def parse_bind_response(data: bytes) -> Dict[str, Any]:
    """解析 BindResponse，返回 {matched, result_code, message}。"""
    try:
        # BindResponse tag = [APPLICATION 1] = 0x61
        if len(data) < 2 or data[0] != 0x30:
            return {"matched": False, "result_code": -1, "message": "响应非 SEQUENCE"}
        # 跳过外层，取内部 messageID + protocolOp
        idx = 2 if data[1] < 0x80 else 2 + (data[1] & 0x7F)
        # messageID INTEGER
        if data[idx] == 0x02:
            ml = data[idx + 1]
            idx += 2 + ml
        # protocolOp [APPLICATION 1]
        if data[idx] != 0x61:
            return {"matched": False, "result_code": -1,
                    "message": f"非 BindResponse (tag=0x{data[idx]:02x})"}
        idx += 2 if data[idx + 1] < 0x80 else 3
        # resultCode ENUMERATED
        rc = data[idx + 2]
        return {"matched": rc == 0, "result_code": rc,
                "message": "成功" if rc == 0 else f"LDAP resultCode={rc}"}
    except Exception as e:
        return {"matched": False, "result_code": -1, "message": f"解析响应失败: {e}"}


class LDAPAuth:
    """LDAP/SSO 认证器。"""

    def __init__(self, config_path: str = CONFIG_PATH):
        """初始化并加载配置。"""
        self.config_path = config_path
        self.config: Dict[str, Any] = json.loads(json.dumps(DEFAULT_CONFIG))
        self.load_config()

    # ==================== 配置读写 ====================

    def load_config(self) -> Dict[str, Any]:
        """加载 LDAP 配置。"""
        try:
            os.makedirs(os.path.dirname(self.config_path), exist_ok=True)
            if os.path.exists(self.config_path):
                with open(self.config_path, "r", encoding="utf-8") as f:
                    saved = json.load(f)
                self.config.update(saved)
            else:
                self.save_config()
        except Exception as e:
            logger.warning("LDAP 配置加载失败，使用默认配置: %s", e)
            self.config = json.loads(json.dumps(DEFAULT_CONFIG))
        return self.config

    def save_config(self) -> bool:
        """保存 LDAP 配置。"""
        try:
            os.makedirs(os.path.dirname(self.config_path), exist_ok=True)
            with open(self.config_path, "w", encoding="utf-8") as f:
                json.dump(self.config, f, ensure_ascii=False, indent=2)
            return True
        except Exception as e:
            logger.error("LDAP 配置保存失败: %s", e)
            return False

    def update_config(self, new_config: Dict[str, Any]) -> Dict[str, Any]:
        self.config.update(new_config or {})
        self.save_config()
        return self.config

    # ==================== 服务器地址解析 ====================

    def _host_port(self):
        server = self.config.get("server", "ldap://127.0.0.1")
        server = server.replace("ldap://", "").replace("ldaps://", "")
        host = server.split(":")[0]
        port = int(self.config.get("port", 636 if self.config.get("use_ssl") else 389))
        return host, port

    # ==================== 认证 ====================

    def _socket_bind(self, username: str, password: str, timeout: int = 5) -> Dict[str, Any]:
        """纯 socket 简单 Bind（无 python-ldap 时的降级实现）。"""
        host, port = self._host_port()
        try:
            with socket.create_connection((host, port), timeout=timeout) as s:
                s.settimeout(timeout)
                req = build_simple_bind_request(1, username, password)
                s.sendall(req)
                data = s.recv(1024)
            result = parse_bind_response(data)
            # 发送 UnbindRequest
            return result
        except Exception as e:
            return {"matched": False, "result_code": -1, "message": f"socket bind 失败: {e}"}

    def _ldap3_bind(self, username: str, password: str) -> Dict[str, Any]:
        """使用 python-ldap 进行完整认证与用户/组查询。"""
        server_url = self.config.get("server", "ldap://127.0.0.1")
        try:
            conn = ldap.initialize(server_url)
            conn.set_option(ldap.OPT_NETWORK_TIMEOUT, 5)
            conn.simple_bind_s(username, password)
            # 搜索用户属性
            user_dn = username
            user_info: Dict[str, Any] = {"dn": user_dn}
            try:
                res = conn.search_s(
                    self.config["base_dn"], ldap.SCOPE_SUBTREE,
                    self.config["user_filter"].format(username=username.split("=")[0]),
                    ["cn", "mail", "displayName", "memberOf"])
                if res:
                    user_dn, attrs = res[0]
                    user_info = {
                        "dn": user_dn,
                        "cn": attrs.get("cn", [b""])[0].decode("utf-8", "ignore"),
                        "mail": attrs.get("mail", [b""])[0].decode("utf-8", "ignore"),
                        "groups": [g.decode("utf-8", "ignore") for g in attrs.get("memberOf", [])],
                    }
            except Exception as e:
                logger.warning("LDAP 用户搜索失败: %s", e)
            conn.unbind_s()
            return {"matched": True, "result_code": 0, "message": "认证成功",
                    "user_info": user_info}
        except Exception as e:
            return {"matched": False, "result_code": -1, "message": f"LDAP 认证失败: {e}"}

    def authenticate(self, username: str, password: str) -> Dict[str, Any]:
        """认证用户，返回 {success, user_info, roles}。"""
        if self.config.get("mock_mode", False):
            roles = self._map_roles(["mock-group"])
            return {"success": bool(password), "user_info": {"cn": username, "mock": True},
                    "roles": roles, "message": "模拟认证"}

        if not self.config.get("enabled", False) and not self.config.get("bind_dn"):
            return {"success": False, "user_info": {}, "roles": [],
                    "message": "LDAP 未启用"}

        # 组装完整用户名（AD 用 user@domain，OpenLDAP 用 uid=...,base_dn）
        if "=" not in username:
            ufilter = self.config.get("user_filter", "(uid={username})")
            if "sAMAccountName" in ufilter or "@" in self.config.get("bind_dn", ""):
                principal = username
            else:
                principal = f"uid={username},{self.config['base_dn']}"
        else:
            principal = username

        if LDAP_AVAILABLE:
            result = self._ldap3_bind(principal, password)
        else:
            result = self._socket_bind(principal, password)

        if not result.get("matched"):
            return {"success": False, "user_info": {}, "roles": [],
                    "message": result.get("message", "认证失败")}

        user_info = result.get("user_info") or {"cn": username, "dn": principal}
        groups = user_info.get("groups", [])
        roles = self._map_roles(groups)
        # 自动同步本地用户
        self._upsert_local_user(username, user_info, roles)
        return {"success": True, "user_info": user_info, "roles": roles,
                "message": result.get("message", "认证成功")}

    # ==================== 用户搜索 / 角色映射 ====================

    def search_user(self, username: str) -> Dict[str, Any]:
        """按 user_filter 搜索用户属性。"""
        if not LDAP_AVAILABLE:
            return {"success": False, "user": None,
                    "message": "当前环境未安装 python-ldap，仅支持 Bind 认证；请安装后使用完整搜索"}
        try:
            server_url = self.config.get("server", "ldap://127.0.0.1")
            conn = ldap.initialize(server_url)
            conn.set_option(ldap.OPT_NETWORK_TIMEOUT, 5)
            if self.config.get("bind_dn"):
                conn.simple_bind_s(self.config["bind_dn"], self.config.get("bind_password", ""))
            res = conn.search_s(
                self.config["base_dn"], ldap.SCOPE_SUBTREE,
                self.config["user_filter"].format(username=username),
                ["cn", "mail", "displayName", "memberOf"])
            conn.unbind_s()
            if not res:
                return {"success": True, "user": None, "message": "未找到用户"}
            dn, attrs = res[0]
            user = {"dn": dn, "attributes": {k: v for k, v in attrs.items()}}
            return {"success": True, "user": user}
        except Exception as e:
            return {"success": False, "user": None, "message": f"搜索失败: {e}"}

    def _map_roles(self, groups: List[str]) -> List[str]:
        """根据 LDAP 组成员映射到本地角色。"""
        mapping = self.config.get("role_mapping", {})
        roles = set()
        for g in groups:
            for group_dn, role in mapping.items():
                if g == group_dn or group_dn in g:
                    roles.add(role)
        if not roles:
            roles.add(self.config.get("default_role", "viewer"))
        return sorted(roles)

    # ==================== 本地用户同步 ====================

    def _upsert_local_user(self, username: str, user_info: Dict[str, Any],
                           roles: List[str]) -> None:
        """首次登录成功后自动创建/更新本地用户记录。"""
        try:
            users: Dict[str, Any] = {}
            if os.path.exists(LOCAL_USERS_PATH):
                with open(LOCAL_USERS_PATH, "r", encoding="utf-8") as f:
                    users = json.load(f)
            users[username] = {
                "username": username,
                "display_name": user_info.get("cn", username),
                "email": user_info.get("mail", ""),
                "roles": roles,
                "last_login": datetime.now(timezone.utc).isoformat(),
                "source": "ldap",
            }
            with open(LOCAL_USERS_PATH, "w", encoding="utf-8") as f:
                json.dump(users, f, ensure_ascii=False, indent=2)
        except Exception as e:
            logger.warning("本地 LDAP 用户同步失败: %s", e)

    def list_synced_users(self) -> Dict[str, Any]:
        """返回已同步的本地用户。"""
        try:
            if not os.path.exists(LOCAL_USERS_PATH):
                return {"users": {}, "total": 0}
            with open(LOCAL_USERS_PATH, "r", encoding="utf-8") as f:
                users = json.load(f)
            return {"users": users, "total": len(users)}
        except Exception as e:
            return {"users": {}, "total": 0, "message": str(e)}

    # ==================== 连接测试 ====================

    def test_connection(self) -> Dict[str, Any]:
        """测试到 LDAP 服务器的连接。"""
        host, port = self._host_port()
        try:
            with socket.create_connection((host, port), timeout=5):
                pass
            return {"success": True,
                    "message": f"TCP {host}:{port} 连接成功",
                    "ldap_lib_available": LDAP_AVAILABLE}
        except Exception as e:
            return {"success": False,
                    "message": f"LDAP 服务器连接失败: {e}",
                    "ldap_lib_available": LDAP_AVAILABLE}


# 模块级单例
ldap_auth = LDAPAuth()
