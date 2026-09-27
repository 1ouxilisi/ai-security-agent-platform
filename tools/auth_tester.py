"""
auth_tester安全工具集成模块，提供相关安全工具的封装和调用。

模块功能：
    - 提供相关安全测试功能
    - 支持API调用和命令行使用
    - 与其他模块集成协作

注意事项：
    - 本模块仅用于授权的安全测试
    - 请勿用于非法用途
    - 使用前请确保已获得相关授权
"""
import base64
import json
import re
import time
from typing import Any, Dict, List, Optional, Tuple
from urllib.parse import urlparse, parse_qs, urlencode, urlunparse

from utils.logger import log


class AuthTester:
    """认证测试器 - 全面的认证和授权安全测试"""

    def __init__(self):
        """初始化AuthTester实例。

            Args:
            self: 类实例。
        """
        self._jwt_algorithms = ["HS256", "HS384", "HS512", "RS256", "RS384", "RS512", "ES256", "ES384", "ES512", "none"]
        self._common_secrets = ["secret", "password", "admin", "123456", "jwt", "token", "key", "default", "changeme"]
        log.info("✅ 认证测试器初始化成功")

    # ========== JWT测试 ==========

    def decode_jwt(self, token: str) -> Optional[Dict]:
        """解码JWT令牌（不验证签名）"""
        try:
            parts = token.split(".")
            if len(parts) != 3:
                return None

            # Base64URL解码
            def b64url_decode(s: str) -> bytes:
                """解码相关数据。

                    Args:
                    s: 相关参数。

                    Returns:
                    操作结果。
                """
                s += "=" * (4 - len(s) % 4)
                return base64.urlsafe_b64decode(s)

            header = json.loads(b64url_decode(parts[0]))
            payload = json.loads(b64url_decode(parts[1]))
            signature = parts[2]

            return {
                "header": header,
                "payload": payload,
                "signature": signature,
                "raw": token,
            }
        except Exception as e:
            log.warning(f"JWT解码失败: {e}")
            return None

    def analyze_jwt(self, token: str) -> Dict:
        """分析JWT令牌安全性"""
        result = {
            "valid_format": False,
            "issues": [],
            "recommendations": [],
            "details": {},
        }

        decoded = self.decode_jwt(token)
        if not decoded:
            result["issues"].append({"severity": "high", "description": "JWT格式无效"})
            return result

        result["valid_format"] = True
        header = decoded["header"]
        payload = decoded["payload"]
        result["details"] = {"header": header, "payload": payload}

        # 1. 检查算法
        alg = header.get("alg", "").upper()
        result["details"]["algorithm"] = alg

        if alg == "NONE":
            result["issues"].append({
                "severity": "critical",
                "description": "JWT使用none算法，签名被禁用",
                "cwe": "CWE-347",
            })
            result["recommendations"].append("禁用none算法，强制使用强签名算法（RS256/ES256）")

        if alg.startswith("HS"):
            result["issues"].append({
                "severity": "medium",
                "description": f"JWT使用对称算法{alg}，密钥可能被暴力破解",
                "cwe": "CWE-327",
            })
            result["recommendations"].append("考虑使用非对称算法（RS256/ES256）替代对称算法")

        # 2. 检查过期时间
        now = time.time()
        if "exp" in payload:
            exp = payload["exp"]
            result["details"]["expires_at"] = time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(exp))
            if exp < now:
                result["issues"].append({
                    "severity": "high",
                    "description": "JWT已过期",
                    "expired_seconds_ago": int(now - exp),
                })
            else:
                validity = exp - now
                result["details"]["valid_for_seconds"] = int(validity)
                if validity > 86400 * 7:  # 超过7天
                    result["issues"].append({
                        "severity": "medium",
                        "description": f"JWT有效期过长（{int(validity/86400)}天）",
                    })
                    result["recommendations"].append("缩短JWT有效期，建议不超过24小时")
        else:
            result["issues"].append({
                "severity": "high",
                "description": "JWT没有过期时间（exp）",
                "cwe": "CWE-613",
            })
            result["recommendations"].append("添加exp声明，设置合理的过期时间")

        # 3. 检查issued at
        if "iat" in payload:
            iat = payload["iat"]
            result["details"]["issued_at"] = time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(iat))
            if iat > now + 60:
                result["issues"].append({
                    "severity": "medium",
                    "description": "JWT签发时间在未来（可能时钟不同步）",
                })

        # 4. 检查not before
        if "nbf" in payload:
            nbf = payload["nbf"]
            if nbf > now:
                result["issues"].append({
                    "severity": "info",
                    "description": "JWT尚未生效",
                })

        # 5. 检查敏感信息
        sensitive_keys = ["password", "secret", "token", "key", "ssn", "credit_card", "private_key"]
        for key in payload:
            if any(s in key.lower() for s in sensitive_keys):
                result["issues"].append({
                    "severity": "high",
                    "description": f"JWT payload包含敏感信息: {key}",
                    "cwe": "CWE-312",
                })
                result["recommendations"].append("不要在JWT中存储敏感信息，JWT只是Base64编码不是加密")

        # 6. 检查算法混淆风险
        if alg.startswith("RS"):
            result["issues"].append({
                "severity": "medium",
                "description": "JWT使用RSA算法，可能存在算法混淆攻击（alg=RS256→HS256）",
                "cwe": "CWE-347",
            })
            result["recommendations"].append("验证时明确指定预期算法，不要信任JWT header中的alg字段")

        # 7. 检查kid头注入
        if "kid" in header:
            result["details"]["kid"] = header["kid"]
            if any(c in header["kid"] for c in ["../", "..\\", "/etc/", "file://"]):
                result["issues"].append({
                    "severity": "high",
                    "description": "JWT kid头包含路径遍历字符，可能存在kid注入攻击",
                    "cwe": "CWE-22",
                })

        # 8. 检查jwk头
        if "jwk" in header:
            result["issues"].append({
                "severity": "high",
                "description": "JWT header包含jwk（JSON Web Key），可能存在jwk注入攻击",
                "cwe": "CWE-347",
            })
            result["recommendations"].append("验证时不要信任JWT header中的jwk，使用预配置的公钥")

        # 风险评分
        critical_count = sum(1 for i in result["issues"] if i["severity"] == "critical")
        high_count = sum(1 for i in result["issues"] if i["severity"] == "high")
        medium_count = sum(1 for i in result["issues"] if i["severity"] == "medium")

        risk_score = min(100, critical_count * 25 + high_count * 15 + medium_count * 8)
        result["risk_score"] = risk_score
        result["risk_level"] = "critical" if risk_score >= 75 else "high" if risk_score >= 50 else "medium" if risk_score >= 25 else "low"

        return result

    def generate_jwt_alg_confusion(self, token: str, target_alg: str = "HS256") -> Optional[str]:
        """生成算法混淆测试令牌（RS256→HS256）"""
        decoded = self.decode_jwt(token)
        if not decoded:
            return None

        try:
            header = decoded["header"]
            payload = decoded["payload"]

            # 修改算法
            header["alg"] = target_alg
            if "kid" in header:
                del header["kid"]

            # 重新编码
            def b64url_encode(data: bytes) -> str:
                """编码相关数据。

                    Args:
                    data: 相关参数。

                    Returns:
                    操作结果。
                """
                return base64.urlsafe_b64encode(data).rstrip(b"=").decode()

            header_b64 = b64url_encode(json.dumps(header, separators=(",", ":")).encode())
            payload_b64 = b64url_encode(json.dumps(payload, separators=(",", ":")).encode())

            # 使用空签名（测试none算法）或伪造签名
            if target_alg.lower() == "none":
                signature = ""
            else:
                # 使用常见密钥生成签名（实际测试时需要真实密钥）
                signature = "fake_signature_for_testing"

            return f"{header_b64}.{payload_b64}.{signature}"
        except Exception as e:
            log.warning(f"生成算法混淆令牌失败: {e}")
            return None

    def brute_force_jwt_secret(self, token: str, wordlist: Optional[List[str]] = None) -> Optional[str]:
        """暴力破解JWT对称密钥（HS256/HS384/HS512）"""
        try:
            import hmac
            import hashlib
        except ImportError:
            return None

        decoded = self.decode_jwt(token)
        if not decoded:
            return None

        alg = decoded["header"].get("alg", "").upper()
        if not alg.startswith("HS"):
            return None  # 只支持对称算法

        parts = token.split(".")
        signing_input = f"{parts[0]}.{parts[1]}"
        expected_sig = parts[2]

        hash_func = hashlib.sha256 if alg == "HS256" else hashlib.sha384 if alg == "HS384" else hashlib.sha512

        def b64url_encode(data: bytes) -> str:
            """编码相关数据。

                Args:
                data: 相关参数。

                Returns:
                操作结果。
            """
            return base64.urlsafe_b64encode(data).rstrip(b"=").decode()

        secrets = wordlist or self._common_secrets

        for secret in secrets:
            try:
                sig = hmac.new(secret.encode(), signing_input.encode(), hash_func).digest()
                if b64url_encode(sig) == expected_sig:
                    log.info(f"JWT密钥破解成功: {secret}")
                    return secret
            except:
                continue

        return None

    # ========== OAuth测试 ==========

    def analyze_oauth_redirect_uri(self, auth_url: str) -> Dict:
        """分析OAuth授权URL的redirect_uri安全性"""
        result = {
            "valid_oauth_url": False,
            "issues": [],
            "recommendations": [],
            "details": {},
        }

        try:
            parsed = urlparse(auth_url)
            params = parse_qs(parsed.query)

            result["details"]["auth_endpoint"] = f"{parsed.scheme}://{parsed.netloc}{parsed.path}"

            # 检查必要参数
            required_params = ["client_id", "redirect_uri", "response_type"]
            for param in required_params:
                if param not in params:
                    result["issues"].append({
                        "severity": "medium",
                        "description": f"OAuth授权URL缺少必要参数: {param}",
                    })

            if "redirect_uri" in params:
                redirect_uri = params["redirect_uri"][0]
                result["details"]["redirect_uri"] = redirect_uri
                result["valid_oauth_url"] = True

                # 检查redirect_uri安全性
                redirect_parsed = urlparse(redirect_uri)

                # 1. 检查是否使用HTTPS
                if redirect_parsed.scheme != "https":
                    result["issues"].append({
                        "severity": "high",
                        "description": f"redirect_uri使用非HTTPS协议: {redirect_parsed.scheme}",
                        "cwe": "CWE-319",
                    })
                    result["recommendations"].append("redirect_uri必须使用HTTPS")

                # 2. 检查是否为localhost
                if redirect_parsed.hostname in ["localhost", "127.0.0.1", "0.0.0.0"]:
                    result["issues"].append({
                        "severity": "medium",
                        "description": "redirect_uri指向本地地址（可能仅用于开发）",
                    })

                # 3. 检查open redirect风险
                if any(c in redirect_uri for c in ["@", "#", "//", "%0a", "%0d"]):
                    result["issues"].append({
                        "severity": "high",
                        "description": "redirect_uri包含可疑字符，可能存在开放重定向",
                        "cwe": "CWE-601",
                    })

                # 4. 检查state参数
                if "state" not in params:
                    result["issues"].append({
                        "severity": "high",
                        "description": "OAuth授权URL缺少state参数，可能存在CSRF攻击",
                        "cwe": "CWE-352",
                    })
                    result["recommendations"].append("添加state参数，使用随机不可预测的值")
                else:
                    state = params["state"][0]
                    if len(state) < 16:
                        result["issues"].append({
                            "severity": "medium",
                            "description": f"state参数过短（{len(state)}字符），可能被暴力破解",
                        })

                # 5. 检查response_type
                if "response_type" in params:
                    rt = params["response_type"][0]
                    if rt == "token":
                        result["issues"].append({
                            "severity": "medium",
                            "description": "使用implicit flow（response_type=token），不推荐",
                            "cwe": "CWE-319",
                        })
                        result["recommendations"].append("使用authorization code flow（response_type=code）+ PKCE")

                # 6. 检查scope
                if "scope" in params:
                    scope = params["scope"][0]
                    result["details"]["scope"] = scope
                    if any(s in scope.lower() for s in ["admin", "write", "delete", "full"]):
                        result["issues"].append({
                            "severity": "info",
                            "description": f"请求高权限scope: {scope}",
                        })

                # 7. 检查PKCE
                if "code_challenge" not in params and "response_type" in params and params["response_type"][0] == "code":
                    result["issues"].append({
                        "severity": "medium",
                        "description": "authorization code flow缺少PKCE（code_challenge）",
                        "cwe": "CWE-347",
                    })
                    result["recommendations"].append("添加PKCE保护，使用code_challenge和code_challenge_method")

        except Exception as e:
            result["issues"].append({"severity": "high", "description": f"OAuth URL解析失败: {e}"})

        # 风险评分
        critical_count = sum(1 for i in result["issues"] if i["severity"] == "critical")
        high_count = sum(1 for i in result["issues"] if i["severity"] == "high")
        medium_count = sum(1 for i in result["issues"] if i["severity"] == "medium")

        risk_score = min(100, critical_count * 25 + high_count * 15 + medium_count * 8)
        result["risk_score"] = risk_score
        result["risk_level"] = "critical" if risk_score >= 75 else "high" if risk_score >= 50 else "medium" if risk_score >= 25 else "low"

        return result

    def generate_oauth_redirect_bypass(self, valid_redirect: str, target_url: str) -> List[str]:
        """生成OAuth redirect_uri绕过测试payload"""
        bypass_payloads = [
            # 开放重定向绕过
            f"{valid_redirect}?next={target_url}",
            f"{valid_redirect}/../{target_url}",
            f"{valid_redirect}@{target_url}",
            f"{valid_redirect}%23{target_url}",
            f"{valid_redirect}%0a{target_url}",
            # 子域名绕过
            f"{valid_redirect}.{target_url}",
            f"{target_url}.{valid_redirect}",
            # 路径遍历
            f"{valid_redirect}/..%2f..%2f{target_url}",
            # 特殊字符
            f"{valid_redirect}\\{target_url}",
            f"{valid_redirect}//{target_url}",
        ]
        return bypass_payloads

    # ========== 会话管理测试 ==========

    def analyze_cookie_security(self, cookies: Dict[str, str], cookie_name: str = "session") -> Dict:
        """分析Cookie安全性"""
        result = {
            "cookie_found": False,
            "issues": [],
            "recommendations": [],
            "details": {},
        }

        # 查找会话Cookie
        session_cookie = None
        for name, value in cookies.items():
            if any(k in name.lower() for k in ["session", "sid", "auth", "token", "jwt"]):
                session_cookie = {"name": name, "value": value}
                break

        if not session_cookie and cookie_name in cookies:
            session_cookie = {"name": cookie_name, "value": cookies[cookie_name]}

        if not session_cookie:
            result["issues"].append({"severity": "medium", "description": "未找到会话Cookie"})
            return result

        result["cookie_found"] = True
        result["details"]["cookie_name"] = session_cookie["name"]
        result["details"]["cookie_value_length"] = len(session_cookie["value"])

        # 检查Cookie值强度
        cookie_value = session_cookie["value"]
        if len(cookie_value) < 16:
            result["issues"].append({
                "severity": "high",
                "description": f"会话ID过短（{len(cookie_value)}字符），可能被暴力破解",
                "cwe": "CWE-330",
            })
            result["recommendations"].append("使用至少128位（16字节）的随机会话ID")

        # 检查是否可预测
        if re.match(r'^\d+$', cookie_value):
            result["issues"].append({
                "severity": "high",
                "description": "会话ID仅包含数字，可能可预测",
                "cwe": "CWE-330",
            })

        if cookie_value.lower() in ["admin", "test", "123456", "session", "default"]:
            result["issues"].append({
                "severity": "critical",
                "description": "会话ID为常见弱值",
                "cwe": "CWE-798",
            })

        # 检查Cookie属性（需要Set-Cookie头信息，这里假设传入的是属性字典）
        if isinstance(cookies.get("_attributes"), dict):
            attrs = cookies["_attributes"]

            # HttpOnly
            if not attrs.get("httponly", False):
                result["issues"].append({
                    "severity": "high",
                    "description": "会话Cookie缺少HttpOnly属性，可能被XSS窃取",
                    "cwe": "CWE-1004",
                })
                result["recommendations"].append("添加HttpOnly属性，防止JavaScript访问Cookie")

            # Secure
            if not attrs.get("secure", False):
                result["issues"].append({
                    "severity": "high",
                    "description": "会话Cookie缺少Secure属性，可能通过HTTP传输",
                    "cwe": "CWE-319",
                })
                result["recommendations"].append("添加Secure属性，仅通过HTTPS传输Cookie")

            # SameSite
            samesite = attrs.get("samesite", "").lower()
            if not samesite:
                result["issues"].append({
                    "severity": "medium",
                    "description": "会话Cookie缺少SameSite属性，可能存在CSRF风险",
                    "cwe": "CWE-352",
                })
                result["recommendations"].append("添加SameSite=Lax或Strict属性")
            elif samesite == "none":
                result["issues"].append({
                    "severity": "medium",
                    "description": "SameSite=None允许跨站发送，增加CSRF风险",
                })

            # Path
            path = attrs.get("path", "/")
            if path == "/":
                result["issues"].append({
                    "severity": "info",
                    "description": "Cookie路径为根路径，应用范围内所有页面都可访问",
                })

            # Domain
            domain = attrs.get("domain", "")
            if domain and domain.startswith("."):
                result["issues"].append({
                    "severity": "medium",
                    "description": f"Cookie域名为通配符形式: {domain}，所有子域名都可访问",
                })

            # Expires/Max-Age
            if attrs.get("max_age"):
                max_age = int(attrs["max_age"])
                if max_age > 86400 * 7:
                    result["issues"].append({
                        "severity": "medium",
                        "description": f"Cookie有效期过长（{max_age/86400:.1f}天）",
                    })

        # 风险评分
        critical_count = sum(1 for i in result["issues"] if i["severity"] == "critical")
        high_count = sum(1 for i in result["issues"] if i["severity"] == "high")
        medium_count = sum(1 for i in result["issues"] if i["severity"] == "medium")

        risk_score = min(100, critical_count * 25 + high_count * 15 + medium_count * 8)
        result["risk_score"] = risk_score
        result["risk_level"] = "critical" if risk_score >= 75 else "high" if risk_score >= 50 else "medium" if risk_score >= 25 else "low"

        return result

    def generate_session_fixation_payloads(self) -> List[str]:
        """生成会话固定测试payload"""
        return [
            "sessionid=attacker_controlled_session_id",
            "JSESSIONID=AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
            "PHPSESSID=test",
            "session=1",
            "auth_token=admin",
        ]

    # ========== 权限绕过测试 ==========

    def generate_idor_payloads(self, param_name: str, current_value: str) -> List[Dict]:
        """生成IDOR（不安全直接对象引用）测试payload"""
        payloads = []

        # 数值型ID
        if current_value.isdigit():
            current_id = int(current_value)
            for delta in [-1, 1, -10, 10, 0, 99999, -1]:
                new_id = current_id + delta
                if new_id >= 0:
                    payloads.append({
                        "param": param_name,
                        "value": str(new_id),
                        "type": "numeric_increment",
                        "description": f"数值ID从{current_value}改为{new_id}",
                    })

        # 常见ID值
        common_ids = ["1", "0", "admin", "root", "test", "guest", "current", "me", "self", "..", "../"]
        for cid in common_ids:
            if cid != current_value:
                payloads.append({
                    "param": param_name,
                    "value": cid,
                    "type": "common_value",
                    "description": f"替换为常见值: {cid}",
                })

        # 类型混淆
        payloads.extend([
            {"param": param_name, "value": f"{current_value} ", "type": "whitespace", "description": "添加空格"},
            {"param": param_name, "value": f"{current_value}%00", "type": "null_byte", "description": "空字节截断"},
            {"param": param_name, "value": f"[{current_value}]", "type": "array", "description": "数组形式"},
            {"param": param_name, "value": f'"{current_value}"', "type": "quoted", "description": "引号包裹"},
        ])

        return payloads

    def generate_privilege_escalation_headers(self) -> List[Dict]:
        """生成权限提升测试HTTP头"""
        return [
            {"header": "X-Original-URL", "value": "/admin", "description": "URL重写头"},
            {"header": "X-Rewrite-URL", "value": "/admin", "description": "URL重写头"},
            {"header": "X-Forwarded-For", "value": "127.0.0.1", "description": "伪造来源IP"},
            {"header": "X-Forwarded-Host", "value": "localhost", "description": "伪造主机头"},
            {"header": "X-Custom-IP-Authorization", "value": "127.0.0.1", "description": "自定义IP授权头"},
            {"header": "X-Admin", "value": "true", "description": "自定义管理员头"},
            {"header": "X-Role", "value": "admin", "description": "自定义角色头"},
            {"header": "X-User-Role", "value": "administrator", "description": "自定义用户角色头"},
        ]

    def generate_method_abuse_tests(self, url: str) -> List[Dict]:
        """生成HTTP方法滥用测试"""
        return [
            {"method": "GET", "url": url, "description": "GET方法访问受限资源"},
            {"method": "POST", "url": url, "description": "POST方法访问受限资源"},
            {"method": "PUT", "url": url, "description": "PUT方法访问受限资源"},
            {"method": "DELETE", "url": url, "description": "DELETE方法访问受限资源"},
            {"method": "PATCH", "url": url, "description": "PATCH方法访问受限资源"},
            {"method": "HEAD", "url": url, "description": "HEAD方法访问受限资源"},
            {"method": "OPTIONS", "url": url, "description": "OPTIONS方法查看允许的方法"},
            {"method": "TRACE", "url": url, "description": "TRACE方法测试（可能XST）"},
            {"method": "CONNECT", "url": url, "description": "CONNECT方法测试"},
        ]

    # ========== 综合测试 ==========

    async def comprehensive_auth_test(self, target_url: str, auth_token: Optional[str] = None) -> Dict:
        """综合认证测试（需要aiohttp）"""
        result = {
            "target": target_url,
            "jwt_analysis": None,
            "cookie_analysis": None,
            "method_abuse": [],
            "header_bypass": [],
            "issues": [],
            "summary": "",
        }

        try:
            import aiohttp

            headers = {}
            if auth_token:
                headers["Authorization"] = f"Bearer {auth_token}"

            # 1. JWT分析
            if auth_token and "." in auth_token and auth_token.count(".") == 2:
                result["jwt_analysis"] = self.analyze_jwt(auth_token)
                if result["jwt_analysis"]["issues"]:
                    result["issues"].extend(result["jwt_analysis"]["issues"])

            # 2. HTTP方法滥用测试
            async with aiohttp.ClientSession(headers=headers) as session:
                for test in self.generate_method_abuse_tests(target_url):
                    try:
                        async with session.request(test["method"], test["url"], timeout=10, allow_redirects=False) as resp:
                            status = resp.status
                            test_result = {**test, "status_code": status, "accessible": status < 400}
                            result["method_abuse"].append(test_result)
                            if status < 400 and test["method"] not in ["GET", "HEAD", "OPTIONS"]:
                                result["issues"].append({
                                    "severity": "high",
                                    "description": f"{test['method']}方法可访问受限资源（状态码: {status}）",
                                    "cwe": "CWE-650",
                                })
                    except Exception as e:
                        result["method_abuse"].append({**test, "error": str(e)})

            # 3. Header绕过测试
            async with aiohttp.ClientSession() as session:
                for test in self.generate_privilege_escalation_headers():
                    try:
                        test_headers = {test["header"]: test["value"]}
                        async with session.get(target_url, headers=test_headers, timeout=10, allow_redirects=False) as resp:
                            status = resp.status
                            test_result = {**test, "status_code": status, "bypassed": status < 400}
                            result["header_bypass"].append(test_result)
                            if status < 400:
                                result["issues"].append({
                                    "severity": "high",
                                    "description": f"通过{test['header']}头绕过访问控制（状态码: {status}）",
                                    "cwe": "CWE-639",
                                })
                    except Exception as e:
                        result["header_bypass"].append({**test, "error": str(e)})

            # 汇总
            high_count = sum(1 for i in result["issues"] if i["severity"] in ["high", "critical"])
            result["summary"] = f"综合认证测试完成，发现{len(result['issues'])}个问题（{high_count}个高危）"

        except ImportError:
            result["summary"] = "aiohttp未安装，无法执行综合测试"
        except Exception as e:
            result["summary"] = f"综合测试失败: {e}"

        return result


# 全局单例
auth_tester = AuthTester()
