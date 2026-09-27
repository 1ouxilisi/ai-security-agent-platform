#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
logic_tester.py — API 业务逻辑漏洞测试器（仅检测，不利用）。

测试类型：
    1. horizontal_privilege_esc  水平越权
    2. vertical_privilege_esc    垂直越权
    3. auth_bypass                认证绕过
    4. session_fixation          会话固定
    5. csrf                       CSRF
    6. idor                       不安全直接对象引用
    7. mass_assignment            批量赋值
    8. race_condition            竞争条件
    9. business_logic_bypass      业务逻辑绕过

设计定位：
    - 仅做检测与响应特征观察，不利用漏洞、不破坏目标数据。
    - 内置速率控制与超时。
    - 本模块仅用于授权的安全评估与合规检查。
"""

from __future__ import annotations

import time
import urllib.parse
import urllib.request
import urllib.error
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import Any, Dict, List, Optional


# 每种测试类型对应的修复建议
REMEDIATION_ADVICE: Dict[str, str] = {
    "horizontal_privilege_esc": "在服务端实施对象级授权（Object-Level Authorization），校验当前用户对目标资源的所有权",
    "vertical_privilege_esc": "实施基于角色的访问控制（RBAC），在服务端强制校验用户角色/权限，不要依赖前端隐藏按钮",
    "auth_bypass": "服务端强制验证 token 有效性/过期时间/签名，所有敏感端点必须经过认证中间件",
    "session_fixation": "登录成功后重新生成 session ID，设置 HttpOnly/Secure/SameSite Cookie 属性",
    "csrf": "对状态变更接口引入 CSRF Token 或校验 Origin/Referer，Cookie 设置 SameSite=Lax/Strict",
    "idor": "使用不可预测的资源标识符（UUID/加密 ID），并在每次访问时校验资源归属",
    "mass_assignment": "使用 DTO/白名单字段，禁止客户端直接传入 role/is_admin 等敏感字段",
    "race_condition": "使用数据库唯一约束/乐观锁/分布式锁，对关键操作做幂等处理",
    "business_logic_bypass": "服务端校验业务流程状态机，禁止跳过中间步骤直接访问最终步骤",
}


class LogicTester:
    """逻辑漏洞测试器。"""

    def __init__(self) -> None:
        self.test_types: List[str] = [
            "horizontal_privilege_esc",
            "vertical_privilege_esc",
            "auth_bypass",
            "session_fixation",
            "csrf",
            "idor",
            "mass_assignment",
            "race_condition",
            "business_logic_bypass",
        ]
        self.remediation: Dict[str, str] = dict(REMEDIATION_ADVICE)

    # ------------------------------------------------------------------ #
    # 元信息
    # ------------------------------------------------------------------ #
    def get_test_types(self) -> List[str]:
        """返回支持的测试类型列表。"""
        try:
            return list(self.test_types)
        except Exception:
            return []

    # ------------------------------------------------------------------ #
    # HTTP 工具
    # ------------------------------------------------------------------ #
    def _send(self, base_url: str, method: str, path: str,
             params: Optional[Dict[str, Any]] = None,
             headers: Optional[Dict[str, str]] = None,
             timeout: float = 10.0) -> Dict[str, Any]:
        start = time.time()
        resp: Dict[str, Any] = {"status_code": 0, "response_time": 0.0,
                                "body": "", "headers": {}, "error": None}
        try:
            url = base_url.rstrip("/") + path
            method = (method or "GET").upper()
            params = params or {}
            headers = dict(headers or {})
            data = None
            if method == "GET":
                qs = urllib.parse.urlencode(params)
                if qs:
                    url = f"{url}?{qs}"
            else:
                data = urllib.parse.urlencode(params).encode("utf-8")
                headers.setdefault("Content-Type", "application/x-www-form-urlencoded")
            req = urllib.request.Request(url, data=data, method=method, headers=headers)
            with urllib.request.urlopen(req, timeout=timeout) as r:
                body = r.read().decode("utf-8", errors="replace")
                resp["status_code"] = r.getcode()
                resp["body"] = body
                resp["headers"] = dict(r.headers)
        except urllib.error.HTTPError as e:
            resp["status_code"] = e.code
            try:
                resp["body"] = e.read().decode("utf-8", errors="replace")
            except Exception:
                resp["body"] = ""
            resp["headers"] = dict(e.headers or {})
        except Exception as e:
            resp["error"] = str(e)
        finally:
            resp["response_time"] = round(time.time() - start, 3)
        return resp

    @staticmethod
    def _auth_headers(token: str) -> Dict[str, str]:
        h: Dict[str, str] = {"User-Agent": "APILogicTester/1.0"}
        if token:
            h["Authorization"] = f"Bearer {token}"
        return h

    # ------------------------------------------------------------------ #
    # 结果评估
    # ------------------------------------------------------------------ #
    def evaluate_result(self, test_type: str, response: Dict[str, Any],
                        expected: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
        """评估测试结果。"""
        expected = expected or {}
        out: Dict[str, Any] = {
            "detected": False, "risk_level": "info", "evidence": "",
            "description": "", "remediation": self.remediation.get(test_type, ""),
        }
        try:
            status = response.get("status_code", 0)
            body = (response.get("body") or "")

            # 默认：200 且非 401/403 视为潜在越权
            expected_block = expected.get("expected_block_status", [401, 403])
            if status not in expected_block and 200 <= status < 300:
                out["detected"] = True
                out["evidence"] = f"请求成功返回 {status}，未被授权拒绝"
                out["risk_level"] = {
                    "horizontal_privilege_esc": "high",
                    "vertical_privilege_esc": "critical",
                    "auth_bypass": "critical",
                    "idor": "high",
                    "mass_assignment": "high",
                    "business_logic_bypass": "high",
                    "race_condition": "high",
                    "csrf": "medium",
                    "session_fixation": "medium",
                }.get(test_type, "medium")
            elif status in (401, 403):
                out["evidence"] = f"服务端正确拒绝（{status}）"
            else:
                out["evidence"] = f"状态码 {status}，未能确认漏洞"

            out["description"] = f"逻辑测试 {test_type} 结果"
        except Exception as e:
            out["evidence"] = f"evaluate异常: {e}"
        return out

    # ------------------------------------------------------------------ #
    # 各测试方法
    # ------------------------------------------------------------------ #
    def test_horizontal_privilege(self, endpoint: Dict[str, Any],
                                 user_a_token: str,
                                 user_b_resource_id: str,
                                 options: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
        """水平越权：用 A 的 token 访问 B 的资源。"""
        options = options or {}
        try:
            base_url = options.get("base_url", "")
            path = endpoint.get("path", "")
            method = endpoint.get("method", "GET")
            # 替换路径中的 {id} 为 user_b_resource_id
            path = path.replace("{id}", str(user_b_resource_id))
            if "{" in path:
                # 尝试替换任意 {xxx}
                import re
                path = re.sub(r"\{[^}]+\}", str(user_b_resource_id), path)
            headers = self._auth_headers(user_a_token)
            resp = self._send(base_url, method, path, headers=headers,
                              timeout=options.get("timeout", 10))
            ev = self.evaluate_result("horizontal_privilege_esc", resp)
            return {
                "test_type": "horizontal_privilege_esc",
                "endpoint": path, "method": method,
                "parameter": "resource_id",
                "request_summary": f"{method} {path} (token=userA, resource=userB)",
                "response_status": resp.get("status_code"),
                "detected": ev["detected"], "risk_level": ev["risk_level"],
                "evidence": ev["evidence"], "remediation": ev["remediation"],
            }
        except Exception as e:
            return {"test_type": "horizontal_privilege_esc", "error": str(e),
                    "detected": False, "risk_level": "info"}

    def test_vertical_privilege(self, endpoint: Dict[str, Any],
                               low_perm_token: str,
                               options: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
        """垂直越权：低权限 token 访问管理端点。"""
        options = options or {}
        try:
            base_url = options.get("base_url", "")
            path = endpoint.get("path", "")
            method = endpoint.get("method", "GET")
            headers = self._auth_headers(low_perm_token)
            resp = self._send(base_url, method, path, headers=headers,
                              timeout=options.get("timeout", 10))
            ev = self.evaluate_result("vertical_privilege_esc", resp)
            return {
                "test_type": "vertical_privilege_esc",
                "endpoint": path, "method": method, "parameter": "role",
                "request_summary": f"{method} {path} (low-perm token)",
                "response_status": resp.get("status_code"),
                "detected": ev["detected"], "risk_level": ev["risk_level"],
                "evidence": ev["evidence"], "remediation": ev["remediation"],
            }
        except Exception as e:
            return {"test_type": "vertical_privilege_esc", "error": str(e),
                    "detected": False, "risk_level": "info"}

    def test_auth_bypass(self, endpoint: Dict[str, Any], valid_token: str,
                        options: Optional[Dict[str, Any]] = None) -> List[Dict[str, Any]]:
        """认证绕过：移除 token / 无效 token / 过期 token 三种场景。"""
        options = options or {}
        results: List[Dict[str, Any]] = []
        base_url = options.get("base_url", "")
        path = endpoint.get("path", "")
        method = endpoint.get("method", "GET")
        scenarios = [
            ("no_token", {}),
            ("invalid_token", {"Authorization": "Bearer invalid-token-12345"}),
            ("expired_token", {"Authorization": "Bearer eyJhbGciOiJIUzI1NiJ9.expired.sig"}),
        ]
        for sname, extra_headers in scenarios:
            try:
                headers = {"User-Agent": "APILogicTester/1.0"}
                headers.update(extra_headers)
                resp = self._send(base_url, method, path, headers=headers,
                                  timeout=options.get("timeout", 10))
                ev = self.evaluate_result("auth_bypass", resp)
                results.append({
                    "test_type": "auth_bypass", "scenario": sname,
                    "endpoint": path, "method": method, "parameter": "Authorization",
                    "request_summary": f"{method} {path} ({sname})",
                    "response_status": resp.get("status_code"),
                    "detected": ev["detected"], "risk_level": ev["risk_level"],
                    "evidence": ev["evidence"], "remediation": ev["remediation"],
                })
            except Exception as e:
                results.append({"test_type": "auth_bypass", "scenario": sname,
                                "error": str(e), "detected": False, "risk_level": "info"})
            time.sleep(float(options.get("request_interval", 0.3)))
        return results

    def test_idor(self, endpoint: Dict[str, Any], param_name: str,
                 valid_token: str,
                 options: Optional[Dict[str, Any]] = None) -> List[Dict[str, Any]]:
        """IDOR：遍历 ID 范围检查是否能访问其他用户数据。"""
        options = options or {}
        results: List[Dict[str, Any]] = []
        base_url = options.get("base_url", "")
        path = endpoint.get("path", "")
        method = endpoint.get("method", "GET")
        start_id = int(options.get("idor_start", 1))
        end_id = int(options.get("idor_end", 5))
        headers = self._auth_headers(valid_token)
        for rid in range(start_id, end_id + 1):
            try:
                import re
                test_path = re.sub(r"\{[^}]+\}", str(rid), path)
                if test_path == path and "?" not in test_path:
                    # 作为查询参数
                    resp = self._send(base_url, method, test_path,
                                      params={param_name: rid}, headers=headers,
                                      timeout=options.get("timeout", 10))
                else:
                    resp = self._send(base_url, method, test_path, headers=headers,
                                      timeout=options.get("timeout", 10))
                ev = self.evaluate_result("idor", resp)
                results.append({
                    "test_type": "idor",
                    "endpoint": test_path, "method": method, "parameter": param_name,
                    "request_summary": f"{method} {test_path} (id={rid})",
                    "response_status": resp.get("status_code"),
                    "detected": ev["detected"], "risk_level": ev["risk_level"],
                    "evidence": ev["evidence"], "remediation": ev["remediation"],
                })
            except Exception as e:
                results.append({"test_type": "idor", "id": rid, "error": str(e),
                                "detected": False, "risk_level": "info"})
            time.sleep(float(options.get("request_interval", 0.3)))
        return results

    def test_mass_assignment(self, endpoint: Dict[str, Any], valid_token: str,
                            extra_fields: Optional[Dict[str, Any]] = None,
                            options: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
        """批量赋值：一次请求提交额外字段（role=admin/is_admin=true）。"""
        options = options or {}
        extra_fields = extra_fields or {"role": "admin", "is_admin": True}
        try:
            base_url = options.get("base_url", "")
            path = endpoint.get("path", "")
            method = endpoint.get("method", "POST")
            headers = self._auth_headers(valid_token)
            resp = self._send(base_url, method, path, params=extra_fields,
                              headers=headers, timeout=options.get("timeout", 10))
            ev = self.evaluate_result("mass_assignment", resp)
            return {
                "test_type": "mass_assignment",
                "endpoint": path, "method": method, "parameter": ",".join(extra_fields.keys()),
                "request_summary": f"{method} {path} (extra={extra_fields})",
                "response_status": resp.get("status_code"),
                "detected": ev["detected"], "risk_level": ev["risk_level"],
                "evidence": ev["evidence"], "remediation": ev["remediation"],
            }
        except Exception as e:
            return {"test_type": "mass_assignment", "error": str(e),
                    "detected": False, "risk_level": "info"}

    def test_csrf(self, endpoint: Dict[str, Any],
                 options: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
        """CSRF 检测：检查请求头和 cookie。"""
        options = options or {}
        try:
            base_url = options.get("base_url", "")
            path = endpoint.get("path", "")
            method = endpoint.get("method", "POST")
            # 不带任何自定义 header，模拟跨站表单提交
            resp = self._send(base_url, method, path,
                              params={"csrf_test": "1"},
                              headers={"User-Agent": "Mozilla/5.0"},
                              timeout=options.get("timeout", 10))
            set_cookie = (resp.get("headers") or {}).get("Set-Cookie", "")
            same_site = "samesite" in set_cookie.lower()
            has_csrf_token = False
            detected = (resp.get("status_code", 0) in (200, 201, 204)) and not same_site
            return {
                "test_type": "csrf", "endpoint": path, "method": method,
                "parameter": "Cookie",
                "request_summary": f"{method} {path} (无 CSRF Token, 无 SameSite)",
                "response_status": resp.get("status_code"),
                "detected": detected,
                "risk_level": "medium" if detected else "info",
                "evidence": f"SameSite={'有' if same_site else '无'}; CSRF Token={'有' if has_csrf_token else '无'}",
                "remediation": self.remediation.get("csrf", ""),
            }
        except Exception as e:
            return {"test_type": "csrf", "error": str(e),
                    "detected": False, "risk_level": "info"}

    def test_session_fixation(self, login_endpoint: Dict[str, Any],
                             options: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
        """会话固定：检查登录前后 session ID 是否变化。"""
        options = options or {}
        try:
            base_url = options.get("base_url", "")
            path = login_endpoint.get("path", "")
            method = login_endpoint.get("method", "POST")
            # 登录前
            before = self._send(base_url, "GET", "/", timeout=options.get("timeout", 10))
            before_cookie = (before.get("headers") or {}).get("Set-Cookie", "")
            # 登录
            self._send(base_url, method, path,
                       params=options.get("credentials", {"username": "test", "password": "test"}),
                       timeout=options.get("timeout", 10))
            after = self._send(base_url, "GET", "/", timeout=options.get("timeout", 10))
            after_cookie = (after.get("headers") or {}).get("Set-Cookie", "")
            changed = before_cookie != after_cookie
            return {
                "test_type": "session_fixation", "endpoint": path, "method": method,
                "parameter": "Cookie",
                "request_summary": f"登录前 Cookie={before_cookie[:40]}... 登录后={after_cookie[:40]}...",
                "response_status": after.get("status_code"),
                "detected": not changed and bool(before_cookie),
                "risk_level": "medium" if (not changed and before_cookie) else "info",
                "evidence": "登录前后 session 未变化（可能存在会话固定）" if not changed else "登录后 session 已刷新",
                "remediation": self.remediation.get("session_fixation", ""),
            }
        except Exception as e:
            return {"test_type": "session_fixation", "error": str(e),
                    "detected": False, "risk_level": "info"}

    def test_race_condition(self, endpoint: Dict[str, Any], valid_token: str,
                           options: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
        """竞争条件：并发发送同一请求，检查是否重复处理。"""
        options = options or {}
        concurrency = int(options.get("race_concurrency", 5))
        try:
            base_url = options.get("base_url", "")
            path = endpoint.get("path", "")
            method = endpoint.get("method", "POST")
            headers = self._auth_headers(valid_token)

            def _one():
                return self._send(base_url, method, path,
                                  params=options.get("race_params", {"action": "redeem"}),
                                  headers=headers,
                                  timeout=options.get("timeout", 10))
            statuses: List[int] = []
            with ThreadPoolExecutor(max_workers=min(concurrency, 8)) as ex:
                futures = [ex.submit(_one) for _ in range(concurrency)]
                for f in as_completed(futures):
                    try:
                        statuses.append(f.result().get("status_code", 0))
                    except Exception:
                        statuses.append(0)
            success = sum(1 for s in statuses if 200 <= s < 300)
            return {
                "test_type": "race_condition", "endpoint": path, "method": method,
                "parameter": "idempotency_key",
                "request_summary": f"并发 {concurrency} 次 {method} {path}",
                "response_status": statuses,
                "detected": success > 1,
                "risk_level": "high" if success > 1 else "info",
                "evidence": f"{concurrency} 个并发请求中 {success} 个成功（疑似重复处理）",
                "remediation": self.remediation.get("race_condition", ""),
            }
        except Exception as e:
            return {"test_type": "race_condition", "error": str(e),
                    "detected": False, "risk_level": "info"}

    def test_business_logic_bypass(self, final_endpoint: Dict[str, Any],
                                  valid_token: str,
                                  options: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
        """业务逻辑绕过：跳过中间步骤直接访问最终步骤。"""
        options = options or {}
        try:
            base_url = options.get("base_url", "")
            path = final_endpoint.get("path", "")
            method = final_endpoint.get("method", "POST")
            headers = self._auth_headers(valid_token)
            resp = self._send(base_url, method, path,
                              params=options.get("bypass_params", {"confirm": "1"}),
                              headers=headers,
                              timeout=options.get("timeout", 10))
            ev = self.evaluate_result("business_logic_bypass", resp)
            return {
                "test_type": "business_logic_bypass",
                "endpoint": path, "method": method, "parameter": "state",
                "request_summary": f"跳过中间步骤直接 {method} {path}",
                "response_status": resp.get("status_code"),
                "detected": ev["detected"], "risk_level": ev["risk_level"],
                "evidence": ev["evidence"], "remediation": ev["remediation"],
            }
        except Exception as e:
            return {"test_type": "business_logic_bypass", "error": str(e),
                    "detected": False, "risk_level": "info"}

    # ------------------------------------------------------------------ #
    # 汇总运行
    # ------------------------------------------------------------------ #
    def run_all_tests(self, endpoint: Dict[str, Any],
                     tokens: Optional[Dict[str, str]] = None,
                     options: Optional[Dict[str, Any]] = None) -> List[Dict[str, Any]]:
        """运行所有适用的逻辑测试。"""
        options = options or {}
        tokens = tokens or {}
        results: List[Dict[str, Any]] = []
        try:
            results.append(self.test_auth_bypass(
                endpoint, tokens.get("valid", ""), options))
            results.append(self.test_csrf(endpoint, options))
            # 仅当路径含 id/me 时做 IDOR / 水平越权
            path = (endpoint.get("path") or "").lower()
            if "{id}" in path or "/me" in path or "user" in path:
                results.append(self.test_idor(
                    endpoint, options.get("idor_param", "id"),
                    tokens.get("valid", ""), options))
            if "admin" in path:
                results.append(self.test_vertical_privilege(
                    endpoint, tokens.get("low_perm", ""), options))
            if endpoint.get("method", "POST") == "POST":
                results.append(self.test_mass_assignment(
                    endpoint, tokens.get("valid", ""),
                    options.get("extra_fields"), options))
        except Exception as e:
            results.append({"test_type": "_exception", "error": str(e),
                            "detected": False, "risk_level": "info"})
        # 展平嵌套 list
        flat: List[Dict[str, Any]] = []
        for r in results:
            if isinstance(r, list):
                flat.extend(r)
            else:
                flat.append(r)
        return flat


__all__ = ["LogicTester", "REMEDIATION_ADVICE"]
