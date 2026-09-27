# -*- coding: utf-8 -*-
"""
scenarios.py - 预定义测试场景库

提供 6 个经典漏洞检测场景。execute_scenario 只做检测性请求，不做实际利用，
全部使用 urllib 并带超时与错误处理。

重要：仅限授权环境使用。
"""

from __future__ import annotations

import logging
from typing import Any, Dict, List, Optional
from urllib.error import URLError
from urllib.parse import quote
from urllib.request import Request, urlopen

logger = logging.getLogger(__name__)

AUTHORIZATION_NOTICE = "仅限授权环境使用：仅检测不利用。"


# ======================================================================
# 6 个预定义测试场景
# ======================================================================
SCENARIOS: Dict[str, Dict[str, Any]] = {
    "sqli_detection": {
        "scenario_id": "sqli_detection",
        "name": "SQL 注入测试",
        "description": "对 DVWA 的 SQL 注入点发送单引号与 UNION 探测，观察数据库错误信息以判断是否存在注入。",
        "target_lab": "dvwa",
        "target_url": "/vulnerabilities/sqli/",
        "steps": [
            "在 id 参数处输入单引号 ' 触发数据库错误",
            "观察响应是否包含 SQL 错误信息",
            "输入 UNION SELECT 探测列数并判断额外数据是否被回显",
        ],
        "expected_result": "检测到 SQL 注入",
        "verification_method": "响应中包含 SQL 错误信息（MySQL syntax / You have an error）或 UNION 查询回显了额外数据。",
        "risk_level": "中",
        "probe": {"path": "/vulnerabilities/sqli/", "param": "id", "payload": "'"},
    },
    "xss_reflected": {
        "scenario_id": "xss_reflected",
        "name": "反射型 XSS 测试",
        "description": "在 DVWA/Juice Shop 的反射点输入简单脚本标签，检查响应是否原样返回未转义内容。",
        "target_lab": "dvwa",
        "target_url": "/vulnerabilities/xss_r/",
        "steps": [
            "在输入框注入 <script>alert(1)</script>",
            "观察页面源码中标签是否未被转义",
            "确认 payload 是否出现在响应 HTML 中",
        ],
        "expected_result": "检测到反射型 XSS",
        "verification_method": "响应 HTML 中包含未转义的 <script> 标签或 alert 关键字。",
        "risk_level": "中",
        "probe": {"path": "/vulnerabilities/xss_r/", "param": "name", "payload": "<script>alert(1)</script>"},
    },
    "cmd_injection": {
        "scenario_id": "cmd_injection",
        "name": "命令注入测试",
        "description": "在 DVWA Ping 功能输入分号拼接命令，观察是否返回系统命令执行结果。",
        "target_lab": "dvwa",
        "target_url": "/vulnerabilities/exec/",
        "steps": [
            "输入 127.0.0.1; id（用分号拼接系统命令）",
            "观察响应是否包含 UID/GID 等系统信息",
        ],
        "expected_result": "检测到命令注入",
        "verification_method": "响应中包含 id 命令的输出（如 uid= 字样）或 shell 错误。",
        "risk_level": "高",
        "probe": {"path": "/vulnerabilities/exec/", "param": "ip", "payload": "127.0.0.1; id"},
    },
    "file_upload": {
        "scenario_id": "file_upload",
        "name": "不安全文件上传测试",
        "description": "向 DVWA 文件上传点尝试上传文件，检测服务端是否缺乏类型/内容校验。",
        "target_lab": "dvwa",
        "target_url": "/vulnerabilities/upload/",
        "steps": [
            "构造一个 .php 文本文件内容（仅检测上传点可达性）",
            "提交上传请求，观察是否返回成功提示",
            "不访问/执行上传后的文件",
        ],
        "expected_result": "检测到不安全文件上传",
        "verification_method": "上传端点返回成功状态码且响应提示上传成功（仅检测，不利用）。",
        "risk_level": "高",
        "probe": {"path": "/vulnerabilities/upload/", "param": "uploaded", "payload": "probe.php"},
    },
    "auth_bypass": {
        "scenario_id": "auth_bypass",
        "name": "认证绕过测试",
        "description": "在 DVWA 登录表单尝试经典 SQL 注入凭据，检测是否可绕过认证。",
        "target_lab": "dvwa",
        "target_url": "/login.php",
        "steps": [
            "用户名输入 admin' OR '1'='1' -- ，密码任意",
            "提交登录请求，观察响应是否跳转/设置会话",
        ],
        "expected_result": "检测到认证绕过",
        "verification_method": "登录请求成功（302 跳转或无密码错误提示），表明存在 SQL 注入认证绕过。",
        "risk_level": "高",
        "probe": {"path": "/login.php", "param": "username", "payload": "admin' OR '1'='1' -- "},
    },
    "privesc_bola": {
        "scenario_id": "privesc_bola",
        "name": "越权访问（BOLA）测试",
        "description": "以低权限身份访问 Juice Shop 的管理端 REST 端点，检查是否存在失效的访问控制。",
        "target_lab": "juice-shop",
        "target_url": "/rest/admin/",
        "steps": [
            "以普通用户身份请求 /rest/admin/ 管理端点",
            "观察响应是否返回管理数据（而非 401/403）",
        ],
        "expected_result": "检测到越权访问",
        "verification_method": "管理端点返回 200 且包含数据字段，而不是 401/403。",
        "risk_level": "中",
        "probe": {"path": "/rest/admin/", "param": None, "payload": ""},
    },
}


class ScenarioLibrary:
    """测试场景库：列出、查询、模拟执行。"""

    def list_scenarios(self) -> List[Dict[str, Any]]:
        try:
            out = []
            for s in SCENARIOS.values():
                out.append({
                    "scenario_id": s["scenario_id"],
                    "name": s["name"],
                    "description": s["description"],
                    "target_lab": s["target_lab"],
                    "target_url": s["target_url"],
                    "risk_level": s["risk_level"],
                })
            return out
        except Exception as e:  # noqa: BLE001
            logger.exception("list_scenarios error")
            return []

    def get_scenario(self, scenario_id: str) -> Optional[Dict[str, Any]]:
        try:
            return SCENARIOS.get(scenario_id)
        except Exception as e:  # noqa: BLE001
            logger.exception("get_scenario error")
            return None

    # ------------------------------------------------------------------
    def execute_scenario(self, scenario_id: str, lab_url: str) -> Dict[str, Any]:
        """
        模拟执行场景：只发送检测性 HTTP 请求，不做利用。
        使用 urllib，带 5 秒超时。
        """
        try:
            sc = SCENARIOS.get(scenario_id)
            if not sc:
                return {"success": False, "error": f"未知场景：{scenario_id}"}
            if not lab_url:
                return {"success": False, "error": "缺少目标靶场 URL"}

            probe = sc.get("probe", {})
            path = probe.get("path", sc["target_url"])
            param = probe.get("param")
            payload = probe.get("payload", "")
            base = lab_url.rstrip("/")
            url = base + path
            if param:
                url = f"{url}?{param}={quote(payload)}"

            evidence: Dict[str, Any] = {"requested_url": url, "detected": False}
            notes: List[str] = []

            try:
                req = Request(url, headers={"User-Agent": "target-labs-probe/8.0 (detection-only)"})
                with urlopen(req, timeout=5) as resp:  # nosec - 仅本地授权靶场，检测性请求
                    code = resp.getcode()
                    body = resp.read(4096).decode("utf-8", errors="ignore")
                evidence["status_code"] = code
                notes.append(f"HTTP {code}")

                # 按场景做特征检测（仅判断，不利用）
                low = body.lower()
                if scenario_id == "sqli_detection" and (
                    "you have an error in your sql syntax" in low or "mysql" in low and "error" in low
                ):
                    evidence["detected"] = True
                    evidence["evidence"] = "响应包含数据库错误信息"
                elif scenario_id == "xss_reflected" and "<script>alert" in low:
                    evidence["detected"] = True
                    evidence["evidence"] = "响应包含未转义的 script 标签"
                elif scenario_id == "cmd_injection" and ("uid=" in body or "gid=" in body):
                    evidence["detected"] = True
                    evidence["evidence"] = "响应包含系统命令输出特征"
                elif scenario_id == "file_upload" and code in (200, 302):
                    evidence["detected"] = True
                    evidence["evidence"] = "上传端点可达且接受请求"
                elif scenario_id == "auth_bypass" and code in (200, 302):
                    evidence["detected"] = True
                    evidence["evidence"] = "认证请求未返回拒绝"
                elif scenario_id == "privesc_bola" and code == 200:
                    evidence["detected"] = True
                    evidence["evidence"] = "管理端点返回 200，存在越权风险"
            except URLError as e:
                notes.append(f"请求失败：{e}")
                evidence["error"] = str(e)
            except Exception as re:  # noqa: BLE001
                notes.append(f"请求异常：{re}")
                evidence["error"] = str(re)

            result = "detected" if evidence.get("detected") else (
                "not_detected" if "status_code" in evidence else "error"
            )
            return {
                "success": True,
                "scenario_id": scenario_id,
                "name": sc["name"],
                "result": result,
                "expected": sc["expected_result"],
                "evidence": evidence,
                "notes": notes,
                "notice": AUTHORIZATION_NOTICE,
            }
        except Exception as e:  # noqa: BLE001
            logger.exception("execute_scenario error")
            return {"success": False, "error": str(e)}
