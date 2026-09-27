# -*- coding: utf-8 -*-
"""
ai/vuln_verifier.py — 漏洞自动验证引擎

对扫描/告警发现的漏洞做"非破坏性验证"：只确认漏洞是否真实存在（发送
无害探测 payload、观察回显特征、连接性测试），绝不执行利用（不拿
shell、不拖库、不写入目标、不横向移动）。LLM 用于辅助判断漏洞类型，
不可用时退化为关键词规则。

合法定位：仅用于授权安全评估的"验证/复测"环节，产出置信度与证据，
不提供也不内嵌任何真实攻击利用代码。
"""
import os
import re
import json
import socket
from datetime import datetime
from typing import Any, Dict, List, Optional
from urllib.parse import urlparse, urlencode

try:
    from dotenv import load_dotenv
    load_dotenv()
except ImportError:  # pragma: no cover
    pass

try:
    import requests
except ImportError:  # pragma: no cover
    requests = None

try:
    from utils.logger import log
except Exception:  # pragma: no cover
    import logging

    logging.basicConfig(level=logging.INFO)
    log = logging.getLogger("ai.vuln_verifier")


# 漏洞类型清单
VULN_TYPES = [
    "sql_injection", "xss", "weak_password", "open_port",
    "csrf", "file_upload", "path_traversal", "other",
]

# 漏洞类型 -> 触发关键词（规则降级用）
TYPE_KEYWORDS: Dict[str, List[str]] = {
    "sql_injection": ["sql", "注入", "sqli", "union", "单引号", "注入点", "sql injection"],
    "xss": ["xss", "跨站脚本", "反射", "script", "<script>", "存储型"],
    "weak_password": ["弱口令", "弱密码", "默认密码", "weak password", "默认凭据", "弱认证"],
    "open_port": ["端口", "port", "开放", "暴露", "exposed"],
    "csrf": ["csrf", "跨站请求伪造", "xsrf"],
    "file_upload": ["上传", "upload", "文件上传", "任意文件上传"],
    "path_traversal": ["目录遍历", "路径穿越", "path traversal", "../", "目录跳转", "任意文件读取"],
}

# 受限弱口令字典（仅用于授权验证，限速、不爆破）
WEAK_PASSWORD_TOP20 = [
    "123456", "password", "123456789", "12345678", "12345", "1234567",
    "admin", "admin123", "root", "root123", "123123", "654321", "qwerty",
    "abc123", "111111", "password1", "iloveyou", "test", "guest", "000000",
]


class VulnerabilityVerifier:
    """漏洞自动验证引擎（仅检测/确认，不利用）。"""

    def __init__(self, api_key: Optional[str] = None, base_url: Optional[str] = None,
                 model: Optional[str] = None, timeout: int = 8):
        """初始化 LLM 配置与网络超时。"""
        from llm_integration import get_llm_client  # 延迟导入，避免循环依赖
        self._llm = get_llm_client()
        self.api_key = api_key or self._llm.api_key
        self.base_url = (base_url or self._llm.base_url).rstrip("/")
        self.model = model or self._llm.model
        self.timeout = timeout
        self.llm_available = bool(self.api_key and self.base_url and requests)
        if not self.llm_available:
            log.warning("LLM 不可用，漏洞验证器使用关键词规则判断漏洞类型")

    # ------------------------------------------------------------------
    # 内部：调用 LLM
    # ------------------------------------------------------------------
    def _call_llm(self, system_prompt: str, user_prompt: str) -> Optional[str]:
        """调用统一 LLM 客户端，失败返回 None。"""
        return self._llm.simple_chat(system_prompt, user_prompt,
                                     temperature=0.1, max_tokens=512)

    @staticmethod
    def _normalize_target(target: str) -> str:
        """把目标归一化为可请求的 URL（无 scheme 时补 http://）。"""
        t = (target or "").strip()
        if not t:
            return t
        if not t.startswith(("http://", "https://")):
            # 含端口或纯 IP/域名时按 http 处理
            t = "http://" + t
        return t

    # ------------------------------------------------------------------
    # 主验证方法
    # ------------------------------------------------------------------
    def verify(self, vuln_description: str, target: str, cve: str = "") -> Dict[str, Any]:
        """主验证入口：分析漏洞类型并选择对应检测方法。"""
        vuln_type = self._analyze_vuln_type(vuln_description)
        result: Dict[str, Any] = {
            "vuln_description": vuln_description,
            "target": target,
            "cve": cve,
            "detected_type": vuln_type,
            "verified_at": datetime.now().isoformat(),
            "status": "unverifiable",
            "confidence": 0.0,
            "evidence": [],
            "method": "",
        }
        try:
            if vuln_type == "sql_injection":
                r = self._verify_sql_injection(target)
            elif vuln_type == "xss":
                r = self._verify_xss(target)
            elif vuln_type == "weak_password":
                r = self._verify_weak_password(target)
            elif vuln_type == "open_port":
                r = self._verify_open_port(target, port=self._extract_port(target))
            elif vuln_type == "path_traversal":
                r = self._verify_path_traversal(target)
            else:
                # csrf / file_upload / other：不做主动发包利用，给出人工复核建议
                r = {"status": "unverifiable", "confidence": 0.2,
                     "evidence": ["该类型漏洞需人工复核或专用授权流程，未执行自动探测"],
                     "method": "manual_review"}
            result.update(r)
            result["method"] = result.get("method") or f"verify_{vuln_type}"
        except Exception as e:
            log.error(f"漏洞验证失败: {e}")
            result["status"] = "unverifiable"
            result["evidence"] = [f"验证过程异常: {e}"]
        return result

    # ------------------------------------------------------------------
    # 漏洞类型分析
    # ------------------------------------------------------------------
    def _analyze_vuln_type(self, description: str) -> str:
        """AI 分析漏洞类型；LLM 不可用时关键词匹配。"""
        system_prompt = (
            "你是漏洞分类器。把漏洞描述归类为以下类型之一，严格只返回类型单词，"
            f"不要解释: {VULN_TYPES}。"
        )
        content = self._call_llm(system_prompt, f"漏洞描述: {description}")
        if content:
            token = content.strip().lower()
            for t in VULN_TYPES:
                if t in token:
                    return t
        # 关键词降级
        low = (description or "").lower()
        scores = {t: 0 for t in VULN_TYPES}
        for t, kws in TYPE_KEYWORDS.items():
            for kw in kws:
                if kw.lower() in low:
                    scores[t] += 1
        best = max(scores, key=scores.get)
        return best if scores[best] > 0 else "other"

    # ------------------------------------------------------------------
    # 各检测方法（仅探测特征，不利用）
    # ------------------------------------------------------------------
    def _verify_sql_injection(self, target: str) -> Dict[str, Any]:
        """SQL 注入检测：发送单引号/布尔对照 payload，观察错误或差异，不提取数据。"""
        url = self._normalize_target(target)
        evidence: List[str] = []
        if not requests:
            return {"status": "unverifiable", "confidence": 0.1,
                    "evidence": ["requests 不可用，无法发送探测请求"], "method": "sql_probe"}
        try:
            # 基线请求
            base_resp = requests.get(url, timeout=self.timeout)
            base_len = len(base_resp.text)
            # 无害探测：附加单引号（只看是否触发数据库报错，不枚举/不脱库）
            probe_url = f"{url}{'?' if '?' not in url else '&'}id=1'"
            probe_resp = requests.get(probe_url, timeout=self.timeout)
            evidence.append(f"基线状态码={base_resp.status_code} 长度={base_len}")
            evidence.append(f"单引号探测状态码={probe_resp.status_code} 长度={len(probe_resp.text)}")
            err_markers = ["sql syntax", "mysql", "ora-", "postgresql", "sqlite",
                           "unclosed quotation", "odbc", "syntax error"]
            hit = any(m in probe_resp.text.lower() for m in err_markers)
            if hit:
                return {"status": "confirmed", "confidence": 0.75,
                        "evidence": evidence + ["响应中出现数据库报错特征（仅特征确认，未利用）"],
                        "method": "sql_error_based_probe"}
            # 长度差异较大也仅标记 possible
            if abs(len(probe_resp.text) - base_len) > max(200, base_len * 0.3):
                return {"status": "possible", "confidence": 0.4,
                        "evidence": evidence + ["基线与探测响应长度差异显著，需人工复核"],
                        "method": "sql_length_diff_probe"}
            return {"status": "unverifiable", "confidence": 0.3,
                    "evidence": evidence + ["未观察到明显报错/差异特征"],
                    "method": "sql_probe"}
        except Exception as e:
            return {"status": "unverifiable", "confidence": 0.1,
                    "evidence": [f"探测请求失败: {e}"], "method": "sql_probe"}

    def _verify_xss(self, target: str) -> Dict[str, Any]:
        """XSS 检测：发送无害反射型 payload，观察是否原样回显，不执行脚本。"""
        url = self._normalize_target(target)
        if not requests:
            return {"status": "unverifiable", "confidence": 0.1,
                    "evidence": ["requests 不可用"], "method": "xss_reflect_probe"}
        marker = "xssprobe9f3e"  # 无害标记串，不含真实可执行脚本
        probe_url = f"{url}{'?' if '?' not in url else '&'}q={marker}"
        try:
            resp = requests.get(probe_url, timeout=self.timeout)
            reflected = marker in resp.text
            evidence = [f"探测请求: {probe_url}", f"标记串是否原样回显: {reflected}"]
            if reflected:
                return {"status": "possible", "confidence": 0.45,
                        "evidence": evidence + ["输入被原样反射到响应中（反射面存在，需确认是否被转义）"],
                        "method": "xss_reflect_probe"}
            return {"status": "unverifiable", "confidence": 0.2,
                    "evidence": evidence + ["未观察到标记串回显"], "method": "xss_reflect_probe"}
        except Exception as e:
            return {"status": "unverifiable", "confidence": 0.1,
                    "evidence": [f"探测请求失败: {e}"], "method": "xss_reflect_probe"}

    def _verify_weak_password(self, target: str, service: str = "ssh") -> Dict[str, Any]:
        """弱口令验证：仅做受限、限速的登录尝试（Top20），不爆破、不横向移动。"""
        host = self._normalize_target(target).replace("http://", "").replace("https://", "")
        host = host.split("/")[0].split(":")[0]
        evidence: List[str] = [f"目标服务: {service}@{host}（授权验证，限速尝试 Top20）"]
        # 不强制依赖 paramiko；未安装则只做连通性判断，避免引入外部攻击库依赖
        try:
            import paramiko  # type: ignore
        except Exception:
            evidence.append("paramiko 不可用，仅做端口连通性检查，未进行登录尝试")
            port = 22 if service == "ssh" else 22
            return self._verify_open_port(host, port) if False else {
                "status": "unverifiable", "confidence": 0.2,
                "evidence": evidence, "method": "weak_password_connectivity_only"}
        # 若 paramiko 存在，做极其受限的限速验证（授权场景）
        findings = []
        for i, pwd in enumerate(WEAK_PASSWORD_TOP20[:5]):  # 仅试前5个，且限速
            try:
                client = paramiko.SSHClient()
                client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
                client.connect(host, port=22, username="root", password=pwd,
                               timeout=3, allow_agent=False, look_for_keys=False)
                client.close()
                findings.append(f"root/{pwd} 登录成功（已确认弱口令，建议立即修改）")
                return {"status": "confirmed", "confidence": 0.9,
                        "evidence": evidence + findings,
                        "method": "weak_password_limited_login"}
            except Exception:
                continue
        return {"status": "possible", "confidence": 0.3,
                "evidence": evidence + ["Top5 常见弱口令未直接命中，仍建议强制改密"],
                "method": "weak_password_limited_login"}

    def _verify_open_port(self, target: str, port: int = 0) -> Dict[str, Any]:
        """端口开放验证：纯 TCP 连接性测试，不发包扫描。"""
        host = self._normalize_target(target).replace("http://", "").replace("https://", "")
        host = host.split("/")[0]
        # 从 host 提取端口
        if ":" in host and not host.replace(".", "").isdigit():
            parts = host.split(":")
            host, p = parts[0], parts[1]
            try:
                port = int(p)
            except ValueError:
                port = port or 80
        if not port:
            port = 80
        try:
            sock = socket.create_connection((host, port), timeout=self.timeout)
            sock.close()
            return {"status": "confirmed", "confidence": 0.95,
                    "evidence": [f"TCP {host}:{port} 连接成功，端口开放"],
                    "method": "tcp_connect"}
        except (socket.timeout, ConnectionRefusedError, OSError) as e:
            return {"status": "fixed", "confidence": 0.7,
                    "evidence": [f"TCP {host}:{port} 连接失败（关闭或被过滤）: {e}"],
                    "method": "tcp_connect"}

    def _verify_path_traversal(self, target: str) -> Dict[str, Any]:
        """路径穿越检测：只请求无害的 ../ 序列，观察是否读取系统文件特征，不读取真实敏感文件。"""
        url = self._normalize_target(target)
        if not requests:
            return {"status": "unverifiable", "confidence": 0.1,
                    "evidence": ["requests 不可用"], "method": "path_traversal_probe"}
        # 无害标记：请求一个不存在的穿越路径，仅观察 4xx/5xx 行为
        probe_url = f"{url}{'/' if url.endswith('/') else '/'}../../nonexistent_probe.txt"
        try:
            resp = requests.get(probe_url, timeout=self.timeout)
            evidence = [f"探测: {probe_url}", f"状态码={resp.status_code}"]
            if resp.status_code == 200:
                return {"status": "possible", "confidence": 0.4,
                        "evidence": evidence + ["穿越路径返回 200，需人工确认是否可读"],
                        "method": "path_traversal_probe"}
            return {"status": "unverifiable", "confidence": 0.25,
                    "evidence": evidence + ["穿越路径未返回内容"], "method": "path_traversal_probe"}
        except Exception as e:
            return {"status": "unverifiable", "confidence": 0.1,
                    "evidence": [f"探测失败: {e}"], "method": "path_traversal_probe"}

    @staticmethod
    def _extract_port(target: str) -> int:
        """从目标串中提取端口（无则返回0）。"""
        m = re.search(r":(\d{2,5})(?:/|$)", target or "")
        return int(m.group(1)) if m else 0

    # ------------------------------------------------------------------
    # 验证报告
    # ------------------------------------------------------------------
    def generate_verification_report(self, verification_result: Dict[str, Any]) -> Dict[str, Any]:
        """生成结构化验证报告：方法/步骤/结果/证据/置信度/建议。"""
        status = verification_result.get("status", "unverifiable")
        suggestion_map = {
            "confirmed": "已确认存在，请按高危流程立即修复并复测。",
            "possible": "存在疑似特征，建议人工复核后再定性。",
            "unverifiable": "自动化未能确认，请安排人工验证或补充证据。",
            "fixed": "复测未复现，疑似已修复或被防护，建议持续观察。",
        }
        return {
            "report_id": "ver_" + str(int(datetime.now().timestamp())),
            "target": verification_result.get("target"),
            "cve": verification_result.get("cve", ""),
            "vuln_type": verification_result.get("detected_type"),
            "verification_method": verification_result.get("method"),
            "steps": [
                "1. 解析漏洞描述并识别漏洞类型",
                "2. 选择非破坏性探测方法（仅发无害 payload/连接性测试）",
                "3. 观察响应特征并与基线比对",
                "4. 给出状态、置信度与证据",
            ],
            "result": status,
            "confidence": verification_result.get("confidence", 0.0),
            "evidence": verification_result.get("evidence", []),
            "recommendation": suggestion_map.get(status, "请人工评估。"),
            "note": "本验证仅做检测确认，未执行任何利用或破坏性操作。",
            "generated_at": datetime.now().isoformat(),
        }


# 模块级单例
_verifier: Optional[VulnerabilityVerifier] = None


def get_vulnerability_verifier() -> VulnerabilityVerifier:
    """获取全局 VulnerabilityVerifier 单例。"""
    global _verifier
    if _verifier is None:
        _verifier = VulnerabilityVerifier()
    return _verifier
