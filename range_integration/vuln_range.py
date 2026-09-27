# -*- coding: utf-8 -*-
"""
vuln_range.py - 漏洞靶场集成模块

集成 6 大类漏洞靶场：
- Web 漏洞靶场：DVWA/Juice Shop/WebGoat/bWAPP/Mutillidae/Pikachu
- 系统漏洞靶场：Metasploitable/Vulhub
- 移动漏洞靶场：Android/iOS
- 云漏洞靶场：AWS/Azure/阿里云
- API 漏洞靶场：OWASP API Top 10/REST/GraphQL
- 工控漏洞靶场：Modbus/S7/DNP3

自动识别漏洞、扫描、验证逻辑。全部内存字典模拟。
"""

from __future__ import annotations

import logging
import time
import uuid
from typing import Any, Dict, List, Optional

logger = logging.getLogger(__name__)

NOTICE = "仅限授权环境使用：漏洞验证仅做检测，不做破坏性利用。"


def _clean(obj: Any) -> Any:
    if isinstance(obj, dict):
        return {k: _clean(v) for k, v in obj.items()}
    if isinstance(obj, list):
        return [_clean(v) for v in obj]
    if isinstance(obj, str):
        return "".join(ch for ch in obj if ch == "\n" or ch == "\t" or ord(ch) >= 32)
    return obj


# ----------------------------------------------------------------------
# 漏洞靶场元数据：按类别组织
# ----------------------------------------------------------------------
WEB_VULN_RANGES: Dict[str, Dict[str, Any]] = {
    "dvwa": {
        "id": "dvwa", "name": "DVWA", "category": "web",
        "vuln_modules": ["Brute Force", "Command Injection", "CSRF", "File Inclusion",
                         "File Upload", "Insecure CAPTCHA", "SQL Injection",
                         "SQL Injection Blind", "XSS DOM", "XSS Reflected", "XSS Stored"],
        "difficulty_levels": ["low", "medium", "high", "impossible"],
        "auto_detect": ["GET 参数反射检测", "SQL 错误信息提取", "上传点枚举"],
    },
    "juice-shop": {
        "id": "juice-shop", "name": "OWASP Juice Shop", "category": "web",
        "vuln_modules": ["Login Admin", "Confidential Document", "Forgotten Feedback",
                         "Privacy Policy", "DOM XSS", "Login Admin", "Bought a Accessory",
                         "Admin Section", "Forgotten Sales Page", "Five-Star Feedback"],
        "difficulty_levels": ["1-star", "2-star", "3-star", "4-star", "6-star"],
        "auto_detect": ["API 路由枚举", "JWT 令牌分析", "敏感文件探测"],
    },
    "webgoat": {
        "id": "webgoat", "name": "OWASP WebGoat", "category": "web",
        "vuln_modules": ["HTTP Basics", "WebGoat Introduction", "JWT", "SQL Injection",
                         "Path Traversal", "XXE", "Insecure Deserialization",
                         "CSRF", "Access Control", "Cryptography"],
        "difficulty_levels": ["beginner", "intermediate", "advanced"],
        "auto_detect": ["课程端点枚举", "Java 反序列化检测", "JWT 弱密钥识别"],
    },
    "bwapp": {
        "id": "bwapp", "name": "bWAPP", "category": "web",
        "vuln_modules": ["SQL Injection", "XSS", "CSRF", "LFI", "RFI",
                         "Command Execution", "File Upload", "HTML Injection",
                         "LDAP Injection", "XML External Entity"],
        "difficulty_levels": ["low", "medium", "high"],
        "auto_detect": ["100+ 漏洞页面枚举", "表单注入测试", "文件包含路径遍历"],
    },
    "mutillidae": {
        "id": "mutillidae", "name": "Mutillidae II", "category": "web",
        "vuln_modules": ["SQL Injection", "XSS", "CSRF", "Directory Traversal",
                         "File Inclusion", "Command Injection", "Authentication Bypass",
                         "Captcha Bypass", "Clickjacking", "Unvalidated Redirects"],
        "difficulty_levels": ["level-0", "level-1", "level-2", "level-3"],
        "auto_detect": ["安全级别切换检测", "OWASP ZAP 集成扫描"],
    },
    "pikachu": {
        "id": "pikachu", "name": "Pikachu", "category": "web",
        "vuln_modules": ["SQL Injection", "XSS", "CSRF", "File Upload",
                         "File Inclusion", "Unsafe Unserialize", "Over Permission",
                         "URL Redirect", "Sensitive Info Disclosure"],
        "difficulty_levels": ["入门", "进阶"],
        "auto_detect": ["中文漏洞页面识别", "表单枚举", "Cookie 分析"],
    },
}

SYSTEM_VULN_RANGES: Dict[str, Dict[str, Any]] = {
    "metasploitable": {
        "id": "metasploitable", "name": "Metasploitable2", "category": "system",
        "services": ["ftp(21)", "ssh(22)", "telnet(23)", "smtp(25)", "dns(53)",
                     "http(80)", "mysql(3306)", "postgresql(5432)", "vnc(5900)", "irc(6667)"],
        "vuln_types": ["vsftpd 后门", "Samba 用户枚举", "MySQL 弱口令",
                       "UnrealIRCd 后门", "Tomcat 弱口令", "PostgreSQL 提权"],
        "privesc": ["内核提权", "SUID 二进制", "sudo 配置错误", "Cron 任务劫持"],
    },
    "vulhub": {
        "id": "vulhub", "name": "Vulhub", "category": "system",
        "vuln_categories": ["WebLogic", "Apache", "Nginx", "Tomcat", "Redis",
                            "MySQL", "PostgreSQL", "Docker", "Kubernetes", "Java框架"],
        "cve_count": 3000,
        "exploit_types": ["RCE", "反序列化", "文件上传", "SQL注入", "权限绕过"],
    },
}

MOBILE_VULN_RANGES: Dict[str, Dict[str, Any]] = {
    "android_diva": {
        "id": "android_diva", "name": "DIVA Android", "category": "mobile",
        "platform": "Android",
        "vuln_modules": ["Insecure Logging", "Hardcoded Credentials", "SQL Injection",
                         "Insecure Data Storage", "Access Control", "Brideg WebView",
                         "Input Validation", "Weak Password"],
        "tools": ["Jadx", "APKTool", "Frida", "MobSF", "Drozer"],
    },
    "ios_goat": {
        "id": "ios_goat", "name": "iOS Goat", "category": "mobile",
        "platform": "iOS",
        "vuln_modules": ["Insecure Data Storage", "Privacy", "Authentication",
                         "Network Security", "Code Security"],
        "tools": ["Hopper", "Cycript", "Frida", "Objection", "iFile"],
    },
    "owasp_mobile_api": {
        "id": "owasp_mobile_api", "name": "OWASP Mobile API", "category": "mobile",
        "platform": "Mobile API",
        "vuln_modules": ["过度暴露", "越权", "认证失效", "敏感数据传输", "速率限制缺失"],
    },
}

CLOUD_VULN_RANGES: Dict[str, Dict[str, Any]] = {
    "aws_privesc": {
        "id": "aws_privesc", "name": "AWS Privesc Workshop", "category": "cloud",
        "provider": "AWS",
        "vuln_types": ["IAM 配置错误", "过度权限", "S3 公开访问",
                       "凭证泄露", "未授权 API 调用", "元数据服务利用"],
        "services": ["IAM", "S3", "EC2", "Lambda", "CloudTrail", "STS"],
    },
    "azure_goat": {
        "id": "azure_goat", "name": "AzureGoat", "category": "cloud",
        "provider": "Azure",
        "vuln_types": ["RBAC 过度权限", "存储账户暴露", "密钥泄露",
                       "App Service 认证绕过", "AMS 接管"],
        "services": ["RBAC", "Storage", "App Service", "Key Vault"],
    },
    "aliyun_hack": {
        "id": "aliyun_hack", "name": "阿里云靶场", "category": "cloud",
        "provider": "阿里云",
        "vuln_types": ["RAM 配置错误", "OSS 公开桶", "AccessKey 泄露",
                       "ECS 安全组过宽", "云监控权限滥用"],
        "services": ["RAM", "OSS", "ECS", "云监控"],
    },
}

API_VULN_RANGES: Dict[str, Dict[str, Any]] = {
    "owasp_api_top10": {
        "id": "owasp_api_top10", "name": "OWASP API Security Top 10", "category": "api",
        "vuln_modules": ["API1 BOLA", "API2 认证失效", "API3 数据过度暴露",
                         "API4 资源消耗", "API5 BOPLA", "API6 未绑定通ant",
                         "API7 服务端请求伪造", "API8 安全配置错误",
                         "API9 不当资产管理", "API10 不安全消费"],
        "protocols": ["REST", "GraphQL", "gRPC", "WebSocket"],
    },
    "rest_booker": {
        "id": "rest_booker", "name": "REST Booker", "category": "api",
        "vuln_modules": ["越权访问", "注入", "数据泄露", "业务逻辑", "速率限制"],
    },
    "graphql_voyager": {
        "id": "graphql_voyager", "name": "GraphQL Voyager", "category": "api",
        "vuln_modules": ["内省查询", "深度嵌套攻击", "批量查询", "字段建议滥用"],
    },
}

ICS_VULN_RANGES: Dict[str, Dict[str, Any]] = {
    "modbus_lab": {
        "id": "modbus_lab", "name": "Modbus 工控靶场", "category": "ics",
        "protocols": ["Modbus TCP", "Modbus RTU"],
        "vuln_types": ["未授权读写", "协议无认证", "寄存器篡改", "物理影响模拟"],
        "devices": ["PLC", "RTU", "HMI", "SCADA"],
    },
    "s7_lab": {
        "id": "s7_lab", "name": "S7comm 工控靶场", "category": "ics",
        "protocols": ["S7comm", "S7comm+", "Profinet"],
        "vuln_types": ["PLC 控制", "程序下载", "CPU 状态修改", "保护绕过"],
        "devices": ["Siemens S7-300", "S7-400", "S7-1200", "S7-1500"],
    },
    "dnp3_lab": {
        "id": "dnp3_lab", "name": "DNP3 工控靶场", "category": "ics",
        "protocols": ["DNP3", "DNP3 Secure Authentication"],
        "vuln_types": ["未控制命令", "数据篡改", "拒绝服务", "重放攻击"],
    },
}

# 汇总
ALL_VULN_RANGES: Dict[str, Dict[str, Any]] = {
    **WEB_VULN_RANGES,
    **SYSTEM_VULN_RANGES,
    **MOBILE_VULN_RANGES,
    **CLOUD_VULN_RANGES,
    **API_VULN_RANGES,
    **ICS_VULN_RANGES,
}


# ======================================================================
# VulnRangeManager
# ======================================================================
class VulnRangeManager:
    """漏洞靶场集成管理器。"""

    def __init__(self) -> None:
        self._scans: Dict[str, Dict[str, Any]] = {}
        self._findings: Dict[str, List[Dict[str, Any]]] = {}

    # ------------------------------------------------------------------
    # 列表
    # ------------------------------------------------------------------
    def list_by_category(self, category: Optional[str] = None) -> Dict[str, List[Dict]]:
        result = {}
        sources = {
            "web": WEB_VULN_RANGES,
            "system": SYSTEM_VULN_RANGES,
            "mobile": MOBILE_VULN_RANGES,
            "cloud": CLOUD_VULN_RANGES,
            "api": API_VULN_RANGES,
            "ics": ICS_VULN_RANGES,
        }
        if category:
            sources = {category: sources.get(category, {})}
        for cat, items in sources.items():
            result[cat] = list(items.values())
        return result

    def get_range_detail(self, range_id: str) -> Optional[Dict[str, Any]]:
        return ALL_VULN_RANGES.get(range_id)

    # ------------------------------------------------------------------
    # 自动漏洞识别
    # ------------------------------------------------------------------
    def auto_identify(self, range_id: str, target_url: str) -> Dict[str, Any]:
        """模拟自动识别靶场漏洞模块。"""
        info = ALL_VULN_RANGES.get(range_id)
        if not info:
            return {"success": False, "error": f"未知靶场: {range_id}"}

        scan_id = f"scan_{uuid.uuid4().hex[:8]}"
        vuln_list = info.get("vuln_modules") or info.get("vuln_types") or []

        findings = []
        for v in vuln_list[:15]:
            findings.append({
                "vuln_name": v,
                "severity": "高" if "注入" in v or "RCE" in v or "泄露" in v else "中",
                "detected": True,
                "evidence": f"在 {target_url} 上检测到 {v} 的存在迹象",
                "verified": False,
            })

        self._scans[scan_id] = {
            "scan_id": scan_id,
            "range_id": range_id,
            "target_url": target_url,
            "findings_count": len(findings),
            "status": "completed",
            "created_at": time.strftime("%Y-%m-%d %H:%M:%S"),
        }
        self._findings[scan_id] = findings

        return {
            "success": True,
            "scan_id": scan_id,
            "range_id": range_id,
            "target_url": target_url,
            "findings_count": len(findings),
            "findings": findings,
        }

    # ------------------------------------------------------------------
    # 漏洞验证
    # ------------------------------------------------------------------
    def verify_vuln(self, scan_id: str, vuln_name: str) -> Dict[str, Any]:
        """模拟漏洞验证（仅检测性，不利用）。"""
        findings = self._findings.get(scan_id)
        if not findings:
            return {"success": False, "error": f"扫描不存在: {scan_id}"}

        for f in findings:
            if f["vuln_name"] == vuln_name:
                f["verified"] = True
                f["verify_result"] = "已确认存在（检测性验证）"
                return {
                    "success": True,
                    "vuln_name": vuln_name,
                    "verified": True,
                    "evidence": f["evidence"],
                }
        return {"success": False, "error": f"未找到漏洞: {vuln_name}"}

    # ------------------------------------------------------------------
    # 漏洞利用场景（教学用，仅步骤描述）
    # ------------------------------------------------------------------
    def get_exploit_guide(self, range_id: str, vuln_name: str) -> Dict[str, Any]:
        """获取漏洞利用教学步骤（仅描述，不提供可执行代码）。"""
        steps = [
            f"1. 信息收集：确认目标 {range_id} 的漏洞入口点",
            f"2. 漏洞确认：验证 {vuln_name} 的存在性",
            f"3. 构造请求：按照漏洞类型构造测试 payload（仅检测性）",
            f"4. 数据验证：确认返回数据是否符合预期",
            f"5. 影响评估：评估漏洞可能造成的影响范围",
            "6. 修复建议：给出针对性的修复方案",
        ]
        return {
            "success": True,
            "range_id": range_id,
            "vuln_name": vuln_name,
            "steps": steps,
            "notice": NOTICE,
        }

    # ------------------------------------------------------------------
    # 扫描结果
    # ------------------------------------------------------------------
    def list_scans(self) -> List[Dict[str, Any]]:
        return list(self._scans.values())

    def get_scan(self, scan_id: str) -> Dict[str, Any]:
        s = self._scans.get(scan_id)
        if not s:
            return {"success": False, "error": "扫描不存在"}
        return {
            "success": True,
            "scan": s,
            "findings": self._findings.get(scan_id, []),
        }


_manager: Optional[VulnRangeManager] = None


def get_vuln_manager() -> VulnRangeManager:
    global _manager
    if _manager is None:
        _manager = VulnRangeManager()
    return _manager
