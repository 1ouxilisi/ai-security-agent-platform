# -*- coding: utf-8 -*-
"""
self_audit模块，提供自身安全审计功能。

模块功能：
    - API安全配置审计
    - 访问控制审计
    - 数据保护审计
    - 硬编码密钥/密码检测
    - 依赖包已知漏洞检查
    - 完整安全审计报告生成

注意事项：
    - 本模块仅用于授权的安全测试
    - 请勿用于非法用途
    - 使用前请确保已获得相关授权
"""
import os
import re
import json
import time
from datetime import datetime
from typing import Any, Dict, List, Optional, Tuple

# 项目根目录
_PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
_DATA_DIR = os.path.join(_PROJECT_ROOT, "data")
_LOGS_DIR = os.path.join(_PROJECT_ROOT, "logs")

# 已知漏洞依赖包列表（包名: (有漏洞的版本上限, 修复版本, 严重程度)）
KNOWN_VULN_DEPS: Dict[str, Tuple[str, str, str]] = {
    "django": ("<2.2.28", "2.2.28", "critical"),
    "flask": ("<1.0", "1.0", "high"),
    "requests": ("<2.20", "2.20", "high"),
    "urllib3": ("<1.24.2", "1.24.2", "high"),
    "pyyaml": ("<5.4", "5.4", "high"),
    "jinja2": ("<2.11.3", "2.11.3", "critical"),
    "pillow": ("<8.1.1", "8.1.1", "high"),
    "numpy": ("<1.22.0", "1.22.0", "medium"),
    "cryptography": ("<3.2", "3.2", "critical"),
    "paramiko": ("<2.10.1", "2.10.1", "high"),
    "openssl": ("<1.1.1", "1.1.1", "critical"),
}


class SelfAuditor:
    """自身安全审计器。

    审计API安全配置、访问控制、数据保护，
    检测硬编码密钥和依赖漏洞，生成安全报告。
    """

    # 硬编码密钥正则模式
    SECRET_PATTERNS = [
        (re.compile(r'api_key\s*=\s*["\']([^"\']{8,})["\']', re.IGNORECASE),
         "hardcoded_api_key"),
        (re.compile(r'password\s*=\s*["\']([^"\']{6,})["\']', re.IGNORECASE),
         "hardcoded_password"),
        (re.compile(r'secret\s*=\s*["\']([^"\']{8,})["\']', re.IGNORECASE),
         "hardcoded_secret"),
        (re.compile(r'token\s*=\s*["\']([^"\']{8,})["\']', re.IGNORECASE),
         "hardcoded_token"),
    ]

    # 排除模式（从配置读取，不是硬编码）
    EXCLUDE_PATTERNS = [
        "os.getenv", "os.environ", "settings.", "config.",
        "getenv", "environ[",
    ]

    def __init__(self, project_root: Optional[str] = None):
        """初始化SelfAuditor实例。

        Args:
            project_root: 项目根目录，默认为当前项目根。
        """
        self.project_root = project_root or _PROJECT_ROOT
        self.risks: List[Dict[str, Any]] = []

    # ------------------------------------------------------------------ #
    # API安全审计
    # ------------------------------------------------------------------ #
    def audit_api_security(self) -> List[Dict[str, Any]]:
        """审计API安全配置。

        检查：API密钥认证、速率限制、请求日志、密钥强度。

        Returns:
            风险项列表。
        """
        risks: List[Dict[str, Any]] = []

        # 检查API密钥认证
        try:
            from security.api_security import APISecurity
            sec = APISecurity()
            if not os.environ.get("DEFAULT_API_KEY"):
                keys_file = os.path.join(_DATA_DIR, "api_keys.json")
                if not os.path.exists(keys_file) or \
                        os.path.getsize(keys_file) < 10:
                    risks.append({
                        "category": "api_security",
                        "severity": "high",
                        "title": "API密钥认证未配置",
                        "description": "未设置DEFAULT_API_KEY环境变量且无用户API密钥",
                        "suggestion": "设置DEFAULT_API_KEY环境变量或通过API创建密钥",
                    })
        except Exception as e:
            risks.append({
                "category": "api_security",
                "severity": "medium",
                "title": "API安全模块加载失败",
                "description": f"APISecurity初始化异常: {e}",
                "suggestion": "检查security/api_security.py是否正确安装",
            })

        # 检查默认密钥强度
        default_key = os.environ.get("DEFAULT_API_KEY", "")
        if default_key and len(default_key) < 32:
            risks.append({
                "category": "api_security",
                "severity": "medium",
                "title": "默认API密钥强度不足",
                "description": f"DEFAULT_API_KEY长度仅{len(default_key)}位，建议至少32位",
                "suggestion": "使用secrets.token_urlsafe(32)生成强密钥",
            })

        # 检查速率限制（通过文件存在性判断中间件是否启用）
        middleware_file = os.path.join(
            self.project_root, "api_server", "security_middleware.py")
        if not os.path.exists(middleware_file):
            risks.append({
                "category": "api_security",
                "severity": "medium",
                "title": "安全中间件文件缺失",
                "description": "api_server/security_middleware.py不存在",
                "suggestion": "确保安全中间件已正确部署",
            })

        # 检查请求日志
        api_log = os.path.join(_LOGS_DIR, "api_requests.log")
        if not os.path.exists(api_log):
            risks.append({
                "category": "api_security",
                "severity": "low",
                "title": "API请求日志未启用",
                "description": "logs/api_requests.log不存在，请求日志可能未配置",
                "suggestion": "确保API安全模块的log_request被正确调用",
            })

        return risks

    # ------------------------------------------------------------------ #
    # 访问控制审计
    # ------------------------------------------------------------------ #
    def audit_access_control(self) -> List[Dict[str, Any]]:
        """审计访问控制配置。

        检查：默认admin账户、RBAC启用、会话超时、密码策略。

        Returns:
            风险项列表。
        """
        risks: List[Dict[str, Any]] = []

        # 检查默认admin账户
        users_file = os.path.join(_DATA_DIR, "users.json")
        if os.path.exists(users_file):
            try:
                with open(users_file, "r", encoding="utf-8") as f:
                    users = json.load(f)
                if isinstance(users, dict):
                    for uid, uinfo in users.items():
                        if isinstance(uinfo, dict):
                            pwd = str(uinfo.get("password", uinfo.get("hashed_password", "")))
                            if uid == "admin" and pwd in ("admin", "123456", "password", ""):
                                risks.append({
                                    "category": "access_control",
                                    "severity": "critical",
                                    "title": "默认admin账户使用弱密码",
                                    "description": f"admin用户密码为弱密码: {pwd}",
                                    "suggestion": "立即修改admin密码，使用强密码策略",
                                })
            except (json.JSONDecodeError, IOError):
                pass

        # 检查会话超时设置
        try:
            from security.access_control import AccessControl
            ac = AccessControl()
            if ac.SESSION_TIMEOUT < 15 * 60:
                risks.append({
                    "category": "access_control",
                    "severity": "medium",
                    "title": "会话超时时间过短",
                    "description": f"会话超时仅{ac.SESSION_TIMEOUT}秒",
                    "suggestion": "建议设置为30分钟（1800秒）",
                })
        except Exception:
            pass

        # 检查密码策略
        try:
            from security.access_control import AccessControl
            ac = AccessControl()
            weak_check = ac.check_password_policy("123456")
            if weak_check.get("valid"):
                risks.append({
                    "category": "access_control",
                    "severity": "high",
                    "title": "密码策略未生效",
                    "description": "弱密码'123456'通过了密码策略检查",
                    "suggestion": "检查AccessControl.check_password_policy逻辑",
                })
        except Exception:
            pass

        return risks

    # ------------------------------------------------------------------ #
    # 数据保护审计
    # ------------------------------------------------------------------ #
    def audit_data_protection(self) -> List[Dict[str, Any]]:
        """审计数据保护配置。

        检查：敏感数据加密、备份机制、数据库文件权限。

        Returns:
            风险项列表。
        """
        risks: List[Dict[str, Any]] = []

        # 检查加密密钥文件
        key_file = os.path.join(_DATA_DIR, ".encryption_key")
        env_key = os.environ.get("DATA_ENCRYPTION_KEY", "")
        if not os.path.exists(key_file) and not env_key:
            risks.append({
                "category": "data_protection",
                "severity": "high",
                "title": "数据加密密钥未配置",
                "description": "未找到.data/.encryption_key文件且DATA_ENCRYPTION_KEY环境变量未设置",
                "suggestion": "DataProtection初始化时会自动生成密钥",
            })

        # 检查备份机制
        backup_dir = os.path.join(_DATA_DIR, "backups")
        if not os.path.isdir(backup_dir):
            risks.append({
                "category": "data_protection",
                "severity": "medium",
                "title": "数据备份目录不存在",
                "description": "data/backups/目录未创建，备份功能可能未使用",
                "suggestion": "定期调用DataProtection.backup_data()",
            })

        # 检查数据库文件
        db_file = os.path.join(_DATA_DIR, "platform.db")
        if os.path.exists(db_file):
            try:
                # 检查文件是否可读（基本权限检查）
                with open(db_file, "rb") as f:
                    f.read(16)
                # Windows上无法直接检查权限，但可以检查文件大小异常小
                size = os.path.getsize(db_file)
                if size < 1000:
                    risks.append({
                        "category": "data_protection",
                        "severity": "low",
                        "title": "数据库文件异常小",
                        "description": f"platform.db仅{size}字节",
                        "suggestion": "检查数据库是否正确初始化",
                    })
            except IOError as e:
                risks.append({
                    "category": "data_protection",
                    "severity": "high",
                    "title": "数据库文件无法读取",
                    "description": str(e),
                    "suggestion": "检查数据库文件权限",
                })

        return risks

    # ------------------------------------------------------------------ #
    # 硬编码密钥检测
    # ------------------------------------------------------------------ #
    def check_hardcoded_secrets(self) -> List[Dict[str, Any]]:
        """扫描项目中Python文件的硬编码密钥/密码。

        Returns:
            可疑文件列表（文件路径/行号/匹配内容/严重程度）。
        """
        findings: List[Dict[str, Any]] = []
        exclude_dirs = {".venv", "venv", "tests", "__pycache__",
                        ".git", "node_modules", "dist", "build",
                        ".pytest_cache", "site-packages"}

        for root, dirs, files in os.walk(self.project_root):
            # 过滤排除目录
            dirs[:] = [d for d in dirs if d not in exclude_dirs]
            for fname in files:
                if not fname.endswith(".py"):
                    continue
                fpath = os.path.join(root, fname)
                try:
                    with open(fpath, "r", encoding="utf-8", errors="ignore") as f:
                        lines = f.readlines()
                except IOError:
                    continue

                for lineno, line in enumerate(lines, 1):
                    stripped = line.strip()
                    # 跳过注释行
                    if stripped.startswith("#"):
                        continue
                    # 跳过排除模式
                    if any(pat in line for pat in self.EXCLUDE_PATTERNS):
                        continue

                    for pattern, secret_type in self.SECRET_PATTERNS:
                        match = pattern.search(line)
                        if match:
                            matched_value = match.group(1)
                            # 进一步过滤：匹配值不能太短或明显是示例
                            if matched_value.lower() in (
                                "your_api_key_here", "your_password",
                                "example", "test", "changeme", "xxx",
                                "placeholder", "default",
                            ):
                                continue
                            # 严重程度判断
                            severity = "medium"
                            if "password" in secret_type:
                                severity = "high"
                            elif "secret" in secret_type:
                                severity = "high"
                            findings.append({
                                "file_path": os.path.relpath(fpath, self.project_root),
                                "line_number": lineno,
                                "match_type": secret_type,
                                "matched_content": matched_value[:20] + "..."
                                if len(matched_value) > 20 else matched_value,
                                "severity": severity,
                                "line_text": stripped[:100],
                            })

        return findings

    # ------------------------------------------------------------------ #
    # 依赖漏洞检查
    # ------------------------------------------------------------------ #
    def check_dependencies(self) -> List[Dict[str, Any]]:
        """检查依赖包已知漏洞。

        读取requirements.txt，与内置已知漏洞列表对比。

        Returns:
            有漏洞的依赖列表。
        """
        findings: List[Dict[str, Any]] = []
        req_file = os.path.join(self.project_root, "requirements.txt")

        if not os.path.exists(req_file):
            return findings

        # 解析requirements.txt
        installed: Dict[str, str] = {}
        try:
            with open(req_file, "r", encoding="utf-8") as f:
                for line in f:
                    line = line.strip()
                    if not line or line.startswith("#"):
                        continue
                    # 解析包名和版本
                    for sep in ("==", ">=", "<=", "~=", "!=", ">", "<"):
                        if sep in line:
                            parts = line.split(sep, 1)
                            pkg_name = parts[0].strip().lower()
                            pkg_version = parts[1].strip() if len(parts) > 1 else ""
                            installed[pkg_name] = pkg_version
                            break
                    else:
                        pkg_name = line.split("[")[0].strip().lower()
                        installed[pkg_name] = ""
        except IOError:
            return findings

        # 对比已知漏洞
        for pkg, (vuln_range, fix_version, severity) in KNOWN_VULN_DEPS.items():
            if pkg in installed:
                current_version = installed[pkg]
                findings.append({
                    "package": pkg,
                    "installed_version": current_version or "unknown",
                    "vulnerable_range": vuln_range,
                    "fixed_version": fix_version,
                    "severity": severity,
                    "description": f"{pkg}存在已知漏洞，建议升级到{fix_version}或更高版本",
                })

        return findings

    # ------------------------------------------------------------------ #
    # 完整审计
    # ------------------------------------------------------------------ #
    def run_full_audit(self) -> Dict[str, Any]:
        """运行完整自身安全审计。

        调用所有检查项，生成审计报告。

        Returns:
            审计报告，包含风险项、修复建议和安全评分。
        """
        all_risks: List[Dict[str, Any]] = []

        # 执行所有审计项
        try:
            all_risks.extend(self.audit_api_security())
        except Exception as e:
            all_risks.append({
                "category": "api_security", "severity": "medium",
                "title": "API安全审计执行失败",
                "description": str(e), "suggestion": "检查模块导入",
            })

        try:
            all_risks.extend(self.audit_access_control())
        except Exception as e:
            all_risks.append({
                "category": "access_control", "severity": "medium",
                "title": "访问控制审计执行失败",
                "description": str(e), "suggestion": "检查模块导入",
            })

        try:
            all_risks.extend(self.audit_data_protection())
        except Exception as e:
            all_risks.append({
                "category": "data_protection", "severity": "medium",
                "title": "数据保护审计执行失败",
                "description": str(e), "suggestion": "检查模块导入",
            })

        try:
            hardcoded = self.check_hardcoded_secrets()
            for h in hardcoded:
                all_risks.append({
                    "category": "hardcoded_secrets",
                    "severity": h["severity"],
                    "title": f"硬编码{h['match_type']}在{h['file_path']}:{h['line_number']}",
                    "description": f"匹配内容: {h['matched_content']}",
                    "suggestion": "使用环境变量或配置文件管理密钥",
                })
        except Exception as e:
            all_risks.append({
                "category": "hardcoded_secrets", "severity": "medium",
                "title": "硬编码密钥扫描失败",
                "description": str(e), "suggestion": "检查文件读取权限",
            })

        try:
            deps = self.check_dependencies()
            for d in deps:
                all_risks.append({
                    "category": "dependencies",
                    "severity": d["severity"],
                    "title": f"漏洞依赖: {d['package']}",
                    "description": d["description"],
                    "suggestion": f"升级{d['package']}到{d['fixed_version']}或更高",
                })
        except Exception as e:
            all_risks.append({
                "category": "dependencies", "severity": "medium",
                "title": "依赖检查失败",
                "description": str(e), "suggestion": "检查requirements.txt",
            })

        # 按严重程度排序
        severity_order = {"critical": 0, "high": 1, "medium": 2, "low": 3}
        all_risks.sort(key=lambda r: severity_order.get(r.get("severity", "low"), 9))

        # 计算安全评分
        score = 100
        for risk in all_risks:
            sev = risk.get("severity", "low")
            if sev == "critical":
                score -= 15
            elif sev == "high":
                score -= 8
            elif sev == "medium":
                score -= 3
            elif sev == "low":
                score -= 1
        score = max(0, min(100, score))

        report = {
            "audit_time": datetime.now().isoformat(),
            "project_root": self.project_root,
            "total_risks": len(all_risks),
            "risk_summary": {
                "critical": sum(1 for r in all_risks if r.get("severity") == "critical"),
                "high": sum(1 for r in all_risks if r.get("severity") == "high"),
                "medium": sum(1 for r in all_risks if r.get("severity") == "medium"),
                "low": sum(1 for r in all_risks if r.get("severity") == "low"),
            },
            "security_score": score,
            "risks": all_risks,
        }

        # 保存报告
        report_path = os.path.join(_DATA_DIR, "self_audit_report.json")
        try:
            with open(report_path, "w", encoding="utf-8") as f:
                json.dump(report, f, indent=2, ensure_ascii=False)
        except IOError:
            pass

        return report


# 全局实例
_self_auditor_instance: Optional[SelfAuditor] = None


def get_self_auditor() -> SelfAuditor:
    """获取全局SelfAuditor实例（单例模式）。"""
    global _self_auditor_instance
    if _self_auditor_instance is None:
        _self_auditor_instance = SelfAuditor()
    return _self_auditor_instance
