# -*- coding: utf-8 -*-
"""
common.py — self_security 包内共享工具。

提供：
    * 项目根目录定位
    * 受限于规模的 Python / 前端 / 配置文件遍历
    * 递归控制字符清理（_clean）
    * 轻量正则式危险模式匹配（供 SAST / 注入检测复用）

所有函数均为只读扫描，不修改任何项目文件。
"""

from __future__ import annotations

import os
import re
from typing import Any, Dict, Iterable, List, Optional

# --------------------------------------------------------------------------- #
# 项目根定位：self_security/ 位于项目根下一级
# --------------------------------------------------------------------------- #
PROJECT_ROOT: str = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

# 扫描时跳过的目录（虚拟环境 / 缓存 / 构建产物）
_SKIP_DIRS = {
    ".git", ".hg", ".svn", "__pycache__", ".pytest_cache", ".mypy_cache",
    ".venv", "venv", "env", "node_modules", "dist", "build", ".idea",
    ".vscode", "screenshots", "logs", "scan_results", "backup",
}

# 单次扫描最多读取的文件数（避免 30 万行规模时 OOM）
MAX_FILES_PY = 1200
MAX_FILES_WEB = 400
MAX_FILES_CONF = 200
MAX_FILE_BYTES = 400_000  # 单文件读取上限 400KB


def clean_project_root() -> str:
    return PROJECT_ROOT


# --------------------------------------------------------------------------- #
# 文件遍历
# --------------------------------------------------------------------------- #
def iter_project_files(ext: str, max_files: int, root: Optional[str] = None) -> Iterable[str]:
    """惰性遍历项目中指定扩展名的文件（跳过噪声目录）。"""
    root = root or PROJECT_ROOT
    count = 0
    for dirpath, dirnames, filenames in os.walk(root):
        dirnames[:] = [d for d in dirnames if d not in _SKIP_DIRS and not d.startswith(".")]
        for fn in filenames:
            if not fn.endswith(ext):
                continue
            full = os.path.join(dirpath, fn)
            try:
                if os.path.getsize(full) > MAX_FILE_BYTES:
                    continue
            except OSError:
                continue
            yield full
            count += 1
            if count >= max_files:
                return


def read_text_safe(path: str, limit: int = MAX_FILE_BYTES) -> str:
    try:
        with open(path, "r", encoding="utf-8", errors="replace") as f:
            return f.read(limit)
    except OSError:
        return ""


def relpath(path: str) -> str:
    try:
        return os.path.relpath(path, PROJECT_ROOT)
    except ValueError:
        return path


# --------------------------------------------------------------------------- #
# 递归清理控制字符（与 data_security_routes._clean 等价的包内版本）
# --------------------------------------------------------------------------- #
_CTRL_RE = re.compile(r"[\x00-\x08\x0b\x0c\x0e-\x1f\x7f]")


def clean(obj: Any) -> Any:
    """递归清理字符串中的控制字符，防止 JSON 序列化 / UTF-8 编码失败。"""
    if isinstance(obj, str):
        return _CTRL_RE.sub("", obj)
    if isinstance(obj, dict):
        return {clean(k): clean(v) for k, v in obj.items()}
    if isinstance(obj, (list, tuple)):
        cleaned = [clean(v) for v in obj]
        return tuple(cleaned) if isinstance(obj, tuple) else cleaned
    return obj


# --------------------------------------------------------------------------- #
# 危险模式库（SAST / 注入检测共用）
# --------------------------------------------------------------------------- #
# (规则ID, 严重级别, 标题, CWE, 编译正则, 修复建议)
DANGEROUS_PATTERNS: List[Dict[str, Any]] = [
    {"id": "PY-EVAL-001", "severity": "critical", "title": "使用 eval() 执行动态代码",
     "cwe": "CWE-95", "pattern": re.compile(r"\beval\s*\("),
     "fix": "避免 eval，使用 ast.literal_eval 或白名单解析"},
    {"id": "PY-EXEC-001", "severity": "critical", "title": "使用 exec() 执行动态代码",
     "cwe": "CWE-95", "pattern": re.compile(r"\bexec\s*\("),
     "fix": "避免 exec，重构为显式分发逻辑"},
    {"id": "PY-SHELL-001", "severity": "high", "title": "subprocess 使用 shell=True",
     "cwe": "CWE-78", "pattern": re.compile(r"subprocess\.[a-zA-Z_]+\([^)]*shell\s*=\s*True"),
     "fix": "使用列表形式传参并设置 shell=False"},
    {"id": "PY-OS-SYSTEM", "severity": "high", "title": "os.system() 调用",
     "cwe": "CWE-78", "pattern": re.compile(r"\bos\.system\s*\("),
     "fix": "改用 subprocess.run([...], shell=False) 并校验输入"},
    {"id": "PY-SQL-STR", "severity": "high", "title": "SQL 语句字符串拼接",
     "cwe": "CWE-89", "pattern": re.compile(r"(SELECT|INSERT|UPDATE|DELETE|DROP)\s+.*%|f\"[^\"]*(SELECT|INSERT|UPDATE|DELETE)"),
     "fix": "使用参数化查询 / ORM 占位符"},
    {"id": "PY-PICKLE", "severity": "high", "title": "使用 pickle 反序列化",
     "cwe": "CWE-502", "pattern": re.compile(r"\bpickle\.loads?\s*\("),
     "fix": "改用 JSON 等安全格式，或对来源做签名校验"},
    {"id": "PY-MD5", "severity": "medium", "title": "使用 MD5 弱哈希",
     "cwe": "CWE-327", "pattern": re.compile(r"hashlib\.md5\s*\("),
     "fix": "密码场景改用 bcrypt/argon2；完整性用 SHA-256"},
    {"id": "PY-SHA1", "severity": "medium", "title": "使用 SHA1 弱哈希",
     "cwe": "CWE-327", "pattern": re.compile(r"hashlib\.sha1\s*\("),
     "fix": "改用 SHA-256 及以上"},
    {"id": "PY-RAND", "severity": "medium", "title": "random 模块用于安全场景",
     "cwe": "CWE-330", "pattern": re.compile(r"[^a-zA-Z_]random\.(random|randint|choice|seed)\s*\("),
     "fix": "令牌 / 密钥改用 secrets 模块"},
    {"id": "PY-RE-COMPILE", "severity": "low", "title": "正则可能存在 ReDoS 风险",
     "cwe": "CWE-1333", "pattern": re.compile(r"re\.compile\s*\([^)]*(\.\*\+|\.\*\{|\(\.\*)"),
     "fix": "限制回溯，使用原子组或超时"},
    {"id": "PY-REQ-VERIFY", "severity": "medium", "title": "requests 未校验 TLS 证书",
     "cwe": "CWE-295", "pattern": re.compile(r"verify\s*=\s*False"),
     "fix": "生产环境 verify=True，自签证书指定 CA bundle"},
    {"id": "PY-CSRF-OFF", "severity": "high", "title": "CSRF 校验被关闭",
     "cwe": "CWE-352", "pattern": re.compile(r"csrf\s*protect|csrf_enabled\s*=\s*False|WTF_CSRF_ENABLED.*False", re.I),
     "fix": "默认开启 CSRF 防护"},
    {"id": "PY-DEBUG", "severity": "high", "title": "应用开启调试模式",
     "cwe": "CWE-489", "pattern": re.compile(r"debug\s*=\s*True\b"),
     "fix": "生产环境关闭 debug，通过环境变量控制"},
    {"id": "PY-PASS-PLAIN", "severity": "critical", "title": "疑似硬编码密码",
     "cwe": "CWE-798",
     "pattern": re.compile(r"(password|passwd|pwd|secret|api[_-]?key|token)\s*=\s*[\"'][^\"'\s]{6,}[\"']", re.I),
     "fix": "密钥从环境变量 / 密钥管理服务读取，禁止入库"},
    {"id": "PY-TMP", "severity": "low", "title": "使用固定临时文件路径",
     "cwe": "CWE-377", "pattern": re.compile(r"(/tmp/[a-zA-Z0-9_.-]+|os\.tmpnam\s*\()"),
     "fix": "使用 tempfile.mkstemp / NamedTemporaryFile"},
    {"id": "PY-EVAL-JINJA", "severity": "high", "title": "Jinja2 模板 autoescape 关闭",
     "cwe": "CWE-116", "pattern": re.compile(r"autoescape\s*=\s*False"),
     "fix": "默认开启 autoescape，对富文本单独白名单"},
]


# --------------------------------------------------------------------------- #
# 硬编码密钥 / 敏感信息正则（供敏感信息泄露扫描）
# --------------------------------------------------------------------------- #
SECRET_PATTERNS: List[Dict[str, str]] = [
    {"id": "AWS-AK", "title": "AWS Access Key", "re": r"AKIA[0-9A-Z]{16}"},
    {"id": "GH-TOKEN", "title": "GitHub Token", "re": r"gh[pousr]_[A-Za-z0-9]{36,}"},
    {"id": "SLACK", "title": "Slack Webhook/Token", "re": r"xox[baprs]-[0-9a-zA-Z-]{10,}"},
    {"id": "JWT", "title": "JWT Token 形态", "re": r"eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}"},
    {"id": "PRIVATE-KEY", "title": "PEM 私钥块", "re": r"-----BEGIN (RSA |EC |OPENSSH |DSA )?PRIVATE KEY-----"},
    {"id": "APIKEY-HEX", "title": "疑似 API Key 长串", "re": r"(api[_-]?key|secret|token)\s*[:=]\s*[\"'][A-Za-z0-9_\-]{24,}[\"']"},
    {"id": "PRIVATE-IP", "title": "内网 IP 地址", "re": r"\b(10\.\d{1,3}\.\d{1,3}\.\d{1,3}|192\.168\.\d{1,3}\.\d{1,3}|172\.(1[6-9]|2\d|3[01])\.\d{1,3}\.\d{1,3})\b"},
    {"id": "EMAIL", "title": "邮箱地址（PII）", "re": r"[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}"},
    {"id": "PHONE-CN", "title": "中国大陆手机号", "re": r"\b1[3-9]\d{9}\b"},
    {"id": "IDCARD-CN", "title": "中国大陆身份证号", "re": r"\b\d{17}[0-9Xx]\b"},
    {"id": "CARD", "title": "疑似信用卡号", "re": r"\b(?:\d[ -]*?){13,19}\b"},
]


def compile_secret_patterns() -> List[Dict[str, Any]]:
    out = []
    for item in SECRET_PATTERNS:
        try:
            out.append({"id": item["id"], "title": item["title"],
                        "re": re.compile(item["re"])})
        except re.error:
            continue
    return out
