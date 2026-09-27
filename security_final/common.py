# -*- coding: utf-8 -*-
"""
common.py — security_final 包内共享工具。

提供：
    * 项目根目录定位
    * 受限于规模的 Python / 前端 / 配置文件遍历
    * 递归控制字符清理（_clean）
    * 轻量正则式危险模式匹配（供 SAST / 注入检测复用）
    * 真实项目文件扫描能力

所有函数均为只读扫描，不修改任何项目文件。
"""

from __future__ import annotations

import os
import re
from typing import Any, Dict, Iterable, List, Optional

# --------------------------------------------------------------------------- #
# 项目根定位：security_final/ 位于项目根下一级
# --------------------------------------------------------------------------- #
PROJECT_ROOT: str = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

# 扫描时跳过的目录（虚拟环境 / 缓存 / 构建产物）
_SKIP_DIRS = {
    ".git", ".hg", ".svn", "__pycache__", ".pytest_cache", ".mypy_cache",
    ".venv", "venv", "env", "node_modules", "dist", "build", ".idea",
    ".vscode", "screenshots", "logs", "scan_results", "backup",
}

# 单次扫描最多读取的文件数
MAX_FILES_PY = 1500
MAX_FILES_WEB = 500
MAX_FILES_CONF = 300
MAX_FILE_BYTES = 400_000  # 单文件读取上限 400KB


def get_project_root() -> str:
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


def count_project_files(ext: str, max_files: int = 5000) -> int:
    """统计项目中指定扩展名的文件数量。"""
    count = 0
    for _ in iter_project_files(ext, max_files):
        count += 1
    return count


# --------------------------------------------------------------------------- #
# 递归清理控制字符
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
# 危险模式库（SAST / 注入检测共用）— 最终版增强
# --------------------------------------------------------------------------- #
DANGEROUS_PATTERNS: List[Dict[str, Any]] = [
    {"id": "PY-EVAL-001", "severity": "critical", "title": "使用 eval() 执行动态代码",
     "cwe": "CWE-95", "owasp": "A03", "pattern": re.compile(r"\beval\s*\("),
     "fix": "避免 eval，使用 ast.literal_eval 或白名单解析"},
    {"id": "PY-EXEC-001", "severity": "critical", "title": "使用 exec() 执行动态代码",
     "cwe": "CWE-95", "owasp": "A03", "pattern": re.compile(r"\bexec\s*\("),
     "fix": "避免 exec，重构为显式分发逻辑"},
    {"id": "PY-SHELL-001", "severity": "high", "title": "subprocess 使用 shell=True",
     "cwe": "CWE-78", "owasp": "A03", "pattern": re.compile(r"subprocess\.[a-zA-Z_]+\([^)]*shell\s*=\s*True"),
     "fix": "使用列表形式传参并设置 shell=False"},
    {"id": "PY-OS-SYSTEM", "severity": "high", "title": "os.system() 调用",
     "cwe": "CWE-78", "owasp": "A03", "pattern": re.compile(r"\bos\.system\s*\("),
     "fix": "改用 subprocess.run([...], shell=False) 并校验输入"},
    {"id": "PY-SQL-STR", "severity": "high", "title": "SQL 语句字符串拼接",
     "cwe": "CWE-89", "owasp": "A03",
     "pattern": re.compile(r"(SELECT|INSERT|UPDATE|DELETE|DROP)\s+.*%|f\"[^\"]*(SELECT|INSERT|UPDATE|DELETE)"),
     "fix": "使用参数化查询 / ORM 占位符"},
    {"id": "PY-PICKLE", "severity": "high", "title": "使用 pickle 反序列化",
     "cwe": "CWE-502", "owasp": "A08", "pattern": re.compile(r"\bpickle\.loads?\s*\("),
     "fix": "改用 JSON 等安全格式，或对来源做签名校验"},
    {"id": "PY-MD5", "severity": "medium", "title": "使用 MD5 弱哈希",
     "cwe": "CWE-327", "owasp": "A02", "pattern": re.compile(r"hashlib\.md5\s*\("),
     "fix": "密码场景改用 bcrypt/argon2；完整性用 SHA-256"},
    {"id": "PY-SHA1", "severity": "medium", "title": "使用 SHA1 弱哈希",
     "cwe": "CWE-327", "owasp": "A02", "pattern": re.compile(r"hashlib\.sha1\s*\("),
     "fix": "改用 SHA-256 及以上"},
    {"id": "PY-RAND", "severity": "medium", "title": "random 模块用于安全场景",
     "cwe": "CWE-330", "owasp": "A02", "pattern": re.compile(r"[^a-zA-Z_]random\.(random|randint|choice|seed)\s*\("),
     "fix": "令牌 / 密钥改用 secrets 模块"},
    {"id": "PY-REQ-VERIFY", "severity": "medium", "title": "requests 未校验 TLS 证书",
     "cwe": "CWE-295", "owasp": "A02", "pattern": re.compile(r"verify\s*=\s*False"),
     "fix": "生产环境 verify=True，自签证书指定 CA bundle"},
    {"id": "PY-CSRF-OFF", "severity": "high", "title": "CSRF 校验被关闭",
     "cwe": "CWE-352", "owasp": "A01", "pattern": re.compile(r"csrf\s*protect|csrf_enabled\s*=\s*False|WTF_CSRF_ENABLED.*False", re.I),
     "fix": "默认开启 CSRF 防护"},
    {"id": "PY-DEBUG", "severity": "high", "title": "应用开启调试模式",
     "cwe": "CWE-489", "owasp": "A05", "pattern": re.compile(r"debug\s*=\s*True\b"),
     "fix": "生产环境关闭 debug，通过环境变量控制"},
    {"id": "PY-PASS-PLAIN", "severity": "critical", "title": "疑似硬编码密码",
     "cwe": "CWE-798", "owasp": "A02",
     "pattern": re.compile(r"(password|passwd|pwd|secret|api[_-]?key|token)\s*=\s*[\"'][^\"'\s]{6,}[\"']", re.I),
     "fix": "密钥从环境变量 / 密钥管理服务读取，禁止入库"},
    {"id": "PY-JINJA-ESC", "severity": "high", "title": "Jinja2 模板 autoescape 关闭",
     "cwe": "CWE-116", "owasp": "A03", "pattern": re.compile(r"autoescape\s*=\s*False"),
     "fix": "默认开启 autoescape，对富文本单独白名单"},
    {"id": "PY-PATH-TRAVERSAL", "severity": "high", "title": "疑似路径遍历风险",
     "cwe": "CWE-22", "owasp": "A01",
     "pattern": re.compile(r"open\s*\(\s*[^)]*request\.|open\s*\(\s*[^)]*\+\s*(request|params|args)"),
     "fix": "对文件路径做规范化并限制在允许目录内"},
    {"id": "PY-SSRF", "severity": "high", "title": "疑似 SSRF 风险",
     "cwe": "CWE-918", "owasp": "A10",
     "pattern": re.compile(r"requests\.(get|post|put)\s*\(\s*(request|url|target|callback)"),
     "fix": "对出站请求 URL 做白名单校验"},
    {"id": "PY-CORS-WILD", "severity": "medium", "title": "CORS 通配符允许所有源",
     "cwe": "CWE-942", "owasp": "A05",
     "pattern": re.compile(r"(CORS_ORIGINS|allow_origins)\s*[:=]\s*[\[\"']\*"),
     "fix": "生产环境限制为可信域名列表"},
    {"id": "PY-NO-LIMIT", "severity": "low", "title": "缺乏速率限制",
     "cwe": "CWE-770", "owasp": "A04",
     "pattern": re.compile(r"throttle|rate_limit|Limiter"),
     "fix": "关键端点添加速率限制"},
]


# --------------------------------------------------------------------------- #
# 硬编码密钥 / 敏感信息正则
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
    {"id": "CARD", "title": "疑似信用卡号", "re": r"\b(?:\d[ -]*?){13,19}\b"},
    {"id": "DB-CONN", "title": "数据库连接串", "re": r"(mysql|postgresql|mongodb|redis)://[^\s\"']+:[^\s\"']+@"},
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


# --------------------------------------------------------------------------- #
# CWE Top 25 映射
# --------------------------------------------------------------------------- #
CWE_TOP25: List[Dict[str, str]] = [
    {"id": "CWE-79", "name": "跨站脚本", "risk": "high"},
    {"id": "CWE-787", "name": "基于堆栈的缓冲区溢出", "risk": "critical"},
    {"id": "CWE-89", "name": "SQL 注入", "risk": "critical"},
    {"id": "CWE-20", "name": "输入验证不当", "risk": "high"},
    {"id": "CWE-125", "name": "越界读取", "risk": "high"},
    {"id": "CWE-78", "name": "操作系统命令注入", "risk": "critical"},
    {"id": "CWE-416", "name": "释放后使用", "risk": "high"},
    {"id": "CWE-22", "name": "路径遍历", "risk": "high"},
    {"id": "CWE-352", "name": "跨站请求伪造", "risk": "medium"},
    {"id": "CWE-434", "name": "危险类型文件无限制上传", "risk": "high"},
    {"id": "CWE-502", "name": "不可信数据反序列化", "risk": "critical"},
    {"id": "CWE-287", "name": "认证不当", "risk": "high"},
    {"id": "CWE-190", "name": "整数溢出/环绕", "risk": "medium"},
    {"id": "CWE-732", "name": "关键资源权限分配不当", "risk": "medium"},
    {"id": "CWE-476", "name": "空指针解引用", "risk": "medium"},
    {"id": "CWE-94", "name": "代码生成控制不当(代码注入)", "risk": "critical"},
    {"id": "CWE-862", "name": "缺失授权", "risk": "high"},
    {"id": "CWE-400", "name": "不受控资源消耗(DoS)", "risk": "medium"},
    {"id": "CWE-269", "name": "权限管理不当", "risk": "high"},
    {"id": "CWE-59", "name": "链接跟随", "risk": "medium"},
    {"id": "CWE-77", "name": "命令注入", "risk": "critical"},
    {"id": "CWE-120", "name": "缓冲区复制未检查输入大小", "risk": "high"},
    {"id": "CWE-306", "name": "关键功能缺失认证", "risk": "critical"},
    {"id": "CWE-863", "name": "授权不正确", "risk": "high"},
    {"id": "CWE-918", "name": "服务端请求伪造(SSRF)", "risk": "high"},
]


# --------------------------------------------------------------------------- #
# 真实项目扫描辅助
# --------------------------------------------------------------------------- #
def scan_project_danger_patterns() -> List[Dict[str, Any]]:
    """真实扫描当前项目 Python 代码中的危险模式。"""
    findings: List[Dict[str, Any]] = []
    files_py = list(iter_project_files(".py", MAX_FILES_PY))
    for pattern_def in DANGEROUS_PATTERNS:
        for filepath in files_py:
            text = read_text_safe(filepath)
            if not text:
                continue
            for m in pattern_def["pattern"].finditer(text):
                line_no = text[:m.start()].count("\n") + 1
                findings.append({
                    "rule_id": pattern_def["id"],
                    "severity": pattern_def["severity"],
                    "title": pattern_def["title"],
                    "cwe": pattern_def["cwe"],
                    "owasp": pattern_def.get("owasp", "A05"),
                    "file": relpath(filepath),
                    "line": line_no,
                    "match": m.group(0)[:120],
                    "fix": pattern_def["fix"],
                })
                if len(findings) > 500:
                    return findings
    return findings


def scan_project_secrets() -> List[Dict[str, Any]]:
    """真实扫描当前项目中的敏感信息泄露。"""
    findings: List[Dict[str, Any]] = []
    compiled = compile_secret_patterns()
    files_py = list(iter_project_files(".py", MAX_FILES_PY))
    files_conf = list(iter_project_files(".env", 50)) + list(iter_project_files(".yaml", 100)) + list(iter_project_files(".yml", 100))
    all_files = files_py + files_conf
    for filepath in all_files:
        text = read_text_safe(filepath)
        if not text:
            continue
        for sp in compiled:
            for m in sp["re"].finditer(text):
                line_no = text[:m.start()].count("\n") + 1
                findings.append({
                    "type": sp["title"],
                    "file": relpath(filepath),
                    "line": line_no,
                    "match_preview": m.group(0)[:40] + "..." if len(m.group(0)) > 40 else m.group(0),
                    "severity": "high" if "PRIVATE" in sp["id"] or "KEY" in sp["id"] else "medium",
                })
                if len(findings) > 300:
                    return findings
    return findings


def scan_project_config_issues() -> List[Dict[str, Any]]:
    """真实检查项目配置安全问题。"""
    issues: List[Dict[str, Any]] = []
    root = PROJECT_ROOT

    # 检查 .env 文件权限敏感信息
    env_path = os.path.join(root, ".env")
    if os.path.exists(env_path):
        text = read_text_safe(env_path)
        if "DEBUG=True" in text or "DEBUG = True" in text:
            issues.append({"check": "DEBUG模式", "status": "fail",
                           "detail": ".env 中存在 DEBUG=True", "severity": "high"})
        if "SECRET_KEY=" in text:
            line = [l for l in text.split("\n") if "SECRET_KEY=" in l]
            if line and len(line[0].split("=")[-1].strip()) < 32:
                issues.append({"check": "SECRET_KEY长度", "status": "warn",
                               "detail": "SECRET_KEY 长度不足32位", "severity": "medium"})
        issues.append({"check": ".env文件存在", "status": "info",
                       "detail": ".env 文件已配置（确认不入库）", "severity": "info"})

    # 检查 requirements.txt 依赖
    req_path = os.path.join(root, "requirements.txt")
    if os.path.exists(req_path):
        text = read_text_safe(req_path)
        pkg_count = len([l for l in text.split("\n") if l.strip() and not l.startswith("#")])
        issues.append({"check": "依赖包数量", "status": "info",
                       "detail": f"requirements.txt 包含 {pkg_count} 个依赖包", "severity": "info"})

    # 检查 docker-compose 安全配置
    dc_path = os.path.join(root, "docker-compose.yml")
    if os.path.exists(dc_path):
        text = read_text_safe(dc_path)
        if "user: root" in text or "user: 0:0" in text:
            issues.append({"check": "容器运行用户", "status": "warn",
                           "detail": "容器以 root 用户运行", "severity": "medium"})
        issues.append({"check": "docker-compose存在", "status": "info",
                       "detail": "已配置 docker-compose", "severity": "info"})

    # 检查 CORS / 安全头配置
    app_py = os.path.join(root, "api_server", "app.py")
    if os.path.exists(app_py):
        text = read_text_safe(app_py)
        if "allow_origins" in text and ("*" in text or "allow_credentials=True" in text):
            issues.append({"check": "CORS配置", "status": "warn",
                           "detail": "CORS 配置可能过于宽松", "severity": "medium"})
        if "TrustedHostMiddleware" not in text:
            issues.append({"check": "主机名验证", "status": "warn",
                           "detail": "未配置 TrustedHostMiddleware", "severity": "low"})

    if not issues:
        issues.append({"check": "配置扫描", "status": "ok",
                       "detail": "未发现明显配置问题", "severity": "info"})
    return issues
