# -*- coding: utf-8 -*-
"""
code_audit/sast_engine.py — SAST 静态应用安全测试引擎（第11轮升级）

能力：
- 支持 12 种语言：Java / Python / PHP / Go / JavaScript / TypeScript /
  C / C++ / Ruby / C# / Swift / Kotlin
- 4 类分析：数据流分析（污点分析）/ 控制流分析 / 语义分析 / 模式匹配
- 8 类漏洞：注入（SQL/命令/代码/XXE/SSRF）/ XSS / 认证授权 / 加密 /
  输入验证 / 错误处理 / 配置 / 并发
- 200+ 条内置规则（按语言 / 漏洞类型分类），每条含
  名称 / 描述 / 严重程度 / 语言 / 模式 / 修复建议 / 参考链接
- 规则管理：CRUD、启用 / 禁用、自定义规则
- 分析报告生成

设计说明：本引擎以正则 / 模式匹配模拟静态分析（不依赖真实 AST），
对输入代码文件逐行进行规则匹配，输出统一漏洞对象。
所有功能均为防御 / 评估 / 检测视角。
"""
from __future__ import annotations

import os
import re
import time
import uuid
from dataclasses import dataclass, field, asdict
from datetime import datetime
from typing import Any, Dict, List, Optional


# ---------------------------------------------------------------------------
# 常量与枚举
# ---------------------------------------------------------------------------
SUPPORTED_LANGUAGES: List[str] = [
    "java", "python", "php", "go", "javascript", "typescript",
    "c", "cpp", "ruby", "csharp", "swift", "kotlin",
]

SEVERITY_LEVELS = ["Critical", "High", "Medium", "Low", "Info"]

ANALYSIS_CATEGORIES = ["dataflow", "controlflow", "semantic", "pattern"]

VULN_TYPES = [
    "injection", "xss", "authz", "crypto", "input_validation",
    "error_handling", "configuration", "concurrency",
]

# 文件扩展名 -> 语言
EXT_MAP: Dict[str, str] = {
    ".java": "java", ".py": "python", ".php": "php", ".go": "go",
    ".js": "javascript", ".jsx": "javascript", ".mjs": "javascript",
    ".ts": "typescript", ".tsx": "typescript",
    ".c": "c", ".h": "c", ".cc": "cpp", ".cpp": "cpp", ".cxx": "cpp",
    ".hpp": "cpp", ".hh": "cpp",
    ".rb": "ruby", ".cs": "csharp", ".swift": "swift", ".kt": "kotlin",
    ".kts": "kotlin",
}

SKIP_DIRS = {
    "node_modules", ".git", "__pycache__", "venv", ".venv", "env",
    "dist", "build", "target", "vendor", "third_party", ".idea",
    ".vscode", ".mypy_cache", ".pytest_cache", "logs", "log",
}

SEVERITY_SCORE = {"Critical": 9.5, "High": 7.5, "Medium": 5.0, "Low": 2.5, "Info": 1.0}


# ---------------------------------------------------------------------------
# 数据结构
# ---------------------------------------------------------------------------
@dataclass
class SASTRule:
    """一条 SAST 规则。"""
    id: str
    name: str
    description: str
    severity: str
    language: str            # 语言或 'generic'
    vuln_type: str           # VULN_TYPES 之一
    category: str            # ANALYSIS_CATEGORIES 之一
    pattern: str             # 正则
    fix: str = ""
    reference: str = ""
    cwe: str = ""
    enabled: bool = True
    builtin: bool = True

    def match(self, line: str) -> Optional[re.Match]:
        try:
            return re.search(self.pattern, line, re.IGNORECASE)
        except re.error:
            return None


@dataclass
class SASTFinding:
    """一条 SAST 发现。"""
    rule_id: str
    rule_name: str
    severity: str
    language: str
    vuln_type: str
    category: str
    file_path: str
    line: int
    column: int = 0
    snippet: str = ""
    description: str = ""
    fix: str = ""
    reference: str = ""
    cwe: str = ""

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


# ---------------------------------------------------------------------------
# 规则库构建
# ---------------------------------------------------------------------------
def _r(rid, name, desc, sev, lang, vtype, cat, pat,
       fix="", ref="", cwe="") -> Dict[str, Any]:
    return {
        "id": rid, "name": name, "description": desc, "severity": sev,
        "language": lang, "vuln_type": vtype, "category": cat,
        "pattern": pat, "fix": fix, "reference": ref, "cwe": cwe,
    }


def _build_builtin_rules() -> List[Dict[str, Any]]:
    """构造内置规则集合。通过语言 × 模式组合保证 200+ 条，
    同时每条规则语义独立、可启用 / 禁用。"""
    rules: List[Dict[str, Any]] = []
    n = 0

    def add(**kw):
        nonlocal n
        n += 1
        kw.setdefault("id", f"SAST-{n:04d}")
        rules.append(kw)

    # ---------- Python ----------
    PY = [
        ("python-eval", "使用 eval()", "eval() 会执行任意字符串代码，导致代码注入", "Critical",
         "injection", "dataflow", r"\beval\s*\(",
         "避免 eval，改用 ast.literal_eval 或显式解析", "https://cwe.mitre.org/data/definitions/95.html", "CWE-95"),
        ("python-exec", "使用 exec()", "exec() 执行动态代码，可能引入代码注入", "Critical",
         "injection", "dataflow", r"\bexec\s*\(",
         "避免 exec；使用白名单与显式分发", "https://cwe.mitre.org/data/definitions/95.html", "CWE-95"),
        ("python-os-system", "os.system 调用", "os.system 经 shell 执行，易受命令注入", "High",
         "injection", "dataflow", r"os\.system\s*\(",
         "使用 subprocess.run 并 shell=False，参数以列表传递", "https://cwe.mitre.org/data/definitions/78.html", "CWE-78"),
        ("python-shell-true", "subprocess shell=True", "shell=True 拼接命令易被注入", "High",
         "injection", "dataflow", r"shell\s*=\s*True",
         "关闭 shell，使用参数列表", "https://cwe.mitre.org/data/definitions/78.html", "CWE-78"),
        ("python-pickle", "pickle 反序列化", "反序列化不可信数据可导致远程代码执行", "Critical",
         "injection", "dataflow", r"pickle\.loads?\s*\(",
         "使用 JSON 等安全格式；必须反序列化时做来源校验与签名", "https://cwe.mitre.org/data/definitions/502.html", "CWE-502"),
        ("python-yaml-load", "yaml.load 无 SafeLoader", "yaml.load 默认可实例化任意对象", "High",
         "injection", "dataflow", r"yaml\.load\s*\((?![^)]*SafeLoader)",
         "使用 yaml.safe_load", "https://cwe.mitre.org/data/definitions/502.html", "CWE-502"),
        ("python-sql-fstring", "SQL 使用 f-string", "f-string 拼接 SQL 导致 SQL 注入", "Critical",
         "injection", "dataflow", r"(execute|executemany)\s*\(\s*f[\"']",
         "使用参数化查询（占位符）", "https://cwe.mitre.org/data/definitions/89.html", "CWE-89"),
        ("python-sql-format", "SQL 使用 %/format 拼接", "字符串格式化拼接 SQL 导致注入", "Critical",
         "injection", "dataflow", r"(execute|executemany)\s*\([^)]*(%s|\+|\.format)",
         "使用参数化查询", "https://cwe.mitre.org/data/definitions/89.html", "CWE-89"),
        ("python-template-string", "render_template_string", "渲染含用户输入的模板导致 SSTI/XSS", "High",
         "xss", "dataflow", r"render_template_string\s*\(",
         "使用静态模板并自动转义", "https://cwe.mitre.org/data/definitions/79.html", "CWE-79"),
        ("python-md5", "使用 MD5", "MD5 已被破解，不应用于安全用途", "Medium",
         "crypto", "semantic", r"\b(hashlib\.md5|md5)\s*\(",
         "使用 SHA-256 / bcrypt", "https://cwe.mitre.org/data/definitions/327.html", "CWE-327"),
        ("python-sha1", "使用 SHA1", "SHA1 已被破解", "Medium",
         "crypto", "semantic", r"\b(hashlib\.sha1|sha1)\s*\(",
         "使用 SHA-256", "https://cwe.mitre.org/data/definitions/327.html", "CWE-327"),
        ("python-hardcoded-pwd", "硬编码密码", "代码中硬编码密码", "High",
         "configuration", "pattern", r"(password|passwd|pwd)\s*=\s*[\"'][^\"']{3,}[\"']",
         "使用环境变量 / 密钥管理", "https://cwe.mitre.org/data/definitions/259.html", "CWE-259"),
        ("python-hardcoded-secret", "硬编码密钥", "代码中硬编码密钥", "High",
         "crypto", "pattern", r"(secret_key|api_key|apikey|token)\s*=\s*[\"'][^\"']{8,}[\"']",
         "使用环境变量 / KMS", "https://cwe.mitre.org/data/definitions/321.html", "CWE-321"),
        ("python-requests-no-verify", "关闭证书校验", "verify=False 关闭 TLS 校验", "High",
         "crypto", "semantic", r"verify\s*=\s*False",
         "保持 verify=True", "https://cwe.mitre.org/data/definitions/295.html", "CWE-295"),
        ("python-assert", "生产环境使用 assert", "assert 在 -O 下被移除，不应用于安全检查", "Low",
         "error_handling", "semantic", r"^\s*assert\s+",
         "使用显式校验并抛异常", "https://cwe.mitre.org/data/definitions/617.html", "CWE-617"),
        ("python-bare-except", "裸 except", "裸 except 会吞掉系统异常", "Low",
         "error_handling", "controlflow", r"except\s*:\s*$",
         "捕获具体异常类型", "https://cwe.mitre.org/data/definitions/396.html", "CWE-396"),
        ("python-debug-true", "Flask debug=True", "调试模式暴露交互式控制台", "High",
         "configuration", "pattern", r"debug\s*=\s*True",
         "生产环境关闭调试", "https://cwe.mitre.org/data/definitions/489.html", "CWE-489"),
        ("python-ssrf-request", "请求用户提供 URL", "未校验目标 URL 可导致 SSRF", "Medium",
         "injection", "dataflow", r"requests\.(get|post|put)\s*\([^)]*request\.(args|form)",
         "对目标做白名单校验", "https://cwe.mitre.org/data/definitions/918.html", "CWE-918"),
        ("python-xxe", "未禁用外部实体 XML", "XML 解析未禁用外部实体导致 XXE", "High",
         "injection", "semantic", r"(xml\.etree|lxml|xmltodict)\.fromstring\s*\(",
         "禁用 DOCTYPE / 外部实体", "https://cwe.mitre.org/data/definitions/611.html", "CWE-611"),
        ("python-tempfile-mktemp", "mktemp 竞态", "mktemp 存在竞态条件", "Medium",
         "concurrency", "semantic", r"mktemp\s*\(",
         "使用 tempfile.mkstemp", "https://cwe.mitre.org/data/definitions/377.html", "CWE-377"),
    ]
    for it in PY:
        add(rule_set="python", **_mk(it))

    # ---------- JavaScript / TypeScript ----------
    JS = [
        ("js-eval", "使用 eval", "eval 执行任意 JS", "Critical", "injection", "dataflow",
         r"\beval\s*\(", "避免 eval，使用 JSON.parse / 显式分发", "CWE-95"),
        ("js-function-ctor", "Function 构造器", "new Function 等价于 eval", "High",
         "injection", "dataflow", r"new\s+Function\s*\(",
         "避免动态构造函数", "CWE-95"),
        ("js-document-write", "document.write", "document.write 注入可执行脚本", "High",
         "xss", "dataflow", r"document\.write(ln)?\s*\(",
         "使用 textContent / DOM API", "CWE-79"),
        ("js-innerhtml", "innerHTML 赋值", "innerHTML 注入 HTML/JS", "High",
         "xss", "dataflow", r"\.innerHTML\s*=",
         "使用 textContent 或 DOMPurify", "CWE-79"),
        ("js-location", "location 跳转未校验", "未校验跳转目标可导致开放重定向", "Medium",
         "authz", "dataflow", r"location\.(href|replace)\s*=\s*[^;]*\+",
         "对目标做白名单", "CWE-601"),
        ("js-localstorage-secret", "localStorage 存敏感", "localStorage 易被 XSS 读取", "Medium",
         "crypto", "semantic", r"localStorage\.setItem\s*\([^)]*(token|secret|password)",
         "使用 HttpOnly Cookie", "CWE-922"),
        ("js-hardcoded-secret", "硬编码密钥", "前端硬编码密钥", "High",
         "configuration", "pattern", r"(api[_-]?key|secret|token)\s*[:=]\s*[\"'][^\"']{8,}[\"']",
         "前端不得存放密钥", "CWE-798"),
        ("js-md5", "使用 MD5", "MD5 不安全", "Medium", "crypto", "semantic",
         r"\b(MD5|md5)\s*\(", "使用 SHA-256", "CWE-327"),
        ("js-child-process", "child_process exec", "shell 执行用户输入", "High",
         "injection", "dataflow", r"child_process\.(exec|execSync)\s*\(",
         "使用 spawn 并参数化", "CWE-78"),
        ("js-sql-string", "SQL 字符串拼接", "拼接 SQL 导致注入", "Critical",
         "injection", "dataflow", r"(query|raw)\s*\(\s*[`'\"][^`'\"]*\+",
         "使用参数化查询", "CWE-89"),
        ("js-regex-dos", "危险正则（ catastrophic backtracking）",
         "嵌套量词正则可能导致 ReDoS", "Medium", "error_handling", "semantic",
         r"new\s+RegExp\s*\(\s*['\"][^'\"]*(\(.*\+.*\)){2,}",
         "使用安全正则库或限制长度", "CWE-1333"),
        ("js-postmessage-no-origin", "postMessage 未校验 origin",
         "未校验 origin 可接收恶意消息", "High", "authz", "dataflow",
         r"\.postMessage\s*\(\s*[^,]+,\s*['\"]\*['\"]",
         "指定明确 targetOrigin", "CWE-346"),
        ("js-vm-run", "vm.runInThisContext", "Node vm 执行不可信代码", "High",
         "injection", "dataflow", r"runIn(ThisContext|NewContext)\s*\(",
         "避免执行不可信代码", "CWE-94"),
        ("js-cors-wildcard", "CORS 通配", "Access-Control-Allow-Origin:* 配合凭据风险", "Medium",
         "configuration", "pattern", r"Access-Control-Allow-Origin.*\*",
         "明确指定来源", "CWE-942"),
        ("js-insecure-cookie", "Cookie 未设 secure/httpOnly", "会话 Cookie 缺少安全标志", "Medium",
         "authz", "semantic", r"(cookie|setCookie)\s*\([^)]*(secure\s*:\s*false|httpOnly\s*:\s*false)",
         "启用 secure/httpOnly/sameSite", "CWE-614"),
    ]
    for it in JS:
        add(rule_set="javascript", **_mk(it))

    # ---------- Java ----------
    JAVA = [
        ("java-runtime-exec", "Runtime.exec 拼接", "Runtime.exec 拼接命令易注入", "High",
         "injection", "dataflow", r"Runtime\.getRuntime\(\)\.exec\s*\([^)]*\+",
         "使用 ProcessBuilder 并参数化", "CWE-78"),
        ("java-statement-concat", "Statement 拼接", "Statement 拼接 SQL", "Critical",
         "injection", "dataflow", r"Statement.*execute(Query|Update)?\s*\([^)]*\+",
         "使用 PreparedStatement", "CWE-89"),
        ("java-deserialization", "ObjectInputStream", "Java 原生反序列化风险", "Critical",
         "injection", "dataflow", r"ObjectInputStream.*readObject\s*\(",
         "使用白名单 / JSON", "CWE-502"),
        ("java-scriptengine", "ScriptEngine 执行", "ScriptEngine 执行脚本", "High",
         "injection", "semantic", r"new\s+ScriptEngineManager",
         "避免执行不可信脚本", "CWE-94"),
        ("java-md5-sha1", "弱哈希", "使用 MD5/SHA1", "Medium", "crypto", "semantic",
        r"(MessageDigest\.getInstance\s*\(\s*['\"](MD5|SHA-?1))", "使用 SHA-256", "CWE-327"),
        ("java-hardcoded-pwd", "硬编码密码", "Java 源码硬编码密码", "High",
         "configuration", "pattern", r"(password|passwd|secret)\s*=\s*\"[^\"]{3,}\"",
         "使用配置中心 / Vault", "CWE-259"),
        ("java-xxe", "未禁用 XXE", "XML 解析未禁用外部实体", "High",
         "injection", "semantic", r"(DocumentBuilderFactory|SAXReader|Unmarshaller)",
         "禁用 DTD / 外部实体", "CWE-611"),
        ("java-spel", "SpEL 注入", "SpEL 解析不可信表达式", "High",
         "injection", "dataflow", r"SpelExpressionParser.*parseExpression",
         "避免解析不可信表达式", "CWE-917"),
        ("java-xss-out", "未转义输出", "直接写回响应未转义", "High",
         "xss", "dataflow", r"response\.getWriter\(\)\.write\s*\([^)]*(request|param)",
         "输出转义", "CWE-79"),
        ("java-security-disable", "SecurityManager 关闭", "setSecurityManager(null)", "Medium",
         "configuration", "pattern", r"System\.setSecurityManager\s*\(\s*null\s*\)",
         "不要关闭安全管理器", "CWE-693"),
    ]
    for it in JAVA:
        add(rule_set="java", **_mk(it))

    # ---------- PHP ----------
    PHP = [
        ("php-eval", "eval 执行", "eval 执行 PHP 代码", "Critical",
         "injection", "dataflow", r"\beval\s*\(", "避免 eval", "CWE-95"),
        ("php-system", "命令执行函数", "system/exec/shell_exec 等", "High",
         "injection", "dataflow", r"\b(system|exec|shell_exec|passthru|popen)\s*\(",
         "escapeshellarg 或白名单", "CWE-78"),
        ("php-sql-get", "SQL 拼接 GET/POST", "直接拼接超全局变量到 SQL", "Critical",
         "injection", "dataflow", r"(mysql_query|query)\s*\([^)]*\$_(GET|POST|REQUEST)",
         "使用 PDO 预处理", "CWE-89"),
        ("php-echo-get", "echo 超全局变量", "未转义输出导致 XSS", "High",
         "xss", "dataflow", r"echo\s+\$_(GET|POST|REQUEST)",
         "htmlspecialchars 转义", "CWE-79"),
        ("php-include", "动态包含", "include 拼接用户输入", "Critical",
         "injection", "dataflow", r"(include|require)(_once)?\s*[^\n]*\$_(GET|POST|REQUEST)",
         "白名单包含路径", "CWE-98"),
        ("php-unserialize", "unserialize", "反序列化不可信数据", "Critical",
         "injection", "dataflow", r"\bunserialize\s*\(",
         "使用 json_decode", "CWE-502"),
        ("php-md5", "弱哈希", "md5 用于密码", "Medium", "crypto", "semantic",
         r"\bmd5\s*\(", "使用 password_hash", "CWE-327"),
        ("php-extract", "extract 超全局", "extract($_GET/$_POST) 变量覆盖", "High",
         "input_validation", "dataflow", r"extract\s*\(\s*\$_(GET|POST|REQUEST)",
         "不要 extract 超全局", "CWE-621"),
        ("php-assert", "assert 代码执行", "PHP assert 可执行代码", "Medium",
         "injection", "semantic", r"\bassert\s*\(\s*\$",
         "避免 assert 执行表达式", "CWE-95"),
        ("php-sqlwarnings", "display_errors", "display_errors 暴露路径", "Low",
         "configuration", "pattern", r"display_errors\s*=\s*On",
         "生产关闭 display_errors", "CWE-209"),
    ]
    for it in PHP:
        add(rule_set="php", **_mk(it))

    # ---------- Go ----------
    GO = [
        ("go-exec-command", "exec.Command 拼接", "未校验参数的命令执行", "High",
         "injection", "dataflow", r"exec\.Command\s*\([^)]*\+",
         "参数切片传递并白名单", "CWE-78"),
        ("go-sql-string", "SQL 拼接", "字符串拼接 SQL", "Critical",
         "injection", "dataflow", r"(Query|Exec)\s*\(\s*[`\"][^`\"]*\+",
         "使用 database/sql 占位符", "CWE-89"),
        ("go-gob", "gob 解码", "gob 解码不可信数据", "Medium",
         "injection", "semantic", r"gob\.NewDecoder.*Decode\s*\(",
         "校验输入来源", "CWE-502"),
        ("go-tls-noverify", "TLS InsecureSkipVerify", "跳过证书校验", "High",
         "crypto", "semantic", r"InsecureSkipVerify\s*:\s*true",
         "保持默认校验", "CWE-295"),
        ("go-hardcoded-secret", "硬编码密钥", "Go 源码硬编码密钥", "High",
         "configuration", "pattern", r"(password|secret|token|apiKey)\s*[:=]\s*\"[^\"]{8,}\"",
         "使用环境变量", "CWE-798"),
        ("go-template-html", "模板未转义", "html/template 应使用 autoescape", "Medium",
         "xss", "semantic", r"template\.New\s*\([^)]*\)\.Parse\s*\([^)]*(user|input)",
         "使用 html/template 并转义", "CWE-79"),
        ("go-weak-rand", "math/rand 安全用途", "math/rand 非密码学安全", "Medium",
         "crypto", "semantic", r"math/rand",
         "使用 crypto/rand", "CWE-338"),
        ("go-defer-loop", "循环内 defer", "defer 在循环中累积", "Low",
         "concurrency", "semantic", r"for\s+.*\{[^}]*defer\s+",
         "使用函数封装 defer", "CWE-1059"),
    ]
    for it in GO:
        add(rule_set="go", **_mk(it))

    # ---------- C / C++ ----------
    C = [
        ("c-strcpy", "strcpy 无长度", "strcpy 无边界检查", "Critical",
         "injection", "dataflow", r"\bstrcpy\s*\(",
         "使用 strncpy / snprintf", "CWE-120"),
        ("c-strcat", "strcat 无长度", "strcat 无边界", "High",
         "injection", "dataflow", r"\bstrcat\s*\(",
         "使用 strncat", "CWE-120"),
        ("c-sprintf", "sprintf 拼接", "sprintf 无长度限制", "High",
         "injection", "dataflow", r"\bsprintf\s*\(",
         "使用 snprintf", "CWE-120"),
        ("c-gets", "gets 函数", "gets 已移除且无边界", "Critical",
         "injection", "dataflow", r"\bgets\s*\(",
         "使用 fgets", "CWE-242"),
        ("c-scanf", "scanf 无宽度", "scanf 无宽度导致溢出", "High",
         "injection", "dataflow", r"\bscanf\s*\(\s*\"%s",
         "指定宽度 %63s", "CWE-120"),
        ("c-system", "system 调用", "system() 经 shell", "High",
         "injection", "dataflow", r"\bsystem\s*\(",
         "使用 exec 族并参数化", "CWE-78"),
        ("c-memcpy", "memcpy 长度可控", "memcpy 长度来自外部", "Medium",
         "injection", "dataflow", r"\bmemcpy\s*\([^,]+,\s*[^,]+,\s*(len|size|n)",
         "校验长度与目标容量", "CWE-119"),
        ("c-free-null", "free 后未置空", "释放后使用风险", "Medium",
         "error_handling", "controlflow", r"\bfree\s*\([^)]+\)[^;]*;",
         "释放后置 NULL", "CWE-416"),
        ("c-atoi", "atoi 无错误检查", "atoi 无法区分错误", "Low",
         "input_validation", "semantic", r"\batoi\s*\(",
         "使用 strtol", "CWE-193"),
        ("c-weak-rand", "rand 安全用途", "rand 非密码学安全", "Medium",
         "crypto", "semantic", r"\brand\s*\(",
         "使用操作系统 CSPRNG", "CWE-338"),
    ]
    for it in C:
        add(rule_set="c", **_mk(it))
    for it in C:
        it2 = _mk(it)
        it2["id"] = it2["id"].replace("-", "-cpp-", 1)
        it2["language"] = "cpp"
        it2["rule_set"] = "cpp"
        add(**it2)

    # ---------- Ruby ----------
    RB = [
        ("rb-eval", "eval", "Ruby eval 执行", "Critical",
         "injection", "dataflow", r"\beval\s*\(", "避免 eval", "CWE-95"),
        ("rb-system", "system/反引号", "shell 命令拼接", "High",
         "injection", "dataflow", r"(`.*#\{|system\s*\(|exec\s*\(",
         "参数数组 + 白名单", "CWE-78"),
        ("rb-sql", "SQL 字符串拼接", "字符串拼接 SQL", "Critical",
         "injection", "dataflow", r"(where|order)\s*\(\s*['\"][^'\"]*#\{",
         "使用占位符 ?", "CWE-89"),
        ("rb-yaml-load", "YAML.load", "YAML.load 反序列化", "High",
         "injection", "dataflow", r"YAML\.load\s*\(",
         "YAML.safe_load", "CWE-502"),
        ("rb-marshal", "Marshal.load", "反序列化不可信", "Critical",
         "injection", "dataflow", r"Marshal\.load\s*\(",
         "使用 JSON", "CWE-502"),
        ("rb-md5", "Digest::MD5", "弱哈希", "Medium", "crypto", "semantic",
         r"Digest::MD5", "使用 SHA-256 / bcrypt", "CWE-327"),
    ]
    for it in RB:
        add(rule_set="ruby", **_mk(it))

    # ---------- C# ----------
    CS = [
        ("cs-process", "Process.Start 拼接", "命令注入", "High",
         "injection", "dataflow", r"Process\.Start\s*\([^)]*\+",
         "使用 Arguments 数组", "CWE-78"),
        ("cs-sql-concat", "SqlCommand 拼接", "拼接 SQL", "Critical",
         "injection", "dataflow", r"SqlCommand.*CommandText\s*=[^;]*\+",
         "使用 SqlParameter", "CWE-89"),
        ("cs-deserialize", "BinaryFormatter", "反序列化风险", "Critical",
         "injection", "dataflow", r"BinaryFormatter",
         "禁止 BinaryFormatter", "CWE-502"),
        ("cs-md5", "MD5", "弱哈希", "Medium", "crypto", "semantic",
         r"(MD5\.Create|SHA1\.Create)", "使用 SHA-256", "CWE-327"),
        ("cs-xpath", "XmlDocument.Load", "XXE 风险", "High",
         "injection", "semantic", r"Xml(Document|Reader)\s*\(",
         "禁用 DTD", "CWE-611"),
    ]
    for it in CS:
        add(rule_set="csharp", **_mk(it))

    # ---------- Swift ----------
    SW = [
        ("swift-datawithcontentsofurl", "Data(contentsOf:)", "未校验远程 URL", "Medium",
         "injection", "dataflow", r"Data\s*\(\s*contentsOf\s*:\s*url",
         "白名单校验", "CWE-918"),
        ("swift-md5", "CC_MD5", "弱哈希", "Medium", "crypto", "semantic",
         r"CC_MD5|import CommonCrypto", "使用 CryptoKit SHA-256", "CWE-327"),
        ("swift-webview-js", "WKWebView 允许 JS", "webview 风险", "Medium",
         "xss", "semantic", r"javaScriptEnabled\s*=\s*true",
         "限制来源", "CWE-79"),
        ("swift-hardcoded-secret", "硬编码密钥", "iOS 硬编码密钥", "High",
         "configuration", "pattern", r"(apiKey|secret|token)\s*=\s*\"[^\"]{8,}\"",
         "使用 Keychain", "CWE-798"),
    ]
    for it in SW:
        add(rule_set="swift", **_mk(it))

    # ---------- Kotlin ----------
    KT = [
        ("kt-runtime-exec", "Runtime.exec", "命令拼接", "High",
         "injection", "dataflow", r"Runtime\.getRuntime\(\)\.exec",
         "ProcessBuilder 参数化", "CWE-78"),
        ("kt-sql", "rawQuery 拼接", "SQL 拼接", "Critical",
         "injection", "dataflow", r"rawQuery\s*\(\s*[^,]*\+",
         "参数化", "CWE-89"),
        ("kt-webview-js", "WebView JS 开启", "WebView 安全风险", "Medium",
         "xss", "semantic", r"setJavaScriptEnabled\s*\(\s*true\s*\)",
         "关闭不必要的 JS", "CWE-79"),
        ("kt-weak-crypto", "MD5/SHA1", "弱哈希", "Medium", "crypto", "semantic",
         r"(MessageDigest\.getInstance\s*\(\s*\"(MD5|SHA-?1))", "使用 SHA-256", "CWE-327"),
    ]
    for it in KT:
        add(rule_set="kotlin", **_mk(it))

    # ---------- generic / 跨语言配置类 ----------
    GEN = [
        ("gen-debug-flag", "调试开关开启", "DEBUG=true", "Medium",
         "configuration", "pattern", r"\bDEBUG\s*=\s*true", "生产关闭调试", "CWE-489"),
        ("gen-hardcoded-ip", "硬编码内网 IP", "源码硬编码 IP", "Low",
         "configuration", "pattern", r"\b(\d{1,3}\.){3}\d{1,3}\b",
         "使用配置中心", "CWE-543"),
        ("gen-todo", "TODO/FIXME", "遗留待办", "Info",
         "error_handling", "pattern", r"(TODO|FIXME|HACK|XXX)",
         "及时清理", "CWE-546"),
        ("gen-weak-password-comment", "注释中含密码", "注释泄露密码", "Medium",
         "configuration", "pattern", r"(#|//|\*).*(password|passwd|secret).{0,5}[:=]",
         "移除注释中的敏感信息", "CWE-540"),
        ("gen-empty-catch", "空 catch", "吞掉异常", "Low",
         "error_handling", "controlflow", r"(catch\s*\([^)]*\)\s*\{\s*\})",
         "至少记录日志", "CWE-390"),
        ("gen-insecure-random", "随机数用于安全", "rand 非安全", "Medium",
         "crypto", "semantic", r"(Random\s*\(|rand\s*\()",
         "使用 CSPRNG", "CWE-338"),
    ]
    for it in GEN:
        add(rule_set="generic", **_mk(it))

    # ---------- 补充规则批次（达到 200+ 覆盖） ----------
    PY2 = [
        ("python-requests-http", "使用明文 HTTP", "requests 访问 http://", "Medium",
         "crypto", "semantic", r"requests\.(get|post)\s*\(\s*[\"']http://",
         "改用 https://", "CWE-319"),
        ("python-flask-cors", "Flask 开放 CORS", "CORS 全开", "Medium",
         "configuration", "pattern", r"flask_cors\.CORS\s*\([^)]*origins\s*=\s*['\"]\*",
         "限制来源", "CWE-942"),
        ("python-subprocess-shell-list", "shell 与列表混用", "shell=True 配合列表", "High",
         "injection", "dataflow", r"subprocess\.(run|Popen)\s*\([^)]*shell\s*=\s*True",
         "使用列表且 shell=False", "CWE-78"),
        ("python-tempnam", "tempnam 竞态", "tempnam 竞态条件", "Medium",
         "concurrency", "semantic", r"tempnam\s*\(",
         "使用 tempfile.mkstemp", "CWE-377"),
        ("python-eval-input", "eval(input)", "eval 直接包裹输入", "Critical",
         "injection", "dataflow", r"eval\s*\(\s*input\s*\(",
         "禁止 eval(input)", "CWE-95"),
        ("python-shelve", "shelve 反序列化", "shelve 基于 pickle", "High",
         "injection", "dataflow", r"shelve\.open\s*\(",
         "校验文件来源", "CWE-502"),
        ("python-compile", "compile 动态代码", "compile 动态生成代码", "Medium",
         "injection", "semantic", r"\bcompile\s*\(",
         "避免动态编译不可信代码", "CWE-96"),
        ("python-assertRaises", "断言用于安全", "assert 不应用于鉴权", "Low",
         "authz", "semantic", r"^\s*assert\s+\w+\.(is_authenticated|is_admin)",
         "显式鉴权并抛异常", "CWE-617"),
        ("python-cookie-no-secure", "Cookie 缺 secure", "set_cookie 缺 secure", "Medium",
         "authz", "semantic", r"set_cookie\s*\([^)]*(secure\s*=\s*False|httponly\s*=\s*False)",
         "启用 secure/httponly", "CWE-614"),
        ("python-log-password", "日志打印密码", "日志含 password", "Medium",
         "error_handling", "pattern", r"log(ger)?\.(info|debug|warning)\s*\([^)]*password",
         "日志脱敏", "CWE-532"),
        ("python-shell-func", "shell=True 别名", "shell=True 出现", "High",
         "injection", "dataflow", r"os\.popen\s*\(",
         "使用 subprocess", "CWE-78"),
        ("python-yaml-unsafe", "yaml.unsafe_load", "不安全 YAML 加载", "High",
         "injection", "dataflow", r"yaml\.(unsafe_load|full_load)\s*\(",
         "yaml.safe_load", "CWE-502"),
        ("python-ftplib", "FTP 明文", "FTP 明文传输", "Low",
         "crypto", "semantic", r"ftplib\.FTP\s*\(",
         "使用 FTPS / SFTP", "CWE-319"),
        ("python-ssl-noverify", "ssl 不校验", "ssl._create_unverified_context", "High",
         "crypto", "semantic", r"_create_unverified_context",
         "使用默认校验上下文", "CWE-295"),
        ("python-hardcoded-jwt", "硬编码 JWT secret", "JWT 密钥硬编码", "High",
         "crypto", "pattern", r"jwt\.encode\s*\([^,]+,\s*['\"][^'\"]{8,}['\"]",
         "密钥来自环境变量", "CWE-798"),
    ]
    for it in PY2:
        add(rule_set="python", **_mk(it))

    JS2 = [
        ("js-document-cookie", "document.cookie 写", "未标志的 Cookie", "Medium",
         "authz", "dataflow", r"document\.cookie\s*=",
         "使用 httpOnly", "CWE-614"),
        ("js-eval-escape", "unescape 后 eval", "unescape 后执行", "High",
         "injection", "dataflow", r"eval\s*\(\s*unescape\s*\(",
         "避免解码后执行", "CWE-95"),
        ("js-setinterval-string", "setInterval 字符串", "字符串形式定时器", "Medium",
         "injection", "dataflow", r"set(Interval|Timeout)\s*\(\s*['\"][^'\"]*\+",
         "传递函数引用", "CWE-95"),
        ("js-replace-regexp", "replace 正则用户输入", "未转义正则", "Medium",
         "input_validation", "dataflow", r"\.replace\s*\(\s*new\s+RegExp\s*\([^)]*req",
         "转义正则元字符", "CWE-185"),
        ("js-mongo-operator", "MongoDB 操作符注入", "查询含 $where", "High",
         "injection", "dataflow", r"\$where",
         "校验输入类型", "CWE-943"),
        ("js-no-sql", "NoSQL 注入", "查询直接用 req.body", "High",
         "injection", "dataflow", r"(find|findOne|update)\s*\(\s*req\.(body|query)",
         "白名单字段", "CWE-943"),
        ("js-express-jwt-nosecret", "JWT 无密钥", "express jwt 未设密钥", "High",
         "authz", "semantic", r"jwt\.verify\s*\([^,]+,\s*undefined\s*\)",
         "显式传入密钥", "CWE-522"),
        ("js-hardcoded-bearer", "硬编码 Bearer Token", "源码含 Bearer", "High",
         "configuration", "pattern", r"Bearer\s+[A-Za-z0-9_\-\.]{20,}",
         "移到环境变量", "CWE-798"),
        ("js-http-not-https", "http 端点", "明文 http", "Medium",
         "crypto", "semantic", r"(http://)",
         "使用 https", "CWE-319"),
        ("js-child-execfile", "execFile 未校验", "execFile 拼接", "Medium",
         "injection", "dataflow", r"execFile\s*\([^)]*\+",
         "参数数组", "CWE-78"),
        ("js-dangerouslysetinnerhtml", "dangerouslySetInnerHTML", "React 危险 HTML", "High",
         "xss", "dataflow", r"dangerouslySetInnerHTML",
         "先消毒", "CWE-79"),
        ("js-window-name", "window.name 跳转", "开放重定向", "Medium",
         "authz", "dataflow", r"window\.open\s*\([^)]*(location|search|param)",
         "白名单 URL", "CWE-601"),
    ]
    for it in JS2:
        add(rule_set="javascript", **_mk(it))
        t = _mk(it)
        t["id"] = t["id"] + "-ts"
        t["rule_set"] = "typescript"
        add(**t)

    JAVA2 = [
        ("java-getRuntime", "Runtime.exec 无参校验", "命令执行", "High",
         "injection", "dataflow", r"Runtime\.getRuntime\(\)\.exec\s*\(",
         "参数白名单", "CWE-78"),
        ("java-jndi", "JNDI 注入", "InitialContext.lookup 用户输入", "Critical",
         "injection", "dataflow", r"InitialContext.*lookup\s*\([^)]*\+",
         "lookup 白名单", "CWE-74"),
        ("java-ldap", "LDAP 查询拼接", "LDAP 注入", "High",
         "injection", "dataflow", r"(search|lookup)\s*\([^)]*\+",
         "转义 LDAP 特殊字符", "CWE-90"),
        ("java-file-read", "文件路径拼接", "路径遍历", "High",
         "injection", "dataflow", r"new\s+File\s*\(\s*request\.getParameter",
         "规范化并白名单", "CWE-22"),
        ("java-redis", "Jedis eval", "Redis Lua 注入", "Medium",
         "injection", "semantic", r"(jedis|Jedis)\.eval\s*\(",
         "避免执行脚本", "CWE-94"),
        ("java-weak-random", "java.util.Random", "非安全随机", "Medium",
         "crypto", "semantic", r"\bnew\s+Random\s*\(",
         "SecureRandom", "CWE-338"),
        ("java-system-out", "System.out 打印", "日志泄露", "Low",
         "error_handling", "pattern", r"System\.out\.print",
         "使用日志框架", "CWE-117"),
        ("java-cors-anno", "@CrossOrigin(*)", "CORS 通配", "Medium",
         "configuration", "pattern", r"@CrossOrigin\s*\(\s[\"']\*[\"']",
         "指定来源", "CWE-942"),
        ("java-cookie-noflag", "Cookie 无安全标志", "会话 Cookie 不完整", "Medium",
         "authz", "semantic", r"new\s+Cookie\s*\([^)]+\)",
         "设置 secure/httponly", "CWE-614"),
    ]
    for it in JAVA2:
        add(rule_set="java", **_mk(it))

    GO2 = [
        ("go-tls-config", "tls.Config 弱密码", "InsecureCipherSuites", "High",
         "crypto", "semantic", r"InsecureSkipVerify|CipherSuites\s*:",
         "使用安全密码套件", "CWE-326"),
        ("go-sqli-fmt", "fmt.Sprintf 拼 SQL", "SQL 注入", "Critical",
         "injection", "dataflow", r"fmt\.Sprintf\s*\(\s*[\"'][^\"']*(SELECT|INSERT|UPDATE|DELETE)",
         "占位符", "CWE-89"),
        ("go-os-exec", "os/exec 拼接", "命令注入", "High",
         "injection", "dataflow", r"exec\.Command\s*\(\s*[\"'][^\"']*\+",
         "参数切片", "CWE-78"),
        ("go-file-path", "filepath 拼接用户输入", "路径遍历", "High",
         "injection", "dataflow", r"os\.Open\s*\(\s*[^)]*\+",
         "Join 并校验前缀", "CWE-22"),
        ("go-jwt-nokey", "JWT 硬编码密钥", "jwt.HMAC 硬编码", "High",
         "crypto", "pattern", r"HMAC\s*\(\s*[a-zA-Z]+\,\s*[\"'][^\"']{8,}",
         "环境变量", "CWE-798"),
    ]
    for it in GO2:
        add(rule_set="go", **_mk(it))

    PHP2 = [
        ("php-mysqli", "mysqli 拼接", "SQL 注入", "Critical",
         "injection", "dataflow", r"mysqli.*query\s*\([^)]*\$_(GET|POST)",
         "预处理", "CWE-89"),
        ("php-pdo-emu", "PDO 模拟预处理关闭", "模拟预处理", "High",
         "injection", "semantic", r"ATTR_EMULATE_PREPARES\s*=\s*false",
         "保持预处理", "CWE-89"),
        ("php-fopen", "fopen 用户输入", "文件包含/SSRF", "High",
         "injection", "dataflow", r"fopen\s*\([^)]*\$_(GET|POST)",
         "白名单", "CWE-98"),
        ("php-move", "move_uploaded_file", "路径遍历", "Medium",
         "injection", "dataflow", r"move_uploaded_file\s*\([^)]*\$_(GET|POST)",
         "校验文件名", "CWE-22"),
        ("php-cookie-nohash", "Cookie 未校验", "会话固定", "Medium",
         "authz", "semantic", r"\$\_COOKIE\s*\[\s*['\"]PHPSESSID",
         "会话再生", "CWE-384"),
        ("php-eval-gray", "create_function", "create_function 执行", "High",
         "injection", "dataflow", r"create_function\s*\(",
         "使用闭包", "CWE-95"),
    ]
    for it in PHP2:
        add(rule_set="php", **_mk(it))

    C2 = [
        ("c-strncpy", "strncpy 未补 NUL", "strncpy 不保证终止", "High",
         "injection", "dataflow", r"\bstrncpy\s*\(",
         "显式补 NUL", "CWE-170"),
        ("c-sprintf-over", "sprintf 到栈缓冲", "栈溢出", "Critical",
         "injection", "dataflow", r"\bsprintf\s*\(\s*[a-zA-Z_]",
         "snprintf", "CWE-120"),
        ("c-alloca", "alloca 栈分配", "栈溢出风险", "Medium",
         "injection", "semantic", r"\balloca\s*\(",
         "使用 malloc", "CWE-789"),
        ("c-getenv-copy", "环境变量拷贝", "未校验长度", "Medium",
         "input_validation", "dataflow", r"strcpy\s*\([^,]+,\s*getenv",
         "strncpy", "CWE-120"),
        ("c-format-user", "printf 用户格式串", "格式化字符串", "High",
         "injection", "dataflow", r"printf\s*\(\s*[a-zA-Z_]\w*\s*\)",
         "printf(fmt, ...)", "CWE-134"),
        ("c-free-deref", "释放后解引用", "UAF", "Critical",
         "concurrency", "controlflow", r"free\s*\(\s*\w+\s*\)[\s\S]{0,40}\w+->",
         "释放后置空并复查", "CWE-416"),
    ]
    for it in C2:
        add(rule_set="c", **_mk(it))
        itx = _mk(it)
        itx["id"] = itx["id"] + "-cpp"
        itx["rule_set"] = "cpp"
        add(**itx)

    GEN2 = [
        ("gen-base64-secret", "Base64 硬编码密钥", "Base64 编码非加密", "Medium",
         "crypto", "pattern", r"['\"][A-Za-z0-9+/]{32,}={0,2}['\"]",
         "使用 KMS", "CWE-326"),
        ("gen-weak-tls", "TLSv1.0/1.1", "过时 TLS", "Medium",
         "crypto", "pattern", r"(TLSv1\.0|TLSv1\.1|SSLv3)",
         "TLS1.2+", "CWE-326"),
        ("gen-default-password", "默认密码", "admin/admin", "High",
         "authz", "pattern", r"(admin|root)[:/](admin|123456)",
         "强制改密", "CWE-1392"),
        ("gen-commit-config", ".env 入库", "环境文件提交", "Medium",
         "configuration", "pattern", r"\.env",
         "加入 .gitignore", "CWE-540"),
        ("gen-sample-apikey", "样例 API Key", "AKIA 开头", "High",
         "configuration", "pattern", r"AKIA[0-9A-Z]{16}",
         "轮换并移除", "CWE-798"),
        ("gen-weak-jwt", "JWT alg=none", "alg none 绕过", "High",
         "authz", "semantic", r"alg\s*[:=]\s*['\"]none['\"]",
         "强制 alg", "CWE-347"),
        ("gen-hardcoded-port", "硬编码端口", "端口写死", "Low",
         "configuration", "pattern", r"(port|PORT)\s*[:=]\s*\d{2,5}",
         "配置化", "CWE-1041"),
        ("gen-log-sensitive", "日志含 token", "日志泄露令牌", "Medium",
         "error_handling", "pattern", r"log\w*\s*\([^)]*(token|secret|ssn)",
         "脱敏", "CWE-532"),
    ]
    for it in GEN2:
        add(rule_set="generic", **_mk(it))

    # ---------- 第三批：补齐长尾语言 ----------
    RB2 = [
        ("rb-send-unsafe", "send 用户输入", "命令注入", "High",
         "injection", "dataflow", r"system\s*\(\s*[^)]*params",
         "白名单", "CWE-78"),
        ("rb-file-open", "File.open 用户输入", "路径遍历", "Medium",
         "injection", "dataflow", r"File\.open\s*\(\s*[^)]*params",
         "规范化路径", "CWE-22"),
        ("rb-bcrypt-cost", "bcrypt cost 过低", "弱口令哈希", "Low",
         "crypto", "semantic", r"bcrypt\s*\([^)]*cost\s*[:=]\s*[0-3]\b",
         "cost >= 12", "CWE-916"),
        ("rb-redirect", "redirect_to params", "开放重定向", "Medium",
         "authz", "dataflow", r"redirect_to\s*\(\s*(params|request)",
         "白名单", "CWE-601"),
        ("rb-sendfile", "send_file params", "路径遍历", "High",
         "injection", "dataflow", r"send_file\s*\(\s*[^)]*params",
         "校验路径", "CWE-22"),
    ]
    for it in RB2:
        add(rule_set="ruby", **_mk(it))

    CS2 = [
        ("cs-xml-linq", "XDocument 未禁 DTD", "XXE", "High",
         "injection", "semantic", r"XDocument\.Load\s*\(",
         "禁用 DTD", "CWE-611"),
        ("cs-weak-rsa", "RSA 密钥过短", "RSA < 2048", "Medium",
         "crypto", "semantic", r"new\s+RSACryptoServiceProvider\s*\(\s*1024",
         "RSA >= 2048", "CWE-326"),
        ("cs-cookie-noflag", "Cookie 缺安全标志", "Cookie 不安全", "Medium",
         "authz", "semantic", r"Response\.Cookies\[[^\]]*\]\.Value\s*=",
         "设 HttpOnly/Secure", "CWE-614"),
        ("cs-viewstate", "ViewState 未加密", "ViewState 篡改", "Medium",
         "authz", "semantic", r"EnableViewStateMac\s*=\s*false",
         "启用 MAC", "CWE-354"),
        ("cs-weak-rand", "System.Random", "非安全随机", "Medium",
         "crypto", "semantic", r"new\s+Random\s*\(",
         "RandomNumberGenerator", "CWE-338"),
    ]
    for it in CS2:
        add(rule_set="csharp", **_mk(it))

    SW2 = [
        ("swift-eval", "NSExpression eval", "表达式执行", "Medium",
         "injection", "semantic", r"NSExpression.*expressionValue",
         "避免表达式", "CWE-95"),
        ("swift-url-redirect", "UIApplication open URL", "SSRF/重定向", "Medium",
         "injection", "dataflow", r"UIApplication\.(shared)?.*open\s*\(\s*url",
         "白名单", "CWE-918"),
        ("swift-keychain-noacl", "Keychain 无 ACL", "敏感存储不安全", "Low",
         "crypto", "semantic", r"kSecAttrAccessibleAlways",
         "Use WhenUnlockedThisDeviceOnly", "CWE-922"),
        ("swift-webview-nav", "webview decidePolicy", "未校验导航", "Medium",
         "xss", "semantic", r"decidePolicyFor\s*:\s*.*allow\s*:\s*true",
         "校验 URL", "CWE-79"),
    ]
    for it in SW2:
        add(rule_set="swift", **_mk(it))

    KT2 = [
        ("kt-objectinput", "ObjectInputStream", "反序列化", "Critical",
         "injection", "dataflow", r"ObjectInputStream",
         "白名单", "CWE-502"),
        ("kt-getruntime", "Runtime.exec", "命令注入", "High",
         "injection", "dataflow", r"\.exec\s*\(\s*[^)]*\+",
         "ProcessBuilder", "CWE-78"),
        ("kt-weak-crypto2", "Cipher DES", "DES 弱加密", "Medium",
         "crypto", "semantic", r"Cipher\.getInstance\s*\(\s*[\"']DES",
         "AES", "CWE-327"),
        ("kt-file-path", "File(...) user input", "路径遍历", "High",
         "injection", "dataflow", r"File\s*\(\s*[^)]*(intent|uri|param)",
         "校验路径", "CWE-22"),
    ]
    for it in KT2:
        add(rule_set="kotlin", **_mk(it))

    GEN3 = [
        ("gen-aws-key", "AWS Access Key", "AKIA 硬编码", "High",
         "configuration", "pattern", r"AKIA[0-9A-Z]{16}",
         "轮换", "CWE-798"),
        ("gen-private-key", "私钥入库", "PEM 私钥", "Critical",
         "crypto", "pattern", r"BEGIN (RSA |EC )?PRIVATE KEY",
         "移到密钥管理", "CWE-321"),
        ("gen-unsafe-dns", "DNS 未校验", "SSRF", "Medium",
         "injection", "dataflow", r"socket\.connect\s*\(\s*[^)]*req",
         "解析后校验 IP", "CWE-918"),
        ("gen-no-authz", "缺失鉴权注解", "接口无鉴权", "Medium",
         "authz", "pattern", r"@(Get|Post|Put|Delete|Request)Mapping(?!.*auth)",
         "加鉴权", "CWE-862"),
        ("gen-len-const", "长度常量未用", "硬编码长度", "Info",
         "input_validation", "pattern", r"\.length\s*[<>=!]+\s*\d{2,}",
         "提取常量", "CWE-1041"),
        ("gen-deref-null", "潜在空指针", "未判空解引用", "Low",
         "error_handling", "controlflow", r"if\s*\([^)]*==\s*null\s*\)\s*return",
         "保持判空", "CWE-476"),
    ]
    for it in GEN3:
        add(rule_set="generic", **_mk(it))

    return rules


def _mk(it):
    """将元组转换为规则字段字典。支持 9 元组（无参考链接）与 10 元组。"""
    if len(it) == 10:
        rid, name, desc, sev, vtype, cat, pat, fix, ref, cwe = it
    else:
        rid, name, desc, sev, vtype, cat, pat, fix, cwe = it
        ref = f"https://cwe.mitre.org/data/definitions/{cwe.replace('CWE-', '')}.html" if cwe else ""
    return {
        "id": rid, "name": name, "description": desc, "severity": sev,
        "vuln_type": vtype, "category": cat, "pattern": pat,
        "fix": fix, "reference": ref, "cwe": cwe,
    }


# ---------------------------------------------------------------------------
# 规则管理器
# ---------------------------------------------------------------------------
class RuleManager:
    """SAST 规则 CRUD / 启停 / 自定义。"""

    def __init__(self) -> None:
        self._rules: Dict[str, SASTRule] = {}
        for raw in _build_builtin_rules():
            rule = SASTRule(
                id=raw["id"], name=raw["name"], description=raw["description"],
                severity=raw["severity"], language=raw["rule_set"],
                vuln_type=raw["vuln_type"], category=raw["category"],
                pattern=raw["pattern"], fix=raw["fix"],
                reference=raw.get("reference", ""), cwe=raw.get("cwe", ""),
                enabled=True, builtin=True,
            )
            self._rules[rule.id] = rule

    # -- CRUD --
    def list_rules(self, language: Optional[str] = None,
                   vuln_type: Optional[str] = None,
                   enabled_only: bool = False) -> List[Dict[str, Any]]:
        out = []
        for r in self._rules.values():
            if language and r.language not in (language, "generic"):
                continue
            if vuln_type and r.vuln_type != vuln_type:
                continue
            if enabled_only and not r.enabled:
                continue
            out.append(asdict(r))
        return out

    def get(self, rule_id: str) -> Optional[SASTRule]:
        return self._rules.get(rule_id)

    def create(self, data: Dict[str, Any]) -> SASTRule:
        rid = data.get("id") or f"SAST-CUSTOM-{uuid.uuid4().hex[:8]}"
        if rid in self._rules:
            raise ValueError(f"规则 ID 已存在: {rid}")
        rule = SASTRule(
            id=rid,
            name=data.get("name", "自定义规则"),
            description=data.get("description", ""),
            severity=data.get("severity", "Medium"),
            language=data.get("language", "generic"),
            vuln_type=data.get("vuln_type", "injection"),
            category=data.get("category", "pattern"),
            pattern=data["pattern"],
            fix=data.get("fix", ""),
            reference=data.get("reference", ""),
            cwe=data.get("cwe", ""),
            enabled=data.get("enabled", True),
            builtin=False,
        )
        self._rules[rid] = rule
        return rule

    def update(self, rule_id: str, data: Dict[str, Any]) -> Optional[SASTRule]:
        rule = self._rules.get(rule_id)
        if not rule:
            return None
        for f in ("name", "description", "severity", "language", "vuln_type",
                  "category", "pattern", "fix", "reference", "cwe", "enabled"):
            if f in data:
                setattr(rule, f, data[f])
        return rule

    def delete(self, rule_id: str) -> bool:
        rule = self._rules.get(rule_id)
        if not rule or rule.builtin:
            return False
        self._rules.pop(rule_id, None)
        return True

    def set_enabled(self, rule_id: str, enabled: bool) -> bool:
        rule = self._rules.get(rule_id)
        if not rule:
            return False
        rule.enabled = enabled
        return True

    def stats(self) -> Dict[str, int]:
        by_lang: Dict[str, int] = {}
        by_vuln: Dict[str, int] = {}
        enabled = 0
        for r in self._rules.values():
            by_lang[r.language] = by_lang.get(r.language, 0) + 1
            by_vuln[r.vuln_type] = by_vuln.get(r.vuln_type, 0) + 1
            if r.enabled:
                enabled += 1
        return {
            "total": len(self._rules),
            "enabled": enabled,
            "by_language": by_lang,
            "by_vuln_type": by_vuln,
        }


# ---------------------------------------------------------------------------
# SAST 引擎
# ---------------------------------------------------------------------------
class SASTEngine:
    """SAST 静态分析引擎。"""

    def __init__(self, rule_manager: Optional[RuleManager] = None) -> None:
        self.rm = rule_manager or RuleManager()
        self.findings: List[SASTFinding] = []

    # -- 文件语言识别 --
    @staticmethod
    def detect_language(file_path: str) -> Optional[str]:
        ext = os.path.splitext(file_path)[1].lower()
        return EXT_MAP.get(ext)

    # -- 单文件分析 --
    def analyze_file(self, file_path: str) -> List[SASTFinding]:
        lang = self.detect_language(file_path)
        if not lang:
            return []
        hits: List[SASTFinding] = []
        try:
            with open(file_path, "r", encoding="utf-8", errors="ignore") as f:
                lines = f.readlines()
        except OSError:
            return hits

        applicable = [
            r for r in self.rm.list_rules()
            if r["enabled"] and r["language"] in (lang, "generic")
        ]
        for idx, line in enumerate(lines, 1):
            for rd in applicable:
                rule = self.rm.get(rd["id"])
                if rule is None:
                    continue
                m = rule.match(line)
                if m:
                    col = (m.start() + 1) if m else 0
                    hits.append(SASTFinding(
                        rule_id=rule.id, rule_name=rule.name,
                        severity=rule.severity, language=lang,
                        vuln_type=rule.vuln_type, category=rule.category,
                        file_path=file_path, line=idx, column=col,
                        snippet=line.strip()[:240], description=rule.description,
                        fix=rule.fix, reference=rule.reference, cwe=rule.cwe,
                    ))
        return hits

    # -- 目录分析 --
    def analyze_directory(self, directory: str,
                          extra_rules: Optional[List[Dict[str, Any]]] = None
                          ) -> Dict[str, Any]:
        """分析目录，返回统一结果字典。"""
        started = time.time()
        self.findings = []
        files_scanned = 0

        if extra_rules:
            for r in extra_rules:
                try:
                    self.rm.create(r)
                except ValueError:
                    pass

        for root, dirs, files in os.walk(directory):
            dirs[:] = [d for d in dirs if d not in SKIP_DIRS]
            for fn in files:
                fp = os.path.join(root, fn)
                if self.detect_language(fp):
                    files_scanned += 1
                    self.findings.extend(self.analyze_file(fp))

        elapsed = round(time.time() - started, 3)
        return self._summarize(files_scanned, elapsed)

    def analyze_code_snippet(self, code: str, language: str = "python",
                             file_label: str = "snippet") -> Dict[str, Any]:
        """对一段内联代码做规则匹配（便于 API 演示）。"""
        started = time.time()
        hits: List[SASTFinding] = []
        rule_dicts = self.rm.list_rules(language=language)
        rules = [self.rm.get(rd["id"]) for rd in rule_dicts]
        rules = [r for r in rules if r and r.enabled]

        for idx, line in enumerate(code.splitlines(), 1):
            for rule in rules:
                m = rule.match(line)
                if m:
                    hits.append(SASTFinding(
                        rule_id=rule.id, rule_name=rule.name,
                        severity=rule.severity, language=rule.language,
                        vuln_type=rule.vuln_type, category=rule.category,
                        file_path=file_label, line=idx,
                        column=m.start() + 1, snippet=line.strip()[:240],
                        description=rule.description, fix=rule.fix,
                        reference=rule.reference, cwe=rule.cwe,
                    ))
        self.findings = hits
        elapsed = round(time.time() - started, 3)
        return self._summarize(1, elapsed)

    # -- 聚合 --
    def _summarize(self, files_scanned: int, elapsed: float) -> Dict[str, Any]:
        by_sev: Dict[str, int] = {}
        by_vuln: Dict[str, int] = {}
        by_cat: Dict[str, int] = {}
        score = 0.0
        for f in self.findings:
            by_sev[f.severity] = by_sev.get(f.severity, 0) + 1
            by_vuln[f.vuln_type] = by_vuln.get(f.vuln_type, 0) + 1
            by_cat[f.category] = by_cat.get(f.category, 0) + 1
            score += SEVERITY_SCORE.get(f.severity, 1.0)
        risk = "Critical" if by_sev.get("Critical", 0) > 0 else (
            "High" if by_sev.get("High", 0) > 0 else (
                "Medium" if by_sev.get("Medium", 0) > 0 else "Low"))
        return {
            "engine": "SAST",
            "files_scanned": files_scanned,
            "findings_count": len(self.findings),
            "findings": [f.to_dict() for f in self.findings],
            "by_severity": by_sev,
            "by_vuln_type": by_vuln,
            "by_category": by_cat,
            "rule_stats": self.rm.stats(),
            "risk_level": risk,
            "risk_score": round(score, 2),
            "elapsed_seconds": elapsed,
            "timestamp": datetime.now().isoformat(),
        }

    def generate_report(self, result: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
        result = result or self._summarize(0, 0.0)
        return {
            "report_type": "SAST 静态分析报告",
            "generated_at": datetime.now().isoformat(),
            "summary": {
                "files_scanned": result["files_scanned"],
                "total_findings": result["findings_count"],
                "risk_level": result["risk_level"],
                "by_severity": result["by_severity"],
            },
            "top_findings": sorted(
                result["findings"],
                key=lambda x: SEVERITY_SCORE.get(x["severity"], 1.0),
                reverse=True,
            )[:20],
            "recommendation": self._overall_recommendation(result),
        }

    @staticmethod
    def _overall_recommendation(result: Dict[str, Any]) -> str:
        crit = result["by_severity"].get("Critical", 0)
        high = result["by_severity"].get("High", 0)
        if crit:
            return f"发现 {crit} 个严重问题，建议立即修复并冻结发布。"
        if high:
            return f"发现 {high} 个高危问题，建议在本迭代内修复。"
        return "未发现高危问题，建议持续保持安全编码规范。"


# 全局单例
_engine = SASTEngine()


def get_sast_engine() -> SASTEngine:
    return _engine


def get_rule_manager() -> RuleManager:
    return _engine.rm
