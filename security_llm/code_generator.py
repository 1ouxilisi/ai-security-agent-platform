#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
code_generator.py — 安全代码生成引擎（第26轮升级方向1）。

六大能力：
    1. 代码生成：根据需求生成安全代码（Python/JS/Java/Go）
    2. 代码审查：静态安全审查，发现注入/XSS/硬编码等问题
    3. 代码解释：解释代码逻辑与安全含义
    4. 代码转换：语言转换/框架迁移
    5. 代码测试：生成安全单元测试
    6. 代码知识库：安全编码规范库

全部内存字典模拟，仅用于授权安全场景。
"""
from __future__ import annotations

import re
import uuid
from datetime import datetime
from typing import Any, Dict, List, Optional


def _now() -> str:
    return datetime.now().isoformat(timespec="seconds")


def _gen_id(prefix: str) -> str:
    return f"{prefix}-{uuid.uuid4().hex[:10]}"


# 安全编码知识库
_SEC_CODING_KB: List[Dict[str, Any]] = [
    {"id": "cc-001", "language": "python", "rule": "参数化查询",
     "bad": "cursor.execute(f\"SELECT * FROM users WHERE name='{name}'\")",
     "good": "cursor.execute(\"SELECT * FROM users WHERE name=%s\", (name,))"},
    {"id": "cc-002", "language": "python", "rule": "禁用 pickle",
     "bad": "data = pickle.loads(user_input)",
     "good": "data = json.loads(user_input)  # 使用JSON安全反序列化"},
    {"id": "cc-003", "language": "python", "rule": "禁用 eval/exec",
     "bad": "result = eval(user_input)",
     "good": "# 用 ast.literal_eval 或白名单函数映射"},
    {"id": "cc-004", "language": "javascript", "rule": "XSS 输出编码",
     "bad": "element.innerHTML = userInput",
     "good": "element.textContent = userInput  # 或使用 DOMPurify"},
    {"id": "cc-005", "language": "javascript", "rule": "禁止 innerHTML 拼接",
     "bad": "el.innerHTML = '<img src=' + url + '>'",
     "good": "const img = document.createElement('img'); img.src = sanitizeUrl(url);"},
    {"id": "cc-006", "language": "java", "rule": "禁用 Runtime.exec 拼接",
     "bad": "Runtime.getRuntime().exec(\"ls \" + userInput)",
     "good": "new ProcessBuilder(\"ls\", safeInput).start()  # 参数分离"},
    {"id": "cc-007", "language": "java", "rule": "安全随机数",
     "bad": "Random r = new Random();  // 可预测",
     "good": "SecureRandom r = SecureRandom.getInstanceStrong();"},
    {"id": "cc-008", "language": "go", "rule": "SQL 占位符",
     "bad": "db.Query(\"SELECT * FROM users WHERE id=\" + id)",
     "good": "db.Query(\"SELECT * FROM users WHERE id = ?\", id)"},
    {"id": "cc-009", "language": "通用", "rule": "密码哈希",
     "bad": "hashlib.md5(password.encode()).hexdigest()",
     "good": "bcrypt.hashpw(password.encode(), bcrypt.gensalt(12))"},
    {"id": "cc-010", "language": "通用", "rule": "错误信息不泄露堆栈",
     "bad": "except Exception as e: return str(e)",
     "good": "logger.exception(e); return {'error': 'internal_error', 'code': 500}"},
]


class CodeGenerator:
    """安全代码生成引擎。"""

    def __init__(self) -> None:
        self.history: List[Dict[str, Any]] = []
        self.review_history: List[Dict[str, Any]] = []
        self.test_history: List[Dict[str, Any]] = []
        self.kb: List[Dict[str, Any]] = list(_SEC_CODING_KB)

    # ==================== 1. 代码生成 ====================
    def generate(self, requirement: str, language: str = "python") -> Dict[str, Any]:
        """根据需求生成安全代码（真实模板生成）。"""
        lang = language.lower()
        code = self._gen_code(requirement, lang)
        result = {
            "id": _gen_id("gen"), "requirement": requirement,
            "language": lang, "code": code,
            "security_notes": self._security_notes(lang),
            "lines": code.count("\n") + 1, "ts": _now(),
        }
        self.history.append(result)
        return result

    def _gen_code(self, requirement: str, lang: str) -> str:
        r = requirement
        if "login" in r.lower() or "登录" in r:
            if lang == "python":
                return (
                    "import bcrypt\n"
                    "from fastapi import HTTPException\n\n"
                    "def login(username: str, password: str, db) -> dict:\n"
                    "    # 输入校验\n"
                    "    if not username or not password:\n"
                    "        raise HTTPException(400, 'missing fields')\n"
                    "    user = db.query('SELECT * FROM users WHERE username=%s', (username,))\n"
                    "    if not user:\n"
                    "        raise HTTPException(401, 'invalid credentials')\n"
                    "    # bcrypt 校验密码\n"
                    "    if not bcrypt.checkpw(password.encode(), user['pw_hash'].encode()):\n"
                    "        raise HTTPException(401, 'invalid credentials')\n"
                    "    return {'token': issue_jwt(user['id']), 'user_id': user['id']}\n"
                )
            if lang == "javascript":
                return (
                    "const bcrypt = require('bcrypt');\n"
                    "async function login(req, res) {\n"
                    "  const {username, password} = req.body;\n"
                    "  if (!username || !password) return res.status(400).json({error:'missing'});\n"
                    "  const user = await db.findUser(username);\n"
                    "  if (!user || !await bcrypt.compare(password, user.pwHash))\n"
                    "    return res.status(401).json({error:'invalid'});\n"
                    "  const token = signJwt(user.id);\n"
                    "  res.json({token});\n"
                    "}\n"
                )
        if "upload" in r.lower() or "上传" in r:
            return (
                "ALLOWED_EXT = {'.png', '.jpg', '.pdf'}\n"
                "MAX_SIZE = 5 * 1024 * 1024\n\n"
                "def upload(file):\n"
                "    if file.size > MAX_SIZE:\n"
                "        raise ValueError('file too large')\n"
                "    ext = os.path.splitext(file.name)[1].lower()\n"
                "    if ext not in ALLOWED_EXT:\n"
                "        raise ValueError('extension not allowed')\n"
                "    # 生成随机文件名，避免路径穿越\n"
                "    safe_name = secrets.token_hex(16) + ext\n"
                "    file.save(os.path.join(UPLOAD_DIR, safe_name))\n"
                "    return safe_name\n"
            )
        if "api" in r.lower() or "接口" in r:
            return (
                "from fastapi import FastAPI, Depends, HTTPException\n"
                "from pydantic import BaseModel, Field\n\n"
                "app = FastAPI()\n\n"
                "class QueryIn(BaseModel):\n"
                "    keyword: str = Field(..., min_length=1, max_length=100)\n\n"
                "@app.post('/api/search')\n"
                "def search(body: QueryIn, user=Depends(auth_required)):\n"
                "    # 参数化查询，防 SQL 注入\n"
                "    rows = db.query(\n"
                "        'SELECT id, title FROM articles WHERE title LIKE %s LIMIT 20',\n"
                "        (f'%{body.keyword}%',))\n"
                "    return {'results': rows}\n"
            )
        # 默认模板
        return (
            f"# 需求：{r}\n"
            f"# 语言：{lang}\n"
            "def handle_request(data: dict) -> dict:\n"
            "    # 1. 输入校验\n"
            "    if not isinstance(data, dict):\n"
            "        raise ValueError('invalid input')\n"
            "    # 2. 鉴权\n"
            "    if not data.get('auth'):\n"
            "        raise PermissionError('unauthorized')\n"
            "    # 3. 业务逻辑（参数化、不拼接 SQL）\n"
            "    result = process(data)\n"
            "    # 4. 安全响应（不泄露内部错误）\n"
            "    return {'success': True, 'data': result}\n"
        )

    def _security_notes(self, lang: str) -> List[str]:
        notes = [
            "所有数据库查询使用参数化占位符，禁止字符串拼接",
            "用户输入必须经过类型校验和长度限制",
            "错误响应不返回堆栈信息，仅返回错误码",
            "敏感数据（密码）使用 bcrypt/argon2 哈希存储",
        ]
        if lang == "javascript":
            notes.append("前端输出使用 textContent 或 DOMPurify，禁止 innerHTML 拼接")
        if lang == "python":
            notes.append("禁止使用 eval/exec/pickle.loads，使用 json/ast.literal_eval")
        return notes

    def list_generations(self) -> List[Dict[str, Any]]:
        return self.history[-50:]

    # ==================== 2. 代码审查 ====================
    def review(self, code: str, language: str = "python") -> Dict[str, Any]:
        """真实静态安全审查：规则匹配检测常见漏洞模式。"""
        findings: List[Dict[str, Any]] = []
        checks = self._review_rules(language.lower())
        for rule in checks:
            pattern = rule["pattern"]
            m = re.search(pattern, code)
            if m:
                line_no = code[:m.start()].count("\n") + 1
                findings.append({
                    "rule": rule["name"], "severity": rule["severity"],
                    "line": line_no, "snippet": m.group(0)[:80],
                    "fix": rule["fix"],
                })
        risk = "high" if any(f["severity"] == "critical" for f in findings) else (
            "medium" if findings else "low")
        result = {
            "id": _gen_id("rev"), "language": language,
            "findings": findings, "total": len(findings),
            "risk_level": risk, "score": max(0, 100 - len(findings) * 10),
            "ts": _now(),
        }
        self.review_history.append(result)
        return result

    def _review_rules(self, lang: str) -> List[Dict[str, Any]]:
        rules = []
        if lang in ("python", "py"):
            rules = [
                {"name": "SQL拼接注入", "pattern": r"(execute|query)\s*\(\s*[\"'][^\"']*\+",
                 "severity": "critical", "fix": "使用参数化查询 %s 占位符"},
                {"name": "eval 危险调用", "pattern": r"\beval\s*\(",
                 "severity": "critical", "fix": "使用 ast.literal_eval 或白名单映射"},
                {"name": "exec 危险调用", "pattern": r"\bexec\s*\(",
                 "severity": "high", "fix": "禁止 exec，重构为函数调用"},
                {"name": "pickle 反序列化", "pattern": r"pickle\.loads?\s*\(",
                 "severity": "high", "fix": "使用 json.loads 替代"},
                {"name": "MD5 弱哈希", "pattern": r"md5\s*\(",
                 "severity": "medium", "fix": "密码使用 bcrypt/argon2"},
                {"name": "硬编码密钥", "pattern": r"(password|secret|api_key)\s*=\s*[\"'][^\"']{8,}[\"']",
                 "severity": "high", "fix": "从环境变量或密钥管理服务读取"},
            ]
        elif lang in ("javascript", "js", "typescript", "ts"):
            rules = [
                {"name": "innerHTML XSS", "pattern": r"\.innerHTML\s*=",
                 "severity": "critical", "fix": "使用 textContent 或 DOMPurify"},
                {"name": "eval 调用", "pattern": r"\beval\s*\(",
                 "severity": "critical", "fix": "禁止 eval"},
                {"name": "危险重定向", "pattern": r"window\.location\s*=\s*[^;]*user",
                 "severity": "high", "fix": "使用 URL 白名单校验"},
            ]
        elif lang in ("java",):
            rules = [
                {"name": "命令拼接", "pattern": r"Runtime\.getRuntime\(\)\.exec\s*\([^)]*\+",
                 "severity": "critical", "fix": "使用 ProcessBuilder 参数分离"},
                {"name": "Random 弱随机", "pattern": r"\bnew\s+Random\s*\(",
                 "severity": "medium", "fix": "使用 SecureRandom"},
            ]
        return rules

    def list_reviews(self) -> List[Dict[str, Any]]:
        return self.review_history[-50:]

    # ==================== 3. 代码解释 ====================
    def explain(self, code: str, language: str = "python") -> Dict[str, Any]:
        lines = code.split("\n")
        structure = []
        for i, line in enumerate(lines[:30], 1):
            stripped = line.strip()
            if stripped.startswith("def ") or stripped.startswith("function ") or stripped.startswith("class "):
                structure.append({"line": i, "type": "定义", "content": stripped})
            elif "import " in stripped or "require(" in stripped:
                structure.append({"line": i, "type": "依赖", "content": stripped})
            elif stripped.startswith("#") or stripped.startswith("//"):
                structure.append({"line": i, "type": "注释", "content": stripped})
        return {
            "id": _gen_id("exp"), "language": language,
            "total_lines": len(lines), "structure": structure,
            "summary": f"该{language}代码共{len(lines)}行，包含{len([s for s in structure if s['type']=='定义'])}个函数/类定义。",
            "ts": _now(),
        }

    # ==================== 4. 代码转换 ====================
    def convert(self, code: str, from_lang: str, to_lang: str) -> Dict[str, Any]:
        """模拟语言转换：生成目标语言等价模板。"""
        converted = self._convert_template(code, from_lang.lower(), to_lang.lower())
        return {
            "id": _gen_id("conv"), "from": from_lang, "to": to_lang,
            "original_lines": code.count("\n") + 1,
            "converted_code": converted,
            "ts": _now(),
        }

    def _convert_template(self, code: str, src: str, dst: str) -> str:
        if src == "python" and dst == "javascript":
            return (
                "// 自动转换自 Python，请人工复核安全逻辑\n"
                "async function handleRequest(data) {\n"
                "  if (typeof data !== 'object') throw new Error('invalid input');\n"
                "  if (!data.auth) throw new Error('unauthorized');\n"
                "  const result = await process(data);\n"
                "  return {success: true, data: result};\n"
                "}\n"
            )
        if src == "python" and dst == "go":
            return (
                "// 自动转换自 Python，请人工复核安全逻辑\n"
                "func handleRequest(data map[string]interface{}) (map[string]interface{}, error) {\n"
                "    if data == nil { return nil, fmt.Errorf(\"invalid input\") }\n"
                "    if _, ok := data[\"auth\"]; !ok { return nil, fmt.Errorf(\"unauthorized\") }\n"
                "    result := process(data)\n"
                "    return map[string]interface{}{\"success\": true, \"data\": result}, nil\n"
                "}\n"
            )
        return f"// {dst} 转换结果：请人工适配。原代码行数: {code.count(chr(10))}"

    # ==================== 5. 代码测试 ====================
    def gen_tests(self, code: str, language: str = "python") -> Dict[str, Any]:
        tests = [
            {"name": "test_input_validation", "scenario": "空输入应拒绝",
             "assert": "assert result == 400"},
            {"name": "test_auth_required", "scenario": "未授权应拒绝",
             "assert": "assert result == 401"},
            {"name": "test_sql_injection_safe", "scenario": "SQL注入 payload 不影响查询",
             "assert": "assert len(results) == 0"},
            {"name": "test_xss_sanitized", "scenario": "<script>标签被转义",
             "assert": "assert '<script>' not in output"},
        ]
        result = {
            "id": _gen_id("test"), "language": language,
            "tests": tests, "coverage_est": 0.78,
            "ts": _now(),
        }
        self.test_history.append(result)
        return result

    def list_tests(self) -> List[Dict[str, Any]]:
        return self.test_history[-50:]

    # ==================== 6. 代码知识库 ====================
    def list_kb(self, language: Optional[str] = None) -> List[Dict[str, Any]]:
        if language:
            return [k for k in self.kb if k["language"] == language.lower()]
        return self.kb

    def kb_search(self, query: str) -> List[Dict[str, Any]]:
        q = query.lower()
        return [k for k in self.kb if q in k["rule"].lower()
                or q in k["language"].lower()
                or q in k["good"].lower()]


# 单例
code_generator = CodeGenerator()
