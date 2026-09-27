# -*- coding: utf-8 -*-
"""
错误处理 / 代码质量静态审计脚本。

扫描项目根目录下所有 .py 文件（排除 venv/.git/__pycache__/site-packages/测试目录），
用 ast 模块做语法分析，检测以下问题：

    - bare except：`except:`（未指定异常类型）
    - 静默异常：`except: pass` / `except Exception: pass`
    - 硬编码绝对路径（C:\\、/home/、/Users/ 等）
    - 硬编码密钥/密码（password= / secret= / api_key= 后跟字符串字面量）
    - requests 调用缺少 timeout 参数
    - 字典直接下标访问（dict[key]，未用 get）
    - 未使用的 import（简单检测）

输出：
    - scripts/error_audit_report.json
    - 控制台按严重程度分组汇总

用法：
    python scripts/error_audit.py           # 只审计
    python scripts/error_audit.py --fix      # 自动修复可安全修复的问题
"""
from __future__ import annotations

import os
import sys
import ast
import json
import time
import argparse
from pathlib import Path
from collections import defaultdict

PROJECT_ROOT = Path(__file__).resolve().parent.parent
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

REPORT_PATH = Path(__file__).resolve().parent / "error_audit_report.json"

# 排除目录
EXCLUDE_DIRS = {
    ".git", ".venv", "venv", "env", "__pycache__", "node_modules",
    "site-packages", ".pytest_cache", "dist", "build", ".mypy_cache",
    "logs", "screenshots", "scan_results", "reports",
}
# 排除测试目录（避免把测试代码当成业务代码误报）
EXCLUDE_DIR_NAMES = {"tests", "test"}
# 排除第三方 / 外部资源目录
TOP_EXCLUDE = {
    ".github", ".idea", ".vscode", "assets", "logs", "screenshots",
    "scan_results", "reports", "report_templates", "data", "cache",
}

SEVERITY_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3}


class Issue(dict):
    """审计问题条目。"""
    def __init__(self, file: str, line: int, kind: str, severity: str,
                 snippet: str, suggestion: str):
        super().__init__(
            file=file, line=line, kind=kind, severity=severity,
            snippet=snippet.strip(), suggestion=suggestion,
        )


def iter_py_files(root: Path):
    """遍历项目根目录下所有 .py 文件。"""
    for dirpath, dirnames, filenames in os.walk(root):
        # 原地修改 dirnames 以剪枝
        dirnames[:] = [
            d for d in dirnames
            if d not in EXCLUDE_DIRS and d not in EXCLUDE_DIR_NAMES
            and not d.startswith(".")
        ]
        rel = Path(dirpath).resolve()
        # 排除顶层第三方目录
        try:
            rel.relative_to(root)
        except ValueError:
            continue
        for fn in filenames:
            if not fn.endswith(".py"):
                continue
            p = Path(dirpath) / fn
            try:
                rel_p = p.relative_to(root)
            except ValueError:
                continue
            # 跳过顶层目录名命中排除
            if rel_p.parts and rel_p.parts[0] in TOP_EXCLUDE:
                continue
            yield p


# ---------------- AST 分析器 ----------------

class AuditVisitor(ast.NodeVisitor):
    """遍历 AST 收集问题。"""

    def __init__(self, filepath: Path, source_lines: list[str]):
        self.filepath = filepath
        self.lines = source_lines
        self.issues: list[Issue] = []
        self.imports: dict[str, tuple[str, int]] = {}  # name -> (module, lineno)
        self.used_names: set[str] = set()

    # --- 访问 except ---
    def visit_ExceptHandler(self, node: ast.ExceptHandler):
        # bare except: type is None
        if node.type is None:
            self.issues.append(Issue(
                file=str(self.filepath.relative_to(PROJECT_ROOT)),
                line=node.lineno, kind="bare_except", severity="high",
                snippet=self._line(node.lineno),
                suggestion="改为 `except Exception:` 或捕获具体异常类型",
            ))
        # 静默异常：body 只有一个 Pass
        if (len(node.body) == 1 and isinstance(node.body[0], ast.Pass)):
            self.issues.append(Issue(
                file=str(self.filepath.relative_to(PROJECT_ROOT)),
                line=node.lineno, kind="silent_except", severity="medium",
                snippet=self._line(node.lineno),
                suggestion="记录日志或重新抛出，避免吞掉异常",
            ))
        self.generic_visit(node)

    # --- 访问 Call（找 requests 缺 timeout、硬编码密码）---
    def visit_Call(self, node: ast.Call):
        # requests.get/post/put/delete/patch 缺 timeout
        func_name = self._dotted_name(node.func)
        if func_name:
            last = func_name.split(".")[-1]
            module = ".".join(func_name.split(".")[:-1])
            if last in ("get", "post", "put", "delete", "patch", "request") and (
                module in ("requests", "httpx") or module.endswith(".requests")
            ):
                has_timeout = any(
                    kw.arg == "timeout" for kw in node.keywords if kw.arg
                )
                if not has_timeout:
                    self.issues.append(Issue(
                        file=str(self.filepath.relative_to(PROJECT_ROOT)),
                        line=node.lineno, kind="missing_timeout", severity="high",
                        snippet=self._line(node.lineno),
                        suggestion=f"为 {func_name}() 调用添加 timeout=10 参数",
                    ))
            # 硬编码密钥：password="xxx" / secret="xxx" / api_key="xxx"
            for kw in node.keywords:
                if kw.arg and kw.arg.lower() in ("password", "secret", "api_key",
                                                 "apikey", "token", "passwd", "pwd"):
                    if isinstance(kw.value, ast.Constant) and isinstance(kw.value.value, str):
                        v = kw.value.value
                        if v and len(v) >= 3 and not v.startswith("${") and "env" not in v.lower():
                            self.issues.append(Issue(
                                file=str(self.filepath.relative_to(PROJECT_ROOT)),
                                line=node.lineno, kind="hardcoded_secret", severity="critical",
                                snippet=self._line(node.lineno),
                                suggestion=f"将 {kw.arg} 改为从环境变量或配置文件读取",
                            ))

        # 记录使用过的名字
        if isinstance(node.func, ast.Name):
            self.used_names.add(node.func.id)
        self.generic_visit(node)

    # --- 访问赋值（硬编码路径、字典直接下标）---
    def visit_Assign(self, node: ast.Assign):
        for tgt in node.targets:
            if isinstance(tgt, ast.Name):
                self.used_names.add(tgt.id)
                # 硬编码密钥的字符串赋值
                if tgt.id.lower() in ("password", "secret", "api_key", "apikey", "token", "passwd"):
                    if isinstance(node.value, ast.Constant) and isinstance(node.value.value, str):
                        v = node.value.value
                        if v and len(v) >= 3 and not v.startswith("${"):
                            self.issues.append(Issue(
                                file=str(self.filepath.relative_to(PROJECT_ROOT)),
                                line=node.lineno, kind="hardcoded_secret", severity="critical",
                                snippet=self._line(node.lineno),
                                suggestion=f"将 {tgt.id} 改为从环境变量读取",
                            ))
        # 硬编码绝对路径
        if isinstance(node.value, ast.Constant) and isinstance(node.value.value, str):
            v = node.value.value
            if self._looks_like_abs_path(v):
                self.issues.append(Issue(
                    file=str(self.filepath.relative_to(PROJECT_ROOT)),
                    line=node.lineno, kind="hardcoded_path", severity="low",
                    snippet=self._line(node.lineno),
                    suggestion="改为相对路径或用 os.path / pathlib 拼接",
                ))
        self.generic_visit(node)

    # --- 字典直接下标 ---
    def visit_Subscript(self, node: ast.Subscript):
        # 只看常量字符串 key 的下标
        if isinstance(node.slice, ast.Constant) and isinstance(node.slice.value, str):
            # 排除字面量 dict 推导 / 已经是字面量赋值的（误报太多）
            self.issues.append(Issue(
                file=str(self.filepath.relative_to(PROJECT_ROOT)),
                line=node.lineno, kind="dict_subscript", severity="low",
                snippet=self._line(node.lineno),
                suggestion=f"考虑用 .get({node.slice.value!r}) 避免 KeyError",
            ))
        self.generic_visit(node)

    # --- import 收集 ---
    def visit_Import(self, node: ast.Import):
        for alias in node.names:
            name = alias.asname or alias.name.split(".")[0]
            self.imports[name] = (alias.name, node.lineno)
        self.generic_visit(node)

    def visit_ImportFrom(self, node: ast.Import):
        for alias in node.names:
            name = alias.asname or alias.name
            self.imports[name] = (alias.name, node.lineno)
        self.generic_visit(node)

    # --- 跟踪 Name 使用 ---
    def visit_Name(self, node: ast.Name):
        if isinstance(node.ctx, ast.Load):
            self.used_names.add(node.id)
        self.generic_visit(node)

    # --- 工具方法 ---
    def _line(self, lineno: int) -> str:
        if 1 <= lineno <= len(self.lines):
            return self.lines[lineno - 1]
        return ""

    @staticmethod
    def _dotted_name(node) -> str:
        if isinstance(node, ast.Name):
            return node.id
        if isinstance(node, ast.Attribute):
            base = AuditVisitor._dotted_name(node.value)
            return f"{base}.{node.attr}" if base else node.attr
        return ""

    @staticmethod
    def _looks_like_abs_path(v: str) -> bool:
        if not isinstance(v, str) or len(v) < 3:
            return False
        s = v.strip().strip("'\"")
        if len(s) < 3:
            return False
        # Windows 绝对路径
        if len(s) >= 3 and s[1] == ":" and s[2] in ("\\", "/"):
            return True
        # Unix 绝对路径
        if s.startswith("/home/") or s.startswith("/Users/") or s.startswith("/etc/"):
            return True
        return False


def audit_file(path: Path) -> list[Issue]:
    """审计单个 .py 文件，返回问题列表。"""
    try:
        src = path.read_text(encoding="utf-8", errors="replace")
    except Exception as e:  # noqa: BLE001
        return [Issue(str(path), 0, "read_error", "high", f"<读取失败: {e}>", "检查文件编码")]
    lines = src.splitlines()
    try:
        tree = ast.parse(src, filename=str(path))
    except SyntaxError as e:
        return [Issue(str(path), e.lineno or 0, "syntax_error", "critical",
                      f"<语法错误: {e.msg}>", "修复语法错误")]

    v = AuditVisitor(path, lines)
    v.visit(tree)

    # 未使用的 import（简单启发式）
    for name, (_mod, lineno) in v.imports.items():
        if name in v.used_names or name == "*":
            continue
        # 常见副作用导入排除
        if _mod in ("__future__",):
            continue
        v.issues.append(Issue(
            file=str(path.relative_to(PROJECT_ROOT)),
            line=lineno, kind="unused_import", severity="low",
            snippet=lines[lineno - 1] if 1 <= lineno <= len(lines) else "",
            suggestion=f"移除未使用的 import {name}",
        ))
    return v.issues


# ---------------- 自动修复 ----------------

def fix_file(path: Path, issues: list[Issue]) -> int:
    """对单个文件做可安全的自动修复，返回修复条数。"""
    try:
        src = path.read_text(encoding="utf-8")
    except Exception:
        return 0
    lines = src.splitlines(keepends=True)
    fixed = 0
    # 按行号倒序修复，避免行号偏移
    by_line: dict[int, list[Issue]] = defaultdict(list)
    for it in issues:
        by_line[it["line"]].append(it)

    for lineno in sorted(by_line.keys(), reverse=True):
        if lineno < 1 or lineno > len(lines):
            continue
        line = lines[lineno - 1]
        for it in by_line[lineno]:
            kind = it["kind"]
            stripped = line.lstrip()
            # bare except → except Exception:
            if kind == "bare_except" and stripped.startswith("except") and stripped.strip() == "except:":
                indent = line[: len(line) - len(stripped)]
                lines[lineno - 1] = f"{indent}except Exception:\n"
                fixed += 1
            # requests 缺 timeout → 粗略在调用结尾加 timeout=10（保守：只对单行且未含 timeout 的）
            elif kind == "missing_timeout" and "timeout" not in line and line.rstrip().endswith(")"):
                # 把最后的 ) 替换为 , timeout=10)
                idx = line.rstrip().rfind(")")
                if idx > 0:
                    lines[lineno - 1] = line[:idx] + ", timeout=10" + line[idx:]
                    fixed += 1
    if fixed:
        path.write_text("".join(lines), encoding="utf-8")
    return fixed


def main():
    parser = argparse.ArgumentParser(description="代码静态审计 / 错误处理检查")
    parser.add_argument("--fix", action="store_true", help="自动修复可安全修复的问题")
    parser.add_argument("--output", default=str(REPORT_PATH), help="报告 JSON 路径")
    args = parser.parse_args()

    print(f"=== 代码静态审计开始 (fix={args.fix}) ===")
    t0 = time.time()
    all_issues: list[Issue] = []
    files_scanned = 0
    for py in iter_py_files(PROJECT_ROOT):
        files_scanned += 1
        # 跳过自身
        try:
            rel = py.relative_to(PROJECT_ROOT)
        except ValueError:
            continue
        if rel.as_posix().endswith("scripts/error_audit.py"):
            continue
        try:
            issues = audit_file(py)
            all_issues.extend(issues)
            if args.fix:
                fix_file(py, issues)
        except Exception as e:  # noqa: BLE001
            all_issues.append(Issue(str(rel), 0, "scan_error", "high",
                                     f"<扫描异常: {e}>", ""))

    # 按严重程度分组统计
    by_sev: dict[str, int] = defaultdict(int)
    by_kind: dict[str, int] = defaultdict(int)
    for it in all_issues:
        by_sev[it["severity"]] += 1
        by_kind[it["kind"]] += 1

    report = {
        "generated_at": time.strftime("%Y-%m-%d %H:%M:%S"),
        "files_scanned": files_scanned,
        "total_issues": len(all_issues),
        "by_severity": dict(by_sev),
        "by_kind": dict(by_kind),
        "issues": all_issues,
    }
    out = Path(args.output)
    out.write_text(json.dumps(report, ensure_ascii=False, indent=2), encoding="utf-8")

    print(f"扫描文件数       : {files_scanned}")
    print(f"总问题数         : {len(all_issues)}  (耗时 {round(time.time()-t0,2)}s)")
    print(f"  critical       : {by_sev.get('critical', 0)}")
    print(f"  high           : {by_sev.get('high', 0)}")
    print(f"  medium         : {by_sev.get('medium', 0)}")
    print(f"  low            : {by_sev.get('low', 0)}")
    print("按类型:")
    for k, v in sorted(by_kind.items(), key=lambda x: -x[1]):
        print(f"  {k:<20} {v}")
    print(f"报告已写入       : {out}")
    return 0


if __name__ == "__main__":
    sys.exit(main() or 0)
