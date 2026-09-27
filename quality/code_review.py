# -*- coding: utf-8 -*-
"""
code_review模块，提供代码审查工具。

模块功能：
    - 扫描Python文件中的代码质量问题
    - 检测未处理的异常、硬编码密钥、未使用的导入/变量
    - 检测函数过长、循环嵌套过深、重复代码
    - 检测缺失文档字符串和类型提示
    - 生成代码质量报告和评分

注意事项：
    - 本模块仅用于授权的安全测试
    - 请勿用于非法用途
    - 使用前请确保已获得相关授权
"""
import os
import ast
import re
from typing import Any, Dict, List, Optional, Set, Tuple


class CodeReviewer:
    """代码审查器。

    使用AST分析和正则匹配检测Python代码中的质量问题。
    """

    # 排除的目录
    EXCLUDE_DIRS = {".venv", "venv", "__pycache__", "node_modules",
                    "dist", "build", ".git", ".pytest_cache",
                    "site-packages", ".mypy_cache", ".tox"}

    # 硬编码路径正则
    HARDCODED_PATH_PATTERNS = [
        re.compile(r'["\']C:\\[^"\']+["\']'),
        re.compile(r'["\']/etc/[^"\']+["\']'),
        re.compile(r'["\']/home/[^"\']+["\']'),
        re.compile(r'["\']/root/[^"\']+["\']'),
    ]

    # 硬编码密钥正则
    SECRET_PATTERNS = [
        re.compile(r'api_key\s*=\s*["\'][^"\']{8,}["\']', re.IGNORECASE),
        re.compile(r'password\s*=\s*["\'][^"\']{6,}["\']', re.IGNORECASE),
        re.compile(r'secret\s*=\s*["\'][^"\']{8,}["\']', re.IGNORECASE),
        re.compile(r'token\s*=\s*["\'][^"\']{8,}["\']', re.IGNORECASE),
    ]

    # 排除的行（从配置读取）
    EXCLUDE_LINE_PATTERNS = [
        "os.getenv", "os.environ", "settings.", "config.",
        "getenv", "environ[",
    ]

    # 阈值
    MAX_FUNCTION_LENGTH = 100
    MAX_LOOP_NESTING = 3
    DUPLICATE_LINE_COUNT = 5

    def __init__(self):
        """初始化CodeReviewer实例。"""
        self.findings: List[Dict[str, Any]] = []

    # ------------------------------------------------------------------ #
    # 单文件扫描
    # ------------------------------------------------------------------ #
    def scan_file(self, file_path: str) -> List[Dict[str, Any]]:
        """扫描单个Python文件，检查代码质量问题。

        Args:
            file_path: Python文件路径。

        Returns:
            发现的问题列表。
        """
        findings: List[Dict[str, Any]] = []

        if not os.path.exists(file_path) or not file_path.endswith(".py"):
            return findings

        try:
            with open(file_path, "r", encoding="utf-8", errors="ignore") as f:
                source = f.read()
        except IOError:
            return findings

        lines = source.splitlines()

        # 1. 检测bare except和except: pass（逐行检查）
        findings.extend(self._check_bare_except(file_path, lines))

        # 2. 检测硬编码路径和密钥
        findings.extend(self._check_hardcoded(file_path, lines))

        # 3. AST分析
        try:
            tree = ast.parse(source, filename=file_path)
            findings.extend(self._check_unused_imports(file_path, tree, source))
            findings.extend(self._check_missing_docstrings(file_path, tree))
            findings.extend(self._check_missing_type_hints(file_path, tree))
            findings.extend(self._check_function_length(file_path, tree, lines))
            findings.extend(self._check_loop_nesting(file_path, tree))
        except SyntaxError:
            findings.append({
                "file_path": file_path,
                "line_number": 1,
                "issue_type": "syntax_error",
                "description": "文件存在语法错误，无法解析",
                "severity": "critical",
                "suggestion": "修复语法错误",
            })

        # 4. 重复代码检测
        findings.extend(self._check_duplicate_code(file_path, lines))

        return findings

    def _check_bare_except(self, file_path: str,
                           lines: List[str]) -> List[Dict[str, Any]]:
        """检测bare except和except: pass。"""
        findings: List[Dict[str, Any]] = []
        for i, line in enumerate(lines, 1):
            stripped = line.strip()
            # bare except:
            if re.match(r'^except\s*:\s*$', stripped):
                findings.append({
                    "file_path": file_path,
                    "line_number": i,
                    "issue_type": "bare_except",
                    "description": "使用了裸except（未指定异常类型）",
                    "severity": "high",
                    "suggestion": "指定具体的异常类型，如except ValueError:",
                })
            # except: pass 或 except Exception: pass
            if re.match(r'^except.*:\s*pass\s*$', stripped):
                findings.append({
                    "file_path": file_path,
                    "line_number": i,
                    "issue_type": "bare_except_pass",
                    "description": "捕获异常后直接pass，未处理",
                    "severity": "medium",
                    "suggestion": "至少记录日志或重新抛出异常",
                })
        return findings

    def _check_hardcoded(self, file_path: str,
                         lines: List[str]) -> List[Dict[str, Any]]:
        """检测硬编码路径和密钥。"""
        findings: List[Dict[str, Any]] = []
        for i, line in enumerate(lines, 1):
            stripped = line.strip()
            if stripped.startswith("#"):
                continue
            # 跳过排除模式
            if any(pat in line for pat in self.EXCLUDE_LINE_PATTERNS):
                continue

            # 硬编码路径
            for pattern in self.HARDCODED_PATH_PATTERNS:
                if pattern.search(line):
                    findings.append({
                        "file_path": file_path,
                        "line_number": i,
                        "issue_type": "hardcoded_path",
                        "description": f"硬编码路径: {stripped[:80]}",
                        "severity": "medium",
                        "suggestion": "使用配置文件或环境变量管理路径",
                    })

            # 硬编码密钥
            for pattern in self.SECRET_PATTERNS:
                if pattern.search(line):
                    findings.append({
                        "file_path": file_path,
                        "line_number": i,
                        "issue_type": "hardcoded_secret",
                        "description": f"硬编码密钥/密码: {stripped[:80]}",
                        "severity": "high",
                        "suggestion": "使用环境变量或密钥管理服务",
                    })
        return findings

    def _check_unused_imports(self, file_path: str, tree: ast.AST,
                              source: str) -> List[Dict[str, Any]]:
        """检测未使用的导入。"""
        findings: List[Dict[str, Any]] = []

        # 收集所有导入的名称
        imported_names: Dict[str, int] = {}  # name -> line_number
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                for alias in node.names:
                    name = alias.asname or alias.name.split(".")[0]
                    imported_names[name] = node.lineno
            elif isinstance(node, ast.ImportFrom):
                for alias in node.names:
                    name = alias.asname or alias.name
                    imported_names[name] = node.lineno

        # 收集所有使用的名称
        used_names: Set[str] = set()
        for node in ast.walk(tree):
            if isinstance(node, ast.Name):
                used_names.add(node.id)
            elif isinstance(node, ast.Attribute):
                # 获取顶层对象名
                obj = node
                while isinstance(obj, ast.Attribute):
                    obj = obj.value
                if isinstance(obj, ast.Name):
                    used_names.add(obj.id)

        # 检查未使用的导入
        for name, lineno in imported_names.items():
            if name not in used_names and name != "*":
                findings.append({
                    "file_path": file_path,
                    "line_number": lineno,
                    "issue_type": "unused_import",
                    "description": f"导入了'{name}'但未使用",
                    "severity": "low",
                    "suggestion": f"移除未使用的导入: import {name}",
                })
        return findings

    def _check_missing_docstrings(self, file_path: str,
                                  tree: ast.AST) -> List[Dict[str, Any]]:
        """检测公共函数/类缺失文档字符串。"""
        findings: List[Dict[str, Any]] = []
        for node in ast.walk(tree):
            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                # 公共函数（不以_开头）
                if not node.name.startswith("_"):
                    docstring = ast.get_docstring(node)
                    if not docstring:
                        findings.append({
                            "file_path": file_path,
                            "line_number": node.lineno,
                            "issue_type": "missing_docstring",
                            "description": f"公共函数'{node.name}'缺少文档字符串",
                            "severity": "low",
                            "suggestion": f"为函数{node.name}添加docstring",
                        })
            elif isinstance(node, ast.ClassDef):
                if not node.name.startswith("_"):
                    docstring = ast.get_docstring(node)
                    if not docstring:
                        findings.append({
                            "file_path": file_path,
                            "line_number": node.lineno,
                            "issue_type": "missing_docstring",
                            "description": f"公共类'{node.name}'缺少文档字符串",
                            "severity": "low",
                            "suggestion": f"为类{node.name}添加docstring",
                        })
        return findings

    def _check_missing_type_hints(self, file_path: str,
                                  tree: ast.AST) -> List[Dict[str, Any]]:
        """检测函数缺少类型提示。"""
        findings: List[Dict[str, Any]] = []
        for node in ast.walk(tree):
            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                if node.name.startswith("_"):
                    continue
                # 检查返回类型注解
                has_return_annotation = node.returns is not None
                # 检查参数类型注解（排除self和*args/**kwargs）
                missing_arg_annotations = []
                for arg in node.args.args:
                    if arg.arg in ("self", "cls"):
                        continue
                    if arg.annotation is None:
                        missing_arg_annotations.append(arg.arg)
                # 检查*args和**kwargs
                if node.args.vararg and node.args.vararg.annotation is None:
                    missing_arg_annotations.append("*" + node.args.vararg.arg)
                if node.args.kwarg and node.args.kwarg.annotation is None:
                    missing_arg_annotations.append("**" + node.args.kwarg.arg)

                if not has_return_annotation:
                    findings.append({
                        "file_path": file_path,
                        "line_number": node.lineno,
                        "issue_type": "missing_return_type",
                        "description": f"函数'{node.name}'缺少返回类型注解",
                        "severity": "info",
                        "suggestion": f"添加 -> 返回类型 注解",
                    })
                if missing_arg_annotations:
                    findings.append({
                        "file_path": file_path,
                        "line_number": node.lineno,
                        "issue_type": "missing_param_type",
                        "description": f"函数'{node.name}'参数缺少类型注解: "
                                       f"{', '.join(missing_arg_annotations)}",
                        "severity": "info",
                        "suggestion": "为函数参数添加类型注解",
                    })
        return findings

    def _check_function_length(self, file_path: str, tree: ast.AST,
                               lines: List[str]) -> List[Dict[str, Any]]:
        """检测函数过长。"""
        findings: List[Dict[str, Any]] = []
        for node in ast.walk(tree):
            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                end_lineno = getattr(node, "end_lineno", node.lineno)
                func_length = end_lineno - node.lineno + 1
                if func_length > self.MAX_FUNCTION_LENGTH:
                    findings.append({
                        "file_path": file_path,
                        "line_number": node.lineno,
                        "issue_type": "function_too_long",
                        "description": f"函数'{node.name}'长度{func_length}行，"
                                       f"超过{self.MAX_FUNCTION_LENGTH}行",
                        "severity": "medium",
                        "suggestion": f"考虑将函数拆分为更小的函数",
                    })
        return findings

    def _check_loop_nesting(self, file_path: str,
                            tree: ast.AST) -> List[Dict[str, Any]]:
        """检测循环嵌套过深。"""
        findings: List[Dict[str, Any]] = []

        def check_nesting(node: ast.AST, depth: int, parent_name: str):
            if depth > self.MAX_LOOP_NESTING:
                findings.append({
                    "file_path": file_path,
                    "line_number": getattr(node, "lineno", 1),
                    "issue_type": "deep_loop_nesting",
                    "description": f"循环嵌套深度{depth}层（在{parent_name}中），"
                                   f"超过{self.MAX_LOOP_NESTING}层",
                    "severity": "medium",
                    "suggestion": "考虑使用函数拆分或数据结构简化嵌套",
                })
                return  # 只报告最深层一次

            for child in ast.iter_child_nodes(node):
                if isinstance(child, (ast.For, ast.While, ast.AsyncFor)):
                    check_nesting(child, depth + 1, parent_name)
                else:
                    check_nesting(child, depth, parent_name)

        for node in ast.walk(tree):
            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                check_nesting(node, 0, node.name)

        return findings

    def _check_duplicate_code(self, file_path: str,
                              lines: List[str]) -> List[Dict[str, Any]]:
        """检测重复代码块（连续5行以上重复）。"""
        findings: List[Dict[str, Any]] = []
        seen_blocks: Dict[str, int] = {}  # hash -> first_line
        block_size = self.DUPLICATE_LINE_COUNT

        for i in range(len(lines) - block_size + 1):
            block_lines = lines[i:i + block_size]
            # 过滤空行和注释
            meaningful = [
                l.strip() for l in block_lines
                if l.strip() and not l.strip().startswith("#")
            ]
            if len(meaningful) < block_size:
                continue
            block_hash = hash("\n".join(meaningful))
            if block_hash in seen_blocks:
                first_line = seen_blocks[block_hash]
                # 避免重复报告同一个块
                if i - first_line > block_size:
                    findings.append({
                        "file_path": file_path,
                        "line_number": i + 1,
                        "issue_type": "duplicate_code",
                        "description": f"检测到{block_size}行以上重复代码块"
                                       f"（与第{first_line}行重复）",
                        "severity": "low",
                        "suggestion": "考虑提取为公共函数",
                    })
                    # 标记已报告
                    seen_blocks[block_hash] = -1
            else:
                seen_blocks[block_hash] = i + 1

        return findings

    # ------------------------------------------------------------------ #
    # 目录扫描
    # ------------------------------------------------------------------ #
    def scan_directory(self, directory: str,
                       exclude_dirs: Optional[Set[str]] = None) -> List[Dict[str, Any]]:
        """扫描目录下所有Python文件。

        Args:
            directory: 目标目录。
            exclude_dirs: 额外排除的目录集合。

        Returns:
            所有发现的问题列表。
        """
        exclude = self.EXCLUDE_DIRS.copy()
        if exclude_dirs:
            exclude.update(exclude_dirs)

        all_findings: List[Dict[str, Any]] = []

        for root, dirs, files in os.walk(directory):
            # 过滤排除目录
            dirs[:] = [d for d in dirs if d not in exclude]
            for fname in files:
                if not fname.endswith(".py"):
                    continue
                fpath = os.path.join(root, fname)
                try:
                    findings = self.scan_file(fpath)
                    all_findings.extend(findings)
                except Exception:
                    continue

        return all_findings

    # ------------------------------------------------------------------ #
    # 报告生成
    # ------------------------------------------------------------------ #
    def generate_report(self, findings: List[Dict[str, Any]]) -> Dict[str, Any]:
        """生成代码审查报告。

        Args:
            findings: 问题列表。

        Returns:
            包含分类统计、评分和问题详情的报告。
        """
        # 按严重程度分类
        severity_order = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
        severity_counts: Dict[str, int] = {}
        type_counts: Dict[str, int] = {}

        for f in findings:
            sev = f.get("severity", "low")
            severity_counts[sev] = severity_counts.get(sev, 0) + 1
            itype = f.get("issue_type", "unknown")
            type_counts[itype] = type_counts.get(itype, 0) + 1

        # 按严重程度排序
        sorted_findings = sorted(
            findings,
            key=lambda f: severity_order.get(f.get("severity", "low"), 9),
        )

        # 计算质量评分（0-100）
        score = 100
        for f in findings:
            sev = f.get("severity", "low")
            if sev == "critical":
                score -= 10
            elif sev == "high":
                score -= 5
            elif sev == "medium":
                score -= 2
            elif sev == "low":
                score -= 0.5
            elif sev == "info":
                score -= 0.1
        score = max(0, min(100, round(score, 1)))

        return {
            "total_findings": len(findings),
            "severity_breakdown": severity_counts,
            "type_breakdown": type_counts,
            "quality_score": score,
            "findings": sorted_findings,
        }

    def run_review(self, directory: str = ".") -> Dict[str, Any]:
        """运行完整代码审查。

        Args:
            directory: 项目目录。

        Returns:
            完整审查报告。
        """
        findings = self.scan_directory(directory)
        report = self.generate_report(findings)
        return report


# 全局实例
_code_reviewer_instance: Optional[CodeReviewer] = None


def get_code_reviewer() -> CodeReviewer:
    """获取全局CodeReviewer实例（单例模式）。"""
    global _code_reviewer_instance
    if _code_reviewer_instance is None:
        _code_reviewer_instance = CodeReviewer()
    return _code_reviewer_instance
