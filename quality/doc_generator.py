# -*- coding: utf-8 -*-
"""
doc_generator模块，提供文档生成工具。

模块功能：
    - 从Python文件提取模块文档（AST解析）
    - 生成模块文档（Markdown格式）
    - 生成API文档（从路由文件）
    - 生成代码结构文档（目录树+依赖关系）

注意事项：
    - 本模块仅用于授权的安全测试
    - 请勿用于非法用途
    - 使用前请确保已获得相关授权
"""
import os
import ast
import re
from typing import Any, Dict, List, Optional, Set, Tuple

# 项目根目录
_PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


class DocGenerator:
    """文档生成器。

    使用AST解析Python文件，提取文档信息并生成Markdown文档。
    """

    # 排除的目录
    EXCLUDE_DIRS = {".venv", "venv", "__pycache__", "node_modules",
                    "dist", "build", ".git", ".pytest_cache",
                    "site-packages", ".mypy_cache"}

    def __init__(self):
        """初始化DocGenerator实例。"""
        pass

    # ------------------------------------------------------------------ #
    # 提取模块文档
    # ------------------------------------------------------------------ #
    def extract_module_doc(self, file_path: str) -> Dict[str, Any]:
        """从Python文件提取模块文档字符串、类、函数及其docstring。

        Args:
            file_path: Python文件路径。

        Returns:
            包含模块docstring、类列表、函数列表的字典。
        """
        if not os.path.exists(file_path) or not file_path.endswith(".py"):
            return {"module": "", "docstring": "", "classes": [], "functions": []}

        try:
            with open(file_path, "r", encoding="utf-8", errors="ignore") as f:
                source = f.read()
        except IOError:
            return {"module": "", "docstring": "", "classes": [], "functions": []}

        try:
            tree = ast.parse(source, filename=file_path)
        except SyntaxError:
            return {"module": os.path.basename(file_path),
                    "docstring": "", "classes": [], "functions": []}

        module_name = os.path.basename(file_path).replace(".py", "")
        module_docstring = ast.get_docstring(tree) or ""

        classes: List[Dict[str, Any]] = []
        functions: List[Dict[str, Any]] = []

        for node in ast.iter_child_nodes(tree):
            if isinstance(node, ast.ClassDef):
                class_info = {
                    "name": node.name,
                    "docstring": ast.get_docstring(node) or "",
                    "methods": [],
                    "line_number": node.lineno,
                }
                # 提取方法
                for item in node.body:
                    if isinstance(item, (ast.FunctionDef, ast.AsyncFunctionDef)):
                        method_info = {
                            "name": item.name,
                            "docstring": ast.get_docstring(item) or "",
                            "signature": self._get_func_signature(item),
                            "line_number": item.lineno,
                        }
                        class_info["methods"].append(method_info)
                classes.append(class_info)

            elif isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                func_info = {
                    "name": node.name,
                    "docstring": ast.get_docstring(node) or "",
                    "signature": self._get_func_signature(node),
                    "line_number": node.lineno,
                }
                functions.append(func_info)

        return {
            "module": module_name,
            "file_path": file_path,
            "docstring": module_docstring,
            "classes": classes,
            "functions": functions,
        }

    @staticmethod
    def _get_func_signature(node: ast.FunctionDef) -> str:
        """提取函数签名字符串。"""
        args = []
        # 位置参数
        for arg in node.args.args:
            arg_str = arg.arg
            if arg.annotation:
                try:
                    ann = ast.unparse(arg.annotation)
                    arg_str += f": {ann}"
                except Exception:
                    pass
            args.append(arg_str)
        # 返回类型
        ret_str = ""
        if node.returns:
            try:
                ret_str = f" -> {ast.unparse(node.returns)}"
            except Exception:
                pass
        return f"def {node.name}({', '.join(args)}){ret_str}"

    # ------------------------------------------------------------------ #
    # 生成模块文档
    # ------------------------------------------------------------------ #
    def generate_module_docs(self, directory: str,
                              output_dir: str = "docs") -> str:
        """为每个模块生成模块文档（Markdown格式）。

        Args:
            directory: 项目目录。
            output_dir: 输出文档目录。

        Returns:
            索引文件路径。
        """
        os.makedirs(output_dir, exist_ok=True)
        modules_info: List[Dict[str, Any]] = []

        for root, dirs, files in os.walk(directory):
            dirs[:] = [d for d in dirs if d not in self.EXCLUDE_DIRS]
            for fname in files:
                if not fname.endswith(".py") or fname.startswith("test_"):
                    continue
                fpath = os.path.join(root, fname)
                try:
                    info = self.extract_module_doc(fpath)
                    if info.get("docstring") or info.get("classes") or info.get("functions"):
                        modules_info.append(info)
                        # 生成单个模块文档
                        self._write_module_doc(info, output_dir)
                except Exception:
                    continue

        # 生成索引文件
        index_path = os.path.join(output_dir, "MODULE_REFERENCE.md")
        with open(index_path, "w", encoding="utf-8") as f:
            f.write("# 模块文档索引\n\n")
            f.write(f"共 {len(modules_info)} 个模块\n\n")
            for info in sorted(modules_info, key=lambda x: x["module"]):
                rel_path = os.path.relpath(info.get("file_path", ""), directory)
                f.write(f"## {info['module']}\n\n")
                if info.get("docstring"):
                    # 取docstring前3行
                    doc_lines = info["docstring"].strip().split("\n")[:3]
                    f.write("> " + "\n> ".join(doc_lines) + "\n\n")
                f.write(f"- 文件: `{rel_path}`\n")
                if info.get("classes"):
                    f.write(f"- 类: {', '.join(c['name'] for c in info['classes'])}\n")
                if info.get("functions"):
                    f.write(f"- 函数: {', '.join(fn['name'] for fn in info['functions'])}\n")
                f.write("\n")

        return index_path

    def _write_module_doc(self, info: Dict[str, Any], output_dir: str):
        """写入单个模块的Markdown文档。"""
        module_name = info["module"]
        doc_path = os.path.join(output_dir, f"{module_name}.md")

        with open(doc_path, "w", encoding="utf-8") as f:
            f.write(f"# {module_name}\n\n")

            if info.get("docstring"):
                f.write("## 功能说明\n\n")
                f.write(info["docstring"].strip() + "\n\n")

            if info.get("classes"):
                f.write("## 主要类\n\n")
                for cls in info["classes"]:
                    f.write(f"### {cls['name']}\n\n")
                    if cls.get("docstring"):
                        f.write(cls["docstring"].strip() + "\n\n")
                    if cls.get("methods"):
                        f.write("**方法:**\n\n")
                        for method in cls["methods"]:
                            f.write(f"- `{method['signature']}`\n")
                            if method.get("docstring"):
                                first_line = method["docstring"].strip().split("\n")[0]
                                f.write(f"  - {first_line}\n")
                        f.write("\n")

            if info.get("functions"):
                f.write("## 主要函数\n\n")
                for func in info["functions"]:
                    f.write(f"### `{func['signature']}`\n\n")
                    if func.get("docstring"):
                        f.write(func["docstring"].strip() + "\n\n")

    # ------------------------------------------------------------------ #
    # 生成API文档
    # ------------------------------------------------------------------ #
    def generate_api_docs(self, routes_module_path: str,
                          output_path: str = "docs/API_REFERENCE.md") -> str:
        """从API路由文件生成API文档。

        扫描路由文件中的@router.xxx("path")装饰器，提取路径和方法。

        Args:
            routes_module_path: 路由文件路径。
            output_path: 输出文档路径。

        Returns:
            输出文件路径。
        """
        if not os.path.exists(routes_module_path):
            # 创建空文档
            os.makedirs(os.path.dirname(output_path) or ".", exist_ok=True)
            with open(output_path, "w", encoding="utf-8") as f:
                f.write("# API文档\n\n路由文件不存在\n")
            return output_path

        try:
            with open(routes_module_path, "r", encoding="utf-8", errors="ignore") as f:
                source = f.read()
        except IOError:
            return output_path

        # 匹配路由装饰器
        route_pattern = re.compile(
            r'@router\.(get|post|put|delete|patch)\s*\(\s*["\']([^"\']+)["\']'
        )

        # 匹配函数定义
        func_pattern = re.compile(
            r'def\s+(\w+)\s*\(([^)]*)\)'
        )

        routes: List[Dict[str, str]] = []
        lines = source.splitlines()

        for i, line in enumerate(lines):
            match = route_pattern.search(line)
            if match:
                http_method = match.group(1).upper()
                path = match.group(2)
                # 查找接下来的函数定义和docstring
                func_name = ""
                func_docstring = ""
                for j in range(i + 1, min(i + 10, len(lines))):
                    func_match = func_pattern.search(lines[j])
                    if func_match:
                        func_name = func_match.group(1)
                        # 查找docstring
                        for k in range(j + 1, min(j + 5, len(lines))):
                            stripped = lines[k].strip()
                            if stripped.startswith('"""') or stripped.startswith("'''"):
                                doc_lines = []
                                doc_char = '"""' if stripped.startswith('"""') else "'''"
                                if stripped.count(doc_char) >= 2 and len(stripped) > 3:
                                    func_docstring = stripped.strip(doc_char).strip()
                                else:
                                    doc_lines.append(stripped.strip(doc_char))
                                    for m in range(k + 1, min(k + 20, len(lines))):
                                        if doc_char in lines[m]:
                                            doc_lines.append(
                                                lines[m].split(doc_char)[0].strip())
                                            break
                                        doc_lines.append(lines[m].strip())
                                    func_docstring = "\n".join(doc_lines)
                                break
                            if stripped and not stripped.startswith("#"):
                                break
                        break

                routes.append({
                    "method": http_method,
                    "path": path,
                    "function": func_name,
                    "docstring": func_docstring,
                })

        # 写入文档
        os.makedirs(os.path.dirname(output_path) or ".", exist_ok=True)
        with open(output_path, "w", encoding="utf-8") as f:
            f.write("# API 参考文档\n\n")
            f.write(f"路由文件: `{routes_module_path}`\n\n")
            f.write(f"共 {len(routes)} 个端点\n\n")

            # 按路径分组
            f.write("## 端点列表\n\n")
            f.write("| 方法 | 路径 | 函数 | 说明 |\n")
            f.write("|------|------|------|------|\n")
            for r in routes:
                desc = r["docstring"].split("\n")[0] if r["docstring"] else ""
                f.write(f"| {r['method']} | `{r['path']}` | {r['function']} | {desc} |\n")

            f.write("\n## 详细说明\n\n")
            for r in routes:
                f.write(f"### {r['method']} `{r['path']}`\n\n")
                f.write(f"- **函数**: `{r['function']}`\n")
                if r["docstring"]:
                    f.write(f"- **说明**: {r['docstring']}\n")
                f.write("\n")

        return output_path

    # ------------------------------------------------------------------ #
    # 生成代码结构文档
    # ------------------------------------------------------------------ #
    def generate_code_structure(self, directory: str,
                                 output_path: str = "docs/CODE_STRUCTURE.md") -> str:
        """生成代码结构文档。

        包含目录结构树和模块依赖关系。

        Args:
            directory: 项目目录。
            output_path: 输出文件路径。

        Returns:
            输出文件路径。
        """
        os.makedirs(os.path.dirname(output_path) or ".", exist_ok=True)

        with open(output_path, "w", encoding="utf-8") as f:
            f.write("# 代码结构文档\n\n")

            # 目录结构树
            f.write("## 目录结构\n\n```\n")
            tree_lines = self._build_directory_tree(directory)
            f.write("\n".join(tree_lines[:100]))  # 限制100行
            f.write("\n```\n\n")

            # 模块依赖关系
            f.write("## 模块依赖关系\n\n")
            deps = self._analyze_imports(directory)
            if deps:
                for module, imported in sorted(deps.items())[:50]:
                    f.write(f"- **{module}** → {', '.join(sorted(imported)[:10])}\n")
            else:
                f.write("未检测到模块依赖关系\n")

            f.write("\n")

        return output_path

    def _build_directory_tree(self, directory: str,
                              prefix: str = "",
                              is_last: bool = True,
                              depth: int = 0) -> List[str]:
        """构建目录树文本。"""
        if depth > 3:
            return []

        entries = sorted(os.listdir(directory))
        # 过滤排除项
        entries = [
            e for e in entries
            if e not in self.EXCLUDE_DIRS and not e.startswith(".")
        ]

        lines: List[str] = []
        name = os.path.basename(directory)
        connector = "└── " if is_last else "├── "
        lines.append(f"{prefix}{connector}{name}/")

        extension = "    " if is_last else "│   "
        new_prefix = prefix + extension

        for i, entry in enumerate(entries):
            is_last_entry = (i == len(entries) - 1)
            entry_path = os.path.join(directory, entry)
            if os.path.isdir(entry_path):
                lines.extend(self._build_directory_tree(
                    entry_path, new_prefix, is_last_entry, depth + 1))
            elif entry.endswith(".py"):
                connector_e = "└── " if is_last_entry else "├── "
                lines.append(f"{new_prefix}{connector_e}{entry}")

        return lines

    def _analyze_imports(self, directory: str) -> Dict[str, Set[str]]:
        """分析模块import依赖关系。"""
        deps: Dict[str, Set[str]] = {}

        for root, dirs, files in os.walk(directory):
            dirs[:] = [d for d in dirs if d not in self.EXCLUDE_DIRS]
            for fname in files:
                if not fname.endswith(".py"):
                    continue
                fpath = os.path.join(root, fname)
                module_name = os.path.relpath(fpath, directory).replace(
                    os.sep, ".").replace(".py", "")

                try:
                    with open(fpath, "r", encoding="utf-8", errors="ignore") as f:
                        source = f.read()
                    tree = ast.parse(source)
                    imported: Set[str] = set()
                    for node in ast.walk(tree):
                        if isinstance(node, ast.Import):
                            for alias in node.names:
                                imported.add(alias.name.split(".")[0])
                        elif isinstance(node, ast.ImportFrom):
                            if node.module:
                                imported.add(node.module.split(".")[0])
                    if imported:
                        deps[module_name] = imported
                except (SyntaxError, IOError):
                    continue

        return deps

    # ------------------------------------------------------------------ #
    # 运行完整文档生成
    # ------------------------------------------------------------------ #
    def run_generation(self, directory: str = ".") -> Dict[str, str]:
        """运行完整文档生成。

        Args:
            directory: 项目目录。

        Returns:
            生成的文档路径字典。
        """
        results: Dict[str, str] = {}

        try:
            results["module_docs"] = self.generate_module_docs(
                directory, os.path.join(directory, "docs"))
        except Exception:
            results["module_docs"] = ""

        try:
            routes_path = os.path.join(directory, "api_server", "security_routes.py")
            if os.path.exists(routes_path):
                results["api_docs"] = self.generate_api_docs(
                    routes_path,
                    os.path.join(directory, "docs", "API_REFERENCE.md"))
        except Exception:
            results["api_docs"] = ""

        try:
            results["code_structure"] = self.generate_code_structure(
                directory,
                os.path.join(directory, "docs", "CODE_STRUCTURE.md"))
        except Exception:
            results["code_structure"] = ""

        return results


# 全局实例
_doc_generator_instance: Optional[DocGenerator] = None


def get_doc_generator() -> DocGenerator:
    """获取全局DocGenerator实例（单例模式）。"""
    global _doc_generator_instance
    if _doc_generator_instance is None:
        _doc_generator_instance = DocGenerator()
    return _doc_generator_instance
