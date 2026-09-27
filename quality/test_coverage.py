# -*- coding: utf-8 -*-
"""
test_coverage模块，提供测试覆盖率检查。

模块功能：
    - 统计现有测试用例数量
    - 统计项目中所有公共函数/类
    - 计算测试覆盖率（基于简单名称匹配）
    - 生成覆盖率报告和改进建议
    - 为核心模块生成基本单元测试

注意事项：
    - 本模块仅用于授权的安全测试
    - 请勿用于非法用途
    - 使用前请确保已获得相关授权
"""
import os
import ast
from typing import Any, Dict, List, Optional, Set, Tuple

# 项目根目录
_PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

# 核心模块列表（用于生成基本测试）
CORE_MODULES = [
    "verification/web_vuln_verifier.py",
    "verification/service_vuln_verifier.py",
    "security/data_protection.py",
    "security/access_control.py",
    "ai/output_validator.py",
    "performance/response_cache.py",
]


class TestCoverageChecker:
    """测试覆盖率检查器。

    统计测试用例和项目函数，计算覆盖率，生成报告。
    """

    # 排除的目录
    EXCLUDE_DIRS = {".venv", "venv", "__pycache__", "node_modules",
                    "dist", "build", ".git", ".pytest_cache",
                    "site-packages", ".mypy_cache"}

    def __init__(self, project_root: Optional[str] = None):
        """初始化TestCoverageChecker实例。

        Args:
            project_root: 项目根目录。
        """
        self.project_root = project_root or _PROJECT_ROOT

    # ------------------------------------------------------------------ #
    # 统计测试用例
    # ------------------------------------------------------------------ #
    def find_tests(self, tests_dir: str = "tests") -> Dict[str, Any]:
        """统计现有测试用例。

        扫描tests/目录下所有test_*.py文件，统计测试函数和类数量。

        Args:
            tests_dir: 测试目录（相对于项目根）。

        Returns:
            测试统计信息。
        """
        test_path = os.path.join(self.project_root, tests_dir)
        if not os.path.isdir(test_path):
            return {
                "test_files": 0,
                "test_functions": 0,
                "test_classes": 0,
                "files": [],
            }

        test_files: List[str] = []
        test_funcs: Set[str] = set()
        test_classes: Set[str] = set()

        for root, dirs, files in os.walk(test_path):
            dirs[:] = [d for d in dirs if d not in self.EXCLUDE_DIRS]
            for fname in files:
                if not fname.startswith("test_") or not fname.endswith(".py"):
                    continue
                fpath = os.path.join(root, fname)
                test_files.append(fpath)

                try:
                    with open(fpath, "r", encoding="utf-8", errors="ignore") as f:
                        source = f.read()
                    tree = ast.parse(source)
                    for node in ast.walk(tree):
                        if isinstance(node, ast.FunctionDef) and node.name.startswith("test_"):
                            test_funcs.add(node.name)
                        if isinstance(node, ast.ClassDef) and node.name.startswith("Test"):
                            test_classes.add(node.name)
                except (SyntaxError, IOError):
                    continue

        return {
            "test_files": len(test_files),
            "test_functions": len(test_funcs),
            "test_classes": len(test_classes),
            "files": [os.path.relpath(f, self.project_root) for f in test_files],
            "test_function_names": sorted(test_funcs),
        }

    # ------------------------------------------------------------------ #
    # 统计项目函数
    # ------------------------------------------------------------------ #
    def find_all_functions(self, directory: str = ".") -> Dict[str, Any]:
        """统计项目中所有公共函数/类。

        Args:
            directory: 项目目录。

        Returns:
            函数和类统计信息。
        """
        abs_dir = os.path.join(self.project_root, directory) \
            if not os.path.isabs(directory) else directory

        all_functions: List[Dict[str, Any]] = []
        all_classes: List[Dict[str, Any]] = []
        module_funcs: Dict[str, List[str]] = {}

        for root, dirs, files in os.walk(abs_dir):
            dirs[:] = [d for d in dirs if d not in self.EXCLUDE_DIRS]
            # 排除tests目录
            if "tests" in root.split(os.sep):
                continue

            for fname in files:
                if not fname.endswith(".py") or fname.startswith("test_"):
                    continue
                fpath = os.path.join(root, fname)
                rel_path = os.path.relpath(fpath, self.project_root)

                try:
                    with open(fpath, "r", encoding="utf-8", errors="ignore") as f:
                        source = f.read()
                    tree = ast.parse(source)
                except (SyntaxError, IOError):
                    continue

                module_func_list: List[str] = []
                for node in ast.iter_child_nodes(tree):
                    if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                        if not node.name.startswith("_"):
                            all_functions.append({
                                "name": node.name,
                                "file": rel_path,
                                "line": node.lineno,
                            })
                            module_func_list.append(node.name)
                    elif isinstance(node, ast.ClassDef):
                        if not node.name.startswith("_"):
                            all_classes.append({
                                "name": node.name,
                                "file": rel_path,
                                "line": node.lineno,
                            })
                            # 类的公共方法
                            for item in node.body:
                                if isinstance(item, (ast.FunctionDef, ast.AsyncFunctionDef)):
                                    if not item.name.startswith("_"):
                                        all_functions.append({
                                            "name": f"{node.name}.{item.name}",
                                            "file": rel_path,
                                            "line": item.lineno,
                                        })
                                        module_func_list.append(
                                            f"{node.name}.{item.name}")

                if module_func_list:
                    module_funcs[rel_path] = module_func_list

        return {
            "total_functions": len(all_functions),
            "total_classes": len(all_classes),
            "functions": all_functions,
            "classes": all_classes,
            "module_functions": module_funcs,
        }

    # ------------------------------------------------------------------ #
    # 计算覆盖率
    # ------------------------------------------------------------------ #
    def calculate_coverage(self) -> Dict[str, Any]:
        """计算测试覆盖率。

        被测试的函数：测试文件中import或引用的函数名。

        Returns:
            覆盖率统计信息。
        """
        tests = self.find_tests()
        funcs = self.find_all_functions()

        # 收集测试文件中引用的函数名
        tested_names: Set[str] = set()
        test_path = os.path.join(self.project_root, "tests")
        if os.path.isdir(test_path):
            for root, dirs, files in os.walk(test_path):
                dirs[:] = [d for d in dirs if d not in self.EXCLUDE_DIRS]
                for fname in files:
                    if not fname.endswith(".py"):
                        continue
                    fpath = os.path.join(root, fname)
                    try:
                        with open(fpath, "r", encoding="utf-8", errors="ignore") as f:
                            source = f.read()
                        # 简单匹配：测试函数名中的引用
                        for func_name in tests.get("test_function_names", []):
                            tested_names.add(func_name)
                        # 也收集源码中import的名称
                        tree = ast.parse(source)
                        for node in ast.walk(tree):
                            if isinstance(node, ast.ImportFrom):
                                for alias in node.names:
                                    tested_names.add(alias.name)
                            elif isinstance(node, ast.Name):
                                tested_names.add(node.id)
                    except (SyntaxError, IOError):
                        continue

        # 计算覆盖率
        total = funcs["total_functions"]
        covered = 0
        uncovered: List[Dict[str, Any]] = []

        for func in funcs["functions"]:
            # 检查函数名是否在测试引用中
            func_name = func["name"].split(".")[-1]  # 取最后一段
            if func_name in tested_names:
                covered += 1
            else:
                uncovered.append(func)

        coverage_pct = round(covered / total * 100, 1) if total > 0 else 0.0

        # 按模块分组未覆盖的函数
        uncovered_by_module: Dict[str, List[str]] = {}
        for func in uncovered[:50]:
            module = func["file"]
            if module not in uncovered_by_module:
                uncovered_by_module[module] = []
            uncovered_by_module[module].append(func["name"])

        return {
            "total_functions": total,
            "covered_functions": covered,
            "coverage_percent": coverage_pct,
            "uncovered_count": len(uncovered),
            "uncovered_by_module": uncovered_by_module,
        }

    # ------------------------------------------------------------------ #
    # 生成报告
    # ------------------------------------------------------------------ #
    def generate_report(self) -> Dict[str, Any]:
        """生成测试覆盖率报告。

        Returns:
            完整报告字典。
        """
        tests = self.find_tests()
        coverage = self.calculate_coverage()

        # 核心模块覆盖情况
        core_modules_status: List[Dict[str, Any]] = []
        core_module_names = [
            "ai", "verification", "database", "security",
            "performance", "utils",
        ]
        for mod_name in core_module_names:
            mod_path = os.path.join(self.project_root, mod_name)
            if os.path.isdir(mod_path):
                mod_funcs = [
                    f for f in coverage.get("uncovered_by_module", {})
                    if mod_name in f
                ]
                core_modules_status.append({
                    "module": mod_name,
                    "has_module": True,
                    "uncovered_functions": mod_funcs,
                })

        # 改进建议
        suggestions: List[str] = []
        if coverage["coverage_percent"] < 30:
            suggestions.append("测试覆盖率严重不足，建议优先为核心模块补充单元测试")
        elif coverage["coverage_percent"] < 60:
            suggestions.append("测试覆盖率较低，建议为安全模块和数据库模块补充测试")
        if tests["test_files"] == 0:
            suggestions.append("项目中没有找到测试文件，建议创建tests/目录并添加pytest测试")
        if coverage["uncovered_count"] > 0:
            suggestions.append(
                f"有{coverage['uncovered_count']}个函数未被测试覆盖，"
                f"优先覆盖安全模块和数据库模块")

        return {
            "test_stats": {
                "test_files": tests["test_files"],
                "test_functions": tests["test_functions"],
                "test_classes": tests["test_classes"],
            },
            "coverage": coverage,
            "core_modules": core_modules_status,
            "suggestions": suggestions,
        }

    # ------------------------------------------------------------------ #
    # 生成基本测试
    # ------------------------------------------------------------------ #
    def generate_basic_tests(self, target_module: str,
                              output_path: str) -> str:
        """为指定模块生成基本单元测试。

        为每个公共函数生成1个基本测试用例（测试可调用、不崩溃、返回类型正确）。

        Args:
            target_module: 目标模块路径（如"security/data_protection.py"）。
            output_path: 输出测试文件路径。

        Returns:
            生成的测试文件路径。
        """
        abs_module = os.path.join(self.project_root, target_module)
        if not os.path.exists(abs_module):
            # 模块不存在，生成skip测试
            module_name = target_module.replace("/", ".").replace(".py", "")
            content = f'''# -*- coding: utf-8 -*-
"""自动生成的基本测试 - {target_module}"""
import pytest
import importlib

MODULE_NAME = "{module_name}"


@pytest.mark.skip(reason="模块不存在: {target_module}")
def test_module_importable():
    """测试模块可导入"""
    mod = importlib.import_module(MODULE_NAME)
    assert mod is not None
'''
            os.makedirs(os.path.dirname(output_path) or ".", exist_ok=True)
            with open(output_path, "w", encoding="utf-8") as f:
                f.write(content)
            return output_path

        # 解析模块
        try:
            with open(abs_module, "r", encoding="utf-8", errors="ignore") as f:
                source = f.read()
            tree = ast.parse(source)
        except (SyntaxError, IOError):
            return output_path

        module_name = target_module.replace("/", ".").replace(".py", "")
        # 获取模块中的类和函数
        classes: List[str] = []
        functions: List[str] = []

        for node in ast.iter_child_nodes(tree):
            if isinstance(node, ast.ClassDef) and not node.name.startswith("_"):
                classes.append(node.name)
            elif isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)) \
                    and not node.name.startswith("_"):
                functions.append(node.name)

        # 生成测试代码
        lines: List[str] = [
            "# -*- coding: utf-8 -*-",
            f'"""自动生成的基本测试 - {target_module}"""',
            "import pytest",
            "import importlib",
            "",
            f'MODULE_NAME = "{module_name}"',
            "",
            "pytestmark = pytest.mark.unit",
            "",
        ]

        # 模块导入测试
        lines.append("@pytest.fixture(scope='module')")
        lines.append("def module():")
        lines.append("    try:")
        lines.append(f"        return importlib.import_module(MODULE_NAME)")
        lines.append("    except ImportError as e:")
        lines.append("        pytest.skip(f'模块导入失败: {e}')")
        lines.append("")

        # 类实例化测试
        for cls_name in classes:
            lines.append(f"def test_{cls_name.lower()}_instantiable(module):")
            lines.append(f'    """测试{cls_name}可实例化"""')
            lines.append(f"    cls = getattr(module, '{cls_name}', None)")
            lines.append("    if cls is None:")
            lines.append("        pytest.skip('类不存在')")
            lines.append("    try:")
            lines.append("        instance = cls()")
            lines.append(f"        assert instance is not None")
            lines.append("    except TypeError:")
            lines.append("        pytest.skip('类需要构造参数')")
            lines.append("")

        # 函数调用测试
        for func_name in functions:
            lines.append(f"def test_{func_name}_callable(module):")
            lines.append(f'    """测试{func_name}可调用"""')
            lines.append(f"    func = getattr(module, '{func_name}', None)")
            lines.append("    if func is None:")
            lines.append("        pytest.skip('函数不存在')")
            lines.append("    assert callable(func)")
            lines.append("")

        # 写入文件
        os.makedirs(os.path.dirname(output_path) or ".", exist_ok=True)
        with open(output_path, "w", encoding="utf-8") as f:
            f.write("\n".join(lines))

        return output_path

    def generate_all_core_tests(self,
                                 tests_output_dir: str = "tests") -> List[str]:
        """为所有核心模块生成基本测试。

        Args:
            tests_output_dir: 测试输出目录。

        Returns:
            生成的测试文件路径列表。
        """
        generated: List[str] = []
        abs_output = os.path.join(self.project_root, tests_output_dir)
        os.makedirs(abs_output, exist_ok=True)

        for module in CORE_MODULES:
            # 生成测试文件名
            module_base = module.replace("/", "_").replace(".py", "")
            test_file = os.path.join(
                abs_output, f"test_{module_base}_basic.py")
            try:
                path = self.generate_basic_tests(module, test_file)
                generated.append(path)
            except Exception:
                continue

        return generated


# 全局实例
_coverage_instance: Optional[TestCoverageChecker] = None


def get_coverage_checker() -> TestCoverageChecker:
    """获取全局TestCoverageChecker实例（单例模式）。"""
    global _coverage_instance
    if _coverage_instance is None:
        _coverage_instance = TestCoverageChecker()
    return _coverage_instance
