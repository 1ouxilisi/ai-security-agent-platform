# -*- coding: utf-8 -*-
"""
code_formatter模块，提供代码格式化工具。

模块功能：
    - 优先使用autopep8或yapf格式化
    - 降级使用基础格式化规则（缩进/引号/空行/导入顺序/行尾空白）
    - 格式化前自动备份
    - 检查文件格式合规性

注意事项：
    - 本模块仅用于授权的安全测试
    - 请勿用于非法用途
    - 使用前请确保已获得相关授权
"""
import os
import shutil
from typing import Any, Dict, List, Optional, Tuple

# 尝试导入格式化工具
try:
    import autopep8
    _AUTOPEP8_AVAILABLE = True
except ImportError:
    _AUTOPEP8_AVAILABLE = False

try:
    import yapf
    _YAPF_AVAILABLE = True
except ImportError:
    _YAPF_AVAILABLE = False


class CodeFormatter:
    """代码格式化器。

    优先使用autopep8/yapf，不可用时使用基础格式化规则。
    """

    # 标准库模块列表（用于导入顺序判断）
    STANDARD_LIBS = {
        "os", "sys", "re", "json", "time", "datetime", "hashlib",
        "hmac", "secrets", "base64", "pathlib", "typing", "collections",
        "dataclasses", "functools", "itertools", "math", "random",
        "logging", "threading", "multiprocessing", "subprocess",
        "asyncio", "io", "abc", "enum", "copy", "pickle", "sqlite3",
        "unittest", "argparse", "configparser", "shutil", "glob",
        "csv", "html", "http", "urllib", "xml", "zipfile", "tarfile",
        "socket", "struct", "traceback", "inspect", "importlib",
        "contextlib", "warnings", "tempfile", "platform",
    }

    def __init__(self):
        """初始化CodeFormatter实例。"""
        self.formatter = None
        if _AUTOPEP8_AVAILABLE:
            self.formatter = "autopep8"
        elif _YAPF_AVAILABLE:
            self.formatter = "yapf"
        else:
            self.formatter = "basic"

    # ------------------------------------------------------------------ #
    # 单文件格式化
    # ------------------------------------------------------------------ #
    def format_file(self, file_path: str,
                    backup: bool = True) -> Dict[str, Any]:
        """格式化单个Python文件。

        Args:
            file_path: Python文件路径。
            backup: 是否在格式化前创建备份。

        Returns:
            {"success": bool, "formatted": bool, "backup_path": str, "changes": int}
        """
        result = {
            "success": False,
            "formatted": False,
            "backup_path": "",
            "changes": 0,
        }

        if not os.path.exists(file_path) or not file_path.endswith(".py"):
            result["backup_path"] = file_path
            return result

        try:
            # 读取原始内容
            with open(file_path, "r", encoding="utf-8", errors="ignore") as f:
                original = f.read()

            # 创建备份
            backup_path = file_path + ".bak"
            if backup:
                shutil.copy2(file_path, backup_path)
                result["backup_path"] = backup_path

            # 执行格式化
            if self.formatter == "autopep8":
                formatted = autopep8.fix_code(original)
            elif self.formatter == "yapf":
                formatted = yapf.format_code(original)
            else:
                formatted = self._basic_format(original)

            # 计算变化
            if formatted != original:
                with open(file_path, "w", encoding="utf-8") as f:
                    f.write(formatted)
                result["formatted"] = True
                # 粗略计算变化行数
                orig_lines = len(original.splitlines())
                new_lines = len(formatted.splitlines())
                result["changes"] = abs(new_lines - orig_lines) + 1
            else:
                result["formatted"] = False
                result["changes"] = 0

            result["success"] = True

        except Exception as e:
            result["success"] = False
            result["changes"] = 0

        return result

    def _basic_format(self, source: str) -> str:
        """基础格式化规则（当autopep8/yapf不可用时）。

        规则：
            1. tab替换为4空格
            2. 移除行尾空白
            3. 函数之间2空行，类方法之间1空行
            4. 统一导入顺序（标准库/第三方/本地）
        """
        lines = source.splitlines(keepends=False)

        # 1. tab替换为4空格
        lines = [line.replace("\t", "    ") for line in lines]

        # 2. 移除行尾空白
        lines = [line.rstrip() for line in lines]

        # 3. 处理空行规范和导入顺序
        # 分离导入段和其他代码
        import_lines: List[str] = []
        other_lines: List[str] = []
        in_docstring = False
        docstring_char = None

        for line in lines:
            stripped = line.strip()
            # 跳过docstring中的内容
            if in_docstring:
                other_lines.append(line)
                if docstring_char and docstring_char in stripped:
                    in_docstring = False
                    docstring_char = None
                continue

            # 检测docstring开始
            if stripped.startswith('"""') or stripped.startswith("'''"):
                doc_char = '"""' if stripped.startswith('"""') else "'''"
                other_lines.append(line)
                # 单行docstring
                if stripped.count(doc_char) >= 2 and len(stripped) > 3:
                    continue
                in_docstring = True
                docstring_char = doc_char
                continue

            # 收集导入行
            if stripped.startswith("import ") or stripped.startswith("from "):
                import_lines.append(line)
            else:
                other_lines.append(line)

        # 分类导入
        std_imports: List[str] = []
        third_imports: List[str] = []
        local_imports: List[str] = []

        for imp_line in import_lines:
            stripped = imp_line.strip()
            # 提取模块名
            if stripped.startswith("from "):
                module = stripped.split(" ")[1].split(".")[0]
            else:
                module = stripped.split(" ")[1].split(".")[0].split(" as ")[0]

            if module in self.STANDARD_LIBS:
                std_imports.append(imp_line)
            elif module.startswith("."):
                local_imports.append(imp_line)
            else:
                third_imports.append(imp_line)

        # 重新组合：导入段 + 空行 + 其他代码
        result_lines: List[str] = []
        if std_imports:
            result_lines.extend(std_imports)
        if third_imports:
            if result_lines:
                result_lines.append("")
            result_lines.extend(third_imports)
        if local_imports:
            if result_lines:
                result_lines.append("")
            result_lines.extend(local_imports)
        if result_lines and other_lines:
            result_lines.append("")
            result_lines.append("")
        result_lines.extend(other_lines)

        # 合并连续空行（最多保留2个）
        final_lines: List[str] = []
        empty_count = 0
        for line in result_lines:
            if line.strip() == "":
                empty_count += 1
                if empty_count <= 2:
                    final_lines.append("")
            else:
                empty_count = 0
                final_lines.append(line)

        return "\n".join(final_lines) + "\n"

    # ------------------------------------------------------------------ #
    # 目录格式化
    # ------------------------------------------------------------------ #
    def format_directory(self, directory: str,
                         backup: bool = True) -> List[Dict[str, Any]]:
        """格式化目录下所有Python文件。

        Args:
            directory: 目标目录。
            backup: 是否备份。

        Returns:
            每个文件的格式化结果列表。
        """
        results: List[Dict[str, Any]] = []
        exclude_dirs = {".venv", "venv", "__pycache__", "node_modules",
                        "dist", "build", ".git"}

        for root, dirs, files in os.walk(directory):
            dirs[:] = [d for d in dirs if d not in exclude_dirs]
            for fname in files:
                if not fname.endswith(".py"):
                    continue
                fpath = os.path.join(root, fname)
                try:
                    result = self.format_file(fpath, backup=backup)
                    results.append(result)
                except Exception:
                    continue

        return results

    # ------------------------------------------------------------------ #
    # 格式检查
    # ------------------------------------------------------------------ #
    def check_format(self, file_path: str) -> Dict[str, Any]:
        """检查文件是否符合格式规范（不修改文件）。

        Args:
            file_path: Python文件路径。

        Returns:
            {"needs_format": bool, "issues": int, "details": str}
        """
        if not os.path.exists(file_path) or not file_path.endswith(".py"):
            return {"needs_format": False, "issues": 0, "details": "文件不存在"}

        try:
            with open(file_path, "r", encoding="utf-8", errors="ignore") as f:
                original = f.read()
        except IOError:
            return {"needs_format": False, "issues": 0, "details": "无法读取"}

        issues = 0

        # 检查tab缩进
        for line in original.splitlines():
            if "\t" in line:
                issues += 1
                break  # 只需报告一次

        # 检查行尾空白
        for line in original.splitlines():
            if line != line.rstrip():
                issues += 1
                break  # 只需报告一次

        # 检查连续空行>2
        lines = original.splitlines()
        empty_count = 0
        for line in lines:
            if line.strip() == "":
                empty_count += 1
                if empty_count > 2:
                    issues += 1
                    break
            else:
                empty_count = 0

        # 用基础格式化对比
        formatted = self._basic_format(original)
        if formatted != original:
            issues += 1

        return {
            "needs_format": issues > 0,
            "issues": issues,
            "details": f"检测到{issues}个格式问题",
        }


# 全局实例
_code_formatter_instance: Optional[CodeFormatter] = None


def get_code_formatter() -> CodeFormatter:
    """获取全局CodeFormatter实例（单例模式）。"""
    global _code_formatter_instance
    if _code_formatter_instance is None:
        _code_formatter_instance = CodeFormatter()
    return _code_formatter_instance
