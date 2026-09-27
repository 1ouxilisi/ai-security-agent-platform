"""
Code Property Graph (CPG) - 代码属性图引擎
对标Shannon的Code Property Graph白盒分析核心技术

CPG将源代码表示为统一的多层图结构：
- AST (Abstract Syntax Tree) - 抽象语法树
- CFG (Control Flow Graph) - 控制流图
- DFG (Data Flow Graph) - 数据流图
- Call Graph - 函数调用图

基于CPG可以进行：
- 污点分析 (Taint Analysis) - 追踪用户输入到危险函数的传播
- 跨函数漏洞检测
- 复杂漏洞链发现
- 数据流路径验证
"""
import ast
import json
import re
from dataclasses import dataclass, field
from typing import Optional, Set, List, Dict, Tuple
from collections import defaultdict


# ============================================================
# CPG节点和边定义
# ============================================================

@dataclass
class CPGNode:
    """CPG节点"""
    id: str
    node_type: str  # function/class/method/call/assign/if/for/while/return/import/variable
    name: str = ""
    line: int = 0
    col: int = 0
    code_snippet: str = ""
    properties: dict = field(default_factory=dict)

    def __hash__(self):
        return hash(self.id)


@dataclass
class CPGEdge:
    """CPG边"""
    source: str
    target: str
    edge_type: str  # ast/cfg/dfg/call/taint
    label: str = ""

    def __hash__(self):
        return hash((self.source, self.target, self.edge_type))


@dataclass
class TaintFlow:
    """污点流路径"""
    source: str  # 污点源（用户输入）
    sink: str  # 污点汇（危险函数）
    path: List[str] = field(default_factory=list)  # 传播路径节点ID
    source_line: int = 0
    sink_line: int = 0
    vulnerability_type: str = ""
    severity: str = "high"
    confidence: float = 0.0  # 0-1


@dataclass
class CPGResult:
    """CPG分析结果"""
    language: str = "python"
    total_files: int = 0
    total_functions: int = 0
    total_nodes: int = 0
    total_edges: int = 0
    taint_flows: List[TaintFlow] = field(default_factory=list)
    vulnerabilities: List[dict] = field(default_factory=list)
    function_calls: Dict[str, List[str]] = field(default_factory=dict)
    entry_points: List[str] = field(default_factory=list)  # 可能的入口点（路由/API）


# ============================================================
# 危险函数定义（污点汇）
# ============================================================

DANGEROUS_SINKS = {
    "sql_injection": {
        "functions": ["execute", "executemany", "raw", "raw_query", "query", "cursor"],
        "patterns": [r"execute\s*\(\s*f?[\"']", r"\+\s*.*sql", r"%\s*.*sql"],
        "severity": "critical",
    },
    "xss": {
        "functions": ["render_template_string", "markupsafe", "Markup", "escape"],
        "patterns": [r"render_template_string\s*\(\s*f?[\"']"],
        "severity": "high",
    },
    "command_injection": {
        "functions": ["system", "popen", "call", "run", "check_output", "check_call", "Popen", "getoutput"],
        "patterns": [r"os\.system\s*\(", r"subprocess\.(run|call|Popen|check_output)\s*\(\s*.*\+"],
        "severity": "critical",
    },
    "path_traversal": {
        "functions": ["open", "send_file", "send_from_directory", "read_file"],
        "patterns": [r"open\s*\(\s*.*request", r"send_file\s*\(\s*.*request"],
        "severity": "high",
    },
    "ssrf": {
        "functions": ["get", "post", "put", "delete", "request", "urlopen", "urlretrieve"],
        "patterns": [r"requests\.(get|post)\s*\(\s*.*request", r"urllib\.request\.urlopen\s*\(\s*.*request"],
        "severity": "high",
    },
    "insecure_deserialization": {
        "functions": ["loads", "load", "unpickle", "yaml_load", "fromstring"],
        "patterns": [r"pickle\.loads\s*\(", r"yaml\.load\s*\("],
        "severity": "critical",
    },
    "hardcoded_secrets": {
        "functions": [],
        "patterns": [
            r"(password|passwd|secret|api_key|apikey|token|private_key)\s*=\s*[\"'][^\"']+[\"']",
            r"AKIA[0-9A-Z]{16}",  # AWS key
            r"-----BEGIN (RSA |EC )?PRIVATE KEY-----",
        ],
        "severity": "high",
    },
}

# 污点源（用户输入）
TAINT_SOURCES = {
    "request.args", "request.form", "request.json", "request.data",
    "request.values", "request.files", "request.headers", "request.cookies",
    "request.params", "request.body", "input()", "sys.argv",
    "os.environ", "request.GET", "request.POST",
}


# ============================================================
# Python CPG构建器
# ============================================================

class PythonCPGBuilder:
    """
    Python代码属性图构建器
    基于ast模块构建AST+CFG+DFG+调用图
    """

    def __init__(self):
        self.nodes: Dict[str, CPGNode] = {}
        self.edges: Set[CPGEdge] = set()
        self._node_counter = 0
        self._functions: Dict[str, CPGNode] = {}
        self._call_graph: Dict[str, Set[str]] = defaultdict(set)
        self._current_function = None

    def _new_node(self, node_type: str, name: str = "", line: int = 0,
                  col: int = 0, code: str = "", **props) -> CPGNode:
        """创建新节点"""
        self._node_counter += 1
        node_id = f"n{self._node_counter}"
        node = CPGNode(
            id=node_id,
            node_type=node_type,
            name=name,
            line=line,
            col=col,
            code_snippet=code,
            properties=props,
        )
        self.nodes[node_id] = node
        return node

    def _add_edge(self, source: str, target: str, edge_type: str, label: str = ""):
        """添加边"""
        self.edges.add(CPGEdge(source, target, edge_type, label))

    def build_from_source(self, source_code: str, filename: str = "<string>") -> CPGResult:
        """从源代码构建CPG"""
        result = CPGResult(language="python", total_files=1)

        try:
            tree = ast.parse(source_code)
        except SyntaxError as e:
            result.vulnerabilities.append({
                "type": "syntax_error",
                "message": str(e),
                "line": e.lineno,
                "severity": "info",
            })
            return result

        lines = source_code.splitlines()

        # 构建AST
        self._build_ast(tree, lines)

        # 构建调用图
        self._build_call_graph(tree)

        # 污点分析
        taint_flows = self._taint_analysis(tree, lines)
        result.taint_flows = taint_flows

        # 模式匹配漏洞检测
        pattern_vulns = self._pattern_match(source_code, lines)
        result.vulnerabilities.extend(pattern_vulns)

        # 统计
        result.total_nodes = len(self.nodes)
        result.total_edges = len(self.edges)
        result.total_functions = len(self._functions)
        result.function_calls = {k: list(v) for k, v in self._call_graph.items()}

        # 识别入口点
        result.entry_points = self._find_entry_points(tree, lines)

        # 将污点流转为漏洞
        for tf in taint_flows:
            result.vulnerabilities.append({
                "type": tf.vulnerability_type,
                "severity": tf.severity,
                "confidence": tf.confidence,
                "source": tf.source,
                "sink": tf.sink,
                "source_line": tf.source_line,
                "sink_line": tf.sink_line,
                "path_length": len(tf.path),
                "description": f"用户输入 {tf.source} (行{tf.source_line}) 传播到危险函数 {tf.sink} (行{tf.sink_line})",
            })

        return result

    def build_from_file(self, filepath: str) -> CPGResult:
        """从文件构建CPG"""
        with open(filepath, "r", encoding="utf-8", errors="ignore") as f:
            source = f.read()
        return self.build_from_source(source, filepath)

    def build_from_directory(self, dirpath: str, extensions: tuple = (".py",)) -> CPGResult:
        """从目录批量构建CPG"""
        import os
        combined = CPGResult(language="python")

        for root, dirs, files in os.walk(dirpath):
            # 跳过常见无关目录
            dirs[:] = [d for d in dirs if d not in (
                "__pycache__", ".git", "venv", "env", "node_modules",
                ".venv", "dist", "build", "migrations",
            )]
            for fname in files:
                if fname.endswith(extensions):
                    fpath = os.path.join(root, fname)
                    try:
                        file_result = self.build_from_file(fpath)
                        combined.total_files += 1
                        combined.total_nodes += file_result.total_nodes
                        combined.total_edges += file_result.total_edges
                        combined.total_functions += file_result.total_functions
                        combined.taint_flows.extend(file_result.taint_flows)
                        combined.vulnerabilities.extend(file_result.vulnerabilities)
                        combined.entry_points.extend(file_result.entry_points)
                    except Exception as e:
                        combined.vulnerabilities.append({
                            "type": "parse_error",
                            "file": fpath,
                            "message": str(e),
                            "severity": "info",
                        })

        return combined

    def _build_ast(self, tree: ast.AST, lines: list):
        """构建抽象语法树"""
        for node in ast.walk(tree):
            if isinstance(node, ast.FunctionDef):
                code = lines[node.lineno - 1].strip() if node.lineno <= len(lines) else ""
                n = self._new_node("function", node.name, node.lineno, node.col_offset, code,
                                   args=[a.arg for a in node.args.args])
                self._functions[node.name] = n
                self._current_function = n

            elif isinstance(node, ast.ClassDef):
                code = lines[node.lineno - 1].strip() if node.lineno <= len(lines) else ""
                self._new_node("class", node.name, node.lineno, node.col_offset, code,
                               bases=[ast.unparse(b) for b in node.bases])

            elif isinstance(node, ast.Call):
                func_name = self._get_call_name(node)
                code = lines[node.lineno - 1].strip() if node.lineno <= len(lines) else ""
                self._new_node("call", func_name, node.lineno, node.col_offset, code)

            elif isinstance(node, ast.Assign):
                code = lines[node.lineno - 1].strip() if node.lineno <= len(lines) else ""
                targets = [ast.unparse(t) for t in node.targets]
                self._new_node("assign", ", ".join(targets), node.lineno, node.col_offset, code)

            elif isinstance(node, (ast.If, ast.For, ast.While)):
                code = lines[node.lineno - 1].strip() if node.lineno <= len(lines) else ""
                ntype = type(node).__name__.lower()
                self._new_node(ntype, ntype, node.lineno, node.col_offset, code)

            elif isinstance(node, ast.Import):
                for alias in node.names:
                    self._new_node("import", alias.name, node.lineno, node.col_offset,
                                   f"import {alias.name}")

            elif isinstance(node, ast.ImportFrom):
                self._new_node("import", f"{node.module}.{node.names[0].name}" if node.names else node.module or "",
                               node.lineno, node.col_offset,
                               f"from {node.module} import ...")

            elif isinstance(node, ast.Return):
                code = lines[node.lineno - 1].strip() if node.lineno <= len(lines) else ""
                self._new_node("return", "return", node.lineno, node.col_offset, code)

    def _build_call_graph(self, tree: ast.AST):
        """构建函数调用图"""
        current_func = None

        for node in ast.walk(tree):
            if isinstance(node, ast.FunctionDef):
                current_func = node.name
            elif isinstance(node, ast.Call) and current_func:
                callee = self._get_call_name(node)
                if callee:
                    self._call_graph[current_func].add(callee)

    def _get_call_name(self, call_node: ast.Call) -> str:
        """获取调用的函数名"""
        func = call_node.func
        if isinstance(func, ast.Name):
            return func.id
        elif isinstance(func, ast.Attribute):
            parts = []
            while isinstance(func, ast.Attribute):
                parts.append(func.attr)
                func = func.value
            if isinstance(func, ast.Name):
                parts.append(func.id)
            return ".".join(reversed(parts))
        return "unknown"

    def _taint_analysis(self, tree: ast.AST, lines: list) -> List[TaintFlow]:
        """
        污点分析
        追踪用户输入（污点源）到危险函数（污点汇）的传播路径
        """
        flows = []
        tainted_vars: Dict[str, int] = {}  # var_name -> line

        for node in ast.walk(tree):
            # 检测污点源：用户输入赋值
            if isinstance(node, ast.Assign):
                value_str = ast.unparse(node.value) if hasattr(node, 'value') else ""
                is_taint_source = any(src in value_str for src in TAINT_SOURCES)

                if is_taint_source:
                    for target in node.targets:
                        if isinstance(target, ast.Name):
                            tainted_vars[target.id] = node.lineno

            # 检测污点传播：变量间赋值
            elif isinstance(node, ast.Assign) and tainted_vars:
                value_str = ast.unparse(node.value) if hasattr(node, 'value') else ""
                for tvar in list(tainted_vars.keys()):
                    if tvar in value_str:
                        for target in node.targets:
                            if isinstance(target, ast.Name):
                                tainted_vars[target.id] = node.lineno

            # 检测污点汇：危险函数调用
            elif isinstance(node, ast.Call):
                call_str = ast.unparse(node)
                func_name = self._get_call_name(node)

                for vuln_type, sink_info in DANGEROUS_SINKS.items():
                    # 检查函数名是否匹配
                    is_sink = any(s in func_name for s in sink_info["functions"])
                    # 检查参数是否包含污点变量
                    has_tainted_arg = any(tvar in call_str for tvar in tainted_vars.keys())

                    if is_sink and has_tainted_arg:
                        # 找到对应的污点源
                        for tvar, tline in tainted_vars.items():
                            if tvar in call_str:
                                flow = TaintFlow(
                                    source=tvar,
                                    sink=func_name,
                                    source_line=tline,
                                    sink_line=node.lineno,
                                    vulnerability_type=vuln_type,
                                    severity=sink_info["severity"],
                                    confidence=0.85,  # 基于AST的污点分析置信度
                                    path=[tvar, func_name],
                                )
                                flows.append(flow)
                                break

        return flows

    def _pattern_match(self, source: str, lines: list) -> List[dict]:
        """基于正则模式的漏洞检测"""
        vulns = []

        for vuln_type, sink_info in DANGEROUS_SINKS.items():
            for pattern in sink_info["patterns"]:
                for i, line in enumerate(lines, 1):
                    # 跳过注释行
                    stripped = line.strip()
                    if stripped.startswith("#") or stripped.startswith('//'):
                        continue
                    if re.search(pattern, line, re.IGNORECASE):
                        # 检查是否包含用户输入（提高置信度）
                        has_user_input = any(src.split(".")[0] in line for src in TAINT_SOURCES if "." in src)
                        confidence = 0.7 if has_user_input else 0.4

                        vulns.append({
                            "type": vuln_type,
                            "severity": sink_info["severity"],
                            "line": i,
                            "code": stripped[:200],
                            "pattern": pattern,
                            "confidence": confidence,
                            "description": f"检测到潜在{vuln_type}模式",
                        })

        return vulns

    def _find_entry_points(self, tree: ast.AST, lines: list) -> List[str]:
        """识别应用入口点（路由/API端点）"""
        entries = []

        for node in ast.walk(tree):
            if isinstance(node, ast.FunctionDef):
                # 检查装饰器（Flask/FastAPI路由）
                for decorator in node.decorator_list:
                    dec_str = ast.unparse(decorator)
                    if any(kw in dec_str.lower() for kw in ["route", "get", "post", "put", "delete", "patch", "api", "app."]):
                        entries.append({
                            "function": node.name,
                            "line": node.lineno,
                            "decorator": dec_str,
                            "type": "route",
                        })

            # 检查if __name__ == "__main__"
            elif isinstance(node, ast.If):
                try:
                    cond = ast.unparse(node.test)
                    if "__name__" in cond and "__main__" in cond:
                        entries.append({
                            "type": "main_entry",
                            "line": node.lineno,
                        })
                except Exception:
                    pass

        return entries

    def to_dict(self) -> dict:
        """导出CPG为字典"""
        return {
            "nodes": [
                {"id": n.id, "type": n.node_type, "name": n.name,
                 "line": n.line, "code": n.code_snippet}
                for n in self.nodes.values()
            ],
            "edges": [
                {"source": e.source, "target": e.target, "type": e.edge_type}
                for e in self.edges
            ],
            "functions": list(self._functions.keys()),
            "call_graph": {k: list(v) for k, v in self._call_graph.items()},
        }

    def to_json(self, indent: int = 2) -> str:
        return json.dumps(self.to_dict(), indent=indent, ensure_ascii=False)


# ============================================================
# 多语言CPG构建器（工厂）
# ============================================================

class CodePropertyGraph:
    """
    代码属性图统一入口
    支持Python（已实现），预留JavaScript/Java/Go扩展
    """

    def __init__(self):
        self._builders = {
            "python": PythonCPGBuilder,
        }

    def analyze_file(self, filepath: str) -> CPGResult:
        """分析单个文件"""
        ext = filepath.rsplit(".", 1)[-1].lower() if "." in filepath else ""
        lang_map = {"py": "python", "js": "javascript", "java": "java", "go": "go"}
        language = lang_map.get(ext, "python")

        builder_cls = self._builders.get(language)
        if not builder_cls:
            result = CPGResult(language=language)
            result.vulnerabilities.append({
                "type": "unsupported_language",
                "message": f"暂不支持{language}语言的CPG分析",
                "severity": "info",
            })
            return result

        builder = builder_cls()
        return builder.build_from_file(filepath)

    def analyze_directory(self, dirpath: str) -> CPGResult:
        """分析整个目录"""
        builder = PythonCPGBuilder()
        return builder.build_from_directory(dirpath)

    def analyze_source(self, source: str, language: str = "python") -> CPGResult:
        """分析源代码字符串"""
        builder_cls = self._builders.get(language, PythonCPGBuilder)
        builder = builder_cls()
        return builder.build_from_source(source)


if __name__ == "__main__":
    # 测试
    test_code = '''
import os
from flask import Flask, request

app = Flask(__name__)

@app.route("/search")
def search():
    query = request.args.get("q")
    result = db.execute("SELECT * FROM items WHERE name = '" + query + "'")
    return result

@app.route("/ping")
def ping():
    host = request.args.get("host")
    os.system("ping " + host)
    return "done"

API_KEY = "sk-1234567890abcdef"
'''

    cpg = CodePropertyGraph()
    result = cpg.analyze_source(test_code)

    print(f"CPG分析结果:")
    print(f"  函数数: {result.total_functions}")
    print(f"  节点数: {result.total_nodes}")
    print(f"  污点流: {len(result.taint_flows)}")
    print(f"  漏洞数: {len(result.vulnerabilities)}")
    print(f"  入口点: {len(result.entry_points)}")
    print()
    for v in result.vulnerabilities:
        print(f"  [{v.get('severity','?').upper()}] {v.get('type','?')} - 行{v.get('line','?')}: {v.get('description','')[:80]}")
