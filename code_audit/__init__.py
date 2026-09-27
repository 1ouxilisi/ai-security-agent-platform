#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
代码审计模块
提供静态代码分析、依赖漏洞扫描、敏感信息检测功能
"""

import os
import re
import json
import subprocess
from datetime import datetime
from typing import Dict, List, Any, Optional
from dataclasses import dataclass, field


@dataclass
class CodeIssue:
    """代码问题"""
    file_path: str = ""
    line_number: int = 0
    issue_type: str = ""
    severity: str = ""
    description: str = ""
    code_snippet: str = ""
    recommendation: str = ""
    cwe: str = ""


class CodeAuditor:
    """代码审计器"""

    # 危险函数模式（按语言）
    DANGEROUS_PATTERNS = {
        'python': [
            {'pattern': r'eval\s*\(', 'issue': '代码注入', 'severity': 'Critical', 'cwe': 'CWE-95'},
            {'pattern': r'exec\s*\(', 'issue': '代码注入', 'severity': 'Critical', 'cwe': 'CWE-95'},
            {'pattern': r'os\.system\s*\(', 'issue': '命令注入', 'severity': 'High', 'cwe': 'CWE-78'},
            {'pattern': r'subprocess\.(call|run|Popen)\s*\([^)]*shell\s*=\s*True', 'issue': '命令注入', 'severity': 'High', 'cwe': 'CWE-78'},
            {'pattern': r'pickle\.loads?\s*\(', 'issue': '反序列化漏洞', 'severity': 'Critical', 'cwe': 'CWE-502'},
            {'pattern': r'yaml\.load\s*\([^)]*\)', 'issue': '反序列化漏洞', 'severity': 'High', 'cwe': 'CWE-502'},
            {'pattern': r'(\.execute|\.executemany)\s*\(\s*["\'].*%s.*["\']\s*%', 'issue': 'SQL注入', 'severity': 'Critical', 'cwe': 'CWE-89'},
            {'pattern': r'(\.execute|\.executemany)\s*\(\s*f["\']', 'issue': 'SQL注入', 'severity': 'Critical', 'cwe': 'CWE-89'},
            {'pattern': r'render_template_string\s*\(\s*f["\']', 'issue': 'XSS/模板注入', 'severity': 'High', 'cwe': 'CWE-79'},
            {'pattern': r'markup\.Markup\s*\(', 'issue': 'XSS', 'severity': 'Medium', 'cwe': 'CWE-79'},
            {'pattern': r'password\s*=\s*["\'][^"\']+["\']', 'issue': '硬编码密码', 'severity': 'High', 'cwe': 'CWE-259'},
            {'pattern': r'secret_key\s*=\s*["\'][^"\']+["\']', 'issue': '硬编码密钥', 'severity': 'High', 'cwe': 'CWE-321'},
            {'pattern': r'api[_-]?key\s*=\s*["\'][^"\']+["\']', 'issue': '硬编码API密钥', 'severity': 'High', 'cwe': 'CWE-798'},
            {'pattern': r'print\s*\(', 'issue': '调试信息泄露', 'severity': 'Low', 'cwe': 'CWE-215'},
            {'pattern': r'#\s*TODO|#\s*FIXME|#\s*HACK|#\s*XXX', 'issue': '待修复代码', 'severity': 'Low', 'cwe': ''},
        ],
        'javascript': [
            {'pattern': r'eval\s*\(', 'issue': '代码注入', 'severity': 'Critical', 'cwe': 'CWE-95'},
            {'pattern': r'Function\s*\(', 'issue': '代码注入', 'severity': 'High', 'cwe': 'CWE-95'},
            {'pattern': r'document\.write\s*\(', 'issue': 'XSS', 'severity': 'High', 'cwe': 'CWE-79'},
            {'pattern': r'(innerHTML|outerHTML)\s*=', 'issue': 'XSS', 'severity': 'High', 'cwe': 'CWE-79'},
            {'pattern': r'window\.location\s*=', 'issue': '开放重定向', 'severity': 'Medium', 'cwe': 'CWE-601'},
            {'pattern': r'localStorage\.(setItem|getItem)', 'issue': '不安全存储', 'severity': 'Medium', 'cwe': 'CWE-922'},
            {'pattern': r'password\s*[:=]\s*["\'][^"\']+["\']', 'issue': '硬编码密码', 'severity': 'High', 'cwe': 'CWE-259'},
            {'pattern': r'api[_-]?key\s*[:=]\s*["\'][^"\']+["\']', 'issue': '硬编码API密钥', 'severity': 'High', 'cwe': 'CWE-798'},
            {'pattern': r'console\.(log|debug|info)', 'issue': '调试信息泄露', 'severity': 'Low', 'cwe': 'CWE-215'},
        ],
        'php': [
            {'pattern': r'eval\s*\(', 'issue': '代码注入', 'severity': 'Critical', 'cwe': 'CWE-95'},
            {'pattern': r'system\s*\(|exec\s*\(|shell_exec\s*\(|passthru\s*\(', 'issue': '命令注入', 'severity': 'High', 'cwe': 'CWE-78'},
            {'pattern': r'mysql_query\s*\([^)]*\$_(GET|POST|REQUEST)', 'issue': 'SQL注入', 'severity': 'Critical', 'cwe': 'CWE-89'},
            {'pattern': r'(\$_GET|\$_POST|\$_REQUEST)\s*\[\s*["\'].*["\']\s*\]\s*\.\s*["\'].*FROM', 'issue': 'SQL注入', 'severity': 'Critical', 'cwe': 'CWE-89'},
            {'pattern': r'echo\s+(\$_GET|\$_POST|\$_REQUEST)', 'issue': 'XSS', 'severity': 'High', 'cwe': 'CWE-79'},
            {'pattern': r'include\s*\(?\s*(\$_GET|\$_POST|\$_REQUEST)', 'issue': '文件包含', 'severity': 'Critical', 'cwe': 'CWE-98'},
            {'pattern': r'unserialize\s*\(', 'issue': '反序列化漏洞', 'severity': 'Critical', 'cwe': 'CWE-502'},
            {'pattern': r'md5\s*\(\s*\$_(GET|POST|REQUEST)', 'issue': '弱加密', 'severity': 'Medium', 'cwe': 'CWE-327'},
        ],
        'java': [
            {'pattern': r'Runtime\.getRuntime\(\)\.exec', 'issue': '命令注入', 'severity': 'High', 'cwe': 'CWE-78'},
            {'pattern': r'Statement\.execute(Query|Update)?\s*\([^)]*\+', 'issue': 'SQL注入', 'severity': 'Critical', 'cwe': 'CWE-89'},
            {'pattern': r'ObjectInputStream\.readObject', 'issue': '反序列化漏洞', 'severity': 'Critical', 'cwe': 'CWE-502'},
            {'pattern': r'new\s+ScriptEngineManager', 'issue': '代码注入', 'severity': 'High', 'cwe': 'CWE-95'},
            {'pattern': r'MD5|SHA-?1', 'issue': '弱加密算法', 'severity': 'Medium', 'cwe': 'CWE-327'},
        ],
    }

    # 支持的文件扩展名
    EXTENSIONS = {
        '.py': 'python',
        '.js': 'javascript',
        '.jsx': 'javascript',
        '.ts': 'javascript',
        '.tsx': 'javascript',
        '.php': 'php',
        '.java': 'java',
        '.jsp': 'java',
    }

    def __init__(self):
        self.issues: List[CodeIssue] = []
        self.scanned_files = 0

    def audit_directory(self, directory: str, extensions: List[str] = None) -> List[CodeIssue]:
        """审计目录中的所有代码文件"""
        self.issues = []
        self.scanned_files = 0

        if extensions is None:
            extensions = list(self.EXTENSIONS.keys())

        for root, dirs, files in os.walk(directory):
            # 跳过常见的不需要审计的目录
            dirs[:] = [d for d in dirs if d not in
                      ['node_modules', '.git', '__pycache__', 'venv', '.venv',
                       'dist', 'build', 'target', 'vendor', 'third_party']]

            for file in files:
                ext = os.path.splitext(file)[1].lower()
                if ext in extensions:
                    file_path = os.path.join(root, file)
                    self.audit_file(file_path)

        return self.issues

    def audit_file(self, file_path: str) -> List[CodeIssue]:
        """审计单个文件"""
        file_issues = []

        try:
            ext = os.path.splitext(file_path)[1].lower()
            language = self.EXTENSIONS.get(ext)
            if not language:
                return []

            with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                lines = f.readlines()

            patterns = self.DANGEROUS_PATTERNS.get(language, [])

            for line_num, line in enumerate(lines, 1):
                for pattern_info in patterns:
                    if re.search(pattern_info['pattern'], line, re.IGNORECASE):
                        issue = CodeIssue(
                            file_path=file_path,
                            line_number=line_num,
                            issue_type=pattern_info['issue'],
                            severity=pattern_info['severity'],
                            description=f"在{language}代码中发现{pattern_info['issue']}",
                            code_snippet=line.strip()[:200],
                            recommendation=self._get_recommendation(pattern_info['issue']),
                            cwe=pattern_info.get('cwe', '')
                        )
                        file_issues.append(issue)
                        break  # 每行只报告一个问题

            self.scanned_files += 1
            self.issues.extend(file_issues)

        except Exception as e:
            print(f"文件审计错误 {file_path}: {e}")

        return file_issues

    def _get_recommendation(self, issue_type: str) -> str:
        """获取修复建议"""
        recommendations = {
            '代码注入': '避免使用eval/exec等动态执行函数，使用安全的替代方案',
            '命令注入': '避免使用shell=True，使用参数化的命令执行方式，对用户输入进行严格验证',
            'SQL注入': '使用参数化查询/预编译语句，不要拼接SQL字符串',
            'XSS': '对输出进行HTML转义，使用安全的模板引擎，设置Content-Security-Policy',
            '反序列化漏洞': '不要反序列化不可信数据，使用安全的数据格式（JSON）',
            '文件包含': '不要使用用户输入作为文件路径，使用白名单验证',
            '硬编码密码': '不要在代码中硬编码密码，使用环境变量或密钥管理服务',
            '硬编码密钥': '不要在代码中硬编码密钥，使用环境变量或密钥管理服务',
            '硬编码API密钥': '不要在代码中硬编码API密钥，使用环境变量或密钥管理服务',
            '调试信息泄露': '在生产环境中移除调试输出，使用日志框架并设置合适的日志级别',
            '待修复代码': '及时修复TODO/FIXME标记的代码',
            '开放重定向': '验证重定向URL，使用白名单，不要信任用户输入',
            '不安全存储': '不要在localStorage中存储敏感信息，使用HttpOnly Cookie',
            '弱加密': '使用强加密算法（AES-256、RSA-2048、SHA-256），不要使用MD5/SHA1',
            '模板注入': '不要在模板中使用用户输入，使用安全的模板引擎',
        }
        return recommendations.get(issue_type, '进行安全代码审查，修复潜在漏洞')

    def scan_dependencies(self, directory: str) -> List[Dict]:
        """扫描依赖漏洞"""
        vulnerabilities = []

        # 检查package.json (npm)
        package_json = os.path.join(directory, 'package.json')
        if os.path.exists(package_json):
            try:
                with open(package_json, 'r', encoding='utf-8') as f:
                    data = json.load(f)
                    deps = {**data.get('dependencies', {}), **data.get('devDependencies', {})}
                    vulnerabilities.append({
                        'type': 'npm',
                        'total_dependencies': len(deps),
                        'dependencies': list(deps.keys())[:50],
                        'status': '待检查（建议使用npm audit）'
                    })
            except Exception:
                pass

        # 检查requirements.txt (Python)
        requirements = os.path.join(directory, 'requirements.txt')
        if os.path.exists(requirements):
            try:
                with open(requirements, 'r', encoding='utf-8') as f:
                    lines = [l.strip() for l in f if l.strip() and not l.startswith('#')]
                    vulnerabilities.append({
                        'type': 'pip',
                        'total_dependencies': len(lines),
                        'dependencies': lines[:50],
                        'status': '待检查（建议使用pip-audit或safety）'
                    })
            except Exception:
                pass

        # 检查pom.xml (Java/Maven)
        pom_xml = os.path.join(directory, 'pom.xml')
        if os.path.exists(pom_xml):
            vulnerabilities.append({
                'type': 'maven',
                'status': '待检查（建议使用OWASP Dependency-Check）'
            })

        return vulnerabilities

    def get_statistics(self) -> Dict[str, Any]:
        """获取统计信息"""
        stats = {
            'scanned_files': self.scanned_files,
            'total_issues': len(self.issues),
            'by_severity': {},
            'by_type': {},
            'by_file': {},
        }

        for issue in self.issues:
            stats['by_severity'][issue.severity] = stats['by_severity'].get(issue.severity, 0) + 1
            stats['by_type'][issue.issue_type] = stats['by_type'].get(issue.issue_type, 0) + 1
            stats['by_file'][issue.file_path] = stats['by_file'].get(issue.file_path, 0) + 1

        return stats

    def generate_report(self) -> Dict:
        """生成审计报告"""
        return {
            'report_title': '代码审计报告',
            'generated_time': datetime.now().isoformat(),
            'statistics': self.get_statistics(),
            'issues': [
                {
                    'file_path': issue.file_path,
                    'line_number': issue.line_number,
                    'issue_type': issue.issue_type,
                    'severity': issue.severity,
                    'description': issue.description,
                    'code_snippet': issue.code_snippet,
                    'recommendation': issue.recommendation,
                    'cwe': issue.cwe,
                }
                for issue in self.issues
            ],
        }


# 全局单例
_code_auditor = None

def get_code_auditor() -> CodeAuditor:
    """获取代码审计器单例"""
    global _code_auditor
    if _code_auditor is None:
        _code_auditor = CodeAuditor()
    return _code_auditor


# ============================================================
# Code Property Graph (CPG) - 代码属性图引擎
# 对标Shannon的白盒分析核心技术
# ============================================================
from .code_property_graph import (
    CodePropertyGraph,
    PythonCPGBuilder,
    CPGResult,
    CPGNode,
    CPGEdge,
    TaintFlow,
    DANGEROUS_SINKS,
    TAINT_SOURCES,
)

__all__ = [
    "CodeAuditor",
    "CodeIssue",
    "get_code_auditor",
    # CPG引擎
    "CodePropertyGraph",
    "PythonCPGBuilder",
    "CPGResult",
    "CPGNode",
    "CPGEdge",
    "TaintFlow",
    "DANGEROUS_SINKS",
    "TAINT_SOURCES",
]
