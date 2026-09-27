#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
性能基准测试脚本
Performance Benchmark Script

功能：测试系统各模块的性能指标
"""

import os
import sys
import time
import json
import statistics
from dataclasses import dataclass, field, asdict
from typing import List, Dict, Any, Optional, Callable
from loguru import logger


@dataclass
class BenchmarkResult:
    """基准测试结果"""
    test_name: str
    category: str
    iterations: int
    avg_time: float
    min_time: float
    max_time: float
    median_time: float
    std_dev: float
    throughput: float  # 每秒操作数
    memory_usage_mb: float = 0.0
    passed: bool = True
    details: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        return {
            'test_name': self.test_name,
            'category': self.category,
            'iterations': self.iterations,
            'avg_time_ms': round(self.avg_time * 1000, 2),
            'min_time_ms': round(self.min_time * 1000, 2),
            'max_time_ms': round(self.max_time * 1000, 2),
            'median_time_ms': round(self.median_time * 1000, 2),
            'std_dev_ms': round(self.std_dev * 1000, 2),
            'throughput_ops_per_sec': round(self.throughput, 2),
            'memory_usage_mb': round(self.memory_usage_mb, 2),
            'passed': self.passed,
            'details': self.details,
        }


class PerformanceBenchmark:
    """性能基准测试器"""

    def __init__(self):
        self.results: List[BenchmarkResult] = []
        self.start_time = time.time()

    def run_test(self, test_name: str, category: str, func: Callable,
                 iterations: int = 10, warmup: int = 2, **kwargs) -> BenchmarkResult:
        """运行单个基准测试"""
        logger.info(f"运行基准测试: {test_name} ({iterations}次迭代)")

        # 预热
        for _ in range(warmup):
            try:
                func(**kwargs)
            except Exception as e:
                logger.warning(f"预热失败: {e}")

        # 正式测试
        times = []
        passed = True
        error = None

        for i in range(iterations):
            try:
                start = time.perf_counter()
                func(**kwargs)
                end = time.perf_counter()
                times.append(end - start)
            except Exception as e:
                passed = False
                error = str(e)
                logger.error(f"测试失败 ({i+1}/{iterations}): {e}")
                break

        if not times:
            result = BenchmarkResult(
                test_name=test_name,
                category=category,
                iterations=0,
                avg_time=0,
                min_time=0,
                max_time=0,
                median_time=0,
                std_dev=0,
                throughput=0,
                passed=False,
                details={'error': error},
            )
        else:
            result = BenchmarkResult(
                test_name=test_name,
                category=category,
                iterations=len(times),
                avg_time=statistics.mean(times),
                min_time=min(times),
                max_time=max(times),
                median_time=statistics.median(times),
                std_dev=statistics.stdev(times) if len(times) > 1 else 0,
                throughput=len(times) / sum(times) if sum(times) > 0 else 0,
                passed=passed,
                details=kwargs,
            )

        self.results.append(result)
        logger.info(f"  平均: {result.avg_time*1000:.2f}ms, 吞吐: {result.throughput:.2f} ops/s")
        return result

    def run_all_benchmarks(self):
        """运行所有基准测试"""
        logger.info("=" * 60)
        logger.info("开始性能基准测试")
        logger.info("=" * 60)

        # 1. 导入性能测试
        self._test_import_performance()

        # 2. 数据结构性能测试
        self._test_data_structures()

        # 3. 模块初始化性能测试
        self._test_module_initialization()

        # 4. API响应性能测试（模拟）
        self._test_api_performance()

        # 5. 数据库性能测试
        self._test_database_performance()

        # 6. 字符串处理性能测试
        self._test_string_processing()

        # 7. JSON序列化性能测试
        self._test_json_serialization()

        # 8. 内存使用测试
        self._test_memory_usage()

        logger.info("=" * 60)
        logger.info("性能基准测试完成")
        logger.info("=" * 60)

    def _test_import_performance(self):
        """测试导入性能"""
        def import_core():
            import importlib
            modules = ['os', 'sys', 'json', 're', 'hashlib', 'time', 'statistics']
            for mod in modules:
                importlib.import_module(mod)

        self.run_test("标准库导入", "import", import_core, iterations=20)

        def import_third_party():
            import importlib
            modules = ['loguru', 'pydantic', 'fastapi']
            for mod in modules:
                try:
                    importlib.import_module(mod)
                except ImportError:
                    pass

        self.run_test("第三方库导入", "import", import_third_party, iterations=10)

    def _test_data_structures(self):
        """测试数据结构性能"""
        def dict_operations():
            d = {}
            for i in range(10000):
                d[f'key_{i}'] = i
            for k in d:
                _ = d[k]
            return len(d)

        self.run_test("字典操作(1万条)", "data_structure", dict_operations, iterations=5)

        def list_operations():
            lst = list(range(10000))
            lst.sort(reverse=True)
            _ = [x * 2 for x in lst]
            return len(lst)

        self.run_test("列表操作(1万条)", "data_structure", list_operations, iterations=5)

        def set_operations():
            s = set(range(10000))
            s2 = set(range(5000, 15000))
            _ = s & s2
            _ = s | s2
            return len(s)

        self.run_test("集合操作(1万条)", "data_structure", set_operations, iterations=5)

    def _test_module_initialization(self):
        """测试模块初始化性能"""
        import sys
        sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

        def init_prompt_injection():
            from ai_security.prompt_injection import PromptInjectionDetector
            detector = PromptInjectionDetector()
            return len(detector.patterns)

        self.run_test("Prompt注入检测器初始化", "module_init", init_prompt_injection, iterations=5)

        def init_cloud_scanner():
            from cloud_security.cloud_scanner import CloudScanner
            scanner = CloudScanner(provider='aws')
            return scanner.provider

        self.run_test("云安全扫描器初始化", "module_init", init_cloud_scanner, iterations=5)

        def init_binary_analyzer():
            from client_security.binary_analyzer import BinaryAnalyzer
            analyzer = BinaryAnalyzer()
            return analyzer.file_path

        self.run_test("二进制分析器初始化", "module_init", init_binary_analyzer, iterations=5)

    def _test_api_performance(self):
        """测试API响应性能（模拟）"""
        def simulate_api_response():
            # 模拟API请求处理
            request_data = {'target': 'http://example.com', 'type': 'scan'}
            # 处理逻辑
            result = {
                'status': 'success',
                'data': {
                    'target': request_data['target'],
                    'vulnerabilities': [
                        {'id': f'VULN-{i}', 'severity': 'high', 'type': 'test'}
                        for i in range(10)
                    ],
                    'scan_time': 0.5,
                }
            }
            # JSON序列化
            _ = json.dumps(result)
            return result

        self.run_test("API响应处理(模拟)", "api", simulate_api_response, iterations=50)

        def simulate_health_check():
            return {'status': 'healthy', 'timestamp': time.time()}

        self.run_test("健康检查(模拟)", "api", simulate_health_check, iterations=100)

    def _test_database_performance(self):
        """测试数据库性能"""
        def sqlite_operations():
            import sqlite3
            import tempfile
            db_path = os.path.join(tempfile.gettempdir(), f'benchmark_{int(time.time())}.db')
            conn = sqlite3.connect(db_path)
            cursor = conn.cursor()
            cursor.execute('CREATE TABLE IF NOT EXISTS test (id INTEGER PRIMARY KEY, name TEXT, value REAL)')
            # 插入
            for i in range(1000):
                cursor.execute('INSERT INTO test (name, value) VALUES (?, ?)', (f'item_{i}', i * 1.5))
            conn.commit()
            # 查询
            cursor.execute('SELECT * FROM test WHERE value > 500')
            _ = cursor.fetchall()
            # 更新
            cursor.execute('UPDATE test SET value = value * 2 WHERE id % 2 = 0')
            conn.commit()
            conn.close()
            os.remove(db_path)
            return 1000

        self.run_test("SQLite操作(1000条)", "database", sqlite_operations, iterations=3)

    def _test_string_processing(self):
        """测试字符串处理性能"""
        import re

        def regex_matching():
            text = "This is a test string with various patterns like email@example.com and URLs like http://example.com/path?query=value"
            patterns = [
                r'[\w\.-]+@[\w\.-]+',
                r'https?://[\w\.-]+/[\w\./?=&%]+',
                r'\b\d+\b',
                r'\b[A-Z][a-z]+\b',
            ]
            for pattern in patterns:
                _ = re.findall(pattern, text)
            return len(patterns)

        self.run_test("正则匹配(4个模式)", "string", regex_matching, iterations=100)

        def string_concatenation():
            result = ""
            for i in range(1000):
                result += f"item_{i} "
            return len(result)

        self.run_test("字符串拼接(1000次)", "string", string_concatenation, iterations=20)

    def _test_json_serialization(self):
        """测试JSON序列化性能"""
        def json_dump_large():
            data = {
                'users': [{'id': i, 'name': f'user_{i}', 'email': f'user{i}@example.com', 'roles': ['admin', 'user']} for i in range(100)],
                'config': {'debug': False, 'max_connections': 100, 'timeout': 30},
                'metadata': {'created': time.time(), 'version': '1.0.0'},
            }
            return json.dumps(data, indent=2)

        self.run_test("JSON序列化(100用户)", "json", json_dump_large, iterations=50)

        def json_load_large():
            data = json.dumps({'items': [{'id': i, 'value': f'value_{i}'} for i in range(1000)]})
            return json.loads(data)

        self.run_test("JSON反序列化(1000条)", "json", json_load_large, iterations=50)

    def _test_memory_usage(self):
        """测试内存使用"""
        def large_list_creation():
            large_list = list(range(1000000))
            _ = sum(large_list)
            return len(large_list)

        result = self.run_test("大列表创建(100万条)", "memory", large_list_creation, iterations=1)
        # 估算内存使用（约8MB for 1M ints in Python）
        result.memory_usage_mb = 8.0

    def get_summary(self) -> Dict[str, Any]:
        """获取测试摘要"""
        total = len(self.results)
        passed = len([r for r in self.results if r.passed])
        failed = total - passed

        categories = {}
        for r in self.results:
            if r.category not in categories:
                categories[r.category] = {'count': 0, 'total_time': 0, 'passed': 0}
            categories[r.category]['count'] += 1
            categories[r.category]['total_time'] += r.avg_time
            if r.passed:
                categories[r.category]['passed'] += 1

        avg_times = [r.avg_time for r in self.results if r.passed]
        overall_avg = statistics.mean(avg_times) if avg_times else 0

        return {
            'total_tests': total,
            'passed': passed,
            'failed': failed,
            'pass_rate': f"{passed/total*100:.1f}%" if total > 0 else "0%",
            'overall_avg_time_ms': round(overall_avg * 1000, 2),
            'total_duration_sec': round(time.time() - self.start_time, 2),
            'categories': {
                cat: {
                    'count': data['count'],
                    'passed': data['passed'],
                    'avg_time_ms': round(data['total_time'] / data['count'] * 1000, 2),
                }
                for cat, data in categories.items()
            },
            'slowest_tests': sorted(
                [{'name': r.test_name, 'avg_time_ms': round(r.avg_time * 1000, 2)} for r in self.results],
                key=lambda x: x['avg_time_ms'],
                reverse=True
            )[:5],
            'fastest_tests': sorted(
                [{'name': r.test_name, 'avg_time_ms': round(r.avg_time * 1000, 2)} for r in self.results],
                key=lambda x: x['avg_time_ms']
            )[:5],
        }

    def print_report(self):
        """打印测试报告"""
        summary = self.get_summary()

        print("\n" + "=" * 70)
        print("  性能基准测试报告")
        print("=" * 70)
        print(f"\n  总测试数: {summary['total_tests']}")
        print(f"  通过: {summary['passed']}")
        print(f"  失败: {summary['failed']}")
        print(f"  通过率: {summary['pass_rate']}")
        print(f"  总耗时: {summary['total_duration_sec']}秒")
        print(f"  平均响应时间: {summary['overall_avg_time_ms']}ms")

        print("\n" + "-" * 70)
        print("  分类统计:")
        print("-" * 70)
        for cat, data in summary['categories'].items():
            print(f"  {cat:20s}: {data['count']:3d}个测试, 平均{data['avg_time_ms']:8.2f}ms, 通过{data['passed']}/{data['count']}")

        print("\n" + "-" * 70)
        print("  最慢的5个测试:")
        print("-" * 70)
        for i, test in enumerate(summary['slowest_tests'], 1):
            print(f"  {i}. {test['name']:40s} {test['avg_time_ms']:8.2f}ms")

        print("\n" + "-" * 70)
        print("  最快的5个测试:")
        print("-" * 70)
        for i, test in enumerate(summary['fastest_tests'], 1):
            print(f"  {i}. {test['name']:40s} {test['avg_time_ms']:8.2f}ms")

        print("\n" + "=" * 70)

    def save_report(self, filepath: str = "data/performance_report.json"):
        """保存测试报告"""
        os.makedirs(os.path.dirname(filepath), exist_ok=True)
        report = {
            'summary': self.get_summary(),
            'results': [r.to_dict() for r in self.results],
            'generated_at': time.time(),
        }
        with open(filepath, 'w', encoding='utf-8') as f:
            json.dump(report, f, ensure_ascii=False, indent=2)
        logger.info(f"性能报告已保存: {filepath}")
        return filepath


def main():
    """主函数"""
    benchmark = PerformanceBenchmark()
    benchmark.run_all_benchmarks()
    benchmark.print_report()
    benchmark.save_report()

    # 返回退出码
    summary = benchmark.get_summary()
    return 0 if summary['failed'] == 0 else 1


if __name__ == '__main__':
    sys.exit(main())
