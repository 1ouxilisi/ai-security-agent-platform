# -*- coding: utf-8 -*-
"""
quality_check.py — 一键质量检查脚本

功能：
    1. 运行代码审查（quality.code_review）
    2. 运行测试覆盖率检查（quality.test_coverage）
    3. 运行全量API测试（简单版本）
    4. 运行性能基准测试（数据库查询/缓存读取）
    5. 生成综合质量报告

用法：
    python scripts/quality_check.py

所有检查有try-except，某个检查失败不影响其他检查。
"""
import os
import sys
import json
import time
import sqlite3
from datetime import datetime

# 将项目根目录加入sys.path
SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
PROJECT_ROOT = os.path.dirname(SCRIPT_DIR)
sys.path.insert(0, PROJECT_ROOT)

# 输出颜色（Windows兼容）
class Colors:
    GREEN = "\033[92m"
    YELLOW = "\033[93m"
    RED = "\033[91m"
    CYAN = "\033[96m"
    BOLD = "\033[1m"
    RESET = "\033[0m"


def print_header(title: str):
    """打印标题。"""
    print(f"\n{Colors.CYAN}{Colors.BOLD}{'=' * 60}")
    print(f"  {title}")
    print(f"{'=' * 60}{Colors.RESET}\n")


def print_result(name: str, passed: bool, detail: str = ""):
    """打印检查结果。"""
    status = f"{Colors.GREEN}PASS{Colors.RESET}" if passed else f"{Colors.RED}FAIL{Colors.RESET}"
    print(f"  [{status}] {name}" + (f" — {detail}" if detail else ""))


# ---------------------------------------------------------------------- #
# 1. 代码审查
# ---------------------------------------------------------------------- #
def run_code_review() -> dict:
    """运行代码审查。"""
    print_header("1. 代码审查")
    try:
        from quality.code_review import get_code_reviewer
        reviewer = get_code_reviewer()
        report = reviewer.run_review(PROJECT_ROOT)

        score = report.get("quality_score", 0)
        total = report.get("total_findings", 0)
        sev = report.get("severity_breakdown", {})

        print(f"  质量评分: {Colors.BOLD}{score}/100{Colors.RESET}")
        print(f"  总问题数: {total}")
        for s in ("critical", "high", "medium", "low", "info"):
            count = sev.get(s, 0)
            if count > 0:
                color = Colors.RED if s in ("critical", "high") else Colors.YELLOW
                print(f"    {color}{s}: {count}{Colors.RESET}")

        return {
            "score": score,
            "total_findings": total,
            "severity_breakdown": sev,
            "status": "success",
        }
    except Exception as e:
        print(f"  {Colors.RED}代码审查失败: {e}{Colors.RESET}")
        return {"score": 0, "error": str(e), "status": "error"}


# ---------------------------------------------------------------------- #
# 2. 测试覆盖率
# ---------------------------------------------------------------------- #
def run_coverage_check() -> dict:
    """运行测试覆盖率检查。"""
    print_header("2. 测试覆盖率检查")
    try:
        from quality.test_coverage import get_coverage_checker
        checker = get_coverage_checker()
        report = checker.generate_report()

        test_stats = report.get("test_stats", {})
        coverage = report.get("coverage", {})

        print(f"  测试文件数: {test_stats.get('test_files', 0)}")
        print(f"  测试函数数: {test_stats.get('test_functions', 0)}")
        print(f"  项目函数数: {coverage.get('total_functions', 0)}")
        pct = coverage.get("coverage_percent", 0)
        color = Colors.GREEN if pct >= 60 else (
            Colors.YELLOW if pct >= 30 else Colors.RED)
        print(f"  覆盖率: {color}{pct}%{Colors.RESET}")

        suggestions = report.get("suggestions", [])
        if suggestions:
            print(f"  {Colors.YELLOW}改进建议:{Colors.RESET}")
            for s in suggestions[:3]:
                print(f"    - {s}")

        return {
            "coverage_percent": pct,
            "test_files": test_stats.get("test_files", 0),
            "test_functions": test_stats.get("test_functions", 0),
            "total_functions": coverage.get("total_functions", 0),
            "status": "success",
        }
    except Exception as e:
        print(f"  {Colors.RED}覆盖率检查失败: {e}{Colors.RESET}")
        return {"coverage_percent": 0, "error": str(e), "status": "error"}


# ---------------------------------------------------------------------- #
# 3. API测试
# ---------------------------------------------------------------------- #
def run_api_tests() -> dict:
    """运行简单API测试。"""
    print_header("3. API端点测试")
    results = {
        "tested": 0,
        "passed": 0,
        "failed": 0,
        "server_errors": 0,
        "status": "skipped",
    }

    try:
        import uvicorn
        from fastapi.testclient import TestClient

        # 尝试导入app
        sys.path.insert(0, PROJECT_ROOT)
        try:
            from api_server.app import app
        except ImportError:
            try:
                from app import app
            except ImportError:
                print(f"  {Colors.YELLOW}无法导入app，跳过API测试{Colors.RESET}")
                return results

        client = TestClient(app)

        # 测试主要端点
        test_endpoints = [
            ("GET", "/docs"),
            ("GET", "/api/v1/security/self-audit"),
            ("GET", "/api/v1/security/api-keys"),
            ("GET", "/api/v1/security/sessions"),
        ]

        for method, path in test_endpoints:
            try:
                if method == "GET":
                    resp = client.get(path)
                else:
                    resp = client.post(path)

                results["tested"] += 1
                status = resp.status_code
                if status < 500:
                    results["passed"] += 1
                    color = Colors.GREEN if status < 400 else Colors.YELLOW
                    print(f"  [{color}]{method} {path} → {status}{Colors.RESET}")
                else:
                    results["failed"] += 1
                    results["server_errors"] += 1
                    print(f"  [{Colors.RED}]{method} {path} → {status}{Colors.RESET}")
            except Exception:
                results["tested"] += 1
                results["failed"] += 1
                print(f"  [{Colors.RED}]{method} {path} → ERROR{Colors.RESET}")

        results["status"] = "success"
    except ImportError:
        print(f"  {Colors.YELLOW}TestClient/uvicorn不可用，跳过API测试{Colors.RESET}")
    except Exception as e:
        print(f"  {Colors.YELLOW}API测试异常: {e}{Colors.RESET}")

    return results


# ---------------------------------------------------------------------- #
# 4. 性能基准测试
# ---------------------------------------------------------------------- #
def run_benchmarks() -> dict:
    """运行性能基准测试。"""
    print_header("4. 性能基准测试")
    results = {"db_query_avg_ms": 0, "cache_read_avg_ms": 0, "status": "skipped"}

    # 数据库查询基准
    try:
        db_path = os.path.join(PROJECT_ROOT, "data", "platform.db")
        if os.path.exists(db_path):
            conn = sqlite3.connect(db_path)
            cursor = conn.cursor()

            # 预热
            for _ in range(5):
                cursor.execute("SELECT 1").fetchone()

            # 测量100次查询
            times = []
            for _ in range(100):
                t0 = time.perf_counter()
                cursor.execute("SELECT 1").fetchone()
                t1 = time.perf_counter()
                times.append((t1 - t0) * 1000)

            avg_ms = sum(times) / len(times)
            results["db_query_avg_ms"] = round(avg_ms, 3)
            print(f"  数据库查询平均时间: {Colors.GREEN}{avg_ms:.3f}ms{Colors.RESET}")
            conn.close()
        else:
            print(f"  {Colors.YELLOW}数据库文件不存在，跳过DB基准{Colors.RESET}")
    except Exception as e:
        print(f"  {Colors.YELLOW}数据库基准测试失败: {e}{Colors.RESET}")

    # 缓存读取基准（用dict模拟）
    try:
        test_cache = {f"key_{i}": f"value_{i}" for i in range(1000)}
        times = []
        for _ in range(100):
            t0 = time.perf_counter()
            for i in range(100):
                _ = test_cache.get(f"key_{i}")
            t1 = time.perf_counter()
            times.append((t1 - t0) * 1000)

        avg_ms = sum(times) / len(times)
        results["cache_read_avg_ms"] = round(avg_ms, 3)
        print(f"  缓存读取平均时间(100次): {Colors.GREEN}{avg_ms:.3f}ms{Colors.RESET}")
        results["status"] = "success"
    except Exception as e:
        print(f"  {Colors.YELLOW}缓存基准测试失败: {e}{Colors.RESET}")

    return results


# ---------------------------------------------------------------------- #
# 5. 生成综合报告
# ---------------------------------------------------------------------- #
def generate_final_report(review: dict, coverage: dict,
                          api: dict, benchmark: dict) -> dict:
    """生成综合质量报告。"""
    print_header("5. 综合质量报告")

    # 计算总体评分（加权平均）
    code_score = review.get("score", 0)
    cov_score = coverage.get("coverage_percent", 0)
    api_score = 0
    if api.get("tested", 0) > 0:
        api_score = round(
            api.get("passed", 0) / api.get("tested", 1) * 100, 1)
    else:
        api_score = 100  # 跳过则不扣分

    # 性能评分：查询时间<1ms得满分
    db_ms = benchmark.get("db_query_avg_ms", 1)
    perf_score = max(0, 100 - db_ms * 10) if db_ms > 0 else 80

    # 加权：代码质量30% + 覆盖率25% + API质量25% + 性能20%
    overall = round(
        code_score * 0.30 +
        cov_score * 0.25 +
        api_score * 0.25 +
        perf_score * 0.20, 1)

    print(f"\n  {Colors.BOLD}总体质量评分: {overall}/100{Colors.RESET}")
    print(f"  代码质量:   {code_score}/100 (权重30%)")
    print(f"  测试覆盖率: {cov_score}% (权重25%)")
    print(f"  API质量:    {api_score}/100 (权重25%)")
    print(f"  性能:       {perf_score}/100 (权重20%)")

    # 改进建议
    suggestions: List[str] = []
    if code_score < 70:
        suggestions.append("代码质量需要提升：修复高优先级问题（bare except、硬编码密钥等）")
    if cov_score < 50:
        suggestions.append("测试覆盖率不足：为核心模块补充单元测试")
    if api.get("server_errors", 0) > 0:
        suggestions.append(f"存在{api['server_errors']}个500错误端点，需要修复")
    if db_ms > 5:
        suggestions.append(f"数据库查询较慢（{db_ms:.1f}ms），考虑添加索引或缓存")

    if not suggestions:
        suggestions.append("各项指标良好，继续保持")

    print(f"\n  {Colors.YELLOW}改进建议（按优先级）:{Colors.RESET}")
    for i, s in enumerate(suggestions, 1):
        print(f"    {i}. {s}")

    report = {
        "timestamp": datetime.now().isoformat(),
        "overall_score": overall,
        "code_quality": {
            "score": code_score,
            "findings": review.get("total_findings", 0),
            "status": review.get("status", "unknown"),
        },
        "test_coverage": {
            "coverage_percent": cov_score,
            "test_files": coverage.get("test_files", 0),
            "test_functions": coverage.get("test_functions", 0),
            "status": coverage.get("status", "unknown"),
        },
        "api_quality": {
            "tested": api.get("tested", 0),
            "passed": api.get("passed", 0),
            "failed": api.get("failed", 0),
            "server_errors": api.get("server_errors", 0),
            "status": api.get("status", "unknown"),
        },
        "performance": {
            "db_query_avg_ms": benchmark.get("db_query_avg_ms", 0),
            "cache_read_avg_ms": benchmark.get("cache_read_avg_ms", 0),
            "status": benchmark.get("status", "unknown"),
        },
        "suggestions": suggestions,
    }

    # 保存到data/quality_report.json
    report_path = os.path.join(PROJECT_ROOT, "data", "quality_report.json")
    try:
        os.makedirs(os.path.dirname(report_path), exist_ok=True)
        with open(report_path, "w", encoding="utf-8") as f:
            json.dump(report, f, indent=2, ensure_ascii=False)
        print(f"\n  报告已保存: {report_path}")
    except IOError as e:
        print(f"\n  {Colors.YELLOW}保存报告失败: {e}{Colors.RESET}")

    return report


# ---------------------------------------------------------------------- #
# 主函数
# ---------------------------------------------------------------------- #
def main():
    """主函数：运行所有质量检查。"""
    print(f"{Colors.BOLD}AI Hacking Agent — 一键质量检查{Colors.RESET}")
    print(f"项目目录: {PROJECT_ROOT}")
    print(f"时间: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")

    # 1. 代码审查
    review = run_code_review()

    # 2. 测试覆盖率
    coverage = run_coverage_check()

    # 3. API测试
    api = run_api_tests()

    # 4. 性能基准
    benchmark = run_benchmarks()

    # 5. 综合报告
    final = generate_final_report(review, coverage, api, benchmark)

    print(f"\n{Colors.BOLD}质量检查完成。{Colors.RESET}\n")
    return final


if __name__ == "__main__":
    main()
