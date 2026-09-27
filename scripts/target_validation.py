#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
target_validation脚本工具模块，提供相关的命令行工具和自动化脚本。

模块功能：
    - 提供相关安全测试功能
    - 支持API调用和命令行使用
    - 与其他模块集成协作

注意事项：
    - 本模块仅用于授权的安全测试
    - 请勿用于非法用途
    - 使用前请确保已获得相关授权
"""
import sys
import json
import time
from pathlib import Path
from datetime import datetime

# 添加项目根目录
project_root = Path(__file__).parent.parent
sys.path.insert(0, str(project_root))


class PentestValidator:
    """渗透测试验证器"""

    def __init__(self):
        """初始化PentestValidator实例。

        Args:
            self: 类实例。
        """
        self.results = []
        self.start_time = None

    def log(self, message, level="INFO"):
        """记录日志"""
        timestamp = datetime.now().strftime("%H:%M:%S")
        print(f"[{timestamp}] [{level}] {message}")
        self.results.append({
            "timestamp": timestamp,
            "level": level,
            "message": message
        })

    def test_target(self, target_url, target_name="Unknown"):
        """测试单个目标"""
        self.log(f"开始测试目标: {target_name} ({target_url})")
        self.start_time = time.time()

        test_results = {
            "target": target_url,
            "name": target_name,
            "start_time": datetime.now().isoformat(),
            "tests": {},
            "vulnerabilities": [],
            "summary": {}
        }

        # 测试1: HTTP连通性
        self.log("测试1: HTTP连通性检测")
        connectivity = self._test_connectivity(target_url)
        test_results["tests"]["connectivity"] = connectivity
        if connectivity["status"] == "success":
            self.log(f"  ✅ 连通性正常，状态码: {connectivity['status_code']}")
        else:
            self.log(f"  ❌ 连通性失败: {connectivity['error']}", "ERROR")

        # 测试2: 信息收集
        self.log("测试2: 信息收集")
        recon = self._test_recon(target_url)
        test_results["tests"]["recon"] = recon
        self.log(f"  ✅ 信息收集完成，发现 {len(recon.get('headers', {}))} 个响应头")

        # 测试3: 目录扫描
        self.log("测试3: 敏感目录扫描")
        dir_scan = self._test_directory_scan(target_url)
        test_results["tests"]["directory_scan"] = dir_scan
        found_dirs = dir_scan.get("found", [])
        self.log(f"  ✅ 目录扫描完成，发现 {len(found_dirs)} 个敏感目录")
        for d in found_dirs:
            self.log(f"     - {d}")

        # 测试4: CVE匹配
        self.log("测试4: CVE漏洞匹配")
        cve_match = self._test_cve_matching(target_url, recon)
        test_results["tests"]["cve_matching"] = cve_match
        matched_cves = cve_match.get("matched", [])
        self.log(f"  ✅ CVE匹配完成，匹配到 {len(matched_cves)} 个潜在CVE")
        for cve in matched_cves:
            self.log(f"     - {cve['id']}: {cve['name']} ({cve['severity']})")
            test_results["vulnerabilities"].append({
                "type": "cve",
                "id": cve["id"],
                "name": cve["name"],
                "severity": cve["severity"],
                "description": cve.get("description", "")
            })

        # 测试5: Web漏洞扫描
        self.log("测试5: Web漏洞扫描")
        web_vuln = self._test_web_vulnerabilities(target_url)
        test_results["tests"]["web_vulnerabilities"] = web_vuln
        vulns = web_vuln.get("vulnerabilities", [])
        self.log(f"  ✅ Web漏洞扫描完成，发现 {len(vulns)} 个漏洞")
        for v in vulns:
            self.log(f"     - {v['type']}: {v['description']} ({v['severity']})")
            test_results["vulnerabilities"].append(v)

        # 测试6: POC验证
        self.log("测试6: POC验证（仅信息泄露类，不执行实际利用）")
        poc_verify = self._test_poc_verification(target_url, matched_cves)
        test_results["tests"]["poc_verification"] = poc_verify
        self.log(f"  ✅ POC验证完成，验证了 {poc_verify.get('verified', 0)} 个POC")

        # 汇总
        elapsed = time.time() - self.start_time
        test_results["summary"] = {
            "elapsed_seconds": round(elapsed, 2),
            "total_vulnerabilities": len(test_results["vulnerabilities"]),
            "by_severity": self._count_by_severity(test_results["vulnerabilities"]),
            "tests_passed": sum(1 for t in test_results["tests"].values() if t.get("status") == "success"),
            "tests_total": len(test_results["tests"])
        }

        self.log(f"测试完成，耗时: {elapsed:.2f}秒")
        self.log(f"发现漏洞: {len(test_results['vulnerabilities'])} 个")
        self.log(f"  Critical: {test_results['summary']['by_severity'].get('critical', 0)}")
        self.log(f"  High: {test_results['summary']['by_severity'].get('high', 0)}")
        self.log(f"  Medium: {test_results['summary']['by_severity'].get('medium', 0)}")
        self.log(f"  Low: {test_results['summary']['by_severity'].get('low', 0)}")

        return test_results

    def _test_connectivity(self, url):
        """测试HTTP连通性"""
        try:
            import requests
            import urllib3
            urllib3.disable_warnings()
            response = requests.get(url, timeout=10, verify=False,
                                   headers={"User-Agent": "Mozilla/5.0 (compatible; AI-Hacking-Agent/1.0)"})
            return {
                "status": "success",
                "status_code": response.status_code,
                "response_time": round(response.elapsed.total_seconds() * 1000, 2),
                "content_length": len(response.content),
                "final_url": response.url
            }
        except Exception as e:
            return {"status": "failed", "error": str(e)}

    def _test_recon(self, url):
        """信息收集"""
        try:
            import requests
            import urllib3
            urllib3.disable_warnings()
            response = requests.get(url, timeout=10, verify=False)
            headers = dict(response.headers)
            server = headers.get("Server", "Unknown")
            powered_by = headers.get("X-Powered-By", "Unknown")

            return {
                "status": "success",
                "headers": headers,
                "server": server,
                "x_powered_by": powered_by,
                "content_type": headers.get("Content-Type", "Unknown"),
                "title": self._extract_title(response.text)
            }
        except Exception as e:
            return {"status": "failed", "error": str(e), "headers": {}}

    def _extract_title(self, html):
        """提取HTML标题"""
        try:
            import re
            match = re.search(r"<title>(.*?)</title>", html, re.IGNORECASE)
            return match.group(1) if match else "No Title"
        except:
            return "No Title"

    def _test_directory_scan(self, url):
        """敏感目录扫描"""
        sensitive_paths = [
            "/admin", "/login", "/wp-admin", "/phpmyadmin",
            "/.env", "/.git/HEAD", "/backup", "/config",
            "/api", "/swagger", "/docs", "/robots.txt",
            "/sitemap.xml", "/.htaccess", "/web.config",
            "/server-status", "/actuator", "/console"
        ]

        found = []
        try:
            import requests
            import urllib3
            urllib3.disable_warnings()
            for path in sensitive_paths:
                try:
                    test_url = url.rstrip("/") + path
                    response = requests.get(test_url, timeout=5, verify=False, allow_redirects=False)
                    if response.status_code in [200, 301, 302, 403]:
                        found.append(f"{path} (HTTP {response.status_code})")
                except:
                    continue
            return {"status": "success", "found": found, "scanned": len(sensitive_paths)}
        except Exception as e:
            return {"status": "failed", "error": str(e), "found": found}

    def _test_cve_matching(self, url, recon):
        """CVE漏洞匹配"""
        try:
            from knowledge.cve import cve_kb
            all_cves = cve_kb.search("")
            matched = []

            server = recon.get("server", "").lower()
            powered_by = recon.get("x_powered_by", "").lower()
            title = recon.get("title", "").lower()

            for cve in all_cves:
                cve_text = (cve.get("name", "") + " " + cve.get("affected", "") + " " + cve.get("category", "")).lower()
                # 简单匹配
                if any(kw in cve_text for kw in [server, powered_by, title] if kw and kw != "unknown"):
                    matched.append(cve)
                # 通用Web漏洞
                elif "web" in cve_text and any(kw in title for kw in ["dvwa", "juice", "web"]):
                    matched.append(cve)

            # 限制返回数量
            matched = matched[:10]
            return {"status": "success", "matched": matched, "total_scanned": len(all_cves)}
        except Exception as e:
            return {"status": "failed", "error": str(e), "matched": []}

    def _test_web_vulnerabilities(self, url):
        """Web漏洞扫描（基础检测）"""
        vulnerabilities = []
        try:
            import requests
            import urllib3
            urllib3.disable_warnings()

            # 检测1: 不安全的HTTP方法
            try:
                response = requests.options(url, timeout=5, verify=False)
                allow = response.headers.get("Allow", "")
                if any(method in allow for method in ["PUT", "DELETE", "TRACE"]):
                    vulnerabilities.append({
                        "type": "insecure_http_methods",
                        "description": f"服务器允许不安全的HTTP方法: {allow}",
                        "severity": "medium"
                    })
            except:
                pass

            # 检测2: 缺少安全头
            response = requests.get(url, timeout=5, verify=False)
            headers = response.headers
            security_headers = [
                ("X-Frame-Options", "点击劫持防护"),
                ("X-Content-Type-Options", "MIME类型嗅探防护"),
                ("X-XSS-Protection", "XSS防护"),
                ("Content-Security-Policy", "内容安全策略"),
                ("Strict-Transport-Security", "HTTPS强制"),
                ("Referrer-Policy", "Referrer策略")
            ]
            missing_headers = []
            for header, desc in security_headers:
                if header not in headers:
                    missing_headers.append(f"{header} ({desc})")
            if missing_headers:
                vulnerabilities.append({
                    "type": "missing_security_headers",
                    "description": f"缺少安全响应头: {', '.join(missing_headers)}",
                    "severity": "low"
                })

            # 检测3: CORS配置错误
            if "Access-Control-Allow-Origin" in headers:
                if headers["Access-Control-Allow-Origin"] == "*":
                    vulnerabilities.append({
                        "type": "cors_misconfiguration",
                        "description": "CORS配置允许任意来源访问 (Access-Control-Allow-Origin: *)",
                        "severity": "medium"
                    })

            # 检测4: 目录列表
            try:
                test_url = url.rstrip("/") + "/test_directory_12345/"
                response = requests.get(test_url, timeout=5, verify=False)
                if "Index of" in response.text or "Directory Listing" in response.text:
                    vulnerabilities.append({
                        "type": "directory_listing",
                        "description": "服务器启用了目录列表功能",
                        "severity": "medium"
                    })
            except:
                pass

            return {"status": "success", "vulnerabilities": vulnerabilities}
        except Exception as e:
            return {"status": "failed", "error": str(e), "vulnerabilities": vulnerabilities}

    def _test_poc_verification(self, url, matched_cves):
        """POC验证（仅信息泄露类）"""
        verified = 0
        try:
            from exploit.poc_library import get_poc_library
            library = get_poc_library()
            # 只验证信息泄露类POC，不执行实际利用
            info_pocs = library.search_pocs(category="info")
            for poc in info_pocs[:5]:  # 限制数量
                try:
                    result = library.verify_poc_simple(poc.poc_id, url)
                    if result.get("success"):
                        verified += 1
                except:
                    continue
            return {"status": "success", "verified": verified, "total": len(info_pocs[:5])}
        except Exception as e:
            return {"status": "failed", "error": str(e), "verified": verified}

    def _count_by_severity(self, vulnerabilities):
        """按严重程度统计"""
        counts = {"critical": 0, "high": 0, "medium": 0, "low": 0}
        for vuln in vulnerabilities:
            sev = vuln.get("severity", "low").lower()
            if sev in counts:
                counts[sev] += 1
        return counts

    def generate_report(self, results, output_path):
        """生成验证报告"""
        report = {
            "report_title": "AI Hacking Agent 靶场验证报告",
            "generated_at": datetime.now().isoformat(),
            "tool_version": "v8.0",
            "targets_tested": len(results),
            "total_vulnerabilities": sum(r["summary"]["total_vulnerabilities"] for r in results),
            "results": results
        }

        with open(output_path, "w", encoding="utf-8") as f:
            json.dump(report, f, ensure_ascii=False, indent=2)

        self.log(f"报告已保存: {output_path}")
        return report


def main():
    """在...中。

        Returns:
            操作结果。
    """
    print("=" * 60)
    print("  AI Hacking Agent - 靶场验证脚本")
    print("=" * 60)
    print()

    validator = PentestValidator()

    # 默认测试目标
    targets = [
        ("http://127.0.0.1:8080", "DVWA (本地)"),
        ("http://127.0.0.1:3000", "OWASP Juice Shop (本地)"),
        ("http://testphp.vulnweb.com", "TestPHP VulnWeb (在线)"),
    ]

    # 如果传入了命令行参数，使用用户指定的目标
    if len(sys.argv) > 1:
        targets = [(sys.argv[1], "用户指定目标")]

    print("测试目标:")
    for i, (url, name) in enumerate(targets, 1):
        print(f"  {i}. {name}: {url}")
    print()

    all_results = []
    for url, name in targets:
        print(f"\n{'='*60}")
        try:
            result = validator.test_target(url, name)
            all_results.append(result)
        except Exception as e:
            print(f"测试失败: {e}")
            all_results.append({
                "target": url,
                "name": name,
                "error": str(e),
                "summary": {"total_vulnerabilities": 0}
            })

    # 生成报告
    output_dir = project_root / "reports"
    output_dir.mkdir(exist_ok=True)
    output_path = output_dir / f"validation_report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
    validator.generate_report(all_results, str(output_path))

    # 生成专业HTML报告
    try:
        import sys
        sys.path.insert(0, str(project_root))
        from reporting.professional_report import generate_professional_report

        # 收集所有漏洞
        all_vulnerabilities = []
        for result in all_results:
            if "vulnerabilities" in result:
                all_vulnerabilities.extend(result["vulnerabilities"])

        # 生成HTML报告
        html_output_path = output_dir / f"validation_report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.html"
        target_str = ", ".join(r.get("name", r.get("target", "Unknown")) for r in all_results)
        generate_professional_report(target_str, all_vulnerabilities, str(html_output_path))
        print(f"专业HTML报告已生成: {html_output_path}")
    except Exception as e:
        print(f"HTML报告生成失败（不影响JSON报告）: {e}")

    # 汇总
    print("\n" + "=" * 60)
    print("  验证汇总")
    print("=" * 60)
    total_vulns = sum(r["summary"]["total_vulnerabilities"] for r in all_results if "summary" in r)
    print(f"测试目标数: {len(all_results)}")
    print(f"总漏洞数: {total_vulns}")
    print(f"JSON报告路径: {output_path}")
    print(f"HTML报告路径: {html_output_path if 'html_output_path' in dir() else '未生成'}")
    print()
    print("提示: 请确保只对拥有合法授权的目标进行测试！")


if __name__ == "__main__":
    main()
