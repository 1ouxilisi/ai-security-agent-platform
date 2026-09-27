"""
CI/CD 命令行工具
=================

通过命令行与AI Hacking Agent API交互，支持：
- scan: 执行安全扫描
- verify: 漏洞真实验证
- report: 生成并下载安全报告
- workflow: 执行预置工作流
- check: 漏洞阈值检查（CI/CD核心命令）

使用方式：
    python -m cicd.cli scan --target https://example.com --type comprehensive
    python -m cicd.cli check --target https://example.com --threshold high

退出码：
    0 = 成功/通过
    1 = 有高危漏洞（检查不通过）
    2 = 扫描/执行失败
    3 = 参数错误

免责声明：本工具仅用于授权安全测试的CI/CD流水线集成。
"""

import argparse
import json
import logging
import os
import sys
import time
from typing import Any, Dict, Optional

# 支持两种导入方式：作为模块导入或直接运行
try:
    from sdk.python.ai_hacking_sdk import (
        AIAgentClient, APIError, AuthenticationError,
        NotFoundError, RateLimitError, ServerError, ValidationError,
    )
except ImportError:
    # 直接运行时，将上级目录加入路径
    sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
    from sdk.python.ai_hacking_sdk import (
        AIAgentClient, APIError, AuthenticationError,
        NotFoundError, RateLimitError, ServerError, ValidationError,
    )


# ============================================================
# 常量与退出码
# ============================================================

EXIT_SUCCESS = 0
EXIT_VULN_FOUND = 1
EXIT_SCAN_FAILED = 2
EXIT_ARG_ERROR = 3

# 支持的扫描类型
SCAN_TYPES = [
    "comprehensive", "web", "mobile", "internal",
    "domain", "ai", "blockchain", "compliance"
]

# 支持的漏洞严重等级
SEVERITY_LEVELS = ["critical", "high", "medium", "low", "info"]

# 支持的工作流模板
WORKFLOW_TEMPLATES = [
    "pentest_full", "web_security", "mobile_security",
    "internal_assessment", "domain_audit", "ai_agent_security",
    "blockchain_security", "compliance_audit",
]

# 支持的报告格式
REPORT_FORMATS = ["html", "json", "pdf", "markdown"]


# ============================================================
# ANSI 颜色输出
# ============================================================

class ColorPrinter:
    """带ANSI颜色的终端输出工具。"""

    COLORS = {
        "red": "\033[91m",
        "green": "\033[92m",
        "yellow": "\033[93m",
        "blue": "\033[94m",
        "magenta": "\033[95m",
        "cyan": "\033[96m",
        "bold": "\033[1m",
        "reset": "\033[0m",
    }

    def __init__(self, use_color: bool = True):
        self.use_color = use_color and sys.stdout.isatty()

    def _c(self, text: str, color: str) -> str:
        if not self.use_color:
            return text
        return f"{self.COLORS.get(color, '')}{text}{self.COLORS['reset']}"

    def info(self, msg: str):
        print(self._c(f"[INFO] {msg}", "cyan"))

    def success(self, msg: str):
        print(self._c(f"[OK] {msg}", "green"))

    def warn(self, msg: str):
        print(self._c(f"[WARN] {msg}", "yellow"))

    def error(self, msg: str):
        print(self._c(f"[ERROR] {msg}", "red"))

    def bold(self, msg: str):
        print(self._c(msg, "bold"))

    def progress(self, current: int, total: int, prefix: str = ""):
        """显示简单进度条。"""
        bar_len = 30
        filled = int(bar_len * current / total) if total > 0 else 0
        bar = "█" * filled + "░" * (bar_len - filled)
        pct = int(100 * current / total) if total > 0 else 0
        print(f"\r{prefix} [{bar}] {pct}%", end="", flush=True)
        if current >= total:
            print()


# ============================================================
# CLI 核心类
# ============================================================

class CICDTool:
    """CI/CD 命令行工具主类。"""

    def __init__(self, args: argparse.Namespace):
        self.args = args
        self.printer = ColorPrinter(use_color=(args.format == "text"))
        self.debug = args.verbose

        # 从环境变量和命令行参数获取配置
        self.api_url = args.api_url or os.environ.get("AI_HACKING_API_URL", "http://localhost:8000")
        self.api_key = args.api_key or os.environ.get("AI_HACKING_API_KEY", "")

        # 初始化SDK客户端
        self.client = AIAgentClient(
            base_url=self.api_url,
            api_key=self.api_key,
            timeout=int(os.environ.get("AI_HACKING_TIMEOUT", "30")),
            max_retries=2,
            debug=self.debug,
        )

        if self.debug:
            self.printer.info(f"API地址: {self.api_url}")
            self.printer.info(f"API密钥: {'已设置' if self.api_key else '未设置'}")

    def _output(self, data: Dict[str, Any], exit_code: int = EXIT_SUCCESS) -> int:
        """统一输出格式处理。"""
        if self.args.format == "json":
            # JSON模式输出到stdout，CI/CD可解析
            output = {
                "exit_code": exit_code,
                **data,
            }
            print(json.dumps(output, ensure_ascii=False, indent=2))
        else:
            # 文本模式，人类可读
            self._output_text(data)
        return exit_code

    def _output_text(self, data: Dict[str, Any]):
        """文本模式输出。"""
        self.printer.bold("=" * 60)
        self.printer.bold(f"结果: {data.get('summary', data.get('status', 'N/A'))}")
        self.printer.bold("=" * 60)

        if "vulnerabilities" in data:
            vulns = data["vulnerabilities"]
            self.printer.info(f"发现漏洞总数: {len(vulns)}")
            # 按严重等级统计
            sev_count = {}
            for v in vulns:
                sev = v.get("severity", "unknown")
                sev_count[sev] = sev_count.get(sev, 0) + 1
            for sev in ["critical", "high", "medium", "low"]:
                cnt = sev_count.get(sev, 0)
                if cnt > 0:
                    color = "red" if sev in ("critical", "high") else "yellow" if sev == "medium" else "green"
                    self.printer._c(f"  {sev.upper():10s}: {cnt}", color)

        if "assessment_id" in data:
            self.printer.info(f"评估ID: {data['assessment_id']}")
        if "report_path" in data:
            self.printer.success(f"报告已保存: {data['report_path']}")

    def _load_config(self):
        """从配置文件加载额外配置。"""
        if not self.args.config:
            return
        config_path = self.args.config
        if not os.path.exists(config_path):
            self.printer.warn(f"配置文件不存在: {config_path}")
            return
        try:
            with open(config_path, "r", encoding="utf-8") as f:
                if config_path.endswith(".json"):
                    cfg = json.load(f)
                else:
                    # YAML格式需要pyyaml
                    try:
                        import yaml
                        cfg = yaml.safe_load(f)
                    except ImportError:
                        self.printer.warn("pyyaml未安装，跳过YAML配置加载")
                        return
            self.printer.info(f"已加载配置: {config_path}")
            if cfg.get("api_url") and not self.args.api_url:
                self.api_url = cfg["api_url"]
                self.client.base_url = cfg["api_url"]
        except Exception as e:
            self.printer.warn(f"配置文件加载失败: {e}")

    # --------------------------------------------------------
    # 命令：scan
    # --------------------------------------------------------

    def cmd_scan(self) -> int:
        """执行安全扫描命令。"""
        target = self.args.target
        scan_type = self.args.type
        depth = self.args.depth
        wait = self.args.wait

        self.printer.bold(f"AI Hacking Agent - 安全扫描")
        self.printer.info(f"目标: {target}")
        self.printer.info(f"类型: {scan_type}")
        self.printer.info(f"深度: {depth}")

        # 创建评估任务
        try:
            config = {"depth": depth}
            result = self.client.create_assessment(
                target=target,
                assessment_type=scan_type,
                config=config,
            )
            assessment_id = result.get("assessment_id")
            self.printer.success(f"扫描已启动，评估ID: {assessment_id}")
        except APIError as e:
            self.printer.error(f"创建扫描任务失败: {e}")
            return self._output({"error": str(e), "status": "failed"}, EXIT_SCAN_FAILED)

        if not wait:
            return self._output({
                "assessment_id": assessment_id,
                "status": "running",
                "summary": "扫描已启动，请稍后查询",
            })

        # 轮询等待完成
        self.printer.info("等待扫描完成...")
        try:
            final = self.client.poll_until_done(
                lambda: self.client.get_assessment(assessment_id),
                interval=10,
                timeout=self.args.timeout,
            )
        except TimeoutError:
            self.printer.warn(f"扫描超时（{self.args.timeout}秒），任务仍在后台运行")
            return self._output({
                "assessment_id": assessment_id,
                "status": "timeout",
                "summary": "扫描超时，后台继续执行",
            }, EXIT_SCAN_FAILED)
        except APIError as e:
            self.printer.error(f"查询扫描状态失败: {e}")
            return self._output({"error": str(e)}, EXIT_SCAN_FAILED)

        status = final.get("status", "unknown")
        summary = final.get("summary", {})

        # 收集漏洞列表
        vulns = []
        try:
            vuln_result = self.client.list_vulnerabilities(
                assessment_id=assessment_id, limit=200
            )
            vulns = vuln_result.get("items", [])
        except APIError:
            pass

        output_data = {
            "assessment_id": assessment_id,
            "status": status,
            "vulnerabilities": vulns,
            "summary": {
                "total": summary.get("total_vulns", len(vulns)),
                "critical": summary.get("critical_count", 0),
                "high": summary.get("high_count", 0),
                "medium": summary.get("medium_count", 0),
                "low": summary.get("low_count", 0),
            },
        }

        # 有高危漏洞时返回退出码1
        exit_code = EXIT_SUCCESS
        if summary.get("critical_count", 0) > 0 or summary.get("high_count", 0) > 0:
            exit_code = EXIT_VULN_FOUND
            self.printer.warn(f"发现高危漏洞！critical={summary.get('critical_count', 0)}, high={summary.get('high_count', 0)}")

        return self._output(output_data, exit_code)

    # --------------------------------------------------------
    # 命令：verify
    # --------------------------------------------------------

    def cmd_verify(self) -> int:
        """漏洞验证命令。"""
        target = self.args.target
        vuln_type = self.args.vuln_type

        self.printer.bold(f"AI Hacking Agent - 漏洞验证")
        self.printer.info(f"目标: {target}")
        self.printer.info(f"漏洞类型: {vuln_type}")

        try:
            params = {}
            if self.args.param:
                params["param"] = self.args.param

            # 根据是否指定service/port选择验证方式
            if self.args.service and self.args.port:
                result = self.client.verify_service_vuln(
                    target=target,
                    service=self.args.service,
                    port=self.args.port,
                    vuln_type=vuln_type,
                )
            else:
                result = self.client.verify_web_vuln(
                    url=target,
                    vuln_type=vuln_type,
                    params=params,
                )

            task_id = result.get("task_id")
            self.printer.success(f"验证任务已创建: {task_id}")

            # 等待验证结果
            self.printer.info("等待验证结果...")
            verify_result = self.client.poll_until_done(
                lambda: self.client.get_verify_result(task_id),
                interval=3,
                timeout=60,
                done_statuses=["verified", "not_vulnerable", "error", "timeout", "completed"],
            )

            verified = verify_result.get("verified", False)
            risk = verify_result.get("risk_level", "unknown")

            self.printer.bold(f"验证结论: {'确认存在漏洞' if verified else '未发现漏洞'}")
            self.printer.info(f"风险等级: {risk}")

            return self._output({
                "task_id": task_id,
                "verified": verified,
                "risk_level": risk,
                "evidence": verify_result.get("evidence", ""),
                "summary": "漏洞确认" if verified else "未发现漏洞",
            }, EXIT_VULN_FOUND if verified else EXIT_SUCCESS)

        except APIError as e:
            self.printer.error(f"验证失败: {e}")
            return self._output({"error": str(e)}, EXIT_SCAN_FAILED)

    # --------------------------------------------------------
    # 命令：report
    # --------------------------------------------------------

    def cmd_report(self) -> int:
        """生成并下载报告命令。"""
        assessment_id = self.args.assessment_id
        report_format = self.args.report_format
        output_path = self.args.output

        self.printer.bold(f"AI Hacking Agent - 报告生成")
        self.printer.info(f"评估ID: {assessment_id}")
        self.printer.info(f"格式: {report_format}")

        try:
            # 生成报告
            result = self.client.generate_report(assessment_id, report_format)
            report_id = result.get("report_id")
            self.printer.success(f"报告已生成: {report_id}")

            # 下载报告
            content = self.client.download_report(report_id)

            # 保存到文件
            if not output_path:
                ext = {"html": ".html", "json": ".json", "pdf": ".pdf", "markdown": ".md"}.get(report_format, ".html")
                output_path = f"security_report_{assessment_id}{ext}"

            with open(output_path, "wb") as f:
                f.write(content)

            self.printer.success(f"报告已保存: {output_path} ({len(content)} 字节)")

            return self._output({
                "report_id": report_id,
                "assessment_id": assessment_id,
                "report_path": output_path,
                "format": report_format,
                "size_bytes": len(content),
                "summary": f"报告已生成并保存",
            })

        except APIError as e:
            self.printer.error(f"报告生成失败: {e}")
            return self._output({"error": str(e)}, EXIT_SCAN_FAILED)
        except IOError as e:
            self.printer.error(f"文件保存失败: {e}")
            return self._output({"error": str(e)}, EXIT_SCAN_FAILED)

    # --------------------------------------------------------
    # 命令：workflow
    # --------------------------------------------------------

    def cmd_workflow(self) -> int:
        """执行工作流命令。"""
        template_id = self.args.template
        target = self.args.target
        wait = self.args.wait

        self.printer.bold(f"AI Hacking Agent - 工作流执行")
        self.printer.info(f"模板: {template_id}")
        self.printer.info(f"目标: {target}")

        # 解析额外参数
        extra_params = None
        if self.args.params:
            try:
                extra_params = json.loads(self.args.params)
            except json.JSONDecodeError:
                self.printer.error(f"参数JSON解析失败: {self.args.params}")
                return self._output({"error": "参数JSON格式错误"}, EXIT_ARG_ERROR)

        try:
            result = self.client.execute_workflow(
                template_id=template_id,
                target=target,
                params=extra_params,
            )
            instance_id = result.get("instance_id")
            self.printer.success(f"工作流已启动: {instance_id}")

            if not wait:
                return self._output({
                    "instance_id": instance_id,
                    "status": "running",
                    "summary": "工作流已启动",
                })

            # 轮询等待完成
            self.printer.info("等待工作流完成...")
            final = self.client.poll_until_done(
                lambda: self.client.get_workflow_status(instance_id),
                interval=10,
                timeout=600,
            )

            status = final.get("status", "unknown")
            self.printer.success(f"工作流完成，状态: {status}")

            # 获取结果
            try:
                report = self.client.get_workflow_result(instance_id)
            except APIError:
                report = {}

            return self._output({
                "instance_id": instance_id,
                "status": status,
                "result": report,
                "summary": f"工作流执行完成: {status}",
            })

        except APIError as e:
            self.printer.error(f"工作流执行失败: {e}")
            return self._output({"error": str(e)}, EXIT_SCAN_FAILED)

    # --------------------------------------------------------
    # 命令：check（CI/CD核心命令）
    # --------------------------------------------------------

    def cmd_check(self) -> int:
        """漏洞阈值检查命令，CI/CD流水线核心。

        执行扫描后根据阈值判断是否通过，返回对应退出码。
        """
        target = self.args.target
        threshold = self.args.threshold
        scan_type = self.args.type
        fail_on = self.args.fail_on
        max_count = self.args.max_count or 999999

        self.printer.bold(f"AI Hacking Agent - 漏洞阈值检查")
        self.printer.info(f"目标: {target}")
        self.printer.info(f"阈值等级: {threshold}")
        self.printer.info(f"失败条件: {fail_on}")

        # 先执行扫描
        try:
            self.printer.info("启动安全扫描...")
            result = self.client.create_assessment(
                target=target,
                assessment_type=scan_type,
                config={"depth": "standard"},
            )
            assessment_id = result.get("assessment_id")

            # 等待完成
            self.printer.info("等待扫描完成...")
            final = self.client.poll_until_done(
                lambda: self.client.get_assessment(assessment_id),
                interval=10,
                timeout=self.args.timeout,
            )

            summary = final.get("summary", {})
            critical = summary.get("critical_count", 0)
            high = summary.get("high_count", 0)
            medium = summary.get("medium_count", 0)
            low = summary.get("low_count", 0)

            self.printer.info(f"扫描结果: critical={critical}, high={high}, medium={medium}, low={low}")

            # 根据阈值和失败条件判断
            blocked = False
            reason = ""

            if fail_on == "any_critical" and critical > 0:
                blocked = True
                reason = f"发现{critical}个严重漏洞"
            elif fail_on == "any_high" and (critical > 0 or high > 0):
                blocked = True
                reason = f"发现{critical}个严重漏洞 + {high}个高危漏洞"
            elif fail_on == "count_gt_N":
                # 统计高于阈值的漏洞数
                counts = {"critical": critical, "high": high, "medium": medium, "low": low}
                threshold_idx = SEVERITY_LEVELS.index(threshold) if threshold in SEVERITY_LEVELS else 1
                total_above = sum(
                    counts.get(sev, 0)
                    for sev in SEVERITY_LEVELS[:threshold_idx + 1]
                )
                if total_above > max_count:
                    blocked = True
                    reason = f"高于阈值({threshold})的漏洞数{total_above}超过上限{max_count}"

            output_data = {
                "assessment_id": assessment_id,
                "target": target,
                "threshold": threshold,
                "fail_on": fail_on,
                "vulnerabilities_summary": {
                    "critical": critical,
                    "high": high,
                    "medium": medium,
                    "low": low,
                },
                "passed": not blocked,
                "reason": reason if blocked else "所有检查通过",
            }

            if blocked:
                self.printer.error(f"检查不通过: {reason}")
                output_data["summary"] = f"CI/CD阻断: {reason}"
                return self._output(output_data, EXIT_VULN_FOUND)
            else:
                self.printer.success("所有安全检查通过，可以部署！")
                output_data["summary"] = "安全检查通过"
                return self._output(output_data, EXIT_SUCCESS)

        except APIError as e:
            self.printer.error(f"检查过程中API错误: {e}")
            return self._output({"error": str(e), "passed": False}, EXIT_SCAN_FAILED)
        except TimeoutError:
            self.printer.error("扫描超时，无法完成阈值检查")
            return self._output({"error": "扫描超时", "passed": False}, EXIT_SCAN_FAILED)


# ============================================================
# 参数解析
# ============================================================

def build_parser() -> argparse.ArgumentParser:
    """构建命令行参数解析器。"""
    parser = argparse.ArgumentParser(
        prog="cicd.cli",
        description="AI Hacking Agent CI/CD 集成命令行工具",
        epilog="退出码: 0=成功, 1=有高危漏洞, 2=执行失败, 3=参数错误",
    )

    # 全局参数
    parser.add_argument("--config", "-c", help="配置文件路径（YAML/JSON）")
    parser.add_argument("--format", "-f", choices=["text", "json"], default="text", help="输出格式（默认text）")
    parser.add_argument("--api-url", default=None, help="API服务地址（默认http://localhost:8000）")
    parser.add_argument("--api-key", default=None, help="API密钥")
    parser.add_argument("--verbose", "-v", action="store_true", help="详细输出模式")

    subparsers = parser.add_subparsers(dest="command", help="可用命令")

    # ---- scan 命令 ----
    scan_parser = subparsers.add_parser("scan", help="执行安全扫描")
    scan_parser.add_argument("--target", "-t", required=True, help="目标IP/域名/URL")
    scan_parser.add_argument("--type", "-y", default="comprehensive", choices=SCAN_TYPES, help="扫描类型")
    scan_parser.add_argument("--depth", default="standard", choices=["quick", "standard", "deep"], help="扫描深度")
    scan_parser.add_argument("--timeout", type=int, default=300, help="超时时间秒数（默认300）")
    scan_parser.add_argument("--wait", type=bool, default=True, help="是否等待完成")

    # ---- verify 命令 ----
    verify_parser = subparsers.add_parser("verify", help="漏洞真实验证")
    verify_parser.add_argument("--target", "-t", required=True, help="目标URL")
    verify_parser.add_argument("--vuln-type", "-vt", required=True,
                               help="漏洞类型: sql_injection/xss/csrf/path_traversal/command_injection/ssrf等")
    verify_parser.add_argument("--param", help="测试参数名")
    verify_parser.add_argument("--port", type=int, help="端口（服务验证时）")
    verify_parser.add_argument("--service", help="服务名（服务验证时）")

    # ---- report 命令 ----
    report_parser = subparsers.add_parser("report", help="生成并下载安全报告")
    report_parser.add_argument("--assessment-id", "-id", required=True, help="评估任务ID")
    report_parser.add_argument("--report-format", "-f", default="html", choices=REPORT_FORMATS, help="报告格式")
    report_parser.add_argument("--output", "-o", help="输出文件路径")

    # ---- workflow 命令 ----
    wf_parser = subparsers.add_parser("workflow", help="执行预置工作流")
    wf_parser.add_argument("--template", "-tpl", required=True, choices=WORKFLOW_TEMPLATES, help="工作流模板ID")
    wf_parser.add_argument("--target", "-t", required=True, help="扫描目标")
    wf_parser.add_argument("--params", help="额外参数（JSON字符串）")
    wf_parser.add_argument("--wait", type=bool, default=True, help="是否等待完成")

    # ---- check 命令（CI/CD核心） ----
    check_parser = subparsers.add_parser("check", help="漏洞阈值检查（CI/CD核心命令）")
    check_parser.add_argument("--target", "-t", required=True, help="目标IP/域名/URL")
    check_parser.add_argument("--threshold", "-th", default="high",
                               choices=["critical", "high", "medium", "low"], help="漏洞严重等级阈值")
    check_parser.add_argument("--type", "-y", default="comprehensive", choices=SCAN_TYPES, help="扫描类型")
    check_parser.add_argument("--fail-on", default="any_high",
                              choices=["any_high", "any_critical", "count_gt_N"],
                              help="失败条件")
    check_parser.add_argument("--max-count", type=int, default=None, help="最大允许漏洞数（配合count_gt_N）")
    check_parser.add_argument("--timeout", type=int, default=300, help="扫描超时秒数")

    return parser


def main():
    """CLI主入口函数。"""
    parser = build_parser()
    args = parser.parse_args()

    if not args.command:
        parser.print_help()
        sys.exit(EXIT_ARG_ERROR)

    # 创建工具实例
    tool = CICDTool(args)
    tool._load_config()

    # 执行对应命令
    try:
        if args.command == "scan":
            exit_code = tool.cmd_scan()
        elif args.command == "verify":
            exit_code = tool.cmd_verify()
        elif args.command == "report":
            exit_code = tool.cmd_report()
        elif args.command == "workflow":
            exit_code = tool.cmd_workflow()
        elif args.command == "check":
            exit_code = tool.cmd_check()
        else:
            parser.print_help()
            exit_code = EXIT_ARG_ERROR
    except KeyboardInterrupt:
        print("\n用户中断操作")
        exit_code = EXIT_SCAN_FAILED
    except Exception as e:
        print(f"未预期的错误: {e}", file=sys.stderr)
        exit_code = EXIT_SCAN_FAILED
    finally:
        tool.client.close()

    sys.exit(exit_code)


if __name__ == "__main__":
    main()
