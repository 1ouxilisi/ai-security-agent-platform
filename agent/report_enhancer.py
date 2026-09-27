"""
report_enhancer智能体模块，提供相关AI驱动的安全分析和决策功能。

模块功能：
    - 提供相关安全测试功能
    - 支持API调用和命令行使用
    - 与其他模块集成协作

注意事项：
    - 本模块仅用于授权的安全测试
    - 请勿用于非法用途
    - 使用前请确保已获得相关授权
"""
from typing import Dict, List, Optional
from datetime import datetime


class CVSSScorer:
    """CVSS v3.1 评分计算器（简化版）"""

    SEVERITY_MATRIX = {
        "critical": {"base": 9.0, "env": "网络可达，无需权限，影响完整"},
        "high": {"base": 7.5, "env": "网络可达，需低权限或影响部分"},
        "medium": {"base": 5.0, "env": "需本地访问或需较高权限"},
        "low": {"base": 2.5, "env": "需物理访问或需管理员权限"},
        "info": {"base": 0.0, "env": "信息泄露，无直接危害"},
    }

    @classmethod
    def calculate(cls, vulnerability_type: str, description: str = "") -> Dict:
        """根据漏洞类型计算CVSS评分"""
        vuln_type_lower = vulnerability_type.lower()

        # 常见漏洞类型的默认严重程度
        severity_map = {
            "sql_injection": "critical",
            "command_injection": "critical",
            "remote_code_execution": "critical",
            "rce": "critical",
            "xss": "high",
            "cross_site_scripting": "high",
            "ssrf": "high",
            "server_side_request_forgery": "high",
            "idor": "medium",
            "insecure_direct_object_reference": "medium",
            "file_upload": "high",
            "unrestricted_file_upload": "high",
            "path_traversal": "high",
            "directory_traversal": "high",
            "xxe": "high",
            "xml_external_entity": "high",
            "csrf": "medium",
            "cross_site_request_forgery": "medium",
            "open_redirect": "low",
            "information_disclosure": "low",
            "sensitive_data_exposure": "medium",
            "weak_password": "medium",
            "default_credentials": "high",
            "misconfiguration": "medium",
            "security_misconfiguration": "medium",
            "outdated_component": "medium",
            "vulnerable_dependency": "medium",
            "port_open": "info",
            "service_detected": "info",
        }

        severity = severity_map.get(vuln_type_lower, "medium")
        score_info = cls.SEVERITY_MATRIX.get(severity, cls.SEVERITY_MATRIX["medium"])

        return {
            "cvss_version": "3.1",
            "base_score": score_info["base"],
            "severity": severity.upper(),
            "environmental_note": score_info["env"],
            "vector": cls._generate_vector(severity, vuln_type_lower),
        }

    @staticmethod
    def _generate_vector(severity: str, vuln_type: str) -> str:
        """生成CVSS向量字符串（简化版）"""
        vectors = {
            "critical": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
            "high": "CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:L",
            "medium": "CVSS:3.1/AV:N/AC:L/PR:L/UI:R/S:U/C:L/I:L/A:L",
            "low": "CVSS:3.1/AV:L/AC:L/PR:H/UI:R/S:U/C:L/I:N/A:N",
            "info": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:N",
        }
        return vectors.get(severity, vectors["medium"])


class RemediationAdvisor:
    """修复建议生成器"""

    REMEDIATION_DB = {
        "sql_injection": {
            "summary": "使用参数化查询/预编译语句，禁止字符串拼接SQL",
            "steps": [
                "将所有动态SQL查询改为参数化查询（PreparedStatement）",
                "使用ORM框架（如SQLAlchemy、Django ORM）",
                "对用户输入进行严格的白名单校验",
                "数据库账号使用最小权限原则",
                "部署WAF进行SQL注入防护",
            ],
            "references": [
                "https://owasp.org/www-community/attacks/SQL_Injection",
                "https://cheatsheetseries.owasp.org/cheatsheets/SQL_Injection_Prevention_Cheat_Sheet.html",
            ],
        },
        "xss": {
            "summary": "对输出进行HTML编码，使用Content Security Policy",
            "steps": [
                "所有用户输入在输出到HTML前进行实体编码",
                "使用框架自带的自动转义功能（如React、Vue）",
                "设置HttpOnly和Secure标志的Cookie",
                "部署Content Security Policy (CSP)头",
                "对富文本输入使用白名单HTML净化库",
            ],
            "references": [
                "https://owasp.org/www-community/attacks/xss/",
                "https://cheatsheetseries.owasp.org/cheatsheets/Cross_Site_Scripting_Prevention_Cheat_Sheet.html",
            ],
        },
        "ssrf": {
            "summary": "限制出站请求目标，使用白名单和URL校验",
            "steps": [
                "对用户提供的URL进行严格校验，禁止内网地址",
                "维护允许访问的域名白名单",
                "禁用不必要的协议（file://、gopher://等）",
                "使用独立的网络隔离环境发起出站请求",
                "部署DNS重绑定防护",
            ],
            "references": [
                "https://owasp.org/www-community/attacks/Server_Side_Request_Forgery",
                "https://cheatsheetseries.owasp.org/cheatsheets/Server_Side_Request_Forgery_Prevention_Cheat_Sheet.html",
            ],
        },
        "command_injection": {
            "summary": "禁止直接执行系统命令，使用安全的API替代",
            "steps": [
                "避免使用system()、exec()、shell_exec()等函数",
                "使用语言内置的安全API替代系统命令",
                "对必须执行的命令使用参数化方式，禁止shell解析",
                "对用户输入进行严格的白名单校验",
                "以最低权限运行应用进程",
            ],
            "references": [
                "https://owasp.org/www-community/attacks/Command_Injection",
                "https://cheatsheetseries.owasp.org/cheatsheets/OS_Command_Injection_Defense_Cheat_Sheet.html",
            ],
        },
        "file_upload": {
            "summary": "严格校验上传文件类型，存储在非Web可访问目录",
            "steps": [
                "通过文件内容（魔数）校验类型，而非仅检查扩展名",
                "重命名上传文件，使用随机文件名",
                "存储在Web根目录之外，通过脚本代理访问",
                "设置上传目录的执行权限为禁用",
                "限制上传文件大小",
            ],
            "references": [
                "https://owasp.org/www-community/vulnerabilities/Unrestricted_File_Upload",
                "https://cheatsheetseries.owasp.org/cheatsheets/File_Upload_Cheat_Sheet.html",
            ],
        },
        "idor": {
            "summary": "实施对象级访问控制，校验用户权限",
            "steps": [
                "在每个对象访问点校验当前用户权限",
                "使用不可预测的对象标识符（UUID）",
                "实施基于角色的访问控制（RBAC）",
                "记录所有对象访问日志",
                "进行自动化的授权测试",
            ],
            "references": [
                "https://owasp.org/www-community/vulnerabilities/Insecure_Direct_Object_Reference",
                "https://cheatsheetseries.owasp.org/cheatsheets/Authorization_Cheat_Sheet.html",
            ],
        },
        "path_traversal": {
            "summary": "规范化文件路径，限制在允许的目录内",
            "steps": [
                "对用户输入的文件路径进行规范化处理",
                "校验最终路径是否在允许的目录内",
                "避免直接使用用户输入拼接文件路径",
                "使用chroot或容器隔离文件系统",
                "以最低权限运行应用进程",
            ],
            "references": [
                "https://owasp.org/www-community/attacks/Path_Traversal",
                "https://cheatsheetseries.owasp.org/cheatsheets/Input_Validation_Cheat_Sheet.html",
            ],
        },
        "default_credentials": {
            "summary": "修改默认密码，实施强密码策略",
            "steps": [
                "首次登录强制修改默认密码",
                "实施强密码策略（长度、复杂度、过期）",
                "禁用默认管理员账号或重命名",
                "实施账户锁定机制",
                "启用多因素认证（MFA）",
            ],
            "references": [
                "https://owasp.org/www-community/controls/Password_Strength",
                "https://cheatsheetseries.owasp.org/cheatsheets/Authentication_Cheat_Sheet.html",
            ],
        },
        "misconfiguration": {
            "summary": "遵循安全配置基线，定期审计配置",
            "steps": [
                "遵循CIS Benchmark等安全配置基线",
                "禁用不必要的服务和功能",
                "启用安全相关的HTTP头（HSTS、X-Frame-Options等）",
                "定期进行配置审计",
                "使用基础设施即代码（IaC）管理配置",
            ],
            "references": [
                "https://owasp.org/www-project-secure-headers/",
                "https://www.cisecurity.org/cis-benchmarks",
            ],
        },
    }

    @classmethod
    def get_remediation(cls, vulnerability_type: str) -> Dict:
        """获取漏洞修复建议"""
        vuln_type_lower = vulnerability_type.lower()

        # 模糊匹配
        for key, value in cls.REMEDIATION_DB.items():
            if key in vuln_type_lower or vuln_type_lower in key:
                return {
                    "vulnerability_type": vulnerability_type,
                    "summary": value["summary"],
                    "remediation_steps": value["steps"],
                    "references": value["references"],
                }

        # 默认建议
        return {
            "vulnerability_type": vulnerability_type,
            "summary": "建议进行安全审计并修复该漏洞",
            "remediation_steps": [
                "确认漏洞的真实性和影响范围",
                "参考OWASP指南进行修复",
                "修复后进行回归测试",
                "定期进行安全扫描",
            ],
            "references": [
                "https://owasp.org/www-project-top-ten/",
                "https://cheatsheetseries.owasp.org/",
            ],
        }


class ReportEnhancer:
    """报告增强器 - 为报告添加CVSS评分、修复建议、参考链接"""

    @staticmethod
    def enhance_finding(finding: Dict) -> Dict:
        """增强单个漏洞发现"""
        vuln_type = finding.get("type", finding.get("vulnerability_type", "unknown"))

        # 添加CVSS评分
        cvss = CVSSScorer.calculate(vuln_type, finding.get("description", ""))
        finding["cvss"] = cvss
        finding["severity"] = cvss["severity"]
        finding["cvss_score"] = cvss["base_score"]

        # 添加修复建议
        remediation = RemediationAdvisor.get_remediation(vuln_type)
        finding["remediation"] = remediation

        return finding

    @staticmethod
    def generate_enhanced_report(task_data: Dict, findings: List[Dict]) -> Dict:
        """生成增强版报告"""
        # 增强每个漏洞发现
        enhanced_findings = [ReportEnhancer.enhance_finding(f) for f in findings]

        # 统计
        severity_counts = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0, "INFO": 0}
        for f in enhanced_findings:
            sev = f.get("severity", "INFO")
            severity_counts[sev] = severity_counts.get(sev, 0) + 1

        # 风险评分（加权）
        risk_score = (
            severity_counts["CRITICAL"] * 10 +
            severity_counts["HIGH"] * 7 +
            severity_counts["MEDIUM"] * 5 +
            severity_counts["LOW"] * 2 +
            severity_counts["INFO"] * 0
        )

        report = {
            "report_version": "2.0-enhanced",
            "generated_at": datetime.now().isoformat(),
            "task_info": {
                "task_id": task_data.get("task_id", ""),
                "target": task_data.get("target", ""),
                "task_type": task_data.get("task_type", ""),
                "description": task_data.get("description", ""),
                "started_at": task_data.get("started_at", ""),
                "completed_at": task_data.get("completed_at", ""),
            },
            "executive_summary": {
                "total_findings": len(enhanced_findings),
                "severity_distribution": severity_counts,
                "overall_risk_score": risk_score,
                "risk_level": "CRITICAL" if risk_score >= 30 else "HIGH" if risk_score >= 15 else "MEDIUM" if risk_score >= 5 else "LOW",
                "top_remediation_priorities": ReportEnhancer._get_top_priorities(enhanced_findings),
            },
            "findings": enhanced_findings,
            "appendix": {
                "methodology": "AI驱动的自动化安全测试，结合主动扫描和智能分析",
                "tools_used": ["端口扫描", "Web漏洞扫描", "子域名枚举", "SSL检测"],
                "limitations": "本报告基于自动化扫描结果，建议进行人工验证确认",
                "disclaimer": "本报告仅供授权安全研究使用，未经授权的测试属于违法行为",
            },
        }

        return report

    @staticmethod
    def _get_top_priorities(findings: List[Dict]) -> List[str]:
        """获取 top 修复优先级"""
        # 按严重程度排序
        severity_order = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "INFO": 4}
        sorted_findings = sorted(findings, key=lambda x: severity_order.get(x.get("severity", "INFO"), 5))

        priorities = []
        seen_types = set()
        for f in sorted_findings[:5]:
            vuln_type = f.get("type", "unknown")
            if vuln_type not in seen_types:
                seen_types.add(vuln_type)
                remediation = f.get("remediation", {})
                priorities.append({
                    "vulnerability": vuln_type,
                    "severity": f.get("severity", "INFO"),
                    "priority_action": remediation.get("summary", "修复该漏洞"),
                })
        return priorities

    @staticmethod
    def report_to_markdown(report: Dict) -> str:
        """将增强报告转换为Markdown格式"""
        lines = []
        lines.append("# 安全测试报告（增强版）")
        lines.append("")
        lines.append(f"**生成时间**: {report['generated_at']}")
        lines.append(f"**任务ID**: {report['task_info']['task_id']}")
        lines.append(f"**测试目标**: {report['task_info']['target']}")
        lines.append(f"**任务类型**: {report['task_info']['task_type']}")
        lines.append("")

        # 执行摘要
        lines.append("## 📊 执行摘要")
        lines.append("")
        summary = report["executive_summary"]
        lines.append(f"- **总发现数**: {summary['total_findings']}")
        lines.append(f"- **严重程度分布**:")
        for sev, count in summary["severity_distribution"].items():
            if count > 0:
                lines.append(f"  - {sev}: {count}")
        lines.append(f"- **整体风险评分**: {summary['overall_risk_score']}")
        lines.append(f"- **风险等级**: **{summary['risk_level']}**")
        lines.append("")

        # Top修复优先级
        lines.append("### 🎯 Top修复优先级")
        lines.append("")
        for i, p in enumerate(summary["top_remediation_priorities"], 1):
            lines.append(f"{i}. **[{p['severity']}]** {p['vulnerability']}: {p['priority_action']}")
        lines.append("")

        # 漏洞详情
        lines.append("## 🔍 漏洞详情")
        lines.append("")
        for i, f in enumerate(report["findings"], 1):
            lines.append(f"### {i}. [{f.get('severity', 'INFO')}] {f.get('name', f.get('type', '未知漏洞'))}")
            lines.append("")
            lines.append(f"**漏洞类型**: {f.get('type', 'unknown')}")
            lines.append(f"**CVSS评分**: {f.get('cvss_score', 0)} ({f.get('severity', 'INFO')})")
            lines.append(f"**CVSS向量**: `{f.get('cvss', {}).get('vector', 'N/A')}`")
            lines.append("")
            if f.get("description"):
                lines.append(f"**描述**: {f['description']}")
                lines.append("")
            if f.get("evidence"):
                lines.append(f"**证据**: {f['evidence']}")
                lines.append("")
            # 修复建议
            remediation = f.get("remediation", {})
            if remediation:
                lines.append(f"**修复建议**: {remediation.get('summary', '')}")
                lines.append("")
                lines.append("**修复步骤**:")
                for step in remediation.get("remediation_steps", []):
                    lines.append(f"  - {step}")
                lines.append("")
                lines.append("**参考链接**:")
                for ref in remediation.get("references", []):
                    lines.append(f"  - {ref}")
                lines.append("")
            lines.append("---")
            lines.append("")

        # 附录
        lines.append("## 📎 附录")
        lines.append("")
        appendix = report["appendix"]
        lines.append(f"**测试方法**: {appendix['methodology']}")
        lines.append(f"**使用工具**: {', '.join(appendix['tools_used'])}")
        lines.append(f"**局限性**: {appendix['limitations']}")
        lines.append(f"**免责声明**: {appendix['disclaimer']}")
        lines.append("")

        return "\n".join(lines)


# 单例
report_enhancer = ReportEnhancer()
