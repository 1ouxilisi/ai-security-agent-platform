#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
检测规则库
蓝队检测规则，用于发现攻击行为和异常
"""

from typing import Dict, List, Optional
from dataclasses import dataclass, field


@dataclass
class DetectionRule:
    """检测规则"""
    rule_id: str = ""
    name: str = ""
    description: str = ""
    severity: str = "medium"  # low/medium/high/critical
    category: str = ""  # network/endpoint/application/cloud
    mitre_technique: str = ""
    mitre_tactic: str = ""
    logic: str = ""  # 检测逻辑（伪代码/Sigma/Splunk）
    indicators: List[str] = field(default_factory=list)
    false_positives: List[str] = field(default_factory=list)
    recommendations: List[str] = field(default_factory=list)
    references: List[str] = field(default_factory=list)
    enabled: bool = True


@dataclass
class DetectionResult:
    """检测结果"""
    rule_id: str = ""
    rule_name: str = ""
    matched: bool = False
    severity: str = ""
    description: str = ""
    evidence: str = ""
    timestamp: str = ""
    source: str = ""


class DetectionRuleLibrary:
    """检测规则库"""

    def __init__(self):
        self.rules: Dict[str, DetectionRule] = {}
        self._init_rules()

    def _init_rules(self):
        """初始化检测规则"""
        rules = [
            # ==================== 网络层检测 ====================
            DetectionRule(
                rule_id="DR-001",
                name="端口扫描检测",
                description="检测来自单一源IP的大量端口连接尝试",
                severity="medium",
                category="network",
                mitre_technique="T1046",
                mitre_tactic="discovery",
                logic="当单个源IP在60秒内连接超过100个不同端口时触发",
                indicators=["短时间内大量SYN包", "来自同一IP的多端口连接", "半开连接"],
                false_positives=["合法的漏洞扫描", "负载均衡器健康检查", "网络监控工具"],
                recommendations=["检查源IP是否为已知扫描器", "临时封禁可疑IP", "通知安全团队"],
                references=["https://attack.mitre.org/techniques/T1046/"],
            ),
            DetectionRule(
                rule_id="DR-002",
                name="SQL注入检测",
                description="检测HTTP请求中的SQL注入特征",
                severity="critical",
                category="application",
                mitre_technique="T1190",
                mitre_tactic="initial_access",
                logic="检测URL参数或POST数据中的SQL注入payload",
                indicators=["UNION SELECT", "OR 1=1", "SLEEP(", "WAITFOR DELAY", "信息_schema", "SQL语法错误"],
                false_positives=["合法的SQL查询参数", "代码搜索功能"],
                recommendations=["启用WAF规则", "检查应用代码是否使用参数化查询", "记录攻击源IP"],
                references=["https://owasp.org/www-community/attacks/SQL_Injection"],
            ),
            DetectionRule(
                rule_id="DR-003",
                name="XSS攻击检测",
                description="检测HTTP请求中的跨站脚本payload",
                severity="high",
                category="application",
                mitre_technique="T1059.007",
                mitre_tactic="execution",
                logic="检测URL参数或POST数据中的XSS payload",
                indicators=["<script>", "javascript:", "onerror=", "onload=", "<img src=x", "alert("],
                false_positives=["富文本编辑器", "代码分享功能"],
                recommendations=["启用WAF XSS防护", "检查输出编码", "实施CSP策略"],
                references=["https://owasp.org/www-community/attacks/xss/"],
            ),
            DetectionRule(
                rule_id="DR-004",
                name="WebShell检测",
                description="检测Web目录中的可疑文件和异常访问",
                severity="critical",
                category="application",
                mitre_technique="T1505.003",
                mitre_tactic="persistence",
                logic="检测Web目录中新增的可疑PHP/JSP/ASP文件，以及异常的POST请求",
                indicators=["eval(", "base64_decode(", "assert(", "system(", "异常文件创建时间", "大量POST到可疑文件"],
                false_positives=["合法的上传功能", "开发测试文件"],
                recommendations=["隔离可疑文件", "检查文件创建者", "扫描整个Web目录", "检查访问日志"],
                references=["https://attack.mitre.org/techniques/T1505/003/"],
            ),
            DetectionRule(
                rule_id="DR-005",
                name="暴力破解检测",
                description="检测针对认证服务的暴力破解尝试",
                severity="high",
                category="network",
                mitre_technique="T1110",
                mitre_tactic="credential_access",
                logic="当单个IP在5分钟内失败登录超过20次时触发",
                indicators=["大量失败登录", "常见用户名组合", "来自同一IP的认证尝试"],
                false_positives=["用户忘记密码", "自动化工具配置错误"],
                recommendations=["实施账户锁定策略", "临时封禁源IP", "启用多因素认证"],
                references=["https://attack.mitre.org/techniques/T1110/"],
            ),
            DetectionRule(
                rule_id="DR-006",
                name="异常出站流量检测",
                description="检测服务器到外部的异常网络连接",
                severity="high",
                category="network",
                mitre_technique="T1071",
                mitre_tactic="command_and_control",
                logic="检测服务器到已知恶意IP或异常端口的出站连接",
                indicators=["连接到已知C2服务器", "异常端口出站流量", "DNS隧道特征", "大流量上传"],
                false_positives=["合法的外部API调用", "软件更新", "备份传输"],
                recommendations=["隔离受感染主机", "检查进程和网络连接", "进行恶意软件分析"],
                references=["https://attack.mitre.org/techniques/T1071/"],
            ),
            DetectionRule(
                rule_id="DR-007",
                name="敏感文件访问检测",
                description="检测对敏感系统文件的异常访问",
                severity="high",
                category="endpoint",
                mitre_technique="T1005",
                mitre_tactic="collection",
                logic="检测Web请求中包含/etc/passwd、/etc/shadow等敏感文件路径",
                indicators=["../../etc/passwd", "/etc/shadow", "win.ini", "boot.ini", "proc/self/environ"],
                false_positives=["合法的文件管理功能"],
                recommendations=["检查是否存在LFI漏洞", "修复路径遍历漏洞", "限制文件访问权限"],
                references=["https://attack.mitre.org/techniques/T1005/"],
            ),
            DetectionRule(
                rule_id="DR-008",
                name="命令注入检测",
                description="检测HTTP请求中的命令注入payload",
                severity="critical",
                category="application",
                mitre_technique="T1059",
                mitre_tactic="execution",
                logic="检测URL参数或POST数据中的命令注入特征",
                indicators=["; id;", "| whoami", "&& ls", "$(whoami)", "`id`", "%0Aid"],
                false_positives=["合法的命令行参数输入"],
                recommendations=["启用WAF防护", "检查应用代码", "实施输入验证"],
                references=["https://owasp.org/www-community/attacks/Command_Injection"],
            ),
            DetectionRule(
                rule_id="DR-009",
                name="SSRF检测",
                description="检测服务器端请求伪造尝试",
                severity="high",
                category="application",
                mitre_technique="T1190",
                mitre_tactic="initial_access",
                logic="检测包含内网IP或云元数据地址的URL参数",
                indicators=["127.0.0.1", "localhost", "169.254.169.254", "10.0.0.", "192.168.", "file://", "gopher://"],
                false_positives=["合法的内部服务调用"],
                recommendations=["实施URL白名单", "禁止访问内网IP", "禁用危险URL协议"],
                references=["https://owasp.org/www-community/attacks/Server_Side_Request_Forgery"],
            ),
            DetectionRule(
                rule_id="DR-010",
                name="目录遍历检测",
                description="检测路径遍历攻击尝试",
                severity="high",
                category="application",
                mitre_technique="T1005",
                mitre_tactic="collection",
                logic="检测URL参数中的路径遍历序列",
                indicators=["../", "..\\", "%2e%2e%2f", "%2e%2e/", "....//", "/etc/passwd"],
                false_positives=["合法的文件路径参数"],
                recommendations=["实施输入验证", "使用basename()处理文件名", "限制文件访问目录"],
                references=["https://owasp.org/www-community/attacks/Path_Traversal"],
            ),
            # ==================== 端点检测 ====================
            DetectionRule(
                rule_id="DR-011",
                name="权限提升检测",
                description="检测异常的权限提升行为",
                severity="critical",
                category="endpoint",
                mitre_technique="T1068",
                mitre_tactic="privilege_escalation",
                logic="检测非root用户突然获得root权限，或异常的sudo使用",
                indicators=["频繁sudo使用", "SUID文件修改", "内核漏洞利用特征", "异常进程权限"],
                false_positives=["合法的管理员操作", "软件安装"],
                recommendations=["检查sudo日志", "审计SUID文件", "检查是否存在内核漏洞"],
                references=["https://attack.mitre.org/techniques/T1068/"],
            ),
            DetectionRule(
                rule_id="DR-012",
                name="凭据转储检测",
                description="检测Mimikatz等凭据转储工具使用",
                severity="critical",
                category="endpoint",
                mitre_technique="T1003",
                mitre_tactic="credential_access",
                logic="检测lsass.exe异常访问，或mimikatz相关进程/文件",
                indicators=["lsass.exe内存读取", "mimikatz.exe", "sekurlsa", "procdump lsass"],
                false_positives=["合法的调试工具", "安全软件扫描"],
                recommendations=["隔离主机", "检查内存转储文件", "重置所有凭据", "启用Credential Guard"],
                references=["https://attack.mitre.org/techniques/T1003/"],
            ),
            DetectionRule(
                rule_id="DR-013",
                name="持久化检测",
                description="检测系统持久化机制的异常修改",
                severity="high",
                category="endpoint",
                mitre_technique="T1547",
                mitre_tactic="persistence",
                logic="检测注册表启动项、计划任务、服务的异常创建或修改",
                indicators=["新增启动项", "可疑计划任务", "异常服务创建", "crontab修改"],
                false_positives=["合法软件安装", "系统更新"],
                recommendations=["检查新增启动项", "审计计划任务", "检查服务配置"],
                references=["https://attack.mitre.org/techniques/T1547/"],
            ),
            DetectionRule(
                rule_id="DR-014",
                name="横向移动检测",
                description="检测网络内的横向移动行为",
                severity="critical",
                category="network",
                mitre_technique="T1021",
                mitre_tactic="lateral_movement",
                logic="检测SMB/WMI/WinRM的异常使用，或同一账户在多主机登录",
                indicators=["异常SMB连接", "WMI远程执行", "同一账户多主机登录", "PsExec使用"],
                false_positives=["合法的远程管理", "域控制器同步"],
                recommendations=["检查源主机是否失陷", "重置相关账户凭据", "隔离受影响主机"],
                references=["https://attack.mitre.org/techniques/T1021/"],
            ),
            DetectionRule(
                rule_id="DR-015",
                name="数据渗出检测",
                description="检测异常的大流量数据传输",
                severity="high",
                category="network",
                mitre_technique="T1041",
                mitre_tactic="exfiltration",
                logic="检测服务器到外部的异常大流量上传",
                indicators=["短时间内大量数据上传", "到未知IP的大流量", "DNS隧道特征", "异常文件压缩"],
                false_positives=["合法备份", "大文件传输", "视频会议"],
                recommendations=["检查传输内容", "阻断可疑连接", "检查是否有数据泄露"],
                references=["https://attack.mitre.org/techniques/T1041/"],
            ),
            # ==================== 云安全检测 ====================
            DetectionRule(
                rule_id="DR-016",
                name="云元数据访问检测",
                description="检测云实例元数据服务的异常访问",
                severity="high",
                category="cloud",
                mitre_technique="T1552.005",
                mitre_tactic="credential_access",
                logic="检测对169.254.169.254的异常HTTP请求",
                indicators=["访问/latest/meta-data/", "获取临时凭据", "SSRF利用云元数据"],
                false_positives=["合法的云初始化脚本"],
                recommendations=["启用IMDSv2", "检查是否存在SSRF漏洞", "轮换云凭据"],
                references=["https://attack.mitre.org/techniques/T1552/005/"],
            ),
            DetectionRule(
                rule_id="DR-017",
                name="异常API调用检测",
                description="检测云API的异常调用模式",
                severity="medium",
                category="cloud",
                mitre_technique="T1078",
                mitre_tactic="initial_access",
                logic="检测来自异常地理位置或异常时间的API调用",
                indicators=["异常登录位置", "非工作时间大量API调用", "新IP地址的API访问"],
                false_positives=["员工出差", "自动化脚本"],
                recommendations=["启用MFA", "检查API调用日志", "实施IP白名单"],
                references=["https://attack.mitre.org/techniques/T1078/"],
            ),
        ]

        for rule in rules:
            self.rules[rule.rule_id] = rule

    def get_rule(self, rule_id: str) -> Optional[DetectionRule]:
        """获取规则"""
        return self.rules.get(rule_id)

    def search_rules(self, keyword: str = "",
                     category: str = "",
                     severity: str = "",
                     mitre_technique: str = "") -> List[DetectionRule]:
        """搜索规则"""
        results = list(self.rules.values())

        if keyword:
            keyword = keyword.lower()
            results = [
                r for r in results
                if keyword in r.name.lower()
                or keyword in r.description.lower()
            ]

        if category:
            results = [r for r in results if r.category == category]

        if severity:
            results = [r for r in results if r.severity == severity]

        if mitre_technique:
            results = [r for r in results if r.mitre_technique == mitre_technique]

        return results

    def get_rules_by_category(self, category: str) -> List[DetectionRule]:
        """按类别获取规则"""
        return [r for r in self.rules.values() if r.category == category]

    def get_rules_by_severity(self, severity: str) -> List[DetectionRule]:
        """按严重级别获取规则"""
        return [r for r in self.rules.values() if r.severity == severity]

    def get_rules_by_mitre(self, technique_id: str) -> List[DetectionRule]:
        """按MITRE技术获取规则"""
        return [r for r in self.rules.values() if r.mitre_technique == technique_id]

    def get_all_rules(self) -> List[DetectionRule]:
        """获取所有规则"""
        return list(self.rules.values())

    def get_stats(self) -> Dict:
        """获取统计信息"""
        by_category = {}
        by_severity = {}
        by_tactic = {}

        for rule in self.rules.values():
            by_category[rule.category] = by_category.get(rule.category, 0) + 1
            by_severity[rule.severity] = by_severity.get(rule.severity, 0) + 1
            by_tactic[rule.mitre_tactic] = by_tactic.get(rule.mitre_tactic, 0) + 1

        return {
            "total": len(self.rules),
            "enabled": sum(1 for r in self.rules.values() if r.enabled),
            "by_category": by_category,
            "by_severity": by_severity,
            "by_tactic": by_tactic,
        }

    def add_rule(self, rule: DetectionRule) -> bool:
        """添加规则"""
        if rule.rule_id in self.rules:
            return False
        self.rules[rule.rule_id] = rule
        return True

    def to_sigma(self, rule: DetectionRule) -> str:
        """转换为Sigma格式（简化版）"""
        sigma = f"""title: {rule.name}
id: {rule.rule_id}
description: {rule.description}
status: experimental
author: ai-hacking-agent
date: 2024/01/01
tags:
    - attack.{rule.mitre_tactic}
    - attack.{rule.mitre_technique}
logsource:
    category: {rule.category}
detection:
    selection:
        - Keywords:
"""
        for indicator in rule.indicators[:5]:
            sigma += f"            - '{indicator}'\n"

        sigma += f"""    condition: selection
falsepositives:
"""
        for fp in rule.false_positives:
            sigma += f"    - {fp}\n"

        sigma += f"level: {rule.severity}\n"
        return sigma

    def export_all_sigma(self, output_path: str) -> bool:
        """导出所有规则为Sigma格式"""
        try:
            with open(output_path, "w", encoding="utf-8") as f:
                for rule in self.rules.values():
                    f.write(self.to_sigma(rule))
                    f.write("\n---\n\n")
            return True
        except Exception:
            return False
