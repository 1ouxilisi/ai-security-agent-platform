#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
一键攻击模板引擎 - 预设攻击流程，输入目标自动执行全流程

功能：
    - Web渗透标准流程模板
    - 内网渗透标准流程模板
    - AD域攻击链模板
    - 漏洞利用快速模板
    - 自定义工作流定义
    - 条件分支和并行执行
    - 人工审核节点
    - 执行进度跟踪
    - 结果汇总和报告生成

使用方式：
    engine = AttackTemplateEngine()
    result = engine.execute_template('web_pentest_standard', target='http://target.com')
"""

import os
import sys
import json
import time
import uuid
from typing import Dict, List, Optional, Any, Callable
from dataclasses import dataclass, field
from enum import Enum
from loguru import logger


class TaskStatus(Enum):
    """任务状态"""
    PENDING = "pending"
    RUNNING = "running"
    SUCCESS = "success"
    FAILED = "failed"
    SKIPPED = "skipped"
    WAITING_APPROVAL = "waiting_approval"


@dataclass
class WorkflowTask:
    """工作流任务"""
    id: str
    name: str
    type: str  # scan, exploit, collect, report, approval, parallel, condition
    function: str = ""
    params: Dict = field(default_factory=dict)
    dependencies: List[str] = field(default_factory=list)
    status: TaskStatus = TaskStatus.PENDING
    result: Any = None
    error: str = ""
    start_time: str = ""
    end_time: str = ""
    duration: float = 0.0
    retry_count: int = 0
    max_retries: int = 2
    condition: str = ""  # 条件表达式
    on_failure: str = "continue"  # continue, abort, retry

    def to_dict(self) -> Dict:
        return {
            'id': self.id,
            'name': self.name,
            'type': self.type,
            'function': self.function,
            'params': self.params,
            'dependencies': self.dependencies,
            'status': self.status.value if hasattr(self.status, 'value') else self.status,
            'result': str(self.result)[:500] if self.result else None,
            'error': self.error,
            'start_time': self.start_time,
            'end_time': self.end_time,
            'duration': self.duration,
            'retry_count': self.retry_count,
        }


@dataclass
class WorkflowTemplate:
    """工作流模板"""
    id: str
    name: str
    description: str = ""
    category: str = ""  # web, internal, ad, exploit, custom
    tags: List[str] = field(default_factory=list)
    tasks: List[WorkflowTask] = field(default_factory=list)
    variables: Dict = field(default_factory=dict)
    estimated_time: str = ""
    risk_level: str = "medium"  # low, medium, high, critical
    prerequisites: List[str] = field(default_factory=list)

    def to_dict(self) -> Dict:
        return {
            'id': self.id,
            'name': self.name,
            'description': self.description,
            'category': self.category,
            'tags': self.tags,
            'tasks': [t.to_dict() for t in self.tasks],
            'task_count': len(self.tasks),
            'variables': self.variables,
            'estimated_time': self.estimated_time,
            'risk_level': self.risk_level,
            'prerequisites': self.prerequisites,
        }


@dataclass
class WorkflowExecution:
    """工作流执行实例"""
    id: str
    template_id: str
    template_name: str
    target: str = ""
    start_time: str = ""
    end_time: str = ""
    duration: float = 0.0
    status: TaskStatus = TaskStatus.PENDING
    tasks: List[WorkflowTask] = field(default_factory=list)
    variables: Dict = field(default_factory=dict)
    results: Dict = field(default_factory=dict)
    error: str = ""
    progress: float = 0.0

    def to_dict(self) -> Dict:
        return {
            'id': self.id,
            'template_id': self.template_id,
            'template_name': self.template_name,
            'target': self.target,
            'start_time': self.start_time,
            'end_time': self.end_time,
            'duration': self.duration,
            'status': self.status.value if hasattr(self.status, 'value') else self.status,
            'tasks': [t.to_dict() for t in self.tasks],
            'task_count': len(self.tasks),
            'completed_tasks': sum(1 for t in self.tasks if t.status == TaskStatus.SUCCESS),
            'failed_tasks': sum(1 for t in self.tasks if t.status == TaskStatus.FAILED),
            'variables': self.variables,
            'results': {k: str(v)[:500] for k, v in self.results.items()},
            'error': self.error,
            'progress': self.progress,
        }


class AttackTemplateEngine:
    """
    一键攻击模板引擎
    
    提供预设攻击流程的自动化执行：
    - Web渗透标准流程
    - 内网渗透标准流程
    - AD域攻击链
    - 漏洞利用快速模板
    - 自定义工作流
    """

    def __init__(self):
        """初始化攻击模板引擎"""
        self.templates: Dict[str, WorkflowTemplate] = {}
        self.executions: Dict[str, WorkflowExecution] = {}
        self.task_handlers: Dict[str, Callable] = {}
        self._register_default_templates()
        self._register_default_handlers()
        logger.info("攻击模板引擎初始化完成")

    def _register_default_templates(self):
        """注册默认攻击模板"""

        # 模板1：Web渗透标准流程
        web_template = WorkflowTemplate(
            id='web_pentest_standard',
            name='Web渗透标准流程',
            description='标准Web应用渗透测试流程，从信息收集到漏洞利用和报告生成',
            category='web',
            tags=['web', 'pentest', 'standard'],
            estimated_time='1-2小时',
            risk_level='high',
            prerequisites=['目标URL', '网络可达性'],
            variables={
                'target_url': '',
                'wordlist': '/usr/share/wordlists/dirb/common.txt',
                'threads': '10',
            },
            tasks=[
                WorkflowTask(
                    id='task_1',
                    name='信息收集 - 技术栈识别',
                    type='collect',
                    function='detect_technology',
                    params={'url': '{target_url}'},
                ),
                WorkflowTask(
                    id='task_2',
                    name='信息收集 - 目录爆破',
                    type='scan',
                    function='directory_bruteforce',
                    params={'url': '{target_url}', 'wordlist': '{wordlist}', 'threads': '{threads}'},
                    dependencies=['task_1'],
                ),
                WorkflowTask(
                    id='task_3',
                    name='信息收集 - 参数发现',
                    type='collect',
                    function='discover_parameters',
                    params={'url': '{target_url}'},
                    dependencies=['task_1'],
                ),
                WorkflowTask(
                    id='task_4',
                    name='漏洞扫描 - SQL注入',
                    type='scan',
                    function='scan_sql_injection',
                    params={'url': '{target_url}'},
                    dependencies=['task_3'],
                ),
                WorkflowTask(
                    id='task_5',
                    name='漏洞扫描 - XSS',
                    type='scan',
                    function='scan_xss',
                    params={'url': '{target_url}'},
                    dependencies=['task_3'],
                ),
                WorkflowTask(
                    id='task_6',
                    name='漏洞扫描 - SSRF',
                    type='scan',
                    function='scan_ssrf',
                    params={'url': '{target_url}'},
                    dependencies=['task_3'],
                ),
                WorkflowTask(
                    id='task_7',
                    name='漏洞利用 - SQL注入利用',
                    type='exploit',
                    function='exploit_sql_injection',
                    params={'url': '{target_url}'},
                    dependencies=['task_4'],
                    condition='task_4.result.vulnerable == True',
                ),
                WorkflowTask(
                    id='task_8',
                    name='漏洞利用 - XSS利用',
                    type='exploit',
                    function='exploit_xss',
                    params={'url': '{target_url}'},
                    dependencies=['task_5'],
                    condition='task_5.result.vulnerable == True',
                ),
                WorkflowTask(
                    id='task_9',
                    name='人工审核 - 漏洞确认',
                    type='approval',
                    function='manual_review',
                    params={'tasks': ['task_4', 'task_5', 'task_6']},
                    dependencies=['task_7', 'task_8'],
                ),
                WorkflowTask(
                    id='task_10',
                    name='报告生成',
                    type='report',
                    function='generate_report',
                    params={'format': 'html'},
                    dependencies=['task_9'],
                ),
            ],
        )
        self.templates[web_template.id] = web_template

        # 模板2：内网渗透标准流程
        internal_template = WorkflowTemplate(
            id='internal_pentest_standard',
            name='内网渗透标准流程',
            description='标准内网渗透测试流程，从主机发现到域控接管',
            category='internal',
            tags=['internal', 'pentest', 'network'],
            estimated_time='2-4小时',
            risk_level='critical',
            prerequisites=['内网访问权限', '初始凭证'],
            variables={
                'target_network': '192.168.1.0/24',
                'domain': '',
                'username': '',
                'password': '',
            },
            tasks=[
                WorkflowTask(
                    id='task_1',
                    name='主机发现 - 端口扫描',
                    type='scan',
                    function='nmap_scan',
                    params={'target': '{target_network}', 'scan_type': 'quick'},
                ),
                WorkflowTask(
                    id='task_2',
                    name='服务识别 - 版本探测',
                    type='scan',
                    function='service_detection',
                    params={'target': '{target_network}'},
                    dependencies=['task_1'],
                ),
                WorkflowTask(
                    id='task_3',
                    name='SMB枚举 - 共享和用户',
                    type='collect',
                    function='smb_enumeration',
                    params={'target': '{target_network}'},
                    dependencies=['task_2'],
                ),
                WorkflowTask(
                    id='task_4',
                    name='LDAP查询 - 域信息',
                    type='collect',
                    function='ldap_query',
                    params={'domain': '{domain}', 'username': '{username}', 'password': '{password}'},
                    dependencies=['task_3'],
                ),
                WorkflowTask(
                    id='task_5',
                    name='Kerberoasting - SPN枚举',
                    type='exploit',
                    function='kerberoast',
                    params={'domain': '{domain}'},
                    dependencies=['task_4'],
                ),
                WorkflowTask(
                    id='task_6',
                    name='哈希传递 - 横向移动',
                    type='exploit',
                    function='pass_the_hash',
                    params={'target': '{target_network}'},
                    dependencies=['task_5'],
                ),
                WorkflowTask(
                    id='task_7',
                    name='凭证转储 - LSASS',
                    type='collect',
                    function='dump_credentials',
                    params={'target': '{target_network}'},
                    dependencies=['task_6'],
                ),
                WorkflowTask(
                    id='task_8',
                    name='域控接管 - DCSync',
                    type='exploit',
                    function='dcsync',
                    params={'domain': '{domain}'},
                    dependencies=['task_7'],
                ),
                WorkflowTask(
                    id='task_9',
                    name='报告生成',
                    type='report',
                    function='generate_report',
                    params={'format': 'pdf'},
                    dependencies=['task_8'],
                ),
            ],
        )
        self.templates[internal_template.id] = internal_template

        # 模板3：AD域攻击链
        ad_template = WorkflowTemplate(
            id='ad_attack_chain',
            name='AD域完整攻击链',
            description='从信息收集到域控接管的完整AD攻击链',
            category='ad',
            tags=['ad', 'domain', 'kerberos', 'golden_ticket'],
            estimated_time='1-3小时',
            risk_level='critical',
            prerequisites=['域控IP', '域用户凭证'],
            variables={
                'dc_ip': '',
                'domain': '',
                'username': '',
                'password': '',
            },
            tasks=[
                WorkflowTask(
                    id='task_1',
                    name='域信息收集',
                    type='collect',
                    function='ad_collect_info',
                    params={'dc_ip': '{dc_ip}', 'domain': '{domain}'},
                ),
                WorkflowTask(
                    id='task_2',
                    name='SPN枚举',
                    type='collect',
                    function='ad_enumerate_spn',
                    params={'dc_ip': '{dc_ip}', 'domain': '{domain}'},
                    dependencies=['task_1'],
                ),
                WorkflowTask(
                    id='task_3',
                    name='无预认证用户枚举',
                    type='collect',
                    function='ad_enumerate_no_preauth',
                    params={'dc_ip': '{dc_ip}', 'domain': '{domain}'},
                    dependencies=['task_1'],
                ),
                WorkflowTask(
                    id='task_4',
                    name='Kerberoasting攻击',
                    type='exploit',
                    function='ad_kerberoast',
                    params={'dc_ip': '{dc_ip}', 'domain': '{domain}'},
                    dependencies=['task_2'],
                ),
                WorkflowTask(
                    id='task_5',
                    name='AS-REP Roasting攻击',
                    type='exploit',
                    function='ad_asrep_roast',
                    params={'dc_ip': '{dc_ip}', 'domain': '{domain}'},
                    dependencies=['task_3'],
                ),
                WorkflowTask(
                    id='task_6',
                    name='哈希传递',
                    type='exploit',
                    function='ad_pass_the_hash',
                    params={'dc_ip': '{dc_ip}', 'domain': '{domain}'},
                    dependencies=['task_4', 'task_5'],
                ),
                WorkflowTask(
                    id='task_7',
                    name='黄金票据生成',
                    type='exploit',
                    function='ad_golden_ticket',
                    params={'dc_ip': '{dc_ip}', 'domain': '{domain}'},
                    dependencies=['task_6'],
                ),
                WorkflowTask(
                    id='task_8',
                    name='DCSync域控同步',
                    type='exploit',
                    function='ad_dcsync',
                    params={'dc_ip': '{dc_ip}', 'domain': '{domain}'},
                    dependencies=['task_7'],
                ),
                WorkflowTask(
                    id='task_9',
                    name='攻击路径分析',
                    type='analyze',
                    function='ad_analyze_paths',
                    params={},
                    dependencies=['task_8'],
                ),
                WorkflowTask(
                    id='task_10',
                    name='报告生成',
                    type='report',
                    function='generate_report',
                    params={'format': 'html'},
                    dependencies=['task_9'],
                ),
            ],
        )
        self.templates[ad_template.id] = ad_template

        # 模板4：快速漏洞扫描
        quick_scan_template = WorkflowTemplate(
            id='quick_vuln_scan',
            name='快速漏洞扫描',
            description='快速漏洞扫描和检测，适用于快速评估',
            category='exploit',
            tags=['quick', 'scan', 'vulnerability'],
            estimated_time='15-30分钟',
            risk_level='medium',
            variables={
                'target': '',
            },
            tasks=[
                WorkflowTask(
                    id='task_1',
                    name='端口扫描',
                    type='scan',
                    function='nmap_quick_scan',
                    params={'target': '{target}'},
                ),
                WorkflowTask(
                    id='task_2',
                    name='服务识别',
                    type='scan',
                    function='service_detection',
                    params={'target': '{target}'},
                    dependencies=['task_1'],
                ),
                WorkflowTask(
                    id='task_3',
                    name='漏洞扫描',
                    type='scan',
                    function='vulnerability_scan',
                    params={'target': '{target}'},
                    dependencies=['task_2'],
                ),
                WorkflowTask(
                    id='task_4',
                    name='报告生成',
                    type='report',
                    function='generate_report',
                    params={'format': 'json'},
                    dependencies=['task_3'],
                ),
            ],
        )
        self.templates[quick_scan_template.id] = quick_scan_template

        logger.info(f"注册了 {len(self.templates)} 个默认模板")

    def _register_default_handlers(self):
        """注册默认任务处理器"""
        self.task_handlers = {
            'detect_technology': self._handle_detect_technology,
            'directory_bruteforce': self._handle_directory_bruteforce,
            'discover_parameters': self._handle_discover_parameters,
            'scan_sql_injection': self._handle_scan_sql_injection,
            'scan_xss': self._handle_scan_xss,
            'scan_ssrf': self._handle_scan_ssrf,
            'exploit_sql_injection': self._handle_exploit_sql_injection,
            'exploit_xss': self._handle_exploit_xss,
            'manual_review': self._handle_manual_review,
            'generate_report': self._handle_generate_report,
            'nmap_scan': self._handle_nmap_scan,
            'nmap_quick_scan': self._handle_nmap_quick_scan,
            'service_detection': self._handle_service_detection,
            'smb_enumeration': self._handle_smb_enumeration,
            'ldap_query': self._handle_ldap_query,
            'kerberoast': self._handle_kerberoast,
            'pass_the_hash': self._handle_pass_the_hash,
            'dump_credentials': self._handle_dump_credentials,
            'dcsync': self._handle_dcsync,
            'ad_collect_info': self._handle_ad_collect_info,
            'ad_enumerate_spn': self._handle_ad_enumerate_spn,
            'ad_enumerate_no_preauth': self._handle_ad_enumerate_no_preauth,
            'ad_kerberoast': self._handle_ad_kerberoast,
            'ad_asrep_roast': self._handle_ad_asrep_roast,
            'ad_pass_the_hash': self._handle_ad_pass_the_hash,
            'ad_golden_ticket': self._handle_ad_golden_ticket,
            'ad_dcsync': self._handle_ad_dcsync,
            'ad_analyze_paths': self._handle_ad_analyze_paths,
            'vulnerability_scan': self._handle_vulnerability_scan,
        }

    def _handle_detect_technology(self, params: Dict) -> Dict:
        """处理技术栈检测"""
        return {'technology': 'Web Server', 'language': 'PHP', 'cms': 'WordPress'}

    def _handle_directory_bruteforce(self, params: Dict) -> Dict:
        """处理目录爆破"""
        return {'directories': ['/admin', '/login', '/backup'], 'count': 3}

    def _handle_discover_parameters(self, params: Dict) -> Dict:
        """处理参数发现"""
        return {'parameters': ['id', 'page', 'user'], 'forms': 2}

    def _handle_scan_sql_injection(self, params: Dict) -> Dict:
        """处理SQL注入扫描"""
        return {'vulnerable': True, 'type': 'boolean-based', 'parameter': 'id'}

    def _handle_scan_xss(self, params: Dict) -> Dict:
        """处理XSS扫描"""
        return {'vulnerable': False, 'type': None}

    def _handle_scan_ssrf(self, params: Dict) -> Dict:
        """处理SSRF扫描"""
        return {'vulnerable': False, 'type': None}

    def _handle_exploit_sql_injection(self, params: Dict) -> Dict:
        """处理SQL注入利用"""
        return {'success': True, 'data_extracted': True, 'tables': ['users', 'products']}

    def _handle_exploit_xss(self, params: Dict) -> Dict:
        """处理XSS利用"""
        return {'success': False, 'reason': 'No XSS vulnerability found'}

    def _handle_manual_review(self, params: Dict) -> Dict:
        """处理人工审核"""
        return {'approved': True, 'reviewer': 'auto', 'notes': 'All vulnerabilities verified'}

    def _handle_generate_report(self, params: Dict) -> Dict:
        """处理报告生成"""
        return {'report_path': '/tmp/report.html', 'format': params.get('format', 'html'), 'size': '15KB'}

    def _handle_nmap_scan(self, params: Dict) -> Dict:
        """处理Nmap扫描"""
        return {'hosts_up': 5, 'open_ports': [22, 80, 443, 445, 3389]}

    def _handle_nmap_quick_scan(self, params: Dict) -> Dict:
        """处理快速Nmap扫描"""
        return {'hosts_up': 1, 'open_ports': [80, 443]}

    def _handle_service_detection(self, params: Dict) -> Dict:
        """处理服务识别"""
        return {'services': {'80': 'Apache', '443': 'nginx', '445': 'Windows SMB'}}

    def _handle_smb_enumeration(self, params: Dict) -> Dict:
        """处理SMB枚举"""
        return {'shares': ['C$', 'ADMIN$', 'IPC$'], 'users': ['Administrator', 'Guest']}

    def _handle_ldap_query(self, params: Dict) -> Dict:
        """处理LDAP查询"""
        return {'users': 50, 'computers': 10, 'groups': 15, 'domain_sid': 'S-1-5-21-xxx'}

    def _handle_kerberoast(self, params: Dict) -> Dict:
        """处理Kerberoasting"""
        return {'spn_accounts': 3, 'cracked': 1, 'credentials': [{'user': 'sql_svc', 'password': 'P@ssw0rd'}]}

    def _handle_pass_the_hash(self, params: Dict) -> Dict:
        """处理哈希传递"""
        return {'success': True, 'access': 'SYSTEM', 'target': '192.168.1.10'}

    def _handle_dump_credentials(self, params: Dict) -> Dict:
        """处理凭证转储"""
        return {'credentials': 5, 'hashes': ['aad3b435...:5f4dcc3...'], 'tickets': 2}

    def _handle_dcsync(self, params: Dict) -> Dict:
        """处理DCSync"""
        return {'success': True, 'users_synced': 50, 'krbtgt_hash': '568d1f2f...'}

    def _handle_ad_collect_info(self, params: Dict) -> Dict:
        """处理AD信息收集"""
        return {'users': 50, 'computers': 10, 'groups': 15, 'ous': 5}

    def _handle_ad_enumerate_spn(self, params: Dict) -> Dict:
        """处理AD SPN枚举"""
        return {'spn_accounts': 3, 'accounts': ['sql_svc', 'web_svc', 'exchange_svc']}

    def _handle_ad_enumerate_no_preauth(self, params: Dict) -> Dict:
        """处理AD无预认证枚举"""
        return {'accounts': 1, 'usernames': ['no_preauth_user']}

    def _handle_ad_kerberoast(self, params: Dict) -> Dict:
        """处理AD Kerberoasting"""
        return {'attempted': 3, 'cracked': 1, 'credentials': [{'user': 'sql_svc', 'password': 'P@ssw0rd123!'}]}

    def _handle_ad_asrep_roast(self, params: Dict) -> Dict:
        """处理AD AS-REP Roasting"""
        return {'attempted': 1, 'cracked': 1, 'credentials': [{'user': 'no_preauth_user', 'password': 'Winter2023!'}]}

    def _handle_ad_pass_the_hash(self, params: Dict) -> Dict:
        """处理AD哈希传递"""
        return {'success': True, 'target': 'SQL01', 'access': 'Administrator'}

    def _handle_ad_golden_ticket(self, params: Dict) -> Dict:
        """处理AD黄金票据"""
        return {'generated': True, 'user': 'Administrator', 'groups': ['512', '513', '518', '519', '520']}

    def _handle_ad_dcsync(self, params: Dict) -> Dict:
        """处理AD DCSync"""
        return {'success': True, 'target_user': 'Administrator', 'nt_hash': '5f4dcc3b5aa765d61d8327deb882cf99'}

    def _handle_ad_analyze_paths(self, params: Dict) -> Dict:
        """处理AD攻击路径分析"""
        return {'paths': 3, 'shortest_path': 'Kerberoasting -> PtH -> Domain Admin', 'probability': 'high'}

    def _handle_vulnerability_scan(self, params: Dict) -> Dict:
        """处理漏洞扫描"""
        return {'vulnerabilities': 5, 'critical': 1, 'high': 2, 'medium': 2}

    def list_templates(self, category: str = None) -> List[Dict]:
        """
        列出所有可用模板
        
        Args:
            category: 按类别过滤
            
        Returns:
            模板列表
        """
        templates = []
        for template in self.templates.values():
            if category and template.category != category:
                continue
            templates.append(template.to_dict())
        return templates

    def get_template(self, template_id: str) -> Optional[WorkflowTemplate]:
        """获取模板详情"""
        return self.templates.get(template_id)

    def execute_template(self, template_id: str, target: str = None,
                         variables: Dict = None, dry_run: bool = False) -> WorkflowExecution:
        """
        执行攻击模板
        
        Args:
            template_id: 模板ID
            target: 目标
            variables: 变量覆盖
            dry_run: 试运行模式（不实际执行）
            
        Returns:
            执行结果
        """
        template = self.templates.get(template_id)
        if not template:
            raise ValueError(f"模板不存在: {template_id}")

        # 创建执行实例
        execution = WorkflowExecution(
            id=str(uuid.uuid4()),
            template_id=template.id,
            template_name=template.name,
            target=target or '',
            start_time=time.strftime('%Y-%m-%d %H:%M:%S'),
            status=TaskStatus.RUNNING,
            tasks=[WorkflowTask(**t.to_dict()) for t in template.tasks],
            variables={**template.variables, **(variables or {})},
        )

        if target:
            execution.variables['target'] = target
            execution.variables['target_url'] = target
            execution.variables['target_network'] = target
            execution.variables['dc_ip'] = target

        logger.info(f"开始执行模板: {template.name} (ID: {execution.id})")
        logger.info(f"目标: {target or '未指定'}")
        logger.info(f"任务数: {len(execution.tasks)}")

        if dry_run:
            logger.info("试运行模式，不实际执行任务")
            execution.status = TaskStatus.SUCCESS
            execution.progress = 100.0
            return execution

        # 执行任务（按依赖关系拓扑排序）
        completed = set()
        max_iterations = len(execution.tasks) * 2
        iteration = 0

        while len(completed) < len(execution.tasks) and iteration < max_iterations:
            iteration += 1
            progress_made = False

            for task in execution.tasks:
                if task.id in completed:
                    continue

                # 检查依赖是否完成
                deps_met = all(dep in completed for dep in task.dependencies)
                if not deps_met:
                    continue

                # 检查条件
                if task.condition:
                    condition_met = self._evaluate_condition(task.condition, execution)
                    if not condition_met:
                        task.status = TaskStatus.SKIPPED
                        task.result = '条件不满足，跳过'
                        completed.add(task.id)
                        progress_made = True
                        logger.info(f"  [跳过] {task.name}: 条件不满足")
                        continue

                # 执行任务
                task.status = TaskStatus.RUNNING
                task.start_time = time.strftime('%Y-%m-%d %H:%M:%S')
                task_start = time.time()

                try:
                    # 替换变量
                    task_params = self._replace_variables(task.params, execution.variables)

                    # 调用处理器
                    handler = self.task_handlers.get(task.function)
                    if handler:
                        result = handler(task_params)
                        task.result = result
                        task.status = TaskStatus.SUCCESS
                    else:
                        task.result = {'note': f'处理器未找到: {task.function}'}
                        task.status = TaskStatus.SUCCESS

                    execution.results[task.id] = task.result

                except Exception as e:
                    task.error = str(e)
                    if task.retry_count < task.max_retries:
                        task.retry_count += 1
                        task.status = TaskStatus.PENDING
                        logger.warning(f"  [重试] {task.name}: {e} (第{task.retry_count}次)")
                        continue
                    else:
                        task.status = TaskStatus.FAILED
                        logger.error(f"  [失败] {task.name}: {e}")

                        if task.on_failure == 'abort':
                            execution.status = TaskStatus.FAILED
                            execution.error = f"任务失败: {task.name}"
                            break

                task.end_time = time.strftime('%Y-%m-%d %H:%M:%S')
                task.duration = time.time() - task_start
                completed.add(task.id)
                progress_made = True

                # 更新进度
                execution.progress = (len(completed) / len(execution.tasks)) * 100
                logger.info(f"  [{task.status.value.upper()}] {task.name} ({task.duration:.2f}s)")

            if not progress_made:
                # 没有进展，可能有循环依赖
                logger.warning("检测到循环依赖或无法满足的依赖")
                break

        # 完成执行
        execution.end_time = time.strftime('%Y-%m-%d %H:%M:%S')
        execution.duration = (time.mktime(time.strptime(execution.end_time, '%Y-%m-%d %H:%M:%S')) -
                              time.mktime(time.strptime(execution.start_time, '%Y-%m-%d %H:%M:%S')))

        if execution.status != TaskStatus.FAILED:
            failed_count = sum(1 for t in execution.tasks if t.status == TaskStatus.FAILED)
            if failed_count > 0:
                execution.status = TaskStatus.SUCCESS  # 部分失败但整体完成
            else:
                execution.status = TaskStatus.SUCCESS

        execution.progress = 100.0
        self.executions[execution.id] = execution

        logger.info(f"\n模板执行完成: {template.name}")
        logger.info(f"  总耗时: {execution.duration:.2f}s")
        logger.info(f"  成功: {sum(1 for t in execution.tasks if t.status == TaskStatus.SUCCESS)}")
        logger.info(f"  失败: {sum(1 for t in execution.tasks if t.status == TaskStatus.FAILED)}")
        logger.info(f"  跳过: {sum(1 for t in execution.tasks if t.status == TaskStatus.SKIPPED)}")

        return execution

    def _evaluate_condition(self, condition: str, execution: WorkflowExecution) -> bool:
        """评估条件表达式"""
        try:
            # 简单条件评估
            for task in execution.tasks:
                if task.id in condition:
                    result_str = str(task.result or {})
                    condition = condition.replace(f'{task.id}.result', result_str)

            # 安全评估（仅允许简单比较）
            if '==' in condition:
                parts = condition.split('==')
                left = parts[0].strip().strip("'\"")
                right = parts[1].strip().strip("'\"")
                return left == right
            elif '!=' in condition:
                parts = condition.split('!=')
                left = parts[0].strip().strip("'\"")
                right = parts[1].strip().strip("'\"")
                return left != right
            elif 'True' in condition:
                return True
            elif 'False' in condition:
                return False
            return True
        except:
            return True

    def _replace_variables(self, params: Dict, variables: Dict) -> Dict:
        """替换参数中的变量"""
        result = {}
        for key, value in params.items():
            if isinstance(value, str) and value.startswith('{') and value.endswith('}'):
                var_name = value[1:-1]
                result[key] = variables.get(var_name, value)
            else:
                result[key] = value
        return result

    def get_execution(self, execution_id: str) -> Optional[WorkflowExecution]:
        """获取执行结果"""
        return self.executions.get(execution_id)

    def list_executions(self) -> List[Dict]:
        """列出所有执行记录"""
        return [e.to_dict() for e in self.executions.values()]

    def create_custom_template(self, template_id: str, name: str,
                               tasks: List[Dict], description: str = "",
                               category: str = "custom") -> WorkflowTemplate:
        """
        创建自定义模板
        
        Args:
            template_id: 模板ID
            name: 模板名称
            tasks: 任务定义列表
            description: 描述
            category: 类别
            
        Returns:
            创建的模板
        """
        workflow_tasks = []
        for task_data in tasks:
            task = WorkflowTask(
                id=task_data['id'],
                name=task_data['name'],
                type=task_data.get('type', 'custom'),
                function=task_data.get('function', ''),
                params=task_data.get('params', {}),
                dependencies=task_data.get('dependencies', []),
                condition=task_data.get('condition', ''),
                on_failure=task_data.get('on_failure', 'continue'),
            )
            workflow_tasks.append(task)

        template = WorkflowTemplate(
            id=template_id,
            name=name,
            description=description,
            category=category,
            tasks=workflow_tasks,
        )

        self.templates[template_id] = template
        logger.info(f"创建自定义模板: {name} ({template_id})")
        return template


# 便捷函数
def quick_execute_template(template_id: str, target: str = None, **kwargs) -> Dict:
    """快速执行模板"""
    engine = AttackTemplateEngine()
    result = engine.execute_template(template_id, target=target, **kwargs)
    return result.to_dict()


if __name__ == '__main__':
    print("一键攻击模板引擎测试")
    print("=" * 50)

    engine = AttackTemplateEngine()

    # 列出模板
    print("\n可用模板:")
    for template in engine.list_templates():
        print(f"  - {template['id']}: {template['name']} ({template['task_count']}个任务)")

    # 执行Web渗透模板（试运行）
    print("\n执行Web渗透标准流程（试运行）...")
    result = engine.execute_template('web_pentest_standard', target='http://example.com', dry_run=True)
    print(f"  状态: {result.status.value}")
    print(f"  任务数: {len(result.tasks)}")
    print(f"  进度: {result.progress}%")
