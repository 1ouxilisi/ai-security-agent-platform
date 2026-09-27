#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
社会工程学模块
提供钓鱼演练、 pretext生成、安全意识培训功能
仅用于授权的安全测试和培训
"""

import os
import json
import random
from datetime import datetime
from typing import Dict, List, Any, Optional
from dataclasses import dataclass, field


@dataclass
class PhishingTemplate:
    """钓鱼模板"""
    template_id: str = ""
    name: str = ""
    category: str = ""  # 邮件/短信/电话/网站
    pretext: str = ""
    target_industry: str = ""
    urgency_level: str = ""
    success_rate_estimate: float = 0.0
    content: str = ""


class SocialEngineeringTester:
    """社会工程学测试器"""

    # 钓鱼 pretext 场景
    PRETEXT_SCENARIOS = [
        {
            'category': 'IT支持',
            'pretext': '冒充IT支持人员，声称需要远程协助解决电脑问题',
            'target': '普通员工',
            'urgency': 'Medium',
            'techniques': ['电话钓鱼', '远程访问', '凭证窃取']
        },
        {
            'category': 'HR部门',
            'pretext': '冒充HR人员，发送工资单或福利更新邮件',
            'target': '全体员工',
            'urgency': 'High',
            'techniques': ['邮件钓鱼', '恶意附件', '凭证窃取']
        },
        {
            'category': '高管',
            'pretext': '冒充公司高管，要求紧急转账或提供敏感信息（BEC攻击）',
            'target': '财务人员',
            'urgency': 'Critical',
            'techniques': ['商务邮件欺诈', '紧急转账', '权威施压']
        },
        {
            'category': '供应商',
            'pretext': '冒充供应商，发送发票更新或合同变更邮件',
            'target': '采购/财务',
            'urgency': 'Medium',
            'techniques': ['供应链钓鱼', '发票欺诈', '恶意附件']
        },
        {
            'category': '客户',
            'pretext': '冒充客户，发送项目需求或合作意向邮件',
            'target': '销售/业务',
            'urgency': 'Low',
            'techniques': ['鱼叉式钓鱼', '恶意附件', '长期潜伏']
        },
        {
            'category': '快递/物流',
            'pretext': '冒充快递公司，发送包裹投递失败通知',
            'target': '普通员工',
            'urgency': 'Medium',
            'techniques': ['短信钓鱼', '恶意链接', '信息收集']
        },
        {
            'category': '税务/政府',
            'pretext': '冒充税务或政府机构，发送税务申报或合规通知',
            'target': '财务/管理层',
            'urgency': 'High',
            'techniques': ['权威钓鱼', '恶意附件', '信息收集']
        },
        {
            'category': '云服务',
            'pretext': '冒充云服务提供商，发送账户异常或密码过期通知',
            'target': 'IT人员/普通员工',
            'urgency': 'High',
            'techniques': ['凭证窃取', '钓鱼网站', '紧急通知']
        },
    ]

    # 安全意识培训主题
    TRAINING_TOPICS = [
        {'topic': '识别钓鱼邮件', 'duration': '30分钟', 'key_points': ['检查发件人地址', '悬停查看链接', '不下载可疑附件', '验证紧急请求']},
        {'topic': '密码安全', 'duration': '20分钟', 'key_points': ['使用强密码', '不重复使用密码', '启用多因素认证', '不共享密码']},
        {'topic': '社会工程学识别', 'duration': '45分钟', 'key_points': ['识别权威施压', '识别紧急请求', '验证身份', '报告可疑行为']},
        {'topic': '数据保护', 'duration': '30分钟', 'key_points': ['敏感数据分类', '数据加密', '安全传输', '安全销毁']},
        {'topic': '物理安全', 'duration': '20分钟', 'key_points': ['尾随识别', '设备安全', '桌面清理', '访客管理']},
        {'topic': '事件响应', 'duration': '40分钟', 'key_points': ['识别安全事件', '报告流程', '隔离措施', '证据保全']},
    ]

    def __init__(self):
        self.templates: List[PhishingTemplate] = []

    def generate_phishing_email(self, scenario: str = "", target_name: str = "",
                                 company_name: str = "", sender_name: str = "") -> Dict:
        """生成钓鱼邮件（用于授权演练）"""
        # 选择场景
        selected = None
        for s in self.PRETEXT_SCENARIOS:
            if scenario and scenario.lower() in s['category'].lower():
                selected = s
                break
        if not selected:
            selected = random.choice(self.PRETEXT_SCENARIOS)

        # 生成邮件内容
        email_templates = {
            'IT支持': {
                'subject': f'【紧急】您的电脑存在安全风险，需要立即处理 - {company_name or "IT部门"}',
                'body': f'''尊敬的{target_name or "同事"}：

我们检测到您的电脑存在安全漏洞，可能影响公司网络安全。请立即配合我们进行远程修复。

请点击以下链接下载远程协助工具：
[恶意链接]

安装后请运行，并将显示的ID和密码回复给我们。

如有疑问请联系IT支持热线。

{sender_name or "IT支持团队"}
{company_name or "公司名称"}
''',
                'red_flags': ['紧急措辞', '要求下载未知软件', '要求提供远程访问', '发件人地址可疑']
            },
            'HR部门': {
                'subject': f'【重要】您的工资单已更新，请查收 - {company_name or "人力资源部"}',
                'body': f'''尊敬的{target_name or "同事"}：

您本月的工资单已生成，请查看附件中的详细信息。

如对工资有任何疑问，请在3个工作日内联系HR部门。

附件：工资单_{datetime.now().strftime("%Y%m")}.exe

{sender_name or "人力资源部"}
{company_name or "公司名称"}
''',
                'red_flags': ['可执行文件附件', '工资单使用exe格式', '发件人地址可疑', '催促查看']
            },
            '高管': {
                'subject': f'【紧急保密】关于XX项目的紧急付款请求',
                'body': f'''{target_name or "财务经理"}：

我正在外出差，有一笔紧急款项需要立即支付。这是XX项目的保密预付款，对方要求今天必须到账。

请将款项汇至以下账户：
账户名：[虚假账户]
账号：[虚假账号]
金额：[虚假金额]

此事保密，不要与任何人讨论。付款后请将凭证发给我。

{sender_name or "总经理"}
''',
                'red_flags': ['高管冒充', '紧急保密', '要求转账到新账户', '禁止讨论', '外出差借口']
            },
        }

        template = email_templates.get(selected['category'], email_templates['IT支持'])

        return {
            'scenario': selected['category'],
            'pretext': selected['pretext'],
            'target': selected['target'],
            'urgency': selected['urgency'],
            'email_subject': template['subject'],
            'email_body': template['body'],
            'red_flags': template['red_flags'],
            'training_note': '此模板仅用于授权的安全意识培训和钓鱼演练，严禁用于非法用途。'
        }

    def get_pretext_scenarios(self) -> List[Dict]:
        """获取pretext场景列表"""
        return self.PRETEXT_SCENARIOS

    def get_training_topics(self) -> List[Dict]:
        """获取安全意识培训主题"""
        return self.TRAINING_TOPICS

    def assess_security_awareness(self, responses: List[Dict] = None) -> Dict:
        """评估安全意识水平"""
        return {
            'overall_score': 0,
            'level': '待评估',
            'categories': {
                '钓鱼识别': {'score': 0, 'max': 100},
                '密码安全': {'score': 0, 'max': 100},
                '社会工程学识别': {'score': 0, 'max': 100},
                '数据保护': {'score': 0, 'max': 100},
                '事件报告': {'score': 0, 'max': 100},
            },
            'recommendations': [
                '定期进行钓鱼演练',
                '开展安全意识培训',
                '建立安全事件报告机制',
                '对高风险岗位进行专项培训',
                '将安全意识纳入绩效考核',
            ],
            'disclaimer': '本模块仅用于授权的安全测试和培训目的。'
        }


# 全局单例
_se_tester = None

def get_social_engineering_tester() -> SocialEngineeringTester:
    global _se_tester
    if _se_tester is None:
        _se_tester = SocialEngineeringTester()
    return _se_tester
