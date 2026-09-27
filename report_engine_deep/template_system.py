# -*- coding: utf-8 -*-
"""template_system.py — 专业报告模板体系（第20轮·报告引擎做深）。

六类模板：
1. 报告类型模板：渗透测试/漏洞评估/安全审计/合规评估/应急响应/红蓝对抗/护网/CTF
2. 行业模板：金融/医疗/政府/教育/电商/互联网/制造/能源
3. 标准框架模板：OWASP Top10/CWE/SANS25/PTES/NIST SP800-115/等保2.0/ISO27001/PCI DSS
4. 报告结构模板：封面/目录/执行摘要/范围/方法/漏洞详情/风险评级/修复/附录/术语表
5. 品牌定制模板：Logo/配色/字体/页眉页脚/水印/封面/公司信息
6. 多语言模板：中/英/日 + 术语翻译与本地化

全部纯内存字典数据，不依赖数据库。
"""

from __future__ import annotations

import copy
import threading
from typing import Any, Dict, List, Optional


# --------------------------------------------------------------------------- #
# 1. 报告类型模板
# --------------------------------------------------------------------------- #
REPORT_TYPE_TEMPLATES: Dict[str, Dict[str, Any]] = {
    "penetration_test": {
        "name": "渗透测试报告",
        "name_en": "Penetration Test Report",
        "description": "授权黑/灰/盒渗透测试全流程发现与利用报告",
        "required_sections": ["执行摘要", "测试范围", "方法论", "漏洞详情", "风险评级", "修复建议"],
        "optional_sections": ["攻击链图", "授权说明", "复测记录"],
        "severity_scale": ["严重", "高危", "中危", "低危", "信息"],
        "audience": ["甲方安全团队", "甲方管理层", "合规部门"],
        "typical_kpis": ["漏洞总数", "高危占比", "平均修复周期"],
    },
    "vulnerability_assessment": {
        "name": "漏洞评估报告",
        "name_en": "Vulnerability Assessment Report",
        "description": "基于扫描与人工复核的资产漏洞盘点与优先级报告",
        "required_sections": ["执行摘要", "资产清单", "漏洞统计", "漏洞详情", "修复建议"],
        "optional_sections": ["趋势对比", "误报排除说明"],
        "severity_scale": ["严重", "高危", "中危", "低危", "信息"],
        "audience": ["运维团队", "安全团队"],
        "typical_kpis": ["受影响资产数", "漏洞密度", "未修复高危数"],
    },
    "security_audit": {
        "name": "安全审计报告",
        "name_en": "Security Audit Report",
        "description": "管理与技术控制的合规符合性审计报告",
        "required_sections": ["审计范围", "审计依据", "控制测试", "发现项", "整改建议"],
        "optional_sections": ["访谈记录", "证据索引"],
        "severity_scale": ["不符合", "部分符合", "符合", "观察项"],
        "audience": ["内审部门", "管理层"],
        "typical_kpis": ["控制符合率", "重大不符合项"],
    },
    "compliance_assessment": {
        "name": "合规评估报告",
        "name_en": "Compliance Assessment Report",
        "description": "等保/ISO/PCI 等合规条款逐项映射评估报告",
        "required_sections": ["评估依据", "条款映射", "合规矩阵", "差距分析", "整改路线图"],
        "optional_sections": ["证据清单", "例外项审批"],
        "severity_scale": ["完全合规", "部分合规", "不合规", "不适用"],
        "audience": ["合规部门", "监管报送对象"],
        "typical_kpis": ["合规覆盖率", "未达标条款数"],
    },
    "incident_response": {
        "name": "应急响应报告",
        "name_en": "Incident Response Report",
        "description": "安全事件从发现到恢复的取证与复盘报告",
        "required_sections": ["事件概述", "时间线", "影响分析", "处置过程", "根因分析", "改进措施"],
        "optional_sections": ["取证镜像哈希", "对外通报口径"],
        "severity_scale": ["特别重大", "重大", "较大", "一般"],
        "audience": ["应急指挥部", "管理层", "监管机构"],
        "typical_kpis": ["MTTD", "MTTR", "影响面"],
    },
    "red_blue_teaming": {
        "name": "红蓝对抗报告",
        "name_en": "Red/Blue Teaming Report",
        "description": "攻防演练全链条对抗过程与检测拦截评估报告",
        "required_sections": ["对抗概述", "攻击路径复盘", "防御有效性", "失陷点", "改进建议"],
        "optional_sections": ["TTPs映射", "演练录像索引"],
        "severity_scale": ["完全突破", "部分突破", "成功拦截", "成功检测"],
        "audience": ["红蓝队", "SOC", "管理层"],
        "typical_kpis": ["初始访问成功率", "平均 dwell time", "拦截率"],
    },
    "hw_protection": {
        "name": "护网行动报告",
        "name_en": "Cyber Protection Campaign Report",
        "description": "护网重保期间值守、监测、处置与战果报告",
        "required_sections": ["重保范围", "值守排班", "攻击事件统计", "处置记录", "总结与建议"],
        "optional_sections": ["通报时间线", "加固前后对比"],
        "severity_scale": ["紧急处置", "已拦截", "已告警", "已封禁"],
        "audience": ["重保指挥部", "上级单位"],
        "typical_kpis": ["攻击拦截数", "有效告警数", "封禁IP数"],
    },
    "ctf_writeup": {
        "name": "CTF 解题报告",
        "name_en": "CTF Challenge Write-up",
        "description": "CTF 赛题解题思路、利用链与技术复盘",
        "required_sections": ["题目信息", "思路分析", "利用过程", "Flag 获取", "防御启示"],
        "optional_sections": "EXP 代码",
        "severity_scale": ["入门", "中等", "困难", "专家"],
        "audience": ["参赛选手", "教学培训"],
        "typical_kpis": ["解题耗时", "技术点覆盖"],
    },
}


# --------------------------------------------------------------------------- #
# 2. 行业模板（行业特定要求与术语）
# --------------------------------------------------------------------------- #
INDUSTRY_TEMPLATES: Dict[str, Dict[str, Any]] = {
    "finance": {
        "name": "金融行业",
        "name_en": "Finance",
        "regulations": ["网络安全法", "数据安全法", "个人信息保护法", "JR/T 0071 金融行业网络安全规范", "央行网络安全检查"],
        "specific_requirements": ["客户资金交易隔离验证", "敏感个人信息脱敏展示", "三方接口资金风险评估", "监管报送留痕"],
        "terminology": {
            "core_banking": "核心交易系统",
            "dora": "分布式交易单元",
            "offsite_backup": "异地灾备",
        },
        "sensitive_assets_focus": ["交易系统", "客户数据库", "网银门户", "支付接口"],
    },
    "healthcare": {
        "name": "医疗行业",
        "name_en": "Healthcare",
        "regulations": ["卫健委医疗数据安全规范", "个人信息保护法", "电子病历应用管理规范"],
        "specific_requirements": ["病历/健康数据加密与脱敏", "医疗设备联网边界隔离", "患者隐私最小披露"],
        "terminology": {
            "emr": "电子病历",
            "his": "医院信息系统",
            "pacs": "医学影像存档系统",
        },
        "sensitive_assets_focus": ["HIS", "EMR库", "体检系统", "物联网医疗设备"],
    },
    "government": {
        "name": "政府行业",
        "name_en": "Government",
        "regulations": ["等保2.0 三级及以上", "密码法", "政务数据共享开放条例"],
        "specific_requirements": ["政务外网与互联网物理/逻辑隔离说明", "密评要求", "国密算法使用情况", "领导驾驶舱权限"],
        "terminology": {
            "gov_extranet": "政务外网",
            "classified_system": "涉密系统(不纳入本次技术测试)",
        },
        "sensitive_assets_focus": ["门户网站", "审批系统", "数据共享交换平台"],
    },
    "education": {
        "name": "教育行业",
        "name_en": "Education",
        "regulations": ["教育信息化网络安全规范", "未成年人网络保护条例"],
        "specific_requirements": ["师生个人信息保护", "校园网边界", "在线教学平台可用性"],
        "terminology": {
            "campus_card": "一卡通系统",
            "lms": "在线学习平台",
        },
        "sensitive_assets_focus": ["教务系统", "一卡通", "招生系统"],
    },
    "ecommerce": {
        "name": "电商行业",
        "name_en": "E-commerce",
        "regulations": ["电子商务法", "个人信息保护法", "网络交易监督管理办法"],
        "specific_requirements": ["交易防刷单/防越权", "订单与支付逻辑漏洞", "大促期间可用性"],
        "terminology": {
            "sku": "商品库存单元",
            "oms": "订单管理系统",
        },
        "sensitive_assets_focus": ["订单系统", "支付网关", "用户中心", "营销活动系统"],
    },
    "internet": {
        "name": "互联网行业",
        "name_en": "Internet",
        "regulations": ["网络安全法", "数据安全法", "App违法违规收集使用个人信息自评估指南"],
        "specific_requirements": ["App SDK 安全", "API 鉴权与限流", "内容安全与账号安全"],
        "terminology": {
            "waf": "Web应用防火墙",
            "cdn": "内容分发网络",
        },
        "sensitive_assets_focus": ["App后端", "开放API", "用户数据平台", "推荐系统"],
    },
    "manufacturing": {
        "name": "制造业",
        "name_en": "Manufacturing",
        "regulations": ["等保2.0", "工业控制系统安全防护指南", "数据安全法"],
        "specific_requirements": ["IT/OT 网络隔离", "工控设备漏洞不直接联网验证", "生产连续性优先"],
        "terminology": {
            "scada": "数据采集与监视控制系统",
            "mes": "制造执行系统",
            "erp": "企业资源计划",
        },
        "sensitive_assets_focus": ["MES", "ERP", "SCADA", "PLC 网络"],
    },
    "energy": {
        "name": "能源行业",
        "name_en": "Energy",
        "regulations": ["等保2.0 关键信息基础设施", "电力监控系统安全防护规定", "密码法"],
        "specific_requirements": ["安全分区/网络专用/横向隔离/纵向认证", "工控协议深度检查", "关键信息基础设施识别说明"],
        "terminology": {
            "tunnel": "纵向加密认证装置",
            "bastion": "横向隔离装置",
        },
        "sensitive_assets_focus": ["调度系统", "变电站监控", "SCADA", "生产管理大区"],
    },
}


# --------------------------------------------------------------------------- #
# 3. 标准框架模板
# --------------------------------------------------------------------------- #
FRAMEWORK_TEMPLATES: Dict[str, Dict[str, Any]] = {
    "owasp_top10_2021": {
        "name": "OWASP Top 10 (2021)",
        "version": "2021",
        "categories": [
            "A01 失效的访问控制", "A02 加密机制失效", "A03 注入",
            "A04 不安全设计", "A05 安全配置错误", "A06 易受攻击和过时的组件",
            "A07 身份识别和认证失败", "A08 软件和数据完整性故障",
            "A09 安全日志和监控失败", "A10 服务端请求伪造(SSRF)",
        ],
        "mapping_fields": ["vuln_id", "owasp_code", "evidence"],
    },
    "cwe_top40": {
        "name": "CWE Top 40",
        "version": "2024",
        "categories": ["CWE-79 XSS", "CWE-89 SQL注入", "CWE-22 路径遍历",
                       "CWE-78 命令注入", "CWE-352 CSRF", "CWE-287 认证不当"],
        "mapping_fields": ["vuln_id", "cwe_id", "cwe_name"],
    },
    "sans_top25": {
        "name": "SANS Top 25 最危险软件缺陷",
        "version": "2024",
        "categories": ["注入类", "失效的访问控制", "不可靠的加密实践",
                       "不安全的随机值", "错误处理不当"],
        "mapping_fields": ["vuln_id", "sans_rank"],
    },
    "ptes": {
        "name": "PTES 渗透测试执行标准",
        "version": "2017",
        "phases": ["前期交互", "情报收集", "威胁建模", "漏洞分析",
                   "渗透利用", "后渗透", "报告编写"],
        "mapping_fields": ["vuln_id", "ptes_phase"],
    },
    "nist_sp800_115": {
        "name": "NIST SP 800-115 信息安全测试与评估指南",
        "version": "2008",
        "phases": ["规划", "执行", "后处理", "报告"],
        "mapping_fields": ["vuln_id", "nist_control"],
    },
    "mlps2": {
        "name": "网络安全等级保护 2.0",
        "version": "GB/T 22239-2019",
        "levels": ["第一级 自主保护", "第二级 指导保护", "第三级 监督保护",
                   "第四级 强制保护", "第五级 专控保护"],
        "control_classes": ["安全物理环境", "安全通信网络", "安全区域边界",
                            "安全计算环境", "安全管理中心", "安全管理制度",
                            "安全管理机构", "安全管理人员", "安全建设管理", "安全运维管理"],
        "mapping_fields": ["vuln_id", "control_class", "control_id"],
    },
    "iso27001": {
        "name": "ISO/IEC 27001:2022 信息安全管理体系",
        "version": "2022",
        "control_groups": ["A.5 组织控制", "A.6 人员控制", "A.7 物理控制",
                          "A.8 技术控制"],
        "mapping_fields": ["vuln_id", "iso_control_id"],
    },
    "pci_dss_4": {
        "name": "PCI DSS v4.0 支付卡行业数据安全标准",
        "version": "4.0",
        "requirements": ["1.网络架构", "2.组件配置", "3.账户数据保护",
                         "4.加密传输", "5.恶意软件防护", "6.安全开发",
                         "7.访问控制", "8.身份认证", "9.漏洞管理", "10.日志监控",
                         "11.定期测试", "12.安全策略"],
        "mapping_fields": ["vuln_id", "pci_req_id"],
    },
}


# --------------------------------------------------------------------------- #
# 4. 报告结构模板
# --------------------------------------------------------------------------- #
STRUCTURE_TEMPLATES: Dict[str, Dict[str, Any]] = {
    "cover": {"name": "封面", "order": 1, "fields": ["报告标题", "客户名称", "项目编号",
              "版本", "密级", "发布日期", "编制单位", "批准人"]},
    "toc": {"name": "目录", "order": 2, "auto": True, "fields": ["一级目录", "二级目录", "页码"]},
    "exec_summary": {"name": "执行摘要", "order": 3, "fields": ["项目概述", "关键发现",
                    "风险概览", "建议优先级"]},
    "scope": {"name": "测试范围", "order": 4, "fields": ["资产清单", "边界", "授权范围",
              "不在范围"]},
    "methodology": {"name": "方法论", "order": 5, "fields": ["测试方法", "工具清单",
                   "时间安排", "人员"]},
    "vuln_details": {"name": "漏洞详情", "order": 6, "fields": ["编号", "名称", "等级",
                     "位置", "复现步骤", "证据", "影响"]},
    "risk_rating": {"name": "风险评级", "order": 7, "fields": ["CVSS", "业务影响",
                    "综合评级", "风险矩阵"]},
    "remediation": {"name": "修复建议", "order": 8, "fields": ["通用修复", "代码级",
                   "配置级", "验证方法", "补丁链接"]},
    "appendix": {"name": "附录", "order": 9, "fields": ["工具版本", "扫描原始结果",
                 "术语表", "参考链接"]},
    "glossary": {"name": "术语表", "order": 10, "fields": ["术语", "英文全称", "中文释义"]},
}


# --------------------------------------------------------------------------- #
# 5. 品牌定制模板
# --------------------------------------------------------------------------- #
BRAND_DEFAULT: Dict[str, Any] = {
    "company_name": "Security Report Lab",
    "logo_url": "",
    "primary_color": "#1f6feb",
    "secondary_color": "#0d1117",
    "accent_color": "#2ea043",
    "font_family": "Microsoft YaHei, PingFang SC, Helvetica, Arial",
    "header_left": "机密 · Confidential",
    "header_right": "{report_id}",
    "footer_left": "© {year} {company}",
    "footer_right": "第 {page} 页 / 共 {total} 页",
    "watermark": "机密",
    "watermark_opacity": 0.08,
    "cover_layout": "centered",
    "contact": {"email": "report@example.com", "phone": "", "website": ""},
}


# --------------------------------------------------------------------------- #
# 6. 多语言模板
# --------------------------------------------------------------------------- #
LANGUAGE_PACKS: Dict[str, Dict[str, str]] = {
    "zh_CN": {
        "label": "简体中文",
        "executive_summary": "执行摘要",
        "vulnerability_details": "漏洞详情",
        "risk_rating": "风险评级",
        "remediation": "修复建议",
        "high": "高危", "medium": "中危", "low": "低危", "critical": "严重", "info": "信息",
        "confidential": "机密",
    },
    "en_US": {
        "label": "English (US)",
        "executive_summary": "Executive Summary",
        "vulnerability_details": "Vulnerability Details",
        "risk_rating": "Risk Rating",
        "remediation": "Remediation Recommendations",
        "high": "High", "medium": "Medium", "low": "Low", "critical": "Critical", "info": "Info",
        "confidential": "Confidential",
    },
    "ja_JP": {
        "label": "日本語",
        "executive_summary": "エグゼクティブサマリー",
        "vulnerability_details": "脆弱性詳細",
        "risk_rating": "リスク評価",
        "remediation": "修復推奨事項",
        "high": "高", "medium": "中", "low": "低", "critical": "致命的", "info": "情報",
        "confidential": "機密",
    },
}


# --------------------------------------------------------------------------- #
# 模板系统主体
# --------------------------------------------------------------------------- #
class TemplateSystem:
    """专业报告模板系统：组合六类模板，产出最终报告蓝图。"""

    def __init__(self) -> None:
        self._lock = threading.RLock()
        self._custom_templates: Dict[str, Dict[str, Any]] = {}
        self._brand_overrides: Dict[str, Dict[str, Any]] = {}

    # ---- 报告类型 ---- #
    def list_report_types(self) -> List[Dict[str, Any]]:
        return [{"id": k, **v} for k, v in REPORT_TYPE_TEMPLATES.items()]

    def get_report_type(self, type_id: str) -> Optional[Dict[str, Any]]:
        t = REPORT_TYPE_TEMPLATES.get(type_id)
        return {"id": type_id, **copy.deepcopy(t)} if t else None

    # ---- 行业 ---- #
    def list_industries(self) -> List[Dict[str, Any]]:
        return [{"id": k, **v} for k, v in INDUSTRY_TEMPLATES.items()]

    def get_industry(self, ind: str) -> Optional[Dict[str, Any]]:
        v = INDUSTRY_TEMPLATES.get(ind)
        return {"id": ind, **copy.deepcopy(v)} if v else None

    # ---- 标准框架 ---- #
    def list_frameworks(self) -> List[Dict[str, Any]]:
        return [{"id": k, **v} for k, v in FRAMEWORK_TEMPLATES.items()]

    def get_framework(self, fid: str) -> Optional[Dict[str, Any]]:
        v = FRAMEWORK_TEMPLATES.get(fid)
        return {"id": fid, **copy.deepcopy(v)} if v else None

    # ---- 结构 ---- #
    def list_structure(self) -> List[Dict[str, Any]]:
        return sorted(({"id": k, **v} for k, v in STRUCTURE_TEMPLATES.items()),
                      key=lambda x: x["order"])

    # ---- 品牌 ---- #
    def get_brand(self, org: str = "default") -> Dict[str, Any]:
        base = copy.deepcopy(BRAND_DEFAULT)
        if org in self._brand_overrides:
            base.update(self._brand_overrides[org])
        return base

    def update_brand(self, org: str, patch: Dict[str, Any]) -> Dict[str, Any]:
        with self._lock:
            cur = self._brand_overrides.setdefault(org, {})
            cur.update(patch or {})
        return self.get_brand(org)

    # ---- 多语言 ---- #
    def list_languages(self) -> List[Dict[str, Any]]:
        return [{"id": k, "label": v["label"],
                 "terms": {kk: vv for kk, vv in v.items() if kk != "label"}}
                for k, v in LANGUAGE_PACKS.items()]

    def get_language(self, lang: str) -> Optional[Dict[str, Any]]:
        v = LANGUAGE_PACKS.get(lang)
        return {"id": lang, **copy.deepcopy(v)} if v else None

    def translate(self, key: str, lang: str = "zh_CN") -> str:
        pack = LANGUAGE_PACKS.get(lang, LANGUAGE_PACKS["zh_CN"])
        return pack.get(key, key)

    # ---- 自定义模板 CRUD ---- #
    def list_custom(self) -> List[Dict[str, Any]]:
        return list(self._custom_templates.values())

    def create_custom(self, name: str, **kwargs: Any) -> Dict[str, Any]:
        tid = f"ct_{abs(hash(name)) & 0xffffff:06x}"
        doc = {"id": tid, "name": name, **kwargs}
        with self._lock:
            self._custom_templates[tid] = doc
        return doc

    def update_custom(self, tid: str, patch: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        with self._lock:
            if tid in self._custom_templates:
                self._custom_templates[tid].update(patch)
                return self._custom_templates[tid]
        return None

    def delete_custom(self, tid: str) -> bool:
        with self._lock:
            return self._custom_templates.pop(tid, None) is not None

    # ---- 组合生成报告蓝图 ---- #
    def compose_blueprint(self, report_type: str = "penetration_test",
                         industry: str = "internet",
                         frameworks: Optional[List[str]] = None,
                         language: str = "zh_CN",
                         org: str = "default") -> Dict[str, Any]:
        """把六类模板组合成一份报告蓝图。"""
        frameworks = frameworks or ["owasp_top10_2021"]
        rt = self.get_report_type(report_type) or REPORT_TYPE_TEMPLATES["penetration_test"]
        ind = self.get_industry(industry) or {"id": industry}
        fr = [self.get_framework(f) for f in frameworks if self.get_framework(f)]
        struct = self.list_structure()
        brand = self.get_brand(org)
        lang = self.get_language(language) or LANGUAGE_PACKS["zh_CN"]
        return {
            "report_type": rt,
            "industry": ind,
            "frameworks": fr,
            "structure": struct,
            "brand": brand,
            "language": lang,
            "meta": {
                "composed_at": __import__("datetime").datetime.now().isoformat(timespec="seconds"),
                "sections_count": len(struct),
                "framework_count": len(fr),
            },
        }


_singleton: Optional[TemplateSystem] = None


def get_template_system() -> TemplateSystem:
    global _singleton
    if _singleton is None:
        _singleton = TemplateSystem()
    return _singleton
