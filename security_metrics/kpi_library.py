#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
kpi_library.py — 安全 KPI 指标库（200+ 指标）。

5 大类：
    - risk     风险类（漏洞/暴露面/威胁/资产风险）
    - ops      运营类（检测/响应/恢复/工单/值班）
    - tech     技术类（防护覆盖率/补丁/配置/加密/身份）
    - compliance 合规类（法规/框架/控制项/审计）
    - finance  财务类（安全投入/ROI/损失规避/成本）

每个指标含：定义、计算方法、数据源、单位、目标值、阈值、预警规则、权重。
"""

from __future__ import annotations

from typing import Any, Dict, List, Optional


KPI_CATEGATEGORIES_RAW: Dict[str, Dict[str, Any]] = {
    "risk": {
        "key": "risk", "name": "风险类", "weight": 0.30,
        "series": {
            "vuln": ("漏洞风险", ["严重漏洞数", "高危漏洞数", "中危漏洞数", "低危漏洞数",
                              "漏洞修复率", "漏洞平均修复时长", "未修复高危漏洞占比",
                              "已知利用漏洞(KEV)数", "漏洞复发率", "新发现漏洞数",
                              "公开POC漏洞占比", "在野利用漏洞数", "平均漏洞暴露天数",
                              "SLA内修复漏洞占比", "补丁已发布未修复漏洞数",
                              "影响核心业务漏洞数", "漏洞误报数", "漏洞验证覆盖率",
                              "重资产漏洞数", "历史漏洞遗留数"]),
            "exposure": ("暴露面", ["公网暴露资产数", "暴露面攻击面指数", "影子IT资产数",
                                "未备案资产数", "高危端口暴露数", "过期证书数",
                                "匿名可访问存储桶数", "暴露API数", "弱口令服务暴露数",
                                "未授权访问接口数", "测试环境公网暴露数", "废弃域名数",
                                "暗网泄露凭证数", "代码仓库公开泄露数", "暴露管理后台数",
                                "VPN/远程接入暴露数", "CDN源站直连暴露数"]),
            "threat": ("威胁", ["月度安全事件数", "成功入侵事件数", "钓鱼邮件攻击数",
                            "勒索软件事件数", "数据泄露事件数", "内部威胁事件数",
                            "恶意代码检出数", "账号失陷数", "DDoS攻击次数", "web攻击拦截数",
                            "暴力破解次数", "异常登录次数", "提权事件数", "横向移动事件数",
                            "命令注入攻击数", "SQL注入攻击数", "XSS攻击拦截数",
                            "0day/1day威胁事件数", "供应链攻击事件数", "社工攻击成功率",
                            "僵尸网络感染主机数", "挖矿木马事件数", "凭证填充攻击次数",
                            "C2回连检测数"]),
            "asset": ("资产风险", ["未管理资产占比", "高风险资产占比", "无负责人资产数",
                              "生命周期过期资产数", "IoT/OT高风险设备数",
                              "资产台账准确率", "核心资产识别率", "互联网-facing资产占比",
                              "云配置漂移数", "未打标签资产数", "容器镜像高危数",
                              "无主云资源数", "影子数据存储数", "供应商接入资产数",
                              "资产风险覆盖率", "资产漏洞关联率"]),
        },
    },
    "ops": {
        "key": "ops", "name": "运营类", "weight": 0.25,
        "series": {
            "ttr": ("响应时效", ["MTTD平均检测时间", "MTTR平均响应时间", "MTRS平均解决时间",
                            "事件升级及时率", "首次响应达标率", "工单平均处理时长",
                            "严重事件闭环时长", "事件遏制时间", "根因分析完成率",
                            " lessons learned闭环率", "7x24值班覆盖率", "节假日值班到位率",
                            "SLA响应达成率", "SLA解决达成率", "跨团队协作响应时长"]),
            "alert": ("告警运营", ["日均告警量", "告警误报率", "告警漏报率", "告警闭环率",
                             "自动化处置率", "人工研判占比", "重复告警占比", "告警降噪率",
                             "告警分级准确率", "告警平均确认时长", "误报调优次数",
                             "规则命中率", "告警积压率", "升级告警占比", "告警覆盖率"]),
            "workload": ("工作量", ["分析师人均日研判数", "夜班工作量占比", "工单积压量",
                               "SLA逾期工单数", "分析师加班率", "疲劳度指数",
                               "人均管理资产数", "人均负责事件数", "分析师持证比例",
                               "人员流动率", "排班满足率", "培训人天", "工具使用率",
                               "工单一次解决率", "知识沉淀数量"]),
            "drill": ("演练", ["应急演练完成率", "桌面推演次数", "红蓝对抗次数",
                          "备份恢复演练成功率", "业务连续性达成率", "勒索恢复演练次数",
                          "断网演练次数", "供应商协同演练次数", "演练改进项闭环率",
                          "演练参与率", "RTO实测达成率", "RPO实测达成率",
                          "演练发现问题数", "演练平均得分", "年度演练计划完成率"]),
        },
    },
    "tech": {
        "key": "tech", "name": "技术类", "weight": 0.20,
        "series": {
            "coverage": ("防护覆盖", ["EDR覆盖率", "防火墙覆盖率", "邮件安全网关覆盖率",
                               "Web应用防火墙覆盖率", "终端补丁覆盖率", "MFA覆盖率",
                               "日志采集覆盖率", "DLP策略覆盖率", "加密覆盖率",
                               "VPN零信任迁移率", "数据库审计覆盖率", "堡垒机覆盖率",
                               "漏扫覆盖率", "基线核查覆盖率", "邮件DKIM/DMARC覆盖率",
                               "主机入侵检测覆盖率", "Web Shell检测覆盖率",
                               "数据库加密覆盖率", "API安全网关覆盖率", "云安全配置基线覆盖率"]),
            "config": ("配置基线", ["基线合规率", "高危配置项数", "特权账号占比",
                             "最小权限落实率", "弱口令账户数", "默认配置未改数",
                             "过期账号数", "共享账号数", "管理员组人员数",
                             "审计日志关闭数", "不安全协议开启数", "开放服务非必要数",
                             "基线偏差自动修复率", "配置漂移检测数", "账号权限复核完成率"]),
            "devsecops": ("开发安全", ["SAST代码扫描覆盖率", "SCA依赖扫描覆盖率",
                                "DAST扫描覆盖率", "CI安全门禁拦截率", "密钥泄露数",
                                "上线前安全评审率", "制品签名率", "容器镜像扫描覆盖率",
                                "IaC扫描覆盖率", "安全左移缺陷密度", "重构漏洞占比",
                                "第三方组件治理覆盖率", "开发者安全培训完成率",
                                "流水线安全任务耗时", "安全质量门禁通过率",
                                "代码安全左移发现占比"]),
            "arch": ("架构", ["零信任覆盖率", "微隔离覆盖率", "纵深防御层数",
                       "网络分段达标率", "API网关覆盖率", "东西向流量监测率",
                       "双活/多活覆盖率", "网关高可用率", "关键链路冗余率",
                       "安全架构评审覆盖率", "最小网络暴露面", "信任边界划分率",
                       "默认拒绝策略覆盖率", "南北向流量清洗率", "数据安全架构覆盖率"]),
        },
    },
    "compliance": {
        "key": "compliance", "name": "合规类", "weight": 0.15,
        "series": {
            "coverage": ("合规覆盖", ["法规映射覆盖率", "控制项落实率", "证据留存完整率",
                                "内审覆盖率", "管理评审完成率", "制度文件覆盖率",
                                "年度合规计划完成率", "岗位合规培训覆盖率",
                                "第三方合规评估覆盖率", "业务线合规覆盖率",
                                "法规更新跟踪覆盖率", "合规责任人到位率",
                                "合规台账准确率", "法规差异分析完成率", "合规知识库更新率"]),
            "audit": ("审计发现", ["外部审计发现数", "内审发现数", "高危发现占比",
                            "发现重复发生率", "审计意见类型", "审计观察项数",
                            "管理层声明书签署率", "审计证据链完整率",
                            "关键控制点测试通过率", "抽样偏差率",
                            "审计整改建议采纳率", "审计计划完成率",
                            "联合审计次数", "专项审计次数", "审计独立性评估结果"]),
            "remediation": ("整改", ["整改完成率", "整改按期率", "逾期未整改项数",
                               "整改平均周期", "重复整改率", "整改验证通过率",
                               "整改责任人落实率", "整改资源到位率",
                               "延期审批合规率", "整改后复发率",
                               "高危整改占比", "整改进度透明度",
                               "整改闭环平均时长", "整改材料归档率", "整改验收一次通过率"]),
            "privacy": ("隐私", ["DPIA完成率", "数据主体请求响应时长", "跨境数据评估完成率",
                            "隐私政策合规率", "隐私培训完成率", "数据泄露通报及时率",
                            "隐私影响评估覆盖率", "数据处理活动记录完整率",
                            "供应商隐私条款合规率", "儿童信息保护合规率",
                            "数据删除请求完成率", "隐私投诉处理时长",
                            "数据最小化落实率", "隐私设计嵌入率", "DPO履职评估结果"]),
        },
    },
    "finance": {
        "key": "finance", "name": "财务类", "weight": 0.10,
        "series": {
            "invest": ("安全投入", ["安全总投入", "安全投入占IT预算比", "人均安全投入",
                              "安全软件采购额", "安全服务采购额", "安全人力成本",
                              "安全硬件投入", "安全培训投入", "应急响应储备金",
                              "合规认证支出", "云安全额外支出", "外部测评支出",
                              "安全研发投入", "安全咨询支出", "年度预算执行率"]),
            "roi": ("投资回报", ["安全ROI", "规避损失金额", "单次事件平均损失",
                           "安全投资回收期", "合规罚款风险敞口", "数据泄露预估损失",
                           "风险敞口下降率", "安全投入产出比", "保险理赔对冲比例",
                           "损失规避率", "预防事件年化收益", "安全资本回报率",
                           "事件损失占营收比", "保费支出与赔付比", "风险转移覆盖率"]),
            "cost": ("成本优化", ["安全自动化节约工时", "云安全成本优化额",
                           "重复采购节约额", "安全工具整合率", "闲置许可成本",
                           "冗余工具下线数", "License使用率", "运维人力节约",
                           "自动化脚本节约人天", "云账单安全优化", "安全采购集采折扣",
                           "合同续约节约", "重复扫描资源节约", "开源替代节约额",
                           "FinOps安全节约率"]),
        },
    },
}

KPI_UNITS = {
    "漏洞风险": "个/条", "暴露面": "个", "威胁": "起", "资产风险": "%",
    "响应时效": "小时/分钟", "告警运营": "%", "工作量": "件/人", "演练": "次/%",
    "防护覆盖": "%", "配置基线": "%/项", "开发安全": "%", "架构": "%",
    "合规覆盖": "%", "审计发现": "项", "整改": "%", "隐私": "天/%",
    "安全投入": "万元", "投资回报": "倍/万元", "成本优化": "万元",
}

KPI_DATA_SOURCES = {
    "漏洞风险": "漏洞管理平台(VulnMgmt)", "暴露面": "攻击面管理(ASM)", "威胁": "SIEM/EDR/威胁情报",
    "资产风险": "资产管理平台(CMDB)", "响应时效": "工单系统/SOAR", "告警运营": "SIEM/SOAR",
    "工作量": "SOC排班系统", "演练": "应急演练记录", "防护覆盖": "终端管理/网络设备",
    "配置基线": "配置管理数据库(CMDB)", "开发安全": "DevSecOps流水线", "架构": "网络拓扑/AIOps",
    "合规覆盖": "GRC平台", "审计发现": "审计管理系统", "整改": "GRC/工单系统",
    "隐私": "隐私治理平台", "安全投入": "财务系统", "投资回报": "财务+风险量化模型",
    "成本优化": "采购/FinOps",
}


def _build_library() -> Dict[str, Dict[str, Any]]:
    """生成 200+ KPI 指标库。"""
    lib: Dict[str, Dict[str, Any]] = {}
    seq = 0
    for cat_key, cat in KPI_CATEGATEGORIES_RAW.items():
        for series_key, (series_name, names) in cat["series"].items():
            for idx, name in enumerate(names, 1):
                seq += 1
                kid = f"KPI-{cat_key.upper()}-{series_key.upper()}-{idx:02d}"
                unit = KPI_UNITS.get(series_name, "个")
                # 方向：higher_better / lower_better
                lower_better = any(w in name for w in
                                   ["时长", "时间", "误报", "逾期", "积压", "加班", "疲劳",
                                    "数", "项", "率"] if "率" not in name)
                higher_better = not lower_better
                if any(w in name for w in ["覆盖率", "修复率", "闭环率", "落实率", "完成率",
                                            "达标率", "及时率", "通过率", "达成率", "ROI"]):
                    higher_better = True
                if any(w in name for w in ["时长", "时间", "积压", "加班率", "疲劳度"]):
                    higher_better = False
                target = 95.0 if higher_better else (4.0 if "MT" in name or "时长" in name else 0.0)
                warn = (target * 0.9) if higher_better else (target * 1.5 + 2)
                lib[kid] = {
                    "id": kid, "name": name, "category": cat_key,
                    "category_name": cat["name"], "series": series_name,
                    "unit": unit, "direction": "higher_better" if higher_better else "lower_better",
                    "target": target,
                    "warning_threshold": round(warn, 2),
                    "weight": round(cat["weight"] / max(1, len(names)), 4),
                    "data_source": KPI_DATA_SOURCES.get(series_name, "内部度量平台"),
                    "formula": f"该指标按 {series_name} 业务系统埋点数据周期性统计（月/季）。",
                    "definition": f"{cat['name']}-{series_name}维度安全度量指标，用于{name}的趋势跟踪与预警。",
                    "alert_rule": (
                        f"连续2期低于目标值 {target}{unit} 触发黄色预警；连续3期触发橙色预警。"
                        if higher_better else
                        f"超过阈值 {round(warn, 2)}{unit} 触发黄色预警；连续2期超限触发橙色预警。"
                    ),
                }
    return lib


KPI_LIBRARY: Dict[str, Dict[str, Any]] = _build_library()
KPI_LIBRARY_SIZE = len(KPI_LIBRARY)
KPI_CATEGORIES = {k: v["name"] for k, v in KPI_CATEGATEGORIES_RAW.items()}


class KPILibrary:
    """KPI 指标库查询与评估器。"""

    def list(self, category: Optional[str] = None,
              series: Optional[str] = None) -> Dict[str, Any]:
        items = list(KPI_LIBRARY.values())
        if category:
            items = [k for k in items if k["category"] == category]
        if series:
            items = [k for k in items if k["series"] == series]
        by_cat: Dict[str, int] = {}
        for k in KPI_LIBRARY.values():
            by_cat[k["category_name"]] = by_cat.get(k["category_name"], 0) + 1
        return {
            "total": KPI_LIBRARY_SIZE, "returned": len(items),
            "categories": by_cat,
            "items": items,
        }

    def get(self, kpi_id: str) -> Optional[Dict[str, Any]]:
        return KPI_LIBRARY.get(kpi_id)

    def categories(self) -> Dict[str, Any]:
        out = {}
        for k, v in KPI_CATEGATEGORIES_RAW.items():
            series_list = list(v["series"].values())
            out[k] = {"name": v["name"], "weight": v["weight"],
                      "series": [s[0] for s in v["series"].values()],
                      "kpi_count": sum(len(s[1]) for s in v["series"].values())}
        return out

    def evaluate(self, readings: Dict[str, float]) -> Dict[str, Any]:
        """
        根据当期读数评估 KPI 达成情况。
        readings: {kpi_id: actual_value}
        """
        results: List[Dict[str, Any]] = []
        hit = 0
        for kid, val in readings.items():
            meta = KPI_LIBRARY.get(kid)
            if not meta:
                continue
            tgt = meta["target"]
            ok_flag = (val >= tgt) if meta["direction"] == "higher_better" else (val <= tgt)
            warn_flag = (val < meta["warning_threshold"]) if meta["direction"] == "higher_better" \
                else (val > meta["warning_threshold"])
            if ok_flag:
                hit += 1
            results.append({
                "id": kid, "name": meta["name"], "category": meta["category_name"],
                "actual": val, "target": tgt, "unit": meta["unit"],
                "status": "hit" if ok_flag else ("warning" if warn_flag else "miss"),
            })
        total = len(results)
        return {
            "evaluated_at": __import__("time").strftime("%Y-%m-%d %H:%M:%S"),
            "total_metrics": total, "hit_count": hit,
            "hit_rate": round(hit / total * 100, 1) if total else 0.0,
            "results": results,
            "summary": {
                "excellent": sum(1 for r in results if r["status"] == "hit"),
                "warning": sum(1 for r in results if r["status"] == "warning"),
                "miss": sum(1 for r in results if r["status"] == "miss"),
            },
        }
