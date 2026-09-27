# -*- coding: utf-8 -*-
"""
合规审计模块

内置三大合规框架检查清单：
    - 等保2.0（MLPS2.0）：技术要求 + 管理要求，30+ 项
    - ISO 27001：14 个控制域，每域 ≥2 项，共 28+ 项
    - PCI-DSS：12 个要求，共 12+ 项

支持：审计执行、合规报告生成、两次审计趋势对比、持久化存储。

注意：本模块仅用于授权合规评估与防御整改。
"""
import os
import json
import time
import uuid
from typing import Any, Dict, List, Optional

from utils.logger import log

PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
DATA_DIR = os.path.join(PROJECT_ROOT, "data", "compliance")


def _item(item_id, framework, category, name, check_method,
          risk_level, clause, remediation, description):
    """构造一个检查项。"""
    return {
        "id": item_id,
        "framework": framework,
        "category": category,
        "name": name,
        "check_method": check_method,
        "risk_level": risk_level,
        "standard_clause": clause,
        "remediation": remediation,
        "description": description,
    }


# ---------------------------------------------------------------------- #
# 等保 2.0 检查清单（31 项）
# ---------------------------------------------------------------------- #
def _build_mlps2_checklist() -> List[Dict[str, Any]]:
    fw = "mlps2"
    items: List[Dict[str, Any]] = []
    # 物理安全（3）
    items += [
        _item("ML-PH-01", fw, "物理安全", "机房选址与防震防风防水",
              "现场检查机房位置及防护措施", "高", "8.1.1",
              "机房应避开危险区域，采取防水防潮措施",
              "机房场地应选择在具有防震、防风和防雨等能力的建筑内"),
        _item("ML-PH-02", fw, "物理安全", "物理访问控制",
              "核查机房出入口与门禁记录", "高", "8.1.2",
              "机房出入口应配置电子门禁系统，控制、鉴别和记录进入人员",
              "应对物理访问进行授权与审计"),
        _item("ML-PH-03", fw, "物理安全", "防盗防破坏与媒体保护",
              "检查机柜上锁及介质存放", "中", "8.1.3",
              "设备应固定并加锁，存储介质应有物理保护",
              "防止设备被盗或被破坏，防止介质泄密"),
    ]
    # 网络安全（5）
    items += [
        _item("ML-NW-01", fw, "网络安全", "网络架构与带宽",
              "核查网络拓扑及关键节点冗余", "高", "8.1.4",
              "应保证网络设备的业务处理能力满足业务高峰需要",
              "网络拓扑应合理，关键设备应有冗余"),
        _item("ML-NW-02", fw, "网络安全", "网络访问控制",
              "核查边界访问控制策略", "高", "8.1.5",
              "应在网络边界部署访问控制设备，启用访问控制功能",
              "默认拒绝，最小化端口开放"),
        _item("ML-NW-03", fw, "网络安全", "入侵防范",
              "检查 IDS/IPS 部署与规则", "高", "8.1.6",
              "应在网络边界处监视攻击行为并告警",
              "部署入侵检测/防御系统"),
        _item("ML-NW-04", fw, "网络安全", "恶意代码防范",
              "检查网络出口防病毒网关", "中", "8.1.7",
              "应在关键节点对恶意代码进行检测和清除",
              "网络层恶意代码检测"),
        _item("ML-NW-05", fw, "网络安全", "安全审计",
              "核查网络设备日志留存", "中", "8.1.8",
              "应对网络系统运行状态和用户行为进行审计，留存不少于6个月",
              "审计记录应受到保护免受未预期删除修改"),
    ]
    # 主机安全（5）
    items += [
        _item("ML-HS-01", fw, "主机安全", "身份鉴别",
              "核查登录口令策略", "高", "8.1.9",
              "应对登录用户进行身份标识和鉴别，口令复杂度达标",
              "唯一标识，复杂度要求，登录失败处理"),
        _item("ML-HS-02", fw, "主机安全", "访问控制",
              "核查权限分配与最小化", "高", "8.1.10",
              "应授予管理用户所需的最小权限",
              "实现权限分离与最小化"),
        _item("ML-HS-03", fw, "主机安全", "安全审计",
              "核查主机审计策略", "中", "8.1.11",
              "应启用安全审计功能，覆盖每个用户",
              "审计记录保护"),
        _item("ML-HS-04", fw, "主机安全", "入侵防范",
              "检查主机 HIDS/补丁", "高", "8.1.12",
              "应遵循最小安装原则，关闭不需要的端口和服务",
              "主机入侵检测与漏洞修复"),
        _item("ML-HS-05", fw, "主机安全", "资源控制",
              "核查 CPU/磁盘/会话配额", "中", "8.1.13",
              "应对资源使用限额进行控制",
              "防止单点耗尽资源导致拒绝服务"),
    ]
    # 应用安全（5）
    items += [
        _item("ML-AP-01", fw, "应用安全", "身份鉴别",
              "检查应用登录认证机制", "高", "8.1.14",
              "应采用口令、密码技术等两种或以上组合技术进行身份鉴别",
              "多因素认证"),
        _item("ML-AP-02", fw, "应用安全", "访问控制",
              "核查应用权限模型", "高", "8.1.15",
              "应由授权主体配置访问控制策略",
              "基于角色的访问控制 RBAC"),
        _item("ML-AP-03", fw, "应用安全", "通信安全",
              "检查传输加密", "中", "8.1.16",
              "应采用密码技术保证通信过程中数据的完整性和保密性",
              "使用 TLS 加密敏感通信"),
        _item("ML-AP-04", fw, "应用安全", "软件容错",
              "检查异常处理与重试机制", "中", "8.1.17",
              "应提供数据有效性检验功能",
              "输入校验，失败自动恢复"),
        _item("ML-AP-05", fw, "应用安全", "资源控制",
              "检查会话超时与并发限制", "中", "8.1.18",
              "应限制用户终端超时锁定和并发会话数",
              "会话管理与限流"),
    ]
    # 数据安全（3）
    items += [
        _item("ML-DS-01", fw, "数据安全", "数据完整性",
              "检查传输/存储完整性保护", "中", "8.1.19",
              "应采用密码技术保证重要数据传输和存储完整性",
              "校验和/MAC"),
        _item("ML-DS-02", fw, "数据安全", "数据保密性",
              "检查敏感数据加密存储", "高", "8.1.20",
              "应采用密码技术保证重要数据存储保密性",
              "敏感字段加密"),
        _item("ML-DS-03", fw, "数据安全", "数据备份恢复",
              "核查备份策略与恢复演练", "高", "8.1.21",
              "应提供本地数据备份与恢复功能，完全备份至少每天一次",
              "异地实时备份，定期恢复演练"),
    ]
    # 管理要求（10）
    items += [
        _item("ML-MG-01", fw, "安全管理", "安全管理制度制定", "查阅制度文件", "中", "8.2.1",
              "应制定信息安全工作的总体方针和安全策略",
              "形成成文的安全策略文件"),
        _item("ML-MG-02", fw, "安全管理", "安全制度发布评审", "检查发布与评审记录", "低", "8.2.2",
              "应定期对制度进行评审和更新", "每年至少评审一次"),
        _item("ML-MG-03", fw, "安全管理", "安全管理机构设置", "核查组织架构", "中", "8.3.1",
              "应成立指导和管理信息安全工作的委员会", "设立信息安全主管部门"),
        _item("ML-MG-04", fw, "安全管理", "人员录用与离岗管理", "查阅人事流程", "中", "8.3.2",
              "应及时终止离岗人员所有访问权限", "权限回收清单"),
        _item("ML-MG-05", fw, "安全管理", "人员安全意识培训", "检查培训记录", "低", "8.4.1",
              "应对各类人员进行安全意识教育培训", "每年至少一次"),
        _item("ML-MG-06", fw, "安全管理", "外部人员访问管理", "核查访客登记", "中", "8.4.2",
              "应对外部人员访问机房等区域进行审批", "访客登记与陪同"),
        _item("ML-MG-07", fw, "安全管理", "系统建设方案审批", "查阅立项文档", "中", "8.5.1",
              "保证建设过程同步考虑安全", "安全方案评审"),
        _item("ML-MG-08", fw, "安全管理", "上线前安全测评", "检查验收材料", "高", "8.5.2",
              "上线前应进行安全性测试和验收", "渗透测试报告"),
        _item("ML-MG-09", fw, "安全管理", "运维漏洞与风险管理", "检查漏洞处置记录", "高", "8.6.1",
              "应定期进行漏洞扫描和风险评估", "按月扫描"),
        _item("ML-MG-10", fw, "安全管理", "应急预案与演练", "查阅预案与演练记录", "高", "8.6.2",
              "应制定应急预案并定期演练", "每年至少一次应急演练"),
    ]
    return items


# ---------------------------------------------------------------------- #
# ISO 27001 检查清单（14 域 × 2 = 28 项）
# ---------------------------------------------------------------------- #
def _build_iso27001_checklist() -> List[Dict[str, Any]]:
    fw = "iso27001"
    domains = [
        ("信息安全策略", "A.5", [
            ("信息安全策略文件", "查阅策略文件", "中",
             "管理层应定义并批准信息安全策略", "策略应经过管理层批准并传达"),
            ("策略定期评审", "检查评审记录", "低",
             "至少每年评审一次", "建立年度评审机制"),
        ]),
        ("组织安全", "A.6", [
            ("职责划分", "查阅岗位说明", "中",
             "信息安全职责应清晰划分", "职责分离原则"),
            ("与外部方通信", "检查外部通信协议", "中",
             "应保护与外部方接口的信息", "签订保密协议"),
        ]),
        ("人力资源", "A.7", [
            ("录用前背景审查", "查阅背调流程", "中",
             "员工录用前应进行背景核查", "背调记录留存"),
            ("纪律处理过程", "检查奖惩制度", "低",
             "对违规员工应有正式纪律处理流程", "成文制度"),
        ]),
        ("资产管理", "A.8", [
            ("资产清单", "核查资产台账", "中",
             "应维护信息与相关资产清单", "资产负责人明确"),
            ("资产正确使用", "检查使用规范", "低",
             "应制定资产使用规则", "防止滥用"),
        ]),
        ("访问控制", "A.9", [
            ("访问控制策略", "核查策略文件", "高",
             "应基于业务和安全需求制定访问控制策略", "最小权限"),
            ("用户权限复核", "检查权限复核记录", "中",
             "应定期复核用户访问权限", "季度复核"),
        ]),
        ("密码学", "A.10", [
            ("密码控制策略", "查阅加密策略", "高",
             "应制定并实施密码学控制策略", "统一加密规范"),
            ("密钥管理", "检查密钥流程", "高",
             "应有完整密钥生成/存储/销毁流程", "密钥分级管理"),
        ]),
        ("物理环境", "A.11", [
            ("安全区域", "现场核查", "高",
             "应定义安全区域并采取物理保护", "门禁+监控"),
            ("设备安置与保护", "检查机房设备", "中",
             "设备应安置在安全区域", "防雷防静电"),
        ]),
        ("操作安全", "A.12", [
            ("操作程序", "查阅运维文档", "中",
             "应形成成文的操作程序", "标准化运维"),
            ("恶意代码防护", "检查防病毒", "高",
             "应实施恶意代码防护与更新", "病毒库最新"),
        ]),
        ("通信安全", "A.13", [
            ("网络控制", "核查网络隔离", "高",
             "应控制网络中的信息流", "VLAN 隔离"),
            ("信息传输保护", "检查传输加密", "中",
             "应保护敏感信息传输", "TLS/IPSec"),
        ]),
        ("系统获取开发维护", "A.14", [
            ("上线安全需求", "检查需求文档", "高",
             "应在系统生命周期中纳入安全需求", "安全左移"),
            ("变更管理", "检查变更审批", "中",
             "系统变更应受控制", "变更评审与回滚"),
        ]),
        ("供应商关系", "A.15", [
            ("供应商安全策略", "查阅供应商协议", "中",
             "应管理供应商链路的信息安全风险", "合同安全条款"),
            ("服务交付", "检查 SLA", "低",
             "应监控供应商服务交付", "定期考核"),
        ]),
        ("事件管理", "A.16", [
            ("事件报告", "检查上报渠道", "中",
             "应提供事件快速上报渠道", "24h 上报"),
            ("事件总结", "检查复盘记录", "低",
             "事件处理后应总结经验教训", "根因分析"),
        ]),
        ("业务连续性", "A.17", [
            ("连续性规划", "查阅 BCP", "高",
             "应制定并保持业务连续性", "容灾演练"),
            ("冗余", "检查冗余架构", "中",
             "应提供信息处理设施冗余", "双活/备份"),
        ]),
        ("合规", "A.18", [
            ("法律合规", "检查合规清单", "高",
             "应识别适用的法律法规要求", "合规义务清单"),
            ("审计独立", "检查审计计划", "中",
             "应独立审计系统与组织", "年度审计"),
        ]),
    ]
    items: List[Dict[str, Any]] = []
    for idx, (dom, clause, checks) in enumerate(domains, start=1):
        for j, (name, method, risk, remediation, desc) in enumerate(checks, start=1):
            items.append(_item(
                "ISO-%02d-%02d" % (idx, j), fw, dom, name, method, risk,
                clause, remediation, desc))
    return items


# ---------------------------------------------------------------------- #
# PCI-DSS 检查清单（12 项）
# ---------------------------------------------------------------------- #
def _build_pci_checklist() -> List[Dict[str, Any]]:
    fw = "pci_dss"
    specs = [
        ("PCI-01", "防火墙", "安装维护防火墙配置保护持卡人数据", "核查防火墙规则", "高", "Req 1",
         "配置并维护防火墙规则", "禁止默认端口暴露"),
        ("PCI-02", "密码配置", "不改用厂商默认密码", "核查账号口令", "高", "Req 2",
         "修改默认口令并使用强口令", "禁用默认账号"),
        ("PCI-03", "保护持卡人数据", "存储持卡人数据须加密", "核查数据存储", "高", "Req 3",
         "PAN 加密存储并截断显示", "不得存储 CVV"),
        ("PCI-04", "加密传输", "开放式公共网络中加密传输持卡人数据", "检查 TLS", "高", "Req 4",
         "强加密传输", "禁用弱加密套件"),
        ("PCI-05", "防病毒", "所有系统部署并维护防病毒软件", "检查 AV", "中", "Req 5",
         "防病毒实时更新", "排除关键系统需补偿控制"),
        ("PCI-06", "安全系统", "维护安全系统与软件", "检查补丁", "高", "Req 6",
         "及时安装关键补丁", "每月漏洞扫描"),
        ("PCI-07", "访问控制", "按业务需要限制访问", "核查权限", "高", "Req 7",
         "最小权限访问持卡人数据", "职责分离"),
        ("PCI-08", "身份认证", "标识访问系统的用户", "核查认证", "中", "Req 8",
         "唯一用户 ID 与强认证", "多因素认证"),
        ("PCI-09", "物理访问", "限制物理访问持卡人数据", "现场检查", "中", "Req 9",
         "门禁与访客登记", "监控录像留存"),
        ("PCI-10", "监控", "跟踪并监控对网络资源和持卡人数据的访问", "检查日志", "高", "Req 10",
         "日志集中采集与告警", "日志留存1年"),
        ("PCI-11", "测试", "定期测试安全系统和流程", "检查测试", "中", "Req 11",
         "每季度漏洞扫描", "年度渗透测试"),
        ("PCI-12", "安全策略", "维护信息安全策略", "查阅策略", "中", "Req 12",
         "成文安全策略并年度评审", "全员知晓"),
    ]
    return [
        _item(i, fw, cat, name, method, risk, clause, rem, desc)
        for (i, cat, name, method, risk, clause, rem, desc) in specs
    ]


# 检查清单注册表
CHECKLISTS: Dict[str, List[Dict[str, Any]]] = {
    "mlps2": _build_mlps2_checklist(),
    "iso27001": _build_iso27001_checklist(),
    "pci_dss": _build_pci_checklist(),
}


class ComplianceAuditor:
    """合规审计器"""

    FRAMEWORK_LABELS = {
        "mlps2": "网络安全等级保护2.0",
        "iso27001": "ISO/IEC 27001:2022",
        "pci_dss": "PCI DSS v4.0",
    }

    def __init__(self, data_dir: Optional[str] = None):
        self.data_dir = data_dir or DATA_DIR
        os.makedirs(self.data_dir, exist_ok=True)
        self.audit_file = os.path.join(self.data_dir, "audits.json")
        self.audits: Dict[str, Dict[str, Any]] = {}
        self._load()
        log.info("合规审计器初始化，共 %d 次历史审计" % len(self.audits))

    # ------------------------------------------------------------------ #
    # 持久化
    # ------------------------------------------------------------------ #
    def _load(self) -> None:
        try:
            if os.path.exists(self.audit_file):
                with open(self.audit_file, "r", encoding="utf-8") as f:
                    self.audits = json.load(f)
        except Exception as e:  # pragma: no cover
            log.warning("加载审计数据失败: %s" % e)
            self.audits = {}

    def _save(self) -> None:
        try:
            with open(self.audit_file, "w", encoding="utf-8") as f:
                json.dump(self.audits, f, ensure_ascii=False, indent=2)
        except Exception as e:  # pragma: no cover
            log.error("保存审计数据失败: %s" % e)

    # ------------------------------------------------------------------ #
    # 清单查询
    # ------------------------------------------------------------------ #
    def list_checklists(self, framework: str) -> List[Dict[str, Any]]:
        """返回某框架的检查清单。"""
        return CHECKLISTS.get(framework, [])

    def get_checklist_item(self, framework: str, item_id: str) -> Optional[Dict[str, Any]]:
        """返回单个检查项。"""
        for it in CHECKLISTS.get(framework, []):
            if it["id"] == item_id:
                return it
        return None

    # ------------------------------------------------------------------ #
    # 审计执行
    # ------------------------------------------------------------------ #
    def run_audit(self, framework: str = "mlps2",
                  target_data: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
        """
        执行一次审计。

        target_data 形如: {check_id: {"status": "pass/fail/na", "evidence": ...}}
        未提供的检查项默认根据 target_data.overall_compliance 推断，
        或标记为 not_applicable。
        """
        checklist = CHECKLISTS.get(framework)
        if not checklist:
            raise ValueError("未知合规框架: %s" % framework)
        target_data = target_data or {}
        overrides = target_data.get("results", {})
        results: List[Dict[str, Any]] = []
        for item in checklist:
            ov = overrides.get(item["id"], {})
            status = ov.get("status", "not_applicable")
            if status not in ("pass", "fail", "not_applicable"):
                status = "not_applicable"
            results.append({
                "check_id": item["id"],
                "name": item["name"],
                "category": item["category"],
                "risk_level": item["risk_level"],
                "standard_clause": item["standard_clause"],
                "status": status,
                "evidence": ov.get("evidence", ""),
                "notes": ov.get("notes", ""),
                "remediation": item["remediation"],
            })
        audit_id = "audit-%s" % uuid.uuid4().hex[:10]
        now = time.time()
        audit = {
            "audit_id": audit_id,
            "framework": framework,
            "framework_label": self.FRAMEWORK_LABELS.get(framework, framework),
            "created_at": now,
            "target": target_data.get("target", ""),
            "results": results,
        }
        audit["report"] = self.generate_report(results)
        self.audits[audit_id] = audit
        self._save()
        log.info("完成 %s 审计 %s，合规率 %.1f%%" % (
            framework, audit_id, audit["report"]["compliance_rate"] * 100))
        return audit

    # ------------------------------------------------------------------ #
    # 报告生成
    # ------------------------------------------------------------------ #
    @staticmethod
    def generate_report(results: List[Dict[str, Any]]) -> Dict[str, Any]:
        """根据审计结果生成合规报告。"""
        applicable = [r for r in results if r["status"] != "not_applicable"]
        passed = [r for r in applicable if r["status"] == "pass"]
        failed = [r for r in applicable if r["status"] == "fail"]
        total = len(applicable)
        rate = (len(passed) / total) if total else 0.0
        # 按类别聚合
        by_category: Dict[str, Dict[str, int]] = {}
        for r in results:
            cat = r["category"]
            by_category.setdefault(cat, {"pass": 0, "fail": 0, "na": 0})
            by_category[cat][r["status"] if r["status"] in ("pass", "fail") else "na"] += 1
        non_compliant = [{
            "check_id": r["check_id"], "name": r["name"],
            "category": r["category"], "risk_level": r["risk_level"],
            "standard_clause": r["standard_clause"], "remediation": r["remediation"],
        } for r in failed]
        # 风险摘要：按风险等级统计不合规数量
        risk_summary: Dict[str, int] = {}
        for r in failed:
            risk_summary[r["risk_level"]] = risk_summary.get(r["risk_level"], 0) + 1
        # 整改计划：按风险排序
        order = {"高": 0, "中": 1, "低": 2}
        non_compliant.sort(key=lambda x: order.get(x["risk_level"], 3))
        remediation_plan = [
            {"check_id": x["check_id"], "name": x["name"],
             "risk_level": x["risk_level"], "action": x["remediation"]}
            for x in non_compliant
        ]
        return {
            "total_items": len(results),
            "applicable_items": total,
            "passed": len(passed),
            "failed": len(failed),
            "not_applicable": len(results) - total,
            "compliance_rate": round(rate, 4),
            "by_category": by_category,
            "non_compliant_items": non_compliant,
            "risk_summary": risk_summary,
            "remediation_plan": remediation_plan,
        }

    # ------------------------------------------------------------------ #
    # 趋势对比
    # ------------------------------------------------------------------ #
    def compare_audits(self, audit_id1: str, audit_id2: str) -> Dict[str, Any]:
        """对比两次审计：合规率变化与改进/退步项。"""
        a = self.audits.get(audit_id1)
        b = self.audits.get(audit_id2)
        if not a or not b:
            raise KeyError("审计记录不存在")
        rate1 = a["report"]["compliance_rate"]
        rate2 = b["report"]["compliance_rate"]
        # 以 check_id 为键对比状态
        map1 = {r["check_id"]: r["status"] for r in a["results"]}
        map2 = {r["check_id"]: r["status"] for r in b["results"]}
        improved, regressed, unchanged = [], [], []
        for cid, st2 in map2.items():
            st1 = map1.get(cid, "not_applicable")
            if st1 == st2:
                unchanged.append(cid)
            elif st1 == "fail" and st2 == "pass":
                improved.append(cid)
            elif st1 == "pass" and st2 == "fail":
                regressed.append(cid)
        return {
            "audit_before": audit_id1,
            "audit_after": audit_id2,
            "rate_before": rate1,
            "rate_after": rate2,
            "rate_delta": round(rate2 - rate1, 4),
            "improved_count": len(improved),
            "regressed_count": len(regressed),
            "improved_items": improved,
            "regressed_items": regressed,
        }

    # ------------------------------------------------------------------ #
    # 持久化接口
    # ------------------------------------------------------------------ #
    def save_audit(self, audit_data: Dict[str, Any]) -> str:
        """保存一次外部审计结果。"""
        audit_id = audit_data.get("audit_id") or "audit-%s" % uuid.uuid4().hex[:10]
        self.audits[audit_id] = audit_data
        self._save()
        return audit_id

    def list_audits(self, framework: Optional[str] = None) -> List[Dict[str, Any]]:
        """列出审计记录（摘要）。"""
        out = []
        for a in self.audits.values():
            if framework and a.get("framework") != framework:
                continue
            out.append({
                "audit_id": a["audit_id"],
                "framework": a.get("framework"),
                "framework_label": a.get("framework_label"),
                "created_at": a.get("created_at"),
                "compliance_rate": a.get("report", {}).get("compliance_rate"),
            })
        out.sort(key=lambda x: x.get("created_at", 0), reverse=True)
        return out

    def get_audit(self, audit_id: str) -> Optional[Dict[str, Any]]:
        """获取完整审计记录。"""
        return self.audits.get(audit_id)


# 全局单例
_auditor: Optional[ComplianceAuditor] = None


def get_auditor() -> ComplianceAuditor:
    """获取全局合规审计器单例。"""
    global _auditor
    if _auditor is None:
        _auditor = ComplianceAuditor()
    return _auditor
