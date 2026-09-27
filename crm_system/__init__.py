# -*- coding: utf-8 -*-
"""crm_system — 客户管理CRM 核心包。

共享内存数据层（单例 DataStore），全部模块通过 `from crm_system import DB`
访问同一份内存数据。无外部数据库依赖，所有第三方库 try-import 回退。
"""

from __future__ import annotations

import threading
import time
import uuid
from typing import Any, Dict, List, Optional


def now_str() -> str:
    return time.strftime("%Y-%m-%d %H:%M:%S", time.localtime())


def new_id(prefix: str = "id") -> str:
    return f"{prefix}_{uuid.uuid4().hex[:10]}"


class DataStore:
    """进程内共享数据仓库（内存字典模拟，不落库）。"""

    def __init__(self) -> None:
        self.lock = threading.RLock()
        # 客户与联系人
        self.customers: Dict[str, Dict[str, Any]] = {}
        self.contacts: Dict[str, Dict[str, Any]] = {}
        # 销售
        self.opportunities: Dict[str, Dict[str, Any]] = {}
        self.opportunity_followups: Dict[str, List[Dict[str, Any]]] = {}
        self.quotes: Dict[str, Dict[str, Any]] = {}
        self.contracts: Dict[str, Dict[str, Any]] = {}
        self.orders: Dict[str, Dict[str, Any]] = {}
        # 沟通与活动
        self.communication: List[Dict[str, Any]] = []
        self.activities: Dict[str, Dict[str, Any]] = {}
        self.tasks: Dict[str, Dict[str, Any]] = {}
        self.reminders: List[Dict[str, Any]] = []
        self.email_log: List[Dict[str, Any]] = []
        self.phone_log: List[Dict[str, Any]] = []
        # 产品与定价
        self.products: Dict[str, Dict[str, Any]] = {}
        self.pricing_strategies: List[Dict[str, Any]] = []
        self.quote_templates: List[Dict[str, Any]] = []
        self.contract_templates: List[Dict[str, Any]] = []
        self.invoices: Dict[str, Dict[str, Any]] = {}
        self.revenue_records: List[Dict[str, Any]] = []
        # 客户服务
        self.tickets: Dict[str, Dict[str, Any]] = {}
        self.ticket_replies: Dict[str, List[Dict[str, Any]]] = {}
        self.kb_articles: Dict[str, Dict[str, Any]] = {}
        self.community_posts: Dict[str, Dict[str, Any]] = {}
        self.surveys: Dict[str, Dict[str, Any]] = {}
        self.customer_success: Dict[str, Dict[str, Any]] = {}
        # 系统
        self.users: List[Dict[str, Any]] = []
        self.audit_log: List[Dict[str, Any]] = []
        self._seeded = False

    # ------------------------------------------------------------------ #
    def log_audit(self, actor: str, action: str, detail: str = "") -> None:
        with self.lock:
            self.audit_log.append({
                "id": new_id("log"), "time": now_str(), "actor": actor,
                "action": action, "detail": detail,
            })
            if len(self.audit_log) > 500:
                self.audit_log = self.audit_log[-500:]


DB = DataStore()


# --------------------------------------------------------------------------- #
# 种子数据
# --------------------------------------------------------------------------- #
_INDUSTRIES = ["互联网", "金融", "制造", "教育", "医疗", "零售", "政府", "物流"]
_REGIONS = ["华东", "华南", "华北", "西南", "华中", "东北", "西北"]
_SIZES = ["1-50人", "51-200人", "201-500人", "501-1000人", "1000人以上"]
_LEVELS = ["A", "B", "C", "D"]
_SOURCES = ["官网咨询", "展会", "转介绍", "广告投放", "电话外呼", "渠道合作"]
_STAGES = ["线索", "潜在", "意向", "试用", "付费", "续费", "增购", "流失"]
_STAGE_PROB = {"线索": 0.1, "潜在": 0.25, "意向": 0.45, "试用": 0.65,
               "付费": 0.9, "续费": 0.95, "增购": 0.85, "流失": 0.0}


def seed_if_needed() -> None:
    """惰性种子数据，仅首次调用时填充。"""
    if DB._seeded:
        return
    with DB.lock:
        if DB._seeded:
            return
        _seed_customers()
        _seed_products()
        _seed_templates()
        _seed_users()
        DB._seeded = True


def _seed_customers() -> None:
    sample = [
        ("华云科技", "互联网", 2, "华东", "A", "官网咨询"),
        ("蓝鲸金融", "金融", 4, "华南", "A", "转介绍"),
        ("东方制造集团", "制造", 3, "华北", "B", "展会"),
        ("明德教育", "教育", 2, "西南", "B", "广告投放"),
        ("仁和医疗", "医疗", 3, "华中", "A", "渠道合作"),
        ("优选零售", "零售", 1, "华东", "C", "电话外呼"),
        ("远航物流", "物流", 2, "东北", "C", "官网咨询"),
        ("绿洲政府项目", "政府", 4, "西北", "B", "展会"),
    ]
    stages_cycle = ["付费", "意向", "试用", "潜在", "付费", "流失", "线索", "意向"]
    for i, (name, ind, size_idx, region, level, src) in enumerate(sample):
        cid = new_id("cus")
        stage = stages_cycle[i]
        created_days_ago = (i + 1) * 12
        created = time.strftime("%Y-%m-%d %H:%M:%S",
                                time.localtime(time.time() - created_days_ago * 86400))
        health = round(max(10, 95 - i * 9), 1)
        DB.customers[cid] = {
            "id": cid, "name": name, "industry": ind,
            "size": _SIZES[size_idx], "region": region, "level": level,
            "source": src, "stage": stage,
            "website": f"https://www.{name[:2].lower()}-example.com",
            "address": f"{region}区示范路{i + 1}号",
            "tags": [ind, level + "级客户"],
            "remark": "", "custom_fields": {},
            "health_score": health, "health_status": _health_label(health),
            "nps": 60 + (i % 4) * 8,
            "login_count_30d": max(0, 40 - i * 5),
            "ticket_count_30d": i % 3,
            "payment_on_time": True if i % 4 != 3 else False,
            "created_at": created, "updated_at": now_str(),
            "stage_entered_at": created,
            "lifecycle_history": [{"stage": "线索", "time": created}],
        }
        # 联系人
        for j in range(2):
            cont = {
                "id": new_id("con"), "customer_id": cid,
                "name": f"{['王','李','张','刘'][j]}经理{j}",
                "title": ["采购总监", "技术负责人"][j],
                "phone": f"138****{1000 + i}{j}", "email": f"contact{i}_{j}@example.com",
                "decision_role": ["决策人", "影响者"][j],
                "preference": ["电话", "邮件"][j],
                "birthday": f"1985-{(i % 12) + 1:02d}-15",
                "anniversary": "", "created_at": now_str(),
            }
            DB.contacts[cont["id"]] = cont
        # 商机
        if stage in ("意向", "试用", "付费", "增购"):
            opp = {
                "id": new_id("opp"), "name": f"{name}-年度续约采购",
                "customer_id": cid, "amount": 80000 + i * 25000,
                "stage": stage, "probability": _STAGE_PROB.get(stage, 0.3),
                "expected_close": time.strftime("%Y-%m-%d", time.localtime(time.time() + 30 * 86400)),
                "owner": ["张伟", "李娜", "王强"][i % 3],
                "competitor": ["竞品A", "竞品B", "暂无"][i % 3],
                "status": "open", "win_reason": "", "lose_reason": "",
                "created_at": now_str(), "updated_at": now_str(),
            }
            DB.opportunities[opp["id"]] = opp
            DB.opportunity_followups[opp["id"]] = [{
                "time": now_str(), "type": "电话沟通", "content": "初次需求确认",
                "next_action": "安排产品演示", "result": "有意向",
            }]
        # 工单
        if i % 3 == 0:
            tid = new_id("tk")
            DB.tickets[tid] = {
                "id": tid, "customer_id": cid, "title": "登录异常反馈",
                "category": "技术支持", "priority": "中", "status": "处理中",
                "assignee": "客服-小赵", "sla_due": now_str(),
                "created_at": now_str(), "resolved_at": None, "rating": None,
            }
            DB.ticket_replies[tid] = []
        # 邮件/电话记录
        DB.email_log.append({
            "id": new_id("em"), "customer_id": cid, "direction": "out",
            "subject": f"产品方案-{name}", "status": "opened",
            "time": now_str(),
        })
        DB.phone_log.append({
            "id": new_id("ph"), "customer_id": cid, "direction": "out",
            "duration_sec": 320, "result": "需求澄清", "time": now_str(),
        })
        # 沟通记录
        DB.communication.append({
            "id": new_id("cm"), "customer_id": cid, "type": "会议",
            "content": "季度业务回顾", "participants": ["客户方", "我方"],
            "result": "达成共识", "next_action": "发送正式报价",
            "time": now_str(),
        })
        # 提醒
        DB.reminders.append({
            "id": new_id("rm"), "type": "跟进提醒", "customer_id": cid,
            "title": f"{name}下次跟进", "due": now_str(), "channel": "站内",
            "done": False,
        })


def _health_label(score: float) -> str:
    if score >= 80:
        return "健康"
    if score >= 60:
        return "关注"
    if score >= 40:
        return "风险"
    return "流失预警"


def _seed_products() -> None:
    prods = [
        ("安全审计平台", "SaaS产品", 120000, "标准定价"),
        ("威胁情报订阅", "服务订阅", 80000, "年付优惠"),
        ("漏洞管理模块", "模块加购", 30000, "按模块定价"),
        ("渗透测试服务", "专业服务", 200000, "自定义定价"),
        ("云安全网关", "硬件产品", 150000, "标准定价"),
    ]
    for i, (n, cat, price, strat) in enumerate(prods):
        pid = new_id("prod")
        DB.products[pid] = {
            "id": pid, "name": n, "category": cat,
            "description": f"{n} — 企业级安全解决方案",
            "price": price, "currency": "CNY", "status": "在售",
            "pricing_strategy": strat, "specs": {"版本": "企业版"},
            "images": [], "videos": [], "created_at": now_str(),
        }
    DB.pricing_strategies = [
        {"name": "标准定价", "rule": "目录价直接成交", "discount_max": 0.1},
        {"name": "阶梯定价", "rule": "采购量越大单价越低", "discount_max": 0.25},
        {"name": "按量定价", "rule": "按用量月度结算", "discount_max": 0.15},
        {"name": "按用户定价", "rule": "按席位数阶梯", "discount_max": 0.2},
        {"name": "年付优惠", "rule": "年付享85折", "discount_max": 0.15},
        {"name": "自定义定价", "rule": "一单一议", "discount_max": 0.4},
    ]


def _seed_templates() -> None:
    DB.quote_templates = [
        {"id": new_id("qt"), "name": "标准报价模板", "category": "通用",
         "variables": ["客户名称", "产品清单", "折扣", "有效期"], "version": "v3",
         "is_default": True},
        {"id": new_id("qt"), "name": "年度框架报价", "category": "续约",
         "variables": ["客户名称", "续约产品", "折扣", "SLA条款"], "version": "v1",
         "is_default": False},
    ]
    DB.contract_templates = [
        {"id": new_id("ct"), "name": "标准采购合同", "category": "销售合同",
         "clauses": ["付款条款", "保密条款", "违约责任"], "variables": ["甲乙方", "金额", "周期"],
         "version": "v2", "esigned": True, "is_default": True},
        {"id": new_id("ct"), "name": "年度服务合同", "category": "服务合同",
         "clauses": ["SLA", "服务范围", "续约条款"], "variables": ["客户", "服务项", "金额"],
         "version": "v1", "esigned": True, "is_default": False},
    ]
    # 知识库
    kbs = [
        ("如何重置管理员密码", "账号", "企业版管理员可在控制台一键重置"),
        ("API接入指南", "开发", "通过OAuth2获取token后调用REST接口"),
        ("常见登录失败排查", "故障", "检查网络、账号状态、IP白名单"),
    ]
    for i, (t, cat, body) in enumerate(kbs):
        kid = new_id("kb")
        DB.kb_articles[kid] = {
            "id": kid, "title": t, "category": cat, "content": body,
            "views": 100 + i * 37, "rating": 4.2 + i * 0.2, "is_hot": i == 0,
            "is_official": True, "created_at": now_str(),
        }
    # 社区
    for i in range(3):
        pid = new_id("post")
        DB.community_posts[pid] = {
            "id": pid, "title": f"用户分享：实践案例{i + 1}", "section": "经验交流",
            "author": f"user_{i}", "content": "分享落地经验...",
            "replies": i * 4, "likes": i * 12, "is_top": i == 0,
            "is_essence": i == 1, "created_at": now_str(),
        }


def _seed_users() -> None:
    DB.users = [
        {"id": "u001", "name": "张伟", "role": "销售经理", "dept": "销售一部",
         "data_scope": "本人", "permissions": ["customer:read", "deal:write"]},
        {"id": "u002", "name": "李娜", "role": "销售总监", "dept": "销售部",
         "data_scope": "本部门", "permissions": ["customer:*", "deal:*"]},
        {"id": "u003", "name": "王强", "role": "客服主管", "dept": "客户成功部",
         "data_scope": "全公司", "permissions": ["ticket:*", "customer:read"]},
    ]


def get_db() -> DataStore:
    """供路由层显式获取数据仓库。"""
    seed_if_needed()
    return DB


__all__ = ["DB", "DataStore", "seed_if_needed", "get_db", "now_str", "new_id",
           "_INDUSTRIES", "_REGIONS", "_SIZES", "_LEVELS", "_SOURCES",
           "_STAGES", "_STAGE_PROB"]
