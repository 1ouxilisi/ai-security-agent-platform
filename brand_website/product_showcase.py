# -*- coding: utf-8 -*-
"""
brand_website/product_showcase.py — 产品展示与功能介绍模块。

覆盖：产品介绍、功能展示、版本对比、技术架构、客户案例、合作伙伴。
"""

from __future__ import annotations

import time
import uuid
from typing import Any, Dict, List, Optional


def _now() -> str:
    return time.strftime("%Y-%m-%d %H:%M:%S")


def _pid(prefix: str) -> str:
    return f"{prefix}_{uuid.uuid4().hex[:10]}"


PRODUCTS: Dict[str, Dict[str, Any]] = {}
FEATURES: Dict[str, Dict[str, Any]] = {}
VERSIONS: Dict[str, Dict[str, Any]] = {}
ARCHITECTURE: Dict[str, Any] = {}
CASES: Dict[str, Dict[str, Any]] = {}
PARTNERS: Dict[str, Dict[str, Any]] = {}


def _seed() -> None:
    if not PRODUCTS:
        PRODUCTS["core_platform"] = {
            "id": "core_platform", "name": "AI Hacking Agent 主平台",
            "positioning": "AI 驱动的一体化安全攻防操作系统",
            "core_value": "33万行代码、2880+ API 端点、77 个控制台页面",
            "target_users": ["安全团队", "渗透测试工程师", "红蓝军", "合规团队"],
            "scenarios": ["攻防演练", "渗透测试", "合规检查", "应急响应"],
            "screenshots": ["/static/product/main.png"], "video": "/static/product/demo.mp4",
            "demo_url": "/demo",
        }
    if not FEATURES:
        for fid, name, cat in [
            ("f_pentest", "AI 渗透测试", "red_team"),
            ("f_dlp", "数据防泄漏 DLP", "data_security"),
            ("f_compliance", "合规治理", "governance"),
            ("f_soc", "智能 SOC", "soc"),
            ("f_ctf", "CTF 靶场", "training"),
        ]:
            FEATURES[fid] = {
                "id": fid, "name": name, "category": cat,
                "description": f"{name} — 由 AI 编排引擎驱动，覆盖完整工作流。",
                "screenshot": f"/static/features/{fid}.png",
                "video": f"/static/features/{fid}.mp4",
                "roadmap": "Q3 已发布 / Q4 增强",
            }
    if not VERSIONS:
        VERSIONS["free"] = {"id": "free", "name": "社区版", "price_monthly": 0,
                            "users": 3, "support": "社区", "features": ["基础扫描"]}
        VERSIONS["pro"] = {"id": "pro", "name": "专业版", "price_monthly": 2999,
                           "users": 50, "support": "工单", "features": list(FEATURES.keys())}
        VERSIONS["ent"] = {"id": "ent", "name": "企业版", "price_monthly": 19999,
                           "users": 9999, "support": "专属客户经理",
                           "features": list(FEATURES.keys()) + ["定制开发"]}
    if not ARCHITECTURE:
        ARCHITECTURE.update({
            "layers": ["接入层 (API Gateway)", "AI 编排层", "能力层 (2880+ 端点)",
                       "数据层", "可视化层 (77 控制台)"],
            "tech_stack": ["Python 3.14", "FastAPI", "Vue3", "PostgreSQL",
                           "Redis", "Docker", "K8s"],
            "data_flow": ["请求 -> 网关鉴权 -> 路由分发 -> 模块执行 -> 结果清洗 -> 统一响应"],
            "deployment": ["单机 Docker Compose", "K8s Helm Chart", "私有化交付"],
            "security": ["RBAC", "审计日志", "加密存储", "网络隔离"],
            "api": {"style": "REST", "prefix": "/api/v1", "response": "{success,data,error}"},
        })
    if not CASES:
        CASES["c_bank"] = {
            "id": "c_bank", "customer": "某股份制银行", "industry": "金融",
            "logo": "/static/logos/bank.png", "quote": "把渗透周期从 2 周压缩到 2 天。",
            "metrics": {"漏洞发现数": 412, "效率提升": "85%", "MTTR": "4小时"},
        }
        CASES["c_gov"] = {
            "id": "c_gov", "customer": "某省级政务云", "industry": "政务",
            "logo": "/static/logos/gov.png", "quote": "合规审计一次通过。",
            "metrics": ["合规项 100%", "审计耗时 -60%"],
        }
    if not PARTNERS:
        PARTNERS["p_integrator"] = {
            "id": "p_integrator", "name": "安全集成商联盟", "type": "集成商",
            "mode": "项目分成", "logo": "/static/partners/integ.png",
        }
        PARTNERS["p_tech"] = {
            "id": "p_tech", "name": "宇树科技", "type": "技术合作",
            "mode": "能力对接", "logo": "/static/partners/uq.png",
        }


_seed()


class ProductShowcase:
    # ---- 产品介绍 ----
    def list_products(self) -> List[Dict[str, Any]]:
        return list(PRODUCTS.values())

    def get_product(self, pid: str) -> Optional[Dict[str, Any]]:
        return PRODUCTS.get(pid)

    def create_product(self, name: str, **fields: Any) -> Dict[str, Any]:
        pid = _pid("prod")
        PRODUCTS[pid] = {"id": pid, "name": name, "positioning": "",
                         "core_value": "", "target_users": [], "scenarios": [],
                         "screenshots": [], "video": "", "demo_url": "", **fields}
        return PRODUCTS[pid]

    # ---- 功能展示 ----
    def list_features(self, category: Optional[str] = None) -> List[Dict[str, Any]]:
        items = list(FEATURES.values())
        if category:
            items = [f for f in items if f["category"] == category]
        return items

    def get_feature(self, fid: str) -> Optional[Dict[str, Any]]:
        return FEATURES.get(fid)

    def compare_features(self, ids: List[str]) -> Dict[str, Any]:
        rows = [FEATURES[i] for i in ids if i in FEATURES]
        cats = sorted({r["category"] for r in rows})
        return {"features": rows, "categories": cats,
                "total": len(rows)}

    # ---- 版本对比 ----
    def list_versions(self) -> List[Dict[str, Any]]:
        return list(VERSIONS.values())

    def compare_versions(self) -> Dict[str, Any]:
        vers = list(VERSIONS.values())
        all_features: List[str] = sorted({feat for v in vers for feat in v["features"]})
        table = []
        for feat in all_features:
            row = {"feature": feat}
            for v in vers:
                row[v["id"]] = feat in v["features"]
            table.append(row)
        return {
            "versions": [{"id": v["id"], "name": v["name"],
                          "price_monthly": v["price_monthly"],
                          "users": v["users"], "support": v["support"]}
                         for v in vers],
            "feature_matrix": table,
        }

    def upgrade_advice(self, current: str, target: str) -> Dict[str, Any]:
        cur = VERSIONS.get(current, {})
        tgt = VERSIONS.get(target, {})
        added = [f for f in tgt.get("features", []) if f not in cur.get("features", [])]
        return {
            "current": current, "target": target,
            "price_delta": tgt.get("price_monthly", 0) - cur.get("price_monthly", 0),
            "new_features": added,
            "advice": f"建议从 {current} 升级到 {target}，新增 {len(added)} 项能力。",
        }

    # ---- 技术架构 ----
    def architecture(self) -> Dict[str, Any]:
        return dict(ARCHITECTURE)

    # ---- 客户案例 ----
    def list_cases(self, industry: Optional[str] = None) -> List[Dict[str, Any]]:
        items = list(CASES.values())
        if industry:
            items = [c for c in items if c.get("industry") == industry]
        return items

    def get_case(self, cid: str) -> Optional[Dict[str, Any]]:
        return CASES.get(cid)

    def create_case(self, customer: str, industry: str,
                    quote: str = "", metrics: Any = None) -> Dict[str, Any]:
        cid = _pid("case")
        CASES[cid] = {"id": cid, "customer": customer, "industry": industry,
                      "logo": f"/static/logos/{cid}.png", "quote": quote,
                      "metrics": metrics or {}, "created_at": _now()}
        return CASES[cid]

    # ---- 合作伙伴 ----
    def list_partners(self, ptype: Optional[str] = None) -> List[Dict[str, Any]]:
        items = list(PARTNERS.values())
        if ptype:
            items = [p for p in items if p.get("type") == ptype]
        return items

    def apply_partner(self, name: str, ptype: str, mode: str) -> Dict[str, Any]:
        pid = _pid("partner")
        PARTNERS[pid] = {"id": pid, "name": name, "type": ptype, "mode": mode,
                         "logo": f"/static/partners/{pid}.png", "status": "待审核",
                         "applied_at": _now()}
        return PARTNERS[pid]
