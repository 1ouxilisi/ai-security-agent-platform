#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
business_logic.py — 业务逻辑漏洞检测器（专业级深化）。

覆盖：
    - BOLA：越权访问对象 / ID 枚举 / 资源归属验证缺失
    - BFLA：越权执行功能 / 管理员功能未授权 / 角色权限混淆
    - 批量赋值：敏感字段可被客户端修改
    - 竞态条件：并发请求绕过限制 / 重复提交 / 优惠券复用 / 余额透支
    - 支付逻辑：金额篡改 / 数量篡改 / 优惠券复用 / 退款缺陷
    - 密码重置：令牌可预测 / 未过期 / 可枚举 / 链接泄露
    - 账户接管：会话固定 / CSRF 改密 / OAuth 关联 / 邮箱/手机验证绕过
    - 业务流程绕过：跳过验证步骤 / 直接访问后续步骤 / 状态机篡改

设计定位：仅输出检测项、风险评级与修复建议。
"""

from __future__ import annotations

import time
from typing import Any, Dict, List, Optional


class BusinessLogicDetector:
    """业务逻辑漏洞检测器。"""

    def __init__(self) -> None:
        self.findings: List[Dict[str, Any]] = []
        self.endpoints: List[Dict[str, Any]] = []

    # ------------------------------------------------------------------ #
    # 入口
    # ------------------------------------------------------------------ #
    def detect(
        self,
        endpoints: Optional[List[Dict[str, Any]]] = None,
        options: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        options = options or {}
        self.endpoints = endpoints or self._default_endpoints()
        self.findings = []

        self._detect_bola()
        self._detect_bfla()
        self._detect_mass_assignment()
        self._detect_race_condition()
        self._detect_payment_logic()
        self._detect_password_reset()
        self._detect_account_takeover()
        self._detect_workflow_bypass()

        return {
            "total_findings": len(self.findings),
            "by_severity": self._severity_breakdown(),
            "by_category": self._category_breakdown(),
            "findings": self.findings,
            "summary": self._summary(),
            "recommendations": self._build_recommendations(),
        }

    @staticmethod
    def _default_endpoints() -> List[Dict[str, Any]]:
        return [
            {"path": "/api/v1/orders/{id}", "method": "GET"},
            {"path": "/api/v1/orders/{id}", "method": "PUT"},
            {"path": "/api/v1/admin/users", "method": "GET"},
            {"path": "/api/v1/admin/users", "method": "POST"},
            {"path": "/api/v1/profile", "method": "PUT"},
            {"path": "/api/v1/payments", "method": "POST"},
            {"path": "/api/v1/coupon/redeem", "method": "POST"},
            {"path": "/api/v1/password/reset", "method": "POST"},
            {"path": "/api/v1/register", "method": "POST"},
            {"path": "/api/v1/upload", "method": "POST"},
        ]

    def _add(self, category: str, name: str, severity: str, description: str,
             evidence: str = "", recommendation: str = "", endpoint: str = "") -> None:
        self.findings.append({
            "category": category, "name": name, "severity": severity,
            "description": description, "evidence": evidence,
            "recommendation": recommendation, "endpoint": endpoint,
            "cwe": self._cwe_for(category),
            "detected_at": time.strftime("%Y-%m-%d %H:%M:%S"),
        })

    @staticmethod
    def _cwe_for(category: str) -> str:
        mapping = {
            "BOLA": "CWE-639", "BFLA": "CWE-862",
            "批量赋值": "CWE-915", "竞态条件": "CWE-362",
            "支付逻辑": "CWE-840", "密码重置": "CWE-640",
            "账户接管": "CWE-287", "业务流程绕过": "CWE-841",
        }
        return mapping.get(category, "CWE-840")

    # ------------------------------------------------------------------ #
    # BOLA
    # ------------------------------------------------------------------ #
    def _detect_bola(self) -> None:
        for ep in self.endpoints:
            if "{" in ep["path"]:
                self._add("BOLA", "越权访问他人资源 (BOLA/IDOR)", "critical",
                          f"端点 {ep['method']} {ep['path']} 使用路径 ID，需验证资源归属",
                          "应使用用户 A 令牌访问用户 B 的资源 ID",
                          "在数据访问层强制 owner_id / tenant_id 过滤；不可仅靠 URL 隐藏",
                          endpoint=f"{ep['method']} {ep['path']}")
        self._add("BOLA", "ID 枚举 / 可预测资源 ID", "high",
                  "自增整数 ID 易被枚举，遍历他人订单/消息/文档",
                  "检查项",
                  "使用 UUID/不可预测 ID；服务端强制归属校验")
        self._add("BOLA", "批量对象访问未校验", "high",
                  "POST /batch-get 接受 ID 列表时未逐个校验归属",
                  "检查项",
                  "批量接口同样必须逐个对象做归属校验")

    # ------------------------------------------------------------------ #
    # BFLA
    # ------------------------------------------------------------------ #
    def _detect_bfla(self) -> None:
        admin_eps = [e for e in self.endpoints if "admin" in e["path"].lower()]
        for ep in admin_eps:
            self._add("BFLA", "管理员功能未授权访问", "critical",
                      f"端点 {ep['method']} {ep['path']} 含 admin 路径，需验证角色",
                      "应使用普通用户令牌访问",
                      "每个管理端点单独做 RBAC 校验；默认拒绝",
                      endpoint=f"{ep['method']} {ep['path']}")
        self._add("BFLA", "角色权限混淆", "high",
                  "普通用户与管理员使用同一套端点，仅靠前端隐藏按钮",
                  "检查项",
                  "服务端按角色拦截；管理端点独立路径前缀")
        self._add("BFLA", "功能级授权缺失", "high",
                  "删除/导出/配置等高危操作未单独鉴权",
                  "检查项",
                  "高危操作要求二次认证 + RBAC 校验")

    # ------------------------------------------------------------------ #
    # 批量赋值
    # ------------------------------------------------------------------ #
    def _detect_mass_assignment(self) -> None:
        sensitive_fields = ["role", "is_admin", "is_staff", "balance", "credit",
                           "status", "verified", "email_verified", "tenant_id", "permissions"]
        self._add("批量赋值", "敏感字段可被客户端修改", "high",
                  f"更新接口若直接绑定整个请求体，攻击者可提交 {sensitive_fields[:5]} 等敏感字段",
                  f"敏感字段清单: {', '.join(sensitive_fields)}",
                  "使用 DTO/白名单字段；服务端忽略客户端传入的角色/权限/余额字段")
        self._add("批量赋值", "角色字段提权", "critical",
                  "注册/更新接口接受 role=admin / is_admin=true",
                  "POST /register {\"role\":\"admin\"}",
                  "禁止客户端指定角色；角色仅由管理员后台设置")
        self._add("批量赋值", "余额字段篡改", "critical",
                  "profile 更新接口接受 balance=999999",
                  "{\"balance\": 999999}",
                  "余额等财务字段只读；服务端从账务系统计算")

    # ------------------------------------------------------------------ #
    # 竞态条件
    # ------------------------------------------------------------------ #
    def _detect_race_condition(self) -> None:
        self._add("竞态条件", "并发请求绕过限制", "high",
                  "同时发起多个请求可绕过单次限制（优惠券/提现/投票）",
                  "应并发 N 个相同请求观察是否全部成功",
                  "数据库唯一约束 + 悲观/乐观锁；原子操作")
        self._add("竞态条件", "优惠券复用", "high",
                  "并发提交同一优惠券可多次抵扣",
                  "POST /coupon/redeem 并发 10 次",
                  "优惠券使用状态用事务+行锁；唯一约束 (user_id, coupon_id)")
        self._add("竞态条件", "余额透支", "critical",
                  "并发转账/提现可在余额检查与扣减之间透支",
                  "应同时发起多笔提现观察余额是否变负",
                  "扣减使用原子 UPDATE ... WHERE balance >= amount；事务")
        self._add("竞态条件", "重复提交 / 非幂等", "medium",
                  "支付/下单接口缺少幂等键，刷新/重试导致重复创建",
                  "检查项",
                  "客户端生成幂等键 Idempotency-Key；服务端去重")

    # ------------------------------------------------------------------ #
    # 支付逻辑
    # ------------------------------------------------------------------ #
    def _detect_payment_logic(self) -> None:
        self._add("支付逻辑", "金额篡改", "critical",
                  "客户端提交 amount，改为 0.01 / 负数 / 超大数",
                  "{\"amount\": 0.01}",
                  "金额服务端从订单系统查询，不信任客户端")
        self._add("支付逻辑", "数量篡改", "high",
                  "数量改为负数可导致反向入账",
                  "{\"quantity\": -1}",
                  "数量必须为正整数；服务端校验范围")
        self._add("支付逻辑", "支付状态篡改", "critical",
                  "客户端直接调用支付成功回调 / 跳过支付步骤",
                  "POST /payment/callback {\"status\":\"success\"}",
                  "支付结果以支付平台回调为准；回调签名校验")
        self._add("支付逻辑", "退款逻辑缺陷", "high",
                  "退款金额/次数未校验，可超额退款/重复退款",
                  "检查项",
                  "退款金额累计不超过原支付；幂等；审批流")

    # ------------------------------------------------------------------ #
    # 密码重置
    # ------------------------------------------------------------------ #
    def _detect_password_reset(self) -> None:
        self._add("密码重置", "重置令牌可预测", "high",
                  "令牌基于时间戳/用户ID/自增，可预测",
                  "检查项",
                  "使用 CSPRNG 生成 >=16 字节令牌")
        self._add("密码重置", "令牌未过期", "high",
                  "重置令牌长期有效，泄露后可永久改密",
                  "检查项",
                  "令牌 15-30 分钟过期；一次性使用")
        self._add("密码重置", "令牌可枚举", "medium",
                  "令牌过短（6 位数字）可被暴力枚举",
                  "检查项",
                  "令牌足够长；失败次数锁定")
        self._add("密码重置", "重置链接泄露", "medium",
                  "重置链接通过 URL/Referer/日志泄露",
                  "检查项",
                  "令牌一次性；不记录日志；Referrer-Policy")
        self._add("密码重置", "用户名枚举", "medium",
                  "响应差异（用户存在/不存在）可枚举账号",
                  "检查项",
                  "统一响应：若存在则发送邮件；不泄露账号是否存在")

    # ------------------------------------------------------------------ #
    # 账户接管
    # ------------------------------------------------------------------ #
    def _detect_account_takeover(self) -> None:
        self._add("账户接管", "CSRF 改密", "critical",
                  "修改密码接口缺少 CSRF Token，且不需要原密码",
                  "检查项",
                  "改密必须验证原密码 + CSRF Token")
        self._add("账户接管", "会话固定", "high",
                  "登录后未重置 Session ID",
                  "检查项",
                  "登录成功后重新生成 Session")
        self._add("账户接管", "OAuth 账户关联劫持", "high",
                  "绑定第三方账号时未验证当前密码/原账号所有权",
                  "检查项",
                  "关联前验证当前登录凭据；防 CSRF state")
        self._add("账户接管", "邮箱验证绕过", "high",
                  "验证码/链接可绕过（返回 true / 空验证码）",
                  "POST /verify {\"code\": \"\"}",
                  "验证码服务端校验；失败锁定")
        self._add("账户接管", "手机号验证绕过", "high",
                  "短信验证码爆破 / 万能验证码",
                  "检查项",
                  "6 位验证码 5 次失败锁定；图形验证码；频率限制")

    # ------------------------------------------------------------------ #
    # 业务流程绕过
    # ------------------------------------------------------------------ #
    def _detect_workflow_bypass(self) -> None:
        self._add("业务流程绕过", "跳过验证步骤", "high",
                  "用户可直接访问后续步骤（如直接跳支付成功页）",
                  "GET /step3 未走 step1/step2",
                  "服务端状态机校验当前步骤；每步检查前置状态")
        self._add("业务流程绕过", "状态机篡改", "critical",
                  "订单 status 字段由客户端控制，可直接改为 paid/shipped",
                  "{\"status\":\"paid\"}",
                  "状态字段服务端管理；仅通过合法事件流转")
        self._add("业务流程绕过", "直接访问后续步骤 API", "high",
                  "前端步骤未完成但后端 API 可直接调用",
                  "检查项",
                  "每个步骤 API 校验前置步骤完成状态")

    # ------------------------------------------------------------------ #
    # 报告辅助
    # ------------------------------------------------------------------ #
    def _severity_breakdown(self) -> Dict[str, int]:
        out: Dict[str, int] = {}
        for f in self.findings:
            s = f.get("severity", "info")
            out[s] = out.get(s, 0) + 1
        return out

    def _category_breakdown(self) -> Dict[str, int]:
        out: Dict[str, int] = {}
        for f in self.findings:
            c = f.get("category", "unknown")
            out[c] = out.get(c, 0) + 1
        return out

    def _summary(self) -> Dict[str, Any]:
        sb = self._severity_breakdown()
        score = sum({"critical": 4, "high": 3, "medium": 2, "low": 1}.get(s, 0) * c
                     for s, c in sb.items())
        risk = "严重" if score >= 15 else "高" if score >= 8 else "中" if score >= 3 else "低"
        return {"risk_level": risk, "risk_score": score}

    def _build_recommendations(self) -> List[Dict[str, str]]:
        seen: Dict[str, str] = {}
        for f in self.findings:
            r = f.get("recommendation", "")
            if r and r not in seen:
                seen[r] = f["category"]
        return [{"category": v, "action": k} for k, v in seen.items()]
