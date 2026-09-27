# -*- coding: utf-8 -*-
"""email_authentication.py — 邮件认证与传输层安全检测。

覆盖：SPF / DKIM / DMARC / ARC / MTA-STS / TLS-RPT / SMTP 配置检查 / 综合评分。
本模块做记录解析与策略判定的本地模拟；真实 DNS 查询可由上层接入。
"""

from __future__ import annotations

import re
import time
from typing import Any, Dict, List, Optional


class SPFValidator:
    """SPF 记录解析与检查模拟。"""

    MECHANISMS = ("ip4", "ip6", "a", "mx", "ptr", "exists", "include", "all")

    @staticmethod
    def parse(record: str) -> Dict[str, Any]:
        rec = (record or "").strip()
        if not rec:
            return {"valid": False, "error": "空记录", "mechanisms": [],
                    "qualifier": None, "has_all": False, "raw": rec}
        if not rec.lower().startswith("v=spf1"):
            return {"valid": False, "error": "缺少 v=spf1 前缀", "raw": rec,
                    "mechanisms": [], "has_all": False}
        tokens = rec.split()
        mechs: List[Dict[str, str]] = []
        qualifier = None
        for t in tokens[1:]:
            q = "+"
            if t and t[0] in "+-?~":
                q = t[0]; t2 = t[1:]
            else:
                t2 = t
            kind = t2.split(":", 1)[0] if ":" in t2 else t2
            mechs.append({"raw": t, "kind": kind, "qualifier": q})
            if kind == "all":
                qualifier = q
        return {"valid": True, "raw": rec, "mechanisms": mechs,
                "has_all": qualifier is not None, "qualifier": qualifier,
                "term_count": len(mechs)}

    def check(self, record: str, sender_ip: str, mail_from_domain: str) -> Dict[str, Any]:
        parsed = self.parse(record)
        result = {
            "spf_record": record, "parsed": parsed, "sender_ip": sender_ip,
            "mail_from": mail_from_domain, "result": "none",
            "result_text": "neutral (无匹配记录)",
            "fail_reasons": [],
        }
        if not parsed.get("valid"):
            result["result"] = "permerror"
            result["fail_reasons"].append(parsed.get("error", "记录无效"))
            return result
        # 模拟 IP 匹配：deterministic
        ip_in_include = (hash(sender_ip + mail_from_domain) % 100) < 80
        qual = parsed.get("qualifier") or "~"
        if ip_in_include:
            result["result"] = "pass"
            result["result_text"] = "pass (IP 匹配 allow 项)"
        else:
            mapping = {"+": "neutral", "-": "fail", "~": "softfail",
                       "?": "neutral"}
            result["result"] = mapping.get(qual, "softfail")
            result["result_text"] = f"end-user 机制 '{qual}all' => {result['result']}"
        if result["result"] in ("fail", "softfail"):
            result["fail_reasons"].append("发件 IP 不在 SPF 授权列表")
        return result


class DKIMValidator:
    """DKIM 签名验证模拟。"""

    @staticmethod
    def verify(signature_header: str, body_hash: str = "",
               selector: str = "default") -> Dict[str, Any]:
        sig = signature_header or ""
        out: Dict[str, Any] = {
            "selector": selector, "result": "none",
            "result_text": "无签名", "fail_reasons": [],
            "key_length_bits": 2048, "algorithm": "rsa-sha256",
            "signature_age_days": 0,
        }
        if not sig:
            return out
        # 解析常见标签
        tags: Dict[str, str] = {}
        for part in sig.replace("\n", " ").split(";"):
            if "=" in part:
                k, v = part.strip().split("=", 1)
                tags[k.strip()] = v.strip()
        out["selector"] = tags.get("s", selector)
        out["algorithm"] = tags.get("a", "rsa-sha256")
        d = tags.get("d", "")
        out["signing_domain"] = d
        b = tags.get("b", "")
        bh = tags.get("bh", "")
        if not b or len(b) < 20:
            out["result"] = "permfail"; out["fail_reasons"].append("签名 b= 缺失或过短")
            return out
        # 模拟密钥长度
        out["key_length_bits"] = 2048 if len(b) > 100 else 1024
        if out["key_length_bits"] < 2048:
            out["fail_reasons"].append("密钥长度不足 2048 位")
        # 模拟过期
        t_exp = tags.get("x", "")
        if t_exp and t_exp.isdigit():
            age = int(time.time()) - int(t_exp)
            out["signature_age_days"] = max(0, age // 86400)
            if age > 0:
                out["result"] = "permfail"
                out["fail_reasons"].append("签名已过期 (x=)")
                return out
        # 模拟 hash 匹配
        if body_hash and bh and body_hash.lower() != bh.lower():
            out["result"] = "permfail"
            out["fail_reasons"].append("正文哈希不匹配 (bh≠body hash)")
            return out
        out["result"] = "pass"
        out["result_text"] = f"pass (d={d} s={out['selector']})"
        return out


class DMARCValidator:
    """DMARC 策略解析与对齐检查。"""

    POLICY_LEVELS = {"none": "无", "quarantine": "隔离", "reject": "拒绝"}

    @staticmethod
    def parse(record: str) -> Dict[str, Any]:
        rec = (record or "").strip()
        if not rec.lower().startswith("v=dmarc1"):
            return {"valid": False, "error": "缺少 v=DMARC1", "raw": rec}
        tags: Dict[str, str] = {}
        for part in rec.split(";"):
            if "=" in part:
                k, v = part.strip().split("=", 1)
                tags[k.strip().lower()] = v.strip()
        return {
            "valid": True, "raw": rec,
            "policy": tags.get("p", "none"),
            "subdomain_policy": tags.get("sp", tags.get("p", "none")),
            "pct": int(tags.get("pct", "100")),
            "rua": tags.get("rua", ""), "ruf": tags.get("ruf", ""),
            "adkim": tags.get("adkim", "r"), "aspf": tags.get("aspf", "r"),
        }

    def check(self, record: str, header_from: str, envelope_from: str,
              spf_result: str, dkim_result: str) -> Dict[str, Any]:
        parsed = self.parse(record)
        out: Dict[str, Any] = {
            "dmarc_record": record, "parsed": parsed,
            "header_from": header_from, "envelope_from": envelope_from,
            "dkim_aligned": False, "spf_aligned": False,
            "result": "none", "disposition": "none", "fail_reasons": [],
        }
        if not parsed.get("valid"):
            out["result"] = "error"
            out["fail_reasons"].append(parsed.get("error", "记录无效"))
            return out
        hdom = header_from.split("@")[-1] if "@" in header_from else header_from
        edom = envelope_from.split("@")[-1] if "@" in envelope_from else envelope_from
        out["spf_aligned"] = (spf_result == "pass" and
                              (hdom == edom or hdom.endswith("." + edom) or
                               edom.endswith("." + hdom)))
        out["dkim_aligned"] = dkim_result == "pass"
        if out["spf_aligned"] or out["dkim_aligned"]:
            out["result"] = "pass"
            out["disposition"] = parsed["policy"]
        else:
            out["result"] = "fail"
            out["disposition"] = parsed["policy"]
            out["fail_reasons"].append("SPF/DKIM 均未对齐")
        out["policy_text"] = self.POLICY_LEVELS.get(parsed["policy"], parsed["policy"])
        return out


class ARCValidator:
    """ARC 认证链验证（简化模型）。"""

    @staticmethod
    def verify(arc_seal: str, arc_ms: str, arc_ar: str) -> Dict[str, Any]:
        seals = [s for s in (arc_seal or "").split(";") if s.strip()]
        msigs = [m for m in (arc_ms or "").split(";") if m.strip()]
        out = {
            "arc_enabled": bool(arc_seal or arc_ms or arc_ar),
            "seal_count": len(seals), "message_signature_count": len(msigs),
            "chain_valid": False, "fail_reasons": [],
            "result": "none",
        }
        if not out["arc_enabled"]:
            out["result"] = "none"
            out["fail_reasons"].append("无 ARC 头")
            return out
        # 链长度一致性
        if len(seals) != len(msigs):
            out["fail_reasons"].append(
                f"Seal({len(seals)}) 与 Message-Signature({len(msigs)}) 数量不一致")
            out["result"] = "fail"
            return out
        out["chain_valid"] = True
        out["result"] = "pass"
        out["result_text"] = f"pass ({len(seals)} 跳)"
        return out


class MTASTSDetector:
    """MTA-STS / TLS-RPT 策略检测。"""

    @staticmethod
    def check(domain: str, sts_policy: str = "", tls_rpt: str = "") -> Dict[str, Any]:
        policy = (sts_policy or "").strip()
        out = {
            "domain": domain, "sts_present": bool(policy),
            "tls_rpt_present": bool(tls_rpt), "mode": "none",
            "max_age_seconds": 0, "mx": [], "fail_reasons": [],
            "result": "none",
        }
        if not policy:
            out["fail_reasons"].append("未配置 MTA-STS 策略文件")
            return out
        for line in policy.splitlines():
            if ":" in line:
                k, v = line.split(":", 1)
                k, v = k.strip(), v.strip()
                if k == "mode":
                    out["mode"] = v
                elif k == "max_age":
                    try: out["max_age_seconds"] = int(v)
                    except ValueError: pass
                elif k == "mx":
                    out["mx"].append(v)
        if out["mode"] not in ("enforce", "testing", "none"):
            out["fail_reasons"].append("mode 字段非法")
        if out["max_age_seconds"] > 0 and out["mode"] == "enforce":
            out["result"] = "pass"
        elif out["mode"] == "testing":
            out["result"] = "policies_defined_testing"
        else:
            out["result"] = "partial"
        return out


class SMTPSecurityChecker:
    """SMTP 服务器安全配置检查（模拟）。"""

    @staticmethod
    def check(host: str) -> Dict[str, Any]:
        h = (host or "").lower()
        # 基于域名 hash 给出确定性结果
        hv = abs(hash(h)) % 1000
        open_relay = hv % 7 == 0
        auth_required = hv % 5 != 0
        starttls = hv % 4 != 0
        vrfy_enabled = hv % 3 == 0
        expn_enabled = hv % 3 == 1
        version_leak = hv % 2 == 0
        issues: List[Dict[str, str]] = []
        if open_relay:
            issues.append({"item": "开放中继", "severity": "critical",
                           "advice": "立即关闭开放中继，仅授权 relay 客户端"})
        if not auth_required:
            issues.append({"item": "未认证即可发送", "severity": "high",
                           "advice": "强制 SMTP AUTH"})
        if not starttls:
            issues.append({"item": "未启用 STARTTLS", "severity": "high",
                           "advice": "强制 TLS 加密通道"})
        if vrfy_enabled:
            issues.append({"item": "VRFY 命令启用", "severity": "medium",
                           "advice": "禁用 VRFY 防止用户枚举"})
        if expn_enabled:
            issues.append({"item": "EXPN 命令启用", "severity": "medium",
                           "advice": "禁用 EXPN 防止邮件列表枚举"})
        if version_leak:
            issues.append({"item": "服务器版本号泄露", "severity": "low",
                           "advice": "隐藏 banner 中的具体版本号"})
        score = 100 - 25 * int(open_relay) - 20 * int(not auth_required) \
                - 15 * int(not starttls) - 8 * int(vrfy_enabled) \
                - 8 * int(expn_enabled) - 5 * int(version_leak)
        return {
            "host": host, "open_relay": open_relay, "auth_required": auth_required,
            "starttls": starttls, "vrfy_enabled": vrfy_enabled,
            "expn_enabled": expn_enabled, "version_leak": version_leak,
            "issues": issues, "hardening_score": max(0, score),
        }


class EmailAuthenticationSuite:
    """综合认证套件，输出统一评分。"""

    def __init__(self) -> None:
        self.spf = SPFValidator()
        self.dkim = DKIMValidator()
        self.dmarc = DMARCValidator()
        self.arc = ARCValidator()
        self.sts = MTASTSDetector()
        self.smtp = SMTPSecurityChecker()

    def run(self, signals: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
        signals = signals or {}
        host = signals.get("host", "mail.example.com")
        spf_r = self.spf.check(
            signals.get("spf_record", "v=spf1 include:_spf.example.com -all"),
            signals.get("sender_ip", "203.0.113.10"),
            signals.get("mail_from", "user@example.com").split("@")[-1],
        )
        dkim_r = self.dkim.verify(
            signals.get("dkim_signature",
                        "v=1; a=rsa-sha256; s=default; d=example.com; b=" +
                        "A" * 120 + "; bh=" + "ab" * 32 + ";"),
            signals.get("body_hash", ""),
            signals.get("selector", "default"),
        )
        dmarc_r = self.dmarc.check(
            signals.get("dmarc_record", "v=DMARC1; p=quarantine; rua=mailto:d@example.com;"),
            signals.get("header_from", "user@example.com"),
            signals.get("envelope_from", "user@example.com"),
            spf_r["result"], dkim_r["result"],
        )
        arc_r = self.arc.verify(signals.get("arc_seal", ""),
                                signals.get("arc_ms", ""),
                                signals.get("arc_ar", ""))
        sts_r = self.sts.check(host,
                               signals.get("sts_policy",
                                           "version: STSv1\nmode: enforce\nmax_age: 8640000\nmx: mail.example.com"),
                               signals.get("tls_rpt", ""))
        smtp_r = self.smtp.check(host)

        # 综合评分
        score = 0
        score += 25 if spf_r["result"] == "pass" else 0
        score += 25 if dkim_r["result"] == "pass" else 0
        score += 25 if dmarc_r["result"] == "pass" and dmarc_r["disposition"] in ("reject", "quarantine") else (15 if dmarc_r["result"] == "pass" else 0)
        score += 10 if arc_r["chain_valid"] else (5 if arc_r["arc_enabled"] else 0)
        score += 15 if sts_r["result"] == "pass" else (8 if sts_r["sts_present"] else 0)
        # SMTP 分数折算
        score += round(smtp_r["hardening_score"] * 0.1)

        score = min(100, score)
        if score >= 85:
            grade, grade_name = "A", "优秀"
        elif score >= 70:
            grade, grade_name = "B", "良好"
        elif score >= 50:
            grade, grade_name = "C", "一般"
        else:
            grade, grade_name = "D", "薄弱"

        return {
            "checked_at": time.strftime("%Y-%m-%d %H:%M:%S"),
            "host": host,
            "spf": spf_r, "dkim": dkim_r, "dmarc": dmarc_r,
            "arc": arc_r, "mta_sts": sts_r, "smtp": smtp_r,
            "auth_score": score, "grade": grade, "grade_name": grade_name,
        }
