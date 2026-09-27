#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
共享知识库 - 四大领域共用的漏洞库、攻击模式库、修复建议库

包含：CWE映射、OWASP映射、各领域Top漏洞、真实案例、修复建议模板。
所有领域模块通过 KnowledgeBase 查询标准漏洞信息，确保报告术语统一。
"""
import json
import os
from typing import Any, Dict, List, Optional

from unified.models import DomainType, Severity


class KnowledgeBase:
    """共享知识库"""

    def __init__(self, data_dir: str = "data/unified"):
        self.data_dir = data_dir
        os.makedirs(data_dir, exist_ok=True)
        self._cache: Dict[str, Any] = {}
        self._init_builtin()

    def _init_builtin(self):
        """初始化内置知识库数据"""
        # CWE通用缺陷映射
        self._cwe_db = {
            "CWE-79": {"name": "跨站脚本(XSS)", "description": "在网页中注入恶意脚本", "severity": "high"},
            "CWE-89": {"name": "SQL注入", "description": "通过输入注入恶意SQL语句", "severity": "critical"},
            "CWE-78": {"name": "OS命令注入", "description": "执行任意系统命令", "severity": "critical"},
            "CWE-22": {"name": "路径遍历", "description": "访问受限目录外的文件", "severity": "high"},
            "CWE-352": {"name": "跨站请求伪造(CSRF)", "description": "诱导用户执行非预期操作", "severity": "medium"},
            "CWE-287": {"name": "认证不当", "description": "身份验证机制存在缺陷", "severity": "high"},
            "CWE-250": {"name": "权限提升", "description": "获取超出预期的权限", "severity": "critical"},
            "CWE-319": {"name": "明文传输敏感信息", "description": "未加密传输敏感数据", "severity": "high"},
            "CWE-798": {"name": "硬编码凭证", "description": "代码中硬编码密码/密钥", "severity": "high"},
            "CWE-200": {"name": "信息泄露", "description": "向未授权方暴露敏感信息", "severity": "medium"},
            "CWE-918": {"name": "服务端请求伪造(SSRF)", "description": "服务器发起非预期请求", "severity": "high"},
            "CWE-434": {"name": "危险文件上传", "description": "上传可执行文件", "severity": "critical"},
            "CWE-611": {"name": "XXE注入", "description": "XML外部实体注入", "severity": "high"},
            "CWE-94": {"name": "代码注入", "description": "注入并执行任意代码", "severity": "critical"},
        }

        # 渗透测试Top漏洞
        self._pentest_top = [
            {"id": "PT-001", "name": "开放端口与服务暴露", "cwe": "CWE-200", "severity": "medium",
             "description": "不必要的端口开放，暴露服务版本信息", "fix": "关闭不必要端口，限制服务绑定地址，隐藏版本信息"},
            {"id": "PT-002", "name": "弱口令与默认凭证", "cwe": "CWE-287", "severity": "high",
             "description": "使用弱密码或厂商默认账号密码", "fix": "强制强密码策略，修改默认凭证，启用多因素认证"},
            {"id": "PT-003", "name": "已知漏洞服务", "cwe": "CWE-200", "severity": "high",
             "description": "运行存在已知CVE漏洞的服务版本", "fix": "及时打补丁，升级到安全版本，虚拟补丁(WAF)"},
            {"id": "PT-004", "name": "SMB共享匿名访问", "cwe": "CWE-200", "severity": "high",
             "description": "SMB共享允许匿名读取敏感文件", "fix": "禁用匿名访问，设置共享权限，启用SMB签名"},
            {"id": "PT-005", "name": "LDAP匿名绑定", "cwe": "CWE-200", "severity": "medium",
             "description": "LDAP服务允许匿名查询用户信息", "fix": "禁用匿名绑定，限制查询权限"},
            {"id": "PT-006", "name": "未授权API端点", "cwe": "CWE-287", "severity": "high",
             "description": "API接口缺少认证授权检查", "fix": "所有API端点强制认证，实施最小权限原则"},
            {"id": "PT-007", "name": "目录列表泄露", "cwe": "CWE-200", "severity": "low",
             "description": "Web服务器开启目录列表", "fix": "禁用目录列表，配置默认文档"},
            {"id": "PT-008", "name": "安全响应头缺失", "cwe": "CWE-200", "severity": "low",
             "description": "缺少CSP/HSTS/X-Frame-Options等安全头", "fix": "配置完整的安全响应头"},
        ]

        # 移动安全Top漏洞 (OWASP Mobile Top 10 2024)
        self._mobile_top = [
            {"id": "M-001", "name": "不安全数据存储", "owasp": "M1", "severity": "high",
             "description": "敏感数据明文存储在本地文件、SQLite、SharedPreferences", "fix": "使用EncryptedSharedPreferences/Keystore加密，避免外部存储"},
            {"id": "M-002", "name": "不安全通信", "owasp": "M3", "severity": "high",
             "description": "使用HTTP明文传输，或SSL/TLS验证不当", "fix": "强制HTTPS，启用证书锁定(SSL Pinning)，禁用明文流量"},
            {"id": "M-003", "name": "不安全认证", "owasp": "M4", "severity": "high",
             "description": "弱认证机制，本地绕过登录，硬编码凭证", "fix": "服务端认证，OAuth2/OIDC，生物识别辅助，不本地存储密码"},
            {"id": "M-004", "name": "不安全授权", "owasp": "M5", "severity": "high",
             "description": "权限过度申请，组件暴露导致越权访问", "fix": "最小权限原则，exported组件加permission保护，服务端鉴权"},
            {"id": "M-005", "name": "不安全代码质量", "owasp": "M7", "severity": "medium",
             "description": "缓冲区溢出、格式化字符串、内存泄漏、不安全函数", "fix": "代码审计，使用安全函数，AddressSanitizer检测"},
            {"id": "M-006", "name": "二进制保护不足", "owasp": "M8", "severity": "medium",
             "description": "未混淆、未加壳、可调试、反编译容易", "fix": "ProGuard/R8混淆，加壳保护，反调试检测，完整性校验"},
            {"id": "M-007", "name": "反向工程风险", "owasp": "M9", "severity": "medium",
             "description": "核心逻辑可被逆向，算法/密钥暴露", "fix": "关键逻辑Native化，白盒加密，代码混淆，运行时保护"},
            {"id": "M-008", "name": "多余功能泄露", "owasp": "M10", "severity": "low",
             "description": "调试接口、测试代码、日志泄露敏感信息", "fix": "Release构建移除调试代码，关闭Log输出，清理测试接口"},
            {"id": "M-009", "name": "硬编码密钥与API Key", "owasp": "M1", "severity": "high",
             "description": "APK中硬编码加密密钥、API Key、Token", "fix": "密钥存入Keystore/Keychain，运行时从安全后端获取，使用NDK隐藏"},
            {"id": "M-010", "name": "WebView安全问题", "owasp": "M7", "severity": "high",
             "description": "WebView启用JS接口、允许文件访问、加载不可信内容", "fix": "禁用setJavaScriptEnabled不必要时，限制file访问，校验URL"},
        ]

        # 区块链安全Top漏洞
        self._blockchain_top = [
            {"id": "BC-001", "name": "重入攻击(Reentrancy)", "severity": "critical",
             "description": "在状态更新前调用外部合约，被递归调用盗取资金", "fix": "检查-生效-交互模式(CEI)，ReentrancyGuard，pull支付模式"},
            {"id": "BC-002", "name": "整数溢出/下溢", "severity": "critical",
             "description": "算术运算超出类型范围导致数值回绕", "fix": "使用SafeMath库，Solidity 0.8+内置溢出检查"},
            {"id": "BC-003", "name": "访问控制缺陷", "severity": "critical",
             "description": "关键函数缺少onlyOwner/权限修饰，任意地址可调用", "fix": "OpenZeppelin Ownable/AccessControl，函数级权限检查"},
            {"id": "BC-004", "name": "未检查返回值", "severity": "high",
             "description": "call/send/transfer返回值未检查，转账失败被忽略", "fix": "检查所有外部调用返回值，使用require(send())"},
            {"id": "BC-005", "name": "时间戳依赖", "severity": "medium",
             "description": "使用block.timestamp作为随机数或关键逻辑判断", "fix": "避免时间戳作为随机源，使用Chainlink VRF，commit-reveal方案"},
            {"id": "BC-006", "name": "短地址攻击", "severity": "medium",
             "description": "ERC20 transfer参数填充不足导致金额解析异常", "fix": "参数长度校验，使用OpenZeppelin标准实现"},
            {"id": "BC-007", "name": "未初始化存储指针", "severity": "high",
             "description": "storage变量未初始化指向slot 0，可覆盖关键状态", "fix": "显式初始化，使用memory临时变量，Solidity 0.5+已禁止"},
            {"id": "BC-008", "name": "DoS with revert", "severity": "high",
             "description": "循环中调用外部地址，单个失败导致整体回滚", "fix": "pull支付模式，记录失败单独处理，避免循环中外部调用"},
            {"id": "BC-009", "name": "强制接收ETH", "severity": "medium",
             "description": "合约假设无法接收ETH，但selfdestruct可强制发送", "fix": "不依赖address(this).balance做逻辑判断，使用会计变量"},
            {"id": "BC-010", "name": "delegatecall风险", "severity": "critical",
             "description": "delegatecall到不可信合约可操纵存储和状态", "fix": "仅delegatecall到可信且审计过的合约，使用库模式"},
            {"id": "BC-011", "name": "私钥泄露", "severity": "critical",
             "description": "私钥明文存储、硬编码、弱随机数生成", "fix": "硬件钱包/冷存储，HSM，安全随机数生成器，永不硬编码"},
            {"id": "BC-012", "name": "钓鱼合约/Rug Pull", "severity": "critical",
             "description": "合约隐藏mint权限、升级权限、黑名单，项目方卷款跑路", "fix": "检查合约权限，流动性锁定，合约 renounceOwnership，审计报告"},
        ]

        # AI智能体安全Top漏洞
        self._ai_top = [
            {"id": "AI-001", "name": "提示注入(Prompt Injection)", "severity": "critical",
             "description": "通过用户输入覆盖系统提示词，操纵AI行为", "fix": "输入过滤/转义，系统提示与用户输入隔离，工具调用权限最小化"},
            {"id": "AI-002", "name": "越狱攻击(Jailbreak)", "severity": "high",
             "description": "构造特殊prompt绕过安全护栏，诱导生成有害内容", "fix": "输入分类检测，输出审核，多层防护，红队测试"},
            {"id": "AI-003", "name": "训练数据投毒", "severity": "high",
             "description": "在训练数据中植入后门，触发特定输入产生异常输出", "fix": "数据来源验证，异常数据检测，模型鲁棒性训练，后门扫描"},
            {"id": "AI-004", "name": "模型窃取(Model Extraction)", "severity": "medium",
             "description": "通过大量查询重建模型功能或参数", "fix": "API速率限制，查询异常检测，输出扰动，水印追踪"},
            {"id": "AI-005", "name": "对抗样本攻击", "severity": "high",
             "description": "输入微小扰动导致模型错误分类", "fix": "对抗训练，输入预处理，集成模型，鲁棒性验证"},
            {"id": "AI-006", "name": "工具调用越权", "severity": "critical",
             "description": "AI Agent被诱导调用高权限工具执行危险操作", "fix": "工具权限分级，人工确认高风险操作，沙箱执行，操作审计"},
            {"id": "AI-007", "name": "目标漂移(Goal Hijacking)", "severity": "high",
             "description": "Agent在执行中被诱导偏离原始目标，执行恶意子任务", "fix": "目标一致性检查，步骤审核，偏离检测，回滚机制"},
            {"id": "AI-008", "name": "敏感信息泄露", "severity": "high",
             "description": "模型输出训练数据中的敏感信息或系统提示词", "fix": "训练数据脱敏，输出过滤，差分隐私，提示词保护"},
            {"id": "AI-009", "name": "API密钥泄露", "severity": "critical",
             "description": "LLM API密钥硬编码、暴露在客户端、日志中记录", "fix": "服务端代理调用，密钥管理服务，环境变量，日志脱敏"},
            {"id": "AI-010", "name": "速率限制缺失", "severity": "medium",
             "description": "LLM API无速率限制导致滥用、费用爆炸、DoS", "fix": "API网关限流，配额管理，异常请求检测，成本告警"},
            {"id": "AI-011", "name": "输出过滤缺失", "severity": "high",
             "description": "AI输出未经过滤直接展示或执行，包含恶意内容/代码", "fix": "输出内容审核，代码沙箱执行，HTML转义，恶意链接检测"},
            {"id": "AI-012", "name": "深度伪造检测缺失", "severity": "medium",
             "description": "无法识别AI生成的虚假文本/图片/音视频", "fix": "AI生成内容检测工具，水印验证，多源交叉验证"},
        ]

        # 修复建议模板
        self._fix_templates = {
            "input_validation": "对所有用户输入进行严格验证：类型检查、长度限制、格式校验、白名单过滤。使用参数化查询避免注入。",
            "authentication": "实施强认证机制：多因素认证(MFA)、密码复杂度策略、账户锁定、会话管理、OAuth2/OIDC。",
            "authorization": "实施最小权限原则：基于角色的访问控制(RBAC)、函数级权限检查、服务端鉴权、定期权限审计。",
            "encryption": "敏感数据加密：传输层TLS 1.2+、存储层AES-256、密钥管理服务(KMS/HSM)、禁止硬编码密钥。",
            "logging": "安全日志记录：记录所有安全事件、防篡改存储、定期审计、日志中不记录敏感信息。",
            "patching": "漏洞管理：定期漏洞扫描、及时补丁更新、CVE监控、变更管理、回滚预案。",
        }

    def get_cwe(self, cwe_id: str) -> Optional[Dict]:
        """获取CWE信息"""
        return self._cwe_db.get(cwe_id)

    def get_domain_top(self, domain: DomainType) -> List[Dict]:
        """获取指定领域的Top漏洞列表"""
        mapping = {
            DomainType.PENTEST: self._pentest_top,
            DomainType.MOBILE: self._mobile_top,
            DomainType.BLOCKCHAIN: self._blockchain_top,
            DomainType.AI_AGENT: self._ai_top,
        }
        return mapping.get(domain, [])

    def get_fix_template(self, category: str) -> str:
        """获取修复建议模板"""
        return self._fix_templates.get(category, "请参考安全最佳实践进行修复。")

    def search(self, keyword: str, domain: Optional[DomainType] = None) -> List[Dict]:
        """搜索知识库"""
        keyword = keyword.lower()
        results = []
        domains = [domain] if domain else DomainType.all_domains()
        for d in domains:
            for item in self.get_domain_top(d):
                text = (item.get("name", "") + item.get("description", "")).lower()
                if keyword in text:
                    results.append({**item, "domain": d.value, "domain_label": d.label()})
        return results

    def get_statistics(self) -> Dict:
        """获取知识库统计"""
        return {
            "cwe_count": len(self._cwe_db),
            "pentest_vulns": len(self._pentest_top),
            "mobile_vulns": len(self._mobile_top),
            "blockchain_vulns": len(self._blockchain_top),
            "ai_vulns": len(self._ai_top),
            "fix_templates": len(self._fix_templates),
            "total": len(self._cwe_db) + len(self._pentest_top) + len(self._mobile_top) + len(self._blockchain_top) + len(self._ai_top),
        }


# 单例
_instance: Optional[KnowledgeBase] = None

def get_knowledge_base(data_dir: str = "data/unified") -> KnowledgeBase:
    global _instance
    if _instance is None:
        _instance = KnowledgeBase(data_dir)
    return _instance


# ===========================================================================
# UnifiedKnowledgeBase — 整合 PoC / 攻击链 / 指纹库的统一查询接口
# （追加模块，不影响上方 KnowledgeBase 的既有逻辑）
# ===========================================================================
class UnifiedKnowledgeBase:
    """统一知识库：整合 PoC 库、攻击链库、指纹库，提供统一搜索/查询入口。"""

    def __init__(self):
        # 延迟导入，避免循环依赖与启动期硬失败
        self.poc_lib = None
        self.chain_lib = None
        self.fp_lib = None
        try:
            from knowledge.poc_library import poc_library
            self.poc_lib = poc_library
        except Exception as e:  # noqa: BLE001
            print(f"[UnifiedKnowledgeBase] 加载 PoC 库失败: {e}")
        try:
            from knowledge.attack_chains import attack_chain_library
            self.chain_lib = attack_chain_library
        except Exception as e:  # noqa: BLE001
            print(f"[UnifiedKnowledgeBase] 加载攻击链库失败: {e}")
        try:
            from knowledge.fingerprint_library import fingerprint_library
            self.fp_lib = fingerprint_library
        except Exception as e:  # noqa: BLE001
            print(f"[UnifiedKnowledgeBase] 加载指纹库失败: {e}")

    # ------------------------------------------------------------------
    # 统一搜索
    # ------------------------------------------------------------------
    def search(self, query: str, category: Optional[str] = None) -> Dict[str, List[Dict]]:
        """在 PoC / 攻击链 / 指纹库中统一搜索，返回合并结果。

        Args:
            query: 搜索关键词。
            category: 限定库来源，取值 poc / attack_chain / fingerprint；None 表示全部。
        """
        result: Dict[str, List[Dict]] = {"poc": [], "attack_chain": [], "fingerprint": []}
        want = {category} if category else result.keys()

        if "poc" in want and self.poc_lib is not None:
            try:
                result["poc"] = self.poc_lib.search_pocs(keyword=query)
            except Exception:  # noqa: BLE001
                result["poc"] = []
        if "attack_chain" in want and self.chain_lib is not None:
            try:
                result["attack_chain"] = self.chain_lib.search_chains(keyword=query)
            except Exception:  # noqa: BLE001
                result["attack_chain"] = []
        if "fingerprint" in want and self.fp_lib is not None:
            try:
                result["fingerprint"] = self.fp_lib.search_rules(keyword=query)
            except Exception:  # noqa: BLE001
                result["fingerprint"] = []
        return result

    # ------------------------------------------------------------------
    # 分库查询
    # ------------------------------------------------------------------
    def get_poc(self, cve_id: Optional[str] = None, cwe_id: Optional[str] = None,
                service: Optional[str] = None,
                severity: Optional[str] = None) -> List[Dict]:
        """查询 PoC。参数为空则返回该条件下的全部匹配。"""
        if self.poc_lib is None:
            return []
        results: List[Dict] = []
        # 优先按已知 ID / 关键词精确匹配
        for kw in (cve_id, cwe_id, service):
            if kw:
                try:
                    results.extend(self.poc_lib.search_pocs(keyword=kw, severity=severity))
                except Exception:  # noqa: BLE001
                    pass
        if not results:
            try:
                results = self.poc_lib.search_pocs(severity=severity)
            except Exception:  # noqa: BLE001
                results = []
        # 去重
        seen, deduped = set(), []
        for item in results:
            key = item.get("poc_id") or item.get("id") or json.dumps(item, sort_keys=True, default=str)
            if key not in seen:
                seen.add(key)
                deduped.append(item)
        return deduped

    def get_attack_chain(self, chain_id: Optional[str] = None,
                         technique: Optional[str] = None) -> List[Dict]:
        """查询攻击链。"""
        if self.chain_lib is None:
            return []
        if chain_id:
            chain = self.chain_lib.get_chain(chain_id)
            return [chain] if chain else []
        if technique:
            try:
                return self.chain_lib.search_chains(keyword=technique)
            except Exception:  # noqa: BLE001
                return []
        return []

    def get_fingerprint(self, banner: Optional[str] = None, path: Optional[str] = None,
                        header: Optional[str] = None) -> List[Dict]:
        """查询指纹：优先用 banner/header/path 做响应识别，否则按关键词搜索规则。"""
        if self.fp_lib is None:
            return []
        # 识别模式：基于真实响应特征
        if banner or header or path:
            try:
                headers = {}
                if header:
                    headers["Server"] = header
                results = self.fp_lib.identify(
                    headers=headers,
                    body=banner or "",
                    title=path or "",
                )
                if results:
                    return results
            except Exception:  # noqa: BLE001
                pass
        # 退化：关键词搜索
        kw = banner or path or header
        if kw:
            try:
                return self.fp_lib.search_rules(keyword=kw)
            except Exception:  # noqa: BLE001
                return []
        return []

    # ------------------------------------------------------------------
    # 统计
    # ------------------------------------------------------------------
    def get_stats(self) -> Dict:
        """知识库统计：各库记录数与分类统计。"""
        stats: Dict[str, Any] = {"poc": None, "attack_chain": None, "fingerprint": None}
        try:
            stats["poc"] = self.poc_lib.get_statistics() if self.poc_lib else None
        except Exception as e:  # noqa: BLE001
            stats["poc"] = {"error": str(e)}
        try:
            stats["attack_chain"] = self.chain_lib.get_statistics() if self.chain_lib else None
        except Exception as e:  # noqa: BLE001
            stats["attack_chain"] = {"error": str(e)}
        try:
            stats["fingerprint"] = self.fp_lib.get_statistics() if self.fp_lib else None
        except Exception as e:  # noqa: BLE001
            stats["fingerprint"] = {"error": str(e)}
        return stats

    # ------------------------------------------------------------------
    # 攻击链匹配
    # ------------------------------------------------------------------
    def match_attack_chain(self, findings: List[Dict]) -> List[Dict]:
        """基于发现的漏洞匹配可能的攻击链。"""
        if self.chain_lib is None:
            return []
        # 汇总发现中的关键词用于匹配
        blob = json.dumps(findings, ensure_ascii=False).lower()
        candidates: Dict[str, float] = {}
        for keyword in self._extract_keywords(findings):
            try:
                matched = self.chain_lib.search_chains(keyword=keyword)
            except Exception:  # noqa: BLE001
                matched = []
            for chain in matched:
                cid = chain.get("chain_id") or chain.get("id") or json.dumps(chain, sort_keys=True, default=str)
                candidates[cid] = candidates.get(cid, 0.0) + 1.0
                # 把命中的链对象挂回去
                chain["_score"] = candidates[cid]
        # 按命中分数排序
        ranked = sorted(
            (c for c in (self._chain_object(k, findings) for k in candidates)),
            key=lambda x: x.get("_score", 0),
            reverse=True,
        )
        return ranked

    def _chain_object(self, chain_id: str, findings: List[Dict]) -> Dict:
        """根据已匹配的 chain_id 取回链对象。"""
        chain = self.chain_lib.get_chain(chain_id) if self.chain_lib else None
        if chain:
            return chain
        return {"chain_id": chain_id, "findings": findings}

    @staticmethod
    def _extract_keywords(findings: List[Dict]) -> List[str]:
        """从发现列表提取攻击链匹配关键词。"""
        kws = set()
        for f in findings:
            if not isinstance(f, dict):
                continue
            for field in ("vuln", "vulnerability", "type", "name", "service"):
                v = f.get(field)
                if isinstance(v, str) and v:
                    kws.add(v)
        return list(kws)[:20]


# UnifiedKnowledgeBase 单例
_unified_kb_instance: Optional[UnifiedKnowledgeBase] = None


def get_unified_knowledge_base() -> UnifiedKnowledgeBase:
    """获取全局 UnifiedKnowledgeBase 单例。"""
    global _unified_kb_instance
    if _unified_kb_instance is None:
        _unified_kb_instance = UnifiedKnowledgeBase()
    return _unified_kb_instance
