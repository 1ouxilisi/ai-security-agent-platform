# -*- coding: utf-8 -*-
"""
ai/output_validator.py — AI 输出质量校验器

对 AI 生成的安全类输出做多维校验：
    1. 事实性校验：CVE 编号是否在项目知识库中、技术术语是否为已知术语；
    2. 代码校验：括号/引号匹配、Python 语法（ast.parse）；
    3. 安全性校验：是否包含危险运维建议（关防火墙、chmod 777 等）；
    4. 完整性校验：修复方案/漏洞分析是否包含必要章节；
    5. 免责声明追加。

合法定位：本模块是 AI 输出的"质检员"，用于减少幻觉与危险建议，不产出
攻击内容。所有校验均为本地规则，不依赖外部网络。
"""
import ast
import re
from typing import Any, Dict, List, Optional, Tuple

try:
    from utils.logger import log
except Exception:  # pragma: no cover
    import logging

    logging.basicConfig(level=logging.INFO)
    log = logging.getLogger("ai.output_validator")


# ---------------------------------------------------------------------------
# 知识库静态部分
# ---------------------------------------------------------------------------

# 项目内置已知 CVE 编号（与 tools/cve_database.py 内置记录保持一致）
KNOWN_CVE_IDS = {
    "CVE-2021-44228", "CVE-2017-0144", "CVE-2014-0160", "CVE-2021-26855",
    "CVE-2019-0708", "CVE-2020-1472", "CVE-2022-22965", "CVE-2023-23397",
    "CVE-2021-34527", "CVE-2018-13379", "CVE-2019-19781", "CVE-2020-5902",
    "CVE-2022-1388", "CVE-2023-27997", "CVE-2023-34362", "CVE-2024-3400",
    "CVE-2024-21762", "CVE-2023-4966", "CVE-2022-30190", "CVE-2021-1675",
}

# 尝试加载扩展 CVE 库（tools/cve_extended.py）
try:  # pragma: no cover - 取决于扩展库是否存在
    from tools.cve_extended import EXTENDED_CVES  # type: ignore

    for _item in EXTENDED_CVES:
        _cid = _item.get("cve_id") if isinstance(_item, dict) else None
        if _cid:
            KNOWN_CVE_IDS.add(_cid)
except Exception:
    pass

# 常见漏洞/技术术语白名单（>=50 个）
KNOWN_VULN_TERMS = {
    # 注入类
    "SQL注入", "命令注入", "代码注入", "LDAP注入", "XPath注入", "NoSQL注入",
    # Web 通用
    "XSS", "跨站脚本", "CSRF", "跨站请求伪造", "SSRF", "服务端请求伪造",
    "路径穿越", "目录遍历", "文件上传", "文件包含", "PHP文件包含",
    "反序列化", "Java反序列化", "Python反序列化", "XXE", "XML外部实体",
    "逻辑漏洞", "越权", "水平越权", "垂直越权", "未授权访问", "信息泄露",
    "弱口令", "CORS跨域", "点击劫持", "HTTP响应拆分", "开放重定向",
    "Node.js原型污染", "原型污染",
    # 知名漏洞名
    "心脏滴血", "Heartbleed", "Log4Shell", "永恒之蓝", "EternalBlue",
    "BlueKeep", "Zerologon", "Spring4Shell", "PrintNightmare", "Follina",
    "ProxyLogon", "XORat",
    # 组件/产品漏洞
    "Struts2", "ThinkPHP", "Shiro", "Fastjson", "Fastjson反序列化",
    "Spring Cloud", "Nacos", "Jenkins", "GitLab", "Docker", "Kubernetes",
    "WebLogic反序列化", "JBoss弱口令", "Tomcat弱口令", "IIS短文件名",
    "Nginx解析漏洞", "Apache解析漏洞",
    # 未授权/匿名访问类
    "Redis未授权", "MongoDB未授权", "Elasticsearch未授权",
    "Zookeeper未授权", "Kafka未授权", "FTP匿名", "SMB空会话",
    "LDAP匿名",
    # 其他
    "缓冲区溢出", "整数溢出", "堆溢出", "栈溢出", "条件竞争", "竞态条件",
    "权限提升", "提权", "中间人攻击", "会话固定", "会话劫持",
    "弱加密", "硬编码密钥", "敏感数据明文存储",
}

# 危险操作关键词 -> 替代建议
DANGEROUS_ACTIONS = {
    "关闭防火墙": "建议仅按需开放必要端口，保留防火墙规则",
    "禁用安全软件": "建议在白名单中放行业务程序，而不是整体禁用",
    "关闭杀毒": "建议调整杀毒软件的实时扫描排除项，而非关闭",
    "禁用UAC": "建议保持 UAC 开启，通过清单提升程序权限",
    "关闭DEP": "DEP 是内存保护机制，建议保持开启",
    "关闭ASLR": "ASLR 是地址随机化保护，建议保持开启",
    "禁用SELINUX": "建议将 SELinux 切换为 permissive 排查，修复后恢复 enforcing",
    "chmod 777": "建议按最小权限设置（如 644/750），避免 777",
    "关闭审计": "审计日志是溯源依据，建议保留并轮转",
    "禁用日志": "日志是排障与合规依据，建议保留并设置轮转",
    "关闭HTTPS": "建议全站 HTTPS，使用 HSTS 强制加密",
    "使用HTTP": "建议优先 HTTPS，仅在内网测试临时使用 HTTP",
    "禁用证书验证": "建议使用受信任 CA 证书，而非跳过校验",
    "跳过认证": "建议实现认证中间件，仅对明确白名单路径放行",
    "关闭密码策略": "建议保持密码复杂度策略，弱口令需单独整改",
    "允许空密码": "空密码会导致任意登录，建议强制密码非空",
    "开放所有端口": "建议只开放业务必需端口，其余默认拒绝",
    "关闭IP白名单": "建议保留白名单，按最小原则收敛源 IP",
    "禁用速率限制": "速率限制可防暴力破解与洪泛，建议保留",
}

# 完整修复方案必备章节（关键词命中即视为存在）
REMEDIATION_SECTIONS = {
    "问题描述": ["问题描述", "漏洞描述", "问题说明", "缺陷描述"],
    "修复步骤": ["修复步骤", "修复方案", "修复方法", "处置步骤", "整改步骤"],
    "验证方法": ["验证方法", "验证步骤", "验证方式", "复测", "验证"],
    "参考链接": ["参考链接", "参考资料", "参考", "参考文献", "参考文档"],
}

# 完整漏洞分析必备章节
ANALYSIS_SECTIONS = {
    "漏洞原理": ["漏洞原理", "原理分析", "漏洞机制", "成因"],
    "影响范围": ["影响范围", "影响版本", "影响资产", "受影响"],
    "利用条件": ["利用条件", "利用前提", "触发条件", "前置条件"],
    "修复建议": ["修复建议", "修复方案", "处置建议", "加固建议"],
}

# CVE 编号正则
_CVE_RE = re.compile(r"CVE-\d{4}-\d{4,7}", re.IGNORECASE)

# 候选"漏洞技术术语"提取：连续中文片段 + 常见漏洞后缀
_VULN_SUFFIX = ("漏洞", "注入", "攻击", "绕过", "泄露", "泄漏", "穿越", "遍历",
                "上传", "反序列化", "劫持", "包含", "污染", "劫持", "提权",
                "溢出", "伪造", "欺骗", "未授权", "弱口令", "越权")
_CHUNK_RE = re.compile(r"[\u4e00-\u9fa5A-Za-z][\u4e00-\u9fa5A-Za-z0-9]{1,14}")


class OutputValidator:
    """AI 输出校验器：事实性 / 代码 / 安全 / 完整性 四维校验。"""

    def __init__(self) -> None:
        """初始化，缓存已知 CVE 集合与术语集合。"""
        self.known_cves = set(KNOWN_CVE_IDS)
        self.known_terms = set(KNOWN_VULN_TERMS)

    # ------------------------------------------------------------------
    # 3.1 事实性校验
    # ------------------------------------------------------------------
    def validate_facts(self, text: str) -> Dict[str, Any]:
        """事实性校验：CVE 编号与技术术语是否在知识库中。

        - 已知 CVE 标记为 known，未知 CVE 标记为"需核实"；
        - 形如"XX 漏洞/注入/绕过"等候选术语，未命中白名单则标记"未知术语"。
        """
        issues: List[str] = []
        cve_found: List[Dict[str, str]] = []
        unknown_terms: List[str] = []

        if not text:
            return {"valid": False, "issues": ["输入为空"],
                    "cve_found": [], "unknown_terms": []}

        # 1) CVE 编号
        for raw in set(_CVE_RE.findall(text)):
            cid = raw.upper()
            if cid in self.known_cves:
                cve_found.append({"id": cid, "status": "known"})
            else:
                cve_found.append({"id": cid, "status": "需核实"})
                issues.append(f"CVE 编号 {cid} 不在项目知识库中，需核实")

        # 2) 候选技术术语
        seen_terms = set()
        for chunk in _CHUNK_RE.findall(text):
            cand = chunk.strip()
            if cand in seen_terms:
                continue
            # 只对"像漏洞术语"的片段做白名单比对
            if cand.endswith(_VULN_SUFFIX) and len(cand) >= 3:
                seen_terms.add(cand)
                if cand not in self.known_terms:
                    unknown_terms.append(cand)
                    issues.append(f"未知术语「{cand}」不在知识库中，请核实")

        return {
            "valid": len(issues) == 0,
            "issues": issues,
            "cve_found": sorted(cve_found, key=lambda x: x["id"]),
            "unknown_terms": unknown_terms,
        }

    # ------------------------------------------------------------------
    # 3.2 代码校验
    # ------------------------------------------------------------------
    @staticmethod
    def _bracket_balance(code: str) -> List[str]:
        """括号匹配检查（忽略字符串与注释内容）。"""
        errors: List[str] = []
        pairs = {")": "(", "]": "[", "}": "{"}
        opens = set(pairs.values())
        stack: List[Tuple[str, int]] = []
        in_str: Optional[str] = None
        i = 0
        n = len(code)
        while i < n:
            ch = code[i]
            # 字符串状态
            if in_str:
                if ch == "\\":
                    i += 2
                    continue
                if ch == in_str:
                    in_str = None
                i += 1
                continue
            # 注释
            if ch == "#":
                while i < n and code[i] != "\n":
                    i += 1
                continue
            # 三引号字符串
            if code[i:i + 3] in ('"""', "'''"):
                quote = code[i:i + 3]
                end = code.find(quote, i + 3)
                i = end + 3 if end != -1 else n
                continue
            if ch in ('"', "'"):
                in_str = ch
                i += 1
                continue
            if ch in opens:
                stack.append((ch, i))
            elif ch in pairs:
                if not stack or stack[-1][0] != pairs[ch]:
                    errors.append(f"位置 {i}：括号不匹配，多余的 '{ch}'")
                else:
                    stack.pop()
            i += 1
        for ch, pos in stack:
            errors.append(f"位置 {pos}：未闭合的 '{ch}'")
        return errors

    @staticmethod
    def _quote_balance(code: str) -> List[str]:
        """简单引号配对检查（忽略转义与注释外的代码区域）。"""
        errors: List[str] = []
        # 去除注释行
        cleaned = "\n".join(
            line.split("#", 1)[0] if not line.strip().startswith("#") else ""
            for line in code.splitlines()
        )
        for q in ('"', "'"):
            count = cleaned.count(q)
            # 成对出现才合理；三引号允许 3 的倍数
            if count % 2 != 0:
                errors.append(f"引号 '{q}' 数量为奇数（{count}），可能未闭合")
        return errors

    def validate_code(self, code: str) -> Dict[str, Any]:
        """代码校验：括号/引号匹配 + Python ast.parse 语法检查。"""
        errors: List[str] = []
        warnings: List[str] = []

        if not code or not code.strip():
            return {"valid": False, "errors": ["代码为空"], "warnings": []}

        errors.extend(self._bracket_balance(code))
        errors.extend(self._quote_balance(code))

        # Python 关键字/基本语法检查
        bad_patterns = [
            (r"\bdef\s+\w+\s*\(\s*$", "def 定义的括号未闭合"),
            (r"\bclass\s+\w+\s*[(:]\s*$", "class 定义不完整"),
            (r"^\s*import\s*$", "import 后缺少模块名"),
            (r"=\s*=\s*", "连续赋值符 '==' 疑似笔误"),
        ]
        for pat, msg in bad_patterns:
            if re.search(pat, code, re.MULTILINE):
                warnings.append(msg)

        # 真正的 Python 语法检查
        try:
            ast.parse(code)
        except SyntaxError as e:
            errors.append(f"Python 语法错误：第 {e.lineno} 行 {e.msg}")
        except ValueError as e:
            warnings.append(f"AST 解析告警：{e}")

        return {
            "valid": len(errors) == 0,
            "errors": errors,
            "warnings": warnings,
        }

    # ------------------------------------------------------------------
    # 3.3 安全性校验
    # ------------------------------------------------------------------
    def validate_safety(self, text: str) -> Dict[str, Any]:
        """安全性校验：扫描危险运维建议并给出替代方案。"""
        risk_items: List[Dict[str, str]] = []
        suggestions: List[str] = []

        if not text:
            return {"safe": True, "risk_items": [], "suggestions": []}

        for keyword, suggestion in DANGEROUS_ACTIONS.items():
            if keyword in text:
                risk_items.append({
                    "action": keyword,
                    "level": "高风险操作，需谨慎",
                    "detail": f"AI 输出中包含「{keyword}」",
                })
                suggestions.append(f"「{keyword}」→ 建议改为：{suggestion}")

        return {
            "safe": len(risk_items) == 0,
            "risk_items": risk_items,
            "suggestions": suggestions,
        }

    # ------------------------------------------------------------------
    # 3.4 完整性校验
    # ------------------------------------------------------------------
    def validate_completeness(self, text: str,
                              expected_type: str = "remediation") -> Dict[str, Any]:
        """完整性校验：检查必备章节是否齐全。"""
        if expected_type == "analysis":
            sections = ANALYSIS_SECTIONS
        else:
            sections = REMEDIATION_SECTIONS

        missing: List[str] = []
        present = 0
        total = len(sections)
        for name, keywords in sections.items():
            if any(kw in text for kw in keywords):
                present += 1
            else:
                missing.append(name)

        score = int(round(present / total * 100)) if total else 0
        return {
            "complete": len(missing) == 0,
            "missing_sections": missing,
            "score": score,
        }

    # ------------------------------------------------------------------
    # 免责声明
    # ------------------------------------------------------------------
    @staticmethod
    def add_disclaimer(text: str) -> str:
        """在 AI 输出末尾追加免责声明（幂等，不重复追加）。"""
        disclaimer = ("\n\n⚠️ AI生成内容，仅供参考，请核实后执行。"
                      "本建议由AI模型生成，可能存在不准确之处。")
        if "AI生成内容，仅供参考" in text:
            return text
        return text + disclaimer

    # ------------------------------------------------------------------
    # 综合校验
    # ------------------------------------------------------------------
    def validate_all(self, text: str, code: Optional[str] = None,
                     expected_type: str = "remediation") -> Dict[str, Any]:
        """运行全部校验，返回综合结果。"""
        result: Dict[str, Any] = {
            "facts": self.validate_facts(text or ""),
            "safety": self.validate_safety(text or ""),
            "completeness": self.validate_completeness(text or "", expected_type),
        }
        if code:
            result["code"] = self.validate_code(code)
        else:
            result["code"] = {"valid": True, "errors": [], "warnings": []}

        fact_ok = result["facts"]["valid"]
        safe_ok = result["safety"]["safe"]
        code_ok = result["code"]["valid"]
        result["overall_valid"] = bool(fact_ok and safe_ok and code_ok)
        result["summary"] = {
            "fact_check": "通过" if fact_ok else "存疑",
            "safety_check": "安全" if safe_ok else "含高风险操作",
            "code_check": "通过" if code_ok else "有语法问题",
            "completeness_score": result["completeness"]["score"],
        }
        return result
