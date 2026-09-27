# -*- coding: utf-8 -*-
"""
ai/knowledge_grounding.py — 知识库增强生成（RAG 雏形）

把项目已有的 CVE 库、漏洞详情字典、合规标准加载进内存，提供关键词
检索与上下文拼装能力：先检索再注入 prompt，让 AI 回答有据可依；
知识库未覆盖的问题会明确标注"可能不准确"，降低幻觉。

合法定位：仅用于授权安全评估场景的知识问答与修复建议参考。
"""
import re
import time
from datetime import datetime
from typing import Any, Callable, Dict, List, Optional

try:
    from utils.logger import log
except Exception:  # pragma: no cover
    import logging

    logging.basicConfig(level=logging.INFO)
    log = logging.getLogger("ai.knowledge_grounding")


# ---------------------------------------------------------------------------
# 内置漏洞详情字典（>=30 个常见漏洞：原理 / 影响 / 修复 / 参考）
# ---------------------------------------------------------------------------
BUILTIN_VULNS: List[Dict[str, str]] = [
    {"title": "SQL注入", "category": "vuln",
     "content": "原理：用户输入被拼接到 SQL 语句中，未参数化导致数据库被任意查询。"
                "影响：拖库、绕过登录、读写文件。"
                "修复：使用预编译语句/ORM，输入白名单校验，最小权限数据库账号。"
                "参考：OWASP SQL Injection Prevention Cheat Sheet。"},
    {"title": "XSS跨站脚本", "category": "vuln",
     "content": "原理：未转义用户输入直接渲染到页面，执行恶意脚本。"
                "影响：窃取 Cookie、会话劫持、钓鱼。"
                "修复：输出编码、CSP 策略、HttpOnly Cookie。"
                "参考：OWASP XSS Prevention Cheat Sheet。"},
    {"title": "CSRF跨站请求伪造", "category": "vuln",
     "content": "原理：利用已登录用户的浏览器自动携带 Cookie 发起伪造请求。"
                "影响：以用户身份执行敏感操作。"
                "修复：Token 校验、SameSite Cookie、校验 Referer。"
                "参考：OWASP CSRF Prevention Cheat Sheet。"},
    {"title": "SSRF服务端请求伪造", "category": "vuln",
     "content": "原理：服务端按用户提供的 URL 发起请求，未校验目标地址。"
                "影响：访问内网服务、云元数据接口（169.254.169.254）。"
                "修复：URL 白名单、禁用内网地址、禁止重定向。"
                "参考：OWASP SSRF Prevention Cheat Sheet。"},
    {"title": "路径穿越", "category": "vuln",
     "content": "原理：文件路径拼接 ../ 等字符跳出限制目录。"
                "影响：读取/写入任意文件。"
                "修复：规范化路径后校验根目录、白名单后缀。"
                "参考：CWE-22。"},
    {"title": "命令注入", "category": "vuln",
     "content": "原理：用户输入拼接到 OS 命令中，通过 ; | $() 注入额外命令。"
                "影响：远程命令执行。"
                "修复：避免 shell=True，使用参数化调用，输入白名单。"
                "参考：CWE-78。"},
    {"title": "文件上传", "category": "vuln",
     "content": "原理：未校验上传文件类型/内容，上传 WebShell。"
                "影响：getshell、服务器被控。"
                "修复：重命名存储、白名单后缀、独立域名、禁止执行权限。"
                "参考：OWASP Unrestricted File Upload。"},
    {"title": "Java反序列化", "category": "vuln",
     "content": "原理：对不可信数据执行反序列化，触发 Gadget 链执行代码。"
                "影响：远程代码执行。"
                "修复：使用白名单反序列化、升级组件、避免原生 readObject。"
                "参考：ysoserial 项目说明。"},
    {"title": "Fastjson反序列化", "category": "vuln",
     "content": "原理：autotype 特性加载恶意类触发 RCE。"
                "影响：远程代码执行。"
                "修复：关闭 autotype 或升级到安全版本，使用安全过滤器。"
                "参考：Fastjson 官方安全公告。"},
    {"title": "Log4Shell (CVE-2021-44228)", "category": "cve",
     "content": "原理：Log4j2 的 JNDI lookup 被日志输入触发，远程加载恶意类。"
                "影响：无需交互的远程代码执行。"
                "修复：升级 Log4j2 到 2.17.1+，移除 JndiLookup 类。"
                "参考：CVE-2021-44228 官方通告。"},
    {"title": "永恒之蓝 (CVE-2017-0144)", "category": "cve",
     "content": "原理：SMBv1 处理特制数据包时缓冲区溢出。"
                "影响：蠕虫式横向传播。"
                "修复：关闭 SMBv1，安装 MS17-010 补丁，隔离内网。"
                "参考：CVE-2017-0144。"},
    {"title": "心脏滴血 (CVE-2014-0160)", "category": "cve",
     "content": "原理：OpenSSL 心跳扩展未校验长度，读取相邻内存。"
                "影响：泄露私钥、会话、密码。"
                "修复：升级 OpenSSL 到 1.0.1g+，轮换泄露的密钥。"
                "参考：CVE-2014-0160。"},
    {"title": "Struts2 远程代码执行", "category": "vuln",
     "content": "原理：OGNL 表达式注入导致 RCE（S2-045/046/057 等）。"
                "影响：远程代码执行。"
                "修复：升级 Struts2 到安全版本，关闭 devMode。"
                "参考：Apache Struts 安全公告。"},
    {"title": "ThinkPHP 模板注入", "category": "vuln",
     "content": "原理：模板渲染函数可控导致代码执行。"
                "影响：远程代码执行。"
                "修复：升级 ThinkPHP 版本，过滤模板渲染参数。"
                "参考：ThinkPHP 官方安全公告。"},
    {"title": "Shiro 反序列化", "category": "vuln",
     "content": "原理：RememberMeAES 密钥硬编码/可预测，反序列化触发 RCE。"
                "影响：远程代码执行。"
                "修复：更换强随机密钥，升级 Shiro。"
                "参考：Shiro-550/721 漏洞分析。"},
    {"title": "Nacos 未授权访问", "category": "vuln",
     "content": "原理：默认开启鉴权或绕过默认 Token。"
                "影响：读取/修改配置，获取数据库密码。"
                "修复：开启鉴权，修改默认密钥，限制访问源。"
                "参考：Alibaba Nacos 安全公告。"},
    {"title": "Jenkins 未授权/未打补丁", "category": "vuln",
     "content": "原理：未授权脚本接口或历史 RCE 漏洞。"
                "影响：任务平台被控、CI/CD 供应链污染。"
                "修复：开启鉴权，升级 LTS 版本，限制公网暴露。"
                "参考：Jenkins Security Advisory。"},
    {"title": "Redis 未授权访问", "category": "vuln",
     "content": "原理：Redis 绑定 0.0.0.0 且无密码。"
                "影响：写 SSH 公钥、主从复制 RCE。"
                "修复：绑定内网、requirepass、rename 危险命令。"
                "参考：Redis 安全基线。"},
    {"title": "MongoDB 未授权访问", "category": "vuln",
     "content": "原理：未开启认证且暴露公网。"
                "影响：数据泄露/被勒索加密。"
                "修复：开启 auth，绑定内网，防火墙收敛。"
                "参考：MongoDB 安全基线。"},
    {"title": "Docker 未授权远程 API", "category": "vuln",
     "content": "原理：2375 端口暴露无 TLS 认证。"
                "影响：控制宿主机、逃逸。"
                "修复：使用 TLS 认证或绑定内网，禁止公网暴露。"
                "参考：Docker Daemon 安全配置。"},
    {"title": "Kubernetes API Server 未授权", "category": "vuln",
     "content": "原理：匿名访问或鉴权配置错误。"
                "影响：集群接管、提权。"
                "修复：开启 RBAC、禁用匿名访问、网络隔离。"
                "参考：CIS Kubernetes Benchmark。"},
    {"title": "WebLogic 反序列化", "category": "vuln",
     "content": "原理：T3/IIOP 协议反序列化 gadget（CVE-2019-2725 等）。"
                "影响：远程代码执行。"
                "修复：补丁最新 CPU，禁用 T3 协议或加白。"
                "参考：Oracle WebLogic 安全公告。"},
    {"title": "Tomcat 弱口令/管理后台", "category": "vuln",
     "content": "原理：manager 控制台暴露且口令薄弱。"
                "影响：部署 WAR 包 getshell。"
                "修复：强口令、限制 IP、删除 manager 应用。"
                "参考：Apache Tomcat 安全指南。"},
    {"title": "IIS 短文件名", "category": "vuln",
     "content": "原理：tilde 枚举 8.3 短文件名泄露目录结构。"
                "影响：信息泄露、辅助定向攻击。"
                "修复：禁用 8.3 命名或升级补丁，URL 规范化。"
                "参考：Microsoft IIS 安全公告。"},
    {"title": "Nginx 解析漏洞", "category": "vuln",
     "content": "原理：cgi.fix_pathinfo 配置不当，把图片当 PHP 解析。"
                "影响：文件上传 getshell。"
                "修复：关闭 fix_pathinfo，上传目录禁止执行。"
                "参考：Nginx 配置安全实践。"},
    {"title": "XXE XML外部实体", "category": "vuln",
     "content": "原理：XML 解析器加载外部实体读取本地文件。"
                "影响：文件读取、SSRF。"
                "修复：禁用 DTD/外部实体，使用安全解析配置。"
                "参考：OWASP XXE Prevention。"},
    {"title": "越权访问", "category": "vuln",
     "content": "原理：服务端未校验对象归属，仅凭前端/参数判断权限。"
                "影响：读写他人数据。"
                "修复：服务端统一鉴权中间件，对象级权限校验。"
                "参考：OWASP Broken Access Control。"},
    {"title": "信息泄露", "category": "vuln",
     "content": "原理：错误页面、调试接口、Git/SVN 目录暴露。"
                "影响：泄露路径、版本、源码。"
                "修复：统一错误页，删除敏感备份目录，关闭调试模式。"
                "参考：OWASP Sensitive Data Exposure。"},
    {"title": "弱口令", "category": "vuln",
     "content": "原理：账号使用常见弱口令或默认口令。"
                "影响：暴力破解登录。"
                "修复：密码复杂度策略、锁定策略、多因子认证。"
                "参考：OWASP Authentication Cheat Sheet。"},
    {"title": "CORS 跨域配置错误", "category": "vuln",
     "content": "原理：Access-Control-Allow-Origin 反射任意来源且允许凭证。"
                "影响：跨站读取用户数据。"
                "修复：白名单来源，不与 Allow-Credentials:* 同时使用。"
                "参考：OWASP CORS Misconfiguration。"},
    {"title": "点击劫持", "category": "vuln",
     "content": "原理：页面被 iframe 嵌套诱导点击。"
                "影响：误操作、授权劫持。"
                "修复：X-Frame-Options/CSP frame-ancestors。"
                "参考：OWASP Clickjacking Defense。"},
    {"title": "开放重定向", "category": "vuln",
     "content": "原理：跳转地址由用户控制。"
                "影响：钓鱼、绕过 OAuth 校验。"
                "修复：跳转白名单、相对路径跳转。"
                "参考：CWE-601。"},
    {"title": "Node.js 原型污染", "category": "vuln",
     "content": "原理：递归合并对象时 __proto__ 污染 Object.prototype。"
                "影响：RCE 或拒绝服务。"
                "修复：使用安全合并库（如 lodash 安全版本），冻结原型。"
                "参考：CVE-2019-10744 等。"},
]


# 合规标准要点（尝试从 security/compliance_audit.py 合并，否则用内置）
BUILTIN_COMPLIANCE: List[Dict[str, str]] = [
    {"title": "等保2.0 三级-安全通信网络", "category": "compliance",
     "content": "应采用加密或其他保护措施实现通信保密性；应提供通信完整性校验。"
                "参考：GB/T 22239-2019 8.1.2。"},
    {"title": "等保2.0 三级-安全区域边界", "category": "compliance",
     "content": "应在网络边界进行访问控制、入侵防范、恶意代码防范和安全审计。"
                "参考：GB/T 22239-2019 8.1.3。"},
    {"title": "等保2.0 三级-安全计算环境", "category": "compliance",
     "content": "应对身份鉴别、访问控制、安全审计、入侵防范、数据完整性与保密性提出要求。"
                "参考：GB/T 22239-2019 8.1.4。"},
    {"title": "OWASP Top 10 2021", "category": "compliance",
     "content": "包含失效的访问控制、加密失败、软件和数据完整性故障等十大风险类别。"
                "参考：owasp.org/Top10。"},
    {"title": "CIS Benchmark 基线", "category": "compliance",
     "content": "操作系统/中间件/容器的安全配置基线，涵盖口令、服务、日志等。"
                "参考：cisecurity.org。"},
]


class KnowledgeGrounding:
    """知识库增强生成器：检索 -> 拼装上下文 -> 标注来源。"""

    def __init__(self) -> None:
        """初始化：加载内置知识，并尽力加载项目已有知识库。"""
        self.entries: List[Dict[str, str]] = []
        self._load_builtin()
        self._load_cve_db()
        self._load_fingerprints()
        self._load_compliance()
        self.updated_at = datetime.now().isoformat(timespec="seconds")

    # ------------------------------------------------------------------
    # 知识库装载（全部降级，失败不影响实例化）
    # ------------------------------------------------------------------
    def _load_builtin(self) -> None:
        """加载内置漏洞详情与合规标准。"""
        for item in BUILTIN_VULNS:
            self.entries.append(dict(item))
        for item in BUILTIN_COMPLIANCE:
            self.entries.append(dict(item))

    def _load_cve_db(self) -> None:
        """尝试从 tools/cve_database.py 加载 CVE 记录。"""
        try:
            from tools.cve_database import CVEDatabase  # type: ignore

            db = CVEDatabase()
            conn = None
            try:
                import sqlite3
                conn = sqlite3.connect(db.db_path)
                rows = conn.execute(
                    "SELECT cve_id, description, severity FROM cves LIMIT 500"
                ).fetchall()
                for cve_id, desc, severity in rows:
                    self.entries.append({
                        "title": cve_id,
                        "category": "cve",
                        "content": f"[{severity}] {desc or ''}",
                    })
            finally:
                if conn:
                    conn.close()
        except Exception as e:  # pragma: no cover
            log.debug(f"CVE 库加载跳过: {e}")

    def _load_fingerprints(self) -> None:
        """尝试加载指纹库（knowledge/fingerprint_library.py）。"""
        try:
            from knowledge.fingerprint_library import FINGERPRINTS  # type: ignore

            for fp in FINGERPRINTS:
                if isinstance(fp, dict):
                    name = fp.get("name") or fp.get("product") or "指纹"
                    self.entries.append({
                        "title": str(name),
                        "category": "fingerprint",
                        "content": str(fp)[:500],
                    })
        except Exception:  # pragma: no cover
            pass

    def _load_compliance(self) -> None:
        """尝试加载 security/compliance_audit.py 中的标准。"""
        try:
            import security.compliance_audit as _mod  # type: ignore

            for attr in dir(_mod):
                if attr.isupper():
                    val = getattr(_mod, attr)
                    if isinstance(val, (list, tuple)) and val:
                        self.entries.append({
                            "title": attr,
                            "category": "compliance",
                            "content": str(val)[:500],
                        })
        except Exception:  # pragma: no cover
            pass

    # ------------------------------------------------------------------
    # 检索
    # ------------------------------------------------------------------
    @staticmethod
    def _score(query: str, text: str) -> float:
        """简单关键词重叠评分：query 中每个字符/词命中即加分。"""
        if not query or not text:
            return 0.0
        q = query.lower()
        t = text.lower()
        # 1) 整词命中
        hits = sum(1 for w in re.findall(r"[A-Za-z0-9]+|[\u4e00-\u9fa5]{2,}", q)
                   if w and w in t)
        # 2) 单字命中（中文）
        char_hits = sum(1 for ch in set(q) if ch in t)
        total_chars = max(len(set(q)), 1)
        return hits * 2.0 + char_hits / total_chars

    def search(self, query: str, top_k: int = 5,
               category: Optional[str] = None) -> List[Dict[str, Any]]:
        """知识库检索：按关键词重叠评分排序，可按类别过滤。"""
        results: List[Dict[str, Any]] = []
        for entry in self.entries:
            if category and entry.get("category") != category:
                continue
            score = self._score(query, entry["title"] + " " + entry["content"])
            if score <= 0:
                continue
            results.append({
                "title": entry["title"],
                "content": entry["content"],
                "category": entry.get("category", "unknown"),
                "score": round(score, 3),
            })
        results.sort(key=lambda x: x["score"], reverse=True)
        return results[:top_k]

    # ------------------------------------------------------------------
    # 上下文拼装
    # ------------------------------------------------------------------
    def build_context(self, query: str, top_k: int = 5) -> str:
        """把检索结果格式化为 LLM 上下文字符串。"""
        hits = self.search(query, top_k=top_k)
        if not hits:
            return "【知识库参考】\n（未检索到相关条目）"
        lines = ["【知识库参考】"]
        for i, h in enumerate(hits, 1):
            lines.append(f"{i}. [{h['category']}] {h['title']}：{h['content']}")
        return "\n".join(lines)

    # ------------------------------------------------------------------
    # 知识库增强生成
    # ------------------------------------------------------------------
    def grounded_generate(self, query: str,
                          llm_call_func: Optional[Callable[[str, str], str]] = None
                          ) -> Dict[str, Any]:
        """知识库增强生成：先检索，再（可选）调用 LLM。

        llm_call_func 形如 system_prompt, user_prompt -> str。
        """
        hits = self.search(query, top_k=5)
        context = self.build_context(query, top_k=5)

        covered = len(hits) > 0 and hits[0]["score"] >= 1.0
        warning = "" if covered else "该问题不在知识库中，AI回答可能不准确"

        if llm_call_func is not None:
            try:
                system_prompt = (
                    "你是安全平台的知识库助手。必须优先参考【知识库参考】中的内容"
                    "作答，并在回答中标注信息来源（如'根据CVE-2021-44228…'）。"
                    "知识库未覆盖的内容要明确说明不确定。"
                )
                user_prompt = f"{context}\n\n用户问题：{query}"
                answer = llm_call_func(system_prompt, user_prompt)
            except Exception as e:  # pragma: no cover
                log.error(f"知识库增强生成失败: {e}")
                answer = ""
        else:
            answer = ""

        if not answer:
            # 降级：模板回答
            if hits:
                top = hits[0]
                answer = (f"根据知识库检索，与「{query}」最相关的条目是："
                          f"{top['title']}。{top['content']}")
            else:
                answer = f"知识库中未找到与「{query}」直接相关的条目。"

        if warning:
            answer = answer + f"\n\n⚠️ {warning}。"

        return {
            "query": query,
            "covered": covered,
            "warning": warning,
            "references": hits,
            "answer": answer,
        }

    # ------------------------------------------------------------------
    # 覆盖统计
    # ------------------------------------------------------------------
    def get_coverage_stats(self) -> Dict[str, Any]:
        """知识库覆盖统计：总数、分类计数、更新时间。"""
        cat_count: Dict[str, int] = {}
        for e in self.entries:
            cat = e.get("category", "unknown")
            cat_count[cat] = cat_count.get(cat, 0) + 1
        return {
            "total": len(self.entries),
            "categories": cat_count,
            "updated_at": self.updated_at,
        }
