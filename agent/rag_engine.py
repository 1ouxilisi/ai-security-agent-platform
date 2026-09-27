"""
RAG知识库引擎 - v3.0核心升级
检索增强生成（Retrieval-Augmented Generation）
让AI智能体在工具调用和结果分析时，自动查询相关漏洞知识、修复建议、技术文档

核心能力：
- 漏洞知识库检索（CVE详情、利用方法、修复建议）
- 技术文档检索（OWASP指南、测试方法论）
- 历史案例检索（类似漏洞的处理经验）
- 语义相似度匹配
- 检索结果自动注入AI上下文
"""
import json
import re
from typing import Any, Dict, List, Optional, Tuple
from dataclasses import dataclass, field
from pathlib import Path
from utils.logger import log
from config.settings import settings


@dataclass
class KnowledgeEntry:
    """知识库条目"""
    id: str
    title: str
    content: str
    category: str = "general"  # cve / technique / remediation / case / documentation
    tags: List[str] = field(default_factory=list)
    metadata: Dict = field(default_factory=dict)
    source: str = ""
    created_at: float = 0.0


@dataclass
class RetrievalResult:
    """检索结果"""
    query: str
    results: List[Tuple[KnowledgeEntry, float]] = field(default_factory=list)  # (条目, 相似度)
    total_found: int = 0
    retrieval_time_ms: float = 0.0


class RAGEngine:
    """RAG知识库引擎"""

    def __init__(self, knowledge_dir: Optional[str] = None):
        """初始化RAGEngine实例。

        Args:
            self: 类实例。
        """
        self.knowledge_dir = Path(knowledge_dir) if knowledge_dir else Path(settings.project_root) / "data" / "knowledge"
        self.knowledge_base: Dict[str, KnowledgeEntry] = {}
        self._initialize_knowledge()
        log.info(f"RAG引擎初始化，知识库条目数: {len(self.knowledge_base)}")

    def _initialize_knowledge(self):
        """初始化知识库"""
        self.knowledge_dir.mkdir(parents=True, exist_ok=True)

        # 加载内置漏洞知识
        self._load_builtin_cves()
        self._load_owasp_techniques()
        self._load_remediation_guides()

        # 加载外部知识文件
        self._load_external_knowledge()

    def _load_builtin_cves(self):
        """加载内置CVE知识"""
        try:
            from knowledge.cve import cve_kb
            for cve_id, cve_data in cve_kb.local_db.items():
                entry = KnowledgeEntry(
                    id=cve_id,
                    title=cve_data.get("name", cve_id),
                    content=json.dumps(cve_data, ensure_ascii=False),
                    category="cve",
                    tags=[cve_id, cve_data.get("severity", ""), "vulnerability"],
                    metadata=cve_data,
                    source="builtin_cve_db",
                )
                self.knowledge_base[cve_id] = entry
        except Exception as e:
            log.error(f"加载内置CVE知识失败: {e}")

    def _load_owasp_techniques(self):
        """加载OWASP测试技术"""
        techniques = [
            {
                "id": "owasp-sqli",
                "title": "SQL注入测试方法",
                "category": "technique",
                "tags": ["sqli", "sql", "injection", "owasp"],
                "content": """SQL注入测试方法论：
1. 识别所有输入点（URL参数、POST数据、HTTP头、Cookie）
2. 测试单引号(')、双引号(")、分号(;)等特殊字符
3. 观察响应变化（错误信息、响应长度、延迟）
4. 使用布尔盲注：' AND 1=1-- / ' AND 1=2--
5. 使用时间盲注：' AND SLEEP(5)--
6. 使用UNION查询获取数据
7. 验证漏洞可利用性

常见绕过技术：
- 大小写混合：UnIoN SeLeCt
- 注释绕过：/**/
- 编码绕过：URL编码、Hex编码
- 等价函数：sleep() → benchmark()
""",
            },
            {
                "id": "owasp-xss",
                "title": "XSS跨站脚本测试方法",
                "category": "technique",
                "tags": ["xss", "cross-site", "scripting", "owasp"],
                "content": """XSS测试方法论：
1. 反射型XSS：在输入点注入<script>alert(1)</script>，观察是否反射到页面
2. 存储型XSS：注入Payload后，访问其他页面观察是否执行
3. DOM型XSS：分析前端JS，寻找document.write、innerHTML等危险API
4. 测试各种Payload：<img src=x onerror=alert(1)>、<svg onload=alert(1)>
5. 测试事件处理器：onmouseover、onfocus、onload
6. 测试JavaScript伪协议：javascript:alert(1)
7. 验证CSP（内容安全策略）是否有效

常见绕过：
- 标签绕过：<scr<script>ipt>
- 事件绕过：onmouseover=alert(1)
- 编码绕过：HTML实体编码、Unicode编码
""",
            },
            {
                "id": "owasp-ssrf",
                "title": "SSRF服务端请求伪造测试方法",
                "category": "technique",
                "tags": ["ssrf", "server-side", "request", "owasp"],
                "content": """SSRF测试方法论：
1. 识别所有可能发起服务端请求的功能点（URL预览、图片加载、Webhook、API调用）
2. 测试内网地址：http://127.0.0.1、http://localhost、http://0.0.0.0
3. 测试云元数据：http://169.254.169.254/latest/meta-data/ (AWS)
4. 测试非HTTP协议：file:///etc/passwd、dict://、gopher://
5. 测试端口扫描：http://127.0.0.1:22、:3306、:6379
6. 测试重定向绕过：http://example.com/redirect?url=http://127.0.0.1
7. 测试DNS重绑定

常见绕过：
- 地址表示：127.0.0.1 → 2130706433（十进制）、0x7f000001（十六进制）
- DNS解析：使用指向127.0.0.1的域名
- URL解析差异：利用不同解析器的差异
""",
            },
        ]

        for tech in techniques:
            entry = KnowledgeEntry(
                id=tech["id"],
                title=tech["title"],
                content=tech["content"],
                category=tech["category"],
                tags=tech["tags"],
                source="builtin_owasp",
            )
            self.knowledge_base[tech["id"]] = entry

    def _load_remediation_guides(self):
        """加载修复指南"""
        guides = [
            {
                "id": "remediate-sqli",
                "title": "SQL注入修复指南",
                "category": "remediation",
                "tags": ["sqli", "fix", "remediation", "security"],
                "content": """SQL注入修复方案：
1. 使用参数化查询/预编译语句（Prepared Statements）
2. 使用ORM框架（SQLAlchemy、Django ORM、Hibernate）
3. 输入验证：白名单校验，拒绝非法字符
4. 最小权限原则：数据库账户只授予必要权限
5. 存储过程：使用参数化的存储过程
6. WAF防护：部署Web应用防火墙作为补充防护
7. 安全编码培训：开发人员安全意识培训

代码示例（Python）：
# 错误（字符串拼接）
cursor.execute(f"SELECT * FROM users WHERE id = {user_id}")
# 正确（参数化查询）
cursor.execute("SELECT * FROM users WHERE id = %s", (user_id,))
""",
            },
            {
                "id": "remediate-xss",
                "title": "XSS跨站脚本修复指南",
                "category": "remediation",
                "tags": ["xss", "fix", "remediation", "security"],
                "content": """XSS修复方案：
1. 输出编码：根据上下文进行HTML实体编码、JavaScript编码、URL编码
2. 使用现代前端框架：React、Vue、Angular默认自动转义
3. Content Security Policy (CSP)：设置严格的CSP策略
4. HttpOnly Cookie：防止XSS窃取Cookie
5. 输入验证：白名单校验用户输入
6. 安全API：使用textContent代替innerHTML，使用setAttribute
7. 信任边界：明确区分可信和不可信数据

CSP示例：
Content-Security-Policy: default-src 'self'; script-src 'self' 'nonce-abc123'; style-src 'self'; img-src 'self' data:;
""",
            },
        ]

        for guide in guides:
            entry = KnowledgeEntry(
                id=guide["id"],
                title=guide["title"],
                content=guide["content"],
                category=guide["category"],
                tags=guide["tags"],
                source="builtin_remediation",
            )
            self.knowledge_base[guide["id"]] = entry

    def _load_external_knowledge(self):
        """加载外部知识文件（JSON格式）"""
        try:
            for json_file in self.knowledge_dir.glob("*.json"):
                try:
                    with open(json_file, "r", encoding="utf-8") as f:
                        data = json.load(f)
                    if isinstance(data, list):
                        for item in data:
                            if "id" in item and "content" in item:
                                entry = KnowledgeEntry(
                                    id=item["id"],
                                    title=item.get("title", item["id"]),
                                    content=item["content"],
                                    category=item.get("category", "general"),
                                    tags=item.get("tags", []),
                                    metadata=item.get("metadata", {}),
                                    source=str(json_file.name),
                                )
                                self.knowledge_base[entry.id] = entry
                except Exception as e:
                    log.error(f"加载知识文件失败 {json_file}: {e}")
        except Exception as e:
            log.error(f"加载外部知识失败: {e}")

    def _calculate_similarity(self, query: str, entry: KnowledgeEntry) -> float:
        """
        计算查询和知识条目的相似度
        简单实现：基于关键词匹配的评分
        （生产环境可替换为向量相似度）
        """
        query_lower = query.lower()
        query_words = set(re.findall(r'\w+', query_lower))

        entry_text = (entry.title + " " + entry.content + " " + " ".join(entry.tags)).lower()
        entry_words = set(re.findall(r'\w+', entry_text))

        if not query_words:
            return 0.0

        # 关键词匹配数
        matches = query_words & entry_words
        match_score = len(matches) / len(query_words) if query_words else 0

        # 标签匹配加分
        tag_matches = [tag for tag in entry.tags if tag.lower() in query_lower]
        tag_score = len(tag_matches) * 0.2

        # 标题匹配加分
        title_score = 0.3 if any(word in entry.title.lower() for word in query_words) else 0

        total_score = min(1.0, match_score + tag_score + title_score)
        return total_score

    def retrieve(self, query: str, top_k: int = 5, category: Optional[str] = None) -> RetrievalResult:
        """
        检索相关知识
        query: 查询文本
        top_k: 返回前K条结果
        category: 按类别筛选
        """
        import time
        start_time = time.time()

        log.debug(f"RAG检索: {query[:50]}...")

        # 计算所有条目的相似度
        scored_entries = []
        for entry in self.knowledge_base.values():
            if category and entry.category != category:
                continue
            similarity = self._calculate_similarity(query, entry)
            if similarity > 0:
                scored_entries.append((entry, similarity))

        # 按相似度排序
        scored_entries.sort(key=lambda x: x[1], reverse=True)
        top_results = scored_entries[:top_k]

        retrieval_time_ms = (time.time() - start_time) * 1000

        result = RetrievalResult(
            query=query,
            results=top_results,
            total_found=len(scored_entries),
            retrieval_time_ms=round(retrieval_time_ms, 2),
        )

        log.debug(f"RAG检索完成，找到 {len(top_results)} 条相关知识，耗时 {retrieval_time_ms:.1f}ms")
        return result

    def get_context_for_prompt(self, query: str, top_k: int = 3) -> str:
        """
        获取可注入Prompt的上下文文本
        用于增强AI智能体的回答
        """
        result = self.retrieve(query, top_k=top_k)
        if not result.results:
            return ""

        context_parts = ["【相关知识库】"]
        for i, (entry, score) in enumerate(result.results, 1):
            context_parts.append(f"\n{i}. {entry.title} (相似度: {score:.2f})")
            context_parts.append(entry.content[:500])

        context_parts.append("\n【请参考以上知识进行回答】")
        return "\n".join(context_parts)

    def add_knowledge(self, entry: KnowledgeEntry):
        """添加知识条目"""
        self.knowledge_base[entry.id] = entry
        log.info(f"知识已添加: {entry.id}")

    def get_statistics(self) -> Dict:
        """获取知识库统计"""
        category_counts = {}
        for entry in self.knowledge_base.values():
            category_counts[entry.category] = category_counts.get(entry.category, 0) + 1

        return {
            "total_entries": len(self.knowledge_base),
            "by_category": category_counts,
            "knowledge_dir": str(self.knowledge_dir),
        }


# 全局RAG引擎实例
rag_engine = RAGEngine()
