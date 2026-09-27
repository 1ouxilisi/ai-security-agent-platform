"""
engine模块，提供相关安全测试功能。

模块功能：
    - 提供相关安全测试功能
    - 支持API调用和命令行使用
    - 与其他模块集成协作

注意事项：
    - 本模块仅用于授权的安全测试
    - 请勿用于非法用途
    - 使用前请确保已获得相关授权
"""
import asyncio
import json
import re
import time
from typing import Any, Dict, List, Optional, Tuple
from pathlib import Path
from dataclasses import dataclass, field
import yaml
import aiohttp
from utils.logger import log


@dataclass
class NucleiTemplate:
    """POC模板"""
    id: str
    name: str
    author: str = ""
    severity: str = "info"  # info/low/medium/high/critical
    description: str = ""
    tags: List[str] = field(default_factory=list)
    reference: List[str] = field(default_factory=list)
    # 请求配置
    method: str = "GET"
    path: str = "/"
    headers: Dict[str, str] = field(default_factory=dict)
    body: str = ""
    # 匹配器
    matchers: List[Dict] = field(default_factory=list)
    matchers_condition: str = "or"  # or / and
    # 提取器
    extractors: List[Dict] = field(default_factory=list)
    # 原始YAML
    raw: Dict = field(default_factory=dict)


@dataclass
class NucleiResult:
    """扫描结果"""
    template_id: str
    template_name: str
    target: str
    url: str
    matched: bool
    severity: str = "info"
    description: str = ""
    matched_at: List[str] = field(default_factory=list)
    extracted_data: Dict[str, Any] = field(default_factory=dict)
    response_status: int = 0
    response_length: int = 0
    duration_ms: float = 0
    error: Optional[str] = None


class NucleiEngine:
    """Nuclei POC模板引擎"""

    def __init__(self, template_dir: Optional[str] = None, concurrency: int = 5, timeout: int = 10):
        """初始化NucleiEngine实例。

        Args:
            self: 类实例。
        """
        self.template_dir = Path(template_dir) if template_dir else Path(__file__).parent / "templates"
        self.template_dir.mkdir(parents=True, exist_ok=True)
        self.concurrency = concurrency
        self.timeout = timeout
        self.templates: Dict[str, NucleiTemplate] = {}
        self._session: Optional[aiohttp.ClientSession] = None
        self._load_builtin_templates()
        self._load_external_templates()
        log.info(f"Nuclei引擎初始化，模板数: {len(self.templates)}, 并发: {concurrency}")

    def _load_builtin_templates(self):
        """加载内置POC模板"""
        builtin_templates = [
            {
                "id": "tech-detect",
                "name": "技术栈识别",
                "author": "ai-hacking-agent",
                "severity": "info",
                "description": "识别目标Web技术栈",
                "tags": ["tech", "detect"],
                "method": "GET",
                "path": "/",
                "matchers": [
                    {"type": "word", "words": ["Apache", "nginx", "Microsoft-IIS"], "part": "header"},
                    {"type": "word", "words": ["PHP", "ASP.NET", "JSP", "Python"], "part": "header"},
                ],
                "matchers_condition": "or",
            },
            {
                "id": "git-exposed",
                "name": "Git仓库暴露",
                "author": "ai-hacking-agent",
                "severity": "high",
                "description": "检测.git目录是否可访问，可能导致源代码泄露",
                "tags": ["git", "exposure", "misconfig"],
                "reference": ["https://github.com/topics/git-exposure"],
                "method": "GET",
                "path": "/.git/config",
                "matchers": [
                    {"type": "word", "words": ["[core]", "[remote", "repositoryformatversion"], "part": "body"},
                    {"type": "status", "status": [200]},
                ],
                "matchers_condition": "and",
            },
            {
                "id": "env-exposed",
                "name": "环境变量文件暴露",
                "author": "ai-hacking-agent",
                "severity": "critical",
                "description": "检测.env文件是否可访问，可能包含数据库密码、API密钥等敏感信息",
                "tags": ["env", "exposure", "critical"],
                "method": "GET",
                "path": "/.env",
                "matchers": [
                    {"type": "word", "words": ["DB_PASSWORD", "API_KEY", "SECRET_KEY", "DATABASE_URL"], "part": "body"},
                    {"type": "status", "status": [200]},
                ],
                "matchers_condition": "and",
            },
            {
                "id": "phpinfo-exposed",
                "name": "PHPInfo暴露",
                "author": "ai-hacking-agent",
                "severity": "medium",
                "description": "检测phpinfo.php是否可访问，可能泄露服务器配置信息",
                "tags": ["php", "info", "exposure"],
                "method": "GET",
                "path": "/phpinfo.php",
                "matchers": [
                    {"type": "word", "words": ["PHP Version", "phpinfo()", "System"], "part": "body"},
                    {"type": "status", "status": [200]},
                ],
                "matchers_condition": "and",
            },
            {
                "id": "directory-listing",
                "name": "目录列表启用",
                "author": "ai-hacking-agent",
                "severity": "low",
                "description": "检测目录列表是否启用，可能泄露文件结构",
                "tags": ["directory", "listing", "misconfig"],
                "method": "GET",
                "path": "/",
                "matchers": [
                    {"type": "word", "words": ["Index of /", "Directory listing for", "Parent Directory"], "part": "body"},
                ],
                "matchers_condition": "or",
            },
            {
                "id": "backup-file",
                "name": "备份文件暴露",
                "author": "ai-hacking-agent",
                "severity": "medium",
                "description": "检测常见备份文件是否可访问",
                "tags": ["backup", "exposure"],
                "method": "GET",
                "path": "/backup.zip",
                "matchers": [
                    {"type": "status", "status": [200]},
                    {"type": "word", "words": ["PK", "application/zip"], "part": "header"},
                ],
                "matchers_condition": "or",
            },
            {
                "id": "admin-panel",
                "name": "管理后台发现",
                "author": "ai-hacking-agent",
                "severity": "info",
                "description": "检测常见管理后台路径",
                "tags": ["admin", "panel"],
                "method": "GET",
                "path": "/admin",
                "matchers": [
                    {"type": "status", "status": [200, 301, 302, 401, 403]},
                ],
                "matchers_condition": "or",
            },
            {
                "id": "cors-misconfig",
                "name": "CORS配置错误",
                "author": "ai-hacking-agent",
                "severity": "medium",
                "description": "检测CORS是否配置为允许任意来源",
                "tags": ["cors", "misconfig"],
                "method": "GET",
                "path": "/",
                "headers": {"Origin": "https://evil.example.com"},
                "matchers": [
                    {"type": "word", "words": ["https://evil.example.com", "*"], "part": "header"},
                ],
                "matchers_condition": "or",
            },
            {
                "id": "missing-security-headers",
                "name": "安全头缺失",
                "author": "ai-hacking-agent",
                "severity": "low",
                "description": "检测常见安全响应头是否缺失",
                "tags": ["headers", "security"],
                "method": "GET",
                "path": "/",
                "matchers": [
                    {"type": "word", "words": ["X-Frame-Options", "Content-Security-Policy", "X-Content-Type-Options"], "part": "header", "negative": True},
                ],
                "matchers_condition": "or",
            },
            {
                "id": "sql-error-based",
                "name": "SQL错误注入",
                "author": "ai-hacking-agent",
                "severity": "high",
                "description": "基于错误信息的SQL注入检测",
                "tags": ["sqli", "error-based"],
                "method": "GET",
                "path": "/?id=1'",
                "matchers": [
                    {"type": "word", "words": ["SQL syntax", "mysql_fetch", "ORA-", "PostgreSQL", "SQLite", "unclosed quotation"], "part": "body"},
                ],
                "matchers_condition": "or",
            },
        ]

        for tpl_data in builtin_templates:
            template = self._parse_template_dict(tpl_data)
            if template:
                self.templates[template.id] = template

    def _load_external_templates(self):
        """加载外部YAML模板"""
        try:
            for yaml_file in self.template_dir.glob("*.yaml"):
                try:
                    with open(yaml_file, "r", encoding="utf-8") as f:
                        data = yaml.safe_load(f)
                    if data and "id" in data:
                        template = self._parse_template_dict(data)
                        if template:
                            self.templates[template.id] = template
                            log.debug(f"外部模板已加载: {template.id}")
                except Exception as e:
                    log.error(f"加载模板失败 {yaml_file}: {e}")
        except Exception as e:
            log.error(f"加载外部模板失败: {e}")

    def _parse_template_dict(self, data: Dict) -> Optional[NucleiTemplate]:
        """解析模板字典"""
        try:
            # 处理Nuclei格式的http请求
            http_info = data.get("http", [{}])
            if isinstance(http_info, list) and http_info:
                http_info = http_info[0]

            method = http_info.get("method", data.get("method", "GET"))
            path = http_info.get("path", [data.get("path", "/")])
            if isinstance(path, list):
                path = path[0] if path else "/"

            headers = http_info.get("headers", data.get("headers", {}))
            body = http_info.get("body", data.get("body", ""))

            matchers = http_info.get("matchers", data.get("matchers", []))
            matchers_condition = http_info.get("matchers-condition", data.get("matchers_condition", "or"))
            extractors = http_info.get("extractors", data.get("extractors", []))

            return NucleiTemplate(
                id=data.get("id", ""),
                name=data.get("name", data.get("id", "")),
                author=data.get("author", ""),
                severity=data.get("severity", "info"),
                description=data.get("description", ""),
                tags=data.get("tags", []),
                reference=data.get("reference", []),
                method=method,
                path=path,
                headers=headers,
                body=body,
                matchers=matchers,
                matchers_condition=matchers_condition,
                extractors=extractors,
                raw=data,
            )
        except Exception as e:
            log.error(f"解析模板失败: {e}")
            return None

    async def _get_session(self) -> aiohttp.ClientSession:
        """获取或创建HTTP会话"""
        if not self._session or self._session.closed:
            timeout = aiohttp.ClientTimeout(total=self.timeout)
            self._session = aiohttp.ClientSession(timeout=timeout)
        return self._session

    async def _execute_template(self, template: NucleiTemplate, target: str) -> NucleiResult:
        """执行单个POC模板"""
        start_time = time.time()
        url = target.rstrip("/") + template.path

        result = NucleiResult(
            template_id=template.id,
            template_name=template.name,
            target=target,
            url=url,
            matched=False,
            severity=template.severity,
            description=template.description,
        )

        try:
            session = await self._get_session()
            headers = {"User-Agent": "AIHackingAgent/5.0 (Nuclei Engine)"}
            headers.update(template.headers)

            if template.method.upper() == "POST":
                resp = await session.post(url, headers=headers, data=template.body)
            else:
                resp = await session.get(url, headers=headers)

            response_text = await resp.text()
            response_headers = dict(resp.headers)

            result.response_status = resp.status
            result.response_length = len(response_text)

            # 执行匹配器
            matched_results = []
            for matcher in template.matchers:
                matched = self._check_matcher(matcher, resp.status, response_text, response_headers)
                matched_results.append(matched)
                if matched:
                    result.matched_at.append(matcher.get("type", "unknown"))

            # 判断整体匹配
            if template.matchers_condition == "and":
                result.matched = all(matched_results) if matched_results else False
            else:  # or
                result.matched = any(matched_results) if matched_results else False

            # 执行提取器
            for extractor in template.extractors:
                extracted = self._run_extractor(extractor, response_text, response_headers)
                if extracted:
                    result.extracted_data.update(extracted)

        except Exception as e:
            result.error = str(e)
            log.debug(f"模板执行失败 {template.id}: {e}")

        result.duration_ms = round((time.time() - start_time) * 1000, 2)
        return result

    def _check_matcher(self, matcher: Dict, status: int, body: str, headers: Dict) -> bool:
        """检查单个匹配器"""
        matcher_type = matcher.get("type", "word")
        negative = matcher.get("negative", False)
        part = matcher.get("part", "body")

        target_text = body if part == "body" else json.dumps(headers, ensure_ascii=False) if part == "header" else ""

        matched = False

        if matcher_type == "status":
            expected_status = matcher.get("status", [])
            matched = status in expected_status

        elif matcher_type == "word":
            words = matcher.get("words", [])
            condition = matcher.get("condition", "or")
            word_matches = [word.lower() in target_text.lower() for word in words]
            matched = all(word_matches) if condition == "and" else any(word_matches)

        elif matcher_type == "regex":
            patterns = matcher.get("regex", [])
            for pattern in patterns:
                try:
                    if re.search(pattern, target_text, re.IGNORECASE):
                        matched = True
                        break
                except re.error:
                    continue

        elif matcher_type == "size":
            size = matcher.get("size", [0])
            matched = len(body) in size

        return (not matched) if negative else matched

    def _run_extractor(self, extractor: Dict, body: str, headers: Dict) -> Dict:
        """运行提取器"""
        extractor_type = extractor.get("type", "regex")
        part = extractor.get("part", "body")
        name = extractor.get("name", "extracted")
        target_text = body if part == "body" else json.dumps(headers, ensure_ascii=False)

        result = {}

        if extractor_type == "regex":
            patterns = extractor.get("regex", [])
            for pattern in patterns:
                try:
                    matches = re.findall(pattern, target_text, re.IGNORECASE)
                    if matches:
                        result[name] = matches[:10]
                        break
                except re.error:
                    continue

        elif extractor_type == "kval":
            # 键值对提取
            pass

        return result

    async def scan_target(self, target: str, template_ids: Optional[List[str]] = None,
                          severity_filter: Optional[List[str]] = None,
                          tags_filter: Optional[List[str]] = None) -> List[NucleiResult]:
        """
        扫描目标
        target: 目标URL
        template_ids: 指定模板ID列表，None表示全部
        severity_filter: 按严重程度过滤
        tags_filter: 按标签过滤
        """
        # 筛选模板
        templates_to_run = []
        for template in self.templates.values():
            if template_ids and template.id not in template_ids:
                continue
            if severity_filter and template.severity not in severity_filter:
                continue
            if tags_filter and not any(tag in template.tags for tag in tags_filter):
                continue
            templates_to_run.append(template)

        log.info(f"Nuclei扫描开始: 目标={target}, 模板数={len(templates_to_run)}")

        # 并发执行
        semaphore = asyncio.Semaphore(self.concurrency)

        async def run_with_limit(template):
            async with semaphore:
                return await self._execute_template(template, target)

        tasks = [run_with_limit(t) for t in templates_to_run]
        results = await asyncio.gather(*tasks, return_exceptions=True)

        # 过滤异常结果
        valid_results = []
        for r in results:
            if isinstance(r, NucleiResult):
                valid_results.append(r)
            else:
                log.error(f"扫描异常: {r}")

        # 按严重程度排序
        severity_order = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
        valid_results.sort(key=lambda x: severity_order.get(x.severity, 99))

        matched_count = sum(1 for r in valid_results if r.matched)
        log.info(f"Nuclei扫描完成: 总模板={len(valid_results)}, 匹配={matched_count}")

        return valid_results

    def list_templates(self, severity: Optional[str] = None, tags: Optional[str] = None) -> List[Dict]:
        """列出所有模板"""
        templates = []
        for t in self.templates.values():
            if severity and t.severity != severity:
                continue
            if tags and tags not in t.tags:
                continue
            templates.append({
                "id": t.id, "name": t.name, "severity": t.severity,
                "description": t.description, "tags": t.tags, "author": t.author,
            })
        return sorted(templates, key=lambda x: x["id"])

    def get_stats(self) -> Dict:
        """获取引擎统计"""
        severity_counts = {}
        tag_counts = {}
        for t in self.templates.values():
            severity_counts[t.severity] = severity_counts.get(t.severity, 0) + 1
            for tag in t.tags:
                tag_counts[tag] = tag_counts.get(tag, 0) + 1
        return {
            "total_templates": len(self.templates),
            "by_severity": severity_counts,
            "by_tags": tag_counts,
            "concurrency": self.concurrency,
            "timeout": self.timeout,
        }

    async def close(self):
        """关闭引擎"""
        if self._session and not self._session.closed:
            await self._session.close()
        log.info("Nuclei引擎已关闭")


# 全局Nuclei引擎实例
nuclei_engine = NucleiEngine()
