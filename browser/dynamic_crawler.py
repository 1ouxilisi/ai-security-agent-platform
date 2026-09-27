"""
动态爬虫 - 基于Playwright的Web应用动态侦察
功能：页面发现、表单提取、API端点发现、JavaScript渲染内容提取、技术指纹识别
对标Shannon的Reconnaissance阶段（Playwright浏览器自动化探索运行中应用）
"""
import asyncio
import hashlib
import json
import re
from dataclasses import dataclass, field
from typing import Optional
from urllib.parse import urljoin, urlparse

from .browser_manager import BrowserManager, BrowserConfig, PageSnapshot


@dataclass
class FormInfo:
    """表单信息"""
    action: str
    method: str
    inputs: list = field(default_factory=list)  # [{name, type, placeholder, value}]
    has_file_upload: bool = False
    has_auth: bool = False  # 包含password字段


@dataclass
class APIEndpoint:
    """API端点"""
    url: str
    method: str
    content_type: str = ""
    status_code: int = 0
    request_body: str = ""
    response_preview: str = ""
    source: str = "network"  # network / js_extract / form


@dataclass
class CrawlResult:
    """爬取结果"""
    base_url: str
    pages_discovered: int = 0
    forms_found: list = field(default_factory=list)
    api_endpoints: list = field(default_factory=list)
    links: list = field(default_factory=list)
    scripts: list = field(default_factory=list)
    tech_stack: dict = field(default_factory=dict)
    screenshots: list = field(default_factory=list)
    errors: list = field(default_factory=list)
    page_snapshots: list = field(default_factory=list)


class DynamicCrawler:
    """
    动态Web应用爬虫
    使用Playwright渲染JavaScript，发现静态爬虫无法找到的内容
    """

    # 常见API路径模式
    API_PATTERNS = [
        r"/api/[a-zA-Z0-9_\-/]+",
        r"/v[0-9]+/[a-zA-Z0-9_\-/]+",
        r"/graphql",
        r"/rest/[a-zA-Z0-9_\-/]+",
        r"/rpc/[a-zA-Z0-9_\-/]+",
        r"/endpoint/[a-zA-Z0-9_\-/]+",
    ]

    # 技术指纹特征
    TECH_SIGNATURES = {
        "frameworks": {
            "React": ["react.js", "react-dom", "_reactRoot", "__REACT"],
            "Vue.js": ["vue.js", "vue.runtime", "__vue__", "_vnode"],
            "Angular": ["angular.js", "ng-version", "ng-app"],
            "Next.js": ["__next", "_next/static", "next/data"],
            "Nuxt.js": ["__nuxt", "_nuxt", "nuxt-link"],
            "Django": ["csrftoken", "django", "Djdt"],
            "Flask": ["flask", "werkzeug"],
            "Spring Boot": ["spring-boot", "Whitelabel Error", "_csrf"],
            "Express": ["x-powered-by: express", "express"],
            "Laravel": ["laravel_session", "XSRF-TOKEN"],
        },
        "servers": {
            "Nginx": ["Server: nginx"],
            "Apache": ["Server: Apache"],
            "IIS": ["Server: Microsoft-IIS"],
            "Tomcat": ["Apache-Coyote", "Tomcat"],
            "Node.js": ["x-powered-by"],
        },
        "security": {
            "Cloudflare": ["cf-ray", "cloudflare", "__cfduid"],
            "WAF": ["x-sucuri-id", "sucuri", "mod_security", "wordfence"],
            "CSP": ["content-security-policy"],
            "HSTS": ["strict-transport-security"],
        },
    }

    def __init__(self, browser_manager: BrowserManager, max_pages: int = 50,
                 max_depth: int = 3, delay: float = 0.5):
        self.bm = browser_manager
        self.max_pages = max_pages
        self.max_depth = max_depth
        self.delay = delay
        self._visited = set()
        self._result = CrawlResult(base_url="")

    async def crawl(self, start_url: str) -> CrawlResult:
        """
        从起始URL开始动态爬取
        """
        self._result = CrawlResult(base_url=start_url)
        self._visited.clear()

        queue = [(start_url, 0)]

        while queue and len(self._visited) < self.max_pages:
            url, depth = queue.pop(0)

            if url in self._visited or depth > self.max_depth:
                continue

            self._visited.add(url)

            try:
                snapshot = await self._crawl_page(url)
                self._result.page_snapshots.append(snapshot)
                self._result.pages_discovered += 1

                # 发现新链接加入队列
                for link in snapshot.links:
                    if link not in self._visited and self._is_same_domain(url, link):
                        queue.append((link, depth + 1))

                await asyncio.sleep(self.delay)

            except Exception as e:
                self._result.errors.append(f"{url}: {str(e)}")

        # 汇总技术栈
        self._result.tech_stack = self._detect_tech_stack(
            self._result.page_snapshots
        )

        return self._result

    async def _crawl_page(self, url: str) -> PageSnapshot:
        """爬取单个页面"""
        page = await self.bm.navigate(url)

        network_requests = []
        console_errors = []

        # 监听网络请求（捕获API调用）
        async def on_request(request):
            req_url = request.url
            if self._is_api_endpoint(req_url):
                endpoint = APIEndpoint(
                    url=req_url,
                    method=request.method,
                    content_type=request.headers.get("content-type", ""),
                    source="network",
                )
                if endpoint not in self._result.api_endpoints:
                    self._result.api_endpoints.append(endpoint)
            network_requests.append({
                "url": req_url,
                "method": request.method,
                "type": request.resource_type,
            })

        async def on_console(msg):
            if msg.type in ("error", "warning"):
                console_errors.append(f"[{msg.type}] {msg.text}")

        page.on("request", on_request)
        page.on("console", on_console)

        # 等待页面稳定
        try:
            await page.wait_for_load_state("networkidle", timeout=10000)
        except Exception:
            pass

        # 提取页面信息
        title = await page.title()
        content = await page.content()
        content_length = len(content)
        html_hash = hashlib.md5(content.encode()).hexdigest()

        # 提取表单
        forms = await self._extract_forms(page)
        self._result.forms_found.extend(forms)

        # 提取链接
        links = await self._extract_links(page, url)
        self._result.links.extend([l for l in links if l not in self._result.links])

        # 提取脚本
        scripts = await self._extract_scripts(page)
        self._result.scripts.extend([s for s in scripts if s not in self._result.scripts])

        # 从JS中提取API端点
        js_endpoints = await self._extract_api_from_js(page)
        for ep in js_endpoints:
            if ep not in self._result.api_endpoints:
                self._result.api_endpoints.append(ep)

        # 截图
        screenshot_path = None
        try:
            safe_name = hashlib.md5(url.encode()).hexdigest()[:12]
            screenshot_dir = os.path.join("screenshots", "dynamic_crawl")
            os.makedirs(screenshot_dir, exist_ok=True)
            screenshot_path = os.path.join(screenshot_dir, f"{safe_name}.png")
            await page.screenshot(path=screenshot_path, full_page=False)
            self._result.screenshots.append(screenshot_path)
        except Exception:
            pass

        # 获取响应状态码
        status_code = 0
        try:
            response = await page.evaluate("() => window.__lastResponseStatus || 200")
            status_code = response if isinstance(response, int) else 200
        except Exception:
            status_code = 200

        await self.bm.release_page(page)

        return PageSnapshot(
            url=url,
            title=title,
            status_code=status_code,
            content_length=content_length,
            forms=[f.__dict__ for f in forms],
            links=links,
            scripts=scripts,
            api_endpoints=[e.__dict__ for e in js_endpoints],
            cookies=await self.bm.get_cookies(),
            screenshot_path=screenshot_path,
            console_errors=console_errors[:20],
            network_requests=network_requests[:50],
            html_hash=html_hash,
        )

    async def _extract_forms(self, page) -> list:
        """提取页面所有表单"""
        forms_js = """
        () => {
            const forms = [];
            document.querySelectorAll('form').forEach(form => {
                const inputs = [];
                form.querySelectorAll('input, select, textarea').forEach(inp => {
                    inputs.push({
                        name: inp.name || '',
                        type: inp.type || 'text',
                        placeholder: inp.placeholder || '',
                        value: inp.value || ''
                    });
                });
                forms.push({
                    action: form.action || window.location.href,
                    method: (form.method || 'GET').toUpperCase(),
                    inputs: inputs,
                    has_file_upload: inputs.some(i => i.type === 'file'),
                    has_auth: inputs.some(i => i.type === 'password')
                });
            });
            return forms;
        }
        """
        try:
            raw_forms = await page.evaluate(forms_js)
            return [FormInfo(**f) for f in raw_forms]
        except Exception:
            return []

    async def _extract_links(self, page, base_url: str) -> list:
        """提取页面所有链接"""
        links_js = """
        () => {
            const links = new Set();
            document.querySelectorAll('a[href]').forEach(a => {
                if (a.href && !a.href.startsWith('javascript:') && !a.href.startsWith('#')) {
                    links.add(a.href.split('#')[0]);
                }
            });
            return Array.from(links);
        }
        """
        try:
            links = await page.evaluate(links_js)
            return [urljoin(base_url, l) for l in links if l]
        except Exception:
            return []

    async def _extract_scripts(self, page) -> list:
        """提取所有外部脚本URL"""
        scripts_js = """
        () => {
            const scripts = new Set();
            document.querySelectorAll('script[src]').forEach(s => {
                scripts.add(s.src);
            });
            return Array.from(scripts);
        }
        """
        try:
            return await page.evaluate(scripts_js)
        except Exception:
            return []

    async def _extract_api_from_js(self, page) -> list:
        """从JavaScript代码中提取API端点"""
        endpoints = []
        try:
            # 获取所有内联脚本内容
            js_content = await page.evaluate("""
                () => {
                    let content = '';
                    document.querySelectorAll('script:not([src])').forEach(s => {
                        content += s.textContent + '\\n';
                    });
                    return content;
                }
            """)

            for pattern in self.API_PATTERNS:
                matches = re.findall(pattern, js_content)
                for m in matches:
                    ep = APIEndpoint(
                        url=m if m.startswith("http") else f"extracted:{m}",
                        method="GET",
                        source="js_extract",
                    )
                    if ep not in endpoints:
                        endpoints.append(ep)
        except Exception:
            pass

        return endpoints

    def _is_api_endpoint(self, url: str) -> bool:
        """判断URL是否为API端点"""
        for pattern in self.API_PATTERNS:
            if re.search(pattern, url):
                return True
        return False

    def _is_same_domain(self, base: str, target: str) -> bool:
        """判断是否同域名"""
        try:
            base_domain = urlparse(base).netloc
            target_domain = urlparse(target).netloc
            return base_domain == target_domain or not target_domain
        except Exception:
            return False

    def _detect_tech_stack(self, snapshots: list) -> dict:
        """从页面快照中检测技术栈"""
        all_content = " ".join(
            f"{s.title} {' '.join(s.scripts)} {' '.join(e['url'] for e in s.api_endpoints if isinstance(e, dict))}"
            for s in snapshots
        )

        tech = {"frameworks": [], "servers": [], "security": []}

        for category, signatures in self.TECH_SIGNATURES.items():
            for tech_name, patterns in signatures.items():
                for pattern in patterns:
                    if pattern.lower() in all_content.lower():
                        if category == "frameworks":
                            tech["frameworks"].append(tech_name)
                        elif category == "servers":
                            tech["servers"].append(tech_name)
                        elif category == "security":
                            tech["security"].append(tech_name)
                        break

        return tech

    def to_dict(self) -> dict:
        """导出结果为字典"""
        return {
            "base_url": self._result.base_url,
            "pages_discovered": self._result.pages_discovered,
            "forms_count": len(self._result.forms_found),
            "api_endpoints_count": len(self._result.api_endpoints),
            "links_count": len(self._result.links),
            "tech_stack": self._result.tech_stack,
            "forms": [f.__dict__ if hasattr(f, '__dict__') else f for f in self._result.forms_found],
            "api_endpoints": [e.__dict__ if hasattr(e, '__dict__') else e for e in self._result.api_endpoints],
            "errors": self._result.errors,
        }


import os  # 补全os导入
