"""
browser_tools模块，提供相关安全测试功能。

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
import time
from typing import Dict, Optional
from utils.logger import log
from utils.helpers import validate_target


class BrowserTools:
    """浏览器自动化工具集合"""

    def __init__(self):
        """初始化BrowserTools实例。

        Args:
            self: 类实例。
        """
        self.browser = None
        self.context = None
        self.page = None
        self._playwright = None
        self._initialized = False

    async def _ensure_browser(self):
        """确保浏览器已启动"""
        if not self._initialized:
            from playwright.async_api import async_playwright
            from config.settings import settings
            self._playwright = await async_playwright().start()
            self.browser = await self._playwright.chromium.launch(
                headless=settings.playwright.headless,
                slow_mo=settings.playwright.slow_mo,
            )
            self.context = await self.browser.new_context(
                user_agent="Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"
            )
            self.page = await self.context.new_page()
            self.page.set_default_timeout(settings.playwright.timeout)
            self._initialized = True
            log.info("浏览器已启动")

    async def navigate(self, url: str) -> Dict:
        """导航到指定URL"""
        if not validate_target(url):
            return {"error": "目标不在授权白名单内，操作已拒绝"}
        try:
            await self._ensure_browser()
            log.info(f"浏览器导航: {url}")
            response = await self.page.goto(url, wait_until="domcontentloaded")
            try:
                await self.page.wait_for_load_state("networkidle", timeout=10000)
            except Exception:
                pass
            result = {
                "url": self.page.url,
                "title": await self.page.title(),
                "status_code": response.status if response else None,
                "content_length": len(await self.page.content()),
            }
            log.info(f"页面加载完成: {result['title']}")
            return result
        except Exception as e:
            log.error(f"浏览器导航异常: {e}")
            return {"url": url, "error": str(e)}

    async def take_screenshot(self, filename: Optional[str] = None, full_page: bool = True) -> Dict:
        """页面截图"""
        try:
            await self._ensure_browser()
            from config.settings import settings
            from utils.helpers import ensure_dir, sanitize_filename
            screenshot_dir = ensure_dir(settings.desktop.screenshot_dir)
            if filename is None:
                filename = f"page_{int(time.time())}.png"
            filename = sanitize_filename(filename)
            filepath = screenshot_dir / filename
            await self.page.screenshot(path=str(filepath), full_page=full_page)
            log.info(f"截图已保存: {filepath}")
            return {"screenshot_path": str(filepath), "full_page": full_page, "url": self.page.url}
        except Exception as e:
            log.error(f"截图异常: {e}")
            return {"error": str(e)}

    async def get_page_content(self) -> Dict:
        """获取页面HTML内容"""
        try:
            await self._ensure_browser()
            content = await self.page.content()
            return {"url": self.page.url, "title": await self.page.title(), "content_length": len(content), "content_preview": content[:2000]}
        except Exception as e:
            log.error(f"获取页面内容异常: {e}")
            return {"error": str(e)}

    async def extract_links(self) -> Dict:
        """提取页面所有链接"""
        try:
            await self._ensure_browser()
            links = await self.page.eval_on_selector_all("a[href]", "elements => elements.map(e => ({text: e.textContent.trim(), href: e.href}))")
            unique_links = []
            seen = set()
            for link in links:
                if link["href"] not in seen:
                    seen.add(link["href"])
                    unique_links.append(link)
            return {"url": self.page.url, "total_links": len(links), "unique_links": len(unique_links), "links": unique_links[:50]}
        except Exception as e:
            log.error(f"提取链接异常: {e}")
            return {"error": str(e)}

    async def extract_forms(self) -> Dict:
        """提取页面所有表单"""
        try:
            await self._ensure_browser()
            forms = await self.page.eval_on_selector_all("form", """elements => elements.map(f => ({action: f.action, method: f.method, id: f.id, name: f.name, inputs: Array.from(f.querySelectorAll('input, select, textarea')).map(i => ({type: i.type, name: i.name, id: i.id, placeholder: i.placeholder}))}))""")
            return {"url": self.page.url, "form_count": len(forms), "forms": forms}
        except Exception as e:
            log.error(f"提取表单异常: {e}")
            return {"error": str(e)}

    async def fill_form(self, selector: str, value: str) -> Dict:
        """填写表单字段"""
        try:
            await self._ensure_browser()
            await self.page.fill(selector, value)
            log.info(f"表单填写: {selector}")
            return {"selector": selector, "filled": True}
        except Exception as e:
            log.error(f"表单填写异常: {e}")
            return {"selector": selector, "error": str(e)}

    async def click_element(self, selector: str) -> Dict:
        """点击页面元素"""
        try:
            await self._ensure_browser()
            await self.page.click(selector)
            log.info(f"点击元素: {selector}")
            return {"selector": selector, "clicked": True, "current_url": self.page.url}
        except Exception as e:
            log.error(f"点击元素异常: {e}")
            return {"selector": selector, "error": str(e)}

    async def evaluate_script(self, script: str) -> Dict:
        """在页面执行JavaScript"""
        try:
            await self._ensure_browser()
            result = await self.page.evaluate(script)
            log.info("JS执行完成")
            return {"script": script[:100], "result": str(result)[:1000]}
        except Exception as e:
            log.error(f"JS执行异常: {e}")
            return {"error": str(e)}

    async def close(self):
        """关闭浏览器"""
        if self._initialized:
            await self.browser.close()
            await self._playwright.stop()
            self._initialized = False
            log.info("浏览器已关闭")


browser_tools = BrowserTools()
