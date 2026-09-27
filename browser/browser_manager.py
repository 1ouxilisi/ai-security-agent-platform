"""
浏览器管理器 - Playwright浏览器生命周期管理
支持无头/有头模式、代理配置、上下文隔离、Cookie管理
对标Shannon的Playwright动态侦察基础设施
"""
import asyncio
import json
import os
from dataclasses import dataclass, field
from typing import Optional

try:
    from playwright.async_api import async_playwright, Browser, BrowserContext, Page
    HAS_PLAYWRIGHT = True
except ImportError:
    HAS_PLAYWRIGHT = False


@dataclass
class BrowserConfig:
    """浏览器配置"""
    headless: bool = True
    proxy: Optional[str] = None  # http://user:pass@host:port
    user_agent: str = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/125.0.0.0 Safari/537.36"
    viewport_width: int = 1920
    viewport_height: int = 1080
    timeout: int = 30000  # 毫秒
    ignore_https_errors: bool = True
    locale: str = "zh-CN"
    extra_headers: dict = field(default_factory=dict)
    max_concurrent_pages: int = 5


@dataclass
class PageSnapshot:
    """页面快照"""
    url: str
    title: str
    status_code: int
    content_length: int
    forms: list = field(default_factory=list)
    links: list = field(default_factory=list)
    scripts: list = field(default_factory=list)
    api_endpoints: list = field(default_factory=list)
    cookies: list = field(default_factory=list)
    screenshot_path: Optional[str] = None
    console_errors: list = field(default_factory=list)
    network_requests: list = field(default_factory=list)
    html_hash: str = ""


class BrowserManager:
    """
    Playwright浏览器管理器
    负责浏览器启动、上下文创建、页面管理、资源回收
    """

    def __init__(self, config: Optional[BrowserConfig] = None):
        self.config = config or BrowserConfig()
        self._playwright = None
        self._browser: Optional[Browser] = None
        self._context: Optional[BrowserContext] = None
        self._pages: list[Page] = []
        self._semaphore: Optional[asyncio.Semaphore] = None

    async def start(self):
        """启动浏览器"""
        if not HAS_PLAYWRIGHT:
            raise RuntimeError(
                "Playwright未安装。请运行: pip install playwright && playwright install chromium"
            )

        self._playwright = await async_playwright().start()

        launch_args = {
            "headless": self.config.headless,
            "args": [
                "--no-sandbox",
                "--disable-blink-features=AutomationControlled",
                "--disable-dev-shm-usage",
            ],
        }

        if self.config.proxy:
            launch_args["proxy"] = {"server": self.config.proxy}

        self._browser = await self._playwright.chromium.launch(**launch_args)

        context_args = {
            "user_agent": self.config.user_agent,
            "viewport": {
                "width": self.config.viewport_width,
                "height": self.config.viewport_height,
            },
            "ignore_https_errors": self.config.ignore_https_errors,
            "locale": self.config.locale,
            "extra_http_headers": self.config.extra_headers,
        }

        self._context = await self._browser.new_context(**context_args)
        self._context.set_default_timeout(self.config.timeout)
        self._semaphore = asyncio.Semaphore(self.config.max_concurrent_pages)

        return self

    async def new_page(self) -> Page:
        """创建新页面（带并发控制）"""
        if not self._context:
            raise RuntimeError("浏览器未启动，请先调用start()")

        await self._semaphore.acquire()
        page = await self._context.new_page()
        self._pages.append(page)
        return page

    async def release_page(self, page: Page):
        """释放页面"""
        if page in self._pages:
            self._pages.remove(page)
        try:
            await page.close()
        except Exception:
            pass
        self._semaphore.release()

    async def navigate(self, url: str, wait_until: str = "networkidle") -> Page:
        """导航到URL并返回页面"""
        page = await self.new_page()
        try:
            await page.goto(url, wait_until=wait_until, timeout=self.config.timeout)
        except Exception as e:
            # 即使超时也保留页面，可能有部分内容加载
            print(f"[BrowserManager] 导航警告: {url} - {e}")
        return page

    async def get_cookies(self) -> list:
        """获取当前上下文所有Cookie"""
        if not self._context:
            return []
        return await self._context.cookies()

    async def set_cookies(self, cookies: list):
        """设置Cookie"""
        if self._context:
            await self._context.add_cookies(cookies)

    async def clear_cookies(self):
        """清除所有Cookie"""
        if self._context:
            await self._context.clear_cookies()

    async def close(self):
        """关闭浏览器并释放资源"""
        for page in self._pages[:]:
            try:
                await page.close()
            except Exception:
                pass
        self._pages.clear()

        if self._context:
            try:
                await self._context.close()
            except Exception:
                pass
            self._context = None

        if self._browser:
            try:
                await self._browser.close()
            except Exception:
                pass
            self._browser = None

        if self._playwright:
            try:
                await self._playwright.stop()
            except Exception:
                pass
            self._playwright = None

    async def __aenter__(self):
        await self.start()
        return self

    async def __aexit__(self, exc_type, exc_val, exc_tb):
        await self.close()


def check_playwright_installed() -> dict:
    """检查Playwright安装状态"""
    result = {
        "playwright_installed": HAS_PLAYWRIGHT,
        "chromium_installed": False,
        "install_command": "pip install playwright && playwright install chromium",
    }

    if HAS_PLAYWRIGHT:
        try:
            # 检查chromium浏览器是否安装
            from playwright._impl._driver import compute_driver_executable
            driver = compute_driver_executable()
            result["driver_path"] = str(driver)
            result["chromium_installed"] = True
        except Exception:
            result["chromium_installed"] = False

    return result


# 同步便捷函数
def sync_check():
    """同步检查Playwright状态"""
    return asyncio.run(check_playwright_installed())


if __name__ == "__main__":
    status = sync_check()
    print(json.dumps(status, indent=2, ensure_ascii=False))
