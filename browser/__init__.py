"""
Playwright浏览器自动化模块 - Web安全测试与动态侦察
对标Shannon的Playwright动态侦察基础设施

核心能力：
- browser_manager: 浏览器生命周期管理（无头/代理/上下文隔离）
- dynamic_crawler: 动态爬虫（JS渲染页面发现、表单提取、API端点发现）
- vuln_validator: 动态漏洞验证（No Exploit No Report原则）
- attack_surface_mapper: 攻击面映射汇总

使用示例：
    import asyncio
    from browser import BrowserManager, DynamicCrawler, DynamicVulnValidator, AttackSurfaceMapper

    async def main():
        bm = BrowserManager()
        await bm.start()

        # 动态爬取
        crawler = DynamicCrawler(bm, max_pages=20)
        crawl_result = await crawler.crawl("https://target.com")

        # 漏洞验证
        validator = DynamicVulnValidator(bm)
        val_results = []
        for page_url in [s.url for s in crawl_result.page_snapshots[:5]]:
            vr = await validator.validate_url(page_url)
            val_results.append(vr)

        # 攻击面映射
        mapper = AttackSurfaceMapper()
        surface = mapper.map(crawl_result, val_results)
        print(mapper.to_json())

        await bm.close()

    asyncio.run(main())
"""

from .browser_manager import (
    BrowserManager,
    BrowserConfig,
    PageSnapshot,
    check_playwright_installed,
    sync_check,
    HAS_PLAYWRIGHT,
)

from .dynamic_crawler import (
    DynamicCrawler,
    CrawlResult,
    FormInfo,
    APIEndpoint,
)

from .vuln_validator import (
    DynamicVulnValidator,
    ValidationResult,
    VulnProof,
)

from .attack_surface_mapper import (
    AttackSurfaceMapper,
    AttackSurface,
)

__all__ = [
    # 浏览器管理
    "BrowserManager",
    "BrowserConfig",
    "PageSnapshot",
    "check_playwright_installed",
    "sync_check",
    "HAS_PLAYWRIGHT",
    # 动态爬虫
    "DynamicCrawler",
    "CrawlResult",
    "FormInfo",
    "APIEndpoint",
    # 漏洞验证
    "DynamicVulnValidator",
    "ValidationResult",
    "VulnProof",
    # 攻击面映射
    "AttackSurfaceMapper",
    "AttackSurface",
]

__version__ = "1.0.0"
