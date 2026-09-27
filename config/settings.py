"""
settings模块，提供相关安全测试功能。

模块功能：
    - 提供相关安全测试功能
    - 支持API调用和命令行使用
    - 与其他模块集成协作

注意事项：
    - 本模块仅用于授权的安全测试
    - 请勿用于非法用途
    - 使用前请确保已获得相关授权
"""
import os
from pathlib import Path
from typing import List
from dotenv import load_dotenv
from pydantic import BaseModel, Field

# 项目根目录
PROJECT_ROOT = Path(__file__).parent.parent

# 加载 .env 文件
load_dotenv(PROJECT_ROOT / ".env")


class LLMConfig(BaseModel):
    """大模型配置"""
    api_key: str = Field(default="", description="API密钥")
    base_url: str = Field(default="https://api.deepseek.com/v1", description="API基础URL")
    model: str = Field(default="deepseek-chat", description="模型名称")
    temperature: float = Field(default=0.1, description="温度参数")
    max_tokens: int = Field(default=4096, description="最大token数")


class MCPConfig(BaseModel):
    """MCP服务端配置"""
    host: str = Field(default="127.0.0.1", description="监听地址")
    port: int = Field(default=8000, description="监听端口")
    mode: str = Field(default="stdio", description="运行模式: stdio/http")


class PlaywrightConfig(BaseModel):
    """Playwright浏览器配置"""
    headless: bool = Field(default=True, description="无头模式")
    browser: str = Field(default="chromium", description="浏览器类型")
    timeout: int = Field(default=30000, description="超时时间(ms)")
    slow_mo: int = Field(default=0, description="操作延迟(ms)")


class DesktopConfig(BaseModel):
    """桌面自动化配置"""
    screenshot_dir: str = Field(default="./screenshots", description="截图保存目录")
    confidence: float = Field(default=0.8, description="图像匹配置信度")
    mouse_duration: float = Field(default=0.5, description="鼠标移动时长(s)")


class SecurityConfig(BaseModel):
    """安全工具配置"""
    allowed_targets: List[str] = Field(
        default_factory=lambda: ["localhost", "127.0.0.1", "*.test.local"],
        description="授权目标白名单"
    )
    scan_rate_limit: float = Field(default=1.0, description="扫描速率限制(秒/请求)")
    max_concurrency: int = Field(default=5, description="最大并发数")
    rate_limit: float = Field(default=1.0, description="通用速率限制(秒/请求，与 scan_rate_limit 同义)")


class LogConfig(BaseModel):
    """日志配置"""
    level: str = Field(default="INFO", description="日志级别")
    file: str = Field(default="./logs/agent.log", description="日志文件路径")
    retention_days: int = Field(default=30, description="日志保留天数")


class ReportConfig(BaseModel):
    """报告配置"""
    output_dir: str = Field(default="./reports", description="报告输出目录")
    format: str = Field(default="markdown", description="报告格式: markdown/html/json")


class Settings(BaseModel):
    """全局设置"""
    llm: LLMConfig = Field(default_factory=LLMConfig)
    mcp: MCPConfig = Field(default_factory=MCPConfig)
    playwright: PlaywrightConfig = Field(default_factory=PlaywrightConfig)
    desktop: DesktopConfig = Field(default_factory=DesktopConfig)
    security: SecurityConfig = Field(default_factory=SecurityConfig)
    log: LogConfig = Field(default_factory=LogConfig)
    report: ReportConfig = Field(default_factory=ReportConfig)
    project_root: Path = Field(default=PROJECT_ROOT)


def load_settings() -> Settings:
    """从环境变量加载配置"""
    return Settings(
        llm=LLMConfig(
            api_key=os.getenv("LLM_API_KEY", ""),
            base_url=os.getenv("LLM_BASE_URL", "https://api.deepseek.com/v1"),
            model=os.getenv("LLM_MODEL", "deepseek-chat"),
            temperature=float(os.getenv("LLM_TEMPERATURE", "0.1")),
            max_tokens=int(os.getenv("LLM_MAX_TOKENS", "4096")),
        ),
        mcp=MCPConfig(
            host=os.getenv("MCP_SERVER_HOST", "127.0.0.1"),
            port=int(os.getenv("MCP_SERVER_PORT", "8000")),
            mode=os.getenv("MCP_SERVER_MODE", "stdio"),
        ),
        playwright=PlaywrightConfig(
            headless=os.getenv("PLAYWRIGHT_HEADLESS", "true").lower() == "true",
            browser=os.getenv("PLAYWRIGHT_BROWSER", "chromium"),
            timeout=int(os.getenv("PLAYWRIGHT_TIMEOUT", "30000")),
            slow_mo=int(os.getenv("PLAYWRIGHT_SLOW_MO", "0")),
        ),
        desktop=DesktopConfig(
            screenshot_dir=os.getenv("DESKTOP_SCREENSHOT_DIR", "./screenshots"),
            confidence=float(os.getenv("DESKTOP_CONFIDENCE", "0.8")),
            mouse_duration=float(os.getenv("DESKTOP_MOUSE_DURATION", "0.5")),
        ),
        security=SecurityConfig(
            allowed_targets=os.getenv("ALLOWED_TARGETS", "localhost,127.0.0.1").split(","),
            scan_rate_limit=float(os.getenv("SCAN_RATE_LIMIT", "1.0")),
            max_concurrency=int(os.getenv("MAX_CONCURRENCY", "5")),
        ),
        log=LogConfig(
            level=os.getenv("LOG_LEVEL", "INFO"),
            file=os.getenv("LOG_FILE", "./logs/agent.log"),
            retention_days=int(os.getenv("LOG_RETENTION_DAYS", "30")),
        ),
        report=ReportConfig(
            output_dir=os.getenv("REPORT_OUTPUT_DIR", "./reports"),
            format=os.getenv("REPORT_FORMAT", "markdown"),
        ),
    )


# 全局配置实例
settings = load_settings()
