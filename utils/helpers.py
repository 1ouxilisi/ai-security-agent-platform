"""
helpers工具函数模块，提供通用的辅助函数和工具类。

模块功能：
    - 提供相关安全测试功能
    - 支持API调用和命令行使用
    - 与其他模块集成协作

注意事项：
    - 本模块仅用于授权的安全测试
    - 请勿用于非法用途
    - 使用前请确保已获得相关授权
"""
import re
import json
import time
import hashlib
from pathlib import Path
from typing import Any, Dict, List, Optional
from urllib.parse import urlparse
from utils.logger import log
from config.settings import settings


def validate_target(target: str) -> bool:
    """
        验证目标是否在授权白名单内
        安全核心函数：防止扫描未授权目标
    """
    if not target:
        return False

    # 提取主机名
    try:
        parsed = urlparse(target)
        host = parsed.hostname or target
    except Exception:
        host = target

    # 检查白名单
    for allowed in settings.security.allowed_targets:
        if allowed.startswith("*."):
            # 通配符域名匹配
            domain = allowed[2:]
            if host.endswith(domain) or host == domain:
                return True
        elif host == allowed:
            return True

    log.warning(f"目标 {target} 不在授权白名单内，已拒绝")
    return False


def rate_limit():
    """简单的速率限制装饰器"""
    last_call = {"time": 0}

    def decorator(func):
        """或...。

            Args:
            func: 相关参数。

            Returns:
            操作结果。
        """
        def wrapper(*args, **kwargs):
            """执行相关操作。

                Returns:
                操作结果。
            """
            elapsed = time.time() - last_call["time"]
            if elapsed < settings.security.scan_rate_limit:
                time.sleep(settings.security.scan_rate_limit - elapsed)
            last_call["time"] = time.time()
            return func(*args, **kwargs)
        return wrapper
    return decorator


def save_json(data: Any, filepath: str) -> None:
    """保存JSON数据到文件"""
    path = Path(filepath)
    path.parent.mkdir(parents=True, exist_ok=True)
    with open(path, "w", encoding="utf-8") as f:
        json.dump(data, f, ensure_ascii=False, indent=2)
    log.info(f"数据已保存到 {filepath}")


def load_json(filepath: str) -> Any:
    """从文件加载JSON数据"""
    with open(filepath, "r", encoding="utf-8") as f:
        return json.load(f)


def generate_id(prefix: str = "task") -> str:
    """生成唯一任务ID"""
    timestamp = int(time.time() * 1000)
    random_hash = hashlib.md5(str(time.time()).encode()).hexdigest()[:8]
    return f"{prefix}_{timestamp}_{random_hash}"


def extract_urls(text: str) -> List[str]:
    """从文本中提取URL"""
    url_pattern = re.compile(
        r'https?://(?:[-\w.]|(?:%[\da-fA-F]{2}))+[/\w\-._~:/?#[\]@!$&\'()*+,;=]*'
    )
    return url_pattern.findall(text)


def sanitize_filename(filename: str) -> str:
    """清理文件名，防止路径遍历"""
    filename = re.sub(r'[<>:"/\\|?*]', '_', filename)
    filename = filename.strip('. ')
    return filename[:200] if len(filename) > 200 else filename


def truncate_text(text: str, max_length: int = 500) -> str:
    """截断长文本，用于日志输出"""
    if len(text) <= max_length:
        return text
    return text[:max_length] + f"... [截断，共{len(text)}字符]"


def format_duration(seconds: float) -> str:
    """格式化时长显示"""
    if seconds < 60:
        return f"{seconds:.1f}秒"
    elif seconds < 3600:
        return f"{seconds/60:.1f}分钟"
    else:
        return f"{seconds/3600:.1f}小时"


def ensure_dir(path: str) -> Path:
    """确保目录存在，返回Path对象"""
    p = Path(path)
    p.mkdir(parents=True, exist_ok=True)
    return p
