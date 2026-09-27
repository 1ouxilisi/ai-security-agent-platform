"""
desktop_tools模块，提供相关安全测试功能。

模块功能：
    - 提供相关安全测试功能
    - 支持API调用和命令行使用
    - 与其他模块集成协作

注意事项：
    - 本模块仅用于授权的安全测试
    - 请勿用于非法用途
    - 使用前请确保已获得相关授权
"""
import time
from typing import Dict, Optional, Tuple
from utils.logger import log


class DesktopTools:
    """桌面自动化工具集合"""

    def __init__(self):
        """初始化DesktopTools实例。

        Args:
            self: 类实例。
        """
        self._pyautogui = None
        self._initialized = False

    def _ensure_initialized(self):
        """确保pyautogui已初始化"""
        if not self._initialized:
            import pyautogui
            pyautogui.FAILSAFE = True
            pyautogui.PAUSE = 0.5
            self._pyautogui = pyautogui
            self._initialized = True
            log.info("桌面自动化已初始化")

    def get_screen_size(self) -> Dict:
        """获取屏幕分辨率"""
        try:
            self._ensure_initialized()
            size = self._pyautogui.size()
            return {"width": size.width, "height": size.height}
        except Exception as e:
            log.error(f"获取屏幕尺寸异常: {e}")
            return {"error": str(e)}

    def get_mouse_position(self) -> Dict:
        """获取当前鼠标位置"""
        try:
            self._ensure_initialized()
            pos = self._pyautogui.position()
            return {"x": pos.x, "y": pos.y}
        except Exception as e:
            log.error(f"获取鼠标位置异常: {e}")
            return {"error": str(e)}

    def screenshot(self, filename: Optional[str] = None, region: Optional[Tuple[int, int, int, int]] = None) -> Dict:
        """屏幕截图，region: (x, y, width, height)"""
        try:
            self._ensure_initialized()
            from config.settings import settings
            from utils.helpers import ensure_dir, sanitize_filename
            screenshot_dir = ensure_dir(settings.desktop.screenshot_dir)
            if filename is None:
                filename = f"desktop_{int(time.time())}.png"
            filename = sanitize_filename(filename)
            filepath = screenshot_dir / filename
            if region:
                img = self._pyautogui.screenshot(region=region)
            else:
                img = self._pyautogui.screenshot()
            img.save(str(filepath))
            log.info(f"桌面截图已保存: {filepath}")
            return {"screenshot_path": str(filepath), "region": region, "screen_size": self.get_screen_size()}
        except Exception as e:
            log.error(f"桌面截图异常: {e}")
            return {"error": str(e)}

    def move_mouse(self, x: int, y: int, duration: Optional[float] = None) -> Dict:
        """移动鼠标到指定坐标"""
        try:
            self._ensure_initialized()
            from config.settings import settings
            dur = duration if duration is not None else settings.desktop.mouse_duration
            self._pyautogui.moveTo(x, y, duration=dur)
            log.info(f"鼠标移动到: ({x}, {y})")
            return {"target_x": x, "target_y": y, "moved": True}
        except Exception as e:
            log.error(f"鼠标移动异常: {e}")
            return {"error": str(e)}

    def click(self, x: Optional[int] = None, y: Optional[int] = None, button: str = "left", clicks: int = 1) -> Dict:
        """鼠标点击，x,y不填则点击当前位置"""
        try:
            self._ensure_initialized()
            if x is not None and y is not None:
                self._pyautogui.click(x, y, button=button, clicks=clicks)
            else:
                self._pyautogui.click(button=button, clicks=clicks)
            log.info(f"鼠标点击: ({x}, {y}), button={button}")
            return {"clicked": True, "button": button, "clicks": clicks}
        except Exception as e:
            log.error(f"鼠标点击异常: {e}")
            return {"error": str(e)}

    def type_text(self, text: str, interval: float = 0.05) -> Dict:
        """键盘输入文本，会输入到当前焦点应用"""
        try:
            self._ensure_initialized()
            self._pyautogui.typewrite(text, interval=interval)
            log.info(f"键盘输入: {text[:50]}...")
            return {"typed": True, "text_length": len(text)}
        except Exception as e:
            log.error(f"键盘输入异常: {e}")
            return {"error": str(e)}

    def press_key(self, key: str, presses: int = 1, interval: float = 0.25) -> Dict:
        """按下单个按键: enter, tab, esc, space, up, down, f1-f12等"""
        try:
            self._ensure_initialized()
            self._pyautogui.press(key, presses=presses, interval=interval)
            log.info(f"按键: {key}")
            return {"pressed": True, "key": key, "presses": presses}
        except Exception as e:
            log.error(f"按键异常: {e}")
            return {"error": str(e)}

    def hotkey(self, *keys: str) -> Dict:
        """组合键，例如 hotkey('ctrl', 'c')"""
        try:
            self._ensure_initialized()
            self._pyautogui.hotkey(*keys)
            log.info(f"组合键: {'+'.join(keys)}")
            return {"hotkey": "+".join(keys), "pressed": True}
        except Exception as e:
            log.error(f"组合键异常: {e}")
            return {"error": str(e)}

    def locate_on_screen(self, image_path: str, confidence: Optional[float] = None) -> Dict:
        """在屏幕上查找图片位置，需要opencv-python"""
        try:
            self._ensure_initialized()
            from config.settings import settings
            conf = confidence if confidence is not None else settings.desktop.confidence
            location = self._pyautogui.locateOnScreen(image_path, confidence=conf)
            if location:
                center = self._pyautogui.center(location)
                return {"found": True, "image": image_path, "position": {"x": center.x, "y": center.y}, "box": {"left": location.left, "top": location.top, "width": location.width, "height": location.height}}
            else:
                return {"found": False, "image": image_path, "message": "未在屏幕上找到该图片"}
        except Exception as e:
            log.error(f"图像识别异常: {e}")
            return {"error": str(e)}

    def scroll(self, amount: int, x: Optional[int] = None, y: Optional[int] = None) -> Dict:
        """鼠标滚轮滚动，正数向上，负数向下"""
        try:
            self._ensure_initialized()
            if x is not None and y is not None:
                self._pyautogui.scroll(amount, x=x, y=y)
            else:
                self._pyautogui.scroll(amount)
            log.info(f"滚轮滚动: {amount}")
            return {"scrolled": True, "amount": amount}
        except Exception as e:
            log.error(f"滚轮滚动异常: {e}")
            return {"error": str(e)}

    def drag_and_drop(self, start_x: int, start_y: int, end_x: int, end_y: int, duration: float = 0.5) -> Dict:
        """拖拽操作"""
        try:
            self._ensure_initialized()
            self._pyautogui.moveTo(start_x, start_y)
            self._pyautogui.dragTo(end_x, end_y, duration=duration, button="left")
            log.info(f"拖拽: ({start_x},{start_y}) -> ({end_x},{end_y})")
            return {"dragged": True, "from": [start_x, start_y], "to": [end_x, end_y]}
        except Exception as e:
            log.error(f"拖拽异常: {e}")
            return {"error": str(e)}


desktop_tools = DesktopTools()
