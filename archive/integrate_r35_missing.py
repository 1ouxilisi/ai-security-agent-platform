"""
第35轮集成脚本：注入4个方向的路由到app.py
方向1: fp_optimizer_pro (误报率优化Pro)
方向3: llm_ultra (LLM极致)
方向4: commercial_ultra (商业极致)
方向5: performance_ultra_pro (性能极致Pro)
"""
import re
import sys

APP_PATH = r'E:\BaiduNetdiskDownload\yuanbao\ai-hacking-agent\api_server\app.py'

# 要注入的代码块
INJECT_BLOCK = '''
# ============================================
# 第35轮升级路由注入（误报率优化Pro + LLM极致 + 商业极致 + 性能极致Pro）
# ============================================
try:
    from api_server.fp_optimizer_pro_routes import router as fp_opt_pro_router
    app.include_router(fp_opt_pro_router)
    print("第35轮 误报率优化Pro路由已注册")
except Exception as e:
    print(f"第35轮 误报率优化Pro路由注册失败: {e}")

try:
    from api_server.llm_ultra_routes import router as llm_ultra_router
    app.include_router(llm_ultra_router)
    print("第35轮 LLM极致路由已注册")
except Exception as e:
    print(f"第35轮 LLM极致路由注册失败: {e}")

try:
    from api_server.commercial_ultra_routes import router as commercial_ultra_router
    app.include_router(commercial_ultra_router)
    print("第35轮 商业极致路由已注册")
except Exception as e:
    print(f"第35轮 商业极致路由注册失败: {e}")

try:
    from api_server.performance_ultra_pro_routes import router as perf_ultra_pro_router
    app.include_router(perf_ultra_pro_router)
    print("第35轮 性能极致Pro路由已注册")
except Exception as e:
    print(f"第35轮 性能极致Pro路由注册失败: {e}")

# 第35轮前端页面注册
try:
    _PAGES_R35 = [
        ("/fp-optimizer-pro", "fp_optimizer_pro_console.html"),
        ("/llm-ultra", "llm_ultra_console.html"),
        ("/commercial-ultra", "commercial_ultra_console.html"),
        ("/performance-ultra-pro", "performance_ultra_pro_console.html"),
    ]
    for _path, _file in _PAGES_R35:
        try:
            @app.get(_path, include_in_schema=False)
            async def _r35_page():
                from pathlib import Path
                from fastapi.responses import HTMLResponse
                _html = Path(__file__).parent / _file
                if _html.exists():
                    return HTMLResponse(_html.read_text(encoding='utf-8'))
                return HTMLResponse(f"<h1>Page not found: {_file}</h1>", status_code=404)
        except Exception:
            pass
    print("第35轮 前端页面已注册: /fp-optimizer-pro /llm-ultra /commercial-ultra /performance-ultra-pro")
except Exception as e:
    print(f"第35轮 前端页面注册失败: {e}")
'''

def main():
    with open(APP_PATH, 'r', encoding='utf-8') as f:
        content = f.read()
    
    # 检查是否已经注入过
    if '第35轮升级路由注入' in content:
        print("第35轮路由已注入，跳过")
        return
    
    # 找到注入点：在"全局异常处理器"之前注入
    # 或者在文件末尾的最后一个路由注册之后
    # 我们找一个稳定的注入点：在 "# 全局异常处理器" 之前
    inject_marker = '# 全局异常处理器'
    if inject_marker in content:
        content = content.replace(inject_marker, INJECT_BLOCK + '\n' + inject_marker)
        print(f"已在 '{inject_marker}' 前注入第35轮路由")
    else:
        # 如果找不到标记，就在文件末尾注入
        content += '\n' + INJECT_BLOCK
        print("已在文件末尾注入第35轮路由")
    
    with open(APP_PATH, 'w', encoding='utf-8') as f:
        f.write(content)
    
    print("app.py 更新完成")

if __name__ == '__main__':
    main()
