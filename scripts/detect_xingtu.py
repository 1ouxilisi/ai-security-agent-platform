"""
detect_xingtu脚本工具模块，提供相关的命令行工具和自动化脚本。

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
from dotenv import load_dotenv
load_dotenv()
from openai import OpenAI

api_key = os.getenv('LLM_API_KEY')
print(f'测试密钥: {api_key[:10]}...{api_key[-6:]}')
print()

# 可能的星图AI/星途AI平台地址
platforms = [
    ('星图AI xingtu.xyz', 'https://api.xingtu.xyz/v1', 'gpt-4o-mini'),
    ('星途AI aimodelhub', 'https://api.aimodelhub.cn/v1', 'gpt-4o-mini'),
    ('星图云 geovisearth', 'https://api.open.geovisearth.com/pj/v1', 'MiniMax-M2.5'),
    ('星辰TokenHub ctyun', 'https://ai.ctaigw.cn/v1', 'GLM-5'),
    ('星辰wishub', 'https://wishub-x6.ctyun.cn/v1', 'GLM-5'),
    ('OpenClaw官方', 'https://api.openclaw.ai/v1', 'gpt-4o-mini'),
    ('星图AI xingtuai', 'https://api.xingtuai.com/v1', 'gpt-4o-mini'),
    ('星途AI xingtui', 'https://api.xingtui.ai/v1', 'gpt-4o-mini'),
]

for name, base_url, model in platforms:
    try:
        client = OpenAI(api_key=api_key, base_url=base_url, timeout=8)
        # 先尝试列出模型
        try:
            models = client.models.list()
            model_list = [m.id for m in models.data[:8]]
            print(f'✅ {name} 连接成功！可用模型: {model_list}')
            print(f'   base_url: {base_url}')
            # 用第一个模型测试
            if model_list:
                test_model = model_list[0]
                response = client.chat.completions.create(
                    model=test_model,
                    messages=[{'role': 'user', 'content': 'hi'}],
                    max_tokens=10
                )
                print(f'   测试模型 {test_model}: {response.choices[0].message.content[:30]}')
            break
        except:
            # 列模型失败，直接试聊天
            response = client.chat.completions.create(
                model=model,
                messages=[{'role': 'user', 'content': 'hi'}],
                max_tokens=10
            )
            print(f'✅ {name} 可用！模型: {model}, 响应: {response.choices[0].message.content[:30]}')
            print(f'   base_url: {base_url}')
            break
    except Exception as e:
        err = str(e)
        if '401' in err or 'authentication' in err.lower() or 'Invalid API' in err:
            print(f'❌ {name}: 认证失败')
        elif 'timeout' in err.lower() or 'connect' in err.lower():
            print(f'⏱️  {name}: 连接超时')
        elif '404' in err:
            print(f'⚠️  {name}: 404（地址可能不对）')
        else:
            print(f'❓ {name}: {err[:50]}')
