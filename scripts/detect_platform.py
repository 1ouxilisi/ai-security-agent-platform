"""
detect_platform脚本工具模块，提供相关的命令行工具和自动化脚本。

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

platforms = [
    ('DeepSeek', 'https://api.deepseek.com/v1', 'deepseek-chat'),
    ('智谱AI', 'https://open.bigmodel.cn/api/paas/v4', 'glm-4-flash'),
    ('月之暗面', 'https://api.moonshot.cn/v1', 'moonshot-v1-8k'),
    ('通义千问', 'https://dashscope.aliyuncs.com/compatible-mode/v1', 'qwen-turbo'),
    ('硅基流动', 'https://api.siliconflow.cn/v1', 'deepseek-ai/DeepSeek-V3'),
    ('一起AI', 'https://api.yi-ai.cn/v1', 'yi-large'),
    ('OpenAI', 'https://api.openai.com/v1', 'gpt-3.5-turbo'),
    ('百度千帆', 'https://qianfan.baidubce.com/v2', 'ernie-turbo'),
]

for name, base_url, model in platforms:
    try:
        client = OpenAI(api_key=api_key, base_url=base_url, timeout=10)
        response = client.chat.completions.create(
            model=model,
            messages=[{'role': 'user', 'content': 'hi'}],
            max_tokens=10
        )
        print(f'✅ {name} 可用！模型: {model}, 响应: {response.choices[0].message.content[:30]}')
        print(f'   base_url: {base_url}')
        print(f'   model: {model}')
        break
    except Exception as e:
        err = str(e)
        if '401' in err or 'authentication' in err.lower() or 'Invalid API' in err:
            print(f'❌ {name}: 认证失败（密钥不匹配）')
        elif '404' in err or 'not found' in err.lower() or 'model' in err.lower():
            print(f'⚠️  {name}: 连接成功但模型不对，尝试其他模型...')
            # 尝试列出模型
            try:
                client = OpenAI(api_key=api_key, base_url=base_url, timeout=10)
                models = client.models.list()
                model_list = [m.id for m in models.data[:5]]
                print(f'   可用模型: {model_list}')
            except:
                pass
        elif 'timeout' in err.lower() or 'connect' in err.lower():
            print(f'⏱️  {name}: 连接超时')
        else:
            print(f'❓ {name}: {err[:60]}')
