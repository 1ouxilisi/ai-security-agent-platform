# -*- coding: utf-8 -*-
"""sdk_tools.py — 多语言 SDK 与工具库。

能力：
- 生成/下载占位 SDK（Python / JavaScript / Java / Go / Rust）
- Postman / Insomnia 集合导出
- cURL 示例、CLI 工具集成说明
"""

from __future__ import annotations

import time
from typing import Any, Dict, List, Optional


SUPPORTED_LANGUAGES: List[Dict[str, Any]] = [
    {
        "lang": "python",
        "package": "aihacking-sdk",
        "install": "pip install aihacking-sdk",
        "min_version": "3.8",
        "status": "stable",
        "latest_version": "1.4.2",
    },
    {
        "lang": "javascript",
        "package": "@aihacking/sdk",
        "install": "npm install @aihacking/sdk",
        "min_version": "16",
        "status": "stable",
        "latest_version": "1.4.2",
    },
    {
        "lang": "java",
        "package": "com.aihacking:sdk",
        "install": "mvn install:install-file",
        "min_version": "8",
        "status": "stable",
        "latest_version": "1.4.2",
    },
    {
        "lang": "go",
        "package": "github.com/aihacking/sdk-go",
        "install": "go get github.com/aihacking/sdk-go@latest",
        "min_version": "1.19",
        "status": "beta",
        "latest_version": "0.9.0",
    },
    {
        "lang": "rust",
        "package": "aihacking-sdk",
        "install": "cargo add aihacking-sdk",
        "min_version": "1.65",
        "status": "alpha",
        "latest_version": "0.2.1",
    },
]


SDK_EXAMPLES: Dict[str, str] = {
    "python": (
        "from aihacking import Client\n\n"
        "client = Client(api_key='YOUR_KEY')\n"
        "resp = client.scanner.start(target='example.com')\n"
        "print(resp)\n"
    ),
    "javascript": (
        "import { Client } from '@aihacking/sdk';\n\n"
        "const client = new Client({ apiKey: 'YOUR_KEY' });\n"
        "const resp = await client.scanner.start({ target: 'example.com' });\n"
        "console.log(resp);\n"
    ),
    "java": (
        "import com.aihacking.sdk.Client;\n\n"
        "Client client = Client.builder().apiKey(\"YOUR_KEY\").build();\n"
        "Map<String, Object> resp = client.scanner.start(\"example.com\");\n"
    ),
    "go": (
        "package main\n\n"
        "import \"github.com/aihacking/sdk-go\"\n\n"
        "func main() {\n"
        "  c := sdk.NewClient(\"YOUR_KEY\")\n"
        "  resp, _ := c.Scanner.Start(ctx, \"example.com\")\n"
        "  _ = resp\n"
        "}\n"
    ),
    "rust": (
        "use aihacking_sdk::Client;\n\n"
        "#[tokio::main]\n"
        "async fn main() {\n"
        "    let client = Client::new(\"YOUR_KEY\");\n"
        "    let resp = client.scanner.start(\"example.com\").await;\n"
        "}\n"
    ),
}


CURL_SNIPPETS: List[Dict[str, str]] = [
    {
        "name": "登录",
        "cmd": "curl -X POST https://api.example.com/api/v1/auth/login "
               "-H 'Content-Type: application/json' "
               "-d '{\"username\":\"u\",\"password\":\"p\"}'",
    },
    {
        "name": "启动扫描",
        "cmd": "curl -X POST https://api.example.com/api/v1/scanner/start "
               "-H 'X-API-Key: YOUR_KEY' "
               "-H 'Content-Type: application/json' "
               "-d '{\"target\":\"example.com\"}'",
    },
    {
        "name": "查询状态",
        "cmd": "curl https://api.example.com/api/v1/scanner/tsk_xxx/status "
               "-H 'X-API-Key: YOUR_KEY'",
    },
]


class SDKToolsManager:
    """SDK 与工具库管理。"""

    def __init__(self) -> None:
        self.languages: List[Dict[str, Any]] = [dict(x) for x in SUPPORTED_LANGUAGES]
        self.downloads: Dict[str, int] = {
            x["lang"]: 10000 + i * 1377 for i, x in enumerate(self.languages)
        }

    def list_sdks(self) -> List[Dict[str, Any]]:
        out = []
        for x in self.languages:
            item = dict(x)
            item["downloads"] = self.downloads.get(x["lang"], 0)
            out.append(item)
        return out

    def get_sdk(self, lang: str) -> Optional[Dict[str, Any]]:
        for x in self.languages:
            if x["lang"] == lang:
                item = dict(x)
                item["downloads"] = self.downloads.get(lang, 0)
                item["example"] = SDK_EXAMPLES.get(lang, "")
                return item
        return None

    def generate_postman_collection(self) -> Dict[str, Any]:
        return {
            "info": {
                "name": "AI Hacking API Collection",
                "description": "自动生成的 Postman 集合",
                "schema": "https://schema.getpostman.com/json/collection/v2.1.0/collection.json",
            },
            "item": [
                {
                    "name": s["name"],
                    "request": {
                        "method": "POST" if "login" in s["cmd"] or "start" in s["cmd"] else "GET",
                        "header": [{"key": "X-API-Key", "value": "{{api_key}}"}],
                        "url": {"raw": "https://api.example.com", "host": ["api", "example", "com"]},
                    },
                }
                for s in CURL_SNIPPETS
            ],
            "variable": [{"key": "api_key", "value": ""}],
        }

    def generate_insomnia_collection(self) -> Dict[str, Any]:
        return {
            "_type": "export",
            "__export_format": 4,
            "_collection": {
                "name": "AI Hacking API",
                "requests": [
                    {"name": s["name"], "url": "https://api.example.com", "body": {"text": s["cmd"]}}
                    for s in CURL_SNIPPETS
                ],
            },
        }

    def list_curl_examples(self) -> List[Dict[str, str]]:
        return CURL_SNIPPETS

    def cli_integration(self) -> Dict[str, Any]:
        return {
            "cli_name": "aihacking-cli",
            "install": "npm i -g aihacking-cli || pip install aihacking-cli",
            "commands": [
                {"cmd": "aihacking auth login", "desc": "交互式登录"},
                {"cmd": "aihacking scan start --target example.com", "desc": "启动扫描"},
                {"cmd": "aihacking scan status <task_id>", "desc": "查询任务"},
                {"cmd": "aihacking report list", "desc": "列出报告"},
            ],
            "config_file": "~/.aihacking/config.yaml",
        }

    def download(self, lang: str) -> Dict[str, Any]:
        if lang not in self.downloads:
            return {}
        self.downloads[lang] += 1
        sdk = self.get_sdk(lang) or {}
        return {
            "lang": lang,
            "download_url": f"https://cdn.example.com/sdk/{lang}/{sdk.get('latest_version', '1.0.0')}.tar.gz",
            "checksum_sha256": "0" * 64,
            "download_count": self.downloads[lang],
            "mirrors": ["https://mirror1.example.com", "https://mirror2.example.com"],
            "generated_at": time.strftime("%Y-%m-%d %H:%M:%S"),
        }


_sdk_manager: Optional[SDKToolsManager] = None


def get_sdk_manager() -> SDKToolsManager:
    global _sdk_manager
    if _sdk_manager is None:
        _sdk_manager = SDKToolsManager()
    return _sdk_manager
