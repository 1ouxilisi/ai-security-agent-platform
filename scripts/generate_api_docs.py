# -*- coding: utf-8 -*-
"""
API 文档自动生成脚本。

从 FastAPI app.openapi() 提取全部端点信息（方法/路径/描述/参数/请求体），
按 tags 分组，生成：
    - docs/API_REFERENCE.md    完整 API 参考（每个端点含方法徽章/路径/描述/参数表/curl 示例）
    - docs/API_QUICKSTART.md   快速参考卡（每模块 2-3 个最常用端点 + 常见任务速查）

用法：
    python scripts/generate_api_docs.py
"""
from __future__ import annotations

import os as _os
_os.environ.setdefault("API_AUTH_ENABLED", "false")
_os.environ.setdefault("API_ENV", "test")

import sys
import json
import time
from pathlib import Path
from collections import OrderedDict, defaultdict

PROJECT_ROOT = Path(__file__).resolve().parent.parent
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

DOCS_DIR = PROJECT_ROOT / "docs"
DOCS_DIR.mkdir(parents=True, exist_ok=True)
REF_PATH = DOCS_DIR / "API_REFERENCE.md"
QS_PATH = DOCS_DIR / "API_QUICKSTART.md"

METHOD_BADGE = {
    "GET": "🟢", "POST": "🔵", "PUT": "🟡",
    "PATCH": "🟣", "DELETE": "🔴",
}


def _escape_md(s: str) -> str:
    return (s or "").replace("|", "\\|").replace("\n", " ").strip()


def _extract_openapi():
    """调用 app.openapi() 拿 OpenAPI schema。"""
    from api_server.app import app
    return app.openapi()


def _param_table(params: list[dict]) -> str:
    if not params:
        return "（无请求参数）\n"
    rows = ["| 参数名 | 位置 | 类型 | 必填 | 说明 |", "|---|---|---|---|---|"]
    for p in params:
        name = p.get("name", "")
        in_ = p.get("in", "")
        sch = p.get("schema", {}) or {}
        ptype = sch.get("type", sch.get("$ref", "any").split("/")[-1])
        required = "✅" if p.get("required") else "—"
        desc = _escape_md(p.get("description", ""))
        rows.append(f"| `{name}` | {in_} | {ptype} | {required} | {desc} |")
    return "\n".join(rows) + "\n"


def _request_body_example(op: dict, schemas: dict) -> str:
    """生成请求体 JSON 示例。"""
    rb = op.get("requestBody", {})
    content = rb.get("content", {})
    for ctype, cval in content.items():
        if "json" not in ctype:
            continue
        sch = cval.get("schema", {})
        # $ref
        if "$ref" in sch:
            ref_name = sch["$ref"].split("/")[-1]
            ref_schema = schemas.get(ref_name, {})
            props = ref_schema.get("properties", {})
            required = set(ref_schema.get("required", []))
            sample = {}
            for k, v in props.items():
                sample[k] = _sample_value(v, k, required)
            return "```json\n" + json.dumps(sample, ensure_ascii=False, indent=2) + "\n```\n"
        # 直接 schema
        props = sch.get("properties", {})
        if props:
            required = set(sch.get("required", []))
            sample = {k: _sample_value(v, k, required) for k, v in props.items()}
            return "```json\n" + json.dumps(sample, ensure_ascii=False, indent=2) + "\n```\n"
    return "（无请求体）\n"


def _sample_value(prop: dict, name: str, required: set) -> object:
    t = prop.get("type", "string")
    if name in ("target", "host", "ip"):
        return "example.com"
    if "id" in name:
        return "xxx-xxx"
    if t == "integer":
        return 1 if name in required else 0
    if t == "number":
        return 0.0
    if t == "boolean":
        return True
    if t == "array":
        return []
    if t == "object":
        return {}
    return "string"


def _curl_example(method: str, path: str, op: dict) -> str:
    url = "http://<host>" + path
    lines = [f"curl -X {method} '{url}' \\",
             f"  -H 'X-API-Key: $API_KEY' \\",
             f"  -H 'Content-Type: application/json'"]
    rb = op.get("requestBody", {})
    if rb:
        body = _request_body_example(op, {})
        # 提取 json 代码块内容
        if "```json" in body:
            inner = body.split("```json")[1].split("```")[0].strip()
            # 缩进 JSON 每一行，便于 curl -d 拼接
            indented = inner.replace("\n", "\n  ")
            lines.append("  -d '" + indented + "'")
    return "```bash\n" + " \\\n".join(lines) + "\n```\n"


def _short_desc(op: dict) -> str:
    s = op.get("summary") or op.get("description") or ""
    return s.split("\n")[0].strip()


def build_reference(spec: dict) -> str:
    """生成完整 API_REFERENCE.md。"""
    paths = spec.get("paths", {})
    schemas = spec.get("components", {}).get("schemas", {})
    info = spec.get("info", {})

    # 按 tag 分组
    grouped: dict[str, list[tuple]] = defaultdict(list)
    total_endpoints = 0
    for path, path_item in paths.items():
        for method, op in path_item.items():
            if method.upper() not in ("GET", "POST", "PUT", "PATCH", "DELETE"):
                continue
            total_endpoints += 1
            tags = op.get("tags") or ["其他"]
            primary = tags[0]
            grouped[primary].append((method.upper(), path, op))

    out = []
    out.append(f"# {info.get('title', 'API')} 参考文档\n")
    out.append(f"> 自动生成时间：{time.strftime('%Y-%m-%d %H:%M:%S')}  ")
    out.append(f"> 版本：{info.get('version', 'N/A')}  ")
    out.append(f"> 端点总数：**{total_endpoints}**  \n")

    out.append("## 通用说明\n")
    out.append("- **基础 URL**：`http://<host>:<port>`（本地默认 `http://127.0.0.1:8000`）")
    out.append("- **认证方式**：在请求头中携带 `X-API-Key: <API_AUTH_KEY>`")
    out.append("- **请求格式**：JSON（`Content-Type: application/json`）")
    out.append("- **响应格式**：统一 JSON，错误时 `{\"detail\": \"...\"}`")
    out.append("- **错误码**：200 成功 / 400 参数错误 / 401 未认证 / 403 无权限 / 404 不存在 / 422 校验失败 / 500 服务器错误\n")

    # 目录
    out.append("## 目录\n")
    for tag in sorted(grouped.keys()):
        anchor = tag.lower().replace(" ", "-")
        out.append(f"- [{tag}](#{anchor})（{len(grouped[tag])} 个端点）")
    out.append("")

    # 各模块
    for tag in sorted(grouped.keys()):
        out.append(f"\n## {tag}\n")
        out.append(f"本模块共 {len(grouped[tag])} 个端点。\n")
        for method, path, op in grouped[tag]:
            badge = METHOD_BADGE.get(method, "⚪")
            desc = _short_desc(op)
            out.append(f"### {badge} `{method} {path}`")
            if desc:
                out.append(f"\n{desc}\n")
            # 参数表
            out.append("**请求参数：**\n")
            out.append(_param_table(op.get("parameters", [])))
            # 请求体
            if op.get("requestBody"):
                out.append("**请求体示例：**\n")
                out.append(_request_body_example(op, schemas))
            # curl
            out.append("**调用示例：**\n")
            out.append(_curl_example(method, path, op))
    return "\n".join(out)


def build_quickstart(spec: dict) -> str:
    """生成 API_QUICKSTART.md。"""
    paths = spec.get("paths", {})
    grouped: dict[str, list[tuple]] = defaultdict(list)
    for path, path_item in paths.items():
        for method, op in path_item.items():
            if method.upper() not in ("GET", "POST", "PUT", "PATCH", "DELETE"):
                continue
            tags = op.get("tags") or ["其他"]
            grouped[tags[0]].append((method.upper(), path, op))

    out = ["# API 快速参考卡\n",
           f"> 自动生成时间：{time.strftime('%Y-%m-%d %H:%M:%S')}\n",
           "## 常用端点速查\n"]

    picked = 0
    for tag in sorted(grouped.keys()):
        eps = grouped[tag]
        # 每模块选 2-3 个：优先 GET 状态/列表类
        prefer = sorted(eps, key=lambda x: (0 if x[0] == "GET" else 1, len(x[1])))[:3]
        out.append(f"\n### {tag}\n")
        for method, path, op in prefer:
            badge = METHOD_BADGE.get(method, "⚪")
            desc = _short_desc(op) or "—"
            out.append(f"- {badge} `{method} {path}` — {desc}")
            out.append(f"  ```bash\n  curl -X {method} 'http://<host>{path}' -H 'X-API-Key: $API_KEY'\n  ```")
            picked += 1

    out.append("\n## 常见任务\n")
    out.append("- **开始一次扫描**：`POST /api/v1/tasks`，body 传 `{\"target\": \"example.com\", \"task_type\": \"scan\"}`")
    out.append("- **查询任务状态**：`GET /api/v1/tasks/{task_id}`")
    out.append("- **查看任务结果**：`GET /api/v1/tasks/{task_id}/result`")
    out.append("- **调用工具**：`POST /api/v1/tools/call`，body 传 `{\"tool_name\": \"nmap\", \"parameters\": {}}`")
    out.append("- **生成报告**：`POST /api/v1/reports/generate`，body 传 `{\"task_id\": \"...\"}`")
    out.append("- **知识库 CVE 查询**：`GET /api/v1/knowledge/cve?keyword=openssl`")
    out.append("- **健康检查**：`GET /health`（无需认证）\n")
    out.append(f"\n> 共选取 {picked} 个常用端点，完整参考见 [API_REFERENCE.md](./API_REFERENCE.md)")
    return "\n".join(out)


def main():
    print("=== API 文档生成开始 ===")
    try:
        spec = _extract_openapi()
    except Exception as e:  # noqa: BLE001
        print(f"✗ 提取 OpenAPI 失败: {e}")
        import traceback; traceback.print_exc()
        return 1

    n_paths = len(spec.get("paths", {}))
    n_ops = sum(
        1 for p in spec.get("paths", {}).values()
        for m in p if m.upper() in ("GET", "POST", "PUT", "PATCH", "DELETE")
    )
    print(f"发现 {n_paths} 条路径，{n_ops} 个操作")

    ref_md = build_reference(spec)
    qs_md = build_quickstart(spec)
    REF_PATH.write_text(ref_md, encoding="utf-8")
    QS_PATH.write_text(qs_md, encoding="utf-8")
    print(f"✓ 完整参考: {REF_PATH}  ({len(ref_md)} 字符)")
    print(f"✓ 快速参考: {QS_PATH}  ({len(qs_md)} 字符)")
    return 0


if __name__ == "__main__":
    sys.exit(main() or 0)
