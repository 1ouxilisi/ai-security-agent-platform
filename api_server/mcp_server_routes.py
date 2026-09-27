# -*- coding: utf-8 -*-
"""MCP工具服务器 - 让Claude Code/Cursor/Hermes等AI客户端调用本项目安全工具
参考Blitz Strike的MCP工具带设计，暴露核心安全能力为MCP工具
"""
from fastapi import APIRouter, HTTPException
from pydantic import BaseModel
from typing import Optional, List, Dict, Any
import json
import time
from datetime import datetime

router = APIRouter(prefix="/api/v1/mcp", tags=["MCP工具服务器"])

# ============== MCP工具注册表 ==============
MCP_TOOLS = [
    {
        "name": "nmap_port_scan",
        "description": "Nmap真实端口扫描，发现目标开放端口和服务",
        "inputSchema": {
            "type": "object",
            "properties": {
                "target": {"type": "string", "description": "IP地址或域名"},
                "mode": {"type": "string", "enum": ["quick", "detailed", "vuln"], "default": "quick"},
                "timeout": {"type": "integer", "default": 60}
            },
            "required": ["target"]
        }
    },
    {
        "name": "nuclei_vuln_scan",
        "description": "Nuclei真实漏洞扫描，基于模板检测已知漏洞",
        "inputSchema": {
            "type": "object",
            "properties": {
                "target": {"type": "string", "description": "目标URL或IP"},
                "severity": {"type": "string", "enum": ["low", "medium", "high", "critical", "all"], "default": "high,critical"},
                "timeout": {"type": "integer", "default": 120}
            },
            "required": ["target"]
        }
    },
    {
        "name": "subfinder_enum",
        "description": "子域名枚举，发现目标域名的子域名",
        "inputSchema": {
            "type": "object",
            "properties": {
                "domain": {"type": "string", "description": "目标域名"},
                "timeout": {"type": "integer", "default": 60}
            },
            "required": ["domain"]
        }
    },
    {
        "name": "web_fingerprint",
        "description": "Web服务指纹识别，识别服务器/框架/CMS/技术栈",
        "inputSchema": {
            "type": "object",
            "properties": {
                "url": {"type": "string", "description": "目标URL"},
                "timeout": {"type": "integer", "default": 15}
            },
            "required": ["url"]
        }
    },
    {
        "name": "directory_scan",
        "description": "Web目录路径枚举，发现隐藏目录和文件",
        "inputSchema": {
            "type": "object",
            "properties": {
                "url": {"type": "string", "description": "目标URL"},
                "threads": {"type": "integer", "default": 10},
                "timeout": {"type": "integer", "default": 30}
            },
            "required": ["url"]
        }
    },
    {
        "name": "ssl_tls_check",
        "description": "SSL/TLS安全检测，证书有效期/协议版本/弱加密套件",
        "inputSchema": {
            "type": "object",
            "properties": {
                "host": {"type": "string", "description": "目标主机"},
                "port": {"type": "integer", "default": 443}
            },
            "required": ["host"]
        }
    },
    {
        "name": "cve_search",
        "description": "CVE漏洞库搜索，从12257条漏洞数据中检索",
        "inputSchema": {
            "type": "object",
            "properties": {
                "keyword": {"type": "string", "description": "搜索关键词（产品名/CVE编号/漏洞类型）"},
                "limit": {"type": "integer", "default": 20}
            },
            "required": ["keyword"]
        }
    },
    {
        "name": "owasp_classify",
        "description": "OWASP Top 10自动分类，将漏洞映射到A01-A10",
        "inputSchema": {
            "type": "object",
            "properties": {
                "vuln_name": {"type": "string", "description": "漏洞名称或描述"},
                "vuln_type": {"type": "string", "description": "漏洞类型"}
            },
            "required": ["vuln_name"]
        }
    },
    {
        "name": "generate_report",
        "description": "生成渗透测试报告（HTML/Markdown格式）",
        "inputSchema": {
            "type": "object",
            "properties": {
                "target": {"type": "string", "description": "测试目标"},
                "findings": {"type": "array", "description": "漏洞发现列表", "items": {"type": "object"}},
                "format": {"type": "string", "enum": ["html", "markdown"], "default": "html"}
            },
            "required": ["target", "findings"]
        }
    },
    {
        "name": "full_recon_workflow",
        "description": "一键完整侦察工作流：子域名→端口→漏洞→报告",
        "inputSchema": {
            "type": "object",
            "properties": {
                "target": {"type": "string", "description": "目标IP或域名"},
                "skip_tools": {"type": "array", "description": "跳过的工具名", "items": {"type": "string"}}
            },
            "required": ["target"]
        }
    },
    {
        "name": "dns_collect",
        "description": "DNS信息收集，A/MX/NS记录+子域名枚举",
        "inputSchema": {
            "type": "object",
            "properties": {
                "domain": {"type": "string", "description": "目标域名"}
            },
            "required": ["domain"]
        }
    },
    {
        "name": "asset_baseline",
        "description": "资产基线对比，检测端口/服务/漏洞变化",
        "inputSchema": {
            "type": "object",
            "properties": {
                "target": {"type": "string", "description": "目标资产"},
                "action": {"type": "string", "enum": ["save", "compare", "list"], "default": "save"}
            },
            "required": ["target"]
        }
    }
]


@router.get("/tools")
def list_mcp_tools():
    """列出所有可用的MCP工具"""
    return {
        "success": True,
        "data": {
            "tools": MCP_TOOLS,
            "total": len(MCP_TOOLS),
            "server_name": "ai-hacking-agent-mcp",
            "version": "1.0.0",
            "protocol": "MCP 2025-03-26"
        }
    }


class MCPRequest(BaseModel):
    tool: str
    arguments: Dict[str, Any] = {}


@router.post("/call")
def call_mcp_tool(req: MCPRequest):
    """调用MCP工具（标准MCP JSON-RPC兼容接口）"""
    tool_map = {t["name"]: t for t in MCP_TOOLS}
    if req.tool not in tool_map:
        raise HTTPException(404, f"工具不存在: {req.tool}")

    args = req.arguments
    result = {"tool": req.tool, "called_at": datetime.now().isoformat()}

    try:
        if req.tool == "nmap_port_scan":
            from asm.real_tools import NmapRunner
            mode = args.get("mode", "quick")
            runner = NmapRunner(args["target"], timeout=args.get("timeout", 60))
            if mode == "quick":
                data = runner.quick_scan()
            elif mode == "detailed":
                data = runner.detailed_scan()
            else:
                data = runner.vuln_scan()
            result["output"] = data

        elif req.tool == "nuclei_vuln_scan":
            from asm.real_tools import NucleiRunner
            runner = NucleiRunner(args["target"], timeout=args.get("timeout", 120))
            data = runner.scan(args.get("severity", "high,critical"))
            result["output"] = data

        elif req.tool == "subfinder_enum":
            from asm.real_tools import SubfinderRunner
            runner = SubfinderRunner(args["domain"], timeout=args.get("timeout", 60))
            data = runner.enumerate()
            result["output"] = data

        elif req.tool == "web_fingerprint":
            from asm.web_fingerprint import WebFingerprinter
            fp = WebFingerprinter(timeout=args.get("timeout", 15))
            data = fp.identify(args["url"])
            result["output"] = data

        elif req.tool == "directory_scan":
            from asm.web_fingerprint import DirectoryScanner
            ds = DirectoryScanner(threads=args.get("threads", 10), timeout=args.get("timeout", 30))
            data = ds.scan(args["url"])
            result["output"] = data

        elif req.tool == "ssl_tls_check":
            from asm.ssl_report import SSLTLSDetector
            detector = SSLTLSDetector()
            data = detector.detect(args["host"], args.get("port", 443))
            result["output"] = data

        elif req.tool == "cve_search":
            from asm.ssl_report import CVESearcher
            searcher = CVESearcher()
            data = searcher.search(args["keyword"], limit=args.get("limit", 20))
            result["output"] = data

        elif req.tool == "owasp_classify":
            from asm.compliance_scheduler import OWASPMapper
            mapper = OWASPMapper()
            data = mapper.classify(args["vuln_name"], args.get("vuln_type", ""))
            result["output"] = data

        elif req.tool == "generate_report":
            from asm.ssl_report import ReportGenerator
            gen = ReportGenerator()
            if args.get("format", "html") == "html":
                data = gen.generate_html(args["target"], args.get("findings", []))
            else:
                data = gen.generate_markdown(args["target"], args.get("findings", []))
            result["output"] = data

        elif req.tool == "full_recon_workflow":
            import requests as _req
            key = "cF_fK3wzzFd3sDU-WykQzDbAKNhn_Jjoyphbmh-adLtwx5ShhU8oLpt94aV_uECT"
            r = _req.post("http://127.0.0.1:8000/api/v1/recon-workflow/run",
                          json={"target": args["target"], "skip_tools": args.get("skip_tools", [])},
                          headers={"X-API-Key": key}, timeout=300)
            result["output"] = r.json().get("data", {})

        elif req.tool == "dns_collect":
            from asm.dns_workflow import DNSCollector
            collector = DNSCollector()
            data = collector.collect(args["domain"])
            result["output"] = data

        elif req.tool == "asset_baseline":
            from asm.dns_workflow import AssetBaseline
            baseline = AssetBaseline()
            action = args.get("action", "save")
            if action == "save":
                data = baseline.save(args["target"])
            elif action == "compare":
                data = baseline.compare(args["target"])
            else:
                data = baseline.list()
            result["output"] = data

        result["status"] = "success"
    except Exception as e:
        result["status"] = "error"
        result["error"] = str(e)

    return {"success": result["status"] == "success", "data": result}


@router.get("/manifest")
def mcp_manifest():
    """MCP服务器清单（用于AI客户端自动发现）"""
    return {
        "mcpServers": {
            "ai-hacking-agent": {
                "command": "python",
                "args": ["-m", "mcp_server"],
                "url": "http://127.0.0.1:8000/api/v1/mcp",
                "env": {"MCP_API_KEY": "cF_fK3wzzFd3sDU-WykQzDbAKNhn_Jjoyphbmh-adLtwx5ShhU8oLpt94aV_uECT"}
            }
        }
    }
