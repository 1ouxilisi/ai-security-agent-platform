"""
v9.5 内网扫描 - SMB/NetBIOS/AD/哈希
"""
import os, re, json, asyncio, socket
from datetime import datetime
from fastapi import APIRouter, Request
from fastapi.responses import JSONResponse

router = APIRouter(prefix="/api/v9/internal", tags=["v9-internal"])


@router.post("/host-discover")
async def host_discover(request: Request):
    """内网存活主机发现"""
    data = await request.json()
    cidr = data.get("cidr", "192.168.1.0/24")
    
    # 解析CIDR
    parts = cidr.split(".")
    base = ".".join(parts[:3])
    
    alive = []
    tasks = []
    
    async def check_host(ip):
        try:
            reader, writer = await asyncio.wait_for(
                asyncio.open_connection(ip, 445), timeout=1
            )
            writer.close()
            return ip
        except:
            return None
    
    for i in range(1, 255):
        ip = f"{base}.{i}"
        tasks.append(check_host(ip))
    
    results = await asyncio.gather(*tasks)
    alive = [r for r in results if r]
    
    return {
        "cidr": cidr,
        "hosts_scanned": 254,
        "hosts_alive": len(alive),
        "hosts": alive,
        "method": "TCP 445 (SMB)",
        "finished_at": datetime.now().isoformat()
    }


@router.post("/port-scan")
async def internal_port_scan(request: Request):
    """内网端口扫描"""
    data = await request.json()
    target = data.get("target", "")
    ports = data.get("ports", [22, 80, 443, 445, 3389, 3306, 5432, 6379, 27017, 8080, 9200])
    
    if not target:
        return JSONResponse(status_code=400, content={"error": "需要target"})
    
    open_ports = []
    
    async def check_port(port):
        try:
            reader, writer = await asyncio.wait_for(
                asyncio.open_connection(target, port), timeout=2
            )
            writer.close()
            return port
        except:
            return None
    
    tasks = [check_port(p) for p in ports]
    results = await asyncio.gather(*tasks)
    open_ports = [r for r in results if r]
    
    # 服务识别
    services = {
        22: "SSH", 80: "HTTP", 443: "HTTPS", 445: "SMB",
        3389: "RDP", 3306: "MySQL", 5432: "PostgreSQL",
        6379: "Redis", 27017: "MongoDB", 8080: "HTTP-Proxy",
        9200: "Elasticsearch"
    }
    
    return {
        "target": target,
        "ports_scanned": len(ports),
        "open_ports": [{"port": p, "service": services.get(p, "unknown")} for p in open_ports],
        "finished_at": datetime.now().isoformat()
    }


@router.post("/smb-enum")
async def smb_enum(request: Request):
    """SMB共享枚举"""
    data = await request.json()
    target = data.get("target", "")
    
    if not target:
        return JSONResponse(status_code=400, content={"error": "需要target"})
    
    try:
        proc = await asyncio.create_subprocess_exec(
            "smbclient", "-L", f"//{target}/", "-N",
            stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE
        )
        stdout, stderr = await asyncio.wait_for(proc.communicate(), timeout=15)
        return {
            "target": target,
            "shares_raw": stdout.decode()[:2000],
            "method": "smbclient -N (匿名)",
            "finished_at": datetime.now().isoformat()
        }
    except FileNotFoundError:
        return {"error": "smbclient未安装", "target": target, "hint": "安装samba客户端"}
    except Exception as e:
        return {"error": str(e), "target": target}
