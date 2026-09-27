# -*- coding: utf-8 -*-
"""
verify_round8_target_labs.py - 第8轮「靶场集成」验证脚本

检查项：
  1. 所有 Python 文件可正常导入
  2. target_lab_routes.py 的 router 至少 12 个端点
  3. manager.py 包含 5 个靶场元数据
  4. docker_compose.py 能生成有效 YAML
  5. scenarios.py 包含 6 个预定义场景
  6. target_lab_console.html 非空、结构完整、含 5 靶场卡片与 6 场景
"""

from __future__ import annotations

import os
import sys

ROOT = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, ROOT)

PASS, FAIL = "PASS", "FAIL"
results = []


def check(name: str, ok: bool, detail: str = ""):
    results.append((PASS if ok else FAIL, name, detail))
    print(f"[{PASS if ok else FAIL}] {name}  {detail}")


def main() -> int:
    # 1. 导入
    try:
        import target_labs.manager as mgr_mod
        import target_labs.docker_compose as dc_mod
        import target_labs.scenarios as sc_mod
        from api_server.target_lab_routes import router
        check("1. 所有模块可导入", True,
              "manager / docker_compose / scenarios / routes")
    except Exception as e:  # noqa: BLE001
        check("1. 所有模块可导入", False, repr(e))
        return 1

    # 2. 端点数量
    n_routes = len(router.routes)
    check("2. router 端点 >= 12", n_routes >= 12, f"实际 {n_routes} 个")

    # 3. 5 个靶场元数据
    labs = getattr(mgr_mod, "SUPPORTED_LABS", {})
    expected_labs = {"dvwa", "juice-shop", "webgoat", "bwapp", "mutillidae"}
    ok_labs = expected_labs.issubset(set(labs.keys())) and len(labs) == 5
    sample = labs.get("dvwa", {})
    has_meta = all(k in sample for k in
                   ("name", "description", "difficulty", "vuln_types",
                    "default_port", "docker_image", "doc_url"))
    check("3. 5 个靶场元数据完整", ok_labs and has_meta,
          f"labs={list(labs.keys())}")

    # 4. compose 生成有效 YAML
    try:
        gen = dc_mod.DockerComposeGenerator()
        res = gen.generate_compose(["dvwa", "juice-shop"])
        yaml_text = res.get("yaml", "") if res.get("success") else ""
        valid = bool(yaml_text) and "services:" in yaml_text and "dvwa:" in yaml_text
        try:
            import yaml  # noqa: WPS433
            yaml.safe_load(yaml_text)
            yaml_ok = True
        except Exception:  # noqa: BLE001
            yaml_ok = False
        check("4. compose 生成有效 YAML", valid and yaml_ok,
              f"chars={len(yaml_text)}")
    except Exception as e:  # noqa: BLE001
        check("4. compose 生成有效 YAML", False, repr(e))

    # 5. 6 个场景
    scns = getattr(sc_mod, "SCENARIOS", {})
    required = {"sqli_detection", "xss_reflected", "cmd_injection",
                "file_upload", "auth_bypass", "privesc_bola"}
    ok_scn = required.issubset(set(scns.keys())) and len(scns) == 6
    check("5. 6 个预定义场景", ok_scn, f"scenarios={list(scns.keys())}")

    # 6. HTML
    html_path = os.path.join(ROOT, "api_server", "target_lab_console.html")
    try:
        with open(html_path, "r", encoding="utf-8") as f:
            html = f.read()
        nonempty = len(html) > 500
        has_structure = ("<!DOCTYPE html>" in html and "</html>" in html
                         and "<body" in html and "<script" in html)
        lab_hits = sum(1 for l in expected_labs if l in html)
        scn_hits = sum(1 for s in required if s in html)
        check("6. HTML 完整(5卡片+6场景)",
              nonempty and has_structure and lab_hits >= 5 and scn_hits >= 6,
              f"size={len(html)}, lab_hits={lab_hits}, scn_hits={scn_hits}")
    except Exception as e:  # noqa: BLE001
        check("6. HTML 完整(5卡片+6场景)", False, repr(e))

    # 汇总
    failed = [r for r in results if r[0] == FAIL]
    print("\n" + "=" * 60)
    print(f"总计 {len(results)} 项，通过 {len(results) - len(failed)}，失败 {len(failed)}")
    print(f"router 端点数量：{n_routes}")
    print("=" * 60)
    return 0 if not failed else 1


if __name__ == "__main__":
    raise SystemExit(main())
