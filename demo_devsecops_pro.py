# -*- coding: utf-8 -*-
"""DevSecOps Pro 端到端演示脚本。"""
from __future__ import annotations

import os
import tempfile


def make_demo_project() -> str:
    tmp = tempfile.mkdtemp(prefix="dso_demo_")
    os.makedirs(os.path.join(tmp, "src"), exist_ok=True)
    with open(os.path.join(tmp, "src", "app.py"), "w", encoding="utf-8") as f:
        f.write(
            'import os, subprocess\n'
            'password = "s3cr3tP@ssw0rd"\n'
            'AWS_KEY = "AKIAIOSFODNN7EXAMPLE"\n'
            'def run_cmd(user_input):\n'
            '    os.system("ls " + user_input)\n'
            'def query(db, uid):\n'
            '    db.execute(f"SELECT * FROM users WHERE id = {uid}")\n'
        )
    with open(os.path.join(tmp, "requirements.txt"), "w", encoding="utf-8") as f:
        f.write("log4j==1.2.3\nlodash==4.17.0\n")
    with open(os.path.join(tmp, "Dockerfile"), "w", encoding="utf-8") as f:
        f.write("FROM ubuntu:latest\nUSER root\n")
    with open(os.path.join(tmp, "main.tf"), "w", encoding="utf-8") as f:
        f.write('resource "aws_s3_bucket" "x" { acl = "public-read" }\n')
    return tmp


def main() -> int:
    target = make_demo_project()
    print(f"[*] 演示项目: {target}")

    from devsecops_pro import get_orchestrator, get_dashboard
    orch = get_orchestrator()
    t = orch.create_task(target)
    t = orch.run_full(target, t.task_id)

    print("\n=== 八阶段结果 ===")
    print(f"STATUS: {t.status} | stage: {t.stage} | progress: {t.progress}")
    print(f"SAST     findings: {len(t.sast.get('findings', []))}")
    print(f"SCA      findings: {len(t.sca.get('findings', []))}")
    print(f"Secrets  findings: {len(t.secrets.get('findings', []))}")
    print(f"IaC      findings: {len(t.iac.get('findings', []))}")
    print(f"Container findings: {len(t.container.get('findings', []))}")
    print(f"Gate     : {t.gate.get('decision')} (score {t.gate.get('score')})")
    print(f"Risk     : {t.risk.get('score')}/100 {t.risk.get('level')} "
          f"{t.risk.get('maturity')}")

    print("\n=== AI 分析 ===")
    print("overall:", (t.ai.get("overall_assessment") or "")[:160])
    print("attack_paths:", len(t.ai.get("attack_paths", [])))
    print("fix_suggestions:", len(t.ai.get("fix_suggestions", [])))
    print("roadmap phases:", len(t.ai.get("roadmap", [])))

    print("\n=== Top 风险项 ===")
    for r in t.risk.get("top_risks", [])[:6]:
        print(f" - [{r.get('severity')}] "
              f"{(r.get('title') or '')[:80]}  @ {r.get('path')}:{r.get('line')}")

    print("\n=== 报告 ===")
    print("HTML:", t.report_path)
    print("exists:", os.path.exists(t.report_path))

    print("\n=== 仪表盘 ===")
    dash = get_dashboard()
    ov = dash.overview()
    print("tasks total:", ov["task_total"], "done:", ov["task_done"])
    print("tools status keys:", list(dash.tools_status().keys()))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
