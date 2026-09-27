# -*- coding: utf-8 -*-
"""
report_generator.py — CTF 赛事报告生成（MD/HTML）。

内容:
    - 执行摘要 / 赛事概况 / 题目分析 / 排名分析 / 解题统计
    - 战队表现 / 比赛复盘 / 知识点覆盖 / 改进建议 / 图表可视化
"""

from __future__ import annotations

import os
from datetime import datetime
from typing import Any, Dict, Optional

REPORTS_DIR = os.path.join(
    os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
    "reports", "ctf_pro")


class ReportGenerator:
    """CTF 赛事报告生成器。"""

    def __init__(self) -> None:
        os.makedirs(REPORTS_DIR, exist_ok=True)

    # ------------------------------------------------------------------ #
    def collect_data(self) -> Dict[str, Any]:
        from .challenge_management_phase import get_challenge_phase
        from .competition_management_phase import get_competition_phase
        from .game_play_phase import get_gameplay_phase
        from .realtime_ranking_phase import get_ranking_phase
        from .team_management_phase import get_team_phase
        from .ctf_dashboard import get_dashboard

        chal = get_challenge_phase().stats()
        comp = get_competition_phase().stats()
        gp = get_gameplay_phase().stats()
        rank = get_ranking_phase().leaderboard()
        teams = get_team_phase().stats()
        dash = get_dashboard().full_screen()
        return {
            "generated_at": datetime.now().isoformat(timespec="seconds"),
            "challenge": chal, "competition": comp,
            "gameplay": gp, "leaderboard": rank,
            "teams": teams, "dashboard": dash,
        }

    # ------------------------------------------------------------------ #
    def to_markdown(self, data: Optional[Dict[str, Any]] = None
                    ) -> str:
        d = data or self.collect_data()
        chal, gp = d["challenge"], d["gameplay"]
        rank = d["leaderboard"]
        lines = []
        lines.append("# CTF 夺旗赛赛事报告")
        lines.append("")
        lines.append(f"- 生成时间：{d['generated_at']}")
        lines.append("")
        lines.append("## 1. 执行摘要")
        lines.append("")
        kpi = d["dashboard"]["kpi"]
        lines.append(f"- 参赛队伍：**{kpi['teams']}**")
        lines.append(f"- 题目总数：**{kpi['challenges']}**")
        lines.append(f"- 解题总数：**{kpi['solved']}**")
        lines.append(f"- 提交总数：**{kpi['submissions']}**")
        lines.append(f"- 一血总数：**{kpi['first_bloods']}**")
        lines.append(f"- 提交正确率：**{kpi['accuracy']*100:.1f}%**")
        lines.append("")
        lines.append("## 2. 赛事概况")
        lines.append("")
        lines.append(f"- 赛事场次：{d['competition']['total']}"
                     f"（进行中 {d['competition']['running']}）")
        lines.append(f"- 战队总数：{d['teams']['total_teams']}")
        lines.append("")
        lines.append("## 3. 排名分析（Top10）")
        lines.append("")
        lines.append("| 排名 | 队伍 | 总分 | 解题数 | 一血 |")
        lines.append("|---|---|---|---|---|")
        for r in rank[:10]:
            lines.append(f"| {r['rank']} | {r['team_name']} "
                         f"| {r['score']} | {r['solved']} "
                         f"| {r['first_bloods']} |")
        lines.append("")
        lines.append("## 4. 题目分布")
        lines.append("")
        for cat, cnt in chal["by_category"].items():
            lines.append(f"- {cat}: {cnt} 题")
        lines.append("")
        lines.append("## 5. 解题统计")
        lines.append("")
        lines.append(f"- 总提交：{gp['total_submissions']}")
        lines.append(f"- 正确：{gp['correct']}，错误：{gp['wrong']}")
        lines.append(f"- 一血/二血/三血："
                     f"{gp['bloods']['first']}/"
                     f"{gp['bloods']['second']}/"
                     f"{gp['bloods']['third']}")
        lines.append("")
        lines.append("## 6. 改进建议")
        lines.append("")
        lines.append("1. 优化题目难度梯度，避免全难或全易")
        lines.append("2. 增加动态 flag 与容器重置，防打靶")
        lines.append("3. 赛后 48h 内发布官方 Writeup 并收集选手题解")
        lines.append("4. 对正确率低的题型补充训练路径与靶场")
        lines.append("")
        return "\n".join(lines)

    # ------------------------------------------------------------------ #
    def to_html(self, md: str) -> str:
        import html as _h
        body = _h.escape(md)
        return f"""<!doctype html>
<html lang="zh-CN"><head><meta charset="utf-8">
<title>CTF 赛事报告</title>
<style>
body{{font-family:-apple-system,Segoe UI,Microsoft YaHei,sans-serif;
background:#0b0f14;color:#e6edf3;padding:32px;line-height:1.7;}}
pre{{white-space:pre-wrap;background:#121821;padding:20px;border-radius:8px;
border:1px solid #243040;}}
h1,h2{{color:#4fc3f7;}}
</style></head><body>
<pre>{body}</pre>
</body></html>"""

    # ------------------------------------------------------------------ #
    def generate(self, fmt: str = "both"
                 ) -> Dict[str, Any]:
        data = self.collect_data()
        md = self.to_markdown(data)
        ts = datetime.now().strftime("%Y%m%d_%H%M%S")
        md_path = os.path.join(REPORTS_DIR, f"ctf_report_{ts}.md")
        html_path = os.path.join(REPORTS_DIR, f"ctf_report_{ts}.html")
        with open(md_path, "w", encoding="utf-8") as f:
            f.write(md)
        html = self.to_html(md)
        with open(html_path, "w", encoding="utf-8") as f:
            f.write(html)
        return {"md_path": md_path, "html_path": html_path,
                "markdown": md, "html": html,
                "stats": data["dashboard"]["kpi"]}


_default: Optional[ReportGenerator] = None


def get_report_generator() -> ReportGenerator:
    global _default
    if _default is None:
        _default = ReportGenerator()
    return _default
