# -*- coding: utf-8 -*-
"""
trend_analysis 模块 —— 趋势分析可视化

模块功能：
    - 漏洞趋势分析（新增/已修复/未修复/累计）
    - 风险趋势分析（平均/最高风险评分/各严重程度数量）
    - 扫描趋势分析（扫描次数/发现漏洞数/修复率/平均耗时）
    - 生成 ECharts 完整可渲染配置（line/bar/pie/area）

定位说明：
    本模块为授权安全评估 / 防御检测产品的趋势分析组件，
    用于帮助安全团队掌握风险随时间的变化趋势，请勿用于非法用途。
"""

from typing import Any, Optional


# ECharts 主题色板
_ECHARTS_COLORS = ["#5470c6", "#91cc75", "#fac858", "#ee6666",
                   "#73c0de", "#3ba272", "#fc8452", "#9a60b4"]


class TrendAnalyzer:
    """趋势分析器。"""

    # ------------------------------------------------------------------
    # 漏洞趋势
    # ------------------------------------------------------------------
    def analyze_vulnerability_trend(self, history_data: list) -> dict:
        """漏洞趋势分析。

        Args:
            history_data: [{date, new_vulns, fixed_vulns, unfixed_vulns, total_vulns}]

        Returns:
            {"dates":[...], "new_vulns":[...], "fixed_vulns":[...],
             "unfixed_vulns":[...], "total_vulns":[...]}
        """
        try:
            dates: list[str] = []
            new_list: list[int] = []
            fixed_list: list[int] = []
            unfixed_list: list[int] = []
            total_list: list[int] = []

            running_total = 0
            for record in (history_data or []):
                date = str(record.get("date", ""))
                new = int(record.get("new_vulns", 0) or 0)
                fixed = int(record.get("fixed_vulns", 0) or 0)
                unfixed = int(record.get("unfixed_vulns", 0) or 0)
                total = int(record.get("total_vulns", 0) or 0)

                dates.append(date)
                new_list.append(new)
                fixed_list.append(fixed)
                unfixed_list.append(unfixed)
                # 累计总数：优先用传入的 total，否则动态计算
                if total:
                    running_total = total
                else:
                    running_total = max(0, running_total + new - fixed)
                total_list.append(running_total)

            return {
                "dates": dates,
                "new_vulns": new_list,
                "fixed_vulns": fixed_list,
                "unfixed_vulns": unfixed_list,
                "total_vulns": total_list,
            }
        except Exception as e:  # noqa: BLE001
            return {"dates": [], "error": f"漏洞趋势分析失败: {e}"}

    # ------------------------------------------------------------------
    # 风险趋势
    # ------------------------------------------------------------------
    def analyze_risk_trend(self, history_data: list) -> dict:
        """风险趋势分析。

        Args:
            history_data: [{date, avg_risk, max_risk, critical_count, high_count, medium_count, low_count}]

        Returns:
            {"dates":[...], "avg_risk":[...], "max_risk":[...],
             "critical":[...], "high":[...], "medium":[...], "low":[...]}
        """
        try:
            dates: list[str] = []
            avg_list: list[int] = []
            max_list: list[int] = []
            crit_list: list[int] = []
            high_list: list[int] = []
            med_list: list[int] = []
            low_list: list[int] = []

            for record in (history_data or []):
                dates.append(str(record.get("date", "")))
                avg_list.append(int(record.get("avg_risk", record.get("average_risk", 0)) or 0))
                max_list.append(int(record.get("max_risk", record.get("highest_risk", 0)) or 0))
                crit_list.append(int(record.get("critical_count", record.get("严重", 0)) or 0))
                high_list.append(int(record.get("high_count", record.get("高", 0)) or 0))
                med_list.append(int(record.get("medium_count", record.get("中", 0)) or 0))
                low_list.append(int(record.get("low_count", record.get("低", 0)) or 0))

            return {
                "dates": dates,
                "avg_risk": avg_list,
                "max_risk": max_list,
                "critical": crit_list,
                "high": high_list,
                "medium": med_list,
                "low": low_list,
            }
        except Exception as e:  # noqa: BLE001
            return {"dates": [], "error": f"风险趋势分析失败: {e}"}

    # ------------------------------------------------------------------
    # 扫描趋势
    # ------------------------------------------------------------------
    def analyze_scan_trend(self, history_data: list) -> dict:
        """扫描趋势分析。

        Args:
            history_data: [{date, scan_count, vulns_found, fix_rate, avg_duration}]

        Returns:
            {"dates":[...], "scan_count":[...], "vulns_found":[...],
             "fix_rate":[...], "avg_duration":[...]}
        """
        try:
            dates: list[str] = []
            scan_list: list[int] = []
            found_list: list[int] = []
            fix_rate_list: list[float] = []
            dur_list: list[float] = []

            for record in (history_data or []):
                dates.append(str(record.get("date", "")))
                scan_list.append(int(record.get("scan_count", record.get("scans", 0)) or 0))
                found_list.append(int(record.get("vulns_found", record.get("found", 0)) or 0))
                fix_rate_list.append(round(float(record.get("fix_rate", record.get("rate", 0)) or 0), 1))
                dur_list.append(round(float(record.get("avg_duration", record.get("duration", 0)) or 0), 1))

            return {
                "dates": dates,
                "scan_count": scan_list,
                "vulns_found": found_list,
                "fix_rate": fix_rate_list,
                "avg_duration": dur_list,
            }
        except Exception as e:  # noqa: BLE001
            return {"dates": [], "error": f"扫描趋势分析失败: {e}"}

    # ------------------------------------------------------------------
    # ECharts 配置生成
    # ------------------------------------------------------------------
    def to_echarts_config(self, analysis_data: dict, chart_type: str) -> dict:
        """生成 ECharts 配置（可直接用于前端渲染）。

        Args:
            analysis_data: analyze_*_trend 的返回结果
            chart_type: line / bar / pie / area

        Returns:
            完整 ECharts option 字典
        """
        try:
            dates = analysis_data.get("dates", [])
            # 排除非数据字段
            series_fields = [k for k in analysis_data.keys()
                             if k != "dates" and isinstance(analysis_data[k], list)]

            # 根据图表类型决定 series 类型
            if chart_type == "line":
                series_type = "line"
                area_style = None
            elif chart_type == "area":
                series_type = "line"
                area_style = {"opacity": 0.3}
            elif chart_type == "bar":
                series_type = "bar"
                area_style = None
            elif chart_type == "pie":
                # 饼图：取最后一个时间点的数据
                return self._pie_config(analysis_data)
            else:
                series_type = "line"
                area_style = None

            series_list: list[dict] = []
            for idx, field in enumerate(series_fields):
                item: dict[str, Any] = {
                    "name": field,
                    "type": series_type,
                    "data": analysis_data[field],
                    "smooth": True,
                }
                if area_style:
                    item["areaStyle"] = area_style
                series_list.append(item)

            config = {
                "title": {
                    "text": f"趋势分析 ({chart_type})",
                    "left": "center",
                    "textStyle": {"fontSize": 16},
                },
                "tooltip": {
                    "trigger": "axis",
                    "axisPointer": {"type": "cross"},
                },
                "legend": {
                    "data": series_fields,
                    "bottom": 0,
                },
                "grid": {
                    "left": "3%", "right": "4%", "bottom": "12%", "containLabel": True,
                },
                "xAxis": {
                    "type": "category",
                    "boundaryGap": False if chart_type in ("line", "area") else True,
                    "data": dates,
                },
                "yAxis": {
                    "type": "value",
                },
                "series": series_list,
                "color": _ECHARTS_COLORS,
            }
            return config
        except Exception as e:  # noqa: BLE001
            return {
                "title": {"text": f"ECharts 配置生成失败: {e}"},
                "series": [],
            }

    def _pie_config(self, analysis_data: dict) -> dict:
        """生成饼图配置（取最新时间点各指标占比）。"""
        try:
            dates = analysis_data.get("dates", [])
            series_fields = [k for k in analysis_data.keys()
                             if k != "dates" and isinstance(analysis_data[k], list)]
            # 取最后一个时间点
            last_idx = -1 if dates else 0
            pie_data = []
            for field in series_fields:
                arr = analysis_data[field]
                if arr and last_idx < len(arr):
                    val = arr[last_idx]
                    if isinstance(val, (int, float)) and val > 0:
                        pie_data.append({"name": field, "value": val})

            return {
                "title": {"text": "最新指标分布", "left": "center"},
                "tooltip": {"trigger": "item", "formatter": "{b}: {c} ({d}%)"},
                "legend": {"bottom": 0, "data": [d["name"] for d in pie_data]},
                "series": [{
                    "type": "pie",
                    "radius": "50%",
                    "data": pie_data,
                    "emphasis": {"itemStyle": {
                        "shadowBlur": 10, "shadowOffsetX": 0,
                        "shadowColor": "rgba(0,0,0,0.5)"
                    }},
                }],
                "color": _ECHARTS_COLORS,
            }
        except Exception as e:  # noqa: BLE001
            return {"title": {"text": f"饼图配置失败: {e}"}, "series": []}

    # ------------------------------------------------------------------
    # 一键获取全部
    # ------------------------------------------------------------------
    def get_all_trends(self, history_data: list) -> dict:
        """获取所有趋势分析数据。"""
        return {
            "vulnerability": self.analyze_vulnerability_trend(history_data),
            "risk": self.analyze_risk_trend(history_data),
            "scan": self.analyze_scan_trend(history_data),
        }
