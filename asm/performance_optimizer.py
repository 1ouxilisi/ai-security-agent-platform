"""
性能优化模块
- 启动时间优化
- CVE库懒加载
- 缓存层
- 预编译字节码
"""

import json
import os
import time
import sys
from typing import Dict, Any, Optional, List
from functools import lru_cache


class PerformanceOptimizer:
    """性能优化器"""

    def __init__(self, project_root: str = ""):
        self.project_root = project_root or os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
        self.cache_dir = os.path.join(self.project_root, ".cache")
        os.makedirs(self.cache_dir, exist_ok=True)
        self._cve_database = None
        self._cve_loaded = False

    def optimize_startup(self) -> Dict[str, Any]:
        """执行启动优化"""
        start_time = time.time()
        results = {}

        # 1. 预编译Python字节码
        results["bytecode_compilation"] = self._compile_bytecode()

        # 2. 生成CVE库索引（加速查询）
        results["cve_index"] = self._build_cve_index()

        # 3. 清理缓存
        results["cache_cleanup"] = self._cleanup_cache()

        results["optimization_duration"] = round(time.time() - start_time, 2)
        return results

    def _compile_bytecode(self) -> Dict[str, Any]:
        """预编译Python字节码"""
        try:
            import py_compile
            import glob

            compiled = 0
            failed = 0
            py_files = glob.glob(os.path.join(self.project_root, "**", "*.py"), recursive=True)

            for py_file in py_files[:500]:  # 限制数量避免超时
                try:
                    py_compile.compile(py_file, doraise=False)
                    compiled += 1
                except Exception:
                    failed += 1

            return {
                "success": True,
                "compiled": compiled,
                "failed": failed,
                "total_scanned": len(py_files)
            }
        except Exception as e:
            return {"success": False, "error": str(e)}

    def _build_cve_index(self) -> Dict[str, Any]:
        """构建CVE库索引（加速查询）"""
        cve_file = os.path.join(self.project_root, "data", "vuln_database.json")
        index_file = os.path.join(self.cache_dir, "cve_index.json")

        if not os.path.exists(cve_file):
            return {"success": False, "error": "CVE库文件不存在"}

        try:
            # 如果索引已存在且比CVE库新，直接使用
            if os.path.exists(index_file) and os.path.getmtime(index_file) > os.path.getmtime(cve_file):
                with open(index_file, "r", encoding="utf-8") as f:
                    index = json.load(f)
                return {"success": True, "cached": True, "total_cves": index.get("total", 0)}

            # 加载CVE库并构建索引
            with open(cve_file, "r", encoding="utf-8") as f:
                cve_data = json.load(f)

            # 构建索引：按严重程度、年份、关键词分类
            index = {
                "total": len(cve_data) if isinstance(cve_data, dict) else len(cve_data),
                "by_severity": {},
                "by_year": {},
                "by_keyword": {},
                "cve_ids": []
            }

            items = cve_data.items() if isinstance(cve_data, dict) else enumerate(cve_data)
            for cve_id, cve_info in items:
                if isinstance(cve_info, dict):
                    # 按严重程度
                    severity = cve_info.get("severity", "unknown").lower()
                    index["by_severity"][severity] = index["by_severity"].get(severity, 0) + 1

                    # 按年份
                    year = cve_id.split("-")[1] if "-" in cve_id else "unknown"
                    index["by_year"][year] = index["by_year"].get(year, 0) + 1

                    # CVE ID列表
                    index["cve_ids"].append(cve_id)

            # 保存索引
            with open(index_file, "w", encoding="utf-8") as f:
                json.dump(index, f, ensure_ascii=False)

            return {
                "success": True,
                "cached": False,
                "total_cves": index["total"],
                "by_severity": index["by_severity"],
                "by_year": index["by_year"]
            }
        except Exception as e:
            return {"success": False, "error": str(e)}

    def _cleanup_cache(self) -> Dict[str, Any]:
        """清理旧缓存"""
        try:
            cleaned = 0
            for filename in os.listdir(self.cache_dir):
                filepath = os.path.join(self.cache_dir, filename)
                if os.path.isfile(filepath):
                    # 删除超过7天的缓存
                    if time.time() - os.path.getmtime(filepath) > 7 * 86400:
                        os.remove(filepath)
                        cleaned += 1
            return {"success": True, "cleaned_files": cleaned}
        except Exception as e:
            return {"success": False, "error": str(e)}

    def load_cve_database(self, force: bool = False) -> Optional[Dict]:
        """懒加载CVE数据库"""
        if self._cve_loaded and not force:
            return self._cve_database

        cve_file = os.path.join(self.project_root, "data", "vuln_database.json")
        if not os.path.exists(cve_file):
            return None

        try:
            with open(cve_file, "r", encoding="utf-8") as f:
                self._cve_database = json.load(f)
            self._cve_loaded = True
            return self._cve_database
        except Exception:
            return None

    def query_cve(self, cve_id: str) -> Optional[Dict]:
        """查询单个CVE（懒加载）"""
        db = self.load_cve_database()
        if db and isinstance(db, dict):
            return db.get(cve_id)
        return None

    def search_cves(self, keyword: str, limit: int = 20) -> List[Dict]:
        """搜索CVE（懒加载）"""
        db = self.load_cve_database()
        if not db:
            return []

        results = []
        keyword_lower = keyword.lower()

        items = db.items() if isinstance(db, dict) else enumerate(db)
        for cve_id, cve_info in items:
            if isinstance(cve_info, dict):
                # 在ID、描述、关键词中搜索
                search_text = f"{cve_id} {cve_info.get('description', '')} {cve_info.get('keywords', '')}".lower()
                if keyword_lower in search_text:
                    results.append({"id": cve_id, **cve_info})
                    if len(results) >= limit:
                        break

        return results

    def get_performance_stats(self) -> Dict[str, Any]:
        """获取性能统计"""
        return {
            "cve_database_loaded": self._cve_loaded,
            "cve_database_size_mb": round(os.path.getsize(
                os.path.join(self.project_root, "data", "vuln_database.json")
            ) / 1024 / 1024, 2) if os.path.exists(
                os.path.join(self.project_root, "data", "vuln_database.json")
            ) else 0,
            "cache_dir": self.cache_dir,
            "cache_files": len(os.listdir(self.cache_dir)) if os.path.exists(self.cache_dir) else 0,
            "python_version": sys.version
        }


# 全局缓存装饰器
def cached(ttl_seconds: int = 300):
    """带TTL的缓存装饰器"""
    def decorator(func):
        cache = {}

        def wrapper(*args, **kwargs):
            key = str(args) + str(kwargs)
            if key in cache:
                result, timestamp = cache[key]
                if time.time() - timestamp < ttl_seconds:
                    return result
            result = func(*args, **kwargs)
            cache[key] = (result, time.time())
            return result

        wrapper.cache_clear = cache.clear
        return wrapper
    return decorator
