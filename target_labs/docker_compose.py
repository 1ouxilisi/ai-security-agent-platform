# -*- coding: utf-8 -*-
"""
docker_compose.py - Docker Compose 生成器

根据选择的靶场生成 docker-compose.yml 内容（手动拼接 YAML，避免额外依赖问题）。
所有方法均包裹 try-except。仅用于授权环境。
"""

from __future__ import annotations

import logging
from typing import Any, Dict, List, Optional

from target_labs.manager import SUPPORTED_LABS, LabManager

logger = logging.getLogger(__name__)

# 需要挂载数据卷的靶场（需要持久化数据库）
_PERSIST_VOLUMES = {
    "dvwa": [("dvwa_data", "/var/lib/mysql")],
    "bwapp": [("bwapp_data", "/var/lib/mysql")],
}


class DockerComposeGenerator:
    """根据靶场选择生成 docker-compose.yml。"""

    NETWORK_NAME = "target-labs"
    DEFAULT_CPU = "0.5"
    DEFAULT_MEMORY = "512M"

    def __init__(self) -> None:
        self.manager = LabManager()

    # ------------------------------------------------------------------
    def _resolve_ports(self, lab_ids: List[str], base_ports: Optional[Dict[str, int]]) -> Dict[str, int]:
        """为每个靶场分配端口，冲突自动递增。"""
        try:
            used = set()
            resolved: Dict[str, int] = {}
            for lid in lab_ids:
                meta = SUPPORTED_LABS.get(lid)
                if not meta:
                    continue
                preferred = int((base_ports or {}).get(lid, meta["default_port"]))
                port = preferred
                while port in used or not self.manager._is_port_free(port):
                    port += 1
                used.add(port)
                resolved[lid] = port
            return resolved
        except Exception as e:  # noqa: BLE001
            logger.exception("_resolve_ports error")
            return {}

    # ------------------------------------------------------------------
    def generate_compose(self, lab_ids: List[str],
                         options: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
        """
        生成 docker-compose.yml 内容。

        Args:
            lab_ids: 要部署的靶场 id 列表
            options: 可选配置 {cpu, memory, network, ports:{...}}

        Returns:
            {"success": bool, "yaml": str, "resolved_ports": dict}
        """
        try:
            options = options or {}
            cpu = str(options.get("cpu", self.DEFAULT_CPU))
            memory = str(options.get("memory", self.DEFAULT_MEMORY))
            network = str(options.get("network", self.NETWORK_NAME))
            base_ports = options.get("ports") or {}
            ports = self._resolve_ports(lab_ids, base_ports)

            lines: List[str] = []
            lines.append("# ============================================================")
            lines.append("#  target-labs docker-compose.yml")
            lines.append("#  自动生成 - 仅限授权环境使用：仅用于授权安全测试/教学/演示")
            lines.append("# ============================================================")
            lines.append("version: '3.8'")
            lines.append("")
            lines.append("networks:")
            lines.append(f"  {network}:")
            lines.append("    driver: bridge")
            lines.append("")
            lines.append("volumes:")
            has_vol = False
            for lid in lab_ids:
                if lid in _PERSIST_VOLUMES:
                    has_vol = True
                    lines.append(f"  {lid}_data:")
            if not has_vol:
                lines.append("  # （本批次无需持久化卷）")
            lines.append("")
            lines.append("services:")

            for lid in lab_ids:
                meta = SUPPORTED_LABS.get(lid)
                if not meta:
                    continue
                port = ports.get(lid, meta["default_port"])
                lines.append(f"  {lid}:")
                lines.append(f"    image: {meta['docker_image']}")
                lines.append("    container_name: target-lab-" + lid)
                lines.append("    restart: unless-stopped")
                lines.append(f"    ports:")
                lines.append(f"      - \"{port}:80\"")
                lines.append(f"    networks:")
                lines.append(f"      - {network}")
                # 资源限制
                lines.append("    deploy:")
                lines.append("      resources:")
                lines.append("        limits:")
                lines.append(f"          cpus: '{cpu}'")
                lines.append(f"          memory: {memory}")
                # 环境变量
                lines.append("    environment:")
                if lid == "dvwa":
                    lines.append("      - OWASP_CSRF_TOKEN=enabled")
                    lines.append("      # DVWA 安全级别：low / medium / high / impossible")
                    lines.append("      - security_level=low")
                elif lid == "bwapp":
                    lines.append("      - VIRTUAL_HOST=bwapp.local")
                else:
                    lines.append("      # （无特殊环境变量）")
                # 数据持久化
                if lid in _PERSIST_VOLUMES:
                    lines.append("    volumes:")
                    for vol_name, container_path in _PERSIST_VOLUMES[lid]:
                        lines.append(f"      - {vol_name}:{container_path}")
                lines.append("")

            return {
                "success": True,
                "yaml": "\n".join(lines) + "\n",
                "resolved_ports": ports,
                "network": network,
                "notice": "仅限授权环境使用。",
            }
        except Exception as e:  # noqa: BLE001
            logger.exception("generate_compose error")
            return {"success": False, "error": str(e), "yaml": ""}
