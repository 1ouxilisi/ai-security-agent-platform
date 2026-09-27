#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
扫描引擎模块
整合Nmap、Nuclei、SQLMap、Nikto的专业扫描引擎
"""

from .nmap_wrapper import (
    NmapWrapper,
    NmapScanResult,
    HostInfo,
    PortInfo,
)
from .nuclei_wrapper import (
    NucleiWrapper,
    NucleiScanResult,
    NucleiFinding,
)
from .sqlmap_wrapper import (
    SqlmapWrapper,
    SqlmapScanResult,
    SqlInjectionFinding,
)
from .nikto_wrapper import (
    NiktoWrapper,
    NiktoScanResult,
    NiktoFinding,
)
from .scan_orchestrator import (
    ScanOrchestrator,
    UnifiedScanResult,
    ScanTask,
)

__all__ = [
    # Nmap
    "NmapWrapper",
    "NmapScanResult",
    "HostInfo",
    "PortInfo",
    # Nuclei
    "NucleiWrapper",
    "NucleiScanResult",
    "NucleiFinding",
    # SQLMap
    "SqlmapWrapper",
    "SqlmapScanResult",
    "SqlInjectionFinding",
    # Nikto
    "NiktoWrapper",
    "NiktoScanResult",
    "NiktoFinding",
    # Orchestrator
    "ScanOrchestrator",
    "UnifiedScanResult",
    "ScanTask",
]

__version__ = "2.0.0"
