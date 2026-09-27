# -*- coding: utf-8 -*-
"""
parsers.py - Scan result parsers for multiple scanner formats.

Supports: Nessus, OpenVAS, Burp Suite, Nmap, Acunetix, AppScan.
Uses xml.etree.ElementTree only (no third-party deps).
"""

import os
import re
import xml.etree.ElementTree as ET
from datetime import datetime
from typing import Dict, List, Any, Optional


# Severity normalization map across scanners.
SEVERITY_MAP = {
    # nessus / generic risk_factor
    "critical": "critical",
    "high": "high",
    "medium": "medium",
    "low": "low",
    "info": "info",
    "none": "info",
    # openvas threat
    "log": "info",
    "debug": "info",
    # burp
    "high severity": "high",
    "medium severity": "medium",
    "low severity": "low",
    "information": "info",
    # acunetix / appscan textual
    "high risk": "high",
    "medium risk": "medium",
    "low risk": "low",
    "informational": "info",
}


def normalize_severity(raw: Optional[str]) -> str:
    """Normalize a raw severity string to critical/high/medium/low/info."""
    if not raw:
        return "info"
    key = str(raw).strip().lower()
    return SEVERITY_MAP.get(key, "info")


def _empty_vuln() -> Dict[str, Any]:
    return {
        "title": "",
        "severity": "info",
        "cve": "",
        "description": "",
        "solution": "",
        "url": "",
        "port": "",
        "service": "",
        "found_time": "",
        "scanner_source": "",
    }


def _text(el: Optional[ET.Element]) -> str:
    if el is None:
        return ""
    return (el.text or "").strip()


def _first_text(parent: ET.Element, tag: str) -> str:
    el = parent.find(tag)
    return _text(el)


class BaseParser:
    """Base class for all scan result parsers."""

    scanner_source: str = "unknown"

    def parse(self, file_path: str) -> Dict[str, Any]:
        """Parse file -> standardized vuln list. Never raises."""
        raise NotImplementedError

    def validate(self, data: Any) -> bool:
        """Validate parsed data shape."""
        return isinstance(data, list) and all(
            isinstance(v, dict) and "title" in v for v in data
        )

    def normalize(self, raw_data: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """Normalize raw records into the unified vulnerability dict."""
        out = []
        for rec in raw_data:
            vuln = _empty_vuln()
            vuln.update(rec)
            vuln["severity"] = normalize_severity(vuln.get("severity"))
            vuln["scanner_source"] = vuln.get("scanner_source") or self.scanner_source
            if not vuln.get("found_time"):
                vuln["found_time"] = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
            out.append(vuln)
        return out


class NessusParser(BaseParser):
    """Parse .nessus XML (ReportHost / ReportItem)."""

    scanner_source = "nessus"

    def parse(self, file_path: str) -> Dict[str, Any]:
        result = {"vulns": [], "error": None, "total": 0}
        try:
            tree = ET.parse(file_path)
            root = tree.getroot()
            raw = []
            for host in root.iter("ReportHost"):
                host_ip = host.get("name", "")
                for item in host.iter("ReportItem"):
                    rec = _empty_vuln()
                    rec["title"] = item.get("plugin_name", "") or item.get("id", "")
                    rec["severity"] = _first_text(item, "risk_factor") or "info"
                    rec["cve"] = _first_text(item, "cve")
                    rec["description"] = _first_text(item, "description")
                    rec["solution"] = _first_text(item, "solution")
                    rec["port"] = item.get("port", "")
                    rec["service"] = item.get("svc_name", "") or item.get("protocol", "")
                    rec["url"] = f"{host_ip}:{rec['port']}" if rec["port"] else host_ip
                    rec["scanner_source"] = self.scanner_source
                    raw.append(rec)
            result["vulns"] = self.normalize(raw)
            result["total"] = len(result["vulns"])
        except Exception as e:  # noqa: BLE001
            result["error"] = f"Nessus parse failed: {e}"
        return result


class OpenVASParser(BaseParser):
    """Parse OpenVAS XML (results/result)."""

    scanner_source = "openvas"

    def parse(self, file_path: str) -> Dict[str, Any]:
        result = {"vulns": [], "error": None, "total": 0}
        try:
            tree = ET.parse(file_path)
            root = tree.getroot()
            raw = []
            for r in root.iter("result"):
                rec = _empty_vuln()
                rec["title"] = _first_text(r, "name")
                rec["severity"] = _first_text(r, "threat") or "info"
                cve_el = r.find("cve")
                rec["cve"] = _text(cve_el)
                rec["description"] = _first_text(r, "description")
                port_el = r.find("port")
                rec["port"] = _text(port_el)
                host_el = r.find("host")
                host = _text(host_el)
                rec["url"] = host
                rec["service"] = ""
                rec["scanner_source"] = self.scanner_source
                if rec["title"]:
                    raw.append(rec)
            result["vulns"] = self.normalize(raw)
            result["total"] = len(result["vulns"])
        except Exception as e:  # noqa: BLE001
            result["error"] = f"OpenVAS parse failed: {e}"
        return result


class BurpParser(BaseParser):
    """Parse Burp Suite XML (issues/issue)."""

    scanner_source = "burp"

    def parse(self, file_path: str) -> Dict[str, Any]:
        result = {"vulns": [], "error": None, "total": 0}
        try:
            tree = ET.parse(file_path)
            root = tree.getroot()
            raw = []
            for issue in root.iter("issue"):
                rec = _empty_vuln()
                rec["title"] = _first_text(issue, "name")
                rec["severity"] = _first_text(issue, "severity") or "info"
                rec["cve"] = _first_text(issue, "cve")
                rec["description"] = _first_text(issue, "issueDetail")
                rec["solution"] = _first_text(issue, "remediationBackground")
                host_el = issue.find("host")
                rec["url"] = _text(host_el)
                rec["port"] = _first_text(issue, "port")
                rec["service"] = _first_text(issue, "protocol")
                rec["scanner_source"] = self.scanner_source
                raw.append(rec)
            result["vulns"] = self.normalize(raw)
            result["total"] = len(result["vulns"])
        except Exception as e:  # noqa: BLE001
            result["error"] = f"Burp parse failed: {e}"
        return result


class NmapParser(BaseParser):
    """Parse Nmap XML (nmaprun/host/ports/port/script). Ports/services as info."""

    scanner_source = "nmap"

    def parse(self, file_path: str) -> Dict[str, Any]:
        result = {"vulns": [], "error": None, "total": 0}
        try:
            tree = ET.parse(file_path)
            root = tree.getroot()
            raw = []
            for host in root.iter("host"):
                addr_el = host.find("address")
                host_ip = addr_el.get("addr", "") if addr_el is not None else ""
                for port in host.iter("port"):
                    portid = port.get("portid", "")
                    protocol = port.get("protocol", "")
                    state_el = port.find("state")
                    state = state_el.get("state", "") if state_el is not None else ""
                    if state and state != "open":
                        continue
                    svc_el = port.find("service")
                    svc_name = svc_el.get("name", "") if svc_el is not None else ""
                    rec = _empty_vuln()
                    rec["title"] = f"Open port {portid}/{protocol} ({svc_name})"
                    rec["severity"] = "info"
                    rec["cve"] = ""
                    rec["description"] = f"Host {host_ip} exposes {svc_name} on {portid}/{protocol}"
                    rec["solution"] = "Close unused ports or restrict access."
                    rec["url"] = f"{host_ip}:{portid}"
                    rec["port"] = portid
                    rec["service"] = svc_name
                    rec["scanner_source"] = self.scanner_source
                    raw.append(rec)
                    for script in port.iter("script"):
                        sid = script.get("id", "")
                        out = (script.get("output", "") or "").strip()
                        srec = _empty_vuln()
                        srec["title"] = f"nmap-script: {sid}"
                        srec["severity"] = "info"
                        srec["description"] = out[:2000]
                        srec["port"] = portid
                        srec["service"] = svc_name
                        srec["url"] = f"{host_ip}:{portid}"
                        srec["scanner_source"] = self.scanner_source
                        raw.append(srec)
            result["vulns"] = self.normalize(raw)
            result["total"] = len(result["vulns"])
        except Exception as e:  # noqa: BLE001
            result["error"] = f"Nmap parse failed: {e}"
        return result


class AcunetixParser(BaseParser):
    """Parse Acunetix XML (ScanGroup/ReportItem)."""

    scanner_source = "acunetix"

    def parse(self, file_path: str) -> Dict[str, Any]:
        result = {"vulns": [], "error": None, "total": 0}
        try:
            tree = ET.parse(file_path)
            root = tree.getroot()
            raw = []
            for item in root.iter("ReportItem"):
                rec = _empty_vuln()
                rec["title"] = _first_text(item, "Name") or item.get("Name", "")
                rec["severity"] = _first_text(item, "Severity") or "info"
                rec["cve"] = _first_text(item, "CVE")
                rec["description"] = _first_text(item, "Description")
                rec["solution"] = _first_text(item, "Recommendation")
                rec["url"] = _first_text(item, "Affects") or _first_text(item, "URL")
                rec["port"] = _first_text(item, "Port")
                rec["service"] = _first_text(item, "Module")
                rec["scanner_source"] = self.scanner_source
                raw.append(rec)
            result["vulns"] = self.normalize(raw)
            result["total"] = len(result["vulns"])
        except Exception as e:  # noqa: BLE001
            result["error"] = f"Acunetix parse failed: {e}"
        return result


class AppScanParser(BaseParser):
    """Parse AppScan XML (results/result)."""

    scanner_source = "appscan"

    def parse(self, file_path: str) -> Dict[str, Any]:
        result = {"vulns": [], "error": None, "total": 0}
        try:
            tree = ET.parse(file_path)
            root = tree.getroot()
            raw = []
            for r in root.iter("result"):
                rec = _empty_vuln()
                rec["title"] = _first_text(r, "name")
                rec["severity"] = _first_text(r, "severity") or "info"
                rec["cve"] = _first_text(r, "cve")
                rec["description"] = _first_text(r, "description")
                rec["solution"] = _first_text(r, "solution")
                rec["url"] = _first_text(r, "url")
                rec["port"] = _first_text(r, "port")
                rec["service"] = _first_text(r, "service")
                rec["scanner_source"] = self.scanner_source
                if rec["title"]:
                    raw.append(rec)
            result["vulns"] = self.normalize(raw)
            result["total"] = len(result["vulns"])
        except Exception as e:  # noqa: BLE001
            result["error"] = f"AppScan parse failed: {e}"
        return result


# Format detection.
_EXT_MAP = {
    ".nessus": "nessus",
    ".xml": "auto",
}

_ROOT_HINTS = [
    ("NessusClientData_v2", "nessus"),
    ("NessusClientData", "nessus"),
    ("nmaprun", "nmap"),
    ("issues", "burp"),
    ("ScanGroup", "acunetix"),
    ("results", "appscan"),
]


def detect_format(file_path: str) -> str:
    """Detect scanner type from extension + XML root element. Returns scanner key or 'unknown'."""
    try:
        ext = os.path.splitext(file_path)[1].lower()
        # Quick sniff root element.
        root_tag = ""
        with open(file_path, "rb") as f:
            # Stream: read first 4KB to find root start tag.
            head = f.read(4096)
        m = re.search(rb"<([A-Za-z_][\w.-]*)[\s>]", head)
        if m:
            root_tag = m.group(1).decode("utf-8", errors="ignore")
        for tag, scanner in _ROOT_HINTS:
            if root_tag == tag:
                return scanner
        # OpenVAS uses <report> ... <results>; detect by content markers.
        try:
            with open(file_path, "rb") as f:
                blob = f.read(8192)
            if b"<results>" in blob or b"<result>" in blob and b"threat" in blob:
                return "openvas"
            if b"ReportHost" in blob:
                return "nessus"
            if b"issues" in blob and b"issue" in blob:
                return "burp"
        except Exception:  # noqa: BLE001
            pass
        if ext == ".nessus":
            return "nessus"
        return "unknown"
    except Exception:  # noqa: BLE001
        return "unknown"


_PARSERS = {
    "nessus": NessusParser,
    "openvas": OpenVASParser,
    "burp": BurpParser,
    "nmap": NmapParser,
    "acunetix": AcunetixParser,
    "appscan": AppScanParser,
}


def parse_file(file_path: str) -> Dict[str, Any]:
    """Auto-detect format and parse. Returns {scanner, vulns, total, error}."""
    scanner = detect_format(file_path)
    if scanner not in _PARSERS:
        return {
            "scanner": scanner,
            "vulns": [],
            "total": 0,
            "error": f"Unknown or unsupported scan format: {scanner}",
        }
    parser = _PARSERS[scanner]()
    res = parser.parse(file_path)
    res["scanner"] = scanner
    return res


def deduplicate(vulns: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """Deduplicate by cve+url+port combination."""
    seen = set()
    out = []
    for v in vulns:
        key = (
            (v.get("cve") or "").strip().lower(),
            (v.get("url") or "").strip().lower(),
            str(v.get("port") or "").strip(),
        )
        if key in seen:
            continue
        seen.add(key)
        out.append(v)
    return out
