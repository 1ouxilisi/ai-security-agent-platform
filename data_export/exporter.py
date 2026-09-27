# -*- coding: utf-8 -*-
"""
exporter.py - Vulnerability data exporter.

Formats: JSON, CSV, XLSX (openpyxl optional), PDF (minimal hand-built), HTML.
"""

import csv
import io
import json
from typing import Dict, List, Any, Optional

try:
    from openpyxl import Workbook  # type: ignore
    _HAS_OPENPYXL = True
except Exception:  # noqa: BLE001
    _HAS_OPENPYXL = False


SUPPORTED_FORMATS = ["json", "csv", "xlsx", "pdf", "html"]

ALL_FIELDS = [
    "id", "title", "severity", "cve", "description", "solution",
    "url", "port", "service", "found_time", "scanner_source",
]

EXPORT_TEMPLATES = {
    "full_report": {
        "name": "Full Report",
        "description": "Export all fields for every vulnerability",
        "fields": ALL_FIELDS,
    },
    "brief_list": {
        "name": "Brief List",
        "description": "Minimal list: title / severity / cve / url",
        "fields": ["title", "severity", "cve", "url"],
    },
    "executive_summary": {
        "name": "Executive Summary",
        "description": "Severity stats + high-risk vuln list",
        "fields": ["title", "severity", "cve", "url", "found_time"],
    },
    "technical_details": {
        "name": "Technical Details",
        "description": "Title / severity / cve / description / solution / url / port / service",
        "fields": ["title", "severity", "cve", "description", "solution", "url", "port", "service"],
    },
}


def list_export_templates() -> List[Dict[str, Any]]:
    return [{"template_id": k, **v} for k, v in EXPORT_TEMPLATES.items()]


def list_supported_formats() -> List[Dict[str, Any]]:
    return [
        {"format": f, "available": (f != "xlsx" or _HAS_OPENPYXL),
         "extension": _EXT_OF(f)}
        for f in SUPPORTED_FORMATS
    ]


def _EXT_OF(fmt: str) -> str:
    return {"json": "json", "csv": "csv", "xlsx": "xlsx", "pdf": "pdf", "html": "html"}.get(fmt, "txt")


def _filter_vulns(vulns: List[Dict[str, Any]], filters: Dict[str, Any]) -> List[Dict[str, Any]]:
    if not filters:
        return vulns
    sev = filters.get("severity")
    port = filters.get("port")
    service = filters.get("service")
    time_from = filters.get("time_from")
    time_to = filters.get("time_to")
    out = []
    for v in vulns:
        if sev and v.get("severity") != sev:
            continue
        if port and str(v.get("port", "")) != str(port):
            continue
        if service and str(v.get("service", "")).lower() != str(service).lower():
            continue
        ft = v.get("found_time", "")
        if time_from and ft and ft < time_from:
            continue
        if time_to and ft and ft > time_to:
            continue
        out.append(v)
    return out


def _select_fields(vulns: List[Dict[str, Any]], fields: Optional[List[str]]) -> List[Dict[str, Any]]:
    if not fields:
        return vulns
    return [{f: v.get(f, "") for f in fields} for v in vulns]


def _export_json(vulns: List[Dict[str, Any]]) -> bytes:
    return json.dumps(vulns, ensure_ascii=False, indent=2).encode("utf-8")


def _export_csv(vulns: List[Dict[str, Any]], fields: List[str]) -> bytes:
    buf = io.StringIO()
    writer = csv.DictWriter(buf, fieldnames=fields, extrasaction="ignore")
    writer.writeheader()
    for v in vulns:
        writer.writerow({f: v.get(f, "") for f in fields})
    return buf.getvalue().encode("utf-8-sig")


def _export_xlsx(vulns: List[Dict[str, Any]], fields: List[str]) -> bytes:
    if not _HAS_OPENPYXL:
        # Fallback to CSV.
        return _export_csv(vulns, fields)
    wb = Workbook()
    ws = wb.active
    ws.title = "Vulnerabilities"
    ws.append(fields)
    for v in vulns:
        ws.append([v.get(f, "") for f in fields])
    buf = io.BytesIO()
    wb.save(buf)
    return buf.getvalue()


def _export_html(vulns: List[Dict[str, Any]], fields: List[str], title: str) -> bytes:
    rows = []
    for v in vulns:
        cells = "".join(
            f"<td>{_esc(str(v.get(f, '')))}</td>" for f in fields
        )
        rows.append(f"<tr>{cells}</tr>")
    head = "".join(f"<th>{_esc(f)}</th>" for f in fields)
    html = f"""<!DOCTYPE html>
<html lang="zh-CN"><head><meta charset="utf-8">
<title>{_esc(title)}</title>
<style>
body {{ background:#0f1419; color:#e6e6e6; font-family:Segoe UI,Arial; margin:24px; }}
h1 {{ color:#4fc3f7; }}
table {{ border-collapse:collapse; width:100%; margin-top:12px; }}
th,td {{ border:1px solid #2a3441; padding:8px; text-align:left; font-size:13px; }}
th {{ background:#1c2530; color:#4fc3f7; }}
tr:nth-child(even) {{ background:#161d26; }}
</style></head><body>
<h1>{_esc(title)}</h1>
<p>Total records: {len(vulns)}</p>
<table><thead><tr>{head}</tr></thead><tbody>{''.join(rows)}</tbody></table>
</body></html>"""
    return html.encode("utf-8")


def _esc(s: str) -> str:
    return (
        s.replace("&", "&amp;").replace("<", "&lt;")
        .replace(">", "&gt;").replace('"', "&quot;")
    )


def _export_pdf(vulns: List[Dict[str, Any]], fields: List[str], title: str) -> bytes:
    """Build a minimal one-line PDF (text page). No reportlab."""
    lines = [title, "=" * len(title), f"Total: {len(vulns)}", ""]
    for i, v in enumerate(vulns[:500], 1):
        line = f"[{i}] " + " | ".join(f"{f}={v.get(f,'')}" for f in fields)
        # PDF latin-1 safe truncation.
        lines.append(line[:200])
    text = "\n".join(lines)
    # Escape parentheses for PDF string.
    safe = text.replace("\\", "\\\\").replace("(", "\\(").replace(")", "\\)")
    safe = safe.encode("latin-1", errors="replace").decode("latin-1")
    stream = f"BT /F1 10 Tf 50 780 Td ({safe}) Tj ET"
    objects = [
        "<< /Type /Catalog /Pages 2 0 R >>",
        "<< /Type /Pages /Kids [3 0 R] /Count 1 >>",
        "<< /Type /Page /Parent 2 0 R /MediaBox [0 0 612 792] /Contents 4 0 R /Resources << /Font << /F1 5 0 R >> >> >>",
        f"<< /Length {len(stream)} >>\nstream\n{stream}\nendstream",
        "<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica >>",
    ]
    out = bytearray(b"%PDF-1.4\n")
    offsets = []
    for i, obj in enumerate(objects, 1):
        offsets.append(len(out))
        out += f"{i} 0 obj\n{obj}\nendobj\n".encode("latin-1", errors="replace")
    xref_pos = len(out)
    out += f"xref\n0 {len(objects)+1}\n".encode()
    out += b"0000000000 65535 f \n"
    for off in offsets:
        out += f"{off:010d} 00000 n \n".encode()
    out += (
        f"trailer\n<< /Size {len(objects)+1} /Root 1 0 R >>\n"
        f"startxref\n{xref_pos}\n%%EOF\n"
    ).encode()
    return bytes(out)


def export_data(
    vulns: List[Dict[str, Any]],
    fmt: str,
    options: Optional[Dict[str, Any]] = None,
) -> Dict[str, Any]:
    """Export vulns. Returns {content(bytes), extension, content_type, count}."""
    options = options or {}
    fmt = (fmt or "json").lower()

    # Template resolution.
    template_id = options.get("template")
    fields = options.get("fields")
    if template_id and template_id in EXPORT_TEMPLATES and not fields:
        fields = EXPORT_TEMPLATES[template_id]["fields"]
    if not fields:
        fields = ALL_FIELDS

    # Filters.
    filtered = _filter_vulns(vulns, options.get("filters") or {})

    # Executive summary is special: produce stats + high-risk list.
    if template_id == "executive_summary":
        stats: Dict[str, int] = {}
        high_list = []
        for v in filtered:
            s = v.get("severity", "info")
            stats[s] = stats.get(s, 0) + 1
            if s in ("critical", "high"):
                high_list.append({k: v.get(k, "") for k in fields})
        payload = {
            "severity_distribution": stats,
            "high_risk_list": high_list,
            "total": len(filtered),
        }
        if fmt == "json":
            return {"content": json.dumps(payload, ensure_ascii=False, indent=2).encode("utf-8"),
                    "extension": "json", "count": len(filtered)}
        # Fall through to HTML/table for other formats.
        filtered = high_list

    selected = _select_fields(filtered, fields)

    # Batch processing (simulate chunking).
    chunk_size = 1000
    chunks = [selected[i:i + chunk_size] for i in range(0, len(selected), chunk_size)] or [[]]
    if fmt == "json":
        content = _export_json(selected)
        ext, ctype = "json", "application/json"
    elif fmt == "csv":
        content = _export_csv(selected, fields)
        ext, ctype = "csv", "text/csv"
    elif fmt == "xlsx":
        content = _export_xlsx(selected, fields)
        ext = "xlsx" if _HAS_OPENPYXL else "csv"
        ctype = "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet"
    elif fmt == "html":
        content = _export_html(selected, fields, options.get("title", "Vulnerability Report"))
        ext, ctype = "html", "text/html"
    elif fmt == "pdf":
        content = _export_pdf(selected, fields, options.get("title", "Vulnerability Report"))
        ext, ctype = "pdf", "application/pdf"
    else:
        content = _export_json(selected)
        ext, ctype = "json", "application/json"

    return {
        "content": content,
        "extension": ext,
        "content_type": ctype,
        "count": len(selected),
        "chunks": len(chunks),
    }
