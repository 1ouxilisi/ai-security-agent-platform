# -*- coding: utf-8 -*-
"""
disk_forensics_phase.py — 阶段3：磁盘取证。

功能:
    - 文件系统分析（NTFS/EXT4/FAT32/exFAT/HFS+）
    - 已删除文件恢复（$MFT/Inode/file carving）
    - 文件 carving（基于签名/结构）
    - 元数据分析（MAC时间/属性/所有者）
    - 时间线重建（MAC时间/文件活动/系统事件）
    - 注册表分析 / 回收站 / Prefetch / 浏览器历史 / 邮件 / 加密容器检测
"""

from __future__ import annotations

import os
import random
import threading
import uuid
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from typing import Any, Dict, List, Optional

FILESYSTEMS = ["NTFS", "EXT4", "FAT32", "exFAT", "HFS+"]
MFT_RECORD_SIZE = 1024


@dataclass
class FileEntry:
    file_id: str = ""
    path: str = ""
    filename: str = ""
    size_bytes: int = 0
    created: str = ""
    modified: str = ""
    accessed: str = ""
    mft_modified: str = ""
    owner: str = ""
    deleted: bool = False
    recovered: bool = False
    fs_type: str = "NTFS"
    mime: str = ""

    def to_dict(self) -> Dict[str, Any]:
        return {
            "file_id": self.file_id, "path": self.path,
            "filename": self.filename, "size_bytes": self.size_bytes,
            "created": self.created, "modified": self.modified,
            "accessed": self.accessed, "mft_modified": self.mft_modified,
            "owner": self.owner, "deleted": self.deleted,
            "recovered": self.recovered, "fs_type": self.fs_type,
            "mime": self.mime,
        }


@dataclass
class RegRecord:
    key: str = ""
    value_name: str = ""
    value: str = ""
    category: str = ""   # user_activity/software/network/usb/startup

    def to_dict(self) -> Dict[str, Any]:
        return {"key": self.key, "value_name": self.value_name,
                "value": self.value, "category": self.category}


# 内置模拟数据
_FAKE_FILES = [
    ("C:\\Users\\Administrator\\Desktop\\bank_stmt.pdf", "application/pdf",
     245760),
    ("C:\\Users\\Admin\\Downloads\\update.exe", "application/x-msdownload",
     4567890),
    ("C:\\Users\\Admin\\AppData\\Local\\Temp\\payload.dll",
     "application/x-dosexec", 102400),
    ("C:\\Windows\\System32\\config\\SYSTEM", "application/registry",
     16777216),
    ("C:\\Users\\Admin\\Documents\\passwords.txt", "text/plain", 4096),
    ("C:\\ProgramData\\Microsoft\\Windows\\Start Menu\\Programs\\Startup\\"
     "backdoor.vbs", "text/vbscript", 2048),
]

_FAKE_REG = [
    ("HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run",
     "UpdateChecker", "C:\\Temp\\upd.exe", "startup"),
    ("HKLM\\SYSTEM\\CurrentControlSet\\Enum\\USB",
     "USBSTOR\\Disk&Ven_Kingston", "U盘序列号: 001A4B2C", "usb"),
    ("HKCU\\Network\\Recent",
     "\\\\10.0.0.5\\c$", "最近访问网络共享", "network"),
    ("HKLM\\Software\\Microsoft\\Windows\\CurrentVersion\\Uninstall",
     "Tor Browser", "版本 13.0.1", "software"),
    ("HKCU\\Software\\Microsoft\\Windows\\Shell\\Bags",
     "RecentDocs", "最近打开文档记录", "user_activity"),
]

_SIGNATURES = {
    "%PDF": "application/pdf",
    "MZ": "application/x-msdownload",
    "PK\x03\x04": "application/zip",
    "\x89PNG": "image/png",
    "\xFF\xD8\xFF": "image/jpeg",
}


class DiskForensicsPhase:
    """阶段3：磁盘取证。"""

    def __init__(self) -> None:
        self._files: Dict[str, FileEntry] = {}
        self._registry: List[RegRecord] = []
        self._timeline: List[Dict[str, Any]] = []
        self._lock = threading.Lock()
        self._seed_data()

    # ------------------------------------------------------------------ #
    def _seed_data(self) -> None:
        base = datetime.now() - timedelta(days=7)
        rng = random.Random(20260920)
        for path, mime, size in _FAKE_FILES:
            fid = "F-" + uuid.uuid4().hex[:8]
            created = base + timedelta(hours=rng.randint(1, 100))
            modified = created + timedelta(hours=rng.randint(0, 20))
            fe = FileEntry(
                file_id=fid, path=path,
                filename=os.path.basename(path),
                size_bytes=size,
                created=created.isoformat(timespec="seconds"),
                modified=modified.isoformat(timespec="seconds"),
                accessed=(modified + timedelta(hours=2)).isoformat(
                    timespec="seconds"),
                mft_modified=modified.isoformat(timespec="seconds"),
                owner="Administrator" if "Admin" in path else "SYSTEM",
                deleted=(rng.random() < 0.3),
                fs_type="NTFS", mime=mime,
            )
            self._files[fid] = fe
            self._timeline.append({
                "time": fe.modified, "type": "file_modified",
                "detail": fe.path, "actor": fe.owner,
            })
        for key, vn, val, cat in _FAKE_REG:
            self._registry.append(
                RegRecord(key=key, value_name=vn, value=val,
                          category=cat))

    # ------------------------------------------------------------------ #
    def analyze_filesystem(self, fs_type: str = "NTFS") -> Dict[str, Any]:
        if fs_type not in FILESYSTEMS:
            fs_type = "NTFS"
        with self._lock:
            total = len(self._files)
            deleted = sum(1 for f in self._files.values() if f.deleted)
            size = sum(f.size_bytes for f in self._files.values())
        return {
            "filesystem": fs_type,
            "total_files": total, "deleted_files": deleted,
            "total_size_mb": round(size / 1048576, 2),
            "mft_records": total * 4,
            "inode_analysis": "Inode 位图已扫描",
        }

    # ------------------------------------------------------------------ #
    def recover_deleted(self, evidence_id: str = "") -> Dict[str, Any]:
        recovered: List[Dict[str, Any]] = []
        with self._lock:
            for f in self._files.values():
                if f.deleted and not f.recovered:
                    f.recovered = True
                    f.deleted = False
                    recovered.append(f.to_dict())
        return {
            "recovered_count": len(recovered),
            "method": "$MFT 记录恢复 + 文件签名 carving",
            "files": recovered[:20],
        }

    # ------------------------------------------------------------------ #
    def file_carving(self, max_files: int = 50) -> Dict[str, Any]:
        carved: List[Dict[str, Any]] = []
        rng = random.Random(7)
        for sig, mime in list(_SIGNATURES.items())[:max_files]:
            carved.append({
                "signature": sig,
                "mime": mime,
                "offset_hex": hex(rng.randint(0x100000, 0x5000000)),
                "size_bytes": rng.randint(2048, 4096000),
                "recovered": True,
            })
        return {"carved_count": len(carved), "files": carved}

    # ------------------------------------------------------------------ #
    def metadata_analysis(self) -> Dict[str, Any]:
        with self._lock:
            items = [f.to_dict() for f in self._files.values()]
        return {
            "total": len(items),
            "fields": ["created", "modified", "accessed",
                       "mft_modified", "owner", "mime"],
            "samples": items[:10],
        }

    # ------------------------------------------------------------------ #
    def build_timeline(self) -> Dict[str, Any]:
        with self._lock:
            tl = sorted(self._timeline, key=lambda x: x["time"])
        return {
            "events": len(tl),
            "timeline": tl[-50:],
            "range": {
                "from": tl[0]["time"] if tl else "",
                "to": tl[-1]["time"] if tl else "",
            },
        }

    # ------------------------------------------------------------------ #
    def registry_analysis(self) -> Dict[str, Any]:
        with self._lock:
            items = [r.to_dict() for r in self._registry]
        by_cat: Dict[str, int] = {}
        for r in self._registry:
            by_cat[r.category] = by_cat.get(r.category, 0) + 1
        return {
            "hives_scanned": ["SYSTEM", "SOFTWARE", "NTUSER.DAT",
                              "SECURITY"],
            "categories": by_cat,
            "records": items,
            "userassist_hits": 2,
            "shimcache_entries": 12,
        }

    # ------------------------------------------------------------------ #
    def recycle_bin_analysis(self) -> Dict[str, Any]:
        return {
            "recycle_items": 5,
            "items": [
                {"original_path": "C:\\Users\\Admin\\setup_log.txt",
                 "deleted_time": (datetime.now() -
                                  timedelta(hours=5)).isoformat(
                                      timespec="seconds")},
                {"original_path": "C:\\Users\\Admin\\old_keys.pem",
                 "deleted_time": (datetime.now() -
                                  timedelta(days=2)).isoformat(
                                      timespec="seconds")},
            ],
        }

    # ------------------------------------------------------------------ #
    def prefetch_analysis(self) -> Dict[str, Any]:
        return {
            "prefetch_files": 18,
            "executables": [
                {"name": "mimikatz.exe", "run_count": 3,
                 "last_run": (datetime.now() -
                              timedelta(hours=8)).isoformat(
                                  timespec="seconds")},
                {"name": "cmd.exe", "run_count": 47,
                 "last_run": datetime.now().isoformat(timespec="seconds")},
                {"name": "procdump.exe", "run_count": 2,
                 "last_run": (datetime.now() -
                              timedelta(hours=3)).isoformat(
                                  timespec="seconds")},
            ],
        }

    # ------------------------------------------------------------------ #
    def browser_history(self, browser: str = "chrome") -> Dict[str, Any]:
        return {
            "browser": browser,
            "history_entries": 120,
            "top_visited": [
                {"url": "https://pastebin.com/raw/xyz",
                 "visits": 8, "title": "exfil paste"},
                {"url": "https://mega.nz/#folders/x",
                 "visits": 4, "title": "Mega 云盘"},
                {"url": "https://whoer.net",
                 "visits": 12, "title": "匿名检测"},
            ],
        }

    # ------------------------------------------------------------------ #
    def email_analysis(self, client: str = "outlook") -> Dict[str, Any]:
        return {
            "client": client,
            "mailbox_size_mb": 256,
            "suspicious_mails": [
                {"from": "hr@fake-company.com",
                 "subject": "紧急：薪资调整通知",
                 "has_attachment": True,
                 "attachment": "update.zip",
                 "received": (datetime.now() -
                              timedelta(days=1)).isoformat(
                                  timespec="seconds")},
            ],
        }

    # ------------------------------------------------------------------ #
    def encrypted_container_detect(self) -> Dict[str, Any]:
        return {
            "containers": [
                {"type": "VeraCrypt", "path": "D:\\secure.vc",
                 "size_mb": 512, "mounted": False},
                {"type": "BitLocker", "path": "\\\\.\\C:",
                 "status": "encrypted"},
            ],
            "truecrypt_detected": False,
        }

    # ------------------------------------------------------------------ #
    def stats(self) -> Dict[str, Any]:
        with self._lock:
            total = len(self._files)
            deleted = sum(1 for f in self._files.values() if f.deleted)
        return {
            "files_total": total, "deleted": deleted,
            "recovered": total - deleted,
            "registry_keys": len(self._registry),
            "timeline_events": len(self._timeline),
        }


_default: Optional[DiskForensicsPhase] = None


def get_disk_forensics_phase() -> DiskForensicsPhase:
    global _default
    if _default is None:
        _default = DiskForensicsPhase()
    return _default
