# -*- coding: utf-8 -*-
"""真实 APK 解析：优先 androguard，否则内置解析器（AXML + ZIP 扫描）。"""
from __future__ import annotations

import io
import os
import re
import struct
import zipfile
from typing import Any, Dict, List, Optional

try:
    from androguard.core.apk import APK  # type: ignore
    _HAS_ANDROGUARD = True
except Exception:  # noqa: BLE001
    _HAS_ANDROGUARD = False


class ApkRealParser:
    """真实读取 APK 文件，输出包名/版本/权限/组件。不 mock。"""

    def __init__(self) -> None:
        self.has_androguard = _HAS_ANDROGUARD

    def available(self) -> Dict[str, Any]:
        return {
            "androguard": _HAS_ANDROGUARD,
            "fallback": "built-in axml parser" if not _HAS_ANDROGUARD else None,
        }

    def parse(self, apk_path: str) -> Dict[str, Any]:
        if not os.path.exists(apk_path):
            return {"success": False, "error": f"APK 文件不存在: {apk_path}"}
        if not zipfile.is_zipfile(apk_path):
            return {"success": False, "error": "不是有效的 APK/ZIP 文件"}

        if _HAS_ANDROGUARD:
            try:
                return self._parse_androguard(apk_path)
            except Exception as e:  # noqa: BLE001
                fallback = self._parse_builtin(apk_path)
                fallback["androguard_error"] = str(e)
                return fallback
        return self._parse_builtin(apk_path)

    # ---------- androguard 路径 ----------
    def _parse_androguard(self, path: str) -> Dict[str, Any]:
        a = APK(path)
        return {
            "success": True,
            "engine": "androguard",
            "package": a.get_package(),
            "version_code": a.get_androidversion_code(),
            "version_name": a.get_androidversion_name(),
            "min_sdk": a.get_min_sdk_version(),
            "target_sdk": a.get_target_sdk_version(),
            "permissions": sorted(a.get_permissions()),
            "activities": a.get_activities(),
            "services": a.get_services(),
            "receivers": a.get_receivers(),
            "providers": a.get_providers(),
            "main_activity": a.get_main_activity(),
            "files_in_apk": len(a.get_files()),
        }

    # ---------- 内置路径 ----------
    def _parse_builtin(self, path: str) -> Dict[str, Any]:
        try:
            with zipfile.ZipFile(path) as z:
                names = z.namelist()
                axml = z.read("AndroidManifest.xml")
        except KeyError:
            return {"success": False, "error": "APK 中缺少 AndroidManifest.xml"}
        except Exception as e:  # noqa: BLE001
            return {"success": False, "error": f"读取 APK 失败: {e}"}

        manifest = self._decode_axml(axml)
        perms = sorted(set(re.findall(r"uses-permission[^>]*android:name=\"([^\"]+)\"", manifest)))
        activities = re.findall(r"<activity[^>]*android:name=\"([^\"]+)\"", manifest)
        services = re.findall(r"<service[^>]*android:name=\"([^\"]+)\"", manifest)
        receivers = re.findall(r"<receiver[^>]*android:name=\"([^\"]+)\"", manifest)
        providers = re.findall(r"<provider[^>]*android:name=\"([^\"]+)\"", manifest)
        m = re.search(r"package=\"([^\"]+)\"", manifest)
        vc = re.search(r"versionCode=\"(\d+)\"", manifest)
        vn = re.search(r"versionName=\"([^\"]+)\"", manifest)
        minsdk = re.search(r"minSdkVersion=\"(\d+)\"", manifest)
        tgtsdk = re.search(r"targetSdkVersion=\"(\d+)\"", manifest)
        return {
            "success": True,
            "engine": "builtin-axml",
            "package": m.group(1) if m else "",
            "version_code": vc.group(1) if vc else "",
            "version_name": vn.group(1) if vn else "",
            "min_sdk": minsdk.group(1) if minsdk else "",
            "target_sdk": tgtsdk.group(1) if tgtsdk else "",
            "permissions": perms,
            "activities": activities,
            "services": services,
            "receivers": receivers,
            "providers": providers,
            "files_in_apk": len(names),
        }

    # ---------- 极简 AXML 字符串池解码 ----------
    def _decode_axml(self, data: bytes) -> str:
        """从二进制 AXML 中抽取字符串池，拼成近似 XML 文本供正则使用。"""
        try:
            # AXML 文件头: 魔数 0x00080003
            if len(data) < 8 or struct.unpack("<H", data[0:2])[0] != 0x0003:
                return data.decode("utf-8", errors="replace")
            # 找到 string pool chunk (type 0x0001)
            off = 8
            strings: List[str] = []
            while off + 8 <= len(data):
                ctype, hsize, csize = struct.unpack("<HHI", data[off:off + 8])
                if ctype == 0x0001:
                    scount, _style, flags, sstart, _stylestart = struct.unpack("<IIIII", data[off + 8:off + 28])
                    utf8 = bool(flags & (1 << 8))
                    off_idx = off + 28
                    str_offsets = struct.unpack(f"<{scount}I", data[off_idx:off_idx + scount * 4])
                    base = off + sstart
                    for so in str_offsets:
                        p = base + so
                        if utf8:
                            # u8 长度(1~2字节) 然后 utf8 字节
                            try:
                                ln = data[p]
                                if ln & 0x80:
                                    ln = ((ln & 0x7f) << 8) | data[p + 1]
                                    p += 2
                                else:
                                    p += 1
                                s = data[p + 1:p + 1 + ln].decode("utf-8", errors="replace")
                            except Exception:  # noqa: BLE001
                                s = ""
                        else:
                            try:
                                ln = struct.unpack("<H", data[p:p + 2])[0]
                                s = data[p + 2:p + 2 + ln * 2].decode("utf-16-le", errors="replace")
                            except Exception:  # noqa: BLE001
                                s = ""
                        strings.append(s)
                    break
                off += csize if csize else 8
            return " ".join(strings)
        except Exception:  # noqa: BLE001
            return data.decode("utf-8", errors="replace")
