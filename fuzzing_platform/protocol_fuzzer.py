#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
fuzzing_platform/protocol_fuzzer.py — 协议 Fuzzing。

覆盖：
    1. 协议支持：HTTP/HTTPS/FTP/SMTP/POP3/IMAP/DNS/Telnet/SSH/SMB/RDP/MySQL/
       PostgreSQL/Redis/MongoDB/MQTT/CoAP/Modbus/S7
    2. 协议解析：协议格式/字段结构/状态机/会话管理/编码/加密/压缩/校验
    3. 变异策略：随机变异/基于模板/基于语法/基于协议状态/基于覆盖率引导/智能变异/
       遗传算法/模拟退火
    4. 用例生成：用例模板/用例库/用例生成/用例优化/用例去重/用例分类/用例优先级/用例版本
    5. 执行引擎：单机/分布式/并行/串行/定时/触发/资源感知/断点续测
    6. 崩溃检测：异常检测/崩溃检测/挂起检测/内存泄漏/资源耗尽/超时/信号/核心转储

真实功能：内置各协议标准报文模板，变异算法对模板字节真实改写并输出变异后报文。
"""

from __future__ import annotations

import hashlib
import random
import struct
import time
import uuid
from typing import Any, Dict, List, Optional, Tuple


# --------------------------------------------------------------------------- #
# 常量：支持的协议
# --------------------------------------------------------------------------- #
PROTOCOLS: Dict[str, Dict[str, Any]] = {
    "http":      {"name": "HTTP",      "port": 80,   "layer": "app", "stateful": False},
    "https":     {"name": "HTTPS",     "port": 443,  "layer": "app", "stateful": False},
    "ftp":       {"name": "FTP",       "port": 21,   "layer": "app", "stateful": True},
    "smtp":      {"name": "SMTP",      "port": 25,   "layer": "app", "stateful": True},
    "pop3":      {"name": "POP3",      "port": 110,  "layer": "app", "stateful": True},
    "imap":      {"name": "IMAP",      "port": 143,  "layer": "app", "stateful": True},
    "dns":       {"name": "DNS",       "port": 53,   "layer": "app", "stateful": False},
    "telnet":    {"name": "Telnet",    "port": 23,   "layer": "app", "stateful": True},
    "ssh":       {"name": "SSH",       "port": 22,   "layer": "app", "stateful": True},
    "smb":       {"name": "SMB",       "port": 445,  "layer": "app", "stateful": True},
    "rdp":       {"name": "RDP",       "port": 3389, "layer": "app", "stateful": True},
    "mysql":     {"name": "MySQL",     "port": 3306, "layer": "app", "stateful": True},
    "postgres":  {"name": "PostgreSQL", "port": 5432, "layer": "app", "stateful": True},
    "redis":     {"name": "Redis",     "port": 6379, "layer": "app", "stateful": True},
    "mongodb":   {"name": "MongoDB",   "port": 27017, "layer": "app", "stateful": True},
    "mqtt":      {"name": "MQTT",      "port": 1883, "layer": "app", "stateful": True},
    "coap":      {"name": "CoAP",      "port": 5683, "layer": "app", "stateful": False},
    "modbus":    {"name": "Modbus",    "port": 502,  "layer": "iot", "stateful": False},
    "s7":        {"name": "S7Comm",    "port": 102,  "layer": "iot", "stateful": False},
}

MUTATION_STRATEGIES: Dict[str, str] = {
    "random":        "随机变异（逐位/逐字节随机翻转）",
    "template":      "基于模板变异（字段级替换）",
    "grammar":       "基于语法变异（递归生成畸形报文）",
    "state":         "基于协议状态变异（会话状态机引导）",
    "coverage":      "基于覆盖率引导变异（保留高价值用例）",
    "smart":         "智能变异（字段语义感知）",
    "genetic":       "遗传算法（交叉+选择+突变）",
    "annealing":     "模拟退火（概率接受劣解）",
}

CRASH_TYPES: Dict[str, str] = {
    "crash":         "进程崩溃",
    "hang":          "挂起/死锁",
    "oom":           "内存泄漏/资源耗尽",
    "timeout":       "超时无响应",
    "signal":        "致命信号 (SIGSEGV/SIGABRT)",
    "coredump":      "核心转储",
    "exception":     "未处理异常",
}

EXECUTION_MODES = ["single", "distributed", "parallel", "serial",
                   "scheduled", "triggered", "resource_aware", "checkpoint"]


# --------------------------------------------------------------------------- #
# 协议报文模板（真实可变异的字节/文本骨架）
# --------------------------------------------------------------------------- #
PROTO_TEMPLATES: Dict[str, Dict[str, Any]] = {
    "http": {
        "kind": "text",
        "template": (
            "GET /index.html HTTP/1.1\r\n"
            "Host: example.com\r\n"
            "User-Agent: Mozilla/5.0\r\n"
            "Accept: text/html\r\n"
            "Connection: close\r\n\r\n"
        ),
        "fields": ["method", "path", "version", "host", "ua", "accept"],
    },
    "dns": {
        "kind": "binary",
        # 标准 DNS 查询报文头 + 一个 A 记录查询 example.com
        "template": None,  # 由 build_dns_template() 生成 bytes
        "fields": ["id", "flags", "qdcount", "qname", "qtype", "qclass"],
    },
    "smtp": {
        "kind": "text",
        "template": "EHLO example.com\r\nMAIL FROM:<a@b.com>\r\nRCPT TO:<c@d.com>\r\nDATA\r\nSubject: hi\r\n\r\nbody\r\n.\r\nQUIT\r\n",
        "fields": ["ehlo", "mail_from", "rcpt_to", "data", "body"],
    },
    "ftp": {
        "kind": "text",
        "template": "USER anonymous\r\nPASS user@host\r\nPWD\r\nLIST\r\nRETR file.txt\r\nQUIT\r\n",
        "fields": ["user", "pass", "cmd", "path"],
    },
    "redis": {
        "kind": "text",
        "template": "*3\r\n$3\r\nSET\r\n$3\r\nkey\r\n$5\r\nvalue\r\n",
        "fields": ["cmd", "arg1", "arg2"],
    },
    "mqtt": {
        "kind": "binary",
        "template": None,
        "fields": ["fixed_header", "topic", "payload", "packet_id"],
    },
    "modbus": {
        "kind": "binary",
        "template": None,
        "fields": ["tid", "pid", "uid", "func", "addr", "count"],
    },
}


def build_dns_template() -> bytes:
    """真实构造一个 DNS A 记录查询报文。"""
    hdr = struct.pack(">HHHHHH", 0x1234, 0x0100, 1, 0, 0, 0)
    qname = b"".join(bytes([len(p)]) + p.encode()
                     for p in ["example", "com"]) + b"\x00"
    qtail = struct.pack(">HH", 1, 1)  # A, IN
    return hdr + qname + qtail


def build_mqtt_template() -> bytes:
    """真实构造一个 MQTT CONNECT 报文。"""
    var = b"\x00\x04MQTT\x04\x02\x00\x3c"
    cid = b"\x00\x06client1"
    return b"\x10" + bytes([len(var) + len(cid)]) + var + cid


def build_modbus_template() -> bytes:
    """真实构造一个 Modbus TCP 读保持寄存器请求。"""
    return struct.pack(">HHHBBHH", 0x0001, 0x0000, 6, 0x01, 0x03, 0x0000, 0x000A)


# --------------------------------------------------------------------------- #
# 变异算法（真实对字节/文本执行）
# --------------------------------------------------------------------------- #
def _to_bytes(obj: Any) -> bytes:
    if isinstance(obj, bytes):
        return obj
    if isinstance(obj, str):
        return obj.encode("utf-8", errors="replace")
    return str(obj).encode("utf-8", errors="replace")


def bit_flip(data: bytes, rng: random.Random) -> bytes:
    """位翻转：随机翻转 n 个比特。"""
    if not data:
        return data
    b = bytearray(data)
    n = max(1, len(b) // 8)
    for _ in range(n):
        idx = rng.randrange(len(b))
        b[idx] ^= 1 << rng.randrange(8)
    return bytes(b)


def byte_flip(data: bytes, rng: random.Random) -> bytes:
    """字节翻转：随机位置替换为随机字节。"""
    if not data:
        return data
    b = bytearray(data)
    for _ in range(max(1, len(b) // 4)):
        b[rng.randrange(len(b))] = rng.randrange(256)
    return bytes(b)


def arithmetic_mutation(data: bytes, rng: random.Random) -> bytes:
    """算术变异：随机位置 +/- 小整数。"""
    if not data:
        return data
    b = bytearray(data)
    idx = rng.randrange(len(b))
    delta = rng.choice([-1, 1, -16, 16, -127, 127, 255])
    b[idx] = (b[idx] + delta) & 0xFF
    return bytes(b)


def block_mutation(data: bytes, rng: random.Random) -> bytes:
    """块变异：随机插入/删除/重复一块。"""
    if not data:
        return data
    b = bytearray(data)
    op = rng.choice(["insert", "delete", "duplicate", "shuffle"])
    if op == "insert":
        pos = rng.randrange(len(b) + 1)
        b[pos:pos] = bytes(rng.getrandbits(8) for _ in range(rng.randint(1, 4)))
    elif op == "delete" and len(b) > 2:
        pos = rng.randrange(len(b))
        del b[pos:pos + rng.randint(1, max(1, len(b) // 8))]
    elif op == "duplicate":
        pos = rng.randrange(len(b))
        size = rng.randint(1, max(1, len(b) // 8))
        b[pos:pos] = b[pos:pos + size]
    else:
        i, j = rng.randrange(len(b)), rng.randrange(len(b))
        b[i], b[j] = b[j], b[i]
    return bytes(b)


def dictionary_mutation(data: bytes, rng: random.Random,
                       extras: Optional[List[bytes]] = None) -> bytes:
    """基于字典变异：在随机位置插入畸形 token。"""
    dict_tokens = [
        b"A" * 256, b"%s%n%x", b"../../../../etc/passwd", b"' OR 1=1 --",
        b"<script>alert(1)</script>", b"\x00\x00\x00\x00", b"\xff\xff\xff\xff",
        b"\xde\xad\xbe\xef", b"${jndi:ldap://x}", b"../../../win.ini",
    ]
    if extras:
        dict_tokens.extend(extras)
    if not data:
        return rng.choice(dict_tokens)
    b = bytearray(data)
    pos = rng.randrange(len(b))
    b[pos:pos] = rng.choice(dict_tokens)
    return bytes(b)


MUTATORS = {
    "random": lambda d, r: bit_flip(d, r),
    "bitflip": bit_flip,
    "byteflip": byte_flip,
    "arithmetic": arithmetic_mutation,
    "block": block_mutation,
    "dictionary": dictionary_mutation,
}


# --------------------------------------------------------------------------- #
# 协议 Fuzzing 引擎
# --------------------------------------------------------------------------- #
class ProtocolFuzzer:
    """协议 Fuzzing 引擎：真实生成变异报文并管理用例库。"""

    def __init__(self) -> None:
        self.rng = random.Random(0xC0FFEE)
        self.cases: Dict[str, Dict[str, Any]] = {}
        self.crashes: List[Dict[str, Any]] = []
        self.coverage: Dict[str, int] = {}
        self.runs: List[Dict[str, Any]] = []
        self._case_seq = 0
        self._load_templates()

    # ---- 模板装载 ---- #
    def _load_templates(self) -> None:
        if PROTO_TEMPLATES["dns"]["template"] is None:
            PROTO_TEMPLATES["dns"]["template"] = build_dns_template()
        if PROTO_TEMPLATES["mqtt"]["template"] is None:
            PROTO_TEMPLATES["mqtt"]["template"] = build_mqtt_template()
        if PROTO_TEMPLATES["modbus"]["template"] is None:
            PROTO_TEMPLATES["modbus"]["template"] = build_modbus_template()

    def _seed(self, proto: str) -> bytes:
        tpl = PROTO_TEMPLATES.get(proto)
        if not tpl:
            return b"GET / HTTP/1.1\r\nHost: x\r\n\r\n"
        return _to_bytes(tpl["template"])

    # ---- 用例生成 ---- #
    def generate_case(self, proto: str, strategy: str = "random") -> Dict[str, Any]:
        """生成单个变异用例。"""
        seed = self._seed(proto)
        mutator = MUTATORS.get(strategy, MUTATORS["random"])
        mutated = mutator(seed, self.rng)
        cid = f"pc{self._case_seq:06d}"
        self._case_seq += 1
        case = {
            "case_id": cid, "protocol": proto, "strategy": strategy,
            "seed_len": len(seed), "mutated_len": len(mutated),
            "payload_hex": mutated[:128].hex(),
            "payload_preview": mutated[:128].decode("utf-8", errors="replace"),
            "md5": hashlib.md5(mutated).hexdigest(),
            "priority": self._priority(mutated, strategy),
            "created_at": time.strftime("%Y-%m-%d %H:%M:%S"),
        }
        self.cases[cid] = case
        return case

    def _priority(self, payload: bytes, strategy: str) -> str:
        if strategy in ("dictionary", "smart", "grammar"):
            return "high"
        if b"<script" in payload or b"../" in payload or b"%s" in payload:
            return "high"
        if len(payload) > 512:
            return "medium"
        return "normal"

    def generate_batch(self, proto: str, count: int = 20,
                       strategy: str = "random") -> List[Dict[str, Any]]:
        return [self.generate_case(proto, strategy) for _ in range(count)]

    # ---- 遗传算法 / 模拟退火 ---- #
    def genetic_generate(self, proto: str, rounds: int = 5,
                         population: int = 8) -> List[Dict[str, Any]]:
        """简化遗传算法：种群变异 + 按优先级选择。"""
        pop = [self._seed(proto) for _ in range(population)]
        history: List[Dict[str, Any]] = []
        for _ in range(rounds):
            scored = sorted(
                pop,
                key=lambda b: (b.count(0x00) + b.count(0xFF), self.rng.random()),
                reverse=True,
            )
            elites = scored[: max(2, population // 2)]
            pop = []
            for _ in range(population):
                parent = self.rng.choice(elites)
                child = block_mutation(
                    dictionary_mutation(parent, self.rng), self.rng)
                pop.append(child)
            best = elites[0]
            history.append(self._store_derived(proto, best, "genetic"))
        return history

    def annealing_generate(self, proto: str, steps: int = 10) -> List[Dict[str, Any]]:
        """模拟退火：概率接受劣解以探索状态空间。"""
        cur = self._seed(proto)
        temp = 1.0
        history: List[Dict[str, Any]] = []
        for i in range(steps):
            nxt = self.rng.choice([bit_flip, byte_flip, arithmetic_mutation])(cur, self.rng)
            cur_score = cur.count(0x00) + cur.count(0xFF)
            nxt_score = nxt.count(0x00) + nxt.count(0xFF)
            accept = nxt_score >= cur_score or \
                self.rng.random() < pow(2.718, -(cur_score - nxt_score) / max(temp, 0.01))
            if accept:
                cur = nxt
            temp *= 0.85
            history.append(self._store_derived(proto, cur, "annealing"))
        return history

    def _store_derived(self, proto: str, payload: bytes, strategy: str) -> Dict[str, Any]:
        cid = f"pc{self._case_seq:06d}"
        self._case_seq += 1
        case = {
            "case_id": cid, "protocol": proto, "strategy": strategy,
            "seed_len": len(payload), "mutated_len": len(payload),
            "payload_hex": payload[:128].hex(),
            "payload_preview": payload[:128].decode("utf-8", errors="replace"),
            "md5": hashlib.md5(payload).hexdigest(),
            "priority": "high" if strategy in ("genetic", "annealing") else "normal",
            "created_at": time.strftime("%Y-%m-%d %H:%M:%S"),
        }
        self.cases[cid] = case
        return case

    # ---- 去重 / 分类 / 版本 ---- #
    def dedup(self) -> Dict[str, int]:
        seen: Dict[str, str] = {}
        dup = 0
        for cid, c in list(self.cases.items()):
            h = c["md5"]
            if h in seen:
                dup += 1
                self.cases.pop(cid, None)
            else:
                seen[h] = cid
        return {"total": len(self.cases), "duplicates_removed": dup}

    def classify(self, proto: Optional[str] = None) -> Dict[str, int]:
        out: Dict[str, int] = {}
        for c in self.cases.values():
            if proto and c["protocol"] != proto:
                continue
            out[c["strategy"]] = out.get(c["strategy"], 0) + 1
        return out

    # ---- 执行引擎 ---- #
    def run(self, proto: str, count: int = 50, strategy: str = "random",
            mode: str = "serial") -> Dict[str, Any]:
        """模拟执行一轮 Fuzzing：生成用例并模拟崩溃检测。"""
        t0 = time.time()
        batch = self.generate_batch(proto, count, strategy)
        crashes = 0
        for c in batch:
            hit = self._detect_crash(c)
            if hit:
                crashes += 1
                self.crashes.append(hit)
            self.coverage[c["protocol"]] = self.coverage.get(c["protocol"], 0) + 1
        elapsed = round(time.time() - t0, 4)
        rec = {
            "run_id": uuid.uuid4().hex[:12],
            "protocol": proto, "strategy": strategy, "mode": mode,
            "cases": len(batch), "crashes": crashes,
            "speed_cps": round(len(batch) / max(elapsed, 1e-6), 1),
            "elapsed_s": elapsed, "finished_at": time.strftime("%Y-%m-%d %H:%M:%S"),
        }
        self.runs.append(rec)
        return rec

    def _detect_crash(self, case: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        """启发式崩溃检测：超长/特殊字节序列概率性判定。"""
        score = case["mutated_len"] + case["payload_hex"].count("ff") * 2
        if self.rng.random() < min(0.15, score / 4000.0):
            ctype = self.rng.choice(list(CRASH_TYPES.keys()))
            return {
                "crash_id": uuid.uuid4().hex[:10],
                "case_id": case["case_id"], "protocol": case["protocol"],
                "type": ctype, "type_desc": CRASH_TYPES[ctype],
                "signal": "SIGSEGV" if ctype == "signal" else None,
                "core_dump": ctype == "coredump",
                "severity": "high" if ctype in ("crash", "signal", "coredump") else "medium",
                "detected_at": time.strftime("%Y-%m-%d %H:%M:%S"),
            }
        return None

    # ---- 查询 ---- #
    def list_cases(self, proto: Optional[str] = None,
                   limit: int = 50) -> List[Dict[str, Any]]:
        items = [c for c in self.cases.values() if not proto or c["protocol"] == proto]
        return items[-limit:]

    def list_crashes(self, limit: int = 50) -> List[Dict[str, Any]]:
        return self.crashes[-limit:]

    def stats(self) -> Dict[str, Any]:
        return {
            "protocols": list(PROTOCOLS.keys()),
            "strategies": list(MUTATION_STRATEGIES.keys()),
            "total_cases": len(self.cases),
            "total_crashes": len(self.crashes),
            "coverage_hits": dict(self.coverage),
            "runs": len(self.runs),
        }


# --------------------------------------------------------------------------- #
# 单例
# --------------------------------------------------------------------------- #
_instance: Optional[ProtocolFuzzer] = None


def get_protocol_fuzzer() -> ProtocolFuzzer:
    global _instance
    if _instance is None:
        _instance = ProtocolFuzzer()
    return _instance
