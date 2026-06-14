#!/usr/bin/env python3
"""
Analyze DisasmStudio network payload logs.

This tool classifies the captured socket buffers DisasmStudio writes from its
ws2_32 send/recv tap. It is meant for reverse-engineering triage: split traffic
by socket, identify TLS ClientHello SNI values, recognize Java RMI/JRMI records,
and pull readable Java serialization strings out of the payloads.

The --toy-rmi-demo option mimics only the *shape* of the observed localhost RMI
heartbeat inside a self-contained local demo. It is deliberately not a working
client for any third-party service.
"""

from __future__ import annotations

import argparse
import collections
import dataclasses
import re
import socket
import struct
import threading
import time
from pathlib import Path
from typing import Iterable


HEADER_RE = re.compile(
    r"^=== (?P<time>\d+-\d+-\d+ \d+:\d+:\d+\.\d+) "
    r"(?P<dir>SEND|RECV) api=(?P<api>\S+) pid=(?P<pid>\d+) "
    r"tid=(?P<tid>\d+) sock=(?P<sock>\S+) total=(?P<total>\d+) "
    r"captured=(?P<cap>\d+)"
)
HEX_RE = re.compile(r"^[0-9A-Fa-f]{8}\s+")


@dataclasses.dataclass
class Record:
    line: int
    time: str
    direction: str
    api: str
    pid: int
    tid: int
    sock: str
    total: int
    captured: int
    data: bytes = b""


def parse_log(path: Path) -> list[Record]:
    records: list[Record] = []
    current: Record | None = None
    hex_bytes = bytearray()
    in_hex = False

    def finish() -> None:
        nonlocal current, hex_bytes
        if current is not None:
            current.data = bytes(hex_bytes)
            records.append(current)
        current = None
        hex_bytes = bytearray()

    with path.open("r", encoding="utf-8", errors="replace") as f:
        for lineno, raw in enumerate(f, 1):
            line = raw.rstrip("\n")
            m = HEADER_RE.match(line)
            if m:
                finish()
                current = Record(
                    line=lineno,
                    time=m.group("time"),
                    direction=m.group("dir"),
                    api=m.group("api"),
                    pid=int(m.group("pid")),
                    tid=int(m.group("tid")),
                    sock=m.group("sock"),
                    total=int(m.group("total")),
                    captured=int(m.group("cap")),
                )
                in_hex = False
                continue

            if current is None:
                continue
            if line == "HEX:":
                in_hex = True
                continue
            if in_hex:
                if not line.strip():
                    in_hex = False
                    continue
                if HEX_RE.match(line):
                    # Bytes live in the fixed-width hexdump field after the offset.
                    for tok in re.findall(r"\b[0-9A-Fa-f]{2}\b", line[10:61]):
                        hex_bytes.append(int(tok, 16))

    finish()
    return records


def ascii_strings(data: bytes, min_len: int = 4) -> list[str]:
    out: list[str] = []
    start = -1
    for i, b in enumerate(data + b"\x00"):
        if 0x20 <= b < 0x7F or b in (9,):
            if start < 0:
                start = i
        elif start >= 0:
            if i - start >= min_len:
                out.append(data[start:i].decode("ascii", errors="replace"))
            start = -1
    return out


def parse_tls_sni(data: bytes) -> str | None:
    if len(data) < 9 or data[0] != 0x16 or data[5] != 0x01:
        return None
    try:
        p = 5 + 4              # handshake header
        p += 2 + 32            # version + random
        sid_len = data[p]
        p += 1 + sid_len
        cs_len = int.from_bytes(data[p:p + 2], "big")
        p += 2 + cs_len
        comp_len = data[p]
        p += 1 + comp_len
        ext_len = int.from_bytes(data[p:p + 2], "big")
        p += 2
        end = min(len(data), p + ext_len)
        while p + 4 <= end:
            etype = int.from_bytes(data[p:p + 2], "big")
            elen = int.from_bytes(data[p + 2:p + 4], "big")
            p += 4
            e = data[p:p + elen]
            p += elen
            if etype != 0 or len(e) < 5:
                continue
            q = 2
            while q + 3 <= len(e):
                name_type = e[q]
                name_len = int.from_bytes(e[q + 1:q + 3], "big")
                q += 3
                name = e[q:q + name_len]
                q += name_len
                if name_type == 0:
                    return name.decode("ascii", errors="replace")
    except (IndexError, ValueError):
        return None
    return None


def parse_endpoint(data: bytes) -> str | None:
    # Observed JRMI endpoint forms:
    #   4E 00 09 "127.0.0.1" 00 00 C7 38
    #   00 09 "localhost" 00 00 C7 32
    p = 1 if data.startswith(b"N") else 0
    if len(data) < p + 2:
        return None
    n = int.from_bytes(data[p:p + 2], "big")
    q = p + 2
    if n <= 0 or q + n + 4 > len(data):
        return None
    host = data[q:q + n]
    if not all(32 <= b < 127 for b in host):
        return None
    port = int.from_bytes(data[q + n:q + n + 4], "big")
    host_s = host.decode("ascii", errors="replace")
    if host_s in ("localhost", "127.0.0.1", "::1"):
        prefix = "JRMI endpoint reply" if p == 0 else "JRMI endpoint"
        return f"{prefix}: {host_s}:{port}"
    return None


def classify(data: bytes) -> str:
    if not data:
        return "empty"

    if data.startswith(b"JRMI"):
        ver = int.from_bytes(data[4:6], "big") if len(data) >= 6 else 0
        proto = chr(data[6]) if len(data) >= 7 and 32 <= data[6] < 127 else "?"
        return f"Java RMI transport header: JRMI version={ver} protocol={proto}"

    endpoint = parse_endpoint(data)
    if endpoint:
        return endpoint

    if data in (b"R", b"S"):
        return f"Java RMI heartbeat marker: {data.decode('ascii')}"

    if len(data) >= 5 and data[1:3] in (b"\x03\x01", b"\x03\x02", b"\x03\x03"):
        tls_types = {
            0x14: "TLS ChangeCipherSpec",
            0x15: "TLS Alert",
            0x16: "TLS Handshake",
            0x17: "TLS ApplicationData",
        }
        name = tls_types.get(data[0], f"TLS record type 0x{data[0]:02X}")
        sni = parse_tls_sni(data)
        return f"{name}; SNI={sni}" if sni else name

    magic_at = data.find(b"\xAC\xED\x00\x05")
    if magic_at >= 0:
        op = chr(data[0]) if data and 32 <= data[0] < 127 else "?"
        strings = ascii_strings(data)
        interesting = [
            s for s in strings
            if s.startswith(("java.", "com.", "javax."))
            or "UnicastRef" in s
            or "Remote" in s
            or "localhost" in s
        ]
        if interesting:
            return f"Java serialization / RMI op={op}: " + "; ".join(interesting[:4])
        return f"Java serialization / RMI op={op}"

    strings = ascii_strings(data)
    if strings:
        return "text-ish: " + "; ".join(strings[:3])
    return "binary"


def summarize(records: list[Record], socket_filter: str | None, max_records: int) -> None:
    if socket_filter:
        records = [r for r in records if r.sock.lower() == socket_filter.lower()]

    print(f"records: {len(records)}")
    by_sock: dict[str, list[Record]] = collections.defaultdict(list)
    for r in records:
        by_sock[r.sock].append(r)

    print("\nby socket:")
    for sock, group in sorted(by_sock.items(), key=lambda kv: kv[1][0].time):
        sent = sum(r.total for r in group if r.direction == "SEND")
        recv = sum(r.total for r in group if r.direction == "RECV")
        tids = ",".join(str(t) for t in sorted({r.tid for r in group}))
        print(
            f"  {sock:>6}  records={len(group):3d}  "
            f"sent={sent:6d}  recv={recv:6d}  "
            f"first={group[0].time}  last={group[-1].time}  tids={tids}"
        )

    print("\nrecords:")
    for r in records[:max_records]:
        print(
            f"  line {r.line:5d}  {r.time}  {r.direction:<4} "
            f"{r.sock:>6} {r.api:<7} {r.total:5d}B  {classify(r.data)}"
        )

    strings = collections.Counter()
    for r in records:
        for s in ascii_strings(r.data):
            if any(k in s for k in ("localhost", "127.0.0.1", "java.", "com.", "UnicastRef", "Remote")):
                strings[s] += 1
    if strings:
        print("\ninteresting strings:")
        for s, count in strings.most_common(30):
            print(f"  {count:3d}x  {s[:160]}")


def dump_records(records: Iterable[Record], out_dir: Path) -> None:
    out_dir.mkdir(parents=True, exist_ok=True)
    for i, r in enumerate(records):
        safe_sock = r.sock.replace("0x", "")
        name = f"{i:04d}-line{r.line}-{safe_sock}-{r.direction.lower()}-{r.total}.bin"
        (out_dir / name).write_bytes(r.data)
    print(f"wrote {i + 1 if 'i' in locals() else 0} payload files to {out_dir}")


def toy_rmi_demo(rounds: int) -> None:
    """Run a self-contained localhost demo that resembles the observed RMI rhythm."""
    endpoint_client = b"N\x00\x09127.0.0.1\x00\x00\xC7\x38"
    endpoint_server = b"\x00\x09localhost\x00\x00\xC7\x32"
    server_payload = b"P\xAC\xED\x00\x05w\x22" + b"toy RemoteNavnetServer heartbeat".ljust(34, b".")[:34]
    client_payload = b"Q\xAC\xED\x00\x05w\x13" + b"toy-client-call".ljust(19, b".")[:19]

    def recv_exactish(s: socket.socket, n: int = 4096) -> bytes:
        s.settimeout(2.0)
        return s.recv(n)

    listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    listener.bind(("127.0.0.1", 0))
    listener.listen(1)
    port = listener.getsockname()[1]

    def server() -> None:
        conn, addr = listener.accept()
        with conn:
            print(f"[server] accepted {addr}")
            conn.sendall(b"JRMI\x00\x02K")
            print("[server] sent JRMI header")
            print(f"[server] recv {recv_exactish(conn).hex(' ')}")
            conn.sendall(endpoint_server)
            print("[server] sent endpoint localhost:50994")
            for _ in range(rounds):
                one = recv_exactish(conn, 1)
                print(f"[server] recv marker {one!r}")
                conn.sendall(b"R")
                conn.sendall(server_payload)
                print("[server] sent R + serialized heartbeat payload")
                print(f"[server] recv reply {recv_exactish(conn).hex(' ')}")

    t = threading.Thread(target=server, daemon=True)
    t.start()

    with socket.create_connection(("127.0.0.1", port), timeout=2.0) as client:
        print(f"[client] connected to toy server on 127.0.0.1:{port}")
        print(f"[client] recv {recv_exactish(client).hex(' ')}")
        client.sendall(endpoint_client)
        print("[client] sent endpoint 127.0.0.1:51000")
        print(f"[client] recv {recv_exactish(client).hex(' ')}")
        for i in range(rounds):
            client.sendall(b"S")
            print(f"[client] round {i + 1}: sent S")
            print(f"[client] recv marker {recv_exactish(client, 1)!r}")
            print(f"[client] recv payload {recv_exactish(client).hex(' ')}")
            client.sendall(client_payload[:-4] + struct.pack(">I", i + 1))
            print("[client] sent Q serialized reply")
            time.sleep(0.1)

    t.join(timeout=1.0)
    listener.close()


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("log", nargs="?", type=Path, help="network_payloads.log from DisasmStudio")
    ap.add_argument("--socket", dest="socket_filter", help="Only show one socket, e.g. 0x9D4")
    ap.add_argument("--max-records", type=int, default=80)
    ap.add_argument("--dump-dir", type=Path, help="Write captured payloads as .bin files")
    ap.add_argument("--toy-rmi-demo", action="store_true", help="Run a local-only JRMI/RMI heartbeat shape demo")
    ap.add_argument("--rounds", type=int, default=3, help="Toy demo heartbeat rounds")
    args = ap.parse_args()

    if args.toy_rmi_demo:
        toy_rmi_demo(max(1, args.rounds))
        return 0

    if not args.log:
        ap.error("log path is required unless --toy-rmi-demo is used")
    records = parse_log(args.log)
    if args.socket_filter:
        selected = [r for r in records if r.sock.lower() == args.socket_filter.lower()]
    else:
        selected = records
    summarize(selected, None, args.max_records)
    if args.dump_dir:
        dump_records(selected, args.dump_dir)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
