"""Read-only PE/x64 inspection for the built-in GameMaker runner adapter.

Uses a local Zydis bridge; never starts or writes to the inspected game.
Addresses accepted by the commands are RVAs unless they are >= the image base.
"""
from __future__ import annotations

import argparse
import bisect
import ctypes as C
import hashlib
import re
import struct
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
DEFAULT_EXE = Path(r"C:\Program Files (x86)\Steam\steamapps\common\Nubby's Number Factory\NNF_FULLVERSION.exe")


class Insn(C.Structure):
    _fields_ = [("address", C.c_uint64), ("size", C.c_uint32), ("text", C.c_char * 256)]


class PE:
    def __init__(self, path):
        self.path = Path(path)
        self.data = self.path.read_bytes()
        self.sha256 = hashlib.sha256(self.data).hexdigest()
        pe = self.u32(0x3c)
        if self.data[pe:pe+4] != b"PE\0\0" or self.u16(pe+4) != 0x8664:
            raise ValueError("an x64 PE image is required")
        opt = pe + 24
        self.base = self.u64(opt + 24)
        self.sections = []
        sh = opt + self.u16(pe + 20)
        for i in range(self.u16(pe+6)):
            off = sh + i * 40
            name = self.data[off:off+8].rstrip(b"\0").decode()
            vs, rva, size, raw = struct.unpack_from("<IIII", self.data, off+8)
            self.sections.append((name, rva, vs, raw, size))
        pdata, size = struct.unpack_from("<II", self.data, opt+112+3*8)
        self.functions = []
        if pdata:
            raw = self.offset(pdata)
            self.functions = [struct.unpack_from("<III", self.data, raw+i)
                              for i in range(0, size-size%12, 12)]
        self.starts = [f[0] for f in self.functions]

    def u16(self, off): return struct.unpack_from("<H", self.data, off)[0]
    def u32(self, off): return struct.unpack_from("<I", self.data, off)[0]
    def u64(self, off): return struct.unpack_from("<Q", self.data, off)[0]
    def rva(self, addr): return addr-self.base if addr >= self.base else addr

    def offset(self, address):
        rva = self.rva(address)
        for _, start, _, raw, size in self.sections:
            if start <= rva < start+size:
                return raw+rva-start
        raise ValueError(f"unbacked RVA {rva:x}")

    def owner(self, address):
        rva = self.rva(address)
        i = bisect.bisect_right(self.starts, rva)-1
        return self.functions[i] if i >= 0 and self.functions[i][0] <= rva < self.functions[i][1] else None

    def owner_text(self, address):
        fn = self.owner(address)
        return f"function {fn[0]:08x}..{fn[1]:08x}" if fn else "no pdata owner"

    def strings(self, pattern):
        rx = re.compile(pattern, re.I)
        for _, rva, _, raw, size in self.sections:
            for m in re.finditer(rb"[\x20-\x7e]{4,}", self.data[raw:raw+size]):
                s = m.group().decode("ascii")
                if rx.search(s):
                    yield rva+m.start(), s

    def refs(self, target):
        target = self.rva(target)
        for name, rva, _, raw, size in self.sections:
            if name != ".text": continue
            text = self.data[raw:raw+size]
            # Candidate RIP-relative LEA/MOV references; validated by disassembly below.
            for m in re.finditer(rb"[\x40-\x4f]?[\x8d\x8b\x89][\x05\x0d\x15\x1d\x25\x2d\x35\x3d]....", text, re.S):
                end = m.end()
                if rva+end+struct.unpack_from("<i", text, end-4)[0] == target:
                    yield rva+m.start()
            for m in re.finditer(rb"[\x40-\x4f]?[\x80\x83\xc6][\x05\x0d\x15\x1d\x25\x2d\x35\x3d].....", text, re.S):
                end = m.end()
                if rva+end+struct.unpack_from("<i", text, end-5)[0] == target:
                    yield rva+m.start()

    def pointers(self, target):
        needle = struct.pack("<Q", self.base+self.rva(target))
        for name,rva,_,raw,size in self.sections:
            for m in re.finditer(re.escape(needle), self.data[raw:raw+size]):
                yield rva+m.start()

    def callers(self, target):
        target = self.rva(target)
        for name, rva, _, raw, size in self.sections:
            if name != ".text": continue
            text = self.data[raw:raw+size]
            for m in re.finditer(rb"\xe8", text):
                off = m.start()
                if off+5 <= len(text) and rva+off+5+struct.unpack_from("<i", text, off+1)[0] == target:
                    yield rva+off


class Decoder:
    def __init__(self):
        self.lib = C.CDLL(str(Path(__file__).parent / ".cache/zydis_bridge.dll"))
        self.lib.DecodeX64.argtypes = [C.c_void_p, C.c_uint32, C.c_uint64, C.POINTER(Insn), C.c_uint32]
        self.lib.DecodeX64.restype = C.c_uint32

    def decode(self, data, address):
        buf = C.create_string_buffer(data)
        result = (Insn * len(data))()
        count = self.lib.DecodeX64(buf, len(data), address, result, len(result))
        rows = []
        for i in result[:count]:
            mnemonic, _, operands = i.text.decode().partition(" ")
            offset = i.address-address
            rows.append((i.address, i.size, data[offset:offset+i.size].hex(" "), mnemonic, operands))
        return rows


def main():
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--exe", type=Path, default=DEFAULT_EXE)
    sub = ap.add_subparsers(dest="cmd", required=True)
    sub.add_parser("info")
    p = sub.add_parser("strings"); p.add_argument("pattern")
    p = sub.add_parser("refs"); p.add_argument("address", type=lambda x:int(x, 16))
    p = sub.add_parser("callers"); p.add_argument("address", type=lambda x:int(x, 16))
    p = sub.add_parser("pointers"); p.add_argument("address", type=lambda x:int(x, 16))
    p = sub.add_parser("disasm"); p.add_argument("address", type=lambda x:int(x, 16)); p.add_argument("--size", type=lambda x:int(x, 16), default=0)
    args = ap.parse_args()
    pe = PE(args.exe)
    if args.cmd == "info":
        print(f"{pe.path}\nSHA256 {pe.sha256}\nImage base {pe.base:x}")
        for s in pe.sections: print(s)
    elif args.cmd == "strings":
        for address, s in pe.strings(args.pattern): print(f"{address:08x} {s}")
    elif args.cmd in ("refs", "callers", "pointers"):
        for address in getattr(pe,args.cmd)(args.address): print(f"{address:08x} {pe.owner_text(address)}")
    elif args.cmd == "disasm":
        rva = pe.rva(args.address)
        owner = pe.owner(rva)
        if not args.size and owner: rva, end, _ = owner
        else: end = rva+(args.size or 0x100)
        raw = pe.offset(rva)
        print(pe.owner_text(rva))
        for address, size, hexb, mnemonic, operands in Decoder().decode(pe.data[raw:raw+end-rva], pe.base+rva):
            print(f"{address-pe.base:08x} {hexb:44} {mnemonic:9} {operands}")


if __name__ == "__main__":
    main()
