import re, zlib, sys

src = open(r"C:\Users\Omack\source\repos\dissassembler\tests\inflate_test.cpp", encoding="utf-8").read()

def arr(name):
    m = re.search(name + r"\[\d+\]\s*=\s*\{(.*?)\};", src, re.S)
    return bytes(int(x, 16) for x in re.findall(r"0x[0-9a-fA-F]{2}", m.group(1)))

fixed = arr("kFixedDeflate")
dyn   = arr("kDynDeflate")
far   = arr("kFarDeflate")

ok = True

want_fixed = b"Hello, inflate! Hello, inflate!"
got = zlib.decompress(fixed, -15)
print("fixed:", got == want_fixed, len(fixed), "bytes ->", len(got))
ok &= got == want_fixed

want_dyn = b"The quick brown fox jumps over the lazy dog. " * 64
got = zlib.decompress(dyn, -15)
print("dyn:", got == want_dyn, len(dyn), "bytes ->", len(got))
ok &= got == want_dyn

want_far = bytes((i*37+11) & 0xFF for i in range(100)) + b"x"*32000 + bytes((i*37+11) & 0xFF for i in range(100))
got = zlib.decompress(far, -15)
print("far:", got == want_far, len(far), "bytes ->", len(got))
ok &= got == want_far

# check the claimed first-byte block types
print("fixed BTYPE bits:", fixed[0] & 7, "(want 3)")
print("dyn   BTYPE bits:", dyn[0] & 7, "(want 5)")

# does kFarDeflate actually contain a distance-32100 match? decode header bits crudely:
# just confirm it's a single fixed block (BFINAL=1 BTYPE=01)
print("far BTYPE bits:", far[0] & 7, "(want 3)")

sys.exit(0 if ok else 1)
