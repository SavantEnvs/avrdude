#!/usr/bin/env python3
# Generates the minimal AVR ELF seeds in testsuite/ (selector byte + ELF32, EM_AVR): python3 gen_seeds.py testsuite
import struct, sys
def elf(segments):
    # segments: list of (name, paddr, bytes)
    shstr = b"\0" + b"".join(n.encode()+b"\0" for n,_,_ in segments) + b".shstrtab\0"
    ehsize, phsize, shsize = 52, 32, 40
    nph = len(segments); off = ehsize + nph*phsize
    data = b""; phs = []; shs = [b"\0"*40]; nameoff = 1
    for n,pa,b in segments:
        o = off + len(data)
        phs.append(struct.pack("<8I", 1, o, pa & 0xffff if pa < 0x800000 else pa, pa, len(b), len(b), 5, 1))
        shs.append(struct.pack("<10I", nameoff, 1, 2|4, pa, o, len(b), 0, 0, 1, 0))
        nameoff += len(n)+1; data += b
    stroff = off + len(data); data += shstr
    shs.append(struct.pack("<10I", nameoff, 3, 0, 0, stroff, len(shstr), 0, 0, 1, 0))
    shoff = off + len(data)
    eh = b"\x7fELF" + bytes([1,1,1,0]) + b"\0"*8 + struct.pack("<HHIIIIIHHHHHH", 2, 83, 1, 0, ehsize, shoff, 0x85, ehsize, phsize, nph, shsize, len(shs), len(shs)-1)
    return eh + b"".join(phs) + data + b"".join(shs)
out = sys.argv[1]
code = bytes.fromhex("0c9434000c943e00") + bytes(range(64))
seeds = {
  "flash_text": (b"\x00", [(".text", 0, code)]),
  "flash_eeprom": (b"\x01", [(".text", 0, code), (".eeprom", 0x810000, b"EEPROMDATA\x01\x02")]),
  "fuses": (b"\x03", [(".text", 0, code), (".fuse", 0x820000, b"\xff\xd9\xfd")]),
  "lock": (b"\x05", [(".text", 0, code), (".lock", 0x830000, b"\xfc")]),
  "m2560_flash": (b"\x08", [(".text", 0, code*4), (".data", 0x200, b"hello")]),
  "xmega": (b"\x10", [(".text", 0, code)]),
}
for k,(sel,segs) in seeds.items():
    open(f"{out}/{k}", "wb").write(sel + elf(segs))
