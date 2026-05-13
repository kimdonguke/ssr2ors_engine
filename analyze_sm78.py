"""
analyze_sm78.py
  Reverse-engineer the bit layout of SM07 / SM08 in the SSR-G stream.

Strategy:
  1. Walk all RTCM3 frames. For each MT 4090 frame, classify by mNo.
  2. For each SM07/SM08 instance, record:
       - the full payload bits as a list
       - the timeline position (frame index in file)
       - the gs (TOW) of the LAST SM02 seen before this SM07/SM08
         (Java keeps a single "current" gs across the stream)
  3. Per-bit analysis: which bits are constant; which form mono-increasing
     fields; which fields, when extracted, exactly match the neighbour SM02 gs.
  4. Try every (offset, width) window in [3..21] bits and check which slot
     matches the expected GPS week (~2417 for May 2026) for SM07.
"""

import sys
from collections import Counter

ssr_udi = [1,2,5,10,15,30,60,120,240,300,600,900,1800,3600,7200,10800]

CRC_TABLE = [
    0x000000,0x864CFB,0x8AD50D,0x0C99F6,0x93E6E1,0x15AA1A,0x1933EC,0x9F7F17,
    0xA18139,0x27CDC2,0x2B5434,0xAD18CF,0x3267D8,0xB42B23,0xB8B2D5,0x3EFE2E,
    0xC54E89,0x430272,0x4F9B84,0xC9D77F,0x56A868,0xD0E493,0xDC7D65,0x5A319E,
    0x64CFB0,0xE2834B,0xEE1ABD,0x685646,0xF72951,0x7165AA,0x7DFC5C,0xFBB0A7,
    0x0CD1E9,0x8A9D12,0x8604E4,0x00481F,0x9F3708,0x197BF3,0x15E205,0x93AEFE,
    0xAD50D0,0x2B1C2B,0x2785DD,0xA1C926,0x3EB631,0xB8FACA,0xB4633C,0x322FC7,
    0xC99F60,0x4FD39B,0x434A6D,0xC50696,0x5A7981,0xDC357A,0xD0AC8C,0x56E077,
    0x681E59,0xEE52A2,0xE2CB54,0x6487AF,0xFBF8B8,0x7DB443,0x712DB5,0xF7614E,
    0x19A3D2,0x9FEF29,0x9376DF,0x153A24,0x8A4533,0x0C09C8,0x00903E,0x86DCC5,
    0xB822EB,0x3E6E10,0x32F7E6,0xB4BB1D,0x2BC40A,0xAD88F1,0xA11107,0x275DFC,
    0xDCED5B,0x5AA1A0,0x563856,0xD074AD,0x4F0BBA,0xC94741,0xC5DEB7,0x43924C,
    0x7D6C62,0xFB2099,0xF7B96F,0x71F594,0xEE8A83,0x68C678,0x645F8E,0xE21375,
    0x15723B,0x933EC0,0x9FA736,0x19EBCD,0x8694DA,0x00D821,0x0C41D7,0x8A0D2C,
    0xB4F302,0x32BFF9,0x3E260F,0xB86AF4,0x2715E3,0xA15918,0xADC0EE,0x2B8C15,
    0xD03CB2,0x567049,0x5AE9BF,0xDCA544,0x43DA53,0xC596A8,0xC90F5E,0x4F43A5,
    0x71BD8B,0xF7F170,0xFB6886,0x7D247D,0xE25B6A,0x641791,0x688E67,0xEEC29C,
    0x3347A4,0xB50B5F,0xB992A9,0x3FDE52,0xA0A145,0x26EDBE,0x2A7448,0xAC38B3,
    0x92C69D,0x148A66,0x181390,0x9E5F6B,0x01207C,0x876C87,0x8BF571,0x0DB98A,
    0xF6092D,0x7045D6,0x7CDC20,0xFA90DB,0x65EFCC,0xE3A337,0xEF3AC1,0x69763A,
    0x578814,0xD1C4EF,0xDD5D19,0x5B11E2,0xC46EF5,0x42220E,0x4EBBF8,0xC8F703,
    0x3F964D,0xB9DAB6,0xB54340,0x330FBB,0xAC70AC,0x2A3C57,0x26A5A1,0xA0E95A,
    0x9E1774,0x185B8F,0x14C279,0x928E82,0x0DF195,0x8BBD6E,0x872498,0x016863,
    0xFAD8C4,0x7C943F,0x700DC9,0xF64132,0x693E25,0xEF72DE,0xE3EB28,0x65A7D3,
    0x5B59FD,0xDD1506,0xD18CF0,0x57C00B,0xC8BF1C,0x4EF3E7,0x426A11,0xC426EA,
    0x2AE476,0xACA88D,0xA0317B,0x267D80,0xB90297,0x3F4E6C,0x33D79A,0xB59B61,
    0x8B654F,0x0D29B4,0x01B042,0x87FCB9,0x1883AE,0x9ECF55,0x9256A3,0x141A58,
    0xEFAAFF,0x69E604,0x657FF2,0xE33309,0x7C4C1E,0xFA00E5,0xF69913,0x70D5E8,
    0x4E2BC6,0xC8673D,0xC4FECB,0x42B230,0xDDCD27,0x5B81DC,0x57182A,0xD154D1,
    0x26359F,0xA07964,0xACE092,0x2AAC69,0xB5D37E,0x339F85,0x3F0673,0xB94A88,
    0x87B4A6,0x01F85D,0x0D61AB,0x8B2D50,0x145247,0x921EBC,0x9E874A,0x18CBB1,
    0xE37B16,0x6537ED,0x69AE1B,0xEFE2E0,0x709DF7,0xF6D10C,0xFA48FA,0x7C0401,
    0x42FA2F,0xC4B6D4,0xC82F22,0x4E63D9,0xD11CCE,0x575035,0x5BC9C3,0xDD8538,
]
def crc24q(buf):
    c = 0
    for b in buf:
        c = CRC_TABLE[((c >> 16) ^ b) & 0xFF] ^ ((c << 8) & 0xFFFFFF)
    return c

def bytes_to_bits(b):
    return "".join(f"{x:08b}" for x in b)

def gather(path):
    """Return list of (mNo, payload_bits, frame_index, last_sm02_gs)."""
    with open(path, "rb") as f:
        data = f.read()
    out = []
    last_sm02_gs = None
    pos = 0
    idx = 0
    while pos < len(data):
        while pos < len(data) and data[pos] != 0xD3:
            pos += 1
        if pos + 3 > len(data): break
        length = ((data[pos+1] & 3) << 8) | data[pos+2]
        end = pos + 3 + length
        if end + 3 > len(data): break
        if crc24q(data[pos:end]) != (data[end]<<16) | (data[end+1]<<8) | data[end+2]:
            pos += 1; continue
        payload = data[pos+3:end]
        bits = bytes_to_bits(payload)
        msg_no = int(bits[0:12], 2)
        if msg_no == 4090:
            mNo = int(bits[16:24], 2)
            if mNo == 2:
                # track current gs from SM02
                last_sm02_gs = int(bits[27:47], 2)
            elif mNo in (7, 8):
                out.append((mNo, bits, idx, last_sm02_gs))
        pos = end + 3
        idx += 1
    return out

def per_bit_stats(records, bitlen, label):
    """For each bit position, count zeros and ones across all records."""
    print(f"\n=== {label}  ({len(records)} samples, payload_bits={bitlen}) ===")
    counts = [[0, 0] for _ in range(bitlen)]
    for mNo, bits, _, _ in records:
        for i in range(min(bitlen, len(bits))):
            counts[i][int(bits[i])] += 1
    print("bit | const?  | ratio   | likely role")
    print("----+---------+---------+------------")
    for i, (z, o) in enumerate(counts):
        tot = z + o
        if tot == 0: continue
        if z == 0 or o == 0:
            tag = "CONST"
            ratio = "1.000" if z == 0 else "0.000"
        else:
            tag = "var"
            ratio = f"{o/tot:.3f}"
        # group every 8 bits as a byte boundary
        sep = "  ← byte" if (i+1) % 8 == 0 else ""
        # only show non-trivial bits or first 24 (type/sub/mNo headers)
        if i < 24 or tag == "var" or (i % 8 == 0):
            print(f"{i:3d} | {tag:7s} | {ratio:7s} |{sep}")
    # print constant byte-pattern as hex for clarity
    print("\nConstant bit pattern (X = variable):")
    s = ""
    for i, (z, o) in enumerate(counts):
        tot = z + o
        if tot == 0:
            s += "?"
        elif z == 0:
            s += "1"
        elif o == 0:
            s += "0"
        else:
            s += "X"
        if (i+1) % 8 == 0: s += " "
    print(s)

def find_tow_window(records, bitlen):
    """Search every (offset, width) for a window whose value equals the
       last_sm02_gs of each record (the SM02 immediately before it)."""
    print(f"\nSearching for TOW field (matches last_sm02_gs)...")
    samples = [(int(b, 2) for b in [bits[s:s+w]] for bits, s, w in []) for _ in []]  # placeholder
    # Try widths 12..21
    matches = []
    for w in range(12, 22):
        for off in range(0, bitlen - w + 1):
            # require sample with known last_sm02_gs
            ok = 0; tot = 0
            for mNo, bits, idx, last in records:
                if last is None: continue
                tot += 1
                v = int(bits[off:off+w], 2)
                if v == last:
                    ok += 1
            if tot > 0 and ok == tot:
                matches.append((off, w, ok, tot))
    if matches:
        print(f"  EXACT TOW matches:")
        for off, w, ok, tot in matches:
            print(f"    bits {off:2d}..{off+w-1:2d}  width={w:2d}  match {ok}/{tot}")
    else:
        # show approximate matches (allow small offsets — SM07 is start, SM02 within block)
        print("  no exact match — searching for fields within ±5 sec of last SM02 gs ...")
        for w in range(12, 22):
            for off in range(0, bitlen - w + 1):
                ok = 0; tot = 0
                for mNo, bits, idx, last in records:
                    if last is None: continue
                    tot += 1
                    v = int(bits[off:off+w], 2)
                    if abs(v - last) <= 5:
                        ok += 1
                if tot > 50 and ok/tot >= 0.98:
                    print(f"    bits {off:2d}..{off+w-1:2d}  width={w:2d}  near-match {ok}/{tot}")

def find_week_window(records, bitlen, expected_week):
    """Search for a window whose value is constant and equal to expected GPS week."""
    print(f"\nSearching for GPS week field (constant value = {expected_week})...")
    for w in range(10, 17):
        for off in range(0, bitlen - w + 1):
            vals = set()
            for mNo, bits, idx, last in records:
                vals.add(int(bits[off:off+w], 2))
                if len(vals) > 3: break
            if len(vals) == 1 and expected_week in vals:
                print(f"    bits {off:2d}..{off+w-1:2d}  width={w:2d}  value={list(vals)[0]}")

def find_message_count(records, bitlen):
    """SM08 should contain a count of SM messages in the preceding block.
       Look for windows whose values are small and consistent (e.g. 7..50)."""
    print("\nSearching for SM-count field in SM08 (small unsigned ~10..50)...")
    for w in range(4, 13):
        for off in range(0, bitlen - w + 1):
            vals = [int(bits[off:off+w], 2) for mNo, bits, idx, last in records]
            c = Counter(vals)
            most_common = c.most_common(3)
            mx = max(vals); mn = min(vals)
            if mx <= 100 and len(c) <= 50 and mx >= 5:
                # print only most-promising
                top_str = ", ".join(f"{v}({n})" for v, n in most_common)
                print(f"    bits {off:2d}..{off+w-1:2d}  width={w:2d}  range={mn}..{mx}  top: {top_str}")

def main(path):
    print(f"Loading {path} ...")
    records = gather(path)
    sm07 = [r for r in records if r[0] == 7]
    sm08 = [r for r in records if r[0] == 8]
    print(f"  SM07: {len(sm07)}    SM08: {len(sm08)}")

    # SM07: 80-bit payload (10 bytes)
    per_bit_stats(sm07, 80, "SM07")
    find_tow_window(sm07, 80)
    # expected GPS week for 2026-05-10:
    # GPS week 0 = 1980-01-06, days = 16927, week = 2418
    find_week_window(sm07, 80, 2417)
    find_week_window(sm07, 80, 2418)
    find_week_window(sm07, 80, 2419)

    # SM08: 88-bit payload (11 bytes)
    per_bit_stats(sm08, 88, "SM08")
    find_tow_window(sm08, 88)
    find_message_count(sm08, 88)

if __name__ == "__main__":
    main(sys.argv[1] if len(sys.argv) > 1 else "../ssr_raw_data_20260510.rtcm3")
