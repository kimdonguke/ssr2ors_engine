#!/usr/bin/env python3
"""
v1 발견을 바탕으로 한 추가 검증:
  - SM07.bits[27..34] 는 8-bit seq counter (확정, 모듈로 256, 위반 0)
  - SM08.bits[27..34] 는 4 SMs epoch에서만 SM07.seq와 일치 (83.3%)
  - SM08.bits[27..34] 가 다른 epoch에서 어떤 값을 가지는가?
  - 0x102010 (bits 67, 74, 83 = 1) 의 의미?
  - SM count (4/16/17/18/19) 가 어디 인코딩 되는가?
"""
import os, sys
from collections import Counter, defaultdict

ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), '..', '..'))
RTCM = os.path.join(ROOT, 'ssr_raw_data_20260510.rtcm3')
CRC24Q_POLY = 0x1864CFB
FRAME_HDR = 24

def crc24q(buf):
    crc = 0
    for b in buf:
        crc ^= b << 16
        for _ in range(8):
            crc <<= 1
            if crc & 0x1000000: crc ^= CRC24Q_POLY
        crc &= 0xFFFFFF
    return crc

def getbitu(buff, pos, ln):
    v = 0
    for i in range(pos, pos + ln):
        v = (v << 1) | ((buff[i >> 3] >> (7 - (i & 7))) & 1)
    return v

def iter_frames(path):
    with open(path, 'rb') as f: data = f.read()
    i, n = 0, len(data)
    while i < n:
        if data[i] != 0xD3: i += 1; continue
        if i + 3 > n: break
        ln = ((data[i+1] & 0x03) << 8) | data[i+2]
        L = 3 + ln + 3
        if i + L > n: break
        payload = data[i:i+3+ln]
        crc_bytes = data[i+3+ln:i+L]
        crc_recv = (crc_bytes[0] << 16) | (crc_bytes[1] << 8) | crc_bytes[2]
        if crc_recv != crc24q(payload): i += 1; continue
        yield ln, data[i:i+L]
        i += L

# Collect SM07/SM08 + intermediate SMs (with mNo) ----------------------------
epochs = []   # list of (sm07_frame, sm08_frame, [(mNo,frame)...])
cur_sm07 = None; cur_inter = []
for ln, fr in iter_frames(RTCM):
    if getbitu(fr, FRAME_HDR, 12) != 4090: continue
    mNo = getbitu(fr, FRAME_HDR + 16, 8)
    if mNo == 7: cur_sm07 = fr; cur_inter = []
    elif mNo == 8:
        if cur_sm07 is not None:
            epochs.append((cur_sm07, fr, cur_inter[:]))
        cur_sm07 = None; cur_inter = []
    elif 1 <= mNo <= 6 and cur_sm07 is not None:
        cur_inter.append((mNo, fr))

print(f"Total epoch pairs: {len(epochs)}")
print()

# Bucket epochs by SM count
buckets = defaultdict(list)
for sm07, sm08, inter in epochs:
    buckets[len(inter)].append((sm07, sm08, inter))

print(f"SM count distribution: {dict((k, len(v)) for k, v in sorted(buckets.items()))}")
print()

# -------------------------------------------------------------------------
# Q1: SM08.bits[27..34] value distribution per SM count bucket
print(f"=== Q1: SM08.bits[27..34] per SM count bucket ===")
for cnt in sorted(buckets.keys()):
    samples = buckets[cnt]
    sm08_field = [getbitu(s8, FRAME_HDR + 27, 8) for _, s8, _ in samples]
    sm07_field = [getbitu(s7, FRAME_HDR + 27, 8) for s7, _, _ in samples]
    eq = sum(1 for i in range(len(samples)) if sm08_field[i] == sm07_field[i])
    diff = sum(1 for i in range(len(samples)) if sm08_field[i] != sm07_field[i])
    print(f"  SM count={cnt}: {len(samples)} epochs, SM08==SM07.seq: {eq}, diff: {diff}")
    if diff:
        diffs = [sm07_field[i] - sm08_field[i] for i in range(len(samples)) if sm08_field[i] != sm07_field[i]]
        diff_hist = Counter(diffs)
        # Also try sm07 - sm08 mod 256
        diffs_mod = [(sm07_field[i] - sm08_field[i]) % 256 for i in range(len(samples)) if sm08_field[i] != sm07_field[i]]
        dmh = Counter(diffs_mod)
        print(f"    sm07-sm08 raw   common: {dmh.most_common(5)}")
        # show some sample (sm07, sm08) pairs
        sample_pairs = [(sm07_field[i], sm08_field[i]) for i in range(min(len(samples), 5))]
        print(f"    samples (s7,s8): {sample_pairs}")
print()

# -------------------------------------------------------------------------
# Q2: is SM08 27..34 always (sm07_seq - cnt) or (sm08_seq + cnt) ?
print(f"=== Q2: relationship between SM07.seq, SM08[27..34], and SM count ===")
# For non-4 buckets, check if SM07.seq - SM08[27..34] = some function of cnt
for cnt in sorted(buckets.keys()):
    if cnt == 4: continue
    samples = buckets[cnt]
    deltas = []
    for s7, s8, _ in samples:
        d = (getbitu(s7, FRAME_HDR + 27, 8) - getbitu(s8, FRAME_HDR + 27, 8)) % 256
        deltas.append(d)
    dh = Counter(deltas)
    print(f"  cnt={cnt}: (SM07.seq - SM08[27..34]) mod 256 distribution: {dh.most_common(5)}")
print()

# -------------------------------------------------------------------------
# Q3: Are there OTHER messages between SM08 of one epoch and SM07 of the next?
# Check that "SM count" really equals the intermediate SMs we counted
print(f"=== Q3: verify intermediate SM types per bucket ===")
for cnt in sorted(buckets.keys()):
    samples = buckets[cnt]
    if not samples: continue
    inter_types = Counter()
    for _, _, inter in samples[:3]:
        ts = tuple(mNo for mNo, _ in inter)
        inter_types[ts] += 1
    print(f"  cnt={cnt}: first 3 intermediate sequences:")
    for ts, c in inter_types.most_common(3):
        print(f"     {ts}")
print()

# -------------------------------------------------------------------------
# Q4: Is the "missing" SM07 epoch (between sm08 and next sm07) something we should worry about?
# Compare: total intermediate SMs counted vs SM07-SM08 gap
# Already done above - cnt = real SMs in pair

# Q5: 0x102010 - is it really bit 67, 74, 83?
# 0x102010 = 0001 0000 0010 0000 0001 0000 (24 bits)
# Positions of 1s in 24-bit field starting at bit 64:
#   bit 64+3=67, 64+10=74, 64+19=83
# Spacing 67->74 = 7, 74->83 = 9 - not uniform
# Could be a CRC-like sparse pattern? Or message-end magic?
print(f"=== Q5: 0x102010 byte alignment investigation ===")
print(f"  payload of SM08 = 11 bytes = 88 bits")
print(f"  bits 64..87 = bytes 8,9,10 = last 3 bytes")
print(f"  in big-endian: byte8=0x10, byte9=0x20, byte10=0x10")
print(f"  Notice: byte8 = byte10 = 0x10. Possibly a fixed trailer/checksum?")
# Check if it's literally "GS" or any other known marker
# 0x10 = LF? No, that's 0x0A. 0x10 is DLE (Data Link Escape).
# 0x102010 in ASCII makes no sense.
# Maybe it's a small Reed-Solomon or Hamming code on previous bits?
print()

# Q6: check if 0x102010 changes with any other bits
# Already shown all 8567 frames have same tail. So it's CONSTANT, not dependent.
# This means it's NOT a CRC over the message contents.
print(f"=== Q6: 0x102010 truly constant - not a CRC ===")
# CRC would change with message content. Since constant across 8567 frames with
# different (week, tow, seq), it MUST be a fixed pattern.

# Q7: Check SM07 bits 12..15 (4 bits between MT and mNo)
print(f"=== Q7: SM07 bits 12..15 - what is it? ===")
b12_15 = Counter(getbitu(fr, FRAME_HDR + 12, 4) for fr, _, _ in epochs)
for v, c in b12_15.most_common():
    print(f"  value 0x{v:X}: {c} epochs ({100*c/len(epochs):.1f}%)")
print()

# Q8: Compare bits 12..15 across SM01..SM08 - is it sub-type field?
print(f"=== Q8: bits 12..15 across all SM types ===")
type_b12_15 = defaultdict(Counter)
for _, fr in iter_frames(RTCM):
    if getbitu(fr, FRAME_HDR, 12) != 4090: continue
    mNo = getbitu(fr, FRAME_HDR + 16, 8)
    b = getbitu(fr, FRAME_HDR + 12, 4)
    type_b12_15[mNo][b] += 1
for mNo in sorted(type_b12_15.keys()):
    print(f"  mNo={mNo}: {dict(type_b12_15[mNo])}")
print()
