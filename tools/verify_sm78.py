#!/usr/bin/env python3
"""
SM07 / SM08 비트 매핑 가설 검증

가설:
  H1: SM07 seq = 8 bit @ 27..34, wrap 빈도 ~33
  H2: SM07 seq = 11 bit @ 27..37, wrap 빈도 ~4
  H3: SM07 bits 35..37 = reserved (전부 0)
  H4: SM07 ver(24..26) = constant 1
  H5: SM07 payload length = constant
  H6: SM08 payload length distribution
  H7: SM08 trailing bits 64..87 (=0x102010 ?) 의 실제 분포
  H8: SM08 어딘가에 매 epoch SM 개수 반영 필드 존재
  H9: SM07 seq vs SM08 seq 1:1 일치
"""
import os, sys, struct
from collections import Counter, defaultdict

ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), '..', '..'))
RTCM = os.path.join(ROOT, 'ssr_raw_data_20260510.rtcm3')
CRC24Q_POLY = 0x1864CFB
FRAME_HDR = 24  # bits

def crc24q(buf):
    crc = 0
    for b in buf:
        crc ^= b << 16
        for _ in range(8):
            crc <<= 1
            if crc & 0x1000000:
                crc ^= CRC24Q_POLY
        crc &= 0xFFFFFF
    return crc

def getbitu(buff, pos, ln):
    v = 0
    for i in range(pos, pos + ln):
        v = (v << 1) | ((buff[i >> 3] >> (7 - (i & 7))) & 1)
    return v

def iter_frames(path):
    with open(path, 'rb') as f:
        data = f.read()
    i = 0
    n = len(data)
    while i < n:
        if data[i] != 0xD3:
            i += 1; continue
        if i + 3 > n: break
        ln = ((data[i+1] & 0x03) << 8) | data[i+2]
        frame_len = 3 + ln + 3
        if i + frame_len > n: break
        payload = data[i:i+3+ln]
        crc_bytes = data[i+3+ln:i+frame_len]
        crc_recv = (crc_bytes[0] << 16) | (crc_bytes[1] << 8) | crc_bytes[2]
        if crc_recv != crc24q(payload):
            i += 1; continue
        yield ln, data[i:i+frame_len]
        i += frame_len

# ---------- 1) Collect all SM07, SM08 ---------------------------------------
sm07_frames = []   # list of (data_len_bytes, frame_bytes)
sm08_frames = []

# group into (sm07, [sm0X frames], sm08) epoch pairs by streaming order
epoch_pairs = []   # list of (sm07_idx, sm08_idx, sms_between)
cur_sm07_idx = None
cur_sms_between = []

frame_idx = 0
for ln, fr in iter_frames(RTCM):
    mt   = getbitu(fr, FRAME_HDR, 12)
    if mt != 4090:
        frame_idx += 1
        continue
    mNo  = getbitu(fr, FRAME_HDR + 16, 8)

    if mNo == 7:
        sm07_frames.append((ln, fr))
        cur_sm07_idx = len(sm07_frames) - 1
        cur_sms_between = []
    elif mNo == 8:
        sm08_frames.append((ln, fr))
        if cur_sm07_idx is not None:
            epoch_pairs.append((cur_sm07_idx, len(sm08_frames) - 1, cur_sms_between[:]))
        cur_sm07_idx = None
        cur_sms_between = []
    elif 1 <= mNo <= 6 and cur_sm07_idx is not None:
        cur_sms_between.append(mNo)
    frame_idx += 1

print(f"SM07 frames: {len(sm07_frames)}")
print(f"SM08 frames: {len(sm08_frames)}")
print(f"Complete epoch pairs (SM07→...→SM08): {len(epoch_pairs)}")
print()

# ---------- H5, H6: payload length distribution -----------------------------
sm07_len_hist = Counter(ln for ln, _ in sm07_frames)
sm08_len_hist = Counter(ln for ln, _ in sm08_frames)
print(f"[H5] SM07 payload length (bytes) distribution:")
for ln, cnt in sorted(sm07_len_hist.items()):
    print(f"     {ln} bytes : {cnt} frames")
print(f"[H6] SM08 payload length (bytes) distribution:")
for ln, cnt in sorted(sm08_len_hist.items()):
    print(f"     {ln} bytes : {cnt} frames")
print()

# ---------- 2) Per-bit variance for SM07 and SM08 ---------------------------
def bit_stats(frames, max_bits=None):
    """Return (n, ones_per_bit) for the data section after the frame header."""
    if not frames:
        return 0, []
    # Use shortest frame's data bits to align
    min_ln = min(ln for ln, _ in frames)
    nbits = min_ln * 8
    if max_bits is not None:
        nbits = min(nbits, max_bits)
    ones = [0] * nbits
    for ln, fr in frames:
        for b in range(nbits):
            ones[b] += getbitu(fr, FRAME_HDR + b, 1)
    return len(frames), ones

n07, ones07 = bit_stats(sm07_frames)
n08, ones08 = bit_stats(sm08_frames)

def fmt_bit_summary(name, n, ones):
    print(f"[{name}] {n} frames, payload bits 0..{len(ones)-1}")
    print(f"   pos | ones / total | flag")
    print(f"   ----+--------------+-----")
    for b, k in enumerate(ones):
        flag = ""
        if k == 0: flag = "0const"
        elif k == n: flag = "1const"
        elif 0.4 * n < k < 0.6 * n: flag = "~random"
        elif k < 0.05 * n or k > 0.95 * n: flag = "sparse"
        print(f"   {b:3d} | {k:5d}/{n:<5d} | {flag}")

fmt_bit_summary("SM07", n07, ones07)
print()
fmt_bit_summary("SM08", n08, ones08)
print()

# ---------- H1/H2: seq wrap detection ---------------------------------------
def extract_seq(frames, pos, ln):
    return [getbitu(fr, FRAME_HDR + pos, ln) for _, fr in frames]

seq07_8  = extract_seq(sm07_frames, 27, 8)
seq07_11 = extract_seq(sm07_frames, 27, 11)
seq08_8  = extract_seq(sm08_frames, 27, 8)
seq08_11 = extract_seq(sm08_frames, 27, 11)

def count_wraps(seq):
    """seq가 단조 증가에서 줄어드는 횟수"""
    wraps = 0
    for i in range(1, len(seq)):
        if seq[i] < seq[i-1]:
            wraps += 1
    return wraps

print(f"[H1] SM07 seq 8-bit (mod 256): wraps={count_wraps(seq07_8)}")
print(f"     first 20: {seq07_8[:20]}")
print(f"     last 10:  {seq07_8[-10:]}")
print(f"     unique values: {len(set(seq07_8))}")
print()
print(f"[H2] SM07 seq 11-bit (mod 2048): wraps={count_wraps(seq07_11)}")
print(f"     first 20: {seq07_11[:20]}")
print(f"     last 10:  {seq07_11[-10:]}")
print(f"     unique values: {len(set(seq07_11))}")
print()

# Verify monotonic-with-wraps by reconstructing absolute counter
def is_clean_modulo(seq, mod):
    """seq가 +1 단조증가 with mod wrap 인지 검사"""
    bad = 0
    for i in range(1, len(seq)):
        expected = (seq[i-1] + 1) % mod
        if seq[i] != expected:
            bad += 1
    return bad

bad_8  = is_clean_modulo(seq07_8, 256)
bad_11 = is_clean_modulo(seq07_11, 2048)
print(f"[H1] SM07 seq 8-bit, # of +1-step violations: {bad_8} / {len(seq07_8)-1}")
print(f"[H2] SM07 seq 11-bit, # of +1-step violations: {bad_11} / {len(seq07_11)-1}")
print()

# ---------- H9: SM07 seq == SM08 seq in same pair ---------------------------
matches = 0
for i07, i08, _ in epoch_pairs:
    s7 = getbitu(sm07_frames[i07][1], FRAME_HDR + 27, 8)
    s8 = getbitu(sm08_frames[i08][1], FRAME_HDR + 27, 8)
    if s7 == s8: matches += 1
print(f"[H9] SM07 seq8 == SM08 seq8 in same epoch pair: {matches}/{len(epoch_pairs)}")
print()

# ---------- H3: bits 35..37 of SM07 ----------------------------------------
print(f"[H3] SM07 bits 35..37 (3 bits) distribution:")
b35_37 = Counter(getbitu(fr, FRAME_HDR + 35, 3) for _, fr in sm07_frames)
for v, c in sorted(b35_37.items()):
    print(f"     value {v}: {c} frames ({100*c/len(sm07_frames):.1f}%)")
print()

# ---------- H4: SM07 bits 24..26 (ver) -------------------------------------
print(f"[H4] SM07 bits 24..26 (3 bits, alleged ver):")
b24_26 = Counter(getbitu(fr, FRAME_HDR + 24, 3) for _, fr in sm07_frames)
for v, c in sorted(b24_26.items()):
    print(f"     value {v}: {c} frames ({100*c/len(sm07_frames):.1f}%)")
print()

# ---------- H7/H8: SM08 trailing field analysis ----------------------------
# Find data portion length for SM08
sm08_total_bits = min(ln for ln, _ in sm08_frames) * 8
print(f"[H6] SM08 data section bits (min): {sm08_total_bits}")
print(f"     payload-after-header range: 0..{sm08_total_bits-1}")
print()

# tail field at 64..87
tails = [getbitu(fr, FRAME_HDR + 64, 24) for _, fr in sm08_frames]
tail_hist = Counter(tails)
print(f"[H7] SM08 bits 64..87 (24 bits, current 'tail') unique values: {len(tail_hist)}")
for v, c in tail_hist.most_common(5):
    print(f"     0x{v:06X}: {c} frames ({100*c/len(sm08_frames):.1f}%)")
print()

# Check actual frame ends — maybe tail varies in last bits
# Try different positions for SM count field
# We know each epoch contains: 1 SM01 + 4 SM02 + 4 SM03 + 1 SM04 + 1 SM05 + 1 SM06 = 12 SMs
# But this is FIXED across epochs in this file, so we need a different angle:
#   does any contiguous bit field in SM08 vary across epochs in correlation with
#   the number of SMs that actually appeared between SM07 and SM08?

# Get number of intermediate SMs per epoch
sms_count_per_pair = [len(sms) for _, _, sms in epoch_pairs]
print(f"[H8] SM count between SM07 and SM08 per pair:")
sm_cnt_hist = Counter(sms_count_per_pair)
for v, c in sorted(sm_cnt_hist.items()):
    print(f"     {v} SMs: {c} epoch pairs ({100*c/len(epoch_pairs):.1f}%)")
print()

# Are there enough epochs with DIFFERENT SM counts to correlate?
if len(sm_cnt_hist) >= 2:
    print(f"[H8] SM count varies - looking for matching bit field in SM08...")
    # Scan every starting position, every reasonable field width
    candidates = []
    for start in range(0, sm08_total_bits):
        for width in (4, 5, 6, 7, 8, 12, 16):
            if start + width > sm08_total_bits: break
            field_vals = [getbitu(sm08_frames[i08][1], FRAME_HDR + start, width)
                          for _, i08, _ in epoch_pairs]
            # Check correlation with sms_count_per_pair
            if len(set(field_vals)) == 1: continue
            # Pearson-like correlation
            if all(v == sms_count_per_pair[i] for i, v in enumerate(field_vals)):
                candidates.append((start, width, 'exact_match'))
            else:
                # If field has same number of distinct values as sms_count
                if set(field_vals) == set(sms_count_per_pair):
                    candidates.append((start, width, 'value_set_match'))
    for c in candidates[:20]:
        print(f"     candidate: start={c[0]}, width={c[1]} ({c[2]})")
    if not candidates:
        print(f"     no field matches SM count variation")
else:
    print(f"[H8] SM count is constant ({list(sm_cnt_hist.keys())[0]}) across all epochs")
    print(f"     → cannot detect SM count field from this file alone (no variance)")
print()

# ---------- Bonus: SM08 payload "all variable bits" --------------------------
print(f"[Bonus] SM08 bit positions that VARY (not constant) across all frames:")
variable_bits = [b for b, k in enumerate(ones08) if k != 0 and k != n08]
print(f"        {len(variable_bits)} variable bits out of {len(ones08)}")
print(f"        positions: {variable_bits}")
print()

# ---------- Bonus: SM07 vs SM08 TOW field re-check --------------------------
# SM07 TOW @ 51..70 (20 bits)
# SM08 TOW @ 35..54 (20 bits)
tow_matches = 0
tow_mismatch_samples = []
for i07, i08, _ in epoch_pairs:
    t7 = getbitu(sm07_frames[i07][1], FRAME_HDR + 51, 20)
    t8 = getbitu(sm08_frames[i08][1], FRAME_HDR + 35, 20)
    if t7 == t8: tow_matches += 1
    else:
        if len(tow_mismatch_samples) < 3:
            tow_mismatch_samples.append((t7, t8))
print(f"[verify] SM07.tow(@51..70) == SM08.tow(@35..54): {tow_matches}/{len(epoch_pairs)}")
if tow_mismatch_samples:
    print(f"         sample mismatches: {tow_mismatch_samples}")
